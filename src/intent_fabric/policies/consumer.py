# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Governed Policy Executor Pipeline.

Ingests an EvidencePackage, validates cryptographic hashes and freshness,
enforces anti-replay guards, generates an evidence-backed plan, evaluates
policy rules, and emits a signed execution token exclusively upon authorization.
Also provides governed single-tool dispatch with fail-closed Etude and Compaction gates.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set

from intent_fabric.approvals.signing import SignedExecutionToken, TokenSigner
from intent_fabric.compaction_lock import (
    CompactionConstraintLock,
    PostCompactionRuleViolationError,
    SilentModelRouteDriftError,
    enforce_post_compaction_lock,
    resolve_and_check_path,
)
from intent_fabric.contracts.evidence_verifier import (
    VerificationResult,
    verify_evidence_package,
)
from intent_fabric.etude_lock import (
    EtudeToolDriftError,
    EtudeToolLockRegistry,
)
from intent_fabric.models import EvidenceItemReference, EvidencePackageReference, IntentRequest
from intent_fabric.planning.planner import Plan, Planner
from intent_fabric.policies.engine import PolicyDecision, PolicyDecisionType, PolicyEngine


@dataclass(slots=True)
class GovernedExecutionResult:
    """Outcome of governed policy pipeline execution."""

    is_authorized: bool
    decision: Optional[PolicyDecision] = None
    verification: Optional[VerificationResult] = None
    plan: Optional[Plan] = None
    execution_token: Optional[SignedExecutionToken] = None
    rejection_reasons: List[str] = field(default_factory=list)


class GovernedPolicyExecutor:
    """Orchestrates evidence verification, plan generation, and policy enforcement."""

    def __init__(
        self,
        policy_engine: PolicyEngine | Any,
        planner: Optional[Planner | Any] = None,
        signer: Optional[TokenSigner | Any] = None,
        compaction_lock: Optional[CompactionConstraintLock] = None,
        compaction_signing_key: Optional[str | bytes] = None,
        etude_registry: Optional[EtudeToolLockRegistry] = None,
        require_pinned: bool = True,
        follow_calls_in: Optional[Sequence[str]] = None,
        base_dir: Optional[str | Path] = None,
    ) -> None:
        self.policy_engine = policy_engine
        self.planner = planner
        self.signer = signer
        self.compaction_lock = compaction_lock
        self.compaction_signing_key = compaction_signing_key
        self.etude_registry = etude_registry
        self.require_pinned = require_pinned
        self._follow_calls_in = tuple(follow_calls_in) if follow_calls_in else ()
        self._base_dir = base_dir
        self._seen_retrieval_ids: Set[str] = set()
        self._tools: Dict[
            str, tuple[Callable[..., Any], Mapping[str, Any], Optional[Sequence[str]]]
        ] = {}

    def register_tool(
        self,
        name: str,
        fn: Callable[..., Any],
        schema: Optional[Mapping[str, Any]] = None,
        allowed_sinks: Optional[Sequence[str]] = None,
    ) -> None:
        """Register a tool handler and its schema for governed execution."""
        self._tools[name] = (fn, schema or {"name": name}, allowed_sinks)

    def execute(
        self,
        target_or_goal: str = "",
        args_or_evidence: Any = None,
        context_or_max_age: Any = 60.0,
        *,
        intent_goal: Optional[str] = None,
        evidence_package: Optional[Dict[str, Any]] = None,
        context: Any = None,
        compaction_lock: Optional[CompactionConstraintLock] = None,
        compaction_signing_key: Optional[str | bytes] = None,
        observed_model_version: Optional[str] = None,
        require_model_version: bool = True,
        max_age_seconds: float = 60.0,
        **kwargs: Any,
    ) -> Any:
        """Executes full verification and policy governance flow, or dispatches a registered tool."""
        effective_goal = intent_goal if intent_goal is not None else target_or_goal
        effective_evidence = evidence_package if evidence_package is not None else args_or_evidence

        # Distinguish between tool execution and evidence package planning
        is_evidence_package = (
            isinstance(effective_evidence, Mapping)
            and (
                "retrieval_id" in effective_evidence
                or "chunks" in effective_evidence
                or "items" in effective_evidence
            )
            and effective_goal not in self._tools
        )

        if not is_evidence_package and (
            effective_goal in self._tools or isinstance(effective_evidence, dict)
        ):
            return self._execute_tool(
                tool_name=effective_goal,
                tool_args=effective_evidence if isinstance(effective_evidence, dict) else {},
                context=context
                if context is not None
                else (
                    context_or_max_age if not isinstance(context_or_max_age, (int, float)) else None
                ),
                compaction_lock=compaction_lock,
                compaction_signing_key=compaction_signing_key,
                observed_model_version=observed_model_version,
                require_model_version=require_model_version,
            )

        evidence_package = effective_evidence if isinstance(effective_evidence, Mapping) else {}
        intent_goal = str(effective_goal)
        actual_max_age = (
            context_or_max_age if isinstance(context_or_max_age, (int, float)) else max_age_seconds
        )

        retrieval_id = evidence_package.get("retrieval_id")

        # 1. Anti-Replay Guard
        if not retrieval_id:
            return GovernedExecutionResult(
                is_authorized=False,
                rejection_reasons=["Missing retrieval_id in evidence package"],
            )

        if retrieval_id in self._seen_retrieval_ids:
            return GovernedExecutionResult(
                is_authorized=False,
                rejection_reasons=[
                    f"Replay detected: retrieval_id '{retrieval_id}' already consumed"
                ],
            )

        # Ensure evidence package is not empty in governed planning
        chunks_present = evidence_package.get("chunks") or evidence_package.get("items")
        if not chunks_present:
            return GovernedExecutionResult(
                is_authorized=False,
                rejection_reasons=[
                    "Empty evidence package: actions require non-empty verified evidence"
                ],
            )

        # 2. Cryptographic and Freshness Verification
        verification = verify_evidence_package(evidence_package, max_age_seconds=actual_max_age)
        if not verification.is_valid:
            return GovernedExecutionResult(
                is_authorized=False,
                verification=verification,
                rejection_reasons=[
                    verification.error_reason or "Cryptographic verification failed"
                ],
            )

        # Mark retrieval_id as seen once verified
        self._seen_retrieval_ids.add(retrieval_id)

        # 3. Evidence-Grounded Planning
        items: List[EvidenceItemReference] = []
        for ch in evidence_package.get("chunks", []):
            item = EvidenceItemReference(
                chunk_id=ch.get("chunk_id", 0),
                document_uri=ch.get("source_uri") or ch.get("document_uri") or "",
                snippet=ch.get("snippet", ch.get("content", "")),
                score=float(ch.get("score", 1.0)),
                metadata=ch.get("metadata", {}),
                provenance_hash=ch.get("chunk_hash", ch.get("provenance_hash", "")),
            )
            items.append(item)

        intent_req = IntentRequest(
            intent_id=f"intent-{str(retrieval_id)[:8]}",
            user_request=intent_goal,
        )
        evidence_ref = EvidencePackageReference(
            query_text=intent_goal,
            items=items,
            retrieval_summary=evidence_package.get("retrieval_summary", {}),
            provenance_digest=evidence_package.get("provenance_digest", ""),
            query_fingerprint=evidence_package.get("query_fingerprint", ""),
            generated_at=evidence_package.get("generated_at", ""),
        )
        plan = (
            self.planner.create_plan(intent=intent_req, evidence=evidence_ref)
            if self.planner
            else None
        )

        # 4. Policy Evaluation
        decision = self.policy_engine.evaluate(plan) if self.policy_engine and plan else None

        # 4b. Pre-Execution ARCBench Post-Compaction Constraint Lock (when active)
        active_lock = compaction_lock if compaction_lock is not None else self.compaction_lock
        active_key = (
            compaction_signing_key
            if compaction_signing_key is not None
            else self.compaction_signing_key
        )
        if active_lock is not None and plan is not None:
            try:
                for step in plan.steps:
                    step_args = dict(step.action_contract.parameters or {})
                    if "__contract_target" not in step_args:
                        step_args["__contract_target"] = step.action_contract.target
                    enforce_post_compaction_lock(
                        active_lock,
                        step.action_contract.action_type,
                        step_args,
                        observed_model_version=observed_model_version,
                        require_model_version=require_model_version,
                        signing_key=active_key,
                    )
            except (PostCompactionRuleViolationError, SilentModelRouteDriftError) as exc:
                return GovernedExecutionResult(
                    is_authorized=False,
                    decision=decision,
                    verification=verification,
                    plan=plan,
                    execution_token=None,
                    rejection_reasons=[str(exc)],
                )

        # 5. Token Generation or Deny Execution
        decision_type = getattr(decision, "decision_type", None) or getattr(
            decision, "decision", None
        )
        if decision_type == PolicyDecisionType.ALLOW:
            token = (
                self.signer.sign_execution(
                    plan_id=plan.plan_id if plan else "plan-unknown",
                    provenance_digest=evidence_package["provenance_digest"],
                    tenant_id=evidence_package["tenant_id"],
                )
                if self.signer
                else None
            )
            return GovernedExecutionResult(
                is_authorized=True,
                decision=decision,
                verification=verification,
                plan=plan,
                execution_token=token,
            )

        # Fail-closed for REQUIRES_APPROVAL or DENY
        reason = (
            getattr(decision, "reason", None)
            or (decision.reasons[0] if getattr(decision, "reasons", None) else None)
            or "Policy rejected plan execution"
        )
        return GovernedExecutionResult(
            is_authorized=False,
            decision=decision,
            verification=verification,
            plan=plan,
            execution_token=None,
            rejection_reasons=[reason],
        )

    def _execute_tool(
        self,
        *,
        tool_name: str,
        tool_args: dict[str, Any],
        context: Any,
        compaction_lock: Optional[CompactionConstraintLock],
        compaction_signing_key: Optional[str | bytes],
        observed_model_version: Optional[str],
        require_model_version: bool,
    ) -> Any:
        """Executes a registered tool under policy governance and cryptographic constraints."""
        # 1. Policy check
        if hasattr(self.policy_engine, "evaluate"):
            try:
                decision = self.policy_engine.evaluate(
                    tool_name=tool_name, tool_args=tool_args, context=context
                )
                if hasattr(decision, "allowed") and not decision.allowed:
                    raise PermissionError(
                        getattr(decision, "reason", "Policy rejected tool execution")
                    )
            except TypeError:
                pass

        # 2. Fail-closed Etude gate
        if self.require_pinned and self.etude_registry is not None:
            lock = self.etude_registry.get_lock(tool_name)
            if lock is None:
                raise EtudeToolDriftError(f"Tool '{tool_name}' is not pinned in etude registry")
            handler_info = self._tools.get(tool_name)
            if handler_info is not None:
                fn, schema, _ = handler_info
                self.etude_registry.verify_tool(
                    tool_name,
                    schema,
                    fn,
                    follow_calls_in=self._follow_calls_in,
                )

        # 3. Compaction constraint lock check
        active_lock = compaction_lock if compaction_lock is not None else self.compaction_lock
        active_key = (
            compaction_signing_key
            if compaction_signing_key is not None
            else self.compaction_signing_key
        )
        if active_lock is not None:
            enforce_post_compaction_lock(
                active_lock,
                tool_name,
                tool_args,
                observed_model_version=observed_model_version,
                require_model_version=require_model_version,
                signing_key=active_key,
            )

        # 4. Path resolution check (C2)
        if active_lock and getattr(active_lock, "forbidden_path_prefixes", None):
            for k in ("path", "file", "filepath", "filename"):
                if k in tool_args and isinstance(tool_args[k], (str, Path, bytes)):
                    resolve_and_check_path(
                        tool_args[k],
                        active_lock.forbidden_path_prefixes,
                        base_dir=self._base_dir,
                    )

        # 5. Handler invocation
        handler_info = self._tools.get(tool_name)
        if handler_info is None:
            raise KeyError(f"Tool '{tool_name}' not registered in GovernedPolicyExecutor")
        fn, _, _ = handler_info
        sig = inspect.signature(fn)
        # Pass tool_args as kwargs if parameters match, else as single dict
        try:
            return fn(**tool_args)
        except TypeError:
            if len(sig.parameters) == 1:
                return fn(tool_args)
            raise
