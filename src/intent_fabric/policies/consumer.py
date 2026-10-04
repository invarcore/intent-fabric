# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Governed Policy Executor Pipeline.

Ingests an EvidencePackage, validates cryptographic hashes and freshness,
enforces anti-replay guards, generates an evidence-backed plan, evaluates
policy rules, and emits a signed execution token exclusively upon authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from intent_fabric.approvals.signing import SignedExecutionToken, TokenSigner
from intent_fabric.contracts.evidence_verifier import (
    VerificationResult,
    verify_evidence_package,
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
        policy_engine: PolicyEngine,
        planner: Planner,
        signer: TokenSigner,
    ) -> None:
        self.policy_engine = policy_engine
        self.planner = planner
        self.signer = signer
        self._seen_retrieval_ids: Set[str] = set()

    def execute(
        self,
        intent_goal: str,
        evidence_package: Dict[str, Any],
        max_age_seconds: float = 60.0,
    ) -> GovernedExecutionResult:
        """Executes full verification and policy governance flow."""
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
                rejection_reasons=[f"Replay detected: retrieval_id '{retrieval_id}' already consumed"],
            )

        # Ensure evidence package is not empty in governed planning
        chunks_present = evidence_package.get("chunks") or evidence_package.get("items")
        if not chunks_present:
            return GovernedExecutionResult(
                is_authorized=False,
                rejection_reasons=["Empty evidence package: actions require non-empty verified evidence"],
            )

        # 2. Cryptographic and Freshness Verification
        verification = verify_evidence_package(evidence_package, max_age_seconds=max_age_seconds)
        if not verification.is_valid:
            return GovernedExecutionResult(
                is_authorized=False,
                verification=verification,
                rejection_reasons=[verification.error_reason or "Cryptographic verification failed"],
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
        plan = self.planner.create_plan(intent=intent_req, evidence=evidence_ref)

        # 4. Policy Evaluation
        decision = self.policy_engine.evaluate(plan)

        # 5. Token Generation or Deny Execution
        decision_type = getattr(decision, "decision_type", None) or getattr(decision, "decision", None)
        if decision_type == PolicyDecisionType.ALLOW:
            token = self.signer.sign_execution(
                plan_id=plan.plan_id,
                provenance_digest=evidence_package["provenance_digest"],
                tenant_id=evidence_package["tenant_id"],
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
