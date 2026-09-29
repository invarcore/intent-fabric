"""MCP-style tools for intent planning and simulation."""

from __future__ import annotations

from typing import Any

from intent_fabric.approvals import ApprovalPackageGenerator
from intent_fabric.approvals.signing import (
    SignedApprovalToken,
    TokenSigner,
    compute_approval_signature,
)
from intent_fabric.mcp.schema import MCP_SCHEMA_VERSION, envelope, unwrap_payload
from intent_fabric.policies import GovernedExecutionResult, GovernedPolicyExecutor, PolicyEngine
from intent_fabric.planning import RuleBasedPlanner, build_planner
from intent_fabric.serde import (
    parse_evidence_package_reference,
    parse_intent_request,
    parse_plan,
    parse_policy_decision,
    to_dict,
)
from intent_fabric.simulation import SimulationExecutor


class IntentFabricMCPTools:
    """Phase 2 MCP tool implementations."""

    def __init__(
        self,
        *,
        planner: RuleBasedPlanner | None = None,
        policy_engine: PolicyEngine | None = None,
        approval_generator: ApprovalPackageGenerator | None = None,
        simulator: SimulationExecutor | None = None,
        governed_executor: GovernedPolicyExecutor | None = None,
    ) -> None:
        self._planner = planner or build_planner() or RuleBasedPlanner()
        self._policy_engine = policy_engine or PolicyEngine()
        self._approval_generator = approval_generator or ApprovalPackageGenerator()
        self._simulator = simulator or SimulationExecutor()
        self._governed_executor = (
            governed_executor
            or GovernedPolicyExecutor(
                policy_engine=self._policy_engine,
                planner=self._planner,
                signer=TokenSigner(),
            )
        )


    def health_check(self) -> dict[str, Any]:
        planner_name = type(self._planner).__name__
        rules_count = getattr(self._policy_engine, "rules_count", 0)
        return envelope(
            tool="health_check",
            payload={
                "status": "healthy",
                "planner": planner_name,
                "policy_rules_count": rules_count,
                "schema_version": MCP_SCHEMA_VERSION,
            },
        )

    def create_plan_from_evidence(
        self,
        intent_request: dict[str, object],
        evidence_package: dict[str, object],
    ) -> dict[str, Any]:
        intent = parse_intent_request(intent_request)
        evidence = parse_evidence_package_reference(evidence_package)
        plan = self._planner.create_plan(intent, evidence)
        return envelope(tool="create_plan_from_evidence", payload=to_dict(plan))

    def validate_plan(self, plan: dict[str, object]) -> dict[str, Any]:
        parsed_plan = parse_plan(unwrap_payload(plan))  # type: ignore[arg-type]
        decision = self._policy_engine.evaluate(parsed_plan)
        return envelope(tool="validate_plan", payload=to_dict(decision))

    def create_approval_package(
        self,
        plan: dict[str, object],
        policy_decision: dict[str, object],
        requested_by: str = "system",
    ) -> dict[str, Any]:
        parsed_plan = parse_plan(unwrap_payload(plan))  # type: ignore[arg-type]
        parsed_decision = parse_policy_decision(unwrap_payload(policy_decision))  # type: ignore[arg-type]
        approval_request = self._approval_generator.create(
            plan=parsed_plan,
            decision=parsed_decision,
            requested_by=requested_by,
        )
        return envelope(tool="create_approval_package", payload=to_dict(approval_request))

    def simulate_plan(
        self,
        plan: dict[str, object],
        policy_decision: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        parsed_plan = parse_plan(unwrap_payload(plan))  # type: ignore[arg-type]
        if policy_decision is None:
            parsed_decision = self._policy_engine.evaluate(parsed_plan)
        else:
            parsed_decision = parse_policy_decision(unwrap_payload(policy_decision))  # type: ignore[arg-type]
        result = self._simulator.simulate(plan=parsed_plan, decision=parsed_decision)
        return envelope(tool="simulate_plan", payload=to_dict(result))

    def sign_approval(
        self,
        approval_id: str,
        plan_id: str,
        step_ids: list[str],
        decision: str = "approved",
        reviewer: str = "system",
        timestamp: str | None = None,
        secret_key: str | None = None,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "approval_id": approval_id,
            "plan_id": plan_id,
            "step_ids": step_ids,
            "decision": decision,
            "reviewer": reviewer,
        }
        if timestamp:
            kwargs["timestamp"] = timestamp
        token = SignedApprovalToken(**kwargs)
        if secret_key:
            token = SignedApprovalToken(
                approval_id=token.approval_id,
                plan_id=token.plan_id,
                step_ids=token.step_ids,
                decision=token.decision,
                reviewer=token.reviewer,
                timestamp=token.timestamp,
                signature=compute_approval_signature(
                    approval_id=token.approval_id,
                    plan_id=token.plan_id,
                    step_ids=token.step_ids,
                    decision=token.decision,
                    reviewer=token.reviewer,
                    timestamp=token.timestamp,
                    secret_key=secret_key,
                ),
            )
        return envelope(
            tool="sign_approval",
            payload={
                "approval_id": token.approval_id,
                "plan_id": token.plan_id,
                "step_ids": token.step_ids,
                "decision": token.decision,
                "reviewer": token.reviewer,
                "timestamp": token.timestamp,
                "signature": token.signature,
                "algorithm": token.algorithm,
            },
        )

    def evaluate_intent(
        self,
        intent_goal: str,
        evidence_package: dict[str, Any],
        max_age_seconds: float = 60.0,
    ) -> dict[str, Any]:
        """Evaluates an agent intent goal against cryptographically verified evidence."""
        return evaluate_governed_intent(
            executor=self._governed_executor,
            intent_goal=intent_goal,
            evidence_package=evidence_package,
            max_age_seconds=max_age_seconds,
        )


def evaluate_governed_intent(
    executor: GovernedPolicyExecutor,
    intent_goal: str,
    evidence_package: dict[str, Any],
    max_age_seconds: float = 60.0,
) -> dict[str, Any]:
    """Evaluates an agent intent goal against cryptographically verified evidence.

    Returns a deterministic dictionary response containing authorization status,
    policy decision details, and the signed execution token if authorized.
    """
    result: GovernedExecutionResult = executor.execute(
        intent_goal=intent_goal,
        evidence_package=evidence_package,
        max_age_seconds=max_age_seconds,
    )

    token_payload = None
    if result.execution_token:
        token_payload = {
            "token_str": getattr(result.execution_token, "token_str", str(result.execution_token)),
            "plan_id": getattr(result.execution_token, "plan_id", None),
            "provenance_digest": getattr(result.execution_token, "provenance_digest", None),
        }

    dec_val = "DENY"
    reason = None
    if result.decision:
        raw_dec = getattr(result.decision, "decision_type", None) or getattr(result.decision, "decision", None)
        if raw_dec is not None:
            dec_val = raw_dec.value if hasattr(raw_dec, "value") else str(raw_dec)
        reason = getattr(result.decision, "reason", None) or (
            result.decision.reasons[0] if getattr(result.decision, "reasons", None) else None
        )

    return {
        "is_authorized": result.is_authorized,
        "decision_type": dec_val,
        "reason": reason,
        "rejection_reasons": result.rejection_reasons,
        "execution_token": token_payload,
        "plan_id": result.plan.plan_id if result.plan else None,
        "verified_at": result.verification.verified_at.isoformat() if result.verification else None,
    }


