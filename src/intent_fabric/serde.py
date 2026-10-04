# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Model serialization and parsing helpers."""

from __future__ import annotations

from dataclasses import asdict

from intent_fabric.models import (
    ActionContract,
    ApprovalRequest,
    EvidenceItemReference,
    EvidencePackageReference,
    IntentRequest,
    Plan,
    PlanStep,
    PolicyDecision,
    PolicyDecisionType,
    SimulationResult,
)


def to_dict(value: object) -> dict[str, object]:
    return asdict(value)  # type: ignore[arg-type]


def parse_intent_request(payload: dict[str, object]) -> IntentRequest:
    return IntentRequest(
        intent_id=str(payload["intent_id"]),
        user_request=str(payload["user_request"]),
        requested_actions=[str(item) for item in payload.get("requested_actions", [])],  # type: ignore[arg-type]
        risk_tolerance=str(payload.get("risk_tolerance", "medium")),
        metadata=dict(payload.get("metadata", {})),  # type: ignore[arg-type]
    )


def parse_evidence_package_reference(payload: dict[str, object]) -> EvidencePackageReference:
    raw_items = payload.get("items", [])
    items = [
        EvidenceItemReference(
            chunk_id=int(item["chunk_id"]),
            document_uri=str(item.get("source_uri") or item.get("document_uri") or ""),
            snippet=str(item["snippet"]),
            score=float(item["score"]),
            metadata=dict(item.get("metadata", {})),  # type: ignore[arg-type]
            provenance_hash=str(item.get("provenance_hash", "")),
        )
        for item in raw_items  # type: ignore[assignment]
    ]
    return EvidencePackageReference(
        query_text=str(payload.get("query_text", "")),
        items=items,
        retrieval_summary=dict(payload.get("retrieval_summary", {})),  # type: ignore[arg-type]
        provenance_digest=str(payload.get("provenance_digest", "")),
        query_fingerprint=str(payload.get("query_fingerprint", "")),
        generated_at=str(payload.get("generated_at", "")),
    )


def parse_plan(payload: dict[str, object]) -> Plan:
    raw_steps = payload.get("steps", [])
    steps = []
    for step in raw_steps:  # type: ignore[assignment]
        raw_contract = step["action_contract"]
        contract = ActionContract(
            contract_id=str(raw_contract["contract_id"]),
            action_type=str(raw_contract["action_type"]),
            target=str(raw_contract["target"]),
            intent=str(raw_contract["intent"]),
            simulated=bool(raw_contract["simulated"]),
            parameters=dict(raw_contract.get("parameters", {})),  # type: ignore[arg-type]
            justification=str(raw_contract.get("justification", "")),
        )
        steps.append(
            PlanStep(
                step_id=str(step["step_id"]),
                title=str(step["title"]),
                description=str(step["description"]),
                action_contract=contract,
                depends_on=[str(item) for item in step.get("depends_on", [])],  # type: ignore[arg-type]
                metadata=dict(step.get("metadata", {})),  # type: ignore[arg-type]
            )
        )

    return Plan(
        plan_id=str(payload["plan_id"]),
        intent_id=str(payload["intent_id"]),
        summary=str(payload["summary"]),
        steps=steps,
        metadata=dict(payload.get("metadata", {})),  # type: ignore[arg-type]
    )


def parse_policy_decision(payload: dict[str, object]) -> PolicyDecision:
    return PolicyDecision(
        plan_id=str(payload["plan_id"]),
        decision=PolicyDecisionType(str(payload["decision"])),
        reasons=[str(item) for item in payload.get("reasons", [])],  # type: ignore[arg-type]
        requires_approval=bool(payload.get("requires_approval", False)),
        metadata=dict(payload.get("metadata", {})),  # type: ignore[arg-type]
    )


def parse_approval_request(payload: dict[str, object]) -> ApprovalRequest:
    return ApprovalRequest(
        approval_id=str(payload["approval_id"]),
        plan_id=str(payload["plan_id"]),
        summary=str(payload["summary"]),
        requested_by=str(payload["requested_by"]),
        step_ids=[str(item) for item in payload.get("step_ids", [])],  # type: ignore[arg-type]
        policy_reasons=[str(item) for item in payload.get("policy_reasons", [])],  # type: ignore[arg-type]
        metadata=dict(payload.get("metadata", {})),  # type: ignore[arg-type]
    )


def parse_simulation_result(payload: dict[str, object]) -> SimulationResult:
    return SimulationResult(
        plan_id=str(payload["plan_id"]),
        status=str(payload["status"]),
        executed_steps=[str(item) for item in payload.get("executed_steps", [])],  # type: ignore[arg-type]
        skipped_steps=[str(item) for item in payload.get("skipped_steps", [])],  # type: ignore[arg-type]
        logs=[str(item) for item in payload.get("logs", [])],  # type: ignore[arg-type]
        no_external_side_effects=bool(payload.get("no_external_side_effects", True)),
    )
