# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Core domain models for Intent Fabric."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class PolicyDecisionType(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRES_APPROVAL = "requires_approval"


@dataclass(slots=True)
class IntentRequest:
    intent_id: str
    user_request: str
    requested_actions: list[str] = field(default_factory=list)
    risk_tolerance: str = "medium"
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class EvidenceItemReference:
    chunk_id: int
    document_uri: str
    snippet: str
    score: float
    metadata: dict[str, object] = field(default_factory=dict)
    provenance_hash: str = ""


@dataclass(slots=True)
class EvidencePackageReference:
    query_text: str
    items: list[EvidenceItemReference] = field(default_factory=list)
    retrieval_summary: dict[str, object] = field(default_factory=dict)
    provenance_digest: str = ""
    query_fingerprint: str = ""
    generated_at: str = ""


@dataclass(slots=True)
class ActionContract:
    contract_id: str
    action_type: str
    target: str
    intent: str
    simulated: bool
    parameters: dict[str, object] = field(default_factory=dict)
    justification: str = ""


@dataclass(slots=True)
class PlanStep:
    step_id: str
    title: str
    description: str
    action_contract: ActionContract
    depends_on: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class Plan:
    plan_id: str
    intent_id: str
    summary: str
    steps: list[PlanStep] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class PolicyDecision:
    plan_id: str = ""
    decision: PolicyDecisionType = PolicyDecisionType.DENY
    reasons: list[str] = field(default_factory=list)
    requires_approval: bool = False
    metadata: dict[str, object] = field(default_factory=dict)
    decision_type: PolicyDecisionType | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.decision_type is not None:
            self.decision = self.decision_type
        else:
            self.decision_type = self.decision

        if self.reason is not None and not self.reasons:
            self.reasons = [self.reason]
        elif self.reasons and self.reason is None:
            self.reason = self.reasons[0]



@dataclass(slots=True)
class ApprovalRequest:
    approval_id: str
    plan_id: str
    summary: str
    requested_by: str
    step_ids: list[str] = field(default_factory=list)
    policy_reasons: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class SimulationResult:
    plan_id: str
    status: str
    executed_steps: list[str] = field(default_factory=list)
    skipped_steps: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    no_external_side_effects: bool = True
