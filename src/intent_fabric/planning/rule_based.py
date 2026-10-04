# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Simple rule-based planner implementation."""

from __future__ import annotations

import re
from hashlib import sha1

from intent_fabric.models import (
    ActionContract,
    EvidencePackageReference,
    IntentRequest,
    Plan,
    PlanStep,
)


class RuleBasedPlanner:
    """Creates deterministic simulated plans from intent input."""

    def create_plan(self, intent: IntentRequest, evidence: EvidencePackageReference) -> Plan:
        plan_id = _stable_id("plan", intent.intent_id)
        actions = self._resolve_actions(intent)

        steps: list[PlanStep] = []
        for index, action_name in enumerate(actions, start=1):
            step_id = _stable_id("step", f"{plan_id}:{index}:{action_name}")
            contract_id = _stable_id("contract", step_id)
            contract = ActionContract(
                contract_id=contract_id,
                action_type=_action_type(action_name),
                target="knowledge-artifact",
                intent=intent.user_request,
                simulated=True,
                parameters={"action_name": action_name, "evidence_items": len(evidence.items)},
                justification=f"Derived from intent action '{action_name}'",
            )
            steps.append(
                PlanStep(
                    step_id=step_id,
                    title=f"Simulate {action_name}",
                    description=f"Simulate action '{action_name}' using evidence-backed planning.",
                    action_contract=contract,
                    depends_on=[steps[-1].step_id] if steps else [],
                )
            )

        summary = f"Plan with {len(steps)} simulated step(s) for intent '{intent.intent_id}'."
        return Plan(
            plan_id=plan_id,
            intent_id=intent.intent_id,
            summary=summary,
            steps=steps,
            metadata={"evidence_query_text": evidence.query_text, "planner": "rule_based"},
        )

    @staticmethod
    def _resolve_actions(intent: IntentRequest) -> list[str]:
        if intent.requested_actions:
            return intent.requested_actions

        lowered = intent.user_request.lower()
        inferred = []
        if re.search(r"\b(ticket|issue)\b", lowered):
            inferred.append("ticket_create")
        if re.search(r"\b(update|document)\b", lowered):
            inferred.append("document_update")
        if re.search(r"\b(notify|notification|alert)\b", lowered):
            inferred.append("notification_send")
        if not inferred:
            inferred.append("analysis_review")
        return inferred


def _stable_id(prefix: str, seed: str) -> str:
    return f"{prefix}_{sha1(seed.encode('utf-8')).hexdigest()[:12]}"


def _action_type(action_name: str) -> str:
    normalized = action_name.strip().lower()
    if normalized in {"ticket_create", "document_update", "notification_send", "analysis_review"}:
        return normalized
    return normalized if normalized else "analysis_review"
