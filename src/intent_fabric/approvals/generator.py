# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Approval request generation."""

from __future__ import annotations

from hashlib import sha1

from intent_fabric.models import ApprovalRequest, Plan, PolicyDecision


class ApprovalPackageGenerator:
    """Builds approval requests for plans requiring review."""

    def create(self, *, plan: Plan, decision: PolicyDecision, requested_by: str) -> ApprovalRequest:
        approval_id = _stable_id("approval", f"{plan.plan_id}:{requested_by}")
        summary = f"Approval required for plan {plan.plan_id}: {plan.summary}"
        return ApprovalRequest(
            approval_id=approval_id,
            plan_id=plan.plan_id,
            summary=summary,
            requested_by=requested_by,
            step_ids=[step.step_id for step in plan.steps],
            policy_reasons=decision.reasons,
            metadata={"decision": decision.decision.value},
        )


def _stable_id(prefix: str, seed: str) -> str:
    return f"{prefix}_{sha1(seed.encode('utf-8')).hexdigest()[:12]}"
