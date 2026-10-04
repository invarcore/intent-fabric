# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Simulation executor with no external side effects."""

from __future__ import annotations

from intent_fabric.models import Plan, PolicyDecision, PolicyDecisionType, SimulationResult


class SimulationExecutor:
    """Executes plans in simulation mode only."""

    def simulate(self, *, plan: Plan, decision: PolicyDecision) -> SimulationResult:
        if decision.decision is PolicyDecisionType.DENY:
            return SimulationResult(
                plan_id=plan.plan_id,
                status="denied",
                executed_steps=[],
                skipped_steps=[step.step_id for step in plan.steps],
                logs=["Simulation aborted: policy decision is deny."],
                no_external_side_effects=True,
            )

        if decision.decision is PolicyDecisionType.REQUIRES_APPROVAL:
            return SimulationResult(
                plan_id=plan.plan_id,
                status="pending_approval",
                executed_steps=[],
                skipped_steps=[step.step_id for step in plan.steps],
                logs=["Simulation paused: approval is required before execution."],
                no_external_side_effects=True,
            )

        executed: list[str] = []
        logs: list[str] = []
        for step in plan.steps:
            executed.append(step.step_id)
            logs.append(f"Simulated step {step.step_id}: {step.title}")

        return SimulationResult(
            plan_id=plan.plan_id,
            status="simulated_success",
            executed_steps=executed,
            skipped_steps=[],
            logs=logs,
            no_external_side_effects=True,
        )
