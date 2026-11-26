from __future__ import annotations

from intent_fabric.models import ActionContract, Plan, PlanStep, PolicyDecision, PolicyDecisionType
from intent_fabric.simulation import SimulationExecutor


def _sample_plan() -> Plan:
    return Plan(
        plan_id="plan_x",
        intent_id="intent_x",
        summary="summary",
        steps=[
            PlanStep(
                step_id="step_1",
                title="one",
                description="one",
                action_contract=ActionContract(
                    contract_id="contract_1",
                    action_type="analysis_review",
                    target="artifact",
                    intent="intent",
                    simulated=True,
                    parameters={},
                    justification="test",
                ),
            )
        ],
    )


def test_simulation_allow() -> None:
    executor = SimulationExecutor()
    decision = PolicyDecision(plan_id="plan_x", decision=PolicyDecisionType.ALLOW)
    result = executor.simulate(plan=_sample_plan(), decision=decision)
    assert result.status == "simulated_success"
    assert result.executed_steps == ["step_1"]
    assert result.no_external_side_effects is True


def test_simulation_requires_approval() -> None:
    executor = SimulationExecutor()
    decision = PolicyDecision(
        plan_id="plan_x", decision=PolicyDecisionType.REQUIRES_APPROVAL, requires_approval=True
    )
    result = executor.simulate(plan=_sample_plan(), decision=decision)
    assert result.status == "pending_approval"
    assert result.executed_steps == []
    assert result.skipped_steps == ["step_1"]


def test_simulation_deny() -> None:
    executor = SimulationExecutor()
    decision = PolicyDecision(plan_id="plan_x", decision=PolicyDecisionType.DENY)
    result = executor.simulate(plan=_sample_plan(), decision=decision)
    assert result.status == "denied"
    assert result.executed_steps == []
    assert result.skipped_steps == ["step_1"]
