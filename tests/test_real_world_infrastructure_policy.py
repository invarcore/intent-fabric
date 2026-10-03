"""Integration tests for real-world infrastructure policies and OpenRouter planner.

Tests Kubernetes StatefulSet manifests, Terraform Aurora RDS definitions,
multi-stage 15+ action enterprise DAG plans, and OpenRouter planner integration.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from intent_fabric.models import (
    ActionContract,
    EvidenceItemReference,
    EvidencePackageReference,
    IntentRequest,
    Plan,
    PlanStep,
    PolicyDecisionType,
)
from intent_fabric.planning.llm import OpenRouterLLMPlanner, PlannerRegistry
from intent_fabric.policies.engine import PolicyEngine
from intent_fabric.simulation.executor import SimulationExecutor

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "corpora"


def test_real_world_k8s_statefulset_fixture() -> None:
    """Validate real-world Kubernetes StatefulSet fixture integrity."""
    k8s_file = FIXTURES_DIR / "k8s_production_statefulset.yaml"
    assert k8s_file.exists(), f"Missing K8s fixture: {k8s_file}"

    with open(k8s_file, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert data["kind"] == "StatefulSet"
    assert data["metadata"]["name"] == "kafka-broker-cluster"
    assert data["spec"]["replicas"] == 5

    # Verify enterprise security context
    container = data["spec"]["template"]["spec"]["containers"][0]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]

    # Verify storage volume claim template
    vct = data["spec"]["volumeClaimTemplates"][0]
    assert vct["spec"]["resources"]["requests"]["storage"] == "500Gi"


def test_real_world_terraform_aurora_fixture() -> None:
    """Validate real-world Terraform AWS Aurora cluster fixture integrity."""
    tf_file = FIXTURES_DIR / "terraform_rds_aurora.tf.json"
    assert tf_file.exists(), f"Missing Terraform fixture: {tf_file}"

    with open(tf_file, encoding="utf-8") as f:
        tf_data = json.load(f)

    cluster = tf_data["resource"]["aws_rds_cluster"]["aurora_cluster"]
    assert cluster["cluster_identifier"] == "prod-ledger-aurora-cluster"
    assert cluster["deletion_protection"] is True
    assert cluster["storage_encrypted"] is True
    assert "arn:aws:kms:" in cluster["kms_key_id"]


def test_multi_stage_16_step_enterprise_dag_policy_evaluation() -> None:
    """Test policy engine and simulation on a 16-step complex infrastructure migration DAG."""
    engine = PolicyEngine()
    sim_executor = SimulationExecutor()

    # Construct a 15-step legitimate enterprise change plan
    clean_steps: list[PlanStep] = []
    action_types = [
        ("analysis_review", "Inspect Terraform Aurora cluster state"),
        ("analysis_review", "Verify Kubernetes StatefulSet pod anti-affinity"),
        ("analysis_review", "Validate KMS customer managed key rotation"),
        ("analysis_review", "Check cross-AZ latency metrics on transit gateway"),
        ("document_update", "Update disaster recovery runbook in Confluence"),
        ("notification_send", "Notify Change Advisory Board (CAB) on Slack"),
        ("ticket_create", "Create Jira deployment ticket in PROD project"),
        ("analysis_review", "Verify database connection pool parameters"),
        ("analysis_review", "Confirm zero write lag across Aurora read replicas"),
        ("analysis_review", "Run pre-flight synthetics probe"),
        ("document_update", "Log maintenance window schedule in compliance wiki"),
        ("notification_send", "Send start-of-window notification to SecOps"),
        ("analysis_review", "Audit TLS 1.3 cipher suite negotiation on ingress"),
        ("analysis_review", "Sample consumer group lag on partition offsets"),
        ("notification_send", "Send deployment completion notice"),
    ]

    for idx, (act_type, desc) in enumerate(action_types, start=1):
        clean_steps.append(
            PlanStep(
                step_id=f"step_{idx:03d}",
                title=f"Stage {idx}: {desc}",
                description=desc,
                action_contract=ActionContract(
                    contract_id=f"contract_{idx:03d}",
                    action_type=act_type,
                    target="enterprise_infra",
                    intent="infra_migration",
                    simulated=True,
                    parameters={"stage": idx, "risk": "low"},
                    justification=f"Operational prerequisite for stage {idx}",
                ),
            )
        )

    clean_plan = Plan(
        plan_id="plan_enterprise_migration_15step",
        intent_id="intent_infra_001",
        summary="15-stage production Aurora and Kafka cluster migration",
        steps=clean_steps,
    )

    decision = engine.evaluate(clean_plan)
    assert decision.decision == PolicyDecisionType.REQUIRES_APPROVAL
    assert decision.requires_approval is True
    assert len(decision.reasons) == 15

    # Simulate execution on clean plan (pauses at pending_approval)
    sim_result = sim_executor.simulate(plan=clean_plan, decision=decision)
    assert sim_result.status == "pending_approval"
    assert len(sim_result.skipped_steps) == 15

    # Now append an adversarial 16th step: unauthorized db_drop
    adversarial_step = PlanStep(
        step_id="step_016",
        title="Stage 16: Purge obsolete database cluster",
        description="DROP DATABASE legacy_ledger",
        action_contract=ActionContract(
            contract_id="contract_016",
            action_type="db_drop",
            target="production_aurora",
            intent="drop_legacy_ledger",
            simulated=True,
            parameters={"database": "legacy_ledger"},
            justification="Reclaim storage quota",
        ),
    )
    adversarial_plan = Plan(
        plan_id="plan_adversarial_16step",
        intent_id="intent_infra_002",
        summary="Adversarial plan attempting destructive database drop",
        steps=clean_steps + [adversarial_step],
    )

    adv_decision = engine.evaluate(adversarial_plan)
    assert adv_decision.decision == PolicyDecisionType.DENY
    assert adv_decision.requires_approval is False

    adv_sim = sim_executor.simulate(plan=adversarial_plan, decision=adv_decision)
    assert adv_sim.status == "denied"
    assert "policy decision is deny" in adv_sim.logs[0]


def test_openrouter_llm_planner_missing_key_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify OpenRouterLLMPlanner raises OSError when OPENROUTER_API_KEY is unset."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(OSError, match="OPENROUTER_API_KEY"):
        OpenRouterLLMPlanner.from_env()


def test_openrouter_llm_planner_mocked_chat_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify OpenRouterLLMPlanner generates and parses plan using OpenRouter format."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-testkey1234567890abcdef")
    monkeypatch.setenv("OPENROUTER_PLAN_MODEL", "meta-llama/llama-3.1-70b-instruct")

    planner = OpenRouterLLMPlanner.from_env()
    assert planner._model == "meta-llama/llama-3.1-70b-instruct"

    mock_openrouter_response = {
        "id": "gen-12345678",
        "model": "meta-llama/llama-3.1-70b-instruct",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": json.dumps({
                        "summary": "Deploy Kafka cluster across multi-AZ topology",
                        "steps": [
                            {
                                "title": "Inspect StatefulSet configuration",
                                "description": "Review volumeClaimTemplates and security contexts",
                                "action_type": "analysis_review",
                                "target": "k8s_production_statefulset",
                                "justification": "Verify compliance with non-root security baseline",
                            },
                            {
                                "title": "Submit change ticket",
                                "description": "Create deployment record in Jira",
                                "action_type": "ticket_create",
                                "target": "jira_prod",
                                "justification": "Required audit trail for production change",
                            },
                        ],
                    }),
                }
            }
        ],
    }

    intent = IntentRequest(
        intent_id="intent_k8s_deploy",
        user_request="Deploy the Kafka StatefulSet to prod-messaging namespace",
    )
    evidence = EvidencePackageReference(
        query_text="StatefulSet kafka volumeClaimTemplates",
        items=[
            EvidenceItemReference(
                chunk_id=1,
                document_uri="k8s_production_statefulset.yaml",
                snippet="volumeClaimTemplates for Kafka broker",
                score=0.99,
            )
        ],
    )

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_openrouter_response).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        plan = planner.create_plan(intent, evidence)

        assert plan.intent_id == "intent_k8s_deploy"
        assert len(plan.steps) == 2
        assert plan.steps[0].action_contract.action_type == "analysis_review"
        assert plan.steps[1].action_contract.action_type == "ticket_create"
        assert "StatefulSet" in plan.steps[0].title


def test_planner_registry_openrouter_registration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify 'openrouter' is registered in PlannerRegistry."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-mock-key")
    assert PlannerRegistry.is_registered("openrouter")
    planner = PlannerRegistry.get("openrouter")
    assert isinstance(planner, OpenRouterLLMPlanner)
