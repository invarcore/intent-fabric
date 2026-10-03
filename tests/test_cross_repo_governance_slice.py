"""Cross-repo integration test demonstrating the complete ecosystem flow.

Flow:
    Knowledge Fabric (Evidence Package)
        -> Intent Fabric (Deterministic Plan grounded in citations)
        -> Intent Fabric (Policy evaluation: REQUIRES_APPROVAL)
        -> Intent Fabric (Approval Package + HMAC-SHA256 signature)
        -> Enterprise Adapters (Approved execution gate verifies token and executes)
"""

from __future__ import annotations

import sys
from pathlib import Path
import pytest

# Add enterprise-adapters to path if available locally
_adapters_path = Path(__file__).resolve().parents[2] / "knowledge-fabric-enterprise-adapters" / "src"
if _adapters_path.exists() and str(_adapters_path) not in sys.path:
    sys.path.insert(0, str(_adapters_path))

from intent_fabric.mcp.tools import IntentFabricMCPTools

try:
    from enterprise_adapters.execution import ApprovedRuntimeActionAdapter
    from enterprise_adapters.policy import (
        PolicyDecision as AdapterPolicyDecision,
        PolicyDecisionType as AdapterPolicyDecisionType,
    )
    HAS_ENTERPRISE_ADAPTERS = True
except ImportError:
    HAS_ENTERPRISE_ADAPTERS = False
    ApprovedRuntimeActionAdapter = None  # type: ignore[assignment, misc]
    AdapterPolicyDecision = None  # type: ignore[assignment, misc]
    AdapterPolicyDecisionType = None  # type: ignore[assignment, misc]


@pytest.mark.skipif(not HAS_ENTERPRISE_ADAPTERS, reason="enterprise-adapters not installed")
def test_cross_repo_governance_lifecycle_end_to_end() -> None:
    """Validate full flow across Knowledge Fabric evidence, Intent planning, and Adapter execution."""
    # 1. Evidence package retrieved from Knowledge Fabric
    kf_evidence_package = {
        "query_text": "runbook for payment pod CrashLoopBackOff",
        "items": [
            {
                "chunk_id": 1042,
                "document_uri": "runbooks://k8s-payment-pod-triage.md",
                "snippet": "If pod payment-svc enters CrashLoopBackOff due to OOM, restart deployment after memory limit increase.",
                "score": 0.96,
                "metadata": {"source_type": "markdown", "tenant_id": "tenant-acme"},
            }
        ],
        "retrieval_summary": {
            "reranker": "cross-encoder",
            "total_candidates": 10,
        },
    }

    # 2. Intent Fabric creates plan grounded in evidence citations
    intent_tools = IntentFabricMCPTools()
    plan_envelope = intent_tools.create_plan_from_evidence(
        intent_request={
            "intent_id": "intent_remediate_oom",
            "user_request": "Investigate payment service failure and restart deployment",
            "requested_actions": ["k8s_get_pods", "k8s_restart_pod"],
        },
        evidence_package=kf_evidence_package,
    )
    plan_payload = plan_envelope["payload"]
    assert plan_payload["intent_id"] == "intent_remediate_oom"
    assert len(plan_payload["steps"]) >= 1

    # 3. Intent Fabric validates plan against declarative policy rules
    decision_envelope = intent_tools.validate_plan(plan=plan_envelope)
    decision_payload = decision_envelope["payload"]
    assert decision_payload["decision"] in ("allow", "requires_approval")

    # 4. Generate human-in-the-loop approval package
    approval_envelope = intent_tools.create_approval_package(
        plan=plan_envelope,
        policy_decision=decision_envelope,
        requested_by="incident-orchestrator",
    )
    approval_payload = approval_envelope["payload"]
    approval_id = approval_payload["approval_id"]
    plan_id = plan_payload["plan_id"]
    step_ids = approval_payload["step_ids"]

    # 5. Reviewer signs approval with HMAC-SHA256 cryptographic token
    signed_envelope = intent_tools.sign_approval(
        approval_id=approval_id,
        plan_id=plan_id,
        step_ids=step_ids,
        decision="approved",
        reviewer="secops-lead@acme.com",
    )
    signed_payload = signed_envelope["payload"]
    assert signed_payload["signature"] != ""

    # 6. Enterprise execution adapter receives action + signed token and executes
    adapter = ApprovedRuntimeActionAdapter()
    adapter_decision = AdapterPolicyDecision(
        decision_id="dec_01",
        decision=AdapterPolicyDecisionType.ALLOW,
        reasons=["SecOps reviewer signed off"],
    )

    action_payload = {
        "action_name": step_ids[0] if step_ids else "k8s_restart_pod",
        "write": True,
        "approval_id": approval_id,
        "plan_id": plan_id,
        "step_ids": step_ids,
        "decision": "approved",
        "reviewer": "secops-lead@acme.com",
        "timestamp": signed_payload["timestamp"],
        "signature": signed_payload["signature"],
        "policy_decision": adapter_decision,
    }

    receipt = adapter.execute_action(action_payload)
    assert receipt["status"] == "executed"
    assert receipt["approval_id"] == approval_id

    # Verify audit event was logged
    audit_types = [getattr(e, "event_type", "") for e in adapter.audit_events()]
    assert "approval.verified" in audit_types
    assert "execution.completed" in audit_types

    # 7. Security verification: Tampered signature MUST fail
    tampered_action = dict(action_payload)
    tampered_action["signature"] = "forged_bad_signature_hex_123456"
    with pytest.raises(PermissionError, match="Cryptographic approval verification failed"):
        adapter.execute_action(tampered_action)
