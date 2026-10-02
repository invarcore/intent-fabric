"""MCP tool tests for Intent Fabric, including evaluate_intent."""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from intent_fabric.contracts.evidence_verifier import compute_chunk_hash, compute_package_digest
from intent_fabric.mcp import IntentFabricMCPTools, MCP_SCHEMA_VERSION
from intent_fabric.mcp.server import mcp
from intent_fabric.mcp.tools import evaluate_governed_intent
from intent_fabric.policies.consumer import GovernedPolicyExecutor
from intent_fabric.policies.engine import PolicyEngine
from intent_fabric.planning.rule_based import RuleBasedPlanner
from intent_fabric.approvals.signing import TokenSigner


@pytest.fixture
def client():
    tools = IntentFabricMCPTools()

    class _Client:
        def call_tool(self, name: str, arguments: dict):
            fn = getattr(tools, name)
            return fn(**arguments)

    return _Client()


def test_mcp_tools_end_to_end() -> None:
    """Legacy MCP tools flow continues to function without regressions."""
    tools = IntentFabricMCPTools()
    plan = tools.create_plan_from_evidence(
        intent_request={
            "intent_id": "intent_1",
            "user_request": "Create a ticket and notify stakeholders",
            "requested_actions": ["ticket_create", "notification_send"],
        },
        evidence_package={
            "query_text": "incident handling",
            "items": [
                {
                    "chunk_id": 1,
                    "document_uri": "memory://doc",
                    "snippet": "Use issue tracking for incidents.",
                    "score": 0.9,
                }
            ],
        },
    )
    decision = tools.validate_plan(plan)
    approval = tools.create_approval_package(plan, decision, requested_by="user")
    simulation = tools.simulate_plan(plan, decision)

    assert plan["schema_version"] == MCP_SCHEMA_VERSION
    assert plan["payload"]["intent_id"] == "intent_1"
    assert decision["payload"]["decision"] in {"allow", "requires_approval", "deny"}
    assert approval["payload"]["plan_id"] == plan["payload"]["plan_id"]
    assert simulation["payload"]["no_external_side_effects"] is True


def test_mcp_evaluate_intent_valid_evidence(client):
    """Evaluating valid evidence through FastMCP returns is_authorized=True and signed token."""
    uri = "docs/rules.md"
    content = "Standard access permitted"
    c_hash = compute_chunk_hash(uri, content)
    payload = {
        "retrieval_id": "ret_mcp_1",
        "tenant_id": "tenant_default",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "chunks": [{"chunk_id": "c1", "content": content, "source_uri": uri, "provenance_hash": c_hash}],
        "provenance_digest": compute_package_digest([c_hash]),
    }

    result = client.call_tool(
        "evaluate_intent",
        {
            "intent_goal": "Read non-confidential docs",
            "evidence_package": payload,
        },
    )

    assert isinstance(result, dict)
    assert "is_authorized" in result
    assert "rejection_reasons" in result
    assert result["is_authorized"] is True
    assert result["execution_token"] is not None
    assert "token_str" in result["execution_token"]


def test_mcp_evaluate_intent_tampered_fails(client):
    """Tampered evidence through FastMCP returns is_authorized=False with zero token."""
    payload = {
        "retrieval_id": "ret_mcp_tampered",
        "tenant_id": "tenant_default",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "chunks": [{"chunk_id": "c1", "content": "Fake content", "source_uri": "uri", "provenance_hash": "bad_hash"}],
        "provenance_digest": "0" * 64,
    }

    result = client.call_tool(
        "evaluate_intent",
        {
            "intent_goal": "Attempt privilege escalation",
            "evidence_package": payload,
        },
    )

    assert result["is_authorized"] is False
    assert len(result["rejection_reasons"]) > 0
    assert result["execution_token"] is None


def test_mcp_evaluate_intent_replay_fails(client):
    """Replay of consumed retrieval_id through FastMCP fails closed."""
    uri = "docs/policy.md"
    content = "Read access approved"
    c_hash = compute_chunk_hash(uri, content)
    payload = {
        "retrieval_id": "ret_mcp_replay",
        "tenant_id": "tenant_default",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "chunks": [{"chunk_id": "c1", "content": content, "source_uri": uri, "provenance_hash": c_hash}],
        "provenance_digest": compute_package_digest([c_hash]),
    }

    first_res = client.call_tool(
        "evaluate_intent",
        {
            "intent_goal": "First legitimate execution",
            "evidence_package": payload,
        },
    )
    assert first_res["is_authorized"] is True

    # Replay
    second_res = client.call_tool(
        "evaluate_intent",
        {
            "intent_goal": "Replayed execution attempt",
            "evidence_package": payload,
        },
    )
    assert second_res["is_authorized"] is False
    assert any("Replay detected" in r for r in second_res["rejection_reasons"])
    assert second_res["execution_token"] is None


def test_evaluate_governed_intent_direct():
    """Direct execution of evaluate_governed_intent returns expected dictionary shape."""
    uri = "docs/guide.md"
    content = "Help guidelines"
    c_hash = compute_chunk_hash(uri, content)
    payload = {
        "retrieval_id": "ret_direct_1",
        "tenant_id": "tenant_direct",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "chunks": [{"chunk_id": "c1", "content": content, "source_uri": uri, "provenance_hash": c_hash}],
        "provenance_digest": compute_package_digest([c_hash]),
    }
    executor = GovernedPolicyExecutor(PolicyEngine(), RuleBasedPlanner(), TokenSigner())
    res = evaluate_governed_intent(executor, "Read guide", payload)

    assert res["is_authorized"] is True
    assert res["plan_id"] is not None
    assert res["verified_at"] is not None
    assert res["execution_token"]["token_str"].startswith("token.")
