from __future__ import annotations

from types import ModuleType
from unittest.mock import MagicMock

from intent_fabric.mcp.server import create_mcp_server
from intent_fabric.mcp.tools import IntentFabricMCPTools


class _FakeFastMCP:
    def __init__(self, name: str) -> None:
        self.name = name
        self.tool_names: list[str] = []
        self.tools: dict[str, object] = {}

    def tool(self, name: str):
        def _decorator(func):
            self.tool_names.append(name)
            self.tools[name] = func
            return func

        return _decorator

    def run(self) -> None:
        return


def test_create_mcp_server_registers_expected_tools(monkeypatch) -> None:
    fastmcp_module = ModuleType("mcp.server.fastmcp")
    fastmcp_module.FastMCP = _FakeFastMCP
    monkeypatch.setitem(__import__("sys").modules, "mcp.server.fastmcp", fastmcp_module)

    server = create_mcp_server()

    assert server.name == "intent-fabric"
    assert sorted(server.tool_names) == [
        "create_approval_package",
        "create_plan_from_evidence",
        "evaluate_intent",
        "health_check",
        "sign_approval",
        "simulate_plan",
        "validate_plan",
    ]



def test_mcp_server_tools_execute_end_to_end(monkeypatch) -> None:
    fastmcp_module = ModuleType("mcp.server.fastmcp")
    fastmcp_module.FastMCP = _FakeFastMCP
    monkeypatch.setitem(__import__("sys").modules, "mcp.server.fastmcp", fastmcp_module)

    server = create_mcp_server()
    tools = server.tools

    # 1. Health check
    hc = tools["health_check"]()
    assert hc["payload"]["status"] == "healthy"
    assert hc["payload"]["policy_rules_count"] > 0

    # 2. Create plan
    plan_envelope = tools["create_plan_from_evidence"](
        intent_request={
            "intent_id": "intent_test_1",
            "user_request": "Restart pod and notify SRE",
            "requested_actions": ["k8s_restart_pod", "notification_send"],
        },
        evidence_package={
            "query_text": "runbook for restarting pod",
            "items": [
                {
                    "chunk_id": 1,
                    "document_uri": "runbook://k8s",
                    "snippet": "Restart pod when crashed.",
                    "score": 0.95,
                }
            ],
        },
    )
    assert plan_envelope["tool"] == "create_plan_from_evidence"
    assert plan_envelope["payload"]["intent_id"] == "intent_test_1"

    # 3. Validate plan
    decision_envelope = tools["validate_plan"](plan=plan_envelope)
    assert decision_envelope["tool"] == "validate_plan"
    assert decision_envelope["payload"]["decision"] in {"allow", "requires_approval", "deny"}

    # 4. Create approval package
    approval_envelope = tools["create_approval_package"](
        plan=plan_envelope,
        policy_decision=decision_envelope,
        requested_by="ai-agent",
    )
    assert approval_envelope["tool"] == "create_approval_package"
    assert approval_envelope["payload"]["requested_by"] == "ai-agent"

    # 5. Sign approval token
    approval_id = approval_envelope["payload"]["approval_id"]
    plan_id = plan_envelope["payload"]["plan_id"]
    signed_envelope = tools["sign_approval"](
        approval_id=approval_id,
        plan_id=plan_id,
        step_ids=["step_1"],
        decision="approved",
        reviewer="secops-lead@company.com",
    )
    assert signed_envelope["tool"] == "sign_approval"
    assert signed_envelope["payload"]["signature"] != ""
    assert signed_envelope["payload"]["algorithm"] == "HMAC-SHA256"

    # 6. Simulate plan
    sim_envelope = tools["simulate_plan"](plan=plan_envelope, policy_decision=decision_envelope)
    assert sim_envelope["tool"] == "simulate_plan"
    assert sim_envelope["payload"]["no_external_side_effects"] is True

    # 7. Evaluate intent
    from datetime import datetime, timezone
    from intent_fabric.contracts.evidence_verifier import compute_chunk_hash, compute_package_digest
    uri = "docs/policy.md"
    content = "Standard access permitted"
    c_hash = compute_chunk_hash(uri, content)
    eval_res = tools["evaluate_intent"](
        intent_goal="Read non-confidential docs",
        evidence_package={
            "retrieval_id": "ret_mcp_test_1",
            "tenant_id": "tenant_1",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "chunks": [{"chunk_id": "c1", "content": content, "source_uri": uri, "provenance_hash": c_hash}],
            "provenance_digest": compute_package_digest([c_hash]),
        },
    )
    assert eval_res["is_authorized"] is True
    assert eval_res["execution_token"] is not None

