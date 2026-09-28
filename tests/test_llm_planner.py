"""Tests for LLM planner implementations.

We do not call real APIs here — we test the JSON parsing logic directly
and verify the fallback behavior when the LLM returns garbage.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from intent_fabric.models import EvidenceItemReference, EvidencePackageReference, IntentRequest
from intent_fabric.planning.llm import (
    OllamaLLMPlanner,
    OpenAILLMPlanner,
    _parse_llm_plan,
    build_planner,
)
from intent_fabric.planning.rule_based import RuleBasedPlanner


def _make_intent(request: str = "open a ticket for a payment timeout") -> IntentRequest:
    return IntentRequest(intent_id="intent-test", user_request=request)


def _make_evidence() -> EvidencePackageReference:
    return EvidencePackageReference(
        query_text="payment timeout",
        items=[
            EvidenceItemReference(
                chunk_id=1,
                document_uri="docs/runbook.md",
                snippet="Restart the payment service when it times out.",
                score=0.9,
            )
        ],
    )


def test_parse_llm_plan_valid_json() -> None:
    raw = json.dumps({
        "summary": "Create a ticket for a payment timeout incident.",
        "steps": [
            {
                "title": "Create incident ticket",
                "description": "Open a P2 ticket in the ticketing system.",
                "action_type": "ticket_create",
                "target": "ticketing-system",
                "justification": "Payment service timeout detected.",
            }
        ],
    })
    plan = _parse_llm_plan(raw, _make_intent(), _make_evidence())
    assert plan.summary == "Create a ticket for a payment timeout incident."
    assert len(plan.steps) == 1
    assert plan.steps[0].action_contract.action_type == "ticket_create"
    assert plan.steps[0].action_contract.simulated is False


def test_parse_llm_plan_invalid_json_falls_back_gracefully() -> None:
    plan = _parse_llm_plan("not json at all {{ broken", _make_intent(), _make_evidence())
    assert len(plan.steps) == 1
    assert plan.steps[0].action_contract.action_type == "analysis_review"


def test_parse_llm_plan_unknown_action_type_normalised() -> None:
    raw = json.dumps({
        "summary": "Plan",
        "steps": [{"title": "Do X", "description": "X", "action_type": "delete_everything", "target": "db", "justification": "bad"}],
    })
    plan = _parse_llm_plan(raw, _make_intent(), _make_evidence())
    assert plan.steps[0].action_contract.action_type == "analysis_review"


def test_build_planner_returns_none_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INTENT_PLANNER", raising=False)
    assert build_planner() is None


def test_build_planner_foundry(monkeypatch: pytest.MonkeyPatch) -> None:
    from intent_fabric.planning.llm import FoundryLocalLLMPlanner
    monkeypatch.setenv("INTENT_PLANNER", "foundry")
    planner = build_planner()
    assert isinstance(planner, FoundryLocalLLMPlanner)


def test_build_planner_ollama(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INTENT_PLANNER", "ollama")
    planner = build_planner()
    assert isinstance(planner, OllamaLLMPlanner)


def test_build_planner_openai_raises_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INTENT_PLANNER", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(EnvironmentError, match="OPENAI_API_KEY"):
        build_planner()


def test_build_planner_gemini_raises_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INTENT_PLANNER", "gemini")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(EnvironmentError, match="GEMINI_API_KEY"):
        build_planner()


def test_build_planner_gemini(monkeypatch: pytest.MonkeyPatch) -> None:
    from intent_fabric.planning.llm import GeminiLLMPlanner
    monkeypatch.setenv("INTENT_PLANNER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
    planner = build_planner()
    assert isinstance(planner, GeminiLLMPlanner)


def test_mcp_tools_falls_back_to_rule_based_when_no_planner_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INTENT_PLANNER", raising=False)
    from intent_fabric.mcp.tools import IntentFabricMCPTools
    tools = IntentFabricMCPTools()
    assert isinstance(tools._planner, RuleBasedPlanner)


def test_planner_registry_list_and_register() -> None:
    from intent_fabric.planning.llm import PlannerRegistry

    planners = PlannerRegistry.list_planners()
    assert "ollama" in planners
    assert "openai" in planners
    assert "gemini" in planners
    assert "foundry" in planners

    class CustomPlanner:
        def create_plan(self, intent, evidence):
            return "custom"

    PlannerRegistry.register("custom_test", lambda: CustomPlanner())
    assert PlannerRegistry.is_registered("custom_test")
    inst = PlannerRegistry.get("custom_test")
    assert isinstance(inst, CustomPlanner)

    # Test build_planner with custom registered name
    planner = build_planner("custom_test")
    assert isinstance(planner, CustomPlanner)
