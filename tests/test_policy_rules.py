"""Unit tests for the YAML-driven policy rule engine."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from intent_fabric.policies.rules import PolicyRule, PolicyRuleSet, RuleDecision


# ── PolicyRule.matches() ───────────────────────────────────────────────────


def test_matches_exact():
    rule = PolicyRule(action_pattern="ticket_create", decision=RuleDecision.DENY, reason="test")
    assert rule.matches("ticket_create")
    assert not rule.matches("ticket_update")


def test_matches_glob_prefix():
    rule = PolicyRule(
        action_pattern="ticket_*", decision=RuleDecision.REQUIRES_APPROVAL, reason="test"
    )
    assert rule.matches("ticket_create")
    assert rule.matches("ticket_update")
    assert not rule.matches("notification_send")


def test_matches_wildcard_catches_all():
    rule = PolicyRule(
        action_pattern="*", decision=RuleDecision.REQUIRES_APPROVAL, reason="safe default"
    )
    assert rule.matches("anything")
    assert rule.matches("db_drop")


def test_matches_with_conditions_pass():
    rule = PolicyRule(
        action_pattern="ticket_*",
        decision=RuleDecision.DENY,
        reason="high risk denied",
        conditions={"risk_tolerance": "high"},
    )
    assert rule.matches("ticket_create", intent_metadata={"risk_tolerance": "high"})


def test_matches_with_conditions_fail():
    rule = PolicyRule(
        action_pattern="ticket_*",
        decision=RuleDecision.DENY,
        reason="high risk denied",
        conditions={"risk_tolerance": "high"},
    )
    # condition doesn't match — rule should not fire
    assert not rule.matches("ticket_create", intent_metadata={"risk_tolerance": "low"})


# ── PolicyRuleSet.evaluate() ────────────────────────────────────────────────


def _ruleset_from_rules(rules: list[PolicyRule]) -> PolicyRuleSet:
    return PolicyRuleSet(rules=rules)


def test_evaluate_deny_wins_highest_priority():
    rules = [
        PolicyRule(
            action_pattern="db_drop", decision=RuleDecision.DENY, reason="hard deny", priority=100
        ),
        PolicyRule(action_pattern="*", decision=RuleDecision.ALLOW, reason="allow all", priority=0),
    ]
    rs = _ruleset_from_rules(rules)
    decision, reason = rs.evaluate("db_drop")
    assert decision == RuleDecision.DENY
    assert "hard deny" in reason


def test_evaluate_allow_when_no_deny():
    rules = [
        PolicyRule(
            action_pattern="analysis_review",
            decision=RuleDecision.ALLOW,
            reason="safe",
            priority=10,
        ),
        PolicyRule(
            action_pattern="*",
            decision=RuleDecision.REQUIRES_APPROVAL,
            reason="default",
            priority=-1,
        ),
    ]
    rs = _ruleset_from_rules(rules)
    decision, reason = rs.evaluate("analysis_review")
    assert decision == RuleDecision.ALLOW


def test_evaluate_requires_approval_default():
    rules = [
        PolicyRule(
            action_pattern="*",
            decision=RuleDecision.REQUIRES_APPROVAL,
            reason="safe default",
            priority=-1,
        ),
    ]
    rs = _ruleset_from_rules(rules)
    decision, reason = rs.evaluate("unknown_action_type")
    assert decision == RuleDecision.REQUIRES_APPROVAL


def test_evaluate_no_matching_rule_falls_back():
    rs = PolicyRuleSet(rules=[])  # empty
    decision, reason = rs.evaluate("completely_unknown")
    assert decision == RuleDecision.REQUIRES_APPROVAL
    assert "No policy rule matched" in reason


def test_evaluate_highest_priority_wins():
    rules = [
        PolicyRule(
            action_pattern="ticket_*",
            decision=RuleDecision.DENY,
            reason="deny override",
            priority=50,
        ),
        PolicyRule(
            action_pattern="ticket_*", decision=RuleDecision.ALLOW, reason="allow base", priority=5
        ),
    ]
    rs = _ruleset_from_rules(rules)
    decision, reason = rs.evaluate("ticket_create")
    assert decision == RuleDecision.DENY
    assert "deny override" in reason


# ── PolicyRuleLoader hot-reload ─────────────────────────────────────────────


def test_loader_uses_defaults_when_no_file():
    from intent_fabric.policies.loader import PolicyRuleLoader

    loader = PolicyRuleLoader(rules_path=None)
    rs = loader.get()
    # Default rules should deny db_drop
    decision, _ = rs.evaluate("db_drop")
    assert decision == RuleDecision.DENY


def test_loader_reads_yaml_file(tmp_path: Path):
    from intent_fabric.policies.loader import PolicyRuleLoader

    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        textwrap.dedent("""\
        rules:
          - action_pattern: "custom_action"
            decision: allow
            reason: "Custom action is always allowed."
            priority: 10
          - action_pattern: "*"
            decision: deny
            reason: "Everything else denied."
            priority: -1
    """)
    )
    loader = PolicyRuleLoader(rules_path=rules_file)
    rs = loader.get()
    allow_d, _ = rs.evaluate("custom_action")
    deny_d, _ = rs.evaluate("something_else")
    assert allow_d == RuleDecision.ALLOW
    assert deny_d == RuleDecision.DENY


def test_loader_hot_reloads_on_mtime_change(tmp_path: Path):
    import time
    from intent_fabric.policies.loader import PolicyRuleLoader

    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        textwrap.dedent("""\
        rules:
          - action_pattern: "*"
            decision: allow
            reason: "Allow all initially."
    """)
    )
    loader = PolicyRuleLoader(rules_path=rules_file)
    d1, _ = loader.get().evaluate("any_action")
    assert d1 == RuleDecision.ALLOW

    # Rewrite with deny-all — simulate file change
    time.sleep(0.05)  # ensure mtime changes
    rules_file.write_text(
        textwrap.dedent("""\
        rules:
          - action_pattern: "*"
            decision: deny
            reason: "Deny all after update."
            priority: 100
    """)
    )
    # Touch mtime explicitly to be safe
    rules_file.touch()

    d2, _ = loader.get().evaluate("any_action")
    assert d2 == RuleDecision.DENY
