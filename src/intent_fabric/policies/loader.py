# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""YAML-driven policy rule loader with hot-reload support."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import yaml

from intent_fabric.policies.rules import PolicyRule, PolicyRuleSet, RuleDecision

# Default rules shipped with the package — sufficient for most deployments.
# Override by setting INTENT_POLICY_RULES=/path/to/your/policy_rules.yaml
_DEFAULT_RULES: list[dict[str, Any]] = [
    {
        "action_pattern": "db_drop",
        "decision": "deny",
        "reason": "Destructive database operations are never permitted.",
        "priority": 100,
    },
    {
        "action_pattern": "external_write",
        "decision": "deny",
        "reason": "Writes to external systems outside simulation boundary are denied.",
        "priority": 100,
    },
    {
        "action_pattern": "runtime_connector",
        "decision": "deny",
        "reason": "Direct runtime connector access is outside simulation boundary.",
        "priority": 100,
    },
    {
        "action_pattern": "ticket_*",
        "decision": "requires_approval",
        "reason": "Ticket creation requires human review before execution.",
    },
    {
        "action_pattern": "notification_send",
        "decision": "requires_approval",
        "reason": "Notifications to users require human review.",
    },
    {
        "action_pattern": "document_update",
        "decision": "requires_approval",
        "reason": "Document changes require human review.",
    },
    {
        "action_pattern": "analysis_review",
        "decision": "allow",
        "reason": "Read-only analysis is permitted without approval.",
    },
    {
        "action_pattern": "*",
        "decision": "requires_approval",
        "reason": "Unknown action type defaults to requires_approval (safe default).",
        "priority": -1,
    },
]

_DECISION_MAP: dict[str, RuleDecision] = {
    "allow": RuleDecision.ALLOW,
    "deny": RuleDecision.DENY,
    "requires_approval": RuleDecision.REQUIRES_APPROVAL,
}


def _parse_rules(raw_rules: list[dict[str, Any]]) -> list[PolicyRule]:
    rules: list[PolicyRule] = []
    for raw in raw_rules:
        decision_str = str(raw.get("decision", "requires_approval")).lower()
        decision = _DECISION_MAP.get(decision_str, RuleDecision.REQUIRES_APPROVAL)
        rules.append(
            PolicyRule(
                action_pattern=str(raw["action_pattern"]),
                decision=decision,
                reason=str(raw.get("reason", "")),
                priority=int(raw.get("priority", 0)),
                conditions=dict(raw.get("conditions", {})),
            )
        )
    # Sort by priority descending so evaluate() can short-circuit on first hit
    rules.sort(key=lambda r: r.priority, reverse=True)
    return rules


class PolicyRuleLoader:
    """Loads PolicyRuleSet from YAML with optional hot-reload.

    The rules file path is resolved from (in order):
        1. Path passed to the constructor
        2. INTENT_POLICY_RULES environment variable
        3. Built-in default rules (no file required)

    Hot-reload: the loader checks the file's mtime on each call to get().
    If the file changed, it reloads automatically — no server restart needed.
    """

    def __init__(self, rules_path: str | Path | None = None) -> None:
        env_path = os.environ.get("INTENT_POLICY_RULES", "")
        if rules_path is not None:
            self._path: Path | None = Path(rules_path)
        elif env_path:
            self._path = Path(env_path)
        else:
            self._path = None

        self._ruleset: PolicyRuleSet | None = None
        self._last_mtime: float = 0.0
        self._load()

    def get(self) -> PolicyRuleSet:
        """Return the current PolicyRuleSet, reloading from disk if modified."""
        if self._path is not None and self._path.exists():
            try:
                mtime = self._path.stat().st_mtime
                if mtime != self._last_mtime:
                    self._load()
            except OSError:
                pass  # keep the last-loaded ruleset on stat failure
        assert self._ruleset is not None
        return self._ruleset

    def _load(self) -> None:
        if self._path is not None and self._path.exists():
            try:
                raw = yaml.safe_load(self._path.read_text(encoding="utf-8"))
                raw_rules = raw.get("rules", []) if isinstance(raw, dict) else []
                rules = _parse_rules(raw_rules)
                self._ruleset = PolicyRuleSet(rules=rules)
                self._last_mtime = self._path.stat().st_mtime
                return
            except Exception:
                pass  # fall through to defaults on any parse error

        # Use built-in defaults
        self._ruleset = PolicyRuleSet(rules=_parse_rules(_DEFAULT_RULES))
        self._last_mtime = time.monotonic()
