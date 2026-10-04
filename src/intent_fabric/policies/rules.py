# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Policy rule data model for YAML-configurable policy evaluation."""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from enum import Enum


class RuleDecision(str, Enum):
    """Outcome a rule produces when it matches an action."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRES_APPROVAL = "requires_approval"


@dataclass(slots=True)
class PolicyRule:
    """A single configurable policy rule.

    Rules are matched against action_type strings using fnmatch glob patterns.
    Higher priority wins when multiple rules match the same action.

    Attributes:
        action_pattern: Glob pattern matched against action_type.
                        Examples: "ticket_*", "db_drop", "*"
        decision: Outcome when the rule matches.
        reason: Human-readable explanation included in PolicyDecision.reasons.
        priority: Rules with higher priority win over lower ones when both match.
                  Default 0. Use 100 for hard-deny rules.
        conditions: Optional key→value conditions checked against the IntentRequest
                    metadata (e.g. {"risk_tolerance": "high"}).
    """

    action_pattern: str
    decision: RuleDecision
    reason: str
    priority: int = 0
    conditions: dict[str, str] = field(default_factory=dict)

    def matches(self, action_type: str, intent_metadata: dict[str, object] | None = None) -> bool:
        """Return True if this rule applies to the given action_type and context."""
        if not fnmatch.fnmatch(action_type, self.action_pattern):
            return False
        if self.conditions and intent_metadata:
            for key, expected in self.conditions.items():
                if str(intent_metadata.get(key, "")) != expected:
                    return False
        return True


# Supports enterprise namespaced actions, e.g. "jira:ticket_create", "aws.s3:put_object", "slack:send-notification"
_DEFAULT_ACTION_SYNTAX_REGEX = re.compile(r"^[a-zA-Z0-9_.:-]{1,128}$")


def is_valid_action_syntax(action_type: str) -> bool:
    """Validate that action_type conforms to safe action naming standards.

    Supports standard and namespaced formats (e.g. 'ticket_create', 'jira:create_issue',
    'aws.s3:put_object') while preventing control character injection, path traversal,
    and null bytes.
    Can be relaxed via INTENT_STRICT_ACTION_VALIDATION=false for specialized integrations.
    """
    if not isinstance(action_type, str):
        return False
    cleaned = action_type.strip()
    if not cleaned:
        return False

    if os.environ.get("INTENT_STRICT_ACTION_VALIDATION", "true").lower() in ("false", "0", "off"):
        # Permissive check: prevent null bytes, path traversal, and unprintable characters
        return "\0" not in cleaned and ".." not in cleaned and len(cleaned) <= 256

    custom_pattern = os.environ.get("INTENT_ACTION_SYNTAX_REGEX", "")
    pattern = re.compile(custom_pattern) if custom_pattern else _DEFAULT_ACTION_SYNTAX_REGEX
    return bool(pattern.match(cleaned)) and ".." not in cleaned


@dataclass
class PolicyRuleSet:
    """An ordered collection of rules evaluated against a plan step."""

    rules: list[PolicyRule] = field(default_factory=list)

    def evaluate(
        self,
        action_type: str,
        intent_metadata: dict[str, object] | None = None,
    ) -> tuple[RuleDecision, str]:
        """Evaluate all rules against action_type and return (decision, reason).

        Matching rule with the highest priority wins.
        Falls back to REQUIRES_APPROVAL if no rule matches.
        Malformed or smuggling action types trigger immediate DENY.
        """
        # Security hardening: Normalize and validate action syntax
        normalized = (action_type or "").strip().lower()
        if not is_valid_action_syntax(normalized):
            return (
                RuleDecision.DENY,
                (
                    f"Security violation: action type '{action_type!r}' failed action syntax validation. "
                    "Action types must match ^[a-zA-Z0-9_.:-]{1,128}$ with no path traversal."
                ),
            )

        matching = [
            rule for rule in self.rules
            if rule.matches(normalized, intent_metadata)
        ]
        if not matching:
            return (
                RuleDecision.REQUIRES_APPROVAL,
                f"No policy rule matched action type '{normalized}'. Defaulting to requires_approval.",
            )
        best = max(matching, key=lambda r: r.priority)
        return best.decision, best.reason

