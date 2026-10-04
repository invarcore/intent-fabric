# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Policy engine for plan validation — YAML-driven, extensible."""

from __future__ import annotations

from intent_fabric.models import Plan, PolicyDecision, PolicyDecisionType
from intent_fabric.policies.loader import PolicyRuleLoader
from intent_fabric.policies.rules import RuleDecision


class PolicyEngine:
    """Applies configurable policy rules to a plan.

    Rules are loaded from YAML (see PolicyRuleLoader) and evaluated per action
    in the plan. The worst outcome across all steps determines the final decision:
        any DENY              → PolicyDecisionType.DENY
        any REQUIRES_APPROVAL → PolicyDecisionType.REQUIRES_APPROVAL
        all ALLOW             → PolicyDecisionType.ALLOW

    Hot-reload: the rule file is reloaded automatically when its mtime changes,
    so policy updates take effect on the next evaluate() call without a restart.

    Configuration:
        Default rules are built-in and work without any configuration.
        To customise rules, set INTENT_POLICY_RULES=/path/to/policy_rules.yaml
        See config/policy_rules.yaml for a commented reference.
    """

    def __init__(self, rules_path: str | None = None) -> None:
        self._loader = PolicyRuleLoader(rules_path=rules_path)

    def evaluate(self, plan: Plan) -> PolicyDecision:
        ruleset = self._loader.get()
        reasons: list[str] = []
        worst = RuleDecision.ALLOW

        for step in plan.steps:
            action_type = step.action_contract.action_type
            # Pass risk context from the action contract parameters for conditional rules
            intent_metadata = step.action_contract.parameters or {}
            decision, reason = ruleset.evaluate(action_type, intent_metadata)
            reasons.append(f"[{action_type}] {reason}")

            if decision == RuleDecision.DENY:
                worst = RuleDecision.DENY
                break  # DENY is absolute — no need to evaluate further steps
            if decision == RuleDecision.REQUIRES_APPROVAL:
                worst = RuleDecision.REQUIRES_APPROVAL

        decision_type = {
            RuleDecision.ALLOW: PolicyDecisionType.ALLOW,
            RuleDecision.REQUIRES_APPROVAL: PolicyDecisionType.REQUIRES_APPROVAL,
            RuleDecision.DENY: PolicyDecisionType.DENY,
        }[worst]

        return PolicyDecision(
            plan_id=plan.plan_id,
            decision=decision_type,
            reasons=reasons,
            requires_approval=(decision_type == PolicyDecisionType.REQUIRES_APPROVAL),
        )

    @property
    def rules_count(self) -> int:
        """Return the number of loaded policy rules."""
        return len(self._loader.get().rules)
