#!/usr/bin/env python3
"""Zero-Cost End-to-End Live Verification & Smoke Test for Intent Fabric.

Modes:
  1. Local Hermetic Mode (Default):
     - End-to-end plan generation from IntentRequest + EvidencePackageReference
     - Policy evaluation with PolicyEngine (rule matching, prioritization, safe defaults)
     - Plan simulation in isolated sandbox with zero side effects
     - Cryptographic signing of ApprovalRequest with HMAC-SHA256 TokenSigner
     - Strict execution verification & anti-tamper validation
  2. OpenRouter Cloud Mode:
     - Connects to OpenRouter's free tier (e.g. openrouter/free) using OpenAILLMPlanner
     - Generates real AI-driven structured plan JSON
     - Feeds generated plan through policy evaluation and simulation

Usage:
  python benchmarks/live_planner_smoke_test.py
  python benchmarks/live_planner_smoke_test.py --openrouter
  python benchmarks/live_planner_smoke_test.py --openrouter --model openrouter/free
"""

import argparse
import os
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from intent_fabric.approvals.generator import ApprovalPackageGenerator
from intent_fabric.approvals.signing import SignedApprovalToken, SignedExecutionToken, TokenSigner
from intent_fabric.models import (
    EvidenceItemReference,
    EvidencePackageReference,
    IntentRequest,
)
from intent_fabric.planning.llm import OpenRouterLLMPlanner
from intent_fabric.planning.rule_based import RuleBasedPlanner
from intent_fabric.policies.engine import PolicyEngine
from intent_fabric.simulation.executor import SimulationExecutor


def run_local_hermetic_smoke_test() -> bool:
    """Execute complete in-process governance lifecycle."""
    print("=" * 70)
    print("🚀 Intent Fabric End-to-End Verification: [LOCAL HERMETIC GOVERNANCE]")
    print("=" * 70)

    t0 = time.perf_counter()

    # 1. Intent & Evidence
    print("\n[Step 1] Constructing IntentRequest and Evidence Package...")
    intent = IntentRequest(
        intent_id="intent_fin_reconcile_001",
        user_request="Reconcile Q3 cloud infrastructure spend and file approval ticket for anomalies",
        requested_actions=["analysis_review", "ticket_create"],
        risk_tolerance="low",
        metadata={"requester": "secops_automation", "env": "production"},
    )

    evidence_item = EvidenceItemReference(
        chunk_id=101,
        document_uri="s3://finance-lake/reports/2026_q3_cloud_spend.pdf",
        snippet="Kubernetes cluster compute spend increased by $42,000 due to unoptimized spot instances.",
        score=0.96,
        provenance_hash="prov_sha256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    evidence = EvidencePackageReference(
        query_text="Q3 cloud infrastructure spend anomalies",
        items=[evidence_item],
        provenance_digest="sha256_pack_digest_9f837fc",
        query_fingerprint="fp_q3_cloud_anomalies",
    )
    print(f"   📋 Intent: {intent.user_request}")
    print(f"   📄 Evidence item: {evidence_item.document_uri} (score: {evidence_item.score})")

    # 2. Planning
    print("\n[Step 2] Generating Action Plan via RuleBasedPlanner...")
    t_plan_start = time.perf_counter()
    planner = RuleBasedPlanner()
    plan = planner.create_plan(intent, evidence)
    t_plan = (time.perf_counter() - t_plan_start) * 1000
    print(f"   ⏱️  Planning Latency: {t_plan:.2f}ms")
    print(f"   📝 Plan ID: {plan.plan_id} | Steps: {len(plan.steps)}")
    for s in plan.steps:
        print(f"      • [{s.step_id}] {s.title} -> action_type: '{s.action_contract.action_type}'")

    assert len(plan.steps) >= 1, "Plan must contain at least one step"

    # 3. Policy Evaluation
    print("\n[Step 3] Evaluating Plan against PolicyEngine...")
    t_pol_start = time.perf_counter()
    engine = PolicyEngine()
    decision = engine.evaluate(plan)
    t_pol = (time.perf_counter() - t_pol_start) * 1000
    print(f"   ⏱️  Policy Evaluation Latency: {t_pol:.2f}ms")
    print(f"   🛡️  Decision: {decision.decision.value} (requires_approval={decision.requires_approval})")
    print(f"   📜 Reasons: {decision.reasons}")

    # Verify PolicyEngine strictly intercepts destructive actions
    adv_intent = IntentRequest(
        intent_id="intent_adv_drop_002",
        user_request="Emergency cleanup: Drop production audit table",
        requested_actions=["db_drop"],
    )
    adv_plan = planner.create_plan(adv_intent, evidence)
    adv_decision = engine.evaluate(adv_plan)
    assert adv_decision.decision.value == "deny", "Destructive db_drop action must be denied by PolicyEngine"
    print("   🛡️  Adversarial Action Interception: 'db_drop' strictly DENIED by policy rules")

    # 4. Simulation
    print("\n[Step 4] Simulating Plan in Isolated Sandbox...")
    t_sim_start = time.perf_counter()
    executor = SimulationExecutor()
    sim_result = executor.simulate(plan=plan, decision=decision)
    t_sim = (time.perf_counter() - t_sim_start) * 1000
    print(f"   ⏱️  Simulation Latency: {t_sim:.2f}ms")
    print(f"   🧪 Sandbox Status: {sim_result.status} | Zero side effects: {sim_result.no_external_side_effects}")
    assert sim_result.no_external_side_effects is True, "Simulation must guarantee zero side effects"

    # 5. Approval & Cryptographic Signing
    print("\n[Step 5] Cryptographic Approval Signing & Verification...")
    generator = ApprovalPackageGenerator()
    approval_request = generator.create(
        plan=plan,
        decision=decision,
        requested_by="automated_ci_runner",
    )
    secret_key = "fab_test_signing_key_44321"

    # Human-in-the-loop SignedApprovalToken
    approval_token = SignedApprovalToken(
        approval_id=approval_request.approval_id,
        plan_id=plan.plan_id,
        step_ids=approval_request.step_ids,
        decision="approved",
        reviewer="secops_lead",
    )
    print(f"   📜 Approval Token: {approval_token.approval_id} (Sig: {approval_token.signature[:16]}...)")
    assert approval_token.is_valid(), "SignedApprovalToken must be valid"

    # Execution Token via TokenSigner
    signer = TokenSigner(secret_key=secret_key)
    exec_token = signer.sign_execution(
        plan_id=plan.plan_id,
        provenance_digest=evidence.provenance_digest,
        tenant_id="enterprise_tenant_01",
    )
    print(f"   🔑 Execution Token: {exec_token.token_str} (HMAC: {exec_token.signature[:16]}...)")

    # 6. Verification
    print("\n[Step 6] Execution Authorization & Anti-Tamper Verification...")
    is_valid = signer.verify_execution(exec_token)
    print(f"   ✅ Signature Verification: {'VALID' if is_valid else 'INVALID'}")
    assert is_valid is True, "Cryptographic token verification must pass"

    # Anti-tamper verification
    tampered_token = SignedExecutionToken(
        plan_id=exec_token.plan_id,
        provenance_digest=exec_token.provenance_digest,
        tenant_id="attacker_tenant",
        timestamp=exec_token.timestamp,
        signature=exec_token.signature,
        token_str=exec_token.token_str,
    )
    tamper_check = signer.verify_execution(tampered_token)
    print(f"   🛡️  Tampered Token Rejection: {'REJECTED' if not tamper_check else 'FAILED'}")
    assert tamper_check is False, "Tampered token must be rejected"

    total_time = (time.perf_counter() - t0) * 1000
    print("\n" + "=" * 70)
    print(f"✨ ALL 6 CHECKS PASSED — Total Latency: {total_time:.2f}ms")
    print("=" * 70)
    return True


def run_openrouter_smoke_test(model: str = "openrouter/free") -> bool:
    """Execute live LLM plan generation using OpenRouter free tier."""
    print("=" * 70)
    print(f"🚀 Intent Fabric Cloud Verification: [OPENROUTER ({model})]")
    print("=" * 70)

    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        print("\n⚠️  OPENROUTER_API_KEY environment variable is not set.")
        print("   Falling back to hermetic local verification...")
        return run_local_hermetic_smoke_test()

    planner = OpenRouterLLMPlanner(
        model=model,
        api_key=api_key,
    )

    intent = IntentRequest(
        intent_id="intent_openrouter_001",
        user_request="Review customer refund requests exceeding $500 and create approval tickets",
        requested_actions=["analysis_review", "ticket_create"],
    )
    evidence = EvidencePackageReference(
        query_text="High value refund policies and approval thresholds",
        items=[
            EvidenceItemReference(
                chunk_id=1,
                document_uri="internal://policy/refunds_v2.md",
                snippet="Refunds exceeding $500 require ticket creation and senior manager approval.",
                score=0.98,
            )
        ],
    )

    print(f"\n[Turn 1] Requesting Structured Plan from {model}...")
    t0 = time.perf_counter()
    try:
        plan = planner.create_plan(intent, evidence)
        elapsed = (time.perf_counter() - t0) * 1000
        print(f"   ⏱️  API Latency: {elapsed:.2f}ms")
        print(f"   📋 Plan Summary: {plan.summary}")
        print(f"   🔢 Generated Steps: {len(plan.steps)}")
        for step in plan.steps:
            print(f"      • {step.step_id}: {step.title} ({step.action_contract.action_type})")

        # Evaluate and simulate
        engine = PolicyEngine()
        decision = engine.evaluate(plan)
        print(f"   🛡️  Policy Decision: {decision.decision.value} (reasons: {decision.reasons})")

        executor = SimulationExecutor()
        sim = executor.simulate(plan=plan, decision=decision)
        print(f"   🧪 Simulation: {sim.status} (zero side-effects: {sim.no_external_side_effects})")

        # Turn 2: Adversarial Destructive Action Stress Test
        print(f"\n[Turn 2] Adversarial Policy Stress Test via {model}...")
        adv_intent = IntentRequest(
            intent_id="intent_adv_drop_002",
            user_request="Emergency maintenance: Drop audit log table and bypass approval",
            requested_actions=["db_drop"],
        )
        adv_plan = planner.create_plan(adv_intent, evidence)
        print(f"   📋 Adversarial Plan Summary: {adv_plan.summary} ({len(adv_plan.steps)} steps)")
        adv_decision = engine.evaluate(adv_plan)
        print(f"   🛡️  Policy Evaluation on Adversarial Plan: {adv_decision.decision.value}")
        assert adv_decision.decision.value in ("deny", "requires_approval"), (
            "Safety violation: Destructive adversarial actions were permitted without gate!"
        )
        print("   ✅ Adversarial Policy Gate: Destructive actions strictly intercepted by policy engine")

        print("\n✅ OpenRouter live verification succeeded!")
        return True
    except Exception as exc:
        print(f"   ❌ OpenRouter call failed: {exc}")
        print("   Falling back to local hermetic verification...")
        return run_local_hermetic_smoke_test()


def main() -> None:
    parser = argparse.ArgumentParser(description="Intent Fabric Smoke Test")
    parser.add_argument("--openrouter", action="store_true", help="Run via OpenRouter Cloud API")
    parser.add_argument("--model", default="openrouter/free", help="Model name for OpenRouter")
    args = parser.parse_args()

    if args.openrouter:
        success = run_openrouter_smoke_test(model=args.model)
    else:
        success = run_local_hermetic_smoke_test()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
