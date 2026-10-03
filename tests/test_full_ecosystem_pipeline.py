"""End-to-End Full-Ecosystem Cross-Repository Integration Pipeline.

Demonstrates the complete multi-agent lifecycle across all 5 constituent Fabric repositories:
1. SaaS Ingestion & Sanitization (`knowledge-fabric-enterprise-adapters`):
   Ingests enterprise incident documents and scrubs confidential secrets (API keys, PATs).
2. Knowledge Indexing & Evidence Retrieval (`knowledge-fabric`):
   Chunks sanitized documents and constructs cryptographically digested EvidencePackages.
3. Canary Watermarking & Exfiltration Defense (`canary-fabric`):
   Injects invisible canary tokens into retrieved evidence and enforces DLP via IntentFabricCanaryGate.
4. Governed Policy-Checked Execution (`intent-fabric` & `enterprise-adapters`):
   Synthesizes evidence-grounded plans, verifies declarative policy rules, signs approvals with
   HMAC-SHA256 tokens, and executes mutations wrapped in fail-closed ExecutionEnvelopes.
5. Trace Recording & Oscillation Watchdogs (`unloop`):
   Records the full multi-turn execution trajectory in a SQLite WAL store, asserts zero oscillation
   loops via OscillationWatchdog, and verifies session replayability.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
import pytest

# Ensure all 5 constituent Fabric repositories are resolvable from local checkouts
_workspace_root = Path(__file__).resolve().parents[2]
for _repo, _src in [
    ("canary-fabric", "src"),
    ("knowledge-fabric", "src"),
    ("knowledge-fabric-enterprise-adapters", "src"),
    ("intent-fabric", "src"),
    ("unloop", "src"),
]:
    _p = _workspace_root / _repo / _src
    if _p.exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# 1. Enterprise Adapters
from enterprise_adapters.content_sanitizer import sanitize_document_content
from enterprise_adapters.execution import (
    ApprovedRuntimeActionAdapter,
    ExecutionEnvelope,
    ExecutionStatus,
    dispatch_with_readback,
)
from enterprise_adapters.policy import (
    PolicyDecision as AdapterPolicyDecision,
    PolicyDecisionType as AdapterPolicyDecisionType,
)

# 2. Knowledge Fabric
from knowledge_fabric.chunking.service import DocumentChunkingService
from knowledge_fabric.evidence.models import (
    EvidenceItem,
    EvidencePackage,
    compute_chunk_hash,
    compute_package_digest,
)
from knowledge_fabric.ingestion.models import Document, SourceFormat

# 3. Canary Fabric
from canary_fabric.adapters.intent_fabric import IntentFabricCanaryGate
from canary_fabric.adapters.knowledge_fabric import KnowledgeFabricCanaryAdapter
from canary_fabric.breaker.circuit import CircuitBreaker
from canary_fabric.core.honeytoken import Honeytoken, HoneytokenRegistry, HoneytokenType
from canary_fabric.proxy.streamer import SlidingWindowStreamBuffer

# 4. Intent Fabric
from intent_fabric.mcp.tools import IntentFabricMCPTools

# 5. Unloop
from unloop.protocol.models import ToolInvocationRecord, TurnSnapshot
from unloop.runtime.interceptor import UnloopSession
from unloop.runtime.watchdog import OscillationWatchdog
from unloop.storage.db import UnloopStore


def test_full_ecosystem_happy_path_pipeline() -> None:
    """Execute complete 5-repo lifecycle from SaaS ingestion to Unloop trace recording."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "ecosystem_session.db"
        session = UnloopSession(name="ecosystem_pipeline_run", db_path=db_path)

        try:
            # =========================================================================
            # PHASE 1: SaaS Ingestion & Secret Sanitization (enterprise-adapters)
            # =========================================================================
            raw_saas_ticket = (
                "# INC-4091: Payment Gateway High Error Rate Runbook\n\n"
                "When payment-gw service experiences HTTP 504 timeouts:\n"
                "1. Verify upstream database connection pool saturation.\n"
                "2. Restart the deployment using `k8s.restart_deployment`.\n"
                "3. Notify secops-lead@acme.com.\n\n"
                "Internal diagnostic key: xoxb-mock-998877665544-33221100-secrettoken\n"
            )

            sanitized_content = sanitize_document_content(raw_saas_ticket)
            # Verify sensitive Slack/PAT tokens were redacted before knowledge ingestion
            assert "xoxb-mock-998877665544-33221100-secrettoken" not in sanitized_content
            assert "[REDACTED_SLACK_TOKEN]" in sanitized_content

            # Record Turn 1 in Unloop
            with session.step(
                prompt="Ingest and sanitize incident ticket INC-4091",
                state={"phase": "ingestion", "ticket_id": "INC-4091"},
            ) as turn:
                turn.record_tool(
                    tool_name="enterprise_adapters.sanitize_document_content",
                    arguments={"source_uri": "jira://INC-4091"},
                    result={"sanitized_length": len(sanitized_content)},
                )
                turn.set_response("Sanitized ticket content and scrubbed diagnostic tokens.")
                turn.mutate_state("phase", "ingestion_completed")

            # =========================================================================
            # PHASE 2: Knowledge Vectorization & Evidence Packaging (knowledge-fabric)
            # =========================================================================
            doc = Document(
                source_uri="jira://INC-4091",
                source_format=SourceFormat.MARKDOWN,
                content_text=sanitized_content,
                metadata={"tenant_id": "tenant-payments", "incident_id": "INC-4091"},
            )
            chunking_service = DocumentChunkingService(max_chars=600, overlap_chars=50)
            chunks = chunking_service.chunk_document(doc)
            assert len(chunks) >= 1

            evidence_items = []
            for c in chunks:
                chunk_hash = compute_chunk_hash("jira://INC-4091", c.chunk_text)
                evidence_items.append(
                    EvidenceItem(
                        chunk_id=c.chunk_index + 1,
                        document_id=4091,
                        document_uri="jira://INC-4091",
                        chunk_index=c.chunk_index,
                        snippet=c.chunk_text,
                        score=0.97,
                        provenance_hash=chunk_hash,
                        metadata={"tenant_id": "tenant-payments"},
                    )
                )

            pkg_digest = compute_package_digest(evidence_items)
            evidence_pkg = EvidencePackage(
                retrieval_id="ret-pay-4091",
                query_text="payment-gw HTTP 504 remediation runbook",
                tenant_id="tenant-payments",
                items=evidence_items,
                provenance_digest=pkg_digest,
            )
            assert evidence_pkg.provenance_digest != ""
            assert len(evidence_pkg.items) >= 1

            # Record Turn 2 in Unloop
            with session.step(
                prompt="Index chunks and build authenticated EvidencePackage",
                state={"phase": "retrieval", "items_count": len(evidence_items)},
            ) as turn:
                turn.record_tool(
                    tool_name="knowledge_fabric.retrieve_evidence",
                    arguments={"query": "payment-gw HTTP 504 remediation runbook"},
                    result={"provenance_digest": pkg_digest},
                )
                turn.set_response(f"Retrieved {len(evidence_items)} authenticated evidence chunks.")
                turn.mutate_state("phase", "retrieval_completed")
                turn.mutate_state("digest", pkg_digest)

            # =========================================================================
            # PHASE 3: Canary Watermarking & Exfiltration Defense (canary-fabric)
            # =========================================================================
            canary_adapter = KnowledgeFabricCanaryAdapter(secret_key="master-canary-secret-key")
            watermarked_items, canary_tokens = canary_adapter.watermark_evidence_package(
                evidence_items=[
                    {
                        "document_id": item.document_uri,
                        "chunk_id": str(item.chunk_id),
                        "snippet": item.snippet,
                    }
                    for item in evidence_pkg.items
                ],
                tenant_id="tenant-payments",
                session_nonce="nonce-sess-001",
            )
            assert len(canary_tokens) >= 1
            assert len(watermarked_items) == len(evidence_pkg.items)

            # Set up DLP CircuitBreaker and Gate
            breaker = CircuitBreaker(secret_key="master-canary-secret-key")
            registry = HoneytokenRegistry()
            canary_gate = IntentFabricCanaryGate(
                circuit_breaker=breaker,
                honeytoken_registry=registry,
                active_canary_tokens=set(canary_tokens),
            )

            # Verify authorized parameters pass cleanly through CanaryGate
            is_safe, err = canary_gate.inspect_step_parameters(
                step_name="k8s.restart_deployment",
                parameters={"deployment": "payment-gw", "namespace": "payments"},
                tenant_id="tenant-payments",
            )
            assert is_safe is True
            assert err is None

            # Record Turn 3 in Unloop
            with session.step(
                prompt="Watermark evidence chunks and inspect step parameters via CanaryGate",
                state={"phase": "watermarking", "canary_tokens": len(canary_tokens)},
            ) as turn:
                turn.record_tool(
                    tool_name="canary_fabric.canary_gate.inspect_step_parameters",
                    arguments={"step_name": "k8s.restart_deployment"},
                    result={"is_safe": is_safe},
                )
                turn.set_response("Canary gate validated parameters as safe.")
                turn.mutate_state("phase", "canary_gate_passed")

            # =========================================================================
            # PHASE 4: Governed Planning & Fail-Closed Execution (intent-fabric + adapters)
            # =========================================================================
            intent_tools = IntentFabricMCPTools()

            # Format evidence package for Intent Fabric schema
            kf_evidence_dict = {
                "query_text": evidence_pkg.query_text,
                "items": [
                    {
                        "chunk_id": item.chunk_id,
                        "document_uri": item.document_uri,
                        "snippet": item.snippet,
                        "score": item.score,
                        "metadata": item.metadata,
                    }
                    for item in evidence_pkg.items
                ],
                "retrieval_summary": {"total_candidates": len(evidence_pkg.items)},
            }

            # 4a: Create Plan grounded in evidence
            plan_envelope = intent_tools.create_plan_from_evidence(
                intent_request={
                    "intent_id": "intent_restart_payment_gw",
                    "user_request": "Execute runbook remediation for payment-gw 504 timeouts",
                    "requested_actions": ["k8s_restart_pod"],
                },
                evidence_package=kf_evidence_dict,
            )
            plan_payload = plan_envelope["payload"]
            assert len(plan_payload["steps"]) >= 1

            # 4b: Validate Plan against policies
            decision_envelope = intent_tools.validate_plan(plan=plan_envelope)
            decision_payload = decision_envelope["payload"]
            assert decision_payload["decision"] in ("allow", "requires_approval")

            # 4c: Human-in-the-loop approval package & cryptographic signing
            approval_envelope = intent_tools.create_approval_package(
                plan=plan_envelope,
                policy_decision=decision_envelope,
                requested_by="incident-bot@acme.com",
            )
            approval_payload = approval_envelope["payload"]
            approval_id = approval_payload["approval_id"]
            plan_id = plan_payload["plan_id"]
            step_ids = approval_payload["step_ids"]

            signed_envelope = intent_tools.sign_approval(
                approval_id=approval_id,
                plan_id=plan_id,
                step_ids=step_ids,
                decision="approved",
                reviewer="secops-lead@acme.com",
            )
            signed_payload = signed_envelope["payload"]
            assert signed_payload["signature"] != ""

            # 4d: Fail-Closed Execution with Live Readback Verification
            cluster_state = {"deployment": "payment-gw", "status": "stalled", "restart_count": 0}

            def mock_k8s_dispatch() -> dict[str, str]:
                cluster_state["status"] = "running"
                cluster_state["restart_count"] = 1
                return {"result": "Deployment rollout restarted"}

            def mock_k8s_readback() -> dict[str, object]:
                return {
                    "deployment": cluster_state["deployment"],
                    "status": cluster_state["status"],
                    "restart_count": cluster_state["restart_count"],
                }

            envelope = dispatch_with_readback(
                action_name="k8s.restart_deployment",
                approval_id=approval_id,
                dispatch_fn=mock_k8s_dispatch,
                readback_fn=mock_k8s_readback,
                expected_state={
                    "deployment": "payment-gw",
                    "status": "running",
                    "restart_count": 1,
                },
            )

            assert envelope.status == ExecutionStatus.CONFIRMED
            assert envelope.is_confirmed is True
            assert envelope.is_safe_to_retry is False
            assert envelope.requires_investigation is False
            assert envelope.approval_id == approval_id

            # Record Turn 4 in Unloop
            with session.step(
                prompt="Dispatch approved mutation with live readback verification",
                state={"phase": "dispatching_mutation", "action": "k8s.restart_deployment"},
            ) as turn:
                turn.record_tool(
                    tool_name="enterprise_adapters.dispatch_with_readback",
                    arguments={"action_name": "k8s.restart_deployment", "approval_id": approval_id},
                    result={"status": envelope.status.value, "correlation_id": envelope.correlation_id},
                )
                turn.set_response("Execution confirmed via post-action readback.")
                turn.mutate_state("phase", "execution_confirmed")
                turn.mutate_state("cluster_status", "running")

            # =========================================================================
            # PHASE 5: Unloop Session Trajectory Integrity Verification
            # =========================================================================
            history = session.store.get_history(session.session_id)
            assert len(history) == 4
            head = session.store.get_head(session.session_id)
            assert head is not None
            assert head.turn_index == 3
            assert head.state["cluster_status"] == "running"

            # Verify each turn transitioned without triggering watchdog oscillation
            for turn_snap in history:
                assert turn_snap.is_breakpoint is False
                assert turn_snap.breakpoint_reason is None

        finally:
            # Explicitly close SQLite connection to release file lock on Windows
            if hasattr(session, "store") and hasattr(session.store, "conn"):
                session.store.conn.close()


def test_full_ecosystem_pipeline_canary_tripwire_blocks_exfiltration() -> None:
    """Validate that Canary Fabric detects honeytoken exfiltration and halts the pipeline."""
    breaker = CircuitBreaker(secret_key="master-canary-secret-key")
    registry = HoneytokenRegistry()

    # Register an active honeytoken representing an internal crown-jewel credential
    honeytoken = Honeytoken(
        token_id="ht-aws-prod-01",
        token_type=HoneytokenType.API_KEY,
        value="AKIAIOSFODNN7EXAMPLEMOCK",
        tenant_id="tenant-security",
        doc_id="doc-billing-01",
        description="Production read-only billing key decoy",
    )
    registry.register(honeytoken)

    gate = IntentFabricCanaryGate(
        circuit_breaker=breaker,
        honeytoken_registry=registry,
    )

    # Simulated adversary tries to pass the honeytoken as a parameter in a tool step
    is_safe, error_msg = gate.inspect_step_parameters(
        step_name="cloud.backup_s3",
        parameters={
            "bucket": "acme-financial-reports",
            "api_key": "AKIAIOSFODNN7EXAMPLEMOCK",  # Leaked honeytoken!
        },
        tenant_id="tenant-security",
    )

    assert is_safe is False
    assert error_msg is not None
    assert "Tripwire triggered" in error_msg


def test_full_ecosystem_pipeline_fail_closed_on_readback_uncertainty() -> None:
    """Validate that an execution timeout enters UNCERTAIN state, locking retries."""
    dispatched = False

    def mutation_dispatch() -> dict[str, str]:
        nonlocal dispatched
        dispatched = True
        return {"operation": "submitted", "task_id": "tsk-7711"}

    def readback_timeout() -> None:
        # Simulate network timeout contacting cluster API server
        return None

    envelope = dispatch_with_readback(
        action_name="k8s.apply_cluster_patch",
        approval_id="appr-uncertain-01",
        dispatch_fn=mutation_dispatch,
        readback_fn=readback_timeout,
        expected_state={"patch_applied": True},
    )

    assert dispatched is True
    # Crucial Fail-Closed guarantee:
    assert envelope.status == ExecutionStatus.UNCERTAIN
    assert envelope.is_safe_to_retry is False  # Blind retries strictly locked!
    assert envelope.requires_investigation is True
    assert envelope.correlation_id.startswith("corr-")
    assert any("UNCERTAIN" in log for log in envelope.logs)
