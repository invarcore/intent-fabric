"""Unit tests for GovernedPolicyExecutor Pipeline (Task 2).

Validates:
1. ALLOW policy decision generates and emits a signed execution token.
2. Tampered evidence payload fails closed with zero tokens emitted.
3. Replay attack with previously consumed retrieval_id is rejected immediately.
4. Missing retrieval_id fails closed before verification.
5. Policy DENY decision fails closed with zero tokens emitted and rejection reason.
6. Policy REQUIRES_APPROVAL decision fails closed with zero tokens emitted.
7. Expired evidence package timestamp fails closed before plan execution.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import pytest

from intent_fabric.contracts.evidence_verifier import compute_chunk_hash, compute_package_digest
from intent_fabric.policies.consumer import GovernedPolicyExecutor
from intent_fabric.policies.engine import PolicyDecision, PolicyDecisionType


@pytest.fixture
def mock_dependencies():
    policy_engine = MagicMock()
    planner = MagicMock()
    signer = MagicMock()

    # Default plan
    plan = MagicMock()
    plan.plan_id = "plan_123"
    planner.create_plan.return_value = plan

    # Default token
    token = MagicMock()
    token.token_str = "signed_token_xyz"
    signer.sign_execution.return_value = token

    return policy_engine, planner, signer


def create_payload(retrieval_id: str = "ret_100", *, age_seconds: float = 0.0) -> dict:
    uri = "docs/policy.md"
    content = "Limit $5000"
    c_hash = compute_chunk_hash(uri, content)
    ts = (datetime.now(timezone.utc) - timedelta(seconds=age_seconds)).isoformat()
    return {
        "retrieval_id": retrieval_id,
        "tenant_id": "tenant_1",
        "timestamp_utc": ts,
        "chunks": [
            {
                "chunk_id": "c1",
                "content": content,
                "source_uri": uri,
                "provenance_hash": c_hash,
                "score": 0.95,
            }
        ],
        "provenance_digest": compute_package_digest([c_hash]),
    }


def test_allow_emits_signed_token(mock_dependencies):
    """1. ALLOW policy evaluation emits a signed execution token."""
    engine, planner, signer = mock_dependencies
    engine.evaluate.return_value = PolicyDecision(
        decision_type=PolicyDecisionType.ALLOW, reason="OK"
    )

    executor = GovernedPolicyExecutor(policy_engine=engine, planner=planner, signer=signer)
    result = executor.execute("Approve invoice", create_payload())

    assert result.is_authorized is True
    assert result.execution_token is not None
    signer.sign_execution.assert_called_once()
    assert result.verification.is_valid is True


def test_tampered_payload_fails_closed(mock_dependencies):
    """2. Tampering with evidence content causes verification failure and zero tokens emitted."""
    engine, planner, signer = mock_dependencies
    executor = GovernedPolicyExecutor(policy_engine=engine, planner=planner, signer=signer)

    payload = create_payload()
    payload["chunks"][0]["content"] = "Tampered text"

    result = executor.execute("Approve invoice", payload)
    assert result.is_authorized is False
    assert result.execution_token is None
    signer.sign_execution.assert_not_called()
    assert "Chunk hash mismatch" in result.rejection_reasons[0]


def test_replay_attack_rejected(mock_dependencies):
    """3. Replay attack with same retrieval_id is rejected on subsequent attempts."""
    engine, planner, signer = mock_dependencies
    engine.evaluate.return_value = PolicyDecision(
        decision_type=PolicyDecisionType.ALLOW, reason="OK"
    )

    executor = GovernedPolicyExecutor(policy_engine=engine, planner=planner, signer=signer)
    payload = create_payload(retrieval_id="ret_replay")

    first_run = executor.execute("Goal 1", payload)
    assert first_run.is_authorized is True

    # Replay same payload
    second_run = executor.execute("Goal 2", payload)
    assert second_run.is_authorized is False
    assert "Replay detected" in second_run.rejection_reasons[0]
    signer.sign_execution.assert_called_once()  # Only called on first run


def test_missing_retrieval_id_fails(mock_dependencies):
    """4. Evidence package missing retrieval_id fails closed immediately."""
    engine, planner, signer = mock_dependencies
    executor = GovernedPolicyExecutor(policy_engine=engine, planner=planner, signer=signer)

    payload = create_payload()
    del payload["retrieval_id"]

    result = executor.execute("Approve invoice", payload)
    assert result.is_authorized is False
    assert result.execution_token is None
    assert "Missing retrieval_id" in result.rejection_reasons[0]
    signer.sign_execution.assert_not_called()


def test_policy_deny_fails_closed(mock_dependencies):
    """5. Policy DENY decision rejects execution with zero tokens emitted."""
    engine, planner, signer = mock_dependencies
    engine.evaluate.return_value = PolicyDecision(
        decision_type=PolicyDecisionType.DENY, reason="Invoice exceeds policy threshold"
    )

    executor = GovernedPolicyExecutor(policy_engine=engine, planner=planner, signer=signer)
    result = executor.execute("Approve high-value invoice", create_payload())

    assert result.is_authorized is False
    assert result.execution_token is None
    assert "Invoice exceeds policy threshold" in result.rejection_reasons[0]
    signer.sign_execution.assert_not_called()


def test_policy_requires_approval_fails_closed(mock_dependencies):
    """6. Policy REQUIRES_APPROVAL rejects execution with zero tokens emitted."""
    engine, planner, signer = mock_dependencies
    engine.evaluate.return_value = PolicyDecision(
        decision_type=PolicyDecisionType.REQUIRES_APPROVAL,
        reason="Requires dual authorization",
    )

    executor = GovernedPolicyExecutor(policy_engine=engine, planner=planner, signer=signer)
    result = executor.execute("Transfer funds", create_payload())

    assert result.is_authorized is False
    assert result.execution_token is None
    assert "Requires dual authorization" in result.rejection_reasons[0]
    signer.sign_execution.assert_not_called()


def test_expired_timestamp_fails_closed(mock_dependencies):
    """7. Stale evidence package older than max_age_seconds is rejected."""
    engine, planner, signer = mock_dependencies
    executor = GovernedPolicyExecutor(policy_engine=engine, planner=planner, signer=signer)

    payload = create_payload(age_seconds=120.0)

    result = executor.execute("Approve invoice", payload, max_age_seconds=60.0)
    assert result.is_authorized is False
    assert result.execution_token is None
    assert "expired" in result.rejection_reasons[0].lower()
    signer.sign_execution.assert_not_called()
