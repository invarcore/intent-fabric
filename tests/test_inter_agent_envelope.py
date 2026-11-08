# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

import pytest

from intent_fabric.inter_agent_envelope import (
    InterAgentAuthError,
    InterAgentEnvelope,
    ReplayNonceLedger,
    mint_inter_agent_envelope,
    rfc8785_canonical_bytes,
    verify_inter_agent_envelope,
)


def test_inter_agent_envelope_freshness_and_replay() -> None:
    ledger = ReplayNonceLedger(max_capacity=3)
    env = mint_inter_agent_envelope(
        caller_agent_id="agent:orchestrator",
        target_agent_id="agent:db-writer",
        tool_name="execute_sql",
        arguments={"query": "SELECT 1"},
        session_nonce="nonce-001",
        secret_key="asi07-secret-key",
        issued_at_epoch_s=1000.0,
        max_ttl_s=60.0,
    )
    assert (
        verify_inter_agent_envelope(
            env,
            "agent:db-writer",
            "execute_sql",
            {"query": "SELECT 1"},
            "asi07-secret-key",
            ledger,
            now_epoch_s=1030.0,
        )
        is True
    )

    # Replay with same nonce
    with pytest.raises(InterAgentAuthError, match="replayed session_nonce"):
        verify_inter_agent_envelope(
            env,
            "agent:db-writer",
            "execute_sql",
            {"query": "SELECT 1"},
            "asi07-secret-key",
            ledger,
            now_epoch_s=1031.0,
        )

    # Expired envelope
    env2 = mint_inter_agent_envelope(
        "agent:orchestrator",
        "agent:db-writer",
        "execute_sql",
        {"query": "SELECT 1"},
        "nonce-002",
        "asi07-secret-key",
        issued_at_epoch_s=1000.0,
        max_ttl_s=60.0,
    )
    with pytest.raises(InterAgentAuthError, match="envelope expired"):
        verify_inter_agent_envelope(
            env2,
            "agent:db-writer",
            "execute_sql",
            {"query": "SELECT 1"},
            "asi07-secret-key",
            ledger,
            now_epoch_s=1061.0,
        )


def test_inter_agent_envelope_tampering_and_mismatches() -> None:
    ledger = ReplayNonceLedger(max_capacity=10)
    env = mint_inter_agent_envelope(
        caller_agent_id="agent:caller",
        target_agent_id="agent:target",
        tool_name="run_task",
        arguments={"step": 1},
        session_nonce="nonce-x",
        secret_key="secret-123",
        issued_at_epoch_s=2000.0,
    )

    # Target audience mismatch
    with pytest.raises(InterAgentAuthError, match="target_agent_id audience mismatch"):
        verify_inter_agent_envelope(
            env,
            "agent:other",
            "run_task",
            {"step": 1},
            "secret-123",
            ledger,
            now_epoch_s=2010.0,
        )

    # Tool binding mismatch
    with pytest.raises(InterAgentAuthError, match="tool_name binding mismatch"):
        verify_inter_agent_envelope(
            env,
            "agent:target",
            "different_tool",
            {"step": 1},
            "secret-123",
            ledger,
            now_epoch_s=2010.0,
        )

    # Arguments payload tampering
    with pytest.raises(InterAgentAuthError, match="arguments_digest payload tampering"):
        verify_inter_agent_envelope(
            env,
            "agent:target",
            "run_task",
            {"step": 2},
            "secret-123",
            ledger,
            now_epoch_s=2010.0,
        )

    # Wrong secret key (HMAC failure)
    with pytest.raises(InterAgentAuthError, match="HMAC signature verification failed"):
        verify_inter_agent_envelope(
            env,
            "agent:target",
            "run_task",
            {"step": 1},
            "wrong-secret",
            ledger,
            now_epoch_s=2010.0,
        )

    # Future dated beyond clock skew (now is 1990.0, issued at 2000.0, max skew 5.0)
    with pytest.raises(InterAgentAuthError, match="future beyond clock skew"):
        verify_inter_agent_envelope(
            env,
            "agent:target",
            "run_task",
            {"step": 1},
            "secret-123",
            ledger,
            now_epoch_s=1990.0,
            max_clock_skew_s=5.0,
        )


def test_minting_parameter_guards() -> None:
    with pytest.raises(InterAgentAuthError, match="INV-03 violation: max_ttl_s"):
        mint_inter_agent_envelope("a", "b", "t", {}, "n", "key", max_ttl_s=0.0)

    with pytest.raises(InterAgentAuthError, match="INV-03 violation: max_ttl_s"):
        mint_inter_agent_envelope("a", "b", "t", {}, "n", "key", max_ttl_s=60.1)

    with pytest.raises(InterAgentAuthError, match="INV-04 violation: session_nonce"):
        mint_inter_agent_envelope("a", "b", "t", {}, "   ", "key")

    with pytest.raises(InterAgentAuthError, match="secret_key is mandatory"):
        mint_inter_agent_envelope("a", "b", "t", {}, "n", "   ")


def test_nonce_ledger_capacity_eviction_and_expiry() -> None:
    ledger = ReplayNonceLedger(max_capacity=2)
    with pytest.raises(InterAgentAuthError, match="session_nonce cannot be empty"):
        ledger.verify_and_record(" ", now_s=100.0, ttl_s=10.0)

    # Record 2 nonces
    ledger.verify_and_record("n1", now_s=100.0, ttl_s=10.0)
    ledger.verify_and_record("n2", now_s=101.0, ttl_s=10.0)

    # n1 cannot be replayed at 105.0
    with pytest.raises(InterAgentAuthError, match="replayed session_nonce 'n1'"):
        ledger.verify_and_record("n1", now_s=105.0, ttl_s=10.0)

    # Pushing n3 when capacity is full with active nonces raises fail-closed rate limit
    with pytest.raises(InterAgentAuthError, match="Nonce ledger capacity exhausted"):
        ledger.verify_and_record("n3", now_s=106.0, ttl_s=10.0)

    # Advance time to 120.0 (all prior expired)
    ledger.verify_and_record("n4", now_s=120.0, ttl_s=10.0)
    # n2 should have been expired and cleared
    assert "n2" not in ledger._nonces
    assert len(ledger._nonces) == 1


def test_rfc8785_canonical_bytes_structures() -> None:
    b = rfc8785_canonical_bytes({"nested": ["a", "b"], "k": 1})
    assert b == b'{"k":1,"nested":["a","b"]}'

