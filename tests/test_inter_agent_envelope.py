import dataclasses
import pytest
from intent_fabric.delegation.envelope import (
    InterAgentAuthError,
    InterAgentEnvelope,
    NonceReplayError,
    verify_inter_agent_envelope,
)

SECRET = b"0123456789abcdef0123456789abcdef"


def test_valid_sign_and_verify_plus_replay_rejection():
    seen: set[str] = set()
    clock = [1000.0]
    env = InterAgentEnvelope.sign(
        sender_id="planner-agent",
        recipient_id="executor-agent",
        payload={"tool": "apply_patch", "path": "src/ café.py", "b": 1, "a": 2},
        secret_key=SECRET,
        ttl_seconds=30.0,
        now_fn=lambda: clock[0],
    )
    assert (
        verify_inter_agent_envelope(
            env, SECRET, seen, expected_recipient="executor-agent", now_fn=lambda: clock[0]
        )
        is True
    )

    # Second replay of identical envelope MUST fail closed (INV-04)
    with pytest.raises(NonceReplayError, match="already consumed"):
        verify_inter_agent_envelope(env, SECRET, seen, now_fn=lambda: clock[0])


def test_rejects_expired_and_oversized_ttl_envelopes():
    seen: set[str] = set()
    clock = [2000.0]
    with pytest.raises(InterAgentAuthError, match="ttl_seconds must be in"):
        InterAgentEnvelope.sign("a", "b", {"k": "v"}, SECRET, ttl_seconds=65.0)

    env = InterAgentEnvelope.sign(
        "a", "b", {"k": "v"}, SECRET, ttl_seconds=10.0, now_fn=lambda: clock[0]
    )
    clock[0] = 2015.0  # Past 10s TTL + 2s skew
    with pytest.raises(NonceReplayError, match="expired"):
        verify_inter_agent_envelope(env, SECRET, seen, now_fn=lambda: clock[0])


def test_rejects_recipient_confusion_and_payload_tampering():
    seen: set[str] = set()
    env = InterAgentEnvelope.sign("agent-a", "agent-b", {"action": "read"}, SECRET)

    with pytest.raises(InterAgentAuthError, match="Recipient mismatch"):
        verify_inter_agent_envelope(env, SECRET, seen, expected_recipient="agent-c")

    tampered = dataclasses.replace(env, canonical_payload='{"action":"drop_table"}')
    with pytest.raises(InterAgentAuthError, match="HMAC signature mismatch"):
        verify_inter_agent_envelope(tampered, SECRET, seen)


def test_string_secret_key_and_validation():
    seen: set[str] = set()
    str_secret = "0123456789abcdef0123456789abcdef"
    env = InterAgentEnvelope.sign("agent-a", "agent-b", {"ping": "pong"}, str_secret)
    assert verify_inter_agent_envelope(env, str_secret, seen) is True

    # Short secret key
    with pytest.raises(InterAgentAuthError, match="Secret key must be at least 16"):
        InterAgentEnvelope.sign("agent-a", "agent-b", {"ping": "pong"}, "short")
    with pytest.raises(InterAgentAuthError, match="Secret key must be at least 16"):
        verify_inter_agent_envelope(env, "short", seen)

    # Empty or whitespace sender/recipient
    with pytest.raises(InterAgentAuthError, match="sender_id and recipient_id are mandatory"):
        InterAgentEnvelope.sign("", "agent-b", {"ping": "pong"}, str_secret)
    with pytest.raises(InterAgentAuthError, match="sender_id and recipient_id are mandatory"):
        InterAgentEnvelope.sign("agent-a", "   ", {"ping": "pong"}, str_secret)

    # Non-positive TTL
    with pytest.raises(InterAgentAuthError, match="ttl_seconds must be in"):
        InterAgentEnvelope.sign("agent-a", "agent-b", {"ping": "pong"}, str_secret, ttl_seconds=0.0)


def test_verify_clock_skew_and_future_issued_at():
    seen: set[str] = set()
    clock = [1000.0]
    # Future issued_at
    env_future = InterAgentEnvelope(
        sender_id="a",
        recipient_id="b",
        nonce="future-nonce",
        issued_at=1010.0,
        expires_at=1040.0,
        canonical_payload="{}",
        signature="fake",
    )
    with pytest.raises(NonceReplayError, match="in the future"):
        verify_inter_agent_envelope(env_future, SECRET, seen, now_fn=lambda: clock[0])

    # Envelope TTL window > 60s + max_clock_skew_seconds (INV-03)
    env_wide = InterAgentEnvelope(
        sender_id="a",
        recipient_id="b",
        nonce="wide-nonce",
        issued_at=1000.0,
        expires_at=1070.0,
        canonical_payload="{}",
        signature="fake",
    )
    with pytest.raises(NonceReplayError, match="Envelope TTL exceeds maximum 60s"):
        verify_inter_agent_envelope(env_wide, SECRET, seen, now_fn=lambda: clock[0])
