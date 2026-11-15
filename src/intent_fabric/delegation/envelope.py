from __future__ import annotations

import hashlib
import hmac
import json
import time
import unicodedata
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Mapping, MutableSet


class InterAgentAuthError(PermissionError):
    """Base error for inter-agent authentication failures."""


class NonceReplayError(InterAgentAuthError):
    """Raised when an inter-agent envelope nonce is replayed or expired."""


def _lp_utf8(value: str) -> str:
    norm = unicodedata.normalize("NFC", value)
    raw = norm.encode("utf-8")
    return f"{len(raw)}:{norm}"


def _canonical_json(payload: Mapping[str, Any]) -> str:
    norm_str = unicodedata.normalize(
        "NFC",
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
    )
    return norm_str


@dataclass(frozen=True)
class InterAgentEnvelope:
    sender_id: str
    recipient_id: str
    nonce: str
    issued_at: float
    expires_at: float
    canonical_payload: str
    signature: str

    @classmethod
    def sign(
        cls,
        sender_id: str,
        recipient_id: str,
        payload: Mapping[str, Any],
        secret_key: bytes | str,
        ttl_seconds: float = 30.0,
        now_fn: Callable[[], float] = time.time,
    ) -> InterAgentEnvelope:
        if isinstance(secret_key, str):
            secret_bytes = secret_key.strip().encode("utf-8")
        else:
            secret_bytes = secret_key.strip()
        if len(secret_bytes) < 16:
            raise InterAgentAuthError("Secret key must be at least 16 non-whitespace bytes.")
        if not sender_id or not sender_id.strip() or not recipient_id or not recipient_id.strip():
            raise InterAgentAuthError("sender_id and recipient_id are mandatory.")
        if ttl_seconds <= 0 or ttl_seconds > 60.0:
            raise InterAgentAuthError("ttl_seconds must be in (0, 60.0] per INV-03 freshness bound.")

        issued_at = float(now_fn())
        expires_at = issued_at + float(ttl_seconds)
        nonce = uuid.uuid4().hex
        canonical = _canonical_json(payload)

        signing_frame = cls._build_signing_frame(
            sender_id=sender_id.strip(),
            recipient_id=recipient_id.strip(),
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
            canonical_payload=canonical,
        )
        sig = hmac.new(secret_bytes, signing_frame, hashlib.sha256).hexdigest()
        return cls(
            sender_id=sender_id.strip(),
            recipient_id=recipient_id.strip(),
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
            canonical_payload=canonical,
            signature=sig,
        )

    @staticmethod
    def _build_signing_frame(
        sender_id: str,
        recipient_id: str,
        nonce: str,
        issued_at: float,
        expires_at: float,
        canonical_payload: str,
    ) -> bytes:
        envelope_dict = {
            "canonical_payload": _lp_utf8(canonical_payload),
            "expires_at": f"{expires_at:.6f}",
            "issued_at": f"{issued_at:.6f}",
            "nonce": _lp_utf8(nonce),
            "recipient_id": _lp_utf8(recipient_id),
            "sender_id": _lp_utf8(sender_id),
            "v": "int03-rfc8785-v1",
        }
        return json.dumps(
            envelope_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")


def verify_inter_agent_envelope(
    env: InterAgentEnvelope,
    secret_key: bytes | str,
    seen_nonces: MutableSet[str],
    expected_recipient: str | None = None,
    now_fn: Callable[[], float] = time.time,
    max_clock_skew_seconds: float = 2.0,
) -> bool:
    if isinstance(secret_key, str):
        secret_bytes = secret_key.strip().encode("utf-8")
    else:
        secret_bytes = secret_key.strip()
    if len(secret_bytes) < 16:
        raise InterAgentAuthError("Secret key must be at least 16 non-whitespace bytes.")

    now = float(now_fn())
    if env.expires_at - env.issued_at > 60.0 + max_clock_skew_seconds:
        raise NonceReplayError("Envelope TTL exceeds maximum 60s freshness window (INV-03).")
    if now > env.expires_at + max_clock_skew_seconds:
        raise NonceReplayError(f"Envelope {env.nonce} has expired.")
    if env.issued_at > now + max_clock_skew_seconds:
        raise NonceReplayError(f"Envelope {env.nonce} issued_at is in the future.")
    if env.nonce in seen_nonces:
        raise NonceReplayError(f"Envelope nonce {env.nonce} was already consumed (INV-04).")
    if expected_recipient is not None and env.recipient_id != expected_recipient.strip():
        raise InterAgentAuthError(
            f"Recipient mismatch: expected '{expected_recipient}', got '{env.recipient_id}'."
        )

    signing_frame = InterAgentEnvelope._build_signing_frame(
        sender_id=env.sender_id,
        recipient_id=env.recipient_id,
        nonce=env.nonce,
        issued_at=env.issued_at,
        expires_at=env.expires_at,
        canonical_payload=env.canonical_payload,
    )
    expected_mac = hmac.new(secret_bytes, signing_frame, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac.lower(), env.signature.strip().lower()):
        raise InterAgentAuthError("Inter-agent HMAC signature mismatch.")

    seen_nonces.add(env.nonce)
    return True
