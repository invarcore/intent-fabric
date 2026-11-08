# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Inter-Agent Delegation Envelope & Replay Nonce Ledger (OWASP ASI07)."""

from __future__ import annotations

import collections
import hashlib
import hmac
import json
import operator
import threading
import time
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Optional, Tuple


def nfc_normalize(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def length_prefixed_utf8(value: str) -> str:
    norm = nfc_normalize(value)
    return f"{len(norm.encode('utf-8'))}:{norm}"


def rfc8785_canonical_bytes(payload: Any) -> bytes:
    def _norm(obj: Any) -> Any:
        if isinstance(obj, str):
            return nfc_normalize(obj)
        if isinstance(obj, Mapping):
            return {nfc_normalize(str(k)): _norm(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_norm(x) for x in obj]
        return obj

    return json.dumps(
        _norm(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


class InterAgentAuthError(ValueError):
    """Raised when inter-agent envelope fails freshness, nonce, audience, or HMAC verification."""


@dataclass(frozen=True)
class InterAgentEnvelope:
    caller_agent_id: str
    target_agent_id: str
    tool_name: str
    arguments_digest: str
    session_nonce: str
    issued_at_epoch_s: float
    max_ttl_s: float
    canonical_bytes: bytes = field(repr=False)
    hmac_signature: str = ""


class ReplayNonceLedger:
    """INV-04 Guard: Bounded, thread-safe replay nonce cache with TTL eviction.

    Prevents both replay attacks and unbounded memory growth under flood attacks.
    """

    def __init__(self, max_capacity: int = 10000) -> None:
        self._max_capacity = max_capacity
        self._nonces: Dict[str, float] = {}
        self._order: Deque[Tuple[str, float]] = collections.deque()
        self._lock = threading.Lock()

    def verify_and_record(self, nonce: str, now_s: float, ttl_s: float) -> None:
        norm_nonce = nfc_normalize(nonce).strip()
        if not norm_nonce:
            raise InterAgentAuthError("INV-04 violation: session_nonce cannot be empty")
        with self._lock:
            while self._order and operator.le(self._order[0][1], now_s):
                old_key, exp = self._order.popleft()
                if self._nonces.get(old_key) == exp:
                    del self._nonces[old_key]

            if norm_nonce in self._nonces and operator.gt(self._nonces[norm_nonce], now_s):
                raise InterAgentAuthError(
                    f"INV-04 violation: replayed session_nonce '{norm_nonce}'"
                )

            while operator.ge(len(self._nonces), self._max_capacity) and self._order:
                evict_key, _ = self._order.popleft()
                self._nonces.pop(evict_key, None)

            expiry = now_s + ttl_s
            self._nonces[norm_nonce] = expiry
            self._order.append((norm_nonce, expiry))


def _validate_secret_key(secret_key: Optional[str]) -> bytes:
    if secret_key is None or nfc_normalize(secret_key).strip() == "":
        raise InterAgentAuthError("secret_key is mandatory and cannot be empty or whitespace")
    return nfc_normalize(secret_key).encode("utf-8")


def mint_inter_agent_envelope(
    caller_agent_id: str,
    target_agent_id: str,
    tool_name: str,
    arguments: Mapping[str, Any],
    session_nonce: str,
    secret_key: str,
    issued_at_epoch_s: Optional[float] = None,
    max_ttl_s: float = 60.0,
) -> InterAgentEnvelope:
    key_bytes = _validate_secret_key(secret_key)
    if operator.le(max_ttl_s, 0.0) or operator.gt(max_ttl_s, 60.0):
        raise InterAgentAuthError("INV-03 violation: max_ttl_s must be in (0, 60] seconds")
    norm_nonce = nfc_normalize(session_nonce).strip()
    if not norm_nonce:
        raise InterAgentAuthError("INV-04 violation: session_nonce cannot be empty")

    ts = round(float(issued_at_epoch_s if issued_at_epoch_s is not None else time.time()), 3)
    args_digest = hashlib.sha256(rfc8785_canonical_bytes(arguments)).hexdigest()
    payload = {
        "arguments_digest": length_prefixed_utf8(args_digest),
        "caller_agent_id": length_prefixed_utf8(caller_agent_id),
        "issued_at_epoch_s": ts,
        "max_ttl_s": round(float(max_ttl_s), 3),
        "session_nonce": length_prefixed_utf8(norm_nonce),
        "target_agent_id": length_prefixed_utf8(target_agent_id),
        "tool_name": length_prefixed_utf8(tool_name),
        "v": "intent-fabric-asi07-v1",
    }
    canon_bytes = rfc8785_canonical_bytes(payload)
    sig = hmac.new(key_bytes, canon_bytes, hashlib.sha256).hexdigest()
    return InterAgentEnvelope(
        caller_agent_id=nfc_normalize(caller_agent_id),
        target_agent_id=nfc_normalize(target_agent_id),
        tool_name=nfc_normalize(tool_name),
        arguments_digest=args_digest,
        session_nonce=norm_nonce,
        issued_at_epoch_s=ts,
        max_ttl_s=round(float(max_ttl_s), 3),
        canonical_bytes=canon_bytes,
        hmac_signature=sig,
    )


def verify_inter_agent_envelope(
    envelope: InterAgentEnvelope,
    expected_target_agent_id: str,
    expected_tool_name: str,
    arguments: Mapping[str, Any],
    secret_key: str,
    nonce_ledger: ReplayNonceLedger,
    now_epoch_s: Optional[float] = None,
    max_clock_skew_s: float = 5.0,
) -> bool:
    key_bytes = _validate_secret_key(secret_key)
    expected_mac = hmac.new(key_bytes, envelope.canonical_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac.lower(), envelope.hmac_signature.lower()):
        raise InterAgentAuthError("ASI07 violation: envelope HMAC signature verification failed")

    if envelope.target_agent_id != nfc_normalize(expected_target_agent_id):
        raise InterAgentAuthError("ASI07 violation: target_agent_id audience mismatch")
    if envelope.tool_name != nfc_normalize(expected_tool_name):
        raise InterAgentAuthError("ASI07 violation: tool_name binding mismatch")

    actual_args_digest = hashlib.sha256(rfc8785_canonical_bytes(arguments)).hexdigest()
    if not hmac.compare_digest(actual_args_digest, envelope.arguments_digest):
        raise InterAgentAuthError("ASI07 violation: arguments_digest payload tampering detected")

    now_s = float(now_epoch_s if now_epoch_s is not None else time.time())
    age_s = now_s - envelope.issued_at_epoch_s
    if operator.lt(age_s, -max_clock_skew_s):
        raise InterAgentAuthError(
            "INV-03 violation: envelope timestamp is in the future beyond clock skew"
        )
    effective_ttl = min(envelope.max_ttl_s, 60.0)
    if operator.gt(age_s, effective_ttl):
        raise InterAgentAuthError(
            f"INV-03 violation: envelope expired (age {age_s:.2f}s exceeds {effective_ttl:.2f}s)"
        )

    nonce_ledger.verify_and_record(
        envelope.session_nonce, now_s=now_s, ttl_s=effective_ttl + max_clock_skew_s
    )
    return True
