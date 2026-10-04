# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Cryptographic signing and verification for human-in-the-loop approvals.

Provides symmetric authentication and integrity verification to prevent approval
forgery and tampering in transit for sensitive action authorization.

Note: HMAC is a symmetric MAC scheme; it guarantees integrity and authenticity
between trusted system components, not non-repudiation against key-holders.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime


_DEFAULT_DEV_KEY = "fabric-insecure-dev-hmac-key-change-in-production"


def get_signing_key(override_key: str | None = None) -> bytes:
    """Retrieve the HMAC signing key from parameter, environment, or default.

    In production/staging environments, FABRIC_SIGNING_KEY is strictly required.
    In local development, an insecure default is permitted with a loud warning.
    """
    if override_key:
        return override_key.encode("utf-8")
    env_key = os.environ.get("FABRIC_SIGNING_KEY", "")
    if env_key:
        return env_key.encode("utf-8")
    env = os.environ.get("FABRIC_ENV", os.environ.get("ENVIRONMENT", "development")).lower()
    if env in ("production", "prod", "staging"):
        raise ValueError(
            "FABRIC_SIGNING_KEY environment variable is required in production/staging environments."
        )
    warnings.warn(
        "Using insecure default HMAC signing key. Set FABRIC_SIGNING_KEY in production.",
        UserWarning,
        stacklevel=2,
    )
    return _DEFAULT_DEV_KEY.encode("utf-8")


def canonical_approval_payload(
    *,
    approval_id: str,
    plan_id: str,
    step_ids: list[str],
    decision: str,
    reviewer: str,
    timestamp: str,
) -> bytes:
    """Create a deterministic canonical byte string representing an approval decision."""
    sorted_steps = ",".join(sorted(step_ids))
    canonical_str = f"{approval_id}|{plan_id}|{sorted_steps}|{decision.strip().lower()}|{reviewer.strip()}|{timestamp.strip()}"
    return canonical_str.encode("utf-8")


def compute_approval_signature(
    *,
    approval_id: str,
    plan_id: str,
    step_ids: list[str],
    decision: str,
    reviewer: str,
    timestamp: str,
    secret_key: str | None = None,
) -> str:
    """Compute an HMAC-SHA256 hex signature over the canonical approval decision."""
    key_bytes = get_signing_key(secret_key)
    payload_bytes = canonical_approval_payload(
        approval_id=approval_id,
        plan_id=plan_id,
        step_ids=step_ids,
        decision=decision,
        reviewer=reviewer,
        timestamp=timestamp,
    )
    return hmac.new(key_bytes, payload_bytes, hashlib.sha256).hexdigest()


def verify_approval_signature(
    *,
    approval_id: str,
    plan_id: str,
    step_ids: list[str],
    decision: str,
    reviewer: str,
    timestamp: str,
    signature: str,
    secret_key: str | None = None,
) -> bool:
    """Verify an approval signature in constant time using hmac.compare_digest."""
    if not signature or not isinstance(signature, str):
        return False
    expected = compute_approval_signature(
        approval_id=approval_id,
        plan_id=plan_id,
        step_ids=step_ids,
        decision=decision,
        reviewer=reviewer,
        timestamp=timestamp,
        secret_key=secret_key,
    )
    return hmac.compare_digest(expected, signature)


@dataclass(slots=True)
class SignedApprovalToken:
    """Tamper-evident approval record carrying a cryptographic HMAC signature."""

    approval_id: str
    plan_id: str
    step_ids: list[str]
    decision: str  # "approved" or "rejected"
    reviewer: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    signature: str = ""
    algorithm: str = "HMAC-SHA256"

    def __post_init__(self) -> None:
        if not self.signature:
            self.signature = compute_approval_signature(
                approval_id=self.approval_id,
                plan_id=self.plan_id,
                step_ids=self.step_ids,
                decision=self.decision,
                reviewer=self.reviewer,
                timestamp=self.timestamp,
            )

    def is_valid(self, secret_key: str | None = None) -> bool:
        """Return True if this token has not been tampered with and matches the secret key."""
        return verify_approval_signature(
            approval_id=self.approval_id,
            plan_id=self.plan_id,
            step_ids=self.step_ids,
            decision=self.decision,
            reviewer=self.reviewer,
            timestamp=self.timestamp,
            signature=self.signature,
            secret_key=secret_key,
        )


@dataclass(slots=True)
class SignedExecutionToken:
    """Tamper-evident token authorizing execution of a governed plan."""

    plan_id: str
    provenance_digest: str
    tenant_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    signature: str = ""
    algorithm: str = "HMAC-SHA256"
    token_str: str = ""

    def __post_init__(self) -> None:
        if not self.signature:
            key_bytes = get_signing_key()
            canonical = f"{self.plan_id}|{self.provenance_digest}|{self.tenant_id}|{self.timestamp}".encode("utf-8")
            self.signature = hmac.new(key_bytes, canonical, hashlib.sha256).hexdigest()
        if not self.token_str:
            self.token_str = f"token.{self.plan_id}.{self.signature[:16]}"


class TokenSigner:
    """Signs execution authorization tokens with HMAC-SHA256."""

    def __init__(self, secret_key: str | None = None) -> None:
        self.secret_key = secret_key

    def sign_execution(
        self,
        plan_id: str,
        provenance_digest: str,
        tenant_id: str,
    ) -> SignedExecutionToken:
        key_bytes = get_signing_key(self.secret_key)
        ts = datetime.now(UTC).isoformat()
        canonical = f"{plan_id}|{provenance_digest}|{tenant_id}|{ts}".encode("utf-8")
        sig = hmac.new(key_bytes, canonical, hashlib.sha256).hexdigest()
        token_str = f"token.{plan_id}.{sig[:16]}"
        return SignedExecutionToken(
            plan_id=plan_id,
            provenance_digest=provenance_digest,
            tenant_id=tenant_id,
            timestamp=ts,
            signature=sig,
            algorithm="HMAC-SHA256",
            token_str=token_str,
        )

    def verify_execution(self, token: SignedExecutionToken) -> bool:
        if not token or not token.signature:
            return False
        key_bytes = get_signing_key(self.secret_key)
        canonical = f"{token.plan_id}|{token.provenance_digest}|{token.tenant_id}|{token.timestamp}".encode("utf-8")
        expected = hmac.new(key_bytes, canonical, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, token.signature)

