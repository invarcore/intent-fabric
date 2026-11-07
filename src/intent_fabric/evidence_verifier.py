# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Evidence provenance verifier for Knowledge Fabric -> Intent Fabric contract.

Enforces RFC 8785 byte-length provenance and mandatory HMAC signing (INT-01/02).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import unicodedata
from collections.abc import Sequence

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class VerificationError(ValueError):
    """Raised when provenance signature, tenant binding, or key invariant fails."""


class EvidenceChunk(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    chunk_id: str
    ## INT-02 Fix: Harmonize Knowledge Fabric 'source_uri' with legacy 'document_uri'
    source_uri: str = Field(validation_alias=AliasChoices("source_uri", "document_uri"))
    content_hash: str


def _length_prefixed_utf8(value: str) -> str:
    """FLASH INVARIANT: Always normalize to NFC and measure UTF-8 byte length, NEVER Python str character length len(value)."""
    normalized = unicodedata.normalize("NFC", value)
    utf8_bytes = normalized.encode("utf-8")
    return f"{len(utf8_bytes)}:{normalized}"


def compute_canonical_provenance_bytes(
    tenant_id: str, chunks: Sequence[EvidenceChunk]
) -> bytes:
    """INT-01 Fix: Length-prefixed RFC 8785 canonical JSON provenance serialization."""
    if not tenant_id or not tenant_id.strip():
        raise VerificationError("Tenant ID is mandatory for provenance calculation.")
    norm_tenant = unicodedata.normalize("NFC", tenant_id.strip())
    canonical_items = [
        {
            "chunk_id": _length_prefixed_utf8(c.chunk_id),
            "content_hash": _length_prefixed_utf8(c.content_hash),
            "source_uri": _length_prefixed_utf8(c.source_uri),
        }
        for c in chunks
    ]
    payload = {
        "chunks": canonical_items,
        "tenant_id": _length_prefixed_utf8(norm_tenant),
        "v": "rfc8785-v1",
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sign_evidence_package(
    chunks: Sequence[EvidenceChunk], secret_key: str, tenant_id: str = "default"
) -> str:
    """Compute keyed HMAC-SHA256 provenance signature over canonical RFC 8785 bytes."""
    if not secret_key or not secret_key.strip():
        raise VerificationError(
            "Signing key is mandatory; unkeyed provenance fallback is forbidden."
        )
    canonical_bytes = compute_canonical_provenance_bytes(tenant_id, chunks)
    return hmac.new(
        secret_key.encode("utf-8"), canonical_bytes, hashlib.sha256
    ).hexdigest()


def verify_evidence_package(
    chunks: Sequence[EvidenceChunk],
    signature: str,
    secret_key: str,
    tenant_id: str = "default",
) -> bool:
    """Fail-closed constant-time verification of RFC 8785 provenance signature."""
    if not signature or not signature.strip():
        raise VerificationError("Provenance signature is mandatory.")
    expected_mac = sign_evidence_package(
        chunks=chunks, secret_key=secret_key, tenant_id=tenant_id
    )
    if not hmac.compare_digest(expected_mac.lower(), signature.strip().lower()):
        raise VerificationError("Provenance HMAC verification failed.")
    return True

