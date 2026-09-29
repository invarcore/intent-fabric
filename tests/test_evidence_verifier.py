"""Unit tests for Canonical Evidence Verifier & Safe Hashing (Task 1).

Validates:
1. Valid EvidencePackage verification passes cleanly.
2. Tampered chunk content fails with chunk hash mismatch error.
3. Tampered package provenance digest fails with digest mismatch error.
4. Expired timestamp fails with expiration error.
5. Missing required schema fields fail closed.
6. Future timestamp drift rejection and allowable skew tolerance.
7. Delimiter collision resistance of RFC 8785 canonical JSON hashing.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from intent_fabric.contracts.evidence_verifier import (
    compute_chunk_hash,
    compute_package_digest,
    compute_package_signature,
    verify_evidence_package,
)


def _make_valid_package(*, age_seconds: float = 0.0) -> dict[str, Any]:
    """Helper to build a valid Task 1 evidence package dictionary."""
    chunk_1_uri = "docs/iam/policy.md"
    chunk_1_content = "All production database write access requires dual-custody approval."
    chunk_1_hash = compute_chunk_hash(chunk_1_uri, chunk_1_content)

    chunk_2_uri = "docs/security/mfa.md"
    chunk_2_content = "Hardware security keys are mandatory for all administrative roles."
    chunk_2_hash = compute_chunk_hash(chunk_2_uri, chunk_2_content)

    digest = compute_package_digest([chunk_1_hash, chunk_2_hash])
    timestamp = (datetime.now(timezone.utc) - timedelta(seconds=age_seconds)).isoformat()

    return {
        "retrieval_id": "ret-7f83b10a9c2e4f1a8b3d09e5b2c7e1fa",
        "tenant_id": "tenant-enterprise-prod",
        "timestamp_utc": timestamp,
        "chunks": [
            {
                "chunk_id": "chunk-001",
                "source_uri": chunk_1_uri,
                "content": chunk_1_content,
                "provenance_hash": chunk_1_hash,
                "score": 0.942,
            },
            {
                "chunk_id": "chunk-002",
                "source_uri": chunk_2_uri,
                "content": chunk_2_content,
                "provenance_hash": chunk_2_hash,
                "score": 0.891,
            },
        ],
        "provenance_digest": digest,
    }


def test_valid_evidence_package_passes():
    """1. A correctly formed evidence package passes verification with is_valid=True."""
    package = _make_valid_package()
    result = verify_evidence_package(package, max_age_seconds=60.0)

    assert result.is_valid is True
    assert result.error_reason is None
    assert result.checked_chunks == 2
    assert result.failed_chunks == []
    assert result.digest_valid is True
    assert result.freshness_valid is True


def test_tampered_chunk_content_fails():
    """2. Tampering with chunk content causes chunk hash mismatch and is_valid=False."""
    package = _make_valid_package()
    package["chunks"][0]["content"] = "Tampered content granting unrestricted access without approval."

    result = verify_evidence_package(package, max_age_seconds=60.0)

    assert result.is_valid is False
    assert result.error_reason is not None
    assert "Chunk hash mismatch" in result.error_reason
    assert "chunk-001" in result.failed_chunks


def test_tampered_package_digest_fails():
    """3. Tampering with root package digest fails with package digest mismatch."""
    package = _make_valid_package()
    package["provenance_digest"] = "f" * 64

    result = verify_evidence_package(package, max_age_seconds=60.0)

    assert result.is_valid is False
    assert result.error_reason is not None
    assert "Package digest mismatch" in result.error_reason
    assert result.digest_valid is False


def test_expired_timestamp_fails():
    """4. Evidence older than max_age_seconds fails freshness validation."""
    package = _make_valid_package(age_seconds=120.0)

    result = verify_evidence_package(package, max_age_seconds=60.0)

    assert result.is_valid is False
    assert result.error_reason is not None
    assert "expired" in result.error_reason.lower()
    assert result.freshness_valid is False


def test_missing_required_fields_fails():
    """5. Missing required schema keys fail closed with descriptive missing field error."""
    for required_key in ["retrieval_id", "tenant_id", "timestamp_utc", "chunks", "provenance_digest"]:
        package = _make_valid_package()
        del package[required_key]

        result = verify_evidence_package(package)

        assert result.is_valid is False
        assert result.error_reason is not None
        assert f"Missing required fields: {required_key}" in result.error_reason


def test_future_timestamp_drift_fails():
    """Timestamps drifted beyond 5.0s into the future are rejected."""
    package = _make_valid_package(age_seconds=-10.0)  # 10s in future

    result = verify_evidence_package(package, max_age_seconds=60.0)

    assert result.is_valid is False
    assert result.error_reason is not None
    assert "Timestamp is set in the future" in result.error_reason


def test_future_timestamp_skew_tolerance_passes():
    """Timestamps within 5.0s clock skew window (e.g. 2.0s in future) pass."""
    package = _make_valid_package(age_seconds=-2.0)  # 2s in future

    result = verify_evidence_package(package, max_age_seconds=60.0)

    assert result.is_valid is True
    assert result.error_reason is None


def test_empty_chunks_package_passes():
    """An evidence package with empty chunks and empty digest passes."""
    now_ts = datetime.now(timezone.utc).isoformat()
    package = {
        "retrieval_id": "ret-empty",
        "tenant_id": "tenant-empty",
        "timestamp_utc": now_ts,
        "chunks": [],
        "provenance_digest": "",
    }

    result = verify_evidence_package(package, max_age_seconds=60.0)

    assert result.is_valid is True
    assert result.checked_chunks == 0
    assert result.error_reason is None


def test_canonical_json_prevents_delimiter_collision():
    """RFC 8785 JSON serialization eliminates delimiter collision attacks.

    Naive concatenation of (uri="a:b", content="c") and (uri="a", content="b:c")
    both yield "a:b:c", producing identical hashes.
    Canonical JSON serialization maps them to distinct payloads:
    ["a:b","c"] vs ["a","b:c"], yielding distinct hashes.
    """
    hash_1 = compute_chunk_hash("a:b", "c")
    hash_2 = compute_chunk_hash("a", "b:c")

    assert hash_1 != hash_2


def test_hmac_signed_package_verification_success():
    """An evidence package signed with HMAC key passes verification."""
    package = _make_valid_package()
    key = "secret-test-hmac-key"
    package["query_fingerprint"] = "fingerprint-123"
    package["package_signature"] = compute_package_signature(
        retrieval_id=package["retrieval_id"],
        tenant_id=package["tenant_id"],
        query_fingerprint=package["query_fingerprint"],
        provenance_digest=package["provenance_digest"],
        timestamp_utc=package["timestamp_utc"],
        key=key,
    )

    result = verify_evidence_package(package, hmac_key=key)
    assert result.is_valid is True
    assert result.signature_valid is True
    assert result.error_reason is None


def test_hmac_tampered_signature_fails():
    """An altered HMAC signature is rejected."""
    package = _make_valid_package()
    key = "secret-test-hmac-key"
    package["query_fingerprint"] = "fingerprint-123"
    package["package_signature"] = "deadbeef" * 8

    result = verify_evidence_package(package, hmac_key=key)
    assert result.is_valid is False
    assert result.signature_valid is False
    assert "HMAC verification failed" in (result.error_reason or "")


def test_hmac_missing_signature_when_key_configured_fails():
    """When HMAC key is enforced, missing signature fails closed."""
    package = _make_valid_package()
    key = "secret-test-hmac-key"
    # No package_signature present

    result = verify_evidence_package(package, hmac_key=key)
    assert result.is_valid is False
    assert result.signature_valid is False
    assert "Missing package_signature" in (result.error_reason or "")


def test_schema_aliases_and_whitespace_tolerance_passes():
    """Evidence verification handles document_uri/snippet/chunk_hash aliases and stripped transport whitespace."""
    package = _make_valid_package()
    # Replace keys with aliases
    for chunk in package["chunks"]:
        chunk["document_uri"] = chunk.pop("source_uri")
        chunk["snippet"] = chunk.pop("content") + "\n  "  # Trailing whitespace added during transport
        chunk["chunk_hash"] = chunk.pop("provenance_hash")

    result = verify_evidence_package(package)
    assert result.is_valid is True
    assert result.error_reason is None


