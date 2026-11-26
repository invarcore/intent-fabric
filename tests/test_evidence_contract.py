"""Evidence contract verification tests for Intent Fabric.

Validates that the EvidenceVerifier correctly detects valid, tampered,
and expired evidence payloads from Knowledge Fabric.
"""

import hashlib
from datetime import UTC, datetime

from intent_fabric.contracts.evidence_verifier import (
    compute_chunk_hash,
    compute_package_digest,
    verify_evidence,
)


def _make_valid_payload(*, tenant_id: str = "test-tenant", query: str = "test query") -> dict:
    """Construct a valid evidence payload matching Knowledge Fabric output."""
    chunk_1_uri = "docs/policy.md"
    chunk_1_snippet = "MFA is required for all admin access."
    chunk_1_hash = compute_chunk_hash(chunk_1_uri, chunk_1_snippet)

    chunk_2_uri = "docs/onboarding.md"
    chunk_2_snippet = "New hires complete security training in week one."
    chunk_2_hash = compute_chunk_hash(chunk_2_uri, chunk_2_snippet)

    fingerprint = hashlib.sha256(f"{tenant_id}:{query}:hybrid".encode("utf-8")).hexdigest()

    digest = compute_package_digest([chunk_1_hash, chunk_2_hash])

    return {
        "query_text": query,
        "generated_at": datetime.now(UTC).isoformat(),
        "items": [
            {
                "chunk_id": 1,
                "document_id": 10,
                "document_uri": chunk_1_uri,
                "chunk_index": 0,
                "snippet": chunk_1_snippet,
                "score": 0.91,
                "retrieval_sources": ["lexical", "vector"],
                "metadata": {},
                "provenance_hash": chunk_1_hash,
            },
            {
                "chunk_id": 2,
                "document_id": 11,
                "document_uri": chunk_2_uri,
                "chunk_index": 0,
                "snippet": chunk_2_snippet,
                "score": 0.84,
                "retrieval_sources": ["lexical"],
                "metadata": {},
                "provenance_hash": chunk_2_hash,
            },
        ],
        "retrieval_summary": {"total_items": 2, "sources": ["lexical", "vector"]},
        "provenance_digest": digest,
        "query_fingerprint": fingerprint,
    }


def test_valid_payload_passes_verification():
    """A correctly constructed payload passes all checks."""
    result = verify_evidence(_make_valid_payload(), max_age_seconds=10.0)
    assert result.is_valid is True
    assert result.checked_chunks == 2
    assert result.failed_chunks == []
    assert result.digest_valid is True
    assert result.fingerprint_present is True


def test_tampered_chunk_content_detected():
    """Modifying a chunk's snippet invalidates its hash."""
    payload = _make_valid_payload()
    payload["items"][0]["snippet"] = "TAMPERED CONTENT"
    result = verify_evidence(payload, max_age_seconds=10.0)
    assert result.is_valid is False
    assert "1" in result.failed_chunks  # chunk_id 1


def test_tampered_chunk_hash_detected():
    """Replacing a chunk's provenance_hash is detected."""
    payload = _make_valid_payload()
    payload["items"][0]["provenance_hash"] = "a" * 64
    result = verify_evidence(payload, max_age_seconds=10.0)
    assert result.is_valid is False
    assert len(result.failed_chunks) >= 1


def test_tampered_package_digest_detected():
    """Modifying provenance_digest without changing chunks is detected."""
    payload = _make_valid_payload()
    payload["provenance_digest"] = "b" * 64
    result = verify_evidence(payload, max_age_seconds=10.0)
    assert result.is_valid is False
    assert result.digest_valid is False


def test_missing_fingerprint_detected():
    """Missing or empty query_fingerprint fails verification."""
    payload = _make_valid_payload()
    payload["query_fingerprint"] = ""
    result = verify_evidence(payload, max_age_seconds=10.0)
    assert result.is_valid is False
    assert result.fingerprint_present is False


def test_expired_evidence_detected():
    """Evidence older than max_age_seconds fails freshness check."""
    payload = _make_valid_payload()
    payload["generated_at"] = "2020-01-01T00:00:00+00:00"  # Very old
    result = verify_evidence(payload, max_age_seconds=60.0)
    assert result.is_valid is False
    assert result.freshness_valid is False


def test_empty_items_passes():
    """An empty evidence payload (no chunks) is valid if digest is empty."""
    payload = {
        "query_text": "no results query",
        "generated_at": datetime.now(UTC).isoformat(),
        "items": [],
        "retrieval_summary": {"total_items": 0},
        "provenance_digest": "",
        "query_fingerprint": "a" * 64,
    }
    result = verify_evidence(payload, max_age_seconds=10.0)
    assert result.is_valid is True
    assert result.checked_chunks == 0


def test_hash_algorithm_matches_knowledge_fabric():
    """Verify hash formula uses canonical JSON: SHA-256(json.dumps([uri, snippet]))."""
    import json

    uri = "docs/test.md"
    snippet = "test content"
    expected = hashlib.sha256(
        json.dumps([uri, snippet], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    assert compute_chunk_hash(uri, snippet) == expected
