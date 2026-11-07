# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Comprehensive regression & multi-byte test suite for canonical RFC 8785 provenance."""

import pytest
from intent_fabric.evidence_verifier import (
    EvidenceChunk,
    VerificationError,
    compute_canonical_provenance_bytes,
    sign_evidence_package,
    verify_evidence_package,
)


def test_accepts_both_source_uri_and_document_uri_aliases():
    c_source = EvidenceChunk.model_validate(
        {"chunk_id": "c1", "source_uri": "s3://bucket/doc.md", "content_hash": "a" * 64}
    )
    c_doc = EvidenceChunk.model_validate(
        {"chunk_id": "c1", "document_uri": "s3://bucket/doc.md", "content_hash": "a" * 64}
    )
    assert c_source.source_uri == c_doc.source_uri == "s3://bucket/doc.md"


def test_rejects_unkeyed_or_whitespace_signing_key():
    chunk = EvidenceChunk(chunk_id="c1", source_uri="s3://b/d.md", content_hash="b" * 64)
    for bad_key in ["", "   ", None]:
        with pytest.raises(VerificationError, match="Signing key is mandatory"):
            verify_evidence_package([chunk], signature="deadbeef", secret_key=bad_key)  # type: ignore

        with pytest.raises(VerificationError, match="Signing key is mandatory"):
            sign_evidence_package([chunk], secret_key=bad_key)  # type: ignore


def test_prevents_delimiter_collision_and_handles_multibyte_utf8():
    # Multi-byte UTF-8 URI ('é' is 2 bytes in UTF-8, 1 char in Python str)
    c1 = [
        EvidenceChunk(chunk_id="1", source_uri="s3://t/caf\u00e9.md", content_hash="ab:c"),
        EvidenceChunk(chunk_id="2", source_uri="s3://t/caf\u00e9.md", content_hash="d"),
    ]
    c2 = [
        EvidenceChunk(chunk_id="1", source_uri="s3://t/caf\u00e9.md", content_hash="ab"),
        EvidenceChunk(chunk_id="2", source_uri="s3://t/caf\u00e9.md", content_hash="c:d"),
    ]
    b1 = compute_canonical_provenance_bytes("tenant_1", c1)
    b2 = compute_canonical_provenance_bytes("tenant_1", c2)
    assert b1 != b2
    # "s3://t/café.md" has 14 chars but 15 UTF-8 bytes
    assert b'"15:s3://t/caf\xc3\xa9.md"' in b1


def test_roundtrip_hmac_verification_and_tamper_rejection():
    chunks = [
        EvidenceChunk(chunk_id="c1", source_uri="s3://tenant-a/1.md", content_hash="1" * 64)
    ]
    sig = sign_evidence_package(chunks, secret_key="super-secret-key", tenant_id="tenant-a")
    assert verify_evidence_package(chunks, signature=sig, secret_key="super-secret-key", tenant_id="tenant-a") is True

    # Cross-tenant replay must fail closed
    with pytest.raises(VerificationError, match="Provenance HMAC verification failed"):
        verify_evidence_package(chunks, signature=sig, secret_key="super-secret-key", tenant_id="tenant-b")


def test_missing_or_empty_tenant_id_raises():
    chunks = [
        EvidenceChunk(chunk_id="c1", source_uri="s3://t/1.md", content_hash="1" * 64)
    ]
    for bad_tenant in ["", "   "]:
        with pytest.raises(VerificationError, match="Tenant ID is mandatory"):
            compute_canonical_provenance_bytes(bad_tenant, chunks)


def test_missing_or_empty_signature_raises():
    chunks = [
        EvidenceChunk(chunk_id="c1", source_uri="s3://t/1.md", content_hash="1" * 64)
    ]
    for bad_sig in ["", "   "]:
        with pytest.raises(VerificationError, match="Provenance signature is mandatory"):
            verify_evidence_package(chunks, signature=bad_sig, secret_key="key")


def test_producer_consumer_symmetry_with_rfc8785_payload():
    # Producer payload emitted with document_uri alias
    raw_producer_items = [
        {"chunk_id": "c1", "source_uri": "s3://tenant-x/report.md", "content_hash": "deadbeef" * 8},
        {"chunk_id": "c2", "document_uri": "s3://tenant-x/data.csv", "content_hash": "cafebabe" * 8},
    ]
    # Ingested into EvidenceChunk consumer models
    chunks = [EvidenceChunk.model_validate(item) for item in raw_producer_items]
    sig = sign_evidence_package(chunks, secret_key="shared-secret", tenant_id="tenant-x")
    assert verify_evidence_package(chunks, signature=sig, secret_key="shared-secret", tenant_id="tenant-x") is True
