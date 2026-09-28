"""Evidence provenance verifier for Knowledge Fabric → Intent Fabric contract.

Re-computes SHA-256 hashes independently using RFC 8785 canonical JSON serialization
and compares them against values reported by Knowledge Fabric to detect tampering,
corruption, delimiter collisions, or replay of stale evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class VerificationResult:
    """Outcome of evidence provenance verification."""

    is_valid: bool
    error_reason: str | None = None
    verified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Diagnostic & backward compatibility fields
    checked_chunks: int = 0
    failed_chunks: list[str] = field(default_factory=list)
    digest_valid: bool = True
    fingerprint_present: bool = True
    freshness_valid: bool = True
    signature_valid: bool = True
    errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.error_reason and not self.errors:
            self.errors = [self.error_reason]
        elif self.errors and not self.error_reason:
            self.error_reason = "; ".join(self.errors)


def compute_chunk_hash(source_uri: str, content: str) -> str:
    """Compute deterministic SHA-256 hash using RFC 8785 canonical JSON serialization.

    Formula: SHA-256(json.dumps([source_uri, content], separators=(',', ':'), ensure_ascii=False))
    Eliminates delimiter collision attacks present in naive string concatenation.
    """
    canonical_payload = json.dumps(
        [source_uri, content],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical_payload).hexdigest()


def compute_package_digest(chunk_hashes: list[str]) -> str:
    """Compute composite SHA-256 digest over ordered chunk hashes.

    Formula: SHA-256(hash_1 + ":" + hash_2 + ":" + ... + hash_N)
    Returns empty string if chunk_hashes list is empty.
    """
    if not chunk_hashes:
        return ""
    combined = ":".join(chunk_hashes).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def compute_package_signature(
    retrieval_id: str,
    tenant_id: str | None,
    query_fingerprint: str,
    provenance_digest: str,
    timestamp_utc: str,
    key: str | bytes | None = None,
) -> str:
    """Compute HMAC-SHA256 signature for evidence package provenance.

    Formula: HMAC-SHA256(key, f"{retrieval_id}:{tenant_id or ''}:{query_fingerprint}:{provenance_digest}:{timestamp_utc}")
    Returns empty string if key is not configured.
    """
    secret = key if key is not None else os.environ.get("KF_EVIDENCE_HMAC_KEY", "")
    if not secret:
        return ""
    if isinstance(secret, str):
        secret_bytes = secret.encode("utf-8")
    else:
        secret_bytes = secret
    tenant = tenant_id or ""
    msg = f"{retrieval_id}:{tenant}:{query_fingerprint}:{provenance_digest}:{timestamp_utc}".encode("utf-8")
    return hmac.new(secret_bytes, msg, hashlib.sha256).hexdigest()


def verify_evidence_package(
    package: dict[str, Any],
    max_age_seconds: float = 60.0,
    hmac_key: str | bytes | None = None,
) -> VerificationResult:
    """Verify cryptographic provenance of a Task 1 EvidencePackage dictionary.

    Checks:
      1. Schema validation: presence of retrieval_id, tenant_id, timestamp_utc, chunks, provenance_digest.
      2. Timestamp freshness: UTC timestamp within max_age_seconds and <= 5.0s future clock drift.
      3. Chunk provenance: recomputes canonical JSON SHA-256 hash for each chunk.
      4. Package digest: recomputed composite hash matches package provenance_digest.

    Args:
        package: Dictionary containing evidence package fields.
        max_age_seconds: Maximum allowed evidence age in seconds (default: 60.0).

    Returns:
        VerificationResult with is_valid=True or is_valid=False with descriptive error_reason.
    """
    if not isinstance(package, dict):
        return VerificationResult(
            is_valid=False,
            error_reason="Package must be a dictionary",
            digest_valid=False,
            freshness_valid=False,
        )

    # 1. Schema Validation
    required_keys = {"retrieval_id", "tenant_id", "timestamp_utc", "chunks", "provenance_digest"}
    missing_keys = sorted(required_keys - set(package.keys()))
    if missing_keys:
        return VerificationResult(
            is_valid=False,
            error_reason=f"Missing required fields: {', '.join(missing_keys)}",
            digest_valid=False,
            freshness_valid=False,
        )

    chunks = package.get("chunks")
    if not isinstance(chunks, list):
        return VerificationResult(
            is_valid=False,
            error_reason="'chunks' field must be a list",
            digest_valid=False,
            freshness_valid=False,
        )

    # 2. Freshness Check
    raw_ts = package.get("timestamp_utc")
    if not isinstance(raw_ts, str):
        return VerificationResult(
            is_valid=False,
            error_reason=f"Invalid timestamp_utc type: {type(raw_ts).__name__}",
            freshness_valid=False,
        )

    try:
        ts = datetime.fromisoformat(raw_ts)
    except (ValueError, TypeError) as exc:
        return VerificationResult(
            is_valid=False,
            error_reason=f"Malformed timestamp_utc format: {exc}",
            freshness_valid=False,
        )

    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    else:
        ts = ts.astimezone(timezone.utc)

    now_utc = datetime.now(timezone.utc)
    age_seconds = (now_utc - ts).total_seconds()

    # Allow up to 5.0s clock drift in the future
    if age_seconds < -5.0:
        return VerificationResult(
            is_valid=False,
            error_reason=f"Timestamp is set in the future (drift: {abs(age_seconds):.2f}s)",
            freshness_valid=False,
        )

    if age_seconds > max_age_seconds:
        return VerificationResult(
            is_valid=False,
            error_reason=f"Evidence timestamp has expired (age: {age_seconds:.2f}s > max: {max_age_seconds:.2f}s)",
            freshness_valid=False,
        )

    # 3. Chunk Hash Verification
    recomputed_chunk_hashes: list[str] = []
    failed_chunks: list[str] = []

    for idx, chunk in enumerate(chunks):
        if not isinstance(chunk, dict):
            return VerificationResult(
                is_valid=False,
                error_reason=f"Chunk at index {idx} must be a dictionary",
                checked_chunks=idx,
            )

        chunk_required = {"chunk_id", "content", "source_uri", "provenance_hash"}
        chunk_missing = sorted(chunk_required - set(chunk.keys()))
        if chunk_missing:
            return VerificationResult(
                is_valid=False,
                error_reason=f"Chunk at index {idx} missing required fields: {', '.join(chunk_missing)}",
                checked_chunks=idx,
            )

        chunk_id = str(chunk["chunk_id"])
        source_uri = str(chunk["source_uri"])
        content = str(chunk["content"])
        reported_hash = str(chunk["provenance_hash"])

        expected_hash = compute_chunk_hash(source_uri, content)
        recomputed_chunk_hashes.append(expected_hash)

        if reported_hash != expected_hash:
            failed_chunks.append(chunk_id)

    if failed_chunks:
        return VerificationResult(
            is_valid=False,
            error_reason=f"Chunk hash mismatch detected for chunks: {', '.join(failed_chunks)}",
            checked_chunks=len(chunks),
            failed_chunks=failed_chunks,
        )

    # 4. Composite Package Digest Verification
    reported_digest = str(package.get("provenance_digest", ""))
    expected_digest = compute_package_digest(recomputed_chunk_hashes)

    if len(chunks) == 0:
        if reported_digest != "":
            return VerificationResult(
                is_valid=False,
                error_reason="Package digest mismatch: expected empty digest for empty chunks list",
                checked_chunks=0,
                digest_valid=False,
            )
    elif reported_digest != expected_digest:
        return VerificationResult(
            is_valid=False,
            error_reason=(
                f"Package digest mismatch (reported={reported_digest[:16]}..., "
                f"expected={expected_digest[:16]}...)"
            ),
            checked_chunks=len(chunks),
            digest_valid=False,
        )

    # 5. Keyed HMAC Provenance Signature Verification (when HMAC key is configured)
    hmac_secret = hmac_key if hmac_key is not None else os.environ.get("KF_EVIDENCE_HMAC_KEY", "")
    if hmac_secret:
        reported_sig = str(package.get("package_signature", ""))
        if not reported_sig:
            return VerificationResult(
                is_valid=False,
                error_reason="Missing package_signature on HMAC-protected evidence package",
                checked_chunks=len(chunks),
                digest_valid=True,
                freshness_valid=True,
                signature_valid=False,
            )
        q_fingerprint = str(package.get("query_fingerprint", ""))
        expected_sig = compute_package_signature(
            retrieval_id=str(package.get("retrieval_id", "")),
            tenant_id=str(package.get("tenant_id") or ""),
            query_fingerprint=q_fingerprint,
            provenance_digest=reported_digest,
            timestamp_utc=str(package.get("timestamp_utc", "")),
            key=hmac_secret,
        )
        if not hmac.compare_digest(reported_sig, expected_sig):
            return VerificationResult(
                is_valid=False,
                error_reason="Invalid package_signature: HMAC verification failed",
                checked_chunks=len(chunks),
                digest_valid=True,
                freshness_valid=True,
                signature_valid=False,
            )

    return VerificationResult(
        is_valid=True,
        error_reason=None,
        checked_chunks=len(chunks),
        failed_chunks=[],
        digest_valid=True,
        freshness_valid=True,
        signature_valid=True,
    )


def verify_evidence(
    payload: dict[str, object],
    *,
    max_age_seconds: float = 60.0,
    hmac_key: str | bytes | None = None,
) -> VerificationResult:
    """Verify cryptographic provenance of an evidence payload.

    Provides dual compatibility:
    - If payload contains 'chunks' and 'retrieval_id', delegates to verify_evidence_package.
    - If payload contains legacy 'items' and 'generated_at', validates using legacy format
      with canonical JSON chunk hashing.
    """
    if not isinstance(payload, dict):
        return VerificationResult(
            is_valid=False,
            error_reason="Payload must be a dictionary",
            digest_valid=False,
            freshness_valid=False,
        )

    # If modern Task 1 package schema, use verify_evidence_package
    if "chunks" in payload and "retrieval_id" in payload:
        return verify_evidence_package(payload, max_age_seconds=max_age_seconds, hmac_key=hmac_key)

    # Legacy Knowledge Fabric payload adapter
    errors: list[str] = []
    failed_chunks: list[str] = []

    items = payload.get("items", [])
    if not isinstance(items, list):
        return VerificationResult(
            is_valid=False,
            error_reason="'items' field is missing or not a list",
            checked_chunks=0,
            failed_chunks=[],
            digest_valid=False,
            fingerprint_present=False,
            freshness_valid=False,
            errors=["'items' field is missing or not a list"],
        )

    recomputed_hashes: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        document_uri = str(item.get("document_uri") or item.get("source_uri", ""))
        snippet = str(item.get("snippet") or item.get("content", ""))
        reported_hash = str(item.get("provenance_hash", ""))
        chunk_id = item.get("chunk_id", "unknown")

        expected_hash = compute_chunk_hash(document_uri, snippet)
        recomputed_hashes.append(expected_hash)

        if reported_hash and reported_hash != expected_hash:
            failed_chunks.append(str(chunk_id))
            errors.append(
                f"Chunk {chunk_id}: provenance_hash mismatch "
                f"(reported={reported_hash[:16]}..., expected={expected_hash[:16]}...)"
            )

    reported_digest = str(payload.get("provenance_digest", ""))
    expected_digest = compute_package_digest(recomputed_hashes)
    digest_valid = (
        reported_digest == expected_digest if reported_digest else len(items) == 0
    )
    if not digest_valid:
        errors.append(
            f"Package digest mismatch "
            f"(reported={reported_digest[:16]}..., expected={expected_digest[:16]}...)"
        )

    fingerprint = str(payload.get("query_fingerprint", ""))
    fingerprint_present = bool(fingerprint and len(fingerprint) == 64)
    if not fingerprint_present:
        errors.append("query_fingerprint is missing or malformed (expected 64-char hex)")

    freshness_valid = True
    generated_at_str = str(payload.get("generated_at") or payload.get("timestamp_utc", ""))
    if generated_at_str:
        try:
            generated_at = datetime.fromisoformat(generated_at_str)
            if generated_at.tzinfo is None:
                generated_at = generated_at.replace(tzinfo=timezone.utc)
            else:
                generated_at = generated_at.astimezone(timezone.utc)
            age = (datetime.now(timezone.utc) - generated_at).total_seconds()
            if age < -5.0:
                freshness_valid = False
                errors.append(f"Timestamp is set in the future (drift: {abs(age):.2f}s)")
            elif age > max_age_seconds:
                freshness_valid = False
                errors.append(f"Evidence is {age:.1f}s old (max: {max_age_seconds}s)")
        except (ValueError, TypeError):
            freshness_valid = False
            errors.append(f"Cannot parse timestamp: {generated_at_str!r}")
    else:
        freshness_valid = False
        errors.append("Missing timestamp field ('generated_at' or 'timestamp_utc')")

    is_valid = (
        len(failed_chunks) == 0
        and digest_valid
        and fingerprint_present
        and freshness_valid
    )

    error_reason = "; ".join(errors) if errors else None

    return VerificationResult(
        is_valid=is_valid,
        error_reason=error_reason,
        checked_chunks=len(items),
        failed_chunks=failed_chunks,
        digest_valid=digest_valid,
        fingerprint_present=fingerprint_present,
        freshness_valid=freshness_valid,
        errors=errors,
    )
