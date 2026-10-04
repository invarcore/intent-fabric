# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Action contract schema and evidence provenance verification."""

from intent_fabric.contracts.evidence_verifier import (
    VerificationResult,
    compute_chunk_hash,
    compute_package_digest,
    verify_evidence,
    verify_evidence_package,
)
from intent_fabric.contracts.schema import action_contract_schema

__all__ = [
    "VerificationResult",
    "action_contract_schema",
    "compute_chunk_hash",
    "compute_package_digest",
    "verify_evidence",
    "verify_evidence_package",
]

