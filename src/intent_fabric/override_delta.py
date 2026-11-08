# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Override Delta & Policy Synthesizer module for human override lineage."""

from __future__ import annotations

import hashlib
import hmac
import json
import operator
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


def nfc_normalize(value: str) -> str:
    """Normalize string to Unicode NFC before canonicalization or hashing."""
    return unicodedata.normalize("NFC", value)


def length_prefixed_utf8(value: str) -> str:
    """Format string with its exact UTF-8 byte length: '{byte_len}:{nfc_str}'."""
    norm = nfc_normalize(value)
    byte_len = len(norm.encode("utf-8"))
    return f"{byte_len}:{norm}"


def rfc8785_canonical_bytes(payload: Any) -> bytes:
    """Serialize payload into deterministic RFC 8785 canonical UTF-8 JSON bytes."""

    def _normalize_obj(obj: Any) -> Any:
        if isinstance(obj, str):
            return nfc_normalize(obj)
        if isinstance(obj, Mapping):
            return {nfc_normalize(str(k)): _normalize_obj(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_normalize_obj(x) for x in obj]
        return obj

    normalized = _normalize_obj(payload)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def rfc8785_sha256(payload: Any) -> str:
    """Compute SHA-256 hex digest over RFC 8785 canonical JSON bytes."""
    return hashlib.sha256(rfc8785_canonical_bytes(payload)).hexdigest()


@dataclass(frozen=True)
class ParameterOverrideEntry:
    json_path: str
    override_kind: str
    proposed_value: Any
    approved_value: Any


@dataclass(frozen=True)
class OverrideLineageReceipt:
    tool_name: str
    actor_id: str
    reviewer_id: str
    proposed_args_digest: str
    approved_args_digest: str
    overrides: Tuple[ParameterOverrideEntry, ...]
    override_occurred: bool
    canonical_payload_bytes: bytes = field(repr=False)
    hmac_signature: str = ""
    receipt_qualifier: str = ""


def _validate_secret_key(secret_key: Optional[str]) -> bytes:
    if secret_key is None or nfc_normalize(secret_key).strip() == "":
        raise ValueError("secret_key is required and cannot be empty or whitespace-only")
    return nfc_normalize(secret_key).encode("utf-8")


def _classify_parameter_override(path: str, prop: Any, appr: Any) -> ParameterOverrideEntry:
    if isinstance(prop, (int, float)) and isinstance(appr, (int, float)) and not isinstance(prop, bool):
        if operator.lt(appr, prop):
            return ParameterOverrideEntry(path, "VALUE_CLAMPED", prop, appr)
    if isinstance(prop, str) and isinstance(appr, str):
        if prop.startswith("-") and not appr.startswith("-"):
            return ParameterOverrideEntry(path, "FLAG_STRIPPED", prop, appr)
        if (".." in prop or prop.startswith("/")) and not (".." in appr):
            return ParameterOverrideEntry(path, "PATH_JAILED", prop, appr)
        return ParameterOverrideEntry(path, "ENUM_RESTRICTED", prop, appr)
    if isinstance(prop, list) and isinstance(appr, list):
        removed = [x for x in prop if x not in appr]
        if any(isinstance(x, str) and x.startswith("-") for x in removed):
            return ParameterOverrideEntry(path, "FLAG_STRIPPED", prop, appr)
    return ParameterOverrideEntry(path, "ENUM_RESTRICTED", prop, appr)


def compute_override_entries(
    proposed: Mapping[str, Any],
    approved: Mapping[str, Any],
    prefix: str = "$",
) -> Tuple[ParameterOverrideEntry, ...]:
    entries: List[ParameterOverrideEntry] = []
    all_keys = sorted(set(proposed.keys()) | set(approved.keys()))
    for key in all_keys:
        norm_key = nfc_normalize(str(key))
        path = f"{prefix}.{norm_key}"
        if key not in approved:
            entries.append(ParameterOverrideEntry(path, "KEY_REMOVED", proposed[key], None))
        elif key not in proposed:
            entries.append(ParameterOverrideEntry(path, "ENUM_RESTRICTED", None, approved[key]))
        else:
            p_val, a_val = proposed[key], approved[key]
            if isinstance(p_val, Mapping) and isinstance(a_val, Mapping):
                entries.extend(compute_override_entries(p_val, a_val, prefix=path))
            elif p_val != a_val:
                entries.append(_classify_parameter_override(path, p_val, a_val))
    return tuple(entries)


def create_override_lineage_receipt(
    tool_name: str,
    actor_id: str,
    reviewer_id: str,
    proposed_args: Mapping[str, Any],
    approved_args: Mapping[str, Any],
    secret_key: str,
) -> OverrideLineageReceipt:
    key_bytes = _validate_secret_key(secret_key)
    prop_digest = rfc8785_sha256(proposed_args)
    appr_digest = rfc8785_sha256(approved_args)
    overrides = compute_override_entries(proposed_args, approved_args)

    canonical_obj = {
        "actor_id": length_prefixed_utf8(actor_id),
        "approved_args_digest": appr_digest,
        "overrides": [
            {
                "approved_value": o.approved_value,
                "json_path": length_prefixed_utf8(o.json_path),
                "override_kind": o.override_kind,
                "proposed_value": o.proposed_value,
            }
            for o in overrides
        ],
        "proposed_args_digest": prop_digest,
        "reviewer_id": length_prefixed_utf8(reviewer_id),
        "tool_name": length_prefixed_utf8(tool_name),
        "v": "intent-fabric-override-v1",
    }
    canon_bytes = rfc8785_canonical_bytes(canonical_obj)
    mac = hmac.new(key_bytes, canon_bytes, hashlib.sha256).hexdigest()
    digest_prefix = hashlib.sha256(canon_bytes).hexdigest()[:16]
    return OverrideLineageReceipt(
        tool_name=nfc_normalize(tool_name),
        actor_id=nfc_normalize(actor_id),
        reviewer_id=nfc_normalize(reviewer_id),
        proposed_args_digest=prop_digest,
        approved_args_digest=appr_digest,
        overrides=overrides,
        override_occurred=operator.gt(len(overrides), 0),
        canonical_payload_bytes=canon_bytes,
        hmac_signature=mac,
        receipt_qualifier=f"@override_delta:sha256:{digest_prefix}",
    )


def verify_override_lineage_receipt(
    receipt: OverrideLineageReceipt,
    secret_key: str,
) -> bool:
    key_bytes = _validate_secret_key(secret_key)
    expected_mac = hmac.new(key_bytes, receipt.canonical_payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_mac.lower(), receipt.hmac_signature.lower())


def synthesize_json_schema_patch(
    receipts: Sequence[OverrideLineageReceipt],
) -> Dict[str, Any]:
    """Deterministically compile human override deltas into a JSON Schema Draft 2020-12

    property constraint patch without invoking an LLM.
    """
    properties_patch: Dict[str, Dict[str, Any]] = {}
    for rec in receipts:
        for ov in rec.overrides:
            prop_name = ov.json_path.split(".")[-1]
            rule = properties_patch.setdefault(prop_name, {})
            if ov.override_kind == "VALUE_CLAMPED" and isinstance(ov.approved_value, (int, float)):
                current_max = rule.get("maximum")
                rule["maximum"] = (
                    min(current_max, ov.approved_value)
                    if current_max is not None
                    else ov.approved_value
                )
            elif ov.override_kind == "FLAG_STRIPPED":
                rule["pattern"] = r"^(?!-).*$"
                rule["description"] = "Leading CLI flags stripped by human override policy"
            elif ov.override_kind == "PATH_JAILED" and isinstance(ov.approved_value, str):
                rule["pattern"] = r"^(?!\.\./|/etc/|/root/).*$"
            elif ov.override_kind == "ENUM_RESTRICTED" and ov.approved_value is not None:
                allowed = rule.setdefault("enum", [])
                if ov.approved_value not in allowed:
                    allowed.append(ov.approved_value)
            elif ov.override_kind == "KEY_REMOVED":
                rule["not"] = {}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "properties": properties_patch,
        "type": "object",
    }
