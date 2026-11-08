# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Tests for Override Delta & Policy Synthesizer module."""

from __future__ import annotations

import pytest
from intent_fabric.override_delta import (
    create_override_lineage_receipt,
    length_prefixed_utf8,
    rfc8785_canonical_bytes,
    rfc8785_sha256,
    synthesize_json_schema_patch,
    verify_override_lineage_receipt,
)


def test_override_lineage_receipt_and_schema_synthesis() -> None:
    proposed = {
        "env": "production",
        "limit": 50000,
        "ref": "--upload-pack=/tmp/evil",
        "path": "../../etc/passwd",
        "debug_token": "secret123",
    }
    approved = {
        "env": "staging",
        "limit": 500,
        "ref": "main",
        "path": "workspace/report.json",
    }
    receipt = create_override_lineage_receipt(
        tool_name="deploy_release",
        actor_id="agent:codex-worker-04",
        reviewer_id="human:vinay@invarcore.com",
        proposed_args=proposed,
        approved_args=approved,
        secret_key="invarcore-test-hmac-key-2026",
    )
    assert receipt.override_occurred is True
    assert receipt.receipt_qualifier.startswith("@override_delta:sha256:")
    assert verify_override_lineage_receipt(receipt, "invarcore-test-hmac-key-2026") is True
    assert verify_override_lineage_receipt(receipt, "wrong-key") is False

    schema = synthesize_json_schema_patch([receipt])
    props = schema["properties"]
    assert props["limit"]["maximum"] == 500
    assert props["env"]["enum"] == ["staging"]
    assert props["ref"]["pattern"] == r"^(?!-).*$"
    assert props["path"]["pattern"] == r"^(?!\.\./|/etc/|/root/).*$"
    assert props["debug_token"]["not"] == {}


def test_empty_secret_key_fails_closed() -> None:
    for bad_key in ["", "   ", None]:
        with pytest.raises(ValueError, match="secret_key is required"):
            create_override_lineage_receipt("t", "a", "r", {}, {}, bad_key)  # type: ignore


def test_multi_receipt_schema_convergence() -> None:
    r1 = create_override_lineage_receipt(
        "query_db",
        "agent:1",
        "human:a",
        {"limit": 10000, "env": "prod"},
        {"limit": 500, "env": "staging"},
        "secret-key-1",
    )
    r2 = create_override_lineage_receipt(
        "query_db",
        "agent:1",
        "human:b",
        {"limit": 5000, "env": "prod"},
        {"limit": 250, "env": "dev"},
        "secret-key-1",
    )
    patch = synthesize_json_schema_patch([r1, r2])
    assert patch["properties"]["limit"]["maximum"] == 250
    assert patch["properties"]["env"]["enum"] == ["staging", "dev"]


def test_multibyte_utf8_and_nfc_symmetry() -> None:
    nfc_actor = "agent:café"
    nfd_actor = "agent:café"
    assert length_prefixed_utf8(nfc_actor) == length_prefixed_utf8(nfd_actor)
    assert length_prefixed_utf8(nfc_actor).startswith("11:")
    assert rfc8785_sha256({"a": nfc_actor}) == rfc8785_sha256({"a": nfd_actor})


def test_nested_mapping_and_list_flag_stripping() -> None:
    proposed = {
        "nested": {"timeout": 120.5, "tags": ["--all", "v1"]},
        "modes": ["alpha", "beta"],
        "added_later": None,
    }
    approved = {
        "nested": {"timeout": 30.0, "tags": ["v1"]},
        "modes": ["alpha"],
        "new_param": "safe_default",
    }
    receipt = create_override_lineage_receipt(
        tool_name="configure_service",
        actor_id="agent:planner",
        reviewer_id="human:reviewer",
        proposed_args=proposed,
        approved_args=approved,
        secret_key="secret-key-2",
    )
    assert receipt.override_occurred is True
    assert len(receipt.overrides) == 5

    # Verify no override occurred when proposed == approved
    noop_receipt = create_override_lineage_receipt(
        tool_name="read_only",
        actor_id="agent:reader",
        reviewer_id="human:approver",
        proposed_args={"limit": 10},
        approved_args={"limit": 10},
        secret_key="secret-key-2",
    )
    assert noop_receipt.override_occurred is False
    assert len(noop_receipt.overrides) == 0

    # Verify canonical bytes serialization on collections
    canon = rfc8785_canonical_bytes(["item1", {"k": "v"}])
    assert b"item1" in canon
