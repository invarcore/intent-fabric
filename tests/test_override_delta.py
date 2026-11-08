# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

import re
import pytest

from intent_fabric.override_delta import (
    JAILED_PATH_PATTERN,
    NO_LEADING_FLAG_PATTERN,
    create_override_lineage_receipt,
    length_prefixed_utf8,
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
    assert props["ref"]["pattern"] == NO_LEADING_FLAG_PATTERN
    assert props["path"]["pattern"] == JAILED_PATH_PATTERN
    assert props["debug_token"]["not"] == {}


def test_p0_4_nested_json_path_isolation_and_cross_tool_rejection() -> None:
    r1 = create_override_lineage_receipt(
        "sync_files",
        "agent:1",
        "human:1",
        {"source": {"path": "workspace/../../etc/shadow"}, "timeout": -1},
        {"source": {"path": "workspace/input.csv"}, "timeout": 30},
        "secret-key",
    )
    schema = synthesize_json_schema_patch([r1])
    assert "source" in schema["properties"]
    assert schema["properties"]["source"]["properties"]["path"]["pattern"] == JAILED_PATH_PATTERN
    assert schema["properties"]["timeout"]["minimum"] == 30

    r_other = create_override_lineage_receipt(
        "delete_db",
        "agent:1",
        "human:1",
        {"limit": 100},
        {"limit": 10},
        "secret-key",
    )
    with pytest.raises(ValueError, match="Cross-tool schema pollution blocked"):
        synthesize_json_schema_patch([r1, r_other])


def test_p0_5_mid_string_and_windows_traversal_blocked_by_jailed_pattern() -> None:
    bs = chr(92)
    pat = re.compile(JAILED_PATH_PATTERN)
    assert pat.match("workspace/report.json") is not None
    assert pat.match("../../etc/passwd") is None
    assert pat.match("workspace/../../etc/passwd") is None
    assert pat.match("workspace" + bs + ".." + bs + ".." + bs + "Windows") is None
    assert pat.match("/etc/passwd") is None
    assert pat.match("C:" + bs + "Windows" + bs + "System32") is None


def test_empty_secret_key_fails_closed() -> None:
    for bad_key in ["", "   ", None]:
        with pytest.raises(ValueError, match="secret_key is required"):
            create_override_lineage_receipt("t", "a", "r", {}, {}, bad_key)  # type: ignore[arg-type]


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
    nfc_actor = "agent:caf" + chr(0xE9)
    nfd_actor = "agent:cafe" + chr(0x301)
    assert length_prefixed_utf8(nfc_actor) == length_prefixed_utf8(nfd_actor)
    assert length_prefixed_utf8(nfc_actor).startswith("11:")
    assert rfc8785_sha256({"a": nfc_actor}) == rfc8785_sha256({"a": nfd_actor})


def test_nested_mapping_and_flag_stripping_in_list() -> None:
    proposed = {
        "flags": ["--force", "-v", "arg1"],
        "nested": {"key_to_drop": "drop_me", "config": {"option": "a"}},
        "new_key": "exists",
    }
    approved = {
        "flags": ["arg1"],
        "nested": {"config": {"option": "b"}},
        "added_key": "new_val",
    }
    receipt = create_override_lineage_receipt(
        tool_name="complex_tool",
        actor_id="actor_1",
        reviewer_id="reviewer_1",
        proposed_args=proposed,
        approved_args=approved,
        secret_key="my-secret-key",
    )
    assert receipt.override_occurred is True
    kinds = {o.json_path: o.override_kind for o in receipt.overrides}
    assert kinds["$.flags"] == "FLAG_STRIPPED"
    assert kinds["$.nested.key_to_drop"] == "KEY_REMOVED"
    assert kinds["$.nested.config.option"] == "ENUM_RESTRICTED"
    assert kinds["$.new_key"] == "KEY_REMOVED"
    assert kinds["$.added_key"] == "ENUM_RESTRICTED"

    empty_schema = synthesize_json_schema_patch([])
    assert empty_schema["type"] == "object"
    assert empty_schema["properties"] == {}


def test_bool_or_generic_override_classification() -> None:
    receipt = create_override_lineage_receipt(
        "tool",
        "actor",
        "reviewer",
        {"enabled": True},
        {"enabled": False},
        "key",
    )
    assert receipt.overrides[0].override_kind == "ENUM_RESTRICTED"
