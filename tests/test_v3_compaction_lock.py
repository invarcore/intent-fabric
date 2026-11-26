from __future__ import annotations

import hashlib
from pathlib import Path
import pytest

from intent_fabric.compaction_lock import (
    CompactionConstraintLock,
    CompactionConstraintViolationError,
    CompactionLockTamperError,
    SilentModelRouteDriftError,
    build_compaction_constraint_lock,
    enforce_post_compaction_lock,
)

TEST_SECRET_KEY = "invarcore-v3-test-hmac-secret-key-32bytes-min!"
WRONG_SECRET_KEY = "wrong-invarcore-v3-test-hmac-secret-key-32bytes!"


def test_hmac_key_length_missing_env_and_forgery_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("COMPACTION_LOCK_SECRET", raising=False)

    for bad_key in (None, "", "   ", "too-short-key"):
        with pytest.raises((ValueError, CompactionLockTamperError)):
            build_compaction_constraint_lock(
                allowed_tools=["read_file"],
                signing_key=bad_key,
            )

    lock = build_compaction_constraint_lock(
        allowed_tools=["read_file"],
        signing_key=TEST_SECRET_KEY,
    )
    assert lock.schema == "arcbench-compaction-lock-v3"

    with pytest.raises((ValueError, CompactionLockTamperError)):
        enforce_post_compaction_lock(
            lock,
            tool_name="read_file",
            tool_args={},
            signing_key=None,
        )

    tampered = lock.to_dict()
    tampered["allowed_tools"] = ["read_file", "shell_exec"]
    with pytest.raises(CompactionLockTamperError):
        CompactionConstraintLock.from_dict(tampered, signing_key=TEST_SECRET_KEY)

    flipped_allow_all = lock.to_dict()
    flipped_allow_all["allow_any_tool"] = True
    with pytest.raises(CompactionLockTamperError):
        CompactionConstraintLock.from_dict(flipped_allow_all, signing_key=TEST_SECRET_KEY)

    forged = lock.to_dict()
    forged["lock_digest"] = "@arcbench_lock:sha256:" + hashlib.sha256(b"forged").hexdigest()
    with pytest.raises(CompactionLockTamperError):
        CompactionConstraintLock.from_dict(forged, signing_key=TEST_SECRET_KEY)

    with pytest.raises(CompactionLockTamperError):
        CompactionConstraintLock.from_dict(lock.to_dict(), signing_key=WRONG_SECRET_KEY)
    with pytest.raises(CompactionLockTamperError):
        enforce_post_compaction_lock(
            lock,
            tool_name="read_file",
            tool_args={},
            signing_key=WRONG_SECRET_KEY,
        )


def test_recursive_strict_type_equality_blocks_nested_bool_int_confusion() -> None:
    lock = build_compaction_constraint_lock(
        allowed_tools=["deploy"],
        pinned_arg_literals={
            "deploy": {
                "options": {"dry_run": True, "retries": 0},
                "flags": [True, 0],
            }
        },
        signing_key=TEST_SECRET_KEY,
    )

    enforce_post_compaction_lock(
        lock,
        tool_name="deploy",
        tool_args={"options": {"dry_run": True, "retries": 0}, "flags": [True, 0]},
        signing_key=TEST_SECRET_KEY,
    )

    with pytest.raises(CompactionConstraintViolationError):
        enforce_post_compaction_lock(
            lock,
            tool_name="deploy",
            tool_args={"options": {"dry_run": 1, "retries": 0}, "flags": [True, 0]},
            signing_key=TEST_SECRET_KEY,
        )

    with pytest.raises(CompactionConstraintViolationError):
        enforce_post_compaction_lock(
            lock,
            tool_name="deploy",
            tool_args={"options": {"dry_run": True, "retries": 0}, "flags": [True, False]},
            signing_key=TEST_SECRET_KEY,
        )


@pytest.mark.parametrize(
    "bad_path",
    [
        "//etc/passwd",
        "///etc/shadow",
        "/ETC/passwd",
        "/e\u200btc/passwd",
        "/\uff45\uff54\uff43/passwd",
        Path("/etc/passwd"),
        b"/etc/passwd",
        "file:///etc/passwd",
        "FILE:///etc/passwd",
        "/etc%2Fpasswd",
        "%2fetc%2fpasswd",
        "/etc%252fpasswd",
        "/app/%2e%2e/etc/passwd",
        "/tmp/safe%00/etc/passwd",
        "../etc/passwd",
        "secrets/safe/../prod/api_keys.json",
        r"C:\REPO\SECRETS\PROD\api_keys.json",
    ],
)
def test_lexical_path_hardening_blocks_bypasses(bad_path: str | Path | bytes) -> None:
    lock = build_compaction_constraint_lock(
        allowed_tools=["read_file"],
        forbidden_path_prefixes=["/etc/", "secrets/prod", r"C:\repo\secrets\prod"],
        signing_key=TEST_SECRET_KEY,
    )
    with pytest.raises(CompactionConstraintViolationError):
        enforce_post_compaction_lock(
            lock,
            tool_name="read_file",
            tool_args={"path": bad_path},
            signing_key=TEST_SECRET_KEY,
        )


@pytest.mark.parametrize(
    "safe_value",
    [
        "/etcetera/config.yaml",
        "/app/secrets/products/catalog.json",
        "app/docs/readme.md",
        "https://example.com/api/v1/status",
    ],
)
def test_lexical_path_avoids_false_positives(safe_value: str) -> None:
    lock = build_compaction_constraint_lock(
        allowed_tools=["read_file"],
        forbidden_path_prefixes=["/etc/", "secrets/prod"],
        signing_key=TEST_SECRET_KEY,
    )
    enforce_post_compaction_lock(
        lock,
        tool_name="read_file",
        tool_args={"path": safe_value},
        signing_key=TEST_SECRET_KEY,
    )


def test_empty_allowed_tools_defaults_to_deny_all_unless_explicit() -> None:
    deny_lock = build_compaction_constraint_lock(
        allowed_tools=(),
        signing_key=TEST_SECRET_KEY,
    )
    with pytest.raises(CompactionConstraintViolationError):
        enforce_post_compaction_lock(
            deny_lock,
            tool_name="read_file",
            tool_args={},
            signing_key=TEST_SECRET_KEY,
        )

    allow_lock = build_compaction_constraint_lock(
        allowed_tools=(),
        allow_any_tool=True,
        signing_key=TEST_SECRET_KEY,
    )
    enforce_post_compaction_lock(
        allow_lock,
        tool_name="read_file",
        tool_args={},
        signing_key=TEST_SECRET_KEY,
    )


def test_pinned_model_version_fails_closed_when_telemetry_missing_by_default() -> None:
    lock = build_compaction_constraint_lock(
        allowed_tools=["deploy"],
        pinned_model_version="gemini-2.5-pro",
        signing_key=TEST_SECRET_KEY,
    )
    with pytest.raises(SilentModelRouteDriftError):
        enforce_post_compaction_lock(
            lock,
            tool_name="deploy",
            tool_args={},
            observed_model_version=None,
            signing_key=TEST_SECRET_KEY,
        )


def test_tuple_pinned_arg_literals_round_trip_through_json() -> None:
    lock = build_compaction_constraint_lock(
        allowed_tools=["deploy"],
        pinned_arg_literals={"deploy": {"targets": ("staging", "canary")}},
        signing_key=TEST_SECRET_KEY,
    )
    reloaded = CompactionConstraintLock.from_json(lock.to_json(), signing_key=TEST_SECRET_KEY)

    enforce_post_compaction_lock(
        reloaded,
        tool_name="deploy",
        tool_args={"targets": ["staging", "canary"]},
        signing_key=TEST_SECRET_KEY,
    )
