# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""ARCBench Post-Compaction Constraint Lock and Silent Model Route Drift Guard.

Binds compacted constraint slots (forbidden_tools, forbidden_path_prefixes,
pinned_arg_literals, and pinned_model_version) into an RFC 8785 canonical
@arcbench_lock:sha256 sidecar enforced deterministically at the pre-execution
tool boundary (arXiv:2611.03223 & EvalShift Model Deprecation Schedule).
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import unquote

from intent_fabric.etude_lock import canonical_json_bytes

_BS = chr(92)
_DRIVE_RE = re.compile(r"^([A-Za-z]:)(/.*)?$")


class PostCompactionRuleViolationError(PermissionError):
    """Raised when a post-compaction tool call violates a rule pinned in CompactionConstraintLock."""


class SilentModelRouteDriftError(RuntimeError):
    """Raised when the provider response.model_version drifts from the pinned model snapshot."""


@dataclass(frozen=True)
class CompactionConstraintLock:
    """Immutable post-compaction constraint lock sidecar with RFC 8785 SHA-256 digest."""

    compaction_epoch: int
    forbidden_tools: Tuple[str, ...]
    forbidden_path_prefixes: Tuple[str, ...]
    pinned_arg_literals: Mapping[str, Mapping[str, Any]]
    pinned_model_version: Optional[str]
    lock_digest: str
    allowed_tools: Tuple[str, ...] = ()


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze_value(v) for k, v in sorted(value.items())})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(v) for v in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_value(v) for v in value)
    return value


def _freeze_arg_literals(
    pinned_arg_literals: Optional[Mapping[str, Mapping[str, Any]]],
) -> Mapping[str, Mapping[str, Any]]:
    if not pinned_arg_literals:
        return MappingProxyType({})
    frozen: Dict[str, Mapping[str, Any]] = {}
    for tname, kv in sorted(pinned_arg_literals.items()):
        frozen[str(tname)] = MappingProxyType({k: _freeze_value(v) for k, v in sorted(kv.items())})
    return MappingProxyType(frozen)


def _normalize_lock_path(raw: str, *, casefold_path: bool = False) -> Tuple[str, bool]:
    """Canonicalize backslashes, percent-escapes, and traversal segments safely."""
    decoded = unquote(raw)
    has_bs = _BS in raw or _BS in decoded
    forward = decoded.replace(_BS, "/").strip()
    is_drive = bool(_DRIVE_RE.match(forward))
    collapsed = re.sub(r"/+", "/", forward)

    norm = posixpath.normpath(collapsed) if collapsed else ""
    if collapsed.startswith("/") and not norm.startswith("/"):
        norm = "/" + norm.lstrip("/")
    if norm == "." and not raw.strip().startswith("."):
        norm = ""
    if len(norm) > 1 and norm.endswith("/") and not _DRIVE_RE.match(norm):
        norm = norm.rstrip("/")
    if norm.endswith(":"):
        norm = norm + "/"
    if is_drive or casefold_path or has_bs:
        return norm.casefold(), (is_drive or has_bs)
    return norm, False


def _unfreeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _unfreeze_value(v) for k, v in sorted(value.items())}
    if isinstance(value, tuple):
        return [_unfreeze_value(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return [_unfreeze_value(v) for v in sorted(value, key=repr)]
    return value


def _compute_lock_digest(
    *,
    compaction_epoch: int,
    allowed_tools: Tuple[str, ...],
    forbidden_tools: Tuple[str, ...],
    forbidden_path_prefixes: Tuple[str, ...],
    pinned_arg_literals: Mapping[str, Mapping[str, Any]],
    pinned_model_version: Optional[str],
) -> str:
    payload = {
        "allowed_tools": list(allowed_tools),
        "compaction_epoch": compaction_epoch,
        "forbidden_path_prefixes": list(forbidden_path_prefixes),
        "forbidden_tools": list(forbidden_tools),
        "pinned_arg_literals": {
            k: _unfreeze_value(v) for k, v in sorted(pinned_arg_literals.items())
        },
        "pinned_model_version": pinned_model_version,
    }
    return "@arcbench_lock:sha256:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _strict_literal_equal(actual: Any, expected: Any) -> bool:
    """Check strict equality preventing bool/int and int/float confusion across nested values."""
    if isinstance(actual, bool) != isinstance(expected, bool):
        return False
    if isinstance(expected, Mapping):
        if not isinstance(actual, Mapping) or set(actual.keys()) != set(expected.keys()):
            return False
        return all(_strict_literal_equal(actual[k], expected[k]) for k in expected)
    if isinstance(expected, (list, tuple)):
        if not isinstance(actual, (list, tuple)) or len(actual) != len(expected):
            return False
        return all(_strict_literal_equal(a, e) for a, e in zip(actual, expected))
    if type(actual) is not type(expected):
        return False
    return actual == expected


def _iter_string_leaves(obj: Any) -> Iterable[str]:
    """Yield every string value and mapping key recursively across nested collections."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            if isinstance(k, str):
                yield k
            yield from _iter_string_leaves(v)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for item in obj:
            yield from _iter_string_leaves(item)


def _path_matches_prefix(raw_value: str, raw_prefix: str) -> bool:
    """Evaluate segment-boundary prefix match with traversal collapse and Windows case-folding."""
    prefix_cf, prefix_win = _normalize_lock_path(raw_prefix, casefold_path=True)
    raw_is_win = (
        prefix_win or (_BS in raw_value) or bool(_DRIVE_RE.match(raw_value.replace(_BS, "/")))
    )
    norm_s, _ = _normalize_lock_path(raw_value, casefold_path=raw_is_win)
    norm_p, _ = _normalize_lock_path(raw_prefix, casefold_path=raw_is_win)
    if raw_is_win:
        norm_p = prefix_cf

    if not norm_p or not norm_s:
        return False

    anchored = norm_p.startswith("/") or bool(_DRIVE_RE.match(norm_p))
    if anchored:
        if norm_p == "/":
            return norm_s.startswith("/")
        base = norm_p.rstrip("/")
        return norm_s == base or norm_s.startswith(base + "/")

    return (
        norm_s == norm_p
        or norm_s.startswith(norm_p + "/")
        or norm_s.endswith("/" + norm_p)
        or f"/{norm_p}/" in norm_s
    )


def build_compaction_constraint_lock(
    compaction_epoch: int,
    *,
    allowed_tools: Sequence[str] = (),
    forbidden_tools: Sequence[str] = (),
    forbidden_path_prefixes: Sequence[str] = (),
    pinned_arg_literals: Optional[Mapping[str, Mapping[str, Any]]] = None,
    pinned_model_version: Optional[str] = None,
) -> CompactionConstraintLock:
    """Construct an immutable @arcbench_lock:sha256 constraint sidecar for a compaction epoch."""
    norm_allowed = tuple(sorted(set(allowed_tools)))
    norm_tools = tuple(sorted(set(forbidden_tools)))
    norm_paths = tuple(sorted({_normalize_lock_path(p)[0] for p in forbidden_path_prefixes if p}))
    frozen_args = _freeze_arg_literals(pinned_arg_literals)
    digest = _compute_lock_digest(
        compaction_epoch=compaction_epoch,
        allowed_tools=norm_allowed,
        forbidden_tools=norm_tools,
        forbidden_path_prefixes=norm_paths,
        pinned_arg_literals=frozen_args,
        pinned_model_version=pinned_model_version,
    )
    return CompactionConstraintLock(
        compaction_epoch=compaction_epoch,
        forbidden_tools=norm_tools,
        forbidden_path_prefixes=norm_paths,
        pinned_arg_literals=frozen_args,
        pinned_model_version=pinned_model_version,
        lock_digest=digest,
        allowed_tools=norm_allowed,
    )


def verify_compaction_lock_digest(lock: CompactionConstraintLock) -> None:
    """Verify lock fields match its @arcbench_lock:sha256 digest; fail closed on tampering."""
    expected = _compute_lock_digest(
        compaction_epoch=lock.compaction_epoch,
        allowed_tools=lock.allowed_tools,
        forbidden_tools=lock.forbidden_tools,
        forbidden_path_prefixes=lock.forbidden_path_prefixes,
        pinned_arg_literals=lock.pinned_arg_literals,
        pinned_model_version=lock.pinned_model_version,
    )
    if lock.lock_digest != expected:
        raise PostCompactionRuleViolationError(
            f"ARCBench Lock integrity failure: expected {expected[:28]}, got {lock.lock_digest[:28]}."
        )


def compaction_lock_to_dict(lock: CompactionConstraintLock) -> Dict[str, Any]:
    """Serialize a CompactionConstraintLock into an RFC 8785 JSON-compatible sidecar dict."""
    return {
        "schema_version": "arcbench-lock-v1",
        "compaction_epoch": lock.compaction_epoch,
        "allowed_tools": list(lock.allowed_tools),
        "forbidden_tools": list(lock.forbidden_tools),
        "forbidden_path_prefixes": list(lock.forbidden_path_prefixes),
        "pinned_arg_literals": {
            k: _unfreeze_value(v) for k, v in sorted(lock.pinned_arg_literals.items())
        },
        "pinned_model_version": lock.pinned_model_version,
        "lock_digest": lock.lock_digest,
    }


def save_compaction_lock(lock: CompactionConstraintLock, path: Union[str, Path]) -> Path:
    """Write CompactionConstraintLock sidecar JSON to disk."""
    verify_compaction_lock_digest(lock)
    target = Path(path)
    target.write_bytes(canonical_json_bytes(compaction_lock_to_dict(lock)))
    return target


def load_compaction_lock(
    path_or_payload: Union[str, Path, Mapping[str, Any]],
) -> CompactionConstraintLock:
    """Load and cryptographically verify an @arcbench_lock:sha256 sidecar JSON."""
    if isinstance(path_or_payload, Mapping):
        data = dict(path_or_payload)
    else:
        data = json.loads(Path(path_or_payload).read_text(encoding="utf-8"))

    lock = CompactionConstraintLock(
        compaction_epoch=int(data["compaction_epoch"]),
        forbidden_tools=tuple(sorted(str(t) for t in data.get("forbidden_tools", ()))),
        forbidden_path_prefixes=tuple(
            sorted(
                _normalize_lock_path(str(p))[0]
                for p in data.get("forbidden_path_prefixes", ())
                if p
            )
        ),
        pinned_arg_literals=_freeze_arg_literals(data.get("pinned_arg_literals")),
        pinned_model_version=data.get("pinned_model_version"),
        lock_digest=str(data["lock_digest"]),
        allowed_tools=tuple(sorted(str(t) for t in data.get("allowed_tools", ()))),
    )
    verify_compaction_lock_digest(lock)
    return lock


def enforce_post_compaction_lock(
    lock: CompactionConstraintLock,
    tool_name: str,
    tool_args: Mapping[str, Any],
    *,
    observed_model_version: Optional[str] = None,
    require_model_version: bool = False,
) -> None:
    """Fail closed if model snapshot or pre-execution tool call violates pinned lock constraints."""
    verify_compaction_lock_digest(lock)

    if lock.pinned_model_version is not None:
        if observed_model_version == "":
            raise SilentModelRouteDriftError(
                f"Silent provider model swap suspected at epoch {lock.compaction_epoch}: "
                f"pinned '{lock.pinned_model_version}', provider returned empty model_version"
            )
        if observed_model_version is None:
            if require_model_version:
                raise SilentModelRouteDriftError(
                    f"Missing provider response.model_version at epoch {lock.compaction_epoch}: "
                    f"pinned '{lock.pinned_model_version}'"
                )
        elif observed_model_version != lock.pinned_model_version:
            raise SilentModelRouteDriftError(
                f"Silent provider model swap detected at epoch {lock.compaction_epoch}: "
                f"pinned '{lock.pinned_model_version}', provider served '{observed_model_version}'"
            )

    if tool_name in lock.forbidden_tools:
        raise PostCompactionRuleViolationError(
            f"ARCBench Lock ({lock.lock_digest[:28]}): tool '{tool_name}' is forbidden across compaction boundaries."
        )

    if lock.allowed_tools and tool_name not in lock.allowed_tools:
        raise PostCompactionRuleViolationError(
            f"ARCBench Lock ({lock.lock_digest[:28]}): tool '{tool_name}' is outside post-compaction allowed_tools."
        )

    if tool_name in lock.pinned_arg_literals:
        expected_map = lock.pinned_arg_literals[tool_name]
        for arg_key, expected_val in expected_map.items():
            if arg_key not in tool_args:
                raise PostCompactionRuleViolationError(
                    f"ARCBench Lock ({lock.lock_digest[:28]}): tool '{tool_name}' required pinned "
                    f"argument '{arg_key}' missing after compaction."
                )
            actual_val = tool_args[arg_key]
            if not _strict_literal_equal(actual_val, expected_val):
                raise PostCompactionRuleViolationError(
                    f"ARCBench Lock ({lock.lock_digest[:28]}): tool '{tool_name}' argument '{arg_key}' "
                    f"drifted after compaction (expected {expected_val!r}, got {actual_val!r})."
                )

    for s_val in _iter_string_leaves(tool_args):
        for bad_prefix in lock.forbidden_path_prefixes:
            if _path_matches_prefix(s_val, bad_prefix):
                raise PostCompactionRuleViolationError(
                    f"ARCBench Lock ({lock.lock_digest[:28]}): argument value '{s_val}' violates "
                    f"post-compaction forbidden path prefix '{bad_prefix}'."
                )
