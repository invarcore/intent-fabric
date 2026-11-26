# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""ARCBench Post-Compaction Constraint Lock and Silent Model Route Drift Guard.

Binds compacted constraint slots (forbidden_tools, forbidden_path_prefixes,
pinned_arg_literals, and pinned_model_version) into an RFC 8785 canonical
@arcbench_lock:hmac-sha256 sidecar enforced deterministically at the pre-execution
tool boundary (arXiv:2611.03223 & EvalShift Model Deprecation Schedule).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import posixpath
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Iterable, Mapping
import unicodedata
import urllib.parse

_WIN_DRIVE_RE = re.compile(r"^[a-zA-Z]:(/|$)")
_FILE_URI_RE = re.compile(r"^file:(//[^/]*)?", re.IGNORECASE)
LOCK_DIGEST_PREFIX = "@arcbench_lock:sha256:"  # unkeyed content id (tamper-evident only)
LOCK_HMAC_PREFIX = "@arcbench_lock:hmac-sha256:"  # keyed (integrity vs an adversary)
LOCK_SCHEMA = "arcbench-compaction-lock-v3"

_UNSET = object()


class CompactionConstraintViolationError(RuntimeError):
    """Raised when a post-compaction tool call or state violates pinned constraints."""


PostCompactionRuleViolationError = CompactionConstraintViolationError


class SilentModelRouteDriftError(CompactionConstraintViolationError):
    """Raised when the post-compaction model version drifts from the pinned version."""


class CompactionLockTamperError(CompactionConstraintViolationError):
    """Raised when a CompactionConstraintLock digest does not match its fields."""


# ---------------------------------------------------------------------------
# FIX C1/C5: JSON-typed values. One type vocabulary shared by digest AND comparison.
# ---------------------------------------------------------------------------
def _type_tag(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return "str"
    if isinstance(v, (list, tuple)):
        return "list"  # tuples serialize to JSON arrays, so they must hash as lists
    if isinstance(v, Mapping):
        return "object"
    raise TypeError(f"Unsupported type in lock payload: {type(v).__name__}")


def _typed(v: Any) -> Any:
    """Recursively wrap values with type tags so 1 / True / 1.0 can never collide."""
    tag = _type_tag(v)
    if tag == "list":
        return {"t": tag, "v": [_typed(x) for x in v]}
    if tag == "object":
        if not all(isinstance(k, str) for k in v):
            raise TypeError("Lock payload objects must have string keys")
        return {"t": tag, "v": {k: _typed(x) for k, x in v.items()}}
    if tag == "float" and not math.isfinite(v):
        raise ValueError("Non-finite floats are not allowed in lock payloads")
    return {"t": tag, "v": v}


def _strict_equal(actual: Any, expected: Any) -> bool:
    """Deep equality that never treats True == 1 == 1.0, at any nesting depth."""
    try:
        ta, te = _type_tag(actual), _type_tag(expected)
    except TypeError:
        return False
    if ta != te:
        return False
    if ta == "list":
        return len(actual) == len(expected) and all(
            _strict_equal(a, e) for a, e in zip(actual, expected)
        )
    if ta == "object":
        return set(actual.keys()) == set(expected.keys()) and all(
            _strict_equal(actual[k], expected[k]) for k in expected
        )
    return actual == expected


def _deep_freeze_literals(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        return MappingProxyType({str(k): _deep_freeze_literals(v) for k, v in obj.items()})
    if isinstance(obj, (list, tuple)):
        return tuple(_deep_freeze_literals(x) for x in obj)
    return obj


def _canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


# ---------------------------------------------------------------------------
# FIX C2: path normalisation. String matching is DEFENCE IN DEPTH; the authority
# is resolve_and_check_path() at the point the tool opens the file.
# ---------------------------------------------------------------------------
def _strip_invisible(s: str) -> str:
    return "".join(ch for ch in s if unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Cn"))


def _normalize_one(s: str) -> str:
    s = s.replace("\\", "/")
    norm = posixpath.normpath(s) if s else ""
    if norm == ".":
        return ""
    if len(norm) > 1:
        norm = norm.rstrip("/")
    return norm


def _candidate_variants(raw: str, base_dir: str | None) -> list[str]:
    """All plausible interpretations of one string argument, casefolded (fail closed)."""
    s = raw.strip()
    for _ in range(5):  # bounded percent-decoding: %2Fetc%2Fpasswd, %252F...
        d = urllib.parse.unquote(s)
        if d == s:
            break
        s = d
    forms = {s}
    if "\x00" in s:
        for part in s.split("\x00"):
            if part:
                forms.add(part)
    s = unicodedata.normalize("NFKC", _strip_invisible(s))
    s = _FILE_URI_RE.sub("", s)
    if not s:
        return []
    forms.add(s)
    if s.startswith("~"):
        forms.add(os.path.expanduser(s))
    out: set[str] = set()
    for f in forms:
        f = f.replace("\\", "/")
        n = _normalize_one(f)
        if not n:
            continue
        out.add(n)
        if n.startswith("//"):  # POSIX: '//etc' == '/etc'; also keep UNC reading
            out.add("/" + n.lstrip("/"))
        if n.startswith("../") or n == "..":
            out.add("/" + re.sub(r"^(?:\.\./)+", "", n))
        if base_dir and not (n.startswith("/") or _WIN_DRIVE_RE.match(n)):
            out.add(_normalize_one(base_dir.replace("\\", "/") + "/" + n))
    return [v.casefold() for v in out]


def _forbidden_form(raw: str) -> str:
    cleaned = raw.strip().replace("\\", "/")
    if cleaned == "/":
        return "/"
    return _normalize_one(unicodedata.normalize("NFKC", cleaned)).casefold()


def _path_violates_prefix(candidates: list[str], forbidden_raw: str) -> bool:
    pref = _forbidden_form(forbidden_raw)
    if not pref:
        return False
    for cand in candidates:
        if pref == "/":
            if cand.startswith("/"):
                return True
        elif pref.startswith("/") or _WIN_DRIVE_RE.match(pref):
            if cand == pref or cand.startswith(pref.rstrip("/") + "/"):
                return True
        else:
            if (
                cand == pref
                or cand.startswith(pref + "/")
                or f"/{pref}/" in f"/{cand.lstrip('/')}/"
            ):
                return True
    return False


def resolve_and_check_path(
    path: str | os.PathLike[str],
    forbidden_roots: Iterable[str],
    *,
    base_dir: str | os.PathLike[str] | None = None,
) -> str:
    """AUTHORITATIVE check: call this in the tool executor right before open().
    Resolves symlinks and '..' on the real filesystem, then compares real paths.
    """
    resolved_base = os.fspath(base_dir) if base_dir else os.getcwd()
    real = os.path.realpath(os.path.join(resolved_base, os.fspath(path)))
    for root in forbidden_roots:
        r = os.path.realpath(root)
        if real == r or real.startswith(r.rstrip(os.sep) + os.sep):
            raise CompactionConstraintViolationError(
                f"Resolved path {real!r} is inside forbidden root {r!r}"
            )
    return real


def _iter_string_leaves(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, (bytes, bytearray)):
        yield bytes(obj).decode("utf-8", "surrogateescape")
    elif isinstance(obj, os.PathLike):
        yield from _iter_string_leaves(os.fspath(obj))
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            yield from _iter_string_leaves(k)
            yield from _iter_string_leaves(v)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for item in obj:
            yield from _iter_string_leaves(item)


def _to_key_bytes(key: Any) -> bytes | None:
    if key is None:
        return None
    if isinstance(key, str):
        return key.encode("utf-8")
    if isinstance(key, (bytes, bytearray)):
        return bytes(key)
    raise TypeError(f"Key must be str or bytes, got {type(key).__name__}")


@dataclass(frozen=True)
class CompactionConstraintLock:
    allowed_tools: tuple[str, ...]
    forbidden_tools: tuple[str, ...]
    forbidden_path_prefixes: tuple[str, ...]
    pinned_arg_literals: Mapping[str, Mapping[str, Any]]
    pinned_model_version: str | None
    lock_digest: str
    allow_any_tool: bool = (
        False  # FIX C3: empty allowed_tools now means "no tools", not "all tools"
    )
    compaction_epoch: int = 1

    @property
    def schema(self) -> str:
        return LOCK_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_tools", tuple(str(x) for x in self.allowed_tools))
        object.__setattr__(self, "forbidden_tools", tuple(str(x) for x in self.forbidden_tools))
        object.__setattr__(
            self, "forbidden_path_prefixes", tuple(str(x) for x in self.forbidden_path_prefixes)
        )

        frozen_outer: dict[str, Mapping[str, Any]] = {}
        for tool_name, arg_map in (self.pinned_arg_literals or {}).items():
            if not isinstance(arg_map, Mapping):
                raise TypeError(f"pinned_arg_literals[{tool_name!r}] must be a mapping")
            _typed(dict(arg_map))  # validates JSON-compatible, finite, string keys
            frozen_outer[str(tool_name)] = _deep_freeze_literals(dict(arg_map))
        object.__setattr__(self, "pinned_arg_literals", MappingProxyType(frozen_outer))

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": LOCK_SCHEMA,
            "allow_any_tool": bool(self.allow_any_tool),
            "allowed_tools": list(self.allowed_tools),
            "forbidden_tools": list(self.forbidden_tools),
            "forbidden_path_prefixes": list(self.forbidden_path_prefixes),
            "pinned_arg_literals": {
                k: {ak: _typed(av) for ak, av in sorted(v.items(), key=lambda i: str(i[0]))}
                for k, v in sorted(self.pinned_arg_literals.items(), key=lambda i: str(i[0]))
            },
            "pinned_model_version": self.pinned_model_version,
            "compaction_epoch": int(self.compaction_epoch),
        }

    def compute_expected_digest(self, key: bytes | str | None = None) -> str:
        k_bytes = _to_key_bytes(key)
        raw = _canonical_json_bytes(self._payload())
        if k_bytes is None:
            return f"{LOCK_DIGEST_PREFIX}{hashlib.sha256(raw).hexdigest()}"
        return f"{LOCK_HMAC_PREFIX}{hmac.new(k_bytes, raw, hashlib.sha256).hexdigest()}"

    def verify_integrity(self, key: bytes | str | None = None) -> None:
        """FIX C4: with a key, ONLY a keyed digest is accepted (no downgrade to bare SHA-256)."""
        if not isinstance(self.lock_digest, str):
            raise CompactionLockTamperError("lock_digest must be a string")
        k_bytes = _to_key_bytes(key)
        if k_bytes is not None and not self.lock_digest.startswith(LOCK_HMAC_PREFIX):
            raise CompactionLockTamperError(
                "Keyed verification requested but lock carries no HMAC digest"
            )
        if k_bytes is None and self.lock_digest.startswith(LOCK_HMAC_PREFIX):
            raise CompactionLockTamperError("Lock is HMAC-signed but no integrity key was supplied")
        expected = self.compute_expected_digest(k_bytes)
        if not hmac.compare_digest(self.lock_digest.encode(), expected.encode()):
            raise CompactionLockTamperError("integrity failure: compaction lock digest mismatch")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": LOCK_SCHEMA,
            "allow_any_tool": bool(self.allow_any_tool),
            "allowed_tools": list(self.allowed_tools),
            "forbidden_tools": list(self.forbidden_tools),
            "forbidden_path_prefixes": list(self.forbidden_path_prefixes),
            "pinned_arg_literals": {k: dict(v) for k, v in self.pinned_arg_literals.items()},
            "pinned_model_version": self.pinned_model_version,
            "lock_digest": self.lock_digest,
            "compaction_epoch": self.compaction_epoch,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        signing_key: bytes | str | None = None,
        key: bytes | str | None = None,
    ) -> CompactionConstraintLock:
        if data.get("schema") != LOCK_SCHEMA:
            raise CompactionLockTamperError(f"Unsupported lock schema {data.get('schema')!r}")
        lock = cls(
            allowed_tools=tuple(data.get("allowed_tools", ())),
            forbidden_tools=tuple(data.get("forbidden_tools", ())),
            forbidden_path_prefixes=tuple(data.get("forbidden_path_prefixes", ())),
            pinned_arg_literals=data.get("pinned_arg_literals", {}),
            pinned_model_version=data.get("pinned_model_version"),
            lock_digest=str(data.get("lock_digest", "")),
            allow_any_tool=bool(data.get("allow_any_tool", False)),
            compaction_epoch=int(data.get("compaction_epoch", 1)),
        )
        effective_key = signing_key if signing_key is not None else key
        lock.verify_integrity(effective_key)
        return lock

    @classmethod
    def from_json(
        cls,
        raw_json: str | bytes,
        *,
        signing_key: bytes | str | None = None,
        key: bytes | str | None = None,
    ) -> CompactionConstraintLock:
        parsed = json.loads(raw_json)
        if not isinstance(parsed, Mapping):
            raise CompactionLockTamperError("Serialized compaction lock must be a JSON object")
        return cls.from_dict(parsed, signing_key=signing_key, key=key)


def build_compaction_constraint_lock(
    compaction_epoch: int = 1,
    *,
    allowed_tools: Iterable[str] = (),
    forbidden_tools: Iterable[str] = (),
    forbidden_path_prefixes: Iterable[str] = (),
    pinned_arg_literals: Mapping[str, Mapping[str, Any]] | None = None,
    pinned_model_version: str | None = None,
    allow_any_tool: bool = False,
    signing_key: Any = _UNSET,
) -> CompactionConstraintLock:
    if signing_key is not _UNSET:
        k_bytes = _to_key_bytes(signing_key)
        if k_bytes is None or len(k_bytes.strip()) < 32:
            raise ValueError("signing_key must be at least 32 non-whitespace bytes")
    else:
        env_key = os.environ.get("COMPACTION_LOCK_SECRET")
        if env_key:
            k_bytes = env_key.encode("utf-8")
            if len(k_bytes.strip()) < 32:
                raise ValueError("COMPACTION_LOCK_SECRET must be at least 32 non-whitespace bytes")
        else:
            k_bytes = None

    provisional = CompactionConstraintLock(
        allowed_tools=tuple(sorted(set(str(x) for x in allowed_tools))),
        forbidden_tools=tuple(sorted(set(str(x) for x in forbidden_tools))),
        forbidden_path_prefixes=tuple(
            sorted(
                set(
                    _normalize_one(str(x)) if _normalize_one(str(x)) else str(x)
                    for x in forbidden_path_prefixes
                )
            )
        ),
        pinned_arg_literals=pinned_arg_literals or {},
        pinned_model_version=pinned_model_version,
        lock_digest="",
        allow_any_tool=allow_any_tool,
        compaction_epoch=compaction_epoch,
    )
    return CompactionConstraintLock(
        allowed_tools=provisional.allowed_tools,
        forbidden_tools=provisional.forbidden_tools,
        forbidden_path_prefixes=provisional.forbidden_path_prefixes,
        pinned_arg_literals=provisional.pinned_arg_literals,
        pinned_model_version=provisional.pinned_model_version,
        lock_digest=provisional.compute_expected_digest(k_bytes),
        allow_any_tool=allow_any_tool,
        compaction_epoch=compaction_epoch,
    )


def enforce_post_compaction_lock(
    lock: CompactionConstraintLock,
    tool_name: str = "",
    tool_args: Mapping[str, Any] | None = None,
    *,
    observed_model_version: str | None = None,
    require_model_version: bool
    | None = None,  # FIX C3: None => required whenever a version is pinned
    signing_key: Any = _UNSET,
    integrity_key: Any = _UNSET,
    base_dir: str | None = None,
) -> None:
    if not isinstance(lock, CompactionConstraintLock):
        raise CompactionLockTamperError(
            "Invalid lock instance passed to enforce_post_compaction_lock"
        )

    chosen_key = signing_key if signing_key is not _UNSET else integrity_key
    if chosen_key is not _UNSET:
        k_bytes = _to_key_bytes(chosen_key)
    else:
        env_key = os.environ.get("COMPACTION_LOCK_SECRET")
        k_bytes = env_key.encode("utf-8") if env_key else None

    lock.verify_integrity(k_bytes)

    args = tool_args if tool_args is not None else {}
    if not isinstance(args, Mapping):
        raise CompactionConstraintViolationError("tool_args must be a mapping")

    if lock.pinned_model_version is not None:
        must_have = True if require_model_version is None else require_model_version
        if observed_model_version is None:
            if must_have:
                raise SilentModelRouteDriftError(
                    f"Silent provider model swap suspected at epoch {lock.compaction_epoch}: "
                    f"Missing provider response.model_version; lock requires {lock.pinned_model_version!r}"
                )
        elif observed_model_version == "":
            raise SilentModelRouteDriftError(
                f"Silent provider model swap suspected at epoch {lock.compaction_epoch}: "
                f"empty model_version; lock requires {lock.pinned_model_version!r}"
            )
        elif observed_model_version != lock.pinned_model_version:
            raise SilentModelRouteDriftError(
                f"Silent provider model swap detected at epoch {lock.compaction_epoch}: "
                f"pinned {lock.pinned_model_version!r}, observed {observed_model_version!r}"
            )

    if tool_name in lock.forbidden_tools:
        raise CompactionConstraintViolationError(
            f"ARCBench Lock ({lock.lock_digest[:28]}): tool '{tool_name}' is forbidden across compaction boundaries."
        )
    if not lock.allow_any_tool and tool_name not in lock.allowed_tools:
        raise CompactionConstraintViolationError(
            f"ARCBench Lock ({lock.lock_digest[:28]}): tool '{tool_name}' is outside post-compaction allowed_tools."
        )

    if tool_name in lock.pinned_arg_literals:
        for arg_key, expected_val in lock.pinned_arg_literals[tool_name].items():
            if arg_key not in args:
                raise CompactionConstraintViolationError(
                    f"ARCBench Lock ({lock.lock_digest[:28]}): tool '{tool_name}' required pinned "
                    f"argument '{arg_key}' missing after compaction."
                )
            if not _strict_equal(args[arg_key], expected_val):  # FIX C1: deep, type-strict
                raise CompactionConstraintViolationError(
                    f"ARCBench Lock ({lock.lock_digest[:28]}): tool '{tool_name}' argument '{arg_key}' "
                    f"drifted after compaction (expected {expected_val!r}, got {args[arg_key]!r})."
                )

    if lock.forbidden_path_prefixes:
        for leaf in _iter_string_leaves(args):
            variants = _candidate_variants(leaf, base_dir)
            if not variants:
                continue
            for bad_prefix in lock.forbidden_path_prefixes:
                if _path_violates_prefix(variants, bad_prefix):
                    raise CompactionConstraintViolationError(
                        f"ARCBench Lock ({lock.lock_digest[:28]}): argument value '{leaf}' violates "
                        f"post-compaction forbidden path prefix '{bad_prefix}'."
                    )


def compaction_lock_to_dict(lock: CompactionConstraintLock) -> dict[str, Any]:
    return lock.to_dict()


def save_compaction_lock(
    lock: CompactionConstraintLock | Mapping[str, Any],
    file_path: str | os.PathLike[str],
) -> None:
    if isinstance(lock, CompactionConstraintLock):
        raw = lock.to_json()
    else:
        raw = json.dumps(lock, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    Path(file_path).write_text(raw, encoding="utf-8")


def load_compaction_lock(
    file_or_data: str | os.PathLike[str] | Mapping[str, Any],
    *,
    signing_key: bytes | str | None = None,
    key: bytes | str | None = None,
) -> CompactionConstraintLock:
    if isinstance(file_or_data, Mapping):
        return CompactionConstraintLock.from_dict(file_or_data, signing_key=signing_key, key=key)
    try:
        path_obj = Path(file_or_data)
        if path_obj.is_file():
            content = path_obj.read_text(encoding="utf-8")
            return CompactionConstraintLock.from_json(content, signing_key=signing_key, key=key)
    except Exception:
        pass
    if isinstance(file_or_data, (str, bytes)):
        return CompactionConstraintLock.from_json(file_or_data, signing_key=signing_key, key=key)
    raise TypeError(f"Expected file path or Mapping, got {type(file_or_data).__name__}")


def verify_compaction_lock_digest(
    lock: CompactionConstraintLock,
    *,
    key: bytes | str | None = None,
) -> bool:
    try:
        lock.verify_integrity(key)
        return True
    except CompactionLockTamperError:
        return False


__all__ = [
    "LOCK_DIGEST_PREFIX",
    "LOCK_HMAC_PREFIX",
    "LOCK_SCHEMA",
    "CompactionConstraintLock",
    "CompactionConstraintViolationError",
    "CompactionLockTamperError",
    "PostCompactionRuleViolationError",
    "SilentModelRouteDriftError",
    "build_compaction_constraint_lock",
    "compaction_lock_to_dict",
    "enforce_post_compaction_lock",
    "load_compaction_lock",
    "resolve_and_check_path",
    "save_compaction_lock",
    "verify_compaction_lock_digest",
]
