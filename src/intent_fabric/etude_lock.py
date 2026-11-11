# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""ETUDE Tool-Update Lock Registry, AST sink analyzer, and cross-invocation guard.

Pins both the RFC 8785 canonical JSON schema digest and normalized Python AST
structure + reachable capability sinks (net, subprocess, env, fs_write, dynamic_exec)
to close the ETUDE Tool Update Gap (arXiv:2611.01976) and cross-invocation
state accumulation (arXiv:2611.06585). Supports lockfile persistence
(`mcp-etude-lock.json`) and manifest-only pinning for non-Python MCP servers.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import math
import operator
import textwrap
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Set, Tuple, Union

SINK_CALL_PATTERNS: Dict[str, Tuple[str, ...]] = {
    "net": (
        "urllib.request",
        "urllib.parse",
        "http.client",
        "socket.",
        "requests.",
        "httpx.",
        "aiohttp.",
        "urlopen",
    ),
    "subprocess": (
        "subprocess.",
        "os.system",
        "os.popen",
        "os.spawn",
        "os.exec",
        "pty.spawn",
    ),
    "env": (
        "os.environ",
        "os.getenv",
    ),
    "fs_write": (
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.removedirs",
        "os.rename",
        "os.renames",
        "os.replace",
        "os.mkdir",
        "os.makedirs",
        "os.chmod",
        "os.chown",
        "shutil.rmtree",
        "shutil.move",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.copytree",
        "tempfile.",
        "Path.write_text",
        "Path.write_bytes",
        "Path.unlink",
        "Path.mkdir",
        "Path.touch",
        "Path.chmod",
        "Path.rename",
        "Path.replace",
        "Path.symlink_to",
        "Path.hardlink_to",
    ),
    "dynamic_exec": (
        "eval",
        "exec",
        "compile",
        "__import__",
        "builtins.__import__",
        "builtins.eval",
        "builtins.exec",
        "importlib.import_module",
        "ctypes.",
        "pickle.loads",
        "pickle.load",
        "marshal.loads",
        "marshal.load",
        "shelve.",
        "yaml.unsafe_load",
        "yaml.unsafe_load_all",
    ),
}

SINK_IMPORT_ROOTS: Dict[str, Tuple[str, ...]] = {
    "net": (
        "urllib",
        "urllib3",
        "http",
        "socket",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "smtplib",
    ),
    "subprocess": ("subprocess", "pty", "commands"),
    "fs_write": ("tempfile",),
    "dynamic_exec": ("ctypes", "pickle", "marshal", "shelve"),
}

_STAR_IMPORT_SINKS: Dict[str, Tuple[str, ...]] = {
    "os": ("env", "subprocess", "fs_write", "dynamic_exec"),
    "subprocess": ("subprocess",),
    "shutil": ("fs_write",),
    "tempfile": ("fs_write",),
    "urllib": ("net",),
    "urllib3": ("net",),
    "http": ("net",),
    "socket": ("net",),
    "requests": ("net",),
    "httpx": ("net",),
    "aiohttp": ("net",),
    "pty": ("subprocess",),
    "ctypes": ("dynamic_exec",),
    "pickle": ("dynamic_exec",),
    "marshal": ("dynamic_exec",),
    "shelve": ("dynamic_exec",),
}

_FS_WRITE_METHODS: Tuple[str, ...] = (
    "write_text",
    "write_bytes",
    "writelines",
    "unlink",
    "rmdir",
    "removedirs",
    "mkdir",
    "makedirs",
    "chmod",
    "chown",
    "touch",
    "symlink_to",
    "hardlink_to",
    "copy2",
    "copyfile",
    "copytree",
    "rmtree",
)
_DYNAMIC_EXEC_BUILTINS: Tuple[str, ...] = (
    "eval",
    "exec",
    "compile",
    "__import__",
    "getattr",
    "setattr",
    "delattr",
    "builtins.getattr",
    "builtins.setattr",
    "builtins.delattr",
    "builtins.__import__",
    "builtins.eval",
    "builtins.exec",
    "globals",
    "locals",
    "vars",
)


class ToolImplementationDriftError(PermissionError):
    """Raised when a tool implementation, schema, lockfile, or sink session drifts."""


@dataclass(frozen=True)
class ToolLockEntry:
    """Immutable cryptographic lock record for an MCP tool schema and implementation."""

    tool_name: str
    schema_sha256: str
    ast_normalized_sha256: str
    detected_sinks: Tuple[str, ...]
    allowed_sinks: Tuple[str, ...]
    source_pinned: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Serialize entry to a deterministic JSON-compatible mapping."""
        return {
            "tool_name": self.tool_name,
            "schema_sha256": self.schema_sha256,
            "ast_normalized_sha256": self.ast_normalized_sha256,
            "detected_sinks": list(self.detected_sinks),
            "allowed_sinks": list(self.allowed_sinks),
            "source_pinned": self.source_pinned,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ToolLockEntry:
        """Construct an entry from a serialized lock dictionary."""
        return cls(
            tool_name=str(data["tool_name"]),
            schema_sha256=str(data["schema_sha256"]),
            ast_normalized_sha256=str(data["ast_normalized_sha256"]),
            detected_sinks=tuple(str(s) for s in data.get("detected_sinks", ())),
            allowed_sinks=tuple(str(s) for s in data.get("allowed_sinks", ())),
            source_pinned=bool(data.get("source_pinned", True)),
        )


def _normalize_jcs(obj: Any) -> Any:
    """Recursively normalize strings (NFC), mappings, sequences, and JCS numbers."""
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError("RFC 8785 canonical JSON cannot encode NaN or Infinity.")
        if obj == 0.0:
            return 0
        if obj.is_integer():
            return int(obj)
        return obj
    if isinstance(obj, Mapping):
        return {unicodedata.normalize("NFC", str(k)): _normalize_jcs(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalize_jcs(x) for x in obj]
    return obj


def canonical_json_bytes(payload: Any) -> bytes:
    """Serialize payload into RFC 8785 (JCS) canonical UTF-8 JSON bytes."""
    normalized = _normalize_jcs(payload)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_schema_sha256(tool_name: str, description: str, input_schema: Mapping[str, Any]) -> str:
    """Compute SHA-256 hex digest over RFC 8785 canonicalized tool name, description, and schema."""
    envelope = {
        "description": unicodedata.normalize("NFC", description.strip()),
        "input_schema": _normalize_jcs(input_schema),
        "tool_name": unicodedata.normalize("NFC", tool_name),
    }
    return hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()


def dotted_name(node: ast.AST) -> str:
    """Resolve an ast.Name or ast.Attribute chain into a dotted identifier string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _resolve_alias(raw_name: str, alias_map: Mapping[str, str]) -> str:
    """Resolve leading imported identifier against module/symbol alias map."""
    if not raw_name:
        return ""
    parts = raw_name.split(".")
    if parts[0] in alias_map:
        resolved = alias_map[parts[0]]
        if operator.gt(len(parts), 1):
            return f"{resolved}.{'.'.join(parts[1:])}"
        return resolved
    return raw_name


def _match_sink_patterns(resolved: str, raw_target: str, sinks: Set[str]) -> None:
    """Add sink categories matched by a resolved identifier or call target."""
    if not resolved and not raw_target:
        return
    if resolved == "os.environ" or resolved.startswith("os.environ."):
        sinks.add("env")
    for sink_cat, patterns in SINK_CALL_PATTERNS.items():
        for pat in patterns:
            if pat.endswith("."):
                if resolved.startswith(pat):
                    sinks.add(sink_cat)
            elif resolved == pat or raw_target.endswith(f".{pat}"):
                sinks.add(sink_cat)


_VALID_OPEN_MODE_CHARS = frozenset("rwaxbt+U")
_PATH_CTORS = (
    "Path",
    "PosixPath",
    "WindowsPath",
    "pathlib.Path",
    "pathlib.PosixPath",
    "pathlib.WindowsPath",
)


def _mode_node_is_writable(mode_arg: ast.AST) -> bool:
    """Return True if an explicit open mode AST node is dynamic or writable."""
    if not isinstance(mode_arg, ast.Constant):
        return True
    return any(ch in str(mode_arg.value) for ch in ("w", "a", "x", "+"))


def _is_module_level_open(node: ast.Call, alias_map: Mapping[str, str]) -> bool:
    """Return True only for open(...), io.open(...), or builtins.open(...) calls."""
    if isinstance(node.func, ast.Name):
        return _resolve_alias(node.func.id, alias_map) in ("open", "io.open", "builtins.open")
    if isinstance(node.func, ast.Attribute) and node.func.attr == "open":
        prefix = dotted_name(node.func.value)
        if not prefix:
            return False
        return _resolve_alias(prefix, alias_map) in ("io", "builtins")
    return False


def _is_write_open_call(node: ast.Call, alias_map: Mapping[str, str] | None = None) -> bool:
    """Return True if an open(...) or Path.open(...) call uses a writable or dynamic mode."""
    aliases = alias_map or {}
    for kw in node.keywords:
        if kw.arg == "mode" and _mode_node_is_writable(kw.value):
            return True
    if not operator.lt(len(node.args), 2) and _mode_node_is_writable(node.args[1]):
        return True
    if (
        not _is_module_level_open(node, aliases)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "open"
        and len(node.args) == 1
    ):
        arg0 = node.args[0]
        if isinstance(node.func.value, ast.Call):
            ctor = dotted_name(node.func.value.func)
            resolved_ctor = _resolve_alias(ctor, aliases)
            if ctor in _PATH_CTORS or resolved_ctor in _PATH_CTORS:
                return _mode_node_is_writable(arg0)
        if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str) and arg0.value:
            if frozenset(arg0.value) <= _VALID_OPEN_MODE_CHARS:
                return any(ch in arg0.value for ch in ("w", "a", "x", "+"))
    return False


def analyze_python_tool_source(source_code: str) -> Tuple[str, Tuple[str, ...]]:
    """Compute normalized AST SHA-256 and sorted reachable capability sinks for Python source."""
    dedented = textwrap.dedent(source_code).strip()
    tree = ast.parse(dedented)
    normalized_ast = ast.dump(tree, annotate_fields=True, include_attributes=False)
    ast_sha256 = hashlib.sha256(normalized_ast.encode("utf-8")).hexdigest()

    sinks: Set[str] = set()
    alias_map: Dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound_name = alias.asname or alias.name
                alias_map[bound_name] = alias.name
                root_mod = alias.name.split(".")[0]
                for sink_cat, roots in SINK_IMPORT_ROOTS.items():
                    if root_mod in roots:
                        sinks.add(sink_cat)
        elif isinstance(node, ast.ImportFrom):
            mod_name = node.module or ""
            root_mod = mod_name.split(".")[0]
            for sink_cat, roots in SINK_IMPORT_ROOTS.items():
                if root_mod in roots:
                    sinks.add(sink_cat)
            for alias in node.names:
                if alias.name == "*":
                    sinks.update(_STAR_IMPORT_SINKS.get(root_mod, ("dynamic_exec",)))
                    continue
                bound_name = alias.asname or alias.name
                full_target = f"{mod_name}.{alias.name}" if mod_name else alias.name
                alias_map[bound_name] = full_target
                for sink_cat, patterns in SINK_CALL_PATTERNS.items():
                    if any(full_target.startswith(p.rstrip(".")) for p in patterns):
                        sinks.add(sink_cat)

    for node in ast.walk(tree):
        if isinstance(node, (ast.Attribute, ast.Name)):
            raw_dotted = dotted_name(node)
            resolved = _resolve_alias(raw_dotted, alias_map)
            if isinstance(node, ast.Attribute):
                _match_sink_patterns(resolved, raw_dotted, sinks)
            elif isinstance(node.ctx, ast.Load):
                _match_sink_patterns(resolved, raw_dotted, sinks)
                if resolved in _DYNAMIC_EXEC_BUILTINS:
                    sinks.add("dynamic_exec")

        if isinstance(node, ast.Call):
            raw_target = dotted_name(node.func)
            resolved_call = _resolve_alias(raw_target, alias_map)
            _match_sink_patterns(resolved_call, raw_target, sinks)

            if isinstance(node.func, ast.Attribute):
                if node.func.attr in _FS_WRITE_METHODS:
                    sinks.add("fs_write")
                elif node.func.attr == "open" and _is_write_open_call(node, alias_map):
                    sinks.add("fs_write")

            if _is_module_level_open(node, alias_map) and _is_write_open_call(node, alias_map):
                sinks.add("fs_write")

            if resolved_call in _DYNAMIC_EXEC_BUILTINS:
                sinks.add("dynamic_exec")

    return ast_sha256, tuple(sorted(sinks))


@dataclass
class CrossInvocationStateGuard:
    """Tracks cross-invocation sink accumulation across tool calls within a session."""

    forbidden_sink_pairs: Tuple[Tuple[str, str], ...] = (
        ("env", "net"),
        ("fs_write", "net"),
    )
    max_calls_per_tool: Optional[int] = None
    _session_sinks: Dict[str, Set[str]] = field(default_factory=dict)
    _tool_counts: Dict[Tuple[str, str], int] = field(default_factory=dict)

    def record_invocation(self, session_id: str, entry: ToolLockEntry) -> Tuple[str, ...]:
        """Record tool capability sinks for a session and fail closed on escalation pairs."""
        key = (session_id, entry.tool_name)
        next_count = self._tool_counts.get(key, 0) + 1
        if self.max_calls_per_tool is not None and operator.gt(next_count, self.max_calls_per_tool):
            raise ToolImplementationDriftError(
                f"Session '{session_id}' exceeded max call budget ({self.max_calls_per_tool}) "
                f"for tool '{entry.tool_name}'."
            )
        self._tool_counts[key] = next_count

        prior = set(self._session_sinks.get(session_id, set()))
        combined = prior | set(entry.detected_sinks)
        for sink_a, sink_b in self.forbidden_sink_pairs:
            if (sink_a in prior and sink_b in entry.detected_sinks) or (
                sink_b in prior and sink_a in entry.detected_sinks
            ):
                raise ToolImplementationDriftError(
                    f"Cross-invocation sink accumulation blocked in session '{session_id}': "
                    f"tool '{entry.tool_name}' bridged forbidden pair ({sink_a}, {sink_b})."
                )
            if sink_a in entry.detected_sinks and sink_b in entry.detected_sinks:
                raise ToolImplementationDriftError(
                    f"Cross-invocation sink accumulation blocked in session '{session_id}': "
                    f"tool '{entry.tool_name}' combines forbidden pair ({sink_a}, {sink_b})."
                )

        self._session_sinks[session_id] = combined
        return tuple(sorted(combined))


def _extract_source(fn_or_source: Any) -> str:
    return inspect.getsource(fn_or_source) if callable(fn_or_source) else str(fn_or_source)


def _analyze_tool_and_helpers(
    fn_or_source: Any,
    helper_sources: Sequence[Any] = (),
) -> Tuple[str, Tuple[str, ...]]:
    """Analyze primary tool implementation plus optional transitive helper sources."""
    primary_hash, primary_sinks = analyze_python_tool_source(_extract_source(fn_or_source))
    if not helper_sources:
        return primary_hash, primary_sinks
    sinks_union: Set[str] = set(primary_sinks)
    hash_parts = [primary_hash]
    for helper in helper_sources:
        h_hash, h_sinks = analyze_python_tool_source(_extract_source(helper))
        hash_parts.append(h_hash)
        sinks_union.update(h_sinks)
    composite_hash = hashlib.sha256(":".join(hash_parts).encode("utf-8")).hexdigest()
    return composite_hash, tuple(sorted(sinks_union))


@dataclass
class EtudeToolLockRegistry:
    """Registry that pins and verifies MCP tool schemas, AST locks, and lockfile persistence."""

    locks: Dict[str, ToolLockEntry] = field(default_factory=dict)

    def pin_tool(
        self,
        tool_name: str,
        description: str,
        input_schema: Mapping[str, Any],
        fn_or_source: Any = None,
        allowed_sinks: Optional[Sequence[str]] = None,
        *,
        helper_sources: Sequence[Any] = (),
    ) -> ToolLockEntry:
        """Pin a tool's canonical schema digest, optional Python AST digest, and allowed sinks."""
        schema_hash = compute_schema_sha256(tool_name, description, input_schema)
        if fn_or_source is None:
            ast_hash = "manifest-only"
            detected: Tuple[str, ...] = ()
            source_pinned = False
        else:
            ast_hash, detected = _analyze_tool_and_helpers(fn_or_source, helper_sources)
            source_pinned = True

        allowed = tuple(sorted(set(allowed_sinks))) if allowed_sinks is not None else detected
        undeclared = set(detected) - set(allowed)
        if undeclared:
            raise ToolImplementationDriftError(
                f"Tool '{tool_name}' contains undeclared capability sinks at pin time: {sorted(undeclared)}"
            )

        entry = ToolLockEntry(
            tool_name=tool_name,
            schema_sha256=schema_hash,
            ast_normalized_sha256=ast_hash,
            detected_sinks=detected,
            allowed_sinks=allowed,
            source_pinned=source_pinned,
        )
        self.locks[tool_name] = entry
        return entry

    def verify_tool(
        self,
        tool_name: str,
        description: str,
        input_schema: Mapping[str, Any],
        fn_or_source: Any = None,
        *,
        helper_sources: Sequence[Any] = (),
    ) -> ToolLockEntry:
        """Verify a tool matches its pinned schema, allowed sinks, and normalized AST digest."""
        if tool_name not in self.locks:
            raise ToolImplementationDriftError(
                f"Tool '{tool_name}' is not pinned in EtudeToolLockRegistry."
            )
        pinned = self.locks[tool_name]
        current_schema_hash = compute_schema_sha256(tool_name, description, input_schema)
        if current_schema_hash != pinned.schema_sha256:
            raise ToolImplementationDriftError(
                f"Tool '{tool_name}' schema drift detected: expected {pinned.schema_sha256[:12]}, got {current_schema_hash[:12]}"
            )

        if fn_or_source is None:
            if pinned.source_pinned:
                raise ToolImplementationDriftError(
                    f"Tool '{tool_name}' requires source/callable verification; manifest-only verification rejected."
                )
            return pinned

        current_ast_hash, current_sinks = _analyze_tool_and_helpers(fn_or_source, helper_sources)

        new_sinks = set(current_sinks) - set(pinned.allowed_sinks)
        if new_sinks:
            raise ToolImplementationDriftError(
                f"ETUDE Tool Update Gap blocked for '{tool_name}': silent implementation update added unauthorized sinks {sorted(new_sinks)}"
            )

        if pinned.source_pinned and current_ast_hash != pinned.ast_normalized_sha256:
            raise ToolImplementationDriftError(
                f"ETUDE Tool Update Gap blocked for '{tool_name}': implementation AST mutated while schema remained identical "
                f"(expected {pinned.ast_normalized_sha256[:12]}, got {current_ast_hash[:12]})"
            )

        return pinned

    def to_dict(self) -> Dict[str, Any]:
        """Serialize registry locks with an RFC 8785 lockfile integrity digest."""
        ordered_locks = {name: entry.to_dict() for name, entry in sorted(self.locks.items())}
        lockfile_sha256 = hashlib.sha256(canonical_json_bytes(ordered_locks)).hexdigest()
        return {
            "schema_version": "mcp-etude-lock-v1",
            "locks": ordered_locks,
            "lockfile_sha256": lockfile_sha256,
        }

    def save_lockfile(self, path: Union[str, Path]) -> Path:
        """Persist lock registry to a JSON lockfile."""
        target = Path(path)
        target.write_bytes(canonical_json_bytes(self.to_dict()))
        return target

    @classmethod
    def from_lockfile(
        cls, path_or_payload: Union[str, Path, Mapping[str, Any]]
    ) -> EtudeToolLockRegistry:
        """Load and verify lockfile integrity, raising ToolImplementationDriftError on tampering."""
        if isinstance(path_or_payload, Mapping):
            payload = dict(path_or_payload)
        else:
            payload = json.loads(Path(path_or_payload).read_text(encoding="utf-8"))

        raw_locks = payload.get("locks")
        if not isinstance(raw_locks, Mapping):
            raise ToolImplementationDriftError("Invalid ETUDE lockfile: missing 'locks' mapping.")

        ordered_locks = {str(k): dict(v) for k, v in sorted(raw_locks.items())}
        expected_sha = hashlib.sha256(canonical_json_bytes(ordered_locks)).hexdigest()
        actual_sha = payload.get("lockfile_sha256")
        if actual_sha != expected_sha:
            raise ToolImplementationDriftError(
                f"ETUDE lockfile integrity mismatch: expected {expected_sha[:12]}, got {actual_sha!r}."
            )

        locks = {name: ToolLockEntry.from_dict(entry) for name, entry in ordered_locks.items()}
        return cls(locks=locks)
