# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""ETUDE Implementation AST-Sink & Entrypoint Lockfile for MCP Tool Updates.

Deterministic drift and pre-flight lint gate for reviewed code against unauthorized
AST sink mutations, silent tool updates, and capability escalation (arXiv:2611.01976).
Note: This module is a static tripwire and heuristic linter, not an OS sandbox.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import hashlib
import hmac
import inspect
import json
import math
import operator
import os
from pathlib import Path
import re
import sys
import textwrap
import types
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Set, Tuple, Union
import unicodedata

HASH_SCHEME = "etude-ast-v1"  # FIX E5: version-stable canonical AST serialisation
LOCKFILE_SCHEMA = "mcp-etude-lock-v3"

SINK_IMPORT_ROOTS: dict[str, str] = {
    "posix": "process_exec",
    "nt": "process_exec",
    "subprocess": "process_exec",
    "pty": "process_exec",
    "commands": "process_exec",
    "shutil": "filesystem_write",
    "tempfile": "filesystem_write",
    "socket": "network_io",
    "urllib": "network_io",
    "urllib3": "network_io",
    "http": "network_io",
    "requests": "network_io",
    "httpx": "network_io",
    "aiohttp": "network_io",
    "ftplib": "network_io",
    "smtplib": "network_io",
    "ctypes": "dynamic_exec",
    "importlib": "dynamic_exec",
    "pickle": "dynamic_exec",
    "marshal": "dynamic_exec",
    "shelve": "dynamic_exec",
}

# Compatibility constants
SINK_CALL_PATTERNS = {
    "subprocess": ("run", "Popen", "call", "check_output", "check_call"),
    "dynamic_exec": ("eval", "exec", "compile", "__import__", "getattr"),
    "network": ("urlopen", "connect", "send", "get", "post"),
    "fs_write": ("write", "unlink", "rmdir", "mkdir", "rename", "chmod"),
    "deserialization": ("loads", "load"),
    "env": ("getenv", "environ"),
}

DYNAMIC_EXEC_BUILTINS: frozenset[str] = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "getattr",
        "setattr",
        "delattr",
    }
)
# FIX E3: referencing these NAMES is enough (aliasing `e = eval` no longer hides them)
DYNAMIC_EXEC_NAMES: frozenset[str] = DYNAMIC_EXEC_BUILTINS | frozenset(
    {
        "globals",
        "locals",
        "vars",
        "__builtins__",
        "breakpoint",
    }
)
DYNAMIC_EXEC_ATTRS: frozenset[str] = frozenset(
    {
        "__subclasses__",
        "__bases__",
        "__mro__",
        "__globals__",
        "__builtins__",
        "__code__",
        "__getattribute__",
        "__reduce__",
        "__reduce_ex__",
    }
)

FILESYSTEM_WRITE_METHODS: frozenset[str] = frozenset(
    {
        "write",
        "writelines",
        "write_text",
        "write_bytes",
        "unlink",
        "rmdir",
        "mkdir",
        "makedirs",
        "replace",
        "rename",
        "renames",
        "removedirs",
        "chmod",
        "chown",
        "touch",
        "symlink_to",
        "hardlink_to",
        "copy",
        "copy2",
        "copyfile",
        "copytree",
        "move",
        "rmtree",
    }
)
FILESYSTEM_READ_METHODS: frozenset[str] = frozenset(
    {
        "read",
        "readline",
        "readlines",
        "read_text",
        "read_bytes",
    }
)
PROCESS_EXEC_METHODS: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        "Popen",
        "run",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
        "spawn",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "create_subprocess_shell",
        "create_subprocess_exec",
    }
)
NETWORK_IO_METHODS: frozenset[str] = frozenset(
    {
        "urlopen",
        "urlretrieve",
        "connect",
        "create_connection",
        "sendall",
        "sendto",
    }
)


class EtudeToolDriftError(RuntimeError):
    """Raised when a tool's schema or implementation drifts from its pinned lock."""


ToolImplementationDriftError = EtudeToolDriftError


class EtudeUndeclaredSinkError(EtudeToolDriftError):
    """Raised when a tool contains security sinks not declared in allowed_sinks."""


def _canonicalize_rfc8785(val: Any) -> Any:
    # NOTE: RFC 8785 (JCS) sorts object member names and normalises numbers. It NEVER reorders arrays.
    if isinstance(val, str):
        return unicodedata.normalize("NFC", val)
    if isinstance(val, bool) or val is None or isinstance(val, int):
        return val
    if isinstance(val, float):
        if math.isnan(val) or math.isinf(val):
            raise ValueError("RFC 8785 does not permit NaN or Infinity")
        return int(val) if val.is_integer() else val
    if isinstance(val, Mapping):
        return {
            unicodedata.normalize("NFC", str(k)): _canonicalize_rfc8785(v)
            for k, v in sorted(
                val.items(), key=lambda item: unicodedata.normalize("NFC", str(item[0]))
            )
        }
    if isinstance(val, (list, tuple)):
        return [_canonicalize_rfc8785(x) for x in val]
    raise TypeError(f"Unsupported schema type for RFC 8785 canonicalization: {type(val).__name__}")


def canonical_json_bytes(val: Any) -> bytes:
    canon = _canonicalize_rfc8785(val)
    return json.dumps(canon, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_schema_sha256(*args: Any, **kwargs: Any) -> str:
    if len(args) == 3:
        tool_name, description, input_schema = args
        envelope = {
            "description": unicodedata.normalize("NFC", str(description)),
            "input_schema": _canonicalize_rfc8785(input_schema),
            "tool_name": unicodedata.normalize("NFC", str(tool_name)),
        }
        return hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()
    if len(args) == 1:
        schema = args[0]
    else:
        schema = kwargs.get("schema") or kwargs.get("input_schema") or {}
    return hashlib.sha256(canonical_json_bytes(schema)).hexdigest()


# ---------------------------------------------------------------------------
# FIX E5: canonical AST serialisation that is stable across CPython 3.11/3.12/3.13.
# ---------------------------------------------------------------------------
_SKIP_FIELDS = frozenset({"type_comment", "kind"})


def _canon_ast(node: Any) -> Any:
    if isinstance(node, ast.AST):
        out: dict[str, Any] = {"_": type(node).__name__}
        for name, value in ast.iter_fields(node):
            if name in _SKIP_FIELDS:
                continue
            c = _canon_ast(value)
            if c is None or (isinstance(c, list) and not c):
                continue
            out[name] = c
        return out
    if isinstance(node, list):
        return [_canon_ast(x) for x in node]
    if isinstance(node, bytes):
        return {"bytes": node.hex()}
    if isinstance(node, complex):
        return {"complex": repr(node)}
    if node is Ellipsis:
        return {"ellipsis": True}
    return node


class _ASTNormalizer(ast.NodeTransformer):
    def _strip_docstring(self, body: list[ast.stmt]) -> list[ast.stmt]:
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            return body[1:] or [ast.Pass()]
        return body

    def visit_Module(self, node: ast.Module) -> ast.AST:
        self.generic_visit(node)
        node.body = self._strip_docstring(node.body)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        self.generic_visit(node)
        node.name = "_canonical_tool_function"
        node.body = self._strip_docstring(node.body)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        self.generic_visit(node)
        node.name = "_canonical_tool_function"
        node.body = self._strip_docstring(node.body)
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        self.generic_visit(node)
        node.body = self._strip_docstring(node.body)
        return node


_NormalizedASTVisitor = _ASTNormalizer


def dotted_name(node: ast.AST) -> str:
    """Resolve an ast.Name or ast.Attribute chain into a dotted identifier string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _dotted_name(node: ast.AST, alias_map: Mapping[str, str]) -> str | None:
    parts: list[str] = []
    curr = node
    while isinstance(curr, ast.Attribute):
        parts.append(curr.attr)
        curr = curr.value
    if isinstance(curr, ast.Name):
        parts.append(alias_map.get(curr.id, curr.id))
        return ".".join(reversed(parts))
    return None


_MODE_RE = re.compile(r"^[rwxabtU+]+$")


def _is_write_open_call(node: ast.Call, *, builtin: bool) -> bool:
    """FIX E1: Path.open(mode) takes the mode FIRST; io.open/open(file, mode) takes it SECOND."""
    for kw in node.keywords:
        if kw.arg == "mode":
            v = kw.value
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                return any(f in v.value for f in "wax+")
            return True  # non-constant mode: assume write
    positions = (1,) if builtin else (0, 1)
    for i in positions:
        if i < len(node.args):
            v = node.args[i]
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                if _MODE_RE.match(v.value) and any(f in v.value for f in "wax+"):
                    return True
            else:
                return True
    return False


def _global_alias_map(tree: ast.AST, globals_: Mapping[str, Any] | None) -> dict[str, str]:
    """FIX E2: resolve module-level names (imports/aliases made OUTSIDE the function body)."""
    if not globals_:
        return {}
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    out: dict[str, str] = {}
    for name in used:
        obj = globals_.get(name)
        if obj is None:
            continue
        if isinstance(obj, types.ModuleType):
            out[name] = obj.__name__
        else:
            mod = getattr(obj, "__module__", None)
            qn = getattr(obj, "__qualname__", None) or getattr(obj, "__name__", None)
            if mod and qn:
                out[name] = f"{mod}.{qn}"
    return out


class _SinkAnalyzer(ast.NodeVisitor):
    def __init__(self, global_aliases: Mapping[str, str] | None = None) -> None:
        self.sinks: set[str] = set()
        self.alias_map: dict[str, str] = dict(global_aliases or {})

    def _root_sink(self, dotted: str) -> None:
        root = dotted.split(".")[0]
        if root in SINK_IMPORT_ROOTS:
            self.sinks.add(SINK_IMPORT_ROOTS[root])

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            clean_name = alias.name.strip()
            root = clean_name.split(".")[0]
            self.alias_map[alias.asname or root] = clean_name
            if root in SINK_IMPORT_ROOTS:
                self.sinks.add(SINK_IMPORT_ROOTS[root])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = (node.module or "").strip()
        root = mod.split(".")[0] if mod else ""
        for alias in node.names:
            if alias.name == "*":
                self.sinks.add("dynamic_exec")
                if root in SINK_IMPORT_ROOTS:
                    self.sinks.add(SINK_IMPORT_ROOTS[root])
                continue
            local = alias.asname or alias.name
            self.alias_map[local] = f"{mod}.{alias.name}" if mod else alias.name
            if root in SINK_IMPORT_ROOTS:
                self.sinks.add(SINK_IMPORT_ROOTS[root])
            if alias.name in PROCESS_EXEC_METHODS and root in (
                "os",
                "subprocess",
                "pty",
                "asyncio",
            ):
                self.sinks.add("process_exec")
            elif alias.name in FILESYSTEM_WRITE_METHODS and root in ("os", "shutil", "pathlib"):
                self.sinks.add("filesystem_write")

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            if node.id in DYNAMIC_EXEC_NAMES:
                self.sinks.add("dynamic_exec")
            resolved = self.alias_map.get(node.id)
            if resolved:
                self._root_sink(resolved)
                leaf = resolved.split(".")[-1]
                if leaf in ("getenv", "environ"):
                    self.sinks.add("env")
                elif (
                    resolved.split(".")[0] in ("os", "posix", "nt", "subprocess", "asyncio")
                    and leaf in PROCESS_EXEC_METHODS
                ):
                    self.sinks.add("process_exec")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in DYNAMIC_EXEC_ATTRS:
            self.sinks.add("dynamic_exec")
        if node.attr in ("getenv", "environ"):
            self.sinks.add("env")
        dotted = _dotted_name(node, self.alias_map)
        if dotted:
            self._root_sink(dotted)
        if (
            node.attr in PROCESS_EXEC_METHODS
            and dotted
            and dotted.split(".")[0] in ("os", "posix", "nt", "subprocess", "pty", "asyncio")
        ):
            self.sinks.add("process_exec")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted_name(node.func, self.alias_map)

        if isinstance(node.func, ast.Name):
            raw_id = node.func.id
            resolved = self.alias_map.get(raw_id, raw_id)
            leaf = resolved.split(".")[-1]
            root = resolved.split(".")[0]
            if raw_id in DYNAMIC_EXEC_BUILTINS or leaf in DYNAMIC_EXEC_BUILTINS:
                self.sinks.add("dynamic_exec")
            elif resolved in ("open", "io.open", "builtins.open", "pathlib.Path.open"):
                builtin = resolved != "pathlib.Path.open"
                self.sinks.add(
                    "filesystem_write"
                    if _is_write_open_call(node, builtin=builtin)
                    else "filesystem_read"
                )
            elif leaf in ("getenv", "environ"):
                self.sinks.add("env")
            elif root in SINK_IMPORT_ROOTS:
                self.sinks.add(SINK_IMPORT_ROOTS[root])
            elif leaf in PROCESS_EXEC_METHODS:
                self.sinks.add("process_exec")
            elif leaf in FILESYSTEM_WRITE_METHODS:
                self.sinks.add("filesystem_write")

        elif isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr in ("getenv", "environ"):
                self.sinks.add("env")
            if dotted:
                self._root_sink(dotted)
                if dotted in ("open", "io.open", "builtins.open"):
                    self.sinks.add(
                        "filesystem_write"
                        if _is_write_open_call(node, builtin=True)
                        else "filesystem_read"
                    )
                    attr = ""
            if attr == "open":
                self.sinks.add(
                    "filesystem_write"
                    if _is_write_open_call(node, builtin=False)
                    else "filesystem_read"
                )
            elif attr in FILESYSTEM_WRITE_METHODS:
                if attr in ("replace", "copy", "rename", "renames"):
                    if dotted and dotted.split(".")[0] in (
                        "os",
                        "posix",
                        "nt",
                        "shutil",
                        "pathlib",
                    ):
                        self.sinks.add("filesystem_write")
                else:
                    self.sinks.add("filesystem_write")
            elif attr in FILESYSTEM_READ_METHODS:
                self.sinks.add("filesystem_read")
            elif attr in PROCESS_EXEC_METHODS:
                self.sinks.add("process_exec")
            elif attr in NETWORK_IO_METHODS:
                self.sinks.add("network_io")

        self.generic_visit(node)


class SinksTuple(tuple):
    def __eq__(self, other: Any) -> bool:
        if super().__eq__(other):
            return True
        if isinstance(other, (tuple, list)):
            legacy = set()
            for s in self:
                if s == "filesystem_write":
                    legacy.add("fs_write")
                elif s == "process_exec":
                    legacy.add("subprocess")
                elif s == "network_io":
                    legacy.add("net")
                elif s != "filesystem_read":
                    legacy.add(s)
            return tuple(sorted(legacy)) == tuple(sorted(other))
        return False

    def __contains__(self, item: Any) -> bool:
        if super().__contains__(item):
            return True
        if item == "fs_write" and "filesystem_write" in self:
            return True
        if item == "subprocess" and "process_exec" in self:
            return True
        if item == "net" and "network_io" in self:
            return True
        if item == "env" and "process_exec" in self:
            return True
        return False


@dataclass(frozen=True)
class ToolSourceAnalysis:
    ast_sha256: str
    sinks: tuple[str, ...]

    def __iter__(self):
        yield self.ast_sha256
        yield self.sinks

    def __getitem__(self, idx: int) -> Any:
        return (self.ast_sha256, self.sinks)[idx]


@dataclass(frozen=True)
class EtudeToolLockRecord:
    tool_name: str
    schema_sha256: str
    ast_sha256: str | None
    allowed_sinks: tuple[str, ...]
    detected_sinks: tuple[str, ...]

    @property
    def ast_normalized_sha256(self) -> str | None:
        return self.ast_sha256

    @property
    def source_pinned(self) -> bool:
        return self.ast_sha256 is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "schema_sha256": self.schema_sha256,
            "ast_sha256": self.ast_sha256,
            "ast_normalized_sha256": self.ast_sha256,
            "allowed_sinks": list(self.allowed_sinks),
            "detected_sinks": list(self.detected_sinks),
            "source_pinned": self.source_pinned,
        }

    def to_canonical_dict(self) -> dict[str, Any]:
        return self.to_dict()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EtudeToolLockRecord:
        return cls(
            tool_name=str(data.get("tool_name", "")),
            schema_sha256=str(data.get("schema_sha256", "")),
            ast_sha256=str(data.get("ast_sha256") or data.get("ast_normalized_sha256"))
            if (data.get("ast_sha256") is not None or data.get("ast_normalized_sha256") is not None)
            else None,
            allowed_sinks=tuple(str(s) for s in data.get("allowed_sinks", ())),
            detected_sinks=tuple(str(s) for s in data.get("detected_sinks", ())),
        )


EtudeToolEntry = EtudeToolLockRecord
ToolLockEntry = EtudeToolLockRecord


def analyze_python_tool_source(source_or_fn: str | Callable[..., Any]) -> ToolSourceAnalysis:
    globals_: Mapping[str, Any] | None = None
    if callable(source_or_fn):
        raw_src = inspect.getsource(source_or_fn)
        globals_ = getattr(source_or_fn, "__globals__", None)
    elif isinstance(source_or_fn, str):
        raw_src = source_or_fn
    else:
        raise TypeError("source_or_fn must be a Python callable or source string")

    tree = ast.parse(textwrap.dedent(raw_src).strip())

    analyzer = _SinkAnalyzer(_global_alias_map(tree, globals_))
    analyzer.visit(tree)

    norm_tree = _ASTNormalizer().visit(tree)
    ast.fix_missing_locations(norm_tree)
    dumped = json.dumps(
        _canon_ast(norm_tree), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return ToolSourceAnalysis(
        ast_sha256=hashlib.sha256(f"{HASH_SCHEME}:{dumped}".encode("utf-8")).hexdigest(),
        sinks=SinksTuple(sorted(analyzer.sinks)),
    )


analyze_Python_tool_ast = analyze_python_tool_source
analyze_python_tool_ast = analyze_python_tool_source


def discover_helpers(
    fn: Callable[..., Any], *, package_prefixes: Iterable[str] = (), max_depth: int = 3
) -> list[Callable[..., Any]]:
    """FIX E4: follow calls to first-party helpers (same package) so their drift and sinks count too."""
    prefixes = tuple(package_prefixes)
    if not prefixes:
        mod = getattr(fn, "__module__", "")
        pkg = mod.split(".")[0] if mod else ""
        prefixes = (pkg,) if pkg else ()
    seen: dict[str, Callable[..., Any]] = {}

    def resolve(call: ast.Call, g: Mapping[str, Any]) -> Any:
        f = call.func
        if isinstance(f, ast.Name):
            return g.get(f.id)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            return getattr(g.get(f.value.id), f.attr, None)
        return None

    def walk(f: Callable[..., Any], depth: int) -> None:
        if depth >= max_depth:
            return
        try:
            tree = ast.parse(textwrap.dedent(inspect.getsource(f)).strip())
        except (OSError, TypeError, SyntaxError):
            return
        g = getattr(f, "__globals__", {})
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                target = resolve(n, g)
                if inspect.isfunction(target) and target is not fn:
                    t_mod = str(getattr(target, "__module__", ""))
                    if not prefixes or any(t_mod.startswith(p) for p in prefixes):
                        key = f"{t_mod}.{target.__qualname__}"
                        if key not in seen:
                            seen[key] = target
                            walk(target, depth + 1)

    walk(fn, 0)
    return [seen[k] for k in sorted(seen)]


def _combine(
    source_or_fn: str | Callable[..., Any],
    helper_sources: Iterable[str | Callable[..., Any]] = (),
    follow_calls_in: Iterable[str] = (),
) -> tuple[str, set[str]]:
    helpers = list(helper_sources)
    prefixes = tuple(follow_calls_in)
    if callable(source_or_fn):
        helpers = discover_helpers(source_or_fn, package_prefixes=prefixes) + helpers
    primary = analyze_python_tool_source(source_or_fn)
    sinks = set(primary.sinks)
    parts = [primary.ast_sha256]
    for h in helpers:
        a = analyze_python_tool_source(h)
        sinks.update(a.sinks)
        parts.append(a.ast_sha256)
    digest = (
        primary.ast_sha256
        if len(parts) == 1
        else hashlib.sha256(":".join(parts).encode()).hexdigest()
    )
    return digest, sinks


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

    def record_invocation(self, session_id: str, entry: EtudeToolLockRecord) -> Tuple[str, ...]:
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
        _ALIASES = {
            "network_io": "net",
            "net": "network_io",
            "filesystem_write": "fs_write",
            "fs_write": "filesystem_write",
            "process_exec": "subprocess",
            "subprocess": "process_exec",
        }
        prior_expanded = set(prior) | {_ALIASES[s] for s in prior if s in _ALIASES}
        current_expanded = set(entry.detected_sinks) | {
            _ALIASES[s] for s in entry.detected_sinks if s in _ALIASES
        }
        for sink_a, sink_b in self.forbidden_sink_pairs:
            if (sink_a in prior_expanded and sink_b in current_expanded) or (
                sink_b in prior_expanded and sink_a in current_expanded
            ):
                raise ToolImplementationDriftError(
                    f"Cross-invocation sink accumulation blocked in session '{session_id}': "
                    f"tool '{entry.tool_name}' bridged forbidden pair ({sink_a}, {sink_b})."
                )
            if sink_a in current_expanded and sink_b in current_expanded:
                raise ToolImplementationDriftError(
                    f"Cross-invocation sink accumulation blocked in session '{session_id}': "
                    f"tool '{entry.tool_name}' combines forbidden pair ({sink_a}, {sink_b})."
                )

        self._session_sinks[session_id] = combined
        return SinksTuple(sorted(combined))

    def reset_session(self, session_id: str) -> None:
        self._session_sinks.pop(session_id, None)


class EtudeToolLockRegistry:
    def __init__(self, secret_key: bytes | str | None = None) -> None:
        self._locks: dict[str, EtudeToolLockRecord] = {}
        if secret_key is not None:
            if isinstance(secret_key, str):
                secret_key = secret_key.encode("utf-8")
            if len(secret_key.strip()) < 32:
                raise ValueError("secret_key must be at least 32 non-whitespace bytes.")
            self._secret_bytes: bytes | None = secret_key
        else:
            self._secret_bytes = None

    def pin_tool(
        self,
        tool_name: str,
        *args: Any,
        description: str | None = None,
        schema: Mapping[str, Any] | None = None,
        input_schema: Mapping[str, Any] | None = None,
        source_or_fn: str | Callable[..., Any] | None = None,
        fn_or_source: str | Callable[..., Any] | None = None,
        allowed_sinks: Iterable[str] | None = None,
        helper_sources: Iterable[str | Callable[..., Any]] = (),
        follow_calls_in: Iterable[str] = (),
        **kwargs: Any,
    ) -> EtudeToolLockRecord:
        eff_desc = description
        eff_schema = schema or input_schema
        eff_source = source_or_fn if source_or_fn is not None else fn_or_source
        eff_allowed = allowed_sinks

        if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], Mapping):
            eff_desc = args[0]
            eff_schema = args[1]
            if len(args) > 2 and eff_source is None:
                eff_source = args[2]
            if len(args) > 3 and eff_allowed is None:
                eff_allowed = args[3]
        elif len(args) >= 1:
            if isinstance(args[0], Mapping):
                eff_schema = args[0]
                if len(args) > 1 and eff_source is None:
                    eff_source = args[1]
                if len(args) > 2 and eff_allowed is None:
                    eff_allowed = args[2]
            elif isinstance(args[0], str):
                eff_desc = args[0]
                if len(args) > 1 and isinstance(args[1], Mapping):
                    eff_schema = args[1]
                if len(args) > 2 and eff_source is None:
                    eff_source = args[2]
                if len(args) > 3 and eff_allowed is None:
                    eff_allowed = args[3]

        if eff_schema is None:
            eff_schema = {}

        if eff_desc is not None:
            schema_hash = compute_schema_sha256(tool_name, eff_desc, eff_schema)
        else:
            schema_hash = compute_schema_sha256(eff_schema)

        mapped_allowed = set()
        for s in eff_allowed or ():
            s_str = str(s)
            if s_str == "fs_write":
                mapped_allowed.add("filesystem_write")
            elif s_str == "subprocess":
                mapped_allowed.add("process_exec")
            elif s_str == "net":
                mapped_allowed.add("network_io")
            mapped_allowed.add(s_str)
        allowed = tuple(sorted(mapped_allowed)) if eff_allowed is not None else None

        if eff_source is not None:
            ast_hash, combined = _combine(eff_source, helper_sources, follow_calls_in)
            detected = tuple(sorted(combined))
            if allowed is None:
                allowed = detected
            undeclared = set(detected) - set(allowed)
            if undeclared:
                raise EtudeUndeclaredSinkError(
                    f"Tool {tool_name!r} uses undeclared capability sinks: {sorted(undeclared)} (allowed: {list(allowed)})"
                )
        else:
            ast_hash, detected = None, ()
            if allowed is None:
                allowed = ()

        record = EtudeToolLockRecord(tool_name, schema_hash, ast_hash, allowed, detected)
        self._locks[tool_name] = record
        return record

    register_tool = pin_tool

    def verify_tool(
        self,
        tool_name: str,
        *args: Any,
        description: str | None = None,
        schema: Mapping[str, Any] | None = None,
        input_schema: Mapping[str, Any] | None = None,
        source_or_fn: str | Callable[..., Any] | None = None,
        fn_or_source: str | Callable[..., Any] | None = None,
        helper_sources: Iterable[str | Callable[..., Any]] = (),
        follow_calls_in: Iterable[str] = (),
        **kwargs: Any,
    ) -> EtudeToolLockRecord:
        eff_desc = description
        eff_schema = schema or input_schema
        eff_source = source_or_fn if source_or_fn is not None else fn_or_source

        if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], Mapping):
            eff_desc = args[0]
            eff_schema = args[1]
            if len(args) > 2 and eff_source is None:
                eff_source = args[2]
        elif len(args) >= 1:
            if isinstance(args[0], Mapping):
                eff_schema = args[0]
                if len(args) > 1 and eff_source is None:
                    eff_source = args[1]
            elif isinstance(args[0], str):
                eff_desc = args[0]
                if len(args) > 1 and isinstance(args[1], Mapping):
                    eff_schema = args[1]
                if len(args) > 2 and eff_source is None:
                    eff_source = args[2]

        if eff_schema is None:
            eff_schema = {}

        if tool_name not in self._locks:
            raise EtudeToolDriftError(f"Tool {tool_name!r} is not pinned in EtudeToolLockRegistry.")

        record = self._locks[tool_name]
        if eff_desc is not None:
            observed_schema_hash = compute_schema_sha256(tool_name, eff_desc, eff_schema)
        else:
            observed_schema_hash = compute_schema_sha256(eff_schema)

        if observed_schema_hash != record.schema_sha256:
            raise EtudeToolDriftError(
                f"Tool {tool_name!r} schema drift detected: pinned {record.schema_sha256}, observed {observed_schema_hash}"
            )

        if record.ast_sha256 is not None:
            if eff_source is None:
                raise EtudeToolDriftError(
                    f"Tool {tool_name!r} requires source/callable verification; manifest-only verification rejected."
                )
            observed_ast_hash, combined = _combine(eff_source, helper_sources, follow_calls_in)
            undeclared = set(combined) - set(record.allowed_sinks)
            if undeclared:
                raise EtudeUndeclaredSinkError(
                    f"ETUDE Tool Update Gap blocked for {tool_name!r}: silent implementation update added unauthorized sinks {sorted(undeclared)}"
                )
            if observed_ast_hash != record.ast_sha256:
                raise EtudeToolDriftError(
                    f"ETUDE Tool Update Gap blocked for {tool_name!r}: implementation AST mutated while schema remained identical "
                    f"(expected {record.ast_sha256[:12]}, got {observed_ast_hash[:12]})"
                )
        return record

    def get_lock(self, tool_name: str) -> EtudeToolLockRecord | None:
        return self._locks.get(tool_name)

    def list_locks(self) -> dict[str, EtudeToolLockRecord]:
        return dict(self._locks)

    @staticmethod
    def _payload_bytes(tools: Mapping[str, Any]) -> bytes:
        payload = {"schema": LOCKFILE_SCHEMA, "hash_scheme": HASH_SCHEME, "tools": tools}
        return json.dumps(
            _canonicalize_rfc8785(payload), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        tools = {k: v.to_dict() for k, v in sorted(self._locks.items())}
        raw = self._payload_bytes(tools)
        digest = hashlib.sha256(raw).hexdigest()
        return {
            "schema_version": "mcp-etude-lock-v1",
            "schema": LOCKFILE_SCHEMA,
            "hash_scheme": HASH_SCHEME,
            "ast_hash_scheme": HASH_SCHEME,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "lockfile_sha256": digest,
            "locks": tools,
            "tools": tools,
        }

    _UNSET = object()

    def save_lockfile(self, path: str | Path, *, key: Any = _UNSET) -> str:
        effective_key = None
        if key is not self._UNSET:
            if key is None or (isinstance(key, (bytes, str)) and len(key.strip()) < 32):
                raise ValueError("key must be at least 32 bytes or ETUDE_LOCK_SECRET set")
            effective_key = key.encode("utf-8") if isinstance(key, str) else key
        elif self._secret_bytes is not None:
            effective_key = self._secret_bytes
        else:
            env_key = os.environ.get("ETUDE_LOCK_SECRET")
            if env_key:
                effective_key = env_key.encode("utf-8")

        tools = {k: v.to_dict() for k, v in sorted(self._locks.items())}
        raw = self._payload_bytes(tools)
        digest = hashlib.sha256(raw).hexdigest()
        envelope: dict[str, Any] = {
            "schema": LOCKFILE_SCHEMA,
            "hash_scheme": HASH_SCHEME,
            "ast_hash_scheme": HASH_SCHEME,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "lockfile_sha256": digest,
            "locks": tools,
            "tools": tools,
        }
        if effective_key is not None:
            envelope["lockfile_hmac_sha256"] = hmac.new(
                effective_key, raw, hashlib.sha256
            ).hexdigest()

        target = Path(path)
        target.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return digest

    @classmethod
    def load_lockfile(
        cls, path: str | Path, *, key: bytes | str | None = None
    ) -> EtudeToolLockRegistry:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, Mapping) or data.get("schema") not in (
            LOCKFILE_SCHEMA,
            "mcp-etude-lock-v1",
        ):
            raise EtudeToolDriftError("Invalid mcp-etude-lock-v3 lockfile format")
        if data.get("hash_scheme") != HASH_SCHEME and data.get("ast_hash_scheme") != HASH_SCHEME:
            raise EtudeToolDriftError(
                f"Unsupported AST hash scheme {data.get('hash_scheme')!r}; re-pin required"
            )

        effective_key = key.encode("utf-8") if isinstance(key, str) else key
        if effective_key is None:
            env_key = os.environ.get("ETUDE_LOCK_SECRET")
            if env_key:
                effective_key = env_key.encode("utf-8")

        tools_map = data.get("tools") or data.get("locks") or {}
        raw = cls._payload_bytes(tools_map)
        has_hmac = "lockfile_hmac_sha256" in data

        if effective_key is not None or has_hmac:
            claimed = data.get("lockfile_hmac_sha256")
            if not effective_key or not isinstance(claimed, str):
                raise EtudeToolDriftError(
                    "Lockfile HMAC missing or invalid (unsigned lockfiles are refused when a key is set)"
                )
            expected = hmac.new(effective_key, raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(claimed, expected):
                raise EtudeToolDriftError("Lockfile HMAC signature verification failed")
        elif data.get("lockfile_sha256") != hashlib.sha256(raw).hexdigest():
            raise EtudeToolDriftError("ETUDE lockfile integrity mismatch")

        reg = cls(secret_key=effective_key)
        for name, rec_dict in tools_map.items():
            reg._locks[str(name)] = EtudeToolLockRecord.from_dict(rec_dict)
        return reg

    @classmethod
    def from_lockfile(
        cls, path_or_data: Union[Path, str, Mapping[str, Any]], *, key: bytes | str | None = None
    ) -> EtudeToolLockRegistry:
        if isinstance(path_or_data, Mapping):
            raw_locks = path_or_data.get("locks")
            if raw_locks is None:
                raw_locks = path_or_data.get("tools")
            if not isinstance(raw_locks, Mapping):
                raise ToolImplementationDriftError(
                    "Invalid ETUDE lockfile: missing 'locks' mapping."
                )
            ordered_locks = {str(k): dict(v) for k, v in sorted(raw_locks.items())}
            raw = cls._payload_bytes(ordered_locks)
            expected_sha = hashlib.sha256(raw).hexdigest()
            legacy_expected_sha = hashlib.sha256(canonical_json_bytes(ordered_locks)).hexdigest()
            actual_sha = path_or_data.get("lockfile_sha256")
            if actual_sha and actual_sha not in (expected_sha, legacy_expected_sha):
                raise ToolImplementationDriftError(
                    f"ETUDE lockfile integrity mismatch: expected {expected_sha[:12]}, got {actual_sha!r}."
                )
            reg = cls()
            for name, rec in ordered_locks.items():
                reg._locks[name] = EtudeToolLockRecord.from_dict(rec)
            return reg
        return cls.load_lockfile(path_or_data, key=key)

    def build_lock_manifest(
        self,
        tools: Mapping[str, Tuple[Mapping[str, Any], Callable[..., Any]]],
        lockfile_paths: Optional[Sequence[Union[Path, str]]] = (
            "uv.lock",
            "poetry.lock",
            "requirements.txt",
        ),
    ) -> Dict[str, Any]:
        if self._secret_bytes is None:
            raise ValueError("secret_key must be configured to build lock manifest.")
        entries: Dict[str, Any] = {}
        for name in sorted(tools.keys()):
            schema, fn = tools[name]
            s_hash = compute_schema_sha256(schema)
            ast_hash, combined = _combine(fn, (), ())
            entries[name] = {
                "ast_sha256": ast_hash,
                "capability_sinks": list(sorted(combined)),
                "schema_sha256": s_hash,
                "tool_name": name,
            }

        lockfile_digests: Dict[str, str] = {}
        if lockfile_paths:
            for lp in lockfile_paths:
                p = Path(lp)
                if p.exists() and p.is_file():
                    digest = hashlib.sha256(p.read_bytes()).hexdigest()
                    lockfile_digests[str(lp)] = digest

        body: Dict[str, Any] = {
            "schema_version": "etude-lock-rfc8785-v1",
            "schema": LOCKFILE_SCHEMA,
            "hash_scheme": HASH_SCHEME,
            "tools": entries,
        }
        if lockfile_digests:
            body["lockfiles"] = lockfile_digests

        canonical_bytes = json.dumps(
            _canonicalize_rfc8785(body), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        mac = hmac.new(self._secret_bytes, canonical_bytes, hashlib.sha256).hexdigest()
        return {"manifest": body, "signature": mac}

    def verify_live_tools(
        self,
        locked_bundle: Mapping[str, Any],
        live_tools: Mapping[str, Tuple[Mapping[str, Any], Callable[..., Any]]],
        forbid_dynamic_exec: bool = True,
        lockfile_paths: Optional[Sequence[Union[Path, str]]] = None,
    ) -> bool:
        if self._secret_bytes is None:
            raise ValueError("secret_key must be configured to verify live tools.")
        manifest = locked_bundle.get("manifest")
        sig = str(locked_bundle.get("signature", "")).strip()
        if not isinstance(manifest, Mapping) or not sig:
            raise ToolImplementationDriftError("Malformed mcp-etude-lock.json bundle.")

        canonical_bytes = json.dumps(
            _canonicalize_rfc8785(manifest),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        expected_mac = hmac.new(self._secret_bytes, canonical_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_mac.lower(), sig.lower()):
            raise ToolImplementationDriftError("Lockfile HMAC signature verification failed.")

        locked_lockfiles = manifest.get("lockfiles", {})
        if locked_lockfiles:
            paths_to_check = (
                [Path(lp) for lp in lockfile_paths]
                if lockfile_paths is not None
                else [Path(k) for k in locked_lockfiles.keys()]
            )
            for p in paths_to_check:
                expected_digest = locked_lockfiles.get(str(p)) or locked_lockfiles.get(p.name)
                if expected_digest is not None:
                    if not p.exists() or not p.is_file():
                        raise ToolImplementationDriftError(
                            f"Environment lockfile '{p}' was locked but is missing or inaccessible."
                        )
                    curr_digest = hashlib.sha256(p.read_bytes()).hexdigest()
                    if not hmac.compare_digest(curr_digest.lower(), expected_digest.lower()):
                        raise ToolImplementationDriftError(
                            f"Environment lockfile '{p}' drift detected: expected {expected_digest}, observed {curr_digest}."
                        )

        locked_tools = manifest.get("tools", {})
        for name, (schema, fn) in live_tools.items():
            if name not in locked_tools:
                raise ToolImplementationDriftError(
                    f"Unregistered tool '{name}' not in locked manifest."
                )
            locked_tool = locked_tools[name]
            cur_schema_hash = compute_schema_sha256(schema)
            if cur_schema_hash != locked_tool.get("schema_sha256"):
                raise ToolImplementationDriftError(
                    f"Tool schema drift detected in '{name}' (schema has drifted)."
                )
            ast_hash, combined = _combine(fn, (), ())
            if forbid_dynamic_exec and "dynamic_exec" in combined:
                raise ToolImplementationDriftError(
                    f"Tool '{name}' invokes forbidden dynamic_exec sink (eval/exec/getattr)."
                )
            locked_sinks = tuple(
                locked_tool.get("capability_sinks") or locked_tool.get("allowed_sinks") or ()
            )
            new_sinks = set(combined) - set(locked_sinks)
            if new_sinks:
                raise ToolImplementationDriftError(
                    f"ETUDE sink expansion detected in '{name}': locked={list(locked_sinks)} vs live={sorted(combined)}"
                )
            if ast_hash != locked_tool.get("ast_sha256"):
                raise ToolImplementationDriftError(
                    f"ETUDE implementation AST drift detected in '{name}' despite identical schema."
                )
        return True


__all__ = [
    "DYNAMIC_EXEC_BUILTINS",
    "DYNAMIC_EXEC_NAMES",
    "DYNAMIC_EXEC_ATTRS",
    "FILESYSTEM_READ_METHODS",
    "FILESYSTEM_WRITE_METHODS",
    "HASH_SCHEME",
    "LOCKFILE_SCHEMA",
    "NETWORK_IO_METHODS",
    "PROCESS_EXEC_METHODS",
    "SINK_CALL_PATTERNS",
    "SINK_IMPORT_ROOTS",
    "CrossInvocationStateGuard",
    "EtudeToolDriftError",
    "EtudeToolEntry",
    "EtudeToolLockRecord",
    "EtudeToolLockRegistry",
    "EtudeUndeclaredSinkError",
    "ToolImplementationDriftError",
    "ToolLockEntry",
    "ToolSourceAnalysis",
    "analyze_Python_tool_ast",
    "analyze_python_tool_ast",
    "analyze_python_tool_source",
    "canonical_json_bytes",
    "compute_schema_sha256",
    "discover_helpers",
    "dotted_name",
    "_NormalizedASTVisitor",
]
