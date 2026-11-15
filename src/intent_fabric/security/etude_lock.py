from __future__ import annotations

import ast
import hashlib
import hmac
import inspect
import json
import textwrap
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Set, Tuple


class ToolImplementationDriftError(PermissionError):
    """Raised when a tool's AST digest or capability sink profile drifts from mcp-etude-lock.json."""


# Deterministic mapping of Python module/call patterns to capability sink classes
_SINK_PATTERNS: Mapping[str, Tuple[str, ...]] = {
    "subprocess": (
        "subprocess.",
        "os.system",
        "os.popen",
        "os.spawn",
        "os.exec",
        "asyncio.create_subprocess",
    ),
    "net": (
        "urllib.",
        "socket.",
        "http.client",
        "requests.",
        "httpx.",
        "aiohttp.",
    ),
    "env": (
        "os.environ",
        "os.getenv",
        "os.putenv",
    ),
    "fs_write": (
        "open(",
        "Path.write_",
        "os.remove",
        "os.unlink",
        "shutil.rmtree",
        "shutil.move",
    ),
    "dynamic_exec": (
        "eval",
        "exec",
        "compile",
        "__import__",
        "importlib.import_module",
        "getattr",
    ),
}


def _lp_utf8(value: str) -> str:
    norm = unicodedata.normalize("NFC", value)
    raw = norm.encode("utf-8")
    return f"{len(raw)}:{norm}"


class _NormalizedASTVisitor(ast.NodeTransformer):
    """Strips docstrings so cosmetic comment/docstring edits do not mask or false-trigger AST structure."""

    def _strip_docstring(self, node: ast.AST) -> ast.AST:
        body = getattr(node, "body", None)
        if isinstance(body, list) and body:
            first = body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                body = body[1:] or [ast.Pass()]
                setattr(node, "body", body)
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.name = "_canonical_tool_function"
        return self._strip_docstring(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.name = "_canonical_tool_function"
        return self._strip_docstring(node)


def analyze_Python_tool_ast(func: Callable[..., Any]) -> Tuple[str, Tuple[str, ...]]:
    """
    Computes the normalized AST SHA-256 digest and sorted capability sink tuple
    for a registered Python tool function.
    """
    raw_src = textwrap.dedent(inspect.getsource(func))
    tree = ast.parse(unicodedata.normalize("NFC", raw_src))

    sinks_found: Set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name
                if mod in ("subprocess",):
                    sinks_found.add("subprocess")
                elif mod in ("socket", "requests", "httpx", "aiohttp", "urllib"):
                    sinks_found.add("net")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod.startswith("subprocess"):
                sinks_found.add("subprocess")
            elif mod.startswith(("urllib", "http", "socket", "requests", "httpx", "aiohttp")):
                sinks_found.add("net")
        elif isinstance(node, ast.Call):
            call_str = ast.unparse(node.func)
            if call_str in ("eval", "exec", "compile", "__import__", "getattr"):
                sinks_found.add("dynamic_exec")
            elif call_str == "open":
                # Check if mode argument includes w, a, x, or +
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                    mode_val = str(node.args[1].value)
                    if any(ch in mode_val for ch in ("w", "a", "x", "+")):
                        sinks_found.add("fs_write")
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        if any(ch in str(kw.value.value) for ch in ("w", "a", "x", "+")):
                            sinks_found.add("fs_write")
            elif call_str.endswith((".write_text", ".write_bytes", ".unlink", ".rmtree")):
                sinks_found.add("fs_write")
            elif call_str.startswith(("subprocess.", "os.system", "os.popen")):
                sinks_found.add("subprocess")
            elif call_str.startswith(("urllib.", "requests.", "httpx.", "socket.")):
                sinks_found.add("net")
            elif call_str.startswith(("os.getenv", "os.putenv")):
                sinks_found.add("env")
        elif isinstance(node, ast.Attribute):
            attr_str = ast.unparse(node)
            if attr_str.startswith("os.environ"):
                sinks_found.add("env")

    clean_tree = _NormalizedASTVisitor().visit(tree)
    ast.fix_missing_locations(clean_tree)
    normalized_code = unicodedata.normalize("NFC", ast.unparse(clean_tree))
    ast_sha256 = hashlib.sha256(normalized_code.encode("utf-8")).hexdigest()

    return ast_sha256, tuple(sorted(sinks_found))


analyze_python_tool_ast = analyze_Python_tool_ast


@dataclass(frozen=True)
class EtudeToolEntry:
    tool_name: str
    schema_sha256: str
    ast_sha256: str
    capability_sinks: Tuple[str, ...]

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "ast_sha256": _lp_utf8(self.ast_sha256),
            "capability_sinks": [_lp_utf8(s) for s in self.capability_sinks],
            "schema_sha256": _lp_utf8(self.schema_sha256),
            "tool_name": _lp_utf8(self.tool_name),
        }


class EtudeToolLockRegistry:
    """
    Generates and enforces `mcp-etude-lock.json` manifests across registered MCP tools.
    """

    def __init__(self, secret_key: bytes | str) -> None:
        secret_bytes = (
            secret_key.strip().encode("utf-8")
            if isinstance(secret_key, str)
            else secret_key.strip()
        )
        if len(secret_bytes) < 16:
            raise ValueError("secret_key must be at least 16 non-whitespace bytes.")
        self._secret_bytes = secret_bytes

    @staticmethod
    def _hash_schema(schema: Mapping[str, Any]) -> str:
        raw = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        return hashlib.sha256(raw).hexdigest()

    def build_lock_manifest(
        self, tools: Mapping[str, Tuple[Mapping[str, Any], Callable[..., Any]]]
    ) -> Dict[str, Any]:
        entries: Dict[str, Any] = {}
        for name in sorted(tools.keys()):
            schema, fn = tools[name]
            s_hash = self._hash_schema(schema)
            a_hash, sinks = analyze_Python_tool_ast(fn)
            entry = EtudeToolEntry(
                tool_name=name,
                schema_sha256=s_hash,
                ast_sha256=a_hash,
                capability_sinks=sinks,
            )
            entries[name] = entry.to_canonical_dict()

        body = {"schema_version": "etude-lock-rfc8785-v1", "tools": entries}
        canonical_bytes = json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        mac = hmac.new(self._secret_bytes, canonical_bytes, hashlib.sha256).hexdigest()
        return {"manifest": body, "signature": mac}

    def verify_live_tools(
        self,
        locked_bundle: Mapping[str, Any],
        live_tools: Mapping[str, Tuple[Mapping[str, Any], Callable[..., Any]]],
        forbid_dynamic_exec: bool = True,
    ) -> bool:
        manifest = locked_bundle.get("manifest")
        sig = str(locked_bundle.get("signature", "")).strip()
        if not isinstance(manifest, Mapping) or not sig:
            raise ToolImplementationDriftError("Malformed mcp-etude-lock.json bundle.")

        canonical_bytes = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        expected_mac = hmac.new(self._secret_bytes, canonical_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_mac.lower(), sig.lower()):
            raise ToolImplementationDriftError("Lockfile HMAC signature verification failed.")

        locked_tools = manifest.get("tools", {})
        for name, (schema, fn) in live_tools.items():
            if name not in locked_tools:
                raise ToolImplementationDriftError(f"Unregistered tool '{name}' not in lockfile.")

            locked_entry = locked_tools[name]
            live_s_hash = _lp_utf8(self._hash_schema(schema))
            live_a_hash_raw, live_sinks_raw = analyze_Python_tool_ast(fn)
            live_a_hash = _lp_utf8(live_a_hash_raw)
            live_sinks = [_lp_utf8(s) for s in live_sinks_raw]

            if forbid_dynamic_exec and "dynamic_exec" in live_sinks_raw:
                raise ToolImplementationDriftError(
                    f"Tool '{name}' invokes forbidden dynamic_exec sink (eval/exec/getattr)."
                )

            if live_sinks != locked_entry["capability_sinks"]:
                raise ToolImplementationDriftError(
                    f"ETUDE sink expansion detected in '{name}': "
                    f"locked={locked_entry['capability_sinks']} vs live={live_sinks}"
                )

            if not hmac.compare_digest(live_a_hash.lower(), locked_entry["ast_sha256"].lower()):
                raise ToolImplementationDriftError(
                    f"ETUDE implementation AST drift detected in '{name}' despite identical schema."
                )

            if not hmac.compare_digest(live_s_hash.lower(), locked_entry["schema_sha256"].lower()):
                raise ToolImplementationDriftError(f"Tool schema drift detected in '{name}'.")

        return True
