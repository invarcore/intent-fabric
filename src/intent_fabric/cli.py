# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""
Command-line interface for Intent Fabric.
Provides developer ergonomics for ETUDE tool lockfile generation, inspection, and CI verification.
"""

from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
import sys
from typing import Any, Sequence

from intent_fabric.etude_lock import (
    EtudeToolDriftError,
    EtudeToolLockRegistry,
    EtudeUndeclaredSinkError,
)

VERSION = "0.2.0"


def _extract_ast_tool_schema(
    tool_name: str, node: ast.FunctionDef | ast.AsyncFunctionDef
) -> dict[str, Any]:
    """Derive a structured JSON function schema from a Python AST function definition."""
    pos_args = list(node.args.posonlyargs) + list(node.args.args)
    kw_args = list(node.args.kwonlyargs)
    filtered_pos = [a for a in pos_args if a.arg not in ("self", "cls")]
    all_args = filtered_pos + kw_args

    properties: dict[str, dict[str, str]] = {}
    for arg in all_args:
        ann_str = ast.unparse(arg.annotation) if arg.annotation is not None else "any"
        properties[arg.arg] = {"type": ann_str}

    # Required = positional args without defaults + kwonly args with None default
    num_pos_defaults = len(node.args.defaults)
    pos_without_defaults = (
        filtered_pos[: len(filtered_pos) - num_pos_defaults] if num_pos_defaults else filtered_pos
    )
    required = [a.arg for a in pos_without_defaults]
    for kw_arg, kw_default in zip(kw_args, node.args.kw_defaults):
        if kw_default is None:
            required.append(kw_arg.arg)

    return {
        "type": "function",
        "name": tool_name,
        "parameters": {
            "type": "object",
            "properties": properties,
            "required": required,
        },
    }


def _discover_python_tools(directory: Path) -> dict[str, tuple[str, dict[str, Any], str]]:
    """
    Discovers public functions and class methods across Python files in directory.
    Disambiguates colliding symbol names across multiple files using relative path prefixes.
    Returns mapping: tool_name -> (source_code, schema_dict, file_path_str)
    """
    raw_entries: list[tuple[str, str, str, dict[str, Any], str]] = []
    for py_file in sorted(directory.rglob("*.py")):
        if py_file.name.startswith("test_") or "tests" in py_file.parts:
            continue
        try:
            content = py_file.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(py_file))
        except Exception:
            continue

        rel_posix = py_file.relative_to(directory).as_posix()

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("_"):
                    fn_source = ast.get_source_segment(content, node) or ""
                    if fn_source:
                        raw_entries.append(
                            (
                                node.name,
                                rel_posix,
                                fn_source,
                                _extract_ast_tool_schema(node.name, node),
                                str(py_file),
                            )
                        )
            elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and not item.name.startswith(
                        "_"
                    ):
                        qualname = f"{node.name}.{item.name}"
                        fn_source = ast.get_source_segment(content, item) or ""
                        if fn_source:
                            raw_entries.append(
                                (
                                    qualname,
                                    rel_posix,
                                    fn_source,
                                    _extract_ast_tool_schema(qualname, item),
                                    str(py_file),
                                )
                            )

    name_counts: dict[str, int] = {}
    for base_name, _, _, _, _ in raw_entries:
        name_counts[base_name] = name_counts.get(base_name, 0) + 1

    discovered: dict[str, tuple[str, dict[str, Any], str]] = {}
    for base_name, rel_posix, fn_source, schema, file_str in raw_entries:
        key_name = f"{rel_posix}::{base_name}" if name_counts[base_name] > 1 else base_name
        if key_name != schema["name"]:
            schema = {**schema, "name": key_name}
        discovered[key_name] = (fn_source, schema, file_str)
    return discovered


def handle_lock_generate(args: argparse.Namespace) -> int:
    target_dir = Path(args.directory).resolve()
    if not target_dir.exists():
        sys.stderr.write(f"Error: directory '{target_dir}' does not exist.\n")
        return 1

    out_file = Path(args.output).resolve()
    key = (
        args.key or os.environ.get("ETUDE_LOCK_SECRET") or os.environ.get("INTENT_FABRIC_LOCK_KEY")
    )
    allow_unsigned = bool(getattr(args, "allow_unsigned", False))
    if not key:
        if not allow_unsigned:
            sys.stderr.write(
                "Error: HMAC signing key required (pass -k/--key or set ETUDE_LOCK_SECRET, "
                "or pass --allow-unsigned explicitly for an unsigned SHA-256 lockfile).\n"
            )
            return 1
    elif len(key.strip()) < 32:
        sys.stderr.write("Error: signing key must be at least 32 non-whitespace bytes.\n")
        return 1

    registry = EtudeToolLockRegistry(secret_key=key)
    tools = _discover_python_tools(target_dir)

    if not tools:
        sys.stderr.write(f"No Python tool definitions found in {target_dir}.\n")
        return 1

    for name, (src, schema, _) in sorted(tools.items()):
        rec = registry.pin_tool(
            tool_name=name,
            source_or_fn=src,
            schema=schema,
        )
        sinks_str = ", ".join(rec.detected_sinks) if rec.detected_sinks else "none"
        ast_val = rec.ast_normalized_sha256 or "none"
        print(f"  [PINNED] {name:<24} | AST: {ast_val[:12]}... | Sinks: {sinks_str}")

    digest = registry.save_lockfile(out_file, key=key) if key else registry.save_lockfile(out_file)
    print(f"\n[+] Generated {registry.to_dict()['schema']} lockfile with {len(tools)} tools.")
    print(f"    Destination: {out_file}")
    print(f"    Lock Digest: {digest[:16]}...")
    return 0


def handle_lock_check(args: argparse.Namespace) -> int:
    target_dir = Path(args.directory).resolve()
    lock_file = Path(args.lockfile).resolve()

    if not lock_file.exists():
        sys.stderr.write(
            f"Error: lockfile '{lock_file}' does not exist. Run 'intent-fabric lock generate' first.\n"
        )
        return 1

    key = (
        args.key or os.environ.get("ETUDE_LOCK_SECRET") or os.environ.get("INTENT_FABRIC_LOCK_KEY")
    )
    try:
        registry = EtudeToolLockRegistry.load_lockfile(lock_file, key=key)
    except Exception as exc:
        sys.stderr.write(f"Error loading lockfile: {exc}\n")
        return 1

    tools = _discover_python_tools(target_dir)
    locked_names = set(registry.list_locks().keys())
    live_names = set(tools.keys())

    errors = 0
    checked = 0

    # 1. Check all live tools against lockfile
    for name, (src, schema, _) in sorted(tools.items()):
        if name not in locked_names:
            sys.stderr.write(
                f"[UNLOCKED TOOL] '{name}' exists in codebase but is not pinned in lockfile.\n"
            )
            errors += 1
            continue

        try:
            checked += 1
            registry.verify_tool(
                tool_name=name,
                source_or_fn=src,
                schema=schema,
            )
            print(f"  [OK] {name:<24} matches lockfile.")
        except EtudeUndeclaredSinkError as exc:
            sys.stderr.write(f"  [DRIFT - UNDECLARED SINK] {name}: {exc}\n")
            errors += 1
        except EtudeToolDriftError as exc:
            sys.stderr.write(f"  [DRIFT - AST MUTATION] {name}: {exc}\n")
            errors += 1
        except Exception as exc:
            sys.stderr.write(f"  [ERROR] {name}: {exc}\n")
            errors += 1

    # 2. Check for missing locked tools
    missing = locked_names - live_names
    for m in missing:
        sys.stderr.write(
            f"[MISSING TOOL] '{m}' is defined in lockfile but not found in codebase.\n"
        )
        errors += 1

    if errors > 0:
        sys.stderr.write(
            f"\n[FAIL] ETUDE lock check failed with {errors} drift error(s) across {checked} checked tool(s).\n"
        )
        return 1

    print(f"\n[PASS] All {checked} tool(s) match lockfile '{lock_file.name}' with 0 drift errors.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="intent-fabric",
        description="Intent Fabric: Vendor-neutral invariant planning & ETUDE tool lockfile guard",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 'lock' command group
    lock_parser = subparsers.add_parser("lock", help="ETUDE AST-sink lockfile operations")
    lock_sub = lock_parser.add_subparsers(dest="lock_action", help="Lock actions")

    # 'lock generate'
    gen_parser = lock_sub.add_parser(
        "generate", help="Generate or update agent-tools.lock from source directory"
    )
    gen_parser.add_argument(
        "directory", nargs="?", default=".", help="Source directory to scan (default: current dir)"
    )
    gen_parser.add_argument(
        "-o",
        "--output",
        default="agent-tools.lock",
        help="Lockfile output path (default: agent-tools.lock)",
    )
    gen_parser.add_argument(
        "-k", "--key", help="HMAC signing key (>=32 bytes, or ETUDE_LOCK_SECRET env var)"
    )
    gen_parser.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="Explicitly allow generating an unsigned SHA-256 lockfile when no signing key is provided",
    )

    # 'lock check'
    chk_parser = lock_sub.add_parser("check", help="Verify source code against agent-tools.lock")
    chk_parser.add_argument(
        "directory", nargs="?", default=".", help="Source directory to scan (default: current dir)"
    )
    chk_parser.add_argument(
        "-l",
        "--lockfile",
        default="agent-tools.lock",
        help="Lockfile path (default: agent-tools.lock)",
    )
    chk_parser.add_argument(
        "-k", "--key", help="HMAC signing key (>=32 bytes, or ETUDE_LOCK_SECRET env var)"
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.subcommand == "lock":
        if args.lock_action == "generate":
            return handle_lock_generate(args)
        elif args.lock_action == "check":
            return handle_lock_check(args)
        else:
            parser.parse_args(["lock", "--help"])
            return 1
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
