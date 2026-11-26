from __future__ import annotations

import json
import sys
from pathlib import Path
import pytest

from intent_fabric.etude_lock import (
    EtudeToolDriftError,
    EtudeToolLockRegistry,
    EtudeUndeclaredSinkError,
    analyze_python_tool_source,
    compute_schema_sha256,
)

TEST_SECRET_KEY = "invarcore-v3-etude-hmac-secret-key-32bytes-min!"
WRONG_SECRET_KEY = "wrong-v3-etude-hmac-secret-key-32bytes-minimum!"


def test_path_open_positional_mode_non_constant_mode_and_pathlib_read_vs_write_fixed() -> None:
    assert analyze_python_tool_source(
        'from pathlib import Path\ndef t():\n    return Path("x.txt").open("w")\n'
    ).sinks == ("filesystem_write",)

    assert analyze_python_tool_source(
        'from pathlib import Path\ndef t():\n    return Path("x.txt").open("r")\n'
    ).sinks == ("filesystem_read",)

    assert analyze_python_tool_source(
        'from pathlib import Path\ndef t(m):\n    return Path("x.txt").open(m)\n'
    ).sinks == ("filesystem_write",)

    assert analyze_python_tool_source(
        'from pathlib import Path\ndef t():\n    return Path("x.txt").read_text()\n'
    ).sinks == ("filesystem_read",)

    assert analyze_python_tool_source(
        'from pathlib import Path\ndef t():\n    return Path("x.txt").write_text("evil")\n'
    ).sinks == ("filesystem_write",)


def test_ast_load_dynamic_exec_names_and_attrs_caught() -> None:
    assert analyze_python_tool_source("def t(x):\n    e = eval\n    return e(x)\n").sinks == (
        "dynamic_exec",
    )
    assert analyze_python_tool_source("def t(cls):\n    return cls.__subclasses__()\n").sinks == (
        "dynamic_exec",
    )


def test_path_parameter_io_open_and_builtins_open_classify_accurately() -> None:
    assert analyze_python_tool_source('def t(p):\n    return p.open("w")\n').sinks == (
        "filesystem_write",
    )
    assert analyze_python_tool_source('def t(p):\n    return p.open("r")\n').sinks == (
        "filesystem_read",
    )
    assert analyze_python_tool_source('def t():\n    return open("x.txt", "w")\n').sinks == (
        "filesystem_write",
    )
    assert analyze_python_tool_source('def t():\n    return open("x.txt", "r")\n').sinks == (
        "filesystem_read",
    )
    assert analyze_python_tool_source('def t():\n    return open("x.txt", mode="a")\n').sinks == (
        "filesystem_write",
    )
    assert analyze_python_tool_source(
        'import io\ndef t():\n    return io.open("x.txt", "r")\n'
    ).sinks == ("filesystem_read",)
    assert analyze_python_tool_source(
        'import io\ndef t():\n    return io.open("x.txt", "w")\n'
    ).sinks == ("filesystem_write",)


@pytest.mark.parametrize(
    "source_code, expected_sinks",
    [
        ('import os\ndef t():\n    fn = os.system\n    fn("whoami")\n', ("process_exec",)),
        ('from os import *\ndef t():\n    system("whoami")\n', ("dynamic_exec", "process_exec")),
        ('def t():\n    __import__("os").system("whoami")\n', ("dynamic_exec", "process_exec")),
    ],
)
def test_v2_sink_probes_do_not_regress(source_code: str, expected_sinks: tuple[str, ...]) -> None:
    assert analyze_python_tool_source(source_code).sinks == expected_sinks
    reg = EtudeToolLockRegistry()
    with pytest.raises(EtudeUndeclaredSinkError):
        reg.pin_tool("evil_tool", {"type": "object"}, source_code, allowed_sinks=())


def test_rfc8785_numeric_canonicalization_preserved() -> None:
    assert compute_schema_sha256({"properties": {"limit": 1}}) == compute_schema_sha256(
        {"properties": {"limit": 1.0}}
    )


def test_ast_unparse_stability_helper_drift_and_python_version_metadata(tmp_path: Path) -> None:
    src_v1 = 'def add(a, b):\n    """Docstring v1."""\n    return a + b  # comment\n'
    src_v2 = 'def add(a, b):\n    """Docstring v2."""\n    return a + b\n'
    src_mutated = "def add(a, b):\n    return a - b\n"

    assert (
        analyze_python_tool_source(src_v1).ast_sha256
        == analyze_python_tool_source(src_v2).ast_sha256
    )
    assert (
        analyze_python_tool_source(src_v1).ast_sha256
        != analyze_python_tool_source(src_mutated).ast_sha256
    )

    helper_v1 = "def helper(x):\n    return x * 2\n"
    helper_v2 = "def helper(x):\n    return x * 3\n"
    reg = EtudeToolLockRegistry()
    reg.pin_tool("add", {"name": "add"}, src_v1, helper_sources=[helper_v1])

    lockfile = tmp_path / "mcp-etude-lock.json"
    reg.save_lockfile(lockfile, key=TEST_SECRET_KEY)

    raw = json.loads(lockfile.read_text(encoding="utf-8"))
    assert raw.get("schema") == "mcp-etude-lock-v3"
    assert raw.get("ast_hash_scheme") == "etude-ast-v1"
    assert raw.get("python_version", "").startswith(
        f"{sys.version_info.major}.{sys.version_info.minor}"
    )

    loaded = EtudeToolLockRegistry.load_lockfile(lockfile, key=TEST_SECRET_KEY)
    loaded.verify_tool("add", {"name": "add"}, src_v2, helper_sources=[helper_v1])
    with pytest.raises(EtudeToolDriftError):
        loaded.verify_tool("add", {"name": "add"}, src_v2, helper_sources=[helper_v2])


def test_etude_lockfile_hmac_fails_closed_on_missing_short_wrong_or_forged_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ETUDE_LOCK_SECRET", raising=False)
    reg = EtudeToolLockRegistry()
    reg.pin_tool("safe_fn", {"name": "safe_fn"}, "def safe_fn(x):\n    return x + 1\n")
    lockfile = tmp_path / "mcp-etude-lock.json"

    for bad_key in (None, "", "short-key"):
        with pytest.raises((ValueError, EtudeToolDriftError)):
            reg.save_lockfile(lockfile, key=bad_key)

    reg.save_lockfile(lockfile, key=TEST_SECRET_KEY)

    with pytest.raises((ValueError, EtudeToolDriftError)):
        EtudeToolLockRegistry.load_lockfile(lockfile, key=None)

    with pytest.raises(EtudeToolDriftError):
        EtudeToolLockRegistry.load_lockfile(lockfile, key=WRONG_SECRET_KEY)

    data = json.loads(lockfile.read_text(encoding="utf-8"))
    data["tools"]["safe_fn"]["allowed_sinks"] = ["process_exec"]
    lockfile.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(EtudeToolDriftError):
        EtudeToolLockRegistry.load_lockfile(lockfile, key=TEST_SECRET_KEY)
