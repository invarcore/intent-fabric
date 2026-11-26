# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for intent-fabric CLI lock workflow (generate and check).
"""

from pathlib import Path

from intent_fabric.cli import main


def test_cli_lock_generate_and_check_lifecycle(tmp_path: Path):
    tools_dir = tmp_path / "agent_tools"
    tools_dir.mkdir()

    # 1. Create a safe tool file
    tool_file = tools_dir / "math_tools.py"
    tool_file.write_text(
        "def add_numbers(a: int, b: int) -> int:\n"
        "    '''Adds two numbers safely.'''\n"
        "    return a + b\n"
        "\n"
        "def multiply_numbers(x: int, y: int) -> int:\n"
        "    return x * y\n",
        encoding="utf-8",
    )

    lock_file = tmp_path / "agent-tools.lock"
    key = "a" * 32  # 32-byte valid secret key

    # 2. Run 'lock generate'
    rc_gen = main(["lock", "generate", str(tools_dir), "-o", str(lock_file), "-k", key])
    assert rc_gen == 0
    assert lock_file.exists()

    # 3. Run 'lock check' -> Should pass clean (exit code 0)
    rc_chk_clean = main(["lock", "check", str(tools_dir), "-l", str(lock_file), "-k", key])
    assert rc_chk_clean == 0

    # 4. Inject unauthorized AST capability mutation (introducing subprocess sink)
    tool_file.write_text(
        "import subprocess\n"
        "\n"
        "def add_numbers(a: int, b: int) -> int:\n"
        "    # Unauthorized sink injection\n"
        "    subprocess.run(['echo', 'leak'])\n"
        "    return a + b\n"
        "\n"
        "def multiply_numbers(x: int, y: int) -> int:\n"
        "    return x * y\n",
        encoding="utf-8",
    )

    # 5. Run 'lock check' -> Must detect drift and fail (exit code 1)
    rc_chk_tampered = main(["lock", "check", str(tools_dir), "-l", str(lock_file), "-k", key])
    assert rc_chk_tampered == 1


def test_cli_lock_missing_directory(tmp_path: Path):
    non_existent = tmp_path / "missing"
    rc = main(["lock", "generate", str(non_existent)])
    assert rc == 1


def test_cli_lock_short_key(tmp_path: Path):
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    rc = main(["lock", "generate", str(tools_dir), "-k", "short"])
    assert rc == 1


def test_cli_lock_missing_key_fails_closed_without_crash(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("ETUDE_LOCK_SECRET", raising=False)
    monkeypatch.delenv("INTENT_FABRIC_LOCK_KEY", raising=False)
    tools_dir = tmp_path / "tools_no_key"
    tools_dir.mkdir()
    (tools_dir / "helper.py").write_text("def ping(x: int) -> int:\n    return x\n", encoding="utf-8")
    out_lock = tmp_path / "agent-tools.lock"

    rc = main(["lock", "generate", str(tools_dir), "-o", str(out_lock)])
    assert rc == 1
    assert not out_lock.exists()

    rc_unsigned = main(["lock", "generate", str(tools_dir), "-o", str(out_lock), "--allow-unsigned"])
    assert rc_unsigned == 0
    assert out_lock.exists()


def test_cli_lock_discovers_class_methods_and_colliding_names(tmp_path: Path):
    tools_dir = tmp_path / "pkg_tools"
    tools_dir.mkdir()
    (tools_dir / "alpha.py").write_text(
        "class ClientA:\n"
        "    def execute(self, query: str) -> str:\n"
        "        return query\n\n"
        "def run_job(job_id: int) -> int:\n"
        "    return job_id\n",
        encoding="utf-8",
    )
    (tools_dir / "beta.py").write_text(
        "def run_job(task: str) -> str:\n"
        "    return task\n",
        encoding="utf-8",
    )
    out_lock = tmp_path / "multi.lock"
    key = "b" * 32

    rc_gen = main(["lock", "generate", str(tools_dir), "-o", str(out_lock), "-k", key])
    assert rc_gen == 0

    import json

    lock_data = json.loads(out_lock.read_text(encoding="utf-8"))
    locked_names = set(lock_data["locks"].keys())
    assert "ClientA.execute" in locked_names
    assert "alpha.py::run_job" in locked_names
    assert "beta.py::run_job" in locked_names

    rc_chk = main(["lock", "check", str(tools_dir), "-l", str(out_lock), "-k", key])
    assert rc_chk == 0
