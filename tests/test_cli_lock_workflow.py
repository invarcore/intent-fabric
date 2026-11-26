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
