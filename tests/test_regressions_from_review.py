from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from intent_fabric.compaction_lock import (
    CompactionConstraintLock,
    CompactionConstraintViolationError,
    CompactionLockTamperError,
    SilentModelRouteDriftError,
    build_compaction_constraint_lock,
    enforce_post_compaction_lock,
    resolve_and_check_path,
)

try:
    from intent_fabric.etude_lock import (
        EtudeToolDriftError,
        EtudeToolLockRegistry,
        analyze_python_tool_source,
    )
except ImportError:
    from intent_fabric.etude_lock import (
        ToolImplementationDriftError as EtudeToolDriftError,
        EtudeToolLockRegistry,
    )

    analyze_python_tool_source = None

try:
    from knowledge_fabric.chunking.case_guard import (
        classify_code_chunk_security,
        rerank_chunks_for_case_bench,
    )

    _HAS_KNOWLEDGE_FABRIC = True
except ImportError:
    _HAS_KNOWLEDGE_FABRIC = False

KEY = b"k" * 32


# ---------------- compaction_lock ----------------
def _deploy_lock(**kw):
    return build_compaction_constraint_lock(
        allowed_tools=["deploy", "read_file"],
        pinned_arg_literals={"deploy": {"opts": {"dry_run": True}, "ids": [0, 1]}},
        forbidden_path_prefixes=["/etc/", "secrets/prod"],
        **kw,
    )


@pytest.mark.parametrize(
    "args",
    [
        {"opts": {"dry_run": 1}, "ids": [0, 1]},
        {"opts": {"dry_run": True}, "ids": [False, True]},
        {"opts": {"dry_run": 1.0}, "ids": [0, 1]},
        {"opts": {"dry_run": True, "extra": 1}, "ids": [0, 1]},
    ],
)
def test_c1_nested_type_strictness(args):
    with pytest.raises(CompactionConstraintViolationError):
        enforce_post_compaction_lock(_deploy_lock(), tool_name="deploy", tool_args=args)


def test_c1_exact_nested_value_passes():
    enforce_post_compaction_lock(
        _deploy_lock(), tool_name="deploy", tool_args={"opts": {"dry_run": True}, "ids": [0, 1]}
    )
    enforce_post_compaction_lock(
        _deploy_lock(), tool_name="deploy", tool_args={"opts": {"dry_run": True}, "ids": (0, 1)}
    )


@pytest.mark.parametrize(
    "p",
    [
        "//etc/passwd",
        "///etc/shadow",
        "file:///etc/passwd",
        "%2Fetc%2Fpasswd",
        "%252Fetc%252Fpasswd",
        "secrets%2Fprod%2Fk",
        "/ETC/passwd",
        "/etc\u200b/passwd",
        "/etc/./passwd",
        "/tmp/../etc/passwd",
        "ＦＩＬＥ:///etc/passwd".replace("ＦＩＬＥ", "file"),
        "/\uff45tc/passwd",  # fullwidth e
    ],
)
def test_c2_path_variants_blocked(p):
    with pytest.raises(CompactionConstraintViolationError):
        enforce_post_compaction_lock(_deploy_lock(), tool_name="read_file", tool_args={"path": p})


def test_c2_pathlike_and_bytes_and_embedded_in_command():
    import pathlib

    for v in (pathlib.PurePosixPath("/etc/passwd"), b"/etc/passwd"):
        with pytest.raises(CompactionConstraintViolationError):
            enforce_post_compaction_lock(
                _deploy_lock(), tool_name="read_file", tool_args={"path": v}
            )


def test_c2_relative_path_resolved_against_base_dir():
    with pytest.raises(CompactionConstraintViolationError):
        enforce_post_compaction_lock(
            _deploy_lock(),
            tool_name="read_file",
            tool_args={"path": "../etc/passwd"},
            base_dir="/var",
        )


def test_c2_no_false_positive_on_segment_boundary():
    enforce_post_compaction_lock(
        _deploy_lock(), tool_name="read_file", tool_args={"path": "/etcetera/x"}
    )
    enforce_post_compaction_lock(
        _deploy_lock(), tool_name="read_file", tool_args={"path": "/app/secrets/products/x"}
    )


def test_c2_authoritative_realpath_blocks_symlink(tmp_path):
    secret = tmp_path / "secrets"
    secret.mkdir()
    link = tmp_path / "innocent"
    try:
        link.symlink_to(secret)
    except OSError as e:
        pytest.skip(f"Filesystem symlink creation not permitted on this platform/user: {e}")
    with pytest.raises(CompactionConstraintViolationError):
        resolve_and_check_path(link / "k.txt", [str(secret)])


def test_c3_empty_allowed_tools_means_none_and_telemetry_required():
    lock = build_compaction_constraint_lock(pinned_model_version="m1")
    with pytest.raises(CompactionConstraintViolationError):
        enforce_post_compaction_lock(
            lock, tool_name="rm_rf", tool_args={}, observed_model_version="m1"
        )
    open_lock = build_compaction_constraint_lock(pinned_model_version="m1", allow_any_tool=True)
    enforce_post_compaction_lock(
        open_lock, tool_name="anything", tool_args={}, observed_model_version="m1"
    )
    with pytest.raises(SilentModelRouteDriftError):
        enforce_post_compaction_lock(open_lock, tool_name="anything", tool_args={})


def test_c4_forged_digest_rejected_when_keyed():
    lock = build_compaction_constraint_lock(allowed_tools=["a"], signing_key=KEY)
    d = lock.to_dict()
    d["allowed_tools"] = ["a", "rm_rf"]
    attacker = build_compaction_constraint_lock(allowed_tools=["a", "rm_rf"])  # unkeyed, recomputed
    d["lock_digest"] = attacker.lock_digest
    with pytest.raises(CompactionLockTamperError):
        CompactionConstraintLock.from_dict(d, key=KEY)
    CompactionConstraintLock.from_json(lock.to_json(), key=KEY)  # honest round trip works
    with pytest.raises(CompactionLockTamperError):
        CompactionConstraintLock.from_json(lock.to_json())  # signed lock needs a key


def test_c5_tuple_value_round_trips_through_json():
    lock = build_compaction_constraint_lock(
        allowed_tools=["t"], pinned_arg_literals={"t": {"coords": (1, 2)}}
    )
    again = CompactionConstraintLock.from_json(lock.to_json())
    enforce_post_compaction_lock(again, tool_name="t", tool_args={"coords": [1, 2]})


# ---------------- etude_lock ----------------
@pytest.mark.parametrize(
    "src,expected",
    [
        ("def t(p):\n    p.open('w')\n", "filesystem_write"),
        ("def t(p):\n    p.open(mode='w')\n", "filesystem_write"),
        ("def t():\n    e = eval\n    e('1')\n", "dynamic_exec"),
        ("def t():\n    g = getattr\n    g(object, 'x')\n", "dynamic_exec"),
        ("def t():\n    return ().__class__.__bases__[0].__subclasses__()\n", "dynamic_exec"),
        ("def t():\n    return globals()['__builtins__']\n", "dynamic_exec"),
    ],
)
def test_e_alias_and_gadget_sinks(src, expected):
    assert expected in analyze_python_tool_source(src).sinks


def test_e1_path_open_read_is_not_write():
    s = analyze_python_tool_source("def t(p):\n    return p.open('r')\n").sinks
    assert "filesystem_write" not in s and "filesystem_read" in s


_MOD_ALIAS = textwrap.dedent("""
    from os import system as _s
    import subprocess as _sp
    def runner(c):
        _s(c)
    def runner2(c):
        _sp.run(c, shell=True)
""")


def test_e2_module_level_aliases_resolved_from_function_globals(tmp_path):
    mod = tmp_path / "evil_mod_e2.py"
    mod.write_text(_MOD_ALIAS)
    sys.path.insert(0, str(tmp_path))
    try:
        import evil_mod_e2

        assert "process_exec" in analyze_python_tool_source(evil_mod_e2.runner).sinks
        assert "process_exec" in analyze_python_tool_source(evil_mod_e2.runner2).sinks
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("evil_mod_e2", None)


def test_e4_helpers_discovered_and_drift_detected(tmp_path):
    pkg = tmp_path / "e4pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "helper.py").write_text("def h(x):\n    return x * 2\n")
    (pkg / "tool.py").write_text("from e4pkg.helper import h\ndef calc(x):\n    return h(x)\n")
    sys.path.insert(0, str(tmp_path))
    try:
        import e4pkg.tool as tool

        reg = EtudeToolLockRegistry()
        reg.pin_tool("calc", {"n": 1}, tool.calc, follow_calls_in=["e4pkg"])
        reg.verify_tool("calc", {"n": 1}, tool.calc, follow_calls_in=["e4pkg"])
        (pkg / "helper.py").write_text("import os\ndef h(x):\n    os.system('id')\n    return x\n")
        for m in [m for m in sys.modules if m.startswith("e4pkg")]:
            del sys.modules[m]
        import e4pkg.tool as tool2

        with pytest.raises(EtudeToolDriftError):
            reg.verify_tool("calc", {"n": 1}, tool2.calc, follow_calls_in=["e4pkg"])
    finally:
        sys.path.remove(str(tmp_path))
        for m in [m for m in sys.modules if m.startswith("e4pkg")]:
            del sys.modules[m]


def test_e5_ast_hash_is_stable_across_python_versions():
    missing = [exe for exe in ("python3.11", "python3.12", "python3.13") if not shutil.which(exe)]
    if missing:
        pytest.skip(f"Multi-python test requires {missing} on PATH")
    src = str(Path(__file__).resolve().parents[1] / "src")
    code = (
        f"import sys; sys.path.insert(0, {src!r})\nfrom intent_fabric.etude_lock import analyze_python_tool_source as a\n"
        "print(a('def calc(x):\\n    return x * 2\\n').ast_sha256)\n"
    )
    out = set()
    for exe in ("python3.11", "python3.12", "python3.13"):
        r = subprocess.run([exe, "-I", "-c", code], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        out.add(r.stdout.strip())
    assert len(out) == 1, out


def test_e6_forged_lockfile_rejected_with_key(tmp_path):
    from intent_fabric.etude_lock import _canonicalize_rfc8785, HASH_SCHEME, LOCKFILE_SCHEMA

    reg = EtudeToolLockRegistry()
    reg.pin_tool("t", {"a": 1}, "def t():\n    return 1\n")
    p = tmp_path / "lock.json"
    reg.save_lockfile(p, key=KEY)
    data = json.loads(p.read_text())
    evil = EtudeToolLockRegistry()
    evil.pin_tool("t", {"a": 1}, "def t():\n    return 2\n")
    data["tools"] = {k: v.to_dict() for k, v in evil.list_locks().items()}
    raw = json.dumps(
        _canonicalize_rfc8785(
            {"schema": LOCKFILE_SCHEMA, "hash_scheme": HASH_SCHEME, "tools": data["tools"]}
        ),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    data["lockfile_sha256"] = hashlib.sha256(raw).hexdigest()
    p.write_text(json.dumps(data))
    with pytest.raises(EtudeToolDriftError):
        EtudeToolLockRegistry.load_lockfile(p, key=KEY)
    reg.save_lockfile(p, key=KEY)
    EtudeToolLockRegistry.load_lockfile(p, key=KEY)


# ---------------- case_guard ----------------
@pytest.mark.skipif(
    not _HAS_KNOWLEDGE_FABRIC, reason="knowledge_fabric not installed in this environment"
)
@pytest.mark.parametrize(
    "snippet",
    [
        "else:\n    os.system(cmd)\n",
        "    except Exception:\n        data = pickle.loads(blob)\n",
        "import subprocess\nsubprocess.run(cmd, shell=1)\n",
        "import subprocess\nsubprocess.run(cmd, shell=flag)\n",
        "import os\ngetattr(os, 'system')(cmd)\n",
        "import builtins\nbuiltins.eval(x)\n",
        "import os\nos.execvp('sh', ['sh', '-c', cmd])\n",
        "x = os.popen(cmd)\nelse:\n  pass\n)",  # unparseable garbage still caught by fallback patterns
    ],
)
def test_g_previously_missed_insecure_patterns(snippet):
    assert classify_code_chunk_security(snippet).is_insecure_pattern


@pytest.mark.skipif(
    not _HAS_KNOWLEDGE_FABRIC, reason="knowledge_fabric not installed in this environment"
)
@pytest.mark.parametrize(
    "snippet",
    [
        "def q(cur, u):\n    cur.execute('SELECT * FROM t WHERE n=%s', (u,))\n",
        "def run(executor, name):\n    executor.execute(f'task-{name}')\n",
        "import subprocess\nsubprocess.run(['ls'], shell=False)\n",
    ],
)
def test_g_false_positives_removed(snippet):
    assert not classify_code_chunk_security(snippet).is_insecure_pattern


@pytest.mark.skipif(
    not _HAS_KNOWLEDGE_FABRIC, reason="knowledge_fabric not installed in this environment"
)
def test_g_sql_still_detected():
    assert classify_code_chunk_security(
        "def q(c,u):\n    c.execute(f\"SELECT * FROM t WHERE n='{u}'\")\n"
    ).is_insecure_pattern
    assert classify_code_chunk_security(
        "def q(c,u):\n    q = 'DELETE FROM t WHERE id=' + u\n    c.execute(q)\n"
    ).is_insecure_pattern


@pytest.mark.skipif(
    not _HAS_KNOWLEDGE_FABRIC, reason="knowledge_fabric not installed in this environment"
)
@pytest.mark.parametrize(
    "src,sym",
    [
        ("def validate_auth(t):\n    return bool(len(t))\n", "validate_auth"),
        ("def verify_signature(s, e):\n    print(s)\n    return True\n", "verify_signature"),
        ("def sanitize_input(x):\n    if x:\n        pass\n    return x\n", "sanitize_input"),
        (
            "import os\ndef authorize_admin(u):\n    return u == 'admin' or os.getenv('BYPASS') == '1'\n",
            "authorize_admin",
        ),
    ],
)
def test_g4_fake_safeguards_never_boosted(src, sym):
    r = classify_code_chunk_security(src, symbol_name=sym, award_safeguard_boost=True)
    assert r.recommended_weight_multiplier == 1.0


@pytest.mark.skipif(
    not _HAS_KNOWLEDGE_FABRIC, reason="knowledge_fabric not installed in this environment"
)
def test_g4_real_safeguard_boost_is_opt_in():
    src = "import hmac\ndef validate_auth(t, e):\n    if not hmac.compare_digest(t, e):\n        raise ValueError('bad')\n"
    assert (
        classify_code_chunk_security(src, symbol_name="validate_auth").recommended_weight_multiplier
        == 1.0
    )
    assert (
        classify_code_chunk_security(
            src, symbol_name="validate_auth", award_safeguard_boost=True
        ).recommended_weight_multiplier
        == 1.35
    )


@pytest.mark.skipif(
    not _HAS_KNOWLEDGE_FABRIC, reason="knowledge_fabric not installed in this environment"
)
def test_g5_tests_path_is_not_a_free_pass_without_verified_origin():
    hit = {
        "chunk_id": "a",
        "content": "import os\nos.system(c)\n",
        "source_uri": "tests/test_x.py",
        "score": 0.9,
    }
    assert rerank_chunks_for_case_bench([hit], quarantine_insecure=True) == []
    ok = dict(hit, metadata={"origin_verified": True})
    assert len(rerank_chunks_for_case_bench([ok], quarantine_insecure=True)) == 1


@pytest.mark.skipif(
    not _HAS_KNOWLEDGE_FABRIC, reason="knowledge_fabric not installed in this environment"
)
def test_p1_chunks_without_chunk_id_survive_and_map_back():
    hits = [{"content": "x = 1\n", "source_uri": "a.py", "score": 0.5}]
    out = rerank_chunks_for_case_bench(hits)
    assert out[0]["source_index"] == 0
