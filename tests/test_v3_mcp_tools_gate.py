from __future__ import annotations

from pathlib import Path
import pytest

from intent_fabric.compaction_lock import (
    CompactionLockTamperError,
    SilentModelRouteDriftError,
    build_compaction_constraint_lock,
)
from intent_fabric.etude_lock import (
    EtudeToolDriftError,
    EtudeToolLockRegistry,
)
from intent_fabric.mcp.tools import IntentFabricMCPTools

COMPACTION_SECRET = "invarcore-v3-mcp-compaction-secret-key-32bytes!"
ETUDE_SECRET = "invarcore-v3-mcp-etude-hmac-secret-key-32bytes!"
WRONG_SECRET = "wrong-v3-mcp-hmac-secret-key-32bytes-minimum!!"


def _safe_tool(x: int) -> int:
    return x + 1


def _safe_tool_mutated(x: int) -> int:
    return x + 999


def test_mcp_tools_fail_closed_on_missing_explicit_lockfile_and_wrong_etude_key(
    tmp_path: Path,
) -> None:
    missing_lockfile = tmp_path / "does-not-exist.json"
    with pytest.raises((FileNotFoundError, EtudeToolDriftError)):
        IntentFabricMCPTools(lockfile_path=missing_lockfile, etude_signing_key=ETUDE_SECRET)

    reg = EtudeToolLockRegistry()
    reg.pin_tool("calc", {"name": "calc"}, _safe_tool, allowed_sinks=())
    lockfile = tmp_path / "mcp-etude-lock.json"
    reg.save_lockfile(lockfile, key=ETUDE_SECRET)

    with pytest.raises(EtudeToolDriftError):
        IntentFabricMCPTools(lockfile_path=lockfile, etude_signing_key=WRONG_SECRET)

    loaded_mcp = IntentFabricMCPTools(lockfile_path=lockfile, etude_signing_key=ETUDE_SECRET)
    assert loaded_mcp._etude_registry.get_lock("calc") is not None


def test_mcp_tools_fail_closed_on_unpinned_dispatch_and_live_drift() -> None:
    reg = EtudeToolLockRegistry()
    reg.pin_tool("calc", {"name": "calc"}, _safe_tool, allowed_sinks=())

    mcp = IntentFabricMCPTools(etude_registry=reg)
    mcp._handlers["unpinned"] = _safe_tool
    mcp._schemas["unpinned"] = {"name": "unpinned"}
    mcp._handlers["calc"] = _safe_tool_mutated
    mcp._schemas["calc"] = {"name": "calc"}

    with pytest.raises(EtudeToolDriftError):
        mcp.dispatch_tool_call("unpinned", {"x": 1})

    with pytest.raises(EtudeToolDriftError):
        mcp.dispatch_tool_call("calc", {"x": 2})


def test_mcp_tools_enforce_compaction_hmac_and_default_model_telemetry() -> None:
    lock = build_compaction_constraint_lock(
        allowed_tools=["calc"],
        pinned_model_version="gemini-2.5-pro",
        signing_key=COMPACTION_SECRET,
    )
    reg = EtudeToolLockRegistry()
    reg.pin_tool("calc", {"name": "calc"}, _safe_tool, allowed_sinks=())

    mcp = IntentFabricMCPTools(
        etude_registry=reg,
        compaction_lock=lock,
        compaction_signing_key=COMPACTION_SECRET,
    )
    mcp._handlers["calc"] = _safe_tool
    mcp._schemas["calc"] = {"name": "calc"}

    with pytest.raises(SilentModelRouteDriftError):
        mcp.dispatch_tool_call("calc", {"x": 1})

    bad_mcp = IntentFabricMCPTools(
        etude_registry=reg,
        compaction_lock=lock,
        compaction_signing_key=WRONG_SECRET,
    )
    bad_mcp._handlers["calc"] = _safe_tool
    bad_mcp._schemas["calc"] = {"name": "calc"}
    with pytest.raises(CompactionLockTamperError):
        bad_mcp.dispatch_tool_call("calc", {"x": 1}, observed_model_version="gemini-2.5-pro")

    assert mcp.dispatch_tool_call("calc", {"x": 1}, observed_model_version="gemini-2.5-pro") == 2
