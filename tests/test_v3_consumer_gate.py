from __future__ import annotations

from dataclasses import dataclass
from typing import Any
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
from intent_fabric.policies.consumer import GovernedPolicyExecutor

TEST_SECRET_KEY = "invarcore-v3-wiring-hmac-secret-key-32bytes-min!"
WRONG_SECRET_KEY = "wrong-v3-wiring-hmac-secret-key-32bytes-minimum!"


@dataclass
class _StubDecision:
    allowed: bool = True
    reason: str = "ok"


class _StubPolicyEngine:
    def evaluate(self, *, tool_name: str, tool_args: dict[str, Any], context: Any) -> _StubDecision:
        return _StubDecision(allowed=True)


def test_executor_fails_closed_on_unpinned_tool_and_never_runs_handler() -> None:
    calls = 0

    def tracked_tool(x: int) -> int:
        nonlocal calls
        calls += 1
        return x + 1

    reg = EtudeToolLockRegistry()
    executor = GovernedPolicyExecutor(
        _StubPolicyEngine(),  # type: ignore[arg-type]
        etude_registry=reg,
    )
    executor.register_tool("unpinned_tool", tracked_tool, schema={"name": "unpinned_tool"})

    with pytest.raises(EtudeToolDriftError):
        executor.execute("unpinned_tool", {"x": 1}, context=None)  # type: ignore[arg-type]
    assert calls == 0


def test_executor_enforces_hmac_compaction_lock_and_default_model_telemetry() -> None:
    calls = 0

    def deploy(env: str) -> str:
        nonlocal calls
        calls += 1
        return env

    lock = build_compaction_constraint_lock(
        allowed_tools=["deploy"],
        pinned_model_version="gemini-2.5-pro",
        signing_key=TEST_SECRET_KEY,
    )
    executor = GovernedPolicyExecutor(
        _StubPolicyEngine(),  # type: ignore[arg-type]
        compaction_lock=lock,
        compaction_signing_key=TEST_SECRET_KEY,
    )
    executor.register_tool("deploy", deploy)

    with pytest.raises(SilentModelRouteDriftError):
        executor.execute("deploy", {"env": "staging"}, context=None)  # type: ignore[arg-type]
    assert calls == 0

    bad_executor = GovernedPolicyExecutor(
        _StubPolicyEngine(),  # type: ignore[arg-type]
        compaction_lock=lock,
        compaction_signing_key=WRONG_SECRET_KEY,
    )
    bad_executor.register_tool("deploy", deploy)
    with pytest.raises(CompactionLockTamperError):
        bad_executor.execute(
            "deploy",
            {"env": "staging"},
            context=None,  # type: ignore[arg-type]
            observed_model_version="gemini-2.5-pro",
        )
    assert calls == 0

    result = executor.execute(
        "deploy",
        {"env": "staging"},
        context=None,  # type: ignore[arg-type]
        observed_model_version="gemini-2.5-pro",
    )
    assert result == "staging"
    assert calls == 1
