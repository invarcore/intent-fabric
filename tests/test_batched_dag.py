import dataclasses
import hashlib
import hmac
import pytest
from intent_fabric.contracts.batched_dag import (
    BatchedDAGToken,
    DAGCycleError,
    DAGHaltedOnReadbackError,
    DAGPolicyViolationError,
    DAGStepSpec,
    ReadbackState,
    verify_and_execute_batched_dag,
)

SECRET = b"0123456789abcdef0123456789abcdef"


def test_batched_dag_topological_execution_and_readback_chaining():
    consumed: set[str] = set()
    steps = [
        DAGStepSpec(
            step_id="step_2_commit",
            tool_name="commit_invoice",
            arguments={"invoice_id": "inv-100", "currency": "EUR €"},
            depends_on=("step_1_validate",),
        ),
        DAGStepSpec(
            step_id="step_1_validate",
            tool_name="validate_budget",
            arguments={"cost_center": "cc-42", "amount": 450},
            depends_on=(),
        ),
    ]
    token = BatchedDAGToken.mint(
        tenant_id="tenant-alpha",
        actor_id="agent:billing-bot",
        steps=steps,
        secret_key=SECRET,
    )
    # Topological sort must place step_1_validate before step_2_commit
    assert [s.step_id for s in token.ordered_steps] == ["step_1_validate", "step_2_commit"]

    registry = {
        "validate_budget": lambda args, prev: (
            ReadbackState.CONFIRMED,
            {"ok": True, "amt": args["amount"]},
        ),
        "commit_invoice": lambda args, prev: (
            ReadbackState.CONFIRMED,
            {"committed": True, "parent_hash": prev["step_1_validate"].readback_hash},
        ),
    }

    report = verify_and_execute_batched_dag(
        token=token,
        secret_key=SECRET,
        tool_A_registry=registry,
        expected_tenant_id="tenant-alpha",
        consumed_token_ids=consumed,
    )
    assert report.final_status == ReadbackState.CONFIRMED
    assert len(report.step_receipts) == 2
    assert len(report.composite_readback_digest) == 64

    # Replay of consumed token MUST fail closed
    with pytest.raises(DAGPolicyViolationError, match="already consumed"):
        verify_and_execute_batched_dag(token, SECRET, registry, "tenant-alpha", consumed)


def test_rejects_cycles_and_halts_on_uncertain_readback():
    cyclic = [
        DAGStepSpec("a", "t1", {}, depends_on=("b",)),
        DAGStepSpec("b", "t2", {}, depends_on=("a",)),
    ]
    with pytest.raises(DAGCycleError, match="cycle"):
        BatchedDAGToken.mint("t1", "a1", cyclic, SECRET)

    steps = [
        DAGStepSpec("s1", "flaky_write", {"id": 1}),
        DAGStepSpec("s2", "downstream_step", {"id": 2}, depends_on=("s1",)),
    ]
    tok = BatchedDAGToken.mint("t1", "a1", steps, SECRET)
    executed_s2 = []
    registry = {
        "flaky_write": lambda a, p: (ReadbackState.UNCERTAIN, {"reason": "timeout"}),
        "downstream_step": lambda a, p: (executed_s2.append(True) or ReadbackState.CONFIRMED, {}),
    }
    with pytest.raises(DAGHaltedOnReadbackError, match="status UNCERTAIN"):
        verify_and_execute_batched_dag(tok, SECRET, registry, "t1", set())
    assert executed_s2 == []


def test_topological_sort_edge_cases():
    with pytest.raises(DAGCycleError, match="at least one step"):
        BatchedDAGToken.mint("t1", "a1", [], SECRET)

    with pytest.raises(DAGCycleError, match="non-empty step_id and tool_name"):
        BatchedDAGToken.mint("t1", "a1", [DAGStepSpec("", "t1", {})], SECRET)

    with pytest.raises(DAGCycleError, match="non-empty step_id and tool_name"):
        BatchedDAGToken.mint("t1", "a1", [DAGStepSpec("s1", "", {})], SECRET)

    with pytest.raises(DAGCycleError, match="Duplicate step_id"):
        BatchedDAGToken.mint(
            "t1", "a1", [DAGStepSpec("s1", "t1", {}), DAGStepSpec("s1", "t2", {})], SECRET
        )

    with pytest.raises(DAGCycleError, match="depends on unknown step"):
        BatchedDAGToken.mint(
            "t1", "a1", [DAGStepSpec("s1", "t1", {}, depends_on=("unknown",))], SECRET
        )

    with pytest.raises(DAGCycleError, match="cannot depend on itself"):
        BatchedDAGToken.mint("t1", "a1", [DAGStepSpec("s1", "t1", {}, depends_on=("s1",))], SECRET)


def test_mint_policy_validations():
    steps = [DAGStepSpec("s1", "t1", {})]

    # Secret key < 32 bytes
    with pytest.raises(DAGPolicyViolationError, match="at least 32 non-whitespace bytes"):
        BatchedDAGToken.mint("t1", "a1", steps, b"short")

    with pytest.raises(DAGPolicyViolationError, match="at least 32 non-whitespace bytes"):
        BatchedDAGToken.mint("t1", "a1", steps, "short_str")

    # Empty tenant or actor
    with pytest.raises(DAGPolicyViolationError, match="tenant_id and actor_id are mandatory"):
        BatchedDAGToken.mint("", "a1", steps, SECRET)

    with pytest.raises(DAGPolicyViolationError, match="tenant_id and actor_id are mandatory"):
        BatchedDAGToken.mint("t1", "", steps, SECRET)

    # Invalid TTL
    with pytest.raises(DAGPolicyViolationError, match="ttl_seconds must be in"):
        BatchedDAGToken.mint("t1", "a1", steps, SECRET, ttl_seconds=0)

    with pytest.raises(DAGPolicyViolationError, match="ttl_seconds must be in"):
        BatchedDAGToken.mint("t1", "a1", steps, SECRET, ttl_seconds=301)


def test_verify_and_execute_policy_violations():
    steps = [DAGStepSpec("s1", "t1", {})]
    token = BatchedDAGToken.mint("tenant-1", "actor-1", steps, SECRET, ttl_seconds=10.0)
    registry = {"t1": lambda a, p: (ReadbackState.CONFIRMED, {"res": "ok"})}

    # Secret key < 32 bytes on verify
    with pytest.raises(DAGPolicyViolationError, match="at least 32 non-whitespace bytes"):
        verify_and_execute_batched_dag(token, b"short", registry, "tenant-1", set())

    with pytest.raises(DAGPolicyViolationError, match="at least 32 non-whitespace bytes"):
        verify_and_execute_batched_dag(token, "short_str", registry, "tenant-1", set())

    # Tenant mismatch
    with pytest.raises(DAGPolicyViolationError, match="Tenant isolation violation"):
        verify_and_execute_batched_dag(token, SECRET, registry, "tenant-2", set())

    # Expired token
    with pytest.raises(DAGPolicyViolationError, match="has expired"):
        verify_and_execute_batched_dag(
            token, SECRET, registry, "tenant-1", set(), now_fn=lambda: token.expires_at + 1.0
        )

    # Tampered dag_digest
    tampered_steps_token = BatchedDAGToken(
        token_id=token.token_id,
        tenant_id=token.tenant_id,
        actor_id=token.actor_id,
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        ordered_steps=(DAGStepSpec("s1", "t1", {"tampered": True}),),
        dag_digest=token.dag_digest,
        signature=token.signature,
    )
    with pytest.raises(DAGPolicyViolationError, match="DAG step_authorizations digest mismatch"):
        verify_and_execute_batched_dag(tampered_steps_token, SECRET, registry, "tenant-1", set())

    # Tampered signature
    tampered_sig_token = BatchedDAGToken(
        token_id=token.token_id,
        tenant_id=token.tenant_id,
        actor_id=token.actor_id,
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        ordered_steps=token.ordered_steps,
        dag_digest=token.dag_digest,
        signature="0000000000000000000000000000000000000000000000000000000000000000",
    )
    with pytest.raises(DAGPolicyViolationError, match="HMAC signature mismatch"):
        verify_and_execute_batched_dag(tampered_sig_token, SECRET, registry, "tenant-1", set())

    # Undeclared tool
    with pytest.raises(DAGPolicyViolationError, match="Undeclared or forbidden tool"):
        verify_and_execute_batched_dag(token, SECRET, {}, "tenant-1", set())


def test_halt_on_failed_readback_and_dependency_failure():
    steps = [
        DAGStepSpec("s1", "t1", {}),
        DAGStepSpec("s2", "t2", {}, depends_on=("s1",)),
    ]
    tok = BatchedDAGToken.mint("t1", "a1", steps, SECRET)

    # s1 returns FAILED
    registry_failed = {
        "t1": lambda a, p: (ReadbackState.FAILED, {"err": "disk full"}),
        "t2": lambda a, p: (ReadbackState.CONFIRMED, {}),
    }
    with pytest.raises(DAGHaltedOnReadbackError, match="status FAILED"):
        verify_and_execute_batched_dag(tok, SECRET, registry_failed, "t1", set())

    # Manually constructed execution where dependency receipt is missing or not CONFIRMED
    # Test line 295 by passing token with unconfirmed dep during step loop
    flaky_tok = BatchedDAGToken.mint("t1", "a1", steps, SECRET)
    executed_s2 = []
    reg_flaky = {
        "t1": lambda a, p: (ReadbackState.UNCERTAIN, {"reason": "timeout"}),
        "t2": lambda a, p: (executed_s2.append(True) or ReadbackState.CONFIRMED, {}),
    }
    with pytest.raises(DAGHaltedOnReadbackError, match="status UNCERTAIN"):
        verify_and_execute_batched_dag(flaky_tok, SECRET, reg_flaky, "t1", set())
    assert executed_s2 == []


def test_dependency_receipt_missing_and_32_byte_key_floor():
    # 1. Verify 32-byte (256-bit) minimum key floor
    short_key = b"short-16byte-key"
    step = DAGStepSpec(step_id="s1", tool_name="noop", arguments={})
    with pytest.raises(DAGPolicyViolationError, match="32 non-whitespace bytes"):
        BatchedDAGToken.mint("tenant-1", "actor-1", [step], secret_key=short_key)

    # 2. Verify defensive guard when a dependency receipt is missing at runtime
    s1 = DAGStepSpec(step_id="s1", tool_name="noop", arguments={})
    s2 = DAGStepSpec(step_id="s2", tool_name="noop", arguments={}, depends_on=("s1",))
    tok = BatchedDAGToken.mint("tenant-1", "actor-1", [s1, s2], secret_key=SECRET)

    # Mutate s2's depends_on via object.__setattr__ inside s1's handler to trigger missing dependency receipt
    def _mutating_s1(args, receipts):
        object.__setattr__(s2, "depends_on", ("missing_ghost_step",))
        return (ReadbackState.CONFIRMED, {"ok": True})

    registry = {
        "noop": _mutating_s1,
    }
    with pytest.raises(DAGHaltedOnReadbackError, match="not CONFIRMED"):
        verify_and_execute_batched_dag(tok, SECRET, registry, "tenant-1", set())
