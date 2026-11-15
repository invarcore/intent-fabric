from __future__ import annotations

import hashlib
import hmac
import json
import time
import unicodedata
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Sequence, Set, Tuple


class ReadbackState(str, Enum):
    CONFIRMED = "CONFIRMED"
    UNCERTAIN = "UNCERTAIN"
    FAILED = "FAILED"


class DAGExecutionError(RuntimeError):
    """Base error for batched DAG authorization or execution failures."""


class DAGCycleError(DAGExecutionError):
    """Raised when a batched execution graph contains a dependency cycle or unknown step."""


class DAGPolicyViolationError(DAGExecutionError):
    """Raised when a batched DAG token signature, TTL, or step digest fails verification."""


class DAGHaltedOnReadbackError(DAGExecutionError):
    """Raised when an intermediate step returns UNCERTAIN or FAILED readback."""


def _lp_utf8(value: str) -> str:
    norm = unicodedata.normalize("NFC", value)
    raw = norm.encode("utf-8")
    return f"{len(raw)}:{norm}"


def _canonical_json(obj: Any) -> str:
    return unicodedata.normalize(
        "NFC",
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
    )


@dataclass(frozen=True)
class DAGStepSpec:
    step_id: str
    tool_name: str
    arguments: Mapping[str, Any]
    depends_on: Tuple[str, ...] = ()

    def canonical_dict(self) -> Dict[str, Any]:
        return {
            "arguments": json.loads(_canonical_json(self.arguments)),
            "depends_on": sorted(unicodedata.normalize("NFC", d.strip()) for d in self.depends_on),
            "step_id": _lp_utf8(self.step_id.strip()),
            "tool_name": _lp_utf8(self.tool_name.strip()),
        }


def topological_sort_steps(steps: Sequence[DAGStepSpec]) -> Tuple[DAGStepSpec, ...]:
    """
    Deterministically validate acyclicity and return a stable topological ordering
    of DAGStepSpec nodes (Kahn's algorithm with lexicographical tie-breaking).
    """
    if not steps:
        raise DAGCycleError("Batched DAG must contain at least one step.")

    step_map: Dict[str, DAGStepSpec] = {}
    for s in steps:
        sid = s.step_id.strip()
        if not sid or not s.tool_name.strip():
            raise DAGCycleError("Each DAG step must have a non-empty step_id and tool_name.")
        if sid in step_map:
            raise DAGCycleError(f"Duplicate step_id '{sid}' in DAG.")
        step_map[sid] = s

    in_degree: Dict[str, int] = {sid: 0 for sid in step_map}
    dependents: Dict[str, List[str]] = {sid: [] for sid in step_map}

    for sid, spec in step_map.items():
        seen_deps: Set[str] = set()
        for dep in spec.depends_on:
            dep_id = dep.strip()
            if dep_id not in step_map:
                raise DAGCycleError(f"Step '{sid}' depends on unknown step '{dep_id}'.")
            if dep_id == sid:
                raise DAGCycleError(f"Step '{sid}' cannot depend on itself.")
            if dep_id not in seen_deps:
                seen_deps.add(dep_id)
                in_degree[sid] += 1
                dependents[dep_id].append(sid)

    ready = sorted([sid for sid, deg in in_degree.items() if deg == 0])
    ordered: List[DAGStepSpec] = []

    while ready:
        current = ready.pop(0)
        ordered.append(step_map[current])
        for nxt in sorted(dependents[current]):
            in_degree[nxt] -= 1
            if in_degree[nxt] == 0:
                ready.append(nxt)
                ready.sort()

    if len(ordered) != len(step_map):
        raise DAGCycleError("Dependency cycle detected in BatchedDAGToken.")

    return tuple(ordered)


@dataclass(frozen=True)
class BatchedDAGToken:
    token_id: str
    tenant_id: str
    actor_id: str
    issued_at: float
    expires_at: float
    ordered_steps: Tuple[DAGStepSpec, ...]
    dag_digest: str
    signature: str

    @classmethod
    def mint(
        cls,
        tenant_id: str,
        actor_id: str,
        steps: Sequence[DAGStepSpec],
        secret_key: bytes | str,
        ttl_seconds: float = 60.0,
        now_fn: Callable[[], float] = time.time,
    ) -> BatchedDAGToken:
        secret_bytes = (
            secret_key.strip().encode("utf-8")
            if isinstance(secret_key, str)
            else secret_key.strip()
        )
        if len(secret_bytes) < 16:
            raise DAGPolicyViolationError("Signing key must be at least 16 non-whitespace bytes.")
        if not tenant_id or not tenant_id.strip() or not actor_id or not actor_id.strip():
            raise DAGPolicyViolationError("tenant_id and actor_id are mandatory.")
        if ttl_seconds <= 0 or ttl_seconds > 300.0:
            raise DAGPolicyViolationError("ttl_seconds must be in (0, 300.0].")

        ordered = topological_sort_steps(steps)
        token_id = uuid.uuid4().hex
        issued_at = float(now_fn())
        expires_at = issued_at + float(ttl_seconds)

        dag_digest = cls._compute_dag_digest(tenant_id.strip(), actor_id.strip(), ordered)
        frame = cls._build_signing_frame(
            token_id=token_id,
            tenant_id=tenant_id.strip(),
            actor_id=actor_id.strip(),
            issued_at=issued_at,
            expires_at=expires_at,
            dag_digest=dag_digest,
        )
        sig = hmac.new(secret_bytes, frame, hashlib.sha256).hexdigest()
        return cls(
            token_id=token_id,
            tenant_id=tenant_id.strip(),
            actor_id=actor_id.strip(),
            issued_at=issued_at,
            expires_at=expires_at,
            ordered_steps=ordered,
            dag_digest=dag_digest,
            signature=sig,
        )

    @staticmethod
    def _compute_dag_digest(
        tenant_id: str, actor_id: str, ordered_steps: Sequence[DAGStepSpec]
    ) -> str:
        payload = {
            "actor_id": _lp_utf8(actor_id),
            "schema": "inv06-batched-dag-v1",
            "step_authorizations": [s.canonical_dict() for s in ordered_steps],
            "tenant_id": _lp_utf8(tenant_id),
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _build_signing_frame(
        token_id: str,
        tenant_id: str,
        actor_id: str,
        issued_at: float,
        expires_at: float,
        dag_digest: str,
    ) -> bytes:
        envelope = {
            "actor_id": _lp_utf8(actor_id),
            "dag_digest": _lp_utf8(dag_digest),
            "expires_at": f"{expires_at:.6f}",
            "issued_at": f"{issued_at:.6f}",
            "tenant_id": _lp_utf8(tenant_id),
            "token_id": _lp_utf8(token_id),
            "v": "inv06-rfc8785-v1",
        }
        return json.dumps(
            envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")


@dataclass(frozen=True)
class StepExecutionReceipt:
    step_id: str
    tool_name: str
    status: ReadbackState
    readback_hash: str
    output: Mapping[str, Any]


@dataclass(frozen=True)
class BatchedDAGExecutionReport:
    token_id: str
    tenant_id: str
    final_status: ReadbackState
    step_receipts: Tuple[StepExecutionReceipt, ...]
    composite_readback_digest: str


def verify_and_execute_batched_dag(
    token: BatchedDAGToken,
    secret_key: bytes | str,
    tool_A_registry: Mapping[
        str,
        Callable[
            [Mapping[str, Any], Mapping[str, StepExecutionReceipt]],
            Tuple[ReadbackState, Mapping[str, Any]],
        ],
    ],
    expected_tenant_id: str,
    consumed_token_ids: Set[str],
    now_fn: Callable[[], float] = time.time,
) -> BatchedDAGExecutionReport:
    """
    Verifies a BatchedDAGToken (INV-06) and executes all steps in topological order in one shot.
    Halts immediately if any step returns UNCERTAIN or FAILED readback (Opportunity 2 + 7).
    """
    secret_bytes = (
        secret_key.strip().encode("utf-8") if isinstance(secret_key, str) else secret_key.strip()
    )
    if len(secret_bytes) < 16:
        raise DAGPolicyViolationError("Signing key must be at least 16 non-whitespace bytes.")
    if token.tenant_id != expected_tenant_id.strip():
        raise DAGPolicyViolationError(
            f"Tenant isolation violation (INV-05): token='{token.tenant_id}', expected='{expected_tenant_id}'."
        )
    if token.token_id in consumed_token_ids:
        raise DAGPolicyViolationError(f"BatchedDAGToken '{token.token_id}' was already consumed.")

    now = float(now_fn())
    if now > token.expires_at:
        raise DAGPolicyViolationError(f"BatchedDAGToken '{token.token_id}' has expired.")

    ordered = topological_sort_steps(token.ordered_steps)
    expected_dag_digest = BatchedDAGToken._compute_dag_digest(
        token.tenant_id, token.actor_id, ordered
    )
    if not hmac.compare_digest(expected_dag_digest.lower(), token.dag_digest.lower()):
        raise DAGPolicyViolationError("DAG step_authorizations digest mismatch (tampered steps).")

    frame = BatchedDAGToken._build_signing_frame(
        token_id=token.token_id,
        tenant_id=token.tenant_id,
        actor_id=token.actor_id,
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        dag_digest=token.dag_digest,
    )
    expected_mac = hmac.new(secret_bytes, frame, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac.lower(), token.signature.strip().lower()):
        raise DAGPolicyViolationError("BatchedDAGToken HMAC signature mismatch.")

    # Pre-execution policy check: all referenced tools must be registered
    for spec in ordered:
        if spec.tool_name not in tool_A_registry:
            raise DAGPolicyViolationError(
                f"Undeclared or forbidden tool '{spec.tool_name}' in DAG."
            )

    consumed_token_ids.add(token.token_id)

    receipts_by_id: Dict[str, StepExecutionReceipt] = {}
    ordered_receipts: List[StepExecutionReceipt] = []

    for spec in ordered:
        for dep_id in spec.depends_on:
            dep_receipt = receipts_by_id.get(dep_id)
            if dep_receipt is None or dep_receipt.status != ReadbackState.CONFIRMED:
                raise DAGHaltedOnReadbackError(
                    f"Cannot execute '{spec.step_id}': dependency '{dep_id}' not CONFIRMED."
                )

        handler = tool_A_registry[spec.tool_name]
        state, out_payload = handler(spec.arguments, receipts_by_id)
        canonical_out = _canonical_json(out_payload)
        rb_hash = hashlib.sha256(canonical_out.encode("utf-8")).hexdigest()

        receipt = StepExecutionReceipt(
            step_id=spec.step_id,
            tool_name=spec.tool_name,
            status=state,
            readback_hash=rb_hash,
            output=out_payload,
        )
        receipts_by_id[spec.step_id] = receipt
        ordered_receipts.append(receipt)

        if state != ReadbackState.CONFIRMED:
            raise DAGHaltedOnReadbackError(
                f"Composed DAG execution halted at step '{spec.step_id}' with status {state.value}."
            )

    composite_payload = {
        "receipts": [
            {
                "readback_hash": _lp_utf8(r.readback_hash),
                "status": _lp_utf8(r.status.value),
                "step_id": _lp_utf8(r.step_id),
                "tool_name": _lp_utf8(r.tool_name),
            }
            for r in ordered_receipts
        ],
        "tenant_id": _lp_utf8(token.tenant_id),
        "token_id": _lp_utf8(token.token_id),
    }
    comp_digest = hashlib.sha256(
        json.dumps(
            composite_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()

    return BatchedDAGExecutionReport(
        token_id=token.token_id,
        tenant_id=token.tenant_id,
        final_status=ReadbackState.CONFIRMED,
        step_receipts=tuple(ordered_receipts),
        composite_readback_digest=comp_digest,
    )
