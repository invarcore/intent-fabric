<p align="center">
  <img src="./assets/banner.jpg" alt="Knowledge Fabric & Intent Fabric" width="100%" style="max-width: 900px; border-radius: 12px;" />
</p>

# Intent Fabric

<p align="center">
  <strong>Vendor-neutral, policy-governed agent planning and approval framework.</strong><br>
  Deterministic Action Contracts &bull; Declarative YAML Policy Engine &bull; Cryptographic HMAC Approvals &bull; Indirect Injection Defense &bull; MCP-Native
</p>

<p align="center">
  <a href="https://github.com/invarcore/intent-fabric/actions"><img src="https://github.com/invarcore/intent-fabric/actions/workflows/ci.yml/badge.svg" alt="CI Status"></a>
  <a href="https://github.com/invarcore/intent-fabric/releases"><img src="https://img.shields.io/badge/Release-v0.1.1-blue.svg" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-Native%20Server-purple.svg" alt="MCP Native"></a>
  <a href="https://github.com/invarcore/knowledge-fabric"><img src="https://img.shields.io/badge/Ecosystem-Knowledge%20Fabric-9B51E0.svg" alt="Knowledge Fabric"></a>
</p>

---

## ⚡ 30-Second Quickstart

```python
from intent_fabric.mcp import IntentFabricMCPTools

tools = IntentFabricMCPTools()

# 1. Create an evidence-grounded plan
plan = tools.create_plan_from_evidence(
    intent_request={
        "intent_id": "intent_001",
        "user_request": "Update billing address for enterprise account 10482",
        "requested_actions": ["ticket_create"],
    },
    evidence_package={
        "query_text": "billing address",
        "items": [{"chunk_id": 10482, "document_uri": "crm://tier", "snippet": "Tier: Enterprise", "score": 0.95}],
    },
)

# 2. Out-of-Band Policy Inspection
decision = tools.validate_plan(plan)
print(f"Policy Decision: {decision['payload']['decision']}")

# 3. Cryptographic HMAC Token for Human Approver
if decision["payload"]["decision"] == "requires_approval":
    signed = tools.sign_approval(
        approval_id="appr_10482",
        plan_id=plan["payload"]["plan_id"],
        step_ids=["step_1"],
        decision="approved",
        reviewer="secops-lead@company.com",
    )
    print(f"Approval Token (HMAC-SHA256): {signed['payload']['signature']}")
```

---

## The Autonomous Agent Fear Factor: Why CTOs Block AI Deployment

Enterprise engineering and security leaders want the productivity of autonomous AI agents, but they cannot accept the catastrophic risk of unconstrained execution. If an AI agent hallucinates an unauthorized refund, deletes a database table, or leaks confidential customer records, the enterprise bears full legal and financial liability.

| Unconstrained Autonomous Agents | Intent Fabric Governance Architecture |
| :--- | :--- |
| **Black-Box API Execution**: The LLM calls external tools and APIs with zero intermediate policy inspection or schema enforcement. | **Deterministic Action Contracts**: Every proposed action is converted into an explicit, auditable `PlanStep` with strict parameter typing before anything can execute. |
| **Brittle Prompt Guardrails**: Safety rules are embedded in natural language system prompts (*"Please do not delete data"*), easily bypassed by jailbreaks. | **Out-of-Band YAML Policy Engine**: Hard deterministic evaluation rules with glob patterns, priority weighting, and hot-reloading that evaluate actions independently of the LLM. |
| **Binary All-or-Nothing Execution**: If an action is risky, the entire agent run crashes or blindly proceeds without oversight. | **Human-in-the-Loop Approval Packages**: Generates structured, tamper-evident approval requests (`requires_approval`) routed to human reviewers in Slack, Jira, or the Visual Admin Console. |
| **Vulnerable to Indirect Prompt Injection**: Adversarial text hidden inside retrieved documents hijacks the agent's planning logic. | **XML Evidence Sandboxing**: Strict evidence boundaries (`<retrieved_evidence>`) isolate untrusted data from instructions, backed by syntax sanitization (`^[a-zA-Z0-9_.:-]{1,128}$`). |
| **Non-Repudiation Failure**: No cryptographic proof of who authorized a production state mutation. | **HMAC-SHA256 Cryptographic Tokens**: Every human approval decision generates a signed, tamper-evident cryptographic token verified by execution adapters. |
| **Vendor Lock-In**: Frameworks tie planning loops to proprietary cloud APIs. | **Local & Multi-Cloud Planner Support**: Runs locally and privately with Ollama (Llama 3, Mistral), with drop-in support for OpenRouter (free tier & multi-model routing), OpenAI, Gemini, and Azure AI Foundry. |

---

## Architecture: Defense-in-Depth Governance

```mermaid
flowchart TB
    subgraph Input ["1. INTENT & EVIDENCE SANDBOX"]
        UserReq["User Intent Request\n'Create emergency access review for jdoe'"]
        Evidence["Knowledge Fabric Evidence Package\n(Encapsulated in <retrieved_evidence> tags)"]
    end

    subgraph Planning ["2. DETERMINISTIC PLANNER"]
        UserReq --> Planner{"Intent Planner\n(Ollama / OpenAI / Gemini / Foundry)"}
        Evidence --> Planner
        Planner --> Plan["Deterministic Plan\n• Step 1: Query user profile [analysis_review]\n• Step 2: Create ticket [ticket_create]\n• Step 3: Dispatch alert [notification_send]"]
    end

    subgraph Governance ["3. OUT-OF-BAND POLICY ENGINE"]
        Rules[("YAML Policy Rules\n(policy_rules.yaml)\n• Globs: ticket_*, db_*\n• Priorities & Conditions")] --> Engine["Policy Evaluation Engine\n(Worst-Outcome Aggregation)"]
        Plan --> Engine
        Engine --> Decision{"Policy Decision"}
    end

    subgraph Outcomes ["4. GOVERNANCE DISPATCH & AUDIT"]
        Decision -- "ALLOW" --> Sim["Simulation & Direct Safe Dispatch"]
        Decision -- "REQUIRES_APPROVAL" --> ApprovalPkg["Approval Package (HMAC Signed)\n• Plan ID & Step Details\n• Exact policy violation reasons\n• Routed to Human Reviewer"]
        Decision -- "DENY" --> Denied["Immediate Hard Rejection\n(Audit Log Recorded)"]
        ApprovalPkg --> Console["Visual Admin Console / Slack / Jira"]
        Console -- "Human Approved" --> Sig["HMAC-SHA256 Token"]
        Sig --> Exec["Enterprise Adapter Execution Gate"]
    end
```

---

## Industry Governance Blueprints

### 1. Financial Services & Banking
* **Scenario**: Automated AML (Anti-Money Laundering) transaction review and account holds.
* **Governance Rule**: Analysis and pattern matching (`analysis_aml_*`) are pre-approved (`allow`). Any fund freeze or account restriction (`account_hold_*`) automatically triggers `REQUIRES_APPROVAL` routed to the Compliance Officer with cited transaction evidence.

### 2. Healthcare & Clinical Operations
* **Scenario**: Clinical workflow triage and medication order validation.
* **Governance Rule**: Medical protocol retrieval is pre-approved. Any order dispatched to the pharmacy EHR (`ehr_rx_order`) requires an attending physician's cryptographic HMAC sign-off.

### 3. Cloud Infrastructure & DevOps
* **Scenario**: Automated SRE alert remediation on Kubernetes clusters.
* **Governance Rule**: Read-only log inspection (`k8s_get_*`, `k8s_describe_*`) executes autonomously. Mutative actions (`k8s_restart_*`, `helm_rollback`) require senior on-call approval. Destructive actions (`k8s_delete_namespace`, `db_drop_*`) are blocked immediately (`deny`).

---

## Cryptographic Non-Repudiation (HMAC-SHA256)

When an action requires human review, Intent Fabric generates a structured `ApprovalPackage`. Once approved by an authorized reviewer, an HMAC-SHA256 signature is generated:

```json
{
  "approval_id": "appr_87f2e1a9",
  "plan_id": "plan_98234",
  "action": "ticket_create",
  "decision": "Approved",
  "reviewer": "secops-lead@company.com",
  "comment": "Verified emergency request against change ticket CHG-4091",
  "timestamp": 1725624000,
  "algorithm": "HMAC-SHA256",
  "signature": "3b7f8c92a1e4d560718294a5c6d7e8f90123456789abcdef0123456789abcdef"
}
```

Downstream enterprise execution adapters verify this cryptographic token before committing any mutative state changes, guaranteeing full auditability and non-repudiation for SOC 2 Type II compliance.

---

## Quickstart

### 1. Install via PyPI
```bash
pip install intent-fabric
```

### 2. Select Planning Backend
Choose between local, zero-cost inference or enterprise cloud providers:
```bash
# Option A: 100% Local & Private (Recommended)
export INTENT_PLANNER=ollama
ollama pull llama3

# Option B: Enterprise Cloud APIs
# export INTENT_PLANNER=openai; export OPENAI_API_KEY=sk-...
# export INTENT_PLANNER=gemini; export GEMINI_API_KEY=...
# export INTENT_PLANNER=foundry; export FOUNDRY_BASE_URL=http://127.0.0.1:61633
```

### 3. Python Usage Example
```python
from intent_fabric.mcp import IntentFabricMCPTools

tools = IntentFabricMCPTools()

# 1. Generate an evidence-grounded plan
plan = tools.create_plan_from_evidence(
    intent_request={
        "intent_id": "intent_001",
        "user_request": "Investigate cluster alert and restart unhealthy pods",
        "requested_actions": ["k8s_get_pods", "k8s_restart_pod"],
    },
    evidence_package={
        "query_text": "runbook for pod crashloop",
        "items": [
            {
                "chunk_id": 101,
                "document_uri": "runbooks://k8s-triage.md",
                "snippet": "If pod status is CrashLoopBackOff for >15m, restart deployment and notify SRE.",
                "score": 0.94,
            }
        ],
    },
)

# 2. Evaluate against declarative YAML policy rules
decision = tools.validate_plan(plan)
print(f"Policy Decision: {decision['payload']['decision']}")
# Output: requires_approval

# 3. Create approval package for human review
if decision["payload"]["decision"] == "requires_approval":
    approval = tools.create_approval_package(plan, decision, requested_by="oncall-agent")
    print(f"Approval ID: {approval['payload']['approval_id']}")
    print(f"Policy Reasons: {approval['payload']['policy_reasons']}")

# 4. Cryptographically sign approval
signed = tools.sign_approval(
    approval_id=approval['payload']['approval_id'],
    plan_id=plan['payload']['plan_id'],
    step_ids=approval['payload']['step_ids'],
    decision="approved",
    reviewer="oncall-lead@company.com",
)
print(f"HMAC Signature: {signed['payload']['signature']}")
```

### 4. FastMCP Server Transport (Stdio)
Run Intent Fabric as an MCP server for Claude Desktop, Cursor, or autonomous AI agents:
```bash
# Run directly via CLI entrypoint
intent-fabric-mcp

# Or via uv
uv run intent-fabric-mcp
```

Add to your host's MCP configuration (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "intent-fabric": {
      "command": "intent-fabric-mcp"
    }
  }
}
```


---

## Declarative YAML Policy Rules

Policies live in `config/policy_rules.yaml` and support live hot-reloading without process restarts:

```yaml
rules:
  # Hard Deny: Destructive database and infrastructure mutations
  - action_pattern: "db_drop*"
    decision: "deny"
    reason: "Destructive database operations are strictly prohibited."
    priority: 100

  - action_pattern: "k8s_delete_*"
    decision: "deny"
    reason: "Namespace or cluster deletion is strictly prohibited."
    priority: 100

  # Require Human Approval: Write and external communication actions
  - action_pattern: "ticket_*"
    decision: "requires_approval"
    reason: "External ticket modifications require human review."
    priority: 50

  - action_pattern: "k8s_restart_*"
    decision: "requires_approval"
    reason: "Production pod restarts require on-call authorization."
    priority: 50

  # Pre-Approved: Safe read-only inspection
  - action_pattern: "analysis_*"
    decision: "allow"
    reason: "Read-only inspection and diagnosis are pre-approved."
    priority: 10

default_decision: "requires_approval"
```

---

## Model Context Protocol (MCP) Tools

Intent Fabric exposes planning and governance tools conforming to the open MCP specification:

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `create_plan_from_evidence` | `intent_request` (dict), `evidence_package` (dict) | Generates a structured multi-step plan grounded in provided evidence citations. |
| `validate_plan` | `plan` (dict) | Evaluates all plan steps against active policy rules and returns a consolidated decision. |
| `create_approval_package` | `plan` (dict), `decision` (dict), `requested_by` (str) | Assembles a tamper-evident approval payload for human sign-off. |
| `simulate_plan` | `plan` (dict), `decision` (dict) | Simulates plan execution with zero external side effects and records state traces. |
| `sign_approval` | `approval_id` (str), `plan_id` (str), `step_ids` (list[str]), `decision` (str), `reviewer` (str), `timestamp` (str\|null) | Generates a deterministic HMAC-SHA256 non-repudiation signature over the approval decision. |
| `health_check` | *None* | Verifies planner provider health and policy rule engine status. |

---

## End-to-End Stack Integration
 
Intent Fabric coordinates governance across the entire 5-repository Fabric ecosystem:
1. **[Knowledge Fabric Enterprise Adapters](https://github.com/invarcore/knowledge-fabric-enterprise-adapters)**: Ingests enterprise SaaS documents (Jira, Confluence, Notion) with automated secret scrubbing (DLP).
2. **[Knowledge Fabric](https://github.com/invarcore/knowledge-fabric)**: Slices content into structure-preserving chunks and compiles cryptographically digested `EvidencePackage`s.
3. **[Canary Fabric](https://github.com/invarcore/canary-fabric)**: Watermarks evidence chunks with invisible canary tripwires and guards step parameters via `IntentFabricCanaryGate` and `SlidingWindowStreamBuffer`.
4. **Intent Fabric** *(this repository)*: Converts user intent + evidence into deterministic, policy-checked action plans with signed HMAC-SHA256 approvals.
5. **[Unloop](https://github.com/invarcore/unloop)**: Records the multi-turn execution trajectory in a SQLite WAL store, asserts loop-freedom with `OscillationWatchdog`, and enables time-travel playback.

The full cross-repo flow is continuously verified in [`tests/test_full_ecosystem_pipeline.py`](tests/test_full_ecosystem_pipeline.py).

---

## Two-Tier Data Architecture (Zero Live HTTP in Unit CI)
- **Tier 1 (Golden Manifest Fixtures)**: Pre-recorded Kubernetes production deployments and AWS Terraform IaC manifests checked into `tests/fixtures/corpora/` for deterministic, sub-second CI policy evaluation.
- **Tier 2 (Opt-in Live Harness)**: Live structured plan verification against OpenRouter (`benchmarks/live_planner_smoke_test.py --openrouter`).

---

## 🧪 Testing & Verification

Intent Fabric maintains strict test coverage (**>=90% enforced**) and hermetic containerized test verification:

```bash
# 1. Run full test suite with coverage
uv run pytest --cov=intent_fabric --cov-report=term-missing --cov-fail-under=90

# 2. Run local hermetic end-to-end governance smoke test (<2ms)
uv run python benchmarks/live_planner_smoke_test.py

# 3. Optional: Run live structured plan verification against OpenRouter Free Tier
uv run python benchmarks/live_planner_smoke_test.py --openrouter --model openrouter/free

# 4. Run hermetic containerized test suite via Docker Compose
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit
```

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
