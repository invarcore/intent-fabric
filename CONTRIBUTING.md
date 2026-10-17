# Contributing to Intent Fabric

Thank you for contributing to Intent Fabric! We appreciate your help in building a robust, policy-governed agent planning framework.

---

## Development Setup

### 1. Prerequisites
- Python 3.11 or 3.12
- Git
- Optional: [Ollama](https://ollama.com) for local LLM planning (`ollama pull llama3`)

### 2. Setup Virtual Environment
```bash
git clone https://github.com/invarcore/intent-fabric.git
cd intent-fabric

python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
```

---

## Coding Standards & Testing

Before submitting a pull request, ensure all checks pass:

```bash
# 1. Run unit tests
python3 -m pytest

# 2. Check code style and linting
python3 -m ruff check src tests

# 3. Verify type checking
python3 -m pyright src
```

---

## Adding a New LLM Planner

To add a new LLM planner (e.g. Mistral, Anthropic, DeepSeek):

1. Open `src/intent_fabric/planning/llm.py`.
2. Implement the `IntentPlanner` protocol:
   ```python
   @dataclass(slots=True)
   class MyNewPlanner:
       def create_plan(
           self,
           intent_request: dict[str, Any],
           evidence_package: dict[str, Any] | None = None,
       ) -> Plan:
           ...
   ```
3. Register the provider in `build_planner()`:
   ```python
   case "mynewplanner":
       return MyNewPlanner(...)
   ```
4. Add unit tests in `tests/test_planners.py` mocking network requests using standard Python libraries.

---

## Extending Policy Rules

Policy rules are defined in YAML. Rules support:
- Exact matches: `action_pattern: "db_drop"`
- Glob wildcards: `action_pattern: "ticket_*"`
- Priority weighting: Higher priority integers take precedence over lower ones.
- Conditional constraints: `conditions: { "environment": "production" }`

See `src/intent_fabric/policies/rules.py` and `config/policy_rules.yaml`.

---

## Pull Request Guidelines

1. Create a feature branch: `git checkout -b feat/my-feature`.
2. Make targeted, well-documented changes with corresponding unit tests.
3. Keep external dependencies minimal (std-lib preferred).
4. Reference related issues in your PR description.
