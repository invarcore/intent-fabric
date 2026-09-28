# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-09-28

### Added
- Extensible `PlannerRegistry` supporting custom LLM and rule-based planner registrations via `register(name, factory)` and dynamic lookup.
- Cryptographic evidence package HMAC-SHA256 signature verification in `evidence_verifier.py` (`verify_evidence_package`).
- Native `GeminiLLMPlanner` for plan generation via Google Gemini models.

### Changed
- Fixed `PolicyEngine.rules_count` property and MCP `health_check` tool to accurately report loaded policy rule counts.
- Updated signing key documentation and added warnings when fallback dev keys are used in production.

## [0.1.1] - 2026-09-06

### Added
- Defense-in-depth prompt injection protections with XML evidence boundary encapsulation (`<retrieved_evidence>`).
- Strict namespaced action syntax validation (`^[a-zA-Z0-9_.:-]{1,128}$`) preventing action smuggling and path traversal.
- Cryptographic HMAC-SHA256 approval signature generation and constant-time verification (`verify_approval_signature`).
- Multi-provider LLM planning support across Ollama, OpenAI, Gemini, and Microsoft Foundry Local.
- Declarative policy engine with dynamic YAML rule loading, fnmatch globbing, and priority weighting.

### Changed
- Standardized ruff linter configurations and strict type validation across planning and policy engines.

## [0.1.0] - 2026-07-12

### Added
- Phase 2 planning, policy, approval, simulation, and MCP tool scaffolding.
