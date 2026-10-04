# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""JSON schema contract for action contracts."""

from __future__ import annotations


def action_contract_schema() -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ActionContract",
        "type": "object",
        "required": ["contract_id", "action_type", "target", "intent", "simulated", "parameters", "justification"],
        "properties": {
            "contract_id": {"type": "string"},
            "action_type": {"type": "string"},
            "target": {"type": "string"},
            "intent": {"type": "string"},
            "simulated": {"type": "boolean"},
            "parameters": {"type": "object", "additionalProperties": True},
            "justification": {"type": "string"},
        },
        "additionalProperties": False,
    }
