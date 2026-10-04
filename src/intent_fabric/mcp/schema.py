# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""MCP payload schema versioning helpers."""

from __future__ import annotations

from typing import Any

MCP_SCHEMA_VERSION = "1.0.0"


def envelope(*, tool: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": MCP_SCHEMA_VERSION,
        "tool": tool,
        "payload": payload,
    }


def unwrap_payload(value: dict[str, Any]) -> dict[str, Any]:
    if "payload" in value and isinstance(value["payload"], dict):
        return value["payload"]  # type: ignore[return-value]
    return value
