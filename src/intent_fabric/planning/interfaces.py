# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Planner interfaces."""

from __future__ import annotations

from typing import Protocol

from intent_fabric.models import EvidencePackageReference, IntentRequest, Plan


class Planner(Protocol):
    """Creates a structured plan from intent and evidence."""

    def create_plan(self, intent: IntentRequest, evidence: EvidencePackageReference) -> Plan:  # pragma: no cover
        """Generate a plan for the given intent and evidence."""
        ...
