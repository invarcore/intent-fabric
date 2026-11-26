"""
Thin re-export shim for backwards compatibility.
All canonical implementation lives in `intent_fabric.etude_lock`.
"""

from __future__ import annotations

from intent_fabric.etude_lock import (
    EtudeToolEntry,
    EtudeToolLockRegistry,
    ToolImplementationDriftError,
    _NormalizedASTVisitor,
    analyze_Python_tool_ast,
)
from intent_fabric.etude_lock import *  # noqa: F401,F403

__all__ = [
    "EtudeToolEntry",
    "EtudeToolLockRegistry",
    "ToolImplementationDriftError",
    "_NormalizedASTVisitor",
    "analyze_Python_tool_ast",
]
