"""MCP server entrypoint for Intent Fabric tools."""

from __future__ import annotations

import logging
from typing import Any

from intent_fabric.mcp.tools import IntentFabricMCPTools

logger = logging.getLogger(__name__)


def create_mcp_server(tools: IntentFabricMCPTools | None = None) -> Any:
    """Create FastMCP server with intent planning, policy evaluation, and approval tools."""
    try:
        from mcp.server.fastmcp import FastMCP  # pyright: ignore[reportMissingImports,reportAttributeAccessIssue]
    except (ImportError, ModuleNotFoundError):
        from mcp.server.mcpserver import MCPServer as FastMCP  # pyright: ignore[reportMissingImports,reportAttributeAccessIssue]

    server: Any = FastMCP("intent-fabric")
    tools_instance = tools or IntentFabricMCPTools()

    @server.tool(name="health_check")
    def health_check() -> dict[str, object]:
        """Check server health and return active planner, policy rules count, and schema version."""
        return tools_instance.health_check()

    @server.tool(name="create_plan_from_evidence")
    def create_plan_from_evidence(
        intent_request: dict[str, object],
        evidence_package: dict[str, object],
    ) -> dict[str, Any]:
        """Generate a deterministic multi-step plan grounded in provided evidence citations."""
        return tools_instance.create_plan_from_evidence(
            intent_request=intent_request,
            evidence_package=evidence_package,
        )

    @server.tool(name="validate_plan")
    def validate_plan(plan: dict[str, object]) -> dict[str, Any]:
        """Evaluate plan steps against active policy rules and return a policy decision (allow/requires_approval/deny)."""
        return tools_instance.validate_plan(plan=plan)

    @server.tool(name="create_approval_package")
    def create_approval_package(
        plan: dict[str, object],
        policy_decision: dict[str, object],
        requested_by: str = "system",
    ) -> dict[str, Any]:
        """Assemble a tamper-evident approval request payload for human sign-off."""
        return tools_instance.create_approval_package(
            plan=plan,
            policy_decision=policy_decision,
            requested_by=requested_by,
        )

    @server.tool(name="simulate_plan")
    def simulate_plan(
        plan: dict[str, object],
        policy_decision: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        """Simulate plan execution with zero external side effects and record step state traces."""
        return tools_instance.simulate_plan(plan=plan, policy_decision=policy_decision)

    @server.tool(name="sign_approval")
    def sign_approval(
        approval_id: str,
        plan_id: str,
        step_ids: list[str],
        decision: str = "approved",
        reviewer: str = "system",
        timestamp: str | None = None,
        secret_key: str | None = None,
    ) -> dict[str, Any]:
        """Cryptographically sign a human approval decision using an HMAC-SHA256 non-repudiation token."""
        return tools_instance.sign_approval(
            approval_id=approval_id,
            plan_id=plan_id,
            step_ids=step_ids,
            decision=decision,
            reviewer=reviewer,
            timestamp=timestamp,
            secret_key=secret_key,
        )

    @server.tool(name="evaluate_intent")
    def evaluate_intent(
        intent_goal: str,
        evidence_package: dict[str, Any],
        max_age_seconds: float = 60.0,
    ) -> dict[str, Any]:
        """Verify evidence cryptographic provenance and evaluate policy boundaries for an intent.

        Args:
            intent_goal: The proposed action or goal.
            evidence_package: The full EvidencePackage dictionary from Knowledge Fabric.
            max_age_seconds: Maximum allowed age of the evidence in seconds (default: 60).

        Returns:
            JSON response with authorization status and signed execution token if allowed.
        """
        return tools_instance.evaluate_intent(
            intent_goal=intent_goal,
            evidence_package=evidence_package,
            max_age_seconds=max_age_seconds,
        )

    orig_call_tool = getattr(server, "call_tool", None)

    def _call_tool_wrapper(name: str, arguments: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        args = arguments if arguments is not None else kwargs
        tool_mgr = getattr(server, "_tool_manager", None)
        if tool_mgr and name in getattr(tool_mgr, "_tools", {}):
            fn = tool_mgr._tools[name].fn
            return fn(**args)
        server_tools = getattr(server, "tools", None)
        if isinstance(server_tools, dict) and name in server_tools:
            return server_tools[name](**args)
        local_tools = getattr(server, "_local_tools", None)
        if isinstance(local_tools, dict) and name in local_tools:
            return local_tools[name](**args)
        if orig_call_tool is not None:
            import asyncio
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop and loop.is_running():
                return orig_call_tool(name, args)
            return asyncio.run(orig_call_tool(name, args))
        raise KeyError(f"Tool '{name}' not found on MCP server")

    setattr(server, "call_tool", _call_tool_wrapper)

    return server


# Module-level default MCP instance
mcp = create_mcp_server()


def run_mcp_server() -> None:
    """Run the Intent Fabric MCP server using stdio transport."""
    server = create_mcp_server()
    server.run()


if __name__ == "__main__":
    run_mcp_server()


