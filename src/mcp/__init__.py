"""MCP Server — Model Context Protocol for external tool discovery.

Ported from Anthropic Claude Code's MCP server architecture.
Provides JSON-RPC based tool discovery and execution.
"""

from src.mcp.mcp_server import (
    MCPServer,
    MCPTransport,
    MCPToolRegistry,
    MCPRequest,
    MCPResponse,
    JSONRPCError,
)
from src.mcp.mcp_tools import (
    MCPToolDefinition,
    MCPToolParameter,
    create_tool_definitions,
    BUILTIN_MCP_TOOLS,
)

__all__ = [
    "MCPServer",
    "MCPTransport",
    "MCPToolRegistry",
    "MCPRequest",
    "MCPResponse",
    "JSONRPCError",
    "MCPToolDefinition",
    "MCPToolParameter",
    "create_tool_definitions",
    "BUILTIN_MCP_TOOLS",
]
