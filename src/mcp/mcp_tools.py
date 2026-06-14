"""
MCP Tool Definitions — Schema definitions for MCP tools.

Ported from Claude Code's tool system.
Each tool has a name, description, input_schema (JSON Schema),
and optional categories and approval requirements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MCPToolParameter:
    """A parameter definition for an MCP tool."""
    name: str
    type: str  # "string", "number", "boolean", "array", "object"
    description: str = ""
    required: bool = False
    default: Any = None
    enum: Optional[List[str]] = None
    items: Optional[Dict[str, Any]] = None  # For array types


@dataclass
class MCPToolDefinition:
    """Schema definition for an MCP tool.

    Matches Claude Code's tool definition format:
    - name: Unique tool identifier
    - description: Human-readable description
    - input_schema: JSON Schema for tool parameters
    - categories: Tool categorization
    - requires_approval: Whether user confirmation is needed
    - handler: Optional handler function
    """

    name: str
    description: str
    input_schema: Dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    categories: List[str] = field(default_factory=list)
    requires_approval: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "categories": self.categories,
            "requires_approval": self.requires_approval,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MCPToolDefinition":
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            input_schema=data.get("input_schema", {"type": "object", "properties": {}}),
            categories=data.get("categories", []),
            requires_approval=data.get("requires_approval", False),
        )


def create_string_param(
    name: str,
    description: str = "",
    required: bool = False,
    default: Any = None,
    enum: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Create a string parameter schema entry."""
    param = {"type": "string", "description": description}
    if default is not None:
        param["default"] = default
    if enum:
        param["enum"] = enum
    return param


def create_int_param(
    name: str,
    description: str = "",
    required: bool = False,
    default: Any = None,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> Dict[str, Any]:
    """Create an integer parameter schema entry."""
    param = {"type": "integer", "description": description}
    if default is not None:
        param["default"] = default
    if minimum is not None:
        param["minimum"] = minimum
    if maximum is not None:
        param["maximum"] = maximum
    return param


def create_bool_param(
    name: str,
    description: str = "",
    required: bool = False,
    default: Any = None,
) -> Dict[str, Any]:
    """Create a boolean parameter schema entry."""
    param = {"type": "boolean", "description": description}
    if default is not None:
        param["default"] = default
    return param


def create_array_param(
    name: str,
    description: str = "",
    required: bool = False,
    items: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create an array parameter schema entry."""
    param = {"type": "array", "description": description}
    if items:
        param["items"] = items
    return param


# ── Built-in MCP Tool Definitions ──
# These match Claude Code's built-in tool set

BUILTIN_MCP_TOOLS = [
    MCPToolDefinition(
        name="analyze_code",
        description="Analyze source code for vulnerabilities and issues",
        input_schema={
            "type": "object",
            "properties": {
                "code": create_string_param("code", "Source code to analyze", required=True),
                "language": create_string_param("language", "Programming language", enum=["python", "javascript", "typescript", "java", "go", "rust", "cpp", "c", "solidity", "other"]),
                "analysis_type": create_string_param("analysis_type", "Type of analysis", enum=["security", "quality", "performance", "full"], default="security"),
            },
            "required": ["code"],
        },
        categories=["code", "security"],
        requires_approval=False,
    ),
    MCPToolDefinition(
        name="execute_python",
        description="Execute Python code in a sandboxed environment",
        input_schema={
            "type": "object",
            "properties": {
                "code": create_string_param("code", "Python code to execute", required=True),
                "timeout": create_int_param("timeout", "Execution timeout in seconds", default=30, minimum=1, maximum=300),
            },
            "required": ["code"],
        },
        categories=["code", "execution"],
        requires_approval=True,
    ),
    MCPToolDefinition(
        name="execute_bash",
        description="Execute a bash command in a sandboxed environment",
        input_schema={
            "type": "object",
            "properties": {
                "command": create_string_param("command", "Bash command to execute", required=True),
                "timeout": create_int_param("timeout", "Execution timeout in seconds", default=30, minimum=1, maximum=300),
            },
            "required": ["command"],
        },
        categories=["system", "execution"],
        requires_approval=True,
    ),
    MCPToolDefinition(
        name="search_codebase",
        description="Search the codebase for patterns and references",
        input_schema={
            "type": "object",
            "properties": {
                "pattern": create_string_param("pattern", "Search pattern (regex or plain text)", required=True),
                "path": create_string_param("path", "Path to search within"),
                "file_pattern": create_string_param("file_pattern", "File glob pattern (e.g., *.py)"),
                "max_results": create_int_param("max_results", "Maximum results to return", default=50, minimum=1, maximum=500),
            },
            "required": ["pattern"],
        },
        categories=["code", "search"],
        requires_approval=False,
    ),
    MCPToolDefinition(
        name="read_file",
        description="Read the contents of a file",
        input_schema={
            "type": "object",
            "properties": {
                "path": create_string_param("path", "Path to the file", required=True),
                "max_length": create_int_param("max_length", "Maximum characters to read", default=None),
            },
            "required": ["path"],
        },
        categories=["system", "files"],
        requires_approval=False,
    ),
    MCPToolDefinition(
        name="write_file",
        description="Write content to a file",
        input_schema={
            "type": "object",
            "properties": {
                "path": create_string_param("path", "Path to the file", required=True),
                "content": create_string_param("content", "Content to write", required=True),
            },
            "required": ["path", "content"],
        },
        categories=["system", "files"],
        requires_approval=True,
    ),
    MCPToolDefinition(
        name="list_directory",
        description="List files and directories in a path",
        input_schema={
            "type": "object",
            "properties": {
                "path": create_string_param("path", "Directory path", required=True),
                "recursive": create_bool_param("recursive", "List recursively", default=False),
            },
            "required": ["path"],
        },
        categories=["system", "files"],
        requires_approval=False,
    ),
    MCPToolDefinition(
        name="think",
        description="Use the adaptive thinking engine for deep reasoning",
        input_schema={
            "type": "object",
            "properties": {
                "query": create_string_param("query", "What to think about", required=True),
                "effort": create_string_param("effort", "Thinking effort level", enum=["low", "medium", "high", "max"], default="high"),
                "context": create_string_param("context", "Optional context for the thinking"),
            },
            "required": ["query"],
        },
        categories=["ai", "reasoning"],
        requires_approval=False,
    ),
    MCPToolDefinition(
        name="run_security_scan",
        description="Run a comprehensive security scan on code or a directory",
        input_schema={
            "type": "object",
            "properties": {
                "target": create_string_param("target", "Code or file/directory path to scan", required=True),
                "scan_type": create_string_param("scan_type", "Type of scan", enum=["vulnerability", "supply_chain", "secret", "full"], default="vulnerability"),
                "depth": create_string_param("depth", "Scan depth", enum=["quick", "deep", "exhaustive"], default="deep"),
            },
            "required": ["target"],
        },
        categories=["security", "scanning"],
        requires_approval=True,
    ),
    MCPToolDefinition(
        name="generate_patch",
        description="Generate a security patch/fix for a vulnerability",
        input_schema={
            "type": "object",
            "properties": {
                "code": create_string_param("code", "Vulnerable code", required=True),
                "vulnerability": create_string_param("vulnerability", "Type of vulnerability", required=True),
                "language": create_string_param("language", "Programming language"),
            },
            "required": ["code", "vulnerability"],
        },
        categories=["code", "security"],
        requires_approval=True,
    ),
    MCPToolDefinition(
        name="query_memory",
        description="Query persistent memory for stored context and information",
        input_schema={
            "type": "object",
            "properties": {
                "query": create_string_param("query", "What to look up in memory", required=True),
                "max_results": create_int_param("max_results", "Maximum results to return", default=5, minimum=1, maximum=20),
            },
            "required": ["query"],
        },
        categories=["memory", "ai"],
        requires_approval=False,
    ),
    MCPToolDefinition(
        name="store_memory",
        description="Store information in persistent memory",
        input_schema={
            "type": "object",
            "properties": {
                "content": create_string_param("content", "Content to remember", required=True),
                "tags": create_array_param("tags", "Tags for categorization", items={"type": "string"}),
                "importance": create_string_param("importance", "Importance level", enum=["low", "medium", "high", "critical"], default="medium"),
            },
            "required": ["content"],
        },
        categories=["memory", "ai"],
        requires_approval=False,
    ),
    MCPToolDefinition(
        name="check_permissions",
        description="Check if an operation is permitted by the permission system",
        input_schema={
            "type": "object",
            "properties": {
                "operation": create_string_param("operation", "Operation to check", required=True),
                "resource": create_string_param("resource", "Resource being accessed"),
            },
            "required": ["operation"],
        },
        categories=["system", "security"],
        requires_approval=False,
    ),
    MCPToolDefinition(
        name="get_system_info",
        description="Get system information and diagnostics",
        input_schema={
            "type": "object",
            "properties": {
                "category": create_string_param("category", "Info category", enum=["all", "system", "agents", "memory", "tools", "commands"], default="all"),
            },
        },
        categories=["system", "diagnostics"],
        requires_approval=False,
    ),
    MCPToolDefinition(
        name="run_command",
        description="Execute a slash command programmatically",
        input_schema={
            "type": "object",
            "properties": {
                "command": create_string_param("command", "Slash command to run (e.g., /help, /doctor, /review)", required=True),
                "args": create_string_param("args", "Arguments for the command"),
            },
            "required": ["command"],
        },
        categories=["system", "commands"],
        requires_approval=False,
    ),
]


def create_tool_definitions() -> Dict[str, MCPToolDefinition]:
    """Create a dictionary of all built-in MCP tool definitions."""
    return {tool.name: tool for tool in BUILTIN_MCP_TOOLS}
