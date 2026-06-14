"""
MCP Server — Model Context Protocol for external tool discovery.

Ported from Anthropic Claude Code's MCP server (src/agent/tools/mcp/).
The MCP (Model Context Protocol) allows models to discover and use external
tools dynamically via a JSON-RPC interface.

Key concepts:
- Transport: Handles communication (stdio, WebSocket, HTTP)
- Tool Registry: Manages available tools and their schemas
- JSON-RPC: Standard for tool discovery and execution requests

Fable 5 Equivalent:
- Tool use system with dynamic discovery
- Schema-driven tool definitions
- Server-client architecture
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    List,
    Optional,
    Union,
)

from src.mcp.mcp_tools import MCPToolDefinition, create_tool_definitions

logger = logging.getLogger(__name__)


# ── JSON-RPC Types ──


class JSONRPCError(Exception):
    """JSON-RPC error with code and message."""

    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"[{code}] {message}")

    def to_dict(self) -> Dict[str, Any]:
        result = {"code": self.code, "message": self.message}
        if self.data is not None:
            result["data"] = self.data
        return result


# Standard JSON-RPC error codes
PARSE_ERROR = JSONRPCError(-32700, "Parse error")
INVALID_REQUEST = JSONRPCError(-32600, "Invalid Request")
METHOD_NOT_FOUND = JSONRPCError(-32601, "Method not found")
INVALID_PARAMS = JSONRPCError(-32602, "Invalid params")
INTERNAL_ERROR = JSONRPCError(-32603, "Internal error")


@dataclass
class MCPRequest:
    """A JSON-RPC request."""
    method: str
    params: Dict[str, Any] = field(default_factory=dict)
    id: Optional[str] = None
    jsonrpc: str = "2.0"

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "jsonrpc": self.jsonrpc,
            "method": self.method,
            "params": self.params,
        }
        if self.id is not None:
            d["id"] = self.id
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MCPRequest":
        return cls(
            method=data["method"],
            params=data.get("params", {}),
            id=data.get("id"),
            jsonrpc=data.get("jsonrpc", "2.0"),
        )


@dataclass
class MCPResponse:
    """A JSON-RPC response."""
    result: Any = None
    error: Optional[Dict[str, Any]] = None
    id: Optional[str] = None
    jsonrpc: str = "2.0"

    def to_dict(self) -> Dict[str, Any]:
        d = {"jsonrpc": self.jsonrpc}
        if self.id is not None:
            d["id"] = self.id
        if self.error:
            d["error"] = self.error
        else:
            d["result"] = self.result
        return d


# ── Transport Layer ──


class MCPTransport(ABC):
    """Abstract transport for MCP communication.

    Claude Code supports multiple transports:
    - stdio: For local tool execution (most common)
    - WebSocket: For IDE bridge integration
    - HTTP: For remote tool servers
    """

    @abstractmethod
    async def send(self, response: MCPResponse) -> None:
        ...

    @abstractmethod
    async def receive(self) -> Optional[MCPRequest]:
        ...

    @abstractmethod
    async def close(self) -> None:
        ...


class StdioTransport(MCPTransport):
    """stdio-based transport for MCP.

    Used by Claude Code's CLI for local tool execution.
    Messages are JSON-RPC encoded, one per line.

    By default reads from sys.stdin and writes to sys.stdout.
    Use with asyncio to connect the reader properly:
        reader, writer = await asyncio.get_event_loop().connect_readline()
    """

    def __init__(
        self,
        reader: Optional[asyncio.StreamReader] = None,
        writer: Optional[asyncio.StreamWriter] = None,
    ):
        self._reader = reader
        self._writer = writer
        self._closed = False
        self._stdin_reader: Optional[asyncio.StreamReader] = None

    async def _ensure_reader(self) -> None:
        """Lazily connect the reader to stdin if not provided."""
        if self._reader is not None:
            return
        if self._stdin_reader is not None:
            return
        try:
            loop = asyncio.get_event_loop()
            self._reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(self._reader)
            await loop.connect_read_pipe(lambda: protocol, sys.stdin)
            self._stdin_reader = self._reader
        except Exception as e:
            logger.warning(f"Could not connect stdin reader: {e}")
            self._reader = asyncio.StreamReader()

    async def send(self, response: MCPResponse) -> None:
        if self._closed:
            return
        line = json.dumps(response.to_dict()) + "\n"
        if self._writer:
            self._writer.write(line.encode("utf-8"))
            await self._writer.drain()
        else:
            # Fallback to stdout
            sys.stdout.write(line)
            sys.stdout.flush()

    async def receive(self) -> Optional[MCPRequest]:
        if self._closed:
            return None
        await self._ensure_reader()
        if self._reader is None:
            return None
        try:
            line = await self._reader.readline()
            if not line:
                return None
            data = json.loads(line.decode("utf-8").strip())
            return MCPRequest.from_dict(data)
        except json.JSONDecodeError:
            raise PARSE_ERROR
        except Exception as e:
            logger.error(f"Error receiving MCP request: {e}")
            return None

    async def close(self) -> None:
        self._closed = True


class WebSocketTransport(MCPTransport):
    """WebSocket transport for MCP.

    Used by Claude Code's IDE Bridge for VS Code/JetBrains integration.
    """

    def __init__(self):
        self._queue: asyncio.Queue = asyncio.Queue()
        self._closed = False

    async def send(self, response: MCPResponse) -> None:
        if self._closed:
            return
        await self._queue.put(response.to_dict())

    async def receive(self) -> Optional[MCPRequest]:
        if self._closed:
            return None
        data = await self._queue.get()
        return MCPRequest.from_dict(data) if isinstance(data, dict) else None

    def feed(self, data: Union[str, bytes, Dict]):
        """Feed data into the transport (called by the WebSocket handler)."""
        if isinstance(data, (str, bytes)):
            data = json.loads(data if isinstance(data, str) else data.decode("utf-8"))
        asyncio.ensure_future(self._queue.put(data))

    async def close(self) -> None:
        self._closed = False


# ── Tool Registry ──


class MCPToolRegistry:
    """Registry of MCP tools that can be discovered and executed.

    Matches Claude Code's MCP tool registration system:
    - Tools are defined by their schemas (name, description, parameters)
    - Tools are executed by their handler functions
    - Tools can be discovered via list_tools()
    """

    def __init__(self):
        self._tools: Dict[str, MCPToolDefinition] = {}
        self._handlers: Dict[str, Callable] = {}

    def register_tool(
        self,
        definition: MCPToolDefinition,
        handler: Callable[[Dict[str, Any]], Any],
    ) -> None:
        """Register a tool with its handler."""
        self._tools[definition.name] = definition
        self._handlers[definition.name] = handler
        logger.info(f"MCP tool registered: {definition.name}")

    def register_tools(
        self,
        tools: Dict[str, MCPToolDefinition],
        handlers: Dict[str, Callable],
    ) -> None:
        """Register multiple tools at once."""
        for name, definition in tools.items():
            handler = handlers.get(name)
            if handler:
                self.register_tool(definition, handler)
            else:
                self._tools[definition.name] = definition
                logger.info(f"MCP tool registered (no handler): {definition.name}")

    def get_tool(self, name: str) -> Optional[MCPToolDefinition]:
        return self._tools.get(name)

    def get_handler(self, name: str) -> Optional[Callable]:
        return self._handlers.get(name)

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all registered tools with their schemas.

        This is the primary discovery mechanism — Claude Code calls this
        to learn what tools are available.
        """
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
                "categories": t.categories,
                "requires_approval": t.requires_approval,
            }
            for t in self._tools.values()
        ]

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    @property
    def tool_count(self) -> int:
        return len(self._tools)


# ── MCP Server ──


class MCPServer:
    """MCP Server — handles JSON-RPC requests for tool discovery and execution.

    Matches Claude Code's MCP server architecture:
    1. Client sends 'list_tools' request → Server returns tool schemas
    2. Client sends 'execute_tool' request → Server runs the tool and returns result
    3. Client sends 'get_tool' request → Server returns detailed tool info

    Supported methods:
    - list_tools: List all available tools with their schemas
    - get_tool: Get detailed info about a specific tool
    - execute_tool: Execute a tool with given parameters
    - ping: Health check
    - shutdown: Graceful shutdown
    """

    def __init__(
        self,
        registry: Optional[MCPToolRegistry] = None,
        transport: Optional[MCPTransport] = None,
        allowed_origins: Optional[List[str]] = None,
    ):
        self.registry = registry or MCPToolRegistry()
        self.transport = transport or StdioTransport()
        self.allowed_origins = allowed_origins
        self._running = False
        self._server_id = f"sentinel-mcp-{uuid.uuid4().hex[:8]}"

        # Register built-in tools
        builtin_tools = create_tool_definitions()
        self.registry.register_tools(builtin_tools, {})

        logger.info(
            f"MCP Server initialized: {self._server_id}, "
            f"transport={type(self.transport).__name__}"
        )

    async def start(self) -> None:
        """Start the MCP server and begin processing requests."""
        self._running = True
        logger.info(f"MCP Server started: {self._server_id}")

        try:
            while self._running:
                request = await self.transport.receive()
                if request is None:
                    break

                response = await self._handle_request(request)
                await self.transport.send(response)

        except asyncio.CancelledError:
            logger.info("MCP Server cancelled")
        except Exception as e:
            logger.error(f"MCP Server error: {e}")
        finally:
            await self.shutdown()

    async def _handle_request(self, request: MCPRequest) -> MCPResponse:
        """Handle a single JSON-RPC request."""
        method = request.method
        params = request.params
        req_id = request.id

        try:
            if method == "list_tools":
                return MCPResponse(
                    result={"tools": self.registry.list_tools()},
                    id=req_id,
                )

            elif method == "get_tool":
                tool_name = params.get("name", "")
                tool = self.registry.get_tool(tool_name)
                if not tool:
                    return MCPResponse(
                        error=METHOD_NOT_FOUND.to_dict(),
                        id=req_id,
                    )
                return MCPResponse(
                    result={
                        "name": tool.name,
                        "description": tool.description,
                        "input_schema": tool.input_schema,
                        "categories": tool.categories,
                        "requires_approval": tool.requires_approval,
                    },
                    id=req_id,
                )

            elif method == "execute_tool":
                return await self._execute_tool(params, req_id)

            elif method == "ping":
                return MCPResponse(
                    result={
                        "status": "ok",
                        "server_id": self._server_id,
                        "tools_count": self.registry.tool_count,
                    },
                    id=req_id,
                )

            elif method == "shutdown":
                self._running = False
                return MCPResponse(
                    result={"status": "shutting_down"},
                    id=req_id,
                )

            else:
                return MCPResponse(
                    error=METHOD_NOT_FOUND.to_dict(),
                    id=req_id,
                )

        except JSONRPCError as e:
            return MCPResponse(
                error=e.to_dict(),
                id=req_id,
            )
        except Exception as e:
            logger.error(f"Unhandled error in MCP request '{method}': {e}")
            return MCPResponse(
                error=INTERNAL_ERROR.to_dict(),
                id=req_id,
            )

    async def _execute_tool(
        self,
        params: Dict[str, Any],
        req_id: Optional[str],
    ) -> MCPResponse:
        """Execute a tool with the given parameters."""
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})

        tool = self.registry.get_tool(tool_name)
        if not tool:
            return MCPResponse(
                error=JSONRPCError(
                    -32601,
                    f"Tool not found: {tool_name}",
                ).to_dict(),
                id=req_id,
            )

        handler = self.registry.get_handler(tool_name)
        if not handler:
            return MCPResponse(
                error=JSONRPCError(
                    -32601,
                    f"Tool has no handler: {tool_name}",
                ).to_dict(),
                id=req_id,
            )

        try:
            start = time.time()
            result = await handler(tool_args) if asyncio.iscoroutinefunction(handler) else handler(tool_args)
            duration = (time.time() - start) * 1000

            logger.info(f"MCP tool executed: {tool_name} ({duration:.0f}ms)")

            return MCPResponse(
                result={
                    "success": True,
                    "data": result,
                    "duration_ms": duration,
                },
                id=req_id,
            )

        except Exception as e:
            logger.error(f"MCP tool '{tool_name}' execution error: {e}")
            return MCPResponse(
                result={
                    "success": False,
                    "error": str(e),
                },
                id=req_id,
            )

    def process_request_sync(self, request_json: str) -> str:
        """Process a JSON-RPC request synchronously (for CLI use).

        Args:
            request_json: JSON string of the request

        Returns:
            JSON string of the response
        """
        try:
            data = json.loads(request_json)
            request = MCPRequest.from_dict(data)
            response = asyncio.run(self._handle_request(request))
            return json.dumps(response.to_dict())
        except Exception as e:
            return json.dumps({
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": str(e)},
                "id": None,
            })

    async def process_request(self, request: MCPRequest) -> MCPResponse:
        """Process a single request (for programmatic use)."""
        return await self._handle_request(request)

    def register_tool(
        self,
        definition: MCPToolDefinition,
        handler: Callable[[Dict[str, Any]], Any],
    ) -> None:
        """Register a tool with the server."""
        self.registry.register_tool(definition, handler)

    async def shutdown(self) -> None:
        """Gracefully shut down the MCP server."""
        self._running = False
        await self.transport.close()
        logger.info(f"MCP Server shut down: {self._server_id}")

    def get_status(self) -> Dict[str, Any]:
        """Get MCP server status."""
        return {
            "server_id": self._server_id,
            "running": self._running,
            "tools_count": self.registry.tool_count,
            "transport": type(self.transport).__name__,
            "tools": [t["name"] for t in self.registry.list_tools()],
        }
