"""Tests for the MCP Server (Claude Code port)."""

import asyncio
import json
import pytest
from src.mcp.mcp_server import (
    MCPServer, MCPRequest, MCPResponse,
    MCPToolRegistry, MCPTransport,
    StdioTransport, WebSocketTransport,
)
from src.mcp.mcp_tools import MCPToolDefinition, create_tool_definitions, BUILTIN_MCP_TOOLS


class TestMCPToolRegistry:
    """Tests for MCPToolRegistry."""

    @pytest.fixture
    def registry(self):
        return MCPToolRegistry()

    def test_register_tool(self, registry):
        """register_tool should add a tool."""
        def handler(p): return "ok"
        tool = MCPToolDefinition(name="test_tool", description="A test tool")
        registry.register_tool(tool, handler)
        assert registry.has_tool("test_tool")
        assert registry.tool_count == 1

    def test_get_tool(self, registry):
        """get_tool should return definition."""
        def handler(p): return "ok"
        tool = MCPToolDefinition(name="my_tool", description="My test")
        registry.register_tool(tool, handler)
        found = registry.get_tool("my_tool")
        assert found is tool
        assert found.name == "my_tool"

    def test_get_handler(self, registry):
        """get_handler should return registered handler."""
        def my_handler(p): return {"result": "done"}
        tool = MCPToolDefinition(name="handler_tool", description="Has handler")
        registry.register_tool(tool, my_handler)
        handler = registry.get_handler("handler_tool")
        assert handler is my_handler
        assert handler({}) == {"result": "done"}

    def test_get_nonexistent_tool(self, registry):
        """get_tool should return None for unknown."""
        assert registry.get_tool("nope") is None

    def test_list_tools(self, registry):
        """list_tools should return tool schemas."""
        handler = lambda p: "ok"
        registry.register_tool(
            MCPToolDefinition(name="tool_a", description="Tool A",
                              input_schema={"type": "object", "properties": {"x": {"type": "string"}}}),
            handler,
        )
        registry.register_tool(
            MCPToolDefinition(name="tool_b", description="Tool B",
                              categories=["code", "security"], requires_approval=True),
            handler,
        )
        tools = registry.list_tools()
        assert len(tools) == 2
        names = [t["name"] for t in tools]
        assert "tool_a" in names
        assert "tool_b" in names

    def test_tool_schema_in_list(self, registry):
        """list_tools should include schema details."""
        handler = lambda p: "ok"
        registry.register_tool(
            MCPToolDefinition(name="schema_tool", description="Has schema",
                              input_schema={"type": "object", "properties": {"p1": {"type": "string"}}},
                              categories=["test"], requires_approval=True),
            handler,
        )
        tools = registry.list_tools()
        t = tools[0]
        assert t["name"] == "schema_tool"
        assert t["input_schema"]["properties"]["p1"]["type"] == "string"
        assert t["requires_approval"] is True
        assert t["categories"] == ["test"]

    def test_register_tools_bulk(self, registry):
        """register_tools should register multiple tools."""
        tools = {
            "t1": MCPToolDefinition(name="t1", description="Tool 1"),
            "t2": MCPToolDefinition(name="t2", description="Tool 2"),
        }
        handlers = {
            "t1": lambda p: "ok",
        }
        registry.register_tools(tools, handlers)
        assert registry.tool_count == 2
        assert registry.get_handler("t1") is not None
        assert registry.get_handler("t2") is None  # No handler registered


class TestMCPRequest:
    """Tests for MCPRequest."""

    def test_minimal_request(self):
        """Should create request with just method."""
        req = MCPRequest(method="ping")
        assert req.method == "ping"
        assert req.params == {}
        assert req.id is None

    def test_full_request(self):
        """Should create request with all fields."""
        req = MCPRequest(method="execute_tool", params={"name": "test"}, id="req-1")
        assert req.method == "execute_tool"
        assert req.params["name"] == "test"
        assert req.id == "req-1"

    def test_to_dict(self):
        """to_dict should produce JSON-RPC format."""
        req = MCPRequest(method="list_tools", id="1")
        d = req.to_dict()
        assert d["jsonrpc"] == "2.0"
        assert d["method"] == "list_tools"
        assert d["id"] == "1"

    def test_from_dict(self):
        """from_dict should parse JSON-RPC format."""
        data = {"jsonrpc": "2.0", "method": "ping", "id": "2"}
        req = MCPRequest.from_dict(data)
        assert req.method == "ping"
        assert req.id == "2"
        assert req.jsonrpc == "2.0"

    def test_from_dict_no_id(self):
        """from_dict should handle notification (no id)."""
        data = {"jsonrpc": "2.0", "method": "ping"}
        req = MCPRequest.from_dict(data)
        assert req.method == "ping"
        assert req.id is None


class TestMCPServer:
    """Tests for MCPServer."""

    @pytest.fixture
    def server(self):
        return MCPServer()

    def test_server_init(self, server):
        """Server should init with built-in tools."""
        assert server.registry.tool_count == len(BUILTIN_MCP_TOOLS)

    def test_get_status(self, server):
        """get_status() should return server info."""
        status = server.get_status()
        assert "server_id" in status
        assert status["tools_count"] == len(BUILTIN_MCP_TOOLS)
        assert "transport" in status

    @pytest.mark.asyncio
    async def test_ping(self, server):
        """Ping should return ok status."""
        req = MCPRequest(method="ping", id="1")
        resp = await server.process_request(req)
        assert resp.result["status"] == "ok"
        assert "server_id" in resp.result
        assert resp.id == "1"

    @pytest.mark.asyncio
    async def test_list_tools(self, server):
        """list_tools should return all tools."""
        req = MCPRequest(method="list_tools", id="2")
        resp = await server.process_request(req)
        tools = resp.result.get("tools", [])
        assert len(tools) == len(BUILTIN_MCP_TOOLS)
        # Check a few known tools exist
        names = [t["name"] for t in tools]
        assert "analyze_code" in names
        assert "execute_python" in names
        assert "think" in names

    @pytest.mark.asyncio
    async def test_get_tool_exists(self, server):
        """get_tool should return tool details."""
        req = MCPRequest(method="get_tool", params={"name": "analyze_code"}, id="3")
        resp = await server.process_request(req)
        assert resp.result["name"] == "analyze_code"
        assert "input_schema" in resp.result

    @pytest.mark.asyncio
    async def test_get_tool_not_found(self, server):
        """get_tool for missing tool should error."""
        req = MCPRequest(method="get_tool", params={"name": "nonexistent"}, id="4")
        resp = await server.process_request(req)
        assert resp.error is not None
        assert resp.error["code"] == -32601

    @pytest.mark.asyncio
    async def test_unknown_method(self, server):
        """Unknown method should return error."""
        req = MCPRequest(method="unknown_method", id="5")
        resp = await server.process_request(req)
        assert resp.error is not None
        assert resp.error["code"] == -32601

    @pytest.mark.asyncio
    async def test_shutdown(self, server):
        """Shutdown should stop the server."""
        req = MCPRequest(method="shutdown", id="6")
        resp = await server.process_request(req)
        assert resp.result["status"] == "shutting_down"
        assert server._running is False

    def test_process_request_sync(self, server):
        """process_request_sync should handle JSON-RPC sync."""
        response = server.process_request_sync('{"jsonrpc":"2.0","method":"ping","id":1}')
        data = json.loads(response)
        assert data["result"]["status"] == "ok"
        assert data["id"] == 1

    def test_process_request_sync_invalid_json(self, server):
        """process_request_sync should handle invalid JSON."""
        response = server.process_request_sync("not json")
        data = json.loads(response)
        assert "error" in data

    @pytest.mark.asyncio
    async def test_execute_tool_no_handler(self, server):
        """execute_tool for tool without handler should return error in error field."""
        # BUILTIN tools are registered without handlers by default
        req = MCPRequest(method="execute_tool", params={
            "name": "analyze_code",
            "arguments": {"code": "test"},
        }, id="7")
        resp = await server.process_request(req)
        # When no handler, server returns error in the JSON-RPC error field
        # resp.result will be None, resp.error will contain the error dict
        assert resp.error is not None, "Should return JSON-RPC error response"
        assert resp.error["code"] == -32601, "Should be 'method not found' error"
        assert "handler" in resp.error.get("message", "").lower()

    @pytest.mark.asyncio
    async def test_execute_tool_not_found(self, server):
        """execute_tool for missing tool should error."""
        req = MCPRequest(method="execute_tool", params={
            "name": "no_such_tool",
        }, id="8")
        resp = await server.process_request(req)
        assert resp.error is not None

    @pytest.mark.asyncio
    async def test_execute_tool_with_handler(self, server):
        """execute_tool should work when handler is registered."""
        def my_handler(params):
            return {"result": f"processed {params.get('x', '')}"}

        tool = MCPToolDefinition(name="custom_tool", description="Custom")
        server.register_tool(tool, my_handler)

        req = MCPRequest(method="execute_tool", params={
            "name": "custom_tool",
            "arguments": {"x": "hello"},
        }, id="9")
        resp = await server.process_request(req)
        assert resp.result["success"]
        assert resp.result["data"]["result"] == "processed hello"

    def test_register_tool(self, server):
        """register_tool should add tool to server."""
        def h(p): return "ok"
        server.register_tool(MCPToolDefinition(name="dynamic_tool", description="Dynamic"), h)
        assert server.registry.has_tool("dynamic_tool")
        assert server.registry.get_handler("dynamic_tool") is h


class TestMCPToolDefinitions:
    """Tests for tool definitions."""

    def test_create_tool_definitions(self):
        """create_tool_definitions should return all tools."""
        tools = create_tool_definitions()
        assert len(tools) == len(BUILTIN_MCP_TOOLS)

    def test_all_tools_have_names(self):
        """All built-in tools should have names."""
        for tool in BUILTIN_MCP_TOOLS:
            assert tool.name, f"Tool missing name: {tool}"

    def test_all_tools_have_descriptions(self):
        """All built-in tools should have descriptions."""
        for tool in BUILTIN_MCP_TOOLS:
            assert tool.description, f"Tool {tool.name} missing description"

    def test_all_tools_have_schemas(self):
        """All built-in tools should have input_schema."""
        for tool in BUILTIN_MCP_TOOLS:
            assert tool.input_schema, f"Tool {tool.name} missing input_schema"
            assert "type" in tool.input_schema
            assert "properties" in tool.input_schema

    def test_required_params_marked(self):
        """Tools should mark required parameters."""
        for tool in BUILTIN_MCP_TOOLS:
            if tool.input_schema.get("required"):
                for req_param in tool.input_schema["required"]:
                    assert req_param in tool.input_schema["properties"], \
                        f"Tool {tool.name}: required param '{req_param}' not in properties"

    def test_unique_names(self):
        """All tool names should be unique."""
        names = [t.name for t in BUILTIN_MCP_TOOLS]
        assert len(names) == len(set(names)), "Duplicate tool names found"

    def test_tool_to_dict(self):
        """Tool to_dict should work."""
        tool = BUILTIN_MCP_TOOLS[0]
        d = tool.to_dict()
        assert d["name"] == tool.name
        assert d["description"] == tool.description


class TestMCPServerEdgeCases:
    """Edge case tests for MCPServer."""

    @pytest.fixture
    def server(self):
        return MCPServer()

    @pytest.mark.asyncio
    async def test_concurrent_pings(self, server):
        """Multiple pings should all respond."""
        reqs = [MCPRequest(method="ping", id=str(i)) for i in range(10)]
        results = await asyncio.gather(*[server.process_request(r) for r in reqs])
        for r in results:
            assert r.result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_malformed_params_handled(self, server):
        """Missing params should not crash."""
        req = MCPRequest(method="execute_tool", params={}, id="err-1")
        resp = await server.process_request(req)
        # Should return gracefully (tool name empty = not found)
        assert resp.error is not None or not resp.result.get("success")

    @pytest.mark.asyncio
    async def test_jsonrpc_version_in_response(self, server):
        """Response should include jsonrpc version."""
        req = MCPRequest(method="ping", id="ver-test")
        resp = await server.process_request(req)
        assert resp.jsonrpc == "2.0"


@pytest.mark.asyncio
async def test_asyncio_gather_compat():
    """Test that MCP server works with asyncio.gather pattern."""
    server = MCPServer()
    results = await asyncio.gather(
        server.process_request(MCPRequest(method="ping", id="a")),
        server.process_request(MCPRequest(method="list_tools", id="b")),
        server.process_request(MCPRequest(method="ping", id="c")),
    )
    assert len(results) == 3
    assert results[0].result["status"] == "ok"
    assert results[1].result["tools"] is not None
    assert results[2].result["status"] == "ok"
