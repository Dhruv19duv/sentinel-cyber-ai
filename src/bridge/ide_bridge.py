"""IDE Bridge — WebSocket layer for VS Code/JetBrains integration.

Ported from Anthropic Claude Code's IDE bridge (src/bridge/).
Claude Code's bridge provides WebSocket-based communication between
the CLI and IDEs (VS Code, JetBrains), enabling:
- In-editor slash command execution
- Diagnostics and inline annotations
- Real-time status updates
- Custom protocol for editor features
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Union
from enum import Enum

try:
    import websockets
    from websockets.asyncio.server import serve as ws_serve, ServerConnection
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False
    # Stubs for type hinting
    ws_serve = None
    ServerConnection = Any

logger = logging.getLogger(__name__)


class BridgeEventType(str, Enum):
    """Events that can be sent between CLI and IDE."""
    DIAGNOSTIC = "diagnostic"
    INLINE_SUGGESTION = "inline_suggestion"
    STATUS_UPDATE = "status_update"
    COMMAND_RESULT = "command_result"
    ERROR = "error"
    PROGRESS = "progress"
    REQUEST_APPROVAL = "request_approval"
    APPROVAL_RESULT = "approval_result"


@dataclass
class BridgeClient:
    """Represents a connected IDE client."""
    client_id: str
    client_type: str  # "vscode", "jetbrains", "other"
    connected_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    capabilities: List[str] = field(default_factory=list)
    active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "client_id": self.client_id,
            "client_type": self.client_type,
            "connected_at": self.connected_at,
            "uptime_seconds": time.time() - self.connected_at,
            "capabilities": self.capabilities,
            "active": self.active,
        }


@dataclass
class BridgeMessage:
    """A message exchanged over the bridge."""
    event_type: BridgeEventType
    payload: Dict[str, Any] = field(default_factory=dict)
    source: str = "sentinel"
    target: Optional[str] = None
    message_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": self.event_type.value,
            "payload": self.payload,
            "source": self.source,
            "target": self.target,
            "id": self.message_id,
            "ts": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class BridgeCommand:
    """A command received from an IDE."""

    def __init__(self, command: str, args: str = "", client_id: Optional[str] = None):
        self.command = command
        self.args = args
        self.client_id = client_id
        self.received_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "args": self.args,
            "client_id": self.client_id,
            "received_at": self.received_at,
        }


class BridgeEventHandler:
    """Handles bridge events and dispatches to appropriate handlers."""

    def __init__(self):
        self._handlers: Dict[BridgeEventType, List[Callable]] = {}

    def on(self, event_type: BridgeEventType, handler: Callable):
        """Register a handler for an event type."""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    async def dispatch(self, message: BridgeMessage) -> List[Any]:
        """Dispatch a message to all registered handlers."""
        handlers = self._handlers.get(message.event_type, [])
        results = []
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    result = await handler(message)
                else:
                    result = handler(message)
                results.append(result)
            except Exception as e:
                logger.error(f"Bridge handler error for {message.event_type}: {e}")
        return results


class IDEBridgeServer:
    """WebSocket-based bridge server for IDE integration.

    Matches Claude Code's IDE bridge architecture:
    - WebSocket server for real-time communication
    - Client management (connect/disconnect/heartbeat)
    - Command dispatcher (slash commands from IDE)
    - Event publishing (diagnostics, suggestions, status)

    Protocol:
    - Client sends: {"command": "review", "args": "check this code"}
    - Server responds: {"event": "command_result", "payload": {...}}
    - Server pushes: {"event": "status_update", "payload": {"status": "running"}}
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9876):
        self.host = host
        self.port = port
        self._clients: Dict[str, BridgeClient] = {}
        self._event_handlers = BridgeEventHandler()
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False
        self._bridge_id = f"sentinel-bridge-{uuid.uuid4().hex[:8]}"

        # Internal command registry (for Editor-bound commands)
        self._editor_commands: Dict[str, Callable] = {}
        # WebSocket connection tracking
        self._ws_clients: Dict[int, tuple] = {}
        self._orchestrator: Any = None

        logger.info(f"IDE Bridge initialized: {self._bridge_id} ({host}:{port})")

    def register_editor_command(self, name: str, handler: Callable):
        """Register a command that can be called from the IDE."""
        self._editor_commands[name] = handler
        logger.info(f"Editor command registered: {name}")

    def on_event(self, event_type: BridgeEventType, handler: Callable):
        """Register a handler for bridge events."""
        self._event_handlers.on(event_type, handler)

    async def start(self):
        """Start the WebSocket server.

        If the `websockets` library is installed, starts an actual
        WebSocket server. Otherwise runs in stub mode (logs only).
        """
        self._running = True

        if HAS_WEBSOCKETS:
            try:
                self._server = await ws_serve(
                    self._handle_ws_connection,
                    self.host,
                    self.port,
                )
                logger.info(f"IDE Bridge WebSocket server: ws://{self.host}:{self.port}")
                print(f"Bridge WebSocket server listening on ws://{self.host}:{self.port}", file=sys.stderr)
            except Exception as e:
                logger.error(f"Failed to start WebSocket server: {e}")
        else:
            logger.info(f"IDE Bridge running in stub mode (install 'websockets' for real WS): ws://{self.host}:{self.port}")

    async def _handle_ws_connection(self, websocket: ServerConnection):
        """Handle an incoming WebSocket connection."""
        # Register client
        client = self.register_client("websocket", ["diagnostics", "suggestions", "commands"])
        self._ws_clients[id(websocket)] = (websocket, client.client_id)

        try:
            async for raw_message in websocket:
                try:
                    data = json.loads(raw_message)
                    # Handle as a command
                    cmd_name = data.get("command", "")
                    cmd_args = data.get("args", "")
                    command = BridgeCommand(cmd_name, cmd_args, client.client_id)

                    # Process and respond
                    result = await self.handle_command(command, self._orchestrator)

                    response_msg = BridgeMessage(
                        event_type=BridgeEventType.COMMAND_RESULT,
                        payload=result,
                        target=client.client_id,
                    )
                    await websocket.send(response_msg.to_json())

                except json.JSONDecodeError:
                    await websocket.send(json.dumps({"error": "Invalid JSON"}))

        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.disconnect_client(client.client_id)
            # Clean up WS connection tracking
            for ws_id, (_, cid) in list(self._ws_clients.items()):
                if cid == client.client_id:
                    del self._ws_clients[ws_id]

    def set_orchestrator(self, orchestrator):
        """Set the orchestrator for command processing."""
        self._orchestrator = orchestrator

    async def broadcast(self, message: BridgeMessage):
        """Broadcast a message to all connected WebSocket clients."""
        payload = message.to_json()
        logger.debug(f"Bridge broadcast: {message.event_type.value} to {len(self._clients)} clients")

        if HAS_WEBSOCKETS:
            disconnected = []
            for ws_id, (ws_conn, client_id) in self._ws_clients.items():
                try:
                    await ws_conn.send(payload)
                except websockets.exceptions.ConnectionClosed:
                    disconnected.append(ws_id)
            for ws_id in disconnected:
                self._ws_clients.pop(ws_id, None)

        return payload

    async def send_to(self, client_id: str, message: BridgeMessage) -> bool:
        """Send a message to a specific WebSocket client."""
        if client_id not in self._clients:
            logger.warning(f"Client not found: {client_id}")
            return False

        if HAS_WEBSOCKETS:
            for ws_id, (ws_conn, cid) in self._ws_clients.items():
                if cid == client_id:
                    try:
                        await ws_conn.send(message.to_json())
                        return True
                    except websockets.exceptions.ConnectionClosed:
                        return False

        logger.debug(f"Bridge send to {client_id}: {message.event_type.value}")
        return True

    async def handle_command(self, command: BridgeCommand, orchestrator=None) -> Dict[str, Any]:
        """Handle a command received from an IDE.

        Args:
            command: The command from the IDE
            orchestrator: Optional orchestrator to process commands

        Returns:
            Command result dict
        """
        cmd = command.command.lower()

        if cmd in self._editor_commands:
            handler = self._editor_commands[cmd]
            if asyncio.iscoroutinefunction(handler):
                result = await handler(command)
            else:
                result = handler(command)
            return {"success": True, "data": result}

        # Route through orchestrator's command registry
        if orchestrator and hasattr(orchestrator, 'command_registry'):
            input_line = f"/{cmd} {command.args}" if command.args else f"/{cmd}"
            cmd_result = await orchestrator.command_registry.execute(input_line, orchestrator)
            if cmd_result:
                return {
                    "success": cmd_result.success,
                    "output": cmd_result.output,
                    "duration_ms": cmd_result.duration_ms,
                }

        return {"success": False, "error": f"Unknown command: {cmd}"}

    def register_client(self, client_type: str = "unknown",
                        capabilities: Optional[List[str]] = None) -> BridgeClient:
        """Register a new IDE client.

        Returns:
            The new BridgeClient
        """
        client_id = f"{client_type}-{uuid.uuid4().hex[:8]}"
        client = BridgeClient(
            client_id=client_id,
            client_type=client_type,
            capabilities=capabilities or [],
        )
        self._clients[client_id] = client
        logger.info(f"IDE client connected: {client_id} ({client_type})")

        # Broadcast connection event (fire-and-forget)
        asyncio.create_task(self.broadcast(BridgeMessage(
            event_type=BridgeEventType.STATUS_UPDATE,
            payload={"event": "client_connected", "client_id": client_id},
        )))

        return client

    def disconnect_client(self, client_id: str):
        """Disconnect an IDE client."""
        if client_id in self._clients:
            self._clients[client_id].active = False
            del self._clients[client_id]
            logger.info(f"IDE client disconnected: {client_id}")

    def heartbeat(self, client_id: str) -> bool:
        """Update client heartbeat timestamp.

        Returns:
            True if client exists
        """
        if client_id in self._clients:
            self._clients[client_id].last_heartbeat = time.time()
            return True
        return False

    def get_clients(self) -> List[Dict[str, Any]]:
        """Get all connected clients."""
        return [c.to_dict() for c in self._clients.values()]

    def get_status(self) -> Dict[str, Any]:
        """Get bridge status."""
        return {
            "bridge_id": self._bridge_id,
            "running": self._running,
            "host": self.host,
            "port": self.port,
            "connected_clients": len(self._clients),
            "editor_commands": list(self._editor_commands.keys()),
            "clients": self.get_clients(),
        }

    async def shutdown(self):
        """Gracefully shut down the bridge."""
        self._running = False
        # Disconnect all clients
        for client_id in list(self._clients.keys()):
            self.disconnect_client(client_id)
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        logger.info(f"IDE Bridge shut down: {self._bridge_id}")


# ── Bridge Protocol Helpers ──


def create_diagnostic_message(
    file_path: str,
    line: int,
    column: int,
    message: str,
    severity: str = "warning",
) -> BridgeMessage:
    """Create a diagnostic message for inline IDE annotations.

    Args:
        file_path: Path to the file
        line: Line number
        column: Column number
        message: Diagnostic message
        severity: "error", "warning", "info", "hint"

    Returns:
        BridgeMessage ready to send
    """
    return BridgeMessage(
        event_type=BridgeEventType.DIAGNOSTIC,
        payload={
            "file": file_path,
            "line": line,
            "column": column,
            "message": message,
            "severity": severity,
        },
    )


def create_suggestion_message(
    file_path: str,
    line: int,
    snippet: str,
    suggestion: str,
) -> BridgeMessage:
    """Create an inline suggestion message.

    Args:
        file_path: Path to the file
        line: Line number
        snippet: The code being replaced
        suggestion: The suggested replacement

    Returns:
        BridgeMessage ready to send
    """
    return BridgeMessage(
        event_type=BridgeEventType.INLINE_SUGGESTION,
        payload={
            "file": file_path,
            "line": line,
            "snippet": snippet,
            "suggestion": suggestion,
        },
    )


def create_status_message(status: str, detail: str = "") -> BridgeMessage:
    """Create a status update message."""
    return BridgeMessage(
        event_type=BridgeEventType.STATUS_UPDATE,
        payload={"status": status, "detail": detail},
    )


def create_approval_request(
    operation: str,
    description: str,
    scope: str,
) -> BridgeMessage:
    """Create an approval request message.

    Claude Code uses this to ask for user approval in the IDE
    before executing potentially dangerous operations.
    """
    return BridgeMessage(
        event_type=BridgeEventType.REQUEST_APPROVAL,
        payload={
            "operation": operation,
            "description": description,
            "scope": scope,
        },
    )
