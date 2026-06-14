"""IDE Bridge — WebSocket layer for VS Code/JetBrains integration.

Ported from Anthropic Claude Code's IDE bridge architecture.
"""

from src.bridge.ide_bridge import (
    IDEBridgeServer,
    BridgeClient,
    BridgeMessage,
    BridgeCommand,
    BridgeEventHandler,
    BridgeEventType,
    create_diagnostic_message,
    create_suggestion_message,
    create_status_message,
    create_approval_request,
)

__all__ = [
    "IDEBridgeServer",
    "BridgeClient",
    "BridgeMessage",
    "BridgeCommand",
    "BridgeEventHandler",
    "BridgeEventType",
    "create_diagnostic_message",
    "create_suggestion_message",
    "create_status_message",
    "create_approval_request",
]
