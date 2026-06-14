# Sentinel IDE Bridge — VS Code Extension

Connects VS Code to the Sentinel Cyber AI platform via WebSocket bridge.

## Features

- **Analyze Selection** (`Ctrl+Shift+A`): Send selected code to Sentinel's AI agents for analysis
- **Review File** (`Ctrl+Shift+R`): Full-file security review with inline diagnostics (squigglies)
- **Scan Workspace**: Trigger a full workspace scan
- **Inline Diagnostics**: Security findings shown as VS Code diagnostics with error/warning squigglies
- **Status Bar**: Connection indicator with status updates from the bridge

## Requirements

- VS Code 1.85+
- Python 3.10+ with Sentinel Cyber AI running
- `websockets` Python package: `pip install websockets`

## Quick Start

1. Start the Sentinel bridge server:
```bash
cd sentinel-cyber-ai
pip install websockets
python -m src.main bridge 9876
```

2. In VS Code, open the `sentinel-vscode` folder
3. Press `F5` to launch the Extension Development Host
4. The extension will auto-connect to `ws://127.0.0.1:9876`
5. Open a Python/JS/TS file and use `Ctrl+Shift+A` to analyze

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `sentinel.bridgeHost` | `127.0.0.1` | Bridge server host |
| `sentinel.bridgePort` | `9876` | Bridge server port |
| `sentinel.autoConnect` | `true` | Auto-connect on startup |
| `sentinel.enableDiagnostics` | `true` | Enable inline diagnostics |

## Protocol

The extension communicates with the bridge via JSON messages over WebSocket:

```json
// Client → Server (command)
{"command": "analyze", "args": "def foo(): pass"}

// Server → Client (response)
{"event": "command_result", "payload": {"success": true, "output": "..."}}

// Server → Client (push diagnostic)
{"event": "diagnostic", "payload": {"file": "/path/to/file.py", "line": 5, "message": "..."}}

// Server → Client (status update)
{"event": "status_update", "payload": {"status": "analyzing"}}
```
