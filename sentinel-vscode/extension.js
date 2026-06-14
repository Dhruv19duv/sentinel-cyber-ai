/**
 * Sentinel IDE Bridge — VS Code Extension
 *
 * Connects to the Sentinel Cyber AI bridge server via WebSocket
 * and provides in-editor analysis, diagnostics, and commands.
 *
 * Features:
 * - Analyze selected code via Sentinel AI agents
 * - Inline diagnostics (squigglies) from security findings
 * - Status bar indicator showing bridge connection state
 * - Slash commands routed to Sentinel's command registry
 */

const vscode = require('vscode');

let bridgeConnection = null;
let statusBarItem = null;
let diagnosticCollection = null;

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('Sentinel IDE Bridge activating...');

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        100
    );
    statusBarItem.command = 'sentinel.status';
    statusBarItem.text = '$(shield) Sentinel: Disconnected';
    statusBarItem.tooltip = 'Click to show Sentinel status';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Create diagnostic collection
    diagnosticCollection = vscode.languages.createDiagnosticCollection('sentinel');
    context.subscriptions.push(diagnosticCollection);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.analyze', analyzeSelection),
        vscode.commands.registerCommand('sentinel.review', reviewFile),
        vscode.commands.registerCommand('sentinel.scan', scanWorkspace),
        vscode.commands.registerCommand('sentinel.connect', connectToBridge),
        vscode.commands.registerCommand('sentinel.disconnect', disconnectFromBridge),
        vscode.commands.registerCommand('sentinel.status', showStatus)
    );

    // Auto-connect on startup
    const config = vscode.workspace.getConfiguration('sentinel');
    if (config.get('autoConnect')) {
        connectToBridge();
    }

    console.log('Sentinel IDE Bridge activated');
}
exports.activate = activate;

function deactivate() {
    disconnectFromBridge();
    if (statusBarItem) statusBarItem.dispose();
    console.log('Sentinel IDE Bridge deactivated');
}
exports.deactivate = deactivate;

/**
 * Connect to the Sentinel bridge server via WebSocket.
 */
async function connectToBridge() {
    const config = vscode.workspace.getConfiguration('sentinel');
    const host = config.get('bridgeHost', '127.0.0.1');
    const port = config.get('bridgePort', 9876);

    const wsUrl = `ws://${host}:${port}`;

    try {
        statusBarItem.text = `$(sync~spin) Sentinel: Connecting...`;
        statusBarItem.tooltip = `Connecting to ${wsUrl}`;

        bridgeConnection = new WebSocket(wsUrl);

        bridgeConnection.onopen = () => {
            console.log(`Connected to Sentinel bridge: ${wsUrl}`);
            statusBarItem.text = '$(shield) Sentinel: Connected';
            statusBarItem.tooltip = `Connected to ${wsUrl}`;
            vscode.window.showInformationMessage(
                `Sentinel: Connected to bridge at ${wsUrl}`
            );
        };

        bridgeConnection.onmessage = (event) => {
            handleBridgeMessage(event.data);
        };

        bridgeConnection.onerror = (err) => {
            console.error('Sentinel bridge error:', err);
            statusBarItem.text = '$(shield-x) Sentinel: Error';
        };

        bridgeConnection.onclose = () => {
            console.log('Disconnected from Sentinel bridge');
            statusBarItem.text = '$(shield) Sentinel: Disconnected';
            statusBarItem.tooltip = 'Click to reconnect';
            bridgeConnection = null;
        };

    } catch (err) {
        console.error('Failed to connect to Sentinel bridge:', err);
        statusBarItem.text = '$(shield-x) Sentinel: Connection Failed';
        vscode.window.showErrorMessage(
            `Sentinel: Could not connect to bridge at ${wsUrl}`
        );
    }
}

/**
 * Disconnect from the Sentinel bridge.
 */
function disconnectFromBridge() {
    if (bridgeConnection) {
        try {
            bridgeConnection.close();
        } catch (e) {
            // Ignore close errors
        }
        bridgeConnection = null;
    }
    statusBarItem.text = '$(shield) Sentinel: Disconnected';
    diagnosticCollection.clear();
}

/**
 * Send a command to the bridge server via WebSocket.
 * @param {string} command - Command name
 * @param {string} args - Command arguments
 * @returns {Promise<Object>}
 */
async function sendCommand(command, args = '') {
    if (!bridgeConnection || bridgeConnection.readyState !== WebSocket.OPEN) {
        const action = await vscode.window.showWarningMessage(
            'Sentinel: Not connected to bridge. Connect now?',
            'Connect',
            'Cancel'
        );
        if (action === 'Connect') {
            await connectToBridge();
            // Wait for connection before retrying
            await new Promise(resolve => setTimeout(resolve, 1000));
            if (!bridgeConnection || bridgeConnection.readyState !== WebSocket.OPEN) {
                return { success: false, error: 'Failed to connect' };
            }
        } else {
            return { success: false, error: 'Not connected' };
        }
    }

    return new Promise((resolve) => {
        const handler = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.event === 'command_result') {
                    bridgeConnection.removeEventListener('message', handler);
                    resolve(data.payload);
                }
            } catch (e) {
                // Ignore parse errors
            }
        };

        // Set timeout
        const timeout = setTimeout(() => {
            bridgeConnection.removeEventListener('message', handler);
            resolve({ success: false, error: 'Command timed out' });
        }, 30000);

        // Wrap handler to also clear timeout
        const wrappedHandler = (event) => {
            clearTimeout(timeout);
            handler(event);
        };

        bridgeConnection.addEventListener('message', wrappedHandler);

        bridgeConnection.send(JSON.stringify({
            command: command,
            args: args,
        }));
    });
}

/**
 * Handle an incoming bridge message (e.g., diagnostics).
 * @param {string} rawData
 */
function handleBridgeMessage(rawData) {
    try {
        const msg = JSON.parse(rawData);
        const event = msg.event;
        const payload = msg.payload;

        if (event === 'diagnostic' && payload) {
            // Add inline diagnostic
            const uri = vscode.Uri.file(payload.file);
            const range = new vscode.Range(
                (payload.line || 0) - 1,
                (payload.column || 0),
                (payload.line || 0) - 1,
                (payload.column || 0) + 1
            );
            const severity = {
                'error': vscode.DiagnosticSeverity.Error,
                'warning': vscode.DiagnosticSeverity.Warning,
                'info': vscode.DiagnosticSeverity.Information,
                'hint': vscode.DiagnosticSeverity.Hint,
            }[payload.severity] || vscode.DiagnosticSeverity.Warning;

            const diagnostic = new vscode.Diagnostic(
                range,
                payload.message,
                severity
            );
            diagnostic.source = 'Sentinel';

            const existing = diagnosticCollection.get(uri) || [];
            diagnosticCollection.set(uri, [...existing, diagnostic]);
        }

        if (event === 'status_update' && payload) {
            statusBarItem.text = `$(shield) Sentinel: ${payload.status || 'OK'}`;
        }

    } catch (e) {
        console.error('Error handling bridge message:', e);
    }
}

/**
 * Analyze the currently selected code in the editor.
 */
async function analyzeSelection() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
    }

    const selection = editor.selection;
    const text = editor.document.getText(selection);

    if (!text) {
        vscode.window.showWarningMessage('No code selected');
        return;
    }

    vscode.window.withProgress(
        { location: vscode.ProgressLocation.Window, title: 'Sentinel analyzing...' },
        async () => {
            const result = await sendCommand('analyze', text);
            if (result.success) {
                const panel = vscode.window.createOutputChannel('Sentinel Analysis');
                panel.clear();
                panel.appendLine('=== Sentinel Analysis ===');
                panel.appendLine(result.output || JSON.stringify(result, null, 2));
                panel.show();
            } else {
                vscode.window.showErrorMessage(
                    `Sentinel analysis failed: ${result.error}`
                );
            }
            return result;
        }
    );
}

/**
 * Review the currently open file for security issues.
 */
async function reviewFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
    }

    const fullText = editor.document.getText();
    const fileName = editor.document.fileName;

    vscode.window.withProgress(
        { location: vscode.ProgressLocation.Window, title: 'Sentinel reviewing file...' },
        async () => {
            const result = await sendCommand('review', fullText.slice(0, 10000));
            if (result.success) {
                const panel = vscode.window.createOutputChannel(
                    `Sentinel Review: ${fileName.split('/').pop() || fileName}`
                );
                panel.clear();
                panel.appendLine(`=== Sentinel Review: ${fileName} ===`);
                panel.appendLine(result.output || 'Review complete');
                panel.show();

                // Add findings as diagnostics
                if (result.findings) {
                    for (const finding of result.findings) {
                        const msg = {
                            event: 'diagnostic',
                            payload: {
                                file: fileName,
                                line: finding.line || 1,
                                column: finding.column || 0,
                                message: `[${finding.severity}] ${finding.title}: ${finding.description}`,
                                severity: finding.severity === 'CRITICAL' ? 'error' : 'warning',
                            }
                        };
                        handleBridgeMessage(JSON.stringify(msg));
                    }
                }
            } else {
                vscode.window.showErrorMessage(
                    `Sentinel review failed: ${result.error}`
                );
            }
            return result;
        }
    );
}

/**
 * Scan the entire workspace.
 */
async function scanWorkspace() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showWarningMessage('No workspace open');
        return;
    }

    const rootPath = workspaceFolders[0].uri.fsPath;

    vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Window,
            title: 'Sentinel scanning workspace...',
            cancellable: true,
        },
        async () => {
            const result = await sendCommand('scan', rootPath);
            if (result.success) {
                const panel = vscode.window.createOutputChannel('Sentinel Scan');
                panel.clear();
                panel.appendLine('=== Sentinel Workspace Scan ===');
                panel.appendLine(`Path: ${rootPath}`);
                panel.appendLine(result.output || JSON.stringify(result, null, 2));
                panel.show();
            } else {
                vscode.window.showErrorMessage(
                    `Sentinel scan failed: ${result.error}`
                );
            }
            return result;
        }
    );
}

/**
 * Show connection status and available commands.
 */
async function showStatus() {
    const config = vscode.workspace.getConfiguration('sentinel');
    const host = config.get('bridgeHost', '127.0.0.1');
    const port = config.get('bridgePort', 9876);

    const isConnected = bridgeConnection && bridgeConnection.readyState === WebSocket.OPEN;

    const items = [
        { label: `$(link) Bridge: ws://${host}:${port}`, description: isConnected ? 'Connected' : 'Disconnected' },
        { label: '', kind: vscode.Separator },
        { label: '$(eye) Analyze Selection', description: 'Ctrl+Shift+A / Cmd+Shift+A', command: 'sentinel.analyze' },
        { label: '$(search) Review File', description: 'Ctrl+Shift+R / Cmd+Shift+R', command: 'sentinel.review' },
        { label: '$(folder) Scan Workspace', description: '', command: 'sentinel.scan' },
    ];

    if (!isConnected) {
        items.push({ label: '$(plug) Connect', description: '', command: 'sentinel.connect' });
    } else {
        items.push({ label: '$(x) Disconnect', description: '', command: 'sentinel.disconnect' });
    }

    const pick = await vscode.window.showQuickPick(items, {
        title: 'Sentinel IDE Bridge',
        placeHolder: 'Select an action...',
    });

    if (pick && pick.command) {
        vscode.commands.executeCommand(pick.command);
    }
}
