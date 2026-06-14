"""
Integration Management UI — Embedded HTML page for configuring external integrations.

Served at /integrations on the WebSocket dashboard server.
Provides forms for Slack, Discord, GitHub, and Monitoring webhook configuration.
"""

INTEGRATIONS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel — Integration Management</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', -apple-system, sans-serif;
            background: #0e1117;
            color: #c9d1d9;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(135deg, #1a1a3e, #0e1117);
            border-bottom: 1px solid #30363d;
            padding: 1rem 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .header h1 { font-size: 1.2rem; color: #00ff88; }
        .header .back-link { color: #58a6ff; text-decoration: none; font-size: 0.9rem; }
        .container { max-width: 1200px; margin: 0 auto; padding: 1.5rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 1rem; }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.25rem;
        }
        .card h3 { color: #00ff88; font-size: 1rem; margin-bottom: 0.75rem; }
        .card h4 { color: #c9d1d9; font-size: 0.9rem; margin-bottom: 0.5rem; }
        .form-group { margin-bottom: 0.75rem; }
        .form-group label { display: block; color: #8b949e; font-size: 0.85rem; margin-bottom: 0.25rem; }
        .form-group input, .form-group select {
            width: 100%;
            background: #0e1117;
            color: #c9d1d9;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 0.5rem;
            font-size: 0.9rem;
        }
        .form-group input:focus { outline: none; border-color: #00ff88; }
        .btn {
            background: #238636;
            color: #fff;
            border: none;
            border-radius: 6px;
            padding: 0.5rem 1.2rem;
            font-size: 0.85rem;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn:hover { background: #2ea043; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .btn-danger { background: #da3633; }
        .btn-danger:hover { background: #f85149; }
        .btn-sm { padding: 0.3rem 0.8rem; font-size: 0.8rem; }
        .status-badge {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .status-badge.connected { background: #23863633; color: #00ff88; border: 1px solid #238636; }
        .status-badge.disconnected { background: #da363333; color: #ff4444; border: 1px solid #da3633; }
        .status-row { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0; border-bottom: 1px solid #21262d; }
        .status-row:last-child { border-bottom: none; }
        .result-box {
            margin-top: 0.75rem;
            padding: 0.5rem;
            border-radius: 4px;
            font-size: 0.85rem;
            font-family: 'Consolas', monospace;
        }
        .result-box.success { background: #23863622; border: 1px solid #238636; color: #00ff88; }
        .result-box.error { background: #da363322; border: 1px solid #da3633; color: #ff4444; }
        .result-box.info { background: #1e3a5f22; border: 1px solid #1e3a5f; color: #58a6ff; }
        .btn-row { display: flex; gap: 0.5rem; margin-top: 0.75rem; flex-wrap: wrap; }
        .integration-icon { font-size: 1.5rem; margin-right: 0.5rem; }
        @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Integration Management</h1>
            <p style="color: #8b949e; font-size: 0.85rem;">Configure external services for Sentinel</p>
        </div>
        <a href="/" class="back-link">Back to Dashboard</a>
    </div>

    <div class="container">
        <div class="grid">
            <!-- Slack Integration -->
            <div class="card">
                <h3><span class="integration-icon">S</span> Slack</h3>
                <div class="status-row">
                    <span>Status</span>
                    <span id="slackStatus"><span class="status-badge disconnected">Checking...</span></span>
                </div>
                <div class="form-group">
                    <label>Bot Token</label>
                    <input type="password" id="slackToken" placeholder="xoxb-...">
                </div>
                <div class="form-group">
                    <label>Webhook URL</label>
                    <input type="url" id="slackWebhook" placeholder="https://hooks.slack.com/...">
                </div>
                <div class="form-group">
                    <label>Signing Secret</label>
                    <input type="password" id="slackSecret" placeholder="Optional">
                </div>
                <div class="btn-row">
                    <button class="btn btn-sm" onclick="configureSlack()">Save</button>
                    <button class="btn btn-sm" onclick="testWebhook('slack')">Test</button>
                    <button class="btn btn-sm" onclick="fetchSlackStatus()">Refresh Status</button>
                </div>
                <div id="slackResult" class="result-box" style="display:none;"></div>
            </div>

            <!-- Discord Integration -->
            <div class="card">
                <h3><span class="integration-icon">D</span> Discord</h3>
                <div class="status-row">
                    <span>Status</span>
                    <span id="discordStatus"><span class="status-badge disconnected">Checking...</span></span>
                </div>
                <div class="form-group">
                    <label>Bot Token</label>
                    <input type="password" id="discordToken" placeholder="MTE4...">
                </div>
                <div class="form-group">
                    <label>Application ID</label>
                    <input type="text" id="discordAppId" placeholder="123456789...">
                </div>
                <div class="form-group">
                    <label>Public Key</label>
                    <input type="text" id="discordPublicKey" placeholder="Optional">
                </div>
                <div class="form-group">
                    <label>Webhook URL</label>
                    <input type="url" id="discordWebhook" placeholder="https://discord.com/api/webhooks/...">
                </div>
                <div class="btn-row">
                    <button class="btn btn-sm" onclick="configureDiscord()">Save</button>
                    <button class="btn btn-sm" onclick="registerDiscordCommands()">Register Commands</button>
                    <button class="btn btn-sm" onclick="fetchDiscordStatus()">Refresh Status</button>
                </div>
                <div id="discordResult" class="result-box" style="display:none;"></div>
            </div>

            <!-- GitHub Integration -->
            <div class="card">
                <h3><span class="integration-icon">G</span> GitHub</h3>
                <div class="status-row">
                    <span>Status</span>
                    <span id="githubStatus"><span class="status-badge disconnected">Checking...</span></span>
                </div>
                <div class="form-group">
                    <label>Personal Access Token</label>
                    <input type="password" id="githubToken" placeholder="ghp_...">
                </div>
                <div class="form-group">
                    <label>Webhook Secret</label>
                    <input type="password" id="githubSecret" placeholder="Optional">
                </div>
                <div class="btn-row">
                    <button class="btn btn-sm" onclick="configureGithub()">Save</button>
                    <button class="btn btn-sm" onclick="testGithubWebhook()">Simulate Push</button>
                    <button class="btn btn-sm" onclick="fetchGithubStatus()">View Scans</button>
                </div>
                <div id="githubResult" class="result-box" style="display:none;"></div>
            </div>

            <!-- Monitoring Webhooks -->
            <div class="card">
                <h3>Monitoring Alerts</h3>
                <div id="monitoringStatus"></div>
                <div class="form-group">
                    <label>Channel Type</label>
                    <select id="webhookChannel">
                        <option value="slack">Slack</option>
                        <option value="discord">Discord</option>
                        <option value="webhook">Generic Webhook</option>
                        <option value="pagerduty">PagerDuty</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Webhook URL</label>
                    <input type="url" id="webhookUrl" placeholder="https://...">
                </div>
                <div class="btn-row">
                    <button class="btn btn-sm" onclick="configureMonitoringWebhook()">Add Webhook</button>
                    <button class="btn btn-sm" onclick="testAlert()">Test Alert</button>
                </div>
                <div id="monitoringResult" class="result-box" style="display:none;"></div>
            </div>

            <!-- All Integrations Overview -->
            <div class="card" style="grid-column: 1 / -1;">
                <h3>Integration Overview</h3>
                <div id="overviewStatus">Loading...</div>
                <div class="btn-row">
                    <button class="btn btn-sm" onclick="fetchOverview()">Refresh All</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        const API_BASE = '/api/v1/integrations';

        async function apiCall(method, path, body) {
            const opts = { method, headers: {'Content-Type': 'application/json'} };
            if (body) opts.body = JSON.stringify(body);
            const resp = await fetch(API_BASE + path, opts);
            return await resp.json();
        }

        function showResult(id, data, isError) {
            const el = document.getElementById(id);
            el.style.display = 'block';
            el.className = 'result-box ' + (isError ? 'error' : 'success');
            el.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
        }

        // ── Slack ──
        async function fetchSlackStatus() {
            const data = await apiCall('GET', '/slack/status');
            const badge = document.getElementById('slackStatus');
            badge.innerHTML = data.configured
                ? '<span class="status-badge connected">Connected</span>'
                : '<span class="status-badge disconnected">Not Configured</span>';
        }

        async function configureSlack() {
            const data = await apiCall('POST', '/slack/configure', {
                bot_token: document.getElementById('slackToken').value,
                webhook_url: document.getElementById('slackWebhook').value,
                signing_secret: document.getElementById('slackSecret').value,
            });
            showResult('slackResult', data.message || 'Configured', data.status === 'error');
            fetchSlackStatus();
        }

        // ── Discord ──
        async function fetchDiscordStatus() {
            const data = await apiCall('GET', '/discord/status');
            const badge = document.getElementById('discordStatus');
            badge.innerHTML = data.configured
                ? '<span class="status-badge connected">Connected</span>'
                : '<span class="status-badge disconnected">Not Configured</span>';
        }

        async function configureDiscord() {
            const data = await apiCall('POST', '/discord/configure', {
                bot_token: document.getElementById('discordToken').value,
                application_id: document.getElementById('discordAppId').value,
                public_key: document.getElementById('discordPublicKey').value,
                webhook_url: document.getElementById('discordWebhook').value,
            });
            showResult('discordResult', data.message || 'Configured', data.status === 'error');
            fetchDiscordStatus();
        }

        async function registerDiscordCommands() {
            const data = await apiCall('POST', '/discord/register-commands', {
                bot_token: document.getElementById('discordToken').value,
                application_id: document.getElementById('discordAppId').value,
            });
            showResult('discordResult', data.registered ? 'Commands registered!' : 'Failed to register', !data.registered);
        }

        // ── GitHub ──
        async function fetchGithubStatus() {
            const data = await apiCall('GET', '/github/status');
            const badge = document.getElementById('githubStatus');
            badge.innerHTML = data.github_token_configured || data.webhook_configured
                ? '<span class="status-badge connected">Connected</span>'
                : '<span class="status-badge disconnected">Not Configured</span>';
            const scans = await apiCall('GET', '/github/scans');
            if (scans.scans && scans.scans.length > 0) {
                let html = '<h4>Recent Scans</h4>';
                scans.scans.slice(-5).reverse().forEach(s => {
                    html += '<div class="status-row"><span>' + s.repo + ' (' + s.branch + ')</span><span>' + s.findings + ' findings</span></div>';
                });
                document.getElementById('githubResult').style.display = 'block';
                document.getElementById('githubResult').className = 'result-box info';
                document.getElementById('githubResult').innerHTML = html;
            }
        }

        async function configureGithub() {
            const data = await apiCall('POST', '/github/configure', {
                github_token: document.getElementById('githubToken').value,
                webhook_secret: document.getElementById('githubSecret').value,
            });
            showResult('githubResult', 'Configuration saved', data.status === 'error');
            fetchGithubStatus();
        }

        async function testGithubWebhook() {
            const data = await apiCall('POST', '/github/test', {});
            showResult('githubResult', 'Test push simulated: ' + data.status, data.status === 'error');
        }

        // ── Monitoring ──
        async function configureMonitoringWebhook() {
            const channel = document.getElementById('webhookChannel').value;
            const url = document.getElementById('webhookUrl').value;
            if (!url) { showResult('monitoringResult', 'URL is required', true); return; }
            const data = await apiCall('POST', '/monitoring/webhook', { channel, url });
            showResult('monitoringResult', 'Webhook added: ' + channel, data.status === 'error');
        }

        async function testAlert() {
            const data = await apiCall('POST', '/monitoring/test-alert', {});
            showResult('monitoringResult', 'Test alert sent: ' + (data.alert ? data.alert.id : 'ok'), false);
        }

        // ── Test Webhook ──
        async function testWebhook(type) {
            let data;
            if (type === 'slack') {
                data = await apiCall('POST', '/slack/test', {});
                showResult('slackResult', 'Test result: ' + data.status, data.status === 'error');
            }
        }

        // ── Overview ──
        async function fetchOverview() {
            const data = await apiCall('GET', '/overview');
            const el = document.getElementById('overviewStatus');
            let html = '';
            for (const [name, info] of Object.entries(data)) {
                if (name === 'timestamp') continue;
                const ok = info.active || info.configured || info.connected;
                html += '<div class="status-row"><span>' + name + '</span><span class="status-badge ' + (ok ? 'connected' : 'disconnected') + '">' + (ok ? 'Active' : 'Inactive') + '</span></div>';
            }
            el.innerHTML = html;
        }

        // ── Init ──
        fetchSlackStatus();
        fetchDiscordStatus();
        fetchGithubStatus();
        fetchOverview();
    </script>
</body>
</html>
"""


def get_integrations_html() -> str:
    """Get the integrations management HTML page."""
    return INTEGRATIONS_HTML
