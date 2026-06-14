-- Sentinel Cyber AI — PostgreSQL Schema
-- Initializes the production database for persistent storage

-- ── Extensions ──
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Analysis Results ──
CREATE TABLE IF NOT EXISTS analyses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    task_id VARCHAR(64) UNIQUE NOT NULL,
    query TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    confidence REAL DEFAULT 0.0,
    summary TEXT,
    findings JSONB DEFAULT '[]',
    agents_used TEXT[] DEFAULT '{}',
    thinking_info JSONB,
    context_info JSONB,
    raw_result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_analyses_created_at ON analyses(created_at DESC);
CREATE INDEX idx_analyses_status ON analyses(status);
CREATE INDEX idx_analyses_confidence ON analyses(confidence DESC);
CREATE INDEX idx_analyses_findings ON analyses USING GIN (findings);

-- ── Scan Results (from GitHub webhook) ──
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repo VARCHAR(255) NOT NULL,
    branch VARCHAR(255) NOT NULL,
    commit_sha VARCHAR(64) NOT NULL,
    commit_message TEXT,
    author VARCHAR(255),
    files_changed TEXT[] DEFAULT '{}',
    files_scanned INTEGER DEFAULT 0,
    findings JSONB DEFAULT '[]',
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    scan_duration_ms REAL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_scans_repo ON scans(repo);
CREATE INDEX idx_scans_created ON scans(created_at DESC);
CREATE INDEX idx_scans_status ON scans(status);

-- ── Alerts & Threats ──
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    message TEXT,
    severity VARCHAR(32) NOT NULL DEFAULT 'info',
    source VARCHAR(64) NOT NULL,
    channel VARCHAR(32) NOT NULL DEFAULT 'console',
    acknowledged BOOLEAN DEFAULT FALSE,
    resolved BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ
);

CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX idx_alerts_resolved ON alerts(resolved);

CREATE TABLE IF NOT EXISTS active_threats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    description TEXT NOT NULL,
    severity VARCHAR(32) NOT NULL DEFAULT 'info',
    source_agent VARCHAR(64) NOT NULL,
    affected_files TEXT[] DEFAULT '{}',
    status VARCHAR(32) NOT NULL DEFAULT 'detected',
    confidence REAL DEFAULT 0.0,
    notes TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX idx_threats_severity ON active_threats(severity);
CREATE INDEX idx_threats_status ON active_threats(status);

-- ── Metrics ──
CREATE TABLE IF NOT EXISTS metrics (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    value REAL NOT NULL,
    labels JSONB DEFAULT '{}',
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_metrics_name ON metrics(name, recorded_at DESC);
CREATE INDEX idx_metrics_recorded ON metrics(recorded_at DESC);

-- ── Webhook Configurations ──
CREATE TABLE IF NOT EXISTS webhook_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider VARCHAR(64) NOT NULL,
    webhook_url TEXT NOT NULL,
    secret TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    events TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_webhook_provider ON webhook_configs(provider);

-- ── Insert default webhook configs ──
INSERT INTO webhook_configs (provider, webhook_url, events)
VALUES
    ('github', COALESCE(current_setting('app.github_webhook_url', TRUE), ''), '{push,pull_request}'),
    ('slack', COALESCE(current_setting('app.slack_webhook_url', TRUE), ''), '{alert}')
ON CONFLICT (provider) DO NOTHING;

-- ── Views ──
CREATE OR REPLACE VIEW daily_scan_summary AS
SELECT
    DATE(created_at) AS day,
    repo,
    COUNT(*) AS total_scans,
    SUM(CASE WHEN status = 'clean' THEN 1 ELSE 0 END) AS clean_scans,
    SUM(CASE WHEN status = 'vulnerabilities_found' THEN 1 ELSE 0 END) AS vulnerable_scans,
    SUM(files_scanned) AS total_files_scanned,
    SUM(jsonb_array_length(findings)) AS total_findings
FROM scans
GROUP BY day, repo
ORDER BY day DESC;

CREATE OR REPLACE VIEW alert_summary AS
SELECT
    DATE(created_at) AS day,
    severity,
    COUNT(*) AS count
FROM alerts
GROUP BY day, severity
ORDER BY day DESC;

-- ── Functions ──
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_analyses_updated_at
    BEFORE UPDATE ON analyses
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_webhook_configs_updated_at
    BEFORE UPDATE ON webhook_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
