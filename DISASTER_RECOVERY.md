# Sentinel Cyber AI — Disaster Recovery Runbook

> **Production DR Plan** — Covers backup restoration, database migration,
> server rebuild, SSL recovery, and full-site disaster scenarios.
>
> Last updated: June 12, 2026

---

## Table of Contents

1. [Recovery Playbooks](#1-recovery-playbooks)
   - [P1: Database Corruption / Data Loss](#p1-database-corruption--data-loss)
   - [P2: Server Compromise](#p2-server-compromise)
   - [P3: SSL Certificate Expiry](#p3-ssl-certificate-expiry)
   - [P4: Full Server Failure](#p4-full-server-failure)
   - [P5: Failed Deployment / Bad Code Push](#p5-failed-deployment--bad-code-push)
2. [Backup Verification Procedure](#2-backup-verification-procedure)
3. [Database Migration Procedure](#3-database-migration-procedure)
4. [Server Rebuild Checklist](#4-server-rebuild-checklist)
5. [Monitoring Incident Response](#5-monitoring-incident-response)
6. [Recovery Testing Schedule](#6-recovery-testing-schedule)

---

## 1. Recovery Playbooks

### P1: Database Corruption / Data Loss

**Severity:** 🔴 CRITICAL
**Response time:** < 30 minutes
**Goal:** Restore database to latest known-good state with minimal data loss.

#### Step 1: Assess Damage

```bash
# Check database status
docker exec sentinel-postgres pg_isready -U sentinel

# Check database size
docker exec sentinel-postgres psql -U sentinel -d sentinel -t -c \
  "SELECT pg_size_pretty(pg_database_size('sentinel'));"

# List recent backups
./scripts/backup.sh list
```

#### Step 2: Stop Affected Services

```bash
# Stop the API and worker to prevent further writes
docker compose -f docker/docker-compose.prod.yml stop api worker dashboard

# Scale workers to 0
docker compose -f docker/docker-compose.prod.yml up -d --scale worker=0
```

#### Step 3: Identify Best Backup to Restore

```bash
# Find the latest backup
./scripts/backup.sh latest

# Verify integrity
./scripts/backup.sh verify
```

If the latest backup is also corrupted, try the previous one:
```bash
ls -lt backups/postgres/*.sql* | head -5
./scripts/backup.sh verify backups/postgres/sentinel_20260611_020000.sql.gz
```

#### Step 4: Restore Database

```bash
# Restore from local backup
./scripts/backup.sh restore backups/postgres/sentinel_20260611_020000.sql.gz

# OR restore from S3 (if local backups are unavailable)
mkdir -p /tmp/restore
aws s3 cp s3://sentinel-backups/sentinel_20260611_020000.sql.gz /tmp/restore/
gunzip /tmp/restore/sentinel_20260611_020000.sql.gz
./scripts/backup.sh restore /tmp/restore/sentinel_20260611_020000.sql
```

#### Step 5: Resume Services

```bash
# Restart all services
docker compose -f docker/docker-compose.prod.yml up -d

# Verify recovery
./scripts/deploy.sh --status
```

#### Step 6: Validate Data Integrity

```bash
# Check table counts
docker exec sentinel-postgres psql -U sentinel -d sentinel -c \
  "SELECT schemaname, tablename, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC;"

# Run basic health check
curl -f http://localhost/health
```

**Expected recovery time:** 15-45 minutes depending on database size.

---

### P2: Server Compromise

**Severity:** 🔴 CRITICAL
**Response time:** < 15 minutes
**Goal:** Isolate compromised server, preserve evidence, restore to clean state.

#### Immediate Actions

```bash
# 1. Isolate the server (run from a separate management machine)
# Block traffic to the compromised server at the firewall level

# 2. Do NOT SSH into the compromised server (attackers may have modified SSH)

# 3. Preserve evidence - snapshot the disk from cloud console
# DigitalOcean: Take a snapshot
# AWS: Create an EBS snapshot
```

#### Restore to Clean Server

```bash
# 1. Provision a new server from the cloud provider dashboard
#    - Same region, same specs
#    - Fresh OS install (Ubuntu 24.04)

# 2. Rotate ALL secrets immediately
#    - SENTINEL_API_KEY (generate new)
#    - POSTGRES_PASSWORD (generate new)
#    - GRAFANA_PASSWORD (generate new)
#    - AWS credentials
#    - GitHub tokens
#    - Slack/Discord bot tokens

# 3. Install Docker and deploy
curl -fsSL https://get.docker.com | sh
git clone https://github.com/your-org/sentinel-cyber-ai.git
cd sentinel-cyber-ai
cp .env.production .env
# Edit .env with NEW secrets (do NOT reuse compromised secrets)
nano .env
./scripts/deploy.sh

# 4. Restore database from uncompromised backup
./scripts/backup.sh restore backups/postgres/sentinel_20260610_020000.sql.gz

# 5. Set up SSL
./scripts/setup-ssl.sh api.yourdomain.com dashboard.yourdomain.com
```

#### Post-Incident

1. **Rotate ALL API keys**, tokens, and secrets (even if not exposed)
2. **Revoke the compromised SSH key pair** and generate new ones
3. **Audit GitHub access logs** for unauthorized activity
4. **Check for backdoors** in the source code (if attacker had push access)
5. **File a report** documenting the incident, timeline, and response

---

### P3: SSL Certificate Expiry

**Severity:** 🟡 HIGH
**Response time:** < 2 hours
**Goal:** Renew certificates before browsers start showing security warnings.

#### Automatic Renewal

The certbot container auto-renews every 12 hours. Check if it's running:

```bash
# Check certbot container status
docker ps --filter name=sentinel-certbot

# Check certbot logs
docker compose -f docker/docker-compose.prod.yml logs certbot --tail=50
```

#### Manual Renewal (if auto-renewal fails)

```bash
# 1. Run manual renewal
docker run --rm \
  --name sentinel-certbot-renew \
  -v $(pwd)/docker/nginx/ssl:/etc/letsencrypt:rw \
  -v sentinel-prod_certbot-www:/var/www/certbot:rw \
  certbot/certbot:v2.11.0 renew \
  --webroot -w /var/www/certbot \
  --quiet

# 2. Reload nginx
docker exec sentinel-nginx nginx -s reload

# 3. Verify new certificates
docker exec sentinel-nginx openssl x509 -in /etc/nginx/ssl/live/api.yourdomain.com/fullchain.pem -text -noout | grep "Not After"
```

#### Full Re-issuance (if certificates are lost)

```bash
# Run the setup script again
./scripts/setup-ssl.sh api.yourdomain.com dashboard.yourdomain.com
```

---

### P4: Full Server Failure

**Severity:** 🔴 CRITICAL
**Response time:** < 1 hour
**Goal:** Restore full service on a new server with minimal data loss.

#### Preconditions

You need:
- Access to your cloud provider dashboard
- The latest backup (local or S3)
- Your `.env` secrets (stored securely outside the server)
- SSH key pair

#### Recovery Procedure

**Phase 1 — Provision New Server (10 min)**

```bash
# 1. Create a new VPS (same region, same or better specs)
#    - Ubuntu 24.04 LTS
#    - 4GB+ RAM, 2+ CPU cores, 50GB+ SSD
#    - Add your SSH key

# 2. Configure firewall
#    - Allow: 22 (SSH), 80 (HTTP), 443 (HTTPS)
#    - Deny: all other inbound

# 3. Note the new public IP
```

**Phase 2 — Install Dependencies (5 min)**

```bash
# SSH in
ssh root@new-server-ip

# Update system
apt-get update && apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh

# Clone repository
git clone https://github.com/your-org/sentinel-cyber-ai.git
cd sentinel-cyber-ai
```

**Phase 3 — Configure Environment (5 min)**

```bash
# Create .env from your securely stored credentials
cp .env.production .env
nano .env
# Paste your saved secrets: SENTINEL_API_KEY, POSTGRES_PASSWORD, GRAFANA_PASSWORD, etc.
```

**Phase 4 — Restore Database from Backup (varies)**

```bash
# If backup is on S3:
aws s3 cp s3://sentinel-backups/sentinel_latest.sql.gz ./backups/postgres/

# If backup is on another server via rsync:
rsync -avzP user@old-server:/path/to/backups/ backups/

# Deploy with monitoring stack
./scripts/deploy.sh --monitoring

# Verify restoration
./scripts/backup.sh restore ./backups/postgres/sentinel_latest.sql.gz
```

**Phase 5 — SSL + DNS (10 min)**

```bash
# Run SSL setup
./scripts/setup-ssl.sh api.yourdomain.com dashboard.yourdomain.com

# Update DNS A records to point to the new server IP
# (TTL was likely 300-3600s, so propagation takes 5-60 minutes)

# Verify
curl -I https://api.yourdomain.com/health
```

---

### P5: Failed Deployment / Bad Code Push

**Severity:** 🟡 HIGH
**Response time:** < 30 minutes
**Goal:** Roll back to the previous working version.

#### Quick Rollback

```bash
# 1. Revert to previous Docker image
docker compose -f docker/docker-compose.prod.yml down

# 2. Tag the previous working image
docker tag sentinel-cyber-ai:previous sentinel-cyber-ai:latest

# 3. Restart
docker compose -f docker/docker-compose.prod.yml up -d
```

#### Full Git Rollback

```bash
# 1. Find the last working commit
git log --oneline -10

# 2. Reset to it
git reset --hard <last-working-commit-hash>

# 3. Rebuild and redeploy
./scripts/deploy.sh --rebuild
```

#### Database Rollback (if migration caused issues)

```bash
# 1. Stop API to prevent further writes
docker compose -f docker/docker-compose.prod.yml stop api worker

# 2. Restore pre-migration backup
./scripts/backup.sh restore backups/postgres/sentinel_20260611_020000.sql.gz

# 3. Revert code
git reset --hard <commit-before-migration>
./scripts/deploy.sh --rebuild
```

---

## 2. Backup Verification Procedure

Run this monthly to ensure backups are restorable:

```bash
#!/bin/bash
# Monthly backup verification script

echo "=== Monthly Backup Verification ==="
date

# 1. Check backup directory exists and has files
BACKUP_DIR="./backups/postgres"
if [ ! -d "$BACKUP_DIR" ] || [ -z "$(ls -A $BACKUP_DIR/*.sql* 2>/dev/null)" ]; then
    echo "❌ No backups found!"
    exit 1
fi

# 2. Verify integrity of all backups (checks gzip + pg_dump header)
FAILURES=0
for backup in $(ls -t $BACKUP_DIR/*.sql*); do
    echo -n "Checking $(basename $backup)... "
    if ./scripts/backup.sh verify "$backup" > /dev/null 2>&1; then
        echo "✅"
    else
        echo "❌"
        FAILURES=$((FAILURES + 1))
    fi
done

# 3. Check backup age (fail if most recent backup is > 48h old)
LATEST=$(ls -t $BACKUP_DIR/*.sql* 2>/dev/null | head -1)
if [ -n "$LATEST" ]; then
    LATEST_EPOCH=$(stat -c%Y "$LATEST" 2>/dev/null || stat -f%m "$LATEST" 2>/dev/null)
    NOW=$(date +%s)
    AGE_HOURS=$(( (NOW - LATEST_EPOCH) / 3600 ))
    if [ "$AGE_HOURS" -gt 48 ]; then
        echo "⚠️  Latest backup is $AGE_HOURS hours old (> 48h threshold)"
        FAILURES=$((FAILURES + 1))
    else
        echo "✅ Latest backup age: ${AGE_HOURS}h"
    fi
fi

# 4. Check S3 sync status (if configured)
if [ -n "${BACKUP_S3_BUCKET:-}" ]; then
    echo -n "Checking S3 replication... "
    aws s3 ls "$BACKUP_S3_BUCKET/" --profile "${AWS_PROFILE:-sentinel-backup}" --max-items 1 > /dev/null 2>&1 \
        && echo "✅" || echo "❌"
fi

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "✅ All backup checks passed!"
else
    echo "❌ $FAILURES check(s) failed — investigate immediately."
fi
```

Save as `scripts/verify-backups.sh` and run monthly.

---

## 3. Database Migration Procedure

Use when migrating to a new PostgreSQL version, new server, or new cloud provider.

### Pre-Migration Checklist

- [ ] Latest backup taken and verified
- [ ] Backup copied off-server (S3 or remote)
- [ ] Target PostgreSQL version noted (upgrade path verified)
- [ ] Maintenance window communicated
- [ ] Rollback plan ready

### Migration Steps

```bash
# 1. Take a final backup on the source server
cd /opt/sentinel-cyber-ai
./scripts/backup.sh backup --compress --s3

# 2. Export the backup (for transfer)
./scripts/backup.sh export --sync

# 3. Transfer to target server
# Option A: Direct from S3
aws s3 cp s3://sentinel-backups/sentinel_latest.sql.gz /tmp/

# Option B: Via rsync (direct server-to-server)
rsync -avzP backups/export/sentinel_postgres_latest.sql.gz \
  user@new-server:/tmp/

# 4. On the TARGET server, set up the environment
#    (Docker, repo clone, .env configuration)
#    Do NOT start the stack yet — we need to restore the DB first

# 5. Start ONLY PostgreSQL (not the full stack)
docker compose -f docker/docker-compose.prod.yml up -d postgres

# 6. Wait for PostgreSQL to be healthy
sleep 10
docker exec sentinel-postgres pg_isready -U sentinel

# 7. Restore the database
gunzip -c /tmp/sentinel_postgres_latest.sql.gz | \
  docker exec -i sentinel-postgres psql -U sentinel -d sentinel

# 8. Verify the restore
docker exec sentinel-postgres psql -U sentinel -d sentinel -c \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';"

# 9. Start the full stack
docker compose -f docker/docker-compose.prod.yml up -d

# 10. Verify everything works
./scripts/deploy.sh --status
```

### Post-Migration

- [ ] Run a full test suite: `python -m pytest tests/ -q`
- [ ] Verify API health: `curl -f http://localhost/health`
- [ ] Verify dashboard loads: `curl -f http://localhost:8500/`
- [ ] Check monitoring stack: `curl -f http://localhost:9090/-/healthy`
- [ ] Update DNS records if server IP changed
- [ ] Update backup cron jobs on new server: `./scripts/backup.sh setup-cron`
- [ ] Decommission old server after 48h of stability

---

## 4. Server Rebuild Checklist

Use when rebuilding the production server from scratch.

### Prerequisites

- [ ] Cloud provider account active
- [ ] SSH key pair ready
- [ ] GitHub repository access (clone URL)
- [ ] `.env` secrets stored securely (password manager)
- [ ] SSL domain DNS records ready to update
- [ ] Latest backup available (local or S3)

### Build Steps

```bash
# ── 1. Provision Server ──
# Create: Ubuntu 24.04 LTS, 4GB+ RAM, 50GB+ SSD
# Open ports: 22, 80, 443

# ── 2. Base Setup ──
ssh root@new-server-ip
apt-get update && apt-get upgrade -y
curl -fsSL https://get.docker.com | sh
usermod -aG docker $USER
# Log out and back in

# ── 3. Clone & Configure ──
git clone https://github.com/your-org/sentinel-cyber-ai.git
cd sentinel-cyber-ai
cp .env.production .env
nano .env  # Paste all secrets from password manager

# ── 4. Deploy ──
./scripts/deploy.sh

# ── 5. SSL ──
# Update DNS A records → api.yourdomain.com + dashboard.yourdomain.com
./scripts/setup-ssl.sh api.yourdomain.com dashboard.yourdomain.com

# ── 6. Restore Database ──
./scripts/backup.sh restore backups/postgres/sentinel_latest.sql.gz

# ── 7. Enable Monitoring ──
./scripts/deploy.sh --monitoring
```

### Post-Build Verification

- [ ] `./scripts/deploy.sh --status` — all 6 services healthy
- [ ] `curl -f https://api.yourdomain.com/health` — 200 OK
- [ ] `curl -f https://api.yourdomain.com/docs` — Swagger UI loads
- [ ] `curl -f https://dashboard.yourdomain.com/` — dashboard loads
- [ ] `curl -f https://api.yourdomain.com/metrics` — Prometheus metrics
- [ ] `curl -f http://localhost:3000/` — Grafana login page
- [ ] `./scripts/backup.sh list` — backups are being created
- [ ] `crontab -l | grep backup` — cron job is active
- [ ] `docker ps` — all containers running with no restarts

---

## 5. Monitoring Incident Response

### Alert: APIDown

```yaml
Alert:  API is unreachable
Check:
  1. docker ps | grep sentinel-api       # Is container running?
  2. docker logs sentinel-api --tail 50  # Check for errors
  3. docker logs sentinel-nginx --tail 50 # Check proxy errors
  4. curl -f http://localhost:8080/health # Direct health (bypass nginx)
Remediation:
  - If container crashed: docker compose restart api
  - If OOM: Check deploy.resources.limits.memory in docker-compose.prod.yml
  - If DB unavailable: Check sentinel-postgres container
```

### Alert: APIHighErrorRate

```yaml
Alert:  5xx error rate > 5%
Check:
  1. curl -f http://localhost:8080/health
  2. docker logs sentinel-api --tail 100 | grep "HTTP/1.1\" 5"
  3. Check recent code deployments
Remediation:
  - Rollback to previous image: deploy.sh — quick
  - Check DB connections: docker exec sentinel-postgres pg_isready
  - Check Redis: docker exec sentinel-redis redis-cli ping
```

### Alert: DiskSpaceLow

```yaml
Alert:  Disk space < 10%
Check:
  1. df -h                    # Overall usage
  2. du -sh backups/          # Backup storage
  3. du -sh docker/nginx/ssl/ # Certificate storage
  4. docker system df         # Docker disk usage
Remediation:
  - Clean old backups: ./scripts/backup.sh clean --keep 3
  - Prune Docker: docker system prune -f
  - Clear old logs: docker compose -f docker/docker-compose.prod.yml logs --tail=0
  - If urgent: Add more disk from cloud console (resize volume)
```

### Alert: HighMemoryUsage

```yaml
Alert:  Memory > 90%
Check:
  1. docker stats --no-stream      # Per-container memory
  2. docker logs sentinel-api --tail 20  # OOM signs
  3. htop or free -m              # System memory
Remediation:
  - Reduce worker replicas: docker compose up -d — scale worker=1
  - Restart services: docker compose restart
  - If persistent: Upgrade to larger server instance
```

### Alert: CriticalVulnerabilityFound

```yaml
Alert:  Critical security finding detected
Check:
  1. Find recent analyses in API logs
  2. Check the analysis result for details
  3. Verify it's not a false positive
Remediation:
  - If real: Apply patch, then re-scan to verify fix
  - If FP: Increase confidence threshold or tune rules
  - Escalate to security team immediately
```

---

## 6. Recovery Testing Schedule

Run these drills to ensure the team can execute the runbook under pressure.

### Monthly

| Test | Procedure | Success Criteria |
|---|---|---|
| **Backup integrity** | Run `verify-backups.sh` | All backups pass integrity check |
| **Restore dry-run** | Restore latest backup to staging DB | Staging DB has same table count as production |
| **SSL expiry check** | Check all cert expiry dates | No cert expires within 30 days |

### Quarterly

| Test | Procedure | Success Criteria |
|---|---|---|
| **Full restore drill** | Provision a temp server → restore from S3 → verify | Full stack operational in < 60 min |
| **Failover test** | Stop production DB → restore from latest backup | Recovery time < 30 min |
| **Secret rotation** | Generate new secrets → update .env → verify | All services start with new secrets |

### Annually

| Test | Procedure | Success Criteria |
|---|---|---|
| **Server rebuild** | Build server from scratch using runbook | Full rebuild in < 2 hours |
| **DR tabletop** | Walk through P1-P5 scenarios with team | All team members know their roles |

### Reporting

After each drill, document:
1. What went well
2. What went wrong
3. How long each step took
4. Improvements needed in the runbook
5. Updates to make to scripts or configs

File reports as GitHub Issues with label `area:dr`.

---

## Appendix: Key Commands Reference

### Database

```bash
# Backup
./scripts/backup.sh backup --compress           # Local backup
./scripts/backup.sh backup --compress --s3      # Backup + S3 sync

# Restore
./scripts/backup.sh restore backups/postgres/file.sql.gz

# Verify
./scripts/backup.sh verify
./scripts/backup.sh list

# Clean old
./scripts/backup.sh clean --keep 14
```

### Deployment

```bash
./scripts/deploy.sh                     # Full deploy
./scripts/deploy.sh --quick             # Quick restart
./scripts/deploy.sh --rebuild           # Force rebuild
./scripts/deploy.sh --monitoring        # Include Prometheus + Grafana
./scripts/deploy.sh --status            # Health check all services
./scripts/deploy.sh --logs              # Follow all logs
./scripts/deploy.sh --down              # Stop everything
```

### SSL

```bash
./scripts/setup-ssl.sh api.example.com dashboard.example.com
docker exec sentinel-nginx nginx -s reload   # Reload certs (no downtime)
```

### Cron

```bash
./scripts/backup.sh setup-cron          # Install daily backup cron
crontab -l                              # Verify cron is installed
```

### Monitoring

```bash
# Access URLs (after deploy --monitoring):
#   Grafana: http://server-ip:3000  (admin / password from .env)
#   Prometheus: http://server-ip:9090
#   Metrics: http://server-ip/metrics
```
