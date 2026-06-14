#!/usr/bin/env bash
# =============================================================================
# Sentinel Cyber AI — VPS Deployment Checklist
# Interactive step-by-step deployment walkthrough.
# Run this after provisioning a new VPS to ensure nothing is missed.
#
# Usage:
#   chmod +x scripts/deploy-checklist.sh
#   ./scripts/deploy-checklist.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Sentinel Cyber AI — VPS Deployment Checklist   ║${NC}"
echo -e "${BLUE}║   Run this step-by-step to deploy to production  ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

TOTAL_STEPS=8
CURRENT=0

check_step() {
    CURRENT=$((CURRENT + 1))
    echo ""
    echo -e "${BOLD}[Step $CURRENT/$TOTAL_STEPS]${NC} $1"
    echo -e "${YELLOW}  $2${NC}"
    echo -n "  Done? [Y/n] "
    read -r answer
    if [[ "$answer" =~ ^[Nn] ]]; then
        echo -e "${RED}  ⛔ Skipped${NC}"
        return 1
    fi
    echo -e "${GREEN}  ✅ Complete${NC}"
    return 0
}

info() {
    echo -e "${CYAN}  ℹ️  $1${NC}"
}

# ── Step 1: Provision VPS ──
check_step "Provision VPS" \
    "Create server: Ubuntu 24.04 LTS, 4GB+ RAM, 2+ CPU, 50GB+ SSD.\n  Open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)" || true

# ── Step 2: SSH & Install Docker ──
check_step "SSH & Install Docker" \
    "SSH into your server, then run:\n    curl -fsSL https://get.docker.com | sh\n    sudo usermod -aG docker \$USER\n  Then log out and back in." || true
info "Verify: docker --version && docker compose version"

# ── Step 3: Clone Repository ──
check_step "Clone Repository" \
    "git clone https://github.com/your-org/sentinel-cyber-ai.git\n  cd sentinel-cyber-ai" || true

# ── Step 4: Configure Environment ──
check_step "Configure Environment" \
    "cp .env.production .env\n  Edit .env with nano/vim:\n    • SENTINEL_API_KEY = openssl rand -hex 32\n    • POSTGRES_PASSWORD = <strong password>\n    • GRAFANA_PASSWORD = <strong password>\n    • CORS origins = your domains\n  (Optional) BACKUP_S3_BUCKET = s3://your-bucket/path" || true

# ── Step 5: Deploy ──
check_step "Deploy Stack" \
    "./scripts/deploy.sh" || true
info "Tip: Use ./scripts/deploy.sh --monitoring to also start Prometheus + Grafana"

# ── Step 6: SSL Certificates ──
check_step "SSL Certificates" \
    "Point DNS A records to your server IP first, then:\n  ./scripts/setup-ssl.sh api.yourdomain.com dashboard.yourdomain.com" || true
info "Verify: curl -I https://api.yourdomain.com/health"

# ── Step 7: Database Backup ──
check_step "Database Backup" \
    "Run initial backup and verify:\n  ./scripts/backup.sh backup --compress\n  ./scripts/backup.sh verify\n  ./scripts/backup.sh list" || true
info "If BACKUP_S3_BUCKET is set, run: ./scripts/backup.sh backup --compress --s3"
info "Install daily cron: ./scripts/backup.sh setup-cron"

# ── Step 8: Final Verification ──
echo ""
echo -e "${BOLD}[Step 8/8] Final Verification${NC}"
echo -e "${YELLOW}  Run these checks to confirm everything is working:${NC}"
echo ""

VERIFY_PASSED=0
VERIFY_TOTAL=9

run_verify() {
    local desc="$1"
    local cmd="$2"
    echo -n "  $desc... "
    if eval "$cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}✅${NC}"
        VERIFY_PASSED=$((VERIFY_PASSED + 1))
    else
        echo -e "${RED}❌${NC}"
    fi
}

if [ -f pyproject.toml ]; then
    run_verify "Project root detected" "[ -f pyproject.toml ]"
    run_verify ".env file exists" "[ -f .env ]"
    run_verify "Docker installed" "command -v docker"
    run_verify "Docker Compose installed" "docker compose version"
    run_verify "Nginx config valid" "[ -f docker/nginx/nginx.conf ] && [ -f docker/nginx/sentinel.conf ]"
    run_verify "Prometheus config exists" "[ -f docker/prometheus/prometheus.yml ]"
    run_verify "Grafana dashboard exists" "[ -f docker/grafana/dashboards/sentinel_overview.json ]"
    run_verify "Backup script executable" "[ -x scripts/backup.sh ]"
    run_verify "DR runbook exists" "[ -f DISASTER_RECOVERY.md ]"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ Checklist Complete!                          ║${NC}"
echo -e "${GREEN}║  $VERIFY_PASSED/$VERIFY_TOTAL verification checks passed     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Next steps:"
echo -e "  • ${CYAN}API:${NC}        curl http://YOUR_SERVER_IP/health"
echo -e "  • ${CYAN}API Docs:${NC}    open http://YOUR_SERVER_IP/docs"
echo -e "  • ${CYAN}Dashboard:${NC}   open http://YOUR_SERVER_IP:8500"
echo -e "  • ${CYAN}Metrics:${NC}     curl http://YOUR_SERVER_IP/metrics"
echo -e "  • ${CYAN}Grafana:${NC}     open http://YOUR_SERVER_IP:3000 (admin / password from .env)"
echo -e "  • ${CYAN}Prometheus:${NC}  open http://YOUR_SERVER_IP:9090"
echo -e ""
echo -e "Run backup: ${CYAN}./scripts/backup.sh backup --compress${NC}"
echo -e "View logs:  ${CYAN}./scripts/deploy.sh --logs${NC}"
echo -e "Check status: ${CYAN}./scripts/deploy.sh --status${NC}"
echo ""
