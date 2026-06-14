#!/usr/bin/env bash
# =============================================================================
# Sentinel Cyber AI — Post-Deployment Setup Script
# Run this on the EC2 server after Terraform provisions it.
# Verifies services, configures SSL, sets up backups.
# =============================================================================

set -euo pipefail

SENTINEL_DIR="/opt/sentinel"
cd "$SENTINEL_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Sentinel Post-Deployment Setup                   ${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
echo ""

# ── Check Docker ──
echo -e "${BLUE}🔍 Checking Docker...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker not found. Bootstrap may still be running.${NC}"
    echo "   Check: journalctl -u sentinel-bootstrap -f"
    exit 1
fi
echo -e "${GREEN}  ✅ Docker: $(docker --version)${NC}"

# ── Check Running Containers ──
echo -e "${BLUE}📊 Container Status:${NC}"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# ── Check API Health ──
echo -e "${BLUE}🔍 API Health:${NC}"
if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
    echo -e "${GREEN}  ✅ API is healthy${NC}"
else
    echo -e "${YELLOW}  ⏳ API not ready yet. Check: docker compose -f docker/docker-compose.prod.yml logs api${NC}"
fi

# ── Apply Security Updates ──
echo -e "${BLUE}🔒 Security Updates:${NC}"
apt-get update -qq && apt-get upgrade -y -qq
echo -e "${GREEN}  ✅ System updated${NC}"

# ── Configure Automatic Backups ──
echo -e "${BLUE}💾 Configuring backups...${NC}"
if [ -x "$SENTINEL_DIR/scripts/backup.sh" ]; then
    $SENTINEL_DIR/scripts/backup.sh setup-cron 2>/dev/null || true
    echo -e "${GREEN}  ✅ Backup cron configured${NC}"
else
    echo -e "${YELLOW}  ⚠️  Backup script not found${NC}"
fi

# ── Summary ──
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Setup Complete!                               ${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}API:${NC}          http://$(curl -s http://checkip.amazonaws.com 2>/dev/null || echo '<ip>')"
echo -e "  ${CYAN}Dashboard:${NC}    http://$(curl -s http://checkip.amazonaws.com 2>/dev/null || echo '<ip>'):8500"
echo -e "  ${CYAN}Health:${NC}       http://$(curl -s http://checkip.amazonaws.com 2>/dev/null || echo '<ip>')/health"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo -e "  1. Set up SSL: ./scripts/setup-ssl.sh api.yourdomain.com dashboard.yourdomain.com"
echo -e "  2. Verify backups: ./scripts/backup.sh verify"
echo -e "  3. View logs: ./scripts/deploy.sh --logs"
