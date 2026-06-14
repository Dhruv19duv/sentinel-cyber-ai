#!/usr/bin/env bash
# =============================================================================
# Sentinel Cyber AI — Let's Encrypt SSL Certificate Setup
# =============================================================================
# Prerequisites:
#   1. Your domain's DNS A records point to this server's public IP
#   2. Port 80 is publicly accessible (Let's Encrypt validates via HTTP-01)
#   3. Docker Compose is already deployed (nginx must be running on port 80)
#
# Usage:
#   ./scripts/setup-ssl.sh                          # Interactive setup
#   ./scripts/setup-ssl.sh api.yourdomain.com dashboard.yourdomain.com  # Non-interactive
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ── Help ──
show_help() {
    echo "Sentinel Cyber AI — Let's Encrypt SSL Certificate Setup"
    echo ""
    echo "Usage:"
    echo "  ./scripts/setup-ssl.sh                                  Interactive setup"
    echo "  ./scripts/setup-ssl.sh <api-domain> <dashboard-domain>  Non-interactive"
    echo ""
    echo "Examples:"
    echo "  ./scripts/setup-ssl.sh sentinel.example.com dashboard.example.com"
    echo ""
    echo "Prerequisites:"
    echo "  - DNS A records pointing to this server for both domains"
    echo "  - Port 80 open (Let's Encrypt validation)"
    echo "  - Docker Compose running with nginx on port 80"
    echo "  - Email address for certificate expiry notifications"
    echo ""
    echo "Actions performed:"
    echo "  1. Stops certbot container if running"
    echo "  2. Obtains certificates via HTTP-01 challenge"
    echo "  3. Updates .env.production with domain names"
    echo "  4. Reloads nginx to serve new certificates"
    echo "  5. Sets up auto-renewal (certbot runs every 12h in Docker)"
    exit 0
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    show_help
fi

# ── Parse arguments ──
if [ $# -ge 2 ]; then
    API_DOMAIN="$1"
    DASHBOARD_DOMAIN="$2"
else
    echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   Let's Encrypt SSL Certificate Setup            ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "Enter the domain for the ${CYAN}API${NC} (e.g., sentinel.example.com):"
    read -r API_DOMAIN
    echo -e "Enter the domain for the ${CYAN}Dashboard${NC} (e.g., dashboard.example.com):"
    read -r DASHBOARD_DOMAIN
fi

if [ -z "$API_DOMAIN" ] || [ -z "$DASHBOARD_DOMAIN" ]; then
    echo -e "${RED}❌ Both API and Dashboard domains are required.${NC}"
    exit 1
fi

echo ""
echo -e "Enter your ${CYAN}email address${NC} for Let's Encrypt notifications:"
read -r EMAIL

# ── Validate inputs ──
echo ""
echo -e "${BLUE}🔍 Summary:${NC}"
echo -e "  API domain:       ${CYAN}$API_DOMAIN${NC}"
echo -e "  Dashboard domain: ${CYAN}$DASHBOARD_DOMAIN${NC}"
echo -e "  Email:            ${CYAN}$EMAIL${NC}"
echo ""
echo -e "Continue? [Y/n]"
read -r CONFIRM
if [[ "$CONFIRM" =~ ^[Nn] ]]; then
    echo -e "${YELLOW}Aborted.${NC}"
    exit 0
fi

# ── Check prerequisites ──
echo ""
echo -e "${BLUE}🔍 Checking prerequisites...${NC}"

# Resolve domains
echo -e "  Resolving API domain ($API_DOMAIN)..."
API_IP=$(dig +short "$API_DOMAIN" 2>/dev/null || nslookup "$API_DOMAIN" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
if [ -z "$API_IP" ]; then
    echo -e "${YELLOW}  ⚠️  Could not resolve $API_DOMAIN (DNS may not have propagated)${NC}"
else
    echo -e "${GREEN}  ✅ $API_DOMAIN → $API_IP${NC}"
fi

echo -e "  Resolving Dashboard domain ($DASHBOARD_DOMAIN)..."
DASH_IP=$(dig +short "$DASHBOARD_DOMAIN" 2>/dev/null || nslookup "$DASHBOARD_DOMAIN" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
if [ -z "$DASH_IP" ]; then
    echo -e "${YELLOW}  ⚠️  Could not resolve $DASHBOARD_DOMAIN (DNS may not have propagated)${NC}"
else
    echo -e "${GREEN}  ✅ $DASHBOARD_DOMAIN → $DASH_IP${NC}"
fi

# Check if nginx is running
if ! docker ps --format '{{.Names}}' | grep -q sentinel-nginx; then
    echo -e "${RED}❌ Nginx container is not running. Deploy first: ./scripts/deploy.sh${NC}"
    exit 1
fi
echo -e "${GREEN}  ✅ Nginx is running${NC}"

# ── Stop existing certbot if running ──
echo ""
echo -e "${BLUE}🛑 Stopping certbot container (if running)...${NC}"
docker rm -f sentinel-certbot 2>/dev/null || true
echo -e "${GREEN}  ✅ Done${NC}"

# ── Obtain certificates ──
echo ""
echo -e "${BLUE}🔐 Obtaining certificates from Let's Encrypt...${NC}"
echo -e "  (This may take 30-60 seconds for DNS validation)${NC}"
echo ""

docker run --rm \
    --name sentinel-certbot-init \
    -v "$SCRIPT_DIR/docker/nginx/ssl:/etc/letsencrypt:rw" \
    -v "sentinel-prod_certbot-www:/var/www/certbot:rw" \
    certbot/certbot:v2.11.0 certonly \
    --webroot -w /var/www/certbot \
    --agree-tos \
    --non-interactive \
    --email "$EMAIL" \
    --domain "$API_DOMAIN" \
    --domain "$DASHBOARD_DOMAIN" \
    --expand

echo -e "${GREEN}  ✅ Certificates obtained!${NC}"

# ── Update .env.production ──
echo ""
echo -e "${BLUE}📝 Updating .env.production with domain names...${NC}"

# Update or add API_DOMAIN
if grep -q "^SENTINEL_API_DOMAIN=" .env.production; then
    sed -i "s|^SENTINEL_API_DOMAIN=.*|SENTINEL_API_DOMAIN=$API_DOMAIN|" .env.production
else
    echo "SENTINEL_API_DOMAIN=$API_DOMAIN" >> .env.production
fi

# Update or add DASHBOARD_DOMAIN
if grep -q "^SENTINEL_DASHBOARD_DOMAIN=" .env.production; then
    sed -i "s|^SENTINEL_DASHBOARD_DOMAIN=.*|SENTINEL_DASHBOARD_DOMAIN=$DASHBOARD_DOMAIN|" .env.production
else
    echo "SENTINEL_DASHBOARD_DOMAIN=$DASHBOARD_DOMAIN" >> .env.production
fi

# Update CORS origins
if grep -q "^SENTINEL_CORS_ORIGINS=" .env.production; then
    sed -i "s|^SENTINEL_CORS_ORIGINS=.*|SENTINEL_CORS_ORIGINS=https://$API_DOMAIN,https://$DASHBOARD_DOMAIN|" .env.production
else
    echo "SENTINEL_CORS_ORIGINS=https://$API_DOMAIN,https://$DASHBOARD_DOMAIN" >> .env.production
fi

# Also update .env if it exists
for env_file in .env .env.production; do
    if [ -f "$env_file" ]; then
        for var_name in SENTINEL_API_DOMAIN SENTINEL_DASHBOARD_DOMAIN; do
            if grep -q "^${var_name}=" "$env_file"; then
                val=$(grep "^${var_name}=" .env.production | cut -d= -f2-)
                sed -i "s|^${var_name}=.*|${var_name}=${val}|" "$env_file"
            fi
        done
    fi
done

echo -e "${GREEN}  ✅ Environment updated${NC}"

# ── Update nginx config with the actual domain names ──
echo ""
echo -e "${BLUE}⚙️  Updating nginx configuration...${NC}"

# Update the server_name in sentinel.conf
sed -i "s/api\\.sentinel-ai\\.dev/$API_DOMAIN/g" docker/nginx/sentinel.conf
sed -i "s/dashboard\\.sentinel-ai\\.dev/$DASHBOARD_DOMAIN/g" docker/nginx/sentinel.conf

# Update certificate paths to point to the domain-specific certs
sed -i "s|/etc/nginx/ssl/live/api\\.sentinel-ai\\.dev|/etc/nginx/ssl/live/$API_DOMAIN|g" docker/nginx/sentinel.conf
sed -i "s|/etc/nginx/ssl/live/dashboard\\.sentinel-ai\\.dev|/etc/nginx/ssl/live/$DASHBOARD_DOMAIN|g" docker/nginx/sentinel.conf

echo -e "${GREEN}  ✅ Nginx config updated${NC}"

# ── Reload nginx ──
echo ""
echo -e "${BLUE}🔄 Reloading nginx...${NC}"
docker exec sentinel-nginx nginx -s reload 2>/dev/null || {
    echo -e "${YELLOW}  ⚠️  Could not reload nginx. Restarting via Docker Compose...${NC}"
    docker compose -f docker/docker-compose.prod.yml --project-name sentinel-prod restart nginx || true
}
echo -e "${GREEN}  ✅ Nginx reloaded${NC}"

# ── Start certbot auto-renewal ──
echo ""
echo -e "${BLUE}📅 Starting certbot auto-renewal container...${NC}"
docker compose -f docker/docker-compose.prod.yml --project-name sentinel-prod --profile ssl up -d certbot
echo -e "${GREEN}  ✅ Certbot renewal container started (checks every 12h)${NC}"

# ── Done ──
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ SSL Setup Complete!                         ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  API:       https://$API_DOMAIN              ║${NC}"
echo -e "${GREEN}║  Dashboard: https://$DASHBOARD_DOMAIN         ║${NC}"
echo -e "${GREEN}║  API Docs:  https://$API_DOMAIN/docs          ║${NC}"
echo -e "${GREEN}║  Health:    https://$API_DOMAIN/health         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Certificates auto-renew every 12 hours."
echo -e "To verify: curl -I https://$API_DOMAIN/health"
