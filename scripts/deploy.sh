#!/usr/bin/env bash
# =============================================================================
# Sentinel Cyber AI — Production Deployment Script
# Automates Docker Compose deployment on any Linux server with Docker.
#
# Usage:
#   chmod +x scripts/deploy.sh
#   ./scripts/deploy.sh                    # Deploy with existing .env
#   ./scripts/deploy.sh --quick            # Quick deploy (no build, use latest)
#   ./scripts/deploy.sh --rebuild          # Force rebuild all images
#   ./scripts/deploy.sh --monitoring       # Include Prometheus + Grafana
#   ./scripts/deploy.sh --status           # Check deployment status
#   ./scripts/deploy.sh --logs             # Follow logs
#   ./scripts/deploy.sh --down             # Stop all services
#   ./scripts/deploy.sh --update           # Git pull + rebuild + restart
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ── Configuration ──
COMPOSE_FILE="docker/docker-compose.prod.yml"
COMPOSE_PROJECT="sentinel-prod"
ENV_FILE=".env"

# Source .env so check_ssl() reads the user's configured domain names
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck source=/dev/null
  . "$ENV_FILE"
  set +a
fi

# ── Prerequisites Check ──
check_prerequisites() {
    echo -e "${BLUE}🔍 Checking prerequisites...${NC}"

    # Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker is not installed.${NC}"
        echo "   Install: https://docs.docker.com/engine/install/"
        exit 1
    fi
    echo -e "${GREEN}  ✅ Docker: $(docker --version)${NC}"

    # Docker Compose
    if ! docker compose version &> /dev/null; then
        echo -e "${RED}❌ Docker Compose is not installed.${NC}"
        echo "   Install: https://docs.docker.com/compose/install/"
        exit 1
    fi
    echo -e "${GREEN}  ✅ Docker Compose: $(docker compose version)${NC}"

    # Environment file
    if [ ! -f "$ENV_FILE" ]; then
        echo -e "${YELLOW}⚠️  No .env file found. Creating from .env.production...${NC}"
        if [ -f ".env.production" ]; then
            cp .env.production .env
            echo -e "${YELLOW}   ✅ Created .env from .env.production template${NC}"
            echo -e "${YELLOW}   ⚠️  IMPORTANT: Edit .env with your production secrets before deploying!${NC}"
            echo ""
            echo -e "${YELLOW}   Edit .env now with: nano .env${NC}"
            exit 0
        else
            echo -e "${RED}❌ No .env.production template found.${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}  ✅ Environment file: $ENV_FILE${NC}"

    # Docker daemon running
    if ! docker info &> /dev/null; then
        echo -e "${RED}❌ Docker daemon is not running.${NC}"
        exit 1
    fi
    echo -e "${GREEN}  ✅ Docker daemon running${NC}"
}

# ── SSL Certificate Check ──
check_ssl() {
    # If Let's Encrypt certs exist (from setup-ssl.sh), use those
    if ls docker/nginx/ssl/live/*/fullchain.pem 2>/dev/null | head -1 | grep -q .; then
        echo -e "${GREEN}  ✅ Let's Encrypt certificates found${NC}"
        ls -d docker/nginx/ssl/live/*/ 2>/dev/null | while read -r d; do
            echo -e "     ${CYAN}$(basename "$d")${NC}"
        done
        return
    fi

    # Fallback: self-signed for testing
    # Must create certs at the certbot-expected paths so nginx can start
    local api_domain="${SENTINEL_API_DOMAIN:-api.sentinel-ai.dev}"
    local dash_domain="${SENTINEL_DASHBOARD_DOMAIN:-dashboard.sentinel-ai.dev}"

    local missing=false
    for domain in "$api_domain" "$dash_domain"; do
        if [ ! -f "docker/nginx/ssl/live/$domain/fullchain.pem" ]; then
            missing=true
        fi
    done

    if [ "$missing" = true ]; then
        echo -e "${YELLOW}⚠️  No SSL certificates found. Generating self-signed for testing...${NC}"
        for domain in "$api_domain" "$dash_domain"; do
            mkdir -p "docker/nginx/ssl/live/$domain"
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "docker/nginx/ssl/live/$domain/privkey.pem" \
                -out "docker/nginx/ssl/live/$domain/fullchain.pem" \
                -subj "/CN=$domain" 2>/dev/null
            echo -e "${GREEN}  ✅ Self-signed cert generated for $domain${NC}"
        done
        # Create the legacy paths too for any configs that still reference them
        cp "docker/nginx/ssl/live/$api_domain/fullchain.pem" docker/nginx/ssl/cert.pem 2>/dev/null || true
        cp "docker/nginx/ssl/live/$api_domain/privkey.pem" docker/nginx/ssl/key.pem 2>/dev/null || true
        echo -e "${YELLOW}   ⚠️  Self-signed certs (NOT for production!)${NC}"
        echo -e "${YELLOW}   Run: ./scripts/setup-ssl.sh to get real Let's Encrypt certs${NC}"
    else
        echo -e "${YELLOW}  ⚠️  Using self-signed certificates (not for production)${NC}"
        echo -e "${YELLOW}   Get real certs: ./scripts/setup-ssl.sh${NC}"
    fi
}

# ── Create Required Directories ──
setup_directories() {
    echo -e "${BLUE}📁 Setting up directories...${NC}"
    mkdir -p data/processed outputs/models outputs/reports outputs/benchmarks
    mkdir -p docker/nginx/ssl docker/nginx/static
    echo -e "${GREEN}  ✅ Directories ready${NC}"
}

# ── Deploy ──
deploy() {
    local rebuild=${1:-false}
    local monitoring=${2:-false}

    echo -e "${BLUE}🚀 Deploying Sentinel Cyber AI...${NC}"
    echo ""

    # Check prerequisites
    check_prerequisites
    check_ssl
    setup_directories

    # Pull latest images if not rebuilding
    if [ "$rebuild" = false ]; then
        echo -e "${BLUE}📦 Pulling images...${NC}"
        docker compose -f "$COMPOSE_FILE" --project-name "$COMPOSE_PROJECT" pull 2>/dev/null || true
        echo -e "${GREEN}  ✅ Images pulled${NC}"
    fi

    # Build images
    echo -e "${BLUE}🔨 Building images...${NC}"
    if [ "$rebuild" = true ]; then
        docker compose -f "$COMPOSE_FILE" --project-name "$COMPOSE_PROJECT" build --no-cache
    else
        docker compose -f "$COMPOSE_FILE" --project-name "$COMPOSE_PROJECT" build
    fi
    echo -e "${GREEN}  ✅ Images built${NC}"

    # Start services
    echo -e "${BLUE}▶️  Starting services...${NC}"
    if [ "$monitoring" = true ]; then
        docker compose -f "$COMPOSE_FILE" --project-name "$COMPOSE_PROJECT" --profile monitoring up -d
    else
        docker compose -f "$COMPOSE_FILE" --project-name "$COMPOSE_PROJECT" up -d
    fi
    echo -e "${GREEN}  ✅ Services started${NC}"

    # Wait for health checks
    echo -e "${BLUE}⏳ Waiting for services to be healthy...${NC}"
    sleep 5

    # Show status
    show_status

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅ Sentinel Cyber AI is LIVE!                  ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  API:      http://YOUR_SERVER_IP                ║${NC}"
    echo -e "${GREEN}║  API Docs: http://YOUR_SERVER_IP/docs            ║${NC}"
    echo -e "${GREEN}║  Dashboard: http://YOUR_SERVER_IP:8500           ║${NC}"
    echo -e "${GREEN}║  Grafana:  http://YOUR_SERVER_IP:3000            ║${NC}"
    echo -e "${GREEN}║  Health:   http://YOUR_SERVER_IP/health          ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}📝 Note: API & Dashboard are behind Nginx on port 80.${NC}"
    echo -e "${YELLOW}   Dashboard WebSocket is at ws://YOUR_SERVER_IP/ws/  ${NC}"
}

# ── Show Status ──
show_status() {
    echo -e "${BLUE}📊 Deployment Status:${NC}"
    docker compose -f "$COMPOSE_FILE" --project-name "$COMPOSE_PROJECT" ps
    echo ""

    local compose_cmd="docker compose -f docker/docker-compose.prod.yml --project-name sentinel-prod"

    echo -e "${BLUE}🔍 Health Checks:${NC}"

    # 1. Nginx (entry point on port 80, returns 301 to HTTPS)
    if curl -sf http://localhost/ > /dev/null 2>&1; then
        echo -e "${GREEN}  ✅ Nginx: Running (HTTP → HTTPS redirect)${NC}"
    else
        echo -e "${RED}  ❌ Nginx: Not responding on port 80${NC}"
        echo -e "${YELLOW}     Check: $compose_cmd logs nginx${NC}"
    fi

    # 2. API via Nginx proxy (SSL port 443 — actual health endpoint)
    if curl -sfk https://localhost/health > /dev/null 2>&1; then
        echo -e "${GREEN}  ✅ API: Healthy (via HTTPS)${NC}"
    else
        echo -e "${RED}  ❌ API: Health check failed${NC}"
        echo -e "${YELLOW}     Check: $compose_cmd logs api${NC}"
    fi

    # 3. Dashboard (port not exposed in production — check container)
    if docker ps --format '{{.Names}}' | grep -q sentinel-dashboard; then
        echo -e "${GREEN}  ✅ Dashboard: Container running${NC}"
        echo -e "${YELLOW}     Access via https://YOUR_SERVER/dashboard (WebSocket at /ws/)${NC}"
    else
        echo -e "${RED}  ❌ Dashboard: Container not running${NC}"
        echo -e "${YELLOW}     Check: $compose_cmd logs dashboard${NC}"
    fi

    # 4. PostgreSQL
    if docker ps --format '{{.Names}}' | grep -q sentinel-postgres; then
        echo -e "${GREEN}  ✅ PostgreSQL: Running${NC}"
    else
        echo -e "${RED}  ❌ PostgreSQL: Not running${NC}"
        echo -e "${YELLOW}     Check: $compose_cmd logs postgres${NC}"
    fi

    # 5. Redis
    if docker ps --format '{{.Names}}' | grep -q sentinel-redis; then
        echo -e "${GREEN}  ✅ Redis: Running${NC}"
    else
        echo -e "${RED}  ❌ Redis: Not running${NC}"
        echo -e "${YELLOW}     Check: $compose_cmd logs redis${NC}"
    fi

    # 6. Worker
    if docker ps --format '{{.Names}}' | grep -q sentinel-worker; then
        echo -e "${GREEN}  ✅ Worker: Running${NC}"
    else
        echo -e "${YELLOW}  ⚠️  Worker: Not running (background tasks disabled)${NC}"
    fi
}

# ── Follow Logs ──
follow_logs() {
    docker compose -f "$COMPOSE_FILE" --project-name "$COMPOSE_PROJECT" logs -f
}

# ── Stop Services ──
stop_services() {
    echo -e "${YELLOW}🛑 Stopping all services...${NC}"
    docker compose -f "$COMPOSE_FILE" --project-name "$COMPOSE_PROJECT" down
    echo -e "${GREEN}  ✅ Services stopped${NC}"
}

# ── Update (git pull + rebuild + restart) ──
update_deployment() {
    echo -e "${BLUE}🔄 Updating Sentinel...${NC}"

    # Git pull
    if git status --porcelain > /dev/null 2>&1; then
        echo -e "${BLUE}📥 Pulling latest code...${NC}"
        git pull
        echo -e "${GREEN}  ✅ Code updated${NC}"
    else
        echo -e "${YELLOW}⚠️  Not a git repository or git not available. Skipping pull.${NC}"
    fi

    # Rebuild and deploy
    deploy true
}

# ── Main ──
main() {
    local cmd=${1:-deploy}

    # Ensure we're in the project root
    if [ ! -f "pyproject.toml" ]; then
        echo -e "${RED}❌ Must be run from project root (sentinel-cyber-ai/)${NC}"
        exit 1
    fi

    case "$cmd" in
        --quick)
            check_prerequisites
            check_ssl
            setup_directories
            echo -e "${BLUE}🚀 Quick deploying (using existing images)...${NC}"
            docker compose -f "$COMPOSE_FILE" --project-name "$COMPOSE_PROJECT" up -d
            show_status
            ;;
        --rebuild)
            deploy true false
            ;;
        --monitoring)
            deploy false true
            ;;
        --status)
            check_prerequisites
            show_status
            ;;
        --logs)
            follow_logs
            ;;
        --down)
            stop_services
            ;;
        --update)
            update_deployment
            ;;
        --help|-h)
            echo "Sentinel Cyber AI — Production Deployment"
            echo ""
            echo "Usage:"
            echo "  ./scripts/deploy.sh                    Deploy with existing .env"
            echo "  ./scripts/deploy.sh --quick            Quick deploy (no build)"
            echo "  ./scripts/deploy.sh --rebuild          Force rebuild all"
            echo "  ./scripts/deploy.sh --monitoring       Include monitoring stack"
            echo "  ./scripts/deploy.sh --status           Check deployment status"
            echo "  ./scripts/deploy.sh --logs             Follow all logs"
            echo "  ./scripts/deploy.sh --down             Stop all services"
            echo "  ./scripts/deploy.sh --update           Git pull + rebuild + restart"
            echo "  ./scripts/deploy.sh --help             Show this help"
            echo ""
            echo "Quick Start:"
            echo "  1. cp .env.production .env"
            echo "  2. nano .env                    # Set your secrets"
            echo "  3. ./scripts/deploy.sh          # Go live!"
            ;;
        *)
            deploy false false
            ;;
    esac
}

main "$@"
