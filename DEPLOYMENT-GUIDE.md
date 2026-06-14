# Sentinel Cyber AI — VPS Deployment Guide

Deploy Sentinel to a production server (DigitalOcean Droplet, AWS EC2, Linode, or any Linux VPS).

---

## 🚀 Quick Start (5 minutes)

```bash
# 1. SSH into your server
ssh root@your-server-ip

# 2. Install Docker & Compose
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in

# 3. Clone and deploy
git clone https://github.com/your-org/sentinel-cyber-ai.git
cd sentinel-cyber-ai
cp .env.production .env
nano .env              # Set SENTINEL_API_KEY, POSTGRES_PASSWORD
./scripts/deploy.sh    # Done!
```

---

## 📋 Prerequisites

| Resource | Minimum | Recommended |
|---|---|---|
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 4 GB | 8+ GB |
| **Disk** | 20 GB SSD | 50 GB SSD |
| **OS** | Ubuntu 22.04+ | Ubuntu 24.04 LTS |
| **Docker** | 24.0+ | Latest |
| **Domain** | — | 2 DNS A records |

---

## 🪜 Step-by-Step Deployment

### 1. Create Your VPS

**DigitalOcean (recommended for first deploy):**
- Create a **Droplet** → **Ubuntu 24.04 LTS** → **$24/mo (4GB RAM)** plan
- Add your SSH key
- Note the public IP

**AWS EC2:**
- Launch **t3.medium** (2 vCPU, 4GB) with Ubuntu 24.04
- Security Group: open ports **22** (SSH), **80** (HTTP), **443** (HTTPS)
- Allocate and associate an Elastic IP

**Linode:**
- Create a **Linode 4GB** with Ubuntu 24.04
- Add your SSH key

### 2. Connect & Install Docker

```bash
# SSH in
ssh root@your-server-ip

# Update system
apt-get update && apt-get upgrade -y

# Install Docker (official script)
curl -fsSL https://get.docker.com | sh

# Add your user to docker group (reduces sudo usage)
usermod -aG docker $USER
# Log out and back in: exit → ssh root@your-server-ip

# Verify
docker --version && docker compose version
```

### 3. Clone & Configure

```bash
# Clone the repository
git clone https://github.com/your-org/sentinel-cyber-ai.git
cd sentinel-cyber-ai

# Create environment from template
cp .env.production .env

# Edit configuration
nano .env
```

**Required changes in `.env`:**
| Variable | What to set |
|---|---|
| `SENTINEL_API_KEY` | `openssl rand -hex 32` (generate a random key) |
| `POSTGRES_PASSWORD` | `openssl rand -hex 16` (generate a strong password) |
| `GRAFANA_PASSWORD` | Another strong password |
| `SENTINEL_API_DOMAIN` | Your API domain (e.g., `api.yourdomain.com`) |
| `SENTINEL_DASHBOARD_DOMAIN` | Your dashboard domain (e.g., `dashboard.yourdomain.com`) |
| `SENTINEL_CORS_ORIGINS` | Update with your actual domains |

### 4. Deploy!

```bash
# Production deploy (builds and starts all services)
./scripts/deploy.sh

# Or for a quick restart after initial setup:
./scripts/deploy.sh --quick
```

Your API should now be running at `http://your-server-ip` (port 80).

### 5. Set Up SSL (Let's Encrypt)

DNS must be configured first. Your domains need A records pointing to this server.

```bash
# !! Before running this, make sure your domains point to this server's IP !!
./scripts/setup-ssl.sh api.yourdomain.com dashboard.yourdomain.com
```

Then verify:
```bash
curl -I https://api.yourdomain.com/health
# Should return 200 OK
```

### 6. Verify Everything

```bash
# Check all services health
./scripts/deploy.sh --status

# Expected output:
#   ✅ Nginx: Running
#   ✅ API: Healthy
#   ✅ Dashboard: Container running
#   ✅ PostgreSQL: Running
#   ✅ Redis: Running
#   ✅ Worker: Running

# Watch logs
./scripts/deploy.sh --logs
```

---

## 🛠 Maintenance

### Updating

```bash
# Pull latest code + rebuild + restart
./scripts/deploy.sh --update

# Or manually:
git pull
./scripts/deploy.sh --rebuild
```

### Monitoring Stack (optional)

```bash
# Start Prometheus + Grafana
./scripts/deploy.sh --monitoring

# Access Grafana at http://your-server-ip:3000 (admin / <password from .env>)
```

### Viewing Logs

```bash
# Live logs for all services
./scripts/deploy.sh --logs

# Logs for a specific service
docker compose -f docker/docker-compose.prod.yml logs api
docker compose -f docker/docker-compose.prod.yml logs worker
docker compose -f docker/docker-compose.prod.yml logs nginx
```

### Scaling Workers

```bash
# Edit .env
WORKER_REPLICAS=3

# Re-deploy
./scripts/deploy.sh --quick
```

### Backup Database

```bash
docker exec sentinel-postgres pg_dump -U sentinel sentinel > backup_$(date +%Y%m%d).sql
```

---

## 🏗 Architecture

```
Internet → Nginx (80/443) ─┬─ /api/* → API (8080) ──┬─ PostgreSQL (5432)
                            │                        └─ Redis (6379)
                            ├─ /dashboard → Dashboard (8500)
                            ├─ /ws/* → Dashboard WebSocket
                            └─ /health → API health check

Background: Worker → Redis (job queue) → PostgreSQL
Monitoring:  Prometheus (9090) → Grafana (3000)
SSL:         Certbot (auto-renewal every 12h)
```

---

## 🔒 Security Checklist

- [ ] `SENTINEL_API_KEY` is a strong random value
- [ ] `POSTGRES_PASSWORD` is a strong random value
- [ ] `GRAFANA_PASSWORD` is a strong random value
- [ ] SSL certificates installed via Let's Encrypt
- [ ] Ports 5432, 6379, 8080, 8500 are NOT open to the internet (Nginx handles ingress)
- [ ] Firewall configured (UFW or cloud firewall) — only 22, 80, 443 open
- [ ] Regular backups configured for PostgreSQL
- [ ] Monitoring stack enabled and alert channels configured

---

## 🐛 Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Nginx won't start | SSL certs missing | Run `./scripts/deploy.sh` (generates self-signed fallback) |
| `port is already allocated` | Service already running | `./scripts/deploy.sh --down` then deploy again |
| API health check fails | DB not ready | Wait 30s, then check again |
| Dashboard not loading | Nginx config | Check `docker compose -f docker/docker-compose.prod.yml logs nginx` |
| Certbot fails | DNS not propagated | Verify `dig yourdomain.com` resolves to this server's IP |
| Out of memory | Too many workers | Reduce `WORKER_REPLICAS` in .env |

---

## ☁️ Provider-Specific Notes

### DigitalOcean
- Enable **Monitoring** on the droplet for CPU/memory graphs
- Use the **Firewall** (not UFW) for port control
- Volumes block storage for PostgreSQL data persistence

### AWS EC2
- Security Group must allow HTTP (80), HTTPS (443), SSH (22)
- Use an **Elastic IP** so the IP doesn't change on restart
- Consider EBS snapshots for automated DB backups

### Linode
- Use **Linode Firewall** for network-level protection
- Enable **Backups** ($2/mo) for automatic weekly snapshots
