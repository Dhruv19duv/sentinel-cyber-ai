# GitHub Secrets & CI/CD Setup Guide

Set up the GitHub Actions CI/CD pipeline for automated Sentinel deployments.

---

## 📋 What You'll Need

| Item | Where to Get It |
|---|---|
| GitHub Account | github.com |
| GitHub Repository | Your Sentinel fork or repo |
| A VPS with Docker | See [DEPLOYMENT-GUIDE.md](./DEPLOYMENT-GUIDE.md) |
| SSH Key Pair | Generated on your local machine |

---

## 🪜 Step-by-Step Setup

### 1. Generate a Deploy SSH Key

On your **local machine** (not the server), generate a dedicated deploy key:

```bash
ssh-keygen -t ed25519 -C "sentinel-deploy" -f ~/.ssh/sentinel-deploy-key
```

This creates two files:
- `~/.ssh/sentinel-deploy-key` — **private key** (keep secret!)
- `~/.ssh/sentinel-deploy-key.pub` — **public key** (goes on the server)

### 2. Add the Public Key to Your Server

```bash
# Copy your public key (local machine)
cat ~/.ssh/sentinel-deploy-key.pub

# SSH into your server and add it
ssh root@your-server-ip
echo "ssh-ed25519 AAAAC3... your-public-key-here" >> ~/.ssh/authorized_keys

# Test it (local machine)
ssh -i ~/.ssh/sentinel-deploy-key deploy@your-server-ip
# You should get a shell prompt (may need to create the 'deploy' user first)
```

### 3. Get Server's SSH Host Key

```bash
# Local machine
ssh-keyscan -H your-server-ip
```

Copy the output — it looks like:
```
your-server-ip ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
```

This goes into the `DEPLOY_KNOWN_HOSTS` secret.

### 4. Set Up GitHub Secrets

Go to your GitHub repository → **Settings** → **Secrets and variables** → **Actions**.

Add these **Repository Secrets**:

| Secret | Value | Example |
|---|---|---|
| `DEPLOY_SSH_HOST` | Your server IP or domain | `123.456.789.0` or `sentinel.example.com` |
| `DEPLOY_SSH_USER` | SSH user on the server | `deploy` or `root` |
| `DEPLOY_SSH_PORT` | SSH port | `22` |
| `DEPLOY_SSH_KEY` | **Full content** of private key file | `-----BEGIN OPENSSH PRIVATE KEY-----\n...` |
| `DEPLOY_KNOWN_HOSTS` | Output from `ssh-keyscan` | `your-server-ip ssh-ed25519 AAAA...` |

> **⚠️ Important:** `DEPLOY_SSH_KEY` must be the **entire** private key file content including `-----BEGIN OPENSSH PRIVATE KEY-----` and `-----END OPENSSH PRIVATE KEY-----`. Copy-paste the whole thing.

**For production + staging on different servers**, also add:
| Secret | Example |
|---|---|
| `DEPLOY_SSH_HOST_PROD` | `prod.sentinel.example.com` |
| `DEPLOY_SSH_USER_PROD` | `deploy` |
| `DEPLOY_SSH_KEY_PROD` | (different SSH key for production server) |
| `DEPLOY_KNOWN_HOSTS_PROD` | (production server's host key) |

### 5. Set Up GitHub Environments (Optional but Recommended)

GitHub Environments add **manual approval gates** before production deployments.

Go to your repository → **Settings** → **Environments**.

**Create the `staging` environment:**
1. Click **New environment** → name: `staging`
2. URL: `https://staging.yourdomain.com` (or your staging server URL)
3. No approval required (auto-deploy)

**Create the `production` environment:**
1. Click **New environment** → name: `production`
2. URL: `https://yourdomain.com`
3. **Required reviewers:** Add yourself (or your team)
4. **Wait timer:** 5 minutes (optional — gives you time to cancel if something's wrong)

Now every push to `main` will:
1. ✅ Run tests
2. ✅ Build and push Docker image to GHCR
3. ✅ Deploy to **staging** (auto)
4. ⏸️ Wait for your manual **approval** to deploy to production
5. ✅ Deploy to **production** (zero-downtime rolling restart)

### 6. Enable Workflow Permissions

Go to your repository → **Settings** → **Actions** → **General**.

Under **Workflow permissions**:
- Select **Read and write permissions**
- Check **Allow GitHub Actions to create and approve pull requests**

Under **Artifact and log retention**:
- Set to your preference (90 days recommended)

### 7. Enable GitHub Container Registry

The CI/CD pipeline pushes Docker images to **GitHub Container Registry (GHCR)**.

Go to your repository → **Settings** → **Actions** → **General** → **Workflow permissions**:
- Make sure **Read and write permissions** is selected

The `GITHUB_TOKEN` secret is automatically available — no need to create it. The pipeline uses it to push images to `ghcr.io/your-org/sentinel-cyber-ai`.

### 8. Verify the Pipeline Works

Push a commit to `main`:

```bash
git add .
git commit -m "ci: test deployment pipeline"
git push origin main
```

Then watch the pipeline:
1. Go to your repo → **Actions** tab
2. Click the running workflow
3. Watch: **test** → **docker** → **staging** → **production** (waiting for approval)

---

## 🔁 CI/CD Pipeline Flow

```
You push to main
      │
      ▼
  ┌──────────┐
  │   Test    │  pytest, coverage
  └────┬─────┘
       │ pass
       ▼
  ┌──────────┐
  │  Docker   │  Build & push to ghcr.io
  └────┬─────┘
       │ pass
       ▼
  ┌──────────┐
  │ Staging  │  SSH deploy to staging server
  └────┬─────┘
       │ pass
       ▼
  ┌──────────┐
  │Production│  ⏸  WAITING for approval
  │  Deploy  │     (Go to Actions tab → Review)
  └────┬─────┘
       │ approved
       ▼
  ┌──────────┐
  │ Monitor  │  Health check endpoints verified
  └──────────┘
```

---

## 🔐 Security Best Practices

1. **Use separate SSH keys** for staging and production servers
2. **Never commit `.env` files** (already in `.gitignore`)
3. **Rotate secrets** every 90 days
4. **Limit production SSH access** to the deploy key only (disable password auth)
5. **Use GitHub Environments** with required reviewers for production
6. **Review workflow runs** regularly for unauthorized changes

---

## 🐛 Troubleshooting

| Problem | Fix |
|---|---|
| `Host key verification failed` | `ssh-keyscan` output is wrong. Re-run and update `DEPLOY_KNOWN_HOSTS` |
| `Permission denied (publickey)` | The public key isn't in `~/.ssh/authorized_keys` on the server |
| `docker: command not found` | Docker isn't installed on the VPS. See [DEPLOYMENT-GUIDE.md](./DEPLOYMENT-GUIDE.md) |
| `GHCR push failed: denied` | Workflow permissions need **Read and write** enabled |
| `Workflow not showing in Actions` | Push to `main` branch (workflow triggers on `push` to `main`) |
