# Sentinel Cyber AI — Terraform Deployment

> **Infrastructure-as-Code for Sentinel's Production Deployment**
> Deploy to AWS (EKS) or GCP (GKE) with one command.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Cloud Load Balancer                    │
├──────────────┬──────────────┬──────────────┬─────────────┤
│   API Tier   │  Dashboard   │   Workers    │   Cronjobs  │
│  (gunicorn)  │  (websocket) │  (analysis)  │ (maintenance)│
├──────┼───────┴──────┼───────┴──────┼───────┴──────┼──────┤
│     PostgreSQL (RDS/CloudSQL)       │  Redis (ElastiCache/Memorystore) │
└─────────────────────────────────────┴─────────────────────────────────┘
```

---

## AWS Deployment

### Prerequisites

```bash
# 1. Install Terraform 1.6+
terraform --version

# 2. Configure AWS credentials
aws configure

# 3. Create S3 bucket for Terraform state
aws s3 mb s3://sentinel-terraform-state --region us-east-1
```

### Quick Start

```bash
# Navigate to AWS Terraform
cd terraform/aws

# Copy and edit variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

# Initialize Terraform
terraform init \
  -backend-config="bucket=sentinel-terraform-state" \
  -backend-config="key=aws/production/terraform.tfstate" \
  -backend-config="region=us-east-1"

# Review the plan
terraform plan -out=tfplan

# Apply
terraform apply tfplan
```

### What Gets Created

| Resource | Description | Cost |
|---|---|---|
| **VPC** | 3 public + 3 private + 3 database subnets, NAT Gateway | $30-60/mo |
| **EKS Cluster** | Kubernetes 1.30, managed node group (3-12 nodes) | $70-300/mo* |
| **RDS PostgreSQL 16** | Multi-AZ in prod, automated backups, encryption | $100-500/mo |
| **ElastiCache Redis 7** | Cluster mode, encryption, auto-failover in prod | $50-200/mo |
| **ECR Repository** | Docker image storage for Sentinel | Free |
| **S3 Bucket** | Sentinel data storage with versioning (prod) | $3-10/mo |
| **CloudFront CDN** | Optional CDN for dashboard assets | $10-50/mo |
| **IAM Roles** | Service accounts, least-privilege policies | Free |

*\*EC2 node costs vary by instance type. Default: m6i.large @ ~$70/mo each.*

### Variables

| Variable | Default | Description |
|---|---|---|
| `aws_region` | `us-east-1` | AWS region |
| `environment` | `production` | Environment (production/staging/development) |
| `vpc_cidr` | `10.0.0.0/16` | VPC CIDR block |
| `kubernetes_version` | `1.30` | EKS version |
| `node_instance_types` | `["m6i.large", "m6i.xlarge"]` | Node instance types |
| `node_min_size` | `3` | Minimum nodes |
| `node_max_size` | `12` | Maximum nodes |
| `rds_instance_class` | `db.r6g.large` | RDS instance class |
| `redis_node_type` | `cache.r6g.large` | Redis node type |
| `sentinel_api_key` | `""` | API authentication key |
| `slack_bot_token` | `""` | Slack bot token |
| `discord_bot_token` | `""` | Discord bot token |
| `github_token` | `""` | GitHub personal access token |

### Post-Deployment

```bash
# Configure kubectl
aws eks update-kubeconfig --region us-east-1 --name sentinel-production

# Verify deployment
kubectl get pods -n sentinel
kubectl get svc -n sentinel

# Check logs
kubectl logs -n sentinel deployment/sentinel-api -f
kubectl logs -n sentinel deployment/sentinel-dashboard -f
```

---

## GCP Deployment

### Prerequisites

```bash
# 1. Install Google Cloud SDK
gcloud auth login

# 2. Enable required APIs
gcloud services enable \
  compute.googleapis.com \
  container.googleapis.com \
  sqladmin.googleapis.com \
  redis.googleapis.com \
  artifactregistry.googleapis.com \
  storage.googleapis.com

# 3. Create GCS bucket for Terraform state
gsutil mb gs://sentinel-terraform-state
```

### Quick Start

```bash
# Navigate to GCP Terraform
cd terraform/gcp

# Copy and edit variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values (requires gcp_project_id)

# Initialize Terraform
terraform init \
  -backend-config="bucket=sentinel-terraform-state" \
  -backend-config="prefix=gcp/production"

# Review the plan
terraform plan -out=tfplan

# Apply
terraform apply tfplan
```

### What Gets Created

| Resource | Description | Cost |
|---|---|---|
| **VPC Network** | Custom VPC with private/public subnets, Cloud NAT | $0-10/mo |
| **GKE Cluster** | Kubernetes 1.30, VPC-native, private nodes | $70-300/mo* |
| **CloudSQL PostgreSQL 16** | Regional in prod, automated backups, Query Insights | $100-500/mo |
| **Memorystore Redis 7** | Standard HA in prod, persistence, maintenance window | $50-200/mo |
| **Artifact Registry** | Docker image storage | Free |
| **GCS Buckets** | Data storage + CDN assets | $5-15/mo |
| **Cloud CDN** | Optional CDN for dashboard | $5-30/mo |
| **IAM & Workload Identity** | Service accounts, WIF for Kubernetes | Free |

*\*GKE node costs vary. Default: e2-standard-4 @ ~$60-80/mo each.*

### Variables

| Variable | Default | Description |
|---|---|---|
| `gcp_project_id` | **(required)** | GCP project ID |
| `gcp_region` | `us-central1` | GCP region |
| `environment` | `production` | Environment |
| `node_machine_type` | `e2-standard-4` | GKE node machine type |
| `node_min_size` | `3` | Minimum nodes |
| `node_max_size` | `12` | Maximum nodes |
| `cloudsql_tier` | `db-custom-4-16384` | CloudSQL tier |
| `redis_memory_size_gb` | `5` | Redis memory (GB) |

### Post-Deployment

```bash
# Configure kubectl
gcloud container clusters get-credentials sentinel-production \
  --region us-central1 --project YOUR_PROJECT_ID

# Verify deployment
kubectl get pods -n sentinel
kubectl get svc -n sentinel

# Connect to CloudSQL via proxy
./cloud_sql_proxy -instances=YOUR_INSTANCE_CONNECTION_NAME=tcp:5432
```

---

## Terraform Module Structure

```
terraform/
├── aws/                      # AWS deployment
│   ├── main.tf               # VPC, EKS, RDS, Redis, CloudFront, ECR, IAM
│   ├── variables.tf           # All configurable parameters (30+)
│   ├── outputs.tf             # Connection strings, endpoints, commands
│   └── terraform.tfvars.example  # Example variable values
├── gcp/                      # GCP deployment
│   ├── main.tf               # VPC, GKE, CloudSQL, Memorystore, CDN, IAM
│   ├── variables.tf           # All configurable parameters (25+)
│   ├── outputs.tf             # Connection strings, endpoints, commands
│   └── terraform.tfvars.example  # Example variable values
└── modules/                  # Reusable Terraform modules
    └── sentinel-cluster/     # Shared cluster config (future)
```

---

## Production Checklist

- [ ] **DNS**: Configure domains (api.sentinel-ai.dev, dashboard.sentinel-ai.dev)
- [ ] **TLS**: Provision ACM/LetsEncrypt certificates
- [ ] **Backups**: Verify RDS/CloudSQL automated backups are running
- [ ] **Monitoring**: Configure Prometheus + Grafana alerts
- [ ] **Logging**: Enable CloudWatch/Stackdriver log exports
- [ ] **Secrets**: Rotate API keys, bot tokens, webhook secrets
- [ ] **Scaling**: Set HPA thresholds based on load testing
- [ ] **DR**: Test restore from backups, multi-region failover
- [ ] **Security**: Run `tfsec` or `checkov` on Terraform configs

---

## Cost Estimates

| Scale | AWS Monthly | GCP Monthly | Nodes | DB Tier |
|---|---|---|---|---|
| **Development** | $300-500 | $250-450 | 3-5 | db.r6g.large / db-custom-2-8192 |
| **Production** | $800-1200 | $700-1100 | 5-10 | db.r6g.xlarge / db-custom-4-16384 |
| **Enterprise** | $2000-4000 | $1800-3500 | 10-20 | db.r6g.2xlarge / db-custom-8-32768 |

*Estimates include compute, database, cache, and networking. Excludes data transfer costs.*

---

## Security

- **Encryption at rest**: RDS/CloudSQL (AES-256), ElastiCache/Memorystore, EBS volumes
- **Encryption in transit**: TLS 1.2+ for all services, VPC-private where possible
- **Network isolation**: Private subnets, no public IPs on nodes, Cloud NAT
- **IAM**: Least-privilege service accounts, Workload Identity (GCP), IRSA (AWS)
- **Secrets**: Terraform sensitive variables marked `sensitive = true`
- **Backups**: Automated, encrypted, retention based on environment

---

## Troubleshooting

| Issue | Solution |
|---|---|
| `terraform init` fails | Check AWS/GCP authentication and backend bucket exists |
| EKS node group stuck | Verify service-linked role exists: `AWSServiceRoleForAmazonEKSNodegroup` |
| CloudSQL connection fails | Ensure Cloud SQL Auth Proxy is running and IAM permissions correct |
| Helm release fails | Check Kubernetes context: `kubectl config current-context` |
| Redis connection refused | Verify security group/firewall rules allow port 6379 from EKS/GKE |
