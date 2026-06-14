# =============================================================================
# Sentinel Cyber AI — Terraform Variables
# Budget-friendly defaults — all optional
# =============================================================================

# ── General ──
variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (production, staging, development)"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "sentinel"
}

# ── VPC ──
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones to use"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

# ── EC2 ──
variable "ec2_instance_type" {
  description = "EC2 instance type for the Sentinel server"
  type        = string    default     = "t3.medium"  # ~$30-35/mo, 2 vCPU, 4GB RAM (t3.small 2GB caused OOM)
}

variable "ec2_volume_size" {
  description = "EBS volume size in GB for the Sentinel server (30GB minimum for Docker)"
  type        = number
  default     = 30
}

variable "ec2_volume_type" {
  description = "EBS volume type"
  type        = string
  default     = "gp3"
}

variable "ec2_key_name" {
  description = "Name of an existing EC2 key pair for SSH access. If empty, a key pair will be generated."
  type        = string
  default     = ""
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to SSH into the server"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Restrict to your IP in production!
}

# ── RDS (Optional) ──
variable "enable_rds" {
  description = "Whether to provision RDS PostgreSQL. Disable to run PostgreSQL in Docker on EC2 (saves ~$15/mo)"
  type        = bool
  default     = false  # Budget-friendly: run PG on EC2
}

variable "rds_instance_class" {
  description = "RDS instance class (only used if enable_rds = true)"
  type        = string
  default     = "db.t3.micro"  # Free tier eligible
}

variable "rds_allocated_storage" {
  description = "RDS allocated storage in GB"
  type        = number
  default     = 20
}

variable "rds_db_name" {
  description = "PostgreSQL database name"
  type        = string
  default     = "sentinel"
}

variable "rds_master_username" {
  description = "RDS master username"
  type        = string
  default     = "sentinel"
  sensitive   = true
}

variable "rds_master_password" {
  description = "RDS master password. If empty, a random one is generated."
  type        = string
  default     = ""
  sensitive   = true
}

# ── S3 ──
variable "s3_bucket_name_prefix" {
  description = "Prefix for S3 bucket names. Full names will be '<prefix>-<environment>-<type>'"
  type        = string
  default     = "sentinel"
}

variable "enable_s3_backups" {
  description = "Whether to create S3 buckets for backup storage"
  type        = bool
  default     = true
}

variable "enable_s3_versioning" {
  description = "Whether to enable S3 bucket versioning"
  type        = bool
  default     = true
}

# ── CloudFront (Optional) ──
variable "enable_cloudfront" {
  description = "Whether to provision CloudFront CDN. Adds ~$5-10/mo."
  type        = bool
  default     = false  # Budget-friendly: skip CDN
}

# ── DNS (Optional) ──
variable "enable_route53" {
  description = "Whether to configure Route53 DNS records. Requires a hosted zone."
  type        = bool
  default     = false
}

variable "route53_zone_name" {
  description = "Route53 hosted zone name (e.g., 'sentinel-ai.dev')"
  type        = string
  default     = ""
}

variable "api_subdomain" {
  description = "Subdomain for the API (e.g., 'api' makes api.sentinel-ai.dev)"
  type        = string
  default     = "api"
}

variable "dashboard_subdomain" {
  description = "Subdomain for the dashboard (e.g., 'dashboard' makes dashboard.sentinel-ai.dev)"
  type        = string
  default     = "dashboard"
}

# ── Sentinel Configuration ──
variable "sentinel_api_key" {
  description = "API key for Sentinel authentication. If empty, a random one is generated."
  type        = string
  default     = ""
  sensitive   = true
}

variable "sentinel_github_token" {
  description = "GitHub personal access token for Sentinel integrations"
  type        = string
  default     = ""
  sensitive   = true
}

variable "sentinel_slack_webhook" {
  description = "Slack webhook URL for Sentinel alerts"
  type        = string
  default     = ""
  sensitive   = true
}

variable "sentinel_discord_webhook" {
  description = "Discord webhook URL for Sentinel alerts"
  type        = string
  default     = ""
  sensitive   = true
}

variable "sentinel_cors_origins" {
  description = "Comma-separated CORS allowed origins"
  type        = string
  default     = "*"
}

# ── Git Repository ──
variable "git_repo_url" {
  description = "Git repository URL containing the Sentinel code"
  type        = string
  default     = "https://github.com/sentinel-cyber-ai/sentinel.git"
}

variable "git_branch" {
  description = "Git branch to deploy"
  type        = string
  default     = "main"
}
