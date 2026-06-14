variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region for deployment"
  type        = string
  default     = "us-central1"
}

variable "gcp_zone" {
  description = "GCP zone for zonal resources"
  type        = string
  default     = "us-central1-a"
}

variable "gcp_zone_alt" {
  description = "Alternative GCP zone for HA resources"
  type        = string
  default     = "us-central1-b"
}

variable "environment" {
  description = "Deployment environment (production, staging, development)"
  type        = string
  default     = "production"
  validation {
    condition     = contains(["production", "staging", "development"], var.environment)
    error_message = "Environment must be production, staging, or development."
  }
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "sentinel"
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

variable "pods_ip_cidrs" {
  description = "CIDR blocks for GKE pod IP ranges"
  type        = list(string)
  default     = ["10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"]
}

variable "services_ip_cidrs" {
  description = "CIDR blocks for GKE service IP ranges"
  type        = list(string)
  default     = ["10.4.0.0/20", "10.4.16.0/20", "10.4.32.0/20"]
}

variable "node_machine_type" {
  description = "GCE machine type for GKE nodes"
  type        = string
  default     = "e2-standard-4"
}

variable "node_min_size" {
  description = "Minimum number of GKE nodes"
  type        = number
  default     = 3
}

variable "node_max_size" {
  description = "Maximum number of GKE nodes"
  type        = number
  default     = 12
}

variable "cloudsql_tier" {
  description = "CloudSQL tier (e.g., db-custom-2-8192)"
  type        = string
  default     = "db-custom-4-16384"
}

variable "cloudsql_disk_size" {
  description = "CloudSQL disk size in GB"
  type        = number
  default     = 100
}

variable "redis_memory_size_gb" {
  description = "Redis memory size in GB"
  type        = number
  default     = 5
}

variable "admin_access_cidrs" {
  description = "CIDR blocks allowed to access the cluster master endpoint"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "kms_key_name" {
  description = "KMS key name for encryption (e.g., projects/project/locations/global/keyRings/ring/cryptoKeys/key)"
  type        = string
  default     = ""
}

variable "sentinel_api_key" {
  description = "API key for Sentinel authentication"
  type        = string
  sensitive   = true
  default     = ""
}

variable "sentinel_image_tag" {
  description = "Docker image tag for Sentinel deployment"
  type        = string
  default     = "latest"
}

variable "github_token" {
  description = "GitHub personal access token for webhooks"
  type        = string
  sensitive   = true
  default     = ""
}

variable "github_webhook_secret" {
  description = "GitHub webhook secret for signature verification"
  type        = string
  sensitive   = true
  default     = ""
}

variable "slack_bot_token" {
  description = "Slack bot token"
  type        = string
  sensitive   = true
  default     = ""
}

variable "slack_webhook_url" {
  description = "Slack incoming webhook URL"
  type        = string
  sensitive   = true
  default     = ""
}

variable "discord_bot_token" {
  description = "Discord bot token"
  type        = string
  sensitive   = true
  default     = ""
}

variable "discord_webhook_url" {
  description = "Discord webhook URL"
  type        = string
  sensitive   = true
  default     = ""
}

variable "api_domain" {
  description = "Domain name for the API"
  type        = string
  default     = "api.sentinel-ai.dev"
}

variable "dashboard_domain" {
  description = "Domain name for the dashboard"
  type        = string
  default     = "dashboard.sentinel-ai.dev"
}
