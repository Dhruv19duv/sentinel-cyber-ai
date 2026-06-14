variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "security_group_id" {
  type = string
}

variable "instance_type" {
  type = string
}

variable "volume_size" {
  type = number
}

variable "volume_type" {
  type = string
}

variable "key_name" {
  type    = string
  default = ""
}

variable "ssh_allowed_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "enable_rds" {
  type    = bool
  default = false
}

variable "rds_endpoint" {
  type    = string
  default = ""
}

variable "rds_db_name" {
  type    = string
  default = "sentinel"
}

variable "rds_master_username" {
  type    = string
  default = "sentinel"
}

variable "rds_master_password" {
  type    = string
  default = ""
}

variable "sentinel_api_key" {
  type    = string
  default = ""
}

variable "sentinel_github_token" {
  type    = string
  default = ""
}

variable "sentinel_slack_webhook" {
  type    = string
  default = ""
}

variable "sentinel_discord_webhook" {
  type    = string
  default = ""
}

variable "sentinel_cors_origins" {
  type    = string
  default = "*"
}

variable "git_repo_url" {
  type    = string
  default = "https://github.com/sentinel-cyber-ai/sentinel.git"
}

variable "git_branch" {
  type    = string
  default = "main"
}

variable "s3_data_bucket" {
  type    = string
  default = ""
}

variable "s3_backups_bucket" {
  type    = string
  default = ""
}
