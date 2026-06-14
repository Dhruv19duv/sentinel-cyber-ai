# =============================================================================
# Sentinel Cyber AI — Terraform AWS Provider Configuration
# Budget-friendly single-EC2 production deployment
# Estimated cost: ~$25-40/mo
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Uncomment and configure for team deployments:
  # backend "s3" {
  #   bucket = "sentinel-terraform-state"
  #   key    = "aws/production/terraform.tfstate"
  #   region = "us-east-1"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "Sentinel-Cyber-AI"
      Environment = var.environment
      ManagedBy   = "Terraform"
      CostCenter  = "sentinel-production"
    }
  }
}
