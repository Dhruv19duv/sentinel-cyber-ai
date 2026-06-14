# =============================================================================
# Sentinel Cyber AI — Terraform Root Module
# Budget-friendly single-EC2 production deployment (~$25-40/mo)
#
# Architecture: Single EC2 with Docker Compose
#   - Runs PostgreSQL, Redis, Nginx, API, Dashboard, Worker all in containers
#   - Optional: S3 for backups, CloudFront for CDN, Route53 for DNS
#   - Optional: RDS for managed PostgreSQL (adds ~$15/mo)
# =============================================================================

module "vpc" {
  source = "./modules/vpc"

  project_name        = var.project_name
  environment         = var.environment
  vpc_cidr            = var.vpc_cidr
  availability_zones  = var.availability_zones
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  ssh_allowed_cidrs    = var.ssh_allowed_cidrs
}

module "s3" {
  source = "./modules/s3"

  project_name      = var.project_name
  environment       = var.environment
  bucket_name_prefix = var.s3_bucket_name_prefix
  enable_versioning = var.enable_s3_versioning
  create_buckets    = var.enable_s3_backups
}

module "rds" {
  source = "./modules/rds"

  project_name         = var.project_name
  environment          = var.environment
  vpc_id               = module.vpc.vpc_id
  subnet_ids           = module.vpc.private_subnet_ids
  security_group_id    = module.vpc.rds_security_group_id
  enabled              = var.enable_rds
  instance_class       = var.rds_instance_class
  allocated_storage    = var.rds_allocated_storage
  db_name              = var.rds_db_name
  master_username      = var.rds_master_username
  master_password      = var.rds_master_password
}

module "ec2" {
  source = "./modules/ec2"

  project_name         = var.project_name
  environment          = var.environment
  vpc_id               = module.vpc.vpc_id
  subnet_id            = module.vpc.public_subnet_ids[0]
  security_group_id    = module.vpc.ec2_security_group_id
  instance_type        = var.ec2_instance_type
  volume_size          = var.ec2_volume_size
  volume_type          = var.ec2_volume_type
  key_name             = var.ec2_key_name
  ssh_allowed_cidrs    = var.ssh_allowed_cidrs
  enable_rds           = var.enable_rds
  rds_endpoint         = module.rds.endpoint
  rds_db_name          = var.rds_db_name
  rds_master_username  = var.rds_master_username
  rds_master_password  = var.rds_master_password
  sentinel_api_key     = var.sentinel_api_key
  sentinel_github_token = var.sentinel_github_token
  sentinel_slack_webhook = var.sentinel_slack_webhook
  sentinel_discord_webhook = var.sentinel_discord_webhook
  sentinel_cors_origins = var.sentinel_cors_origins
  git_repo_url         = var.git_repo_url
  git_branch           = var.git_branch
  s3_data_bucket       = module.s3.data_bucket_name
  s3_backups_bucket    = module.s3.backups_bucket_name
}

module "cloudfront" {
  source = "./modules/cloudfront"

  project_name      = var.project_name
  environment       = var.environment
  enabled           = var.enable_cloudfront
  ec2_public_ip     = module.ec2.public_ip
  api_subdomain     = var.api_subdomain
  dashboard_subdomain = var.dashboard_subdomain
  route53_zone_name = var.route53_zone_name
  enable_route53    = var.enable_route53
}

module "route53" {
  source = "./modules/route53"

  project_name         = var.project_name
  environment          = var.environment
  enabled              = var.enable_route53
  zone_name            = var.route53_zone_name
  ec2_public_ip        = module.ec2.public_ip
  api_subdomain        = var.api_subdomain
  dashboard_subdomain  = var.dashboard_subdomain
  cloudfront_domain    = module.cloudfront.domain_name
  cloudfront_zone_id   = module.cloudfront.hosted_zone_id
  enable_cloudfront    = var.enable_cloudfront
}
