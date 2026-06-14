# =============================================================================
# Sentinel Cyber AI — EC2 Module
# Single EC2 instance with Docker Compose for the full production stack
# Budget: t3.small ~$15-20/mo, Elastic IP ~$3.60/mo
# =============================================================================

locals {
  key_pair_name = var.key_name != "" ? var.key_name : aws_key_pair.generated[0].key_name
}

# ── SSH Key Pair ──
resource "tls_private_key" "main" {
  count = var.key_name == "" ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_key_pair" "generated" {
  count      = var.key_name == "" ? 1 : 0
  key_name   = "${var.project_name}-${var.environment}-key"
  public_key = tls_private_key.main[0].public_key_openssh

  tags = {
    Name = "${var.project_name}-${var.environment}-key"
  }
}

# Save private key locally for SSH access
resource "local_sensitive_file" "ssh_private_key" {
  count           = var.key_name == "" ? 1 : 0
  filename        = "${var.project_name}-key.pem"
  content         = tls_private_key.main[0].private_key_pem
  file_permission = "0600"
}

# ── IAM Role for EC2 ──
resource "aws_iam_role" "sentinel" {
  name = "${var.project_name}-${var.environment}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# ── IAM Policy for S3 and CloudWatch access ──
resource "aws_iam_policy" "sentinel" {
  name = "${var.project_name}-${var.environment}-ec2-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
        ]
        Resource = [
          "arn:aws:s3:::${var.project_name}-*",
          "arn:aws:s3:::${var.project_name}-*/*",
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
        ]
        Resource = ["*"]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "sentinel" {
  role       = aws_iam_role.sentinel.name
  policy_arn = aws_iam_policy.sentinel.arn
}

resource "aws_iam_instance_profile" "sentinel" {
  name = "${var.project_name}-${var.environment}-instance-profile"
  role = aws_iam_role.sentinel.name
}

# ── API Key (random, stored in Secrets Manager) ──
resource "random_password" "api_key" {
  length  = 32
  special = false
}

# ── Ubuntu 24.04 AMI (hardcoded to skip DescribeImages permission) ──
# Latest: ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20260610
# Update this variable when you need a newer AMI
variable "ami_id" {
  description = "Ubuntu 24.04 LTS AMI ID (us-east-1)"
  type        = string
  default     = "ami-0f8a61b66d1accaee"
}

resource "aws_instance" "sentinel" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.security_group_id]
  iam_instance_profile   = aws_iam_instance_profile.sentinel.name
  key_name               = local.key_pair_name

  root_block_device {
    volume_type = var.volume_type
    volume_size = var.volume_size
    encrypted   = true
  }

  # Cloud-init user data
  user_data = templatefile("${path.module}/user-data.sh.tpl", {
    api_key          = random_password.api_key.result
    cors_origins     = var.sentinel_cors_origins
    github_token     = var.sentinel_github_token
    slack_webhook    = var.sentinel_slack_webhook
    discord_webhook  = var.sentinel_discord_webhook
    git_repo_url     = var.git_repo_url
    git_branch       = var.git_branch
    enable_rds       = var.enable_rds
    rds_endpoint     = var.rds_endpoint
    rds_db_name      = var.rds_db_name
    rds_user         = var.rds_master_username
    rds_password     = var.rds_master_password
    s3_data_bucket   = var.s3_data_bucket
    s3_backups_bucket = var.s3_backups_bucket
  })

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"  # IMDSv2
  }

  monitoring = true

  tags = {
    Name = "${var.project_name}-${var.environment}"
  }
}

# ── Elastic IP ──
resource "aws_eip" "main" {
  domain  = "vpc"
  instance = aws_instance.sentinel.id

  tags = {
    Name = "${var.project_name}-${var.environment}-eip"
  }
}

# ── CloudWatch Log Group ──
resource "aws_cloudwatch_log_group" "sentinel" {
  name              = "/sentinel/${var.environment}"
  retention_in_days = 30

  tags = {
    Name = "${var.project_name}-${var.environment}-logs"
  }
}
