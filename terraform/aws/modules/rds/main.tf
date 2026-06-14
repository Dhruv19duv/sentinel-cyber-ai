# =============================================================================
# Sentinel Cyber AI — RDS PostgreSQL Module (Optional)
# Budget: db.t3.micro ~$15/mo (free tier eligible)
# Disabled by default — PostgreSQL runs in Docker on EC2
# =============================================================================

locals {
  db_password = var.master_password != "" ? var.master_password : try(random_password.main[0].result, "")
}

resource "random_password" "main" {
  count  = var.enabled ? 1 : 0
  length = 16
}

resource "aws_db_subnet_group" "main" {
  count      = var.enabled ? 1 : 0
  name       = "${var.project_name}-${var.environment}"
  subnet_ids = var.subnet_ids

  tags = {
    Name = "${var.project_name}-${var.environment}-db-subnet-group"
  }
}

resource "aws_db_instance" "main" {
  count = var.enabled ? 1 : 0

  identifier = "${var.project_name}-${var.environment}-db"

  engine         = "postgres"
  engine_version = "16.3"
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.db_name
  username = var.master_username
  password = local.db_password

  db_subnet_group_name   = aws_db_subnet_group.main[0].name
  vpc_security_group_ids = [var.security_group_id]

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  auto_minor_version_upgrade = true
  copy_tags_to_snapshot      = true
  deletion_protection        = false  # Set to true in production after initial deploy
  skip_final_snapshot        = false
  final_snapshot_identifier  = "${var.project_name}-${var.environment}-final-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"

  performance_insights_enabled          = true
  performance_insights_retention_period = 7

  monitoring_interval = 60
  monitoring_role_arn = var.enabled ? aws_iam_role.rds_monitoring[0].arn : null

  enabled_cloudwatch_logs_exports = ["postgresql"]

  tags = {
    Name = "${var.project_name}-${var.environment}-db"
  }
}

# ── IAM Role for RDS Enhanced Monitoring ──
resource "aws_iam_role" "rds_monitoring" {
  count = var.enabled ? 1 : 0
  name  = "${var.project_name}-${var.environment}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "monitoring.rds.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  count      = var.enabled ? 1 : 0
  role       = aws_iam_role.rds_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# ── SSM Parameter Store for DB credentials ──
resource "aws_ssm_parameter" "db_password" {
  count  = var.enabled ? 1 : 0
  name   = "/sentinel/${var.environment}/db-password"
  type   = "SecureString"
  value  = local.db_password
}

resource "aws_ssm_parameter" "db_connection_string" {
  count  = var.enabled ? 1 : 0
  name   = "/sentinel/${var.environment}/db-connection-string"
  type   = "SecureString"
  value  = "postgresql+asyncpg://${var.master_username}:${urlencode(local.db_password)}@${aws_db_instance.main[0].endpoint}/${var.db_name}"
}
