# =============================================================================
# Sentinel Cyber AI — S3 Module
# Buckets for data storage, backups, and outputs
# Budget: ~$1-5/mo
# =============================================================================

locals {
  data_bucket_name    = "${var.bucket_name_prefix}-${var.environment}-data"
  outputs_bucket_name = "${var.bucket_name_prefix}-${var.environment}-outputs"
  backups_bucket_name = "${var.bucket_name_prefix}-${var.environment}-backups"
}

# ── Data Storage ──
resource "aws_s3_bucket" "data" {
  count         = var.create_buckets ? 1 : 0
  bucket        = local.data_bucket_name
  force_destroy = true

  tags = {
    Name = local.data_bucket_name
  }
}

resource "aws_s3_bucket_versioning" "data" {
  count  = var.create_buckets && var.enable_versioning ? 1 : 0
  bucket = aws_s3_bucket.data[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  count  = var.create_buckets ? 1 : 0
  bucket = aws_s3_bucket.data[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  count  = var.create_buckets ? 1 : 0
  bucket = aws_s3_bucket.data[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── Outputs ──
resource "aws_s3_bucket" "outputs" {
  count         = var.create_buckets ? 1 : 0
  bucket        = local.outputs_bucket_name
  force_destroy = true

  tags = {
    Name = local.outputs_bucket_name
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "outputs" {
  count  = var.create_buckets ? 1 : 0
  bucket = aws_s3_bucket.outputs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "outputs" {
  count  = var.create_buckets ? 1 : 0
  bucket = aws_s3_bucket.outputs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── Backups ──
resource "aws_s3_bucket" "backups" {
  count         = var.create_buckets ? 1 : 0
  bucket        = local.backups_bucket_name
  force_destroy = false  # Never auto-destroy backup bucket

  tags = {
    Name = local.backups_bucket_name
  }
}

resource "aws_s3_bucket_versioning" "backups" {
  count  = var.create_buckets && var.enable_versioning ? 1 : 0
  bucket = aws_s3_bucket.backups[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  count  = var.create_buckets ? 1 : 0
  bucket = aws_s3_bucket.backups[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "backups" {
  count  = var.create_buckets ? 1 : 0
  bucket = aws_s3_bucket.backups[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  count  = var.create_buckets ? 1 : 0
  bucket = aws_s3_bucket.backups[0].id

  rule {
    id     = "expire-old-backups"
    status = "Enabled"
    filter {
      prefix = ""
    }

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}
