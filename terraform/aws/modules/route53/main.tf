# =============================================================================
# Sentinel Cyber AI — Route53 DNS Module (Optional)
# Configures DNS records for API and dashboard subdomains
# Requires an existing Route53 hosted zone.
# Budget: ~$0.50/mo per hosted zone
# =============================================================================

data "aws_route53_zone" "main" {
  count = var.enabled ? 1 : 0
  name  = var.zone_name
}

# ── API Record (points to EC2 EIP or CloudFront) ──
resource "aws_route53_record" "api" {
  count   = var.enabled ? 1 : 0
  zone_id = data.aws_route53_zone.main[0].zone_id
  name    = "${var.api_subdomain}.${var.zone_name}"
  type    = "A"

  # Use TTL + records for direct EC2 IP, or alias for CloudFront
  ttl     = var.enable_cloudfront ? null : 300
  records = var.enable_cloudfront ? null : [var.ec2_public_ip]

  dynamic "alias" {
    for_each = var.enable_cloudfront && var.cloudfront_domain != "" ? [1] : []
    content {
      name                   = var.cloudfront_domain
      zone_id                = var.cloudfront_zone_id
      evaluate_target_health = false
    }
  }
}

# ── Dashboard Record ──
resource "aws_route53_record" "dashboard" {
  count   = var.enabled ? 1 : 0
  zone_id = data.aws_route53_zone.main[0].zone_id
  name    = "${var.dashboard_subdomain}.${var.zone_name}"
  type    = "CNAME"
  ttl     = 300
  records = [var.ec2_public_ip]
}

# ── ACM Certificate (for CloudFront HTTPS) ──
resource "aws_acm_certificate" "main" {
  count = var.enabled && var.enable_cloudfront ? 1 : 0

  domain_name       = "${var.api_subdomain}.${var.zone_name}"
  subject_alternative_names = [
    "${var.dashboard_subdomain}.${var.zone_name}",
  ]
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-cert"
  }
}

resource "aws_route53_record" "cert_validation" {
  count   = var.enabled && var.enable_cloudfront ? 1 : 0
  zone_id = data.aws_route53_zone.main[0].zone_id
  name    = tolist(aws_acm_certificate.main[0].domain_validation_options)[0].resource_record_name
  type    = tolist(aws_acm_certificate.main[0].domain_validation_options)[0].resource_record_type
  records = [tolist(aws_acm_certificate.main[0].domain_validation_options)[0].resource_record_value]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "main" {
  count                   = var.enabled && var.enable_cloudfront ? 1 : 0
  certificate_arn         = aws_acm_certificate.main[0].arn
  validation_record_fqdns = [aws_route53_record.cert_validation[0].fqdn]
}

# ── SSM Parameter for DNS info ──
resource "aws_ssm_parameter" "dns_info" {
  count = var.enabled ? 1 : 0
  name  = "/sentinel/${var.environment}/dns"
  type  = "String"
  value = jsonencode({
    api_domain        = "${var.api_subdomain}.${var.zone_name}"
    dashboard_domain  = "${var.dashboard_subdomain}.${var.zone_name}"
    zone_id           = data.aws_route53_zone.main[0].zone_id
    ec2_ip            = var.ec2_public_ip
    cloudfront_domain = var.enable_cloudfront ? var.cloudfront_domain : null
  })
}
