# =============================================================================
# Sentinel Cyber AI — CloudFront CDN Module (Optional)
# Adds ~$5-10/mo. Disabled by default for budget-friendly deployment.
# =============================================================================

resource "aws_cloudfront_origin_access_control" "main" {
  count = var.enabled ? 1 : 0

  name                              = "${var.project_name}-${var.environment}-oac"
  description                       = "OAC for ${var.project_name} ${var.environment}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# ── API Distribution ──
resource "aws_cloudfront_distribution" "api" {
  count = var.enabled ? 1 : 0

  enabled     = true
  price_class = "PriceClass_100"  # US, Canada, Europe only (cheapest)
  http_version = "http2"

  aliases = var.enable_route53 && var.route53_zone_name != "" ? [
    "${var.api_subdomain}.${var.route53_zone_name}",
    "${var.dashboard_subdomain}.${var.route53_zone_name}",
  ] : []

  origin {
    domain_name = var.ec2_public_ip
    origin_id   = "sentinel-api"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "X-Sentinel-Origin"
      value = "cloudfront"
    }
  }

  default_cache_behavior {
    target_origin_id       = "sentinel-api"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    forwarded_values {
      query_string = true
      headers      = ["Authorization", "Content-Type", "Origin", "X-API-Key"]
      cookies {
        forward = "all"
      }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
  }

  ordered_cache_behavior {
    path_pattern           = "/dashboard*"
    target_origin_id       = "sentinel-api"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 60
    max_ttl     = 300
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = var.enable_route53 ? false : true
    acm_certificate_arn            = var.enable_route53 ? var.acm_certificate_arn : ""
    ssl_support_method             = var.enable_route53 ? "sni-only" : ""
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-cdn"
  }
}
