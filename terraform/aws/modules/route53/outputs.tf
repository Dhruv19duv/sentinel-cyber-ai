output "api_domain" {
  value = var.enabled ? "${var.api_subdomain}.${var.zone_name}" : ""
}

output "dashboard_domain" {
  value = var.enabled ? "${var.dashboard_subdomain}.${var.zone_name}" : ""
}

output "certificate_arn" {
  value = var.enabled && var.enable_cloudfront ? aws_acm_certificate.main[0].arn : ""
}

output "zone_id" {
  value = var.enabled ? data.aws_route53_zone.main[0].zone_id : ""
}
