output "domain_name" {
  value = var.enabled ? aws_cloudfront_distribution.api[0].domain_name : ""
}

output "distribution_id" {
  value = var.enabled ? aws_cloudfront_distribution.api[0].id : ""
}

output "hosted_zone_id" {
  value = var.enabled ? aws_cloudfront_distribution.api[0].hosted_zone_id : ""
}
