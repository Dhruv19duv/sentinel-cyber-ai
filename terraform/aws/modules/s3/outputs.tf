output "data_bucket_name" {
  value = var.create_buckets ? local.data_bucket_name : ""
}

output "outputs_bucket_name" {
  value = var.create_buckets ? local.outputs_bucket_name : ""
}

output "backups_bucket_name" {
  value = var.create_buckets ? local.backups_bucket_name : ""
}

output "bucket_names" {
  value = var.create_buckets ? [
    local.data_bucket_name,
    local.outputs_bucket_name,
    local.backups_bucket_name,
  ] : []
}

output "data_bucket_arn" {
  value = var.create_buckets ? aws_s3_bucket.data[0].arn : ""
}
