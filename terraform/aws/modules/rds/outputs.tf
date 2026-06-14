output "enabled" {
  value = var.enabled
}

output "endpoint" {
  value = var.enabled ? one(aws_db_instance.main[*].endpoint) : ""
}

output "address" {
  value = var.enabled ? aws_db_instance.main[0].address : ""
}

output "port" {
  value = var.enabled ? aws_db_instance.main[0].port : 5432
}

output "connection_string" {
  value     = var.enabled ? one(aws_ssm_parameter.db_connection_string[*].value) : ""
  sensitive = true
}

output "db_name" {
  value = var.db_name
}

output "master_username" {
  value = var.master_username
}
