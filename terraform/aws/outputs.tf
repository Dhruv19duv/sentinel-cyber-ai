# =============================================================================
# Sentinel Cyber AI — Terraform Outputs
# =============================================================================

output "ec2_public_ip" {
  description = "Public IP address of the Sentinel EC2 instance"
  value       = module.ec2.public_ip
}

output "ec2_public_dns" {
  description = "Public DNS name of the Sentinel EC2 instance"
  value       = module.ec2.public_dns
}

output "ec2_key_name" {
  description = "Name of the SSH key pair for EC2 access"
  value       = module.ec2.key_name
}

output "ssh_command" {
  description = "SSH command to connect to the Sentinel server"
  value       = "ssh -i sentinel-key.pem ubuntu@${module.ec2.public_ip}"
}

output "api_url" {
  description = "Sentinel API URL"
  value       = "http://${module.ec2.public_ip}"
}

output "api_health_url" {
  description = "Sentinel API health check endpoint"
  value       = "http://${module.ec2.public_ip}/health"
}

output "dashboard_url" {
  description = "Sentinel dashboard URL"
  value       = "http://${module.ec2.public_ip}:8500"
}

output "grafana_url" {
  description = "Grafana monitoring dashboard URL"
  value       = module.rds.enabled ? "http://${module.ec2.public_ip}:3000" : "Grafana not available without RDS enabled"
}

output "sentinel_api_key" {
  description = "Sentinel API key for authentication"
  value       = module.ec2.api_key
  sensitive   = true
}

output "rds_connection_string" {
  description = "PostgreSQL connection string (only if RDS enabled)"
  value       = module.rds.enabled ? module.rds.connection_string : null
  sensitive   = true
}

output "s3_buckets" {
  description = "S3 bucket names created for Sentinel"
  value       = module.s3.bucket_names
}

output "deployment_commands" {
  description = "Commands to verify and manage the deployment"
  value = <<-EOT
    # Connect to the server:
    ssh -i sentinel-key.pem ubuntu@${module.ec2.public_ip}

    # Check deployment logs:
    sudo journalctl -u sentinel -f

    # View Docker containers:
    docker ps

    # Check API health:
    curl http://${module.ec2.public_ip}/health

    # View post-deployment status:
    ./scripts/deploy.sh --status
  EOT
}

output "next_steps" {
  description = "Post-deployment next steps"
  value = <<-EOT
  1. Configure DNS: Point your domain to ${module.ec2.public_ip}
  2. Add SSL: Run ./scripts/setup-ssl.sh on the server
  3. Set up backups: Configure ./scripts/backup.sh
  4. Verify API: curl http://${module.ec2.public_ip}/health
  EOT
}
