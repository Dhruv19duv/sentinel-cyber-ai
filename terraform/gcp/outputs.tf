output "vpc_name" {
  description = "VPC network name"
  value       = google_compute_network.vpc.name
}

output "gke_cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.primary.name
}

output "gke_cluster_endpoint" {
  description = "GKE cluster endpoint URL"
  value       = google_container_cluster.primary.endpoint
  sensitive   = true
}

output "cloudsql_connection_name" {
  description = "CloudSQL instance connection name"
  value       = google_sql_database_instance.postgres.connection_name
  sensitive   = true
}

output "cloudsql_password" {
  description = "CloudSQL PostgreSQL password"
  value       = random_password.cloudsql_password.result
  sensitive   = true
}

output "redis_host" {
  description = "Redis instance host"
  value       = google_redis_instance.cache.host
  sensitive   = true
}

output "redis_port" {
  description = "Redis instance port"
  value       = google_redis_instance.cache.port
}

output "artifact_registry_repo" {
  description = "Artifact Registry repository name"
  value       = google_artifact_registry_repository.sentinel.name
}

output "artifact_registry_location" {
  description = "Artifact Registry repository location"
  value       = google_artifact_registry_repository.sentinel.location
}

output "data_bucket_name" {
  description = "GCS bucket for Sentinel data"
  value       = google_storage_bucket.sentinel_data.name
}

output "workload_identity_service_account" {
  description = "Workload Identity service account email"
  value       = google_service_account.sentinel_workload.email
}

output "workload_identity_namespace" {
  description = "Workload Identity namespace for Kubernetes"
  value       = "${var.gcp_project_id}.svc.id.goog"
}

output "gcloud_get_credentials_command" {
  description = "Command to get GKE credentials for kubectl"
  value       = "gcloud container clusters get-credentials ${google_container_cluster.primary.name} --region ${var.gcp_region} --project ${var.gcp_project_id}"
}

output "database_url" {
  description = "Full database connection URL (for Cloud SQL Proxy)"
  value       = "postgresql+asyncpg://sentinel:${random_password.cloudsql_password.result}@localhost:5432/sentinel?host=/cloudsql/${google_sql_database_instance.postgres.connection_name}"
  sensitive   = true
}
