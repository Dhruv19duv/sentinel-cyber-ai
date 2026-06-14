terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 6.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.31"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.14"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
  backend "gcs" {
    # Configure in terraform.tfvars:
    # bucket = "sentinel-terraform-state"
    # prefix = "gcp/production"
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# ── VPC Network ──
resource "google_compute_network" "vpc" {
  name                    = "${var.project_name}-${var.environment}-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "private" {
  count = length(var.private_subnet_cidrs)

  name          = "${var.project_name}-${var.environment}-private-${count.index}"
  ip_cidr_range = var.private_subnet_cidrs[count.index]
  region        = var.gcp_region
  network       = google_compute_network.vpc.id

  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "pods-${count.index}"
    ip_cidr_range = var.pods_ip_cidrs[count.index]
  }
  secondary_ip_range {
    range_name    = "services-${count.index}"
    ip_cidr_range = var.services_ip_cidrs[count.index]
  }
}

resource "google_compute_subnetwork" "public" {
  count = length(var.public_subnet_cidrs)

  name          = "${var.project_name}-${var.environment}-public-${count.index}"
  ip_cidr_range = var.public_subnet_cidrs[count.index]
  region        = var.gcp_region
  network       = google_compute_network.vpc.id

  private_ip_google_access = false
}

resource "google_compute_router" "nat" {
  name    = "${var.project_name}-${var.environment}-nat-router"
  network = google_compute_network.vpc.id
  region  = var.gcp_region
}

resource "google_compute_router_nat" "nat" {
  name                               = "${var.project_name}-${var.environment}-nat"
  router                             = google_compute_router.nat.name
  region                             = var.gcp_region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# ── Cloud NAT for private instances ──
resource "google_compute_address" "nat" {
  name   = "${var.project_name}-${var.environment}-nat-ip"
  region = var.gcp_region
}

# ── GKE Cluster ──
resource "google_service_account" "gke" {
  account_id   = "${var.project_name}-${var.environment}-gke"
  display_name = "Sentinel GKE Service Account"
}

resource "google_project_iam_member" "gke_logging" {
  project = var.gcp_project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gke.email}"
}

resource "google_project_iam_member" "gke_monitoring" {
  project = var.gcp_project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gke.email}"
}

resource "google_project_iam_member" "gke_metrics" {
  project = var.gcp_project_id
  role    = "roles/monitoring.viewer"
  member  = "serviceAccount:${google_service_account.gke.email}"
}

resource "google_container_cluster" "primary" {
  name     = "${var.project_name}-${var.environment}"
  location = var.gcp_region

  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.vpc.id
  subnetwork = google_compute_subnetwork.private[0].id

  networking_mode = "VPC_NATIVE"

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods-0"
    services_secondary_range_name = "services-0"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = var.environment == "production"
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  master_authorized_networks_config {
    dynamic "cidr_blocks" {
      for_each = var.admin_access_cidrs
      content {
        cidr_block   = cidr_blocks.value
        display_name = "admin-${cidr_blocks.key}"
      }
    }
  }

  addons_config {
    horizontal_pod_autoscaling {
      disabled = false
    }
    http_load_balancing {
      disabled = false
    }
    network_policy_config {
      disabled = false
    }
  }

  workload_identity_config {
    workload_pool = "${var.gcp_project_id}.svc.id.goog"
  }

  release_channel {
    channel = "REGULAR"
  }

  maintenance_policy {
    recurring_window {
      start_time = "2024-01-01T04:00:00Z"
      end_time   = "2024-01-01T05:00:00Z"
      recurrence = "FREQ=WEEKLY;BYDAY=MON,SUN"
    }
  }
}

resource "google_container_node_pool" "primary_nodes" {
  name     = "${var.project_name}-${var.environment}-nodes"
  location = var.gcp_region
  cluster  = google_container_cluster.primary.name

  initial_node_count = var.node_min_size
  autoscaling {
    min_node_count = var.node_min_size
    max_node_count = var.node_max_size
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    machine_type = var.node_machine_type
    disk_size_gb = 100
    disk_type    = "pd-ssd"
    image_type   = "COS_CONTAINERD"

    service_account = google_service_account.gke.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = {
      "app" = var.project_name
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }
}

# ── CloudSQL PostgreSQL ──
resource "random_password" "cloudsql_password" {
  length  = 32
  special = false
}

resource "google_service_account" "cloudsql" {
  account_id   = "${var.project_name}-${var.environment}-db"
  display_name = "Sentinel CloudSQL Service Account"
}

resource "google_sql_database_instance" "postgres" {
  name             = "${var.project_name}-${var.environment}-db"
  database_version = "POSTGRES_16"
  region           = var.gcp_region

  settings {
    tier              = var.cloudsql_tier
    disk_type         = "PD_SSD"
    disk_size         = var.cloudsql_disk_size
    disk_autoresize   = true
    disk_autoresize_limit = 500

    availability_type = var.environment == "production" ? "REGIONAL" : "ZONAL"

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = var.environment == "production" ? 30 : 7
      }
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
      require_ssl     = true
    }

    database_flags {
      name  = "shared_buffers"
      value = "1GB"
    }
    database_flags {
      name  = "effective_cache_size"
      value = "3GB"
    }
    database_flags {
      name  = "work_mem"
      value = "64MB"
    }
    database_flags {
      name  = "log_min_duration_statement"
      value = "1000"
    }

    insights_config {
      query_insights_enabled  = true
      record_client_address   = true
      query_string_length     = 4500
    }

    deletion_protection = var.environment == "production"
  }

  depends_on = [google_service_account.cloudsql]
}

resource "google_sql_database" "sentinel" {
  name     = "sentinel"
  instance = google_sql_database_instance.postgres.name
}

resource "google_sql_user" "sentinel" {
  name     = "sentinel"
  instance = google_sql_database_instance.postgres.name
  password = random_password.cloudsql_password.result
}

# ── Memorystore Redis ──
resource "google_redis_instance" "cache" {
  name           = "${var.project_name}-${var.environment}-redis"
  tier           = var.environment == "production" ? "STANDARD_HA" : "BASIC"
  memory_size_gb = var.redis_memory_size_gb
  region         = var.gcp_region

  location_id             = var.gcp_zone
  alternative_location_id = var.environment == "production" ? var.gcp_zone_alt : null

  redis_version  = "REDIS_7_2"
  display_name   = "Sentinel Redis Cache"
  connect_mode   = "PRIVATE_SERVICE_ACCESS"
  authorized_network = google_compute_network.vpc.id

  persistence_config {
    persistence_mode = var.environment == "production" ? "RDB" : "DISABLED"
    rdb_snapshot_period = "ONE_HOUR"
  }

  maintenance_policy {
    weekly_maintenance_window {
      day         = "MONDAY"
      start_time  = "04:00"
    }
  }
}

# ── Cloud CDN ──
resource "google_compute_backend_bucket" "dashboard_assets" {
  name        = "${var.project_name}-${var.environment}-dashboard-assets"
  description = "Dashboard static assets"
  bucket_name = google_storage_bucket.dashboard_assets.name
  enable_cdn  = true
}

resource "google_storage_bucket" "dashboard_assets" {
  name          = "${var.project_name}-${var.environment}-dashboard-assets"
  location      = var.gcp_region
  storage_class = "STANDARD"
  force_destroy = var.environment != "production"

  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.dashboard_assets.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# ── Artifact Registry ──
resource "google_artifact_registry_repository" "sentinel" {
  location      = var.gcp_region
  repository_id = "${var.project_name}-${var.environment}"
  format        = "DOCKER"
  description   = "Sentinel Docker images"

  cleanup_policy_dry_run = false
}

# ── GCS Bucket for Data ──
resource "google_storage_bucket" "sentinel_data" {
  name          = "${var.project_name}-${var.environment}-data"
  location      = var.gcp_region
  storage_class = "STANDARD"
  force_destroy = var.environment != "production"

  versioning {
    enabled = var.environment == "production"
  }

  encryption {
    default_kms_key_name = var.kms_key_name
  }
}

# ── IAM for Workload Identity ──
resource "google_service_account" "sentinel_workload" {
  account_id   = "${var.project_name}-${var.environment}-workload"
  display_name = "Sentinel Workload Identity"
}

resource "google_project_iam_member" "workload_secret_accessor" {
  project = var.gcp_project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.sentinel_workload.email}"
}

resource "google_project_iam_member" "workload_artifact_reader" {
  project = var.gcp_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.sentinel_workload.email}"
}

# ── Helm Deployment ──
data "google_client_config" "default" {}

provider "kubernetes" {
  host                   = "https://${google_container_cluster.primary.endpoint}"
  cluster_ca_certificate = base64decode(google_container_cluster.primary.master_auth[0].cluster_ca_certificate)
  token                  = data.google_client_config.default.access_token
}

provider "helm" {
  kubernetes {
    host                   = "https://${google_container_cluster.primary.endpoint}"
    cluster_ca_certificate = base64decode(google_container_cluster.primary.master_auth[0].cluster_ca_certificate)
    token                  = data.google_client_config.default.access_token
  }
}

resource "helm_release" "sentinel" {
  name       = "sentinel"
  chart      = "../../helm/sentinel"
  namespace  = "sentinel"
  create_namespace = true
  timeout    = 600

  values = [
    yamlencode({
      image = {
        repository = "${var.gcp_region}-docker.pkg.dev/${var.gcp_project_id}/${google_artifact_registry_repository.sentinel.repository_id}/sentinel"
        tag        = var.sentinel_image_tag
      }
      postgresql = {
        enabled = false
      }
      redis = {
        enabled = false
      }
      api = {
        env = {
          DATABASE_URL = "postgresql+asyncpg://sentinel:${random_password.cloudsql_password.result}@//cloudsql/${google_sql_database_instance.postgres.connection_name}/sentinel"
          REDIS_URL    = "redis://${google_redis_instance.cache.host}:6379"
        }
        secrets = {
          SENTINEL_API_KEY      = var.sentinel_api_key
          GITHUB_TOKEN          = var.github_token
          GITHUB_WEBHOOK_SECRET = var.github_webhook_secret
          SLACK_BOT_TOKEN       = var.slack_bot_token
          SLACK_WEBHOOK_URL     = var.slack_webhook_url
          DISCORD_BOT_TOKEN     = var.discord_bot_token
          DISCORD_WEBHOOK_URL   = var.discord_webhook_url
        }
      }
      ingress = {
        enabled = true
        hosts = [
          { host = var.api_domain, paths = [{ path = "/", pathType = "Prefix", service = "api" }] },
          { host = var.dashboard_domain, paths = [{ path = "/", pathType = "Prefix", service = "dashboard" }] },
        ]
        tls = [{
          secretName = "sentinel-tls"
          hosts      = [var.api_domain, var.dashboard_domain]
        }]
      }
    })
  ]
}
