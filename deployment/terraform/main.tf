locals {
  required_apis = toset([
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "dlp.googleapis.com",
    "cloudtrace.googleapis.com",
    "logging.googleapis.com",
    "sqladmin.googleapis.com",
    "aiplatform.googleapis.com",
  ])
}

resource "google_project_service" "enabled_apis" {
  for_each           = local.required_apis
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# Secret Manager containers (secret payloads are populated out-of-band, never in Terraform state)
resource "google_secret_manager_secret" "gemini_api_key" {
  secret_id = "kubeguard-gemini-api-key"
  replication {
    auto {}
  }
  depends_on = [google_project_service.enabled_apis]
}

resource "google_secret_manager_secret" "api_auth_token" {
  secret_id = "kubeguard-api-auth-token"
  replication {
    auto {}
  }
  depends_on = [google_project_service.enabled_apis]
}

resource "google_secret_manager_secret" "database_dsn" {
  secret_id = "kubeguard-database-dsn"
  replication {
    auto {}
  }
  depends_on = [google_project_service.enabled_apis]
}

# Cloud SQL PostgreSQL 16 for persistent ADK sessions, SRE runbooks, and incident memory
resource "google_sql_database_instance" "kubeguard_db" {
  name                = "${var.service_name}-pg"
  database_version    = "POSTGRES_16"
  region              = var.region
  deletion_protection = true

  settings {
    tier = var.db_tier

    ip_configuration {
      ssl_mode = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }
  }

  depends_on = [google_project_service.enabled_apis]
}

resource "google_sql_database" "sessions" {
  name     = "kubeguard"
  instance = google_sql_database_instance.kubeguard_db.name
}

# Cloud Run v2 service running KubeGuard ADK Go v2 REST & A2A server
resource "google_cloud_run_v2_service" "kubeguard" {
  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.kubeguard_sa.email

    scaling {
      min_instance_count = 1
      max_instance_count = 10
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [google_sql_database_instance.kubeguard_db.connection_name]
      }
    }

    containers {
      image = var.container_image
      args  = ["web", "api", "a2a"]

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      env {
        name  = "KUBEGUARD_ENV"
        value = "production"
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "GOOGLE_CLOUD_LOCATION"
        value = var.region
      }
      env {
        name  = "KUBEGUARD_FAST_MODEL"
        value = "gemini-4-hydrogen"
      }
      env {
        name  = "KUBEGUARD_REASONING_MODEL"
        value = "gemini-4-neon"
      }
      env {
        name  = "KUBEGUARD_ALLOWED_ORIGINS"
        value = var.allowed_origins
      }
      env {
        name  = "GEMINI_API_KEY_SECRET_ID"
        value = google_secret_manager_secret.gemini_api_key.secret_id
      }
      env {
        name  = "API_AUTH_TOKEN_SECRET_ID"
        value = google_secret_manager_secret.api_auth_token.secret_id
      }
      env {
        name  = "DATABASE_DSN_SECRET_ID"
        value = google_secret_manager_secret.database_dsn.secret_id
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "1Gi"
        }
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.gemini_secret_access,
    google_secret_manager_secret_iam_member.auth_secret_access,
    google_secret_manager_secret_iam_member.db_secret_access,
  ]
}
