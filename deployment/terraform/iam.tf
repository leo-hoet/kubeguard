# Dedicated least-privilege Service Account for KubeGuard runtime
resource "google_service_account" "kubeguard_sa" {
  account_id   = "kubeguard-agent-sa"
  display_name = "KubeGuard ADK Agent Runtime Service Account"
}

locals {
  runtime_roles = toset([
    "roles/aiplatform.user",
    "roles/dlp.user",
    "roles/cloudtrace.agent",
    "roles/logging.logWriter",
    "roles/cloudsql.client",
  ])
}

resource "google_project_iam_member" "runtime_least_privilege" {
  for_each = local.runtime_roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.kubeguard_sa.email}"
}

# Per-secret IAM bindings (strictly scoped to KubeGuard secrets, not project-wide)
resource "google_secret_manager_secret_iam_member" "gemini_secret_access" {
  secret_id = google_secret_manager_secret.gemini_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.kubeguard_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "auth_secret_access" {
  secret_id = google_secret_manager_secret.api_auth_token.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.kubeguard_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "db_secret_access" {
  secret_id = google_secret_manager_secret.database_dsn.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.kubeguard_sa.email}"
}
