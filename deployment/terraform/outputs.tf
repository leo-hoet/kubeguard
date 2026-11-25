output "cloud_run_service_uri" {
  description = "HTTPS endpoint URI of the deployed KubeGuard Cloud Run service."
  value       = google_cloud_run_v2_service.kubeguard.uri
}

output "service_account_email" {
  description = "Least-privilege Google Cloud service account used by KubeGuard."
  value       = google_service_account.kubeguard_sa.email
}

output "cloud_sql_connection_name" {
  description = "Cloud SQL PostgreSQL connection identifier for ADK persistent session storage."
  value       = google_sql_database_instance.kubeguard_db.connection_name
}
