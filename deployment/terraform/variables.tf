variable "project_id" {
  description = "Google Cloud Project ID hosting KubeGuard."
  type        = string
}

variable "region" {
  description = "Primary Google Cloud region for Cloud Run and Cloud SQL."
  type        = string
  default     = "us-central1"
}

variable "service_name" {
  description = "Cloud Run v2 service name."
  type        = string
  default     = "kubeguard-agent"
}

variable "container_image" {
  description = "Artifact Registry container image digest/URI for KubeGuard."
  type        = string
}

variable "allowed_origins" {
  description = "Comma-separated explicit CORS origin allow-list (never wildcard '*')."
  type        = string
  default     = "https://console.cloud.google.com"
}

variable "db_tier" {
  description = "Cloud SQL PostgreSQL machine tier for persistent ADK session & memory storage."
  type        = string
  default     = "db-custom-1-3840"
}
