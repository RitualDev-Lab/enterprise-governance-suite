output "vpc_network_name" {
  description = "Name of the created air-gapped VPC network"
  value       = google_compute_network.ritual_vpc.name
}

output "subnet_name" {
  description = "Name of the private GKE subnet"
  value       = google_compute_subnetwork.ritual_subnet.name
}

output "gke_cluster_name" {
  description = "Name of the hardened GKE cluster"
  value       = google_container_cluster.ritual_gke.name
}

output "gke_cluster_endpoint" {
  description = "Private control plane endpoint for the GKE cluster"
  value       = google_container_cluster.ritual_gke.endpoint
  sensitive   = true
}

output "gke_ca_certificate" {
  description = "Public CA certificate for authenticating to GKE cluster"
  value       = google_container_cluster.ritual_gke.master_auth[0].cluster_ca_certificate
  sensitive   = true
}

output "cmek_key_id" {
  description = "Resource ID of the Customer-Managed Encryption Key"
  value       = google_kms_crypto_key.ritual_cmek_key.id
}
