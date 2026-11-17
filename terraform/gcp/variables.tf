variable "project_id" {
  description = "The Google Cloud Project ID to deploy the Ritual Governance VPC and GKE cluster into"
  type        = string
}

variable "region" {
  description = "The GCP region for regional cluster and subnet resources"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Deployment environment (production, staging, or airgap)"
  type        = string
  default     = "production"
}

variable "network_name" {
  description = "Name prefix for the custom air-gapped VPC"
  type        = string
  default     = "ritual-governance-vpc"
}

variable "vpc_cidr" {
  description = "Primary CIDR block for the private GKE subnet"
  type        = string
  default     = "10.240.0.0/20"
}

variable "pods_cidr" {
  description = "Secondary CIDR block for GKE Pod IP allocation"
  type        = string
  default     = "10.241.0.0/16"
}

variable "services_cidr" {
  description = "Secondary CIDR block for GKE ClusterIP Services"
  type        = string
  default     = "10.242.0.0/20"
}

variable "master_ipv4_cidr_block" {
  description = "Internal /28 CIDR block reserved for GKE control plane private endpoint"
  type        = string
  default     = "172.16.0.0/28"
}

variable "air_gapped" {
  description = "Enforces strict air-gapped zero-egress mode: disables Cloud NAT and enforces VPC Service Controls"
  type        = bool
  default     = true
}

variable "node_machine_type" {
  description = "Machine type for the hardened GKE worker nodes"
  type        = string
  default     = "e2-standard-4"
}

variable "min_node_count" {
  description = "Minimum node count per zone for autoscaling"
  type        = number
  default     = 1
}

variable "max_node_count" {
  description = "Maximum node count per zone for autoscaling"
  type        = number
  default     = 5
}
