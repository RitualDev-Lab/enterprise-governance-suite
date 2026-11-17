terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.20"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ─── 1. Custom Air-Gapped VPC Network ──────────────────────────────────────────
# Auto-create subnetworks disabled to guarantee deterministic CIDR scoping
resource "google_compute_network" "ritual_vpc" {
  name                    = "${var.environment}-${var.network_name}"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "Air-gapped private VPC for Ritual Agent Governance Suite"
}

# ─── 2. Private Subnet with Secondary Pod/Service Ranges & Private Google Access
resource "google_compute_subnetwork" "ritual_subnet" {
  name                     = "${var.environment}-ritual-gke-subnet"
  ip_cidr_range            = var.vpc_cidr
  region                   = var.region
  network                  = google_compute_network.ritual_vpc.id
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "gke-pods-range"
    ip_cidr_range = var.pods_cidr
  }

  secondary_ip_range {
    range_name    = "gke-services-range"
    ip_cidr_range = var.services_cidr
  }
}

# ─── 3. Cloud KMS Key Ring & CMEK Disk Encryption Key ─────────────────────────
resource "google_kms_key_ring" "ritual_keyring" {
  name     = "${var.environment}-ritual-keyring"
  location = var.region
}

resource "google_kms_crypto_key" "ritual_cmek_key" {
  name            = "${var.environment}-cmek-gke"
  key_ring        = google_kms_key_ring.ritual_keyring.id
  rotation_period = "7776000s" # 90 days

  lifecycle {
    prevent_destroy = false
  }
}

# ─── 4. Strict Zero-Egress Firewall Rules ─────────────────────────────────────
# Allow internal VPC communications only
resource "google_compute_firewall" "allow_internal" {
  name    = "${var.environment}-allow-internal-vpc"
  network = google_compute_network.ritual_vpc.name

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  source_ranges = [var.vpc_cidr, var.pods_cidr, var.services_cidr]
}

# Explicitly drop all outbound egress when air-gapped mode is active
resource "google_compute_firewall" "deny_egress_internet" {
  count     = var.air_gapped ? 1 : 0
  name      = "${var.environment}-deny-all-internet-egress"
  network   = google_compute_network.ritual_vpc.name
  direction = "EGRESS"
  priority  = 65534

  deny {
    protocol = "all"
  }

  destination_ranges = ["0.0.0.0/0"]
}

# Explicitly block IMDS (169.254.169.254) from worker nodes and pods
resource "google_compute_firewall" "block_imds_egress" {
  name      = "${var.environment}-block-imds-egress"
  network   = google_compute_network.ritual_vpc.name
  direction = "EGRESS"
  priority  = 1000

  deny {
    protocol = "all"
  }

  destination_ranges = ["169.254.169.254/32"]
}
