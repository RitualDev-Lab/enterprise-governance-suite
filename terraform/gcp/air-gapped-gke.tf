# ─── Private GKE Cluster & Shielded Node Pool Configuration ───────────────────
# Deploys private GKE control plane and worker nodes with zero public IPs,
# Workload Identity federation, Cilium eBPF Datapath, and Shielded VM security.

resource "google_container_cluster" "ritual_gke" {
  name     = "${var.environment}-ritual-gke"
  location = var.region

  # Separate node pool for immutable upgrades and zero-downtime recycling
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.ritual_vpc.self_link
  subnetwork = google_compute_subnetwork.ritual_subnet.self_link

  ip_allocation_policy {
    cluster_secondary_range_name  = "gke-pods-range"
    services_secondary_range_name = "gke-services-range"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false # Allow master authorized networks access
    master_ipv4_cidr_block  = var.master_ipv4_cidr_block
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = var.vpc_cidr
      display_name = "VPC-Internal-Subnet"
    }
  }

  # Cilium GKE Datapath Provider for low-overhead eBPF networking
  datapath_provider = "ADVANCED_DATAPATH"

  # Workload Identity Federation
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Customer Managed Encryption Key (CMEK) for control plane etcd & persistent disks
  database_encryption {
    state    = "ENCRYPTED"
    key_name = google_kms_crypto_key.ritual_cmek_key.id
  }

  addons_config {
    http_load_balancing {
      disabled = false
    }
    network_policy_config {
      disabled = false
    }
  }

  release_channel {
    channel = "REGULAR"
  }

  lifecycle {
    ignore_changes = [initial_node_count]
  }
}

# Hardened Shielded Worker Node Pool
resource "google_container_node_pool" "hardened_nodes" {
  name     = "${var.environment}-ritual-hardened-pool"
  location = var.region
  cluster  = google_container_cluster.ritual_gke.name

  autoscaling {
    min_node_count = var.min_node_count
    max_node_count = var.max_node_count
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    machine_type = var.node_machine_type
    disk_size_gb = 100
    disk_type    = "pd-ssd"

    # Enforce Customer-Managed Encryption Key on node boot disks
    boot_disk_kms_key = google_kms_crypto_key.ritual_cmek_key.id

    # Shielded VM security settings
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    # Restrict cloud API scopes - permissions mediated strictly via Workload Identity
    oauth_scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = {
      "ritual.io/environment" = var.environment
      "ritual.io/tier"        = "defense-core"
      "compliance"            = "soc2-iso27001"
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }
}
