terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }
}

provider "azurerm" {
  features {}
}

# ─── 1. Resource Group ──────────────────────────────────────────────────
resource "azurerm_resource_group" "ritual_rg" {
  name     = "${var.environment}-${var.resource_group_name}"
  location = var.location

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
    Compliance  = "SOC2-CC6.6"
    AirGapped   = var.air_gapped ? "true" : "false"
  }
}

# ─── 2. Virtual Network & Subnets ─────────────────────────────────────────
resource "azurerm_virtual_network" "ritual_vnet" {
  name                = "${var.environment}-ritual-defense-vnet"
  address_space       = [var.vnet_cidr]
  location            = azurerm_resource_group.ritual_rg.location
  resource_group_name = azurerm_resource_group.ritual_rg.name

  tags = {
    Environment = var.environment
    Tier        = "Defense-Fabric"
  }
}

# Ingress Subnet
resource "azurerm_subnet" "ingress" {
  name                 = "snet-ingress"
  resource_group_name  = azurerm_resource_group.ritual_rg.name
  virtual_network_name = azurerm_virtual_network.ritual_vnet.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 8, 1)]
}

# Private Governance Core Subnet
resource "azurerm_subnet" "core" {
  name                 = "snet-ritual-core"
  resource_group_name  = azurerm_resource_group.ritual_rg.name
  virtual_network_name = azurerm_virtual_network.ritual_vnet.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 8, 2)]
}

# Redis Private Endpoint Subnet
resource "azurerm_subnet" "redis" {
  name                 = "snet-redis-cache"
  resource_group_name  = azurerm_resource_group.ritual_rg.name
  virtual_network_name = azurerm_virtual_network.ritual_vnet.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 8, 3)]
}

# AKS Subnet
resource "azurerm_subnet" "aks" {
  name                 = "snet-aks-cluster"
  resource_group_name  = azurerm_resource_group.ritual_rg.name
  virtual_network_name = azurerm_virtual_network.ritual_vnet.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 4, 1)]
}

# ─── 3. Network Security Group (Air-Gapped Ingress/Egress Rules) ────────
resource "azurerm_network_security_group" "core_nsg" {
  name                = "${var.environment}-ritual-core-nsg"
  location            = azurerm_resource_group.ritual_rg.location
  resource_group_name = azurerm_resource_group.ritual_rg.name

  # Allow DBShield Wire Protocol from inside VNet
  security_rule {
    name                       = "AllowDBShieldPostgres"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5433"
    source_address_prefix      = var.vnet_cidr
    destination_address_prefix = "*"
  }

  # Allow SkillPrism Team Hub
  security_rule {
    name                       = "AllowSkillPrismHub"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8080"
    source_address_prefix      = var.vnet_cidr
    destination_address_prefix = "*"
  }

  # Allow SSO & Web Management Dashboard
  security_rule {
    name                       = "AllowSSODashboard"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3100"
    source_address_prefix      = var.vnet_cidr
    destination_address_prefix = "*"
  }

  # Air-Gapped Egress Rule: Deny Azure Instance Metadata Service (IMDS) 169.254.169.254
  security_rule {
    name                       = "DenyAzureIMDS"
    priority                   = 200
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "169.254.169.254/32"
  }

  tags = {
    Environment = var.environment
    Policy      = "AirGappedEnforcement"
  }
}

resource "azurerm_subnet_network_security_group_association" "core_assoc" {
  subnet_id                 = azurerm_subnet.core.id
  network_security_group_id = azurerm_network_security_group.core_nsg.id
}

# ─── 4. Azure Cache for Redis (Clustered VPC Tier for SkillPrism) ───────
resource "azurerm_redis_cache" "skillprism_redis" {
  name                = "${var.environment}-ritual-skillprism-redis"
  location            = azurerm_resource_group.ritual_rg.location
  resource_group_name = azurerm_resource_group.ritual_rg.name
  capacity            = var.redis_capacity
  family              = var.redis_family
  sku_name            = var.redis_sku
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"

  redis_configuration {
    enable_authentication = true
    rdb_backup_enabled    = true
    rdb_backup_frequency  = 60
    rdb_backup_max_snapshot_count = 1
  }

  tags = {
    Environment = var.environment
    Service     = "SkillPrism-Cache"
  }
}

# ─── 5. Azure Kubernetes Service (AKS v1.30 Private Cluster) ─────────────
resource "azurerm_kubernetes_cluster" "ritual_aks" {
  name                = "${var.environment}-ritual-agent-governance-aks"
  location            = azurerm_resource_group.ritual_rg.location
  resource_group_name = azurerm_resource_group.ritual_rg.name
  dns_prefix          = "${var.environment}-ritual-gov"
  kubernetes_version  = "1.30.0"

  private_cluster_enabled = var.air_gapped

  default_node_pool {
    name           = "agentpool"
    node_count     = var.aks_node_count
    vm_size        = var.aks_vm_size
    vnet_subnet_id = azurerm_subnet.aks.id
    os_disk_size_gb = 128
    type           = "VirtualMachineScaleSets"
    node_labels = {
      "ritualdev.in/tier" = "governance-mesh"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    load_balancer_sku = "standard"
  }

  tags = {
    Environment = var.environment
    Component   = "ControlPlane"
  }
}
