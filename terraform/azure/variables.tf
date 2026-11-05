variable "environment" {
  description = "Deployment environment (e.g. prod, staging, airgap)"
  type        = string
  default     = "prod"
}

variable "location" {
  description = "Azure region for resource deployment"
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Name of the Azure Resource Group"
  type        = string
  default     = "ritual-governance-rg"
}

variable "vnet_cidr" {
  description = "CIDR block for the Ritual Defense Virtual Network"
  type        = string
  default     = "10.100.0.0/16"
}

variable "air_gapped" {
  description = "Enforce strict zero-egress air-gapped configuration (AGENTSHIELD_AIR_GAPPED=1)"
  type        = bool
  default     = true
}

variable "redis_sku" {
  description = "Redis cache SKU (Premium recommended for private endpoints and zone redundancy)"
  type        = string
  default     = "Premium"
}

variable "redis_family" {
  description = "Redis cache family"
  type        = string
  default     = "P"
}

variable "redis_capacity" {
  description = "Redis cache capacity unit"
  type        = number
  default     = 1
}

variable "aks_node_count" {
  description = "Number of worker nodes for the Ritual Agent Governance AKS cluster"
  type        = number
  default     = 3
}

variable "aks_vm_size" {
  description = "Virtual machine SKU for AKS worker nodes"
  type        = string
  default     = "Standard_D4s_v5"
}
