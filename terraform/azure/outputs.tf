output "resource_group_name" {
  description = "The name of the Azure Resource Group"
  value       = azurerm_resource_group.ritual_rg.name
}

output "vnet_id" {
  description = "The ID of the Ritual Defense Virtual Network"
  value       = azurerm_virtual_network.ritual_vnet.id
}

output "aks_cluster_name" {
  description = "The name of the deployed AKS cluster"
  value       = azurerm_kubernetes_cluster.ritual_aks.name
}

output "redis_hostname" {
  description = "The SSL hostname of the SkillPrism Redis cache"
  value       = azurerm_redis_cache.skillprism_redis.ssl_port
}

output "redis_ssl_port" {
  description = "Redis SSL port"
  value       = 6380
}

output "kubeconfig_command" {
  description = "Azure CLI command to retrieve cluster credentials"
  value       = "az aks get-credentials --resource-group ${azurerm_resource_group.ritual_rg.name} --name ${azurerm_kubernetes_cluster.ritual_aks.name}"
}
