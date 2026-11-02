output "vpc_id" {
  description = "The ID of the hardened Ritual VPC"
  value       = aws_vpc.ritual_vpc.id
}

output "eks_cluster_name" {
  description = "The name of the provisioned EKS cluster"
  value       = aws_eks_cluster.ritual.name
}

output "eks_cluster_endpoint" {
  description = "Endpoint URL for Kubernetes control plane"
  value       = aws_eks_cluster.ritual.endpoint
}

output "elasticache_redis_endpoint" {
  description = "Primary Redis cluster configuration endpoint for SkillPrism"
  value       = aws_elasticache_replication_group.skillprism_cache.configuration_endpoint_address
}

output "configure_kubeconfig_cmd" {
  description = "Command to authenticate local kubectl with the new cluster"
  value       = "aws eks --region ${var.aws_region} update-kubeconfig --name ${aws_eks_cluster.ritual.name}"
}
