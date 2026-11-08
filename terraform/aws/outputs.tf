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

output "airgap_isolated_subnet_ids" {
  description = "IDs of the air-gapped zero-egress isolated subnets"
  value       = aws_subnet.airgap_isolated[*].id
}

output "privatelink_endpoint_dns" {
  description = "DNS entries for AWS PrivateLink VPC interface endpoints"
  value = {
    for k, v in aws_vpc_endpoint.interface_endpoints : k => v.dns_entry[0].dns_name
  }
}

