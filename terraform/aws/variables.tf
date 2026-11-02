variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (e.g. production, staging, sandbox)"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  description = "CIDR block for the hardened private VPC"
  type        = string
  default     = "10.100.0.0/16"
}

variable "redis_node_type" {
  description = "AWS ElastiCache node instance type"
  type        = string
  default     = "cache.m7g.large"
}

variable "redis_auth_token" {
  description = "Strong authentication secret for Redis transit encryption"
  type        = string
  sensitive   = true
}
