terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ─── 1. Hardened Enterprise VPC ──────────────────────────────────────────
resource "aws_vpc" "ritual_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-ritual-agent-governance-vpc"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Compliance  = "SOC2-CC6.6"
  }
}

# ─── 2. Subnets (Public Ingress + Isolated Private Core) ─────────────────
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.ritual_vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.environment}-ritual-public-${count.index + 1}"
    Type = "Public-Ingress"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.ritual_vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 4)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.environment}-ritual-private-isolated-${count.index + 1}"
    Type = "Private-Core"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.ritual_vpc.id
  tags = {
    Name = "${var.environment}-ritual-igw"
  }
}

resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${var.environment}-ritual-nat"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.ritual_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.ritual_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ─── 3. Security Groups & IMDS Metadata Boundary ────────────────────────
resource "aws_security_group" "agent_core" {
  name        = "${var.environment}-ritual-agent-core-sg"
  description = "Hardened security group with metadata isolation for Ritual Governance Core"
  vpc_id      = aws_vpc.ritual_vpc.id

  # Ingress for DBShield Wire Protocol (5433) from VPC
  ingress {
    description = "DBShield PostgreSQL Wire Proxy"
    from_port   = 5433
    to_port     = 5433
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Ingress for SkillPrism Team Hub (8080)
  ingress {
    description = "SkillPrism Shared Hub & Cache"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Ingress for Live Dashboard & SSO (3100)
  ingress {
    description = "DBShield Approval Feed & SSO Portal"
    from_port   = 3100
    to_port     = 3100
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Standard Outbound (Egress Filtering Engine blocks IMDS at pod/kernel layer)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-ritual-core-sg"
  }
}

# ─── 4. ElastiCache Redis Cluster (Multi-AZ for SkillPrism) ──────────────
resource "aws_elasticache_subnet_group" "redis" {
  name       = "${var.environment}-ritual-redis-subnet-group"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_security_group" "redis" {
  name        = "${var.environment}-ritual-redis-sg"
  description = "Allows Redis access from Ritual agent core nodes"
  vpc_id      = aws_vpc.ritual_vpc.id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.agent_core.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_elasticache_replication_group" "skillprism_cache" {
  replication_group_id          = "${var.environment}-skillprism-redis"
  description                   = "High-Availability Redis Cluster for SkillPrism Shared Embedding Cache"
  node_type                     = var.redis_node_type
  port                          = 6379
  parameter_group_name          = "default.redis7"
  subnet_group_name             = aws_elasticache_subnet_group.redis.name
  security_group_ids            = [aws_security_group.redis.id]
  automatic_failover_enabled    = true
  multi_az_enabled              = true
  at_rest_encryption_enabled    = true
  transit_encryption_enabled    = true
  auth_token                    = var.redis_auth_token

  num_node_groups         = 1
  replicas_per_node_group = 1

  tags = {
    Environment = var.environment
    Service     = "SkillPrism-Hub"
  }
}

# ─── 5. AWS EKS Kubernetes Cluster (v1.30) ──────────────────────────────
resource "aws_iam_role" "eks_cluster" {
  name = "${var.environment}-ritual-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_eks_cluster" "ritual" {
  name     = "${var.environment}-ritual-agent-governance"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.30"

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_private_access = true
    endpoint_public_access  = true
    security_group_ids      = [aws_security_group.agent_core.id]
  }

  depends_on = [aws_iam_role_policy_attachment.eks_cluster_policy]
}

# ─── 6. Hardened EKS Managed Node Group with IMDSv2 Metadata Boundary ───
resource "aws_iam_role" "eks_nodes" {
  name = "${var.environment}-ritual-eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "eks_container_registry" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_launch_template" "eks_hardened_nodes" {
  name_prefix   = "${var.environment}-ritual-hardened-node-"
  instance_type = "m7i.xlarge"

  # Enforce IMDSv2 with hop limit 1 to block container SSRF credential exfiltration
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  vpc_security_group_ids = [aws_security_group.agent_core.id]

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "${var.environment}-ritual-governance-worker"
      Compliance  = "SOC2-CC6.1-IMDSv2"
      Environment = var.environment
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_eks_node_group" "governance_workers" {
  cluster_name    = aws_eks_cluster.ritual.name
  node_group_name = "${var.environment}-governance-workers"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = aws_subnet.private[*].id

  launch_template {
    id      = aws_launch_template.eks_hardened_nodes.id
    version = "$Latest"
  }

  scaling_config {
    desired_size = 3
    max_size     = 10
    min_size     = 2
  }

  update_config {
    max_unavailable = 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_container_registry,
  ]

  tags = {
    Environment = var.environment
    Component   = "RitualAgentGovernanceMesh"
  }
}
