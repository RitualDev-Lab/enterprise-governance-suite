# ─── Enterprise Air-Gapped Private VPC & AWS PrivateLink Stack ───────────────
# Zero-Egress VPC Architecture: No Internet Gateway (IGW) or NAT Gateway routes.
# All communications to AWS managed services occur strictly over AWS PrivateLink endpoints.

variable "enable_air_gapped_privatelink" {
  description = "Enables strict zero-egress mode with AWS PrivateLink VPC endpoints"
  type        = bool
  default     = true
}

# 1. Air-Gapped Core Isolated Subnets (No public IP, no default gateway route)
resource "aws_subnet" "airgap_isolated" {
  count             = 2
  vpc_id            = aws_vpc.ritual_vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 8)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name       = "${var.environment}-ritual-airgap-isolated-${count.index + 1}"
    Type       = "AirGapped-ZeroEgress"
    Compliance = "SOC2-CC6.6-PCI-DSS-v4"
  }
}

# 2. Strict Zero-Egress Route Table (VPC Local CIDR Only - Zero 0.0.0.0/0 Routes)
resource "aws_route_table" "airgap_isolated" {
  vpc_id = aws_vpc.ritual_vpc.id

  tags = {
    Name       = "${var.environment}-ritual-airgap-route-table"
    EgressMode = "ZERO_OUTBOUND_EGRESS"
  }
}

resource "aws_route_table_association" "airgap_isolated" {
  count          = 2
  subnet_id      = aws_subnet.airgap_isolated[count.index].id
  route_table_id = aws_route_table.airgap_isolated.id
}

# 3. Security Group for AWS PrivateLink Interface VPC Endpoints
resource "aws_security_group" "privatelink_endpoints" {
  name        = "${var.environment}-ritual-privatelink-sg"
  description = "Controls HTTPS 443 traffic to AWS PrivateLink Interface endpoints"
  vpc_id      = aws_vpc.ritual_vpc.id

  ingress {
    description     = "HTTPS inbound from Ritual agent and proxy pods"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.agent_core.id]
  }

  egress {
    description = "No outbound from interface endpoints"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "${var.environment}-privatelink-endpoints-sg"
  }
}

# 4. AWS PrivateLink Interface Endpoints for Air-Gapped Agent Infrastructure
locals {
  privatelink_services = [
    "ecr.api",
    "ecr.dkr",
    "kms",
    "logs",
    "secretsmanager",
    "sts"
  ]
}

resource "aws_vpc_endpoint" "interface_endpoints" {
  for_each = var.enable_air_gapped_privatelink ? toset(locals.privatelink_services) : []

  vpc_id              = aws_vpc.ritual_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.airgap_isolated[*].id
  security_group_ids  = [aws_security_group.privatelink_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name       = "${var.environment}-ritual-vpce-${each.value}"
    Compliance = "AirGapped-VPC"
  }
}

# 5. AWS S3 Gateway Endpoint (Zero-cost S3 data transport within VPC)
resource "aws_vpc_endpoint" "s3_gateway" {
  count             = var.enable_air_gapped_privatelink ? 1 : 0
  vpc_id            = aws_vpc.ritual_vpc.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.airgap_isolated.id]

  tags = {
    Name = "${var.environment}-ritual-vpce-s3-gateway"
  }
}
