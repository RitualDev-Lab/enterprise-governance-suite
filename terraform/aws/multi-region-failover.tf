# ─── Multi-Region High-Availability & 99.99% SLA Disaster Recovery ─────
# Provides Route 53 DNS failover, latency routing, and active-active DynamoDB
# global replication across Primary (us-east-1) and Secondary (eu-central-1) regions.

variable "secondary_aws_region" {
  description = "Disaster recovery failover region for 99.99% SLA"
  type        = string
  default     = "eu-central-1"
}

variable "governance_domain_name" {
  description = "Fully qualified enterprise governance API domain name"
  type        = string
  default     = "fleet.ritualdev.in"
}

# ─── 1. Route 53 Health Checks (< 30s Detection Window) ────────────────
resource "aws_route53_health_check" "primary_fleet_health" {
  fqdn              = "primary-${var.governance_domain_name}"
  port              = 443
  type              = "HTTPS"
  resource_path     = "/v1/health"
  failure_threshold = 3
  request_interval  = 10 # Fast 10-second interval for < 60s failover SLA
  measure_latency   = true
  enable_sni        = true

  tags = {
    Name        = "${var.environment}-primary-health-check"
    Environment = var.environment
    SLA         = "P1-Critical-Sub60m"
  }
}

resource "aws_route53_health_check" "secondary_fleet_health" {
  fqdn              = "secondary-${var.governance_domain_name}"
  port              = 443
  type              = "HTTPS"
  resource_path     = "/v1/health"
  failure_threshold = 3
  request_interval  = 10
  measure_latency   = true
  enable_sni        = true

  tags = {
    Name        = "${var.environment}-secondary-health-check"
    Environment = var.environment
    SLA         = "P1-Critical-Sub60m"
  }
}

# ─── 2. Route 53 DNS Active-Passive / Latency Failover Routing ────────
resource "aws_route53_zone" "primary_zone" {
  name = var.governance_domain_name

  tags = {
    Environment = var.environment
    Compliance  = "SOC2-CC6.6"
  }
}

resource "aws_route53_record" "fleet_dns_primary" {
  zone_id = aws_route53_zone.primary_zone.zone_id
  name    = var.governance_domain_name
  type    = "A"
  ttl     = 30

  failover_routing_policy {
    type = "PRIMARY"
  }

  set_identifier = "primary-region"
  records        = ["10.100.1.10"] # In real deployment, points to primary NLB/ALB IP
  health_check_id = aws_route53_health_check.primary_fleet_health.id
}

resource "aws_route53_record" "fleet_dns_secondary" {
  zone_id = aws_route53_zone.primary_zone.zone_id
  name    = var.governance_domain_name
  type    = "A"
  ttl     = 30

  failover_routing_policy {
    type = "SECONDARY"
  }

  set_identifier = "secondary-region"
  records        = ["10.200.1.10"] # In real deployment, points to secondary NLB/ALB IP
  health_check_id = aws_route53_health_check.secondary_fleet_health.id
}

# ─── 3. DynamoDB Global Table (Cross-Region Audit Ledger Replication) ──
resource "aws_dynamodb_table" "audit_ledger_global" {
  name             = "${var.environment}-audit-ledger-global"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "pk"
  range_key        = "sk"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  replica {
    region_name = var.secondary_aws_region
  }

  tags = {
    Name        = "${var.environment}-audit-ledger-global"
    Compliance  = "SOC2-CC7.2-ISO27001-8.16"
    Environment = var.environment
  }
}

# ─── 4. P1 Incident Automated CloudWatch Alarms ────────────────────────
resource "aws_cloudwatch_metric_alarm" "primary_region_outage_alarm" {
  alarm_name          = "${var.environment}-p1-primary-region-outage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HealthCheckStatus"
  namespace           = "AWS/Route53"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "P1 Outage: Primary region health check failed for 2 consecutive minutes. Automated failover initiated."

  dimensions = {
    HealthCheckId = aws_route53_health_check.primary_fleet_health.id
  }

  tags = {
    Severity = "P1_CRITICAL"
    SLA      = "Sub60m-Response"
  }
}
