import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

describe('Phase 3: Consolidated Helm Charts & Multi-Cloud Infrastructure', () => {
  const rootDir = path.resolve(__dirname, '..');

  it('validates consolidated Helm charts (agentshield, poly-cloud-api, ritual-agent-governance)', () => {
    const umbrellaChartPath = path.join(rootDir, 'helm', 'ritual-agent-governance', 'Chart.yaml');
    expect(fs.existsSync(umbrellaChartPath)).toBe(true);
    const umbrellaChart = fs.readFileSync(umbrellaChartPath, 'utf8');
    expect(umbrellaChart).toContain('name: ritual-agent-governance');
    expect(umbrellaChart).toContain('name: agentshield');
    expect(umbrellaChart).toContain('name: poly-cloud-api');

    const agentshieldChartPath = path.join(rootDir, 'helm', 'agentshield', 'Chart.yaml');
    expect(fs.existsSync(agentshieldChartPath)).toBe(true);
    const agentshieldValues = fs.readFileSync(path.join(rootDir, 'helm', 'agentshield', 'values.yaml'), 'utf8');
    expect(agentshieldValues).toContain('agentshield');

    const polyChartPath = path.join(rootDir, 'helm', 'poly-cloud-api', 'Chart.yaml');
    expect(fs.existsSync(polyChartPath)).toBe(true);
    const polyValues = fs.readFileSync(path.join(rootDir, 'helm', 'poly-cloud-api', 'values.yaml'), 'utf8');
    expect(polyValues).toContain('poly-cloud-api');
    expect(polyValues).toContain('storageBackend:');
    expect(polyValues).toContain('oidc:');
  });

  it('validates umbrella values.yaml exposes unified multi-engine configurations', () => {
    const umbrellaValuesPath = path.join(rootDir, 'helm', 'ritual-agent-governance', 'values.yaml');
    const valuesContent = fs.readFileSync(umbrellaValuesPath, 'utf8');

    expect(valuesContent).toContain('dbshield:');
    expect(valuesContent).toContain('agentshield:');
    expect(valuesContent).toContain('skillprism:');
    expect(valuesContent).toContain('polyCloudApi:');
    expect(valuesContent).toContain('/api/cache');
  });

  it('validates AWS turnkey air-gapped Terraform module', () => {
    const awsVpcPath = path.join(rootDir, 'terraform', 'aws', 'air-gapped-vpc.tf');
    expect(fs.existsSync(awsVpcPath)).toBe(true);
    const awsContent = fs.readFileSync(awsVpcPath, 'utf8');

    expect(awsContent).toContain('aws_route_table');
    expect(awsContent).toContain('ZERO_OUTBOUND_EGRESS');
    expect(awsContent).toContain('privatelink');
  });

  it('validates Azure turnkey Private VNet & AKS Terraform module', () => {
    const azureMainPath = path.join(rootDir, 'terraform', 'azure', 'main.tf');
    expect(fs.existsSync(azureMainPath)).toBe(true);
    const azureContent = fs.readFileSync(azureMainPath, 'utf8');

    expect(azureContent).toContain('azurerm_virtual_network');
    expect(azureContent).toContain('SOC2-CC6.6');
  });

  it('validates Google Cloud (GCP) turnkey air-gapped GKE & VPC module', () => {
    const gcpMainPath = path.join(rootDir, 'terraform', 'gcp', 'main.tf');
    const gcpGkePath = path.join(rootDir, 'terraform', 'gcp', 'air-gapped-gke.tf');
    const gcpVarsPath = path.join(rootDir, 'terraform', 'gcp', 'variables.tf');

    expect(fs.existsSync(gcpMainPath)).toBe(true);
    expect(fs.existsSync(gcpGkePath)).toBe(true);
    expect(fs.existsSync(gcpVarsPath)).toBe(true);

    const mainContent = fs.readFileSync(gcpMainPath, 'utf8');
    const gkeContent = fs.readFileSync(gcpGkePath, 'utf8');

    // Enforce IMDS block rule
    expect(mainContent).toContain('169.254.169.254/32');
    expect(mainContent).toContain('deny_egress_internet');

    // Enforce GKE private cluster and Workload Identity
    expect(gkeContent).toContain('enable_private_nodes    = true');
    expect(gkeContent).toContain('workload_identity_config');
    expect(gkeContent).toContain('boot_disk_kms_key');
    expect(gkeContent).toContain('ADVANCED_DATAPATH');
  });
});
