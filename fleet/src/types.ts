export type SsoProtocol = 'oidc' | 'saml2';

export type FleetRole = 'SecurityAdmin' | 'LeadDeveloper' | 'Contributor' | 'Auditor';

export interface SsoUserIdentity {
  sub: string;
  email: string;
  name: string;
  tenantId: string;
  roles: FleetRole[];
  groups: string[];
  protocol: SsoProtocol;
  issuer: string;
  authenticatedAt: string;
}

export interface RitualRulesPolicy {
  promptInjectionGuard: {
    enabled: boolean;
    failClosed: boolean;
    blockPatterns: string[];
    canaryDecoyInjection: boolean;
  };
  databaseShadowMode: {
    enabled: boolean;
    requireProofOfIntent: boolean;
    mutationSandbox: 'virtual_duckdb' | 'isolated_sqlite' | 'read_only_abort';
  };
  egressDomainWhitelist: string[];
  secretEntropyThreshold: number; // e.g. 4.5 bits/char
  allowedAiGateways: string[]; // e.g. ['azure-openai', 'aws-bedrock', 'local-ollama']
  maxTokensPerMinute: number;
}

export interface RitualRulesBundle {
  bundleVersion: string;
  tenantId: string;
  updatedAt: string;
  policy: RitualRulesPolicy;
  policyHashSha256: string;
  signature: string;
  signedBy: string;
}

export interface WorkstationSyncRequest {
  machineId: string;
  hostname: string;
  os: 'windows' | 'linux' | 'macos';
  userToken: string;
  tenantId: string;
  installedRulesHash?: string;
}

export interface WorkstationSyncResponse {
  status: 'synced' | 'updated' | 'unauthorized' | 'revoked';
  bundle?: RitualRulesBundle;
  enforceIntervalSeconds: number;
  message: string;
}

export interface OTelCollectorConfig {
  endpoint: string;
  protocol: 'grpc' | 'http/protobuf';
  headers: Record<string, string>;
  batchSize: number;
  piiRedactionEnabled: boolean;
  destinations: ('datadog' | 'splunk' | 'sentinel' | 'prometheus')[];
}
