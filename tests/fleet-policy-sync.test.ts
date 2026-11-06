import { describe, it, expect, beforeEach } from 'vitest';
import { SsoPolicySyncService } from '../fleet/src/sso-policy-sync';
import { OpenTelemetryFleetManager } from '../fleet/src/otel-collector-config';
import type { RitualRulesPolicy, WorkstationSyncRequest } from '../fleet/src/types';

describe('Phase 3.4 Enterprise Fleet Governance Suite', () => {
  let service: SsoPolicySyncService;
  const masterSecret = 'test_enterprise_signing_secret_hmac_256';

  beforeEach(() => {
    service = new SsoPolicySyncService(masterSecret);
  });

  describe('SSO Identity & RBAC Role Enforcement', () => {
    it('parses valid OIDC bearer token and extracts SecurityAdmin role', () => {
      // Craft test OIDC JWT token
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(
        JSON.stringify({
          sub: 'usr_sec_admin_99',
          email: 'ciso@enterprise.corp',
          name: 'Chief Information Security Officer',
          tenantId: 'tenant-acme-corp',
          roles: ['SecurityAdmin', 'InfraSec'],
          iss: 'https://login.microsoftonline.com/acme/v2.0',
        })
      ).toString('base64url');
      const dummySig = 'dummy_crypto_signature';
      const token = `${header}.${payload}.${dummySig}`;

      const identity = service.validateSsoToken(token);
      expect(identity.protocol).toBe('oidc');
      expect(identity.email).toBe('ciso@enterprise.corp');
      expect(identity.tenantId).toBe('tenant-acme-corp');
      expect(identity.roles).toContain('SecurityAdmin');
    });

    it('parses SAML 2.0 XML assertion attributes', () => {
      const samlAssertion = `
        <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
          <saml2:Subject>
            <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">lead-dev@enterprise.corp</saml2:NameID>
          </saml2:Subject>
          <saml2:AttributeStatement>
            <saml2:Attribute Name="Role">
              <saml2:AttributeValue>Contributor</saml2:AttributeValue>
            </saml2:Attribute>
          </saml2:AttributeStatement>
        </saml2:Assertion>
      `;

      const identity = service.validateSsoToken(samlAssertion);
      expect(identity.protocol).toBe('saml2');
      expect(identity.email).toBe('lead-dev@enterprise.corp');
      expect(identity.roles).toContain('Contributor');
    });

    it('rejects malformed SSO tokens', () => {
      expect(() => service.validateSsoToken('invalid-token')).toThrow('Unsupported or malformed SSO token structure');
    });
  });

  describe('Cryptographic .ritualrules Policy Signing & Integrity', () => {
    it('signs policy bundle with deterministic SHA-256 and HMAC-SHA256 signature', () => {
      const policy: RitualRulesPolicy = SsoPolicySyncService.createDefaultEnterprisePolicy();
      const bundle = service.signPolicyBundle('tenant-acme-corp', policy, 'security-admin@acme.corp', '2.1.0');

      expect(bundle.tenantId).toBe('tenant-acme-corp');
      expect(bundle.bundleVersion).toBe('2.1.0');
      expect(bundle.policyHashSha256).toBeDefined();
      expect(bundle.signature).toBeDefined();
      expect(bundle.signedBy).toBe('security-admin@acme.corp');

      // Verify integrity
      const isValid = service.verifyBundleIntegrity(bundle);
      expect(isValid).toBe(true);
    });

    it('detects tampered policy rules and rejects invalid signature', () => {
      const policy: RitualRulesPolicy = SsoPolicySyncService.createDefaultEnterprisePolicy();
      const bundle = service.signPolicyBundle('tenant-acme-corp', policy, 'sec@acme.corp', '1.0.0');

      // Tamper with policy rule after signing
      bundle.policy.promptInjectionGuard.failClosed = false;

      const isValid = service.verifyBundleIntegrity(bundle);
      expect(isValid).toBe(false);
    });
  });

  describe('Workstation Fleet Synchronization', () => {
    it('returns "synced" when workstation already has current policy hash', () => {
      const policy = SsoPolicySyncService.createDefaultEnterprisePolicy();
      const bundle = service.signPolicyBundle('tenant-acme-corp', policy, 'ciso@acme.corp', '1.0.0');

      const simToken = 'sso_sim_dev1_admin';
      const syncReq: WorkstationSyncRequest = {
        machineId: 'win-laptop-7489',
        hostname: 'DEV-LT-7489',
        os: 'windows',
        userToken: simToken,
        tenantId: 'tenant-acme-corp',
        installedRulesHash: bundle.policyHashSha256,
      };

      const response = service.syncWorkstation(syncReq);
      expect(response.status).toBe('synced');
      expect(response.bundle).toBeUndefined();
    });

    it('distributes updated signed bundle when workstation is out of date', () => {
      const policy = SsoPolicySyncService.createDefaultEnterprisePolicy();
      const bundle = service.signPolicyBundle('tenant-acme-corp', policy, 'ciso@acme.corp', '1.1.0');

      const simToken = 'sso_sim_dev2_contributor';
      const syncReq: WorkstationSyncRequest = {
        machineId: 'mac-m3-1234',
        hostname: 'MAC-ENG-1234',
        os: 'macos',
        userToken: simToken,
        tenantId: 'tenant-acme-corp',
        installedRulesHash: 'outdated_old_hash_0000000',
      };

      const response = service.syncWorkstation(syncReq);
      expect(response.status).toBe('updated');
      expect(response.bundle).toBeDefined();
      expect(response.bundle?.bundleVersion).toBe('1.1.0');
    });

    it('rejects unauthenticated workstation requests', () => {
      const syncReq: WorkstationSyncRequest = {
        machineId: 'rogue-pc',
        hostname: 'ROGUE',
        os: 'linux',
        userToken: 'bad_token',
        tenantId: 'tenant-acme-corp',
      };

      const response = service.syncWorkstation(syncReq);
      expect(response.status).toBe('unauthorized');
    });
  });

  describe('OpenTelemetry (OTel) Fleet Telemetry Integration', () => {
    it('generates standard OpenTelemetry collector YAML with PII redaction and SIEM headers', () => {
      const yaml = OpenTelemetryFleetManager.generateCollectorConfigYaml({
        endpoint: 'https://otlp.datadoghq.com:443',
        protocol: 'grpc',
        headers: {
          'DD-API-KEY': 'secret_datadog_key_here',
        },
        batchSize: 500,
        piiRedactionEnabled: true,
        destinations: ['datadog', 'prometheus'],
      });

      expect(yaml).toContain('receivers:');
      expect(yaml).toContain('transform/pii_redact:');
      expect(yaml).toContain('replace_pattern(body');
      expect(yaml).toContain('https://otlp.datadoghq.com:443');
      expect(yaml).toContain('DD-API-KEY');
    });

    it('formats security audit events with standard OTLP attributes and severity numbers', () => {
      const record = OpenTelemetryFleetManager.formatAuditRecord({
        serviceName: 'AgentShield',
        eventType: 'PROMPT_INJECTION_BLOCKED',
        severity: 'CRITICAL',
        userId: 'usr_dev_42',
        tenantId: 'tenant-enterprise-tier',
        details: {
          blockedPattern: 'exfiltrate private key',
          agentId: 'claude-code-subagent-1',
          syscallBlocked: 'ptrace',
        },
      });

      expect(record.severityText).toBe('CRITICAL');
      expect(record.severityNumber).toBe(17);
      expect(record.attributes['service.name']).toBe('AgentShield');
      expect(record.attributes['event.type']).toBe('PROMPT_INJECTION_BLOCKED');
      expect(record.body).toContain('blockedPattern');
    });
  });
});
