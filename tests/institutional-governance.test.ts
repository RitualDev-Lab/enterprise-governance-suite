import { describe, expect, it } from 'vitest';
import { EnterpriseAuditLedger } from '../fleet/src/audit-ledger';
import { SiemForwarderEngine } from '../fleet/src/siem-forwarders';
import { ScimDirectoryService } from '../fleet/src/scim-directory';

describe('Phase 2: Institutional Governance Fabric & Unified Control Plane', () => {
  describe('Tamper-Evident HMAC-SHA256 Audit Ledger', () => {
    it('appends records and creates a valid cryptographic hash chain', () => {
      const ledger = new EnterpriseAuditLedger('test-master-hmac-secret-key');

      const entry1 = ledger.append({
        tenantId: 'acme-corp',
        userId: 'usr_alice_sec',
        service: 'AgentShield',
        action: 'AGENT_SHELL_EXEC_INTERCEPTED',
        severity: 'WARN',
        payload: { command: 'curl http://169.254.169.254/latest/meta-data', decision: 'BLOCKED' },
      });

      const entry2 = ledger.append({
        tenantId: 'acme-corp',
        userId: 'usr_bob_dev',
        service: 'PromptShield',
        action: 'PROMPT_SECRET_REDACTED',
        severity: 'INFO',
        payload: { detectedSecret: 'STRIPE_LIVE_KEY', surrogate: '[PROMPT_SHIELD:STRIPE:a1b2]' },
      });

      expect(entry1.sequence).toBe(0);
      expect(entry2.sequence).toBe(1);
      expect(entry2.previousHash).toBe(entry1.entryHash);

      const verification = ledger.verifyChainIntegrity();
      expect(verification.valid).toBe(true);
      expect(verification.totalEntries).toBe(2);
    });

    it('detects tampering when payload content or previousHash is modified', () => {
      const ledger = new EnterpriseAuditLedger('test-master-hmac-secret-key');

      ledger.append({
        tenantId: 'acme-corp',
        userId: 'usr_dev_1',
        service: 'DBShield',
        action: 'DB_MUTATION_DRYRUN',
        payload: { query: 'DELETE FROM accounts WHERE id = 1', affectedRows: 1 },
      });

      ledger.append({
        tenantId: 'acme-corp',
        userId: 'usr_dev_2',
        service: 'WebSecAuditor',
        action: 'PR_SECURITY_GATE_PASSED',
        payload: { prNumber: 42, findings: 0 },
      });

      // Tamper with entry 0
      const entries = ledger.getEntries() as any[];
      entries[0].payload = { query: 'SELECT 1', affectedRows: 0 }; // modified!

      const verification = ledger.verifyChainIntegrity();
      expect(verification.valid).toBe(false);
      expect(verification.tamperedIndex).toBe(0);
    });

    it('generates a signed audit bundle with valid cryptographic attestation', () => {
      const ledger = new EnterpriseAuditLedger('test-master-hmac-secret-key');
      ledger.append({
        tenantId: 'acme-corp',
        userId: 'usr_lead',
        service: 'FleetPolicy',
        action: 'POLICY_SYNCHRONIZED',
        payload: { version: '2026.11' },
      });

      const bundle = ledger.exportAuditBundle();
      expect(bundle.totalEntries).toBe(1);
      expect(bundle.signature).toBeDefined();
      expect(bundle.rootHash).toBe(bundle.entries[0].entryHash);
    });
  });

  describe('Multi-SIEM Telemetry & Forwarders', () => {
    it('formats Splunk HEC events correctly with unix timestamp and source', () => {
      const forwarder = new SiemForwarderEngine({
        splunk: {
          endpoint: 'https://splunk.corp:8088/services/collector/event',
          token: 'splunk-hec-token-xyz',
          index: 'security_mesh',
        },
      });

      const ledger = new EnterpriseAuditLedger();
      const entry = ledger.append({
        tenantId: 'acme-corp',
        userId: 'usr_dev',
        service: 'AgentShield',
        action: 'EXEC_SANDBOX_CONFINED',
        payload: { pid: 4912, sandbox: 'landlock' },
      });

      const splunkPayload = forwarder.formatSplunkEvent(entry);
      expect(splunkPayload.sourcetype).toBe('_json');
      expect(splunkPayload.index).toBe('security_mesh');
      expect(splunkPayload.event.action).toBe('EXEC_SANDBOX_CONFINED');
      expect(splunkPayload.time).toBeGreaterThan(0);
    });

    it('formats Datadog Logs with correct tagging and service mapping', () => {
      const forwarder = new SiemForwarderEngine({
        datadog: { apiKey: 'dd-api-key-12345', service: 'ritual-governance' },
      });

      const ledger = new EnterpriseAuditLedger();
      const entry = ledger.append({
        tenantId: 'acme-corp',
        userId: 'usr_audit',
        service: 'DBShield',
        action: 'TWO_PHASE_COMMIT_APPROVED',
        severity: 'INFO',
        payload: { transactionId: 'tx_99' },
      });

      const ddLog = forwarder.formatDatadogLog(entry);
      expect(ddLog.service).toBe('ritual-governance');
      expect(ddLog.ddtags).toContain('tenant:acme-corp');
      expect(ddLog.entry_hash).toBe(entry.entryHash);
      expect(ddLog.hmac_signature).toBe(entry.hmacSignature);
    });

    it('generates Microsoft Sentinel / Azure Log Analytics SharedKey signature', () => {
      const forwarder = new SiemForwarderEngine({
        sentinel: {
          workspaceId: '11111111-2222-3333-4444-555555555555',
          sharedKey: Buffer.from('mock-32-byte-azure-secret-shared-key-2026').toString('base64'),
          logType: 'RitualAgentSecurityEvents',
        },
      });

      const ledger = new EnterpriseAuditLedger();
      const entry = ledger.append({
        tenantId: 'acme-corp',
        userId: 'usr_sec',
        service: 'WebSecAuditor',
        action: 'TAINT_FLOW_BLOCKED',
        severity: 'CRITICAL',
        payload: { cwe: 'CWE-89', source: 'req.query.id', sink: 'db.query' },
      });

      const sentinelReq = forwarder.formatSentinelRequest(entry);
      expect(sentinelReq.url).toContain('11111111-2222-3333-4444-555555555555.ods.opinsights.azure.com');
      expect(sentinelReq.headers['Authorization']).toMatch(/^SharedKey 11111111-2222-3333-4444-555555555555:/);
      expect(sentinelReq.headers['Log-Type']).toBe('RitualAgentSecurityEvents');
      expect(sentinelReq.headers['x-ms-date']).toBeDefined();
    });
  });

  describe('RFC 7644 SCIM 2.0 Directory Provisioning', () => {
    it('provisions new enterprise users with SCIM 2.0 schema', () => {
      const scim = new ScimDirectoryService();
      const user = scim.createUser({
        userName: 'diane.prince@enterprise.corp',
        email: 'diane.prince@enterprise.corp',
        givenName: 'Diane',
        familyName: 'Prince',
        role: 'SecurityAdmin',
        tenantId: 'tenant-enterprise-prod',
      });

      expect(user.id).toMatch(/^usr_/);
      expect(user.schemas).toContain('urn:ietf:params:scim:schemas:core:2.0:User');
      expect(user.active).toBe(true);
      expect(user.roles[0].value).toBe('SecurityAdmin');

      // Query by filter
      const search = scim.listUsers('userName eq "diane.prince@enterprise.corp"');
      expect(search.totalResults).toBe(1);
      expect(search.Resources[0].id).toBe(user.id);
    });

    it('handles automated de-provisioning and role mutation (PATCH /Users/{id})', () => {
      const scim = new ScimDirectoryService();
      const user = scim.createUser({
        userName: 'clark.kent@enterprise.corp',
        email: 'clark.kent@enterprise.corp',
        role: 'Contributor',
      });

      // Employee departs enterprise: Okta issues de-provisioning PATCH
      const patched = scim.patchUser(user.id, { active: false });
      expect(patched.active).toBe(false);

      // Verify state in directory
      const retrieved = scim.getUser(user.id);
      expect(retrieved?.active).toBe(false);
    });

    it('provisions SCIM groups and manages member assignments', () => {
      const scim = new ScimDirectoryService();
      const u1 = scim.createUser({ userName: 'u1@corp.com', email: 'u1@corp.com' });
      const u2 = scim.createUser({ userName: 'u2@corp.com', email: 'u2@corp.com' });

      const group = scim.createGroup('AI-Security-Champions', [u1.id]);
      expect(group.members.length).toBe(1);
      expect(group.displayName).toBe('AI-Security-Champions');

      const updatedGroup = scim.addMemberToGroup(group.id, u2.id);
      expect(updatedGroup.members.length).toBe(2);

      const allGroups = scim.listGroups();
      expect(allGroups.totalResults).toBe(1);
    });
  });
});
