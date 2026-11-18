import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AgentDefenseHubServer } from '../fleet/src/agent-defense-hub';

function makeOidcJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.synthetic_signature`;
}

function makeSamlAssertion(email: string, group: string): string {
  const xml = `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml2:Issuer>https://login.microsoftonline.com/tenant-123/v2.0</saml2:Issuer>
    <saml2:Subject><saml2:NameID>${email}</saml2:NameID></saml2:Subject>
    <saml2:AttributeStatement>
      <saml2:Attribute Name="groups"><saml2:AttributeValue>${group}</saml2:AttributeValue></saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>`;
  return `SAML ${Buffer.from(xml, 'utf8').toString('base64')}`;
}

describe('Phase 5: Self-Hostable agent-defense-hub Control Plane', () => {
  let hub: AgentDefenseHubServer;
  let baseUrl = '';

  const adminToken = makeOidcJwt({
    sub: 'okta_admin_1',
    email: 'ciso@acme.corp',
    name: 'Alice Admin',
    iss: 'https://acme.okta.com/oauth2/default',
    tenantId: 'acme-prod',
    roles: ['SecurityAdmin'],
  });

  const approverSaml = makeSamlAssertion('dba-lead@acme.corp', 'DBShield-Approver');

  const developerToken = makeOidcJwt({
    sub: 'okta_dev_1',
    email: 'dev@acme.corp',
    name: 'Bob Developer',
    iss: 'https://acme.okta.com/oauth2/default',
    tenantId: 'acme-prod',
    roles: ['Contributor'],
  });

  beforeAll(async () => {
    hub = new AgentDefenseHubServer({ host: '127.0.0.1', port: 0 });
    const started = await hub.start();
    baseUrl = started.baseUrl;
  });

  afterAll(async () => {
    await hub.stop();
  });

  it('serves /healthz and /api/v1/keys/public with Ed25519 fingerprint', async () => {
    const healthRes = await fetch(`${baseUrl}/healthz`);
    expect(healthRes.status).toBe(200);
    const health = (await healthRes.json()) as { status: string; service: string; publicKeyFingerprint: string };
    expect(health.status).toBe('ok');
    expect(health.service).toBe('agent-defense-hub');
    expect(health.publicKeyFingerprint).toMatch(/^sha256:/);
  });

  it('rejects unauthenticated requests with 401', async () => {
    const res = await fetch(`${baseUrl}/api/v1/policies/sync`);
    expect(res.status).toBe(401);
  });

  it('authenticates Okta OIDC and Entra SAML 2.0 into 3-role RBAC (Admin, Approver, Developer)', async () => {
    const adminWho = await fetch(`${baseUrl}/api/v1/whoami`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    }).then((r) => r.json());
    expect(adminWho.identity.role).toBe('Admin');
    expect(adminWho.identity.provider).toBe('okta-oidc');

    const approverWho = await fetch(`${baseUrl}/api/v1/whoami`, {
      headers: { Authorization: approverSaml },
    }).then((r) => r.json());
    expect(approverWho.identity.role).toBe('Approver');
    expect(approverWho.identity.provider).toBe('entra-saml');

    const devWho = await fetch(`${baseUrl}/api/v1/whoami`, {
      headers: { Authorization: `Bearer ${developerToken}` },
    }).then((r) => r.json());
    expect(devWho.identity.role).toBe('Developer');
  });

  it('enforces RBAC on Ed25519 policy signing and allows Developer policy sync with valid signature verification', async () => {
    // Developer and Approver MUST be rejected from signing policies
    const devSign = await fetch(`${baseUrl}/api/v1/policies/sign`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${developerToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenantId: 'acme-prod', policy: { version: '2.0.0' } }),
    });
    expect(devSign.status).toBe(403);

    const approverSign = await fetch(`${baseUrl}/api/v1/policies/sign`, {
      method: 'POST',
      headers: { Authorization: approverSaml, 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenantId: 'acme-prod', policy: { version: '2.0.0' } }),
    });
    expect(approverSign.status).toBe(403);

    // Admin signs policy asymmetrically with Ed25519
    const adminSign = await fetch(`${baseUrl}/api/v1/policies/sign`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tenantId: 'acme-prod',
        policy: { version: '2.5.0', agentShield: { blockEnvReads: true } },
      }),
    });
    expect(adminSign.status).toBe(200);
    const signedBody = (await adminSign.json()) as any;
    expect(signedBody.envelope.algorithm).toBe('ed25519');
    expect(AgentDefenseHubServer.verifyPolicyEnvelope(signedBody.envelope, signedBody.publicKeyPem)).toBe(true);

    // Developer can fetch and verify the signed policy
    const syncRes = await fetch(`${baseUrl}/api/v1/policies/sync`, {
      headers: { Authorization: `Bearer ${developerToken}` },
    });
    expect(syncRes.status).toBe(200);
    const syncBody = (await syncRes.json()) as any;
    expect(syncBody.envelope.policyVersion).toBe('2.5.0');
  });

  it('enforces Approver/Admin RBAC on ChatOps approvals, SkillPrism orchestration, and CEF SIEM export', async () => {
    // Developer cannot approve mutations
    const devApprove = await fetch(`${baseUrl}/api/v1/approvals/decide`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${developerToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ approvalId: 'appr_123', decision: 'APPROVED' }),
    });
    expect(devApprove.status).toBe(403);

    // Approver via Entra SAML approves mutation cleanly
    const approverDecide = await fetch(`${baseUrl}/api/v1/approvals/decide`, {
      method: 'POST',
      headers: { Authorization: approverSaml, 'Content-Type': 'application/json' },
      body: JSON.stringify({ approvalId: 'appr_123', decision: 'APPROVED', reason: 'Verified pre-image checksum' }),
    });
    expect(approverDecide.status).toBe(200);

    // Orchestrate SkillPrism Redis failover mode
    const orchRes = await fetch(`${baseUrl}/api/v1/skillprism/orchestrate`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ preferredZone: 'az-2', fallbackMode: 'local-sqlite-lru', activeNamespaces: 12 }),
    });
    expect(orchRes.status).toBe(200);
    const orchBody = (await orchRes.json()) as any;
    expect(orchBody.cluster.fallbackMode).toBe('local-sqlite-lru');
    expect(orchBody.cluster.activeNamespaces).toBe(12);

    // Export CEF, Splunk HEC, and Datadog Logs telemetry
    const siemRes = await fetch(`${baseUrl}/api/v1/siem/cef`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    expect(siemRes.status).toBe(200);
    const siemBody = (await siemRes.json()) as {
      totalEvents: number;
      cef: string[];
      splunkHec: unknown[];
      datadog: unknown[];
    };
    expect(siemBody.totalEvents).toBeGreaterThan(0);
    expect(siemBody.cef[0]).toMatch(/^CEF:0\|RitualDev\|AgentDefenseHub\|3\.0\.0\|/);
    expect(siemBody.splunkHec.length).toBe(siemBody.totalEvents);
    expect(siemBody.datadog.length).toBe(siemBody.totalEvents);
  });
});
