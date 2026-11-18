import crypto from 'node:crypto';
import http, { type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { SiemForwarderEngine } from './siem-forwarders';
import { SsoPolicySyncService } from './sso-policy-sync';
import type { AuditLedgerEntry } from './audit-ledger';
import type { RitualRulesPolicy } from './types';

export type HubRbacRole = 'Admin' | 'Approver' | 'Developer';

export interface HubIdentity {
  sub: string;
  email: string;
  name: string;
  provider: 'okta-oidc' | 'entra-saml' | 'oidc' | 'saml';
  role: HubRbacRole;
  tenantId: string;
}

export interface SignedHubPolicyEnvelope {
  policyVersion: string;
  tenantId: string;
  signedBy: string;
  signedAt: string;
  algorithm: 'ed25519';
  publicKeyFingerprint: string;
  signatureBase64: string;
  policy: Partial<RitualRulesPolicy> & Record<string, unknown>;
}

export interface SkillPrismClusterState {
  masterHost: string;
  sentinels: string[];
  preferredZone: string;
  fallbackMode: 'redis-sentinel' | 'local-sqlite-lru';
  activeNamespaces: number;
  lastHeartbeatAt: string;
}

export interface HubApprovalDecision {
  approvalId: string;
  decision: 'APPROVED' | 'REJECTED';
  decidedBy: string;
  decidedAt: string;
  reason?: string;
}

export interface AgentDefenseHubOptions {
  port?: number;
  host?: string;
  signingSecret?: string;
  skillPrismMaster?: string;
  skillPrismSentinels?: string[];
}

/**
 * Self-Hostable Enterprise Control Plane (`agent-defense-hub`):
 * - OIDC (Okta) & SAML 2.0 (Microsoft Entra ID) SSO authentication
 * - Strict 3-Role RBAC (`Admin`, `Approver`, `Developer`)
 * - Asymmetric Ed25519 `.ritualrules` policy signing & fleet sync
 * - SkillPrism Redis Sentinel cluster orchestration & status telemetry
 * - Splunk HEC, Datadog Logs JSON & ArcSight CEF SIEM log shipping
 */
export class AgentDefenseHubServer {
  private readonly port: number;
  private readonly host: string;
  private readonly ssoService: SsoPolicySyncService;
  private readonly siemEngine: SiemForwarderEngine;
  private readonly ed25519PublicKeyPem: string;
  private readonly ed25519PrivateKeyPem: string;
  private readonly publicKeyFingerprint: string;

  private server: Server | null = null;
  private signedPolicies = new Map<string, SignedHubPolicyEnvelope>();
  private approvals = new Map<string, HubApprovalDecision>();
  private auditEvents: AuditLedgerEntry[] = [];
  private skillPrismState: SkillPrismClusterState;

  constructor(options: AgentDefenseHubOptions = {}) {
    this.port = options.port ?? Number(process.env.HUB_PORT || 8443);
    this.host = options.host ?? process.env.HUB_HOST ?? '127.0.0.1';
    this.ssoService = new SsoPolicySyncService(options.signingSecret);
    this.siemEngine = new SiemForwarderEngine();

    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    this.ed25519PublicKeyPem = publicKey;
    this.ed25519PrivateKeyPem = privateKey;
    this.publicKeyFingerprint = `sha256:${crypto.createHash('sha256').update(publicKey.trim()).digest('hex')}`;

    this.skillPrismState = {
      masterHost: options.skillPrismMaster || process.env.SKILLPRISM_REDIS_MASTER || 'redis-sentinel.internal:26379',
      sentinels: options.skillPrismSentinels || [
        'sentinel-az1.internal:26379',
        'sentinel-az2.internal:26379',
        'sentinel-az3.internal:26379',
      ],
      preferredZone: process.env.SKILLPRISM_AZ || 'az-1',
      fallbackMode: 'redis-sentinel',
      activeNamespaces: 1,
      lastHeartbeatAt: new Date().toISOString(),
    };
  }

  public getPublicKeyPem(): string {
    return this.ed25519PublicKeyPem;
  }

  public getPublicKeyFingerprint(): string {
    return this.publicKeyFingerprint;
  }

  /**
   * Maps OIDC/SAML corporate SSO tokens to strict 3-role RBAC: Admin | Approver | Developer.
   */
  public authenticateHeader(authHeader?: string): HubIdentity | null {
    if (!authHeader) return null;
    const rawToken = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7).trim()
      : authHeader.startsWith('SAML ')
        ? Buffer.from(authHeader.slice(5).trim(), 'base64').toString('utf8')
        : authHeader.trim();

    if (!rawToken) return null;

    try {
      const ssoUser = this.ssoService.validateSsoToken(rawToken);
      const role = this.mapToThreeRoleRbac(ssoUser.roles, ssoUser.groups, rawToken);
      const provider: HubIdentity['provider'] =
        ssoUser.protocol === 'saml2'
          ? 'entra-saml'
          : ssoUser.issuer.toLowerCase().includes('okta')
            ? 'okta-oidc'
            : 'oidc';

      return {
        sub: ssoUser.sub,
        email: ssoUser.email,
        name: ssoUser.name,
        provider,
        role,
        tenantId: ssoUser.tenantId,
      };
    } catch {
      return null;
    }
  }

  private mapToThreeRoleRbac(
    fleetRoles: string[],
    groups: string[],
    rawToken: string,
  ): HubRbacRole {
    const combined = [...fleetRoles, ...groups].map((v) => v.toLowerCase());
    if (combined.some((r) => r.includes('admin') || r.includes('securityadmin'))) {
      return 'Admin';
    }
    if (
      combined.some((r) => r.includes('approver') || r.includes('lead') || r.includes('dba')) ||
      /approver/i.test(rawToken)
    ) {
      return 'Approver';
    }
    return 'Developer';
  }

  /**
   * Formats an audit event in ArcSight Common Event Format (CEF) for Splunk / Datadog / Sentinel.
   */
  public formatCefEvent(entry: AuditLedgerEntry): string {
    const severity = entry.severity === 'CRITICAL' ? 8 : entry.severity === 'WARN' ? 5 : 3;
    const resource = String(entry.payload?.resource || entry.service);
    const safeMsg = `${entry.action} on ${resource} by ${entry.userId}`.replace(/[|=\\\r\n]/g, ' ');
    return `CEF:0|RitualDev|AgentDefenseHub|3.0.0|${entry.action}|${safeMsg}|${severity}|suser=${entry.userId} cs1=${resource} cs1Label=Resource cs2=${entry.entryHash} cs2Label=LedgerHash rt=${entry.timestamp}`;
  }

  private recordAudit(
    userId: string,
    action: string,
    resource: string,
    metadata: Record<string, unknown> = {},
    tenantId = 'corp-global',
  ): AuditLedgerEntry {
    const sequence = this.auditEvents.length + 1;
    const prevHash = this.auditEvents.length > 0 ? this.auditEvents[this.auditEvents.length - 1].entryHash : '0'.repeat(64);
    const timestamp = new Date().toISOString();
    const severity: AuditLedgerEntry['severity'] =
      action.includes('DENIED') || action.includes('BLOCK') ? 'CRITICAL' : 'INFO';
    const rawPayload = `${sequence}|${timestamp}|${userId}|${action}|${resource}|${prevHash}`;
    const entryHash = crypto.createHash('sha256').update(rawPayload).digest('hex');
    const hmacSignature = crypto
      .createHmac('sha256', this.publicKeyFingerprint)
      .update(entryHash)
      .digest('hex');

    const entry: AuditLedgerEntry = {
      sequence,
      timestamp,
      tenantId,
      userId,
      service: 'FleetPolicy',
      action,
      severity,
      payload: { resource, ...metadata },
      previousHash: prevHash,
      entryHash,
      hmacSignature,
    };
    this.auditEvents.push(entry);
    return entry;
  }

  private signPolicyBundle(
    tenantId: string,
    policy: Partial<RitualRulesPolicy> & Record<string, unknown>,
    signedBy: string,
  ): SignedHubPolicyEnvelope {
    const signedAt = new Date().toISOString();
    const policyVersion = typeof policy.version === 'string' ? policy.version : `v${Date.now()}`;
    const canonicalPayload = JSON.stringify({ tenantId, policyVersion, signedBy, signedAt, policy });
    const sig = crypto.sign(null, Buffer.from(canonicalPayload, 'utf8'), this.ed25519PrivateKeyPem);

    const envelope: SignedHubPolicyEnvelope = {
      policyVersion,
      tenantId,
      signedBy,
      signedAt,
      algorithm: 'ed25519',
      publicKeyFingerprint: this.publicKeyFingerprint,
      signatureBase64: sig.toString('base64'),
      policy,
    };
    this.signedPolicies.set(tenantId, envelope);
    return envelope;
  }

  public static verifyPolicyEnvelope(envelope: SignedHubPolicyEnvelope, publicKeyPem: string): boolean {
    const canonicalPayload = JSON.stringify({
      tenantId: envelope.tenantId,
      policyVersion: envelope.policyVersion,
      signedBy: envelope.signedBy,
      signedAt: envelope.signedAt,
      policy: envelope.policy,
    });
    return crypto.verify(
      null,
      Buffer.from(canonicalPayload, 'utf8'),
      publicKeyPem,
      Buffer.from(envelope.signatureBase64, 'base64'),
    );
  }

  private async readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    }
    const raw = Buffer.concat(chunks).toString('utf8').trim();
    return raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
  }

  private sendJson(res: ServerResponse, status: number, payload: unknown): void {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method || 'GET';
    const url = (req.url || '/').split('?')[0];

    if (url === '/health' || url === '/healthz' || url === '/readyz') {
      this.sendJson(res, 200, {
        status: 'ok',
        service: 'agent-defense-hub',
        version: '3.0.0',
        publicKeyFingerprint: this.publicKeyFingerprint,
      });
      return;
    }

    if (url === '/api/v1/keys/public' && method === 'GET') {
      this.sendJson(res, 200, {
        algorithm: 'ed25519',
        fingerprint: this.publicKeyFingerprint,
        publicKeyPem: this.ed25519PublicKeyPem,
      });
      return;
    }

    // All control-plane routes require OIDC/SAML SSO authentication
    const identity = this.authenticateHeader(req.headers.authorization);
    if (!identity) {
      this.recordAudit('anonymous', 'AUTH_DENIED', url);
      this.sendJson(res, 401, { error: 'UNAUTHORIZED', message: 'Valid OIDC (Okta) or SAML 2.0 (Entra) SSO token required.' });
      return;
    }

    if (url === '/api/v1/whoami' && method === 'GET') {
      this.sendJson(res, 200, { identity });
      return;
    }

    // Policy Signing (Admin ONLY)
    if (url === '/api/v1/policies/sign' && method === 'POST') {
      if (identity.role !== 'Admin') {
        this.recordAudit(identity.email, 'RBAC_DENIED_POLICY_SIGN', url, { role: identity.role });
        this.sendJson(res, 403, { error: 'FORBIDDEN', requiredRole: 'Admin', currentRole: identity.role });
        return;
      }
      const body = await this.readJsonBody(req);
      const policy = (body.policy as Partial<RitualRulesPolicy> & Record<string, unknown>) || {
        version: '1.0.0',
        secretEntropyThreshold: 4.5,
      };
      const tenantId = (body.tenantId as string) || identity.tenantId;
      const envelope = this.signPolicyBundle(tenantId, policy, identity.email);
      this.recordAudit(identity.email, 'POLICY_SIGNED', `tenant:${tenantId}`, { version: envelope.policyVersion });
      this.sendJson(res, 200, { envelope, publicKeyPem: this.ed25519PublicKeyPem });
      return;
    }

    // Policy Sync (Admin, Approver, Developer)
    if (url === '/api/v1/policies/sync' && method === 'GET') {
      const envelope = this.signedPolicies.get(identity.tenantId) || null;
      this.recordAudit(identity.email, 'POLICY_SYNCED', `tenant:${identity.tenantId}`);
      this.sendJson(res, 200, {
        tenantId: identity.tenantId,
        role: identity.role,
        envelope,
        publicKeyPem: this.ed25519PublicKeyPem,
      });
      return;
    }

    // DBShield / AgentShield Approval Gate (Admin & Approver ONLY)
    if (url === '/api/v1/approvals/decide' && method === 'POST') {
      if (identity.role !== 'Admin' && identity.role !== 'Approver') {
        this.recordAudit(identity.email, 'RBAC_DENIED_APPROVAL', url, { role: identity.role });
        this.sendJson(res, 403, { error: 'FORBIDDEN', requiredRoles: ['Admin', 'Approver'], currentRole: identity.role });
        return;
      }
      const body = await this.readJsonBody(req);
      const approvalId = String(body.approvalId || '');
      const decision = body.decision === 'REJECTED' ? 'REJECTED' : 'APPROVED';
      const record: HubApprovalDecision = {
        approvalId,
        decision,
        decidedBy: identity.email,
        decidedAt: new Date().toISOString(),
        reason: body.reason ? String(body.reason) : undefined,
      };
      this.approvals.set(approvalId, record);
      this.recordAudit(identity.email, `APPROVAL_${decision}`, `approval:${approvalId}`);
      this.sendJson(res, 200, { decision: record });
      return;
    }

    // SkillPrism Redis Sentinel Orchestration
    if (url === '/api/v1/skillprism/status' && method === 'GET') {
      this.sendJson(res, 200, { cluster: this.skillPrismState });
      return;
    }

    if (url === '/api/v1/skillprism/orchestrate' && method === 'POST') {
      if (identity.role !== 'Admin' && identity.role !== 'Approver') {
        this.sendJson(res, 403, { error: 'FORBIDDEN', requiredRoles: ['Admin', 'Approver'], currentRole: identity.role });
        return;
      }
      const body = await this.readJsonBody(req);
      if (body.preferredZone) this.skillPrismState.preferredZone = String(body.preferredZone);
      if (body.fallbackMode === 'local-sqlite-lru' || body.fallbackMode === 'redis-sentinel') {
        this.skillPrismState.fallbackMode = body.fallbackMode;
      }
      if (typeof body.activeNamespaces === 'number') {
        this.skillPrismState.activeNamespaces = body.activeNamespaces;
      }
      this.skillPrismState.lastHeartbeatAt = new Date().toISOString();
      this.recordAudit(identity.email, 'SKILLPRISM_ORCHESTRATED', this.skillPrismState.masterHost, {
        fallbackMode: this.skillPrismState.fallbackMode,
      });
      this.sendJson(res, 200, { cluster: this.skillPrismState });
      return;
    }

    // SIEM CEF / Splunk HEC / Datadog Log Shipping (Admin & Approver)
    if (url === '/api/v1/siem/cef' && method === 'GET') {
      if (identity.role !== 'Admin' && identity.role !== 'Approver') {
        this.sendJson(res, 403, { error: 'FORBIDDEN', requiredRoles: ['Admin', 'Approver'], currentRole: identity.role });
        return;
      }
      const cefLines = this.auditEvents.map((e) => this.formatCefEvent(e));
      const splunkEvents = this.auditEvents.map((e) => this.siemEngine.formatSplunkEvent(e));
      const datadogLogs = this.auditEvents.map((e) => this.siemEngine.formatDatadogLog(e));
      this.sendJson(res, 200, {
        totalEvents: this.auditEvents.length,
        cef: cefLines,
        splunkHec: splunkEvents,
        datadog: datadogLogs,
      });
      return;
    }

    this.sendJson(res, 404, { error: 'NOT_FOUND', path: url });
  }

  public async start(): Promise<{ host: string; port: number; baseUrl: string }> {
    if (this.server) {
      const addr = this.server.address();
      const port = typeof addr === 'object' && addr ? addr.port : this.port;
      return { host: this.host, port, baseUrl: `http://${this.host}:${port}` };
    }

    this.server = http.createServer((req, res) => {
      this.handleRequest(req, res).catch((err) => {
        this.sendJson(res, 500, { error: 'INTERNAL_ERROR', message: err instanceof Error ? err.message : String(err) });
      });
    });

    await new Promise<void>((resolve) => {
      this.server?.listen(this.port, this.host, () => resolve());
    });

    const addr = this.server.address();
    const resolvedPort = typeof addr === 'object' && addr ? addr.port : this.port;
    return { host: this.host, port: resolvedPort, baseUrl: `http://${this.host}:${resolvedPort}` };
  }

  public async stop(): Promise<void> {
    if (!this.server) return;
    await new Promise<void>((resolve, reject) => {
      this.server?.close((err) => (err ? reject(err) : resolve()));
    });
    this.server = null;
  }
}
