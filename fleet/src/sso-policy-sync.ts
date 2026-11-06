import crypto from 'crypto';
import type {
  FleetRole,
  RitualRulesBundle,
  RitualRulesPolicy,
  SsoUserIdentity,
  WorkstationSyncRequest,
  WorkstationSyncResponse,
} from './types';

function canonicalJson(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return `[${obj.map(canonicalJson).join(',')}]`;
  }
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}

export class SsoPolicySyncService {
  private signingSecret: string;
  private tenantPolicies = new Map<string, RitualRulesBundle>();

  constructor(signingSecret: string = 'ritualdev_enterprise_fleet_signing_master_key_2026') {
    this.signingSecret = signingSecret;
  }

  /**
   * Validates corporate SSO authentication token (OIDC Bearer or SAML assertion).
   */
  public validateSsoToken(token: string): SsoUserIdentity {
    if (!token || typeof token !== 'string') {
      throw new Error('Invalid or missing SSO authorization token');
    }

    // Handle SAML 2.0 XML Assertion
    if (token.includes('<saml2:Assertion') || token.includes('<saml:Assertion')) {
      return this.parseSamlAssertion(token);
    }

    // Handle OIDC / JWT Token format
    const parts = token.split('.');
    if (parts.length === 3) {
      try {
        const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf8');
        const payload = JSON.parse(payloadJson);

        const roles: FleetRole[] = [];
        const rawRoles: string[] = payload.roles || payload.groups || ['Contributor'];

        for (const r of rawRoles) {
          const upper = r.toLowerCase();
          if (upper.includes('admin') || upper.includes('security')) {
            roles.push('SecurityAdmin');
          } else if (upper.includes('lead') || upper.includes('maintainer')) {
            roles.push('LeadDeveloper');
          } else if (upper.includes('audit')) {
            roles.push('Auditor');
          } else {
            roles.push('Contributor');
          }
        }

        return {
          sub: payload.sub || 'usr_enterprise_default',
          email: payload.email || 'developer@enterprise.corp',
          name: payload.name || 'Enterprise Developer',
          tenantId: payload.tenantId || payload.tid || 'corp-global',
          roles: roles.length > 0 ? roles : ['Contributor'],
          groups: payload.groups || [],
          protocol: 'oidc',
          issuer: payload.iss || 'https://identity.enterprise.corp/oauth2',
          authenticatedAt: new Date(payload.auth_time ? payload.auth_time * 1000 : Date.now()).toISOString(),
        };
      } catch (e) {
        throw new Error(`Failed to decode OIDC token payload: ${(e as Error).message}`);
      }
    }

    // Fallback simulation/mock token for testing: sso_sim_<user>_<role>_<tenantId>
    if (token.startsWith('sso_sim_')) {
      const parts = token.split('_');
      const user = parts[2] || 'dev';
      const roleStr = parts[3] || 'contributor';
      let role: FleetRole = 'Contributor';
      if (roleStr === 'admin') role = 'SecurityAdmin';
      else if (roleStr === 'lead') role = 'LeadDeveloper';
      else if (roleStr === 'auditor') role = 'Auditor';

      const tenant = parts[4] || 'tenant-acme-corp';

      return {
        sub: `usr_${user}`,
        email: `${user}@enterprise.corp`,
        name: `Dev ${user}`,
        tenantId: tenant,
        roles: [role],
        groups: ['engineering'],
        protocol: 'oidc',
        issuer: 'https://login.microsoftonline.com/enterprise/v2.0',
        authenticatedAt: new Date().toISOString(),
      };
    }

    throw new Error('Unsupported or malformed SSO token structure');
  }

  private parseSamlAssertion(samlXml: string): SsoUserIdentity {
    const emailMatch = samlXml.match(/NameID[^>]*>([^<]+)<\//i);
    const email = emailMatch ? emailMatch[1] : 'saml-user@enterprise.corp';
    const roles: FleetRole[] = [];

    if (samlXml.includes('SecurityAdmin') || samlXml.includes('InfraSec')) {
      roles.push('SecurityAdmin');
    } else {
      roles.push('Contributor');
    }

    return {
      sub: email,
      email,
      name: email.split('@')[0],
      tenantId: 'tenant-enterprise-saml',
      roles,
      groups: ['sso-users'],
      protocol: 'saml2',
      issuer: 'https://okta.enterprise.corp/app/ritualdev/sso/saml',
      authenticatedAt: new Date().toISOString(),
    };
  }

  /**
   * Computes policy hash and signs a bundle using HMAC-SHA256.
   */
  public signPolicyBundle(
    tenantId: string,
    policy: RitualRulesPolicy,
    signedBy: string,
    version: string = '1.0.0'
  ): RitualRulesBundle {
    const policyString = canonicalJson(policy);
    const policyHashSha256 = crypto
      .createHash('sha256')
      .update(policyString)
      .digest('hex');

    const signature = crypto
      .createHmac('sha256', this.signingSecret)
      .update(`${tenantId}:${version}:${policyHashSha256}:${signedBy}`)
      .digest('hex');

    const bundle: RitualRulesBundle = {
      bundleVersion: version,
      tenantId,
      updatedAt: new Date().toISOString(),
      policy,
      policyHashSha256,
      signature,
      signedBy,
    };

    this.tenantPolicies.set(tenantId, bundle);
    return bundle;
  }

  /**
   * Verifies the cryptographic integrity and signature of a policy bundle.
   */
  public verifyBundleIntegrity(bundle: RitualRulesBundle): boolean {
    const policyString = canonicalJson(bundle.policy);
    const expectedHash = crypto
      .createHash('sha256')
      .update(policyString)
      .digest('hex');

    if (expectedHash !== bundle.policyHashSha256) {
      return false;
    }

    const expectedSig = crypto
      .createHmac('sha256', this.signingSecret)
      .update(`${bundle.tenantId}:${bundle.bundleVersion}:${bundle.policyHashSha256}:${bundle.signedBy}`)
      .digest('hex');

    return expectedSig === bundle.signature;
  }

  /**
   * Handles local developer workstation synchronization request.
   */
  public syncWorkstation(request: WorkstationSyncRequest): WorkstationSyncResponse {
    let identity: SsoUserIdentity;
    try {
      identity = this.validateSsoToken(request.userToken);
    } catch (err) {
      return {
        status: 'unauthorized',
        enforceIntervalSeconds: 300,
        message: `SSO authentication rejected: ${(err as Error).message}`,
      };
    }

    // Verify tenant authorization
    if (identity.tenantId !== request.tenantId && identity.tenantId !== 'corp-global') {
      return {
        status: 'unauthorized',
        enforceIntervalSeconds: 300,
        message: `Tenant ID mismatch: identity tenant ${identity.tenantId} != requested ${request.tenantId}`,
      };
    }

    const currentBundle = this.tenantPolicies.get(request.tenantId);
    if (!currentBundle) {
      return {
        status: 'revoked',
        enforceIntervalSeconds: 300,
        message: `No active policy registered for tenant ${request.tenantId}`,
      };
    }

    // Check if workstation's installed rules match latest hash
    if (request.installedRulesHash === currentBundle.policyHashSha256) {
      return {
        status: 'synced',
        enforceIntervalSeconds: 900, // 15 mins polling interval
        message: `Workstation ${request.hostname} is up to date with policy version ${currentBundle.bundleVersion}`,
      };
    }

    // Workstation rules are out of date or missing, distribute signed bundle
    return {
      status: 'updated',
      bundle: currentBundle,
      enforceIntervalSeconds: 900,
      message: `Updated to latest policy bundle v${currentBundle.bundleVersion} signed by ${currentBundle.signedBy}`,
    };
  }

  /**
   * Generates default institutional .ritualrules policy.
   */
  public static createDefaultEnterprisePolicy(): RitualRulesPolicy {
    return {
      promptInjectionGuard: {
        enabled: true,
        failClosed: true,
        blockPatterns: [
          'ignore all previous instructions',
          'reveal environmental tokens',
          'exfiltrate private key',
        ],
        canaryDecoyInjection: true,
      },
      databaseShadowMode: {
        enabled: true,
        requireProofOfIntent: true,
        mutationSandbox: 'virtual_duckdb',
      },
      egressDomainWhitelist: [
        'api.github.com',
        'api.openai.com',
        '*.openai.azure.com',
        'bedrock-runtime.*.amazonaws.com',
        'ritualdev.in',
      ],
      secretEntropyThreshold: 4.5,
      allowedAiGateways: ['azure-openai', 'aws-bedrock', 'local-ollama'],
      maxTokensPerMinute: 200000,
    };
  }
}
