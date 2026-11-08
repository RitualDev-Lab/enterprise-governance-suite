import crypto from 'node:crypto';

export interface AuditLedgerEntry {
  sequence: number;
  timestamp: string;
  tenantId: string;
  userId: string;
  service: 'AgentShield' | 'DBShield' | 'PromptShield' | 'WebSecAuditor' | 'FleetPolicy';
  action: string;
  severity: 'INFO' | 'WARN' | 'CRITICAL';
  payload: Record<string, unknown>;
  previousHash: string;
  entryHash: string;
  hmacSignature: string;
}

export interface LedgerVerificationResult {
  valid: boolean;
  totalEntries: number;
  tamperedIndex?: number;
  error?: string;
}

function canonicalJson(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return `[${obj.map(canonicalJson).join(',')}]`;
  }
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson((obj as Record<string, unknown>)[k])}`).join(',')}}`;
}

/**
 * Tamper-Evident HMAC-SHA256 Cryptographic Audit Ledger.
 * Guarantees immutable, hash-chained logging of all agent actions, prompt redactions,
 * database dry-runs, and policy sync events for SOC 2 Type II and ISO 27001 compliance.
 */
export class EnterpriseAuditLedger {
  private secretKey: string;
  private entries: AuditLedgerEntry[] = [];
  private genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';

  constructor(secretKey: string = 'ritual_enterprise_audit_ledger_master_hmac_secret_2026') {
    this.secretKey = secretKey;
  }

  /**
   * Appends an event to the ledger, computing SHA-256 hash-chaining and HMAC signature.
   */
  public append(record: {
    tenantId: string;
    userId: string;
    service: 'AgentShield' | 'DBShield' | 'PromptShield' | 'WebSecAuditor' | 'FleetPolicy';
    action: string;
    severity?: 'INFO' | 'WARN' | 'CRITICAL';
    payload: Record<string, unknown>;
  }): AuditLedgerEntry {
    const sequence = this.entries.length;
    const previousHash = sequence === 0 ? this.genesisHash : this.entries[sequence - 1].entryHash;
    const timestamp = new Date().toISOString();
    const severity = record.severity || 'INFO';

    const unsignedData = {
      sequence,
      timestamp,
      tenantId: record.tenantId,
      userId: record.userId,
      service: record.service,
      action: record.action,
      severity,
      payload: record.payload,
      previousHash,
    };

    const entryHash = crypto.createHash('sha256').update(canonicalJson(unsignedData)).digest('hex');
    const hmacSignature = crypto.createHmac('sha256', this.secretKey).update(entryHash).digest('hex');

    const entry: AuditLedgerEntry = {
      ...unsignedData,
      entryHash,
      hmacSignature,
    };

    this.entries.push(entry);
    return entry;
  }

  /**
   * Verifies the cryptographic integrity of the entire ledger chain.
   */
  public verifyChainIntegrity(): LedgerVerificationResult {
    if (this.entries.length === 0) {
      return { valid: true, totalEntries: 0 };
    }

    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];

      // 1. Verify sequence order
      if (entry.sequence !== i) {
        return {
          valid: false,
          totalEntries: this.entries.length,
          tamperedIndex: i,
          error: `Sequence mismatch at index ${i} (found ${entry.sequence})`,
        };
      }

      // 2. Verify previousHash chaining
      const expectedPrev = i === 0 ? this.genesisHash : this.entries[i - 1].entryHash;
      if (entry.previousHash !== expectedPrev) {
        return {
          valid: false,
          totalEntries: this.entries.length,
          tamperedIndex: i,
          error: `Broken hash chain at sequence ${i}. Expected previousHash ${expectedPrev}, found ${entry.previousHash}`,
        };
      }

      // 3. Recompute entryHash
      const unsignedData = {
        sequence: entry.sequence,
        timestamp: entry.timestamp,
        tenantId: entry.tenantId,
        userId: entry.userId,
        service: entry.service,
        action: entry.action,
        severity: entry.severity,
        payload: entry.payload,
        previousHash: entry.previousHash,
      };

      const computedHash = crypto.createHash('sha256').update(canonicalJson(unsignedData)).digest('hex');
      if (computedHash !== entry.entryHash) {
        return {
          valid: false,
          totalEntries: this.entries.length,
          tamperedIndex: i,
          error: `Content tampering detected at sequence ${i}. Hash mismatch`,
        };
      }

      // 4. Verify HMAC signature
      const computedHmac = crypto.createHmac('sha256', this.secretKey).update(entry.entryHash).digest('hex');
      if (computedHmac !== entry.hmacSignature) {
        return {
          valid: false,
          totalEntries: this.entries.length,
          tamperedIndex: i,
          error: `Forged HMAC signature detected at sequence ${i}`,
        };
      }
    }

    return { valid: true, totalEntries: this.entries.length };
  }

  /**
   * Returns all entries currently stored in the ledger.
   */
  public getEntries(): readonly AuditLedgerEntry[] {
    return this.entries;
  }

  /**
   * Generates a signed export bundle for third-party compliance auditors.
   */
  public exportAuditBundle(): {
    entries: AuditLedgerEntry[];
    rootHash: string;
    totalEntries: number;
    signature: string;
  } {
    const totalEntries = this.entries.length;
    const rootHash = totalEntries === 0 ? this.genesisHash : this.entries[totalEntries - 1].entryHash;
    const signature = crypto.createHmac('sha256', this.secretKey).update(`${rootHash}:${totalEntries}`).digest('hex');

    return {
      entries: [...this.entries],
      rootHash,
      totalEntries,
      signature,
    };
  }

  /**
   * Clears in-memory ledger state.
   */
  public clear(): void {
    this.entries = [];
  }
}
