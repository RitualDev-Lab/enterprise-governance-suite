import crypto from 'node:crypto';
import type { AuditLedgerEntry } from './audit-ledger';

export interface SplunkHecConfig {
  endpoint: string; // e.g. "https://splunk.internal:8088/services/collector/event"
  token: string;
  index?: string;
  source?: string;
  sourcetype?: string;
}

export interface DatadogLogsConfig {
  apiKey: string;
  site?: string; // e.g. "datadoghq.com" or "datadoghq.eu"
  service?: string;
}

export interface MicrosoftSentinelConfig {
  workspaceId: string;
  sharedKey: string;
  logType?: string; // e.g. "RitualAgentAudit"
}

export interface MultiSiemConfig {
  splunk?: SplunkHecConfig;
  datadog?: DatadogLogsConfig;
  sentinel?: MicrosoftSentinelConfig;
}

/**
 * Enterprise Multi-SIEM Telemetry & Forwarding Engine.
 * Converts HMAC-signed audit ledger events into certified Splunk HEC,
 * Datadog Logs, and Microsoft Sentinel (Azure Monitor) log ingest formats.
 */
export class SiemForwarderEngine {
  private config: MultiSiemConfig;

  constructor(config: MultiSiemConfig = {}) {
    this.config = config;
  }

  /**
   * Formats an audit ledger entry into Splunk HTTP Event Collector (HEC) payload.
   */
  public formatSplunkEvent(entry: AuditLedgerEntry): {
    time: number;
    host: string;
    source: string;
    sourcetype: string;
    index?: string;
    event: AuditLedgerEntry;
  } {
    const splunkCfg = this.config.splunk || { endpoint: '', token: '' };
    return {
      time: Math.floor(new Date(entry.timestamp).getTime() / 1000),
      host: 'ritualdev-agent-fleet',
      source: splunkCfg.source || 'ritual-agent-governance',
      sourcetype: splunkCfg.sourcetype || '_json',
      index: splunkCfg.index,
      event: entry,
    };
  }

  /**
   * Formats an audit ledger entry into Datadog Logs API JSON structure.
   */
  public formatDatadogLog(entry: AuditLedgerEntry): {
    ddsource: string;
    ddtags: string;
    service: string;
    hostname: string;
    message: string;
    ledger_sequence: number;
    entry_hash: string;
    hmac_signature: string;
    audit_data: Record<string, unknown>;
  } {
    const ddCfg = this.config.datadog || { apiKey: '' };
    return {
      ddsource: 'ritual-governance-mesh',
      ddtags: `tenant:${entry.tenantId},user:${entry.userId},severity:${entry.severity}`,
      service: ddCfg.service || `ritual-${entry.service.toLowerCase()}`,
      hostname: 'agent-workstation',
      message: `[${entry.service}] ${entry.action} by ${entry.userId} (${entry.severity})`,
      ledger_sequence: entry.sequence,
      entry_hash: entry.entryHash,
      hmac_signature: entry.hmacSignature,
      audit_data: entry.payload,
    };
  }

  /**
   * Formats and cryptographically signs payload for Microsoft Sentinel / Azure Log Analytics.
   * Generates Azure HMAC-SHA256 SharedKey authorization header.
   */
  public formatSentinelRequest(entry: AuditLedgerEntry): {
    url: string;
    headers: Record<string, string>;
    body: string;
  } {
    const sentinelCfg = this.config.sentinel || {
      workspaceId: 'mock-sentinel-workspace-id',
      sharedKey: Buffer.from('mock-shared-key-base64-secret').toString('base64'),
      logType: 'RitualAgentSecurityEvents',
    };

    const logType = sentinelCfg.logType || 'RitualAgentSecurityEvents';
    const jsonBody = JSON.stringify([entry]);
    const contentLength = Buffer.byteLength(jsonBody, 'utf8');
    const rfc1123Date = new Date().toUTCString();

    // Azure Log Analytics signature construction:
    // StringToSign = "POST\n" + contentLength + "\napplication/json\nx-ms-date:" + date + "\n/api/logs"
    const stringToSign = `POST\n${contentLength}\napplication/json\nx-ms-date:${rfc1123Date}\n/api/logs`;
    const keyBuffer = Buffer.from(sentinelCfg.sharedKey, 'base64');
    const signature = crypto.createHmac('sha256', keyBuffer).update(stringToSign, 'utf8').digest('base64');

    const authHeader = `SharedKey ${sentinelCfg.workspaceId}:${signature}`;

    return {
      url: `https://${sentinelCfg.workspaceId}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01`,
      headers: {
        'Content-Type': 'application/json',
        'Log-Type': logType,
        Authorization: authHeader,
        'x-ms-date': rfc1123Date,
        'time-generated-field': 'timestamp',
      },
      body: jsonBody,
    };
  }
}
