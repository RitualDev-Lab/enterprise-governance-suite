import type { OTelCollectorConfig } from './types';

export class OpenTelemetryFleetManager {
  /**
   * Generates standard OpenTelemetry Collector YAML configuration.
   */
  public static generateCollectorConfigYaml(config: OTelCollectorConfig): string {
    return `receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  memory_limiter:
    check_interval: 1s
    limit_percentage: 75
    spike_limit_percentage: 20
  batch:
    timeout: 5s
    send_batch_size: ${config.batchSize}
  transform/pii_redact:
    error_mode: ignore
    log_statements:
      - context: log
        statements:
          - replace_pattern(body, "(?i)(api[-_]?key|secret|password|bearer)[\\\\s:=]+([a-zA-Z0-9_\\\\-]{8,})", "$$1: [REDACTED_BY_OTEL]")

exporters:
  otlp/siem:
    endpoint: ${config.endpoint}
    tls:
      insecure: false
    headers:
${Object.entries(config.headers)
  .map(([k, v]) => `      ${k}: "${v}"`)
  .join('\n')}
  prometheus:
    endpoint: "0.0.0.0:8889"
    namespace: "ritualdev_fleet"

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlp/siem]
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [prometheus, otlp/siem]
    logs:
      receivers: [otlp]
      processors: [memory_limiter, transform/pii_redact, batch]
      exporters: [otlp/siem]
  telemetry:
    logs:
      level: info
`;
  }

  /**
   * Formats a security audit event into OTLP log structure.
   */
  public static formatAuditRecord(event: {
    serviceName: 'AgentShield' | 'DBShield' | 'GitWhisper' | 'WebSecAuditor';
    eventType: string;
    severity: 'INFO' | 'WARN' | 'CRITICAL';
    userId: string;
    tenantId: string;
    details: Record<string, unknown>;
  }) {
    return {
      timestamp: new Date().toISOString(),
      traceId: crypto.randomUUID().replace(/-/g, ''),
      severityText: event.severity,
      severityNumber: event.severity === 'CRITICAL' ? 17 : event.severity === 'WARN' ? 13 : 9,
      body: JSON.stringify(event.details),
      attributes: {
        'service.name': event.serviceName,
        'tenant.id': event.tenantId,
        'user.id': event.userId,
        'event.type': event.eventType,
        'security.mesh': 'RitualDev-Enterprise',
      },
    };
  }
}
