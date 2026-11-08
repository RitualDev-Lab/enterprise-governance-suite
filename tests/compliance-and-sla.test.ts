import { describe, it, expect } from 'vitest';
import {
  EnterpriseAuditLedger,
  CompliancePackCompiler,
  P1IncidentAutomationEngine,
  SLA_TARGETS
} from '../fleet/src/index';

describe('Automated Compliance Evidence Compiler (SOC 2, ISO 27001, EU AI Act, DPDP)', () => {
  it('Compiles full compliance evidence pack with HMAC signature and ledger verification', () => {
    const ledger = new EnterpriseAuditLedger('test-secret-hmac-2026');
    ledger.append({
      tenantId: 'tenant-test',
      userId: 'usr-agent-01',
      service: 'AgentShield',
      action: 'PROCESS_CONFINEMENT',
      severity: 'INFO',
      payload: { pid: 4891, syscallConfinement: 'SECCOMP_STRICT' }
    });

    const compiler = new CompliancePackCompiler({
      tenantId: 'tenant-test',
      organization: 'RitualDev Test Org',
      hmacSecret: 'test-secret-hmac-2026'
    });

    const pack = compiler.compile(ledger);

    expect(pack.tenantId).toBe('tenant-test');
    expect(pack.organization).toBe('RitualDev Test Org');
    expect(pack.ledgerVerification.valid).toBe(true);
    expect(pack.ledgerVerification.totalEntries).toBe(1);
    expect(pack.digitalSignature.length).toBe(64);

    // Verify all 4 major frameworks are assessed
    expect(pack.frameworks.SOC2_TYPE_II.complianceRate).toBe(100);
    expect(pack.frameworks.ISO_27001_2022.complianceRate).toBe(100);
    expect(pack.frameworks.EU_AI_ACT.complianceRate).toBe(100);
    expect(pack.frameworks.DPDP_GDPR.complianceRate).toBe(100);

    // Verify specific critical controls
    const imds = pack.controls.find((c) => c.id === 'SOC2-CC6.1');
    expect(imds?.status).toBe('SATISFIED');
    expect(imds?.enforcementMechanism).toContain('IMDSv2');

    const euaiact = pack.controls.find((c) => c.id === 'EU-AI-ACT-ART15');
    expect(euaiact?.status).toBe('SATISFIED');
    expect(euaiact?.enforcementMechanism).toContain('RedTeamFuzzer');
  });

  it('Exports valid JSON serialization of compliance pack', () => {
    const compiler = new CompliancePackCompiler();
    const jsonStr = compiler.exportJson();
    const parsed = JSON.parse(jsonStr);

    expect(parsed.packId).toBeDefined();
    expect(parsed.controls.length).toBeGreaterThan(5);
    expect(parsed.digitalSignature).toBeDefined();
  });

  it('Generates formatted executive Markdown compliance report for external auditors', () => {
    const compiler = new CompliancePackCompiler({ organization: 'Acme AI Lab' });
    const md = compiler.exportMarkdown();

    expect(md).toContain('# Enterprise Compliance & Regulatory Attestation Pack');
    expect(md).toContain('**Organization**: Acme AI Lab');
    expect(md).toContain('## 1. Executive Framework Compliance Summary');
    expect(md).toContain('SOC2_TYPE_II');
    expect(md).toContain('EU_AI_ACT');
    expect(md).toContain('## 3. Detailed Control Evidence Matrix');
    expect(md).toContain('Non-Repudiation Notice');
  });

  it('Generates OASIS SARIF v2.1.0 compliance evaluation report', () => {
    const compiler = new CompliancePackCompiler();
    const sarif = compiler.exportSarif() as any;

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
    expect(sarif.runs.length).toBe(1);

    const driver = sarif.runs[0].tool.driver;
    expect(driver.name).toContain('Compliance');
    expect(driver.rules.length).toBeGreaterThan(5);

    const results = sarif.runs[0].results;
    expect(results.length).toBe(driver.rules.length);
    expect(results[0].level).toBe('none'); // Passed control
  });
});

describe('Mission-Critical 24/7/365 P1 SLA (< 60-min response) & Failover Engine', () => {
  it('Tracks P1 incident lifecycle with MTTA (< 15m) and MTTR (< 60m) thresholds', () => {
    const engine = new P1IncidentAutomationEngine();
    const t0 = new Date('2026-11-08T10:00:00Z');
    const tAck = new Date('2026-11-08T10:12:00Z'); // 12 mins -> compliant
    const tMit = new Date('2026-11-08T10:48:00Z'); // 48 mins -> compliant

    const inc = engine.triggerIncident({
      title: 'Database Shadow Mode Proxy Latency Spike',
      severity: 'P1_CRITICAL',
      service: 'DBShield Wire Proxy',
      detectedAt: t0.toISOString()
    });

    expect(inc.state).toBe('DETECTED');
    expect(inc.mttaBreached).toBe(false);

    engine.acknowledgeIncident(inc.id, 'sre@ritualdev.in', tAck.toISOString());
    expect(inc.state).toBe('ACKNOWLEDGED');
    expect(inc.mttaMinutes).toBe(12);
    expect(inc.mttaBreached).toBe(false);

    engine.mitigateIncident(inc.id, 'Scaled shadow proxy replica pool from 3 to 12', tMit.toISOString());
    expect(inc.state).toBe('MITIGATED');
    expect(inc.mttrMinutes).toBe(48);
    expect(inc.mttrBreached).toBe(false);

    engine.resolveIncident(inc.id, 'Temporary downstream network saturation resolved');
    expect(inc.state).toBe('RESOLVED');
  });

  it('Detects and flags SLA breach when MTTR exceeds 60 minutes for P1 incident', () => {
    const engine = new P1IncidentAutomationEngine();
    const t0 = new Date('2026-11-08T10:00:00Z');
    const tMit = new Date('2026-11-08T11:15:00Z'); // 75 mins -> breached

    const inc = engine.triggerIncident({
      title: 'Global eBPF Filter Gateway Unresponsive',
      severity: 'P1_CRITICAL',
      service: 'AgentShield Core',
      detectedAt: t0.toISOString()
    });

    engine.mitigateIncident(inc.id, 'Fallback policy activated', tMit.toISOString());
    expect(inc.mttrMinutes).toBe(75);
    expect(inc.mttrBreached).toBe(true);
  });

  it('Evaluates multi-region health probes and initiates automated failover to secondary', () => {
    const engine = new P1IncidentAutomationEngine();
    expect(engine.getActiveRegion()).toBe('primary');

    // Probe: primary fails 3 consecutive times, secondary healthy
    const decision = engine.evaluateMultiRegionHealth({
      primaryHealthy: false,
      secondaryHealthy: true,
      consecutiveFailures: 3
    });

    expect(decision.failoverTriggered).toBe(true);
    expect(decision.activeRegion).toBe('secondary');
    expect(engine.getActiveRegion()).toBe('secondary');
    expect(decision.incidentId).toBeDefined();

    const inc = engine.getIncident(decision.incidentId!);
    expect(inc?.severity).toBe('P1_CRITICAL');
    expect(inc?.title).toContain('Automated Multi-Region DNS Failover');

    // Probe: primary recovers
    const recovery = engine.evaluateMultiRegionHealth({
      primaryHealthy: true,
      secondaryHealthy: true,
      consecutiveFailures: 0
    });
    expect(recovery.activeRegion).toBe('primary');
    expect(engine.getActiveRegion()).toBe('primary');
  });

  it('Generates bi-hourly status updates for customer status pages', () => {
    const engine = new P1IncidentAutomationEngine();
    const inc = engine.triggerIncident({
      title: 'Synthetic Canary Secret Mismatch',
      severity: 'P2_MAJOR',
      service: 'Fleet Telemetry Gateway'
    });

    const update = engine.generateStatusUpdate(inc.id);
    expect(update).toContain('Synthetic Canary Secret Mismatch');
    expect(update).toContain('P2_MAJOR');
    expect(update).toContain('RitualDev Mission-Critical Incident Automation');
  });

  it('Calculates contractual SLA breach credits accurately', () => {
    const engine = new P1IncidentAutomationEngine();
    const monthlyFee = 10000; // $10,000 / month contract

    // Case 1: 100% uptime, 0 breaches -> $0 credit
    const res1 = engine.calculateSlaBreachCredit(monthlyFee, 0, 0);
    expect(res1.uptimePercent).toBe(100);
    expect(res1.totalCreditPercent).toBe(0);
    expect(res1.creditAmountUSD).toBe(0);

    // Case 2: 99.8% uptime (< 99.9%) -> 25% credit
    // 43200 * (1 - 0.998) = ~86.4 mins downtime
    const res2 = engine.calculateSlaBreachCredit(monthlyFee, 87, 0);
    expect(res2.uptimeCreditPercent).toBe(25);
    expect(res2.totalCreditPercent).toBe(25);
    expect(res2.creditAmountUSD).toBe(2500);

    // Case 3: 1 P1 breach (> 60m resolution) -> adds 10% credit
    const res3 = engine.calculateSlaBreachCredit(monthlyFee, 87, 1);
    expect(res3.breachCreditPercent).toBe(10);
    expect(res3.totalCreditPercent).toBe(35);
    expect(res3.creditAmountUSD).toBe(3500);
  });
});
