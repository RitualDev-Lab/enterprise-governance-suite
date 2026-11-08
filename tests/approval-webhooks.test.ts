import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import { TwoManApprovalWebhookManager } from '../fleet/src/approval-webhooks';

describe('Phase 4: Two-Man Rule Approval Webhooks (cloud.ritualdev.in)', () => {
  it('enforces two unique approvers and prevents requester self-approval', () => {
    const manager = new TwoManApprovalWebhookManager();

    const request = manager.createApprovalRequest({
      tenantId: 'tenant_acme_corp',
      sourceSystem: 'dbshield',
      actionType: 'DROP TABLE',
      resource: 'production.customer_pii',
      payloadSummary: 'DROP TABLE customer_pii CASCADE;',
      riskScore: 95,
      riskLevel: 'CRITICAL',
      requesterId: 'usr_dev_alice',
      requesterEmail: 'alice@acme.corp',
      requiredApproversCount: 2,
    });

    expect(request.status).toBe('PENDING');

    // Requester attempting to self-approve must be rejected
    expect(() => {
      manager.recordApproval(request.requestId, {
        id: 'usr_dev_alice',
        email: 'alice@acme.corp',
        role: 'LeadDeveloper',
      });
    }).toThrow(/SeparationOfDuties/);

    // First valid approver
    const res1 = manager.recordApproval(request.requestId, {
      id: 'usr_lead_bob',
      email: 'bob@acme.corp',
      role: 'LeadDeveloper',
    });
    expect(res1.status).toBe('PARTIALLY_APPROVED');
    expect(res1.remainingApprovals).toBe(1);

    // Same approver attempting to approve second time must be rejected
    expect(() => {
      manager.recordApproval(request.requestId, {
        id: 'usr_lead_bob',
        email: 'bob@acme.corp',
        role: 'LeadDeveloper',
      });
    }).toThrow(/already recorded an approval/);

    // Second unique approver (Security Admin)
    const res2 = manager.recordApproval(request.requestId, {
      id: 'usr_sec_charlie',
      email: 'charlie@acme.corp',
      role: 'SecurityAdmin',
    });
    expect(res2.status).toBe('APPROVED');
    expect(res2.remainingApprovals).toBe(0);
  });

  it('immediately transitions request to REJECTED on rejection', () => {
    const manager = new TwoManApprovalWebhookManager();

    const request = manager.createApprovalRequest({
      tenantId: 'tenant_fintech_inc',
      sourceSystem: 'agentshield',
      actionType: 'POLICY_BYPASS',
      resource: 'kernel.ebpf.egress',
      payloadSummary: 'Disable eBPF egress filtering for pid 9988',
      riskScore: 85,
      riskLevel: 'HIGH',
      requesterId: 'usr_dev_dave',
      requesterEmail: 'dave@fintech.inc',
    });

    const rejected = manager.recordRejection(request.requestId, 'sec_officer@fintech.inc', 'Violates SOC 2 CC6.6');
    expect(rejected.status).toBe('REJECTED');
    expect(rejected.rejection?.reason).toBe('Violates SOC 2 CC6.6');
  });

  it('generates compliant Slack Block Kit message with action buttons', () => {
    const manager = new TwoManApprovalWebhookManager();

    const request = manager.createApprovalRequest({
      tenantId: 'tenant_acme',
      sourceSystem: 'dbshield',
      actionType: 'UNMASK_SSN',
      resource: 'payroll_db',
      payloadSummary: 'SELECT ssn, bank_account FROM payroll WHERE id = 1;',
      riskScore: 75,
      riskLevel: 'HIGH',
      requesterId: 'usr_eve',
      requesterEmail: 'eve@acme.com',
    });

    const slackPayload = manager.formatSlackBlockKit(request);
    expect(slackPayload.text).toContain('Two-Man Approval Required');
    expect(slackPayload.blocks.length).toBeGreaterThanOrEqual(4);

    const actionBlock = slackPayload.blocks.find((b) => b.type === 'actions');
    expect(actionBlock).toBeDefined();
  });

  it('generates Microsoft Teams Adaptive Card v1.5 payload', () => {
    const manager = new TwoManApprovalWebhookManager();

    const request = manager.createApprovalRequest({
      tenantId: 'tenant_acme',
      sourceSystem: 'gitwhisper',
      actionType: 'COMMIT_SECRET_BYPASS',
      resource: 'api_keys.ts',
      payloadSummary: 'Bypass pre-commit AST entropy check',
      riskScore: 60,
      riskLevel: 'MEDIUM',
      requesterId: 'usr_frank',
      requesterEmail: 'frank@acme.com',
    });

    const teamsCard = manager.formatTeamsAdaptiveCard(request);
    expect(teamsCard.type).toBe('message');
    expect(teamsCard.attachments[0].contentType).toBe('application/vnd.microsoft.card.adaptive');
  });

  it('verifies Slack HMAC-SHA256 signature and rejects expired timestamps', () => {
    const secret = 'slack_test_signing_secret_9988';
    const manager = new TwoManApprovalWebhookManager(secret);

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const rawBody = 'payload={"type":"block_actions","action_id":"approve"}';
    const sigBasestring = `v0:${timestamp}:${rawBody}`;
    const validSig = `v0=${crypto.createHmac('sha256', secret).update(sigBasestring).digest('hex')}`;

    expect(manager.verifySlackSignature(validSig, timestamp, rawBody)).toBe(true);

    // Replay attack with expired timestamp (> 300s)
    const oldTimestamp = (Math.floor(Date.now() / 1000) - 400).toString();
    expect(manager.verifySlackSignature(validSig, oldTimestamp, rawBody)).toBe(false);
  });
});
