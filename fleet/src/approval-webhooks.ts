import crypto from 'node:crypto';

export type ApprovalStatus = 'PENDING' | 'PARTIALLY_APPROVED' | 'APPROVED' | 'REJECTED' | 'EXPIRED';

export interface ApprovalRequest {
  requestId: string;
  tenantId: string;
  sourceSystem: 'dbshield' | 'agentshield' | 'gitwhisper';
  actionType: string; // e.g. "DROP TABLE", "UNMASK_PII", "POLICY_BYPASS"
  resource: string;
  payloadSummary: string;
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  requesterId: string;
  requesterEmail: string;
  createdAt: number;
  expiresAt: number;
  requiredApproversCount: number; // default: 2 (Two-Man Rule)
  approvals: Array<{
    approverId: string;
    approverEmail: string;
    role: string;
    timestamp: number;
  }>;
  rejection?: {
    rejectedBy: string;
    reason: string;
    timestamp: number;
  };
  status: ApprovalStatus;
}

export interface SlackBlockKitPayload {
  channel?: string;
  text: string;
  blocks: Array<Record<string, unknown>>;
}

export interface TeamsAdaptiveCardPayload {
  type: 'message';
  attachments: Array<{
    contentType: 'application/vnd.microsoft.card.adaptive';
    content: Record<string, unknown>;
  }>;
}

/**
 * Enterprise Two-Man Rule Approval Webhook Manager for cloud.ritualdev.in.
 * Dispatches interactive action cards to Slack and Microsoft Teams for high-risk
 * agent actions and verifies cryptographic webhook callbacks.
 */
export class TwoManApprovalWebhookManager {
  private readonly requests: Map<string, ApprovalRequest> = new Map();
  private readonly slackSigningSecret?: string;

  constructor(slackSigningSecret?: string) {
    this.slackSigningSecret = slackSigningSecret || process.env.SLACK_SIGNING_SECRET;
  }

  /**
   * Creates a new approval request requiring the Two-Man Rule.
   */
  public createApprovalRequest(input: {
    tenantId: string;
    sourceSystem: 'dbshield' | 'agentshield' | 'gitwhisper';
    actionType: string;
    resource: string;
    payloadSummary: string;
    riskScore: number;
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    requesterId: string;
    requesterEmail: string;
    ttlMs?: number;
    requiredApproversCount?: number;
  }): ApprovalRequest {
    const requestId = `appr_${crypto.randomBytes(8).toString('hex')}`;
    const now = Date.now();
    const ttlMs = input.ttlMs || 15 * 60 * 1000; // 15 min

    const request: ApprovalRequest = {
      requestId,
      tenantId: input.tenantId,
      sourceSystem: input.sourceSystem,
      actionType: input.actionType,
      resource: input.resource,
      payloadSummary: input.payloadSummary,
      riskScore: input.riskScore,
      riskLevel: input.riskLevel,
      requesterId: input.requesterId,
      requesterEmail: input.requesterEmail,
      createdAt: now,
      expiresAt: now + ttlMs,
      requiredApproversCount: input.requiredApproversCount || 2,
      approvals: [],
      status: 'PENDING',
    };

    this.requests.set(requestId, request);
    return request;
  }

  /**
   * Records an approval from an authorized security lead.
   * Enforces that the original requester cannot approve their own action,
   * and that two unique approvers are required to reach 'APPROVED' status.
   */
  public recordApproval(
    requestId: string,
    approver: { id: string; email: string; role: string },
  ): { status: ApprovalStatus; remainingApprovals: number } {
    const request = this.requests.get(requestId);
    if (!request) {
      throw new Error(`[TwoManApproval] Request '${requestId}' not found`);
    }

    if (request.status === 'REJECTED' || request.status === 'EXPIRED') {
      throw new Error(`[TwoManApproval] Request is already in terminal state '${request.status}'`);
    }

    if (Date.now() > request.expiresAt) {
      request.status = 'EXPIRED';
      return { status: 'EXPIRED', remainingApprovals: 0 };
    }

    // Separation of duties: requester cannot self-approve
    if (approver.id === request.requesterId || approver.email === request.requesterEmail) {
      throw new Error('[TwoManApproval:SeparationOfDuties] Requester cannot approve their own request');
    }

    // Approver cannot approve twice
    const alreadyApproved = request.approvals.some(
      (a) => a.approverId === approver.id || a.approverEmail === approver.email,
    );
    if (alreadyApproved) {
      throw new Error('[TwoManApproval] Approver has already recorded an approval for this request');
    }

    request.approvals.push({
      approverId: approver.id,
      approverEmail: approver.email,
      role: approver.role,
      timestamp: Date.now(),
    });

    const remaining = request.requiredApproversCount - request.approvals.length;
    if (remaining <= 0) {
      request.status = 'APPROVED';
    } else {
      request.status = 'PARTIALLY_APPROVED';
    }

    return { status: request.status, remainingApprovals: Math.max(0, remaining) };
  }

  /**
   * Records an explicit rejection.
   */
  public recordRejection(requestId: string, rejectedBy: string, reason: string): ApprovalRequest {
    const request = this.requests.get(requestId);
    if (!request) {
      throw new Error(`[TwoManApproval] Request '${requestId}' not found`);
    }

    request.status = 'REJECTED';
    request.rejection = {
      rejectedBy,
      reason,
      timestamp: Date.now(),
    };

    return request;
  }

  /**
   * Formats the approval request into Slack Block Kit with interactive buttons.
   */
  public formatSlackBlockKit(request: ApprovalRequest): SlackBlockKitPayload {
    const urgencyEmoji = request.riskLevel === 'CRITICAL' ? '🚨' : request.riskLevel === 'HIGH' ? '⚠️' : 'ℹ️';

    return {
      text: `${urgencyEmoji} [${request.riskLevel}] Two-Man Approval Required: ${request.actionType} on ${request.resource}`,
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: `${urgencyEmoji} Security Approval Required (Two-Man Rule)`,
            emoji: true,
          },
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*System:*\n\`${request.sourceSystem}\`` },
            { type: 'mrkdwn', text: `*Risk Score:*\n\`${request.riskScore} (${request.riskLevel})\`` },
            { type: 'mrkdwn', text: `*Resource:*\n\`${request.resource}\`` },
            { type: 'mrkdwn', text: `*Requester:*\n${request.requesterEmail}` },
          ],
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Payload / Mutation Diff:*\n\`\`\`${request.payloadSummary}\`\`\``,
          },
        },
        {
          type: 'context',
          elements: [
            {
              type: 'mrkdwn',
              text: `*Approvals:* ${request.approvals.length}/${request.requiredApproversCount} completed. Expires in < 15 minutes.`,
            },
          ],
        },
        {
          type: 'actions',
          elements: [
            {
              type: 'button',
              text: { type: 'plain_text', text: 'Approve Action' },
              style: 'primary',
              value: request.requestId,
              action_id: `approve_${request.requestId}`,
            },
            {
              type: 'button',
              text: { type: 'plain_text', text: 'Reject' },
              style: 'danger',
              value: request.requestId,
              action_id: `reject_${request.requestId}`,
            },
          ],
        },
      ],
    };
  }

  /**
   * Formats the approval request into Microsoft Teams Adaptive Card v1.5.
   */
  public formatTeamsAdaptiveCard(request: ApprovalRequest): TeamsAdaptiveCardPayload {
    return {
      type: 'message',
      attachments: [
        {
          contentType: 'application/vnd.microsoft.card.adaptive',
          content: {
            $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
            version: '1.5',
            type: 'AdaptiveCard',
            body: [
              {
                type: 'TextBlock',
                text: '🛡️ RitualDev Governance: Two-Man Approval Required',
                weight: 'Bolder',
                size: 'Medium',
              },
              {
                type: 'FactSet',
                facts: [
                  { title: 'System', value: request.sourceSystem },
                  { title: 'Action', value: request.actionType },
                  { title: 'Resource', value: request.resource },
                  { title: 'Requester', value: request.requesterEmail },
                  { title: 'Risk Score', value: `${request.riskScore} (${request.riskLevel})` },
                  { title: 'Required Approvals', value: `${request.approvals.length}/${request.requiredApproversCount}` },
                ],
              },
              {
                type: 'TextBlock',
                text: request.payloadSummary,
                wrap: true,
                fontType: 'Monospace',
              },
            ],
            actions: [
              {
                type: 'Action.Submit',
                title: 'Approve',
                data: { action: 'approve', requestId: request.requestId },
              },
              {
                type: 'Action.Submit',
                title: 'Reject',
                data: { action: 'reject', requestId: request.requestId },
              },
            ],
          },
        },
      ],
    };
  }

  /**
   * Verifies Slack HMAC-SHA256 request signature.
   */
  public verifySlackSignature(signature: string, timestamp: string, rawBody: string): boolean {
    if (!this.slackSigningSecret) return true; // Bypass in unconfigured test mode

    const time = Number.parseInt(timestamp, 10);
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - time) > 300) {
      return false; // Replay attack prevention (> 5 min old)
    }

    const sigBasestring = `v0:${timestamp}:${rawBody}`;
    const mySignature = `v0=${crypto
      .createHmac('sha256', this.slackSigningSecret)
      .update(sigBasestring, 'utf8')
      .digest('hex')}`;

    return crypto.timingSafeEqual(Buffer.from(mySignature, 'utf8'), Buffer.from(signature, 'utf8'));
  }

  public getRequest(requestId: string): ApprovalRequest | undefined {
    return this.requests.get(requestId);
  }
}
