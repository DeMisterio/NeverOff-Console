import { getPool } from '@neveroff-console/db';
import type { Permission } from '@neveroff-console/shared';
import type { PoolClient } from 'pg';

import { actorLabel, type Actor } from './actor.js';

/**
 * Audit writing (§7).
 *
 * The single most important property here is that the audit write shares a
 * transaction with the action it records. `writeAudit` takes a PoolClient, and
 * every mutating route runs inside `withTransaction`. So either the enforcement
 * row and its audit entry both land, or neither does. An audit log that can
 * silently miss entries when the database hiccups is not an audit log.
 *
 * The corollary is that callers must NOT catch-and-continue around writeAudit.
 * If the audit write fails the whole action must fail.
 */

export type AuditTargetType =
  | 'user' | 'admin' | 'channel' | 'case' | 'report' | 'ticket' | 'appeal'
  | 'setting' | 'role' | 'export' | 'session' | 'retention' | 'legal_hold'
  | 'dsr' | 'automod_rule' | 'system';

export interface AuditEntry {
  /** Dotted action name, e.g. 'user.ban.temp'. Keep stable; dashboards group on it. */
  readonly action: string;
  readonly targetType: AuditTargetType;
  readonly targetId?: string | null;
  readonly targetLabel?: string | null;
  readonly permission?: Permission | null;
  readonly before?: unknown;
  readonly after?: unknown;
  readonly reasonCode?: string | null;
  readonly note?: string | null;
  readonly isPiiAccess?: boolean;
  readonly breakGlassRequestId?: string | null;
  readonly origin?: 'manual' | 'automated' | 'system';
}

const INSERT = `
  INSERT INTO admin.audit_log (
    actor_admin_id, actor_label, actor_role, origin, action, permission_key,
    target_type, target_id, target_label, before_state, after_state,
    reason_code, note, ip, session_id, user_agent, request_id,
    is_pii_access, break_glass_request_id, entry_hash
  ) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11,
    $12, $13, $14, $15, $16, $17,
    $18, $19, ''
  )
  RETURNING id, occurred_at
`;

function toJson(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  return JSON.stringify(value);
}

export async function writeAudit(
  client: PoolClient,
  actor: Actor,
  entry: AuditEntry,
): Promise<{ id: string; occurredAt: Date }> {
  // entry_hash is passed as '' and overwritten by the BEFORE INSERT trigger,
  // which is also what computes prev_hash. Doing it in the trigger rather than
  // here means a row inserted by any path — including psql — is still chained.
  const result = await client.query<{ id: string; occurred_at: Date }>(INSERT, [
    actor.id,
    actorLabel(actor),
    actor.role,
    entry.origin ?? 'manual',
    entry.action,
    entry.permission ?? null,
    entry.targetType,
    entry.targetId ?? null,
    entry.targetLabel ?? null,
    toJson(entry.before),
    toJson(entry.after),
    entry.reasonCode ?? null,
    entry.note ?? null,
    actor.ip,
    actor.sessionId,
    actor.userAgent,
    actor.requestId,
    entry.isPiiAccess ?? false,
    entry.breakGlassRequestId ?? null,
  ]);

  const row = result.rows[0]!;
  return { id: String(row.id), occurredAt: row.occurred_at };
}

/**
 * Record an action taken by the system rather than by a person — an expiry
 * worker lifting a ban, an automod rule firing. §7 requires the log to
 * distinguish these from manual actions.
 */
export async function writeSystemAudit(
  client: PoolClient,
  entry: AuditEntry & { actorLabel?: string },
): Promise<void> {
  await client.query(INSERT, [
    null,
    entry.actorLabel ?? 'system',
    null,
    entry.origin ?? 'system',
    entry.action,
    entry.permission ?? null,
    entry.targetType,
    entry.targetId ?? null,
    entry.targetLabel ?? null,
    toJson(entry.before),
    toJson(entry.after),
    entry.reasonCode ?? null,
    entry.note ?? null,
    null,
    null,
    null,
    null,
    entry.isPiiAccess ?? false,
    entry.breakGlassRequestId ?? null,
  ]);
}

// ---------------------------------------------------------------------------
// Anomaly alerting (§7)
// ---------------------------------------------------------------------------

export type AlertKind =
  | 'bulk_action_out_of_hours'
  | 'unusual_pii_access_volume'
  | 'repeated_single_user_access'
  | 'mass_export'
  | 'audit_chain_broken'
  | 'failed_login_burst'
  | 'privilege_escalation_attempt'
  | 'shadow_restriction_applied'
  | 'appeal_sla_breached'
  | 'notification_delivery_failing'
  | 'worker_stalled';

export async function raiseAlert(
  client: PoolClient,
  alert: {
    kind: AlertKind;
    severity?: 'low' | 'medium' | 'high' | 'critical';
    title: string;
    detail: string;
    subjectAdminId?: string | null;
    evidence?: Record<string, unknown>;
  },
): Promise<void> {
  await client.query(
    `INSERT INTO admin.alerts (kind, severity, title, detail, subject_admin_id, evidence)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      alert.kind,
      alert.severity ?? 'medium',
      alert.title,
      alert.detail,
      alert.subjectAdminId ?? null,
      JSON.stringify(alert.evidence ?? {}),
    ],
  );
}

/**
 * Behavioural checks run after a PII access is recorded.
 *
 * Deliberately cheap and bounded: two indexed counts over the last hour and
 * day. Anything heavier belongs in a scheduled job, not on the request path —
 * a moderator should never wait on anomaly detection to see a profile.
 */
export async function checkPiiAccessAnomalies(
  client: PoolClient,
  actor: Actor,
  targetUserId: string,
): Promise<void> {
  const { rows } = await client.query<{ hour_count: string; target_count: string }>(
    `SELECT
       (SELECT count(*) FROM admin.audit_log
         WHERE actor_admin_id = $1 AND is_pii_access
           AND occurred_at > NOW() - INTERVAL '1 hour')          AS hour_count,
       (SELECT count(*) FROM admin.audit_log
         WHERE actor_admin_id = $1 AND is_pii_access
           AND target_type = 'user' AND target_id = $2
           AND occurred_at > NOW() - INTERVAL '1 day')           AS target_count`,
    [actor.id, targetUserId],
  );

  const hourCount = Number(rows[0]?.hour_count ?? 0);
  const targetCount = Number(rows[0]?.target_count ?? 0);

  if (hourCount === 50) {
    await raiseAlert(client, {
      kind: 'unusual_pii_access_volume',
      severity: 'high',
      title: `${actor.displayName} has viewed 50 users' personal data in an hour`,
      detail:
        'High-volume PII access can be legitimate during an incident, but it is also what ' +
        'scraping looks like. Confirm there is an open incident justifying this.',
      subjectAdminId: actor.id,
      evidence: { hourCount, role: actor.role },
    });
  }

  if (targetCount === 10) {
    await raiseAlert(client, {
      kind: 'repeated_single_user_access',
      severity: 'high',
      title: `${actor.displayName} has viewed the same user's data 10 times today`,
      detail:
        'Repeated access to one specific user, absent an open case, is the signature of ' +
        'personal rather than professional interest.',
      subjectAdminId: actor.id,
      evidence: { targetUserId, targetCount },
    });
  }
}

/** Fire-and-forget alert from a context with no open transaction. */
export async function raiseAlertStandalone(
  alert: Parameters<typeof raiseAlert>[1],
): Promise<void> {
  const client = await getPool().connect();
  try {
    await raiseAlert(client, alert);
  } finally {
    client.release();
  }
}
