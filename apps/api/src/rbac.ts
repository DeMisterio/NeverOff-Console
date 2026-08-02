import { createHash } from 'node:crypto';

import {
  canDelegate,
  canManageAdmin,
  permissionMeta,
  scopeAdmits,
  type AdminIdentity,
  type BreakGlassMode,
  type Permission,
} from '@neveroff-console/shared';
import type { PoolClient } from 'pg';

import type { Actor } from './actor.js';
import { raiseAlert, writeAudit } from './audit.js';
import {
  breakGlassInvalid,
  breakGlassRequired,
  forbidden,
  outOfScope,
  validationFailed,
} from './errors.js';

/**
 * Authorisation guards.
 *
 * Every one of these throws rather than returning a boolean. That is a
 * deliberate ergonomic choice: a handler that forgets to check the return value
 * of `can()` fails open, whereas a handler that forgets to call `require()` at
 * all fails closed, because the route will simply never have been granted
 * anything. Boolean helpers exist only for shaping the UI.
 */

export function can(actor: Actor, permission: Permission): boolean {
  return actor.permissions.has(permission);
}

export function requirePermission(actor: Actor, permission: Permission): void {
  if (actor.permissions.has(permission)) return;

  const meta = permissionMeta(permission);
  throw forbidden(
    `This action requires "${meta.label}" (${permission}), which your role does not include.`,
    { required: permission, role: actor.role },
    // Reserved atoms are the ones worth alerting on: a request for one is
    // either a UI bug or someone probing the boundary.
    meta.superAdminOnly ? 'reserved_permission_attempt' : undefined,
  );
}

export function requireAny(actor: Actor, permissions: readonly Permission[]): void {
  if (permissions.some((p) => actor.permissions.has(p))) return;
  throw forbidden(`Requires one of: ${permissions.join(', ')}.`, { required: permissions });
}

/**
 * Scope check for a specific record (§1.3).
 *
 * Note the deliberate strictness in `scopeAdmits`: a scoped admin cannot act on
 * a record whose relevant attribute is unknown. If we do not know a user's
 * country, we cannot assert they fall inside a DE-only moderator's remit, so we
 * deny. That will occasionally frustrate a moderator working a case on a user
 * with no geo data — the alternative is a scope boundary that leaks whenever
 * data is missing, which is worse.
 */
export function assertInScope(
  actor: Actor,
  subject: {
    country?: string | null;
    language?: string | null;
    channelId?: string | null;
    reportCategory?: string | null;
  },
): void {
  if (scopeAdmits(actor.scope, subject)) return;
  throw outOfScope();
}

export function isInScope(
  actor: Actor,
  subject: Parameters<typeof assertInScope>[1],
): boolean {
  return scopeAdmits(actor.scope, subject);
}

/**
 * Ban-duration cap (§1.1: "ban up to MAX_BAN_DAYS_T2 days").
 * Enforced server-side; the UI's date picker limit is a convenience, not a control.
 */
export function assertBanDurationAllowed(actor: Actor, expiresAt: Date | null): void {
  const cap = actor.maxBanDays;
  if (cap === null) return; // unlimited

  if (cap === 0) {
    throw forbidden('Your role cannot issue bans.', { maxBanDays: 0, role: actor.role });
  }

  if (expiresAt === null) {
    throw forbidden(
      `Your role can only issue bans up to ${cap} days. A permanent ban is not available to you.`,
      { maxBanDays: cap },
    );
  }

  const days = Math.ceil((expiresAt.getTime() - Date.now()) / 86_400_000);
  if (days > cap) {
    throw forbidden(
      `Your role can issue bans up to ${cap} days; this one is ${days}. ` +
        'Escalate to a Platform Manager if a longer ban is warranted.',
      { maxBanDays: cap, requestedDays: days },
    );
  }
}

// ---------------------------------------------------------------------------
// Delegation (§1.3)
// ---------------------------------------------------------------------------

export async function assertCanDelegate(
  client: PoolClient,
  actor: Actor,
  target: Parameters<typeof canDelegate>[1],
  action: 'create' | 'edit' | 'delete',
): Promise<void> {
  const verdict = canDelegate(actor, target, action);
  if (verdict.ok) return;

  // A blocked escalation is a security event, not a validation error. Record it
  // even though the request failed — especially because the request failed.
  if (verdict.code === 'permission_not_held' || verdict.code === 'scope_not_contained') {
    await raiseAlert(client, {
      kind: 'privilege_escalation_attempt',
      severity: 'high',
      title: `${actor.displayName} attempted to grant beyond their own authority`,
      detail: verdict.message,
      subjectAdminId: actor.id,
      evidence: { code: verdict.code, action, target, details: verdict.details ?? {} },
    });
  }

  throw forbidden(verdict.message, { code: verdict.code, ...(verdict.details ?? {}) });
}

export function assertCanManageAdmin(actor: Actor, subject: AdminIdentity): void {
  const verdict = canManageAdmin(actor, subject);
  if (verdict.ok) return;
  throw forbidden(verdict.message, { code: verdict.code });
}

// ---------------------------------------------------------------------------
// Break glass (§1.3)
// ---------------------------------------------------------------------------

export interface BreakGlassInput {
  readonly requestId?: string;
  readonly confirmationPhrase?: string;
  readonly justification?: string;
}

/** Canonical hash of a request payload, so an approval cannot be reused for a different action. */
export function hashPayload(payload: unknown): string {
  return createHash('sha256').update(JSON.stringify(payload ?? null)).digest('hex');
}

/**
 * The phrase an admin must retype. Built from the action and the target so it
 * cannot be muscle-memoried across different users — typing
 * "PERMANENTLY BAN @alice" does not authorise banning @bob.
 */
export function expectedPhrase(action: string, targetLabel: string): string {
  return `${action.toUpperCase().replace(/[._]/g, ' ')} ${targetLabel}`;
}

export interface BreakGlassContext {
  readonly permission: Permission;
  readonly action: string;
  readonly targetType: string;
  readonly targetId: string;
  readonly targetLabel: string;
  readonly payload: unknown;
  /** Overrides the permission's default mode, e.g. bulk actions over threshold. */
  readonly forceMode?: BreakGlassMode;
}

/**
 * Verify that the extra friction a break-glass action requires has been
 * satisfied, and consume the authorisation so it cannot be replayed.
 *
 * Returns the consumed request id (if any) so the caller can reference it from
 * the audit entry.
 */
export async function requireBreakGlass(
  client: PoolClient,
  actor: Actor,
  ctx: BreakGlassContext,
  input: BreakGlassInput | undefined,
): Promise<string | null> {
  const mode: BreakGlassMode = ctx.forceMode ?? permissionMeta(ctx.permission).breakGlass;
  if (mode === 'none') return null;

  const payloadHash = hashPayload(ctx.payload);

  if (mode === 'typed_phrase') {
    const expected = expectedPhrase(ctx.action, ctx.targetLabel);
    const supplied = (input?.confirmationPhrase ?? '').trim();

    if (supplied !== expected) {
      throw breakGlassRequired(
        'This action requires a typed confirmation.',
        { mode, expectedPhrase: expected, action: ctx.action, target: ctx.targetLabel },
      );
    }

    // Recorded even though no second admin was involved, so the audit trail
    // shows the friction was applied rather than bypassed.
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO admin.break_glass_requests
         (requested_by, permission_key, mode, target_type, target_id, payload,
          payload_hash, justification, status, approved_at, consumed_at, expires_at)
       VALUES ($1, $2, 'typed_phrase', $3, $4, $5, $6, $7, 'consumed', NOW(), NOW(),
               NOW() + INTERVAL '1 minute')
       RETURNING id`,
      [
        actor.id,
        ctx.permission,
        ctx.targetType,
        ctx.targetId,
        JSON.stringify(ctx.payload ?? null),
        payloadHash,
        input?.justification?.trim() || 'Typed confirmation supplied.',
      ],
    );
    return rows[0]!.id;
  }

  // mode === 'second_admin'
  if (!input?.requestId) {
    throw breakGlassRequired(
      'This action requires approval from a second admin who independently holds this permission.',
      { mode, permission: ctx.permission, action: ctx.action, target: ctx.targetLabel },
    );
  }

  // Lock the request row so two concurrent executions cannot both consume one
  // approval. SKIP LOCKED would be wrong here: we want the second caller to
  // wait and then see status = 'consumed', not to silently miss the row.
  const { rows } = await client.query<{
    id: string;
    requested_by: string;
    status: string;
    payload_hash: string;
    permission_key: string;
    approved_by: string | null;
    expires_at: Date;
  }>(
    `SELECT id, requested_by, status, payload_hash, permission_key, approved_by, expires_at
       FROM admin.break_glass_requests
      WHERE id = $1
      FOR UPDATE`,
    [input.requestId],
  );

  const request = rows[0];
  if (!request) throw breakGlassInvalid('That approval request does not exist.');

  if (request.requested_by !== actor.id) {
    throw breakGlassInvalid('That approval was raised by a different admin.');
  }
  if (request.permission_key !== ctx.permission) {
    throw breakGlassInvalid('That approval was for a different kind of action.');
  }
  if (request.status === 'consumed') {
    throw breakGlassInvalid('That approval has already been used.');
  }
  if (request.status !== 'approved') {
    throw breakGlassInvalid(`That request is ${request.status}, not approved.`);
  }
  if (request.expires_at.getTime() <= Date.now()) {
    throw breakGlassInvalid('That approval has expired. Raise a new request.');
  }
  // The whole point of hashing: the approver saw a specific payload.
  if (request.payload_hash !== payloadHash) {
    throw breakGlassInvalid(
      'The action has changed since it was approved. Raise a new approval request.',
    );
  }

  await client.query(
    `UPDATE admin.break_glass_requests SET status = 'consumed', consumed_at = NOW() WHERE id = $1`,
    [request.id],
  );

  return request.id;
}

/** Bulk actions over the configured threshold escalate to second-admin approval (§1.3). */
export function bulkModeFor(count: number, threshold: number): BreakGlassMode | undefined {
  return count > threshold ? 'second_admin' : undefined;
}

// ---------------------------------------------------------------------------
// PII access (§8: "shown to the accessing admin as such")
// ---------------------------------------------------------------------------

/**
 * Gate and record a personal-data reveal.
 *
 * Callers must pass the case or ticket that justifies the access. §1.1 says
 * Tier 3 "cannot see PII beyond what the case requires"; making the
 * justification a required argument is how that stops being a slogan.
 */
export async function recordPiiAccess(
  client: PoolClient,
  actor: Actor,
  target: { userId: string; label: string },
  justification: { caseRef?: string; ticketId?: string; reason: string },
): Promise<void> {
  requirePermission(actor, 'users.view_pii');

  if (!justification.reason || justification.reason.trim().length < 5) {
    throw validationFailed('State why this personal data is needed. The reason is recorded.');
  }

  await writeAudit(client, actor, {
    action: 'user.pii.reveal',
    targetType: 'user',
    targetId: target.userId,
    targetLabel: target.label,
    permission: 'users.view_pii',
    note: justification.reason,
    isPiiAccess: true,
    after: {
      caseRef: justification.caseRef ?? null,
      ticketId: justification.ticketId ?? null,
    },
  });
}
