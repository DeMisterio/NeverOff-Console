import {
  LADDER,
  reasonMeta,
  validateProposedAction,
  type EnforcementActionType,
  type RestrictableFeature,
} from '@neveroff-console/shared';
import type { PoolClient } from 'pg';

import type { Actor } from '../actor.js';
import { raiseAlert, writeAudit } from '../audit.js';
import { forbidden, underLegalHold, validationFailed } from '../errors.js';
import {
  assertBanDurationAllowed,
  requireBreakGlass,
  requirePermission,
  type BreakGlassInput,
} from '../rbac.js';

/**
 * Applying an enforcement action, in one place.
 *
 * There are two routes that issue enforcement — the user profile panel and the
 * moderation case decision panel — and they must behave identically. If the
 * ban-length cap or the isolated-category refusal existed in one and not the
 * other, the weaker path would be a permission bypass rather than a cosmetic
 * inconsistency. So both call this.
 *
 * The ordering below is deliberate: every cheap rejection happens before any
 * side effect, and break-glass is the last check before the write. Nobody
 * should burn a second admin's approval only to be told their reason code was
 * invalid.
 */

export interface ApplyEnforcementInput {
  readonly type: EnforcementActionType;
  readonly reasonCode: string;
  readonly note: string;
  readonly expiresAt: Date | null;
  readonly restrictedFeatures?: readonly RestrictableFeature[] | null;
  readonly rateLimitPerMinute?: number | null;
  readonly contentRemovalScope?: 'none' | 'last_24h' | 'last_30d' | 'all';
  readonly notifyUser?: boolean;
  readonly breakGlass?: BreakGlassInput;
  /** Links the action back to the case that produced it. */
  readonly caseId?: string | null;
}

export interface AppliedEnforcement {
  readonly id: string;
  readonly caseRef: string;
  readonly type: EnforcementActionType;
  readonly expiresAt: Date | null;
  readonly userNotified: boolean;
  readonly contentRemoved: { messages: number; channelPosts: number };
}

export interface EnforcementTarget {
  readonly userId: string;
  readonly username: string;
  readonly underLegalHold: boolean;
}

const REMOVAL_INTERVAL: Record<string, string | null> = {
  last_24h: '24 hours',
  last_30d: '30 days',
  all: null,
};

export async function applyEnforcement(
  client: PoolClient,
  actor: Actor,
  target: EnforcementTarget,
  input: ApplyEnforcementInput,
): Promise<AppliedEnforcement> {
  const spec = LADDER[input.type];
  const removalScope = input.contentRemovalScope ?? 'none';
  const targetLabel = `@${target.username}`;

  // --- 1. Permission for this specific rung ---------------------------------
  requirePermission(actor, spec.requiredPermission);

  // --- 2. Reason must exist and belong in general tooling -------------------
  const reason = reasonMeta(input.reasonCode);
  if (!reason) {
    throw validationFailed(`"${input.reasonCode}" is not a reason code in the catalogue.`, {
      reasonCode: input.reasonCode,
    });
  }
  if (reason.isolated) {
    throw forbidden(
      'That reason belongs to the child safety pipeline and cannot be used here. ' +
        'Route the case through the isolated queue instead.',
      { reasonCode: input.reasonCode },
    );
  }
  if (reason.category === 'self_harm') {
    throw forbidden(
      'Self-harm reports route to the safety escalation path, not to enforcement. ' +
        'A person disclosing risk is not committing a violation.',
      { reasonCode: input.reasonCode },
    );
  }

  // --- 3. Structural validity ----------------------------------------------
  const structural = validateProposedAction({
    type: input.type,
    expiresAt: input.expiresAt,
    restrictedFeatures: input.restrictedFeatures ?? null,
    rateLimitPerMinute: input.rateLimitPerMinute ?? null,
    reasonCode: input.reasonCode,
    note: input.note,
  });
  if (!structural.ok) {
    throw validationFailed(structural.message, { code: structural.code });
  }

  // --- 4. Role ban cap ------------------------------------------------------
  if (input.type === 'ban_temporary') assertBanDurationAllowed(actor, input.expiresAt);
  if (input.type === 'ban_permanent') assertBanDurationAllowed(actor, null);

  // --- 5. Legal hold --------------------------------------------------------
  if (target.underLegalHold) {
    if (input.type === 'account_deletion') {
      throw underLegalHold(
        `${targetLabel} is under an active legal hold. Deletion is blocked until it is released.`,
      );
    }
    if (removalScope !== 'none') {
      throw underLegalHold(
        `${targetLabel} is under an active legal hold. Content removal would destroy material ` +
          'that is being preserved.',
      );
    }
  }

  // --- 6. Break glass, last before the write --------------------------------
  // Content removal against end-to-end encrypted messages is irreversible —
  // there is no copy the server could restore from — so it forces a typed
  // confirmation even on rungs that would otherwise need none.
  const forceMode =
    removalScope !== 'none' && spec.breakGlass === 'none' ? ('typed_phrase' as const) : undefined;

  const breakGlassId = await requireBreakGlass(
    client,
    actor,
    {
      permission: spec.requiredPermission,
      action: input.type,
      targetType: 'user',
      targetId: target.userId,
      targetLabel,
      payload: {
        type: input.type,
        reasonCode: input.reasonCode,
        expiresAt: input.expiresAt?.toISOString() ?? null,
        contentRemovalScope: removalScope,
      },
      forceMode,
    },
    input.breakGlass,
  );

  // --- 7. Write -------------------------------------------------------------
  const { rows } = await client.query<{ id: string; case_ref: string }>(
    `INSERT INTO admin.enforcement_actions
       (user_id, type, reason_code, note, issued_by, issued_by_label,
        expires_at, restricted_features, rate_limit_per_minute,
        content_removal_scope, origin, break_glass_request_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'manual', $11)
     RETURNING id, case_ref`,
    [
      target.userId,
      input.type,
      input.reasonCode,
      input.note,
      actor.id,
      `${actor.displayName} <${actor.email}>`,
      input.expiresAt,
      input.restrictedFeatures ?? null,
      input.rateLimitPerMinute ?? null,
      removalScope,
      breakGlassId,
    ],
  );
  const action = rows[0]!;

  // --- 8. Content removal, only if explicitly chosen ------------------------
  let removedMessages = 0;
  let removedPosts = 0;

  if (removalScope !== 'none') {
    const interval = REMOVAL_INTERVAL[removalScope];

    const messages = interval
      ? await client.query(
          `DELETE FROM public.messages WHERE sender_id = $1 AND created_at >= NOW() - $2::interval`,
          [target.userId, interval],
        )
      : await client.query(`DELETE FROM public.messages WHERE sender_id = $1`, [target.userId]);

    const posts = interval
      ? await client.query(
          `DELETE FROM public.channel_posts
            WHERE author_id = $1 AND created_at >= NOW() - $2::interval`,
          [target.userId, interval],
        )
      : await client.query(`DELETE FROM public.channel_posts WHERE author_id = $1`, [
          target.userId,
        ]);

    removedMessages = messages.rowCount ?? 0;
    removedPosts = posts.rowCount ?? 0;
  }

  // --- 9. Audit -------------------------------------------------------------
  await writeAudit(client, actor, {
    action: `user.enforcement.${input.type}`,
    targetType: 'user',
    targetId: target.userId,
    targetLabel,
    permission: spec.requiredPermission,
    reasonCode: input.reasonCode,
    note: input.note,
    breakGlassRequestId: breakGlassId,
    after: {
      actionId: action.id,
      caseRef: action.case_ref,
      type: input.type,
      expiresAt: input.expiresAt,
      restrictedFeatures: input.restrictedFeatures ?? null,
      rateLimitPerMinute: input.rateLimitPerMinute ?? null,
      contentRemovalScope: removalScope,
      removedMessages,
      removedChannelPosts: removedPosts,
      fromCaseId: input.caseId ?? null,
    },
  });

  // --- 10. Notify the user (§3.3, §4) ---------------------------------------
  // `silent` is the shadow-restriction case: telling them defeats the mechanism.
  const shouldNotify =
    (input.notifyUser ?? true) && spec.visibility === 'notified' && spec.type !== 'note';

  if (shouldNotify) {
    await client.query(
      `INSERT INTO admin.notification_outbox (user_id, kind, payload, related_action_id)
       VALUES ($1, $2, $3, $4)`,
      [
        target.userId,
        input.type === 'warning' ? 'warning_issued' : 'enforcement_applied',
        JSON.stringify({
          case_ref: action.case_ref,
          action_type: input.type,
          reason_code: input.reasonCode,
          policy_clause: reason.policyClause,
          expires_at: input.expiresAt,
          appealable: reason.appealable,
        }),
        action.id,
      ],
    );
  }

  // --- 11. Shadow restrictions are flagged for periodic review --------------
  if (input.type === 'shadow_restriction') {
    await raiseAlert(client, {
      kind: 'shadow_restriction_applied',
      severity: 'medium',
      title: `${actor.displayName} shadow-restricted ${targetLabel}`,
      detail:
        'Shadow restriction is deceptive by construction and §3.3 requires it be used ' +
        'sparingly. This entry exists so the practice can be reviewed in aggregate.',
      subjectAdminId: actor.id,
      evidence: {
        caseRef: action.case_ref,
        reasonCode: input.reasonCode,
        justification: input.note,
        expiresAt: input.expiresAt,
      },
    });
  }

  return {
    id: action.id,
    caseRef: action.case_ref,
    type: input.type,
    expiresAt: input.expiresAt,
    userNotified: shouldNotify,
    contentRemoved: { messages: removedMessages, channelPosts: removedPosts },
  };
}

/** Load the fields `applyEnforcement` needs, with a scope-safe lookup. */
export async function loadEnforcementTarget(
  client: PoolClient,
  userId: string,
): Promise<(EnforcementTarget & { country: string | null }) | null> {
  const { rows } = await client.query<{
    username: string;
    country: string | null;
    under_legal_hold: boolean;
  }>(
    `SELECT username, country, under_legal_hold FROM admin.user_directory WHERE id = $1`,
    [userId],
  );

  const row = rows[0];
  if (!row) return null;

  return {
    userId,
    username: row.username,
    underLegalHold: row.under_legal_hold,
    country: row.country,
  };
}
