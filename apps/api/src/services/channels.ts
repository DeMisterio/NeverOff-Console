import {
  CHANNEL_LADDER,
  validateChannelAction,
  type ChannelActionType,
} from '@neveroff-console/shared';
import type { PoolClient } from 'pg';

import type { Actor } from '../actor.js';
import { writeAudit } from '../audit.js';
import { forbidden, notFound, validationFailed } from '../errors.js';
import { requireBreakGlass, requirePermission, type BreakGlassInput } from '../rbac.js';

/**
 * Applying a channel action (§6.5), in one place.
 *
 * Same reasoning as services/enforcement.ts: the channel directory and the
 * moderation case decision panel both issue these, and two copies of the
 * takedown gate would eventually disagree.
 */

export interface ApplyChannelActionInput {
  readonly type: ChannelActionType;
  readonly reasonCode: string;
  readonly note: string;
  readonly expiresAt: Date | null;
  readonly countries?: readonly string[] | null;
  readonly breakGlass?: BreakGlassInput;
  readonly caseId?: string | null;
}

export interface ChannelTarget {
  readonly channelId: string;
  readonly name: string;
  readonly ownerId: string | null;
  readonly subscriberCount: number;
  readonly underLegalHold: boolean;
}

export async function loadChannelTarget(
  client: PoolClient,
  channelId: string,
): Promise<ChannelTarget | null> {
  const { rows } = await client.query<{
    name: string;
    owner_id: string | null;
    subscriber_count: number;
    held: boolean;
  }>(
    `SELECT c.name, c.owner_id, c.subscriber_count,
            admin.is_under_legal_hold('channel', c.id::text) AS held
       FROM public.channels c WHERE c.id = $1`,
    [channelId],
  );

  const row = rows[0];
  if (!row) return null;

  return {
    channelId,
    name: row.name,
    ownerId: row.owner_id,
    subscriberCount: Number(row.subscriber_count),
    underLegalHold: row.held,
  };
}

export interface AppliedChannelAction {
  readonly id: string;
  readonly caseRef: string;
  readonly type: ChannelActionType;
  readonly expiresAt: Date | null;
  readonly membersNotified: number;
  readonly ownerNotified: boolean;
}

export async function applyChannelAction(
  client: PoolClient,
  actor: Actor,
  target: ChannelTarget,
  input: ApplyChannelActionInput,
): Promise<AppliedChannelAction> {
  const spec = CHANNEL_LADDER[input.type];

  // --- 1. Permission ---------------------------------------------------------
  requirePermission(actor, spec.requiredPermission);

  // --- 2. Structural validity ------------------------------------------------
  const structural = validateChannelAction({
    type: input.type,
    expiresAt: input.expiresAt,
    countries: input.countries ?? null,
    note: input.note,
    reasonCode: input.reasonCode,
  });
  if (!structural.ok) {
    throw validationFailed(structural.message, { code: structural.code });
  }

  // --- 3. Legal hold ---------------------------------------------------------
  // A takedown makes the channel inaccessible, which is not a deletion — the
  // rows survive — so a hold does not block it. What a hold blocks is anything
  // that would destroy what is being preserved.
  if (target.underLegalHold && input.type === 'takedown') {
    const { rows } = await client.query<{ reference: string }>(
      `SELECT reference FROM admin.legal_holds
        WHERE subject_type = 'channel' AND subject_id = $1 AND released_at IS NULL LIMIT 1`,
      [target.channelId],
    );
    if (rows[0]) {
      // Not a refusal: takedown preserves rows. But the reviewer should know.
      await writeAudit(client, actor, {
        action: 'channel.takedown.under_hold',
        targetType: 'channel',
        targetId: target.channelId,
        targetLabel: target.name,
        note: `Taken down while under legal hold ${rows[0].reference}. Content preserved.`,
      });
    }
  }

  // --- 4. Break glass, last before the write ---------------------------------
  const breakGlassId = await requireBreakGlass(
    client,
    actor,
    {
      permission: spec.requiredPermission,
      action: input.type,
      targetType: 'channel',
      targetId: target.channelId,
      targetLabel: target.name,
      payload: {
        type: input.type,
        reasonCode: input.reasonCode,
        expiresAt: input.expiresAt?.toISOString() ?? null,
        countries: input.countries ?? null,
      },
      forceMode: spec.breakGlass === 'none' ? undefined : spec.breakGlass,
    },
    input.breakGlass,
  );

  // --- 5. Write --------------------------------------------------------------
  const { rows } = await client.query<{ id: string; case_ref: string }>(
    `INSERT INTO admin.channel_actions
       (channel_id, type, reason_code, note, issued_by, issued_by_label,
        expires_at, countries, case_id, break_glass_request_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
     RETURNING id, case_ref`,
    [
      target.channelId,
      input.type,
      input.reasonCode,
      input.note,
      actor.id,
      `${actor.displayName} <${actor.email}>`,
      input.expiresAt,
      input.countries ? [...input.countries] : null,
      input.caseId ?? null,
      breakGlassId,
    ],
  );
  const action = rows[0]!;

  // --- 6. Audit --------------------------------------------------------------
  await writeAudit(client, actor, {
    action: `channel.${input.type}`,
    targetType: 'channel',
    targetId: target.channelId,
    targetLabel: target.name,
    permission: spec.requiredPermission,
    reasonCode: input.reasonCode,
    note: input.note,
    breakGlassRequestId: breakGlassId,
    after: {
      actionId: action.id,
      caseRef: action.case_ref,
      type: input.type,
      expiresAt: input.expiresAt,
      countries: input.countries ?? null,
      subscriberCount: target.subscriberCount,
      fromCaseId: input.caseId ?? null,
    },
  });

  // --- 7. Notify -------------------------------------------------------------
  let ownerNotified = false;
  if (spec.notifiesOwner && target.ownerId) {
    await client.query(
      `INSERT INTO admin.notification_outbox (user_id, kind, payload)
       VALUES ($1, 'enforcement_applied', $2)`,
      [
        target.ownerId,
        JSON.stringify({
          case_ref: action.case_ref,
          action_type: input.type,
          reason_code: input.reasonCode,
          channel_name: target.name,
          scope: 'channel',
          expires_at: input.expiresAt,
        }),
      ],
    );
    ownerNotified = true;
    await client.query(
      `UPDATE admin.channel_actions SET owner_notified_at = NOW() WHERE id = $1`,
      [action.id],
    );
  }

  // §6.5: takedown and the other member-visible states notify subscribers with
  // the stated reason. People who joined in good faith deserve to know why a
  // channel they follow has gone.
  let membersNotified = 0;
  if (spec.notifiesMembers) {
    const notified = await client.query(
      `INSERT INTO admin.notification_outbox (user_id, kind, payload)
       SELECT cs.user_id, 'admin_message', $2
         FROM public.channel_subscribers cs
        WHERE cs.channel_id = $1
       RETURNING id`,
      [
        target.channelId,
        JSON.stringify({
          case_ref: action.case_ref,
          action_type: input.type,
          channel_name: target.name,
          reason_code: input.reasonCode,
          scope: 'channel_member_notice',
        }),
      ],
    );
    membersNotified = notified.rowCount ?? 0;

    await client.query(
      `UPDATE admin.channel_actions SET members_notified_at = NOW() WHERE id = $1`,
      [action.id],
    );
  }

  await client.query(`SELECT admin.bump_transparency_counter('channel_action', $1)`, [input.type]);

  return {
    id: action.id,
    caseRef: action.case_ref,
    type: input.type,
    expiresAt: input.expiresAt,
    membersNotified,
    ownerNotified,
  };
}

export async function reverseChannelAction(
  client: PoolClient,
  actor: Actor,
  actionId: string,
  reason: string,
): Promise<{ id: string; caseRef: string; reversedAt: Date }> {
  requirePermission(actor, 'channels.restrict');

  const { rows } = await client.query<{
    id: string;
    channel_id: string;
    type: string;
    case_ref: string;
    reversed_at: Date | null;
    name: string;
    owner_id: string | null;
  }>(
    `SELECT ca.id, ca.channel_id, ca.type, ca.case_ref, ca.reversed_at, c.name, c.owner_id
       FROM admin.channel_actions ca
       JOIN public.channels c ON c.id = ca.channel_id
      WHERE ca.id = $1
      FOR UPDATE OF ca`,
    [actionId],
  );

  const action = rows[0];
  if (!action) throw notFound('Channel action');
  if (action.reversed_at) {
    throw validationFailed('That action has already been reversed.');
  }

  // Lifting a takedown is as consequential as applying one — it puts content
  // back in front of everyone who was told it had been removed.
  if (action.type === 'takedown') {
    requirePermission(actor, 'channels.takedown');
  }

  const updated = await client.query<{ reversed_at: Date }>(
    `UPDATE admin.channel_actions
        SET reversed_at = NOW(), reversed_by = $2, reversal_reason = $3
      WHERE id = $1 RETURNING reversed_at`,
    [action.id, actor.id, reason],
  );

  await writeAudit(client, actor, {
    action: 'channel.restriction.reversed',
    targetType: 'channel',
    targetId: action.channel_id,
    targetLabel: action.name,
    permission: 'channels.restrict',
    note: reason,
    before: { actionId: action.id, type: action.type, active: true },
    after: { actionId: action.id, type: action.type, active: false },
  });

  if (action.owner_id) {
    await client.query(
      `INSERT INTO admin.notification_outbox (user_id, kind, payload)
       VALUES ($1, 'enforcement_reversed', $2)`,
      [
        action.owner_id,
        JSON.stringify({
          case_ref: action.case_ref,
          action_type: action.type,
          channel_name: action.name,
          scope: 'channel',
        }),
      ],
    );
  }

  return { id: action.id, caseRef: action.case_ref, reversedAt: updated.rows[0]!.reversed_at };
}

/** Guard used by routes: a scoped admin may only act inside their channel list. */
export function assertChannelInScope(actor: Actor, channelId: string): void {
  if (actor.scope.channelIds === null) return;
  if (!actor.scope.channelIds.includes(channelId)) {
    throw forbidden('That channel is outside your assigned scope.');
  }
}
