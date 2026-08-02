import { getPool, withTransaction } from '@neveroff-console/db';

import { sendDataMessage, toDataPayload } from '../services/fcm.js';

/**
 * Deliver queued user notifications (§3.3, §4).
 *
 * Retry policy is exponential with a hard stop: a user who cannot be reached
 * after eight attempts across roughly a day is not going to be reached, and
 * retrying forever turns the outbox into an ever-growing table of failures that
 * masks the ones worth looking at.
 *
 * A user with no push token is not a failure — plenty of accounts have never
 * granted notification permission. Those are marked abandoned immediately with
 * a clear reason, because the enforcement status is also readable from the
 * app's own status endpoint the moment they next open it.
 */

const BATCH_SIZE = 50;
const MAX_ATTEMPTS = 8;

/** 1m, 5m, 15m, 1h, 3h, 6h, 12h, then give up. */
const BACKOFF_MINUTES = [1, 5, 15, 60, 180, 360, 720];

export async function deliverNotifications(): Promise<number> {
  const pool = getPool();

  // Claim a batch. SKIP LOCKED means a second worker takes different rows
  // rather than blocking on ours.
  const claimed = await withTransaction(async (client) => {
    const { rows } = await client.query<{
      id: string;
      user_id: string;
      kind: string;
      payload: Record<string, unknown>;
      locale: string;
      attempts: number;
      fcm_token: string | null;
    }>(
      `SELECT o.id, o.user_id, o.kind, o.payload, o.locale, o.attempts, p.fcm_token
         FROM admin.notification_outbox o
         JOIN public.profiles p ON p.id = o.user_id
        WHERE o.sent_at IS NULL
          AND o.abandoned_at IS NULL
          AND o.next_attempt_at <= NOW()
        ORDER BY o.next_attempt_at ASC
        LIMIT $1
        FOR UPDATE OF o SKIP LOCKED`,
      [BATCH_SIZE],
    );

    // Bump attempts inside the claiming transaction so a crash mid-delivery
    // cannot produce an infinite retry loop on the same row.
    if (rows.length > 0) {
      await client.query(
        `UPDATE admin.notification_outbox
            SET attempts = attempts + 1,
                next_attempt_at = NOW() + INTERVAL '30 minutes'
          WHERE id = ANY($1::uuid[])`,
        [rows.map((r) => r.id)],
      );
    }

    return rows;
  });

  if (claimed.length === 0) return 0;

  let delivered = 0;

  for (const item of claimed) {
    if (!item.fcm_token) {
      await pool.query(
        `UPDATE admin.notification_outbox
            SET abandoned_at = NOW(),
                last_error = 'No push token registered for this account.'
          WHERE id = $1`,
        [item.id],
      );
      continue;
    }

    const result = await sendDataMessage(
      item.fcm_token,
      toDataPayload(item.kind, { ...item.payload, locale: item.locale }),
    );

    if (result.ok) {
      await pool.query(
        `UPDATE admin.notification_outbox SET sent_at = NOW(), last_error = NULL WHERE id = $1`,
        [item.id],
      );
      delivered += 1;
      continue;
    }

    const attempts = item.attempts + 1;
    const giveUp = result.tokenInvalid || attempts >= MAX_ATTEMPTS;

    if (giveUp) {
      await withTransaction(async (client) => {
        await client.query(
          `UPDATE admin.notification_outbox
              SET abandoned_at = NOW(), last_error = $2 WHERE id = $1`,
          [item.id, result.error ?? 'Delivery failed'],
        );

        // A dead token should not keep being tried by every future
        // notification either.
        if (result.tokenInvalid) {
          await client.query(
            `UPDATE public.profiles SET fcm_token = NULL WHERE id = $1 AND fcm_token = $2`,
            [item.user_id, item.fcm_token],
          );
        }
      });
      continue;
    }

    const backoff = BACKOFF_MINUTES[Math.min(attempts - 1, BACKOFF_MINUTES.length - 1)]!;
    await pool.query(
      `UPDATE admin.notification_outbox
          SET next_attempt_at = NOW() + make_interval(mins => $2::int), last_error = $3
        WHERE id = $1`,
      [item.id, backoff, result.error ?? 'Delivery failed'],
    );
  }

  // A broad delivery failure is worth surfacing: §4 depends on users actually
  // being told why they were restricted.
  const { rows: failureRows } = await pool.query<{ failing: string }>(
    `SELECT count(*)::text AS failing
       FROM admin.notification_outbox
      WHERE abandoned_at IS NULL AND sent_at IS NULL AND attempts >= 3`,
  );

  if (Number(failureRows[0]?.failing ?? 0) > 25) {
    await pool.query(
      `INSERT INTO admin.alerts (kind, severity, title, detail, evidence)
       SELECT 'notification_delivery_failing', 'high',
              'User notifications are not being delivered',
              'More than 25 enforcement notifications have failed three or more times. Users '
              || 'are being restricted without being told why, which §4 requires.',
              jsonb_build_object('failing', $1::int)
        WHERE NOT EXISTS (
          SELECT 1 FROM admin.alerts
           WHERE kind = 'notification_delivery_failing'
             AND acknowledged_at IS NULL
             AND raised_at > NOW() - INTERVAL '6 hours')`,
      [Number(failureRows[0]?.failing ?? 0)],
    );
  }

  return delivered;
}
