import { getPool } from '@neveroff-console/db';

/**
 * Enforcement expiry and appeal SLA escalation.
 *
 * Both are thin wrappers over the database functions from migration 0009. The
 * work is done in SQL rather than here so that the lift, its audit entry and
 * the user's notification are written in one transaction — a crash halfway
 * cannot leave a user notified of a restoration that did not happen, or
 * restored with no record of why.
 *
 * §11 acceptance criterion: "the ban lifts → access is automatically restored
 * on expiry". Worth restating precisely, because it is easy to misread what
 * this job does: access is restored by the *passage of time*, since every
 * access check compares expires_at against NOW(). This job records that the
 * expiry happened and tells the user. If it stops running, users are still
 * correctly unbanned — they just are not notified.
 */

const BATCH_SIZE = 100;

export async function processExpiredEnforcements(): Promise<number> {
  const pool = getPool();
  let total = 0;

  // Drain in batches rather than one giant transaction: a backlog of ten
  // thousand expiries should not hold locks for minutes.
  for (;;) {
    const { rows } = await pool.query<{ processed: number }>(
      `SELECT admin.process_expired_enforcements($1) AS processed`,
      [BATCH_SIZE],
    );
    const processed = Number(rows[0]?.processed ?? 0);
    total += processed;
    if (processed < BATCH_SIZE) break;
  }

  return total;
}

export async function escalateAppeals(): Promise<number> {
  const { rows } = await getPool().query<{ escalated: number }>(
    `SELECT admin.escalate_breached_appeals($1) AS escalated`,
    [BATCH_SIZE],
  );
  return Number(rows[0]?.escalated ?? 0);
}
