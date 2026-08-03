import { getPool } from '@neveroff-console/db';

/**
 * Channel governance background work (§6.5).
 *
 * Same shape as the user enforcement worker, and the same property: channel
 * restrictions lift by the passage of time, because every predicate compares
 * expires_at against NOW(). If this stops running, a frozen channel still
 * unfreezes on schedule — what stops is the owner being told, and the audit
 * entry recording that it happened.
 */

const BATCH_SIZE = 100;

export async function processExpiredChannelActions(): Promise<number> {
  const pool = getPool();
  let total = 0;

  for (;;) {
    const { rows } = await pool.query<{ processed: number }>(
      `SELECT admin.process_expired_channel_actions($1) AS processed`,
      [BATCH_SIZE],
    );
    const processed = Number(rows[0]?.processed ?? 0);
    total += processed;
    if (processed < BATCH_SIZE) break;
  }

  return total;
}

/**
 * Snapshot subscriber counts so growth has a baseline to be measured against.
 *
 * Runs hourly. The anomaly check needs at least five days of history before it
 * will say anything, which is deliberate — flagging a channel on its second day
 * of existence tells you only that it is new.
 */
export async function captureChannelGrowth(): Promise<number> {
  const { rows } = await getPool().query<{ captured: number }>(
    `SELECT admin.capture_channel_growth() AS captured`,
  );
  return Number(rows[0]?.captured ?? 0);
}

/**
 * Flag channels growing far above their own baseline, and owners with repeated
 * violations across channels.
 *
 * Both raise alerts for human review and neither restricts anything. Sudden
 * growth is also what a channel looks like when it is simply having a good
 * week, and three actioned channels might mean a bad actor or an overwhelmed
 * moderator of a large community. Automating either judgement would get it
 * wrong in exactly the cases where being wrong matters most.
 */
export async function detectChannelAnomalies(): Promise<number> {
  const pool = getPool();

  const growth = await pool.query<{ flagged: number }>(
    `SELECT admin.detect_channel_growth_anomalies() AS flagged`,
  );
  const owners = await pool.query<{ flagged: number }>(
    `SELECT admin.flag_repeat_channel_owners() AS flagged`,
  );

  return Number(growth.rows[0]?.flagged ?? 0) + Number(owners.rows[0]?.flagged ?? 0);
}
