import { getPool } from '@neveroff-console/db';

/**
 * Analytics rollup refresh (§2.6: "heavy queries run against pre-aggregated
 * rollup tables, not raw event logs").
 *
 * Every refresh recomputes whole buckets inside a lookback window rather than
 * appending deltas. That costs a little more work and buys two things worth
 * more: an event that arrives late still lands in the right bucket, and a
 * re-run after a crash cannot double-count. Analytics that silently drift are
 * worse than analytics that are briefly stale, because nobody notices drift.
 *
 * The lookback is deliberately generous — 48 hours for events and messages —
 * so a worker that was down overnight self-heals on its next run without
 * anyone triggering a rebuild.
 */

export async function refreshRollups(): Promise<number> {
  const pool = getPool();
  let total = 0;

  const [events, messages, users] = await Promise.all([
    pool.query<{ n: number }>(`SELECT admin.refresh_event_rollups(48) AS n`),
    pool.query<{ n: number }>(`SELECT admin.refresh_message_rollups(48) AS n`),
    pool.query<{ n: number }>(`SELECT admin.refresh_user_rollups(30) AS n`),
  ]);

  total += Number(events.rows[0]?.n ?? 0);
  total += Number(messages.rows[0]?.n ?? 0);
  total += Number(users.rows[0]?.n ?? 0);

  return total;
}
