import { getPool } from '@neveroff-console/db';

/**
 * Retention purge (§8).
 *
 * Each data class maps to one delete statement with an explicit legal-hold
 * exclusion. The mapping is a hand-written table rather than something derived
 * from the schema, because "which column dates this row, and what does deleting
 * it break" is a judgement per table, not a pattern.
 *
 * Two classes are deliberately absent:
 *
 *   - `audit_log` has no purge implementation. It is append-only by trigger, and
 *     an automated job that could delete audit entries would defeat the point of
 *     §7. Legally-mandated audit expiry, if it ever applies, should be an
 *     explicit, individually-approved operation rather than a background sweep.
 *   - `enforcement_actions` likewise: the safety history is what makes repeat
 *     offending visible, and its TTL floor is set high in the seeded policy.
 */

interface PurgeRule {
  readonly dataClass: string;
  /** $1 is the cutoff timestamp. Must return the deleted row count. */
  readonly sql: string;
}

const RULES: PurgeRule[] = [
  {
    dataClass: 'raw_events',
    sql: `DELETE FROM admin.telemetry_events
           WHERE occurred_at < $1
             AND (user_id IS NULL
                  OR NOT admin.is_under_legal_hold('user', user_id::text))`,
  },
  {
    dataClass: 'sessions',
    sql: `DELETE FROM admin.sessions WHERE absolute_expires_at < $1`,
  },
  {
    dataClass: 'notifications',
    sql: `DELETE FROM admin.notification_outbox
           WHERE created_at < $1 AND (sent_at IS NOT NULL OR abandoned_at IS NOT NULL)`,
  },
  {
    dataClass: 'admin_messages',
    sql: `DELETE FROM admin.admin_messages
           WHERE sent_at < $1
             AND NOT admin.is_under_legal_hold('user', user_id::text)`,
  },
  {
    dataClass: 'consent_records',
    // Only superseded records. The current consent state must never be purged —
    // losing it would mean losing the record that consent was given at all,
    // which is itself a compliance requirement.
    sql: `DELETE FROM admin.consent_records c
           WHERE c.recorded_at < $1
             AND EXISTS (
               SELECT 1 FROM admin.consent_records newer
                WHERE newer.user_id = c.user_id
                  AND newer.consent_key = c.consent_key
                  AND newer.recorded_at > c.recorded_at)`,
  },
];

export async function purgeExpiredData(): Promise<number> {
  const pool = getPool();

  const { rows: policies } = await pool.query<{
    data_class: string;
    ttl_days: number | null;
    enabled: boolean;
  }>(
    `SELECT data_class, ttl_days, enabled FROM admin.retention_policies WHERE enabled`,
  );

  const byClass = new Map(policies.map((p) => [p.data_class, p]));
  let totalPurged = 0;

  for (const rule of RULES) {
    const policy = byClass.get(rule.dataClass);
    if (!policy || policy.ttl_days === null) continue;

    const cutoff = new Date(Date.now() - policy.ttl_days * 86_400_000);

    const result = await pool.query(rule.sql, [cutoff]);
    const purged = result.rowCount ?? 0;
    totalPurged += purged;

    await pool.query(
      `UPDATE admin.retention_policies
          SET last_purge_at = NOW(), last_purge_rows = $2
        WHERE data_class = $1`,
      [rule.dataClass, purged],
    );

    if (purged > 0) {
      // Purging is a data-affecting operation and §7 wants every one recorded.
      await pool.query(
        `INSERT INTO admin.audit_log
           (actor_admin_id, actor_label, origin, action, target_type, target_id,
            target_label, after_state, note, entry_hash)
         VALUES (NULL, 'system:retention', 'system', 'retention.purged',
                 'retention', $1, $1, $2, $3, '')`,
        [
          rule.dataClass,
          JSON.stringify({ rows: purged, cutoff: cutoff.toISOString(), ttlDays: policy.ttl_days }),
          `Purged ${purged} row(s) older than ${policy.ttl_days} days. Records under legal hold were excluded.`,
        ],
      );
    }
  }

  return totalPurged;
}
