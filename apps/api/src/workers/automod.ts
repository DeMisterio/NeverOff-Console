import { getPool } from '@neveroff-console/db';

/**
 * Automod rule drift detection (§6.6).
 *
 * Compares each rule's firings today against its own median over the preceding
 * fortnight. A global threshold would flag every busy rule and nothing else;
 * the useful signal is a rule departing from its own history.
 *
 * Raises an alert and changes nothing. A rule firing five times its baseline
 * usually means the traffic changed rather than the rule — but an *enforcing*
 * rule doing that is worth a look before it actions another few hundred people.
 */
export async function detectAutomodDrift(): Promise<number> {
  const { rows } = await getPool().query<{ n: number }>(
    `SELECT admin.detect_automod_drift() AS n`,
  );
  return Number(rows[0]?.n ?? 0);
}
