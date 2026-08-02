import { randomUUID } from 'node:crypto';

import { closePool, getPool } from '@neveroff-console/db';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * Integration tests for the guarantees enforced in the database rather than in
 * application code.
 *
 * These are the ones worth testing at this level precisely because they are
 * meant to hold regardless of which code path writes: a future ingestion
 * endpoint, a backfill script, someone in psql. Testing them through the API
 * would only prove the API respects them.
 *
 * Requires a migrated local database. The whole suite skips (rather than fails)
 * when one is not reachable, so `npm test` still works on a fresh checkout.
 */

const pool = getPool();
let dbAvailable = false;

/** Unique per run so repeated runs do not collide on usernames. */
const tag = randomUUID().slice(0, 8);
const userIds: string[] = [];
let adminA = '';
let adminB = '';

async function createUser(consentAnalytics: boolean): Promise<string> {
  const id = randomUUID();
  await pool.query(`INSERT INTO auth.users (id, email) VALUES ($1, $2)`, [
    id,
    `test-${tag}-${userIds.length}@example.test`,
  ]);
  await pool.query(
    `INSERT INTO public.profiles (id, username, display_name, public_key)
     VALUES ($1, $2, $3, 'test-key')`,
    [id, `test_${tag}_${userIds.length}`, 'Test User'],
  );
  await pool.query(
    `INSERT INTO admin.consent_records
       (user_id, consent_key, consent_version, granted, wording_shown, country)
     VALUES ($1, 'analytics', 1, $2, 'test wording', 'DE')`,
    [id, consentAnalytics],
  );
  userIds.push(id);
  return id;
}

async function createAdmin(email: string): Promise<string> {
  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO admin.admin_users
       (email, display_name, password_hash, role_key, status,
        totp_secret_encrypted, totp_enrolled_at)
     VALUES ($1, 'Test Admin', 'not-a-real-hash', 'tier2_moderation_lead', 'active',
             'encrypted', NOW())
     RETURNING id`,
    [email],
  );
  return rows[0]!.id;
}

beforeAll(async () => {
  try {
    await pool.query('SELECT 1');
    const { rows } = await pool.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM admin.schema_migrations`,
    );
    dbAvailable = Number(rows[0]?.count ?? 0) > 0;
  } catch {
    dbAvailable = false;
  }

  if (!dbAvailable) return;

  adminA = await createAdmin(`admin-a-${tag}@test.local`);
  adminB = await createAdmin(`admin-b-${tag}@test.local`);
});

afterAll(async () => {
  if (dbAvailable) {
    // profiles cascade to enforcement actions, appeals, consent and telemetry.
    await pool.query(`DELETE FROM public.profiles WHERE id = ANY($1::uuid[])`, [userIds]);
    await pool.query(`DELETE FROM auth.users WHERE id = ANY($1::uuid[])`, [userIds]);
    await pool.query(`DELETE FROM admin.admin_users WHERE email LIKE $1`, [`%-${tag}@test.local`]);
  }
  await closePool();
});

const maybe = (name: string, fn: () => Promise<void>): void => {
  it(name, async () => {
    if (!dbAvailable) {
      console.warn('  skipped — no migrated database at DATABASE_URL');
      return;
    }
    await fn();
  });
};

describe('audit log is append-only (§7)', () => {
  maybe('rejects UPDATE on an audit entry', async () => {
    const { rows } = await pool.query<{ id: string }>(
      `INSERT INTO admin.audit_log
         (actor_label, origin, action, target_type, target_label, entry_hash)
       VALUES ('test', 'system', 'test.entry', 'system', 'test', '')
       RETURNING id`,
    );

    await expect(
      pool.query(`UPDATE admin.audit_log SET note = 'tampered' WHERE id = $1`, [rows[0]!.id]),
    ).rejects.toThrow(/append-only/i);
  });

  maybe('rejects DELETE on an audit entry', async () => {
    const { rows } = await pool.query<{ id: string }>(
      `INSERT INTO admin.audit_log
         (actor_label, origin, action, target_type, target_label, entry_hash)
       VALUES ('test', 'system', 'test.entry', 'system', 'test', '')
       RETURNING id`,
    );

    await expect(
      pool.query(`DELETE FROM admin.audit_log WHERE id = $1`, [rows[0]!.id]),
    ).rejects.toThrow(/append-only/i);
  });

  maybe('chains each entry to the previous one and verifies intact', async () => {
    for (let i = 0; i < 3; i += 1) {
      await pool.query(
        `INSERT INTO admin.audit_log
           (actor_label, origin, action, target_type, target_label, entry_hash)
         VALUES ('test', 'system', 'test.chain', 'system', $1, '')`,
        [`entry-${i}`],
      );
    }

    const { rows } = await pool.query(`SELECT * FROM admin.verify_audit_chain(0)`);
    expect(rows, 'hash chain reported a break').toHaveLength(0);
  });
});

describe('telemetry consent is enforced at the storage layer (§8)', () => {
  maybe('rejects events for a user who declined analytics', async () => {
    const decliner = await createUser(false);

    await expect(
      pool.query(
        `INSERT INTO admin.telemetry_events (user_id, event_name) VALUES ($1, 'send_message')`,
        [decliner],
      ),
    ).rejects.toThrow(/analytics consent/i);
  });

  maybe('accepts events for a user who granted analytics', async () => {
    const consenter = await createUser(true);

    await expect(
      pool.query(
        `INSERT INTO admin.telemetry_events (user_id, event_name) VALUES ($1, 'send_message')`,
        [consenter],
      ),
    ).resolves.toBeDefined();
  });

  maybe('rejects any payload that could carry message content', async () => {
    const consenter = await createUser(true);

    for (const key of ['message', 'body', 'ciphertext', 'email']) {
      await expect(
        pool.query(
          `INSERT INTO admin.telemetry_events (user_id, event_name, properties)
           VALUES ($1, 'send_message', $2::jsonb)`,
          [consenter, JSON.stringify({ [key]: 'should never be stored' })],
        ),
        `payload key "${key}" should have been rejected`,
      ).rejects.toThrow(/message content or PII/i);
    }
  });
});

describe('appeal reviewer independence (§4)', () => {
  maybe('refuses a decision by the admin who issued the action', async () => {
    const user = await createUser(true);

    const { rows: actionRows } = await pool.query<{ id: string }>(
      `INSERT INTO admin.enforcement_actions
         (user_id, type, reason_code, note, issued_by, issued_by_label, expires_at)
       VALUES ($1, 'ban_temporary', 'spam.phishing', 'Seeded for the independence test.',
               $2, 'Admin A', NOW() + INTERVAL '7 days')
       RETURNING id`,
      [user, adminA],
    );

    const { rows: appealRows } = await pool.query<{ id: string }>(
      `INSERT INTO admin.appeals (action_id, user_id, body, sla_due_at)
       VALUES ($1, $2, 'Please reconsider.', NOW() + INTERVAL '72 hours')
       RETURNING id`,
      [actionRows[0]!.id, user],
    );

    await expect(
      pool.query(
        `UPDATE admin.appeals
            SET status = 'upheld', reviewed_by = $2, reviewed_at = NOW(),
                decision_note = 'Upholding my own decision.'
          WHERE id = $1`,
        [appealRows[0]!.id, adminA],
      ),
    ).rejects.toThrow(/cannot be reviewed by the admin who issued/i);
  });

  maybe('allows a decision by a different admin', async () => {
    const user = await createUser(true);

    const { rows: actionRows } = await pool.query<{ id: string }>(
      `INSERT INTO admin.enforcement_actions
         (user_id, type, reason_code, note, issued_by, issued_by_label, expires_at)
       VALUES ($1, 'ban_temporary', 'spam.phishing', 'Seeded for the independence test.',
               $2, 'Admin A', NOW() + INTERVAL '7 days')
       RETURNING id`,
      [user, adminA],
    );

    const { rows: appealRows } = await pool.query<{ id: string }>(
      `INSERT INTO admin.appeals (action_id, user_id, body, sla_due_at)
       VALUES ($1, $2, 'Please reconsider.', NOW() + INTERVAL '72 hours')
       RETURNING id`,
      [actionRows[0]!.id, user],
    );

    await expect(
      pool.query(
        `UPDATE admin.appeals
            SET status = 'overturned', reviewed_by = $2, reviewed_at = NOW(),
                decision_note = 'Reviewed independently; the original call was wrong.'
          WHERE id = $1`,
        [appealRows[0]!.id, adminB],
      ),
    ).resolves.toBeDefined();
  });
});

describe('enforcement state', () => {
  maybe('blocks sending while a ban is live and stops when it expires', async () => {
    const user = await createUser(true);

    await pool.query(
      `INSERT INTO admin.enforcement_actions
         (user_id, type, reason_code, note, issued_by_label, expires_at)
       VALUES ($1, 'ban_temporary', 'spam.phishing', 'Live ban for the expiry test.',
               'test', NOW() + INTERVAL '1 hour')`,
      [user],
    );

    const live = await pool.query<{ blocked: boolean }>(
      `SELECT admin.is_send_blocked($1) AS blocked`, [user],
    );
    expect(live.rows[0]!.blocked).toBe(true);

    // Move the expiry into the past. §11: access is restored automatically —
    // no worker involved, the same row simply evaluates differently.
    await pool.query(
      `UPDATE admin.enforcement_actions
          SET expires_at = NOW() - INTERVAL '1 minute' WHERE user_id = $1`,
      [user],
    );

    const after = await pool.query<{ blocked: boolean }>(
      `SELECT admin.is_send_blocked($1) AS blocked`, [user],
    );
    expect(after.rows[0]!.blocked).toBe(false);
  });

  maybe('refuses an automated permanent ban (§6.6 hard rule)', async () => {
    const user = await createUser(true);

    await expect(
      pool.query(
        `INSERT INTO admin.enforcement_actions
           (user_id, type, reason_code, note, issued_by_label, origin)
         VALUES ($1, 'ban_permanent', 'spam.phishing', 'Automation should not be able to do this.',
                 'automod', 'automated')`,
        [user],
      ),
    ).rejects.toThrow();
  });

  maybe('refuses a mute with no expiry', async () => {
    const user = await createUser(true);

    await expect(
      pool.query(
        `INSERT INTO admin.enforcement_actions
           (user_id, type, reason_code, note, issued_by_label)
         VALUES ($1, 'mute', 'spam.phishing', 'A mute must always end.', 'test')`,
        [user],
      ),
    ).rejects.toThrow();
  });

  maybe('keeps the projection in step with the actions', async () => {
    const user = await createUser(true);

    await pool.query(
      `INSERT INTO admin.enforcement_actions
         (user_id, type, reason_code, note, issued_by_label, expires_at)
       VALUES ($1, 'mute', 'harassment.targeted_abuse', 'Projection consistency test.',
               'test', NOW() + INTERVAL '2 hours')`,
      [user],
    );

    const { rows } = await pool.query<{ status: string; blocks_sending: boolean }>(
      `SELECT status, blocks_sending FROM admin.user_restriction_state WHERE user_id = $1`,
      [user],
    );
    expect(rows[0]?.status).toBe('muted');
    expect(rows[0]?.blocks_sending).toBe(true);
  });
});

describe('legal holds block erasure (§8)', () => {
  maybe('refuses to complete an erasure request while a hold is active', async () => {
    const user = await createUser(true);

    await pool.query(
      `INSERT INTO admin.legal_holds (subject_type, subject_id, reference, reason)
       VALUES ('user', $1, 'REF-TEST', 'Preservation for an ongoing matter.')`,
      [user],
    );

    const { rows } = await pool.query<{ id: string }>(
      `INSERT INTO admin.dsr_requests (user_id, kind, sla_due_at)
       VALUES ($1, 'erasure', NOW() + INTERVAL '30 days')
       RETURNING id`,
      [user],
    );

    await expect(
      pool.query(
        `UPDATE admin.dsr_requests
            SET status = 'completed', resolution_note = 'Erased.' WHERE id = $1`,
        [rows[0]!.id],
      ),
    ).rejects.toThrow(/legal hold/i);
  });
});

describe('enforcement policies are attached to the app tables (§11)', () => {
  maybe('has four restrictive enforcement policies in public', async () => {
    const { rows } = await pool.query<{ policyname: string; permissive: string }>(
      `SELECT policyname, permissive FROM pg_policies
        WHERE schemaname = 'public' AND policyname LIKE 'Enforcement:%'`,
    );

    expect(rows).toHaveLength(4);
    for (const row of rows) {
      expect(row.permissive, `${row.policyname} must be RESTRICTIVE`).toBe('RESTRICTIVE');
    }
  });

  maybe('leaves the app’s original message policies untouched', async () => {
    const { rows } = await pool.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'messages'
          AND policyname NOT LIKE 'Enforcement:%'`,
    );
    expect(Number(rows[0]!.count)).toBeGreaterThanOrEqual(3);
  });

  maybe('never grants the client roles access to the admin schema', async () => {
    const { rows } = await pool.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM information_schema.role_table_grants
        WHERE table_schema = 'admin' AND grantee IN ('anon', 'authenticated')`,
    );
    expect(Number(rows[0]!.count)).toBe(0);
  });
});
