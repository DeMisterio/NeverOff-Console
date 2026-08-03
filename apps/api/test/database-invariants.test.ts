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

/**
 * Assigned in beforeAll, not at module scope.
 *
 * `getPool()` throws when DATABASE_URL is unset, and calling it during
 * collection killed the whole suite before `beforeAll` could skip. A Proxy was
 * the wrong fix: pg's Pool.query mutates `this` for its internal bookkeeping,
 * and those writes hit the proxy's default set trap — landing on the dummy
 * target rather than the real pool. The accounting corrupted, clients were
 * never returned, and the pool deadlocked after a handful of tests.
 *
 * Every helper below runs inside a test or hook, so a plain lazy binding is
 * both sufficient and honest.
 */
let pool!: ReturnType<typeof getPool>;
let dbAvailable = false;

/** Unique per run so repeated runs do not collide on usernames. */
const tag = randomUUID().slice(0, 8);
const userIds: string[] = [];

/**
 * Incremented synchronously on entry to createUser.
 *
 * Deriving the email from userIds.length raced: several createUser calls in a
 * Promise.all all read the same length before any of them had pushed, so they
 * generated identical addresses and collided on auth.users' unique index.
 */
let userSeq = 0;
let adminA = '';
let adminB = '';

async function createUser(consentAnalytics: boolean): Promise<string> {
  const id = randomUUID();
  const seq = userSeq++;
  await pool.query(`INSERT INTO auth.users (id, email) VALUES ($1, $2)`, [
    id,
    `test-${tag}-${seq}@example.test`,
  ]);
  await pool.query(
    `INSERT INTO public.profiles (id, username, display_name, public_key)
     VALUES ($1, $2, $3, 'test-key')`,
    [id, `test_${tag}_${seq}`, 'Test User'],
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
    if (!process.env.DATABASE_URL) {
      dbAvailable = false;
      return;
    }
    pool = getPool();
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
  if (!pool) return;
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

  maybe('lets an account with enforcement history be erased (§8, §11)', async () => {
    const user = await createUser(true);

    await pool.query(
      `INSERT INTO admin.enforcement_actions
         (user_id, type, reason_code, note, issued_by_label, expires_at)
       VALUES ($1, 'ban_temporary', 'spam.phishing',
               'Active ban, so the projection row exists at delete time.',
               'test', NOW() + INTERVAL '7 days')`,
      [user],
    );

    // The projection trigger used to re-insert a row for the profile being
    // deleted, and the FK rejected it — so erasure failed for exactly the
    // accounts anyone would want to erase. Found by teardown, not by a test.
    await expect(
      pool.query(`DELETE FROM public.profiles WHERE id = $1`, [user]),
    ).resolves.toBeDefined();

    const { rows } = await pool.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM admin.user_restriction_state WHERE user_id = $1`,
      [user],
    );
    expect(Number(rows[0]!.count)).toBe(0);
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
  maybe('attaches every enforcement policy as RESTRICTIVE', async () => {
    const { rows } = await pool.query<{ policyname: string; permissive: string }>(
      `SELECT policyname, permissive FROM pg_policies
        WHERE schemaname = 'public' AND policyname LIKE 'Enforcement:%'
        ORDER BY policyname`,
    );

    // Named rather than counted: a count says nothing about which guarantee
    // went missing, and it goes stale every time a migration adds one — as it
    // did when 0013 brought the two channel policies.
    expect(rows.map((r) => r.policyname)).toEqual([
      'Enforcement: blocked users cannot post to channels',
      'Enforcement: blocked users cannot send messages',
      'Enforcement: blocked users cannot subscribe',
      'Enforcement: frozen channels cannot receive posts',
      'Enforcement: restricted channels cannot gain subscribers',
      'Enforcement: restricted users cannot create channels',
    ]);

    // PERMISSIVE would silently widen access instead of narrowing it — the
    // policies would be OR-ed with the app's own rather than AND-ed.
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

// ---------------------------------------------------------------------------
// Report intake and clustering (§6.3)
// ---------------------------------------------------------------------------

/**
 * Submit a report as a specific end user, through the real intake RPC.
 *
 * `auth.uid()` in the local shim reads the `app.current_user_id` GUC, so
 * impersonation is a set_config away. Going through submit_report rather than
 * inserting rows directly means these tests exercise clustering, coordination
 * detection and priority scoring for real.
 */
async function report(
  reporterId: string,
  targetType: string,
  targetId: string,
  reasonCode: string,
  evidence: string | null = null,
): Promise<Record<string, unknown>> {
  // A dedicated client, not pool.query.
  //
  // set_config(..., false) sets the value for the *session*, and consecutive
  // pool.query() calls are not guaranteed to land on the same connection — so
  // the impersonation could be applied to one client while submit_report ran on
  // another, where auth.uid() is null. It happened to work whenever the pool
  // handed back the same idle client, which is the worst kind of bug.
  const client = await pool.connect();
  try {
    await client.query(`SELECT set_config('app.current_user_id', $1, false)`, [reporterId]);
    const { rows } = await client.query<{ result: Record<string, unknown> }>(
      `SELECT public.submit_report($1, $2, $3, NULL, 'just_report', $4, NULL, FALSE, NULL) AS result`,
      [targetType, targetId, reasonCode, evidence],
    );
    return rows[0]!.result;
  } finally {
    await client.query(`SELECT set_config('app.current_user_id', '', false)`).catch(() => {});
    client.release();
  }
}

describe('report clustering (§6.3, §11)', () => {
  maybe('collapses many reports on one target into a single case', async () => {
    const victim = await createUser(true);
    const reporters = await Promise.all([
      createUser(true), createUser(true), createUser(true), createUser(true), createUser(true),
    ]);

    for (const reporter of reporters) {
      await report(reporter, 'user', victim, 'harassment.targeted_abuse');
    }

    const { rows } = await pool.query<{ count: string; reporters: string }>(
      `SELECT count(*)::text AS count,
              COALESCE(max(distinct_reporter_count), 0)::text AS reporters
         FROM admin.cases WHERE target_type = 'user' AND target_id = $1`,
      [victim],
    );

    // §11: "Five users report the same channel → one clustered case, not five."
    expect(Number(rows[0]!.count)).toBe(1);
    expect(Number(rows[0]!.reporters)).toBe(5);
  });

  maybe('counts one reporter reporting twice as a single report', async () => {
    const victim = await createUser(true);
    const reporter = await createUser(true);

    await report(reporter, 'user', victim, 'spam.phishing');
    await report(reporter, 'user', victim, 'harassment.targeted_abuse');

    const { rows } = await pool.query<{ reports: string; distinct: string }>(
      `SELECT report_count::text AS reports, distinct_reporter_count::text AS distinct
         FROM admin.cases WHERE target_type = 'user' AND target_id = $1`,
      [victim],
    );
    expect(Number(rows[0]!.reports)).toBe(1);
    expect(Number(rows[0]!.distinct)).toBe(1);
  });

  maybe('takes the most severe category, not the most frequent', async () => {
    const victim = await createUser(true);
    const spammers = await Promise.all([createUser(true), createUser(true), createUser(true)]);
    const serious = await createUser(true);

    for (const r of spammers) await report(r, 'user', victim, 'spam.unsolicited_bulk');
    await report(serious, 'user', victim, 'violence.threat');

    const { rows } = await pool.query<{ category: string }>(
      `SELECT primary_category AS category FROM admin.cases
        WHERE target_type = 'user' AND target_id = $1`,
      [victim],
    );
    // Three spam reports must not bury one credible violence report.
    expect(rows[0]!.category).toBe('violence');
  });

  maybe('refuses to let a user report themselves', async () => {
    const user = await createUser(true);
    await expect(report(user, 'user', user, 'spam.phishing')).rejects.toThrow(/your own content/i);
  });

  maybe('opens a new case once the previous one is closed', async () => {
    const victim = await createUser(true);
    const first = await createUser(true);
    const second = await createUser(true);

    await report(first, 'user', victim, 'spam.phishing');
    await pool.query(
      `UPDATE admin.cases SET status = 'dismissed', resolved_at = NOW()
        WHERE target_type = 'user' AND target_id = $1`,
      [victim],
    );
    await report(second, 'user', victim, 'spam.phishing');

    const { rows } = await pool.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM admin.cases
        WHERE target_type = 'user' AND target_id = $1`,
      [victim],
    );
    // Repeat offending should read as several cases over time, not one that
    // never closes.
    expect(Number(rows[0]!.count)).toBe(2);
  });
});

describe('report routing (§6.2, §6.7)', () => {
  maybe('routes child safety reports out of the ordinary queue entirely', async () => {
    const victim = await createUser(true);
    const reporter = await createUser(true);

    const result = await report(reporter, 'user', victim, 'child_safety.grooming');
    expect(result.routing).toBe('priority_review');

    // §6.7: never through general tooling. No ordinary case, and no report row
    // linking the reporter to it in the general tables.
    const ordinary = await pool.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM admin.cases
        WHERE target_type = 'user' AND target_id = $1`,
      [victim],
    );
    expect(Number(ordinary.rows[0]!.count)).toBe(0);

    const isolated = await pool.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM admin.child_safety_cases
        WHERE reported_user_id = $1`,
      [victim],
    );
    expect(Number(isolated.rows[0]!.count)).toBe(1);
  });

  maybe('places an automatic legal hold on a child safety case', async () => {
    const victim = await createUser(true);
    const reporter = await createUser(true);
    await report(reporter, 'user', victim, 'child_safety.csam');

    const { rows } = await pool.query<{ held: boolean }>(
      `SELECT admin.is_under_legal_hold('user', $1) AS held`,
      [victim],
    );
    // No retention job may ever purge the evidence.
    expect(rows[0]!.held).toBe(true);
  });

  maybe('auto-escalates a self-harm report instead of queueing it', async () => {
    const atRisk = await createUser(true);
    const reporter = await createUser(true);

    const result = await report(reporter, 'user', atRisk, 'self_harm.risk_disclosure');
    expect(result.routing).toBe('safety_escalation');

    const { rows } = await pool.query<{ escalated_at: Date | null; escalation_note: string | null }>(
      `SELECT escalated_at, escalation_note FROM admin.cases
        WHERE target_type = 'user' AND target_id = $1`,
      [atRisk],
    );
    expect(rows[0]!.escalated_at).not.toBeNull();
    expect(rows[0]!.escalation_note).toMatch(/not enforcement/i);
  });

  maybe('refuses enforcement citing a self-harm reason, at the database level', async () => {
    const atRisk = await createUser(true);

    // The API service layer refuses this too, but that refusal only covers
    // paths that go through it. A person disclosing risk has not violated
    // anything, so this is a hard stop rather than a policy convention.
    await expect(
      pool.query(
        `INSERT INTO admin.enforcement_actions
           (user_id, type, reason_code, note, issued_by_label, expires_at)
         VALUES ($1, 'ban_temporary', 'self_harm.risk_disclosure',
                 'This should never be possible.', 'test', NOW() + INTERVAL '1 day')`,
        [atRisk],
      ),
    ).rejects.toThrow(/safety escalation path/i);
  });
});

describe('coordinated reporting (§6.3)', () => {
  maybe('flags a burst of brand-new accounts and lowers the priority', async () => {
    const victim = await createUser(true);
    const brigade = await Promise.all([
      createUser(true), createUser(true), createUser(true),
      createUser(true), createUser(true), createUser(true),
    ]);

    for (const reporter of brigade) {
      await report(reporter, 'user', victim, 'harassment.targeted_abuse');
    }

    const { rows } = await pool.query<{
      suspected: boolean; signals: unknown[]; score: string;
    }>(
      `SELECT coordinated_suspected AS suspected, coordination_signals AS signals,
              priority_score::text AS score
         FROM admin.cases WHERE target_type = 'user' AND target_id = $1`,
      [victim],
    );

    expect(rows[0]!.suspected).toBe(true);
    expect((rows[0]!.signals as unknown[]).length).toBeGreaterThan(0);

    // Brigading must not float to the top of the queue — that is the outcome
    // the brigade wanted. The coordination factor pulls the score down.
    const breakdown = await pool.query<{ p: { components: Array<Record<string, unknown>> } }>(
      `SELECT admin.case_priority(c.id) AS p FROM admin.cases c
        WHERE c.target_type = 'user' AND c.target_id = $1`,
      [victim],
    );
    const coordination = breakdown.rows[0]!.p.components.find((c) => c.key === 'coordination');
    expect(Number(coordination?.factor)).toBeLessThan(1);
  });
});

describe('evidence (§6.3)', () => {
  maybe('stores reporter-submitted content and marks it as such', async () => {
    const victim = await createUser(true);
    const reporter = await createUser(true);

    await report(reporter, 'user', victim, 'spam.phishing', 'send me your login code');

    const { rows } = await pool.query<{ source: string; content_text: string }>(
      `SELECT e.source, e.content_text
         FROM admin.evidence_snapshots e
         JOIN admin.reports r ON r.id = e.report_id
        WHERE r.target_id = $1`,
      [victim],
    );

    // The server could never have obtained this itself.
    expect(rows[0]!.source).toBe('reporter_submitted');
    expect(rows[0]!.content_text).toBe('send me your login code');
  });

  maybe('refuses to modify a captured snapshot', async () => {
    const victim = await createUser(true);
    const reporter = await createUser(true);
    await report(reporter, 'user', victim, 'spam.phishing', 'original text');

    const { rows } = await pool.query<{ id: string }>(
      `SELECT e.id FROM admin.evidence_snapshots e
         JOIN admin.reports r ON r.id = e.report_id WHERE r.target_id = $1`,
      [victim],
    );

    await expect(
      pool.query(`UPDATE admin.evidence_snapshots SET content_text = 'tampered' WHERE id = $1`, [
        rows[0]!.id,
      ]),
    ).rejects.toThrow(/immutable/i);
  });
});

describe('case locking (§6.4)', () => {
  maybe('lets one moderator claim and refuses the second', async () => {
    const victim = await createUser(true);
    const reporter = await createUser(true);
    await report(reporter, 'user', victim, 'spam.phishing');

    const { rows: caseRows } = await pool.query<{ id: string }>(
      `SELECT id FROM admin.cases WHERE target_type = 'user' AND target_id = $1`,
      [victim],
    );
    const caseId = caseRows[0]!.id;

    const first = await pool.query<{ claimed: boolean }>(
      `SELECT admin.claim_case($1, $2) AS claimed`, [caseId, adminA],
    );
    expect(first.rows[0]!.claimed).toBe(true);

    const second = await pool.query<{ claimed: boolean }>(
      `SELECT admin.claim_case($1, $2) AS claimed`, [caseId, adminB],
    );
    expect(second.rows[0]!.claimed).toBe(false);

    await pool.query(`SELECT admin.release_case($1, $2)`, [caseId, adminA]);

    const third = await pool.query<{ claimed: boolean }>(
      `SELECT admin.claim_case($1, $2) AS claimed`, [caseId, adminB],
    );
    expect(third.rows[0]!.claimed).toBe(true);
  });

  maybe('records time-to-first-touch exactly once', async () => {
    const victim = await createUser(true);
    const reporter = await createUser(true);
    await report(reporter, 'user', victim, 'spam.phishing');

    const { rows: caseRows } = await pool.query<{ id: string }>(
      `SELECT id FROM admin.cases WHERE target_type = 'user' AND target_id = $1`,
      [victim],
    );
    const caseId = caseRows[0]!.id;

    await pool.query(`SELECT admin.claim_case($1, $2)`, [caseId, adminA]);
    const first = await pool.query<{ t: Date }>(
      `SELECT first_touched_at AS t FROM admin.cases WHERE id = $1`, [caseId],
    );

    await pool.query(`SELECT admin.release_case($1, $2)`, [caseId, adminA]);
    await pool.query(`SELECT admin.claim_case($1, $2)`, [caseId, adminB]);
    const second = await pool.query<{ t: Date }>(
      `SELECT first_touched_at AS t FROM admin.cases WHERE id = $1`, [caseId],
    );

    // The §2.5 KPI is time to *first* touch; re-claiming must not reset it.
    expect(second.rows[0]!.t.getTime()).toBe(first.rows[0]!.t.getTime());
  });
});
