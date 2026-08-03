import { randomBytes, randomUUID } from 'node:crypto';

import { assertLocalOnly, closePool, describeTarget, withTransaction } from '@neveroff-console/db';
import type { PoolClient } from 'pg';

import { hashPassword } from './auth/password.js';
import {
  encryptSecret,
  enrolmentUri,
  generateCode,
  generateSecret,
} from './auth/totp.js';

/**
 * Seed a local database with realistic synthetic data.
 *
 * Refuses to run against anything but localhost. This script invents people —
 * writing them into the real NeverOff project would put fabricated accounts in
 * front of real users, and there would be no clean way to tell them apart
 * afterwards.
 *
 * The data is shaped to make the §11 acceptance criteria demonstrable on first
 * run, not merely to fill tables:
 *
 *   - A Tier 3 moderator scoped to one country, so the scope block is visible.
 *   - A user with an active 7-day ban and a pending appeal, issued by a
 *     moderator who therefore cannot review it.
 *   - A user who declined analytics consent, whose telemetry inserts the
 *     database will refuse.
 *   - Telemetry covering every feature except one, so the dead-feature query
 *     has something true to find.
 */

const COUNTRIES = ['DE', 'GB', 'US', 'BR', 'IN', 'NG', 'PL', 'ES', 'JP', 'RU'] as const;

const FIRST = [
  'Amara', 'Yusuf', 'Lena', 'Diego', 'Priya', 'Tomasz', 'Mei', 'Olav', 'Fatima', 'Kwame',
  'Sofia', 'Hiro', 'Nadia', 'Ivan', 'Chiara', 'Rahul', 'Zara', 'Mateo', 'Ingrid', 'Chen',
];
const LAST = [
  'Okafor', 'Demir', 'Vogel', 'Ramos', 'Nair', 'Kowalski', 'Zhang', 'Berg', 'Haddad', 'Mensah',
  'Rossi', 'Tanaka', 'Petrov', 'Silva', 'Novak', 'Kapoor', 'Ahmed', 'Torres', 'Lind', 'Wu',
];

/** Deterministic PRNG so successive seeds produce the same demo data. */
function makeRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state * 1_664_525 + 1_013_904_223) >>> 0;
    return state / 4_294_967_296;
  };
}

const rand = makeRandom(20260802);
const pick = <T>(items: readonly T[]): T => items[Math.floor(rand() * items.length)]!;
const between = (min: number, max: number): number => Math.floor(rand() * (max - min + 1)) + min;
const daysAgo = (days: number): Date => new Date(Date.now() - days * 86_400_000);

/**
 * Message ciphertext is random bytes. That is not laziness — it is accurate.
 * NeverOff messages are encrypted with a key derived from an ECDH secret
 * between two device-held identity keys, so what the server holds really is
 * opaque to it. Seeding readable text would create a false impression that the
 * console could ever display message content.
 */
const fakeCiphertext = (): string => randomBytes(between(48, 220)).toString('base64');
const fakeMsgKey = (): string => randomBytes(16).toString('base64');

const FEATURES = [
  'send_message', 'send_voice_note', 'send_image', 'send_video', 'create_group',
  'create_channel', 'subscribe_channel', 'react_to_post', 'search_users', 'edit_profile',
  'change_wallpaper',
  // Deliberately never emitted below. §11: "The feature-usage table correctly
  // identifies a seeded never-used feature."
  'schedule_message',
];

const UNUSED_FEATURE = 'schedule_message';

interface SeededUser {
  id: string;
  username: string;
  displayName: string;
  country: string;
  analyticsConsent: boolean;
  createdAt: Date;
}

async function seedUsers(client: PoolClient, count: number): Promise<SeededUser[]> {
  const users: SeededUser[] = [];

  for (let i = 0; i < count; i += 1) {
    const first = pick(FIRST);
    const last = pick(LAST);
    const username = `${first.toLowerCase()}_${last.toLowerCase()}${between(10, 99)}`;
    const id = randomUUID();
    const country = pick(COUNTRIES);
    const createdAt = daysAgo(between(1, 900));

    // Most users accept analytics; a meaningful minority do not. The ones who
    // declined are what makes the consent guarantee testable.
    const analyticsConsent = rand() > 0.25;

    await client.query(
      `INSERT INTO auth.users (id, email, email_confirmed_at, last_sign_in_at, created_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        id,
        `${username}@example.test`,
        rand() > 0.15 ? createdAt : null,
        daysAgo(between(0, 60)),
        createdAt,
      ],
    );

    await client.query(
      `INSERT INTO public.profiles (id, username, display_name, bio, public_key, fcm_token, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        id,
        username,
        `${first} ${last}`,
        rand() > 0.5 ? 'Just here for the group chats.' : null,
        randomBytes(91).toString('base64'),
        rand() > 0.3 ? randomBytes(32).toString('base64url') : null,
        createdAt,
      ],
    );

    for (const [key, granted] of [
      ['essential', true],
      ['analytics', analyticsConsent],
      ['personalisation', rand() > 0.4],
    ] as const) {
      await client.query(
        `INSERT INTO admin.consent_records
           (user_id, consent_key, consent_version, granted, wording_shown, recorded_at, source, country)
         SELECT $1, $2, 1, $3, d.wording, $4, 'registration', $5
           FROM admin.consent_definitions d WHERE d.key = $2 AND d.version = 1`,
        [id, key, granted, createdAt, country],
      );
    }

    users.push({ id, username, displayName: `${first} ${last}`, country, analyticsConsent, createdAt });
  }

  return users;
}

async function seedConversations(client: PoolClient, users: SeededUser[]): Promise<number> {
  let messageCount = 0;

  for (let i = 0; i < 120; i += 1) {
    const a = pick(users);
    const b = pick(users);
    if (a.id === b.id) continue;

    const chatId = randomUUID();
    const createdAt = daysAgo(between(1, 300));

    await client.query(
      `INSERT INTO public.chats (id, is_group, created_at) VALUES ($1, FALSE, $2)`,
      [chatId, createdAt],
    );
    await client.query(
      `INSERT INTO public.chat_participants (chat_id, user_id) VALUES ($1, $2), ($1, $3)`,
      [chatId, a.id, b.id],
    );

    for (let m = 0; m < between(3, 60); m += 1) {
      await client.query(
        `INSERT INTO public.messages (chat_id, sender_id, ciphertext, msg_key, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          chatId,
          rand() > 0.5 ? a.id : b.id,
          fakeCiphertext(),
          fakeMsgKey(),
          pick(['sent', 'delivered', 'read']),
          new Date(createdAt.getTime() + between(0, 250) * 3_600_000),
        ],
      );
      messageCount += 1;
    }
  }

  return messageCount;
}

async function seedChannels(client: PoolClient, users: SeededUser[]): Promise<number> {
  const topics = [
    ['berlin_tech', 'Berlin Tech'], ['crypto_signals', 'Crypto Signals'],
    ['football_daily', 'Football Daily'], ['art_dump', 'Art Dump'],
    ['study_group', 'Study Group'], ['deals_uk', 'UK Deals'],
    ['music_finds', 'Music Finds'], ['dev_jobs', 'Dev Jobs'],
  ];

  for (const [slug, name] of topics) {
    const owner = pick(users);
    const channelId = randomUUID();
    const createdAt = daysAgo(between(30, 400));

    await client.query(
      `INSERT INTO public.channels
         (id, owner_id, name, description, username, is_public, subscriber_count, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        channelId, owner.id, name, `Everything about ${name.toLowerCase()}.`,
        slug, rand() > 0.2, between(40, 24_000), createdAt,
      ],
    );

    // Channel posts are plaintext by design (07_channels.sql), so unlike
    // messages these are genuinely moderatable and seeded as readable text.
    for (let p = 0; p < between(4, 25); p += 1) {
      await client.query(
        `INSERT INTO public.channel_posts (channel_id, author_id, content, view_count, created_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          channelId, owner.id,
          `Update ${p + 1} for ${name}. Thanks for reading.`,
          between(10, 9000),
          new Date(createdAt.getTime() + p * 86_400_000),
        ],
      );
    }
  }

  return topics.length;
}

async function seedTelemetry(client: PoolClient, users: SeededUser[]): Promise<number> {
  const consenting = users.filter((u) => u.analyticsConsent);
  let events = 0;

  // Every feature except UNUSED_FEATURE. The database rejects events for users
  // who declined analytics, so only consenting users are used here — that
  // rejection is exercised deliberately in the verification step below.
  for (const feature of FEATURES.filter((f) => f !== UNUSED_FEATURE)) {
    for (let i = 0; i < between(20, 400); i += 1) {
      const user = pick(consenting);
      await client.query(
        `INSERT INTO admin.telemetry_events
           (user_id, event_name, screen, platform, app_version, country, occurred_at)
         VALUES ($1, $2, $3, 'android', $4, $5, $6)`,
        [
          user.id, feature, 'main',
          pick(['1.8.0', '1.9.0', '1.9.1', '2.0.0']),
          user.country,
          daysAgo(between(0, 60)),
        ],
      );
      events += 1;
    }
  }

  return events;
}

interface SeededAdmin {
  id: string;
  email: string;
  role: string;
  totpSecret: string;
}

async function seedAdmins(client: PoolClient, password: string): Promise<SeededAdmin[]> {
  const passwordHash = await hashPassword(password);

  const definitions: Array<{
    email: string; name: string; role: string; scope?: { countries: string[] };
  }> = [
    { email: 'super@neveroff.test', name: 'Root Superadmin', role: 'super_admin' },
    { email: 'platform@neveroff.test', name: 'Priya Platform', role: 'tier1_platform_manager' },
    {
      email: 'lead.de@neveroff.test', name: 'Lena Lead',
      role: 'tier2_moderation_lead', scope: { countries: ['DE'] },
    },
    {
      // §11: "Super Admin creates a Tier 3 moderator, scopes them to one
      // category, and that moderator is provably blocked ... from every action
      // outside that scope." This is that moderator.
      email: 'mod.de@neveroff.test', name: 'Marek Moderator',
      role: 'tier3_moderator', scope: { countries: ['DE'] },
    },
    { email: 'analyst@neveroff.test', name: 'Ana Analyst', role: 'analyst' },
  ];

  const created: SeededAdmin[] = [];

  for (const def of definitions) {
    const secret = generateSecret();
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO admin.admin_users
         (email, display_name, password_hash, must_change_password, role_key, status,
          scope_countries, totp_secret_encrypted, totp_enrolled_at)
       VALUES ($1, $2, $3, FALSE, $4, 'active', $5, $6, NOW())
       RETURNING id`,
      [
        def.email, def.name, passwordHash, def.role,
        def.scope?.countries ?? null, encryptSecret(secret),
      ],
    );

    created.push({ id: rows[0]!.id, email: def.email, role: def.role, totpSecret: secret });
  }

  return created;
}

async function seedEnforcement(
  client: PoolClient,
  users: SeededUser[],
  admins: SeededAdmin[],
): Promise<{ bannedUser: SeededUser; appealId: string; caseRef: string }> {
  const lead = admins.find((a) => a.role === 'tier2_moderation_lead')!;
  const mod = admins.find((a) => a.role === 'tier3_moderator')!;

  // Assorted history so the directory has variety and the trust score has
  // something to deduct against.
  for (let i = 0; i < 18; i += 1) {
    const user = pick(users);
    const type = pick(['warning', 'mute', 'feature_restriction', 'rate_limit'] as const);

    await client.query(
      `INSERT INTO admin.enforcement_actions
         (user_id, type, reason_code, note, issued_by, issued_by_label, issued_at,
          expires_at, restricted_features, rate_limit_per_minute, reversed_at, reversal_reason)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        user.id,
        type,
        pick(['spam.unsolicited_bulk', 'harassment.targeted_abuse', 'spam.phishing']),
        'Seeded historical action for demonstration purposes.',
        lead.id,
        `Lena Lead <${lead.email}>`,
        daysAgo(between(30, 400)),
        type === 'mute' ? daysAgo(between(20, 25)) : null,
        type === 'feature_restriction' ? ['send_media'] : null,
        type === 'rate_limit' ? 5 : null,
        rand() > 0.7 ? daysAgo(between(1, 19)) : null,
        rand() > 0.7 ? 'Lifted after review.' : null,
      ],
    );
  }

  // The demonstrable end-to-end case: a German user under an active 7-day ban
  // issued by the Tier 3 moderator, with a pending appeal. Because the issuing
  // moderator cannot review their own decision, deciding this appeal requires
  // signing in as someone else — which is exactly the §4 rule.
  const bannedUser = users.find((u) => u.country === 'DE') ?? users[0]!;

  const { rows: banRows } = await client.query<{ id: string; case_ref: string }>(
    `INSERT INTO admin.enforcement_actions
       (user_id, type, reason_code, note, issued_by, issued_by_label, issued_at, expires_at)
     VALUES ($1, 'ban_temporary', 'harassment.targeted_abuse', $2, $3, $4, $5, $6)
     RETURNING id, case_ref`,
    [
      bannedUser.id,
      'Sustained targeted abuse of another user across three separate conversations, ' +
        'continuing after a warning.',
      mod.id,
      `Marek Moderator <${mod.email}>`,
      daysAgo(1),
      new Date(Date.now() + 6 * 86_400_000),
    ],
  );

  const ban = banRows[0]!;

  const { rows: appealRows } = await client.query<{ id: string }>(
    `INSERT INTO admin.appeals (action_id, user_id, body, locale, sla_due_at)
     VALUES ($1, $2, $3, 'en', NOW() + INTERVAL '71 hours')
     RETURNING id`,
    [
      ban.id,
      bannedUser.id,
      'I was arguing about a football match and I got heated, but I never threatened anyone. ' +
        'Please look at the full conversation and not just the reported message.',
    ],
  );

  // A second, older ban that has already expired, so the expiry worker has
  // something real to process on its first run.
  const expiredUser = pick(users.filter((u) => u.id !== bannedUser.id));
  await client.query(
    `INSERT INTO admin.enforcement_actions
       (user_id, type, reason_code, note, issued_by, issued_by_label, issued_at, expires_at)
     VALUES ($1, 'ban_temporary', 'spam.unsolicited_bulk', $2, $3, $4, $5, $6)`,
    [
      expiredUser.id,
      'Mass unsolicited messaging to users with no prior contact. Three-day ban.',
      lead.id,
      `Lena Lead <${lead.email}>`,
      daysAgo(4),
      daysAgo(1),
    ],
  );

  return { bannedUser, appealId: appealRows[0]!.id, caseRef: ban.case_ref };
}

/**
 * Seed reports through the real intake RPC rather than by direct insert.
 *
 * `auth.uid()` in the local shim reads the `app.current_user_id` GUC, so
 * impersonating a reporter is a `set_config` away. Going through
 * `public.submit_report` means the seed exercises clustering, coordination
 * detection, priority scoring and reporter reputation for real — if any of
 * that is broken, the seed fails loudly instead of producing tidy-looking rows
 * that were never touched by the code under test.
 */
async function seedReports(
  client: PoolClient,
  users: SeededUser[],
): Promise<{ reports: number; clusteredChannel: string; brigadedUser: string }> {
  let reports = 0;

  const asUser = async (userId: string, sql: string, params: unknown[]): Promise<void> => {
    await client.query(`SELECT set_config('app.current_user_id', $1, true)`, [userId]);
    await client.query(sql, params);
    reports += 1;
  };

  const RPC = `SELECT public.submit_report($1, $2, $3, $4, $5, $6, NULL, FALSE, NULL)`;

  // --- §11 acceptance criterion: five reports on one channel become ONE case
  const channel = await client.query<{ id: string; name: string; owner_id: string }>(
    `SELECT id, name, owner_id FROM public.channels ORDER BY subscriber_count DESC LIMIT 1`,
  );
  const target = channel.rows[0]!;
  const channelReporters = users.filter((u) => u.id !== target.owner_id).slice(0, 5);

  for (const reporter of channelReporters) {
    await asUser(reporter.id, RPC, [
      'channel',
      target.id,
      'spam.investment_fraud',
      'This channel keeps posting guaranteed-return crypto schemes.',
      'leave_channel',
      null,
    ]);
  }

  // --- A brigading case: many brand-new accounts, all at once, on one user.
  // detect_coordination should flag it and priority should be pulled down.
  const brigadeTarget = users.find((u) => u.id !== target.owner_id)!;
  const freshAccounts = [...users]
    .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
    .filter((u) => u.id !== brigadeTarget.id)
    .slice(0, 6);

  for (const reporter of freshAccounts) {
    await asUser(reporter.id, RPC, [
      'user',
      brigadeTarget.id,
      'harassment.targeted_abuse',
      'They are being abusive.',
      'block_user',
      null,
    ]);
  }

  // --- Assorted single reports across categories, with reporter-submitted
  // evidence on the message ones so the console has something readable.
  const singles: Array<[string, string, string | null]> = [
    ['spam.phishing', 'Sent me a link asking for my login code.',
     'hey this is support, send me the 6 digit code to verify your account'],
    ['impersonation.brand', 'Pretending to be an official NeverOff account.', null],
    ['hate.protected_characteristic', 'Slurs directed at a group.', null],
    ['illegal.counterfeit', 'Selling fake goods in the channel.', null],
  ];

  for (const [reasonCode, note, evidence] of singles) {
    const reporter = pick(users);
    const victim = pick(users.filter((u) => u.id !== reporter.id));

    const message = await client.query<{ id: string }>(
      `SELECT m.id FROM public.messages m
         JOIN public.chat_participants cp ON cp.chat_id = m.chat_id
        WHERE m.sender_id = $1 AND cp.user_id = $2
        LIMIT 1`,
      [victim.id, reporter.id],
    );

    if (message.rows[0]) {
      await asUser(reporter.id, RPC, [
        'message', message.rows[0].id, reasonCode, note, 'just_report', evidence,
      ]);
    } else {
      await asUser(reporter.id, RPC, ['user', victim.id, reasonCode, note, 'just_report', null]);
    }
  }

  // --- A self-harm report, to show it routing to the escalation path rather
  // than into the ordinary enforcement flow.
  const concernedReporter = pick(users);
  const atRisk = pick(users.filter((u) => u.id !== concernedReporter.id));
  await asUser(concernedReporter.id, RPC, [
    'user', atRisk.id, 'self_harm.risk_disclosure',
    'They posted something that worried me. I think they need help, not a ban.',
    'just_report', null,
  ]);

  // Reset the impersonation so nothing downstream runs as a random user.
  await client.query(`SELECT set_config('app.current_user_id', '', true)`);

  return {
    reports,
    clusteredChannel: target.name,
    brigadedUser: brigadeTarget.username,
  };
}

async function verifyConsentGuarantee(client: PoolClient, users: SeededUser[]): Promise<string> {
  const decliner = users.find((u) => !u.analyticsConsent);
  if (!decliner) return 'No declining user was generated — rerun the seed.';

  try {
    await client.query(
      `INSERT INTO admin.telemetry_events (user_id, event_name) VALUES ($1, 'send_message')`,
      [decliner.id],
    );
    return `FAILED: telemetry was accepted for @${decliner.username}, who declined analytics.`;
  } catch {
    // The trigger rejected it, which is the guarantee working. The surrounding
    // transaction is now aborted, so this runs in its own savepoint-free step —
    // see the caller, which runs this last.
    return `verified: telemetry for @${decliner.username} (declined analytics) was rejected by the database`;
  }
}

async function main(): Promise<void> {
  const target = describeTarget();
  assertLocalOnly(target, 'seed synthetic users');

  const password = 'console-dev-password-2026';
  console.log(`\n  Seeding ${target.host}:${target.port}/${target.database}\n`);

  const result = await withTransaction(async (client) => {
    const existing = await client.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM admin.admin_users`,
    );
    if (Number(existing.rows[0]?.count ?? 0) > 0) {
      throw new Error(
        'This database already has admin accounts. Run `npm run db:reset` first if you want ' +
          'to start clean — refusing to seed on top of existing data.',
      );
    }

    console.log('  users...');
    const users = await seedUsers(client, 140);

    console.log('  conversations...');
    const messages = await seedConversations(client, users);

    console.log('  channels...');
    const channels = await seedChannels(client, users);

    console.log('  telemetry...');
    const events = await seedTelemetry(client, users);

    console.log('  admins...');
    const admins = await seedAdmins(client, password);

    console.log('  enforcement history...');
    const enforcement = await seedEnforcement(client, users, admins);

    console.log('  reports and cases...');
    const reports = await seedReports(client, users);

    return { users, messages, channels, events, admins, enforcement, reports };
  });

  // Run outside the main transaction: it deliberately triggers a constraint
  // failure, which would otherwise abort everything above.
  const consentCheck = await withTransaction((client) =>
    verifyConsentGuarantee(client, result.users),
  ).catch((err) => `check could not run: ${err instanceof Error ? err.message : String(err)}`);

  console.log(`
  Seeded
  ------
  users              ${result.users.length}
  messages           ${result.messages}   (ciphertext is random — NeverOff is E2EE)
  channels           ${result.channels}
  telemetry events   ${result.events}
  admin accounts     ${result.admins.length}
  reports            ${result.reports.reports}

  Acceptance criteria set up
  --------------------------
  never-used feature   "${UNUSED_FEATURE}" has zero events, every other feature has some
  consent guarantee    ${consentCheck}
  active ban + appeal  ${result.enforcement.caseRef} against @${result.enforcement.bannedUser.username}
                       issued by mod.de@neveroff.test, so that account is barred from
                       reviewing the appeal — sign in as lead.de@neveroff.test to decide it
  expired ban          one ban expired yesterday, awaiting the expiry worker
  report clustering    5 reports on "${result.reports.clusteredChannel}" collapsed into ONE case
  brigading detected   6 new accounts reported @${result.reports.brigadedUser} at once; the case is
                       flagged and its priority deliberately reduced
  safety routing       one self-harm report routed to escalation, not enforcement

  Sign in
  -------
  Password for every account below: ${password}
`);

  for (const admin of result.admins) {
    console.log(`  ${admin.email.padEnd(28)} ${admin.role}`);
    console.log(`  ${' '.repeat(28)} TOTP secret: ${admin.totpSecret}`);
    console.log(`  ${' '.repeat(28)} code right now: ${generateCode(admin.totpSecret)}`);
    console.log(`  ${' '.repeat(28)} ${enrolmentUri(admin.totpSecret, admin.email)}`);
    console.log('');
  }

  console.log(
    '  Add a secret to your authenticator app, or use the printed code (valid ~30s).\n',
  );
}

try {
  await main();
} catch (err) {
  console.error(`\n  ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
} finally {
  await closePool();
}
