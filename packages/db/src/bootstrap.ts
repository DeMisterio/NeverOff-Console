import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { assertLocalOnly, closePool, describeTarget, getPool } from './client.js';

/**
 * Local-only bootstrap: turn a bare Postgres into something that looks enough
 * like the NeverOff Supabase project that the real migrations run against it.
 *
 * Two steps:
 *   1. Apply the Supabase shim (auth/storage schemas, auth.uid(), roles,
 *      realtime publication).
 *   2. Apply NeverOff's own migrations, read directly out of the app repo.
 *
 * Step 2 reads the sibling repository rather than keeping a copy here. A copy
 * would drift, and the entire value of the local environment is that it is a
 * faithful replica — rehearsing against a stale schema is worse than not
 * rehearsing, because it produces false confidence.
 */

const HERE = dirname(fileURLToPath(import.meta.url));

function findConsoleRoot(): string {
  let dir = HERE;
  for (let i = 0; i < 8; i += 1) {
    if (existsSync(join(dir, 'docker-compose.yml'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('Could not locate the console repository root.');
}

function findNeverOffMigrations(): string {
  const fromEnv = process.env.NEVEROFF_REPO_PATH;
  const candidates = [
    fromEnv ? join(fromEnv, 'supabase', 'migrations') : null,
    join(dirname(findConsoleRoot()), 'NeverOff', 'supabase', 'migrations'),
  ].filter((c): c is string => c !== null);

  for (const candidate of candidates) {
    if (existsSync(candidate) && statSync(candidate).isDirectory()) {
      return resolve(candidate);
    }
  }

  throw new Error(
    'Could not find the NeverOff app migrations.\n' +
      `Looked in:\n${candidates.map((c) => `  ${c}`).join('\n')}\n\n` +
      'Set NEVEROFF_REPO_PATH to the NeverOff repository root.',
  );
}

async function ensureTracking(): Promise<void> {
  await getPool().query(`
    CREATE SCHEMA IF NOT EXISTS admin;
    CREATE TABLE IF NOT EXISTS admin.schema_migrations (
      name        TEXT PRIMARY KEY,
      checksum    TEXT NOT NULL,
      applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      applied_by  TEXT NOT NULL DEFAULT current_user,
      duration_ms INTEGER
    );
  `);
}

async function applyOnce(name: string, sql: string): Promise<boolean> {
  const pool = getPool();
  const checksum = createHash('sha256').update(sql).digest('hex');

  const existing = await pool.query<{ checksum: string }>(
    'SELECT checksum FROM admin.schema_migrations WHERE name = $1',
    [name],
  );

  if (existing.rows.length > 0) {
    if (existing.rows[0]!.checksum !== checksum) {
      console.log(`  [ drift  ] ${name} — file changed since it was applied here`);
    }
    return false;
  }

  const client = await pool.connect();
  const started = Date.now();
  try {
    await client.query('BEGIN');
    await client.query(sql);
    await client.query(
      `INSERT INTO admin.schema_migrations (name, checksum, duration_ms) VALUES ($1, $2, $3)`,
      [name, checksum, Date.now() - started],
    );
    await client.query('COMMIT');
    console.log(`  [ applied ] ${name}  (${Date.now() - started}ms)`);
    return true;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw new Error(
      `${name} failed and was rolled back:\n  ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    client.release();
  }
}

export async function bootstrap(): Promise<void> {
  const target = describeTarget();
  assertLocalOnly(target, 'bootstrap a Supabase replica');

  console.log(`\n  Bootstrapping local replica at ${target.host}:${target.port}/${target.database}\n`);

  await ensureTracking();

  // --- 1. Supabase shim ---------------------------------------------------
  const shimDir = join(findConsoleRoot(), 'packages', 'db', 'local-bootstrap');
  console.log('  Supabase primitives:');
  for (const file of readdirSync(shimDir).filter((f) => f.endsWith('.sql')).sort()) {
    await applyOnce(`shim/${file}`, readFileSync(join(shimDir, file), 'utf8'));
  }

  // --- 2. NeverOff app schema --------------------------------------------
  const appDir = findNeverOffMigrations();
  console.log(`\n  NeverOff app schema (from ${appDir}):`);
  for (const file of readdirSync(appDir).filter((f) => f.endsWith('.sql')).sort()) {
    await applyOnce(`neveroff/${file}`, readFileSync(join(appDir, file), 'utf8'));
  }

  // --- 3. Sanity check ----------------------------------------------------
  const check = await getPool().query<{ table_name: string }>(
    `SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_name IN ('profiles','chats','chat_participants','messages',
                           'channels','channel_posts','channel_subscribers','versions')
      ORDER BY table_name`,
  );

  const found = check.rows.map((r) => r.table_name);
  const expected = [
    'channel_posts', 'channel_subscribers', 'channels', 'chat_participants',
    'chats', 'messages', 'profiles', 'versions',
  ];
  const missing = expected.filter((t) => !found.includes(t));

  console.log(`\n  App tables present: ${found.length}/${expected.length}`);
  if (missing.length > 0) {
    throw new Error(`Missing expected app tables: ${missing.join(', ')}`);
  }

  console.log('\n  Local replica ready. Run `npm run db:migrate` next.\n');
}

try {
  await bootstrap();
} catch (err) {
  console.error(`\n  ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
} finally {
  await closePool();
}
