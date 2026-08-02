import { readFileSync } from 'node:fs';
import { Pool, type PoolConfig } from 'pg';

/**
 * Database connection, plus the guard rails that stop a development command
 * from firing at the live NeverOff project.
 *
 * The console is explicitly intended to reach production eventually — that is
 * the whole point of enforcement write-back. The rails here are not about
 * preventing that; they are about making it deliberate. Three levels:
 *
 *   - `assertAllowedHost`  — the host must be in DB_ALLOWED_HOSTS.
 *   - `assertLocalOnly`    — refuses anything but localhost. Used by the seed,
 *                            which fabricates users and must never invent
 *                            people in the real database.
 *   - `assertProductionAck`— touching an existing NeverOff table on a non-local
 *                            host additionally requires PRODUCTION_MIGRATION_ACK
 *                            to be set to the exact acknowledgement string.
 */

export interface DbTarget {
  readonly url: string;
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly isLocal: boolean;
}

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

export const PRODUCTION_ACK_PHRASE = 'I understand this writes to the live NeverOff database';

export function describeTarget(url = process.env.DATABASE_URL): DbTarget {
  if (!url) {
    throw new Error('DATABASE_URL is not set. Copy .env.example to .env and fill it in.');
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('DATABASE_URL is not a valid connection URI.');
  }

  const host = parsed.hostname;
  return {
    url,
    host,
    port: parsed.port ? Number(parsed.port) : 5432,
    database: parsed.pathname.replace(/^\//, '') || 'postgres',
    isLocal: LOCAL_HOSTS.has(host),
  };
}

export function assertAllowedHost(target: DbTarget): void {
  const allowed = (process.env.DB_ALLOWED_HOSTS ?? 'localhost,127.0.0.1')
    .split(',')
    .map((h) => h.trim())
    .filter(Boolean);

  if (!allowed.includes(target.host)) {
    throw new Error(
      `Refusing to connect to "${target.host}": it is not in DB_ALLOWED_HOSTS (${allowed.join(', ')}).\n` +
        'Add it deliberately if you really mean to target that database.',
    );
  }
}

export function assertLocalOnly(target: DbTarget, what: string): void {
  if (!target.isLocal) {
    throw new Error(
      `Refusing to ${what} against "${target.host}".\n` +
        'This command fabricates data and may only ever run against a local database.',
    );
  }
}

/**
 * Called by the migration runner before applying any migration that touches an
 * existing NeverOff table. Deliberately tedious — the acknowledgement string is
 * long enough that it cannot be typed by reflex.
 */
export function assertProductionAck(target: DbTarget, migrationName: string): void {
  if (target.isLocal) return;

  const ack = process.env.PRODUCTION_MIGRATION_ACK ?? '';
  if (ack.trim() !== PRODUCTION_ACK_PHRASE) {
    throw new Error(
      `"${migrationName}" modifies the live NeverOff app schema on host "${target.host}".\n\n` +
        'This migration adds RLS policies to public.messages and public.channel_posts.\n' +
        'A mistake here can stop real users sending messages.\n\n' +
        'Review the SQL, then set this in your environment to proceed:\n\n' +
        `  PRODUCTION_MIGRATION_ACK=${PRODUCTION_ACK_PHRASE}\n\n` +
        'Roll back at any time with 0006_neveroff_integration.down.sql.',
    );
  }
}

function sslConfig(target: DbTarget): PoolConfig['ssl'] {
  if (target.isLocal) return undefined;

  // Supabase requires TLS. If a CA bundle is supplied we verify properly;
  // otherwise we still encrypt but skip chain verification, which is the
  // common Supabase setup and is called out in the README as a known
  // weakening rather than left as a silent default.
  const caPath = process.env.DATABASE_CA_CERT_PATH;
  if (caPath) {
    return { ca: readFileSync(caPath, 'utf8'), rejectUnauthorized: true };
  }
  return { rejectUnauthorized: false };
}

let pool: Pool | undefined;

export function getPool(url = process.env.DATABASE_URL): Pool {
  if (pool) return pool;

  const target = describeTarget(url);
  assertAllowedHost(target);

  pool = new Pool({
    connectionString: target.url,
    ssl: sslConfig(target),
    max: Number(process.env.DB_POOL_MAX ?? 10),
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 15_000,
    // Statement timeout keeps a runaway console query from pinning a connection
    // that the app's own traffic may be sharing on a pooled Supabase plan.
    statement_timeout: Number(process.env.DB_STATEMENT_TIMEOUT_MS ?? 30_000),
  });

  pool.on('error', (err) => {
    // A pool-level error is an idle client dying, not a query failure. Log and
    // let pg replace the client rather than crashing the process.
    console.error('[db] idle client error:', err.message);
  });

  return pool;
}

export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = undefined;
  }
}

/** Run a function inside a transaction, rolling back on any throw. */
export async function withTransaction<T>(
  fn: (client: import('pg').PoolClient) => Promise<T>,
): Promise<T> {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // The connection is already broken; the original error is the useful one.
    }
    throw err;
  } finally {
    client.release();
  }
}
