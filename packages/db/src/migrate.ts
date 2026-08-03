import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { QueryResult } from 'pg';

import {
  assertProductionAck,
  closePool,
  describeTarget,
  getPool,
} from './client.js';
import { syncCatalogue } from './sync-catalogue.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = join(HERE, '..', 'migrations');

/**
 * Migrations that alter the live NeverOff app schema. Applying one of these to
 * a non-local host requires PRODUCTION_MIGRATION_ACK.
 *
 * Kept as an explicit list rather than inferred from the SQL: inference would
 * silently stop working the day someone writes a policy in a way the pattern
 * does not match, and the failure mode is "quietly skipped the safety check".
 */
const PRODUCTION_TOUCHING = new Set([
  '0006_neveroff_integration.sql',
  // Reads public.profiles/messages/channels through a view and function.
  '0007_user_directory.sql',
  // Builds indexes on the app's own tables.
  '0008_app_indexes.sql',
  // Reads public.messages/channels metadata through the target resolver.
  '0011_reports_and_cases.sql',
  // Creates public-schema RPCs and grants EXECUTE to `authenticated`.
  '0012_report_intake.sql',
]);

/**
 * Migrations opt out of the wrapping transaction with `-- @no-transaction` on
 * the first line. Required for CREATE INDEX CONCURRENTLY, which Postgres
 * refuses inside a transaction block.
 */
const NO_TRANSACTION_MARKER = '@no-transaction';

interface Migration {
  readonly name: string;
  readonly sql: string;
  readonly checksum: string;
  readonly transactional: boolean;
}

function loadMigrations(): Migration[] {
  return readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql'))
    // `.down.sql` files are rollbacks, applied deliberately and by hand.
    .filter((f) => !f.endsWith('.down.sql'))
    .sort()
    .map((name) => {
      const sql = readFileSync(join(MIGRATIONS_DIR, name), 'utf8');
      const firstLine = sql.slice(0, sql.indexOf('\n') + 1 || sql.length);
      return {
        name,
        sql,
        checksum: createHash('sha256').update(sql).digest('hex'),
        transactional: !firstLine.includes(NO_TRANSACTION_MARKER),
      };
    });
}

async function ensureTrackingTable(): Promise<void> {
  const pool = getPool();
  await pool.query(`
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

/** Rows from a migration's trailing verification SELECT, if it has one. */
function reportVerification(results: QueryResult | QueryResult[]): void {
  const list = Array.isArray(results) ? results : [results];
  const last = list[list.length - 1];
  if (!last || !last.rows?.length) return;
  if (!('ok' in (last.rows[0] as Record<string, unknown>))) return;

  for (const row of last.rows as Array<Record<string, unknown>>) {
    const ok = row.ok === true;
    const mark = ok ? '  ok  ' : ' FAIL ';
    console.log(`      [${mark}] ${String(row.check_name)} — ${String(row.detail ?? '')}`);
  }

  const failed = (last.rows as Array<Record<string, unknown>>).filter((r) => r.ok !== true);
  if (failed.length > 0) {
    throw new Error(
      `${failed.length} post-condition check(s) failed. The migration applied but its ` +
        'guarantees are not in force — investigate before proceeding.',
    );
  }
}

export async function migrate(): Promise<void> {
  const target = describeTarget();
  const pool = getPool();

  console.log(`\n  Target: ${target.host}:${target.port}/${target.database}` +
    `${target.isLocal ? '  (local)' : '  ** NOT LOCAL **'}\n`);

  await ensureTrackingTable();

  const applied = new Map<string, string>(
    (await pool.query<{ name: string; checksum: string }>(
      'SELECT name, checksum FROM admin.schema_migrations',
    )).rows.map((r) => [r.name, r.checksum]),
  );

  const migrations = loadMigrations();
  let ran = 0;

  for (const migration of migrations) {
    const previous = applied.get(migration.name);

    if (previous) {
      if (previous !== migration.checksum) {
        throw new Error(
          `Migration "${migration.name}" has already been applied but its contents have ` +
            'changed since.\n' +
            'Editing an applied migration desynchronises environments silently. ' +
            'Add a new migration instead.',
        );
      }
      continue;
    }

    if (PRODUCTION_TOUCHING.has(migration.name)) {
      assertProductionAck(target, migration.name);
    }

    console.log(
      `  applying ${migration.name}${migration.transactional ? '' : '  (outside a transaction)'}`,
    );
    const started = Date.now();

    const client = await pool.connect();
    try {
      if (migration.transactional) await client.query('BEGIN');

      const result = await client.query(migration.sql);
      reportVerification(result as QueryResult | QueryResult[]);

      await client.query(
        `INSERT INTO admin.schema_migrations (name, checksum, duration_ms)
         VALUES ($1, $2, $3)`,
        [migration.name, migration.checksum, Date.now() - started],
      );

      if (migration.transactional) await client.query('COMMIT');
      ran += 1;
      console.log(`      applied in ${Date.now() - started}ms`);
    } catch (err) {
      if (migration.transactional) {
        await client.query('ROLLBACK').catch(() => {});
      }
      const message = err instanceof Error ? err.message : String(err);

      if (!migration.transactional) {
        // A CONCURRENTLY build that fails leaves an INVALID index behind rather
        // than rolling back. Say so, because the fix is manual.
        throw new Error(
          `Migration "${migration.name}" failed and could NOT be rolled back — it runs ` +
            `outside a transaction:\n  ${message}\n\n` +
            'Statements before the failure have already taken effect. Check for a leftover ' +
            'invalid index with:\n' +
            '  SELECT indexrelid::regclass FROM pg_index WHERE NOT indisvalid;\n' +
            'Drop any it reports, then re-run the migration.',
        );
      }

      throw new Error(`Migration "${migration.name}" failed and was rolled back:\n  ${message}`);
    } finally {
      client.release();
    }
  }

  if (ran === 0) {
    console.log('  Schema already up to date.');
  } else {
    console.log(`\n  Applied ${ran} migration(s).`);
  }

  // The permission, role and reason catalogues live in TypeScript and the
  // database holds a derived copy for referential integrity and for reporting.
  // Syncing here means the two cannot drift across a deploy.
  console.log('\n  Syncing catalogues from packages/shared...');
  const summary = await syncCatalogue();
  console.log(
    `      permissions ${summary.permissions}, roles ${summary.roles}, ` +
      `grants ${summary.rolePermissions}, reasons ${summary.reasons}`,
  );
  if (summary.removed.length > 0) {
    console.log(`      removed stale entries: ${summary.removed.join(', ')}`);
  }
}

export async function status(): Promise<void> {
  const target = describeTarget();
  await ensureTrackingTable();
  const pool = getPool();

  const applied = new Map<string, { checksum: string; applied_at: Date }>(
    (
      await pool.query<{ name: string; checksum: string; applied_at: Date }>(
        'SELECT name, checksum, applied_at FROM admin.schema_migrations',
      )
    ).rows.map((r) => [r.name, r]),
  );

  console.log(`\n  Target: ${target.host}:${target.port}/${target.database}\n`);
  for (const migration of loadMigrations()) {
    const row = applied.get(migration.name);
    if (!row) {
      console.log(`  [ pending ] ${migration.name}`);
    } else if (row.checksum !== migration.checksum) {
      console.log(`  [ DRIFTED ] ${migration.name}  (file changed after apply)`);
    } else {
      console.log(`  [ applied ] ${migration.name}  ${row.applied_at.toISOString()}`);
    }
  }
  console.log('');
}

const entry = process.argv[2] ?? 'up';

try {
  if (entry === 'status') {
    await status();
  } else {
    await migrate();
  }
} catch (err) {
  console.error(`\n  ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
} finally {
  await closePool();
}
