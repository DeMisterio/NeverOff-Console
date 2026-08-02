import { assertLocalOnly, closePool, describeTarget, getPool } from './client.js';

/**
 * Drop everything and start clean. Local only, always.
 *
 * Deliberately drops the `admin` schema *and* the app tables, because a
 * half-reset database — console tables gone, NeverOff tables still populated —
 * produces foreign key failures on the next seed that are far more confusing
 * than just starting over.
 *
 * Run `npm run db:bootstrap && npm run db:migrate && npm run db:seed` afterwards.
 */
async function reset(): Promise<void> {
  const target = describeTarget();
  assertLocalOnly(target, 'drop every table');

  console.log(`\n  Dropping all schemas on ${target.host}:${target.port}/${target.database}`);

  const pool = getPool();

  // Order matters only in that admin references public; CASCADE handles the rest.
  await pool.query(`
    DROP SCHEMA IF EXISTS admin CASCADE;
    DROP SCHEMA IF EXISTS test_support CASCADE;
    DROP SCHEMA IF EXISTS storage CASCADE;
    DROP SCHEMA IF EXISTS auth CASCADE;
    DROP SCHEMA IF EXISTS public CASCADE;
    CREATE SCHEMA public;
  `);

  // The publication survives a schema drop and would still list dropped tables.
  await pool.query(`DROP PUBLICATION IF EXISTS supabase_realtime`);

  console.log('  Done. Run: npm run db:bootstrap && npm run db:migrate && npm run db:seed\n');
}

try {
  await reset();
} catch (err) {
  console.error(`\n  ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
} finally {
  await closePool();
}
