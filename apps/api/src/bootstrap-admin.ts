import { randomBytes } from 'node:crypto';

import { closePool, describeTarget, getPool, withTransaction } from '@neveroff-console/db';

import { hashPassword } from './auth/password.js';
import { encryptSecret, enrolmentUri, generateCode, generateSecret } from './auth/totp.js';

/**
 * Create the first Super Admin.
 *
 * Every other route that creates an admin requires an authenticated admin to
 * already exist, which leaves a fresh deployment with no way in. The seed
 * script fills that gap locally but deliberately refuses any non-local host,
 * because it fabricates users. This is the production-safe counterpart: it
 * creates exactly one account and touches nothing else.
 *
 * Usage:
 *   npm run bootstrap:admin --workspace @neveroff-console/api -- \
 *     --email you@example.com --name "Your Name"
 *
 * It refuses to run if a Super Admin already exists. Recovering a lost Super
 * Admin is a different operation with different risks, and quietly minting a
 * second one would be a privilege-escalation path rather than a convenience.
 */

function arg(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
}

async function main(): Promise<void> {
  const email = arg('email');
  const displayName = arg('name');

  if (!email || !displayName) {
    throw new Error(
      'Usage: --email you@example.com --name "Your Name"\n\n' +
        'Creates the first Super Admin on this database.',
    );
  }
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    throw new Error(`"${email}" does not look like an email address.`);
  }

  const target = describeTarget();
  const pool = getPool();

  console.log(`\n  Target: ${target.host}:${target.port}/${target.database}`);
  if (!target.isLocal) {
    console.log('  ** This is NOT a local database. **');
  }

  const existing = await pool.query<{ email: string }>(
    `SELECT email FROM admin.admin_users WHERE role_key = 'super_admin'`,
  );

  if (existing.rows.length > 0) {
    throw new Error(
      `A Super Admin already exists on this database (${existing.rows[0]!.email}).\n\n` +
        'Refusing to create a second. If you have lost access to that account, use the\n' +
        'Super Admin transfer flow from a signed-in session, or restore from backup —\n' +
        'both leave an audit trail, and this script would not.',
    );
  }

  // Shown once, never stored. Long enough that it is not worth attacking, and
  // the account cannot be used at all until TOTP enrolment completes anyway.
  const password = randomBytes(18).toString('base64url');
  const secret = generateSecret();

  const id = await withTransaction(async (client) => {
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO admin.admin_users
         (email, display_name, password_hash, must_change_password, role_key, status,
          totp_secret_encrypted, totp_enrolled_at)
       VALUES ($1, $2, $3, TRUE, 'super_admin', 'active', $4, NOW())
       RETURNING id`,
      [email, displayName, await hashPassword(password), encryptSecret(secret)],
    );

    const adminId = rows[0]!.id;

    // §7 wants every admin action recorded, and the creation of the account
    // that can do everything is the one most worth having a record of. Written
    // as a system action because there is no actor to attribute it to yet.
    await client.query(
      `INSERT INTO admin.audit_log
         (actor_admin_id, actor_label, origin, action, target_type, target_id,
          target_label, after_state, note, entry_hash)
       VALUES (NULL, 'system:bootstrap-admin', 'system', 'admin.bootstrapped',
               'admin', $1, $2, $3,
               'First Super Admin created from the command line on a database with none.', '')`,
      [
        adminId,
        email,
        JSON.stringify({ role: 'super_admin', displayName, host: target.host }),
      ],
    );

    return adminId;
  });

  console.log(`
  Super Admin created
  -------------------
  id        ${id}
  email     ${email}

  Password (shown once, not stored):

      ${password}

  Two-factor secret — add this to your authenticator app now:

      ${secret}

  otpauth URI:
      ${enrolmentUri(secret, email)}

  Code right now (valid ~30s), to check the secret went in correctly:

      ${generateCode(secret)}

  Sign in, then change the password immediately — the account is flagged
  must_change_password. Delete your shell history if it captured this output.
`);
}

try {
  await main();
} catch (err) {
  console.error(`\n  ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
} finally {
  await closePool();
}
