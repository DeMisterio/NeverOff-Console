import {
  PERMISSIONS,
  REASONS,
  ROLES,
  ROLE_KEYS,
  localiseReason,
} from '@neveroff-console/shared';

import { withTransaction } from './client.js';

/**
 * Push the TypeScript catalogues into the database.
 *
 * There is one source of truth for permissions, roles and reason codes — the
 * files under packages/shared — and the database holds a derived copy so that:
 *
 *   - grants have referential integrity (you cannot grant an atom that does not
 *     exist, and removing an atom removes every grant of it), and
 *   - a compliance reviewer can produce the permission matrix with a plain SQL
 *     query rather than by reading TypeScript.
 *
 * Runs automatically at the end of every `db:migrate`, so a deploy that adds a
 * permission cannot leave the database a version behind.
 *
 * Custom roles created at runtime through `roles.edit` are left untouched: only
 * rows flagged `is_system` are reconciled against the code.
 */

export interface SyncSummary {
  permissions: number;
  roles: number;
  rolePermissions: number;
  reasons: number;
  removed: string[];
}

export async function syncCatalogue(): Promise<SyncSummary> {
  return withTransaction(async (client) => {
    const removed: string[] = [];

    // --- Permissions ------------------------------------------------------
    for (const p of PERMISSIONS) {
      await client.query(
        `INSERT INTO admin.permissions (key, label, description, category, break_glass, pii, super_admin_only)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (key) DO UPDATE SET
           label = EXCLUDED.label,
           description = EXCLUDED.description,
           category = EXCLUDED.category,
           break_glass = EXCLUDED.break_glass,
           pii = EXCLUDED.pii,
           super_admin_only = EXCLUDED.super_admin_only`,
        [p.key, p.label, p.description, p.category, p.breakGlass, p.pii, p.superAdminOnly],
      );
    }

    const staleP = await client.query<{ key: string }>(
      `DELETE FROM admin.permissions
        WHERE key <> ALL($1::text[])
        RETURNING key`,
      [PERMISSIONS.map((p) => p.key)],
    );
    for (const row of staleP.rows) removed.push(`permission:${row.key}`);

    // --- Roles ------------------------------------------------------------
    for (const key of ROLE_KEYS) {
      const role = ROLES[key];
      await client.query(
        `INSERT INTO admin.roles (key, label, description, rank, max_ban_days, singleton, scopable, is_system)
         VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE)
         ON CONFLICT (key) DO UPDATE SET
           label = EXCLUDED.label,
           description = EXCLUDED.description,
           rank = EXCLUDED.rank,
           max_ban_days = EXCLUDED.max_ban_days,
           singleton = EXCLUDED.singleton,
           scopable = EXCLUDED.scopable,
           is_system = TRUE`,
        [
          role.key,
          role.label,
          role.description,
          role.rank,
          role.maxBanDays,
          role.singleton,
          role.scopable,
        ],
      );
    }

    const staleR = await client.query<{ key: string }>(
      `DELETE FROM admin.roles
        WHERE is_system = TRUE AND key <> ALL($1::text[])
        RETURNING key`,
      [[...ROLE_KEYS]],
    );
    for (const row of staleR.rows) removed.push(`role:${row.key}`);

    // --- Role -> permission grants ---------------------------------------
    let grantCount = 0;
    for (const key of ROLE_KEYS) {
      const perms = ROLES[key].permissions;

      // Replace wholesale rather than diffing: the set is small, and a
      // full replace cannot leave a revoked grant behind.
      await client.query(
        `DELETE FROM admin.role_permissions
          WHERE role_key = $1 AND permission_key <> ALL($2::text[])`,
        [key, [...perms]],
      );

      for (const permission of perms) {
        await client.query(
          `INSERT INTO admin.role_permissions (role_key, permission_key)
           VALUES ($1, $2)
           ON CONFLICT DO NOTHING`,
          [key, permission],
        );
        grantCount += 1;
      }
    }

    // --- Reason catalogue -------------------------------------------------
    // Guarded: admin.reason_catalogue arrives in migration 0006, so a partial
    // migration state should not make the whole sync fail.
    const hasReasons = await client.query<{ exists: boolean }>(
      `SELECT EXISTS (
         SELECT 1 FROM information_schema.tables
          WHERE table_schema = 'admin' AND table_name = 'reason_catalogue'
       ) AS exists`,
    );

    let reasonCount = 0;
    if (hasReasons.rows[0]?.exists) {
      for (const r of REASONS) {
        await client.query(
          `INSERT INTO admin.reason_catalogue
             (code, category, policy_clause, appealable, isolated, label_en, label_ru)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (code) DO UPDATE SET
             category = EXCLUDED.category,
             policy_clause = EXCLUDED.policy_clause,
             appealable = EXCLUDED.appealable,
             isolated = EXCLUDED.isolated,
             label_en = EXCLUDED.label_en,
             label_ru = EXCLUDED.label_ru`,
          [
            r.code,
            r.category,
            r.policyClause,
            r.appealable,
            r.isolated,
            localiseReason(r.code, 'en'),
            localiseReason(r.code, 'ru'),
          ],
        );
        reasonCount += 1;
      }

      const staleReasons = await client.query<{ code: string }>(
        `DELETE FROM admin.reason_catalogue
          WHERE code <> ALL($1::text[])
          RETURNING code`,
        [REASONS.map((r) => r.code)],
      );
      for (const row of staleReasons.rows) removed.push(`reason:${row.code}`);
    }

    return {
      permissions: PERMISSIONS.length,
      roles: ROLE_KEYS.length,
      rolePermissions: grantCount,
      reasons: reasonCount,
      removed,
    };
  });
}
