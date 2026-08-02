import { randomBytes } from 'node:crypto';

import { getPool, withTransaction } from '@neveroff-console/db';
import {
  ROLE_KEYS,
  ROLES,
  isPermission,
  isRoleKey,
  resolvePermissions,
  type AdminScope,
  type Permission,
  type RoleKey,
} from '@neveroff-console/shared';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { rowToIdentity } from '../actor.js';
import { writeAudit } from '../audit.js';
import { hashPassword } from '../auth/password.js';
import { revokeAllSessions } from '../auth/session.js';
import { conflict, forbidden, notFound, validationFailed } from '../errors.js';
import { actorOf } from '../plugins/auth.js';
import {
  assertCanDelegate,
  assertCanManageAdmin,
  requireBreakGlass,
  requirePermission,
} from '../rbac.js';

/**
 * Admin accounts and delegation (§1.3).
 *
 * Every mutation here routes through `assertCanDelegate` / `assertCanManageAdmin`
 * in packages/shared, which hold the two invariants: you cannot grant what you
 * do not hold, and you cannot touch an admin of equal or higher rank. Those
 * functions are pure and exhaustively unit-tested; these routes are the thin
 * layer that loads rows and writes audit entries around them.
 */

const ScopeSchema = z.object({
  countries: z.array(z.string().length(2).toUpperCase()).nullable().default(null),
  languages: z.array(z.string().min(2).max(8).toLowerCase()).nullable().default(null),
  channelIds: z.array(z.string().uuid()).nullable().default(null),
  reportCategories: z.array(z.string().min(1).max(60)).nullable().default(null),
});

const AdminRowSchema = z.object({
  id: z.string(),
  email: z.string(),
  displayName: z.string(),
  role: z.string(),
  roleLabel: z.string(),
  rank: z.number(),
  status: z.string(),
  scope: ScopeSchema,
  extraPermissions: z.array(z.string()),
  revokedPermissions: z.array(z.string()),
  effectivePermissionCount: z.number(),
  totpEnrolled: z.boolean(),
  lastLoginAt: z.date().nullable(),
  createdAt: z.date(),
  manageableByYou: z.boolean(),
});

interface AdminDbRow {
  id: string;
  email: string;
  display_name: string;
  role_key: RoleKey;
  status: string;
  scope_countries: string[] | null;
  scope_languages: string[] | null;
  scope_channel_ids: string[] | null;
  scope_report_categories: string[] | null;
  extra_permissions: string[];
  revoked_permissions: string[];
  max_ban_days_override: number | null;
  totp_enrolled_at: Date | null;
  last_login_at: Date | null;
  created_at: Date;
}

const SELECT_COLUMNS = `
  id, email, display_name, role_key, status,
  scope_countries, scope_languages, scope_channel_ids, scope_report_categories,
  extra_permissions, revoked_permissions, max_ban_days_override,
  totp_enrolled_at, last_login_at, created_at
`;

function toScope(row: AdminDbRow): AdminScope {
  return {
    countries: row.scope_countries,
    languages: row.scope_languages,
    channelIds: row.scope_channel_ids,
    reportCategories: row.scope_report_categories,
  };
}

function validatePermissionList(values: readonly string[] | undefined, field: string): Permission[] {
  if (!values) return [];
  const bad = values.filter((v) => !isPermission(v));
  if (bad.length > 0) {
    throw validationFailed(`${field} contains unknown permissions: ${bad.join(', ')}`, { bad });
  }
  return values as Permission[];
}

export default async function adminRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  // -------------------------------------------------------------------------
  app.get(
    '/',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['admins'],
        summary: 'List admin accounts',
        response: { 200: z.array(AdminRowSchema) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      // Seeing who else has access is part of holding admin powers at all;
      // creating or editing them is the gated part.
      requirePermission(actor, 'users.view');

      const { rows } = await getPool().query<AdminDbRow>(
        `SELECT ${SELECT_COLUMNS} FROM admin.admin_users ORDER BY
           (SELECT rank FROM admin.roles r WHERE r.key = role_key) DESC, display_name ASC`,
      );

      return rows.map((row) => {
        const identity = rowToIdentity(row as never);
        return {
          id: row.id,
          email: row.email,
          displayName: row.display_name,
          role: row.role_key,
          roleLabel: ROLES[row.role_key]?.label ?? row.role_key,
          rank: ROLES[row.role_key]?.rank ?? 0,
          status: row.status,
          scope: {
            countries: row.scope_countries,
            languages: row.scope_languages,
            channelIds: row.scope_channel_ids,
            reportCategories: row.scope_report_categories,
          },
          extraPermissions: row.extra_permissions ?? [],
          revokedPermissions: row.revoked_permissions ?? [],
          effectivePermissionCount: resolvePermissions(identity).size,
          totpEnrolled: row.totp_enrolled_at !== null,
          lastLoginAt: row.last_login_at,
          createdAt: row.created_at,
          manageableByYou: assertCanManageAdminSafely(actor, identity),
        };
      });
    },
  );

  // -------------------------------------------------------------------------
  app.post(
    '/',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['admins'],
        summary: 'Create an admin account, optionally scoped',
        body: z.object({
          email: z.string().email().max(320),
          displayName: z.string().trim().min(1).max(120),
          role: z.enum(ROLE_KEYS),
          scope: ScopeSchema.optional(),
          extraPermissions: z.array(z.string()).optional(),
          revokedPermissions: z.array(z.string()).optional(),
          maxBanDaysOverride: z.number().int().min(0).nullable().optional(),
        }),
        response: {
          200: z.object({
            id: z.string(),
            email: z.string(),
            setupPassword: z.string(),
            notice: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'admins.create');

      const body = request.body;
      const scope: AdminScope = body.scope ?? {
        countries: null, languages: null, channelIds: null, reportCategories: null,
      };
      const extras = validatePermissionList(body.extraPermissions, 'extraPermissions');
      const revoked = validatePermissionList(body.revokedPermissions, 'revokedPermissions');

      if (!isRoleKey(body.role)) throw validationFailed('Unknown role.');
      if (!ROLES[body.role].scopable && !isUnscoped(scope)) {
        throw validationFailed(`The ${ROLES[body.role].label} role cannot be scoped.`);
      }

      return withTransaction(async (client) => {
        // Holds both delegation invariants and raises a security alert if the
        // actor is reaching past their own authority.
        await assertCanDelegate(
          client,
          actor,
          { role: body.role, scope, extraPermissions: extras },
          'create',
        );

        const existing = await client.query(
          `SELECT 1 FROM admin.admin_users WHERE lower(email) = lower($1)`,
          [body.email],
        );
        if (existing.rowCount) throw conflict('An admin with that email already exists.');

        // One-time credential. The account starts as `invited`, cannot sign in
        // past the password step without enrolling TOTP, and must change this
        // on first use.
        const setupPassword = randomBytes(18).toString('base64url');

        const { rows } = await client.query<{ id: string }>(
          `INSERT INTO admin.admin_users
             (email, display_name, password_hash, must_change_password, role_key, status,
              scope_countries, scope_languages, scope_channel_ids, scope_report_categories,
              extra_permissions, revoked_permissions, max_ban_days_override, created_by)
           VALUES ($1, $2, $3, TRUE, $4, 'invited', $5, $6, $7, $8, $9, $10, $11, $12)
           RETURNING id`,
          [
            body.email,
            body.displayName,
            await hashPassword(setupPassword),
            body.role,
            scope.countries,
            scope.languages,
            scope.channelIds,
            scope.reportCategories,
            extras,
            revoked,
            body.maxBanDaysOverride ?? null,
            actor.id,
          ],
        );

        const created = rows[0]!;
        await writeAudit(client, actor, {
          action: 'admin.created',
          targetType: 'admin',
          targetId: created.id,
          targetLabel: body.email,
          permission: 'admins.create',
          after: {
            role: body.role,
            scope,
            extraPermissions: extras,
            revokedPermissions: revoked,
          },
        });

        return {
          id: created.id,
          email: body.email,
          setupPassword,
          notice:
            'Give this password to the new admin through a channel other than email, and ' +
            'delete your copy. They must enrol two-factor authentication and change it on ' +
            'first sign-in. It is not stored and cannot be shown again.',
        };
      });
    },
  );

  // -------------------------------------------------------------------------
  app.patch(
    '/:id',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['admins'],
        summary: 'Change an admin’s role, scope, permissions or status',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({
          displayName: z.string().trim().min(1).max(120).optional(),
          role: z.enum(ROLE_KEYS).optional(),
          scope: ScopeSchema.optional(),
          extraPermissions: z.array(z.string()).optional(),
          revokedPermissions: z.array(z.string()).optional(),
          maxBanDaysOverride: z.number().int().min(0).nullable().optional(),
          status: z.enum(['active', 'suspended', 'disabled']).optional(),
        }),
        response: { 200: z.object({ id: z.string(), updated: z.array(z.string()) }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'admins.edit');

      return withTransaction(async (client) => {
        const { rows } = await client.query<AdminDbRow>(
          `SELECT ${SELECT_COLUMNS} FROM admin.admin_users WHERE id = $1 FOR UPDATE`,
          [request.params.id],
        );
        const row = rows[0];
        if (!row) throw notFound('Admin');

        const subject = rowToIdentity(row as never);
        assertCanManageAdmin(actor, subject);

        const body = request.body;
        const nextRole = body.role ?? row.role_key;
        const nextScope = body.scope ?? toScope(row);
        const nextExtras = body.extraPermissions
          ? validatePermissionList(body.extraPermissions, 'extraPermissions')
          : ((row.extra_permissions ?? []) as Permission[]);

        // Re-check delegation against the *resulting* state, not the delta.
        await assertCanDelegate(
          client,
          actor,
          { id: row.id, role: nextRole, scope: nextScope, extraPermissions: nextExtras },
          'edit',
        );

        const updates: string[] = [];
        const params: unknown[] = [row.id];
        const changed: string[] = [];
        const set = (column: string, value: unknown, label: string): void => {
          params.push(value);
          updates.push(`${column} = $${params.length}`);
          changed.push(label);
        };

        if (body.displayName !== undefined) set('display_name', body.displayName, 'displayName');
        if (body.role !== undefined) set('role_key', body.role, 'role');
        if (body.scope !== undefined) {
          set('scope_countries', nextScope.countries, 'scope.countries');
          set('scope_languages', nextScope.languages, 'scope.languages');
          set('scope_channel_ids', nextScope.channelIds, 'scope.channelIds');
          set('scope_report_categories', nextScope.reportCategories, 'scope.reportCategories');
        }
        if (body.extraPermissions !== undefined) set('extra_permissions', nextExtras, 'extraPermissions');
        if (body.revokedPermissions !== undefined) {
          set(
            'revoked_permissions',
            validatePermissionList(body.revokedPermissions, 'revokedPermissions'),
            'revokedPermissions',
          );
        }
        if (body.maxBanDaysOverride !== undefined) {
          set('max_ban_days_override', body.maxBanDaysOverride, 'maxBanDaysOverride');
        }
        if (body.status !== undefined) set('status', body.status, 'status');

        if (updates.length === 0) return { id: row.id, updated: [] };

        await client.query(
          `UPDATE admin.admin_users SET ${updates.join(', ')} WHERE id = $1`,
          params,
        );

        // Losing permissions must take effect now, not at session expiry.
        if (body.role !== undefined || body.status !== undefined || body.revokedPermissions !== undefined) {
          await revokeAllSessions(
            client, row.id, actor.id, 'Permissions changed by another admin.',
          );
        }

        await writeAudit(client, actor, {
          action: 'admin.updated',
          targetType: 'admin',
          targetId: row.id,
          targetLabel: row.email,
          permission: 'admins.edit',
          before: {
            role: row.role_key, status: row.status, scope: toScope(row),
            extraPermissions: row.extra_permissions, revokedPermissions: row.revoked_permissions,
          },
          after: { role: nextRole, status: body.status ?? row.status, scope: nextScope, extraPermissions: nextExtras },
          note: `Changed: ${changed.join(', ')}`,
        });

        return { id: row.id, updated: changed };
      });
    },
  );

  // -------------------------------------------------------------------------
  app.delete(
    '/:id',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['admins'],
        summary: 'Delete an admin account (Super Admin only)',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({
          reason: z.string().trim().min(10).max(500),
          confirmationPhrase: z.string().max(300),
        }),
        response: { 200: z.object({ id: z.string(), deleted: z.literal(true) }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'admins.delete');

      return withTransaction(async (client) => {
        const { rows } = await client.query<AdminDbRow>(
          `SELECT ${SELECT_COLUMNS} FROM admin.admin_users WHERE id = $1 FOR UPDATE`,
          [request.params.id],
        );
        const row = rows[0];
        if (!row) throw notFound('Admin');

        assertCanManageAdmin(actor, rowToIdentity(row as never));

        await requireBreakGlass(
          client,
          actor,
          {
            permission: 'admins.delete',
            action: 'admins.delete',
            targetType: 'admin',
            targetId: row.id,
            targetLabel: row.email,
            payload: { id: row.id, email: row.email },
          },
          { confirmationPhrase: request.body.confirmationPhrase, justification: request.body.reason },
        );

        // Audit first. The FK from audit_log to admin_users is ON DELETE SET
        // NULL and actor_label is denormalised, so the record of this deletion
        // survives the row it describes.
        await writeAudit(client, actor, {
          action: 'admin.deleted',
          targetType: 'admin',
          targetId: row.id,
          targetLabel: row.email,
          permission: 'admins.delete',
          note: request.body.reason,
          before: { role: row.role_key, status: row.status, email: row.email },
        });

        await client.query(`DELETE FROM admin.admin_users WHERE id = $1`, [row.id]);
        return { id: row.id, deleted: true as const };
      });
    },
  );

  // -------------------------------------------------------------------------
  app.post(
    '/:id/force-totp-reenrolment',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['admins'],
        summary: 'Force an admin to enrol a new second factor (§1.3)',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({ reason: z.string().trim().min(10).max(500) }),
        response: { 200: z.object({ id: z.string(), sessionsRevoked: z.number() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'admins.edit');

      return withTransaction(async (client) => {
        const { rows } = await client.query<AdminDbRow>(
          `SELECT ${SELECT_COLUMNS} FROM admin.admin_users WHERE id = $1 FOR UPDATE`,
          [request.params.id],
        );
        const row = rows[0];
        if (!row) throw notFound('Admin');
        assertCanManageAdmin(actor, rowToIdentity(row as never));

        await client.query(
          `UPDATE admin.admin_users
              SET totp_reenrollment_forced = TRUE,
                  totp_enrolled_at = NULL,
                  totp_last_step = NULL,
                  totp_recovery_hashes = '{}'
            WHERE id = $1`,
          [row.id],
        );

        const revoked = await revokeAllSessions(
          client, row.id, actor.id, 'Two-factor re-enrolment forced.',
        );

        await writeAudit(client, actor, {
          action: 'admin.totp.reenrolment_forced',
          targetType: 'admin',
          targetId: row.id,
          targetLabel: row.email,
          permission: 'admins.edit',
          note: request.body.reason,
        });

        return { id: row.id, sessionsRevoked: revoked };
      });
    },
  );

  // -------------------------------------------------------------------------
  app.post(
    '/transfer-super-admin',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['admins'],
        summary: 'Transfer the Super Admin role to another active admin',
        body: z.object({
          toAdminId: z.string().uuid(),
          newRoleForYou: z.enum(ROLE_KEYS).default('tier1_platform_manager'),
          confirmationPhrase: z.string().max(300),
          reason: z.string().trim().min(10).max(500),
        }),
        response: { 200: z.object({ from: z.string(), to: z.string() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      if (actor.role !== 'super_admin') {
        throw forbidden('Only the current Super Admin can transfer the role.');
      }
      if (request.body.newRoleForYou === 'super_admin') {
        throw validationFailed('Pick a different role for yourself after the transfer.');
      }

      return withTransaction(async (client) => {
        const { rows } = await client.query<{ email: string; status: string }>(
          `SELECT email, status FROM admin.admin_users WHERE id = $1`,
          [request.body.toAdminId],
        );
        const target = rows[0];
        if (!target) throw notFound('Admin');
        if (target.status !== 'active') {
          throw conflict('The new Super Admin must be an active account with TOTP enrolled.');
        }

        await requireBreakGlass(
          client,
          actor,
          {
            permission: 'admins.edit',
            action: 'transfer.super.admin',
            targetType: 'admin',
            targetId: request.body.toAdminId,
            targetLabel: target.email,
            payload: { to: request.body.toAdminId },
            forceMode: 'typed_phrase',
          },
          { confirmationPhrase: request.body.confirmationPhrase, justification: request.body.reason },
        );

        // Atomic, and the only path the protect_super_admin trigger permits.
        await client.query(`SELECT admin.transfer_super_admin($1, $2, $3)`, [
          actor.id,
          request.body.toAdminId,
          request.body.newRoleForYou,
        ]);

        await writeAudit(client, actor, {
          action: 'admin.super_admin.transferred',
          targetType: 'admin',
          targetId: request.body.toAdminId,
          targetLabel: target.email,
          note: request.body.reason,
          before: { superAdmin: actor.id },
          after: { superAdmin: request.body.toAdminId, previousBecame: request.body.newRoleForYou },
        });

        return { from: actor.id, to: request.body.toAdminId };
      });
    },
  );
}

function isUnscoped(scope: AdminScope): boolean {
  return (
    scope.countries === null &&
    scope.languages === null &&
    scope.channelIds === null &&
    scope.reportCategories === null
  );
}

/** Boolean form for list rendering; the throwing form guards the writes. */
function assertCanManageAdminSafely(
  actor: Parameters<typeof assertCanManageAdmin>[0],
  subject: Parameters<typeof assertCanManageAdmin>[1],
): boolean {
  try {
    assertCanManageAdmin(actor, subject);
    return true;
  } catch {
    return false;
  }
}
