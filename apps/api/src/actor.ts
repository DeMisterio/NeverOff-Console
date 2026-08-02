import { getPool } from '@neveroff-console/db';
import {
  effectiveMaxBanDays,
  resolvePermissions,
  ROLES,
  type AdminIdentity,
  type AdminScope,
  type Permission,
  type RoleKey,
} from '@neveroff-console/shared';
import type { PoolClient } from 'pg';

import { getConfig } from './config.js';

/**
 * The authenticated admin, as every request handler sees them.
 *
 * Permissions are resolved once per request and carried on the actor, so a
 * handler that checks three atoms does not make three round trips — and, more
 * importantly, cannot observe a permission set that changed halfway through its
 * own execution.
 */
export interface Actor extends AdminIdentity {
  readonly email: string;
  readonly displayName: string;
  readonly roleLabel: string;
  readonly rank: number;
  readonly permissions: ReadonlySet<Permission>;
  readonly maxBanDays: number | null;
  readonly sessionId: string;
  readonly ip: string | null;
  readonly userAgent: string | null;
  readonly requestId: string;
}

interface AdminRow {
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
}

const SELECT_ADMIN = `
  SELECT id, email, display_name, role_key, status,
         scope_countries, scope_languages, scope_channel_ids, scope_report_categories,
         extra_permissions, revoked_permissions, max_ban_days_override
    FROM admin.admin_users
   WHERE id = $1
`;

export function rowToScope(row: AdminRow): AdminScope {
  // NULL means "unrestricted on this axis" and must survive the round trip as
  // null, not as an empty array — an empty array means "restricted to nothing"
  // and would deny everything.
  return {
    countries: row.scope_countries,
    languages: row.scope_languages,
    channelIds: row.scope_channel_ids,
    reportCategories: row.scope_report_categories,
  };
}

export function rowToIdentity(row: AdminRow): AdminIdentity {
  return {
    id: row.id,
    role: row.role_key,
    scope: rowToScope(row),
    extraPermissions: (row.extra_permissions ?? []) as Permission[],
    revokedPermissions: (row.revoked_permissions ?? []) as Permission[],
    maxBanDaysOverride: row.max_ban_days_override,
    active: row.status === 'active',
  };
}

export async function loadIdentity(
  adminId: string,
  client?: PoolClient,
): Promise<AdminIdentity | null> {
  const runner = client ?? getPool();
  const result = await runner.query<AdminRow>(SELECT_ADMIN, [adminId]);
  const row = result.rows[0];
  return row ? rowToIdentity(row) : null;
}

export async function buildActor(
  adminId: string,
  session: { sessionId: string; ip: string | null; userAgent: string | null; requestId: string },
  client?: PoolClient,
): Promise<Actor | null> {
  const runner = client ?? getPool();
  const result = await runner.query<AdminRow>(SELECT_ADMIN, [adminId]);
  const row = result.rows[0];
  if (!row) return null;

  const identity = rowToIdentity(row);
  const config = getConfig();

  return {
    ...identity,
    email: row.email,
    displayName: row.display_name,
    roleLabel: ROLES[row.role_key].label,
    rank: ROLES[row.role_key].rank,
    permissions: resolvePermissions(identity),
    // The Tier 2 cap is configuration, not a constant, so the role definition's
    // fallback is overridden from the environment here rather than in shared.
    maxBanDays: effectiveMaxBanDays(identity, {
      tier2_moderation_lead: config.MAX_BAN_DAYS_T2,
    }),
    sessionId: session.sessionId,
    ip: session.ip,
    userAgent: session.userAgent,
    requestId: session.requestId,
  };
}

/** Label used in the audit log, kept stable even after an account is deleted. */
export function actorLabel(actor: Pick<Actor, 'displayName' | 'email'>): string {
  return `${actor.displayName} <${actor.email}>`;
}
