/**
 * Roles, scopes, and the delegation rules from §1.3.
 *
 * A role is nothing more than a named bundle of permission atoms plus a couple
 * of numeric caps. All authorisation decisions are made against the *resolved*
 * atom set (see `resolvePermissions`), never against the role name.
 *
 * The two invariants this file exists to enforce:
 *
 *   1. No privilege escalation. An admin can never grant a permission they do
 *      not themselves hold, nor a scope broader than their own, nor touch an
 *      admin of equal or higher rank.
 *   2. Fail closed. Super-Admin-only atoms are stripped from every non-Super-
 *      Admin's effective set even if a corrupted role row or a direct grant
 *      names them.
 */

import {
  ALL_PERMISSIONS,
  isPermission,
  SUPER_ADMIN_ONLY,
  type Permission,
} from './permissions.js';

export const ROLE_KEYS = [
  'super_admin',
  'tier1_platform_manager',
  'tier2_moderation_lead',
  'tier3_moderator',
  'analyst',
] as const;

export type RoleKey = (typeof ROLE_KEYS)[number];

export interface RoleDefinition {
  readonly key: RoleKey;
  readonly label: string;
  readonly description: string;
  /**
   * Strictly ordered. An admin may only create, edit or delete admins of a
   * *strictly lower* rank — so two Tier 1s can never demote each other, and
   * nobody can touch the Super Admin.
   */
  readonly rank: number;
  /** Atoms this role bundles. Ignored for super_admin, which holds everything. */
  readonly permissions: readonly Permission[];
  /**
   * Longest temporary ban this role may issue, in days.
   * `null` = unlimited. `0` = may not ban at all.
   * Enforced server-side on every ban request, not just hidden in the UI.
   */
  readonly maxBanDays: number | null;
  /** Only ever one holder, and they cannot be banned or demoted (§1.1). */
  readonly singleton: boolean;
  /** Whether the role may be scoped to regions/languages/channels/categories. */
  readonly scopable: boolean;
}

/**
 * Where the spec was ambiguous, the narrower reading won and the reasoning is
 * recorded inline. Under-granting surfaces as a moderator asking for access;
 * over-granting surfaces as an incident.
 */
const TIER1_PERMISSIONS: readonly Permission[] = [
  'analytics.view',
  'analytics.export',
  'users.view',
  'users.search',
  'users.view_pii',
  'users.contact',
  'users.note',
  'users.warn',
  'users.restrict',
  'users.mute',
  'users.shadow_restrict',
  'users.ban.temp',
  'users.ban.permanent',
  'users.unban',
  'channels.view',
  'channels.restrict',
  'channels.takedown',
  'reports.view',
  'reports.triage',
  'reports.resolve',
  'reports.escalate',
  'reports.reopen',
  'support.view',
  'support.reply',
  'support.assign',
  'admins.create',
  'admins.edit',
  'audit.view',
  'settings.edit',
  'automod.configure',
  'privacy.dsr.view',
  'privacy.dsr.process',
  'legalhold.manage',
  'transparency.generate',
];

const TIER2_PERMISSIONS: readonly Permission[] = [
  // "view analytics (read-only)" — view without export.
  'analytics.view',
  'users.view',
  'users.search',
  // Granted: a Moderation Lead reviewing ban-evasion and override requests
  // needs the connections graph, which is the whole point of users.view_pii.
  'users.view_pii',
  'users.contact',
  'users.note',
  'users.warn',
  'users.restrict',
  'users.mute',
  'users.ban.temp',
  'users.unban',
  // Withheld: shadow restriction is deceptive by construction. §3.3 says "use
  // sparingly"; keeping it at Tier 1 and above makes that structural.
  'channels.view',
  'channels.restrict',
  'reports.view',
  'reports.triage',
  'reports.resolve',
  'reports.escalate',
  'reports.reopen',
  'support.view',
  'support.reply',
  'support.assign',
  // Scoped audit access — the resolver narrows what rows this actually returns.
  'audit.view',
];

const TIER3_PERMISSIONS: readonly Permission[] = [
  'users.view',
  'users.search',
  'users.contact',
  'users.note',
  // §1.1 enumerates exactly "warnings and mutes" for this tier.
  'users.warn',
  'users.mute',
  // Withheld: users.view_pii. §1.1 — "Cannot see PII beyond what the case
  // requires". Case-scoped reveals are handled by a separate, individually
  // audited just-in-time grant rather than a standing permission.
  'channels.view',
  'reports.view',
  'reports.triage',
  // Granted: without it a Tier 3 could warn a user but never close the case
  // they actioned, which just moves the work to someone else.
  'reports.resolve',
  'reports.escalate',
  // Withheld: reports.reopen. §1.1 gives Tier 2 the power to "override Tier 3
  // decisions"; that only means something if Tier 3 cannot reopen its own.
  'support.view',
  'support.reply',
  // Withheld: support.assign. §1.1 gives ticket reassignment to Tier 2.
];

const ANALYST_PERMISSIONS: readonly Permission[] = ['analytics.view', 'analytics.export'];

export const ROLES: Readonly<Record<RoleKey, RoleDefinition>> = {
  super_admin: {
    key: 'super_admin',
    label: 'Super Admin',
    description:
      'Global. Exactly one, transferable. Holds every permission including role definitions, admin deletion, raw export, retention policy and account purge. Cannot be banned or demoted.',
    rank: 100,
    permissions: ALL_PERMISSIONS,
    maxBanDays: null,
    singleton: true,
    scopable: false,
  },
  tier1_platform_manager: {
    key: 'tier1_platform_manager',
    label: 'Tier 1 — Platform Manager',
    description:
      'Global. All analytics, all user management, ban/unban, all moderation queues, automation rules, and management of Tier 2/3 accounts. Cannot alter role definitions or delete admins.',
    rank: 80,
    permissions: TIER1_PERMISSIONS,
    maxBanDays: null,
    singleton: false,
    scopable: true,
  },
  tier2_moderation_lead: {
    key: 'tier2_moderation_lead',
    label: 'Tier 2 — Moderation Lead',
    description:
      'Scoped to assigned queues, regions or languages. Full moderation queue, bounded temporary bans, override of Tier 3 decisions, ticket reassignment, read-only analytics.',
    rank: 60,
    permissions: TIER2_PERMISSIONS,
    // Overridden at runtime from MAX_BAN_DAYS_T2; this is the fallback.
    maxBanDays: 30,
    singleton: false,
    scopable: true,
  },
  tier3_moderator: {
    key: 'tier3_moderator',
    label: 'Tier 3 — Moderator / Support Agent',
    description:
      'Scoped to assigned queues only. Triage reports, apply warnings and mutes, escalate, answer @support tickets. No bans, no standing PII access.',
    rank: 40,
    permissions: TIER3_PERMISSIONS,
    maxBanDays: 0,
    singleton: false,
    scopable: true,
  },
  analyst: {
    key: 'analyst',
    label: 'Analyst',
    description:
      'Read-only. Analytics dashboards and aggregate exports only. No user records, no moderation, no message metadata.',
    rank: 20,
    permissions: ANALYST_PERMISSIONS,
    maxBanDays: 0,
    singleton: false,
    scopable: false,
  },
};

export function isRoleKey(value: unknown): value is RoleKey {
  return typeof value === 'string' && (ROLE_KEYS as readonly string[]).includes(value);
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/**
 * A scope narrows *which records* an admin's permissions apply to (§1.3).
 * `null` on an axis means "unrestricted on this axis" — deliberately not an
 * empty array, which means "restricted to nothing" and would deny everything.
 */
export interface AdminScope {
  /** ISO 3166-1 alpha-2, uppercase. */
  readonly countries: readonly string[] | null;
  /** BCP-47 primary subtags, lowercase. */
  readonly languages: readonly string[] | null;
  readonly channelIds: readonly string[] | null;
  readonly reportCategories: readonly string[] | null;
}

export const GLOBAL_SCOPE: AdminScope = {
  countries: null,
  languages: null,
  channelIds: null,
  reportCategories: null,
};

export function isGlobalScope(scope: AdminScope): boolean {
  return (
    scope.countries === null &&
    scope.languages === null &&
    scope.channelIds === null &&
    scope.reportCategories === null
  );
}

type ScopeAxis = keyof AdminScope;
const SCOPE_AXES: readonly ScopeAxis[] = [
  'countries',
  'languages',
  'channelIds',
  'reportCategories',
];

/**
 * Does `outer` fully contain `inner`?
 *
 * Unrestricted outer contains anything. A restricted outer never contains an
 * unrestricted inner — that is precisely the escalation we are blocking, e.g. a
 * DE-scoped lead trying to mint a globally-scoped moderator.
 */
export function scopeContains(outer: AdminScope, inner: AdminScope): boolean {
  for (const axis of SCOPE_AXES) {
    const o = outer[axis];
    if (o === null) continue;
    const i = inner[axis];
    if (i === null) return false;
    const allowed = new Set(o);
    for (const value of i) {
      if (!allowed.has(value)) return false;
    }
  }
  return true;
}

/** Does this scope permit acting on a record with these attributes? */
export function scopeAdmits(
  scope: AdminScope,
  subject: {
    country?: string | null;
    language?: string | null;
    channelId?: string | null;
    reportCategory?: string | null;
  },
): boolean {
  const checks: [readonly string[] | null, string | null | undefined][] = [
    [scope.countries, subject.country],
    [scope.languages, subject.language],
    [scope.channelIds, subject.channelId],
    [scope.reportCategories, subject.reportCategory],
  ];
  for (const [allowed, value] of checks) {
    if (allowed === null) continue;
    // A scoped admin cannot act on a record whose attribute is unknown. If we
    // do not know a user's country we cannot claim they are inside a DE-only
    // moderator's remit, so we deny.
    if (value === null || value === undefined) return false;
    if (!allowed.includes(value)) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Effective permissions
// ---------------------------------------------------------------------------

export interface AdminIdentity {
  readonly id: string;
  readonly role: RoleKey;
  readonly scope: AdminScope;
  /** Atoms granted on top of the role bundle. */
  readonly extraPermissions: readonly Permission[];
  /** Atoms removed from the role bundle for this individual. */
  readonly revokedPermissions: readonly Permission[];
  /** Per-admin override of the role's ban cap. Never widens past the role's. */
  readonly maxBanDaysOverride?: number | null;
  readonly active: boolean;
}

/**
 * Resolve the atoms an admin actually holds.
 *
 * Order matters: role bundle, plus extras, minus revocations, then the
 * Super-Admin-only filter last so nothing can slip past it. An inactive admin
 * resolves to the empty set rather than throwing — callers then fail every
 * permission check naturally instead of needing a separate liveness branch.
 */
export function resolvePermissions(admin: AdminIdentity): ReadonlySet<Permission> {
  if (!admin.active) return new Set();

  if (admin.role === 'super_admin') {
    return new Set(ALL_PERMISSIONS);
  }

  const effective = new Set<Permission>(ROLES[admin.role].permissions);

  for (const p of admin.extraPermissions) {
    if (isPermission(p)) effective.add(p);
  }
  for (const p of admin.revokedPermissions) {
    effective.delete(p);
  }
  for (const reserved of SUPER_ADMIN_ONLY) {
    effective.delete(reserved);
  }

  return effective;
}

export function hasPermission(admin: AdminIdentity, permission: Permission): boolean {
  return resolvePermissions(admin).has(permission);
}

/** Longest temporary ban this admin may issue, in days. `null` = unlimited. */
export function effectiveMaxBanDays(
  admin: AdminIdentity,
  roleCapOverride?: Partial<Record<RoleKey, number | null>>,
): number | null {
  if (admin.role === 'super_admin') return null;

  const roleCap =
    roleCapOverride && admin.role in roleCapOverride
      ? (roleCapOverride[admin.role] ?? null)
      : ROLES[admin.role].maxBanDays;

  const override = admin.maxBanDaysOverride;
  if (override === undefined) return roleCap;
  if (override === null) return roleCap; // an override may not lift a role cap
  if (roleCap === null) return override;
  return Math.min(override, roleCap);
}

// ---------------------------------------------------------------------------
// Delegation guards (§1.3)
// ---------------------------------------------------------------------------

export type DelegationDenial =
  | { ok: true }
  | { ok: false; code: DelegationDenialCode; message: string; details?: Record<string, unknown> };

export type DelegationDenialCode =
  | 'inactive_actor'
  | 'missing_permission'
  | 'rank_not_lower'
  | 'cannot_touch_super_admin'
  | 'permission_not_held'
  | 'reserved_permission'
  | 'scope_not_contained'
  | 'role_rank_not_lower'
  | 'self_modification';

const OK: DelegationDenial = { ok: true };

/**
 * May `actor` create or modify an admin account holding `targetRole`,
 * `targetScope` and `targetExtras`?
 *
 * Checked on every write, server-side. The UI hides what it can, but the UI is
 * not a security boundary.
 */
export function canDelegate(
  actor: AdminIdentity,
  target: {
    id?: string;
    role: RoleKey;
    scope: AdminScope;
    extraPermissions?: readonly Permission[];
  },
  action: 'create' | 'edit' | 'delete',
): DelegationDenial {
  if (!actor.active) {
    return { ok: false, code: 'inactive_actor', message: 'Acting admin account is not active.' };
  }

  if (target.id && target.id === actor.id) {
    return {
      ok: false,
      code: 'self_modification',
      message:
        'An admin cannot change their own role, scope or permissions. Ask another admin of higher rank.',
    };
  }

  const required: Permission =
    action === 'create' ? 'admins.create' : action === 'edit' ? 'admins.edit' : 'admins.delete';
  const held = resolvePermissions(actor);
  if (!held.has(required)) {
    return {
      ok: false,
      code: 'missing_permission',
      message: `Requires ${required}.`,
      details: { required },
    };
  }

  // Nobody may touch the Super Admin. Transfer is a separate, deliberate flow.
  if (target.role === 'super_admin') {
    return {
      ok: false,
      code: 'cannot_touch_super_admin',
      message:
        'The Super Admin role cannot be assigned or removed here. Use the Super Admin transfer flow.',
    };
  }

  // Strictly lower rank. Equal rank is denied so peers cannot demote each other.
  const actorRank = ROLES[actor.role].rank;
  const targetRank = ROLES[target.role].rank;
  if (targetRank >= actorRank) {
    return {
      ok: false,
      code: 'role_rank_not_lower',
      message: `A ${ROLES[actor.role].label} cannot manage a ${ROLES[target.role].label}.`,
      details: { actorRank, targetRank },
    };
  }

  // Reserved atoms must be rejected explicitly, before the check below.
  //
  // resolvePermissions() strips Super-Admin-only atoms as a fail-closed
  // backstop, which means a request naming one never reaches the
  // `permission_not_held` loop — the guard would return ok, the atom would be
  // quietly dropped, and the caller would be told the grant succeeded. Worse,
  // assertCanDelegate would raise no escalation alert, so an admin probing for
  // reserved permissions would leave no trace.
  //
  // The effective grant was always safe. The reporting was not.
  for (const permission of target.extraPermissions ?? []) {
    if ((SUPER_ADMIN_ONLY as readonly string[]).includes(permission)) {
      return {
        ok: false,
        code: 'reserved_permission',
        message: `"${permission}" is reserved to the Super Admin and cannot be granted to anyone.`,
        details: { permission },
      };
    }
  }

  // Every atom the target would hold must be held by the actor.
  const wouldHold = resolvePermissions({
    id: target.id ?? '',
    role: target.role,
    scope: target.scope,
    extraPermissions: target.extraPermissions ?? [],
    revokedPermissions: [],
    active: true,
  });

  for (const p of wouldHold) {
    if (!held.has(p)) {
      return {
        ok: false,
        code: 'permission_not_held',
        message: `Cannot grant "${p}" — you do not hold it yourself.`,
        details: { permission: p },
      };
    }
  }

  // Scope may only ever narrow.
  if (!scopeContains(actor.scope, target.scope)) {
    return {
      ok: false,
      code: 'scope_not_contained',
      message: 'The requested scope is broader than your own.',
      details: { actorScope: actor.scope, targetScope: target.scope },
    };
  }

  return OK;
}

/** May `actor` manage the existing admin `subject` at all, whatever the change? */
export function canManageAdmin(actor: AdminIdentity, subject: AdminIdentity): DelegationDenial {
  if (!actor.active) {
    return { ok: false, code: 'inactive_actor', message: 'Acting admin account is not active.' };
  }
  if (actor.id === subject.id) {
    return {
      ok: false,
      code: 'self_modification',
      message: 'An admin cannot administer their own account.',
    };
  }
  if (subject.role === 'super_admin') {
    return {
      ok: false,
      code: 'cannot_touch_super_admin',
      message: 'The Super Admin cannot be modified, suspended or deleted by another admin.',
    };
  }
  if (ROLES[subject.role].rank >= ROLES[actor.role].rank) {
    return {
      ok: false,
      code: 'rank_not_lower',
      message: 'You can only manage admins of a strictly lower rank.',
    };
  }
  if (!scopeContains(actor.scope, subject.scope)) {
    return {
      ok: false,
      code: 'scope_not_contained',
      message: 'That admin operates outside your scope.',
    };
  }
  return OK;
}
