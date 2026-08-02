import { describe, expect, it } from 'vitest';

import {
  ALL_PERMISSIONS,
  PERMISSIONS,
  SUPER_ADMIN_ONLY,
  permissionMeta,
  type Permission,
} from './permissions.js';
import {
  GLOBAL_SCOPE,
  ROLES,
  ROLE_KEYS,
  canDelegate,
  canManageAdmin,
  effectiveMaxBanDays,
  hasPermission,
  resolvePermissions,
  scopeAdmits,
  scopeContains,
  type AdminIdentity,
  type AdminScope,
  type RoleKey,
} from './roles.js';

/**
 * Exhaustive authorisation tests.
 *
 * §9.3: "Permission checks in particular need exhaustive tests — a bug there is
 * a security incident." So the first block below really does assert every role
 * against every atom, rather than sampling. 5 roles × the full catalogue.
 *
 * The expected grid is expressed as invariants rather than a hardcoded 200-cell
 * table, because a hardcoded table gets regenerated from the implementation the
 * first time it fails, which turns the test into a tautology. Invariants keep
 * failing until someone thinks about whether the change was intended.
 */

function identity(role: RoleKey, overrides: Partial<AdminIdentity> = {}): AdminIdentity {
  return {
    id: `admin-${role}`,
    role,
    scope: GLOBAL_SCOPE,
    extraPermissions: [],
    revokedPermissions: [],
    active: true,
    ...overrides,
  };
}

const scope = (partial: Partial<AdminScope>): AdminScope => ({ ...GLOBAL_SCOPE, ...partial });

describe('permission catalogue integrity', () => {
  it('has no duplicate keys', () => {
    expect(new Set(ALL_PERMISSIONS).size).toBe(ALL_PERMISSIONS.length);
  });

  it('covers every atom named in the §1.2 minimum set', () => {
    const required: Permission[] = [
      'analytics.view', 'analytics.export',
      'users.view', 'users.view_pii', 'users.search',
      'users.contact', 'users.warn', 'users.mute',
      'users.ban.temp', 'users.ban.permanent', 'users.unban',
      'channels.view', 'channels.restrict', 'channels.takedown',
      'reports.view', 'reports.triage', 'reports.resolve',
      'reports.escalate', 'reports.reopen',
      'support.view', 'support.reply', 'support.assign',
      'admins.create', 'admins.edit', 'admins.delete',
      'roles.edit', 'audit.view', 'settings.edit',
      'automod.configure', 'retention.configure',
    ];
    for (const key of required) {
      expect(ALL_PERMISSIONS, `spec atom ${key} is missing`).toContain(key);
    }
  });

  it('documents a justification for every atom added beyond the spec', () => {
    const specAtoms = new Set<string>([
      'analytics.view', 'analytics.export', 'users.view', 'users.view_pii', 'users.search',
      'users.contact', 'users.warn', 'users.mute', 'users.ban.temp', 'users.ban.permanent',
      'users.unban', 'channels.view', 'channels.restrict', 'channels.takedown', 'reports.view',
      'reports.triage', 'reports.resolve', 'reports.escalate', 'reports.reopen', 'support.view',
      'support.reply', 'support.assign', 'admins.create', 'admins.edit', 'admins.delete',
      'roles.edit', 'audit.view', 'settings.edit', 'automod.configure', 'retention.configure',
    ]);

    for (const meta of PERMISSIONS) {
      if (!specAtoms.has(meta.key)) {
        expect(meta.addedBeyondSpec, `${meta.key} was added but not justified`).toBeTruthy();
      }
    }
  });

  it('marks every terminal or irreversible action as break-glass', () => {
    for (const key of ['users.ban.permanent', 'users.delete', 'channels.takedown', 'admins.delete'] as const) {
      expect(permissionMeta(key).breakGlass, `${key} should require break-glass`).not.toBe('none');
    }
  });
});

describe('every role against every permission', () => {
  const resolved = new Map<RoleKey, ReadonlySet<Permission>>(
    ROLE_KEYS.map((role) => [role, resolvePermissions(identity(role))]),
  );

  it('gives the Super Admin every atom without exception', () => {
    const superAdmin = resolved.get('super_admin')!;
    for (const permission of ALL_PERMISSIONS) {
      expect(superAdmin.has(permission), `super_admin missing ${permission}`).toBe(true);
    }
    expect(superAdmin.size).toBe(ALL_PERMISSIONS.length);
  });

  it('withholds every Super-Admin-only atom from every other role', () => {
    for (const role of ROLE_KEYS) {
      if (role === 'super_admin') continue;
      for (const reserved of SUPER_ADMIN_ONLY) {
        expect(
          resolved.get(role)!.has(reserved),
          `${role} must not hold reserved atom ${reserved}`,
        ).toBe(false);
      }
    }
  });

  it('resolves a decision for every (role, permission) pair', () => {
    let checked = 0;
    for (const role of ROLE_KEYS) {
      for (const permission of ALL_PERMISSIONS) {
        expect(typeof resolved.get(role)!.has(permission)).toBe('boolean');
        checked += 1;
      }
    }
    expect(checked).toBe(ROLE_KEYS.length * ALL_PERMISSIONS.length);
  });

  it('nests the moderation tiers: Tier 1 ⊇ Tier 2 ⊇ Tier 3', () => {
    const t1 = resolved.get('tier1_platform_manager')!;
    const t2 = resolved.get('tier2_moderation_lead')!;
    const t3 = resolved.get('tier3_moderator')!;

    for (const p of t2) expect(t1.has(p), `Tier 1 should hold everything Tier 2 does (${p})`).toBe(true);
    for (const p of t3) expect(t2.has(p), `Tier 2 should hold everything Tier 3 does (${p})`).toBe(true);

    // Strictly larger, not merely equal — otherwise the tiers are decorative.
    expect(t1.size).toBeGreaterThan(t2.size);
    expect(t2.size).toBeGreaterThan(t3.size);
  });

  it('keeps the Analyst orthogonal to the moderation tiers, not below them', () => {
    const analyst = resolved.get('analyst')!;
    const t3 = resolved.get('tier3_moderator')!;

    // Analyst holds analytics.export, which Tier 3 does not — so "lower rank"
    // does not mean "fewer permissions" across the whole lattice. Delegation
    // relies on rank, and this test exists so nobody assumes a total ordering.
    expect(analyst.has('analytics.export')).toBe(true);
    expect(t3.has('analytics.export')).toBe(false);
    expect([...analyst].every((p) => t3.has(p))).toBe(false);
  });

  describe('§1.1 role descriptions', () => {
    it('Tier 1 cannot alter role definitions or delete admins', () => {
      const t1 = resolved.get('tier1_platform_manager')!;
      expect(t1.has('roles.edit')).toBe(false);
      expect(t1.has('admins.delete')).toBe(false);
      expect(t1.has('admins.create')).toBe(true);
      expect(t1.has('admins.edit')).toBe(true);
    });

    it('Tier 2 has read-only analytics', () => {
      const t2 = resolved.get('tier2_moderation_lead')!;
      expect(t2.has('analytics.view')).toBe(true);
      expect(t2.has('analytics.export')).toBe(false);
    });

    it('Tier 2 cannot permanently ban or shadow-restrict', () => {
      const t2 = resolved.get('tier2_moderation_lead')!;
      expect(t2.has('users.ban.permanent')).toBe(false);
      expect(t2.has('users.shadow_restrict')).toBe(false);
      expect(t2.has('users.ban.temp')).toBe(true);
    });

    it('Tier 3 cannot ban at all and has no standing PII access', () => {
      const t3 = resolved.get('tier3_moderator')!;
      expect(t3.has('users.ban.permanent')).toBe(false);
      expect(t3.has('users.ban.temp')).toBe(false);
      expect(t3.has('users.view_pii')).toBe(false);
      expect(t3.has('users.warn')).toBe(true);
      expect(t3.has('users.mute')).toBe(true);
    });

    it('Tier 3 cannot reopen its own decisions, so Tier 2 override means something', () => {
      expect(resolved.get('tier3_moderator')!.has('reports.reopen')).toBe(false);
      expect(resolved.get('tier2_moderation_lead')!.has('reports.reopen')).toBe(true);
    });

    it('Analyst sees no user records and no moderation', () => {
      const analyst = resolved.get('analyst')!;
      expect([...analyst].sort()).toEqual(['analytics.export', 'analytics.view']);
      expect(analyst.has('users.view')).toBe(false);
      expect(analyst.has('reports.view')).toBe(false);
      expect(analyst.has('support.view')).toBe(false);
    });

    it('never grants child-safety access through an ordinary role bundle', () => {
      for (const role of ROLE_KEYS) {
        if (role === 'super_admin') continue;
        expect(
          resolved.get(role)!.has('childsafety.access'),
          `${role} must not reach the isolated pipeline via its role`,
        ).toBe(false);
      }
    });
  });
});

describe('individual grant adjustments', () => {
  it('adds extra permissions on top of the role bundle', () => {
    const admin = identity('tier3_moderator', { extraPermissions: ['users.ban.temp'] });
    expect(hasPermission(admin, 'users.ban.temp')).toBe(true);
  });

  it('removes revoked permissions from the role bundle', () => {
    const admin = identity('tier3_moderator', { revokedPermissions: ['users.mute'] });
    expect(hasPermission(admin, 'users.mute')).toBe(false);
  });

  it('applies revocation after addition, so a revoked extra stays revoked', () => {
    const admin = identity('tier3_moderator', {
      extraPermissions: ['users.ban.temp'],
      revokedPermissions: ['users.ban.temp'],
    });
    expect(hasPermission(admin, 'users.ban.temp')).toBe(false);
  });

  it('strips Super-Admin-only atoms even when granted directly', () => {
    // The fail-closed backstop: a corrupted row or a bug in the admin editor
    // must not be able to hand out roles.edit.
    const admin = identity('tier1_platform_manager', {
      extraPermissions: ['roles.edit', 'admins.delete', 'retention.configure'],
    });
    expect(hasPermission(admin, 'roles.edit')).toBe(false);
    expect(hasPermission(admin, 'admins.delete')).toBe(false);
    expect(hasPermission(admin, 'retention.configure')).toBe(false);
  });

  it('gives an inactive admin nothing at all', () => {
    for (const role of ROLE_KEYS) {
      expect(resolvePermissions(identity(role, { active: false })).size).toBe(0);
    }
  });
});

describe('ban duration caps', () => {
  it('leaves the Super Admin and Tier 1 uncapped', () => {
    expect(effectiveMaxBanDays(identity('super_admin'))).toBeNull();
    expect(effectiveMaxBanDays(identity('tier1_platform_manager'))).toBeNull();
  });

  it('caps Tier 2 at the configured value', () => {
    expect(
      effectiveMaxBanDays(identity('tier2_moderation_lead'), { tier2_moderation_lead: 14 }),
    ).toBe(14);
  });

  it('gives Tier 3 and Analyst a cap of zero', () => {
    expect(effectiveMaxBanDays(identity('tier3_moderator'))).toBe(0);
    expect(effectiveMaxBanDays(identity('analyst'))).toBe(0);
  });

  it('lets a per-admin override tighten a role cap but never loosen it', () => {
    const tightened = identity('tier2_moderation_lead', { maxBanDaysOverride: 3 });
    expect(effectiveMaxBanDays(tightened, { tier2_moderation_lead: 30 })).toBe(3);

    const attemptedWiden = identity('tier2_moderation_lead', { maxBanDaysOverride: 365 });
    expect(effectiveMaxBanDays(attemptedWiden, { tier2_moderation_lead: 30 })).toBe(30);
  });
});

describe('scope containment', () => {
  it('treats an unrestricted scope as containing everything', () => {
    expect(scopeContains(GLOBAL_SCOPE, scope({ countries: ['DE'] }))).toBe(true);
    expect(scopeContains(GLOBAL_SCOPE, GLOBAL_SCOPE)).toBe(true);
  });

  it('refuses to let a restricted scope contain an unrestricted one', () => {
    // The core escalation: a DE-scoped lead minting a global moderator.
    expect(scopeContains(scope({ countries: ['DE'] }), GLOBAL_SCOPE)).toBe(false);
  });

  it('allows narrowing within an axis but not widening', () => {
    const outer = scope({ countries: ['DE', 'AT', 'CH'] });
    expect(scopeContains(outer, scope({ countries: ['DE'] }))).toBe(true);
    expect(scopeContains(outer, scope({ countries: ['DE', 'FR'] }))).toBe(false);
  });

  it('checks each axis independently', () => {
    const outer = scope({ countries: ['DE'], languages: ['de', 'en'] });
    expect(scopeContains(outer, scope({ countries: ['DE'], languages: ['de'] }))).toBe(true);
    expect(scopeContains(outer, scope({ countries: ['DE'], languages: ['fr'] }))).toBe(false);
  });
});

describe('scope admission', () => {
  it('admits everything for a global scope', () => {
    expect(scopeAdmits(GLOBAL_SCOPE, { country: 'BR' })).toBe(true);
    expect(scopeAdmits(GLOBAL_SCOPE, { country: null })).toBe(true);
  });

  it('admits a subject inside the scope', () => {
    expect(scopeAdmits(scope({ countries: ['DE'] }), { country: 'DE' })).toBe(true);
  });

  it('denies a subject outside the scope', () => {
    expect(scopeAdmits(scope({ countries: ['DE'] }), { country: 'GB' })).toBe(false);
  });

  it('denies a subject whose attribute is unknown', () => {
    // Deliberate strictness: if we do not know the user's country we cannot
    // claim they fall inside a DE-only moderator's remit. Failing open here
    // would leak the whole unknown-country population into every scope.
    expect(scopeAdmits(scope({ countries: ['DE'] }), { country: null })).toBe(false);
    expect(scopeAdmits(scope({ countries: ['DE'] }), {})).toBe(false);
  });
});

describe('delegation guards (§1.3)', () => {
  const superAdmin = identity('super_admin');
  const tier1 = identity('tier1_platform_manager');
  const tier2De = identity('tier2_moderation_lead', { scope: scope({ countries: ['DE'] }) });

  it('lets the Super Admin create a scoped Tier 3 moderator', () => {
    const verdict = canDelegate(
      superAdmin,
      { role: 'tier3_moderator', scope: scope({ countries: ['DE'] }) },
      'create',
    );
    expect(verdict.ok).toBe(true);
  });

  it('blocks granting a permission the actor does not hold', () => {
    const verdict = canDelegate(
      tier2De,
      {
        role: 'tier3_moderator',
        scope: scope({ countries: ['DE'] }),
        extraPermissions: ['users.ban.permanent'],
      },
      'create',
    );
    expect(verdict).toMatchObject({ ok: false, code: 'permission_not_held' });
  });

  it('blocks widening scope beyond the actor’s own', () => {
    const verdict = canDelegate(
      tier2De,
      { role: 'tier3_moderator', scope: GLOBAL_SCOPE },
      'create',
    );
    expect(verdict).toMatchObject({ ok: false, code: 'scope_not_contained' });
  });

  it('blocks creating a peer of equal rank', () => {
    const verdict = canDelegate(
      tier1,
      { role: 'tier1_platform_manager', scope: GLOBAL_SCOPE },
      'create',
    );
    expect(verdict).toMatchObject({ ok: false, code: 'role_rank_not_lower' });
  });

  it('blocks assigning the Super Admin role through the ordinary path', () => {
    const verdict = canDelegate(
      superAdmin,
      { role: 'super_admin', scope: GLOBAL_SCOPE },
      'create',
    );
    expect(verdict).toMatchObject({ ok: false, code: 'cannot_touch_super_admin' });
  });

  it('blocks self-modification', () => {
    const verdict = canDelegate(
      tier1,
      { id: tier1.id, role: 'tier3_moderator', scope: GLOBAL_SCOPE },
      'edit',
    );
    expect(verdict).toMatchObject({ ok: false, code: 'self_modification' });
  });

  it('blocks an actor without the relevant admin permission', () => {
    const verdict = canDelegate(
      identity('tier3_moderator'),
      { role: 'analyst', scope: GLOBAL_SCOPE },
      'create',
    );
    expect(verdict).toMatchObject({ ok: false, code: 'missing_permission' });
  });

  it('blocks Tier 1 from deleting admins, which is Super-Admin-only', () => {
    const verdict = canDelegate(
      tier1,
      { role: 'tier3_moderator', scope: GLOBAL_SCOPE },
      'delete',
    );
    expect(verdict).toMatchObject({ ok: false, code: 'missing_permission' });
  });

  it('blocks an inactive actor from delegating anything', () => {
    const verdict = canDelegate(
      identity('super_admin', { active: false }),
      { role: 'analyst', scope: GLOBAL_SCOPE },
      'create',
    );
    expect(verdict).toMatchObject({ ok: false, code: 'inactive_actor' });
  });

  it('never lets any role escalate to a permission it lacks, across every pair', () => {
    // Brute force over every (actor, target) role pair and every atom: if the
    // actor does not hold it, delegation of it must fail. This is the property
    // that matters most, so it is checked exhaustively rather than by example.
    for (const actorRole of ROLE_KEYS) {
      const actor = identity(actorRole);
      const held = resolvePermissions(actor);

      for (const targetRole of ROLE_KEYS) {
        for (const permission of ALL_PERMISSIONS) {
          if (held.has(permission)) continue;

          const verdict = canDelegate(
            actor,
            { role: targetRole, scope: GLOBAL_SCOPE, extraPermissions: [permission] },
            'create',
          );
          expect(
            verdict.ok,
            `${actorRole} must not be able to grant ${permission} to ${targetRole}`,
          ).toBe(false);
        }
      }
    }
  });
});

describe('canManageAdmin', () => {
  it('refuses to let anyone touch the Super Admin', () => {
    const verdict = canManageAdmin(identity('tier1_platform_manager'), identity('super_admin'));
    expect(verdict).toMatchObject({ ok: false, code: 'cannot_touch_super_admin' });
  });

  it('refuses equal rank', () => {
    const a = identity('tier2_moderation_lead', { id: 'a' });
    const b = identity('tier2_moderation_lead', { id: 'b' });
    expect(canManageAdmin(a, b)).toMatchObject({ ok: false, code: 'rank_not_lower' });
  });

  it('allows strictly lower rank inside scope', () => {
    const lead = identity('tier2_moderation_lead', {
      id: 'lead', scope: scope({ countries: ['DE'] }),
    });
    const mod = identity('tier3_moderator', {
      id: 'mod', scope: scope({ countries: ['DE'] }),
    });
    expect(canManageAdmin(lead, mod).ok).toBe(true);
  });

  it('refuses a lower-ranked admin who operates outside the actor’s scope', () => {
    const leadDe = identity('tier2_moderation_lead', {
      id: 'lead', scope: scope({ countries: ['DE'] }),
    });
    const modGb = identity('tier3_moderator', {
      id: 'mod', scope: scope({ countries: ['GB'] }),
    });
    expect(canManageAdmin(leadDe, modGb)).toMatchObject({
      ok: false, code: 'scope_not_contained',
    });
  });
});

describe('role definition sanity', () => {
  it('gives every role a unique rank', () => {
    const ranks = ROLE_KEYS.map((k) => ROLES[k].rank);
    expect(new Set(ranks).size).toBe(ranks.length);
  });

  it('ranks the Super Admin above everyone', () => {
    const others = ROLE_KEYS.filter((k) => k !== 'super_admin').map((k) => ROLES[k].rank);
    expect(Math.max(...others)).toBeLessThan(ROLES.super_admin.rank);
  });

  it('only marks the Super Admin as a singleton', () => {
    for (const key of ROLE_KEYS) {
      expect(ROLES[key].singleton).toBe(key === 'super_admin');
    }
  });

  it('references only real permission atoms', () => {
    for (const key of ROLE_KEYS) {
      for (const permission of ROLES[key].permissions) {
        expect(ALL_PERMISSIONS, `${key} references unknown atom ${permission}`).toContain(permission);
      }
    }
  });
});
