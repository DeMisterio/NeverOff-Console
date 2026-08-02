/**
 * The §3.3 enforcement ladder, as data plus a state machine.
 *
 * Two things live here and nowhere else:
 *
 *   - LADDER: what each rung is, what it requires, and what it does to a user.
 *   - deriveUserState(): the single function that turns a set of active actions
 *     into the effective restrictions the app must apply.
 *
 * The API, the workers, the Android client's status endpoint and the seed data
 * all go through `deriveUserState`. There is deliberately no second place where
 * "is this user banned?" gets decided — divergence between two such places is
 * how users end up locked out with no matching action row, or banned on paper
 * but still sending messages.
 */

import type { Permission } from './permissions.js';
import type { BreakGlassMode } from './permissions.js';

export const ENFORCEMENT_ACTION_TYPES = [
  'note',
  'warning',
  'feature_restriction',
  'rate_limit',
  'mute',
  'shadow_restriction',
  'ban_temporary',
  'ban_permanent',
  'account_deletion',
] as const;

export type EnforcementActionType = (typeof ENFORCEMENT_ACTION_TYPES)[number];

/** Individually disableable capabilities (§3.3 "Feature restriction"). */
export const RESTRICTABLE_FEATURES = [
  'send_media',
  'send_links',
  'create_group',
  'create_channel',
  'add_strangers',
  'join_groups',
] as const;

export type RestrictableFeature = (typeof RESTRICTABLE_FEATURES)[number];

export interface EnforcementActionSpec {
  readonly type: EnforcementActionType;
  readonly label: string;
  readonly description: string;
  /** Ordering on the ladder. Higher wins when deriving a single user status. */
  readonly severity: number;
  readonly requiredPermission: Permission;
  /** May carry an expiry. `required` means an expiry must be supplied. */
  readonly duration: 'none' | 'optional' | 'required';
  /** Does the user get told? `silent` is the shadow case and is heavily gated. */
  readonly visibility: 'internal' | 'notified' | 'silent';
  readonly reversible: boolean;
  readonly breakGlass: BreakGlassMode;
  /** Blocks the app entirely, showing the §4 ban screen. */
  readonly blocksAccess: boolean;
  /** Prevents sending while still allowing receipt. */
  readonly blocksSending: boolean;
}

export const LADDER: Readonly<Record<EnforcementActionType, EnforcementActionSpec>> = {
  note: {
    type: 'note',
    label: 'Internal note',
    description: 'Recorded on the profile for other admins. The user sees nothing.',
    severity: 0,
    requiredPermission: 'users.note',
    duration: 'none',
    visibility: 'internal',
    reversible: true,
    breakGlass: 'none',
    blocksAccess: false,
    blocksSending: false,
  },
  warning: {
    type: 'warning',
    label: 'Warning',
    description: 'In-app notice the user must acknowledge, citing the rule broken.',
    severity: 10,
    requiredPermission: 'users.warn',
    duration: 'none',
    visibility: 'notified',
    reversible: true,
    breakGlass: 'none',
    blocksAccess: false,
    blocksSending: false,
  },
  feature_restriction: {
    type: 'feature_restriction',
    label: 'Feature restriction',
    description: 'Selectively disables media, links, group/channel creation or adding strangers.',
    severity: 20,
    requiredPermission: 'users.restrict',
    duration: 'optional',
    visibility: 'notified',
    reversible: true,
    breakGlass: 'none',
    blocksAccess: false,
    blocksSending: false,
  },
  rate_limit: {
    type: 'rate_limit',
    label: 'Rate limit',
    description: 'Throttles messages per minute and new conversation starts.',
    severity: 30,
    requiredPermission: 'users.restrict',
    duration: 'optional',
    visibility: 'notified',
    reversible: true,
    breakGlass: 'none',
    blocksAccess: false,
    blocksSending: false,
  },
  mute: {
    type: 'mute',
    label: 'Mute',
    description: 'Read-only. The user can receive but not send, until the expiry.',
    severity: 40,
    requiredPermission: 'users.mute',
    duration: 'required',
    visibility: 'notified',
    reversible: true,
    breakGlass: 'none',
    blocksAccess: false,
    blocksSending: true,
  },
  shadow_restriction: {
    type: 'shadow_restriction',
    label: 'Shadow restriction',
    description:
      'Messages to strangers silently fail to deliver. Deceptive by construction: requires a typed confirmation and a written policy justification, and every application is flagged for periodic review.',
    severity: 50,
    requiredPermission: 'users.shadow_restrict',
    duration: 'required',
    visibility: 'silent',
    reversible: true,
    breakGlass: 'typed_phrase',
    blocksAccess: false,
    blocksSending: false,
  },
  ban_temporary: {
    type: 'ban_temporary',
    label: 'Temporary ban',
    description:
      'Account suspended until the expiry, then automatically restored. The user is told the reason and the exact expiry.',
    severity: 60,
    requiredPermission: 'users.ban.temp',
    duration: 'required',
    visibility: 'notified',
    reversible: true,
    breakGlass: 'none',
    blocksAccess: true,
    blocksSending: true,
  },
  ban_permanent: {
    type: 'ban_permanent',
    label: 'Permanent ban',
    description: 'Terminal suspension. Requires a second admin to approve.',
    severity: 70,
    requiredPermission: 'users.ban.permanent',
    duration: 'none',
    visibility: 'notified',
    reversible: true,
    breakGlass: 'second_admin',
    blocksAccess: true,
    blocksSending: true,
  },
  account_deletion: {
    type: 'account_deletion',
    label: 'Account deletion & data purge',
    description:
      'Irreversible erasure across every store, satisfying a legal erasure request. Super Admin only, and refused outright while a legal hold is in force.',
    severity: 100,
    requiredPermission: 'users.delete',
    duration: 'none',
    visibility: 'notified',
    reversible: false,
    breakGlass: 'typed_phrase',
    blocksAccess: true,
    blocksSending: true,
  },
};

export const LADDER_ORDER: readonly EnforcementActionType[] = ENFORCEMENT_ACTION_TYPES.slice().sort(
  (a, b) => LADDER[a].severity - LADDER[b].severity,
);

// ---------------------------------------------------------------------------
// Active actions -> effective state
// ---------------------------------------------------------------------------

export type UserStatus =
  | 'active'
  | 'warned'
  | 'restricted'
  | 'muted'
  | 'shadow_restricted'
  | 'banned_temporary'
  | 'banned_permanent'
  | 'deleted';

/** The shape `deriveUserState` needs. Mirrors admin.enforcement_actions. */
export interface ActiveEnforcement {
  readonly id: string;
  readonly type: EnforcementActionType;
  readonly reasonCode: string;
  readonly caseRef: string;
  readonly issuedAt: Date;
  /** null = no expiry (permanent, or a rung that does not expire). */
  readonly expiresAt: Date | null;
  readonly reversedAt: Date | null;
  readonly restrictedFeatures?: readonly RestrictableFeature[] | null;
  readonly rateLimitPerMinute?: number | null;
}

export interface EffectiveUserState {
  readonly status: UserStatus;
  /** The action that determined `status`, if any. Drives the §4 ban screen. */
  readonly governingAction: ActiveEnforcement | null;
  readonly blocksAccess: boolean;
  readonly blocksSending: boolean;
  readonly shadowRestricted: boolean;
  readonly restrictedFeatures: readonly RestrictableFeature[];
  readonly rateLimitPerMinute: number | null;
  /** Every action currently in force, severity-descending. */
  readonly activeActions: readonly ActiveEnforcement[];
  /** Soonest expiry across active actions — when the worker must next act. */
  readonly nextExpiryAt: Date | null;
}

const STATUS_BY_TYPE: Readonly<Record<EnforcementActionType, UserStatus>> = {
  note: 'active',
  warning: 'warned',
  feature_restriction: 'restricted',
  rate_limit: 'restricted',
  mute: 'muted',
  shadow_restriction: 'shadow_restricted',
  ban_temporary: 'banned_temporary',
  ban_permanent: 'banned_permanent',
  account_deletion: 'deleted',
};

export function isActionActive(action: ActiveEnforcement, now: Date): boolean {
  if (action.reversedAt !== null) return false;
  if (action.expiresAt !== null && action.expiresAt.getTime() <= now.getTime()) return false;
  return true;
}

/**
 * Fold every enforcement action on an account into the state the app enforces.
 *
 * Restrictions accumulate rather than replace: a user under both a media
 * restriction and a rate limit is subject to both. Only `status` collapses to a
 * single value, taken from the most severe active rung, because the UI badge
 * and the ban screen need one answer.
 *
 * A `note` never changes status — it is internal by definition.
 */
export function deriveUserState(
  actions: readonly ActiveEnforcement[],
  now: Date = new Date(),
): EffectiveUserState {
  const active = actions
    .filter((a) => isActionActive(a, now))
    .slice()
    .sort((a, b) => LADDER[b.type].severity - LADDER[a.type].severity);

  const restrictedFeatures = new Set<RestrictableFeature>();
  let rateLimitPerMinute: number | null = null;
  let blocksAccess = false;
  let blocksSending = false;
  let shadowRestricted = false;
  let nextExpiryAt: Date | null = null;

  for (const action of active) {
    const spec = LADDER[action.type];
    if (spec.blocksAccess) blocksAccess = true;
    if (spec.blocksSending) blocksSending = true;
    if (action.type === 'shadow_restriction') shadowRestricted = true;

    for (const f of action.restrictedFeatures ?? []) restrictedFeatures.add(f);

    if (action.rateLimitPerMinute != null) {
      // Most restrictive limit wins when several are in force.
      rateLimitPerMinute =
        rateLimitPerMinute === null
          ? action.rateLimitPerMinute
          : Math.min(rateLimitPerMinute, action.rateLimitPerMinute);
    }

    if (action.expiresAt !== null) {
      if (nextExpiryAt === null || action.expiresAt.getTime() < nextExpiryAt.getTime()) {
        nextExpiryAt = action.expiresAt;
      }
    }
  }

  // `note` is severity 0 and maps to 'active', so a user whose only action is a
  // note correctly reads as Active rather than as something the user could see.
  const governing = active.find((a) => a.type !== 'note') ?? null;

  return {
    status: governing ? STATUS_BY_TYPE[governing.type] : 'active',
    governingAction: governing,
    blocksAccess,
    blocksSending,
    shadowRestricted,
    restrictedFeatures: [...restrictedFeatures],
    rateLimitPerMinute,
    activeActions: active,
    nextExpiryAt,
  };
}

// ---------------------------------------------------------------------------
// Transition validation
// ---------------------------------------------------------------------------

export interface ProposedAction {
  readonly type: EnforcementActionType;
  readonly expiresAt: Date | null;
  readonly restrictedFeatures?: readonly RestrictableFeature[] | null;
  readonly rateLimitPerMinute?: number | null;
  readonly reasonCode: string;
  readonly note: string;
}

export type ValidationResult =
  | { ok: true }
  | { ok: false; code: string; message: string };

/**
 * Structural validity of an action, independent of who is asking.
 * Permission and ban-length checks live in the API layer, which knows the actor.
 */
export function validateProposedAction(
  proposed: ProposedAction,
  now: Date = new Date(),
): ValidationResult {
  const spec = LADDER[proposed.type];
  if (!spec) {
    return { ok: false, code: 'unknown_action', message: `Unknown action "${proposed.type}".` };
  }

  if (spec.duration === 'required' && proposed.expiresAt === null) {
    return {
      ok: false,
      code: 'expiry_required',
      message: `${spec.label} must have an expiry.`,
    };
  }
  if (spec.duration === 'none' && proposed.expiresAt !== null) {
    return {
      ok: false,
      code: 'expiry_not_allowed',
      message: `${spec.label} cannot carry an expiry.`,
    };
  }
  if (proposed.expiresAt !== null && proposed.expiresAt.getTime() <= now.getTime()) {
    return {
      ok: false,
      code: 'expiry_in_past',
      message: 'The expiry must be in the future.',
    };
  }

  if (proposed.type === 'feature_restriction') {
    const features = proposed.restrictedFeatures ?? [];
    if (features.length === 0) {
      return {
        ok: false,
        code: 'no_features_selected',
        message: 'Select at least one feature to restrict.',
      };
    }
    for (const f of features) {
      if (!(RESTRICTABLE_FEATURES as readonly string[]).includes(f)) {
        return { ok: false, code: 'unknown_feature', message: `Unknown feature "${f}".` };
      }
    }
  }

  if (proposed.type === 'rate_limit') {
    const rl = proposed.rateLimitPerMinute;
    if (rl == null || !Number.isFinite(rl) || rl < 1 || rl > 600) {
      return {
        ok: false,
        code: 'invalid_rate_limit',
        message: 'Rate limit must be between 1 and 600 messages per minute.',
      };
    }
  }

  // §3.3: every action requires a reason category and a free-text note.
  if (!proposed.reasonCode || proposed.reasonCode.trim().length === 0) {
    return { ok: false, code: 'reason_required', message: 'A reason code is required.' };
  }
  if (!proposed.note || proposed.note.trim().length < 10) {
    return {
      ok: false,
      code: 'note_too_short',
      message: 'Describe the decision in at least 10 characters — this is read on appeal.',
    };
  }

  return { ok: true };
}

/** Days between now and an expiry, rounded up. Used against a role's ban cap. */
export function durationInDays(expiresAt: Date, now: Date = new Date()): number {
  const ms = expiresAt.getTime() - now.getTime();
  return Math.ceil(ms / 86_400_000);
}
