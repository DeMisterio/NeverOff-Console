import { describe, expect, it } from 'vitest';

import {
  ENFORCEMENT_ACTION_TYPES,
  LADDER,
  deriveUserState,
  durationInDays,
  isActionActive,
  validateProposedAction,
  type ActiveEnforcement,
  type EnforcementActionType,
} from './enforcement.js';

/**
 * Enforcement state machine.
 *
 * The fold in `deriveUserState` decides whether a real person can use their
 * account, so the cases below lean on the ones that are easy to get subtly
 * wrong: expiry boundaries, several actions in force at once, and the
 * distinction between an internal note and something the user can see.
 */

const NOW = new Date('2026-08-02T12:00:00.000Z');
const hours = (n: number): Date => new Date(NOW.getTime() + n * 3_600_000);

let counter = 0;
function action(
  type: EnforcementActionType,
  overrides: Partial<ActiveEnforcement> = {},
): ActiveEnforcement {
  counter += 1;
  return {
    id: `action-${counter}`,
    type,
    reasonCode: 'other.terms_violation',
    caseRef: `NO-2026-${String(counter).padStart(6, '0')}`,
    issuedAt: hours(-24),
    expiresAt: null,
    reversedAt: null,
    ...overrides,
  };
}

describe('ladder definition', () => {
  it('defines every action type exactly once', () => {
    for (const type of ENFORCEMENT_ACTION_TYPES) {
      expect(LADDER[type], `${type} missing from the ladder`).toBeDefined();
      expect(LADDER[type].type).toBe(type);
    }
  });

  it('orders severity strictly, so the most severe action always wins the fold', () => {
    const severities = ENFORCEMENT_ACTION_TYPES.map((t) => LADDER[t].severity);
    expect(new Set(severities).size).toBe(severities.length);
  });

  it('marks only the terminal rungs as access-blocking', () => {
    const blocking = ENFORCEMENT_ACTION_TYPES.filter((t) => LADDER[t].blocksAccess);
    expect(blocking.sort()).toEqual(['account_deletion', 'ban_permanent', 'ban_temporary']);
  });

  it('lets a mute block sending without blocking access', () => {
    expect(LADDER.mute.blocksSending).toBe(true);
    expect(LADDER.mute.blocksAccess).toBe(false);
  });

  it('marks account deletion as the only irreversible rung', () => {
    const irreversible = ENFORCEMENT_ACTION_TYPES.filter((t) => !LADDER[t].reversible);
    expect(irreversible).toEqual(['account_deletion']);
  });

  it('keeps shadow restriction silent and gated behind a typed confirmation', () => {
    expect(LADDER.shadow_restriction.visibility).toBe('silent');
    expect(LADDER.shadow_restriction.breakGlass).toBe('typed_phrase');
  });

  it('requires a second admin for a permanent ban', () => {
    expect(LADDER.ban_permanent.breakGlass).toBe('second_admin');
  });
});

describe('isActionActive', () => {
  it('treats an unexpired, unreversed action as active', () => {
    expect(isActionActive(action('mute', { expiresAt: hours(1) }), NOW)).toBe(true);
  });

  it('treats a reversed action as inactive even before its expiry', () => {
    const reversed = action('ban_temporary', { expiresAt: hours(48), reversedAt: hours(-1) });
    expect(isActionActive(reversed, NOW)).toBe(false);
  });

  it('treats an action expiring exactly now as inactive', () => {
    // Boundary matters: the alternative leaves a user banned for one extra tick
    // and makes the API and the SQL predicate disagree at the same instant.
    expect(isActionActive(action('mute', { expiresAt: NOW }), NOW)).toBe(false);
  });

  it('treats a null expiry as never expiring', () => {
    expect(isActionActive(action('ban_permanent'), NOW)).toBe(true);
  });
});

describe('deriveUserState', () => {
  it('reports an unrestricted account as active', () => {
    const state = deriveUserState([], NOW);
    expect(state.status).toBe('active');
    expect(state.blocksAccess).toBe(false);
    expect(state.governingAction).toBeNull();
  });

  it('does not let an internal note change the visible status', () => {
    // A note is severity 0 and internal by definition. If it governed status,
    // an admin jotting something down would show the user as restricted.
    const state = deriveUserState([action('note')], NOW);
    expect(state.status).toBe('active');
    expect(state.governingAction).toBeNull();
    expect(state.activeActions).toHaveLength(1);
  });

  it('takes status from the most severe active action', () => {
    const state = deriveUserState(
      [
        action('warning'),
        action('ban_temporary', { expiresAt: hours(48) }),
        action('mute', { expiresAt: hours(2) }),
      ],
      NOW,
    );
    expect(state.status).toBe('banned_temporary');
    expect(state.governingAction?.type).toBe('ban_temporary');
    expect(state.blocksAccess).toBe(true);
  });

  it('ignores expired actions when deriving status', () => {
    const state = deriveUserState(
      [action('ban_temporary', { expiresAt: hours(-1) }), action('warning')],
      NOW,
    );
    expect(state.status).toBe('warned');
    expect(state.blocksAccess).toBe(false);
  });

  it('accumulates restricted features across several actions', () => {
    const state = deriveUserState(
      [
        action('feature_restriction', { expiresAt: hours(24), restrictedFeatures: ['send_media'] }),
        action('feature_restriction', { expiresAt: hours(48), restrictedFeatures: ['send_links', 'create_group'] }),
      ],
      NOW,
    );
    expect([...state.restrictedFeatures].sort()).toEqual(['create_group', 'send_links', 'send_media']);
  });

  it('applies the most restrictive rate limit when several are in force', () => {
    const state = deriveUserState(
      [
        action('rate_limit', { expiresAt: hours(24), rateLimitPerMinute: 20 }),
        action('rate_limit', { expiresAt: hours(24), rateLimitPerMinute: 5 }),
      ],
      NOW,
    );
    expect(state.rateLimitPerMinute).toBe(5);
  });

  it('reports the soonest expiry as the next thing to act on', () => {
    const state = deriveUserState(
      [
        action('mute', { expiresAt: hours(6) }),
        action('feature_restriction', { expiresAt: hours(2), restrictedFeatures: ['send_media'] }),
        action('ban_permanent'),
      ],
      NOW,
    );
    expect(state.nextExpiryAt?.toISOString()).toBe(hours(2).toISOString());
  });

  it('flags shadow restriction separately from status when a ban dominates', () => {
    const state = deriveUserState(
      [
        action('shadow_restriction', { expiresAt: hours(72) }),
        action('ban_temporary', { expiresAt: hours(24) }),
      ],
      NOW,
    );
    expect(state.status).toBe('banned_temporary');
    // Still true, so the app applies both — the ban screen shows, and if the
    // ban is lifted the shadow restriction is still in force underneath.
    expect(state.shadowRestricted).toBe(true);
  });

  it('restores the account automatically once the only ban expires', () => {
    const ban = action('ban_temporary', { expiresAt: hours(1) });

    const during = deriveUserState([ban], NOW);
    expect(during.blocksAccess).toBe(true);

    // §11 acceptance criterion: access is restored on expiry with no worker
    // involvement — the same rows simply evaluate differently a moment later.
    const after = deriveUserState([ban], hours(2));
    expect(after.blocksAccess).toBe(false);
    expect(after.status).toBe('active');
  });

  it('restores the account immediately when a ban is reversed', () => {
    const ban = action('ban_temporary', { expiresAt: hours(48), reversedAt: hours(-1) });
    const state = deriveUserState([ban], NOW);
    expect(state.status).toBe('active');
    expect(state.blocksAccess).toBe(false);
  });
});

describe('validateProposedAction', () => {
  const base = { reasonCode: 'spam.phishing', note: 'Detailed enough justification.' };

  it('requires an expiry on rungs that must be time-bounded', () => {
    for (const type of ['mute', 'shadow_restriction', 'ban_temporary'] as const) {
      const result = validateProposedAction({ ...base, type, expiresAt: null }, NOW);
      expect(result).toMatchObject({ ok: false, code: 'expiry_required' });
    }
  });

  it('refuses an expiry on rungs that cannot carry one', () => {
    for (const type of ['warning', 'ban_permanent', 'note', 'account_deletion'] as const) {
      const result = validateProposedAction({ ...base, type, expiresAt: hours(24) }, NOW);
      expect(result).toMatchObject({ ok: false, code: 'expiry_not_allowed' });
    }
  });

  it('refuses an expiry in the past', () => {
    const result = validateProposedAction(
      { ...base, type: 'mute', expiresAt: hours(-1) }, NOW,
    );
    expect(result).toMatchObject({ ok: false, code: 'expiry_in_past' });
  });

  it('requires at least one feature on a feature restriction', () => {
    const result = validateProposedAction(
      { ...base, type: 'feature_restriction', expiresAt: hours(24), restrictedFeatures: [] },
      NOW,
    );
    expect(result).toMatchObject({ ok: false, code: 'no_features_selected' });
  });

  it('rejects an unknown feature name', () => {
    const result = validateProposedAction(
      {
        ...base, type: 'feature_restriction', expiresAt: hours(24),
        restrictedFeatures: ['delete_everything'] as never,
      },
      NOW,
    );
    expect(result).toMatchObject({ ok: false, code: 'unknown_feature' });
  });

  it('bounds the rate limit', () => {
    for (const rate of [0, -1, 601]) {
      const result = validateProposedAction(
        { ...base, type: 'rate_limit', expiresAt: hours(24), rateLimitPerMinute: rate },
        NOW,
      );
      expect(result).toMatchObject({ ok: false, code: 'invalid_rate_limit' });
    }
  });

  it('requires a reason code and a substantive note', () => {
    expect(
      validateProposedAction({ ...base, reasonCode: '', type: 'warning', expiresAt: null }, NOW),
    ).toMatchObject({ ok: false, code: 'reason_required' });

    expect(
      validateProposedAction({ ...base, note: 'spam', type: 'warning', expiresAt: null }, NOW),
    ).toMatchObject({ ok: false, code: 'note_too_short' });
  });

  it('accepts a well-formed action', () => {
    expect(
      validateProposedAction({ ...base, type: 'ban_temporary', expiresAt: hours(168) }, NOW),
    ).toEqual({ ok: true });
  });
});

describe('durationInDays', () => {
  it('rounds a partial day up, so a 7-day ban never reads as 6', () => {
    expect(durationInDays(new Date(NOW.getTime() + 7 * 86_400_000), NOW)).toBe(7);
    expect(durationInDays(new Date(NOW.getTime() + 7.5 * 86_400_000), NOW)).toBe(8);
    expect(durationInDays(new Date(NOW.getTime() + 3_600_000), NOW)).toBe(1);
  });
});
