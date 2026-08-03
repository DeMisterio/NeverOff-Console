/**
 * The §6.5 channel action ladder.
 *
 * Separate from the §3.3 user ladder because the user ladder cannot express
 * what channel moderation needs. Banning the owner of a 24,000-subscriber
 * channel does not stop the channel — the posts stay up and the subscribers
 * stay subscribed. And the proportionate response to a channel that has
 * drifted is usually not a ban at all: it is blocking new joins while the
 * owner is warned, or geo-blocking in the one jurisdiction where the content
 * is unlawful.
 *
 * As with the user ladder, the ordering is severity, and the API enforces
 * permissions and break-glass from the metadata here rather than from a
 * hardcoded switch.
 */

import type { BreakGlassMode, Permission } from './permissions.js';

export const CHANNEL_ACTION_TYPES = [
  'warn_owner',
  'restrict_joins',
  'disable_media',
  'disable_links',
  'disable_forwarding',
  'age_gate',
  'geo_restrict',
  'delist',
  'freeze',
  'takedown',
] as const;

export type ChannelActionType = (typeof CHANNEL_ACTION_TYPES)[number];

export interface ChannelActionSpec {
  readonly type: ChannelActionType;
  readonly label: string;
  readonly description: string;
  readonly severity: number;
  readonly requiredPermission: Permission;
  readonly duration: 'none' | 'optional' | 'required';
  readonly breakGlass: BreakGlassMode;
  /** Requires a list of countries. */
  readonly needsCountries: boolean;
  /** Members are told, with the stated reason (§6.5). */
  readonly notifiesMembers: boolean;
  /** The owner is told. */
  readonly notifiesOwner: boolean;
}

export const CHANNEL_LADDER: Readonly<Record<ChannelActionType, ChannelActionSpec>> = {
  warn_owner: {
    type: 'warn_owner',
    label: 'Warn the owner',
    description:
      'The owner is told what is wrong and what happens next. Nothing changes for members.',
    severity: 10,
    requiredPermission: 'channels.restrict',
    duration: 'none',
    breakGlass: 'none',
    needsCountries: false,
    notifiesMembers: false,
    notifiesOwner: true,
  },
  restrict_joins: {
    type: 'restrict_joins',
    label: 'Block new joins',
    description:
      'Existing members keep access; nobody new can subscribe. The usual first structural step — it stops growth while a case is reviewed without punishing people already there.',
    severity: 20,
    requiredPermission: 'channels.restrict',
    duration: 'optional',
    breakGlass: 'none',
    needsCountries: false,
    notifiesMembers: false,
    notifiesOwner: true,
  },
  disable_media: {
    type: 'disable_media',
    label: 'Disable media',
    description: 'Text posts only. Useful where the problem is imagery rather than the channel.',
    severity: 25,
    requiredPermission: 'channels.restrict',
    duration: 'optional',
    breakGlass: 'none',
    needsCountries: false,
    notifiesMembers: false,
    notifiesOwner: true,
  },
  disable_links: {
    type: 'disable_links',
    label: 'Disable links',
    description: 'No outbound links. The standard response to a channel used to funnel scams.',
    severity: 25,
    requiredPermission: 'channels.restrict',
    duration: 'optional',
    breakGlass: 'none',
    needsCountries: false,
    notifiesMembers: false,
    notifiesOwner: true,
  },
  disable_forwarding: {
    type: 'disable_forwarding',
    label: 'Disable forwarding',
    description:
      'Posts cannot be forwarded out. Caps virality on a channel whose content spreads faster than it can be reviewed.',
    severity: 30,
    requiredPermission: 'channels.restrict',
    duration: 'optional',
    breakGlass: 'none',
    needsCountries: false,
    notifiesMembers: false,
    notifiesOwner: true,
  },
  age_gate: {
    type: 'age_gate',
    label: 'Age-gate',
    description: 'Members confirm they are 18+ before viewing. For lawful adult content.',
    severity: 35,
    requiredPermission: 'channels.restrict',
    duration: 'none',
    breakGlass: 'none',
    needsCountries: false,
    notifiesMembers: true,
    notifiesOwner: true,
  },
  geo_restrict: {
    type: 'geo_restrict',
    label: 'Geo-restrict',
    description:
      'Blocked in named countries only. §8 prefers local-law-only removal over global deletion: content unlawful in one jurisdiction and lawful elsewhere should disappear only where it must.',
    severity: 40,
    requiredPermission: 'channels.restrict',
    duration: 'optional',
    breakGlass: 'none',
    needsCountries: true,
    notifiesMembers: true,
    notifiesOwner: true,
  },
  delist: {
    type: 'delist',
    label: 'Delist from discovery',
    description:
      'Removed from search and discovery. The link still works, so existing members are unaffected — this stops recruitment, not participation.',
    severity: 45,
    requiredPermission: 'channels.restrict',
    duration: 'optional',
    breakGlass: 'none',
    needsCountries: false,
    notifiesMembers: false,
    notifiesOwner: true,
  },
  freeze: {
    type: 'freeze',
    label: 'Freeze (read-only)',
    description:
      'Existing posts stay visible; no new ones. Preserves the channel as evidence while stopping the harm.',
    severity: 60,
    requiredPermission: 'channels.restrict',
    duration: 'optional',
    breakGlass: 'none',
    needsCountries: false,
    notifiesMembers: true,
    notifiesOwner: true,
  },
  takedown: {
    type: 'takedown',
    label: 'Take down',
    description:
      'Fully inaccessible. Rows are preserved, not deleted — the posts are evidence for the owner’s appeal, and §6.5 gives channel owners the same appeal path as individuals.',
    severity: 100,
    requiredPermission: 'channels.takedown',
    duration: 'none',
    breakGlass: 'second_admin',
    needsCountries: false,
    notifiesMembers: true,
    notifiesOwner: true,
  },
};

export const CHANNEL_LADDER_ORDER: readonly ChannelActionType[] = CHANNEL_ACTION_TYPES.slice().sort(
  (a, b) => CHANNEL_LADDER[a].severity - CHANNEL_LADDER[b].severity,
);

export interface ChannelRestrictionState {
  readonly taken_down: boolean;
  readonly frozen: boolean;
  readonly joins_blocked: boolean;
  readonly delisted: boolean;
  readonly age_gated: boolean;
  readonly media_disabled: boolean;
  readonly links_disabled: boolean;
  readonly forwarding_disabled: boolean;
  readonly geo_blocked_in: readonly string[];
  readonly next_expiry_at: string | null;
}

export type ChannelValidation = { ok: true } | { ok: false; code: string; message: string };

/** Structural validity, independent of who is asking. */
export function validateChannelAction(proposed: {
  type: ChannelActionType;
  expiresAt: Date | null;
  countries?: readonly string[] | null;
  note: string;
  reasonCode: string;
}, now: Date = new Date()): ChannelValidation {
  const spec = CHANNEL_LADDER[proposed.type];
  if (!spec) {
    return { ok: false, code: 'unknown_action', message: `Unknown action "${proposed.type}".` };
  }

  if (spec.duration === 'none' && proposed.expiresAt !== null) {
    return {
      ok: false,
      code: 'expiry_not_allowed',
      message: `${spec.label} cannot carry an expiry.`,
    };
  }
  if (proposed.expiresAt !== null && proposed.expiresAt.getTime() <= now.getTime()) {
    return { ok: false, code: 'expiry_in_past', message: 'The expiry must be in the future.' };
  }

  if (spec.needsCountries) {
    const countries = proposed.countries ?? [];
    if (countries.length === 0) {
      return {
        ok: false,
        code: 'countries_required',
        message: 'Name at least one country to restrict in.',
      };
    }
    for (const country of countries) {
      if (!/^[A-Z]{2}$/.test(country)) {
        return {
          ok: false,
          code: 'invalid_country',
          message: `"${country}" is not a two-letter country code.`,
        };
      }
    }
  } else if ((proposed.countries?.length ?? 0) > 0) {
    return {
      ok: false,
      code: 'countries_not_allowed',
      message: `${spec.label} does not take a country list.`,
    };
  }

  if (!proposed.reasonCode) {
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
