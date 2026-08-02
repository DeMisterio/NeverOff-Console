/**
 * Permission atoms.
 *
 * These are the only unit of authorisation in the console. There are no
 * role-name checks anywhere in the API or the UI — code asks "does this actor
 * hold `users.ban.temp`?", never "is this actor a Tier 2?". Roles exist purely
 * as named bundles of atoms (see ./roles.ts), which is what makes custom roles
 * and per-admin scoping possible without touching enforcement code.
 *
 * Adding an atom here is the *only* correct way to add a new capability. The
 * permission matrix doc and the exhaustive permission tests are both generated
 * from this file, so a new atom that nobody has deliberately granted starts out
 * denied to everyone including the Super Admin's subordinates — fail closed.
 */

/** How much friction a permission's use requires at the point of action (§1.3). */
export type BreakGlassMode =
  /** Ordinary action. Audit-logged like everything else, but no extra gate. */
  | 'none'
  /** Actor must retype an exact confirmation phrase naming the target. */
  | 'typed_phrase'
  /** A second admin who independently holds the permission must approve. */
  | 'second_admin';

export type PermissionCategory =
  | 'analytics'
  | 'users'
  | 'channels'
  | 'reports'
  | 'support'
  | 'administration'
  | 'compliance'
  | 'child_safety';

export interface PermissionMeta {
  readonly key: Permission;
  readonly label: string;
  readonly description: string;
  readonly category: PermissionCategory;
  readonly breakGlass: BreakGlassMode;
  /**
   * Exercising this permission reads or exports personal data. Every use is
   * additionally written to the audit log as a PII access event and surfaced to
   * the acting admin in the UI as "this access is recorded" (§8).
   */
  readonly pii: boolean;
  /**
   * Only the Super Admin may ever hold this, even via a custom role. Guards the
   * powers §1.1 reserves: role definitions, admin deletion, raw export,
   * retention policy, account purge.
   */
  readonly superAdminOnly: boolean;
  /** Present when this atom was not in the spec's §1.2 list. */
  readonly addedBeyondSpec?: string;
}

/**
 * The catalogue. Order is presentation order in the UI and the matrix doc.
 *
 * Every atom in the spec's §1.2 minimum set appears here verbatim. Atoms marked
 * `addedBeyondSpec` were required to express the §3.3 enforcement ladder and the
 * §8 compliance surface without overloading an existing atom — overloading is
 * how you end up with a moderator who can mute also being able to shadow-ban.
 */
const CATALOGUE = [
  // --- Analytics ----------------------------------------------------------
  {
    key: 'analytics.view',
    label: 'View analytics',
    description: 'Read dashboards, charts and aggregate metrics.',
    category: 'analytics',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'analytics.export',
    label: 'Export analytics',
    description: 'Download aggregate data as CSV/PNG. Aggregates only, never raw event rows.',
    category: 'analytics',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'analytics.export_raw',
    label: 'Export raw data',
    description:
      'Export unaggregated event and user records. Super Admin only per §1.1; every export is audit-logged with the row count and filter used.',
    category: 'analytics',
    breakGlass: 'typed_phrase',
    pii: true,
    superAdminOnly: true,
    addedBeyondSpec:
      '§1.1 reserves "export raw data" to the Super Admin, but §1.2 only lists analytics.export. Splitting them keeps aggregate export delegable while raw export stays reserved.',
  },

  // --- Users --------------------------------------------------------------
  {
    key: 'users.view',
    label: 'View users',
    description: 'Open the user directory and non-PII profile fields.',
    category: 'users',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'users.search',
    label: 'Search users',
    description: 'Exact-match lookup by username, display name, user ID or identifier hash.',
    category: 'users',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'users.view_pii',
    label: 'View personal data',
    description:
      'Reveal email, device list, IP-derived country history and the connections graph. Each reveal is individually logged against the case that justified it.',
    category: 'users',
    breakGlass: 'none',
    pii: true,
    superAdminOnly: false,
  },
  {
    key: 'users.contact',
    label: 'Message users',
    description: 'Send a message from the verified @admin identity, or a segment broadcast.',
    category: 'users',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'users.note',
    label: 'Add internal note',
    description: 'Attach an internal-only note to a user. The user never sees it.',
    category: 'users',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
    addedBeyondSpec: 'The §3.3 ladder starts at "Note", which had no atom of its own.',
  },
  {
    key: 'users.warn',
    label: 'Warn user',
    description: 'Issue an in-app warning the user must acknowledge, citing the rule broken.',
    category: 'users',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'users.restrict',
    label: 'Restrict features',
    description:
      'Selectively disable media, links, group/channel creation, adding strangers; or apply a rate limit.',
    category: 'users',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
    addedBeyondSpec:
      'The ladder\'s "Feature restriction" and "Rate limit" rungs sit between warn and mute and needed their own atom.',
  },
  {
    key: 'users.mute',
    label: 'Mute user',
    description: 'Read-only for a bounded duration: can receive but not send.',
    category: 'users',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'users.shadow_restrict',
    label: 'Shadow-restrict user',
    description:
      'Messages to strangers silently fail to deliver. Deliberately separated from mute: it is deceptive by construction, so it carries its own atom, a typed confirmation and a mandatory policy justification.',
    category: 'users',
    breakGlass: 'typed_phrase',
    pii: false,
    superAdminOnly: false,
    addedBeyondSpec:
      '§3.3 requires shadow restriction be "used sparingly and logged heavily". Bundling it with users.mute would have made it a silent side effect of a routine permission.',
  },
  {
    key: 'users.ban.temp',
    label: 'Ban temporarily',
    description:
      'Duration-bound ban that auto-lifts. A role may cap the maximum duration it can issue (see roles.maxBanDays).',
    category: 'users',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'users.ban.permanent',
    label: 'Ban permanently',
    description: 'Terminal account ban. Requires four-eyes approval.',
    category: 'users',
    breakGlass: 'second_admin',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'users.unban',
    label: 'Reverse enforcement',
    description: 'Lift any active enforcement action, with a documented reason.',
    category: 'users',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'users.delete',
    label: 'Delete account & purge data',
    description:
      'Irreversible erasure across all stores, satisfying a legal erasure request. Super Admin only; blocked outright while the account is under legal hold.',
    category: 'users',
    breakGlass: 'typed_phrase',
    pii: true,
    superAdminOnly: true,
    addedBeyondSpec: 'The ladder\'s terminal rung ("Account deletion / data purge", Super Admin only).',
  },

  // --- Channels -----------------------------------------------------------
  {
    key: 'channels.view',
    label: 'View channels',
    description: 'Browse the channel directory, membership counts and public posts.',
    category: 'channels',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'channels.restrict',
    label: 'Restrict channel',
    description:
      'Block new joins, disable media/links/forwarding, age-gate, geo-restrict, delist from discovery, or freeze read-only.',
    category: 'channels',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'channels.takedown',
    label: 'Take down channel',
    description: 'Remove a channel entirely, notifying members with a stated reason.',
    category: 'channels',
    breakGlass: 'second_admin',
    pii: false,
    superAdminOnly: false,
  },

  // --- Reports ------------------------------------------------------------
  {
    key: 'reports.view',
    label: 'View reports',
    description: 'Read the moderation queue and case detail.',
    category: 'reports',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'reports.triage',
    label: 'Triage reports',
    description: 'Claim, categorise, prioritise and assign cases.',
    category: 'reports',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'reports.resolve',
    label: 'Resolve cases',
    description: 'Record a decision on a case and close it.',
    category: 'reports',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'reports.escalate',
    label: 'Escalate cases',
    description: 'Push a case to a higher tier or a specialist queue.',
    category: 'reports',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'reports.reopen',
    label: 'Reopen cases',
    description: 'Reverse a closure and return a case to the queue.',
    category: 'reports',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },

  // --- Support ------------------------------------------------------------
  {
    key: 'support.view',
    label: 'View tickets',
    description: 'Read the @support ticket inbox and ticket threads.',
    category: 'support',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'support.reply',
    label: 'Reply to tickets',
    description: 'Answer a user in-thread as @support.',
    category: 'support',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'support.assign',
    label: 'Assign tickets',
    description: 'Route, reassign, merge, transfer or escalate tickets.',
    category: 'support',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },

  // --- Administration -----------------------------------------------------
  {
    key: 'admins.create',
    label: 'Create admins',
    description:
      'Create an admin account. The grantor can never confer a permission or a scope broader than their own.',
    category: 'administration',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'admins.edit',
    label: 'Edit admins',
    description:
      'Change another admin\'s role, scope or status. Only ever applies to admins of strictly lower rank.',
    category: 'administration',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'admins.delete',
    label: 'Delete admins',
    description: 'Remove an admin account. Super Admin only per §1.1.',
    category: 'administration',
    breakGlass: 'typed_phrase',
    pii: false,
    superAdminOnly: true,
  },
  {
    key: 'roles.edit',
    label: 'Edit role definitions',
    description:
      'Change which atoms a role bundles, or define a custom role. Super Admin only per §1.1 — this is the power to rewrite every other check.',
    category: 'administration',
    breakGlass: 'typed_phrase',
    pii: false,
    superAdminOnly: true,
  },
  {
    key: 'audit.view',
    label: 'View audit log',
    description:
      'Read the immutable audit log. Scoped admins see only entries concerning targets inside their scope; the full log is Super Admin only.',
    category: 'administration',
    breakGlass: 'none',
    pii: true,
    superAdminOnly: false,
  },
  {
    key: 'settings.edit',
    label: 'Edit settings',
    description: 'Change console configuration: SLAs, break-glass modes, session policy, alerting.',
    category: 'administration',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },
  {
    key: 'automod.configure',
    label: 'Configure automod',
    description: 'Create and enable automated detection rules, including shadow-mode rules.',
    category: 'administration',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
  },

  // --- Compliance ---------------------------------------------------------
  {
    key: 'retention.configure',
    label: 'Configure retention',
    description:
      'Set per-data-class TTLs and trigger purges. Super Admin only per §1.1 — shortening a TTL destroys evidence.',
    category: 'compliance',
    breakGlass: 'typed_phrase',
    pii: false,
    superAdminOnly: true,
  },
  {
    key: 'privacy.dsr.view',
    label: 'View data requests',
    description: 'See incoming export, correction and erasure requests and their SLA state.',
    category: 'compliance',
    breakGlass: 'none',
    pii: true,
    superAdminOnly: false,
    addedBeyondSpec: '§8 requires tracked data-subject-rights workflows, which had no atom.',
  },
  {
    key: 'privacy.dsr.process',
    label: 'Process data requests',
    description: 'Fulfil or reject a data subject request and produce the export package.',
    category: 'compliance',
    breakGlass: 'typed_phrase',
    pii: true,
    superAdminOnly: false,
    addedBeyondSpec: '§8 requires tracked data-subject-rights workflows, which had no atom.',
  },
  {
    key: 'legalhold.manage',
    label: 'Manage legal holds',
    description:
      'Place or release a legal hold, suspending automatic deletion for records under investigation.',
    category: 'compliance',
    breakGlass: 'typed_phrase',
    pii: false,
    superAdminOnly: false,
    addedBeyondSpec: '§8 requires a legal hold mechanism, which had no atom.',
  },
  {
    key: 'transparency.generate',
    label: 'Generate transparency report',
    description: 'Produce the periodic aggregate report suitable for publication.',
    category: 'compliance',
    breakGlass: 'none',
    pii: false,
    superAdminOnly: false,
    addedBeyondSpec: '§8 requires periodic transparency reporting, which had no atom.',
  },

  // --- Child safety (§6.7) ------------------------------------------------
  {
    key: 'childsafety.access',
    label: 'Access child safety queue',
    description:
      'Enter the isolated child-safety pipeline. Holding this atom is NOT sufficient: the account must also appear on the named allowlist, and every individual view is separately audit-logged. Never granted through an ordinary role bundle.',
    category: 'child_safety',
    breakGlass: 'typed_phrase',
    pii: true,
    superAdminOnly: false,
    addedBeyondSpec:
      '§6.7 requires an isolated pipeline restricted to a named allowlist. It must never be reachable via reports.view.',
  },
  {
    key: 'childsafety.administer',
    label: 'Administer child safety allowlist',
    description: 'Add or remove accounts from the child-safety allowlist. Super Admin only.',
    category: 'child_safety',
    breakGlass: 'second_admin',
    pii: false,
    superAdminOnly: true,
    addedBeyondSpec: '§6.7 requires the allowlist itself be tightly controlled.',
  },
] as const;

export type Permission = (typeof CATALOGUE)[number]['key'];

/**
 * Annotating rather than casting is deliberate: it makes TypeScript check every
 * catalogue entry against PermissionMeta at compile time. A cast would silently
 * accept a typo'd category or a missing field.
 */
export const PERMISSIONS: readonly PermissionMeta[] = CATALOGUE;

export const ALL_PERMISSIONS: readonly Permission[] = CATALOGUE.map((p) => p.key);

const BY_KEY = new Map<string, PermissionMeta>(CATALOGUE.map((p) => [p.key, p]));

export function permissionMeta(key: Permission): PermissionMeta {
  const meta = BY_KEY.get(key);
  // Unreachable for a well-typed caller, but the API also validates strings
  // arriving from the database, where a stale row could name a removed atom.
  if (!meta) throw new Error(`Unknown permission atom: ${key}`);
  return meta;
}

export function isPermission(value: unknown): value is Permission {
  return typeof value === 'string' && BY_KEY.has(value);
}

/** Atoms that only the Super Admin may ever hold, whatever a role says. */
export const SUPER_ADMIN_ONLY: readonly Permission[] = CATALOGUE.filter(
  (p) => p.superAdminOnly,
).map((p) => p.key);

/** Atoms whose use must be recorded as a personal-data access (§8). */
export const PII_PERMISSIONS: readonly Permission[] = CATALOGUE.filter((p) => p.pii).map(
  (p) => p.key,
);

export function permissionsByCategory(): Map<PermissionCategory, PermissionMeta[]> {
  const out = new Map<PermissionCategory, PermissionMeta[]>();
  for (const p of PERMISSIONS) {
    const list = out.get(p.category);
    if (list) list.push(p);
    else out.set(p.category, [p]);
  }
  return out;
}
