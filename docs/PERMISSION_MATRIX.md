# Permission matrix

Role × permission grid. **Generated** — regenerate after any change to
`packages/shared/src/permissions.ts` or `roles.ts`:

```bash
npm run docs:matrix
```

Legend: **✓** granted · **·** not granted · **SA** reserved to the Super Admin regardless of role
· **BG** requires break-glass friction at the point of use (typed phrase or second-admin approval)
· **PII** use is recorded as a personal-data access

| Permission | Super Admin | Tier 1 | Tier 2 | Tier 3 | Analyst | Notes |
|---|:--:|:--:|:--:|:--:|:--:|---|
| **Analytics** |
| `analytics.view` | ✓ | ✓ | ✓ | · | ✓ | |
| `analytics.export` | ✓ | ✓ | · | · | ✓ | Tier 2 is read-only per §1.1 |
| `analytics.export_raw` | ✓ | · | · | · | · | SA · BG · PII |
| **Users** |
| `users.view` | ✓ | ✓ | ✓ | ✓ | · | |
| `users.search` | ✓ | ✓ | ✓ | ✓ | · | Exact match on identifiers only |
| `users.view_pii` | ✓ | ✓ | ✓ | · | · | PII · Tier 3 excluded per §1.1 |
| `users.contact` | ✓ | ✓ | ✓ | ✓ | · | |
| `users.note` | ✓ | ✓ | ✓ | ✓ | · | |
| `users.warn` | ✓ | ✓ | ✓ | ✓ | · | |
| `users.restrict` | ✓ | ✓ | ✓ | · | · | Feature restriction and rate limit |
| `users.mute` | ✓ | ✓ | ✓ | ✓ | · | |
| `users.shadow_restrict` | ✓ | ✓ | · | · | · | BG · deceptive by construction |
| `users.ban.temp` | ✓ | ✓ | ✓ | · | · | Tier 2 capped at `MAX_BAN_DAYS_T2` |
| `users.ban.permanent` | ✓ | ✓ | · | · | · | BG (second admin) |
| `users.unban` | ✓ | ✓ | ✓ | · | · | |
| `users.delete` | ✓ | · | · | · | · | SA · BG · PII · irreversible |
| **Channels** |
| `channels.view` | ✓ | ✓ | ✓ | ✓ | · | |
| `channels.restrict` | ✓ | ✓ | ✓ | · | · | |
| `channels.takedown` | ✓ | ✓ | · | · | · | BG (second admin) |
| **Reports** |
| `reports.view` | ✓ | ✓ | ✓ | ✓ | · | |
| `reports.triage` | ✓ | ✓ | ✓ | ✓ | · | |
| `reports.resolve` | ✓ | ✓ | ✓ | ✓ | · | |
| `reports.escalate` | ✓ | ✓ | ✓ | ✓ | · | |
| `reports.reopen` | ✓ | ✓ | ✓ | · | · | Tier 2 overrides Tier 3 (§1.1) |
| **Support** |
| `support.view` | ✓ | ✓ | ✓ | ✓ | · | |
| `support.reply` | ✓ | ✓ | ✓ | ✓ | · | |
| `support.assign` | ✓ | ✓ | ✓ | · | · | Reassignment is a Tier 2 power |
| **Administration** |
| `admins.create` | ✓ | ✓ | · | · | · | Never above your own authority |
| `admins.edit` | ✓ | ✓ | · | · | · | Strictly lower rank only |
| `admins.delete` | ✓ | · | · | · | · | SA · BG |
| `roles.edit` | ✓ | · | · | · | · | SA · BG · rewrites every other check |
| `audit.view` | ✓ | ✓ | ✓ | · | · | PII · scoped below Super Admin |
| `settings.edit` | ✓ | ✓ | · | · | · | |
| `automod.configure` | ✓ | ✓ | · | · | · | |
| **Compliance** |
| `retention.configure` | ✓ | · | · | · | · | SA · BG |
| `privacy.dsr.view` | ✓ | ✓ | · | · | · | PII |
| `privacy.dsr.process` | ✓ | ✓ | · | · | · | BG · PII |
| `legalhold.manage` | ✓ | ✓ | · | · | · | BG |
| `transparency.generate` | ✓ | ✓ | · | · | · | |
| **Child safety (§6.7)** |
| `childsafety.access` | ✓ | · | · | · | · | BG · PII · **allowlist also required** |
| `childsafety.administer` | ✓ | · | · | · | · | SA · BG |

**Totals:** Super Admin 41 · Tier 1 34 · Tier 2 22 · Tier 3 13 · Analyst 2

---

## Properties the tests enforce

`packages/shared/src/roles.test.ts` asserts these on every run. They are invariants, not a snapshot
of the table above — a snapshot gets regenerated the first time it fails and stops meaning anything.

1. **The Super Admin holds every atom.** No exceptions, no gaps.
2. **Super-Admin-only atoms are stripped from everyone else** — even when granted directly as an
   individual extra permission. Fail closed.
3. **The moderation tiers nest: Tier 1 ⊇ Tier 2 ⊇ Tier 3**, and each is strictly larger than the
   next.
4. **Analyst is orthogonal, not below.** It holds `analytics.export`, which Tier 3 does not. Rank
   ordering drives delegation; permission sets are not totally ordered, and assuming otherwise is
   a bug waiting to happen.
5. **No role can ever grant an atom it does not hold** — checked by brute force over every
   (actor role, target role, permission) triple.
6. **Child-safety access never arrives through a role bundle.** It is granted individually, and
   the permission alone is not sufficient: the account must also appear on the named allowlist
   with unexpired training, checked in the database.
7. **Every atom beyond §1.2's minimum set carries a written justification.**

## Scoping

Orthogonal to the grid. A scope narrows *which records* an admin's permissions apply to, across
four independent axes: countries, languages, channel IDs and report categories. `null` on an axis
means unrestricted; an empty array means restricted to nothing.

Two rules matter:

- **Scope may only ever narrow.** A DE-scoped lead cannot mint a globally-scoped moderator.
- **A scoped admin cannot act on a record whose relevant attribute is unknown.** If a user's
  country is unknown, a DE-only moderator is denied. Failing open would leak the entire
  unknown-country population into every scope.
