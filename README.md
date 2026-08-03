# NeverOff Admin & Trust/Safety Console

Administration, analytics and moderation tooling for the NeverOff messenger.

This is a **separate application** from the NeverOff Android app. It lives in its own repository
and talks to the same Supabase project over the network. Nothing here is built into the app.

---

## Read this first: what this console can and cannot do

**NeverOff 1:1 and group messages are end-to-end encrypted, and that is not a setting.**

`CryptoManager.kt` derives a per-conversation secret with ECDH-P256 between two identity keys that
never leave their devices; `messages.msg_key` is a random per-message salt fed into an HMAC KDF,
not a key. The server holds ciphertext it cannot decrypt.

Consequences, which shaped every design decision here:

| Surface | Server can read it? | Moderation approach |
|---|---|---|
| 1:1 and group messages | **No** | Reporter-submitted evidence and unencrypted metadata only |
| Channel posts | Yes — plaintext by design (`07_channels.sql`) | Full server-side moderation |
| Profile fields (name, bio, avatar) | Yes | Full server-side moderation |
| Chat media | No — client-side encrypted before upload | Reporter-submitted evidence only |

**No endpoint in this API returns private message content, and none can.** If a future requirement
seems to need it, the answer is a reporting flow where the reporter voluntarily submits decrypted
evidence — not a change to the encryption. §8 of the spec is explicit: do not build any capability
that weakens or bypasses E2EE for moderation convenience.

---

## Status

Build-order steps 1, 2 and 4 are implemented (§10 of the spec):

- **Step 1** — auth, RBAC, admin accounts, immutable audit log
- **Step 2** — user directory, profiles, the §3.3 enforcement ladder, the ban experience
- **Step 4** — report intake, case clustering, the prioritised moderation queue, decisions
- **Step 3** — event rollups, dashboards, feature adoption, trust & safety KPIs
- **Step 5** — `@support` ticketing, in-app and reachable while banned
- **Step 6** — appeals and channel governance
- **Step 7** — the automod rules engine, shadow-mode first
- Plus **§8 privacy in full** and **§6.7 scaffolded**

### What the encryption rules out, and what it does not

This comes up in every section, so it is worth stating once:

- **Content-type splits on message volume are impossible.** The server holds ciphertext. Those
  metrics come from client telemetry, which is consented-only, so they are a *sample* and every
  response says so. Presenting a consented-user count as a platform total is not a rounding
  error — it is a wrong number with a confident label.
- **Keyword and regex automod rules cannot target private messages.** A database CHECK and an
  API guard both refuse it, because a rule that can never fire reads as coverage and is not.
- **Identical-content fan-out is not detectable.** Under ECDH the same sentence sent to twenty
  people produces twenty unrelated ciphertexts. Not hard — absent. The spam-ring patterns §6.6
  cares about are caught behaviourally instead: velocity, fan-out breadth, account age against
  recipient count.

What *is* a census: message counts, the sent → delivered → read funnel (`messages.status` is
plaintext), channel posts in full, registrations, retention, and geography at country granularity.

**Remaining gaps**, both real rather than merely unbuilt:

- `disable_forwarding` records the state and the app can read it through
  `channel_restriction_state`, but nothing in the client consumes it, and §6.5's forward-chain
  tracking does not exist.
- The automod engine has its schema, signals, shadow mode and quality measurement, but **no
  evaluation loop** — nothing calls the signal functions on a schedule yet, so no rule has ever
  fired. The rules ship in shadow mode, which is where they would start regardless.

---

## Setup

### Requirements

- Node.js 20.11 or later
- Docker (for the local Postgres and Redis)
- The NeverOff app repository checked out as a sibling directory, or `NEVEROFF_REPO_PATH` set

### First run

```bash
npm install
cp .env.example .env
```

Generate the two secrets `.env` needs:

```bash
node -e "console.log('SESSION_SECRET=' + require('crypto').randomBytes(48).toString('base64url'))"
```

```bash
node -e "console.log('TOTP_ENCRYPTION_KEY=' + require('crypto').randomBytes(48).toString('base64url'))"
```

Then bring everything up:

```bash
npm run setup:local
```

That runs `docker compose up -d`, installs the Supabase shim, applies NeverOff's own migrations
from the sibling repo, applies the console migrations, and seeds synthetic data. It prints admin
credentials and TOTP secrets when it finishes.

Start the app:

```bash
npm run dev
```

The console is at http://localhost:5173, the API at http://localhost:4000, and the OpenAPI
explorer at http://localhost:4000/docs.

Run the workers in a second terminal — enforcement expiry notifications and retention purging
depend on them:

```bash
npm run worker --workspace @neveroff-console/api
```

### Testing

```bash
npm test
```

The permission and enforcement tests are pure and always run. The database invariant tests skip
themselves when `DATABASE_URL` does not point at a migrated database.

---

## Local environment

`npm run db:bootstrap` turns a bare Postgres into something close enough to Supabase that the
**real, unmodified** migration files run against it — the `auth` and `storage` schemas,
`auth.uid()`, the realtime publication, and the anon/authenticated/service_role roles.

That matters more than it might look. The point of the local environment is to rehearse the exact
SQL that will later run in production. A local-only variant of the migrations would produce false
confidence.

NeverOff's own migrations are read from the sibling repository rather than copied here, so the
local schema cannot drift from the app's.

---

## Going to production

The console is designed to reach the live Supabase project — enforcement write-back is the whole
point. Three guard rails make that deliberate rather than accidental:

1. `DB_ALLOWED_HOSTS` must list the host before anything will connect.
2. The seed script refuses any non-local host outright. It invents people, and fabricated accounts
   in the real database would be indistinguishable from real ones afterwards.
3. Migrations that touch the live app schema require `PRODUCTION_MIGRATION_ACK` set to an
   exact, deliberately tedious phrase.

### Applying to production

```bash
npm run db:migrate:status
```

Review `packages/db/migrations/0006_neveroff_integration.sql` before running anything. It is the
only migration that touches the app's own tables. Then set `DATABASE_URL` to the Supabase
connection string, set `PRODUCTION_MIGRATION_ACK`, and run `npm run db:migrate`.

`0008_app_indexes.sql` builds indexes `CONCURRENTLY` and runs outside a transaction. On a large
`messages` table it will take a while. It does not block writes, which is the point.

### Rolling back

```bash
psql "$DATABASE_URL" -f packages/db/migrations/0006_neveroff_integration.down.sql
```

This removes the enforcement policies and the app-facing RPCs, returning the database to exactly
its pre-console behaviour. It deliberately does **not** drop the `admin` schema — rolling back an
integration should never destroy the audit log.

---

## Architecture decisions

### Enforcement correctness beats enforcement speed

Whether a user is banned is a time-dependent question. A projection table is always stale by
however long since the last worker run, and a stale projection either lets a banned user keep
sending or keeps someone locked out past their expiry.

So there are two representations with different jobs. `admin.enforcement_actions` is the source of
truth, and every access-control decision reads it live through an indexed `EXISTS` that evaluates
expiry against `NOW()`. `admin.user_restriction_state` is a denormalised projection used **only**
to sort and filter the directory. Nothing security-relevant reads the projection.

A consequence worth knowing: if the expiry worker stops, users are still correctly unbanned on
time. What stops is the *notification* that it happened. That is the right thing to degrade.

### Enforcement rides on RESTRICTIVE policies

Migration 0006 adds no columns to existing tables and modifies no existing policy. Postgres
`RESTRICTIVE` policies are AND-ed with the permissive ones already there, so the app's existing
rules keep working untouched and the new ones can only subtract.

No columns were added because the Android client reads these tables with `select {}` (`select=*`)
into fixed Kotlin data classes. Whether an extra column breaks decoding depends on the JSON
decoder's leniency — a library default that should not be load-bearing for a shipped app.

### Postgres for the job queue, not Redis

The spec suggests Redis + BullMQ (§9.1). The two jobs that matter in this phase — enforcement
expiry and retention purging — must be exactly-once-ish, survive restarts, and be transactionally
consistent with the rows they act on. `FOR UPDATE SKIP LOCKED` gives all three in the same
transaction as the enforcement write, so a ban lift, its audit entry and its user notification
either all land or none do.

Doing that across Redis and Postgres means a distributed transaction, or accepting that a crash
between the two leaves a user banned with no record of why.

The trade-off is throughput: this tops out in the low thousands of jobs per second, far above what
enforcement expiry needs and far below what an event pipeline needs. Redis is in the stack and
should take the analytics fan-out in step 3, where losing a job is survivable.

### Two privacy guarantees are enforced by trigger, not by code

Guarantees that live only in application code hold until someone adds a second code path. So:

- A user who declined analytics consent has their telemetry insert **rejected** by the database.
- Any event payload containing a `message`/`body`/`ciphertext`-shaped key is **rejected**.

A future ingestion endpoint, a backfill script or someone in `psql` cannot route around either.
Both raise rather than silently dropping, so a violating caller fails loudly in development
instead of quietly under-collecting in production.

The §4 rule that an appeal cannot be decided by the admin who issued the action is enforced the
same way.

### The audit log is tamper-evident, not tamper-proof

Each entry stores the SHA-256 of its own canonical content chained to the previous entry's hash,
and `UPDATE`/`DELETE`/`TRUNCATE` are blocked by trigger. `admin.verify_audit_chain()` reports
exactly where a break occurs.

**A Postgres superuser can still disable the trigger, rewrite rows and recompute the chain.**
Defeating that needs the log shipped to append-only external storage — an object-lock bucket or a
SIEM. This schema gives you detection, not prevention, against an attacker who already owns the
database. The runbook covers that as a deployment requirement.

### Evidence is reporter-submitted, because it has to be

When a user reports a message, the server holds ciphertext it cannot read. It cannot snapshot the
content, show it to a moderator, or classify it. The only party who can produce readable evidence
is the reporter, whose device already holds the key.

So `evidence_snapshots.source` distinguishes `reporter_submitted` from `server_captured`, and a
database constraint stops the second being claimed for a message. Channel posts and profile
fields are plaintext server-side and are captured directly; messages and chat media never can be.

A message report with no reporter-submitted evidence is a metadata-only case. It is still
actionable on pattern — volume, velocity, the reported account's history — and the queue says so
rather than showing an empty content pane and letting a moderator assume the report was empty.

Reporter-submitted plaintext is the most sensitive data this console holds, so reading it is a
separate audited call rather than part of loading the case, and it is logged as a personal-data
access so the §7 anomaly checks cover it.

### Brigading lowers priority rather than raising it

Coordinated reporting is detected from account age, burst shape and reporting history, and a
flagged case has its priority multiplied by 0.4. Manufactured volume floating to the top of the
queue is precisely the outcome a brigade is trying to buy.

Honest limitation: real brigading detection leans on device fingerprints and social-graph
clustering. This console deliberately collects neither, so the available signals are weaker.
They flag a case for human attention and never action or dismiss anything by themselves.

### One source of truth for permissions

Permission atoms, roles and reason codes live in `packages/shared`. The database holds a derived
copy, synced automatically at the end of every migration run, so grants have referential integrity
and a compliance reviewer can produce the permission matrix with a SQL query rather than by reading
TypeScript.

There are no role-name checks anywhere. Code asks "does this actor hold `users.ban.temp`?", never
"is this actor a Tier 2?".

---

## Where the spec was ambiguous

These are policy calls, not technical ones. Each is documented inline where it is implemented, and
each takes the narrower reading — under-granting surfaces as a moderator asking for access,
over-granting surfaces as an incident.

- **Tier 3 cannot ban at all.** §1.1 enumerates exactly "warnings and mutes"; "Cannot permanently
  ban" reads as belt-and-braces rather than as licence to issue temporary bans.
- **Tier 2 cannot shadow-restrict.** §3.3 says use it sparingly. Keeping it at Tier 1 and above
  makes that structural rather than cultural.
- **Tier 3 gets `reports.resolve`.** Otherwise they can warn a user but never close the case they
  just actioned, which only moves the work.
- **Tier 2 gets `users.view_pii`.** A Moderation Lead reviewing ban evasion needs the connections
  graph, which is what that atom is for.
- **Twelve permission atoms were added** beyond §1.2's minimum set, each carrying an
  `addedBeyondSpec` note explaining why an existing atom could not carry the meaning. A test
  fails if a new atom is added without one.

---

## Documentation

- [Deploying to Oracle Cloud](docs/DEPLOY-ORACLE.md) — start to finish, with TLS and systemd
- [Permission matrix](docs/PERMISSION_MATRIX.md) — role × permission grid
- [Database ERD](docs/ERD.md)
- [Operations runbook](docs/RUNBOOK.md) — how to handle each escalation type
- OpenAPI spec — `npm run openapi --workspace @neveroff-console/api` writes `apps/api/openapi.json`

---

## Legal note

Two areas carry statutory weight and are **not** ordinary features:

- **§6.7 child safety** is scaffolded only. The access gate, isolated case table, per-view audit
  logging and automatic legal hold work. Hash matching and mandatory authority reporting return
  501 with an explanation, because a reporting path that appears to work but does not is worse
  than none — it produces the false belief that a legal obligation has been discharged.
- **§8 retention TTLs and jurisdiction rules** ship with defensible defaults, not legal
  determinations.

Engage counsel before this console handles a single real user.
