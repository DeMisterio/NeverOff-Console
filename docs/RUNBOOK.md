# Admin operations runbook

How to handle each escalation type. Written for whoever is on call, not for whoever wrote the code.

---

## Deployment prerequisites

Two things must be true before this console governs real users. Neither is code.

**1. Ship the audit log to append-only external storage.**

The in-database audit log is tamper-*evident*: hash-chained, with `UPDATE`/`DELETE`/`TRUNCATE`
blocked by trigger. A Postgres superuser can still disable the trigger, rewrite rows and recompute
the chain. Stream `admin.audit_log` to an object-lock bucket or a SIEM. Until that exists, treat
the log as strong evidence against an ordinary admin and no evidence at all against someone with
database credentials.

**2. Have counsel sign off on §6.7 and §8.**

The child-safety pipeline is scaffolding. Hash matching and mandatory authority reporting return
501 by design. Retention TTLs and jurisdiction rules ship with defensible defaults, not legal
determinations.

---

## Daily checks

```bash
curl -s localhost:4000/ready | jq
```

Then, in the console:

- **Audit → integrity banner.** Green means the hash chain is intact. Red is an incident, not a bug.
- **Audit → alerts.** Anything unacknowledged.
- **Appeals → breaching SLA.** Someone is waiting on an account they believe was wrongly restricted.

Worker health:

```sql
SELECT name, last_success_at, consecutive_failures, last_error FROM admin.worker_runs ORDER BY name;
```

If `enforcement-expiry` has not succeeded in over an hour, users are being restored on time but not
being *told*. Fix within the day; it is not a lockout.

---

## Escalations

### The audit chain reports a break

**Severity: critical. Treat as compromise until proven otherwise.**

1. Do not restart anything. Do not run migrations.
2. Capture the evidence:
   ```sql
   SELECT * FROM admin.verify_audit_chain(0);
   ```
3. The first `broken_at_id` bounds when tampering began. Everything before it is still trustworthy.
4. Pull the external copy of the log, if you have one, and diff. That is the authoritative record.
5. Rotate every database credential and every admin session:
   ```sql
   UPDATE admin.sessions SET revoked_at = NOW(), revoke_reason = 'Audit integrity incident'
    WHERE revoked_at IS NULL;
   ```
6. Only then start asking who.

A break with no external copy means you cannot reconstruct what happened. That is why the external
copy is a prerequisite.

---

### A user says they were banned by mistake

1. Find them in **Users**, open the profile, read **Safety history**.
2. The decision note explains the moderator's reasoning; it is written for exactly this moment.
3. If they have appealed, it is in **Appeals**. **You cannot decide an appeal against an action you
   issued** — the database refuses it. Hand it to a colleague.
4. If they have not appealed and the reason is appealable, tell them to use the button on the ban
   screen rather than deciding unilaterally. The appeal path is the record.
5. Overturning lifts the action immediately and notifies them.

---

### A ban did not lift on expiry

Almost certainly a notification failure, not an enforcement failure. Check first:

```sql
SELECT admin.is_send_blocked('<user-uuid>'), admin.is_access_blocked('<user-uuid>');
```

If both are `false`, the user **is** unbanned — every access check evaluates expiry against
`NOW()`, so restoration does not depend on any worker. They were simply never told. Check the
outbox:

```sql
SELECT kind, attempts, last_error, abandoned_at
  FROM admin.notification_outbox
 WHERE user_id = '<user-uuid>' ORDER BY created_at DESC LIMIT 10;
```

`No push token registered` is normal and not a fault — the app shows current status on next open.

If either function returns `true` past the expiry, that **is** a real bug. Capture the action row
and escalate to engineering:

```sql
SELECT * FROM admin.enforcement_actions WHERE user_id = '<user-uuid>' AND reversed_at IS NULL;
```

---

### Enforcement is blocking users it should not

The blast-radius control. Removing the four `RESTRICTIVE` policies returns the app to exactly its
pre-console behaviour, immediately, without touching any console data:

```bash
psql "$DATABASE_URL" -f packages/db/migrations/0006_neveroff_integration.down.sql
```

Users can send again within seconds. Enforcement records, the audit log and appeals are all
untouched, so nothing is lost and the policies can be reapplied once the cause is understood.

Do this before debugging, not after. A messenger that will not send messages is a worse problem
than an unenforced ban.

---

### A moderator is suspected of abusing access

1. **Suspend first, investigate second.** Suspending revokes every session immediately.
2. Pull their trail:
   ```sql
   SELECT occurred_at, action, target_label, is_pii_access, note
     FROM admin.audit_log WHERE actor_admin_id = '<admin-uuid>'
    ORDER BY occurred_at DESC LIMIT 500;
   ```
3. PII access specifically — each row carries the reason they typed:
   ```sql
   SELECT occurred_at, target_label, note FROM admin.audit_log
    WHERE actor_admin_id = '<admin-uuid>' AND is_pii_access ORDER BY occurred_at DESC;
   ```
4. Check for alerts already raised against them in `admin.alerts`.
5. Every enforcement action they issued is reversible with a documented reason. Review rather than
   mass-revert — some will have been correct.

---

### A safety emergency (self-harm, imminent threat)

**This path must never be handled by automation alone.**

Self-harm reasons are refused by the enforcement API on purpose — a person disclosing risk is not
committing a violation, and the code says so:

> Self-harm reports route to the safety escalation path, not to enforcement.

1. Page the on-call human. Do not queue it.
2. Surface the appropriate regional crisis resources to the user. **Which resources, for which
   region, is a policy question your safety lead must answer before this situation arises** — it is
   not defined in this repository, and improvising it at 3am is how it goes wrong.
3. Enforcement against the person at risk is almost never the answer. Restricting someone in
   crisis removes their support network.
4. For a credible threat to others, follow your legal escalation policy.

---

### Child safety report

**Do not open it in general tooling. Do not forward it. Do not screenshot it.**

1. Reports in this category bypass the ordinary queue entirely and land in the isolated pipeline.
2. Only accounts on `admin.child_safety_allowlist` with current training can open them. Every view
   is individually logged.
3. Every case automatically places a legal hold, so no retention job can purge the evidence.
4. **Mandatory reporting is not implemented.** The endpoint returns 501. Follow the manual
   procedure your counsel has defined. If no such procedure exists, that is the blocker — escalate
   to legal, not to engineering.

---

### Lost authenticator

Only an admin of strictly higher rank can reset it, from **Admins → force re-enrolment**. This
revokes their sessions and clears their recovery codes.

**Verify out of band first.** A phone call to a known number, not a reply to the email asking for
the reset. Talking someone through a 2FA reset is the single most effective social-engineering
attack against a console like this.

---

### The Super Admin has left

Transfer, do not delete — the account cannot be deleted while it holds the role, and the database
enforces that.

The outgoing Super Admin runs the transfer themselves from **Admins**. It is atomic and requires a
typed confirmation.

**If they have already gone**, this needs direct database access:

```sql
BEGIN;
SELECT admin.transfer_super_admin('<old-uuid>', '<new-uuid>', 'tier1_platform_manager');
COMMIT;
```

Then immediately: force TOTP re-enrolment on the old account, suspend it, and record why in the
audit log. Do this with two people present.

---

## Reference

| Task | Where |
|---|---|
| Roll back enforcement | `packages/db/migrations/0006_neveroff_integration.down.sql` |
| Verify audit integrity | Console → Audit, or `SELECT * FROM admin.verify_audit_chain(0)` |
| Worker health | `SELECT * FROM admin.worker_runs` |
| Pending approvals | `SELECT * FROM admin.break_glass_requests WHERE status = 'pending'` |
| Active legal holds | `SELECT * FROM admin.legal_holds WHERE released_at IS NULL` |
| Retention state | `SELECT * FROM admin.retention_policies` |
| Invalid indexes after a failed concurrent build | `SELECT indexrelid::regclass FROM pg_index WHERE NOT indisvalid` |
