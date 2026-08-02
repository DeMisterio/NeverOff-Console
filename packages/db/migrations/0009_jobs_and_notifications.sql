-- ============================================================================
-- 0009_jobs_and_notifications.sql — durable background work.
--
-- Why Postgres rather than the Redis/BullMQ the spec suggests (§9.1):
--
--   The two jobs that matter in this phase are enforcement expiry and retention
--   purging. Both must be exactly-once-ish, must survive a process restart, and
--   must be transactionally consistent with the rows they act on. A Postgres
--   queue claimed with FOR UPDATE SKIP LOCKED gives all three for free, in the
--   same transaction as the enforcement write — a ban lift and its audit entry
--   and its user notification either all land or none do.
--
--   Doing that across Redis and Postgres means a distributed transaction, or
--   accepting that a crash between the two leaves a user banned with no record
--   of why. Redis stays in the stack for caching and for the analytics fan-out
--   in a later phase, where losing a job is survivable.
--
-- The trade-off is throughput: this design tops out in the low thousands of
-- jobs per second, far above what enforcement expiry needs and far below what
-- an event pipeline needs. Revisit when the queue is doing analytics work.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Outbound user notifications
--
-- Written in the same transaction as the action that causes them, then
-- delivered by a worker. §4 requires the user be told the reason and the expiry;
-- §3.3 requires they be told again when access is restored. A notification that
-- is dropped because FCM was briefly unavailable is a compliance failure, not a
-- cosmetic one, so retries are persistent and failures are visible.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.notification_outbox (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  kind             TEXT NOT NULL,
  -- Reason code, case ref, expiry — never free text, so the client renders it
  -- in the user's own language from its own string resources.
  payload          JSONB NOT NULL DEFAULT '{}'::jsonb,
  locale           TEXT NOT NULL DEFAULT 'en',
  related_action_id UUID REFERENCES admin.enforcement_actions(id) ON DELETE CASCADE,

  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  attempts         INTEGER NOT NULL DEFAULT 0,
  sent_at          TIMESTAMPTZ,
  abandoned_at     TIMESTAMPTZ,
  last_error       TEXT,

  CONSTRAINT notification_kind_valid CHECK (kind IN (
    'enforcement_applied', 'enforcement_expired', 'enforcement_reversed',
    'appeal_received', 'appeal_decided', 'admin_message', 'warning_issued')),
  CONSTRAINT notification_locale_shape CHECK (locale ~ '^[a-z]{2}$')
);

-- The claim query's index: unsent, unabandoned, due now, oldest first.
CREATE INDEX IF NOT EXISTS idx_notification_pending
  ON admin.notification_outbox(next_attempt_at)
  WHERE sent_at IS NULL AND abandoned_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_notification_user
  ON admin.notification_outbox(user_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Worker bookkeeping
--
-- Exists so "the expiry worker has not run for two hours" is answerable. A
-- silent worker is the failure mode that keeps users banned past their expiry,
-- and nothing else in the system would notice.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.worker_runs (
  name            TEXT PRIMARY KEY,
  last_started_at TIMESTAMPTZ,
  last_success_at TIMESTAMPTZ,
  last_error_at   TIMESTAMPTZ,
  last_error      TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  items_processed_total BIGINT NOT NULL DEFAULT 0
);

CREATE OR REPLACE FUNCTION admin.worker_started(p_name TEXT)
RETURNS VOID
LANGUAGE sql
AS $$
  INSERT INTO admin.worker_runs (name, last_started_at)
  VALUES (p_name, NOW())
  ON CONFLICT (name) DO UPDATE SET last_started_at = NOW();
$$;

CREATE OR REPLACE FUNCTION admin.worker_succeeded(p_name TEXT, p_items INTEGER DEFAULT 0)
RETURNS VOID
LANGUAGE sql
AS $$
  INSERT INTO admin.worker_runs (name, last_success_at, items_processed_total, consecutive_failures)
  VALUES (p_name, NOW(), p_items, 0)
  ON CONFLICT (name) DO UPDATE SET
    last_success_at = NOW(),
    items_processed_total = admin.worker_runs.items_processed_total + p_items,
    consecutive_failures = 0;
$$;

CREATE OR REPLACE FUNCTION admin.worker_failed(p_name TEXT, p_error TEXT)
RETURNS VOID
LANGUAGE sql
AS $$
  INSERT INTO admin.worker_runs (name, last_error_at, last_error, consecutive_failures)
  VALUES (p_name, NOW(), p_error, 1)
  ON CONFLICT (name) DO UPDATE SET
    last_error_at = NOW(),
    last_error = p_error,
    consecutive_failures = admin.worker_runs.consecutive_failures + 1;
$$;

-- ---------------------------------------------------------------------------
-- Enforcement expiry, done in the database.
--
-- This is the §3.3 promise that "the system must automatically restore access
-- on expiry and notify the user", and the §11 acceptance criterion that access
-- is restored automatically.
--
-- It runs as one statement so the lift, the audit entry and the notification
-- are atomic. FOR UPDATE SKIP LOCKED means two workers running at once split
-- the work rather than colliding, and a worker that dies mid-batch loses only
-- its own uncommitted rows.
--
-- Note it does NOT modify enforcement_actions: an action with expires_at in the
-- past is *already* inactive to every reader, because every predicate compares
-- against NOW(). This only records that expiry happened and tells the user. If
-- this worker never ran, users would still be unbanned on time — they just
-- would not be told. That is the right failure mode.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.process_expired_enforcements(p_limit INTEGER DEFAULT 100)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  r       RECORD;
  v_count INTEGER := 0;
BEGIN
  FOR r IN
    SELECT id, user_id, type, case_ref, reason_code, expires_at
      FROM admin.enforcement_actions
     WHERE reversed_at IS NULL
       AND expires_at IS NOT NULL
       AND expires_at <= NOW()
       AND expiry_notified_at IS NULL
     ORDER BY expires_at ASC
     LIMIT p_limit
     FOR UPDATE SKIP LOCKED
  LOOP
    UPDATE admin.enforcement_actions
       SET expiry_notified_at = NOW()
     WHERE id = r.id;

    -- Shadow restrictions are never disclosed, so their expiry is not either.
    IF r.type <> 'shadow_restriction' THEN
      INSERT INTO admin.notification_outbox (user_id, kind, payload, related_action_id)
      VALUES (r.user_id, 'enforcement_expired',
              jsonb_build_object(
                'case_ref', r.case_ref,
                'action_type', r.type,
                'reason_code', r.reason_code,
                'expired_at', r.expires_at),
              r.id);
    END IF;

    INSERT INTO admin.audit_log (
      actor_admin_id, actor_label, actor_role, origin, action,
      target_type, target_id, target_label, after_state, note, entry_hash)
    VALUES (
      NULL, 'system:enforcement-expiry', NULL, 'system', 'user.enforcement.expired',
      'user', r.user_id::text, r.case_ref,
      jsonb_build_object('action_id', r.id, 'type', r.type, 'expired_at', r.expires_at),
      'Access automatically restored on expiry.', '');

    PERFORM admin.recompute_user_restrictions(r.user_id);
    v_count := v_count + 1;
  END LOOP;

  RETURN v_count;
END;
$$;

-- ---------------------------------------------------------------------------
-- Appeal SLA escalation (§4: "auto-escalation if breached")
-- ---------------------------------------------------------------------------

-- Widen the alert taxonomy for the kinds this migration introduces. Done as a
-- constraint swap rather than a free-text column: an unconstrained `kind` drifts
-- into a dozen near-duplicate spellings and stops being groupable.
ALTER TABLE admin.alerts DROP CONSTRAINT IF EXISTS alerts_kind_valid;
ALTER TABLE admin.alerts ADD CONSTRAINT alerts_kind_valid CHECK (kind IN (
  'bulk_action_out_of_hours',
  'unusual_pii_access_volume',
  'repeated_single_user_access',
  'mass_export',
  'audit_chain_broken',
  'failed_login_burst',
  'privilege_escalation_attempt',
  'shadow_restriction_applied',
  'appeal_sla_breached',
  'notification_delivery_failing',
  'worker_stalled'
));

CREATE OR REPLACE FUNCTION admin.escalate_breached_appeals(p_limit INTEGER DEFAULT 100)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  r       RECORD;
  v_count INTEGER := 0;
BEGIN
  FOR r IN
    SELECT a.id, a.user_id, a.sla_due_at, e.case_ref
      FROM admin.appeals a
      JOIN admin.enforcement_actions e ON e.id = a.action_id
     WHERE a.status IN ('pending', 'under_review')
       AND a.escalated_at IS NULL
       AND a.sla_due_at <= NOW()
     ORDER BY a.sla_due_at ASC
     LIMIT p_limit
     FOR UPDATE OF a SKIP LOCKED
  LOOP
    UPDATE admin.appeals SET escalated_at = NOW() WHERE id = r.id;

    INSERT INTO admin.alerts (kind, severity, title, detail, evidence)
    VALUES ('appeal_sla_breached', 'high',
            'Appeal ' || r.case_ref || ' has breached its SLA',
            'This appeal passed its review deadline without a decision. Someone is waiting on ' ||
            'an account they believe was wrongly restricted.',
            jsonb_build_object('appeal_id', r.id, 'case_ref', r.case_ref, 'due_at', r.sla_due_at));

    v_count := v_count + 1;
  END LOOP;

  RETURN v_count;
END;
$$;

-- ---------------------------------------------------------------------------
-- Post-conditions
-- ---------------------------------------------------------------------------
SELECT 'worker_functions' AS check_name,
       count(*) = 5 AS ok,
       count(*)::text || ' of 5' AS detail
  FROM pg_proc
 WHERE pronamespace = 'admin'::regnamespace
   AND proname IN ('worker_started', 'worker_succeeded', 'worker_failed',
                   'process_expired_enforcements', 'escalate_breached_appeals')
UNION ALL
SELECT 'outbox_table',
       count(*) = 1,
       'admin.notification_outbox'
  FROM information_schema.tables
 WHERE table_schema = 'admin' AND table_name = 'notification_outbox';
