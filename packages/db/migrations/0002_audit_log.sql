-- ============================================================================
-- 0002_audit_log.sql — immutable audit log and admin-behaviour alerting (§7).
--
-- Three properties, in order of how much they are worth:
--
--   1. Append-only. A trigger rejects every UPDATE and DELETE, so no console
--      code path — including one running as the Super Admin — can rewrite
--      history.
--   2. Tamper-evident. Each row stores the SHA-256 of its own canonical content
--      chained to the previous row's hash. Editing or removing a row out of band
--      (say, by a superuser who dropped the trigger first) breaks the chain from
--      that point on, and admin.verify_audit_chain() will report exactly where.
--   3. Denormalised actor. The acting admin's name and role are copied onto the
--      row. Deleting an admin account must never blank out what they did.
--
-- Honest limitation: a Postgres superuser can disable the trigger, rewrite rows
-- and recompute the whole chain. Defeating that needs the log shipped to
-- append-only external storage (object-lock bucket or a SIEM). The runbook
-- documents that as a deployment requirement; this schema gets you detection,
-- not prevention, against an attacker who already owns the database.
-- ============================================================================

CREATE TABLE IF NOT EXISTS admin.audit_log (
  id                     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- NULL when the actor is the system (an expiry worker, an automod rule).
  actor_admin_id         UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  -- Denormalised so the record survives the account being deleted.
  actor_label            TEXT NOT NULL,
  actor_role             TEXT,

  origin                 TEXT NOT NULL DEFAULT 'manual',

  -- Dotted action name, e.g. 'user.ban.temp', 'admin.create', 'pii.reveal'.
  action                 TEXT NOT NULL,
  -- The permission atom exercised, when there was one.
  permission_key         TEXT REFERENCES admin.permissions(key) ON DELETE SET NULL,

  target_type            TEXT NOT NULL,
  target_id              TEXT,
  target_label           TEXT,

  -- §7 requires before/after state. Both NULL for a pure read (a PII reveal).
  before_state           JSONB,
  after_state            JSONB,

  reason_code            TEXT,
  note                   TEXT,

  ip                     INET,
  session_id             UUID,
  user_agent             TEXT,
  -- Correlates every row written while serving one HTTP request.
  request_id             TEXT,

  -- Drives the §8 requirement that PII access is itself logged and countable.
  is_pii_access          BOOLEAN NOT NULL DEFAULT FALSE,
  break_glass_request_id UUID REFERENCES admin.break_glass_requests(id) ON DELETE SET NULL,

  -- Tamper-evidence chain.
  prev_hash              TEXT,
  entry_hash             TEXT NOT NULL,

  CONSTRAINT audit_origin_valid CHECK (origin IN ('manual', 'automated', 'system')),
  CONSTRAINT audit_target_type_valid
    CHECK (target_type IN ('user', 'admin', 'channel', 'case', 'report', 'ticket',
                           'appeal', 'setting', 'role', 'export', 'session',
                           'retention', 'legal_hold', 'dsr', 'automod_rule', 'system'))
);

CREATE INDEX IF NOT EXISTS idx_audit_occurred_at ON admin.audit_log(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON admin.audit_log(actor_admin_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_target ON admin.audit_log(target_type, target_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON admin.audit_log(action, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_pii ON admin.audit_log(actor_admin_id, occurred_at DESC)
  WHERE is_pii_access;

-- Full-text search over the human-readable columns (§7: "Full-text search").
CREATE INDEX IF NOT EXISTS idx_audit_fts ON admin.audit_log
  USING GIN (to_tsvector('simple',
    coalesce(actor_label,'') || ' ' || coalesce(action,'') || ' ' ||
    coalesce(target_label,'') || ' ' || coalesce(target_id,'') || ' ' ||
    coalesce(reason_code,'') || ' ' || coalesce(note,'')));

-- ---------------------------------------------------------------------------
-- Hash chain
--
-- sha256() is built into PostgreSQL 11+, so this needs no extension and behaves
-- identically on local Postgres and on Supabase.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.audit_canonical_payload(
  p_occurred_at TIMESTAMPTZ, p_actor UUID, p_actor_label TEXT, p_origin TEXT,
  p_action TEXT, p_target_type TEXT, p_target_id TEXT,
  p_before JSONB, p_after JSONB, p_reason TEXT, p_note TEXT, p_prev TEXT
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
AS $$
  -- Fixed field order and explicit NULL sentinels: two different rows must never
  -- serialise to the same string. jsonb::text is stable because jsonb
  -- normalises key order on storage.
  SELECT concat_ws(
    '|',
    to_char(p_occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'),
    coalesce(p_actor::text, '~'),
    coalesce(p_actor_label, '~'),
    coalesce(p_origin, '~'),
    coalesce(p_action, '~'),
    coalesce(p_target_type, '~'),
    coalesce(p_target_id, '~'),
    coalesce(p_before::text, '~'),
    coalesce(p_after::text, '~'),
    coalesce(p_reason, '~'),
    coalesce(p_note, '~'),
    coalesce(p_prev, '~')
  );
$$;

CREATE OR REPLACE FUNCTION admin.audit_chain_link()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  v_prev TEXT;
BEGIN
  -- Serialise chain construction. Without this, two concurrent inserts could
  -- both read the same predecessor and produce a forked chain.
  PERFORM pg_advisory_xact_lock(hashtext('admin.audit_log.chain'));

  SELECT entry_hash INTO v_prev
    FROM admin.audit_log
   ORDER BY id DESC
   LIMIT 1;

  NEW.prev_hash := v_prev;
  NEW.entry_hash := encode(sha256(convert_to(
    admin.audit_canonical_payload(
      NEW.occurred_at, NEW.actor_admin_id, NEW.actor_label, NEW.origin,
      NEW.action, NEW.target_type, NEW.target_id,
      NEW.before_state, NEW.after_state, NEW.reason_code, NEW.note, v_prev
    ), 'UTF8')), 'hex');

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_chain ON admin.audit_log;
CREATE TRIGGER trg_audit_chain
  BEFORE INSERT ON admin.audit_log
  FOR EACH ROW EXECUTE FUNCTION admin.audit_chain_link();

-- ---------------------------------------------------------------------------
-- Append-only enforcement
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.audit_reject_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION
    'admin.audit_log is append-only: % is not permitted on audit entries.', TG_OP
    USING ERRCODE = 'raise_exception',
          HINT = 'Correct a mistaken entry by appending a corrective entry that references it.';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_no_update ON admin.audit_log;
CREATE TRIGGER trg_audit_no_update
  BEFORE UPDATE ON admin.audit_log
  FOR EACH ROW EXECUTE FUNCTION admin.audit_reject_mutation();

DROP TRIGGER IF EXISTS trg_audit_no_delete ON admin.audit_log;
CREATE TRIGGER trg_audit_no_delete
  BEFORE DELETE ON admin.audit_log
  FOR EACH ROW EXECUTE FUNCTION admin.audit_reject_mutation();

-- Also block TRUNCATE, which does not fire row-level triggers.
DROP TRIGGER IF EXISTS trg_audit_no_truncate ON admin.audit_log;
CREATE TRIGGER trg_audit_no_truncate
  BEFORE TRUNCATE ON admin.audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION admin.audit_reject_mutation();

-- ---------------------------------------------------------------------------
-- Chain verification — used by the compliance export and a scheduled check.
-- Returns one row per break. An empty result means the chain is intact.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.verify_audit_chain(p_from_id BIGINT DEFAULT 0)
RETURNS TABLE (broken_at_id BIGINT, expected_hash TEXT, stored_hash TEXT, reason TEXT)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
  r          RECORD;
  v_prev     TEXT;
  v_expected TEXT;
  v_first    BOOLEAN := TRUE;
BEGIN
  FOR r IN
    SELECT * FROM admin.audit_log WHERE id >= p_from_id ORDER BY id ASC
  LOOP
    IF v_first THEN
      -- Trust the starting row's stored predecessor when resuming partway.
      v_prev := r.prev_hash;
      v_first := FALSE;
    ELSIF r.prev_hash IS DISTINCT FROM v_prev THEN
      broken_at_id := r.id;
      expected_hash := v_prev;
      stored_hash := r.prev_hash;
      reason := 'prev_hash does not match the preceding entry — a row was removed or reordered';
      RETURN NEXT;
    END IF;

    v_expected := encode(sha256(convert_to(
      admin.audit_canonical_payload(
        r.occurred_at, r.actor_admin_id, r.actor_label, r.origin,
        r.action, r.target_type, r.target_id,
        r.before_state, r.after_state, r.reason_code, r.note, r.prev_hash
      ), 'UTF8')), 'hex');

    IF v_expected IS DISTINCT FROM r.entry_hash THEN
      broken_at_id := r.id;
      expected_hash := v_expected;
      stored_hash := r.entry_hash;
      reason := 'entry_hash does not match the row content — the row was edited';
      RETURN NEXT;
    END IF;

    v_prev := r.entry_hash;
  END LOOP;

  RETURN;
END;
$$;

-- ---------------------------------------------------------------------------
-- Anomaly alerts (§7)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.alerts (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind          TEXT NOT NULL,
  severity      TEXT NOT NULL DEFAULT 'medium',
  title         TEXT NOT NULL,
  detail        TEXT NOT NULL,
  subject_admin_id UUID REFERENCES admin.admin_users(id) ON DELETE CASCADE,
  evidence      JSONB NOT NULL DEFAULT '{}'::jsonb,
  raised_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  acknowledged_at TIMESTAMPTZ,
  acknowledged_by UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  resolution    TEXT,

  CONSTRAINT alerts_severity_valid CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  CONSTRAINT alerts_kind_valid CHECK (kind IN (
    'bulk_action_out_of_hours',
    'unusual_pii_access_volume',
    'repeated_single_user_access',
    'mass_export',
    'audit_chain_broken',
    'failed_login_burst',
    'privilege_escalation_attempt',
    'shadow_restriction_applied'
  ))
);

CREATE INDEX IF NOT EXISTS idx_alerts_open
  ON admin.alerts(raised_at DESC) WHERE acknowledged_at IS NULL;

COMMENT ON TABLE admin.audit_log IS
  'Append-only, hash-chained. UPDATE/DELETE/TRUNCATE are blocked by trigger. Ship to external WORM storage for true immutability.';
