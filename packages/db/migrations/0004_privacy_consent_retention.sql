-- ============================================================================
-- 0004_privacy_consent_retention.sql — §8, built in rather than retrofitted.
--
-- The load-bearing idea: privacy guarantees that live only in application code
-- are guarantees until someone adds a second code path. So the two that matter
-- most are enforced by database triggers, where no future ingestion endpoint,
-- backfill script or well-meaning analytics job can route around them:
--
--   1. A user who declined analytics consent generates zero telemetry events.
--      admin.telemetry_events rejects the insert outright.
--   2. Telemetry never carries message content. The same trigger rejects any
--      payload containing a key that looks like message text.
--
-- Both raise rather than silently dropping, so a violating caller fails loudly
-- in development instead of quietly under-collecting in production.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Consent (§8: granular, versioned, independently revocable)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.consent_definitions (
  key            TEXT NOT NULL,
  version        INTEGER NOT NULL,
  label          TEXT NOT NULL,
  -- The exact text shown to the user, stored verbatim (§8). If the wording
  -- changes, that is a new version and previously-recorded consent does not
  -- carry over to it.
  wording        TEXT NOT NULL,
  -- Essential-only must be a genuinely available choice, so exactly one
  -- definition may be `required`.
  required       BOOLEAN NOT NULL DEFAULT FALSE,
  effective_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (key, version),

  CONSTRAINT consent_key_valid CHECK (key IN ('essential', 'analytics', 'personalisation'))
);

CREATE TABLE IF NOT EXISTS admin.consent_records (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  consent_key     TEXT NOT NULL,
  consent_version INTEGER NOT NULL,
  granted         BOOLEAN NOT NULL,
  -- Copied at record time so the audit trail survives a definition edit.
  wording_shown   TEXT NOT NULL,
  recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Where the choice was made: 'registration', 'settings', 'dsr_withdrawal'.
  source          TEXT NOT NULL DEFAULT 'registration',
  -- Coarse only. §2.4: store the derivation, never the raw IP.
  country         TEXT,
  app_version     TEXT,

  FOREIGN KEY (consent_key, consent_version)
    REFERENCES admin.consent_definitions(key, version),
  CONSTRAINT consent_country_shape CHECK (country IS NULL OR country ~ '^[A-Z]{2}$')
);

-- Append-only history; the current state is the newest row per (user, key).
CREATE INDEX IF NOT EXISTS idx_consent_current
  ON admin.consent_records(user_id, consent_key, recorded_at DESC);

CREATE OR REPLACE VIEW admin.current_consent AS
SELECT DISTINCT ON (user_id, consent_key)
       user_id, consent_key, consent_version, granted, recorded_at, wording_shown
  FROM admin.consent_records
 ORDER BY user_id, consent_key, recorded_at DESC;

CREATE OR REPLACE FUNCTION admin.has_consent(p_user UUID, p_key TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  -- Default deny: no recorded decision is not consent.
  SELECT COALESCE(
    (SELECT granted
       FROM admin.consent_records
      WHERE user_id = p_user AND consent_key = p_key
      ORDER BY recorded_at DESC
      LIMIT 1),
    FALSE);
$$;

-- ---------------------------------------------------------------------------
-- Telemetry, with consent and minimisation enforced at the storage layer
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.telemetry_events (
  id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id      UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
  event_name   TEXT NOT NULL,
  screen       TEXT,
  element      TEXT,
  platform     TEXT,
  app_version  TEXT,
  -- Coarse geography only, derived from IP at ingestion and stored as the
  -- derivation (§2.4). The raw IP is never persisted here.
  country      TEXT,
  properties   JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT telemetry_country_shape CHECK (country IS NULL OR country ~ '^[A-Z]{2}$'),
  CONSTRAINT telemetry_event_name_len CHECK (char_length(event_name) BETWEEN 1 AND 100)
);

CREATE INDEX IF NOT EXISTS idx_telemetry_name_time
  ON admin.telemetry_events(event_name, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_user
  ON admin.telemetry_events(user_id, occurred_at DESC);

-- Keys that would carry message content. Data minimisation is not a matter of
-- trusting the caller (§8: "Reject any event payload containing message bodies").
CREATE OR REPLACE FUNCTION admin.telemetry_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_forbidden TEXT[] := ARRAY[
    'message', 'message_body', 'body', 'text', 'content', 'ciphertext',
    'msg_key', 'plaintext', 'caption', 'transcript', 'email', 'phone'
  ];
  v_key TEXT;
BEGIN
  -- 1. Consent. An event with no user attached is an anonymous app-health
  --    signal and is allowed; anything attributable requires analytics consent.
  IF NEW.user_id IS NOT NULL AND NOT admin.has_consent(NEW.user_id, 'analytics') THEN
    RAISE EXCEPTION
      'Telemetry rejected: user % has not granted analytics consent.', NEW.user_id
      USING ERRCODE = 'raise_exception',
            HINT = 'Consent is checked at the storage layer; exclude this user upstream.';
  END IF;

  -- 2. Minimisation.
  FOREACH v_key IN ARRAY v_forbidden LOOP
    IF NEW.properties ? v_key THEN
      RAISE EXCEPTION
        'Telemetry rejected: property "%" may carry message content or PII.', v_key
        USING ERRCODE = 'raise_exception';
    END IF;
  END LOOP;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_telemetry_guard ON admin.telemetry_events;
CREATE TRIGGER trg_telemetry_guard
  BEFORE INSERT ON admin.telemetry_events
  FOR EACH ROW EXECUTE FUNCTION admin.telemetry_guard();

-- ---------------------------------------------------------------------------
-- Retention policy engine (§8)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.retention_policies (
  data_class   TEXT PRIMARY KEY,
  ttl_days     INTEGER,
  description  TEXT NOT NULL,
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  -- Purging is refused below this floor so a mis-set TTL cannot destroy
  -- evidence that an open appeal still depends on.
  min_ttl_days INTEGER NOT NULL DEFAULT 0,
  last_purge_at TIMESTAMPTZ,
  last_purge_rows BIGINT,
  updated_by   UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT retention_ttl_positive CHECK (ttl_days IS NULL OR ttl_days > 0),
  CONSTRAINT retention_ttl_above_floor
    CHECK (ttl_days IS NULL OR ttl_days >= min_ttl_days)
);

-- ---------------------------------------------------------------------------
-- Legal hold (§8) — suspends automatic deletion for records under investigation
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.legal_holds (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_type TEXT NOT NULL,
  subject_id   TEXT NOT NULL,
  reference    TEXT NOT NULL,
  reason       TEXT NOT NULL,
  placed_by    UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  placed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  released_by  UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  released_at  TIMESTAMPTZ,
  release_note TEXT,

  CONSTRAINT legal_hold_subject_valid
    CHECK (subject_type IN ('user', 'channel', 'case', 'message', 'ticket')),
  CONSTRAINT legal_hold_release_documented
    CHECK (released_at IS NULL OR release_note IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_legal_holds_active
  ON admin.legal_holds(subject_type, subject_id) WHERE released_at IS NULL;

CREATE OR REPLACE FUNCTION admin.is_under_legal_hold(p_type TEXT, p_id TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM admin.legal_holds
     WHERE subject_type = p_type AND subject_id = p_id AND released_at IS NULL
  );
$$;

-- ---------------------------------------------------------------------------
-- Data subject rights (§8) — export, correction, erasure, with a tracked SLA
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.dsr_requests (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  kind           TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'received',
  received_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Statutory clocks are jurisdiction-specific; the default is set from config.
  sla_due_at     TIMESTAMPTZ NOT NULL,
  completed_at   TIMESTAMPTZ,
  handled_by     UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  -- How the requester proved they are the account holder. Fulfilling an
  -- unverified erasure request is itself a data breach.
  verification   TEXT,
  request_note   TEXT,
  resolution_note TEXT,
  -- Short-lived signed object key for the export package, never a public URL.
  export_object_key TEXT,
  export_expires_at TIMESTAMPTZ,

  CONSTRAINT dsr_kind_valid
    CHECK (kind IN ('export', 'correction', 'erasure', 'restriction', 'objection', 'portability')),
  CONSTRAINT dsr_status_valid
    CHECK (status IN ('received', 'verifying', 'in_progress', 'completed', 'rejected', 'on_hold')),
  CONSTRAINT dsr_completion_documented
    CHECK (status NOT IN ('completed', 'rejected') OR resolution_note IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_dsr_open
  ON admin.dsr_requests(sla_due_at) WHERE status NOT IN ('completed', 'rejected');
CREATE INDEX IF NOT EXISTS idx_dsr_user ON admin.dsr_requests(user_id, received_at DESC);

-- An erasure request must not proceed while a legal hold is in force.
CREATE OR REPLACE FUNCTION admin.dsr_respect_legal_hold()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
BEGIN
  IF NEW.kind = 'erasure' AND NEW.status = 'completed'
     AND admin.is_under_legal_hold('user', NEW.user_id::text) THEN
    RAISE EXCEPTION
      'Erasure cannot complete: user % is under an active legal hold.', NEW.user_id
      USING ERRCODE = 'raise_exception',
            HINT = 'Release the hold, or record the request as on_hold with the legal reference.';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_dsr_legal_hold ON admin.dsr_requests;
CREATE TRIGGER trg_dsr_legal_hold
  BEFORE INSERT OR UPDATE ON admin.dsr_requests
  FOR EACH ROW EXECUTE FUNCTION admin.dsr_respect_legal_hold();

-- ---------------------------------------------------------------------------
-- Jurisdictional configuration (§8) — geo-block rather than global delete
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.jurisdiction_rules (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  country      TEXT NOT NULL,
  regime       TEXT NOT NULL,
  description  TEXT NOT NULL,
  -- 'geo_block' removes locally only; 'global_remove' is reserved for content
  -- violating the platform's own policy everywhere.
  default_remedy TEXT NOT NULL DEFAULT 'geo_block',
  active       BOOLEAN NOT NULL DEFAULT TRUE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT jurisdiction_country_shape CHECK (country ~ '^[A-Z]{2}$'),
  CONSTRAINT jurisdiction_remedy_valid
    CHECK (default_remedy IN ('geo_block', 'global_remove', 'age_gate', 'delist'))
);

CREATE TABLE IF NOT EXISTS admin.geo_restrictions (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_type TEXT NOT NULL,
  subject_id   TEXT NOT NULL,
  country      TEXT NOT NULL,
  reason       TEXT NOT NULL,
  legal_basis  TEXT,
  applied_by   UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  lifted_at    TIMESTAMPTZ,

  CONSTRAINT geo_subject_valid CHECK (subject_type IN ('channel', 'post', 'user')),
  CONSTRAINT geo_country_shape CHECK (country ~ '^[A-Z]{2}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_geo_restriction_unique
  ON admin.geo_restrictions(subject_type, subject_id, country)
  WHERE lifted_at IS NULL;
