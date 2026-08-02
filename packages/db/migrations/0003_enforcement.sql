-- ============================================================================
-- 0003_enforcement.sql — the §3.3 action ladder, appeals, and admin messaging.
--
-- Correctness note that drives the whole design:
--
--   Whether a user is currently blocked is a *time-dependent* question. A
--   projection table can always be stale by however long it has been since the
--   worker last ran, and a stale projection either lets a banned user keep
--   sending or keeps a user locked out past their expiry. Both are unacceptable.
--
--   So there are two representations, with different jobs:
--     - admin.enforcement_actions is the source of truth. Every access-control
--       decision (RLS, the app's status endpoint) reads it live through an
--       indexed EXISTS that evaluates expiry against NOW(). Never stale.
--     - admin.user_restriction_state is a denormalised projection used *only*
--       to sort and filter the console's user directory, where being a few
--       seconds behind costs nothing.
--
--   Nothing security-relevant reads the projection.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Human-facing case references: NO-2026-000123
-- ---------------------------------------------------------------------------
CREATE SEQUENCE IF NOT EXISTS admin.case_ref_seq;

CREATE OR REPLACE FUNCTION admin.next_case_ref()
RETURNS TEXT
LANGUAGE sql
VOLATILE
AS $$
  SELECT 'NO-' || to_char(NOW(), 'YYYY') || '-' ||
         lpad(nextval('admin.case_ref_seq')::text, 6, '0');
$$;

-- ---------------------------------------------------------------------------
-- Enforcement actions
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.enforcement_actions (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Cascades on purge: §8's erasure requirement means erasure. Aggregate
  -- transparency counts are kept separately (admin.transparency_counters) so
  -- deleting a user never silently rewrites published statistics.
  user_id                UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,

  type                   TEXT NOT NULL,
  reason_code            TEXT NOT NULL,
  -- §3.3: mandatory free-text note alongside the structured reason. Read by the
  -- appeal reviewer; never shown to the user.
  note                   TEXT NOT NULL,
  case_ref               TEXT NOT NULL DEFAULT admin.next_case_ref(),

  issued_by              UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  issued_by_label        TEXT NOT NULL,
  issued_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- NULL = no expiry. Required for mute/shadow/temp ban, forbidden elsewhere.
  expires_at             TIMESTAMPTZ,

  restricted_features    TEXT[],
  rate_limit_per_minute  INTEGER,

  -- Reversal (§3.3: "reversible with a documented reason").
  reversed_at            TIMESTAMPTZ,
  reversed_by            UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  reversal_reason        TEXT,
  -- Set when the expiry worker lifted it rather than a human.
  auto_lifted            BOOLEAN NOT NULL DEFAULT FALSE,

  -- §4: content removal is an explicit, separate choice with its own scope.
  content_removal_scope  TEXT NOT NULL DEFAULT 'none',

  origin                 TEXT NOT NULL DEFAULT 'manual',
  automod_rule_id        UUID,
  break_glass_request_id UUID REFERENCES admin.break_glass_requests(id) ON DELETE SET NULL,

  -- User notification bookkeeping (§3.3 "notify the user on expiry").
  notified_at            TIMESTAMPTZ,
  expiry_notified_at     TIMESTAMPTZ,
  -- Warnings must be acknowledged by the user before the notice clears.
  acknowledged_at        TIMESTAMPTZ,

  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT enforcement_type_valid CHECK (type IN (
    'note', 'warning', 'feature_restriction', 'rate_limit', 'mute',
    'shadow_restriction', 'ban_temporary', 'ban_permanent', 'account_deletion')),
  CONSTRAINT enforcement_origin_valid CHECK (origin IN ('manual', 'automated')),
  CONSTRAINT enforcement_removal_scope_valid
    CHECK (content_removal_scope IN ('none', 'last_24h', 'last_30d', 'all')),
  CONSTRAINT enforcement_note_len CHECK (char_length(note) >= 10),
  CONSTRAINT enforcement_rate_limit_range
    CHECK (rate_limit_per_minute IS NULL OR rate_limit_per_minute BETWEEN 1 AND 600),
  CONSTRAINT enforcement_reversal_documented
    CHECK (reversed_at IS NULL OR reversal_reason IS NOT NULL),

  -- Expiry semantics matched to the ladder, enforced by the database so a bug
  -- in one API path cannot create a mute that never ends.
  CONSTRAINT enforcement_expiry_required
    CHECK (type NOT IN ('mute', 'shadow_restriction', 'ban_temporary') OR expires_at IS NOT NULL),
  CONSTRAINT enforcement_expiry_forbidden
    CHECK (type NOT IN ('note', 'warning', 'ban_permanent', 'account_deletion')
           OR expires_at IS NULL),

  -- §6.6 hard rule: automation may restrict or queue, never terminally ban.
  CONSTRAINT enforcement_no_automated_terminal_action
    CHECK (origin <> 'automated'
           OR type NOT IN ('ban_permanent', 'account_deletion'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_enforcement_case_ref
  ON admin.enforcement_actions(case_ref);

-- The index the live access-control check rides on. Partial on the "still in
-- force" predicate so the EXISTS below touches only live rows.
CREATE INDEX IF NOT EXISTS idx_enforcement_live
  ON admin.enforcement_actions(user_id, type)
  WHERE reversed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_enforcement_user_history
  ON admin.enforcement_actions(user_id, issued_at DESC);

-- Drives the expiry worker: only unreversed, unexpired-notification rows.
CREATE INDEX IF NOT EXISTS idx_enforcement_pending_expiry
  ON admin.enforcement_actions(expires_at)
  WHERE reversed_at IS NULL AND expires_at IS NOT NULL AND expiry_notified_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_enforcement_issued_by
  ON admin.enforcement_actions(issued_by, issued_at DESC);

-- ---------------------------------------------------------------------------
-- The single live predicate. Everything that gates a user reads this.
-- ---------------------------------------------------------------------------

-- Types that block the app entirely (the §4 ban screen).
CREATE OR REPLACE FUNCTION admin.is_access_blocked(p_user UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM admin.enforcement_actions
     WHERE user_id = p_user
       AND reversed_at IS NULL
       AND type IN ('ban_temporary', 'ban_permanent', 'account_deletion')
       AND (expires_at IS NULL OR expires_at > NOW())
  );
$$;

-- Types that prevent sending while still allowing receipt.
CREATE OR REPLACE FUNCTION admin.is_send_blocked(p_user UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM admin.enforcement_actions
     WHERE user_id = p_user
       AND reversed_at IS NULL
       AND type IN ('mute', 'ban_temporary', 'ban_permanent', 'account_deletion')
       AND (expires_at IS NULL OR expires_at > NOW())
  );
$$;

CREATE OR REPLACE FUNCTION admin.is_feature_restricted(p_user UUID, p_feature TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM admin.enforcement_actions
     WHERE user_id = p_user
       AND reversed_at IS NULL
       AND type = 'feature_restriction'
       AND (expires_at IS NULL OR expires_at > NOW())
       AND restricted_features @> ARRAY[p_feature]
  );
$$;

-- ---------------------------------------------------------------------------
-- Projection for the console's user directory (never for access control).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.user_restriction_state (
  user_id               UUID PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
  status                TEXT NOT NULL DEFAULT 'active',
  blocks_access         BOOLEAN NOT NULL DEFAULT FALSE,
  blocks_sending        BOOLEAN NOT NULL DEFAULT FALSE,
  shadow_restricted     BOOLEAN NOT NULL DEFAULT FALSE,
  restricted_features   TEXT[] NOT NULL DEFAULT '{}',
  rate_limit_per_minute INTEGER,
  governing_action_id   UUID REFERENCES admin.enforcement_actions(id) ON DELETE SET NULL,
  next_expiry_at        TIMESTAMPTZ,
  active_action_count   INTEGER NOT NULL DEFAULT 0,
  recomputed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT restriction_status_valid CHECK (status IN (
    'active', 'warned', 'restricted', 'muted', 'shadow_restricted',
    'banned_temporary', 'banned_permanent', 'deleted'))
);

CREATE INDEX IF NOT EXISTS idx_restriction_status ON admin.user_restriction_state(status);
CREATE INDEX IF NOT EXISTS idx_restriction_next_expiry
  ON admin.user_restriction_state(next_expiry_at) WHERE next_expiry_at IS NOT NULL;

-- Mirrors deriveUserState() in packages/shared/src/enforcement.ts. A test seeds
-- identical action sets through both and asserts they agree, because two
-- implementations of the same fold is exactly the kind of thing that drifts.
CREATE OR REPLACE FUNCTION admin.recompute_user_restrictions(p_user UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_status     TEXT := 'active';
  v_access     BOOLEAN := FALSE;
  v_sending    BOOLEAN := FALSE;
  v_shadow     BOOLEAN := FALSE;
  v_features   TEXT[] := '{}';
  v_rate       INTEGER;
  v_governing  UUID;
  v_next       TIMESTAMPTZ;
  v_count      INTEGER := 0;
  r            RECORD;
BEGIN
  FOR r IN
    SELECT *,
           CASE type
             WHEN 'note' THEN 0 WHEN 'warning' THEN 10
             WHEN 'feature_restriction' THEN 20 WHEN 'rate_limit' THEN 30
             WHEN 'mute' THEN 40 WHEN 'shadow_restriction' THEN 50
             WHEN 'ban_temporary' THEN 60 WHEN 'ban_permanent' THEN 70
             WHEN 'account_deletion' THEN 100
           END AS severity
      FROM admin.enforcement_actions
     WHERE user_id = p_user
       AND reversed_at IS NULL
       AND (expires_at IS NULL OR expires_at > NOW())
     ORDER BY severity DESC, issued_at DESC
  LOOP
    v_count := v_count + 1;

    IF r.type IN ('ban_temporary', 'ban_permanent', 'account_deletion') THEN
      v_access := TRUE;
      v_sending := TRUE;
    ELSIF r.type = 'mute' THEN
      v_sending := TRUE;
    ELSIF r.type = 'shadow_restriction' THEN
      v_shadow := TRUE;
    END IF;

    IF r.restricted_features IS NOT NULL THEN
      SELECT ARRAY(SELECT DISTINCT unnest(v_features || r.restricted_features)) INTO v_features;
    END IF;

    IF r.rate_limit_per_minute IS NOT NULL THEN
      v_rate := LEAST(COALESCE(v_rate, r.rate_limit_per_minute), r.rate_limit_per_minute);
    END IF;

    IF r.expires_at IS NOT NULL AND (v_next IS NULL OR r.expires_at < v_next) THEN
      v_next := r.expires_at;
    END IF;

    -- First non-note row wins, matching the TypeScript fold.
    IF v_governing IS NULL AND r.type <> 'note' THEN
      v_governing := r.id;
      v_status := CASE r.type
        WHEN 'warning' THEN 'warned'
        WHEN 'feature_restriction' THEN 'restricted'
        WHEN 'rate_limit' THEN 'restricted'
        WHEN 'mute' THEN 'muted'
        WHEN 'shadow_restriction' THEN 'shadow_restricted'
        WHEN 'ban_temporary' THEN 'banned_temporary'
        WHEN 'ban_permanent' THEN 'banned_permanent'
        WHEN 'account_deletion' THEN 'deleted'
      END;
    END IF;
  END LOOP;

  INSERT INTO admin.user_restriction_state AS s (
    user_id, status, blocks_access, blocks_sending, shadow_restricted,
    restricted_features, rate_limit_per_minute, governing_action_id,
    next_expiry_at, active_action_count, recomputed_at)
  VALUES (
    p_user, v_status, v_access, v_sending, v_shadow,
    COALESCE(v_features, '{}'), v_rate, v_governing,
    v_next, v_count, NOW())
  ON CONFLICT (user_id) DO UPDATE SET
    status = EXCLUDED.status,
    blocks_access = EXCLUDED.blocks_access,
    blocks_sending = EXCLUDED.blocks_sending,
    shadow_restricted = EXCLUDED.shadow_restricted,
    restricted_features = EXCLUDED.restricted_features,
    rate_limit_per_minute = EXCLUDED.rate_limit_per_minute,
    governing_action_id = EXCLUDED.governing_action_id,
    next_expiry_at = EXCLUDED.next_expiry_at,
    active_action_count = EXCLUDED.active_action_count,
    recomputed_at = NOW();
END;
$$;

CREATE OR REPLACE FUNCTION admin.enforcement_touch_projection()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM admin.recompute_user_restrictions(COALESCE(NEW.user_id, OLD.user_id));
  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_enforcement_projection ON admin.enforcement_actions;
CREATE TRIGGER trg_enforcement_projection
  AFTER INSERT OR UPDATE OR DELETE ON admin.enforcement_actions
  FOR EACH ROW EXECUTE FUNCTION admin.enforcement_touch_projection();

-- ---------------------------------------------------------------------------
-- Appeals (§4)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.appeals (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action_id       UUID NOT NULL REFERENCES admin.enforcement_actions(id) ON DELETE CASCADE,
  user_id         UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,

  body            TEXT NOT NULL,
  submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  locale          TEXT NOT NULL DEFAULT 'en',

  status          TEXT NOT NULL DEFAULT 'pending',

  -- §4: "must be reviewed by someone other than the moderator who issued the
  -- original action". Enforced by trigger below, not merely by convention.
  reviewed_by     UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  reviewed_at     TIMESTAMPTZ,
  decision_note   TEXT,

  -- SLA target and auto-escalation (§4).
  sla_due_at      TIMESTAMPTZ NOT NULL,
  escalated_at    TIMESTAMPTZ,

  CONSTRAINT appeals_status_valid CHECK (status IN (
    'pending', 'under_review', 'upheld', 'overturned', 'partially_upheld', 'withdrawn')),
  CONSTRAINT appeals_body_len CHECK (char_length(body) BETWEEN 1 AND 5000),
  CONSTRAINT appeals_decision_documented
    CHECK (status IN ('pending', 'under_review', 'withdrawn')
           OR (reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL AND decision_note IS NOT NULL))
);

-- One appeal per action. A second bite is a reopen, not a new appeal.
CREATE UNIQUE INDEX IF NOT EXISTS idx_appeals_one_per_action ON admin.appeals(action_id);
CREATE INDEX IF NOT EXISTS idx_appeals_queue
  ON admin.appeals(status, sla_due_at) WHERE status IN ('pending', 'under_review');
CREATE INDEX IF NOT EXISTS idx_appeals_user ON admin.appeals(user_id, submitted_at DESC);

CREATE OR REPLACE FUNCTION admin.enforce_appeal_reviewer_independence()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_issuer UUID;
BEGIN
  IF NEW.reviewed_by IS NULL THEN
    RETURN NEW;
  END IF;

  SELECT issued_by INTO v_issuer
    FROM admin.enforcement_actions
   WHERE id = NEW.action_id;

  IF v_issuer IS NOT NULL AND v_issuer = NEW.reviewed_by THEN
    RAISE EXCEPTION
      'An appeal cannot be reviewed by the admin who issued the original action.'
      USING ERRCODE = 'raise_exception',
            HINT = 'Reassign this appeal to another reviewer.';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_appeal_reviewer_independence ON admin.appeals;
CREATE TRIGGER trg_appeal_reviewer_independence
  BEFORE INSERT OR UPDATE ON admin.appeals
  FOR EACH ROW EXECUTE FUNCTION admin.enforce_appeal_reviewer_independence();

-- ---------------------------------------------------------------------------
-- Admin -> user messaging (§3.4)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.admin_messages (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  sent_by       UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  sent_by_label TEXT NOT NULL,
  -- Plaintext by necessity: this is sent *from* the platform, so there is no
  -- ECDH pair to encrypt under. Users are told these come from @admin.
  body          TEXT NOT NULL,
  template_key  TEXT,
  locale        TEXT NOT NULL DEFAULT 'en',
  related_action_id UUID REFERENCES admin.enforcement_actions(id) ON DELETE SET NULL,
  sent_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  delivered_at  TIMESTAMPTZ,
  read_at       TIMESTAMPTZ,

  CONSTRAINT admin_messages_body_len CHECK (char_length(body) BETWEEN 1 AND 4000)
);

CREATE INDEX IF NOT EXISTS idx_admin_messages_user
  ON admin.admin_messages(user_id, sent_at DESC);

-- ---------------------------------------------------------------------------
-- Transparency counters (§8)
--
-- Incremented at write time so published aggregate statistics survive an
-- erasure request that removes the underlying rows.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.transparency_counters (
  period        DATE NOT NULL,
  metric        TEXT NOT NULL,
  dimension     TEXT NOT NULL DEFAULT '',
  count         BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (period, metric, dimension)
);

CREATE OR REPLACE FUNCTION admin.bump_transparency_counter(
  p_metric TEXT, p_dimension TEXT DEFAULT '', p_at TIMESTAMPTZ DEFAULT NOW())
RETURNS VOID
LANGUAGE sql
AS $$
  INSERT INTO admin.transparency_counters (period, metric, dimension, count)
  VALUES (date_trunc('month', p_at)::date, p_metric, p_dimension, 1)
  ON CONFLICT (period, metric, dimension)
  DO UPDATE SET count = admin.transparency_counters.count + 1;
$$;

CREATE OR REPLACE FUNCTION admin.enforcement_bump_counters()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM admin.bump_transparency_counter('enforcement_action', NEW.type, NEW.issued_at);
  PERFORM admin.bump_transparency_counter('enforcement_by_reason', NEW.reason_code, NEW.issued_at);
  IF NEW.origin = 'automated' THEN
    PERFORM admin.bump_transparency_counter('enforcement_automated', NEW.type, NEW.issued_at);
  END IF;
  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_enforcement_counters ON admin.enforcement_actions;
CREATE TRIGGER trg_enforcement_counters
  AFTER INSERT ON admin.enforcement_actions
  FOR EACH ROW EXECUTE FUNCTION admin.enforcement_bump_counters();
