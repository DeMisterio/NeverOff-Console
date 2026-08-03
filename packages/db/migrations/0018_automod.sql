-- ============================================================================
-- 0018_automod.sql — the §6.6 automated detection engine.
--
-- WHAT THE ENCRYPTION RULES OUT
--
-- §6.6 lists "keyword and regex lists (per language)" and "identical-content
-- fan-out across conversations" among the signals. Neither is available for
-- private messages, and it is worth being precise about why rather than
-- shipping a rule type that silently never fires:
--
--   - Keyword/regex needs plaintext. The server has ciphertext.
--   - Identical-content fan-out needs to recognise the same message sent to
--     many people. Under ECDH each conversation has its own shared secret and
--     each message its own random salt, so the same sentence sent to twenty
--     people produces twenty unrelated ciphertexts. There is no fingerprint to
--     match on. Not "hard" — absent.
--
-- Content rules therefore apply ONLY to surfaces that are plaintext by design:
-- channel posts, profile fields, channel metadata. A rule's `surface` column
-- makes that explicit, and a CHECK stops anyone creating a content rule scoped
-- to private messages — a rule that can never fire is worse than no rule,
-- because it looks like coverage.
--
-- What IS available for private messages is behaviour: velocity, breadth of
-- fan-out, account age against recipient count, burst shape. Those catch the
-- spam-ring and mass-DM patterns §6.6 cares most about, and they catch them
-- without reading anything.
--
-- THE HARD RULE
--
-- "No fully automated permanent bans." Already enforced by a CHECK constraint
-- on admin.enforcement_actions since 0003 — an insert with origin='automated'
-- and type in (ban_permanent, account_deletion) is rejected by the database.
-- This migration adds the same guard at the rule level so it is refused when
-- the rule is *written*, not when it first fires at 3am.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Rules
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.automod_rules (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           TEXT NOT NULL,
  description    TEXT,

  -- §6.6: "every rule having a shadow/monitor mode so you can measure its
  -- false-positive rate before enabling enforcement". New rules start in
  -- shadow and the API refuses to create one directly in enforce.
  mode           TEXT NOT NULL DEFAULT 'shadow',

  -- Which surface the rule reads. Content rules cannot name 'direct_message'.
  surface        TEXT NOT NULL,
  signal         TEXT NOT NULL,

  -- Signal parameters: thresholds, patterns, window sizes.
  config         JSONB NOT NULL DEFAULT '{}'::jsonb,

  action         TEXT NOT NULL,
  action_config  JSONB NOT NULL DEFAULT '{}'::jsonb,
  reason_code    TEXT REFERENCES admin.reason_catalogue(code),

  created_by     UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Set when a rule is promoted out of shadow, so "how long was this measured
  -- before we trusted it" is answerable.
  enforcing_since TIMESTAMPTZ,

  CONSTRAINT automod_mode_valid CHECK (mode IN ('disabled', 'shadow', 'enforce')),
  CONSTRAINT automod_surface_valid
    CHECK (surface IN ('direct_message', 'channel_post', 'profile', 'account')),
  CONSTRAINT automod_signal_valid CHECK (signal IN (
    -- Metadata signals, available on every surface including encrypted ones.
    'message_velocity',        -- messages per minute from one sender
    'conversation_fanout',     -- distinct conversations opened in a window
    'new_account_mass_dm',     -- account age vs distinct recipients
    'channel_join_burst',      -- mass-join behaviour
    -- Content signals, plaintext surfaces only.
    'keyword_match',
    'regex_match',
    'link_domain',
    'media_hash')),
  CONSTRAINT automod_action_valid CHECK (action IN (
    'flag_for_review',   -- opens a case; the default and the safest
    'auto_hide',         -- hides pending review
    'rate_limit',
    'notify_moderators',
    'auto_escalate')),
  CONSTRAINT automod_name_len CHECK (char_length(name) BETWEEN 3 AND 120),

  -- Content signals need plaintext. Scoping one to private messages would
  -- create a rule that can never fire, which reads as coverage and is not.
  CONSTRAINT automod_content_needs_plaintext
    CHECK (signal NOT IN ('keyword_match', 'regex_match', 'link_domain', 'media_hash')
           OR surface <> 'direct_message'),

  -- §6.6 hard rule, refused at authoring time as well as at execution time.
  -- The action list above already excludes bans; this makes the intent
  -- explicit so a future migration that widens the list has to confront it.
  CONSTRAINT automod_no_terminal_actions
    CHECK (action NOT IN ('ban_permanent', 'account_deletion', 'ban_temporary'))
);

CREATE INDEX IF NOT EXISTS idx_automod_active
  ON admin.automod_rules(mode, signal) WHERE mode <> 'disabled';

DROP TRIGGER IF EXISTS trg_automod_updated_at ON admin.automod_rules;
CREATE TRIGGER trg_automod_updated_at
  BEFORE UPDATE ON admin.automod_rules
  FOR EACH ROW EXECUTE FUNCTION admin.touch_updated_at();

-- ---------------------------------------------------------------------------
-- Firings
--
-- Every evaluation that matched is recorded, in shadow mode as well as enforce.
-- Shadow firings are the entire measurement: a rule's false-positive rate is
-- the proportion of its shadow firings a human later judged harmless, and
-- without the rows there is nothing to judge.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.automod_firings (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id        UUID NOT NULL REFERENCES admin.automod_rules(id) ON DELETE CASCADE,
  fired_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- What matched.
  subject_type   TEXT NOT NULL,
  subject_id     TEXT NOT NULL,
  subject_user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,

  -- §6.6: "explainable (rule X fired on signal Y)". The observed values that
  -- crossed the threshold, kept verbatim so the explanation survives a later
  -- change to the rule's config.
  signals        JSONB NOT NULL DEFAULT '{}'::jsonb,

  mode_at_firing TEXT NOT NULL,
  -- Populated only when mode was 'enforce'. In shadow the rule records what it
  -- WOULD have done and does nothing.
  action_taken   TEXT,
  case_id        UUID REFERENCES admin.cases(id) ON DELETE SET NULL,
  enforcement_action_id UUID REFERENCES admin.enforcement_actions(id) ON DELETE SET NULL,

  -- Filled in by a human later. This is what turns firings into precision.
  review_outcome TEXT,
  reviewed_by    UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  reviewed_at    TIMESTAMPTZ,

  CONSTRAINT firing_mode_valid CHECK (mode_at_firing IN ('shadow', 'enforce')),
  CONSTRAINT firing_outcome_valid
    CHECK (review_outcome IS NULL OR review_outcome IN
           ('true_positive', 'false_positive', 'unclear')),
  -- A shadow firing must never carry an action. If it does, the shadow mode
  -- is not shadow and the measurement is worthless.
  CONSTRAINT firing_shadow_takes_no_action
    CHECK (mode_at_firing <> 'shadow'
           OR (action_taken IS NULL AND enforcement_action_id IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_firings_rule ON admin.automod_firings(rule_id, fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_firings_unreviewed
  ON admin.automod_firings(fired_at DESC) WHERE review_outcome IS NULL;
CREATE INDEX IF NOT EXISTS idx_firings_subject
  ON admin.automod_firings(subject_user_id, fired_at DESC);

-- ---------------------------------------------------------------------------
-- Blocklists (§6.6 signals)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.automod_blocklist (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind        TEXT NOT NULL,
  value       TEXT NOT NULL,
  locale      TEXT,
  note        TEXT,
  added_by    UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  active      BOOLEAN NOT NULL DEFAULT TRUE,

  CONSTRAINT blocklist_kind_valid CHECK (kind IN ('domain', 'keyword', 'media_sha256'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_blocklist_unique
  ON admin.automod_blocklist(kind, lower(value)) WHERE active;

-- ---------------------------------------------------------------------------
-- Behavioural signal evaluation.
--
-- Metadata only. None of this reads message content, and none of it could.
-- ---------------------------------------------------------------------------

/** Messages per minute from one sender over a window. */
CREATE OR REPLACE FUNCTION admin.signal_message_velocity(p_user UUID, p_window_minutes INTEGER)
RETURNS NUMERIC
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT COALESCE(count(*)::numeric / GREATEST(p_window_minutes, 1), 0)
    FROM public.messages
   WHERE sender_id = p_user
     AND created_at > NOW() - make_interval(mins => p_window_minutes);
$$;

/** Distinct conversations a sender has messaged in a window. */
CREATE OR REPLACE FUNCTION admin.signal_conversation_fanout(p_user UUID, p_window_minutes INTEGER)
RETURNS BIGINT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT COALESCE(count(DISTINCT chat_id), 0)
    FROM public.messages
   WHERE sender_id = p_user
     AND created_at > NOW() - make_interval(mins => p_window_minutes);
$$;

/**
 * The classic spam-ring shape: a young account messaging many strangers fast.
 *
 * Returns the observed values rather than a boolean so the firing row can carry
 * the numbers that crossed the line — §6.6's "explainable" requirement means a
 * moderator seeing this should be able to tell WHY without rerunning anything.
 */
CREATE OR REPLACE FUNCTION admin.signal_new_account_mass_dm(p_user UUID, p_window_minutes INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_age_hours   NUMERIC;
  v_recipients  BIGINT;
  v_messages    BIGINT;
BEGIN
  SELECT EXTRACT(EPOCH FROM (NOW() - created_at)) / 3600 INTO v_age_hours
    FROM public.profiles WHERE id = p_user;

  SELECT count(DISTINCT cp.user_id), count(*)
    INTO v_recipients, v_messages
    FROM public.messages m
    JOIN public.chat_participants cp ON cp.chat_id = m.chat_id AND cp.user_id <> p_user
   WHERE m.sender_id = p_user
     AND m.created_at > NOW() - make_interval(mins => p_window_minutes);

  RETURN jsonb_build_object(
    'account_age_hours', round(COALESCE(v_age_hours, 0), 1),
    'distinct_recipients', COALESCE(v_recipients, 0),
    'messages_sent', COALESCE(v_messages, 0),
    'window_minutes', p_window_minutes);
END;
$$;

/** Channel posts matching a blocklisted domain. Plaintext surface only. */
CREATE OR REPLACE FUNCTION admin.signal_blocklisted_domain(p_post_id UUID)
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT b.value
    FROM public.channel_posts p
    JOIN admin.automod_blocklist b
      ON b.kind = 'domain' AND b.active
     AND position(lower(b.value) IN lower(p.content)) > 0
   WHERE p.id = p_post_id
   LIMIT 1;
$$;

-- ---------------------------------------------------------------------------
-- Rule quality (§6.6: "precision/recall per rule, drift alerts, and a sampled
-- human audit of automated decisions")
--
-- Recall is deliberately absent. Recall needs a known ground truth of
-- everything the rule SHOULD have caught, and that does not exist — the misses
-- are, by definition, the things nobody flagged. Reporting a made-up recall
-- figure would be worse than reporting none. What is measurable is precision
-- against reviewed firings, and the review coverage that precision rests on.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.automod_rule_quality(p_days INTEGER DEFAULT 30)
RETURNS TABLE (
  rule_id          UUID,
  rule_name        TEXT,
  mode             TEXT,
  firings          BIGINT,
  reviewed         BIGINT,
  true_positives   BIGINT,
  false_positives  BIGINT,
  precision_pct    NUMERIC,
  review_coverage  NUMERIC,
  ready_to_enforce BOOLEAN
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT r.id,
         r.name,
         r.mode,
         count(f.id),
         count(f.id) FILTER (WHERE f.review_outcome IS NOT NULL),
         count(f.id) FILTER (WHERE f.review_outcome = 'true_positive'),
         count(f.id) FILTER (WHERE f.review_outcome = 'false_positive'),
         round(100.0 * count(f.id) FILTER (WHERE f.review_outcome = 'true_positive')
               / NULLIF(count(f.id) FILTER (WHERE f.review_outcome IN
                        ('true_positive','false_positive')), 0), 1),
         round(100.0 * count(f.id) FILTER (WHERE f.review_outcome IS NOT NULL)
               / NULLIF(count(f.id), 0), 1),
         -- A rule is only proposed for promotion once it has fired enough to
         -- mean something, been reviewed enough to trust the number, and kept
         -- precision high. These are floors, not a recommendation: a human
         -- still decides, and the console says so.
         (r.mode = 'shadow'
          AND count(f.id) >= 30
          AND count(f.id) FILTER (WHERE f.review_outcome IS NOT NULL) >= 20
          AND COALESCE(100.0 * count(f.id) FILTER (WHERE f.review_outcome = 'true_positive')
              / NULLIF(count(f.id) FILTER (WHERE f.review_outcome IN
                       ('true_positive','false_positive')), 0), 0) >= 95)
    FROM admin.automod_rules r
    LEFT JOIN admin.automod_firings f
           ON f.rule_id = r.id AND f.fired_at > NOW() - make_interval(days => p_days)
   GROUP BY r.id, r.name, r.mode
   ORDER BY count(f.id) DESC;
$$;

/**
 * Drift: a rule whose firing rate has changed sharply against its own recent
 * baseline. Compares the last day to the median of the fortnight before it,
 * the same shape as the channel growth check and for the same reason — a
 * global threshold would flag every busy rule and nothing else.
 */
CREATE OR REPLACE FUNCTION admin.detect_automod_drift()
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
    WITH daily AS (
      SELECT rule_id, fired_at::date AS day, count(*) AS firings
        FROM admin.automod_firings
       WHERE fired_at > NOW() - INTERVAL '15 days'
       GROUP BY rule_id, fired_at::date
    ),
    baseline AS (
      SELECT rule_id, percentile_cont(0.5) WITHIN GROUP (ORDER BY firings) AS median
        FROM daily WHERE day < CURRENT_DATE
       GROUP BY rule_id HAVING count(*) >= 5
    )
    SELECT d.rule_id, d.firings, b.median, ru.name, ru.mode
      FROM daily d
      JOIN baseline b ON b.rule_id = d.rule_id
      JOIN admin.automod_rules ru ON ru.id = d.rule_id
     WHERE d.day = CURRENT_DATE
       AND (d.firings > GREATEST(b.median * 5, 25) OR d.firings < b.median / 5)
  LOOP
    INSERT INTO admin.alerts (kind, severity, title, detail, evidence)
    SELECT 'automod_drift',
           CASE WHEN r.mode = 'enforce' THEN 'high' ELSE 'medium' END,
           'Rule "' || r.name || '" fired ' || r.firings || ' times today',
           'Its median is ' || round(r.median, 1) || '. A sharp change usually means the '
             || 'traffic changed, not the rule — but an enforcing rule firing five times its '
             || 'baseline is worth looking at before it actions another few hundred people.',
           jsonb_build_object('rule_id', r.rule_id, 'today', r.firings, 'median', r.median)
     WHERE NOT EXISTS (
       SELECT 1 FROM admin.alerts
        WHERE kind = 'automod_drift' AND acknowledged_at IS NULL
          AND evidence->>'rule_id' = r.rule_id::text);

    v_count := v_count + 1;
  END LOOP;

  RETURN v_count;
END;
$$;

ALTER TABLE admin.alerts DROP CONSTRAINT IF EXISTS alerts_kind_valid;
ALTER TABLE admin.alerts ADD CONSTRAINT alerts_kind_valid CHECK (kind IN (
  'bulk_action_out_of_hours', 'unusual_pii_access_volume', 'repeated_single_user_access',
  'mass_export', 'audit_chain_broken', 'failed_login_burst', 'privilege_escalation_attempt',
  'shadow_restriction_applied', 'appeal_sla_breached', 'notification_delivery_failing',
  'worker_stalled', 'channel_growth_anomaly', 'channel_owner_repeat_offender',
  'support_emergency', 'support_sla_breached', 'automod_drift'));

-- ---------------------------------------------------------------------------
-- Starter rules, all in shadow. §6.6 wants the false-positive rate measured
-- before anything enforces, so none of these do anything on install.
-- ---------------------------------------------------------------------------
INSERT INTO admin.automod_rules
  (name, description, mode, surface, signal, config, action, reason_code)
VALUES
  ('New account mass DM',
   'A young account messaging many distinct people quickly — the standard spam-ring shape. Reads only metadata: no message content is involved, and none could be.',
   'shadow', 'account', 'new_account_mass_dm',
   '{"window_minutes": 60, "max_age_hours": 48, "min_recipients": 15}'::jsonb,
   'flag_for_review', 'spam.unsolicited_bulk'),

  ('High message velocity',
   'Sustained sending far above human pace. Catches automation regardless of what is being sent.',
   'shadow', 'account', 'message_velocity',
   '{"window_minutes": 5, "min_per_minute": 30}'::jsonb,
   'flag_for_review', 'spam.unsolicited_bulk'),

  ('Wide conversation fan-out',
   'One sender opening many separate conversations in a short window.',
   'shadow', 'account', 'conversation_fanout',
   '{"window_minutes": 30, "min_conversations": 25}'::jsonb,
   'flag_for_review', 'spam.unsolicited_bulk'),

  ('Blocklisted link in a channel post',
   'Channel posts are plaintext by design, so link inspection is possible here — and only here.',
   'shadow', 'channel_post', 'link_domain',
   '{}'::jsonb,
   'flag_for_review', 'spam.phishing')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- Post-conditions
-- ---------------------------------------------------------------------------
SELECT 'tables' AS check_name,
       count(*) = 3 AS ok, count(*)::text || ' of 3' AS detail
  FROM information_schema.tables
 WHERE table_schema = 'admin'
   AND table_name IN ('automod_rules', 'automod_firings', 'automod_blocklist')
UNION ALL
SELECT 'all_starter_rules_in_shadow',
       bool_and(mode = 'shadow'),
       'nothing enforces on install'
  FROM admin.automod_rules
UNION ALL
SELECT 'no_content_rules_on_encrypted_surface',
       NOT EXISTS (
         SELECT 1 FROM admin.automod_rules
          WHERE surface = 'direct_message'
            AND signal IN ('keyword_match','regex_match','link_domain','media_hash')),
       'content rules cannot target end-to-end encrypted messages'
UNION ALL
SELECT 'terminal_actions_unavailable',
       NOT EXISTS (
         SELECT 1 FROM admin.automod_rules
          WHERE action IN ('ban_permanent','account_deletion','ban_temporary')),
       'automation may restrict or queue, never terminally ban'
UNION ALL
SELECT 'quality_functions',
       count(*) = 2, count(*)::text || ' of 2'
  FROM pg_proc
 WHERE pronamespace = 'admin'::regnamespace
   AND proname IN ('automod_rule_quality', 'detect_automod_drift');
