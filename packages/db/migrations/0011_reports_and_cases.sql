-- ============================================================================
-- 0011_reports_and_cases.sql — report intake, clustering, and the moderation
-- queue (§6.1–6.4).
--
-- THE CONSTRAINT THAT SHAPES THIS ENTIRE FILE
--
-- NeverOff private messages are end-to-end encrypted. When a user reports a
-- message, the server holds ciphertext it cannot read. It cannot snapshot the
-- content, cannot show it to a moderator, and cannot run a classifier over it.
--
-- The only party who can produce readable evidence is the reporter, whose own
-- device already holds the key. So message evidence is *reporter-submitted*:
-- the client decrypts what it is reporting and uploads that plaintext, with the
-- reporter's explicit consent, as a voluntary disclosure.
--
-- That has three consequences encoded below:
--
--   1. evidence_snapshots.source distinguishes 'reporter_submitted' from
--      'server_captured'. Channel posts and profile fields are plaintext
--      server-side and can be captured directly; messages and chat media never
--      can.
--   2. A message report with no reporter-submitted evidence is a metadata-only
--      report. It is still actionable on pattern (volume, velocity, repeat
--      targets) but a moderator will never see what was said, and the queue
--      says so rather than showing an empty content pane.
--   3. Reporter-submitted plaintext is the most sensitive data this console
--      holds — it is decrypted private conversation. It is retained only for
--      the case plus its appeal window, and every read is audit-logged.
--
-- Nothing here weakens or works around the encryption. §8 is explicit that no
-- capability may be built to do so, and the correct design was available.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Reports — one row per user submission
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.reports (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- §6.3: anonymity by default. The reported party never learns who reported
  -- them; this column is readable only through permission-gated API paths and
  -- is never included in any payload the reported user can reach.
  reporter_id         UUID REFERENCES public.profiles(id) ON DELETE SET NULL,

  target_type         TEXT NOT NULL,
  target_id           TEXT NOT NULL,
  -- Denormalised so a case survives the target being deleted by its owner.
  target_owner_id     UUID REFERENCES public.profiles(id) ON DELETE SET NULL,

  reason_code         TEXT NOT NULL REFERENCES admin.reason_catalogue(code),
  reporter_note       TEXT,

  -- §6.2: "The reporter chooses an outcome preference where applicable."
  outcome_preference  TEXT NOT NULL DEFAULT 'just_report',

  submitted_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Coarse only, consistent with §2.4. Used for scope routing, never displayed
  -- as a location.
  reporter_country    TEXT,
  app_version         TEXT,

  case_id             UUID,

  -- Set when the case closes, so the reporter can be told the outcome (§6.4
  -- "reporter feedback loop"). Generic terms only.
  outcome_notified_at TIMESTAMPTZ,

  CONSTRAINT reports_target_type_valid
    CHECK (target_type IN ('message', 'user', 'channel', 'media', 'bot', 'call', 'channel_post')),
  CONSTRAINT reports_outcome_pref_valid
    CHECK (outcome_preference IN ('just_report', 'block_user', 'leave_channel', 'hide_content')),
  CONSTRAINT reports_country_shape
    CHECK (reporter_country IS NULL OR reporter_country ~ '^[A-Z]{2}$'),
  CONSTRAINT reports_note_length
    CHECK (reporter_note IS NULL OR char_length(reporter_note) <= 2000)
);

-- §6.3: one report per reporter per target. A second submission updates the
-- first rather than inflating the count — ten reports from one angry user is
-- one signal, not ten.
CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_one_per_reporter_target
  ON admin.reports(reporter_id, target_type, target_id)
  WHERE reporter_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_reports_case ON admin.reports(case_id);
CREATE INDEX IF NOT EXISTS idx_reports_target ON admin.reports(target_type, target_id, submitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_reporter ON admin.reports(reporter_id, submitted_at DESC);

-- ---------------------------------------------------------------------------
-- Cases — the clustered unit of work (§6.3)
--
-- Five reports about one channel produce one case with a count of five, not
-- five cases. Ten reports in ten minutes and ten reports over a month are very
-- different signals, so velocity is tracked separately from volume.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.cases (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_ref              TEXT NOT NULL DEFAULT admin.next_case_ref(),

  target_type           TEXT NOT NULL,
  target_id             TEXT NOT NULL,
  target_owner_id       UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
  target_label          TEXT,

  -- Most severe category among the clustered reports; recomputed on each new
  -- report so a case that starts as spam and gains a harassment report escalates.
  primary_reason_code   TEXT REFERENCES admin.reason_catalogue(code),
  primary_category      TEXT,

  status                TEXT NOT NULL DEFAULT 'open',
  priority_score        NUMERIC(10, 2) NOT NULL DEFAULT 0,

  report_count          INTEGER NOT NULL DEFAULT 0,
  distinct_reporter_count INTEGER NOT NULL DEFAULT 0,
  first_reported_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_reported_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- §6.3 coordinated-reporting detection. A flagged case is NOT auto-actioned;
  -- brigading must never trigger enforcement by itself, so this raises the case
  -- for human attention and *lowers* its volume-driven priority instead.
  coordinated_suspected BOOLEAN NOT NULL DEFAULT FALSE,
  coordination_signals  JSONB NOT NULL DEFAULT '[]'::jsonb,

  -- §6.4 locking: a case opened by one moderator is locked so two people do not
  -- work it at once. The lock expires on its own so an abandoned case does not
  -- stay stuck behind someone who closed their laptop.
  locked_by             UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  locked_at             TIMESTAMPTZ,
  lock_expires_at       TIMESTAMPTZ,

  assigned_to           UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  assigned_at           TIMESTAMPTZ,

  escalated_at          TIMESTAMPTZ,
  escalated_by          UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  escalation_note       TEXT,

  -- SLA clocks for the §2.5 trust & safety KPIs.
  first_touched_at      TIMESTAMPTZ,
  resolved_at           TIMESTAMPTZ,
  sla_due_at            TIMESTAMPTZ,

  -- Set when an automod rule opened or flagged this case (§6.6).
  auto_flagged          BOOLEAN NOT NULL DEFAULT FALSE,
  automod_rule_id       UUID,

  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT cases_status_valid CHECK (status IN (
    'open', 'triaging', 'awaiting_decision', 'escalated', 'resolved', 'dismissed')),
  CONSTRAINT cases_target_type_valid
    CHECK (target_type IN ('message', 'user', 'channel', 'media', 'bot', 'call', 'channel_post')),
  CONSTRAINT cases_resolution_timestamps
    CHECK (status NOT IN ('resolved', 'dismissed') OR resolved_at IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_case_ref ON admin.cases(case_ref);

-- The clustering lookup: at most one *open* case per target. Once a case is
-- resolved, a later report legitimately opens a new one — repeat offending
-- should read as several cases over time, not one that never closes.
CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_one_open_per_target
  ON admin.cases(target_type, target_id)
  WHERE status NOT IN ('resolved', 'dismissed');

CREATE INDEX IF NOT EXISTS idx_cases_queue
  ON admin.cases(priority_score DESC, first_reported_at ASC)
  WHERE status NOT IN ('resolved', 'dismissed');
CREATE INDEX IF NOT EXISTS idx_cases_assigned ON admin.cases(assigned_to, status);
CREATE INDEX IF NOT EXISTS idx_cases_owner ON admin.cases(target_owner_id);
CREATE INDEX IF NOT EXISTS idx_cases_sla
  ON admin.cases(sla_due_at) WHERE status NOT IN ('resolved', 'dismissed');

ALTER TABLE admin.reports
  ADD CONSTRAINT reports_case_fk FOREIGN KEY (case_id)
  REFERENCES admin.cases(id) ON DELETE SET NULL;

-- ---------------------------------------------------------------------------
-- Evidence snapshots (§6.3: "immutable evidence snapshot taken at report time
-- so deletion by the offender doesn't destroy the case")
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.evidence_snapshots (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  report_id           UUID NOT NULL REFERENCES admin.reports(id) ON DELETE CASCADE,
  case_id             UUID REFERENCES admin.cases(id) ON DELETE CASCADE,

  -- The distinction that matters. 'server_captured' is only possible for data
  -- the server can actually read: channel posts, profile fields, channel
  -- metadata. Message and chat-media evidence is always 'reporter_submitted'.
  source              TEXT NOT NULL,

  captured_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Plaintext content, when there is any. NULL for a metadata-only report.
  content_text        TEXT,
  -- Surrounding messages, only when the reporter explicitly consented (§6.1).
  context_text        JSONB,
  context_consented   BOOLEAN NOT NULL DEFAULT FALSE,

  -- Media is identified by hash rather than copied. A perceptual hash lets us
  -- match the same image across reports without the console storing a second
  -- copy of abuse imagery.
  media_sha256        TEXT,
  media_perceptual_hash TEXT,
  media_mime_type     TEXT,

  -- Non-content metadata the server can always see.
  metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,

  -- Graphic or sexual media is blurred by default in the UI (§6.8). Set from
  -- the reason category at capture time.
  requires_blur       BOOLEAN NOT NULL DEFAULT FALSE,

  CONSTRAINT evidence_source_valid
    CHECK (source IN ('reporter_submitted', 'server_captured')),
  -- The invariant this whole file exists to protect: the server cannot capture
  -- message or chat-media content, so claiming it did is a bug.
  CONSTRAINT evidence_e2ee_honesty
    CHECK (source = 'reporter_submitted' OR content_text IS NULL
           OR metadata->>'target_type' NOT IN ('message', 'media')),
  CONSTRAINT evidence_content_length
    CHECK (content_text IS NULL OR char_length(content_text) <= 20000)
);

CREATE INDEX IF NOT EXISTS idx_evidence_report ON admin.evidence_snapshots(report_id);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON admin.evidence_snapshots(case_id);
-- §6.4 "related cases — same media hash". A perceptual hash match links an
-- image across cases even when it has been recompressed or lightly edited.
CREATE INDEX IF NOT EXISTS idx_evidence_media_hash
  ON admin.evidence_snapshots(media_sha256) WHERE media_sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_evidence_perceptual
  ON admin.evidence_snapshots(media_perceptual_hash) WHERE media_perceptual_hash IS NOT NULL;

-- Evidence is immutable once captured. The entire point is that it survives
-- the offender deleting the original.
CREATE OR REPLACE FUNCTION admin.evidence_reject_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION
    'Evidence snapshots are immutable. Capture a new snapshot rather than editing this one.'
    USING ERRCODE = 'raise_exception';
END;
$$;

DROP TRIGGER IF EXISTS trg_evidence_immutable ON admin.evidence_snapshots;
CREATE TRIGGER trg_evidence_immutable
  BEFORE UPDATE ON admin.evidence_snapshots
  FOR EACH ROW EXECUTE FUNCTION admin.evidence_reject_update();

-- ---------------------------------------------------------------------------
-- Reporter reputation (§6.3)
--
-- Tracked so accurate reporters are weighted up in triage and serial false
-- reporters are deprioritised. Deliberately NOT used to auto-dismiss: a
-- low-reputation reporter can still be right, and a report that is never seen
-- by a human because of a score is a report that was silently discarded.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.reporter_reputation (
  user_id            UUID PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
  reports_filed      INTEGER NOT NULL DEFAULT 0,
  reports_actioned   INTEGER NOT NULL DEFAULT 0,
  reports_dismissed  INTEGER NOT NULL DEFAULT 0,
  -- reports_actioned / (actioned + dismissed), null until there is enough to say.
  accuracy           NUMERIC(4, 3),
  -- Set when someone is abusing the report function. §6.3 requires they be
  -- notified rather than silently throttled.
  rate_limited_until TIMESTAMPTZ,
  notified_of_abuse_at TIMESTAMPTZ,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION admin.reporter_weight(p_user UUID)
RETURNS NUMERIC
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  -- Neutral 1.0 until a reporter has a track record. Bounded to [0.5, 1.5] so
  -- reputation nudges triage order without ever dominating category severity —
  -- a child-safety report from an unknown account must still outrank a spam
  -- report from a trusted one.
  SELECT COALESCE(
    (SELECT CASE
              WHEN (reports_actioned + reports_dismissed) < 5 THEN 1.0
              ELSE GREATEST(0.5, LEAST(1.5, 0.5 + COALESCE(accuracy, 0.5) * 1.0))
            END
       FROM admin.reporter_reputation WHERE user_id = p_user),
    1.0);
$$;

-- ---------------------------------------------------------------------------
-- Decisions (§6.4 decision panel)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.case_decisions (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id            UUID NOT NULL REFERENCES admin.cases(id) ON DELETE CASCADE,

  decided_by         UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  decided_by_label   TEXT NOT NULL,
  decided_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  outcome            TEXT NOT NULL,
  reason_code        TEXT REFERENCES admin.reason_catalogue(code),
  note               TEXT NOT NULL,

  -- The enforcement action this decision produced, if any. A case can resolve
  -- with no action ("reviewed, no violation found") and that is a real outcome
  -- worth counting, not an absence of one.
  enforcement_action_id UUID REFERENCES admin.enforcement_actions(id) ON DELETE SET NULL,

  -- §6.4 four-eyes review on precedent-setting cases.
  requires_second_review BOOLEAN NOT NULL DEFAULT FALSE,
  second_reviewed_by     UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  second_reviewed_at     TIMESTAMPTZ,

  -- Optional message shown to the reporter, in generic terms.
  reporter_message   TEXT,

  CONSTRAINT decision_outcome_valid CHECK (outcome IN (
    'action_taken', 'no_violation', 'duplicate', 'insufficient_evidence',
    'out_of_scope', 'escalated')),
  CONSTRAINT decision_note_length CHECK (char_length(note) >= 10),
  CONSTRAINT decision_second_review_complete
    CHECK (NOT requires_second_review
           OR second_reviewed_by IS NULL
           OR second_reviewed_by <> decided_by)
);

CREATE INDEX IF NOT EXISTS idx_decisions_case ON admin.case_decisions(case_id, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_decisions_moderator
  ON admin.case_decisions(decided_by, decided_at DESC);

-- ---------------------------------------------------------------------------
-- Priority scoring (§6.4)
--
-- "category severity × report volume × velocity × reporter reputation ×
--  reported-user trust score × audience size"
--
-- Returned with its breakdown for the same reason the trust score is: a
-- moderator asking "why is this at the top of my queue?" deserves an answer,
-- and an unexplainable ordering is one nobody trusts or tunes.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.case_priority(p_case UUID)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  c              RECORD;
  v_severity     NUMERIC := 1;
  v_volume       NUMERIC := 1;
  v_velocity     NUMERIC := 1;
  v_reputation   NUMERIC := 1;
  v_trust        NUMERIC := 1;
  v_audience     NUMERIC := 1;
  v_coordination NUMERIC := 1;
  v_total        NUMERIC;
  v_window_hours NUMERIC;
  v_subscribers  BIGINT := 0;
  v_trust_score  INTEGER;
BEGIN
  SELECT * INTO c FROM admin.cases WHERE id = p_case;
  IF c.id IS NULL THEN
    RETURN jsonb_build_object('total', 0, 'components', '[]'::jsonb);
  END IF;

  -- Category severity, straight from the reason catalogue's weighting.
  SELECT COALESCE(
    CASE cat.category
      WHEN 'child_safety' THEN 10 WHEN 'self_harm' THEN 9
      WHEN 'violence' THEN 6 WHEN 'hate_speech' THEN 5
      WHEN 'adult_sexual' THEN 5 WHEN 'harassment' THEN 4
      WHEN 'illegal_goods' THEN 4 WHEN 'impersonation' THEN 3
      WHEN 'spam_scams' THEN 2 WHEN 'misinformation' THEN 2
      WHEN 'intellectual_property' THEN 2 ELSE 1
    END, 1)
    INTO v_severity
    FROM admin.reason_catalogue cat WHERE cat.code = c.primary_reason_code;
  v_severity := COALESCE(v_severity, 1);

  -- Volume, dampened. Twenty reports is a stronger signal than two, but not
  -- ten times stronger — log keeps a brigade from burying everything else.
  v_volume := 1 + ln(GREATEST(c.distinct_reporter_count, 1)::numeric);

  -- Velocity: reports per hour since the first one. A burst outranks a trickle.
  v_window_hours := GREATEST(
    EXTRACT(EPOCH FROM (c.last_reported_at - c.first_reported_at)) / 3600.0, 0.25);
  v_velocity := 1 + LEAST(ln(1 + (c.report_count / v_window_hours)), 2.0);

  -- Reporter reputation, averaged across everyone who reported this case.
  SELECT COALESCE(AVG(admin.reporter_weight(r.reporter_id)), 1.0)
    INTO v_reputation
    FROM admin.reports r WHERE r.case_id = p_case AND r.reporter_id IS NOT NULL;

  -- Reported user's trust score: a low-trust account gets looked at sooner.
  IF c.target_owner_id IS NOT NULL THEN
    v_trust_score := admin.trust_score_value(c.target_owner_id);
    v_trust := 1 + ((100 - COALESCE(v_trust_score, 50))::numeric / 100.0);
  END IF;

  -- Audience size. §6.5: "a channel with 100k members outranks a 1:1 chat."
  IF c.target_type IN ('channel', 'channel_post') THEN
    SELECT COALESCE(MAX(ch.subscriber_count), 0) INTO v_subscribers
      FROM public.channels ch
     WHERE ch.id::text = c.target_id
        OR ch.id = (SELECT cp.channel_id FROM public.channel_posts cp
                     WHERE cp.id::text = c.target_id);
    v_audience := 1 + ln(1 + GREATEST(v_subscribers, 0)::numeric) / 2.0;
  END IF;

  -- Suspected brigading pulls priority DOWN rather than up. The volume is
  -- probably manufactured, and letting it float to the top is exactly the
  -- outcome the brigade wanted.
  IF c.coordinated_suspected THEN
    v_coordination := 0.4;
  END IF;

  v_total := v_severity * v_volume * v_velocity * v_reputation * v_trust
             * v_audience * v_coordination;

  RETURN jsonb_build_object(
    'total', round(v_total, 2),
    'components', jsonb_build_array(
      jsonb_build_object('key', 'severity', 'label', 'Category severity',
                         'factor', round(v_severity, 2),
                         'detail', COALESCE(c.primary_category, 'uncategorised')),
      jsonb_build_object('key', 'volume', 'label', 'Distinct reporters',
                         'factor', round(v_volume, 2),
                         'detail', c.distinct_reporter_count || ' reporters'),
      jsonb_build_object('key', 'velocity', 'label', 'Report velocity',
                         'factor', round(v_velocity, 2),
                         'detail', round(c.report_count / v_window_hours, 1) || ' reports/hour'),
      jsonb_build_object('key', 'reputation', 'label', 'Reporter accuracy',
                         'factor', round(v_reputation, 2),
                         'detail', 'weighted by historical report-to-action rate'),
      jsonb_build_object('key', 'trust', 'label', 'Reported user trust',
                         'factor', round(v_trust, 2),
                         'detail', COALESCE('trust score ' || v_trust_score::text, 'not applicable')),
      jsonb_build_object('key', 'audience', 'label', 'Audience size',
                         'factor', round(v_audience, 2),
                         'detail', CASE WHEN v_subscribers > 0
                                        THEN v_subscribers || ' subscribers'
                                        ELSE 'private conversation' END),
      jsonb_build_object('key', 'coordination', 'label', 'Coordination penalty',
                         'factor', round(v_coordination, 2),
                         'detail', CASE WHEN c.coordinated_suspected
                                        THEN 'suspected brigading — deprioritised pending review'
                                        ELSE 'no coordination signals' END)
    ));
END;
$$;

-- ---------------------------------------------------------------------------
-- Coordinated-reporting detection (§6.3)
--
-- Honest limitation: real brigading detection leans on device fingerprints and
-- social-graph clustering. This console deliberately does not collect device
-- fingerprints (§2.4 keeps geography coarse and §8 minimises telemetry), so the
-- signals available are weaker: account age, reporting burst shape, and whether
-- the reporters have any history at all.
--
-- These flag a case for human attention and reduce its priority. They never
-- action anything, and they never dismiss a report.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.detect_coordination(p_case UUID)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_signals        JSONB := '[]'::jsonb;
  v_total          INTEGER;
  v_new_accounts   INTEGER;
  v_no_history     INTEGER;
  v_burst_minutes  NUMERIC;
BEGIN
  SELECT count(*) INTO v_total FROM admin.reports WHERE case_id = p_case;
  IF v_total < 3 THEN
    RETURN v_signals;
  END IF;

  -- Reporters whose accounts are younger than a week.
  SELECT count(*) INTO v_new_accounts
    FROM admin.reports r
    JOIN public.profiles p ON p.id = r.reporter_id
   WHERE r.case_id = p_case AND p.created_at > NOW() - INTERVAL '7 days';

  IF v_new_accounts::numeric / v_total > 0.5 THEN
    v_signals := v_signals || jsonb_build_object(
      'signal', 'new_accounts',
      'detail', v_new_accounts || ' of ' || v_total || ' reporters registered in the last week');
  END IF;

  -- Reporters who have never reported anything before and have little activity.
  SELECT count(*) INTO v_no_history
    FROM admin.reports r
    LEFT JOIN admin.reporter_reputation rep ON rep.user_id = r.reporter_id
   WHERE r.case_id = p_case
     AND COALESCE(rep.reports_filed, 0) <= 1;

  IF v_no_history = v_total AND v_total >= 5 THEN
    v_signals := v_signals || jsonb_build_object(
      'signal', 'no_reporting_history',
      'detail', 'every reporter is filing their first report');
  END IF;

  -- A tight burst: many distinct reporters inside a few minutes.
  SELECT EXTRACT(EPOCH FROM (MAX(submitted_at) - MIN(submitted_at))) / 60.0
    INTO v_burst_minutes
    FROM admin.reports WHERE case_id = p_case;

  IF v_total >= 5 AND COALESCE(v_burst_minutes, 999) < 10 THEN
    v_signals := v_signals || jsonb_build_object(
      'signal', 'burst',
      'detail', v_total || ' reports within ' || round(COALESCE(v_burst_minutes, 0), 1) || ' minutes');
  END IF;

  RETURN v_signals;
END;
$$;

-- ---------------------------------------------------------------------------
-- Recompute a case's derived fields. Called after every new report.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.refresh_case(p_case UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_signals JSONB;
BEGIN
  v_signals := admin.detect_coordination(p_case);

  UPDATE admin.cases c SET
    report_count = sub.report_count,
    distinct_reporter_count = sub.distinct_reporters,
    first_reported_at = sub.first_at,
    last_reported_at = sub.last_at,
    primary_reason_code = sub.top_reason,
    primary_category = sub.top_category,
    coordinated_suspected = (jsonb_array_length(v_signals) > 0),
    coordination_signals = v_signals
  FROM (
    SELECT
      count(*)                                   AS report_count,
      count(DISTINCT r.reporter_id)              AS distinct_reporters,
      min(r.submitted_at)                        AS first_at,
      max(r.submitted_at)                        AS last_at,
      -- Most severe category present wins, not the most frequent: one credible
      -- violence report inside twenty spam reports must set the case category.
      (SELECT r2.reason_code FROM admin.reports r2
         JOIN admin.reason_catalogue rc2 ON rc2.code = r2.reason_code
        WHERE r2.case_id = p_case
        ORDER BY CASE rc2.category
                   WHEN 'child_safety' THEN 10 WHEN 'self_harm' THEN 9
                   WHEN 'violence' THEN 6 WHEN 'hate_speech' THEN 5
                   WHEN 'adult_sexual' THEN 5 WHEN 'harassment' THEN 4
                   WHEN 'illegal_goods' THEN 4 WHEN 'impersonation' THEN 3
                   ELSE 1 END DESC, r2.submitted_at ASC
        LIMIT 1)                                 AS top_reason,
      (SELECT rc3.category FROM admin.reports r3
         JOIN admin.reason_catalogue rc3 ON rc3.code = r3.reason_code
        WHERE r3.case_id = p_case
        ORDER BY CASE rc3.category
                   WHEN 'child_safety' THEN 10 WHEN 'self_harm' THEN 9
                   WHEN 'violence' THEN 6 WHEN 'hate_speech' THEN 5
                   WHEN 'adult_sexual' THEN 5 WHEN 'harassment' THEN 4
                   WHEN 'illegal_goods' THEN 4 WHEN 'impersonation' THEN 3
                   ELSE 1 END DESC, r3.submitted_at ASC
        LIMIT 1)                                 AS top_category
    FROM admin.reports r WHERE r.case_id = p_case
  ) sub
  WHERE c.id = p_case;

  -- Priority depends on the counts above, so it is computed after they land.
  UPDATE admin.cases
     SET priority_score = (admin.case_priority(p_case) ->> 'total')::numeric
   WHERE id = p_case;
END;
$$;

-- ---------------------------------------------------------------------------
-- Reporter reputation maintenance — recomputed when a case is decided
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.update_reporter_reputation(p_case UUID, p_actioned BOOLEAN)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
BEGIN
  INSERT INTO admin.reporter_reputation (user_id, reports_filed, reports_actioned, reports_dismissed)
  SELECT r.reporter_id, 0,
         CASE WHEN p_actioned THEN 1 ELSE 0 END,
         CASE WHEN p_actioned THEN 0 ELSE 1 END
    FROM admin.reports r
   WHERE r.case_id = p_case AND r.reporter_id IS NOT NULL
  ON CONFLICT (user_id) DO UPDATE SET
    reports_actioned = admin.reporter_reputation.reports_actioned
                       + CASE WHEN p_actioned THEN 1 ELSE 0 END,
    reports_dismissed = admin.reporter_reputation.reports_dismissed
                        + CASE WHEN p_actioned THEN 0 ELSE 1 END,
    updated_at = NOW();

  UPDATE admin.reporter_reputation
     SET accuracy = CASE
           WHEN (reports_actioned + reports_dismissed) = 0 THEN NULL
           ELSE round(reports_actioned::numeric
                      / (reports_actioned + reports_dismissed), 3)
         END
   WHERE user_id IN (SELECT reporter_id FROM admin.reports WHERE case_id = p_case);
END;
$$;

-- Keep reports_filed accurate as reports arrive.
CREATE OR REPLACE FUNCTION admin.bump_reports_filed()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
BEGIN
  IF NEW.reporter_id IS NULL THEN RETURN NULL; END IF;

  INSERT INTO admin.reporter_reputation (user_id, reports_filed)
  VALUES (NEW.reporter_id, 1)
  ON CONFLICT (user_id) DO UPDATE SET
    reports_filed = admin.reporter_reputation.reports_filed + 1,
    updated_at = NOW();

  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_bump_reports_filed ON admin.reports;
CREATE TRIGGER trg_bump_reports_filed
  AFTER INSERT ON admin.reports
  FOR EACH ROW EXECUTE FUNCTION admin.bump_reports_filed();

-- ---------------------------------------------------------------------------
-- Case locking (§6.4)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.claim_case(
  p_case UUID, p_admin UUID, p_minutes INTEGER DEFAULT 15)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_locked_by UUID;
  v_expires   TIMESTAMPTZ;
BEGIN
  SELECT locked_by, lock_expires_at INTO v_locked_by, v_expires
    FROM admin.cases WHERE id = p_case FOR UPDATE;

  -- Already held by someone else and still live.
  IF v_locked_by IS NOT NULL AND v_locked_by <> p_admin
     AND v_expires IS NOT NULL AND v_expires > NOW() THEN
    RETURN FALSE;
  END IF;

  UPDATE admin.cases
     SET locked_by = p_admin,
         locked_at = NOW(),
         lock_expires_at = NOW() + make_interval(mins => p_minutes),
         status = CASE WHEN status = 'open' THEN 'triaging' ELSE status END,
         -- Time-to-first-touch for the §2.5 KPIs, set once and never reset.
         first_touched_at = COALESCE(first_touched_at, NOW())
   WHERE id = p_case;

  RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION admin.release_case(p_case UUID, p_admin UUID)
RETURNS VOID
LANGUAGE sql
SECURITY DEFINER
SET search_path = admin, public
AS $$
  UPDATE admin.cases
     SET locked_by = NULL, locked_at = NULL, lock_expires_at = NULL
   WHERE id = p_case AND locked_by = p_admin;
$$;

-- ---------------------------------------------------------------------------
-- Post-conditions
-- ---------------------------------------------------------------------------
SELECT 'tables' AS check_name,
       count(*) = 5 AS ok,
       count(*)::text || ' of 5' AS detail
  FROM information_schema.tables
 WHERE table_schema = 'admin'
   AND table_name IN ('reports', 'cases', 'evidence_snapshots',
                      'reporter_reputation', 'case_decisions')
UNION ALL
SELECT 'clustering_index',
       count(*) = 1,
       'at most one open case per target'
  FROM pg_indexes
 WHERE schemaname = 'admin' AND indexname = 'idx_cases_one_open_per_target'
UNION ALL
SELECT 'functions',
       count(*) = 7,
       count(*)::text || ' of 7'
  FROM pg_proc
 WHERE pronamespace = 'admin'::regnamespace
   AND proname IN ('case_priority', 'detect_coordination', 'refresh_case',
                   'reporter_weight', 'update_reporter_reputation',
                   'claim_case', 'release_case')
UNION ALL
SELECT 'evidence_immutable',
       count(*) = 1,
       'UPDATE blocked by trigger'
  FROM pg_trigger
 WHERE NOT tgisinternal AND tgname = 'trg_evidence_immutable';
