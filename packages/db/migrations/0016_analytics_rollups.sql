-- ============================================================================
-- 0016_analytics_rollups.sql — the §2 analytics layer.
--
-- WHAT THE ENCRYPTION MAKES IMPOSSIBLE, AND WHAT IT DOES NOT
--
-- §2.1 asks for message volume "split by content type: text, image, video,
-- voice note, file, sticker/GIF, link, location". For 1:1 and group messages
-- the server cannot know any of that — it holds ciphertext. There is no query
-- that recovers it, and any dashboard claiming to show it would be showing
-- something else.
--
-- So content-type splits come from client telemetry, which means they are
-- consented-only and therefore a *sample*, not a census. Every such metric is
-- returned with the sample basis attached so nobody reads a partial figure as a
-- total. The alternative — quietly presenting consented-user counts as platform
-- totals — is how analytics starts lying.
--
-- What IS available from metadata, exactly and for everyone:
--   - message counts, senders, timestamps, conversation type
--   - the sent → delivered → read funnel, because messages.status is plaintext
--   - channel posts in full, because they are plaintext by design
--   - registrations, activity, retention, geography at country granularity
--
-- WHY ROLLUPS LIVE IN POSTGRES FOR NOW
--
-- §9.1 suggests ClickHouse or TimescaleDB and says not to run analytics against
-- the transactional database. That is right at volume, and the rollup tables
-- below are precisely the seam that makes the move cheap: the query API reads
-- rollups and never raw events, so replacing the *producer* with a ClickHouse
-- job leaves every consumer untouched. Standing up a second datastore before
-- there is data to justify it would be architecture for its own sake.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Watermarks — every rollup records how far it has processed, so a refresh is
-- incremental and re-runnable rather than a full rebuild each time.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.rollup_state (
  name              TEXT PRIMARY KEY,
  processed_through TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01T00:00:00Z',
  last_run_at       TIMESTAMPTZ,
  last_duration_ms  INTEGER,
  rows_written      BIGINT NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------------------
-- Event rollups (§2.3)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.rollup_events_hourly (
  bucket        TIMESTAMPTZ NOT NULL,
  event_name    TEXT NOT NULL,
  platform      TEXT NOT NULL DEFAULT '',
  app_version   TEXT NOT NULL DEFAULT '',
  country       TEXT NOT NULL DEFAULT '',
  total_events  BIGINT NOT NULL DEFAULT 0,
  unique_users  BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, event_name, platform, app_version, country)
);

CREATE INDEX IF NOT EXISTS idx_rollup_events_name_time
  ON admin.rollup_events_hourly(event_name, bucket DESC);
CREATE INDEX IF NOT EXISTS idx_rollup_events_time
  ON admin.rollup_events_hourly(bucket DESC);

-- ---------------------------------------------------------------------------
-- Message rollups (§2.1) — metadata only
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.rollup_messages_hourly (
  bucket            TIMESTAMPTZ NOT NULL,
  -- 'direct' | 'group' | 'channel'. Derived from chats.is_group and the
  -- channel_posts table, all of which is unencrypted metadata.
  surface           TEXT NOT NULL,
  total_messages    BIGINT NOT NULL DEFAULT 0,
  unique_senders    BIGINT NOT NULL DEFAULT 0,
  -- Delivery funnel. messages.status is plaintext, so this is a census.
  sent_count        BIGINT NOT NULL DEFAULT 0,
  delivered_count   BIGINT NOT NULL DEFAULT 0,
  read_count        BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, surface)
);

CREATE INDEX IF NOT EXISTS idx_rollup_messages_time
  ON admin.rollup_messages_hourly(bucket DESC);

-- ---------------------------------------------------------------------------
-- Daily active users (§2.2)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.rollup_active_users_daily (
  day           DATE NOT NULL,
  country       TEXT NOT NULL DEFAULT '',
  active_users  BIGINT NOT NULL DEFAULT 0,
  new_users     BIGINT NOT NULL DEFAULT 0,
  -- §2.2 activation: registered → sent first message.
  activated_users BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (day, country)
);

-- ---------------------------------------------------------------------------
-- Feature catalogue (§2.3)
--
-- Every feature the app can emit, whether or not anyone has. That "whether or
-- not" is the whole point: a table built only from observed events can never
-- show a feature nobody touched, and §2.3's "sort ascending to instantly
-- surface dead features nobody uses" needs the zero rows to exist.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.feature_catalogue (
  key            TEXT PRIMARY KEY,
  label          TEXT NOT NULL,
  surface        TEXT,
  shipped_in     TEXT,
  shipped_at     TIMESTAMPTZ,
  retired_at     TIMESTAMPTZ,
  notes          TEXT
);

-- ---------------------------------------------------------------------------
-- Refresh
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.refresh_event_rollups(p_lookback_hours INTEGER DEFAULT 48)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_from  TIMESTAMPTZ;
  v_rows  INTEGER;
  v_start TIMESTAMPTZ := clock_timestamp();
BEGIN
  SELECT GREATEST(processed_through, NOW() - make_interval(hours => p_lookback_hours))
    INTO v_from FROM admin.rollup_state WHERE name = 'events_hourly';
  v_from := COALESCE(v_from, NOW() - make_interval(hours => p_lookback_hours));

  -- Recompute whole buckets rather than adding deltas: an event arriving late
  -- would otherwise be lost, and a re-run would double-count.
  INSERT INTO admin.rollup_events_hourly
    (bucket, event_name, platform, app_version, country, total_events, unique_users)
  SELECT date_trunc('hour', occurred_at),
         event_name,
         COALESCE(platform, ''),
         COALESCE(app_version, ''),
         COALESCE(country, ''),
         count(*),
         count(DISTINCT user_id)
    FROM admin.telemetry_events
   WHERE occurred_at >= date_trunc('hour', v_from)
   GROUP BY 1, 2, 3, 4, 5
  ON CONFLICT (bucket, event_name, platform, app_version, country) DO UPDATE SET
    total_events = EXCLUDED.total_events,
    unique_users = EXCLUDED.unique_users;

  GET DIAGNOSTICS v_rows = ROW_COUNT;

  INSERT INTO admin.rollup_state (name, processed_through, last_run_at, last_duration_ms, rows_written)
  VALUES ('events_hourly', date_trunc('hour', NOW()), NOW(),
          EXTRACT(MILLISECONDS FROM clock_timestamp() - v_start)::int, v_rows)
  ON CONFLICT (name) DO UPDATE SET
    processed_through = EXCLUDED.processed_through,
    last_run_at = NOW(),
    last_duration_ms = EXCLUDED.last_duration_ms,
    rows_written = admin.rollup_state.rows_written + EXCLUDED.rows_written;

  RETURN v_rows;
END;
$$;

CREATE OR REPLACE FUNCTION admin.refresh_message_rollups(p_lookback_hours INTEGER DEFAULT 48)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_from  TIMESTAMPTZ;
  v_rows  INTEGER;
  v_start TIMESTAMPTZ := clock_timestamp();
BEGIN
  SELECT GREATEST(processed_through, NOW() - make_interval(hours => p_lookback_hours))
    INTO v_from FROM admin.rollup_state WHERE name = 'messages_hourly';
  v_from := COALESCE(v_from, NOW() - make_interval(hours => p_lookback_hours));

  INSERT INTO admin.rollup_messages_hourly
    (bucket, surface, total_messages, unique_senders, sent_count, delivered_count, read_count)
  SELECT date_trunc('hour', m.created_at),
         CASE WHEN c.is_group THEN 'group' ELSE 'direct' END,
         count(*),
         count(DISTINCT m.sender_id),
         count(*) FILTER (WHERE m.status = 'sent'),
         count(*) FILTER (WHERE m.status = 'delivered'),
         count(*) FILTER (WHERE m.status = 'read')
    FROM public.messages m
    JOIN public.chats c ON c.id = m.chat_id
   WHERE m.created_at >= date_trunc('hour', v_from)
   GROUP BY 1, 2
  ON CONFLICT (bucket, surface) DO UPDATE SET
    total_messages = EXCLUDED.total_messages,
    unique_senders = EXCLUDED.unique_senders,
    sent_count = EXCLUDED.sent_count,
    delivered_count = EXCLUDED.delivered_count,
    read_count = EXCLUDED.read_count;

  GET DIAGNOSTICS v_rows = ROW_COUNT;

  -- Channel broadcasts are a separate surface and have no delivery status:
  -- a post is published, not delivered to a recipient.
  INSERT INTO admin.rollup_messages_hourly (bucket, surface, total_messages, unique_senders)
  SELECT date_trunc('hour', created_at), 'channel', count(*), count(DISTINCT author_id)
    FROM public.channel_posts
   WHERE created_at >= date_trunc('hour', v_from)
   GROUP BY 1
  ON CONFLICT (bucket, surface) DO UPDATE SET
    total_messages = EXCLUDED.total_messages,
    unique_senders = EXCLUDED.unique_senders;

  INSERT INTO admin.rollup_state (name, processed_through, last_run_at, last_duration_ms, rows_written)
  VALUES ('messages_hourly', date_trunc('hour', NOW()), NOW(),
          EXTRACT(MILLISECONDS FROM clock_timestamp() - v_start)::int, v_rows)
  ON CONFLICT (name) DO UPDATE SET
    processed_through = EXCLUDED.processed_through,
    last_run_at = NOW(),
    last_duration_ms = EXCLUDED.last_duration_ms,
    rows_written = admin.rollup_state.rows_written + EXCLUDED.rows_written;

  RETURN v_rows;
END;
$$;

CREATE OR REPLACE FUNCTION admin.refresh_user_rollups(p_lookback_days INTEGER DEFAULT 30)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_rows  INTEGER;
  v_start TIMESTAMPTZ := clock_timestamp();
  v_from  DATE := (NOW() - make_interval(days => p_lookback_days))::date;
BEGIN
  -- "Active" is defined as having sent a message. Opening the app without
  -- sending anything is invisible without client telemetry, and telemetry is
  -- consented-only — so this is a deliberately conservative floor, not DAU as
  -- a growth team would define it. The API labels it as such.
  INSERT INTO admin.rollup_active_users_daily (day, country, active_users, new_users, activated_users)
  SELECT d.day,
         COALESCE(cc.country, ''),
         count(DISTINCT m.sender_id),
         count(DISTINCT p.id) FILTER (WHERE p.created_at::date = d.day),
         count(DISTINCT first_msg.sender_id)
    FROM generate_series(v_from, CURRENT_DATE, INTERVAL '1 day') AS d(day)
    LEFT JOIN public.messages m ON m.created_at::date = d.day
    LEFT JOIN public.profiles p ON p.created_at::date = d.day
    LEFT JOIN LATERAL (
      SELECT c.user_id, c.country FROM admin.consent_records c
       WHERE c.user_id = m.sender_id AND c.country IS NOT NULL
       ORDER BY c.recorded_at DESC LIMIT 1
    ) cc ON TRUE
    LEFT JOIN LATERAL (
      SELECT m2.sender_id
        FROM public.messages m2
       WHERE m2.sender_id = p.id
       ORDER BY m2.created_at ASC LIMIT 1
    ) first_msg ON first_msg.sender_id IS NOT NULL
   GROUP BY d.day, COALESCE(cc.country, '')
  ON CONFLICT (day, country) DO UPDATE SET
    active_users = EXCLUDED.active_users,
    new_users = EXCLUDED.new_users,
    activated_users = EXCLUDED.activated_users;

  GET DIAGNOSTICS v_rows = ROW_COUNT;

  INSERT INTO admin.rollup_state (name, processed_through, last_run_at, last_duration_ms, rows_written)
  VALUES ('active_users_daily', date_trunc('day', NOW()), NOW(),
          EXTRACT(MILLISECONDS FROM clock_timestamp() - v_start)::int, v_rows)
  ON CONFLICT (name) DO UPDATE SET
    processed_through = EXCLUDED.processed_through,
    last_run_at = NOW(),
    last_duration_ms = EXCLUDED.last_duration_ms,
    rows_written = admin.rollup_state.rows_written + EXCLUDED.rows_written;

  RETURN v_rows;
END;
$$;

-- ---------------------------------------------------------------------------
-- Feature adoption (§2.3) — including the features nobody uses
--
-- LEFT JOIN from the catalogue, not a GROUP BY over events. That is the entire
-- reason this answers the question §2.3 actually asks.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.feature_adoption(p_days INTEGER DEFAULT 30)
RETURNS TABLE (
  feature_key   TEXT,
  label         TEXT,
  surface       TEXT,
  shipped_at    TIMESTAMPTZ,
  unique_users  BIGINT,
  total_uses    BIGINT,
  pct_of_active NUMERIC,
  last_used_at  TIMESTAMPTZ,
  is_dead       BOOLEAN
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_active BIGINT;
BEGIN
  SELECT GREATEST(count(DISTINCT user_id), 1) INTO v_active
    FROM admin.telemetry_events
   WHERE occurred_at > NOW() - make_interval(days => p_days);

  RETURN QUERY
  SELECT f.key,
         f.label,
         f.surface,
         f.shipped_at,
         COALESCE(sum(r.unique_users), 0)::bigint,
         COALESCE(sum(r.total_events), 0)::bigint,
         round(COALESCE(sum(r.unique_users), 0)::numeric * 100 / v_active, 2),
         max(r.bucket),
         -- Dead means shipped long enough ago to have been found, and still
         -- untouched. A feature released yesterday is not dead, it is new.
         (COALESCE(sum(r.total_events), 0) = 0
          AND (f.shipped_at IS NULL OR f.shipped_at < NOW() - INTERVAL '30 days'))
    FROM admin.feature_catalogue f
    LEFT JOIN admin.rollup_events_hourly r
           ON r.event_name = f.key
          AND r.bucket > NOW() - make_interval(days => p_days)
   WHERE f.retired_at IS NULL
   GROUP BY f.key, f.label, f.surface, f.shipped_at
   ORDER BY COALESCE(sum(r.total_events), 0) ASC, f.key ASC;
END;
$$;

-- ---------------------------------------------------------------------------
-- Retention cohorts (§2.2)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.retention_cohorts(p_weeks INTEGER DEFAULT 8)
RETURNS TABLE (
  cohort_week   DATE,
  cohort_size   BIGINT,
  d1_retained   BIGINT,
  d7_retained   BIGINT,
  d30_retained  BIGINT
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  WITH cohorts AS (
    SELECT date_trunc('week', p.created_at)::date AS cohort_week, p.id, p.created_at
      FROM public.profiles p
     WHERE p.created_at > NOW() - make_interval(weeks => p_weeks)
  )
  SELECT c.cohort_week,
         count(DISTINCT c.id),
         count(DISTINCT c.id) FILTER (WHERE EXISTS (
           SELECT 1 FROM public.messages m WHERE m.sender_id = c.id
             AND m.created_at BETWEEN c.created_at + INTERVAL '1 day'
                                  AND c.created_at + INTERVAL '2 days')),
         count(DISTINCT c.id) FILTER (WHERE EXISTS (
           SELECT 1 FROM public.messages m WHERE m.sender_id = c.id
             AND m.created_at BETWEEN c.created_at + INTERVAL '7 days'
                                  AND c.created_at + INTERVAL '8 days')),
         count(DISTINCT c.id) FILTER (WHERE EXISTS (
           SELECT 1 FROM public.messages m WHERE m.sender_id = c.id
             AND m.created_at BETWEEN c.created_at + INTERVAL '30 days'
                                  AND c.created_at + INTERVAL '31 days'))
    FROM cohorts c
   GROUP BY c.cohort_week
   ORDER BY c.cohort_week DESC;
$$;

-- ---------------------------------------------------------------------------
-- Trust & safety KPIs (§2.5)
--
-- The two that matter most, and the two most consoles omit: appeal rate and
-- appeal *overturn* rate. Overturn rate is the closest thing to a direct
-- measure of whether moderation decisions are correct. A rising overturn rate
-- with steady volume means the decisions are getting worse, and nothing else on
-- a dashboard tells you that.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.trust_safety_kpis(p_days INTEGER DEFAULT 30)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_from        TIMESTAMPTZ := NOW() - make_interval(days => p_days);
  v_messages    BIGINT;
  v_reports     BIGINT;
  v_cases       BIGINT;
  v_actioned    BIGINT;
  v_appeals     BIGINT;
  v_overturned  BIGINT;
  v_actions     BIGINT;
  v_automated   BIGINT;
  v_repeat      BIGINT;
BEGIN
  SELECT COALESCE(sum(total_messages), 0) INTO v_messages
    FROM admin.rollup_messages_hourly WHERE bucket >= v_from;

  SELECT count(*) INTO v_reports FROM admin.reports WHERE submitted_at >= v_from;

  SELECT count(*) FILTER (WHERE status IN ('resolved', 'dismissed')),
         count(*) FILTER (WHERE status = 'resolved')
    INTO v_cases, v_actioned
    FROM admin.cases WHERE first_reported_at >= v_from;

  SELECT count(*) INTO v_appeals FROM admin.appeals WHERE submitted_at >= v_from;
  SELECT count(*) INTO v_overturned
    FROM admin.appeals
   WHERE submitted_at >= v_from AND status IN ('overturned', 'partially_upheld');

  SELECT count(*) FILTER (WHERE type <> 'note'),
         count(*) FILTER (WHERE origin = 'automated')
    INTO v_actions, v_automated
    FROM admin.enforcement_actions WHERE issued_at >= v_from;

  SELECT count(*) INTO v_repeat FROM (
    SELECT user_id FROM admin.enforcement_actions
     WHERE issued_at >= v_from AND type <> 'note'
     GROUP BY user_id HAVING count(*) > 1
  ) repeat_offenders;

  RETURN jsonb_build_object(
    'window_days', p_days,
    'reports_per_1k_messages',
      CASE WHEN v_messages = 0 THEN NULL
           ELSE round(v_reports::numeric * 1000 / v_messages, 3) END,
    'reports_received', v_reports,
    'cases_closed', v_cases,
    -- The core signal of report quality: what proportion of reports were worth acting on.
    'report_to_action_rate',
      CASE WHEN v_cases = 0 THEN NULL
           ELSE round(v_actioned::numeric / v_cases, 3) END,
    'enforcement_actions', v_actions,
    'automated_actions', v_automated,
    'automated_share',
      CASE WHEN v_actions = 0 THEN NULL
           ELSE round(v_automated::numeric / v_actions, 3) END,
    'appeals_submitted', v_appeals,
    'appeal_rate',
      CASE WHEN v_actions = 0 THEN NULL
           ELSE round(v_appeals::numeric / v_actions, 3) END,
    -- The single best measure of whether decisions are correct.
    'appeal_overturn_rate',
      CASE WHEN v_appeals = 0 THEN NULL
           ELSE round(v_overturned::numeric / v_appeals, 3) END,
    'repeat_offenders', v_repeat,
    'median_time_to_first_touch_hours', (
      SELECT round(percentile_cont(0.5) WITHIN GROUP (
        ORDER BY EXTRACT(EPOCH FROM (first_touched_at - first_reported_at)) / 3600)::numeric, 2)
        FROM admin.cases
       WHERE first_touched_at IS NOT NULL AND first_reported_at >= v_from),
    'p90_time_to_resolution_hours', (
      SELECT round(percentile_cont(0.9) WITHIN GROUP (
        ORDER BY EXTRACT(EPOCH FROM (resolved_at - first_reported_at)) / 3600)::numeric, 2)
        FROM admin.cases
       WHERE resolved_at IS NOT NULL AND first_reported_at >= v_from),
    'computed_at', NOW());
END;
$$;

-- Per-moderator throughput and overturn rate (§2.5, §7 admin performance).
CREATE OR REPLACE FUNCTION admin.moderator_performance(p_days INTEGER DEFAULT 30)
RETURNS TABLE (
  admin_id           UUID,
  display_name       TEXT,
  decisions          BIGINT,
  actions_issued     BIGINT,
  appeals_against    BIGINT,
  overturned         BIGINT,
  overturn_rate      NUMERIC,
  median_handling_minutes NUMERIC
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT u.id,
         u.display_name,
         (SELECT count(*) FROM admin.case_decisions d
           WHERE d.decided_by = u.id AND d.decided_at > NOW() - make_interval(days => p_days)),
         (SELECT count(*) FROM admin.enforcement_actions e
           WHERE e.issued_by = u.id AND e.type <> 'note'
             AND e.issued_at > NOW() - make_interval(days => p_days)),
         (SELECT count(*) FROM admin.appeals a
            JOIN admin.enforcement_actions e ON e.id = a.action_id
           WHERE e.issued_by = u.id AND a.submitted_at > NOW() - make_interval(days => p_days)),
         (SELECT count(*) FROM admin.appeals a
            JOIN admin.enforcement_actions e ON e.id = a.action_id
           WHERE e.issued_by = u.id AND a.status IN ('overturned', 'partially_upheld')
             AND a.submitted_at > NOW() - make_interval(days => p_days)),
         COALESCE((
           SELECT round(count(*) FILTER (WHERE a.status IN ('overturned','partially_upheld'))::numeric
                        / NULLIF(count(*), 0), 3)
             FROM admin.appeals a
             JOIN admin.enforcement_actions e ON e.id = a.action_id
            WHERE e.issued_by = u.id
              AND a.submitted_at > NOW() - make_interval(days => p_days)), NULL),
         (SELECT round(percentile_cont(0.5) WITHIN GROUP (
            ORDER BY EXTRACT(EPOCH FROM (c.resolved_at - c.first_touched_at)) / 60)::numeric, 1)
            FROM admin.cases c
            JOIN admin.case_decisions d ON d.case_id = c.id
           WHERE d.decided_by = u.id AND c.resolved_at IS NOT NULL
             AND c.first_touched_at IS NOT NULL)
    FROM admin.admin_users u
   WHERE u.status = 'active'
   ORDER BY 3 DESC;
$$;

-- ---------------------------------------------------------------------------
-- Post-conditions
-- ---------------------------------------------------------------------------
SELECT 'rollup_tables' AS check_name,
       count(*) = 4 AS ok, count(*)::text || ' of 4' AS detail
  FROM information_schema.tables
 WHERE table_schema = 'admin'
   AND table_name IN ('rollup_state', 'rollup_events_hourly',
                      'rollup_messages_hourly', 'rollup_active_users_daily')
UNION ALL
SELECT 'analytics_functions',
       count(*) = 7, count(*)::text || ' of 7'
  FROM pg_proc
 WHERE pronamespace = 'admin'::regnamespace
   AND proname IN ('refresh_event_rollups', 'refresh_message_rollups',
                   'refresh_user_rollups', 'feature_adoption', 'retention_cohorts',
                   'trust_safety_kpis', 'moderator_performance')
UNION ALL
SELECT 'feature_catalogue_exists',
       count(*) = 1, 'dead features need a catalogue to be absent from events'
  FROM information_schema.tables
 WHERE table_schema = 'admin' AND table_name = 'feature_catalogue';
