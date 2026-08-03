-- ============================================================================
-- 0013_channel_governance.sql — the §6.5 channel action ladder.
--
-- Touches the live app surface: adds RESTRICTIVE policies to public.channel_posts
-- and public.channel_subscribers. Listed in PRODUCTION_TOUCHING in migrate.ts.
--
-- Why channels get their own ladder rather than reusing §3.3:
--
--   §6.5 opens with "Channels are the highest-leverage abuse surface — one bad
--   channel reaches thousands." The user ladder cannot express what is needed
--   here. Banning the owner of a 24,000-subscriber channel does not stop the
--   channel; the posts stay up and the subscribers stay subscribed. And the
--   proportionate response to a channel that has drifted is usually not a ban
--   at all — it is blocking new joins while the owner is warned, or geo-blocking
--   in one jurisdiction where the content is illegal but lawful elsewhere.
--
-- TAKEDOWN IS A STATE, NOT A DELETE. A taken-down channel keeps every row: the
-- posts are evidence for an appeal, and §6.5 gives channel owners the same
-- structured appeal path as individuals. Deleting on takedown would make that
-- appeal unreviewable and the decision unauditable.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Channel actions
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.channel_actions (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  channel_id             UUID NOT NULL REFERENCES public.channels(id) ON DELETE CASCADE,

  type                   TEXT NOT NULL,
  reason_code            TEXT NOT NULL REFERENCES admin.reason_catalogue(code),
  note                   TEXT NOT NULL,
  case_ref               TEXT NOT NULL DEFAULT admin.next_case_ref(),

  issued_by              UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  issued_by_label        TEXT NOT NULL,
  issued_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at             TIMESTAMPTZ,

  -- Only for geo_restrict. ISO 3166-1 alpha-2, uppercase.
  countries              TEXT[],

  reversed_at            TIMESTAMPTZ,
  reversed_by            UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  reversal_reason        TEXT,
  auto_lifted            BOOLEAN NOT NULL DEFAULT FALSE,

  -- The moderation case this came from, when it came from one.
  case_id                UUID REFERENCES admin.cases(id) ON DELETE SET NULL,
  break_glass_request_id UUID REFERENCES admin.break_glass_requests(id) ON DELETE SET NULL,

  -- §6.5 takedown notifies members with a stated reason.
  members_notified_at    TIMESTAMPTZ,
  owner_notified_at      TIMESTAMPTZ,

  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT channel_action_type_valid CHECK (type IN (
    'warn_owner',        -- owner is told; nothing changes for members
    'restrict_joins',    -- no new subscribers
    'disable_media',     -- text only
    'disable_links',     -- no outbound links
    'disable_forwarding',-- posts cannot be forwarded out
    'age_gate',          -- 18+ interstitial before viewing
    'geo_restrict',      -- blocked in named countries only
    'delist',            -- removed from search and discovery; link still works
    'freeze',            -- read-only: existing posts stay, no new ones
    'takedown')),        -- fully inaccessible, rows preserved
  CONSTRAINT channel_action_note_len CHECK (char_length(note) >= 10),
  CONSTRAINT channel_action_geo_needs_countries
    CHECK (type <> 'geo_restrict'
           OR (countries IS NOT NULL AND array_length(countries, 1) >= 1)),
  CONSTRAINT channel_action_reversal_documented
    CHECK (reversed_at IS NULL OR reversal_reason IS NOT NULL),
  -- A warning is a point-in-time event, not a state, so it never expires.
  CONSTRAINT channel_action_warn_no_expiry
    CHECK (type <> 'warn_owner' OR expires_at IS NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_channel_actions_case_ref
  ON admin.channel_actions(case_ref);

-- The index the live predicates ride on.
CREATE INDEX IF NOT EXISTS idx_channel_actions_live
  ON admin.channel_actions(channel_id, type)
  WHERE reversed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_channel_actions_history
  ON admin.channel_actions(channel_id, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_channel_actions_pending_expiry
  ON admin.channel_actions(expires_at)
  WHERE reversed_at IS NULL AND expires_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Live predicates.
--
-- Same rule as user enforcement: evaluated against NOW() on every call, never
-- read from a cached projection. A channel frozen for 24 hours must unfreeze
-- on time whether or not a worker happened to run.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.channel_has_action(p_channel UUID, p_types TEXT[])
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM admin.channel_actions
     WHERE channel_id = p_channel
       AND reversed_at IS NULL
       AND type = ANY(p_types)
       AND (expires_at IS NULL OR expires_at > NOW())
  );
$$;

-- Blocks posting: frozen or taken down.
CREATE OR REPLACE FUNCTION admin.is_channel_posting_blocked(p_channel UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = admin, public
AS $$ SELECT admin.channel_has_action(p_channel, ARRAY['freeze', 'takedown']); $$;

-- Blocks new subscribers: joins restricted or taken down.
CREATE OR REPLACE FUNCTION admin.is_channel_join_blocked(p_channel UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = admin, public
AS $$ SELECT admin.channel_has_action(p_channel, ARRAY['restrict_joins', 'takedown']); $$;

CREATE OR REPLACE FUNCTION admin.is_channel_taken_down(p_channel UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = admin, public
AS $$ SELECT admin.channel_has_action(p_channel, ARRAY['takedown']); $$;

CREATE OR REPLACE FUNCTION admin.is_channel_delisted(p_channel UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = admin, public
AS $$ SELECT admin.channel_has_action(p_channel, ARRAY['delist', 'takedown']); $$;

/**
 * §8 geo-blocking: "local-law-only removal (geo-block rather than global
 * delete) where appropriate". A channel legal in one jurisdiction and not in
 * another should disappear only where it must.
 */
CREATE OR REPLACE FUNCTION admin.is_channel_geo_blocked(p_channel UUID, p_country TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM admin.channel_actions
     WHERE channel_id = p_channel
       AND reversed_at IS NULL
       AND type = 'geo_restrict'
       AND (expires_at IS NULL OR expires_at > NOW())
       AND p_country IS NOT NULL
       AND countries @> ARRAY[upper(p_country)]
  );
$$;

/** Everything the app needs about a channel's restriction state, in one call. */
CREATE OR REPLACE FUNCTION admin.channel_state(p_channel UUID)
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT jsonb_build_object(
    'taken_down',        admin.channel_has_action(p_channel, ARRAY['takedown']),
    'frozen',            admin.channel_has_action(p_channel, ARRAY['freeze']),
    'joins_blocked',     admin.is_channel_join_blocked(p_channel),
    'delisted',          admin.is_channel_delisted(p_channel),
    'age_gated',         admin.channel_has_action(p_channel, ARRAY['age_gate']),
    'media_disabled',    admin.channel_has_action(p_channel, ARRAY['disable_media']),
    'links_disabled',    admin.channel_has_action(p_channel, ARRAY['disable_links']),
    'forwarding_disabled', admin.channel_has_action(p_channel, ARRAY['disable_forwarding']),
    'geo_blocked_in',    COALESCE((
        SELECT jsonb_agg(DISTINCT country)
          FROM admin.channel_actions ca, unnest(ca.countries) AS country
         WHERE ca.channel_id = p_channel
           AND ca.reversed_at IS NULL
           AND ca.type = 'geo_restrict'
           AND (ca.expires_at IS NULL OR ca.expires_at > NOW())), '[]'::jsonb),
    'next_expiry_at',    (
        SELECT min(expires_at) FROM admin.channel_actions
         WHERE channel_id = p_channel AND reversed_at IS NULL AND expires_at > NOW())
  );
$$;

-- ---------------------------------------------------------------------------
-- Enforcement against the app, as RESTRICTIVE policies.
--
-- AND-ed with the existing permissive policies from 07_channels.sql, which are
-- left untouched. Dropping these two returns the app to its prior behaviour.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.neveroff_channel_posting_blocked(p_channel UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = admin, public
AS $$ SELECT admin.is_channel_posting_blocked(p_channel); $$;

CREATE OR REPLACE FUNCTION public.neveroff_channel_join_blocked(p_channel UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = admin, public
AS $$ SELECT admin.is_channel_join_blocked(p_channel); $$;

REVOKE ALL ON FUNCTION public.neveroff_channel_posting_blocked(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.neveroff_channel_join_blocked(UUID) FROM PUBLIC;

DROP POLICY IF EXISTS "Enforcement: frozen channels cannot receive posts" ON public.channel_posts;
CREATE POLICY "Enforcement: frozen channels cannot receive posts" ON public.channel_posts
  AS RESTRICTIVE
  FOR INSERT
  TO authenticated
  WITH CHECK (NOT public.neveroff_channel_posting_blocked(channel_id));

DROP POLICY IF EXISTS "Enforcement: restricted channels cannot gain subscribers"
  ON public.channel_subscribers;
CREATE POLICY "Enforcement: restricted channels cannot gain subscribers" ON public.channel_subscribers
  AS RESTRICTIVE
  FOR INSERT
  TO authenticated
  WITH CHECK (NOT public.neveroff_channel_join_blocked(channel_id));

-- App-facing: a channel screen asks what it may render.
CREATE OR REPLACE FUNCTION public.channel_restriction_state(p_channel UUID)
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$ SELECT admin.channel_state(p_channel); $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.neveroff_channel_posting_blocked(UUID) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.neveroff_channel_join_blocked(UUID) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.channel_restriction_state(UUID) TO authenticated';
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Growth tracking (§6.5: "a channel adding members far above baseline gets
-- flagged for review")
--
-- Snapshots rather than a running rate, because the interesting signal is the
-- shape of the curve. A channel that gained 5,000 subscribers in an hour after
-- eight months at forty a week is not the same as one growing steadily.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.channel_growth_snapshots (
  channel_id       UUID NOT NULL REFERENCES public.channels(id) ON DELETE CASCADE,
  captured_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  subscriber_count INTEGER NOT NULL,
  post_count       INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (channel_id, captured_at)
);

CREATE INDEX IF NOT EXISTS idx_channel_growth_recent
  ON admin.channel_growth_snapshots(channel_id, captured_at DESC);

CREATE OR REPLACE FUNCTION admin.capture_channel_growth()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_count INTEGER;
BEGIN
  INSERT INTO admin.channel_growth_snapshots (channel_id, subscriber_count, post_count)
  SELECT c.id, c.subscriber_count,
         (SELECT count(*) FROM public.channel_posts p WHERE p.channel_id = c.id)
    FROM public.channels c
  ON CONFLICT DO NOTHING;

  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;

/**
 * Flag channels growing far above their own baseline.
 *
 * Compares the last 24 hours against the median daily gain over the preceding
 * fortnight. Comparing against a global average would flag every popular
 * channel and nothing else; the useful signal is a channel departing from its
 * own history.
 *
 * Raises an alert for human review. It never restricts anything — sudden growth
 * is also what a channel looks like when it is simply having a good week.
 */
CREATE OR REPLACE FUNCTION admin.detect_channel_growth_anomalies()
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
      SELECT channel_id,
             captured_at::date AS day,
             max(subscriber_count) - min(subscriber_count) AS gain
        FROM admin.channel_growth_snapshots
       WHERE captured_at > NOW() - INTERVAL '15 days'
       GROUP BY channel_id, captured_at::date
    ),
    baseline AS (
      SELECT channel_id,
             percentile_cont(0.5) WITHIN GROUP (ORDER BY gain) AS median_gain
        FROM daily
       WHERE day < CURRENT_DATE
       GROUP BY channel_id
      HAVING count(*) >= 5
    )
    SELECT d.channel_id, d.gain, b.median_gain, c.name, c.subscriber_count
      FROM daily d
      JOIN baseline b ON b.channel_id = d.channel_id
      JOIN public.channels c ON c.id = d.channel_id
     WHERE d.day = CURRENT_DATE
       AND d.gain > GREATEST(b.median_gain * 10, 500)
  LOOP
    -- One open alert per channel; re-raising daily would bury the queue.
    INSERT INTO admin.alerts (kind, severity, title, detail, evidence)
    SELECT 'channel_growth_anomaly', 'medium',
           'Channel "' || r.name || '" is growing far above its baseline',
           'Gained ' || r.gain || ' subscribers today against a median of '
             || round(r.median_gain, 1) || '. Sudden growth is also what a channel '
             || 'looks like when it is simply popular — this is for review, not action.',
           jsonb_build_object('channel_id', r.channel_id, 'today_gain', r.gain,
                              'median_gain', r.median_gain,
                              'subscriber_count', r.subscriber_count)
     WHERE NOT EXISTS (
       SELECT 1 FROM admin.alerts
        WHERE kind = 'channel_growth_anomaly'
          AND acknowledged_at IS NULL
          AND evidence->>'channel_id' = r.channel_id::text);

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
  'worker_stalled', 'channel_growth_anomaly', 'channel_owner_repeat_offender'));

-- ---------------------------------------------------------------------------
-- Owner accountability (§6.5: "repeated violations in a channel escalate to
-- action against the owner's account, not just the channel")
--
-- Surfaces the pattern; it does not act on it. Whether three actioned channels
-- means a bad actor or an overwhelmed moderator of a large community is a
-- judgement, and automating it would get that wrong in exactly the cases where
-- being wrong matters.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW admin.channel_owner_accountability AS
SELECT
  c.owner_id,
  p.username                                              AS owner_username,
  count(DISTINCT c.id)                                    AS channels_owned,
  count(DISTINCT ca.channel_id) FILTER (
    WHERE ca.type NOT IN ('warn_owner'))                  AS channels_actioned,
  count(ca.id) FILTER (WHERE ca.type = 'takedown')        AS takedowns,
  count(ca.id) FILTER (WHERE ca.type = 'warn_owner')      AS warnings,
  max(ca.issued_at)                                       AS last_action_at,
  sum(c.subscriber_count)                                 AS total_reach
FROM public.channels c
JOIN public.profiles p ON p.id = c.owner_id
LEFT JOIN admin.channel_actions ca
       ON ca.channel_id = c.id AND ca.reversed_at IS NULL
GROUP BY c.owner_id, p.username;

CREATE OR REPLACE FUNCTION admin.flag_repeat_channel_owners()
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
    SELECT * FROM admin.channel_owner_accountability
     WHERE channels_actioned >= 2 OR takedowns >= 1
  LOOP
    INSERT INTO admin.alerts (kind, severity, title, detail, subject_admin_id, evidence)
    SELECT 'channel_owner_repeat_offender', 'high',
           '@' || r.owner_username || ' owns ' || r.channels_actioned || ' actioned channel(s)',
           'Repeated violations across channels are grounds for action against the owner '
             || 'rather than only the channels (§6.5). Review whether this is a pattern or '
             || 'a large community that is hard to moderate.',
           NULL,
           jsonb_build_object('owner_id', r.owner_id, 'channels_actioned', r.channels_actioned,
                              'takedowns', r.takedowns, 'total_reach', r.total_reach)
     WHERE NOT EXISTS (
       SELECT 1 FROM admin.alerts
        WHERE kind = 'channel_owner_repeat_offender'
          AND acknowledged_at IS NULL
          AND evidence->>'owner_id' = r.owner_id::text);

    v_count := v_count + 1;
  END LOOP;

  RETURN v_count;
END;
$$;

-- ---------------------------------------------------------------------------
-- Channel directory read model
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW admin.channel_directory AS
SELECT
  c.id,
  c.name,
  c.username,
  c.description,
  c.is_public,
  c.subscriber_count,
  c.created_at,
  c.owner_id,
  p.username                                        AS owner_username,
  (SELECT count(*) FROM public.channel_posts cp
    WHERE cp.channel_id = c.id)                     AS post_count,
  (SELECT max(created_at) FROM public.channel_posts cp
    WHERE cp.channel_id = c.id)                     AS last_post_at,
  (SELECT count(*) FROM admin.cases ca
    WHERE ca.target_type = 'channel' AND ca.target_id = c.id::text) AS case_count,
  (SELECT count(*) FROM admin.cases ca
    WHERE ca.target_type = 'channel' AND ca.target_id = c.id::text
      AND ca.status NOT IN ('resolved', 'dismissed'))               AS open_case_count,
  (SELECT count(*) FROM admin.channel_actions ca
    WHERE ca.channel_id = c.id AND ca.reversed_at IS NULL)          AS action_count,
  admin.channel_state(c.id)                         AS restriction_state,
  -- Risk is reach × trouble. A channel with 100k subscribers and one open case
  -- deserves attention before one with 40 subscribers and three.
  round(
    (ln(1 + c.subscriber_count::numeric) / 2)
    * (1 + (SELECT count(*) FROM admin.cases ca
             WHERE ca.target_type = 'channel' AND ca.target_id = c.id::text
               AND ca.status NOT IN ('resolved', 'dismissed'))), 2
  )                                                 AS risk_score
FROM public.channels c
JOIN public.profiles p ON p.id = c.owner_id;

COMMENT ON VIEW admin.channel_directory IS
  'Channel list for the console. Reach x trouble risk score; restriction_state is evaluated live against NOW().';

-- ---------------------------------------------------------------------------
-- Expiry, mirroring admin.process_expired_enforcements
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.process_expired_channel_actions(p_limit INTEGER DEFAULT 100)
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
    SELECT ca.id, ca.channel_id, ca.type, ca.case_ref, c.owner_id, c.name
      FROM admin.channel_actions ca
      JOIN public.channels c ON c.id = ca.channel_id
     WHERE ca.reversed_at IS NULL
       AND ca.expires_at IS NOT NULL
       AND ca.expires_at <= NOW()
       AND ca.auto_lifted = FALSE
     ORDER BY ca.expires_at ASC
     LIMIT p_limit
     FOR UPDATE OF ca SKIP LOCKED
  LOOP
    UPDATE admin.channel_actions SET auto_lifted = TRUE WHERE id = r.id;

    IF r.owner_id IS NOT NULL THEN
      INSERT INTO admin.notification_outbox (user_id, kind, payload)
      VALUES (r.owner_id, 'enforcement_expired',
              jsonb_build_object('case_ref', r.case_ref, 'action_type', r.type,
                                 'channel_name', r.name, 'scope', 'channel'));
    END IF;

    INSERT INTO admin.audit_log (
      actor_admin_id, actor_label, origin, action, target_type, target_id,
      target_label, after_state, note, entry_hash)
    VALUES (NULL, 'system:channel-expiry', 'system', 'channel.restriction.expired',
            'channel', r.channel_id::text, r.name,
            jsonb_build_object('action_id', r.id, 'type', r.type),
            'Channel restriction automatically lifted on expiry.', '');

    v_count := v_count + 1;
  END LOOP;

  RETURN v_count;
END;
$$;

-- ---------------------------------------------------------------------------
-- Post-conditions
-- ---------------------------------------------------------------------------
SELECT 'channel_actions_table' AS check_name,
       count(*) = 1 AS ok, 'admin.channel_actions' AS detail
  FROM information_schema.tables
 WHERE table_schema = 'admin' AND table_name = 'channel_actions'
UNION ALL
SELECT 'restrictive_policies',
       count(*) = 2,
       count(*)::text || ' of 2'
  FROM pg_policies
 WHERE schemaname = 'public'
   AND policyname IN ('Enforcement: frozen channels cannot receive posts',
                      'Enforcement: restricted channels cannot gain subscribers')
   AND permissive = 'RESTRICTIVE'
UNION ALL
SELECT 'live_predicates',
       count(*) = 6,
       count(*)::text || ' of 6'
  FROM pg_proc
 WHERE pronamespace = 'admin'::regnamespace
   AND proname IN ('channel_has_action', 'is_channel_posting_blocked',
                   'is_channel_join_blocked', 'is_channel_taken_down',
                   'is_channel_delisted', 'is_channel_geo_blocked')
UNION ALL
SELECT 'directory_view',
       count(*) = 1, 'admin.channel_directory'
  FROM information_schema.views
 WHERE table_schema = 'admin' AND table_name = 'channel_directory'
UNION ALL
SELECT 'original_channel_policies_intact',
       count(*) >= 4,
       count(*)::text || ' original policies on public.channel_posts'
  FROM pg_policies
 WHERE schemaname = 'public' AND tablename = 'channel_posts'
   AND policyname NOT LIKE 'Enforcement:%';
