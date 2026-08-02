-- ============================================================================
-- 0007_user_directory.sql — the console's read model over NeverOff users.
--
-- §3.2 requires the trust score to be "a transparent, explainable 0-100
-- composite … with a breakdown of contributing factors. Never a black box."
-- So admin.trust_score() returns the components alongside the total, and the
-- profile screen renders exactly those rows. There is no hidden term: what the
-- function returns is the whole calculation.
--
-- Everything here is a view or a function over existing tables. No user data is
-- copied, so there is nothing to keep in sync and nothing extra to purge when
-- an erasure request lands.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Trust score
--
-- Weights are policy, not physics. They live in admin.settings so they can be
-- tuned without a migration, with these as the defaults.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.trust_score(p_user UUID)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_created      TIMESTAMPTZ;
  v_age_days     INTEGER;
  v_verified     BOOLEAN := FALSE;
  v_messages     BIGINT := 0;
  v_components   JSONB := '[]'::jsonb;
  v_total        INTEGER := 50;
  v_age_pts      INTEGER;
  v_verify_pts   INTEGER;
  v_activity_pts INTEGER;
  v_penalty      INTEGER := 0;
  r              RECORD;
BEGIN
  SELECT p.created_at INTO v_created FROM public.profiles p WHERE p.id = p_user;
  IF v_created IS NULL THEN
    RETURN jsonb_build_object('total', 0, 'components', '[]'::jsonb, 'known', false);
  END IF;

  v_age_days := GREATEST(0, EXTRACT(DAY FROM NOW() - v_created)::int);

  SELECT (u.email_confirmed_at IS NOT NULL) INTO v_verified
    FROM auth.users u WHERE u.id = p_user;
  v_verified := COALESCE(v_verified, FALSE);

  SELECT count(*) INTO v_messages FROM public.messages m WHERE m.sender_id = p_user;

  -- --- Positive contributions -------------------------------------------
  -- Account age: 1 point per 18 days, capped at 20. A year-old account is
  -- fully trusted on this axis; a day-old one gets nothing.
  v_age_pts := LEAST(20, v_age_days / 18);
  v_total := v_total + v_age_pts;
  v_components := v_components || jsonb_build_object(
    'key', 'account_age', 'label', 'Account age', 'points', v_age_pts, 'max', 20,
    'detail', v_age_days || ' days old');

  v_verify_pts := CASE WHEN v_verified THEN 10 ELSE 0 END;
  v_total := v_total + v_verify_pts;
  v_components := v_components || jsonb_build_object(
    'key', 'verification', 'label', 'Verified email', 'points', v_verify_pts, 'max', 10,
    'detail', CASE WHEN v_verified THEN 'Email confirmed' ELSE 'Email not confirmed' END);

  -- Sustained ordinary use. Capped low on purpose: volume is weak evidence of
  -- good faith, and a spam account produces a lot of it.
  v_activity_pts := LEAST(10, (v_messages / 50)::int);
  v_total := v_total + v_activity_pts;
  v_components := v_components || jsonb_build_object(
    'key', 'activity', 'label', 'Sustained activity', 'points', v_activity_pts, 'max', 10,
    'detail', v_messages || ' messages sent');

  -- --- Penalties ---------------------------------------------------------
  -- Older actions weigh half. People change, and a permanent 50-point hole for
  -- one warning three years ago makes the score useless for triage.
  FOR r IN
    SELECT type, issued_at,
           (issued_at < NOW() - INTERVAL '180 days') AS is_old
      FROM admin.enforcement_actions
     WHERE user_id = p_user AND type <> 'note'
  LOOP
    v_penalty := v_penalty + (
      CASE r.type
        WHEN 'warning' THEN 5
        WHEN 'feature_restriction' THEN 8
        WHEN 'rate_limit' THEN 8
        WHEN 'mute' THEN 12
        WHEN 'shadow_restriction' THEN 15
        WHEN 'ban_temporary' THEN 25
        WHEN 'ban_permanent' THEN 50
        WHEN 'account_deletion' THEN 50
        ELSE 0
      END / CASE WHEN r.is_old THEN 2 ELSE 1 END
    );
  END LOOP;

  v_penalty := LEAST(v_penalty, 80);
  v_total := v_total - v_penalty;
  v_components := v_components || jsonb_build_object(
    'key', 'enforcement_history', 'label', 'Enforcement history', 'points', -v_penalty, 'max', 0,
    'detail', CASE WHEN v_penalty = 0 THEN 'No prior actions'
                   ELSE v_penalty || ' points deducted (actions over 180 days old count half)' END);

  v_total := GREATEST(0, LEAST(100, v_total));

  RETURN jsonb_build_object(
    'total', v_total,
    'baseline', 50,
    'components', v_components,
    'known', true,
    'computed_at', NOW());
END;
$$;

-- Scalar form for sorting the directory without materialising the breakdown.
CREATE OR REPLACE FUNCTION admin.trust_score_value(p_user UUID)
RETURNS INTEGER
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT (admin.trust_score(p_user) ->> 'total')::int;
$$;

-- ---------------------------------------------------------------------------
-- Directory read model
--
-- Deliberately excludes email and every other identifier: this view backs the
-- list that any `users.view` holder can see. Personal data is a separate,
-- individually-audited lookup behind `users.view_pii`.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW admin.user_directory AS
SELECT
  p.id,
  p.username,
  p.display_name,
  p.avatar_url,
  p.created_at                                   AS registered_at,
  -- Coarse geography, taken from the consent record written at registration.
  -- §2.4 forbids storing raw IPs beyond a short security window, so the
  -- country derivation is the only geo signal that exists — there is
  -- deliberately no city, region or precise location anywhere in the console.
  -- NULL means unknown, and a region-scoped admin is denied access to unknown
  -- users rather than being given the benefit of the doubt (see scopeAdmits).
  (SELECT c.country FROM admin.consent_records c
    WHERE c.user_id = p.id AND c.country IS NOT NULL
    ORDER BY c.recorded_at DESC LIMIT 1)         AS country,
  COALESCE(s.status, 'active')                   AS status,
  COALESCE(s.blocks_access, FALSE)               AS blocks_access,
  COALESCE(s.blocks_sending, FALSE)              AS blocks_sending,
  COALESCE(s.shadow_restricted, FALSE)           AS shadow_restricted,
  COALESCE(s.restricted_features, '{}')          AS restricted_features,
  s.next_expiry_at,
  COALESCE(s.active_action_count, 0)             AS active_action_count,
  (SELECT count(*) FROM admin.enforcement_actions e
    WHERE e.user_id = p.id AND e.type <> 'note') AS lifetime_action_count,
  (SELECT count(*) FROM admin.appeals a
    WHERE a.user_id = p.id)                      AS appeal_count,
  (SELECT max(m.created_at) FROM public.messages m
    WHERE m.sender_id = p.id)                    AS last_message_at,
  (SELECT count(*) FROM public.messages m
    WHERE m.sender_id = p.id)                    AS message_count,
  (SELECT count(*) FROM public.channels c
    WHERE c.owner_id = p.id)                     AS owned_channel_count,
  EXISTS (SELECT 1 FROM admin.legal_holds h
           WHERE h.subject_type = 'user' AND h.subject_id = p.id::text
             AND h.released_at IS NULL)          AS under_legal_hold
FROM public.profiles p
LEFT JOIN admin.user_restriction_state s ON s.user_id = p.id;

COMMENT ON VIEW admin.user_directory IS
  'Non-PII user list for the console directory. Contains no email, phone, IP or device data — those require users.view_pii and are logged per access.';

-- The indexes this view needs on the app's own tables are created separately in
-- 0008, CONCURRENTLY and outside a transaction. Building them here would take an
-- ACCESS EXCLUSIVE lock on public.messages for the duration of the build, which
-- on a live table means every send blocks until it finishes.

-- ---------------------------------------------------------------------------
-- Post-conditions
-- ---------------------------------------------------------------------------
SELECT 'trust_score_fn' AS check_name,
       count(*) = 2 AS ok,
       count(*)::text || ' of 2' AS detail
  FROM pg_proc
 WHERE pronamespace = 'admin'::regnamespace
   AND proname IN ('trust_score', 'trust_score_value')
UNION ALL
SELECT 'user_directory_view',
       count(*) = 1,
       'admin.user_directory'
  FROM information_schema.views
 WHERE table_schema = 'admin' AND table_name = 'user_directory'
UNION ALL
SELECT 'directory_excludes_pii',
       NOT EXISTS (
         SELECT 1 FROM information_schema.columns
          WHERE table_schema = 'admin' AND table_name = 'user_directory'
            AND column_name IN ('email', 'phone', 'ip', 'fcm_token')),
       'no identifier columns in the directory view';
