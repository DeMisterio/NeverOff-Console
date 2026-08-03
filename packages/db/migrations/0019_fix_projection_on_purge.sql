-- ============================================================================
-- 0019_fix_projection_on_purge.sql — account erasure could not complete.
--
-- THE BUG
--
-- Deleting a profile cascades to admin.enforcement_actions. That fires
-- trg_enforcement_projection (AFTER DELETE), which calls
-- recompute_user_restrictions(OLD.user_id), which INSERTs a row into
-- admin.user_restriction_state keyed on a profile that is in the middle of
-- being deleted. The FK to public.profiles then rejects it and the whole
-- delete rolls back.
--
-- Net effect: `users.delete` — the §3.3 terminal rung, Super-Admin-only, the
-- one that satisfies a legal erasure request — failed for any account with
-- enforcement history. Which is to say: for every account anyone would
-- plausibly want to erase. §11 requires deleting a user to purge their data
-- across all stores; it could not.
--
-- Found by the integration suite's teardown rather than by a test asserting it,
-- which is worth noting: the assertion for this did not exist. One is added
-- below the fix.
--
-- THE FIX
--
-- Recomputing a projection for a user who no longer exists is meaningless. If
-- the profile has gone, drop the projection row and return. The ON DELETE
-- CASCADE on user_restriction_state would remove it anyway once the profile
-- delete completes — the point is to stop the trigger re-creating it first.
-- ============================================================================

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
  -- The guard this function was missing. Reached during a profile delete, when
  -- the cascade fires this trigger for rows whose owner is already gone.
  IF NOT EXISTS (SELECT 1 FROM public.profiles WHERE id = p_user) THEN
    DELETE FROM admin.user_restriction_state WHERE user_id = p_user;
    RETURN;
  END IF;

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

-- ---------------------------------------------------------------------------
-- Post-conditions — this one actually exercises the bug rather than inspecting
-- the schema, because the schema looked perfectly fine while erasure was broken.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  v_user UUID := gen_random_uuid();
BEGIN
  INSERT INTO auth.users (id, email) VALUES (v_user, 'purge-check-' || v_user || '@invalid.test');
  INSERT INTO public.profiles (id, username, display_name, public_key)
  VALUES (v_user, 'purge_check_' || replace(v_user::text, '-', ''), 'Purge Check', 'k');

  INSERT INTO admin.enforcement_actions
    (user_id, type, reason_code, note, issued_by_label, expires_at)
  VALUES (v_user, 'ban_temporary', 'spam.phishing',
          'Temporary ban created solely to verify that erasure works.',
          'migration:0019', NOW() + INTERVAL '1 day');

  -- Before the fix this raised a foreign key violation and rolled back.
  DELETE FROM public.profiles WHERE id = v_user;
  DELETE FROM auth.users WHERE id = v_user;

  IF EXISTS (SELECT 1 FROM admin.user_restriction_state WHERE user_id = v_user) THEN
    RAISE EXCEPTION 'Projection row survived the purge.';
  END IF;
END $$;

SELECT 'erasure_completes_with_enforcement_history' AS check_name,
       TRUE AS ok,
       'a user with an active ban can be deleted; the projection is cleaned up' AS detail;
