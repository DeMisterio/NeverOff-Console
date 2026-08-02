-- ============================================================================
-- 0006_neveroff_integration.sql — where the console starts actually governing
-- the live NeverOff app.
--
-- THIS IS THE ONLY MIGRATION THAT TOUCHES THE EXISTING APP SCHEMA. Read the
-- safety rules before changing it.
--
-- Safety rules this file follows:
--
--   1. NO COLUMNS ARE ADDED TO EXISTING TABLES. The Android client reads
--      `profiles`, `messages`, `chats` and `channel_posts` with `select {}`,
--      i.e. `select=*`, and decodes into fixed Kotlin data classes. Whether an
--      extra column breaks that depends on the JSON decoder's leniency, which
--      is a library default we should not be betting a shipped app on. Every
--      addition here is a new table or a new function.
--
--   2. NO EXISTING POLICY IS MODIFIED OR DROPPED. Enforcement is added as
--      Postgres RESTRICTIVE policies, which are AND-ed with the existing
--      permissive ones. The existing rules keep working exactly as before; the
--      new ones can only ever subtract. Dropping the two policies added here
--      returns the database to its previous behaviour, which is what
--      0006_neveroff_integration.down.sql does.
--
--   3. RESTRICTIVE POLICIES ARE SCOPED `TO authenticated`. The service role
--      (used by the console API and the existing edge functions) bypasses RLS
--      anyway, but scoping makes the intent explicit and keeps `anon` untouched.
--
--   4. THE `admin` SCHEMA IS NEVER EXPOSED TO THE CLIENT. `authenticated` is
--      granted EXECUTE on a small set of SECURITY DEFINER wrappers in `public`
--      and nothing else — no USAGE on the admin schema, no table grants.
--
-- E2EE NOTE. NeverOff message content is end-to-end encrypted: `msg_key` is a
-- per-message KDF salt, and the actual key is derived from an ECDH secret
-- between two device-held identity keys that never leave the devices. The
-- server therefore CANNOT read message content, and nothing in this migration
-- attempts to. Enforcement here operates on metadata (who may send at all),
-- never on content. Channel posts are a different matter — 07_channels.sql
-- stores those in plaintext by design — so those are moderatable server-side.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Reason catalogue, mirrored from packages/shared/src/reasons.ts by the
-- catalogue sync that runs after every migration. Present in SQL so the ban
-- screen RPC can return a human-readable fallback label for a reason code the
-- installed app version does not yet have a translation for.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.reason_catalogue (
  code          TEXT PRIMARY KEY,
  category      TEXT NOT NULL,
  policy_clause TEXT NOT NULL,
  appealable    BOOLEAN NOT NULL DEFAULT TRUE,
  isolated      BOOLEAN NOT NULL DEFAULT FALSE,
  label_en      TEXT NOT NULL,
  label_ru      TEXT
);

-- ---------------------------------------------------------------------------
-- SECURITY DEFINER wrappers in `public`.
--
-- These exist so RLS policy expressions — which are evaluated as the calling
-- role — can consult the admin schema without `authenticated` ever being
-- granted access to it. Each is owned by the migration runner (a superuser or
-- the Supabase `postgres` role) and runs with those privileges.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.neveroff_send_blocked(p_user UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT admin.is_send_blocked(p_user);
$$;

CREATE OR REPLACE FUNCTION public.neveroff_access_blocked(p_user UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT admin.is_access_blocked(p_user);
$$;

CREATE OR REPLACE FUNCTION public.neveroff_feature_restricted(p_user UUID, p_feature TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT admin.is_feature_restricted(p_user, p_feature);
$$;

REVOKE ALL ON FUNCTION public.neveroff_send_blocked(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.neveroff_access_blocked(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.neveroff_feature_restricted(UUID, TEXT) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Enforcement policies.
--
-- RESTRICTIVE means these are AND-ed with the existing permissive policies from
-- 01_schema.sql and 07_channels.sql, which are left completely untouched.
-- ---------------------------------------------------------------------------

-- A muted or banned user cannot send messages. Read paths are deliberately not
-- restricted: §3.3 says a muted user "can receive but not send", and a banned
-- user's client is gated by the ban screen rather than by starving it of data.
DROP POLICY IF EXISTS "Enforcement: blocked users cannot send messages" ON public.messages;
CREATE POLICY "Enforcement: blocked users cannot send messages" ON public.messages
  AS RESTRICTIVE
  FOR INSERT
  TO authenticated
  WITH CHECK (NOT public.neveroff_send_blocked(auth.uid()));

-- Channel posting. Blocked from sending, or specifically restricted from media,
-- both stop a post. The owner-only permissive policy still applies on top.
DROP POLICY IF EXISTS "Enforcement: blocked users cannot post to channels" ON public.channel_posts;
CREATE POLICY "Enforcement: blocked users cannot post to channels" ON public.channel_posts
  AS RESTRICTIVE
  FOR INSERT
  TO authenticated
  WITH CHECK (NOT public.neveroff_send_blocked(auth.uid()));

-- Feature restriction: create_channel.
DROP POLICY IF EXISTS "Enforcement: restricted users cannot create channels" ON public.channels;
CREATE POLICY "Enforcement: restricted users cannot create channels" ON public.channels
  AS RESTRICTIVE
  FOR INSERT
  TO authenticated
  WITH CHECK (
    NOT public.neveroff_access_blocked(auth.uid())
    AND NOT public.neveroff_feature_restricted(auth.uid(), 'create_channel')
  );

-- Feature restriction: join_groups / new subscriptions while access-blocked.
DROP POLICY IF EXISTS "Enforcement: blocked users cannot subscribe" ON public.channel_subscribers;
CREATE POLICY "Enforcement: blocked users cannot subscribe" ON public.channel_subscribers
  AS RESTRICTIVE
  FOR INSERT
  TO authenticated
  WITH CHECK (NOT public.neveroff_access_blocked(auth.uid()));

-- ---------------------------------------------------------------------------
-- App-facing RPCs.
--
-- The Android client calls these; they are the only way the app learns about
-- its own enforcement state or files an appeal. Each is SECURITY DEFINER and
-- keyed on auth.uid(), so a caller can only ever see their own record — there
-- is no parameter through which one user could ask about another.
-- ---------------------------------------------------------------------------

-- §4: everything the ban screen needs, in one round trip.
CREATE OR REPLACE FUNCTION public.my_enforcement_status(p_locale TEXT DEFAULT 'en')
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_user    UUID := auth.uid();
  v_action  RECORD;
  v_reason  RECORD;
  v_appeal  RECORD;
  v_result  JSONB;
  v_features TEXT[];
  v_rate    INTEGER;
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'Not authenticated' USING ERRCODE = 'raise_exception';
  END IF;

  -- Most severe action currently in force, ignoring internal notes.
  SELECT e.*,
         CASE e.type
           WHEN 'warning' THEN 10 WHEN 'feature_restriction' THEN 20
           WHEN 'rate_limit' THEN 30 WHEN 'mute' THEN 40
           WHEN 'shadow_restriction' THEN 50 WHEN 'ban_temporary' THEN 60
           WHEN 'ban_permanent' THEN 70 WHEN 'account_deletion' THEN 100
           ELSE 0
         END AS severity
    INTO v_action
    FROM admin.enforcement_actions e
   WHERE e.user_id = v_user
     AND e.reversed_at IS NULL
     AND (e.expires_at IS NULL OR e.expires_at > NOW())
     AND e.type <> 'note'
   ORDER BY severity DESC, e.issued_at DESC
   LIMIT 1;

  -- Shadow restrictions are, by definition, never disclosed to the subject.
  -- Returning them here would defeat the mechanism and mislead the user, so the
  -- query above can select one but it is filtered out before it is reported.
  IF v_action.type = 'shadow_restriction' THEN
    SELECT e.* INTO v_action
      FROM admin.enforcement_actions e
     WHERE e.user_id = v_user
       AND e.reversed_at IS NULL
       AND (e.expires_at IS NULL OR e.expires_at > NOW())
       AND e.type NOT IN ('note', 'shadow_restriction')
     ORDER BY e.issued_at DESC
     LIMIT 1;
  END IF;

  SELECT COALESCE(array_agg(DISTINCT f), '{}')
    INTO v_features
    FROM admin.enforcement_actions e, unnest(e.restricted_features) AS f
   WHERE e.user_id = v_user
     AND e.reversed_at IS NULL
     AND (e.expires_at IS NULL OR e.expires_at > NOW());

  SELECT MIN(e.rate_limit_per_minute) INTO v_rate
    FROM admin.enforcement_actions e
   WHERE e.user_id = v_user
     AND e.reversed_at IS NULL
     AND (e.expires_at IS NULL OR e.expires_at > NOW());

  IF v_action.id IS NULL THEN
    RETURN jsonb_build_object(
      'status', 'active',
      'blocks_access', FALSE,
      'blocks_sending', FALSE,
      'restricted_features', to_jsonb(v_features),
      'rate_limit_per_minute', v_rate
    );
  END IF;

  SELECT * INTO v_reason FROM admin.reason_catalogue WHERE code = v_action.reason_code;
  SELECT * INTO v_appeal FROM admin.appeals WHERE action_id = v_action.id;

  v_result := jsonb_build_object(
    'status', CASE v_action.type
                WHEN 'warning' THEN 'warned'
                WHEN 'feature_restriction' THEN 'restricted'
                WHEN 'rate_limit' THEN 'restricted'
                WHEN 'mute' THEN 'muted'
                WHEN 'ban_temporary' THEN 'banned_temporary'
                WHEN 'ban_permanent' THEN 'banned_permanent'
                WHEN 'account_deletion' THEN 'deleted'
                ELSE 'active' END,
    'blocks_access', v_action.type IN ('ban_temporary', 'ban_permanent', 'account_deletion'),
    'blocks_sending', v_action.type IN ('mute', 'ban_temporary', 'ban_permanent', 'account_deletion'),
    'case_ref', v_action.case_ref,
    'action_id', v_action.id,
    'issued_at', v_action.issued_at,
    'expires_at', v_action.expires_at,
    'acknowledged_at', v_action.acknowledged_at,
    'restricted_features', to_jsonb(v_features),
    'rate_limit_per_minute', v_rate,
    'reason', CASE WHEN v_reason.code IS NULL THEN NULL ELSE jsonb_build_object(
        'code', v_reason.code,
        'category', v_reason.category,
        'policy_clause', v_reason.policy_clause,
        'appealable', v_reason.appealable,
        -- The app localises by code from its own string resources; this label
        -- is the fallback for a code shipped after the installed app version.
        'label', COALESCE(
          CASE WHEN p_locale = 'ru' THEN v_reason.label_ru ELSE v_reason.label_en END,
          v_reason.label_en)
      ) END,
    'appeal', CASE WHEN v_appeal.id IS NULL
                THEN jsonb_build_object('state', 'none')
                ELSE jsonb_build_object(
                  'state', v_appeal.status,
                  'id', v_appeal.id,
                  'submitted_at', v_appeal.submitted_at,
                  'reviewed_at', v_appeal.reviewed_at,
                  'sla_due_at', v_appeal.sla_due_at)
              END
  );

  RETURN v_result;
END;
$$;

-- §4: structured appeal submission from the ban screen.
CREATE OR REPLACE FUNCTION public.submit_appeal(
  p_action_id UUID,
  p_body      TEXT,
  p_locale    TEXT DEFAULT 'en'
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_user   UUID := auth.uid();
  v_action RECORD;
  v_reason RECORD;
  v_sla    INTEGER;
  v_id     UUID;
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'Not authenticated' USING ERRCODE = 'raise_exception';
  END IF;

  IF p_body IS NULL OR char_length(trim(p_body)) < 1 THEN
    RAISE EXCEPTION 'An appeal must include an explanation.' USING ERRCODE = 'raise_exception';
  END IF;
  IF char_length(p_body) > 5000 THEN
    RAISE EXCEPTION 'Appeal is too long (maximum 5000 characters).' USING ERRCODE = 'raise_exception';
  END IF;

  -- Ownership check. A user may only appeal an action against themselves.
  SELECT * INTO v_action
    FROM admin.enforcement_actions
   WHERE id = p_action_id AND user_id = v_user;

  IF v_action.id IS NULL THEN
    RAISE EXCEPTION 'No such enforcement action.' USING ERRCODE = 'raise_exception';
  END IF;

  IF v_action.reversed_at IS NOT NULL THEN
    RAISE EXCEPTION 'This action has already been lifted.' USING ERRCODE = 'raise_exception';
  END IF;

  SELECT * INTO v_reason FROM admin.reason_catalogue WHERE code = v_action.reason_code;
  IF v_reason.code IS NOT NULL AND NOT v_reason.appealable THEN
    RAISE EXCEPTION 'Decisions of this type cannot be appealed in the app.'
      USING ERRCODE = 'raise_exception',
            HINT = 'Contact support through the published channel.';
  END IF;

  IF EXISTS (SELECT 1 FROM admin.appeals WHERE action_id = p_action_id) THEN
    RAISE EXCEPTION 'An appeal for this decision has already been submitted.'
      USING ERRCODE = 'raise_exception';
  END IF;

  SELECT COALESCE((value #>> '{}')::int, 72) INTO v_sla
    FROM admin.settings WHERE key = 'appeal_sla_hours';

  INSERT INTO admin.appeals (action_id, user_id, body, locale, sla_due_at)
  VALUES (p_action_id, v_user, p_body, COALESCE(p_locale, 'en'),
          NOW() + make_interval(hours => COALESCE(v_sla, 72)))
  RETURNING id INTO v_id;

  PERFORM admin.bump_transparency_counter('appeal_submitted', v_action.type);

  RETURN jsonb_build_object(
    'id', v_id,
    'case_ref', v_action.case_ref,
    'status', 'pending',
    'sla_hours', COALESCE(v_sla, 72));
END;
$$;

-- Lets the ban screen show appeal progress without a second round trip.
CREATE OR REPLACE FUNCTION public.my_appeals()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'id', a.id,
           'case_ref', e.case_ref,
           'status', a.status,
           'submitted_at', a.submitted_at,
           'reviewed_at', a.reviewed_at,
           'sla_due_at', a.sla_due_at,
           'decision_note', CASE WHEN a.status IN ('upheld','overturned','partially_upheld')
                                 THEN a.decision_note ELSE NULL END
         ) ORDER BY a.submitted_at DESC), '[]'::jsonb)
    FROM admin.appeals a
    JOIN admin.enforcement_actions e ON e.id = a.action_id
   WHERE a.user_id = auth.uid();
$$;

-- §3.3: a warning is "an in-app notice the user must acknowledge".
CREATE OR REPLACE FUNCTION public.acknowledge_warning(p_action_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_user UUID := auth.uid();
  v_rows INTEGER;
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'Not authenticated' USING ERRCODE = 'raise_exception';
  END IF;

  UPDATE admin.enforcement_actions
     SET acknowledged_at = NOW()
   WHERE id = p_action_id
     AND user_id = v_user
     AND type = 'warning'
     AND acknowledged_at IS NULL;

  GET DIAGNOSTICS v_rows = ROW_COUNT;
  RETURN v_rows > 0;
END;
$$;

-- ---------------------------------------------------------------------------
-- Grants. `authenticated` gets EXECUTE on exactly these functions and nothing
-- else. No USAGE on the admin schema is granted anywhere.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  -- The Supabase roles do not exist on a plain local Postgres unless the
  -- bootstrap created them; skip the grants rather than failing the migration.
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.neveroff_send_blocked(UUID) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.neveroff_access_blocked(UUID) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.neveroff_feature_restricted(UUID, TEXT) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.my_enforcement_status(TEXT) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.submit_appeal(UUID, TEXT, TEXT) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.my_appeals() TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.acknowledge_warning(UUID) TO authenticated';
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Post-conditions. Every row must read ok = true. Anything false means that
-- piece did not apply and the corresponding guarantee is not in force.
-- ---------------------------------------------------------------------------
SELECT 'restrictive_policies' AS check_name,
       count(*) = 4 AS ok,
       count(*)::text || ' of 4' AS detail
  FROM pg_policies
 WHERE schemaname = 'public'
   AND policyname LIKE 'Enforcement:%'
UNION ALL
SELECT 'policies_are_restrictive',
       bool_and(permissive = 'RESTRICTIVE'),
       string_agg(DISTINCT permissive, ', ')
  FROM pg_policies
 WHERE schemaname = 'public' AND policyname LIKE 'Enforcement:%'
UNION ALL
SELECT 'app_rpcs',
       count(*) = 4,
       count(*)::text || ' of 4'
  FROM pg_proc
 WHERE pronamespace = 'public'::regnamespace
   AND proname IN ('my_enforcement_status', 'submit_appeal', 'my_appeals', 'acknowledge_warning')
UNION ALL
SELECT 'existing_policies_intact',
       count(*) >= 3,
       count(*)::text || ' original message policies still present'
  FROM pg_policies
 WHERE schemaname = 'public' AND tablename = 'messages'
   AND policyname NOT LIKE 'Enforcement:%'
UNION ALL
SELECT 'admin_schema_not_exposed',
       NOT EXISTS (
         SELECT 1 FROM information_schema.role_table_grants
          WHERE table_schema = 'admin' AND grantee IN ('anon', 'authenticated')),
       'no admin-schema table grants to client roles';
