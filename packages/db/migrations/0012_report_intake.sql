-- ============================================================================
-- 0012_report_intake.sql — the app-facing reporting RPC (§6.1–6.3).
--
-- Touches the live app surface: creates functions in `public` and grants
-- EXECUTE to `authenticated`. Listed in PRODUCTION_TOUCHING in migrate.ts, so
-- applying it to a non-local host requires PRODUCTION_MIGRATION_ACK.
--
-- One entry point, `public.submit_report`, keyed on auth.uid(). It clusters
-- into cases, captures evidence, and routes the two categories that must never
-- reach the ordinary queue.
--
-- ROUTING RULES, in the order they are applied:
--
--   1. child_safety  → admin.child_safety_cases, the isolated pipeline (§6.7).
--                      Never touches admin.cases, so no general queue query can
--                      surface it and no analytics rollup can count it.
--   2. self_harm     → flagged for the safety escalation path (§6.2). A person
--                      disclosing risk is not committing a violation, so this
--                      creates a case marked for escalation rather than one
--                      headed towards enforcement.
--   3. everything else → ordinary clustered case.
--
-- EVIDENCE AND E2EE. `p_evidence_text` is content the *reporter's own device*
-- decrypted and chose to submit. The server cannot obtain it any other way for
-- a private message. Passing NULL is legitimate and produces a metadata-only
-- report: still actionable on pattern, but no moderator will ever see the text.
-- ============================================================================

-- Extend the notification taxonomy for the reporter feedback loop (§6.4).
ALTER TABLE admin.notification_outbox DROP CONSTRAINT IF EXISTS notification_kind_valid;
ALTER TABLE admin.notification_outbox ADD CONSTRAINT notification_kind_valid CHECK (kind IN (
  'enforcement_applied', 'enforcement_expired', 'enforcement_reversed',
  'appeal_received', 'appeal_decided', 'admin_message', 'warning_issued',
  'report_outcome', 'report_abuse_warning'));

-- ---------------------------------------------------------------------------
-- Resolve who owns a reported object, using metadata only.
--
-- Note this reads messages.sender_id, not message content. Sender, timestamp
-- and conversation membership are unencrypted metadata; the ciphertext is not
-- touched.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.resolve_report_target(p_type TEXT, p_id TEXT)
RETURNS TABLE (owner_id UUID, label TEXT, exists_now BOOLEAN)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
BEGIN
  IF p_type = 'message' THEN
    RETURN QUERY
      SELECT m.sender_id, 'message from @' || COALESCE(p.username, 'unknown'), TRUE
        FROM public.messages m
        LEFT JOIN public.profiles p ON p.id = m.sender_id
       WHERE m.id::text = p_id;

  ELSIF p_type = 'user' THEN
    RETURN QUERY
      SELECT p.id, '@' || p.username, TRUE
        FROM public.profiles p WHERE p.id::text = p_id;

  ELSIF p_type = 'channel' THEN
    RETURN QUERY
      SELECT c.owner_id, c.name || ' (@' || c.username || ')', TRUE
        FROM public.channels c WHERE c.id::text = p_id;

  ELSIF p_type = 'channel_post' THEN
    RETURN QUERY
      SELECT cp.author_id, 'post in ' || COALESCE(c.name, 'a channel'), TRUE
        FROM public.channel_posts cp
        LEFT JOIN public.channels c ON c.id = cp.channel_id
       WHERE cp.id::text = p_id;

  ELSE
    -- media / bot / call: no server-side object to resolve an owner from.
    RETURN QUERY SELECT NULL::uuid, p_type || ' ' || left(p_id, 12), FALSE;
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- May this user report this object?
--
-- Prevents message-ID enumeration: you can only report a message in a
-- conversation you are actually part of. Without this, an attacker could walk
-- UUIDs and learn which ones exist from the difference between "reported" and
-- "no such message".
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.may_report(p_user UUID, p_type TEXT, p_id TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
BEGIN
  IF p_type = 'message' THEN
    RETURN EXISTS (
      SELECT 1 FROM public.messages m
       JOIN public.chat_participants cp ON cp.chat_id = m.chat_id
      WHERE m.id::text = p_id AND cp.user_id = p_user);
  END IF;

  -- Channels and posts are readable by any signed-in user, and profiles are
  -- public, so anyone who can see them can report them.
  IF p_type IN ('channel', 'channel_post', 'user') THEN
    RETURN TRUE;
  END IF;

  RETURN TRUE;
END;
$$;

-- ---------------------------------------------------------------------------
-- The intake RPC
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.submit_report(
  p_target_type        TEXT,
  p_target_id          TEXT,
  p_reason_code        TEXT,
  p_note               TEXT DEFAULT NULL,
  p_outcome_preference TEXT DEFAULT 'just_report',
  -- Content the reporter's device decrypted and chose to share. NULL is fine.
  p_evidence_text      TEXT DEFAULT NULL,
  -- Surrounding messages, only when the reporter opted in (§6.1).
  p_context            JSONB DEFAULT NULL,
  p_context_consented  BOOLEAN DEFAULT FALSE,
  p_media_sha256       TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_user       UUID := auth.uid();
  v_reason     RECORD;
  v_target     RECORD;
  v_case       UUID;
  v_report     UUID;
  v_rate_limit TIMESTAMPTZ;
  v_isolated   UUID;
  v_blur       BOOLEAN := FALSE;
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'Not authenticated' USING ERRCODE = 'raise_exception';
  END IF;

  SELECT * INTO v_reason FROM admin.reason_catalogue WHERE code = p_reason_code;
  IF v_reason.code IS NULL THEN
    RAISE EXCEPTION 'Unknown reason code.' USING ERRCODE = 'raise_exception';
  END IF;

  IF NOT admin.may_report(v_user, p_target_type, p_target_id) THEN
    -- Same message whether the object is missing or simply not theirs to see,
    -- so this cannot be used to probe for existence.
    RAISE EXCEPTION 'That content is not available to report.'
      USING ERRCODE = 'raise_exception';
  END IF;

  -- §6.3: serial false reporters are rate-limited, having first been told.
  SELECT rate_limited_until INTO v_rate_limit
    FROM admin.reporter_reputation WHERE user_id = v_user;
  IF v_rate_limit IS NOT NULL AND v_rate_limit > NOW() THEN
    RAISE EXCEPTION 'You have reached the reporting limit on your account.'
      USING ERRCODE = 'raise_exception',
            HINT = 'This limit is applied when reports are repeatedly found to be inaccurate.';
  END IF;

  SELECT * INTO v_target FROM admin.resolve_report_target(p_target_type, p_target_id);

  IF v_target.owner_id = v_user THEN
    RAISE EXCEPTION 'You cannot report your own content.' USING ERRCODE = 'raise_exception';
  END IF;

  -- Graphic categories are blurred by default for the moderator (§6.8).
  v_blur := v_reason.category IN ('adult_sexual', 'violence', 'child_safety');

  -- ---------------------------------------------------------------------
  -- 1. Child safety — isolated pipeline. Returns before any ordinary case
  --    machinery runs, so this never touches admin.cases at all.
  -- ---------------------------------------------------------------------
  IF v_reason.isolated THEN
    INSERT INTO admin.child_safety_cases (reported_user_id, reason_code)
    VALUES (v_target.owner_id, p_reason_code)
    RETURNING id INTO v_isolated;

    -- Deliberately no evidence row and no reporter linkage in the general
    -- tables: §6.7 requires this content never pass through general tooling,
    -- general logging, or third-party analytics.
    RETURN jsonb_build_object(
      'status', 'received',
      'routing', 'priority_review',
      'message', 'This report has been sent for immediate specialist review.');
  END IF;

  -- ---------------------------------------------------------------------
  -- 2. Ordinary clustering: find the open case for this target, or open one.
  --    The unique partial index on (target_type, target_id) WHERE not resolved
  --    makes this race-safe — a concurrent insert loses and falls through to
  --    the SELECT.
  -- ---------------------------------------------------------------------
  SELECT id INTO v_case
    FROM admin.cases
   WHERE target_type = p_target_type
     AND target_id = p_target_id
     AND status NOT IN ('resolved', 'dismissed')
   FOR UPDATE;

  IF v_case IS NULL THEN
    INSERT INTO admin.cases (
      target_type, target_id, target_owner_id, target_label,
      primary_reason_code, primary_category, status,
      sla_due_at, escalated_at, escalation_note)
    VALUES (
      p_target_type, p_target_id, v_target.owner_id, v_target.label,
      p_reason_code, v_reason.category, 'open',
      -- Safety categories get a much tighter clock than ordinary abuse.
      NOW() + CASE WHEN v_reason.category = 'self_harm' THEN INTERVAL '1 hour'
                   WHEN v_reason.category IN ('violence', 'hate_speech') THEN INTERVAL '4 hours'
                   ELSE INTERVAL '48 hours' END,
      -- §6.2: self-harm routes to the safety escalation path immediately,
      -- not to the ordinary queue.
      CASE WHEN v_reason.category = 'self_harm' THEN NOW() ELSE NULL END,
      CASE WHEN v_reason.category = 'self_harm'
           THEN 'Auto-escalated: self-harm disclosure. Handle via the safety '
                || 'escalation path, not enforcement. Never automation alone.'
           ELSE NULL END)
    ON CONFLICT (target_type, target_id)
      WHERE status NOT IN ('resolved', 'dismissed')
      DO NOTHING
    RETURNING id INTO v_case;

    IF v_case IS NULL THEN
      SELECT id INTO v_case FROM admin.cases
       WHERE target_type = p_target_type AND target_id = p_target_id
         AND status NOT IN ('resolved', 'dismissed');
    END IF;
  END IF;

  -- ---------------------------------------------------------------------
  -- 3. The report itself. A repeat submission by the same reporter updates
  --    their existing report rather than inflating the count.
  -- ---------------------------------------------------------------------
  INSERT INTO admin.reports (
    reporter_id, target_type, target_id, target_owner_id,
    reason_code, reporter_note, outcome_preference, case_id, reporter_country)
  VALUES (
    v_user, p_target_type, p_target_id, v_target.owner_id,
    p_reason_code, p_note, COALESCE(p_outcome_preference, 'just_report'), v_case,
    (SELECT country FROM admin.consent_records
      WHERE user_id = v_user AND country IS NOT NULL
      ORDER BY recorded_at DESC LIMIT 1))
  ON CONFLICT (reporter_id, target_type, target_id)
    WHERE reporter_id IS NOT NULL
    DO UPDATE SET
      reason_code = EXCLUDED.reason_code,
      reporter_note = EXCLUDED.reporter_note,
      submitted_at = NOW(),
      case_id = EXCLUDED.case_id
  RETURNING id INTO v_report;

  -- ---------------------------------------------------------------------
  -- 4. Evidence snapshot (§6.3), immutable once written.
  -- ---------------------------------------------------------------------
  IF p_evidence_text IS NOT NULL OR p_media_sha256 IS NOT NULL THEN
    INSERT INTO admin.evidence_snapshots (
      report_id, case_id, source, content_text, context_text, context_consented,
      media_sha256, requires_blur, metadata)
    VALUES (
      v_report, v_case,
      -- Messages and chat media can only ever be reporter-submitted; channel
      -- content is plaintext server-side, but when the reporter supplies it we
      -- record it honestly as what it is.
      'reporter_submitted',
      p_evidence_text,
      CASE WHEN p_context_consented THEN p_context ELSE NULL END,
      COALESCE(p_context_consented, FALSE),
      p_media_sha256,
      v_blur,
      jsonb_build_object(
        'target_type', p_target_type,
        'target_id', p_target_id,
        'captured_by_reporter', TRUE));
  END IF;

  -- ---------------------------------------------------------------------
  -- 5. Recompute counts, category, coordination signals and priority.
  -- ---------------------------------------------------------------------
  PERFORM admin.refresh_case(v_case);
  PERFORM admin.bump_transparency_counter('report_received', v_reason.category);

  RETURN jsonb_build_object(
    'status', 'received',
    'routing', CASE WHEN v_reason.category = 'self_harm' THEN 'safety_escalation'
                    ELSE 'moderation_queue' END,
    'message', CASE
      WHEN v_reason.category = 'self_harm'
        THEN 'Thank you. Someone will look at this urgently. If you or someone '
             || 'else is in immediate danger, please contact your local emergency services.'
      ELSE 'Thank you. We will review this and let you know the outcome.'
    END);
END;
$$;

-- ---------------------------------------------------------------------------
-- Defence in depth: a self-harm reason code may never appear on an enforcement
-- action.
--
-- The API service layer already refuses this, but that refusal lives in
-- TypeScript and applies only to paths that go through it. Someone disclosing
-- that they are at risk has not violated anything, and punishing them for it
-- removes the support network they just reached for. This is the one place a
-- reason code is categorically not a violation, so it is worth a hard stop.
--
-- Isolated (child safety) codes are deliberately NOT blocked: §6.7's pipeline
-- legitimately applies an immediate suspension on a confirmed match, and
-- child_safety_cases.suspension_action_id points at exactly such a row.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.reject_self_harm_enforcement()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM admin.reason_catalogue
     WHERE code = NEW.reason_code AND category = 'self_harm'
  ) THEN
    RAISE EXCEPTION
      'Self-harm reasons cannot be used for enforcement. Route this through the safety escalation path.'
      USING ERRCODE = 'raise_exception',
            HINT = 'A person disclosing risk has not committed a violation.';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_reject_self_harm_enforcement ON admin.enforcement_actions;
CREATE TRIGGER trg_reject_self_harm_enforcement
  BEFORE INSERT OR UPDATE ON admin.enforcement_actions
  FOR EACH ROW EXECUTE FUNCTION admin.reject_self_harm_enforcement();

-- ---------------------------------------------------------------------------
-- Reporter's own history. Deliberately does NOT expose the case, the reported
-- party's status, or what action was taken — only that their report was
-- reviewed and whether it led to action, in generic terms (§6.4).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.my_reports()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'submitted_at', r.submitted_at,
           'reason_code', r.reason_code,
           'target_type', r.target_type,
           'state', CASE
             WHEN c.status IN ('resolved') THEN 'reviewed_action_taken'
             WHEN c.status IN ('dismissed') THEN 'reviewed_no_violation'
             WHEN c.id IS NULL THEN 'received'
             ELSE 'under_review' END
         ) ORDER BY r.submitted_at DESC), '[]'::jsonb)
    FROM admin.reports r
    LEFT JOIN admin.cases c ON c.id = r.case_id
   WHERE r.reporter_id = auth.uid();
$$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.submit_report(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, BOOLEAN, TEXT) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.my_reports() TO authenticated';
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Post-conditions
-- ---------------------------------------------------------------------------
SELECT 'intake_rpcs' AS check_name,
       count(*) = 2 AS ok,
       count(*)::text || ' of 2' AS detail
  FROM pg_proc
 WHERE pronamespace = 'public'::regnamespace
   AND proname IN ('submit_report', 'my_reports')
UNION ALL
SELECT 'helper_functions',
       count(*) = 2,
       count(*)::text || ' of 2'
  FROM pg_proc
 WHERE pronamespace = 'admin'::regnamespace
   AND proname IN ('resolve_report_target', 'may_report')
UNION ALL
SELECT 'admin_schema_still_not_exposed',
       NOT EXISTS (
         SELECT 1 FROM information_schema.role_table_grants
          WHERE table_schema = 'admin' AND grantee IN ('anon', 'authenticated')),
       'no admin-schema table grants to client roles';
