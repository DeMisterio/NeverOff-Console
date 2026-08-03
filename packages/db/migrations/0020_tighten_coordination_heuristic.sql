-- ============================================================================
-- 0020_tighten_coordination_heuristic.sql — the brigading detector was firing
-- on ordinary reports.
--
-- WHAT RUNNING IT SHOWED
--
-- The seed files five legitimate reports against one channel from five
-- unrelated users. detect_coordination flagged it as suspected brigading, and
-- case_priority duly multiplied its score by 0.4.
--
-- The cause is the `no_reporting_history` signal standing on its own: it fires
-- when every reporter is filing their first report and there are at least five
-- of them. On a real platform that is not brigading — it is what a genuinely
-- bad channel looks like. Most people never report anything until the one time
-- they do, so the modal genuine report comes from a first-time reporter.
--
-- Deprioritising those by 60% is worse than not detecting brigading at all: it
-- systematically pushes real mass-reports down the queue, which is precisely
-- the outcome a brigade wants and precisely the outcome an honest crowd does
-- not deserve.
--
-- THE CHANGE
--
-- Brigading's actual signature is *coordination in time*. A burst is now
-- necessary: the account-quality signals (new accounts, no history) only mark a
-- case as suspected when they co-occur with many reports inside a few minutes.
-- The signals are still recorded individually so a moderator can see what was
-- observed — only the conclusion is stricter.
-- ============================================================================

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
  v_burst          BOOLEAN := FALSE;
BEGIN
  SELECT count(*) INTO v_total FROM admin.reports WHERE case_id = p_case;
  IF v_total < 5 THEN
    RETURN v_signals;
  END IF;

  SELECT EXTRACT(EPOCH FROM (MAX(submitted_at) - MIN(submitted_at))) / 60.0
    INTO v_burst_minutes
    FROM admin.reports WHERE case_id = p_case;

  -- Necessary condition. Reports trickling in over hours or days are not
  -- coordinated however new the accounts are.
  v_burst := COALESCE(v_burst_minutes, 999) < 10;

  IF NOT v_burst THEN
    RETURN v_signals;
  END IF;

  v_signals := v_signals || jsonb_build_object(
    'signal', 'burst',
    'detail', v_total || ' reports within ' || round(COALESCE(v_burst_minutes, 0), 1) || ' minutes');

  SELECT count(*) INTO v_new_accounts
    FROM admin.reports r
    JOIN public.profiles p ON p.id = r.reporter_id
   WHERE r.case_id = p_case AND p.created_at > NOW() - INTERVAL '7 days';

  IF v_new_accounts::numeric / v_total > 0.5 THEN
    v_signals := v_signals || jsonb_build_object(
      'signal', 'new_accounts',
      'detail', v_new_accounts || ' of ' || v_total || ' reporters registered in the last week');
  END IF;

  SELECT count(*) INTO v_no_history
    FROM admin.reports r
    LEFT JOIN admin.reporter_reputation rep ON rep.user_id = r.reporter_id
   WHERE r.case_id = p_case
     AND COALESCE(rep.reports_filed, 0) <= 1;

  IF v_no_history = v_total THEN
    v_signals := v_signals || jsonb_build_object(
      'signal', 'no_reporting_history',
      'detail', 'every reporter is filing their first report');
  END IF;

  -- A burst on its own is not enough either: a channel posting something
  -- egregious genuinely does get reported by many people at once. Require the
  -- burst AND at least one account-quality signal before drawing a conclusion.
  IF jsonb_array_length(v_signals) < 2 THEN
    RETURN '[]'::jsonb;
  END IF;

  RETURN v_signals;
END;
$$;

-- Recompute every open case against the tightened rule, so existing flags are
-- not left behind by a heuristic that no longer holds.
DO $$
DECLARE
  r RECORD;
BEGIN
  FOR r IN SELECT id FROM admin.cases WHERE status NOT IN ('resolved', 'dismissed')
  LOOP
    PERFORM admin.refresh_case(r.id);
  END LOOP;
END $$;

SELECT 'coordination_requires_a_burst' AS check_name,
       NOT EXISTS (
         SELECT 1 FROM admin.cases
          WHERE coordinated_suspected
            AND NOT (coordination_signals @> '[{"signal":"burst"}]'::jsonb)
       ) AS ok,
       'no case is flagged without reports clustering in time' AS detail;
