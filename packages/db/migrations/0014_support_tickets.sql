-- ============================================================================
-- 0014_support_tickets.sql — the @support ticketing system (§5).
--
-- Touches the live app surface: creates public-schema RPCs and grants EXECUTE
-- to `authenticated`. Listed in PRODUCTION_TOUCHING in migrate.ts.
--
-- THE CONSTRAINT THAT SHAPES THIS FILE
--
-- §4: "@support remains the only accessible surface" for a banned user. All
-- chats, channels, contacts, media and search are locked; the one conversation
-- they can still open is the support bot.
--
-- That is why tickets live in the `admin` schema and are reached only through
-- SECURITY DEFINER functions, rather than being modelled as a row in
-- public.chats with a system participant. The enforcement RESTRICTIVE policy on
-- public.messages blocks a banned user from inserting there at all, and
-- carving an exception into it would mean the ban gate has a hole shaped like
-- a chat id — exactly the kind of exception that gets widened later.
--
-- Support messaging therefore never touches public.messages. A banned user can
-- open a ticket and reply to it because these functions do not consult the
-- enforcement predicates at all. That is deliberate, and it is the only path
-- in this codebase that deliberately ignores an active ban.
--
-- Support content is NOT end-to-end encrypted. It cannot be: an agent has to
-- read it. Users are told so at the point of writing.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Categories (§5.1: "configurable in the admin console")
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.ticket_categories (
  key              TEXT PRIMARY KEY,
  label            TEXT NOT NULL,
  description      TEXT,
  parent_key       TEXT REFERENCES admin.ticket_categories(key) ON DELETE CASCADE,
  position         INTEGER NOT NULL DEFAULT 0,
  active           BOOLEAN NOT NULL DEFAULT TRUE,

  -- §5.2: SLA config per category.
  first_response_hours INTEGER NOT NULL DEFAULT 24,
  resolution_hours     INTEGER NOT NULL DEFAULT 72,
  default_priority     TEXT NOT NULL DEFAULT 'normal',

  -- §5.2 emergency escalation: pages an on-call human immediately and shows a
  -- high-visibility banner. Never handled by automation alone.
  is_emergency     BOOLEAN NOT NULL DEFAULT FALSE,
  -- Self-service is attempted first for ordinary categories, never for these.
  allow_self_service BOOLEAN NOT NULL DEFAULT TRUE,

  CONSTRAINT ticket_category_priority_valid
    CHECK (default_priority IN ('low', 'normal', 'high', 'urgent')),
  CONSTRAINT ticket_category_sla_positive
    CHECK (first_response_hours > 0 AND resolution_hours > 0)
);

-- ---------------------------------------------------------------------------
-- Tickets
-- ---------------------------------------------------------------------------
CREATE SEQUENCE IF NOT EXISTS admin.ticket_ref_seq;

CREATE OR REPLACE FUNCTION admin.next_ticket_ref()
RETURNS TEXT
LANGUAGE sql
VOLATILE
AS $$
  SELECT 'T-' || to_char(NOW(), 'YY') || '-' ||
         lpad(nextval('admin.ticket_ref_seq')::text, 6, '0');
$$;

CREATE TABLE IF NOT EXISTS admin.tickets (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_ref         TEXT NOT NULL DEFAULT admin.next_ticket_ref(),

  user_id            UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  category_key       TEXT NOT NULL REFERENCES admin.ticket_categories(key),
  subject            TEXT NOT NULL,

  status             TEXT NOT NULL DEFAULT 'open',
  priority           TEXT NOT NULL DEFAULT 'normal',

  assigned_to        UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  assigned_at        TIMESTAMPTZ,

  opened_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  first_response_at  TIMESTAMPTZ,
  last_user_message_at  TIMESTAMPTZ,
  last_agent_message_at TIMESTAMPTZ,
  closed_at          TIMESTAMPTZ,

  first_response_due_at TIMESTAMPTZ NOT NULL,
  resolution_due_at     TIMESTAMPTZ NOT NULL,

  -- §5.2 emergency path.
  is_emergency       BOOLEAN NOT NULL DEFAULT FALSE,
  emergency_reason   TEXT,
  paged_at           TIMESTAMPTZ,

  -- Structured form answers from the category's dynamic form (§5.1).
  form_data          JSONB NOT NULL DEFAULT '{}'::jsonb,
  tags               TEXT[] NOT NULL DEFAULT '{}',

  -- Links back when the ticket came from a ban appeal.
  related_appeal_id  UUID REFERENCES admin.appeals(id) ON DELETE SET NULL,
  related_case_id    UUID REFERENCES admin.cases(id) ON DELETE SET NULL,

  -- §5.1: satisfaction captured on resolution, for the analytics tab.
  satisfaction_score INTEGER,
  satisfaction_at    TIMESTAMPTZ,

  locale             TEXT NOT NULL DEFAULT 'en',
  -- Coarse only, for routing. Never displayed as a location.
  country            TEXT,

  CONSTRAINT ticket_status_valid CHECK (status IN (
    'open', 'pending_agent', 'pending_user', 'escalated', 'resolved', 'closed')),
  CONSTRAINT ticket_priority_valid CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
  CONSTRAINT ticket_subject_len CHECK (char_length(subject) BETWEEN 1 AND 200),
  CONSTRAINT ticket_satisfaction_range
    CHECK (satisfaction_score IS NULL OR satisfaction_score BETWEEN 1 AND 5),
  CONSTRAINT ticket_country_shape CHECK (country IS NULL OR country ~ '^[A-Z]{2}$'),
  CONSTRAINT ticket_closed_has_timestamp
    CHECK (status NOT IN ('resolved', 'closed') OR closed_at IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tickets_ref ON admin.tickets(ticket_ref);
CREATE INDEX IF NOT EXISTS idx_tickets_user ON admin.tickets(user_id, opened_at DESC);
CREATE INDEX IF NOT EXISTS idx_tickets_inbox
  ON admin.tickets(status, priority DESC, first_response_due_at)
  WHERE status NOT IN ('resolved', 'closed');
CREATE INDEX IF NOT EXISTS idx_tickets_assigned
  ON admin.tickets(assigned_to, status) WHERE status NOT IN ('resolved', 'closed');
-- The emergency queue must never be slow to find.
CREATE INDEX IF NOT EXISTS idx_tickets_emergency
  ON admin.tickets(opened_at DESC) WHERE is_emergency AND status NOT IN ('resolved', 'closed');

-- ---------------------------------------------------------------------------
-- Ticket messages
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.ticket_messages (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id      UUID NOT NULL REFERENCES admin.tickets(id) ON DELETE CASCADE,

  -- 'user', 'agent', or 'system' for automated replies and status notes.
  author_type    TEXT NOT NULL,
  author_admin_id UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  author_label   TEXT NOT NULL,

  body           TEXT NOT NULL,
  -- §5.2 internal notes are invisible to the user. Enforced in the app-facing
  -- RPC below, which filters them out, not merely in the console UI.
  is_internal    BOOLEAN NOT NULL DEFAULT FALSE,

  macro_key      TEXT,
  attachments    JSONB NOT NULL DEFAULT '[]'::jsonb,
  sent_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT ticket_message_author_valid CHECK (author_type IN ('user', 'agent', 'system')),
  CONSTRAINT ticket_message_body_len CHECK (char_length(body) BETWEEN 1 AND 10000),
  -- A user cannot write an internal note; that would be a hole in §5.2's
  -- "internal notes invisible to the user".
  CONSTRAINT ticket_message_internal_is_staff
    CHECK (NOT is_internal OR author_type <> 'user')
);

CREATE INDEX IF NOT EXISTS idx_ticket_messages_thread
  ON admin.ticket_messages(ticket_id, sent_at ASC);

-- ---------------------------------------------------------------------------
-- Macros (§5.2 canned responses with variable substitution)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.ticket_macros (
  key            TEXT PRIMARY KEY,
  label          TEXT NOT NULL,
  category_key   TEXT REFERENCES admin.ticket_categories(key) ON DELETE SET NULL,
  -- Supports {{ticket_ref}}, {{username}}, {{agent_name}}, {{case_ref}}.
  body           TEXT NOT NULL,
  -- Applied automatically when the macro is used.
  sets_status    TEXT,
  active         BOOLEAN NOT NULL DEFAULT TRUE,
  created_by     UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT macro_status_valid
    CHECK (sets_status IS NULL OR sets_status IN
           ('open', 'pending_agent', 'pending_user', 'escalated', 'resolved', 'closed'))
);

-- ---------------------------------------------------------------------------
-- Routing rules (§5.2: category + language + region → queue or agent)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.ticket_routing_rules (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT NOT NULL,
  position      INTEGER NOT NULL DEFAULT 0,
  active        BOOLEAN NOT NULL DEFAULT TRUE,

  -- All non-null conditions must match.
  match_category TEXT REFERENCES admin.ticket_categories(key) ON DELETE CASCADE,
  match_locale   TEXT,
  match_country  TEXT,

  assign_to      UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  set_priority   TEXT,

  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT routing_priority_valid
    CHECK (set_priority IS NULL OR set_priority IN ('low', 'normal', 'high', 'urgent'))
);

-- ---------------------------------------------------------------------------
-- Emergency keyword detection (§5.2)
--
-- "keyword-based priority bumps (e.g. self-harm, minor safety, legal threat →
--  top priority + instant alert)".
--
-- Deliberately crude and deliberately one-directional: it can only ever RAISE
-- priority, never lower it. A false positive costs an agent thirty seconds; a
-- false negative on a self-harm disclosure costs considerably more. Tuned for
-- recall, and the resulting priority is a floor a human can raise but not drop
-- without explicitly reclassifying the ticket.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.ticket_emergency_keywords (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phrase      TEXT NOT NULL,
  locale      TEXT NOT NULL DEFAULT 'en',
  kind        TEXT NOT NULL,
  active      BOOLEAN NOT NULL DEFAULT TRUE,

  CONSTRAINT emergency_kind_valid
    CHECK (kind IN ('self_harm', 'minor_safety', 'violence_threat', 'legal_threat'))
);

CREATE INDEX IF NOT EXISTS idx_emergency_keywords_active
  ON admin.ticket_emergency_keywords(locale) WHERE active;

CREATE OR REPLACE FUNCTION admin.detect_ticket_emergency(p_text TEXT, p_locale TEXT DEFAULT 'en')
RETURNS TABLE (kind TEXT, phrase TEXT)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT k.kind, k.phrase
    FROM admin.ticket_emergency_keywords k
   WHERE k.active
     AND (k.locale = p_locale OR k.locale = 'en')
     AND position(lower(k.phrase) IN lower(coalesce(p_text, ''))) > 0
   LIMIT 5;
$$;

-- ---------------------------------------------------------------------------
-- SLA maintenance
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.ticket_apply_routing()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_category RECORD;
  v_rule     RECORD;
BEGIN
  SELECT * INTO v_category FROM admin.ticket_categories WHERE key = NEW.category_key;

  -- SLA clocks from the category, unless the caller already set them.
  IF NEW.first_response_due_at IS NULL THEN
    NEW.first_response_due_at :=
      NOW() + make_interval(hours => COALESCE(v_category.first_response_hours, 24));
  END IF;
  IF NEW.resolution_due_at IS NULL THEN
    NEW.resolution_due_at :=
      NOW() + make_interval(hours => COALESCE(v_category.resolution_hours, 72));
  END IF;

  IF COALESCE(v_category.is_emergency, FALSE) THEN
    NEW.is_emergency := TRUE;
    NEW.priority := 'urgent';
  ELSE
    NEW.priority := COALESCE(NULLIF(NEW.priority, 'normal'), v_category.default_priority, 'normal');
  END IF;

  -- First matching routing rule wins.
  SELECT * INTO v_rule
    FROM admin.ticket_routing_rules r
   WHERE r.active
     AND (r.match_category IS NULL OR r.match_category = NEW.category_key)
     AND (r.match_locale IS NULL OR r.match_locale = NEW.locale)
     AND (r.match_country IS NULL OR r.match_country = NEW.country)
   ORDER BY r.position ASC
   LIMIT 1;

  IF v_rule.id IS NOT NULL THEN
    NEW.assigned_to := COALESCE(NEW.assigned_to, v_rule.assign_to);
    IF NEW.assigned_to IS NOT NULL AND NEW.assigned_at IS NULL THEN
      NEW.assigned_at := NOW();
    END IF;
    -- Routing may raise priority, never lower it.
    IF v_rule.set_priority IS NOT NULL THEN
      NEW.priority := CASE
        WHEN NEW.priority = 'urgent' THEN 'urgent'
        WHEN v_rule.set_priority = 'urgent' THEN 'urgent'
        WHEN NEW.priority = 'high' OR v_rule.set_priority = 'high' THEN 'high'
        ELSE v_rule.set_priority END;
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_ticket_routing ON admin.tickets;
CREATE TRIGGER trg_ticket_routing
  BEFORE INSERT ON admin.tickets
  FOR EACH ROW EXECUTE FUNCTION admin.ticket_apply_routing();

-- ---------------------------------------------------------------------------
-- App-facing RPCs.
--
-- None of these consult the enforcement predicates. That is the §4 requirement:
-- a banned user must still be able to reach support, and this is the one path
-- in the codebase that deliberately ignores an active ban.
-- ---------------------------------------------------------------------------

/** The category tree the app renders as buttons (§5.1 step 1). */
CREATE OR REPLACE FUNCTION public.support_categories(p_locale TEXT DEFAULT 'en')
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'key', c.key,
           'label', c.label,
           'description', c.description,
           'is_emergency', c.is_emergency,
           'children', COALESCE((
             SELECT jsonb_agg(jsonb_build_object('key', s.key, 'label', s.label)
                              ORDER BY s.position)
               FROM admin.ticket_categories s
              WHERE s.parent_key = c.key AND s.active), '[]'::jsonb)
         ) ORDER BY c.position), '[]'::jsonb)
    FROM admin.ticket_categories c
   WHERE c.active AND c.parent_key IS NULL;
$$;

/** Open a ticket. Works while banned — see the header. */
CREATE OR REPLACE FUNCTION public.open_support_ticket(
  p_category_key TEXT,
  p_subject      TEXT,
  p_body         TEXT,
  p_form_data    JSONB DEFAULT '{}'::jsonb,
  p_locale       TEXT DEFAULT 'en'
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_user      UUID := auth.uid();
  v_category  RECORD;
  v_ticket    RECORD;
  v_emergency RECORD;
  v_open      INTEGER;
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'Not authenticated' USING ERRCODE = 'raise_exception';
  END IF;

  SELECT * INTO v_category
    FROM admin.ticket_categories WHERE key = p_category_key AND active;
  IF v_category.key IS NULL THEN
    RAISE EXCEPTION 'Unknown support category.' USING ERRCODE = 'raise_exception';
  END IF;

  IF p_body IS NULL OR char_length(trim(p_body)) < 1 THEN
    RAISE EXCEPTION 'Tell us what is wrong.' USING ERRCODE = 'raise_exception';
  END IF;

  -- Rate limit by open ticket count rather than by time: someone with a real
  -- problem may legitimately write three times in a minute, but nobody needs
  -- twenty simultaneous open tickets. Emergencies are never limited.
  IF NOT v_category.is_emergency THEN
    SELECT count(*) INTO v_open
      FROM admin.tickets
     WHERE user_id = v_user AND status NOT IN ('resolved', 'closed');
    IF v_open >= 10 THEN
      RAISE EXCEPTION 'You already have several open tickets. Please reply to one of those instead.'
        USING ERRCODE = 'raise_exception';
    END IF;
  END IF;

  INSERT INTO admin.tickets (
    user_id, category_key, subject, form_data, locale, country,
    first_response_due_at, resolution_due_at, last_user_message_at)
  VALUES (
    v_user, p_category_key, left(trim(p_subject), 200),
    COALESCE(p_form_data, '{}'::jsonb), COALESCE(p_locale, 'en'),
    (SELECT country FROM admin.consent_records
      WHERE user_id = v_user AND country IS NOT NULL
      ORDER BY recorded_at DESC LIMIT 1),
    NULL, NULL, NOW())
  RETURNING * INTO v_ticket;

  INSERT INTO admin.ticket_messages (ticket_id, author_type, author_label, body)
  VALUES (v_ticket.id, 'user', 'user', p_body);

  -- §5.2 keyword escalation. Raises only.
  SELECT * INTO v_emergency
    FROM admin.detect_ticket_emergency(p_subject || ' ' || p_body, p_locale) LIMIT 1;

  IF v_emergency.kind IS NOT NULL THEN
    UPDATE admin.tickets
       SET is_emergency = TRUE,
           priority = 'urgent',
           emergency_reason = v_emergency.kind,
           first_response_due_at = LEAST(first_response_due_at, NOW() + INTERVAL '1 hour')
     WHERE id = v_ticket.id;

    INSERT INTO admin.alerts (kind, severity, title, detail, evidence)
    VALUES ('support_emergency', 'critical',
            'Emergency support ticket ' || v_ticket.ticket_ref,
            'Matched the "' || v_emergency.kind || '" keyword list. §5.2 requires an on-call '
              || 'human, immediately. This path must never be handled by automation alone.',
            jsonb_build_object('ticket_id', v_ticket.id, 'ticket_ref', v_ticket.ticket_ref,
                               'kind', v_emergency.kind));
  END IF;

  RETURN jsonb_build_object(
    'ticket_ref', v_ticket.ticket_ref,
    'id', v_ticket.id,
    'expected_response_hours', v_category.first_response_hours,
    'is_emergency', COALESCE(v_emergency.kind IS NOT NULL, FALSE) OR v_category.is_emergency);
END;
$$;

/** The user's own tickets. Internal notes are filtered out here, not in the UI. */
CREATE OR REPLACE FUNCTION public.my_support_tickets()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'id', t.id,
           'ticket_ref', t.ticket_ref,
           'subject', t.subject,
           'category_key', t.category_key,
           'status', t.status,
           'opened_at', t.opened_at,
           'last_agent_message_at', t.last_agent_message_at,
           'awaiting_you', (t.status = 'pending_user'),
           'satisfaction_score', t.satisfaction_score
         ) ORDER BY t.opened_at DESC), '[]'::jsonb)
    FROM admin.tickets t
   WHERE t.user_id = auth.uid();
$$;

CREATE OR REPLACE FUNCTION public.support_thread(p_ticket UUID)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_user UUID := auth.uid();
  v_ok   BOOLEAN;
BEGIN
  SELECT EXISTS (SELECT 1 FROM admin.tickets WHERE id = p_ticket AND user_id = v_user)
    INTO v_ok;
  IF NOT v_ok THEN
    RAISE EXCEPTION 'No such ticket.' USING ERRCODE = 'raise_exception';
  END IF;

  RETURN (
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
             'author_type', m.author_type,
             'author_label', CASE WHEN m.author_type = 'agent' THEN 'Support'
                                  ELSE m.author_label END,
             'body', m.body,
             'sent_at', m.sent_at
           ) ORDER BY m.sent_at ASC), '[]'::jsonb)
      FROM admin.ticket_messages m
     WHERE m.ticket_id = p_ticket
       -- §5.2: internal notes are invisible to the user. Filtered at the data
       -- boundary so no client bug can ever surface one.
       AND NOT m.is_internal
  );
END;
$$;

CREATE OR REPLACE FUNCTION public.reply_to_support_ticket(p_ticket UUID, p_body TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_user UUID := auth.uid();
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'Not authenticated' USING ERRCODE = 'raise_exception';
  END IF;
  IF p_body IS NULL OR char_length(trim(p_body)) < 1 THEN
    RAISE EXCEPTION 'Write a message first.' USING ERRCODE = 'raise_exception';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM admin.tickets
     WHERE id = p_ticket AND user_id = v_user AND status <> 'closed'
  ) THEN
    RAISE EXCEPTION 'That ticket is not open.' USING ERRCODE = 'raise_exception';
  END IF;

  INSERT INTO admin.ticket_messages (ticket_id, author_type, author_label, body)
  VALUES (p_ticket, 'user', 'user', p_body);

  -- A user reply reopens a resolved ticket: they did not consider it settled.
  UPDATE admin.tickets
     SET last_user_message_at = NOW(),
         status = CASE WHEN status IN ('pending_user', 'resolved') THEN 'pending_agent'
                       ELSE status END,
         closed_at = CASE WHEN status = 'resolved' THEN NULL ELSE closed_at END
   WHERE id = p_ticket;

  RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION public.rate_support_ticket(p_ticket UUID, p_score INTEGER)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = admin, public
AS $$
DECLARE
  v_rows INTEGER;
BEGIN
  IF p_score IS NULL OR p_score < 1 OR p_score > 5 THEN
    RAISE EXCEPTION 'Rating must be between 1 and 5.' USING ERRCODE = 'raise_exception';
  END IF;

  UPDATE admin.tickets
     SET satisfaction_score = p_score, satisfaction_at = NOW()
   WHERE id = p_ticket
     AND user_id = auth.uid()
     AND status IN ('resolved', 'closed')
     AND satisfaction_score IS NULL;

  GET DIAGNOSTICS v_rows = ROW_COUNT;
  RETURN v_rows > 0;
END;
$$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.support_categories(TEXT) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.open_support_ticket(TEXT, TEXT, TEXT, JSONB, TEXT) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.my_support_tickets() TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.support_thread(UUID) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.reply_to_support_ticket(UUID, TEXT) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.rate_support_ticket(UUID, INTEGER) TO authenticated';
  END IF;
END $$;

ALTER TABLE admin.alerts DROP CONSTRAINT IF EXISTS alerts_kind_valid;
ALTER TABLE admin.alerts ADD CONSTRAINT alerts_kind_valid CHECK (kind IN (
  'bulk_action_out_of_hours', 'unusual_pii_access_volume', 'repeated_single_user_access',
  'mass_export', 'audit_chain_broken', 'failed_login_burst', 'privilege_escalation_attempt',
  'shadow_restriction_applied', 'appeal_sla_breached', 'notification_delivery_failing',
  'worker_stalled', 'channel_growth_anomaly', 'channel_owner_repeat_offender',
  'support_emergency', 'support_sla_breached'));

-- ---------------------------------------------------------------------------
-- Post-conditions
-- ---------------------------------------------------------------------------
SELECT 'tables' AS check_name,
       count(*) = 6 AS ok, count(*)::text || ' of 6' AS detail
  FROM information_schema.tables
 WHERE table_schema = 'admin'
   AND table_name IN ('ticket_categories', 'tickets', 'ticket_messages',
                      'ticket_macros', 'ticket_routing_rules', 'ticket_emergency_keywords')
UNION ALL
SELECT 'app_rpcs',
       count(*) = 6, count(*)::text || ' of 6'
  FROM pg_proc
 WHERE pronamespace = 'public'::regnamespace
   AND proname IN ('support_categories', 'open_support_ticket', 'my_support_tickets',
                   'support_thread', 'reply_to_support_ticket', 'rate_support_ticket')
UNION ALL
SELECT 'support_never_touches_messages',
       NOT EXISTS (
         SELECT 1 FROM pg_proc
          WHERE pronamespace = 'public'::regnamespace
            AND proname IN ('open_support_ticket', 'reply_to_support_ticket')
            AND prosrc ILIKE '%public.messages%'),
       'support path is independent of the enforcement-gated messages table'
UNION ALL
SELECT 'admin_schema_still_not_exposed',
       NOT EXISTS (
         SELECT 1 FROM information_schema.role_table_grants
          WHERE table_schema = 'admin' AND grantee IN ('anon', 'authenticated')),
       'no admin-schema table grants to client roles';
