-- ============================================================================
-- 0005_child_safety_scaffold.sql — §6.7 isolated pipeline. SCAFFOLD ONLY.
--
-- READ THIS BEFORE TOUCHING ANYTHING IN THIS FILE.
--
-- What is built here:
--   - An isolated case table that no general moderation query can reach.
--   - A named allowlist: holding the childsafety.access permission is necessary
--     but not sufficient; the account must also be on the allowlist.
--   - Per-view audit logging, separate from the general audit surface.
--   - Automatic legal hold on every case, so retention purging cannot reach it.
--   - Routing hooks so a report in this category never lands in the ordinary
--     queue in the first place.
--
-- What is deliberately NOT built, pending legal counsel (§13):
--   - Hash-matching against known-CSAM databases (PhotoDNA or equivalent).
--     Access to those corpora is contractual and jurisdiction-specific.
--   - The mandatory reporting workflow to NCMEC or the local equivalent. The
--     content, timing, format and retention obligations of that report are set
--     by statute, not by product design, and getting them wrong carries
--     criminal exposure.
--   - Any evidence-preservation scheme beyond the legal hold flag. What must be
--     preserved, for how long, and in what form is a question for counsel.
--
-- The stub tables for those exist so the shape is visible and the integration
-- points are obvious, but the API refuses every operation against them and
-- returns an explicit "not implemented pending legal sign-off" error. That is
-- intentional: a half-implemented mandatory-reporting path that silently fails
-- is worse than no path at all, because it looks like compliance.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Named allowlist (§6.7: "a restricted, specially-trained team")
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.child_safety_allowlist (
  admin_id      UUID PRIMARY KEY REFERENCES admin.admin_users(id) ON DELETE CASCADE,
  added_by      UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  added_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Evidence that the statutory / contractual training requirement was met.
  training_ref  TEXT NOT NULL,
  training_completed_at TIMESTAMPTZ NOT NULL,
  -- Access lapses unless renewed; nobody keeps this permission by inertia.
  expires_at    TIMESTAMPTZ NOT NULL,
  revoked_at    TIMESTAMPTZ,
  revoked_by    UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  revoke_reason TEXT
);

CREATE OR REPLACE FUNCTION admin.is_child_safety_authorised(p_admin UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = admin, public
AS $$
  -- Both conditions, always. The permission atom alone never suffices.
  SELECT EXISTS (
    SELECT 1
      FROM admin.child_safety_allowlist a
      JOIN admin.admin_users u ON u.id = a.admin_id
     WHERE a.admin_id = p_admin
       AND a.revoked_at IS NULL
       AND a.expires_at > NOW()
       AND u.status = 'active'
  );
$$;

-- ---------------------------------------------------------------------------
-- Isolated case table
--
-- Never joined to admin.cases, never surfaced by a general queue query, and
-- never included in an analytics rollup or a third-party export (§6.7).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.child_safety_cases (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_ref           TEXT NOT NULL DEFAULT admin.next_case_ref(),

  -- Subject is referenced by ID only. No denormalised profile snapshot: this
  -- table holds the minimum needed to act.
  reported_user_id   UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
  reported_channel_id UUID,

  reason_code        TEXT NOT NULL,
  status             TEXT NOT NULL DEFAULT 'awaiting_review',
  received_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  assigned_to        UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  assigned_at        TIMESTAMPTZ,

  -- Set when an immediate suspension was applied on receipt.
  suspension_action_id UUID REFERENCES admin.enforcement_actions(id) ON DELETE SET NULL,

  -- --- Pending legal counsel: none of these are populated by any code path ---
  hash_match_result  TEXT,
  authority_report_ref TEXT,
  authority_reported_at TIMESTAMPTZ,
  preservation_ref   TEXT,

  closed_at          TIMESTAMPTZ,
  closure_note       TEXT,

  CONSTRAINT cs_status_valid CHECK (status IN (
    'awaiting_review', 'under_review', 'escalated_to_authority', 'closed_no_action', 'closed_actioned')),
  CONSTRAINT cs_reason_valid CHECK (reason_code LIKE 'child_safety.%')
);

CREATE INDEX IF NOT EXISTS idx_cs_cases_open
  ON admin.child_safety_cases(received_at) WHERE closed_at IS NULL;

-- ---------------------------------------------------------------------------
-- Per-view audit (§6.7: "every view individually audit-logged")
--
-- Separate from admin.audit_log on purpose. The general audit log is read by
-- Tier 1 and exported for compliance review; access to *this* log is itself
-- restricted, because the pattern of who looked at which case is sensitive.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.child_safety_access_log (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  case_id     UUID NOT NULL REFERENCES admin.child_safety_cases(id) ON DELETE CASCADE,
  admin_id    UUID NOT NULL REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  admin_label TEXT NOT NULL,
  action      TEXT NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ip          INET,
  session_id  UUID,

  CONSTRAINT cs_access_action_valid
    CHECK (action IN ('list', 'open', 'assign', 'act', 'close', 'export_denied'))
);

CREATE INDEX IF NOT EXISTS idx_cs_access_case ON admin.child_safety_access_log(case_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_cs_access_admin ON admin.child_safety_access_log(admin_id, occurred_at DESC);

CREATE OR REPLACE FUNCTION admin.cs_access_reject_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'admin.child_safety_access_log is append-only.'
    USING ERRCODE = 'raise_exception';
END;
$$;

DROP TRIGGER IF EXISTS trg_cs_access_no_update ON admin.child_safety_access_log;
CREATE TRIGGER trg_cs_access_no_update
  BEFORE UPDATE OR DELETE ON admin.child_safety_access_log
  FOR EACH ROW EXECUTE FUNCTION admin.cs_access_reject_mutation();

-- ---------------------------------------------------------------------------
-- Automatic legal hold on every case, so no retention job can ever purge one.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.cs_case_auto_hold()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = admin, public
AS $$
BEGIN
  IF NEW.reported_user_id IS NOT NULL THEN
    INSERT INTO admin.legal_holds (subject_type, subject_id, reference, reason, placed_by)
    VALUES ('user', NEW.reported_user_id::text, NEW.case_ref,
            'Automatic hold: child safety case opened. Release requires legal sign-off.', NULL)
    ON CONFLICT DO NOTHING;
  END IF;
  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_cs_case_auto_hold ON admin.child_safety_cases;
CREATE TRIGGER trg_cs_case_auto_hold
  AFTER INSERT ON admin.child_safety_cases
  FOR EACH ROW EXECUTE FUNCTION admin.cs_case_auto_hold();

-- ---------------------------------------------------------------------------
-- STUBS — shape only. The API refuses every operation against these.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.csam_hash_matches (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id     UUID REFERENCES admin.child_safety_cases(id) ON DELETE CASCADE,
  -- Which corpus matched. Populating this requires a signed agreement with the
  -- hash provider; there is deliberately no client code for it.
  provider    TEXT NOT NULL,
  matched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  confidence  TEXT,
  notes       TEXT
);

COMMENT ON TABLE admin.csam_hash_matches IS
  'SCAFFOLD ONLY (§6.7, §13). No integration exists. Do not populate without legal counsel and a signed agreement with the hash provider.';

CREATE TABLE IF NOT EXISTS admin.authority_reports (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id      UUID NOT NULL REFERENCES admin.child_safety_cases(id) ON DELETE RESTRICT,
  authority    TEXT NOT NULL,
  jurisdiction TEXT NOT NULL,
  submitted_at TIMESTAMPTZ,
  reference    TEXT,
  status       TEXT NOT NULL DEFAULT 'not_submitted',
  notes        TEXT,

  CONSTRAINT authority_status_valid
    CHECK (status IN ('not_submitted', 'submitted', 'acknowledged', 'closed'))
);

COMMENT ON TABLE admin.authority_reports IS
  'SCAFFOLD ONLY (§6.7, §13). Mandatory reporting obligations are statutory and jurisdiction-specific. Counsel defines content, timing and retention before any code writes here.';

-- Refuse to let the stubs be used by accident.
CREATE OR REPLACE FUNCTION admin.cs_stub_not_implemented()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION
    'Child safety reporting is not implemented. This pipeline requires legal counsel to define the statutory obligations before it may be used (§6.7, §13).'
    USING ERRCODE = 'raise_exception';
END;
$$;

DROP TRIGGER IF EXISTS trg_csam_hash_stub ON admin.csam_hash_matches;
CREATE TRIGGER trg_csam_hash_stub
  BEFORE INSERT OR UPDATE ON admin.csam_hash_matches
  FOR EACH ROW EXECUTE FUNCTION admin.cs_stub_not_implemented();

DROP TRIGGER IF EXISTS trg_authority_report_stub ON admin.authority_reports;
CREATE TRIGGER trg_authority_report_stub
  BEFORE INSERT OR UPDATE ON admin.authority_reports
  FOR EACH ROW EXECUTE FUNCTION admin.cs_stub_not_implemented();

COMMENT ON SCHEMA admin IS
  'NeverOff admin console. Never exposed through PostgREST. Child-safety tables (§6.7) are additionally gated by admin.is_child_safety_authorised().';
