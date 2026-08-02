-- ============================================================================
-- 0010_default_config.sql — the configuration the console needs to function.
--
-- This is configuration, not sample data: without it the retention worker has
-- no policies to act on, the consent tables have no definitions to reference,
-- and the appeal SLA falls back to a hardcoded constant. It runs in every
-- environment including production, unlike the seed script.
--
-- Every value here is a starting point chosen to be defensible, not a legal
-- determination. The TTLs in particular must be reviewed by counsel against the
-- jurisdictions you actually operate in (§13).
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Retention policy (§8)
--
-- `min_ttl_days` is a floor the console refuses to configure below. It exists
-- because shortening a TTL destroys evidence, and the most likely time someone
-- shortens one is while under pressure to make a problem go away.
-- ---------------------------------------------------------------------------
INSERT INTO admin.retention_policies (data_class, ttl_days, min_ttl_days, description, enabled)
VALUES
  ('raw_events', 90, 30,
   'Individual telemetry events. Aggregates outlive these — the rollups are what analytics reads.',
   TRUE),

  ('aggregates', 1095, 365,
   'Pre-computed rollups. No personal data, so a long retention costs little and enables year-over-year comparison.',
   TRUE),

  ('evidence_snapshots', 400, 180,
   'Report evidence. Must outlive the case plus its appeal window; 400 days covers an annual review cycle.',
   TRUE),

  ('tickets', 730, 365,
   'Support tickets and their threads.',
   TRUE),

  ('audit_log', NULL, 2555,
   'Never purged automatically. Append-only by trigger, and an automated deletion path would defeat §7. Expiry, if ever legally required, is a deliberate individually-approved operation.',
   FALSE),

  ('enforcement_actions', NULL, 1095,
   'Never purged automatically. The safety history is what makes repeat offending visible. Removed only by an erasure request, which cascades.',
   FALSE),

  ('admin_messages', 730, 365,
   'Messages sent to users from the @admin identity.',
   TRUE),

  ('consent_records', 2555, 1095,
   'Only superseded records are purged; the current consent state is never removed, since the record that consent was given is itself a compliance artefact.',
   TRUE),

  ('sessions', 30, 7,
   'Expired admin sessions. Kept briefly so the device list has recent history.',
   TRUE),

  ('notifications', 90, 30,
   'Delivered or abandoned notification outbox rows.',
   TRUE)
ON CONFLICT (data_class) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Consent definitions (§8)
--
-- Three independent toggles. "Essential" is the only required one, which is what
-- makes essential-only a genuinely available choice rather than a dark pattern.
-- The wording is stored verbatim because §8 requires recording exactly what the
-- user was shown — if this text changes, that is a new version and previously
-- recorded consent does not carry over.
-- ---------------------------------------------------------------------------
INSERT INTO admin.consent_definitions (key, version, label, wording, required)
VALUES
  ('essential', 1, 'Essential',
   'We store what is needed to run NeverOff: your account, your messages, and the settings you choose. This cannot be turned off, because the app does not work without it.',
   TRUE),

  ('analytics', 1, 'Usage analytics',
   'Share anonymous information about which features you use, so we can find what is broken and what nobody needs. We never collect the content of your messages. You can turn this off at any time, and if you do, we stop collecting entirely rather than just hiding it.',
   FALSE),

  ('personalisation', 1, 'Personalisation',
   'Use your activity to suggest channels and people you might want to follow. You can turn this off at any time.',
   FALSE)
ON CONFLICT (key, version) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Console settings
-- ---------------------------------------------------------------------------
INSERT INTO admin.settings (key, value, description)
VALUES
  ('appeal_sla_hours', '72'::jsonb,
   'Hours before an unanswered appeal breaches its SLA and auto-escalates (§4).'),

  ('bulk_action_threshold', '50'::jsonb,
   'Bulk actions affecting more than this many users require a second admin''s approval (§1.3).'),

  ('dsr_sla_days', '30'::jsonb,
   'Statutory response window for data subject requests. 30 days matches GDPR Art. 12(3); confirm against every jurisdiction you operate in.'),

  ('shadow_restriction_review_days', '30'::jsonb,
   'Shadow restrictions are surfaced for review after this many days. §3.3 requires they be used sparingly, which needs a periodic look at whether they still are.'),

  ('policy_base_url', '"https://neveroff.app/policy"'::jsonb,
   'Base URL for the deep link shown on the ban screen next to the cited clause.'),

  ('out_of_hours_start', '"22:00"'::jsonb,
   'Start of the window in which bulk actions raise an anomaly alert (§7).'),

  ('out_of_hours_end', '"06:00"'::jsonb,
   'End of that window.')
ON CONFLICT (key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Jurisdictional configuration (§8)
--
-- Deliberately sparse. These are placeholders showing the shape; which regimes
-- actually apply is a question for counsel, and guessing at them in a migration
-- would give a false impression of compliance coverage.
-- ---------------------------------------------------------------------------
INSERT INTO admin.jurisdiction_rules (country, regime, description, default_remedy, active)
VALUES
  ('DE', 'NetzDG',
   'PLACEHOLDER. Germany''s Network Enforcement Act imposes removal deadlines and reporting duties. Confirm applicability and thresholds with counsel before relying on this.',
   'geo_block', FALSE),

  ('FR', 'DSA',
   'PLACEHOLDER. EU Digital Services Act obligations. Scope depends on platform size classification. Confirm with counsel.',
   'geo_block', FALSE)
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- Post-conditions
-- ---------------------------------------------------------------------------
SELECT 'retention_policies' AS check_name,
       count(*) >= 10 AS ok,
       count(*)::text || ' data classes configured' AS detail
  FROM admin.retention_policies
UNION ALL
SELECT 'audit_log_never_auto_purged',
       NOT enabled AND ttl_days IS NULL,
       'audit_log purge disabled'
  FROM admin.retention_policies WHERE data_class = 'audit_log'
UNION ALL
SELECT 'consent_definitions',
       count(*) = 3,
       count(*)::text || ' of 3'
  FROM admin.consent_definitions
UNION ALL
SELECT 'exactly_one_required_consent',
       count(*) = 1,
       'only "essential" is mandatory, so essential-only is a real choice'
  FROM admin.consent_definitions WHERE required
UNION ALL
SELECT 'settings',
       count(*) >= 7,
       count(*)::text || ' settings'
  FROM admin.settings;
