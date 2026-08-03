-- ============================================================================
-- 0015_support_default_config.sql — the categories, macros and keyword lists
-- @support needs to function.
--
-- Configuration, not sample data: without it there are no category buttons and
-- the emergency detector matches nothing. Runs in every environment.
--
-- THE KEYWORD LIST NEEDS A SPECIALIST. What follows is a starting point chosen
-- to be defensible, not a clinically validated screen. It is tuned for recall
-- on purpose — a false positive costs an agent thirty seconds, a false negative
-- on a self-harm disclosure costs considerably more — but a real list should be
-- reviewed by someone with safeguarding training, localised properly rather
-- than translated, and revisited as language shifts. Treat this as scaffolding.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Categories (§5.1)
-- ---------------------------------------------------------------------------
INSERT INTO admin.ticket_categories
  (key, label, description, position, first_response_hours, resolution_hours,
   default_priority, is_emergency, allow_self_service)
VALUES
  ('account_access', 'Account access and login',
   'Cannot sign in, lost access, or did not receive a code.',
   1, 12, 48, 'high', FALSE, TRUE),

  ('report_content', 'Report a user, message or channel',
   'Something you have seen that breaks the rules.',
   2, 24, 72, 'normal', FALSE, TRUE),

  ('ban_appeal', 'Appeal a suspension',
   'You believe a restriction on your account was a mistake.',
   3, 72, 120, 'high', FALSE, FALSE),

  ('payments', 'Payments and subscriptions',
   'Charges, refunds and billing.',
   4, 24, 72, 'normal', FALSE, TRUE),

  ('bug_report', 'Bug or technical problem',
   'Something in the app is broken.',
   5, 48, 168, 'low', FALSE, TRUE),

  ('privacy_request', 'Privacy and your data',
   'Export, correct or delete your data.',
   -- §8 ties this to the statutory DSR clock. Shorter than the 30-day
   -- deadline on purpose: the deadline is when the answer must be delivered,
   -- not when work should start.
   6, 24, 168, 'high', FALSE, FALSE),

  ('safety_emergency', 'Safety emergency',
   'Someone is in danger, being threatened, or at risk of harm.',
   7, 1, 4, 'urgent', TRUE, FALSE),

  ('feedback', 'Feedback and feature requests',
   'Ideas and things you would like to see.',
   8, 72, 336, 'low', FALSE, TRUE),

  ('other', 'Something else',
   'Anything not covered above.',
   9, 48, 120, 'normal', FALSE, TRUE)
ON CONFLICT (key) DO NOTHING;

-- Sub-categories (§5.1: "Each category can branch into sub-categories")
INSERT INTO admin.ticket_categories
  (key, label, parent_key, position, first_response_hours, resolution_hours, default_priority)
VALUES
  ('account_access.no_code', 'I did not get my login code', 'account_access', 1, 12, 48, 'high'),
  ('account_access.lost_device', 'I lost my device', 'account_access', 2, 12, 48, 'high'),
  ('account_access.compromised', 'I think someone else is in my account',
   'account_access', 3, 4, 24, 'urgent'),

  ('report_content.user', 'A person', 'report_content', 1, 24, 72, 'normal'),
  ('report_content.message', 'A message', 'report_content', 2, 24, 72, 'normal'),
  ('report_content.channel', 'A channel', 'report_content', 3, 24, 72, 'normal'),

  ('privacy_request.export', 'Send me my data', 'privacy_request', 1, 24, 168, 'high'),
  ('privacy_request.correct', 'Correct my data', 'privacy_request', 2, 24, 168, 'normal'),
  ('privacy_request.delete', 'Delete my account and data', 'privacy_request', 3, 24, 168, 'high')
ON CONFLICT (key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Emergency keyword lists (§5.2)
--
-- Matched as case-insensitive substrings against subject + body. Short or
-- ambiguous phrases are deliberately absent: "hurt" alone would match "my
-- feelings are hurt" and drown the emergency queue, which is its own kind of
-- failure — an emergency queue nobody trusts is an emergency queue nobody reads.
-- ---------------------------------------------------------------------------
INSERT INTO admin.ticket_emergency_keywords (phrase, locale, kind) VALUES
  ('kill myself', 'en', 'self_harm'),
  ('killing myself', 'en', 'self_harm'),
  ('end my life', 'en', 'self_harm'),
  ('want to die', 'en', 'self_harm'),
  ('suicidal', 'en', 'self_harm'),
  ('suicide', 'en', 'self_harm'),
  ('hurt myself', 'en', 'self_harm'),
  ('self harm', 'en', 'self_harm'),
  ('overdose', 'en', 'self_harm'),
  ('no reason to live', 'en', 'self_harm'),

  ('покончить с собой', 'ru', 'self_harm'),
  ('не хочу жить', 'ru', 'self_harm'),
  ('самоубийство', 'ru', 'self_harm'),
  ('причинить себе вред', 'ru', 'self_harm'),

  ('child abuse', 'en', 'minor_safety'),
  ('underage', 'en', 'minor_safety'),
  ('my child', 'en', 'minor_safety'),
  ('grooming', 'en', 'minor_safety'),
  ('i am 13', 'en', 'minor_safety'),
  ('i am 14', 'en', 'minor_safety'),
  ('i am 15', 'en', 'minor_safety'),

  ('going to kill', 'en', 'violence_threat'),
  ('threatened to kill', 'en', 'violence_threat'),
  ('death threat', 'en', 'violence_threat'),
  ('going to hurt me', 'en', 'violence_threat'),
  ('stalking me', 'en', 'violence_threat'),

  ('my lawyer', 'en', 'legal_threat'),
  ('legal action', 'en', 'legal_threat'),
  ('court order', 'en', 'legal_threat'),
  ('subpoena', 'en', 'legal_threat'),
  ('law enforcement request', 'en', 'legal_threat')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- Macros (§5.2)
--
-- Substitution happens in the API when the macro is applied. Kept short and
-- plain: a canned response that reads as canned is worse than no canned
-- response, because it tells the person nobody actually read what they wrote.
-- ---------------------------------------------------------------------------
INSERT INTO admin.ticket_macros (key, label, category_key, body, sets_status) VALUES
  ('ack_looking', 'Acknowledge — looking into it', NULL,
   E'Hi {{username}},\n\nThanks for getting in touch. I am looking into this now and will come back to you shortly.\n\n{{agent_name}}',
   'pending_agent'),

  ('need_more_info', 'Need more information', NULL,
   E'Hi {{username}},\n\nI want to help with this, but I need a bit more to go on. Could you tell me:\n\n- When did this start?\n- What did you see on screen?\n\nReference: {{ticket_ref}}\n\n{{agent_name}}',
   'pending_user'),

  ('appeal_received', 'Ban appeal received', 'ban_appeal',
   E'Hi {{username}},\n\nYour appeal has been received and will be reviewed by someone other than the person who made the original decision.\n\nReference: {{ticket_ref}}\n\n{{agent_name}}',
   'pending_agent'),

  ('privacy_export_started', 'Data export started', 'privacy_request',
   E'Hi {{username}},\n\nI have started your data export. You will get a secure link when it is ready — it expires after a short time, so download it when it arrives.\n\nReference: {{ticket_ref}}\n\n{{agent_name}}',
   'pending_agent'),

  ('resolved_generic', 'Resolved', NULL,
   E'Hi {{username}},\n\nI believe this is sorted now. If it is not, reply here and the ticket reopens — no need to start a new one.\n\n{{agent_name}}',
   'resolved'),

  ('no_action_report', 'Report reviewed — no violation', 'report_content',
   E'Hi {{username}},\n\nWe reviewed what you reported and did not find a breach of our policies. Thank you for taking the time to flag it — reports like yours are how we find the ones that are.\n\n{{agent_name}}',
   'resolved')
ON CONFLICT (key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Settings
-- ---------------------------------------------------------------------------
INSERT INTO admin.settings (key, value, description) VALUES
  ('support_emergency_oncall_webhook', '""'::jsonb,
   'Webhook paged when an emergency ticket opens (§5.2). Empty means alerts are raised in-console only, which is NOT sufficient for a live deployment.'),
  ('support_crisis_resources_url', '"https://neveroff.app/help/crisis"'::jsonb,
   'Regional crisis resources shown to a user who discloses risk. WHICH resources for WHICH region is a policy question for your safety lead — see the runbook.')
ON CONFLICT (key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Post-conditions
-- ---------------------------------------------------------------------------
SELECT 'top_level_categories' AS check_name,
       count(*) = 9 AS ok, count(*)::text || ' of 9' AS detail
  FROM admin.ticket_categories WHERE parent_key IS NULL
UNION ALL
SELECT 'exactly_one_emergency_category',
       count(*) = 1, 'safety_emergency'
  FROM admin.ticket_categories WHERE is_emergency
UNION ALL
SELECT 'emergency_keywords',
       count(*) >= 25, count(*)::text || ' phrases'
  FROM admin.ticket_emergency_keywords
UNION ALL
SELECT 'ban_appeal_no_self_service',
       NOT allow_self_service,
       'an appeal always reaches a human'
  FROM admin.ticket_categories WHERE key = 'ban_appeal'
UNION ALL
SELECT 'macros', count(*) >= 6, count(*)::text || ' macros'
  FROM admin.ticket_macros;
