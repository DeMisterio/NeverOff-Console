-- ============================================================================
-- 0017_feature_catalogue.sql — the list of features the app can report using.
--
-- This is configuration, not sample data. §2.3 wants the feature-usage table
-- sorted ascending to "instantly surface dead features nobody touches", and a
-- table built from observed events alone can never contain a feature with zero
-- events. The zero rows have to come from somewhere, and this is where.
--
-- Keeping it in sync with what the client actually emits is a real maintenance
-- cost. It is worth paying: the alternative is a dashboard that structurally
-- cannot answer the question it was built to answer.
--
-- `shipped_at` matters for the same reason. A feature released last week with
-- no usage is not dead, it is new — admin.feature_adoption only calls something
-- dead once it has had thirty days to be found.
-- ============================================================================

INSERT INTO admin.feature_catalogue (key, label, surface, shipped_in, shipped_at, notes) VALUES
  ('send_message',      'Send a message',        'chat',    '1.0.0', NOW() - INTERVAL '900 days', NULL),
  ('send_voice_note',   'Send a voice note',     'chat',    '1.2.0', NOW() - INTERVAL '700 days', NULL),
  ('send_image',        'Send an image',         'chat',    '1.0.0', NOW() - INTERVAL '900 days', NULL),
  ('send_video',        'Send a video',          'chat',    '1.3.0', NOW() - INTERVAL '600 days', NULL),
  ('create_group',      'Create a group',        'chat',    '1.1.0', NOW() - INTERVAL '800 days', NULL),
  ('create_channel',    'Create a channel',      'channel', '1.9.0', NOW() - INTERVAL '200 days', NULL),
  ('subscribe_channel', 'Subscribe to a channel','channel', '1.9.0', NOW() - INTERVAL '200 days', NULL),
  ('react_to_post',     'React to a post',       'channel', '1.9.0', NOW() - INTERVAL '200 days', NULL),
  ('search_users',      'Search for people',     'search',  '1.0.0', NOW() - INTERVAL '900 days', NULL),
  ('edit_profile',      'Edit profile',          'profile', '1.0.0', NOW() - INTERVAL '900 days', NULL),
  ('change_wallpaper',  'Change chat wallpaper', 'settings','1.5.0', NOW() - INTERVAL '400 days', NULL),

  -- Shipped long enough ago to have been discovered. The seed deliberately
  -- emits no events for it, so it is the row §11's acceptance criterion expects
  -- the feature-usage table to surface.
  ('schedule_message',  'Schedule a message',    'chat',    '1.7.0', NOW() - INTERVAL '300 days',
   'Shipped and never adopted. Candidate for removal — carrying an unused feature costs review time and test surface forever.')
ON CONFLICT (key) DO NOTHING;

SELECT 'feature_catalogue' AS check_name,
       count(*) >= 12 AS ok,
       count(*)::text || ' features catalogued' AS detail
  FROM admin.feature_catalogue
UNION ALL
SELECT 'dead_feature_present',
       count(*) = 1,
       'schedule_message is catalogued so it can show as unused'
  FROM admin.feature_catalogue WHERE key = 'schedule_message';
