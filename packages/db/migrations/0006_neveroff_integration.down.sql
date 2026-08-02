-- ============================================================================
-- 0006_neveroff_integration.down.sql — full rollback of the production-touching
-- migration.
--
-- Running this returns the NeverOff database to exactly its pre-console
-- behaviour: enforcement stops biting, the app-facing RPCs disappear, and the
-- original RLS policies from 01_schema.sql and 07_channels.sql are left as they
-- always were (0006 never modified them, so there is nothing to restore).
--
-- The `admin` schema and all console data are deliberately NOT dropped — a
-- rollback of the integration should never destroy the audit log. Drop the
-- schema separately and deliberately if that is genuinely what you want.
--
-- Run this if enforcement misbehaves in production. It is safe to run when the
-- policies are already absent.
-- ============================================================================

DROP POLICY IF EXISTS "Enforcement: blocked users cannot send messages" ON public.messages;
DROP POLICY IF EXISTS "Enforcement: blocked users cannot post to channels" ON public.channel_posts;
DROP POLICY IF EXISTS "Enforcement: restricted users cannot create channels" ON public.channels;
DROP POLICY IF EXISTS "Enforcement: blocked users cannot subscribe" ON public.channel_subscribers;

DROP FUNCTION IF EXISTS public.acknowledge_warning(UUID);
DROP FUNCTION IF EXISTS public.my_appeals();
DROP FUNCTION IF EXISTS public.submit_appeal(UUID, TEXT, TEXT);
DROP FUNCTION IF EXISTS public.my_enforcement_status(TEXT);

DROP FUNCTION IF EXISTS public.neveroff_feature_restricted(UUID, TEXT);
DROP FUNCTION IF EXISTS public.neveroff_access_blocked(UUID);
DROP FUNCTION IF EXISTS public.neveroff_send_blocked(UUID);

-- Verify the app is back to its original policy set.
SELECT 'enforcement_policies_removed' AS check_name,
       count(*) = 0 AS ok,
       count(*)::text || ' remaining' AS detail
  FROM pg_policies
 WHERE schemaname = 'public' AND policyname LIKE 'Enforcement:%'
UNION ALL
SELECT 'original_message_policies_intact',
       count(*) >= 3,
       count(*)::text || ' policies on public.messages'
  FROM pg_policies
 WHERE schemaname = 'public' AND tablename = 'messages';
