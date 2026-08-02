-- @no-transaction
-- ============================================================================
-- 0008_app_indexes.sql — indexes on the app's own tables, built CONCURRENTLY.
--
-- The `-- @no-transaction` marker on line 1 tells the migration runner to
-- execute this file outside a transaction block. That is required: Postgres
-- refuses CREATE INDEX CONCURRENTLY inside one.
--
-- Why concurrently matters here specifically: a plain CREATE INDEX takes an
-- ACCESS EXCLUSIVE lock for the whole build. On public.messages in production
-- that means every user's send blocks until the index finishes. CONCURRENTLY
-- trades a longer build and a second table pass for not blocking writes.
--
-- Trade-off to know about: a CONCURRENTLY build that fails leaves an INVALID
-- index behind rather than rolling back. It is not used by the planner and is
-- safe, but it must be dropped and rebuilt. Check for leftovers with:
--
--   SELECT indexrelid::regclass FROM pg_index WHERE NOT indisvalid;
--
-- All four are IF NOT EXISTS, so re-running after a partial failure is safe
-- once any invalid index has been dropped.
-- ============================================================================

-- Backs the directory's message-count and last-active columns, and the
-- per-user message history on the profile page.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_messages_sender_created
  ON public.messages(sender_id, created_at DESC);

-- Registration-window filter and default directory ordering.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_profiles_created_at
  ON public.profiles(created_at DESC);

-- Exact-match username lookup. §3.1 requires identifier search to be
-- exact-match only, so this is a plain b-tree on lower(username) rather than a
-- trigram index — there is deliberately no fuzzy search over user identifiers.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_profiles_username_lower
  ON public.profiles(lower(username));

-- "is channel owner" directory filter and the owner-accountability view (§6.5).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_channels_owner_lookup
  ON public.channels(owner_id);
