-- ============================================================================
-- 00_supabase_shim.sql — LOCAL DEVELOPMENT ONLY. Never run against Supabase.
--
-- The console's migrations, and NeverOff's own migrations, are written against
-- a Supabase project and depend on primitives Supabase provides out of the box:
-- the `auth` and `storage` schemas, `auth.uid()`, the `supabase_realtime`
-- publication, and the anon/authenticated/service_role roles.
--
-- This file creates just enough of each that the *real, unmodified* migration
-- files run locally. That matters: we want to rehearse the exact SQL that will
-- later run in production, not a local-only variant of it.
--
-- The bootstrap script refuses to execute this against any host outside
-- DB_ALLOWED_HOSTS, so it cannot be pointed at the live project by accident.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Roles. Supabase ships these; a bare Postgres does not.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    CREATE ROLE anon NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    CREATE ROLE authenticated NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    -- BYPASSRLS mirrors Supabase: the service role is not subject to RLS, which
    -- is why the console API can write enforcement rows and read any profile.
    CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS;
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;

-- ---------------------------------------------------------------------------
-- auth schema
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE IF NOT EXISTS auth.users (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email              TEXT UNIQUE,
  phone              TEXT UNIQUE,
  encrypted_password TEXT,
  email_confirmed_at TIMESTAMPTZ,
  last_sign_in_at    TIMESTAMPTZ,
  raw_user_meta_data JSONB DEFAULT '{}'::jsonb,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at         TIMESTAMPTZ
);

-- Mirrors Supabase's behaviour closely enough to exercise RLS locally.
-- Real Supabase reads the verified JWT; tests set the GUC directly with
--   SELECT set_config('app.current_user_id', '<uuid>', true);
-- which lets an integration test act as a specific user inside a transaction.
CREATE OR REPLACE FUNCTION auth.uid()
RETURNS UUID
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    NULLIF(current_setting('request.jwt.claim.sub', true), ''),
    NULLIF(current_setting('app.current_user_id', true), '')
  )::uuid;
$$;

CREATE OR REPLACE FUNCTION auth.role()
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    NULLIF(current_setting('request.jwt.claim.role', true), ''),
    NULLIF(current_setting('app.current_role', true), ''),
    'authenticated'
  );
$$;

CREATE OR REPLACE FUNCTION auth.email()
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
  SELECT email FROM auth.users WHERE id = auth.uid();
$$;

GRANT USAGE ON SCHEMA auth TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.uid() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.role() TO anon, authenticated, service_role;

-- ---------------------------------------------------------------------------
-- storage schema — enough for 06_missing_backend_setup.sql to apply
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS storage;

CREATE TABLE IF NOT EXISTS storage.buckets (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  public     BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS storage.objects (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bucket_id  TEXT REFERENCES storage.buckets(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  owner      UUID,
  metadata   JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;

GRANT USAGE ON SCHEMA storage TO anon, authenticated, service_role;

-- ---------------------------------------------------------------------------
-- Realtime publication. NeverOff's migrations ALTER this; it must exist first.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    CREATE PUBLICATION supabase_realtime;
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Convenience for integration tests: run a block as a specific end user, with
-- RLS applied. Restores the previous setting on exit.
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS test_support;

CREATE OR REPLACE FUNCTION test_support.act_as(p_user UUID)
RETURNS VOID
LANGUAGE sql
VOLATILE
AS $$
  SELECT set_config('app.current_user_id', COALESCE(p_user::text, ''), true);
$$;

COMMENT ON SCHEMA auth IS 'LOCAL SHIM of Supabase auth. Not present in production, where Supabase provides the real thing.';
