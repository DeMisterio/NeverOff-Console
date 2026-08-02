-- ============================================================================
-- 0001_admin_core.sql — the `admin` schema: RBAC, admin accounts, sessions.
--
-- Everything the console owns lives in the `admin` schema. Nothing here is
-- reachable through Supabase's PostgREST API: the schema is never added to
-- `pgrst.db_schemas`, and the API server connects as its own role. The Android
-- client can therefore never see an admin account, a session or an audit entry,
-- even if a client-side RLS bug existed.
--
-- Design note — why the permission catalogue is duplicated in SQL when it also
-- exists in packages/shared/src/permissions.ts:
--   The TypeScript copy is the authority for *code*. This copy exists so the
--   database can enforce referential integrity on grants (you cannot grant an
--   atom that does not exist) and so the permission matrix can be produced by a
--   plain SQL query for a compliance reviewer who will not read TypeScript.
--   0002 seeds it from the same list, and a test asserts the two never drift.
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS admin;

-- Deliberately not using citext: it is an extension, and on Supabase extensions
-- live in a separate schema with their own search_path rules. A unique index on
-- lower(email) is portable and does the same job.

-- ---------------------------------------------------------------------------
-- Permission catalogue
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.permissions (
  key              TEXT PRIMARY KEY,
  label            TEXT NOT NULL,
  description      TEXT NOT NULL,
  category         TEXT NOT NULL,
  break_glass      TEXT NOT NULL DEFAULT 'none',
  pii              BOOLEAN NOT NULL DEFAULT FALSE,
  super_admin_only BOOLEAN NOT NULL DEFAULT FALSE,

  CONSTRAINT permissions_break_glass_valid
    CHECK (break_glass IN ('none', 'typed_phrase', 'second_admin')),
  CONSTRAINT permissions_category_valid
    CHECK (category IN ('analytics', 'users', 'channels', 'reports', 'support',
                        'administration', 'compliance', 'child_safety'))
);

-- ---------------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.roles (
  key           TEXT PRIMARY KEY,
  label         TEXT NOT NULL,
  description   TEXT NOT NULL,
  -- Strictly ordered. An admin may only manage admins of strictly lower rank.
  rank          INTEGER NOT NULL,
  -- NULL = unlimited, 0 = may not ban at all.
  max_ban_days  INTEGER,
  singleton     BOOLEAN NOT NULL DEFAULT FALSE,
  scopable      BOOLEAN NOT NULL DEFAULT TRUE,
  -- System roles cannot be deleted; their permission sets can still be edited
  -- by the Super Admin, which is why roles.edit is a reserved atom.
  is_system     BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT roles_rank_range CHECK (rank BETWEEN 0 AND 100),
  CONSTRAINT roles_max_ban_days_nonneg CHECK (max_ban_days IS NULL OR max_ban_days >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_rank_unique ON admin.roles(rank);

CREATE TABLE IF NOT EXISTS admin.role_permissions (
  role_key       TEXT NOT NULL REFERENCES admin.roles(key) ON DELETE CASCADE,
  permission_key TEXT NOT NULL REFERENCES admin.permissions(key) ON DELETE CASCADE,
  PRIMARY KEY (role_key, permission_key)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_permission
  ON admin.role_permissions(permission_key);

-- ---------------------------------------------------------------------------
-- Admin accounts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.admin_users (
  id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email                    TEXT NOT NULL,
  display_name             TEXT NOT NULL,

  -- Argon2id. Never a fast hash: an admin password is the outer gate on every
  -- user record on the platform.
  password_hash            TEXT NOT NULL,
  password_updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  must_change_password     BOOLEAN NOT NULL DEFAULT FALSE,

  role_key                 TEXT NOT NULL REFERENCES admin.roles(key),
  status                   TEXT NOT NULL DEFAULT 'invited',

  -- --- 2FA (§1.3: every admin account requires TOTP) ---------------------
  -- Encrypted with TOTP_ENCRYPTION_KEY before it is stored, so a database dump
  -- alone does not yield working second factors.
  totp_secret_encrypted    TEXT,
  totp_enrolled_at         TIMESTAMPTZ,
  -- Highest TOTP step already accepted. Rejecting <= this prevents a replay of
  -- an intercepted code inside its own 30-second window.
  totp_last_step           BIGINT,
  totp_reenrollment_forced BOOLEAN NOT NULL DEFAULT FALSE,
  -- Argon2 hashes of single-use recovery codes.
  totp_recovery_hashes     TEXT[] NOT NULL DEFAULT '{}',

  -- --- Brute force ------------------------------------------------------
  failed_login_count       INTEGER NOT NULL DEFAULT 0,
  locked_until             TIMESTAMPTZ,

  -- --- Scope (§1.3). NULL on an axis = unrestricted on that axis. --------
  -- NULL and '{}' mean different things: NULL is "global", '{}' is "nothing",
  -- which is why these are nullable arrays rather than NOT NULL DEFAULT '{}'.
  scope_countries          TEXT[],
  scope_languages          TEXT[],
  scope_channel_ids        UUID[],
  scope_report_categories  TEXT[],

  -- --- Individual grant adjustments on top of the role bundle -----------
  extra_permissions        TEXT[] NOT NULL DEFAULT '{}',
  revoked_permissions      TEXT[] NOT NULL DEFAULT '{}',
  max_ban_days_override    INTEGER,

  created_by               UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at            TIMESTAMPTZ,
  deactivated_at           TIMESTAMPTZ,
  deactivated_reason       TEXT,

  CONSTRAINT admin_users_status_valid
    CHECK (status IN ('invited', 'active', 'suspended', 'disabled')),
  CONSTRAINT admin_users_email_shape
    CHECK (email ~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'),
  CONSTRAINT admin_users_display_name_len
    CHECK (char_length(display_name) BETWEEN 1 AND 120),
  CONSTRAINT admin_users_max_ban_days_nonneg
    CHECK (max_ban_days_override IS NULL OR max_ban_days_override >= 0),
  -- An active account must have completed TOTP enrolment. Invited accounts are
  -- the only state in which an admin exists without a second factor, and they
  -- cannot authenticate.
  CONSTRAINT admin_users_active_requires_totp
    CHECK (status <> 'active' OR totp_secret_encrypted IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_email_lower
  ON admin.admin_users (lower(email));

-- §1.1: "Global, exactly one (transferable)". Enforced by the database rather
-- than by application code, so a race between two concurrent transfers cannot
-- produce two Super Admins.
CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_single_super_admin
  ON admin.admin_users ((role_key))
  WHERE role_key = 'super_admin';

CREATE INDEX IF NOT EXISTS idx_admin_users_role ON admin.admin_users(role_key);
CREATE INDEX IF NOT EXISTS idx_admin_users_status ON admin.admin_users(status);

-- ---------------------------------------------------------------------------
-- Sessions (§1.3: idle timeout, device list, force-logout-everywhere)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.sessions (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_id            UUID NOT NULL REFERENCES admin.admin_users(id) ON DELETE CASCADE,

  -- SHA-256 of the session token. The raw token exists only in the client
  -- cookie; a database read cannot reconstruct a usable session.
  token_hash          TEXT NOT NULL,

  -- Idle timeout and absolute cap are tracked separately: a long-running
  -- session must die at the absolute cap even if it is being actively used.
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  idle_expires_at     TIMESTAMPTZ NOT NULL,
  absolute_expires_at TIMESTAMPTZ NOT NULL,

  -- Device list surface.
  ip                  INET,
  user_agent          TEXT,
  device_label        TEXT,

  -- TOTP satisfied for this session. A session that has passed the password
  -- step but not the TOTP step exists but authorises nothing.
  mfa_satisfied       BOOLEAN NOT NULL DEFAULT FALSE,

  revoked_at          TIMESTAMPTZ,
  revoked_by          UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  revoke_reason       TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_token_hash ON admin.sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_admin_active
  ON admin.sessions(admin_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_expiry
  ON admin.sessions(absolute_expires_at) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Break-glass (§1.3)
--
-- Permanent bans, channel takedowns, PII export and bulk actions over the
-- configured threshold cannot be performed in a single step. The actor opens a
-- request; it is either confirmed by typing an exact phrase or approved by a
-- second admin who independently holds the permission. The request carries the
-- full payload so the approver sees exactly what they are approving, and it is
-- consumed atomically so one approval cannot authorise two actions.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.break_glass_requests (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requested_by     UUID NOT NULL REFERENCES admin.admin_users(id) ON DELETE CASCADE,
  permission_key   TEXT NOT NULL REFERENCES admin.permissions(key),
  mode             TEXT NOT NULL,

  target_type      TEXT NOT NULL,
  target_id        TEXT NOT NULL,
  -- Exact request body, hashed so an approved payload cannot be swapped for a
  -- different one between approval and execution.
  payload          JSONB NOT NULL,
  payload_hash     TEXT NOT NULL,
  justification    TEXT NOT NULL,

  status           TEXT NOT NULL DEFAULT 'pending',
  approved_by      UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  approved_at      TIMESTAMPTZ,
  rejected_reason  TEXT,
  consumed_at      TIMESTAMPTZ,

  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at       TIMESTAMPTZ NOT NULL,

  CONSTRAINT break_glass_mode_valid CHECK (mode IN ('typed_phrase', 'second_admin')),
  CONSTRAINT break_glass_status_valid
    CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'consumed')),
  CONSTRAINT break_glass_justification_len CHECK (char_length(justification) >= 10),
  -- A second-admin request can never be approved by the person who raised it.
  CONSTRAINT break_glass_no_self_approval
    CHECK (approved_by IS NULL OR approved_by <> requested_by)
);

CREATE INDEX IF NOT EXISTS idx_break_glass_pending
  ON admin.break_glass_requests(status, created_at DESC) WHERE status = 'pending';

-- ---------------------------------------------------------------------------
-- Console settings
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin.settings (
  key         TEXT PRIMARY KEY,
  value       JSONB NOT NULL,
  description TEXT,
  updated_by  UUID REFERENCES admin.admin_users(id) ON DELETE SET NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- updated_at maintenance
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.touch_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_admin_users_updated_at ON admin.admin_users;
CREATE TRIGGER trg_admin_users_updated_at
  BEFORE UPDATE ON admin.admin_users
  FOR EACH ROW EXECUTE FUNCTION admin.touch_updated_at();

DROP TRIGGER IF EXISTS trg_roles_updated_at ON admin.roles;
CREATE TRIGGER trg_roles_updated_at
  BEFORE UPDATE ON admin.roles
  FOR EACH ROW EXECUTE FUNCTION admin.touch_updated_at();

-- ---------------------------------------------------------------------------
-- Guard: the Super Admin cannot be demoted, suspended or deleted (§1.1).
-- Transfer is a deliberate two-step flow that sets the flag below.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION admin.protect_super_admin()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.role_key = 'super_admin' THEN
      RAISE EXCEPTION 'The Super Admin account cannot be deleted. Transfer the role first.'
        USING ERRCODE = 'raise_exception';
    END IF;
    RETURN OLD;
  END IF;

  IF OLD.role_key = 'super_admin' AND NEW.role_key <> 'super_admin' THEN
    -- Permitted only inside admin.transfer_super_admin(), which sets this flag
    -- for the duration of its transaction.
    IF current_setting('admin.super_admin_transfer', true) IS DISTINCT FROM 'on' THEN
      RAISE EXCEPTION 'The Super Admin cannot be demoted outside the transfer flow.'
        USING ERRCODE = 'raise_exception';
    END IF;
  END IF;

  IF OLD.role_key = 'super_admin' AND NEW.status <> 'active'
     AND current_setting('admin.super_admin_transfer', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'The Super Admin account cannot be suspended or disabled.'
      USING ERRCODE = 'raise_exception';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_protect_super_admin_update ON admin.admin_users;
CREATE TRIGGER trg_protect_super_admin_update
  BEFORE UPDATE ON admin.admin_users
  FOR EACH ROW EXECUTE FUNCTION admin.protect_super_admin();

DROP TRIGGER IF EXISTS trg_protect_super_admin_delete ON admin.admin_users;
CREATE TRIGGER trg_protect_super_admin_delete
  BEFORE DELETE ON admin.admin_users
  FOR EACH ROW EXECUTE FUNCTION admin.protect_super_admin();

-- Atomic, race-free Super Admin transfer.
CREATE OR REPLACE FUNCTION admin.transfer_super_admin(
  p_from UUID,
  p_to   UUID,
  p_new_role_for_previous TEXT DEFAULT 'tier1_platform_manager'
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
  IF p_from = p_to THEN
    RAISE EXCEPTION 'Cannot transfer the Super Admin role to the current holder.';
  END IF;

  PERFORM set_config('admin.super_admin_transfer', 'on', true);

  -- Lock both rows in a deterministic order to avoid deadlocking against a
  -- concurrent transfer attempt.
  PERFORM 1 FROM admin.admin_users
   WHERE id IN (p_from, p_to)
   ORDER BY id
   FOR UPDATE;

  IF NOT EXISTS (SELECT 1 FROM admin.admin_users WHERE id = p_from AND role_key = 'super_admin') THEN
    RAISE EXCEPTION 'Source account is not the Super Admin.';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM admin.admin_users WHERE id = p_to AND status = 'active') THEN
    RAISE EXCEPTION 'Target account must be an active admin with TOTP enrolled.';
  END IF;

  -- Demote first: the single-super-admin unique index would otherwise reject
  -- the promotion.
  UPDATE admin.admin_users
     SET role_key = p_new_role_for_previous
   WHERE id = p_from;

  UPDATE admin.admin_users
     SET role_key = 'super_admin'
   WHERE id = p_to;

  PERFORM set_config('admin.super_admin_transfer', 'off', true);
END;
$$;

COMMENT ON SCHEMA admin IS
  'NeverOff admin console. Never exposed through PostgREST — do not add to the API schema list.';
