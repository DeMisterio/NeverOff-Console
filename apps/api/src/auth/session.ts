import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import { getPool } from '@neveroff-console/db';
import type { PoolClient } from 'pg';

import { getConfig } from '../config.js';

/**
 * Server-side sessions (§1.3).
 *
 * The cookie holds a random 256-bit token; the database holds only its SHA-256.
 * So a database read — a leaked backup, a SQL injection that gets SELECT — does
 * not yield a usable session. Hashing is plain SHA-256 rather than Argon2 on
 * purpose: the token is already full-entropy random, so there is nothing to
 * brute force, and session validation happens on every single request.
 *
 * Two independent clocks, per §1.3:
 *   - idle_expires_at slides forward on each request
 *   - absolute_expires_at never moves, so a session that is kept warm by
 *     activity still dies at the hard cap
 */

export interface SessionRecord {
  readonly id: string;
  readonly adminId: string;
  readonly mfaSatisfied: boolean;
  readonly idleExpiresAt: Date;
  readonly absoluteExpiresAt: Date;
  readonly deviceLabel: string | null;
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/** Very rough device label for the session list. Not a fingerprint. */
export function describeDevice(userAgent: string | null): string {
  if (!userAgent) return 'Unknown device';

  const os =
    /Windows NT/i.test(userAgent) ? 'Windows'
    : /Mac OS X|Macintosh/i.test(userAgent) ? 'macOS'
    : /Android/i.test(userAgent) ? 'Android'
    : /iPhone|iPad|iOS/i.test(userAgent) ? 'iOS'
    : /Linux/i.test(userAgent) ? 'Linux'
    : 'Unknown OS';

  const browser =
    /Edg\//i.test(userAgent) ? 'Edge'
    : /OPR\//i.test(userAgent) ? 'Opera'
    : /Chrome\//i.test(userAgent) ? 'Chrome'
    : /Safari\//i.test(userAgent) && !/Chrome/i.test(userAgent) ? 'Safari'
    : /Firefox\//i.test(userAgent) ? 'Firefox'
    : 'Unknown browser';

  return `${browser} on ${os}`;
}

export interface CreatedSession {
  readonly token: string;
  readonly session: SessionRecord;
}

export async function createSession(
  client: PoolClient,
  adminId: string,
  meta: { ip: string | null; userAgent: string | null; mfaSatisfied: boolean },
): Promise<CreatedSession> {
  const config = getConfig();
  const token = randomBytes(32).toString('base64url');

  const { rows } = await client.query<{
    id: string;
    idle_expires_at: Date;
    absolute_expires_at: Date;
    device_label: string | null;
  }>(
    `INSERT INTO admin.sessions
       (admin_id, token_hash, ip, user_agent, device_label, mfa_satisfied,
        idle_expires_at, absolute_expires_at)
     VALUES ($1, $2, $3, $4, $5, $6,
             NOW() + make_interval(mins => $7::int),
             NOW() + make_interval(hours => $8::int))
     RETURNING id, idle_expires_at, absolute_expires_at, device_label`,
    [
      adminId,
      hashToken(token),
      meta.ip,
      meta.userAgent,
      describeDevice(meta.userAgent),
      meta.mfaSatisfied,
      config.SESSION_IDLE_TIMEOUT_MINUTES,
      config.SESSION_ABSOLUTE_TIMEOUT_HOURS,
    ],
  );

  const row = rows[0]!;
  return {
    token,
    session: {
      id: row.id,
      adminId,
      mfaSatisfied: meta.mfaSatisfied,
      idleExpiresAt: row.idle_expires_at,
      absoluteExpiresAt: row.absolute_expires_at,
      deviceLabel: row.device_label,
    },
  };
}

/**
 * Validate a token and slide the idle window.
 *
 * Returns null for anything that is not a live session — revoked, expired on
 * either clock, or belonging to an admin who is no longer active. The last case
 * matters: suspending an admin must take effect immediately, not whenever their
 * current session happens to expire.
 */
export async function validateSession(token: string): Promise<SessionRecord | null> {
  const config = getConfig();
  const pool = getPool();

  const { rows } = await pool.query<{
    id: string;
    admin_id: string;
    mfa_satisfied: boolean;
    idle_expires_at: Date;
    absolute_expires_at: Date;
    device_label: string | null;
  }>(
    `UPDATE admin.sessions s
        SET last_seen_at = NOW(),
            idle_expires_at = NOW() + make_interval(mins => $2::int)
      FROM admin.admin_users u
      WHERE s.token_hash = $1
        AND s.admin_id = u.id
        AND s.revoked_at IS NULL
        AND s.idle_expires_at > NOW()
        AND s.absolute_expires_at > NOW()
        AND u.status = 'active'
      RETURNING s.id, s.admin_id, s.mfa_satisfied,
                s.idle_expires_at, s.absolute_expires_at, s.device_label`,
    [hashToken(token), config.SESSION_IDLE_TIMEOUT_MINUTES],
  );

  const row = rows[0];
  if (!row) return null;

  return {
    id: row.id,
    adminId: row.admin_id,
    mfaSatisfied: row.mfa_satisfied,
    idleExpiresAt: row.idle_expires_at,
    absoluteExpiresAt: row.absolute_expires_at,
    deviceLabel: row.device_label,
  };
}

/** Promote a password-only session once TOTP has been satisfied. */
export async function markMfaSatisfied(client: PoolClient, sessionId: string): Promise<void> {
  await client.query(
    `UPDATE admin.sessions SET mfa_satisfied = TRUE WHERE id = $1`,
    [sessionId],
  );
}

export async function revokeSession(
  client: PoolClient,
  sessionId: string,
  revokedBy: string | null,
  reason: string,
): Promise<void> {
  await client.query(
    `UPDATE admin.sessions
        SET revoked_at = NOW(), revoked_by = $2, revoke_reason = $3
      WHERE id = $1 AND revoked_at IS NULL`,
    [sessionId, revokedBy, reason],
  );
}

/** §1.3 force-logout-everywhere. `exceptSessionId` keeps the caller signed in. */
export async function revokeAllSessions(
  client: PoolClient,
  adminId: string,
  revokedBy: string | null,
  reason: string,
  exceptSessionId?: string,
): Promise<number> {
  const { rowCount } = await client.query(
    `UPDATE admin.sessions
        SET revoked_at = NOW(), revoked_by = $2, revoke_reason = $3
      WHERE admin_id = $1
        AND revoked_at IS NULL
        AND ($4::uuid IS NULL OR id <> $4::uuid)`,
    [adminId, revokedBy, reason, exceptSessionId ?? null],
  );
  return rowCount ?? 0;
}

export async function listSessions(adminId: string): Promise<
  Array<{
    id: string;
    deviceLabel: string | null;
    ip: string | null;
    createdAt: Date;
    lastSeenAt: Date;
    absoluteExpiresAt: Date;
    current: boolean;
  }>
> {
  const { rows } = await getPool().query<{
    id: string;
    device_label: string | null;
    ip: string | null;
    created_at: Date;
    last_seen_at: Date;
    absolute_expires_at: Date;
  }>(
    `SELECT id, device_label, ip::text AS ip, created_at, last_seen_at, absolute_expires_at
       FROM admin.sessions
      WHERE admin_id = $1 AND revoked_at IS NULL AND absolute_expires_at > NOW()
      ORDER BY last_seen_at DESC`,
    [adminId],
  );

  return rows.map((r) => ({
    id: r.id,
    deviceLabel: r.device_label,
    ip: r.ip,
    createdAt: r.created_at,
    lastSeenAt: r.last_seen_at,
    absoluteExpiresAt: r.absolute_expires_at,
    current: false,
  }));
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

/**
 * Double-submit CSRF token.
 *
 * The session cookie is SameSite=Strict, which already blocks the classic
 * cross-site form post. This is the second layer, for the cases SameSite does
 * not cover cleanly — notably a same-site subdomain compromise.
 */
export function generateCsrfToken(): string {
  return randomBytes(32).toString('base64url');
}

export function csrfMatches(cookieValue: string | undefined, headerValue: string | undefined): boolean {
  if (!cookieValue || !headerValue) return false;
  const a = Buffer.from(cookieValue);
  const b = Buffer.from(headerValue);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
