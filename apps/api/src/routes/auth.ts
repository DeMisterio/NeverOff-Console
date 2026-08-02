import { getPool, withTransaction } from '@neveroff-console/db';
import type { FastifyInstance, FastifyReply } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import QRCode from 'qrcode';
import { z } from 'zod';

import { actorLabel } from '../actor.js';
import { raiseAlert, writeAudit, writeSystemAudit } from '../audit.js';
import {
  assertPasswordAcceptable,
  hashPassword,
  verifyPassword,
} from '../auth/password.js';
import {
  createSession,
  generateCsrfToken,
  listSessions,
  markMfaSatisfied,
  revokeAllSessions,
  revokeSession,
} from '../auth/session.js';
import {
  decryptSecret,
  encryptSecret,
  enrolmentUri,
  generateRecoveryCodes,
  generateSecret,
  normaliseRecoveryCode,
  verifyCode,
} from '../auth/totp.js';
import { getConfig } from '../config.js';
import { conflict, forbidden, unauthenticated, validationFailed } from '../errors.js';
import { actorOf } from '../plugins/auth.js';

const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MINUTES = 15;

/**
 * A real Argon2id hash of a random string, used to burn the same CPU time when
 * the supplied email does not exist. Without it, "no such account" returns in
 * ~0ms while a wrong password takes ~50ms, and the login endpoint becomes an
 * account-enumeration oracle for anyone with a stopwatch.
 */
let dummyHashPromise: Promise<string> | undefined;
function dummyHash(): Promise<string> {
  dummyHashPromise ??= hashPassword(`decoy-${Math.random()}-${Date.now()}`);
  return dummyHashPromise;
}

function setSessionCookies(reply: FastifyReply, token: string, csrf: string): void {
  const config = getConfig();
  const maxAge = config.SESSION_ABSOLUTE_TIMEOUT_HOURS * 3600;

  reply.setCookie(config.cookieName, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: config.isProduction,
    path: '/',
    maxAge,
  });

  // Readable by the web console so it can echo the value back in a header.
  // That is the whole mechanism of a double-submit token; it is not a secret in
  // the way the session token is.
  reply.setCookie(config.csrfCookieName, csrf, {
    httpOnly: false,
    sameSite: 'strict',
    secure: config.isProduction,
    path: '/',
    maxAge,
  });
}

function clearSessionCookies(reply: FastifyReply): void {
  const config = getConfig();
  reply.clearCookie(config.cookieName, { path: '/' });
  reply.clearCookie(config.csrfCookieName, { path: '/' });
}

interface AdminAuthRow {
  id: string;
  email: string;
  display_name: string;
  password_hash: string;
  status: string;
  must_change_password: boolean;
  totp_secret_encrypted: string | null;
  totp_enrolled_at: Date | null;
  totp_last_step: string | null;
  totp_reenrollment_forced: boolean;
  totp_recovery_hashes: string[];
  failed_login_count: number;
  locked_until: Date | null;
}

export default async function authRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  // -------------------------------------------------------------------------
  // Step 1: password
  // -------------------------------------------------------------------------
  app.post(
    '/login',
    {
      schema: {
        tags: ['auth'],
        summary: 'Sign in with email and password (step 1 of 2)',
        body: z.object({
          email: z.string().email().max(320),
          password: z.string().min(1).max(200),
        }),
        response: {
          200: z.object({
            status: z.enum(['totp_required', 'totp_enrolment_required']),
            mustChangePassword: z.boolean(),
          }),
        },
      },
      // Tight limit: this is the endpoint an attacker hammers.
      config: { rateLimit: { max: 10, timeWindow: '5 minutes' } },
    },
    async (request, reply) => {
      const { email, password } = request.body;
      const pool = getPool();

      const { rows } = await pool.query<AdminAuthRow>(
        `SELECT id, email, display_name, password_hash, status, must_change_password,
                totp_secret_encrypted, totp_enrolled_at, totp_last_step::text,
                totp_reenrollment_forced, totp_recovery_hashes,
                failed_login_count, locked_until
           FROM admin.admin_users
          WHERE lower(email) = lower($1)`,
        [email],
      );

      const admin = rows[0];

      if (!admin) {
        // Spend the same time as a real verification would.
        await verifyPassword(await dummyHash(), password);
        await withTransaction((client) =>
          writeSystemAudit(client, {
            action: 'auth.login.failed',
            targetType: 'admin',
            targetLabel: email,
            note: 'No such admin account.',
            actorLabel: `anonymous <${email}>`,
            origin: 'system',
          }),
        );
        throw unauthenticated('Email or password is incorrect.');
      }

      if (admin.locked_until && admin.locked_until.getTime() > Date.now()) {
        const minutes = Math.ceil((admin.locked_until.getTime() - Date.now()) / 60_000);
        throw forbidden(
          `Too many failed attempts. This account is locked for another ${minutes} minute(s).`,
        );
      }

      if (admin.status === 'suspended' || admin.status === 'disabled') {
        throw forbidden('This admin account is not active. Contact the Super Admin.');
      }

      const passwordOk = await verifyPassword(admin.password_hash, password);

      if (!passwordOk) {
        const failures = admin.failed_login_count + 1;
        await withTransaction(async (client) => {
          await client.query(
            `UPDATE admin.admin_users
                SET failed_login_count = $2,
                    locked_until = CASE WHEN $2 >= $3
                                        THEN NOW() + make_interval(mins => $4::int)
                                        ELSE locked_until END
              WHERE id = $1`,
            [admin.id, failures, MAX_FAILED_LOGINS, LOCKOUT_MINUTES],
          );

          await writeSystemAudit(client, {
            action: 'auth.login.failed',
            targetType: 'admin',
            targetId: admin.id,
            targetLabel: admin.email,
            note: `Incorrect password (attempt ${failures}).`,
            actorLabel: `${admin.display_name} <${admin.email}>`,
            origin: 'system',
          });

          if (failures >= MAX_FAILED_LOGINS) {
            await raiseAlert(client, {
              kind: 'failed_login_burst',
              severity: 'high',
              title: `${admin.display_name}'s account locked after ${failures} failed sign-ins`,
              detail:
                'Either the admin has forgotten their password, or someone is guessing it. ' +
                'Confirm with them out of band before unlocking.',
              subjectAdminId: admin.id,
              evidence: { failures, ip: request.ip },
            });
          }
        });

        throw unauthenticated('Email or password is incorrect.');
      }

      // Password accepted. Create a session that satisfies nothing yet.
      const result = await withTransaction(async (client) => {
        await client.query(
          `UPDATE admin.admin_users
              SET failed_login_count = 0, locked_until = NULL, last_login_at = NOW()
            WHERE id = $1`,
          [admin.id],
        );

        const created = await createSession(client, admin.id, {
          ip: request.ip || null,
          userAgent: request.headers['user-agent'] ?? null,
          mfaSatisfied: false,
        });

        await writeSystemAudit(client, {
          action: 'auth.password.accepted',
          targetType: 'admin',
          targetId: admin.id,
          targetLabel: admin.email,
          note: 'Password step passed; awaiting second factor.',
          actorLabel: `${admin.display_name} <${admin.email}>`,
          origin: 'system',
        });

        return created;
      });

      const csrf = generateCsrfToken();
      setSessionCookies(reply, result.token, csrf);

      const needsEnrolment =
        !admin.totp_secret_encrypted || !admin.totp_enrolled_at || admin.totp_reenrollment_forced;

      return {
        status: needsEnrolment ? ('totp_enrolment_required' as const) : ('totp_required' as const),
        mustChangePassword: admin.must_change_password,
      };
    },
  );

  // -------------------------------------------------------------------------
  // Step 2a: enrol a second factor (first sign-in, or after a forced reset)
  // -------------------------------------------------------------------------
  app.post(
    '/totp/enrolment',
    {
      preHandler: fastify.requirePartialAuth,
      schema: {
        tags: ['auth'],
        summary: 'Begin TOTP enrolment; returns a secret and QR code',
        response: {
          200: z.object({
            secret: z.string(),
            otpauthUri: z.string(),
            qrDataUrl: z.string(),
          }),
        },
      },
      config: { rateLimit: { max: 10, timeWindow: '10 minutes' } },
    },
    async (request) => {
      const actor = actorOf(request);
      const pool = getPool();

      const { rows } = await pool.query<{ totp_enrolled_at: Date | null; totp_reenrollment_forced: boolean }>(
        `SELECT totp_enrolled_at, totp_reenrollment_forced FROM admin.admin_users WHERE id = $1`,
        [actor.id],
      );
      const current = rows[0];

      if (current?.totp_enrolled_at && !current.totp_reenrollment_forced) {
        throw conflict(
          'Two-factor authentication is already set up. Ask the Super Admin to force re-enrolment if you have lost your device.',
        );
      }

      const secret = generateSecret();

      // Stored immediately but `totp_enrolled_at` stays null until a code is
      // confirmed, so an abandoned enrolment cannot leave an account thinking
      // it has a working second factor.
      await pool.query(
        `UPDATE admin.admin_users
            SET totp_secret_encrypted = $2, totp_enrolled_at = NULL, totp_last_step = NULL
          WHERE id = $1`,
        [actor.id, encryptSecret(secret)],
      );

      const uri = enrolmentUri(secret, actor.email);
      return {
        secret,
        otpauthUri: uri,
        qrDataUrl: await QRCode.toDataURL(uri, { margin: 1, width: 240 }),
      };
    },
  );

  app.post(
    '/totp/enrolment/confirm',
    {
      preHandler: fastify.requirePartialAuth,
      schema: {
        tags: ['auth'],
        summary: 'Confirm TOTP enrolment and receive recovery codes',
        body: z.object({ code: z.string().regex(/^\d{6}$/, 'Enter the 6-digit code.') }),
        response: {
          200: z.object({
            recoveryCodes: z.array(z.string()),
            message: z.string(),
          }),
        },
      },
      config: { rateLimit: { max: 10, timeWindow: '5 minutes' } },
    },
    async (request) => {
      const actor = actorOf(request);

      return withTransaction(async (client) => {
        const { rows } = await client.query<{ totp_secret_encrypted: string | null }>(
          `SELECT totp_secret_encrypted FROM admin.admin_users WHERE id = $1 FOR UPDATE`,
          [actor.id],
        );

        const encrypted = rows[0]?.totp_secret_encrypted;
        if (!encrypted) throw conflict('Start enrolment before confirming it.');

        const secret = decryptSecret(encrypted);
        const verdict = verifyCode(secret, request.body.code, null);
        if (!verdict.valid) {
          throw unauthenticated('That code is not correct. Check your authenticator app.');
        }

        const recoveryCodes = generateRecoveryCodes();
        const hashes = await Promise.all(
          recoveryCodes.map((code) => hashPassword(normaliseRecoveryCode(code))),
        );

        await client.query(
          `UPDATE admin.admin_users
              SET totp_enrolled_at = NOW(),
                  totp_last_step = $2,
                  totp_reenrollment_forced = FALSE,
                  totp_recovery_hashes = $3,
                  status = CASE WHEN status = 'invited' THEN 'active' ELSE status END
            WHERE id = $1`,
          [actor.id, verdict.step!.toString(), hashes],
        );

        await markMfaSatisfied(client, actor.sessionId);

        await writeAudit(client, actor, {
          action: 'auth.totp.enrolled',
          targetType: 'admin',
          targetId: actor.id,
          targetLabel: actor.email,
          note: 'Second factor enrolled and confirmed.',
        });

        return {
          recoveryCodes,
          message:
            'Store these recovery codes somewhere safe. Each works once, and they are the only ' +
            'way back in if you lose your authenticator. They will not be shown again.',
        };
      });
    },
  );

  // -------------------------------------------------------------------------
  // Step 2b: verify a code on an already-enrolled account
  // -------------------------------------------------------------------------
  app.post(
    '/totp/verify',
    {
      preHandler: fastify.requirePartialAuth,
      schema: {
        tags: ['auth'],
        summary: 'Complete sign-in with a TOTP code (step 2 of 2)',
        body: z.object({ code: z.string().regex(/^\d{6}$/, 'Enter the 6-digit code.') }),
        response: { 200: z.object({ status: z.literal('authenticated') }) },
      },
      config: { rateLimit: { max: 10, timeWindow: '5 minutes' } },
    },
    async (request) => {
      const actor = actorOf(request);

      return withTransaction(async (client) => {
        // FOR UPDATE serialises concurrent attempts, which is what makes the
        // replay guard below actually hold under a race.
        const { rows } = await client.query<{
          totp_secret_encrypted: string | null;
          totp_enrolled_at: Date | null;
          totp_last_step: string | null;
        }>(
          `SELECT totp_secret_encrypted, totp_enrolled_at, totp_last_step::text
             FROM admin.admin_users WHERE id = $1 FOR UPDATE`,
          [actor.id],
        );

        const row = rows[0];
        if (!row?.totp_secret_encrypted || !row.totp_enrolled_at) {
          throw conflict('Two-factor authentication is not set up on this account.');
        }

        const lastStep = row.totp_last_step ? BigInt(row.totp_last_step) : null;
        const verdict = verifyCode(decryptSecret(row.totp_secret_encrypted), request.body.code, lastStep);

        if (!verdict.valid) {
          await writeSystemAudit(client, {
            action: 'auth.totp.failed',
            targetType: 'admin',
            targetId: actor.id,
            targetLabel: actor.email,
            note: 'Incorrect or already-used TOTP code.',
            actorLabel: actorLabel(actor),
            origin: 'system',
          });
          throw unauthenticated('That code is not correct, or it has already been used.');
        }

        await client.query(
          `UPDATE admin.admin_users SET totp_last_step = $2 WHERE id = $1`,
          [actor.id, verdict.step!.toString()],
        );
        await markMfaSatisfied(client, actor.sessionId);

        await writeAudit(client, actor, {
          action: 'auth.login.succeeded',
          targetType: 'admin',
          targetId: actor.id,
          targetLabel: actor.email,
        });

        return { status: 'authenticated' as const };
      });
    },
  );

  app.post(
    '/totp/recovery',
    {
      preHandler: fastify.requirePartialAuth,
      schema: {
        tags: ['auth'],
        summary: 'Complete sign-in with a single-use recovery code',
        body: z.object({ recoveryCode: z.string().min(8).max(32) }),
        response: {
          200: z.object({ status: z.literal('authenticated'), remainingCodes: z.number() }),
        },
      },
      config: { rateLimit: { max: 5, timeWindow: '15 minutes' } },
    },
    async (request) => {
      const actor = actorOf(request);
      const supplied = normaliseRecoveryCode(request.body.recoveryCode);

      return withTransaction(async (client) => {
        const { rows } = await client.query<{ totp_recovery_hashes: string[] }>(
          `SELECT totp_recovery_hashes FROM admin.admin_users WHERE id = $1 FOR UPDATE`,
          [actor.id],
        );

        const hashes = rows[0]?.totp_recovery_hashes ?? [];

        let matchedIndex = -1;
        for (let i = 0; i < hashes.length; i += 1) {
          if (await verifyPassword(hashes[i]!, supplied)) {
            matchedIndex = i;
            break;
          }
        }

        if (matchedIndex === -1) {
          throw unauthenticated('That recovery code is not valid.');
        }

        const remaining = hashes.filter((_, i) => i !== matchedIndex);
        await client.query(
          `UPDATE admin.admin_users SET totp_recovery_hashes = $2 WHERE id = $1`,
          [actor.id, remaining],
        );
        await markMfaSatisfied(client, actor.sessionId);

        await writeAudit(client, actor, {
          action: 'auth.recovery_code.used',
          targetType: 'admin',
          targetId: actor.id,
          targetLabel: actor.email,
          note: `Recovery code consumed; ${remaining.length} remaining.`,
        });

        await raiseAlert(client, {
          kind: 'failed_login_burst',
          severity: 'medium',
          title: `${actor.displayName} signed in with a recovery code`,
          detail:
            'Recovery codes are for lost devices. If this was not expected, treat the account ' +
            'as compromised and force re-enrolment.',
          subjectAdminId: actor.id,
          evidence: { remaining: remaining.length, ip: request.ip },
        });

        return { status: 'authenticated' as const, remainingCodes: remaining.length };
      });
    },
  );

  // -------------------------------------------------------------------------
  // Session management
  // -------------------------------------------------------------------------
  app.get(
    '/me',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['auth'],
        summary: 'The signed-in admin, their permissions and their scope',
        response: {
          200: z.object({
            id: z.string(),
            email: z.string(),
            displayName: z.string(),
            role: z.string(),
            roleLabel: z.string(),
            rank: z.number(),
            permissions: z.array(z.string()),
            scope: z.object({
              countries: z.array(z.string()).nullable(),
              languages: z.array(z.string()).nullable(),
              channelIds: z.array(z.string()).nullable(),
              reportCategories: z.array(z.string()).nullable(),
            }),
            maxBanDays: z.number().nullable(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      return {
        id: actor.id,
        email: actor.email,
        displayName: actor.displayName,
        role: actor.role,
        roleLabel: actor.roleLabel,
        rank: actor.rank,
        // The UI hides controls based on this list. It is a convenience, not a
        // control — every endpoint re-checks server-side.
        permissions: [...actor.permissions],
        scope: {
          countries: actor.scope.countries ? [...actor.scope.countries] : null,
          languages: actor.scope.languages ? [...actor.scope.languages] : null,
          channelIds: actor.scope.channelIds ? [...actor.scope.channelIds] : null,
          reportCategories: actor.scope.reportCategories ? [...actor.scope.reportCategories] : null,
        },
        maxBanDays: actor.maxBanDays,
      };
    },
  );

  app.get(
    '/sessions',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['auth'],
        summary: 'Devices currently signed in as this admin',
        response: {
          200: z.array(
            z.object({
              id: z.string(),
              deviceLabel: z.string().nullable(),
              ip: z.string().nullable(),
              createdAt: z.date(),
              lastSeenAt: z.date(),
              absoluteExpiresAt: z.date(),
              current: z.boolean(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      const sessions = await listSessions(actor.id);
      return sessions.map((s) => ({ ...s, current: s.id === actor.sessionId }));
    },
  );

  app.post(
    '/sessions/revoke-others',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['auth'],
        summary: 'Force-logout everywhere except this device',
        response: { 200: z.object({ revoked: z.number() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      return withTransaction(async (client) => {
        const revoked = await revokeAllSessions(
          client,
          actor.id,
          actor.id,
          'Force-logout-everywhere by the account holder.',
          actor.sessionId,
        );
        await writeAudit(client, actor, {
          action: 'auth.sessions.revoke_others',
          targetType: 'admin',
          targetId: actor.id,
          targetLabel: actor.email,
          note: `${revoked} session(s) revoked.`,
        });
        return { revoked };
      });
    },
  );

  app.post(
    '/logout',
    {
      preHandler: fastify.requirePartialAuth,
      schema: {
        tags: ['auth'],
        summary: 'Sign out of this device',
        response: { 200: z.object({ status: z.literal('signed_out') }) },
      },
    },
    async (request, reply) => {
      const actor = actorOf(request);
      await withTransaction((client) =>
        revokeSession(client, actor.sessionId, actor.id, 'Signed out.'),
      );
      clearSessionCookies(reply);
      return { status: 'signed_out' as const };
    },
  );

  app.post(
    '/password',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['auth'],
        summary: 'Change your own password',
        body: z.object({
          currentPassword: z.string().min(1).max(200),
          newPassword: z.string().min(12).max(200),
        }),
        response: { 200: z.object({ status: z.literal('changed'), otherSessionsRevoked: z.number() }) },
      },
      config: { rateLimit: { max: 5, timeWindow: '15 minutes' } },
    },
    async (request) => {
      const actor = actorOf(request);
      const { currentPassword, newPassword } = request.body;

      assertPasswordAcceptable(newPassword, {
        email: actor.email,
        displayName: actor.displayName,
      });

      return withTransaction(async (client) => {
        const { rows } = await client.query<{ password_hash: string }>(
          `SELECT password_hash FROM admin.admin_users WHERE id = $1 FOR UPDATE`,
          [actor.id],
        );

        const stored = rows[0]?.password_hash;
        if (!stored || !(await verifyPassword(stored, currentPassword))) {
          throw unauthenticated('Current password is incorrect.');
        }
        if (await verifyPassword(stored, newPassword)) {
          throw validationFailed('The new password must be different from the current one.');
        }

        await client.query(
          `UPDATE admin.admin_users
              SET password_hash = $2, password_updated_at = NOW(), must_change_password = FALSE
            WHERE id = $1`,
          [actor.id, await hashPassword(newPassword)],
        );

        // A password change should end every other session — that is the whole
        // point when the reason for changing it is suspected compromise.
        const revoked = await revokeAllSessions(
          client,
          actor.id,
          actor.id,
          'Password changed.',
          actor.sessionId,
        );

        await writeAudit(client, actor, {
          action: 'auth.password.changed',
          targetType: 'admin',
          targetId: actor.id,
          targetLabel: actor.email,
          note: `Own password changed; ${revoked} other session(s) revoked.`,
        });

        return { status: 'changed' as const, otherSessionsRevoked: revoked };
      });
    },
  );

}
