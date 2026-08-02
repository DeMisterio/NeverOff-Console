import { getPool, withTransaction } from '@neveroff-console/db';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { checkPiiAccessAnomalies, writeAudit } from '../audit.js';
import { notFound } from '../errors.js';
import { actorOf } from '../plugins/auth.js';
import { assertInScope, recordPiiAccess, requirePermission } from '../rbac.js';

/**
 * User directory and profiles (§3.1, §3.2).
 *
 * Two things shape every query here:
 *
 *   1. Scope is pushed into SQL, not applied after the fact. Filtering rows in
 *      JavaScript after a paginated query would produce short pages and a wrong
 *      total, and would leak the existence of out-of-scope users through the count.
 *
 *   2. The directory view carries no identifiers at all. Email, devices and the
 *      connections graph live behind `users.view_pii` on a separate endpoint
 *      that records every single reveal against the case that justified it.
 */

const StatusEnum = z.enum([
  'active', 'warned', 'restricted', 'muted', 'shadow_restricted',
  'banned_temporary', 'banned_permanent', 'deleted',
]);

const DirectoryQuery = z.object({
  search: z.string().trim().min(1).max(120).optional(),
  status: z.union([StatusEnum, z.array(StatusEnum)]).optional(),
  country: z.string().length(2).toUpperCase().optional(),
  registeredAfter: z.coerce.date().optional(),
  registeredBefore: z.coerce.date().optional(),
  activeSince: z.coerce.date().optional(),
  minActions: z.coerce.number().int().min(0).optional(),
  isChannelOwner: z.coerce.boolean().optional(),
  underLegalHold: z.coerce.boolean().optional(),
  sort: z
    .enum(['registered_at', 'last_message_at', 'message_count', 'lifetime_action_count', 'username'])
    .default('registered_at'),
  direction: z.enum(['asc', 'desc']).default('desc'),
  limit: z.coerce.number().int().min(1).max(100).default(25),
  offset: z.coerce.number().int().min(0).default(0),
});

const DirectoryRow = z.object({
  id: z.string(),
  username: z.string(),
  displayName: z.string().nullable(),
  avatarUrl: z.string().nullable(),
  country: z.string().nullable(),
  registeredAt: z.date(),
  status: z.string(),
  blocksAccess: z.boolean(),
  blocksSending: z.boolean(),
  restrictedFeatures: z.array(z.string()),
  nextExpiryAt: z.date().nullable(),
  activeActionCount: z.number(),
  lifetimeActionCount: z.number(),
  appealCount: z.number(),
  messageCount: z.number(),
  lastMessageAt: z.date().nullable(),
  ownedChannelCount: z.number(),
  underLegalHold: z.boolean(),
  trustScore: z.number().nullable(),
});

// Whitelist, not interpolation. `sort` is validated by zod above, but mapping
// it through a fixed table means a future refactor that loosens the enum still
// cannot turn this into an injection point.
const SORT_COLUMNS: Record<string, string> = {
  registered_at: 'registered_at',
  last_message_at: 'last_message_at',
  message_count: 'message_count',
  lifetime_action_count: 'lifetime_action_count',
  username: 'username',
};

export default async function userRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  // -------------------------------------------------------------------------
  // Directory
  // -------------------------------------------------------------------------
  app.get(
    '/',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['users'],
        summary: 'Server-side filtered, paginated user directory',
        querystring: DirectoryQuery,
        response: {
          200: z.object({
            rows: z.array(DirectoryRow),
            total: z.number(),
            limit: z.number(),
            offset: z.number(),
            scopeApplied: z.boolean(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'users.view');

      const q = request.query;
      const where: string[] = [];
      const params: unknown[] = [];
      const add = (clause: string, value: unknown): void => {
        params.push(value);
        where.push(clause.replace('?', `$${params.length}`));
      };

      if (q.search) {
        requirePermission(actor, 'users.search');
        // §3.1: "exact-match only for identifiers (no fuzzy PII scraping)".
        // Username and id are exact; display name is a prefix match, which is
        // a display field rather than an identifier.
        params.push(q.search, `${q.search.toLowerCase()}%`);
        const exact = `$${params.length - 1}`;
        const prefix = `$${params.length}`;
        where.push(
          `(lower(username) = lower(${exact})
            OR id::text = ${exact}
            OR lower(coalesce(display_name, '')) LIKE ${prefix})`,
        );
      }

      if (q.status) {
        const statuses = Array.isArray(q.status) ? q.status : [q.status];
        add('status = ANY(?)', statuses);
      }
      if (q.country) add('country = ?', q.country);
      if (q.registeredAfter) add('registered_at >= ?', q.registeredAfter);
      if (q.registeredBefore) add('registered_at <= ?', q.registeredBefore);
      if (q.activeSince) add('last_message_at >= ?', q.activeSince);
      if (q.minActions !== undefined) add('lifetime_action_count >= ?', q.minActions);
      if (q.isChannelOwner !== undefined) {
        where.push(q.isChannelOwner ? 'owned_channel_count > 0' : 'owned_channel_count = 0');
      }
      if (q.underLegalHold !== undefined) add('under_legal_hold = ?', q.underLegalHold);

      // --- Scope, pushed into SQL -----------------------------------------
      const scopeApplied = actor.scope.countries !== null;
      if (actor.scope.countries !== null) {
        // `country IS NOT NULL AND country = ANY(...)` — a scoped admin does not
        // see users whose country is unknown. Same rule as scopeAdmits().
        add('(country IS NOT NULL AND country = ANY(?))', [...actor.scope.countries]);
      }

      const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
      const sortColumn = SORT_COLUMNS[q.sort] ?? 'registered_at';
      const direction = q.direction === 'asc' ? 'ASC' : 'DESC';

      const pool = getPool();

      const countResult = await pool.query<{ total: string }>(
        `SELECT count(*)::text AS total FROM admin.user_directory ${whereSql}`,
        params,
      );

      const rowsResult = await pool.query(
        `SELECT *, admin.trust_score_value(id) AS trust_score
           FROM admin.user_directory
           ${whereSql}
          ORDER BY ${sortColumn} ${direction} NULLS LAST, id ASC
          LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, q.limit, q.offset],
      );

      return {
        rows: rowsResult.rows.map((r) => ({
          id: r.id,
          username: r.username,
          displayName: r.display_name,
          avatarUrl: r.avatar_url,
          country: r.country,
          registeredAt: r.registered_at,
          status: r.status,
          blocksAccess: r.blocks_access,
          blocksSending: r.blocks_sending,
          restrictedFeatures: r.restricted_features ?? [],
          nextExpiryAt: r.next_expiry_at,
          activeActionCount: Number(r.active_action_count),
          lifetimeActionCount: Number(r.lifetime_action_count),
          appealCount: Number(r.appeal_count),
          messageCount: Number(r.message_count),
          lastMessageAt: r.last_message_at,
          ownedChannelCount: Number(r.owned_channel_count),
          underLegalHold: r.under_legal_hold,
          trustScore: r.trust_score === null ? null : Number(r.trust_score),
        })),
        total: Number(countResult.rows[0]?.total ?? 0),
        limit: q.limit,
        offset: q.offset,
        scopeApplied,
      };
    },
  );

  // -------------------------------------------------------------------------
  // Profile
  // -------------------------------------------------------------------------
  app.get(
    '/:id',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['users'],
        summary: 'User profile with safety history and trust breakdown',
        params: z.object({ id: z.string().uuid() }),
        response: {
          200: z.object({
            user: DirectoryRow,
            trustScore: z.object({
              total: z.number(),
              baseline: z.number(),
              known: z.boolean(),
              components: z.array(
                z.object({
                  key: z.string(),
                  label: z.string(),
                  points: z.number(),
                  max: z.number(),
                  detail: z.string(),
                }),
              ),
            }),
            enforcementHistory: z.array(
              z.object({
                id: z.string(),
                type: z.string(),
                caseRef: z.string(),
                reasonCode: z.string(),
                note: z.string(),
                issuedByLabel: z.string(),
                issuedAt: z.date(),
                expiresAt: z.date().nullable(),
                reversedAt: z.date().nullable(),
                reversalReason: z.string().nullable(),
                autoLifted: z.boolean(),
                origin: z.string(),
                active: z.boolean(),
              }),
            ),
            appeals: z.array(
              z.object({
                id: z.string(),
                actionId: z.string(),
                status: z.string(),
                submittedAt: z.date(),
                reviewedAt: z.date().nullable(),
                slaDueAt: z.date(),
              }),
            ),
            ownedChannels: z.array(
              z.object({
                id: z.string(),
                name: z.string(),
                username: z.string(),
                subscriberCount: z.number(),
                isPublic: z.boolean(),
              }),
            ),
            piiAvailable: z.boolean(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'users.view');

      const pool = getPool();
      const { id } = request.params;

      const userResult = await pool.query(
        `SELECT *, admin.trust_score_value(id) AS trust_score
           FROM admin.user_directory WHERE id = $1`,
        [id],
      );
      const row = userResult.rows[0];
      if (!row) throw notFound('User');

      // Scope check before returning anything. Out-of-scope reads as 403 rather
      // than 404 by design — see errors.ts on not building an enumeration oracle.
      assertInScope(actor, { country: row.country });

      const [scoreResult, historyResult, appealsResult, channelsResult] = await Promise.all([
        pool.query<{ score: unknown }>(`SELECT admin.trust_score($1) AS score`, [id]),
        pool.query(
          `SELECT id, type, case_ref, reason_code, note, issued_by_label, issued_at,
                  expires_at, reversed_at, reversal_reason, auto_lifted, origin,
                  (reversed_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())) AS active
             FROM admin.enforcement_actions
            WHERE user_id = $1
            ORDER BY issued_at DESC`,
          [id],
        ),
        pool.query(
          `SELECT id, action_id, status, submitted_at, reviewed_at, sla_due_at
             FROM admin.appeals WHERE user_id = $1 ORDER BY submitted_at DESC`,
          [id],
        ),
        pool.query(
          `SELECT id, name, username, subscriber_count, is_public
             FROM public.channels WHERE owner_id = $1 ORDER BY subscriber_count DESC`,
          [id],
        ),
      ]);

      const score = scoreResult.rows[0]?.score as {
        total: number;
        baseline: number;
        known: boolean;
        components: Array<{ key: string; label: string; points: number; max: number; detail: string }>;
      };

      return {
        user: {
          id: row.id,
          username: row.username,
          displayName: row.display_name,
          avatarUrl: row.avatar_url,
          country: row.country,
          registeredAt: row.registered_at,
          status: row.status,
          blocksAccess: row.blocks_access,
          blocksSending: row.blocks_sending,
          restrictedFeatures: row.restricted_features ?? [],
          nextExpiryAt: row.next_expiry_at,
          activeActionCount: Number(row.active_action_count),
          lifetimeActionCount: Number(row.lifetime_action_count),
          appealCount: Number(row.appeal_count),
          messageCount: Number(row.message_count),
          lastMessageAt: row.last_message_at,
          ownedChannelCount: Number(row.owned_channel_count),
          underLegalHold: row.under_legal_hold,
          trustScore: row.trust_score === null ? null : Number(row.trust_score),
        },
        trustScore: score,
        enforcementHistory: historyResult.rows.map((r) => ({
          id: r.id,
          type: r.type,
          caseRef: r.case_ref,
          reasonCode: r.reason_code,
          note: r.note,
          issuedByLabel: r.issued_by_label,
          issuedAt: r.issued_at,
          expiresAt: r.expires_at,
          reversedAt: r.reversed_at,
          reversalReason: r.reversal_reason,
          autoLifted: r.auto_lifted,
          origin: r.origin,
          active: r.active,
        })),
        appeals: appealsResult.rows.map((r) => ({
          id: r.id,
          actionId: r.action_id,
          status: r.status,
          submittedAt: r.submitted_at,
          reviewedAt: r.reviewed_at,
          slaDueAt: r.sla_due_at,
        })),
        ownedChannels: channelsResult.rows.map((r) => ({
          id: r.id,
          name: r.name,
          username: r.username,
          subscriberCount: Number(r.subscriber_count),
          isPublic: r.is_public,
        })),
        piiAvailable: actor.permissions.has('users.view_pii'),
      };
    },
  );

  // -------------------------------------------------------------------------
  // Personal data (§8: gated, justified, and logged every single time)
  // -------------------------------------------------------------------------
  app.post(
    '/:id/personal-data',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['users'],
        summary: 'Reveal personal data. Requires a justification and is audit-logged.',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({
          reason: z.string().trim().min(5).max(500),
          caseRef: z.string().max(64).optional(),
          ticketId: z.string().uuid().optional(),
        }),
        response: {
          200: z.object({
            email: z.string().nullable(),
            emailConfirmedAt: z.date().nullable(),
            lastSignInAt: z.date().nullable(),
            registrationCountry: z.string().nullable(),
            hasPushToken: z.boolean(),
            consent: z.array(
              z.object({
                key: z.string(),
                granted: z.boolean(),
                recordedAt: z.date(),
                version: z.number(),
              }),
            ),
            notice: z.string(),
          }),
        },
      },
      // A reveal is not something anyone needs to do fifty times a minute.
      config: { rateLimit: { max: 30, timeWindow: '1 minute' } },
    },
    async (request) => {
      const actor = actorOf(request);
      const { id } = request.params;
      const pool = getPool();

      const dirResult = await pool.query<{ country: string | null; username: string }>(
        `SELECT country, username FROM admin.user_directory WHERE id = $1`,
        [id],
      );
      const dir = dirResult.rows[0];
      if (!dir) throw notFound('User');
      assertInScope(actor, { country: dir.country });

      return withTransaction(async (client) => {
        // Throws if the actor lacks users.view_pii or gave no real reason.
        await recordPiiAccess(
          client,
          actor,
          { userId: id, label: `@${dir.username}` },
          {
            reason: request.body.reason,
            caseRef: request.body.caseRef,
            ticketId: request.body.ticketId,
          },
        );

        await checkPiiAccessAnomalies(client, actor, id);

        const [authResult, profileResult, consentResult] = await Promise.all([
          client.query<{ email: string | null; email_confirmed_at: Date | null; last_sign_in_at: Date | null }>(
            `SELECT email, email_confirmed_at, last_sign_in_at FROM auth.users WHERE id = $1`,
            [id],
          ),
          client.query<{ fcm_token: string | null }>(
            `SELECT fcm_token FROM public.profiles WHERE id = $1`,
            [id],
          ),
          client.query(
            `SELECT consent_key, granted, recorded_at, consent_version
               FROM admin.current_consent WHERE user_id = $1`,
            [id],
          ),
        ]);

        const auth = authResult.rows[0];

        return {
          email: auth?.email ?? null,
          emailConfirmedAt: auth?.email_confirmed_at ?? null,
          lastSignInAt: auth?.last_sign_in_at ?? null,
          registrationCountry: dir.country,
          // The token itself is a credential for sending push to this device.
          // Whether one exists is all an admin needs to know.
          hasPushToken: Boolean(profileResult.rows[0]?.fcm_token),
          consent: consentResult.rows.map((r) => ({
            key: r.consent_key,
            granted: r.granted,
            recordedAt: r.recorded_at,
            version: Number(r.consent_version),
          })),
          notice:
            'This access has been recorded in the audit log against your account, with the ' +
            'reason you supplied.',
        };
      });
    },
  );

  // -------------------------------------------------------------------------
  // Internal note (§3.3, first rung of the ladder)
  // -------------------------------------------------------------------------
  app.post(
    '/:id/notes',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['users'],
        summary: 'Attach an internal note. The user never sees it.',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({ note: z.string().trim().min(10).max(2000) }),
        response: { 200: z.object({ id: z.string(), caseRef: z.string() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'users.note');

      const { id } = request.params;
      const pool = getPool();

      const dirResult = await pool.query<{ country: string | null; username: string }>(
        `SELECT country, username FROM admin.user_directory WHERE id = $1`,
        [id],
      );
      const dir = dirResult.rows[0];
      if (!dir) throw notFound('User');
      assertInScope(actor, { country: dir.country });

      return withTransaction(async (client) => {
        const { rows } = await client.query<{ id: string; case_ref: string }>(
          `INSERT INTO admin.enforcement_actions
             (user_id, type, reason_code, note, issued_by, issued_by_label)
           VALUES ($1, 'note', 'other.terms_violation', $2, $3, $4)
           RETURNING id, case_ref`,
          [id, request.body.note, actor.id, `${actor.displayName} <${actor.email}>`],
        );

        const created = rows[0]!;
        await writeAudit(client, actor, {
          action: 'user.note.added',
          targetType: 'user',
          targetId: id,
          targetLabel: `@${dir.username}`,
          permission: 'users.note',
          note: request.body.note,
          after: { caseRef: created.case_ref },
        });

        return { id: created.id, caseRef: created.case_ref };
      });
    },
  );
}
