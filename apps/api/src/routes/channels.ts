import { getPool, withTransaction } from '@neveroff-console/db';
import { CHANNEL_ACTION_TYPES } from '@neveroff-console/shared';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { notFound } from '../errors.js';
import { actorOf } from '../plugins/auth.js';
import { requirePermission } from '../rbac.js';
import {
  applyChannelAction,
  assertChannelInScope,
  loadChannelTarget,
  reverseChannelAction,
} from '../services/channels.js';

/**
 * Channel governance (§6.5).
 *
 * Channels are the highest-leverage abuse surface, so the directory is sorted
 * by risk — reach × open trouble — rather than by report count. A channel with
 * 100,000 subscribers and one open case matters more than one with forty
 * subscribers and three.
 */

export const ChannelActionBody = z.object({
  type: z.enum(CHANNEL_ACTION_TYPES),
  reasonCode: z.string().min(1).max(80),
  note: z.string().trim().min(10).max(2000),
  expiresAt: z.coerce.date().nullable().default(null),
  countries: z.array(z.string().length(2).toUpperCase()).optional(),
  breakGlass: z
    .object({
      requestId: z.string().uuid().optional(),
      confirmationPhrase: z.string().max(300).optional(),
      justification: z.string().max(1000).optional(),
    })
    .optional(),
});

const DirectoryRow = z.object({
  id: z.string(),
  name: z.string(),
  username: z.string(),
  isPublic: z.boolean(),
  subscriberCount: z.number(),
  postCount: z.number(),
  lastPostAt: z.date().nullable(),
  createdAt: z.date(),
  ownerId: z.string(),
  ownerUsername: z.string(),
  caseCount: z.number(),
  openCaseCount: z.number(),
  actionCount: z.number(),
  riskScore: z.number(),
  restrictionState: z.record(z.unknown()),
});

export default async function channelRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  // -------------------------------------------------------------------------
  app.get(
    '/',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['channels'],
        summary: 'Channel directory, ordered by risk',
        querystring: z.object({
          search: z.string().trim().min(1).max(120).optional(),
          restricted: z.coerce.boolean().optional(),
          hasOpenCase: z.coerce.boolean().optional(),
          minSubscribers: z.coerce.number().int().min(0).optional(),
          sort: z.enum(['risk_score', 'subscriber_count', 'created_at', 'open_case_count'])
            .default('risk_score'),
          limit: z.coerce.number().int().min(1).max(100).default(25),
          offset: z.coerce.number().int().min(0).default(0),
        }),
        response: {
          200: z.object({
            rows: z.array(DirectoryRow),
            total: z.number(),
            scopeApplied: z.boolean(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'channels.view');

      const q = request.query;
      const where: string[] = [];
      const params: unknown[] = [];

      if (q.search) {
        params.push(q.search, `${q.search.toLowerCase()}%`);
        where.push(
          `(lower(username) = lower($${params.length - 1}) OR lower(name) LIKE $${params.length})`,
        );
      }
      if (q.minSubscribers !== undefined) {
        params.push(q.minSubscribers);
        where.push(`subscriber_count >= $${params.length}`);
      }
      if (q.hasOpenCase !== undefined) {
        where.push(q.hasOpenCase ? 'open_case_count > 0' : 'open_case_count = 0');
      }
      if (q.restricted !== undefined) {
        where.push(q.restricted ? 'action_count > 0' : 'action_count = 0');
      }

      const scopeApplied = actor.scope.channelIds !== null;
      if (scopeApplied) {
        params.push([...actor.scope.channelIds!]);
        where.push(`id = ANY($${params.length}::uuid[])`);
      }

      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
      // Whitelisted, not interpolated from user input.
      const sortColumn = {
        risk_score: 'risk_score',
        subscriber_count: 'subscriber_count',
        created_at: 'created_at',
        open_case_count: 'open_case_count',
      }[q.sort];

      const pool = getPool();
      const [countResult, rowsResult] = await Promise.all([
        pool.query<{ total: string }>(
          `SELECT count(*)::text AS total FROM admin.channel_directory ${whereSql}`,
          params,
        ),
        pool.query(
          `SELECT * FROM admin.channel_directory ${whereSql}
            ORDER BY ${sortColumn} DESC NULLS LAST, id ASC
            LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
          [...params, q.limit, q.offset],
        ),
      ]);

      return {
        rows: rowsResult.rows.map((r) => ({
          id: r.id,
          name: r.name,
          username: r.username,
          isPublic: r.is_public,
          subscriberCount: Number(r.subscriber_count),
          postCount: Number(r.post_count),
          lastPostAt: r.last_post_at,
          createdAt: r.created_at,
          ownerId: r.owner_id,
          ownerUsername: r.owner_username,
          caseCount: Number(r.case_count),
          openCaseCount: Number(r.open_case_count),
          actionCount: Number(r.action_count),
          riskScore: Number(r.risk_score),
          restrictionState: r.restriction_state,
        })),
        total: Number(countResult.rows[0]?.total ?? 0),
        scopeApplied,
      };
    },
  );

  // -------------------------------------------------------------------------
  app.get(
    '/:id',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['channels'],
        summary: 'Channel detail with action history and growth',
        params: z.object({ id: z.string().uuid() }),
        response: {
          200: z.object({
            channel: DirectoryRow,
            actions: z.array(
              z.object({
                id: z.string(),
                type: z.string(),
                caseRef: z.string(),
                reasonCode: z.string(),
                note: z.string(),
                issuedByLabel: z.string(),
                issuedAt: z.date(),
                expiresAt: z.date().nullable(),
                countries: z.array(z.string()).nullable(),
                reversedAt: z.date().nullable(),
                reversalReason: z.string().nullable(),
                active: z.boolean(),
              }),
            ),
            growth: z.array(
              z.object({ capturedAt: z.date(), subscriberCount: z.number() }),
            ),
            ownerAccountability: z
              .object({
                channelsOwned: z.number(),
                channelsActioned: z.number(),
                takedowns: z.number(),
                totalReach: z.number(),
              })
              .nullable(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'channels.view');
      assertChannelInScope(actor, request.params.id);

      const pool = getPool();
      const channelResult = await pool.query(
        `SELECT * FROM admin.channel_directory WHERE id = $1`,
        [request.params.id],
      );
      const c = channelResult.rows[0];
      if (!c) throw notFound('Channel');

      const [actions, growth, accountability] = await Promise.all([
        pool.query(
          `SELECT id, type, case_ref, reason_code, note, issued_by_label, issued_at,
                  expires_at, countries, reversed_at, reversal_reason,
                  (reversed_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())) AS active
             FROM admin.channel_actions
            WHERE channel_id = $1
            ORDER BY issued_at DESC`,
          [request.params.id],
        ),
        pool.query(
          `SELECT captured_at, subscriber_count FROM admin.channel_growth_snapshots
            WHERE channel_id = $1 AND captured_at > NOW() - INTERVAL '30 days'
            ORDER BY captured_at ASC`,
          [request.params.id],
        ),
        pool.query(
          `SELECT channels_owned, channels_actioned, takedowns, total_reach
             FROM admin.channel_owner_accountability WHERE owner_id = $1`,
          [c.owner_id],
        ),
      ]);

      const acc = accountability.rows[0];

      return {
        channel: {
          id: c.id,
          name: c.name,
          username: c.username,
          isPublic: c.is_public,
          subscriberCount: Number(c.subscriber_count),
          postCount: Number(c.post_count),
          lastPostAt: c.last_post_at,
          createdAt: c.created_at,
          ownerId: c.owner_id,
          ownerUsername: c.owner_username,
          caseCount: Number(c.case_count),
          openCaseCount: Number(c.open_case_count),
          actionCount: Number(c.action_count),
          riskScore: Number(c.risk_score),
          restrictionState: c.restriction_state,
        },
        actions: actions.rows.map((a) => ({
          id: a.id,
          type: a.type,
          caseRef: a.case_ref,
          reasonCode: a.reason_code,
          note: a.note,
          issuedByLabel: a.issued_by_label,
          issuedAt: a.issued_at,
          expiresAt: a.expires_at,
          countries: a.countries,
          reversedAt: a.reversed_at,
          reversalReason: a.reversal_reason,
          active: a.active,
        })),
        growth: growth.rows.map((g) => ({
          capturedAt: g.captured_at,
          subscriberCount: Number(g.subscriber_count),
        })),
        ownerAccountability: acc
          ? {
              channelsOwned: Number(acc.channels_owned),
              channelsActioned: Number(acc.channels_actioned),
              takedowns: Number(acc.takedowns),
              totalReach: Number(acc.total_reach ?? 0),
            }
          : null,
      };
    },
  );

  // -------------------------------------------------------------------------
  app.post(
    '/:id/actions',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['channels'],
        summary: 'Apply a channel action from the §6.5 ladder',
        params: z.object({ id: z.string().uuid() }),
        body: ChannelActionBody,
        response: {
          200: z.object({
            id: z.string(),
            caseRef: z.string(),
            type: z.string(),
            expiresAt: z.date().nullable(),
            membersNotified: z.number(),
            ownerNotified: z.boolean(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      assertChannelInScope(actor, request.params.id);

      return withTransaction(async (client) => {
        const target = await loadChannelTarget(client, request.params.id);
        if (!target) throw notFound('Channel');
        return applyChannelAction(client, actor, target, request.body);
      });
    },
  );

  // -------------------------------------------------------------------------
  app.post(
    '/actions/:actionId/reverse',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['channels'],
        summary: 'Lift a channel restriction',
        params: z.object({ actionId: z.string().uuid() }),
        body: z.object({ reason: z.string().trim().min(10).max(1000) }),
        response: {
          200: z.object({ id: z.string(), caseRef: z.string(), reversedAt: z.date() }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      return withTransaction((client) =>
        reverseChannelAction(client, actor, request.params.actionId, request.body.reason),
      );
    },
  );

  // -------------------------------------------------------------------------
  app.get(
    '/owners/accountability',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['channels'],
        summary: 'Owners with repeated violations across their channels (§6.5)',
        response: {
          200: z.array(
            z.object({
              ownerId: z.string(),
              ownerUsername: z.string(),
              channelsOwned: z.number(),
              channelsActioned: z.number(),
              takedowns: z.number(),
              warnings: z.number(),
              totalReach: z.number(),
              lastActionAt: z.date().nullable(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'channels.view');

      const { rows } = await getPool().query(
        `SELECT * FROM admin.channel_owner_accountability
          WHERE channels_actioned > 0
          ORDER BY takedowns DESC, channels_actioned DESC, total_reach DESC
          LIMIT 100`,
      );

      return rows.map((r) => ({
        ownerId: r.owner_id,
        ownerUsername: r.owner_username,
        channelsOwned: Number(r.channels_owned),
        channelsActioned: Number(r.channels_actioned),
        takedowns: Number(r.takedowns),
        warnings: Number(r.warnings),
        totalReach: Number(r.total_reach ?? 0),
        lastActionAt: r.last_action_at,
      }));
    },
  );
}
