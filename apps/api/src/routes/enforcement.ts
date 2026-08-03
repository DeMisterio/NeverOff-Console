import { getPool, withTransaction } from '@neveroff-console/db';
import {
  ENFORCEMENT_ACTION_TYPES,
  LADDER,
  RESTRICTABLE_FEATURES,
  isPermission,
} from '@neveroff-console/shared';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { writeAudit } from '../audit.js';
import { conflict, forbidden, notFound, validationFailed } from '../errors.js';
import { actorOf } from '../plugins/auth.js';
import { assertInScope, hashPayload, requirePermission } from '../rbac.js';
import { applyEnforcement, loadEnforcementTarget } from '../services/enforcement.js';

/**
 * Enforcement, appeals and break-glass approvals.
 *
 * The action-application logic lives in services/enforcement.ts because the
 * moderation case decision panel issues enforcement too, and two copies of the
 * ban-length cap would eventually disagree.
 */

const BreakGlassInputSchema = z
  .object({
    requestId: z.string().uuid().optional(),
    confirmationPhrase: z.string().max(300).optional(),
    justification: z.string().max(1000).optional(),
  })
  .optional();

export const ApplyActionBody = z.object({
  type: z.enum(ENFORCEMENT_ACTION_TYPES),
  reasonCode: z.string().min(1).max(80),
  note: z.string().trim().min(10).max(2000),
  expiresAt: z.coerce.date().nullable().default(null),
  restrictedFeatures: z.array(z.enum(RESTRICTABLE_FEATURES)).optional(),
  rateLimitPerMinute: z.number().int().min(1).max(600).optional(),
  contentRemovalScope: z.enum(['none', 'last_24h', 'last_30d', 'all']).default('none'),
  notifyUser: z.boolean().default(true),
  breakGlass: BreakGlassInputSchema,
});

export default async function enforcementRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  /**
   * Permission names arriving in a request body are strings, not `Permission`.
   * Narrowing them through the catalogue rather than casting means an unknown
   * atom is a 422, not a silent grant of something that never existed.
   */
  const permissionFromRequest = (value: string) => {
    if (!isPermission(value)) {
      throw validationFailed(`"${value}" is not a known permission.`, { permission: value });
    }
    return value;
  };

  // -------------------------------------------------------------------------
  app.post(
    '/users/:userId/actions',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['enforcement'],
        summary: 'Apply an enforcement action from the §3.3 ladder',
        params: z.object({ userId: z.string().uuid() }),
        body: ApplyActionBody,
        response: {
          200: z.object({
            id: z.string(),
            caseRef: z.string(),
            type: z.string(),
            expiresAt: z.date().nullable(),
            userNotified: z.boolean(),
            contentRemoved: z.object({ messages: z.number(), channelPosts: z.number() }),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);

      return withTransaction(async (client) => {
        const target = await loadEnforcementTarget(client, request.params.userId);
        if (!target) throw notFound('User');
        assertInScope(actor, { country: target.country });

        return applyEnforcement(client, actor, target, request.body);
      });
    },
  );

  // -------------------------------------------------------------------------
  app.post(
    '/actions/:actionId/reverse',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['enforcement'],
        summary: 'Lift an active enforcement action, with a documented reason',
        params: z.object({ actionId: z.string().uuid() }),
        body: z.object({ reason: z.string().trim().min(10).max(1000) }),
        response: {
          200: z.object({ id: z.string(), caseRef: z.string(), reversedAt: z.date() }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'users.unban');

      return withTransaction(async (client) => {
        const { rows } = await client.query<{
          id: string;
          user_id: string;
          type: string;
          case_ref: string;
          reversed_at: Date | null;
          username: string;
          country: string | null;
        }>(
          `SELECT e.id, e.user_id, e.type, e.case_ref, e.reversed_at, d.username, d.country
             FROM admin.enforcement_actions e
             JOIN admin.user_directory d ON d.id = e.user_id
            WHERE e.id = $1
            FOR UPDATE OF e`,
          [request.params.actionId],
        );

        const action = rows[0];
        if (!action) throw notFound('Enforcement action');
        assertInScope(actor, { country: action.country });

        if (action.reversed_at) throw conflict('That action has already been reversed.');
        if (action.type === 'account_deletion') {
          // The data is gone. Pretending otherwise would be worse than refusing.
          throw conflict('Account deletion is irreversible and cannot be lifted.');
        }

        const updated = await client.query<{ reversed_at: Date }>(
          `UPDATE admin.enforcement_actions
              SET reversed_at = NOW(), reversed_by = $2, reversal_reason = $3
            WHERE id = $1
            RETURNING reversed_at`,
          [action.id, actor.id, request.body.reason],
        );

        await writeAudit(client, actor, {
          action: 'user.enforcement.reversed',
          targetType: 'user',
          targetId: action.user_id,
          targetLabel: `@${action.username}`,
          permission: 'users.unban',
          note: request.body.reason,
          before: { actionId: action.id, type: action.type, active: true },
          after: { actionId: action.id, type: action.type, active: false },
        });

        if (LADDER[action.type as keyof typeof LADDER]?.visibility === 'notified') {
          await client.query(
            `INSERT INTO admin.notification_outbox (user_id, kind, payload, related_action_id)
             VALUES ($1, 'enforcement_reversed', $2, $3)`,
            [
              action.user_id,
              JSON.stringify({ case_ref: action.case_ref, action_type: action.type }),
              action.id,
            ],
          );
        }

        return {
          id: action.id,
          caseRef: action.case_ref,
          reversedAt: updated.rows[0]!.reversed_at,
        };
      });
    },
  );

  // -------------------------------------------------------------------------
  // Appeals (§4)
  // -------------------------------------------------------------------------
  app.get(
    '/appeals',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['enforcement'],
        summary: 'Appeals queue',
        querystring: z.object({
          status: z
            .enum(['pending', 'under_review', 'upheld', 'overturned', 'partially_upheld', 'withdrawn'])
            .optional(),
          breachingSla: z.coerce.boolean().optional(),
          limit: z.coerce.number().int().min(1).max(100).default(25),
          offset: z.coerce.number().int().min(0).default(0),
        }),
        response: {
          200: z.object({
            rows: z.array(
              z.object({
                id: z.string(),
                caseRef: z.string(),
                userId: z.string(),
                username: z.string(),
                actionType: z.string(),
                reasonCode: z.string(),
                body: z.string(),
                status: z.string(),
                submittedAt: z.date(),
                slaDueAt: z.date(),
                escalatedAt: z.date().nullable(),
                issuedByAdminId: z.string().nullable(),
                reviewableByYou: z.boolean(),
              }),
            ),
            total: z.number(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'reports.view');

      const q = request.query;
      const where: string[] = [];
      const params: unknown[] = [];

      if (q.status) {
        params.push(q.status);
        where.push(`a.status = $${params.length}`);
      }
      if (q.breachingSla) {
        where.push(`a.sla_due_at <= NOW() AND a.status IN ('pending','under_review')`);
      }
      if (actor.scope.countries !== null) {
        params.push([...actor.scope.countries]);
        where.push(`(d.country IS NOT NULL AND d.country = ANY($${params.length}))`);
      }

      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
      const pool = getPool();

      const [countResult, rowsResult] = await Promise.all([
        pool.query<{ total: string }>(
          `SELECT count(*)::text AS total
             FROM admin.appeals a
             JOIN admin.enforcement_actions e ON e.id = a.action_id
             JOIN admin.user_directory d ON d.id = a.user_id
             ${whereSql}`,
          params,
        ),
        pool.query(
          `SELECT a.id, e.case_ref, a.user_id, d.username, e.type AS action_type,
                  e.reason_code, a.body, a.status, a.submitted_at, a.sla_due_at,
                  a.escalated_at, e.issued_by
             FROM admin.appeals a
             JOIN admin.enforcement_actions e ON e.id = a.action_id
             JOIN admin.user_directory d ON d.id = a.user_id
             ${whereSql}
            ORDER BY a.sla_due_at ASC
            LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
          [...params, q.limit, q.offset],
        ),
      ]);

      return {
        rows: rowsResult.rows.map((r) => ({
          id: r.id,
          caseRef: r.case_ref,
          userId: r.user_id,
          username: r.username,
          actionType: r.action_type,
          reasonCode: r.reason_code,
          body: r.body,
          status: r.status,
          submittedAt: r.submitted_at,
          slaDueAt: r.sla_due_at,
          escalatedAt: r.escalated_at,
          issuedByAdminId: r.issued_by,
          // §4: the issuing moderator may not review their own decision.
          reviewableByYou: r.issued_by !== actor.id && actor.permissions.has('reports.resolve'),
        })),
        total: Number(countResult.rows[0]?.total ?? 0),
      };
    },
  );

  app.post(
    '/appeals/:appealId/decide',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['enforcement'],
        summary: 'Decide an appeal. The issuing admin cannot decide their own.',
        params: z.object({ appealId: z.string().uuid() }),
        body: z.object({
          outcome: z.enum(['upheld', 'overturned', 'partially_upheld']),
          decisionNote: z.string().trim().min(10).max(2000),
        }),
        response: {
          200: z.object({ id: z.string(), outcome: z.string(), actionReversed: z.boolean() }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'reports.resolve');

      return withTransaction(async (client) => {
        const { rows } = await client.query<{
          id: string;
          action_id: string;
          user_id: string;
          status: string;
          issued_by: string | null;
          case_ref: string;
          action_type: string;
          username: string;
          country: string | null;
        }>(
          `SELECT a.id, a.action_id, a.user_id, a.status,
                  e.issued_by, e.case_ref, e.type AS action_type, d.username, d.country
             FROM admin.appeals a
             JOIN admin.enforcement_actions e ON e.id = a.action_id
             JOIN admin.user_directory d ON d.id = a.user_id
            WHERE a.id = $1
            FOR UPDATE OF a`,
          [request.params.appealId],
        );

        const appeal = rows[0];
        if (!appeal) throw notFound('Appeal');
        assertInScope(actor, { country: appeal.country });

        if (!['pending', 'under_review'].includes(appeal.status)) {
          throw conflict(`This appeal is already ${appeal.status}.`);
        }

        // Checked here for a readable error; also enforced by a database
        // trigger, so it holds even if some future path forgets.
        if (appeal.issued_by && appeal.issued_by === actor.id) {
          throw forbidden(
            'You issued the action being appealed. §4 requires a different reviewer. ' +
              'Reassign this appeal to a colleague.',
            { issuedBy: appeal.issued_by },
          );
        }

        const overturn = request.body.outcome !== 'upheld';

        await client.query(
          `UPDATE admin.appeals
              SET status = $2, reviewed_by = $3, reviewed_at = NOW(), decision_note = $4
            WHERE id = $1`,
          [appeal.id, request.body.outcome, actor.id, request.body.decisionNote],
        );

        if (overturn) {
          requirePermission(actor, 'users.unban');
          await client.query(
            `UPDATE admin.enforcement_actions
                SET reversed_at = NOW(), reversed_by = $2, reversal_reason = $3
              WHERE id = $1 AND reversed_at IS NULL`,
            [appeal.action_id, actor.id, `Overturned on appeal: ${request.body.decisionNote}`],
          );
        }

        await writeAudit(client, actor, {
          action: 'appeal.decided',
          targetType: 'appeal',
          targetId: appeal.id,
          targetLabel: appeal.case_ref,
          permission: 'reports.resolve',
          note: request.body.decisionNote,
          before: { status: appeal.status },
          after: {
            status: request.body.outcome,
            actionReversed: overturn,
            originalIssuer: appeal.issued_by,
          },
        });

        await client.query(
          `INSERT INTO admin.notification_outbox (user_id, kind, payload, related_action_id)
           VALUES ($1, 'appeal_decided', $2, $3)`,
          [
            appeal.user_id,
            JSON.stringify({
              case_ref: appeal.case_ref,
              outcome: request.body.outcome,
              action_type: appeal.action_type,
            }),
            appeal.action_id,
          ],
        );

        await client.query(`SELECT admin.bump_transparency_counter('appeal_decided', $1)`, [
          request.body.outcome,
        ]);

        return { id: appeal.id, outcome: request.body.outcome, actionReversed: overturn };
      });
    },
  );

  // -------------------------------------------------------------------------
  // Break-glass approvals (§1.3)
  // -------------------------------------------------------------------------
  app.post(
    '/break-glass',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['enforcement'],
        summary: 'Raise a request for a second admin to approve',
        body: z.object({
          permission: z.string().min(1).max(80),
          targetType: z.string().min(1).max(40),
          targetId: z.string().min(1).max(120),
          payload: z.record(z.unknown()),
          justification: z.string().trim().min(10).max(1000),
        }),
        response: { 200: z.object({ id: z.string(), expiresAt: z.date(), status: z.string() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      const body = request.body;

      // You cannot ask for approval to do something you could not do yourself.
      const permission = permissionFromRequest(body.permission);
      requirePermission(actor, permission);

      return withTransaction(async (client) => {
        const { rows } = await client.query<{ id: string; expires_at: Date; status: string }>(
          `INSERT INTO admin.break_glass_requests
             (requested_by, permission_key, mode, target_type, target_id,
              payload, payload_hash, justification, expires_at)
           VALUES ($1, $2, 'second_admin', $3, $4, $5, $6, $7, NOW() + INTERVAL '1 hour')
           RETURNING id, expires_at, status`,
          [
            actor.id,
            permission,
            body.targetType,
            body.targetId,
            JSON.stringify(body.payload),
            hashPayload(body.payload),
            body.justification,
          ],
        );

        const created = rows[0]!;
        await writeAudit(client, actor, {
          action: 'break_glass.requested',
          targetType: 'system',
          targetId: created.id,
          targetLabel: `${permission} on ${body.targetId}`,
          note: body.justification,
        });

        return { id: created.id, expiresAt: created.expires_at, status: created.status };
      });
    },
  );

  app.get(
    '/break-glass',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['enforcement'],
        summary: 'Pending approval requests',
        response: {
          200: z.array(
            z.object({
              id: z.string(),
              requestedByLabel: z.string(),
              permission: z.string(),
              targetType: z.string(),
              targetId: z.string(),
              payload: z.record(z.unknown()),
              justification: z.string(),
              createdAt: z.date(),
              expiresAt: z.date(),
              youMayApprove: z.boolean(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);

      const { rows } = await getPool().query(
        `SELECT b.id, b.permission_key, b.target_type, b.target_id, b.payload,
                b.justification, b.created_at, b.expires_at, b.requested_by,
                u.display_name || ' <' || u.email || '>' AS requested_by_label
           FROM admin.break_glass_requests b
           JOIN admin.admin_users u ON u.id = b.requested_by
          WHERE b.status = 'pending' AND b.expires_at > NOW()
          ORDER BY b.created_at DESC
          LIMIT 100`,
      );

      return rows.map((r) => ({
        id: r.id,
        requestedByLabel: r.requested_by_label,
        permission: r.permission_key,
        targetType: r.target_type,
        targetId: r.target_id,
        payload: r.payload,
        justification: r.justification,
        createdAt: r.created_at,
        expiresAt: r.expires_at,
        youMayApprove: r.requested_by !== actor.id && actor.permissions.has(r.permission_key),
      }));
    },
  );

  app.post(
    '/break-glass/:id/approve',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['enforcement'],
        summary: 'Approve another admin’s break-glass request',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({ note: z.string().max(1000).optional() }),
        response: { 200: z.object({ id: z.string(), status: z.string() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);

      return withTransaction(async (client) => {
        const { rows } = await client.query<{
          id: string;
          requested_by: string;
          permission_key: string;
          status: string;
          expires_at: Date;
          target_id: string;
        }>(
          `SELECT id, requested_by, permission_key, status, expires_at, target_id
             FROM admin.break_glass_requests WHERE id = $1 FOR UPDATE`,
          [request.params.id],
        );

        const req = rows[0];
        if (!req) throw notFound('Approval request');
        if (req.status !== 'pending') throw conflict(`That request is already ${req.status}.`);
        if (req.expires_at.getTime() <= Date.now()) throw conflict('That request has expired.');
        if (req.requested_by === actor.id) {
          throw forbidden('You cannot approve your own request. That is the entire point.');
        }
        requirePermission(actor, permissionFromRequest(req.permission_key));

        await client.query(
          `UPDATE admin.break_glass_requests
              SET status = 'approved', approved_by = $2, approved_at = NOW()
            WHERE id = $1`,
          [req.id, actor.id],
        );

        await writeAudit(client, actor, {
          action: 'break_glass.approved',
          targetType: 'system',
          targetId: req.id,
          targetLabel: `${req.permission_key} on ${req.target_id}`,
          note: request.body.note ?? null,
        });

        return { id: req.id, status: 'approved' };
      });
    },
  );
}
