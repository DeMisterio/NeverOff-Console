import { getPool, withTransaction } from '@neveroff-console/db';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { writeAudit } from '../audit.js';
import { conflict, notFound } from '../errors.js';
import { actorOf } from '../plugins/auth.js';
import { assertInScope, requirePermission } from '../rbac.js';

/**
 * The @support agent console (§5.2).
 *
 * Two things worth knowing before reading the handlers:
 *
 *   - Emergency tickets are never hidden behind a tab. They sort to the top of
 *     every view, because §5.2 requires a "distinct high-visibility banner" and
 *     a queue where the urgent thing is one click away is a queue where it gets
 *     missed on a busy shift.
 *
 *   - Agent replies go to admin.ticket_messages, never to public.messages. The
 *     enforcement policy blocks a banned user from that table entirely, and
 *     support has to keep working while someone is banned — that is the whole
 *     point of §4's "@support remains the only accessible surface".
 */

const INBOX_TABS = [
  'unassigned', 'mine', 'all_open', 'pending_user', 'escalated', 'breaching_sla', 'closed',
] as const;

const TICKET_STATUSES = [
  'open', 'pending_agent', 'pending_user', 'escalated', 'resolved', 'closed',
] as const;

export default async function supportRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  // -------------------------------------------------------------------------
  app.get(
    '/tickets',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['support'],
        summary: 'Ticket inbox',
        querystring: z.object({
          tab: z.enum(INBOX_TABS).default('all_open'),
          category: z.string().max(80).optional(),
          limit: z.coerce.number().int().min(1).max(100).default(25),
          offset: z.coerce.number().int().min(0).default(0),
        }),
        response: {
          200: z.object({
            rows: z.array(
              z.object({
                id: z.string(),
                ticketRef: z.string(),
                subject: z.string(),
                userId: z.string(),
                username: z.string().nullable(),
                categoryKey: z.string(),
                status: z.string(),
                priority: z.string(),
                isEmergency: z.boolean(),
                emergencyReason: z.string().nullable(),
                assignedTo: z.string().nullable(),
                assignedToLabel: z.string().nullable(),
                openedAt: z.date(),
                firstResponseDueAt: z.date(),
                resolutionDueAt: z.date(),
                slaBreached: z.boolean(),
                awaitingAgent: z.boolean(),
                messageCount: z.number(),
              }),
            ),
            total: z.number(),
            emergencyCount: z.number(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'support.view');

      const q = request.query;
      const where: string[] = [];
      const params: unknown[] = [actor.id];

      switch (q.tab) {
        case 'unassigned':
          where.push(`t.assigned_to IS NULL AND t.status NOT IN ('resolved','closed')`);
          break;
        case 'mine':
          where.push(`t.assigned_to = $1 AND t.status NOT IN ('resolved','closed')`);
          break;
        case 'pending_user':
          where.push(`t.status = 'pending_user'`);
          break;
        case 'escalated':
          where.push(`t.status = 'escalated'`);
          break;
        case 'breaching_sla':
          where.push(
            `t.status NOT IN ('resolved','closed')
             AND (t.first_response_due_at <= NOW() AND t.first_response_at IS NULL
                  OR t.resolution_due_at <= NOW())`,
          );
          break;
        case 'closed':
          where.push(`t.status IN ('resolved','closed')`);
          break;
        default:
          where.push(`t.status NOT IN ('resolved','closed')`);
      }

      if (q.category) {
        params.push(q.category);
        where.push(`t.category_key = $${params.length}`);
      }

      // Scope. A region-scoped agent sees tickets from users in their region.
      if (actor.scope.countries !== null) {
        params.push([...actor.scope.countries]);
        where.push(`(t.country IS NOT NULL AND t.country = ANY($${params.length}))`);
      }

      const whereSql = `WHERE ${where.join(' AND ')}`;
      const pool = getPool();

      const [countResult, rowsResult, emergencyResult] = await Promise.all([
        pool.query<{ total: string }>(
          `SELECT count(*)::text AS total FROM admin.tickets t ${whereSql}`,
          params,
        ),
        pool.query(
          `SELECT t.*, d.username,
                  u.display_name AS assigned_label,
                  (SELECT count(*) FROM admin.ticket_messages m WHERE m.ticket_id = t.id)
                    AS message_count,
                  (t.status NOT IN ('resolved','closed')
                     AND (t.first_response_due_at <= NOW() AND t.first_response_at IS NULL
                          OR t.resolution_due_at <= NOW()))            AS sla_breached,
                  (t.status IN ('open','pending_agent','escalated'))   AS awaiting_agent
             FROM admin.tickets t
             LEFT JOIN admin.user_directory d ON d.id = t.user_id
             LEFT JOIN admin.admin_users u ON u.id = t.assigned_to
             ${whereSql}
            ORDER BY t.is_emergency DESC,
                     CASE t.priority WHEN 'urgent' THEN 4 WHEN 'high' THEN 3
                                     WHEN 'normal' THEN 2 ELSE 1 END DESC,
                     t.first_response_due_at ASC
            LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
          [...params, q.limit, q.offset],
        ),
        pool.query<{ count: string }>(
          `SELECT count(*)::text AS count FROM admin.tickets
            WHERE is_emergency AND status NOT IN ('resolved','closed')`,
        ),
      ]);

      return {
        rows: rowsResult.rows.map((r) => ({
          id: r.id,
          ticketRef: r.ticket_ref,
          subject: r.subject,
          userId: r.user_id,
          username: r.username,
          categoryKey: r.category_key,
          status: r.status,
          priority: r.priority,
          isEmergency: r.is_emergency,
          emergencyReason: r.emergency_reason,
          assignedTo: r.assigned_to,
          assignedToLabel: r.assigned_label,
          openedAt: r.opened_at,
          firstResponseDueAt: r.first_response_due_at,
          resolutionDueAt: r.resolution_due_at,
          slaBreached: r.sla_breached,
          awaitingAgent: r.awaiting_agent,
          messageCount: Number(r.message_count),
        })),
        total: Number(countResult.rows[0]?.total ?? 0),
        emergencyCount: Number(emergencyResult.rows[0]?.count ?? 0),
      };
    },
  );

  // -------------------------------------------------------------------------
  app.get(
    '/tickets/:id',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['support'],
        summary: 'Ticket detail with thread and user context',
        params: z.object({ id: z.string().uuid() }),
        response: {
          200: z.object({
            ticket: z.record(z.unknown()),
            thread: z.array(
              z.object({
                id: z.string(),
                authorType: z.string(),
                authorLabel: z.string(),
                body: z.string(),
                isInternal: z.boolean(),
                sentAt: z.date(),
              }),
            ),
            user: z
              .object({
                id: z.string(),
                username: z.string(),
                status: z.string(),
                trustScore: z.number().nullable(),
                lifetimeActionCount: z.number(),
                openCaseCount: z.number(),
                priorTicketCount: z.number(),
              })
              .nullable(),
            emergencyGuidance: z.string().nullable(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'support.view');

      const pool = getPool();
      const ticketResult = await pool.query(
        `SELECT * FROM admin.tickets WHERE id = $1`,
        [request.params.id],
      );
      const ticket = ticketResult.rows[0];
      if (!ticket) throw notFound('Ticket');
      assertInScope(actor, { country: ticket.country });

      const [thread, user, priorTickets, openCases] = await Promise.all([
        pool.query(
          `SELECT id, author_type, author_label, body, is_internal, sent_at
             FROM admin.ticket_messages WHERE ticket_id = $1 ORDER BY sent_at ASC`,
          [request.params.id],
        ),
        pool.query(
          `SELECT id, username, status, lifetime_action_count,
                  admin.trust_score_value(id) AS trust_score
             FROM admin.user_directory WHERE id = $1`,
          [ticket.user_id],
        ),
        pool.query<{ count: string }>(
          `SELECT count(*)::text AS count FROM admin.tickets
            WHERE user_id = $1 AND id <> $2`,
          [ticket.user_id, request.params.id],
        ),
        pool.query<{ count: string }>(
          `SELECT count(*)::text AS count FROM admin.cases
            WHERE target_owner_id = $1 AND status NOT IN ('resolved','dismissed')`,
          [ticket.user_id],
        ),
      ]);

      const u = user.rows[0];

      return {
        ticket: ticket as Record<string, unknown>,
        thread: thread.rows.map((m) => ({
          id: m.id,
          authorType: m.author_type,
          authorLabel: m.author_label,
          body: m.body,
          isInternal: m.is_internal,
          sentAt: m.sent_at,
        })),
        user: u
          ? {
              id: u.id,
              username: u.username,
              status: u.status,
              trustScore: u.trust_score === null ? null : Number(u.trust_score),
              lifetimeActionCount: Number(u.lifetime_action_count),
              openCaseCount: Number(openCases.rows[0]?.count ?? 0),
              priorTicketCount: Number(priorTickets.rows[0]?.count ?? 0),
            }
          : null,
        emergencyGuidance: ticket.is_emergency
          ? 'This ticket matched the emergency keyword list. §5.2 requires a human on this path — ' +
            'it must never be handled by automation alone. Surface the crisis resources for this ' +
            'person’s region, follow the escalation procedure in the operations runbook, and do ' +
            'not close it without a second pair of eyes. Enforcement against someone disclosing ' +
            'risk is almost never the right answer.'
          : null,
      };
    },
  );

  // -------------------------------------------------------------------------
  app.post(
    '/tickets/:id/messages',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['support'],
        summary: 'Reply to a ticket, or add an internal note',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({
          body: z.string().trim().min(1).max(10000),
          isInternal: z.boolean().default(false),
          macroKey: z.string().max(80).optional(),
          setStatus: z.enum(TICKET_STATUSES).optional(),
        }),
        response: {
          200: z.object({ id: z.string(), status: z.string(), firstResponse: z.boolean() }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, request.body.isInternal ? 'support.view' : 'support.reply');

      return withTransaction(async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM admin.tickets WHERE id = $1 FOR UPDATE`,
          [request.params.id],
        );
        const ticket = rows[0];
        if (!ticket) throw notFound('Ticket');
        assertInScope(actor, { country: ticket.country });
        if (ticket.status === 'closed') throw conflict('That ticket is closed.');

        const inserted = await client.query<{ id: string }>(
          `INSERT INTO admin.ticket_messages
             (ticket_id, author_type, author_admin_id, author_label, body, is_internal, macro_key)
           VALUES ($1, 'agent', $2, $3, $4, $5, $6)
           RETURNING id`,
          [
            ticket.id,
            actor.id,
            `${actor.displayName} <${actor.email}>`,
            request.body.body,
            request.body.isInternal,
            request.body.macroKey ?? null,
          ],
        );

        // An internal note is not a response to the user, so it must not stop
        // the first-response clock — otherwise the SLA measures how fast an
        // agent typed a note to themselves.
        const isFirstResponse =
          !request.body.isInternal && ticket.first_response_at === null;

        const nextStatus =
          request.body.setStatus ??
          (request.body.isInternal ? ticket.status : 'pending_user');

        await client.query(
          `UPDATE admin.tickets
              SET status = $2,
                  first_response_at = CASE WHEN $3 THEN NOW() ELSE first_response_at END,
                  last_agent_message_at = CASE WHEN $4 THEN NOW() ELSE last_agent_message_at END,
                  closed_at = CASE WHEN $2 IN ('resolved','closed') THEN NOW() ELSE NULL END,
                  assigned_to = COALESCE(assigned_to, $5)
            WHERE id = $1`,
          [ticket.id, nextStatus, isFirstResponse, !request.body.isInternal, actor.id],
        );

        if (!request.body.isInternal) {
          await client.query(
            `INSERT INTO admin.notification_outbox (user_id, kind, payload)
             VALUES ($1, 'admin_message', $2)`,
            [
              ticket.user_id,
              JSON.stringify({
                ticket_ref: ticket.ticket_ref,
                scope: 'support_reply',
              }),
            ],
          );
        }

        await writeAudit(client, actor, {
          action: request.body.isInternal ? 'support.note.added' : 'support.replied',
          targetType: 'ticket',
          targetId: ticket.id,
          targetLabel: ticket.ticket_ref,
          permission: request.body.isInternal ? 'support.view' : 'support.reply',
          note: request.body.isInternal ? request.body.body : null,
          after: { status: nextStatus, macroKey: request.body.macroKey ?? null },
        });

        return {
          id: inserted.rows[0]!.id,
          status: nextStatus,
          firstResponse: isFirstResponse,
        };
      });
    },
  );

  // -------------------------------------------------------------------------
  app.patch(
    '/tickets/:id',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['support'],
        summary: 'Assign, reprioritise, tag or escalate a ticket',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({
          assignedTo: z.string().uuid().nullable().optional(),
          status: z.enum(TICKET_STATUSES).optional(),
          priority: z.enum(['low', 'normal', 'high', 'urgent']).optional(),
          tags: z.array(z.string().max(40)).optional(),
        }),
        response: { 200: z.object({ id: z.string(), updated: z.array(z.string()) }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'support.assign');

      return withTransaction(async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM admin.tickets WHERE id = $1 FOR UPDATE`,
          [request.params.id],
        );
        const ticket = rows[0];
        if (!ticket) throw notFound('Ticket');
        assertInScope(actor, { country: ticket.country });

        const body = request.body;
        const updates: string[] = [];
        const params: unknown[] = [ticket.id];
        const changed: string[] = [];
        const set = (col: string, value: unknown, label: string): void => {
          params.push(value);
          updates.push(`${col} = $${params.length}`);
          changed.push(label);
        };

        if (body.assignedTo !== undefined) {
          set('assigned_to', body.assignedTo, 'assignedTo');
          updates.push(`assigned_at = ${body.assignedTo ? 'NOW()' : 'NULL'}`);
        }
        if (body.status !== undefined) {
          set('status', body.status, 'status');
          if (['resolved', 'closed'].includes(body.status)) updates.push('closed_at = NOW()');
        }
        // Priority may be raised freely but not lowered on an emergency ticket:
        // the keyword match is a floor, and quietly downgrading it is exactly
        // how an emergency gets lost.
        if (body.priority !== undefined) {
          if (ticket.is_emergency && body.priority !== 'urgent') {
            throw conflict(
              'This ticket was flagged as an emergency. Reclassify the category if that was ' +
                'wrong; do not simply lower the priority.',
            );
          }
          set('priority', body.priority, 'priority');
        }
        if (body.tags !== undefined) set('tags', body.tags, 'tags');

        if (updates.length === 0) return { id: ticket.id, updated: [] };

        await client.query(
          `UPDATE admin.tickets SET ${updates.join(', ')} WHERE id = $1`,
          params,
        );

        await writeAudit(client, actor, {
          action: 'support.ticket.updated',
          targetType: 'ticket',
          targetId: ticket.id,
          targetLabel: ticket.ticket_ref,
          permission: 'support.assign',
          before: { status: ticket.status, priority: ticket.priority, assignedTo: ticket.assigned_to },
          after: { ...body },
          note: `Changed: ${changed.join(', ')}`,
        });

        return { id: ticket.id, updated: changed };
      });
    },
  );

  // -------------------------------------------------------------------------
  app.get(
    '/macros',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['support'],
        summary: 'Canned responses with variables already substituted',
        querystring: z.object({ ticketId: z.string().uuid().optional() }),
        response: {
          200: z.array(
            z.object({
              key: z.string(),
              label: z.string(),
              categoryKey: z.string().nullable(),
              body: z.string(),
              setsStatus: z.string().nullable(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'support.view');

      const pool = getPool();
      const macros = await pool.query(
        `SELECT key, label, category_key, body, sets_status
           FROM admin.ticket_macros WHERE active ORDER BY label`,
      );

      // Substitution happens here rather than in the browser so an agent never
      // sends a reply with a literal {{username}} in it.
      let vars: Record<string, string> = { agent_name: actor.displayName };
      if (request.query.ticketId) {
        const { rows } = await pool.query<{
          ticket_ref: string; username: string | null;
        }>(
          `SELECT t.ticket_ref, d.username
             FROM admin.tickets t
             LEFT JOIN admin.user_directory d ON d.id = t.user_id
            WHERE t.id = $1`,
          [request.query.ticketId],
        );
        if (rows[0]) {
          vars = {
            ...vars,
            ticket_ref: rows[0].ticket_ref,
            username: rows[0].username ?? 'there',
          };
        }
      }

      const substitute = (template: string): string =>
        template.replace(/\{\{(\w+)\}\}/g, (match, key: string) => vars[key] ?? match);

      return macros.rows.map((m) => ({
        key: m.key,
        label: m.label,
        categoryKey: m.category_key,
        body: substitute(m.body),
        setsStatus: m.sets_status,
      }));
    },
  );
}
