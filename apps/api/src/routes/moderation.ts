import { getPool, withTransaction } from '@neveroff-console/db';
import { REASON_CATEGORIES } from '@neveroff-console/shared';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { writeAudit } from '../audit.js';
import { conflict, forbidden, notFound } from '../errors.js';
import { actorOf } from '../plugins/auth.js';
import { assertInScope, requirePermission } from '../rbac.js';
import { ApplyActionBody } from './enforcement.js';
import { ChannelActionBody } from './channels.js';
import { applyChannelAction, loadChannelTarget } from '../services/channels.js';
import { applyEnforcement, loadEnforcementTarget } from '../services/enforcement.js';

/**
 * The moderation queue (§6.4).
 *
 * Two things here are load-bearing beyond the obvious CRUD:
 *
 *   - Reading evidence is an audited event, not a page view. Evidence for a
 *     private message is decrypted conversation the reporter volunteered; it is
 *     the most sensitive data this console holds. Opening a case does not open
 *     the evidence, and opening the evidence is logged against the moderator.
 *
 *   - Case locking is advisory but real. Two moderators working the same case
 *     produce contradictory decisions and duplicate enforcement, so a case is
 *     claimed before it can be decided, and the claim expires on its own so an
 *     abandoned case does not stay stuck.
 */

const QUEUE_VIEWS = [
  'all', 'mine', 'unassigned', 'escalated', 'aged', 'auto_flagged', 'coordinated',
] as const;

export default async function moderationRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  // -------------------------------------------------------------------------
  // Queue
  // -------------------------------------------------------------------------
  app.get(
    '/queue',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['moderation'],
        summary: 'Prioritised moderation queue',
        querystring: z.object({
          view: z.enum(QUEUE_VIEWS).default('all'),
          category: z.enum(REASON_CATEGORIES).optional(),
          targetType: z
            .enum(['message', 'user', 'channel', 'media', 'bot', 'call', 'channel_post'])
            .optional(),
          limit: z.coerce.number().int().min(1).max(100).default(25),
          offset: z.coerce.number().int().min(0).default(0),
        }),
        response: {
          200: z.object({
            rows: z.array(
              z.object({
                id: z.string(),
                caseRef: z.string(),
                targetType: z.string(),
                targetId: z.string(),
                targetLabel: z.string().nullable(),
                targetOwnerId: z.string().nullable(),
                primaryCategory: z.string().nullable(),
                primaryReasonCode: z.string().nullable(),
                status: z.string(),
                priorityScore: z.number(),
                reportCount: z.number(),
                distinctReporterCount: z.number(),
                firstReportedAt: z.date(),
                lastReportedAt: z.date(),
                slaDueAt: z.date().nullable(),
                overdue: z.boolean(),
                coordinatedSuspected: z.boolean(),
                autoFlagged: z.boolean(),
                lockedByYou: z.boolean(),
                lockedByOther: z.boolean(),
                hasReadableEvidence: z.boolean(),
              }),
            ),
            total: z.number(),
            scopeApplied: z.boolean(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'reports.view');

      const q = request.query;
      const where: string[] = [`c.status NOT IN ('resolved', 'dismissed')`];
      const params: unknown[] = [actor.id];

      switch (q.view) {
        case 'mine':
          where.push(`c.assigned_to = $1`);
          break;
        case 'unassigned':
          where.push(`c.assigned_to IS NULL`);
          break;
        case 'escalated':
          where.push(`c.escalated_at IS NOT NULL`);
          break;
        case 'aged':
          where.push(`c.sla_due_at IS NOT NULL AND c.sla_due_at <= NOW()`);
          break;
        case 'auto_flagged':
          where.push(`c.auto_flagged`);
          break;
        case 'coordinated':
          where.push(`c.coordinated_suspected`);
          break;
        default:
          break;
      }

      if (q.category) {
        params.push(q.category);
        where.push(`c.primary_category = $${params.length}`);
      }
      if (q.targetType) {
        params.push(q.targetType);
        where.push(`c.target_type = $${params.length}`);
      }

      // Scope: a region-scoped moderator sees cases whose reported user is in
      // their region. Cases with no resolvable owner (a call, a bot) have no
      // country and so are visible only to unscoped admins — same strictness as
      // everywhere else, for the same reason.
      const scopeApplied = actor.scope.countries !== null;
      if (scopeApplied) {
        params.push([...actor.scope.countries!]);
        where.push(
          `EXISTS (SELECT 1 FROM admin.user_directory d
                    WHERE d.id = c.target_owner_id
                      AND d.country IS NOT NULL
                      AND d.country = ANY($${params.length}))`,
        );
      }
      if (actor.scope.reportCategories !== null) {
        params.push([...actor.scope.reportCategories!]);
        where.push(`c.primary_category = ANY($${params.length})`);
      }

      const whereSql = `WHERE ${where.join(' AND ')}`;
      const pool = getPool();

      const [countResult, rowsResult] = await Promise.all([
        pool.query<{ total: string }>(
          `SELECT count(*)::text AS total FROM admin.cases c ${whereSql}`,
          params,
        ),
        pool.query(
          `SELECT c.*,
                  (c.sla_due_at IS NOT NULL AND c.sla_due_at <= NOW()) AS overdue,
                  (c.locked_by = $1 AND c.lock_expires_at > NOW())     AS locked_by_you,
                  (c.locked_by IS NOT NULL AND c.locked_by <> $1
                     AND c.lock_expires_at > NOW())                    AS locked_by_other,
                  EXISTS (SELECT 1 FROM admin.evidence_snapshots e
                           WHERE e.case_id = c.id AND e.content_text IS NOT NULL)
                                                                       AS has_readable_evidence
             FROM admin.cases c
             ${whereSql}
            ORDER BY c.priority_score DESC, c.first_reported_at ASC
            LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
          [...params, q.limit, q.offset],
        ),
      ]);

      return {
        rows: rowsResult.rows.map((r) => ({
          id: r.id,
          caseRef: r.case_ref,
          targetType: r.target_type,
          targetId: r.target_id,
          targetLabel: r.target_label,
          targetOwnerId: r.target_owner_id,
          primaryCategory: r.primary_category,
          primaryReasonCode: r.primary_reason_code,
          status: r.status,
          priorityScore: Number(r.priority_score),
          reportCount: Number(r.report_count),
          distinctReporterCount: Number(r.distinct_reporter_count),
          firstReportedAt: r.first_reported_at,
          lastReportedAt: r.last_reported_at,
          slaDueAt: r.sla_due_at,
          overdue: r.overdue,
          coordinatedSuspected: r.coordinated_suspected,
          autoFlagged: r.auto_flagged,
          lockedByYou: r.locked_by_you,
          lockedByOther: r.locked_by_other,
          hasReadableEvidence: r.has_readable_evidence,
        })),
        total: Number(countResult.rows[0]?.total ?? 0),
        scopeApplied,
      };
    },
  );

  // -------------------------------------------------------------------------
  // Case detail
  // -------------------------------------------------------------------------
  app.get(
    '/cases/:id',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['moderation'],
        summary: 'Case detail with linked reports, priority breakdown and related cases',
        params: z.object({ id: z.string().uuid() }),
        response: {
          200: z.object({
            case: z.record(z.unknown()),
            priority: z.object({ total: z.number(), components: z.array(z.record(z.unknown())) }),
            reports: z.array(
              z.object({
                id: z.string(),
                reasonCode: z.string(),
                reporterNote: z.string().nullable(),
                outcomePreference: z.string(),
                submittedAt: z.date(),
                reporterId: z.string().nullable(),
                reporterAccuracy: z.number().nullable(),
              }),
            ),
            evidence: z.array(
              z.object({
                id: z.string(),
                source: z.string(),
                capturedAt: z.date(),
                hasContent: z.boolean(),
                hasContext: z.boolean(),
                requiresBlur: z.boolean(),
                mediaSha256: z.string().nullable(),
                mediaMimeType: z.string().nullable(),
              }),
            ),
            relatedCases: z.array(
              z.object({
                id: z.string(),
                caseRef: z.string(),
                relation: z.string(),
                status: z.string(),
                targetLabel: z.string().nullable(),
              }),
            ),
            ownerHistory: z.array(
              z.object({
                id: z.string(),
                type: z.string(),
                reasonCode: z.string(),
                issuedAt: z.date(),
                active: z.boolean(),
              }),
            ),
            evidenceNotice: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'reports.view');

      const pool = getPool();
      const { id } = request.params;

      const caseResult = await pool.query(`SELECT * FROM admin.cases WHERE id = $1`, [id]);
      const row = caseResult.rows[0];
      if (!row) throw notFound('Case');

      if (row.target_owner_id) {
        const owner = await pool.query<{ country: string | null }>(
          `SELECT country FROM admin.user_directory WHERE id = $1`,
          [row.target_owner_id],
        );
        assertInScope(actor, { country: owner.rows[0]?.country ?? null });
      } else if (actor.scope.countries !== null) {
        throw forbidden('That case has no resolvable owner and is outside your scope.');
      }

      const [priority, reports, evidence, related, history] = await Promise.all([
        pool.query<{ p: unknown }>(`SELECT admin.case_priority($1) AS p`, [id]),
        pool.query(
          `SELECT r.id, r.reason_code, r.reporter_note, r.outcome_preference,
                  r.submitted_at, r.reporter_id, rep.accuracy
             FROM admin.reports r
             LEFT JOIN admin.reporter_reputation rep ON rep.user_id = r.reporter_id
            WHERE r.case_id = $1
            ORDER BY r.submitted_at ASC`,
          [id],
        ),
        pool.query(
          // Note what is NOT selected: content_text and context_text. Listing a
          // case must not reveal decrypted conversation. Fetching content is a
          // separate, audited call.
          `SELECT id, source, captured_at,
                  (content_text IS NOT NULL) AS has_content,
                  (context_text IS NOT NULL) AS has_context,
                  requires_blur, media_sha256, media_mime_type
             FROM admin.evidence_snapshots
            WHERE case_id = $1
            ORDER BY captured_at ASC`,
          [id],
        ),
        pool.query(
          // §6.4 related cases: same reported user, or the same media hash.
          `SELECT DISTINCT c.id, c.case_ref, c.status, c.target_label, 'same_user' AS relation
             FROM admin.cases c
            WHERE c.target_owner_id = $2 AND c.id <> $1 AND $2 IS NOT NULL
            UNION
           SELECT DISTINCT c.id, c.case_ref, c.status, c.target_label, 'same_media' AS relation
             FROM admin.cases c
             JOIN admin.evidence_snapshots e ON e.case_id = c.id
            WHERE c.id <> $1
              AND e.media_sha256 IN (
                SELECT media_sha256 FROM admin.evidence_snapshots
                 WHERE case_id = $1 AND media_sha256 IS NOT NULL)
            LIMIT 50`,
          [id, row.target_owner_id],
        ),
        row.target_owner_id
          ? pool.query(
              `SELECT id, type, reason_code, issued_at,
                      (reversed_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())) AS active
                 FROM admin.enforcement_actions
                WHERE user_id = $1 AND type <> 'note'
                ORDER BY issued_at DESC LIMIT 20`,
              [row.target_owner_id],
            )
          : Promise.resolve({ rows: [] as Array<Record<string, unknown>> }),
      ]);

      const priorityValue = priority.rows[0]?.p as {
        total: number;
        components: Array<Record<string, unknown>>;
      };

      const anyReporterSubmitted = evidence.rows.some(
        (e) => e.source === 'reporter_submitted' && e.has_content,
      );

      return {
        case: row as Record<string, unknown>,
        priority: priorityValue ?? { total: 0, components: [] },
        reports: reports.rows.map((r) => ({
          id: r.id,
          reasonCode: r.reason_code,
          reporterNote: r.reporter_note,
          outcomePreference: r.outcome_preference,
          submittedAt: r.submitted_at,
          // §6.3 anonymity: reporter identity is permission-gated even inside
          // the console, because most decisions do not need it.
          reporterId: actor.permissions.has('users.view_pii') ? r.reporter_id : null,
          reporterAccuracy: r.accuracy === null ? null : Number(r.accuracy),
        })),
        evidence: evidence.rows.map((e) => ({
          id: e.id,
          source: e.source,
          capturedAt: e.captured_at,
          hasContent: e.has_content,
          hasContext: e.has_context,
          requiresBlur: e.requires_blur,
          mediaSha256: e.media_sha256,
          mediaMimeType: e.media_mime_type,
        })),
        relatedCases: related.rows.map((c) => ({
          id: c.id,
          caseRef: c.case_ref,
          relation: c.relation,
          status: c.status,
          targetLabel: c.target_label,
        })),
        ownerHistory: history.rows.map((h) => ({
          id: h.id as string,
          type: h.type as string,
          reasonCode: h.reason_code as string,
          issuedAt: h.issued_at as Date,
          active: h.active as boolean,
        })),
        evidenceNotice: anyReporterSubmitted
          ? 'Evidence here was decrypted and submitted by the reporter. NeverOff messages are ' +
            'end-to-end encrypted, so this is a voluntary disclosure, not something the server ' +
            'could read. Opening it is recorded against your account.'
          : row.target_type === 'message'
            ? 'No readable evidence. NeverOff messages are end-to-end encrypted and the reporter ' +
              'did not share the content, so this case can only be judged on pattern — volume, ' +
              'velocity and the reported account’s history.'
            : 'No evidence was captured for this case.',
      };
    },
  );

  // -------------------------------------------------------------------------
  // Evidence content — separate, gated and audited
  // -------------------------------------------------------------------------
  app.post(
    '/cases/:id/evidence/:evidenceId',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['moderation'],
        summary: 'Read evidence content. Audit-logged as a personal-data access.',
        params: z.object({ id: z.string().uuid(), evidenceId: z.string().uuid() }),
        response: {
          200: z.object({
            contentText: z.string().nullable(),
            contextText: z.unknown().nullable(),
            contextConsented: z.boolean(),
            source: z.string(),
            requiresBlur: z.boolean(),
            notice: z.string(),
          }),
        },
      },
      config: { rateLimit: { max: 60, timeWindow: '1 minute' } },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'reports.view');

      return withTransaction(async (client) => {
        const { rows } = await client.query(
          `SELECT e.*, c.case_ref, c.target_owner_id
             FROM admin.evidence_snapshots e
             JOIN admin.cases c ON c.id = e.case_id
            WHERE e.id = $1 AND e.case_id = $2`,
          [request.params.evidenceId, request.params.id],
        );

        const evidence = rows[0];
        if (!evidence) throw notFound('Evidence');

        if (evidence.target_owner_id) {
          const owner = await client.query<{ country: string | null }>(
            `SELECT country FROM admin.user_directory WHERE id = $1`,
            [evidence.target_owner_id],
          );
          assertInScope(actor, { country: owner.rows[0]?.country ?? null });
        }

        // Decrypted private conversation is PII-grade. Logged as such, so the
        // §7 anomaly checks on PII volume cover evidence reads too.
        await writeAudit(client, actor, {
          action: 'moderation.evidence.read',
          targetType: 'case',
          targetId: request.params.id,
          targetLabel: evidence.case_ref,
          permission: 'reports.view',
          isPiiAccess: true,
          note: `Read ${evidence.source} evidence.`,
        });

        return {
          contentText: evidence.content_text,
          contextText: evidence.context_text,
          contextConsented: evidence.context_consented,
          source: evidence.source,
          requiresBlur: evidence.requires_blur,
          notice: 'This access has been recorded in the audit log against your account.',
        };
      });
    },
  );

  // -------------------------------------------------------------------------
  // Claim / release
  // -------------------------------------------------------------------------
  app.post(
    '/cases/:id/claim',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['moderation'],
        summary: 'Lock a case so nobody else works it at the same time',
        params: z.object({ id: z.string().uuid() }),
        response: {
          200: z.object({ claimed: z.boolean(), heldBy: z.string().nullable() }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'reports.triage');

      return withTransaction(async (client) => {
        const { rows } = await client.query<{ claimed: boolean }>(
          `SELECT admin.claim_case($1, $2) AS claimed`,
          [request.params.id, actor.id],
        );

        if (!rows[0]?.claimed) {
          const holder = await client.query<{ display_name: string }>(
            `SELECT u.display_name FROM admin.cases c
               JOIN admin.admin_users u ON u.id = c.locked_by
              WHERE c.id = $1`,
            [request.params.id],
          );
          return { claimed: false, heldBy: holder.rows[0]?.display_name ?? 'another moderator' };
        }

        await client.query(
          `UPDATE admin.cases SET assigned_to = $2, assigned_at = COALESCE(assigned_at, NOW())
            WHERE id = $1 AND assigned_to IS NULL`,
          [request.params.id, actor.id],
        );

        return { claimed: true, heldBy: null };
      });
    },
  );

  app.post(
    '/cases/:id/release',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['moderation'],
        summary: 'Release your lock on a case',
        params: z.object({ id: z.string().uuid() }),
        response: { 200: z.object({ released: z.literal(true) }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      await getPool().query(`SELECT admin.release_case($1, $2)`, [request.params.id, actor.id]);
      return { released: true as const };
    },
  );

  // -------------------------------------------------------------------------
  // Decide
  // -------------------------------------------------------------------------
  app.post(
    '/cases/:id/decide',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['moderation'],
        summary: 'Record a decision, optionally applying enforcement',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({
          outcome: z.enum([
            'action_taken', 'no_violation', 'duplicate', 'insufficient_evidence', 'out_of_scope',
          ]),
          note: z.string().trim().min(10).max(2000),
          reporterMessage: z.string().max(500).optional(),
          // Omit both to close the case with no action.
          //
          // These are separate because a channel case usually needs both and
          // sometimes needs only one. Banning the owner of a 24,000-subscriber
          // channel does not take the channel down, and freezing a channel does
          // not stop its owner opening another — §6.5's owner accountability
          // exists precisely because those are different levers.
          enforcement: ApplyActionBody.optional(),
          channelAction: ChannelActionBody.optional(),
        }),
        response: {
          200: z.object({
            caseId: z.string(),
            outcome: z.string(),
            enforcementActionId: z.string().nullable(),
            channelActionId: z.string().nullable(),
            reportersNotified: z.number(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'reports.resolve');
      const body = request.body;

      return withTransaction(async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM admin.cases WHERE id = $1 FOR UPDATE`,
          [request.params.id],
        );
        const kase = rows[0];
        if (!kase) throw notFound('Case');
        if (['resolved', 'dismissed'].includes(kase.status)) {
          throw conflict(`This case is already ${kase.status}.`);
        }

        if (kase.target_owner_id) {
          const owner = await client.query<{ country: string | null }>(
            `SELECT country FROM admin.user_directory WHERE id = $1`,
            [kase.target_owner_id],
          );
          assertInScope(actor, { country: owner.rows[0]?.country ?? null });
        }

        // Locking is only useful if deciding respects it.
        if (
          kase.locked_by &&
          kase.locked_by !== actor.id &&
          kase.lock_expires_at &&
          new Date(kase.lock_expires_at).getTime() > Date.now()
        ) {
          throw conflict(
            'Another moderator currently holds this case. Wait for their lock to expire or ask them to release it.',
          );
        }

        // --- Action, if the decision carries any --------------------------
        let actionId: string | null = null;
        let channelActionId: string | null = null;

        if ((body.enforcement || body.channelAction) && body.outcome !== 'action_taken') {
          throw conflict('A decision that applies an action must be recorded as "action taken".');
        }

        if (body.enforcement) {
          if (!kase.target_owner_id) {
            throw conflict(
              'This case has no resolvable account to action. Escalate it instead.',
            );
          }

          const target = await loadEnforcementTarget(client, kase.target_owner_id);
          if (!target) throw notFound('Reported account');

          const applied = await applyEnforcement(client, actor, target, {
            ...body.enforcement,
            caseId: kase.id,
          });
          actionId = applied.id;
        }

        if (body.channelAction) {
          // Resolve the channel: for a post report the case target is the post,
          // and the thing to restrict is the channel it sits in.
          let channelId: string | null = null;
          if (kase.target_type === 'channel') {
            channelId = kase.target_id;
          } else if (kase.target_type === 'channel_post') {
            const post = await client.query<{ channel_id: string }>(
              `SELECT channel_id FROM public.channel_posts WHERE id = $1`,
              [kase.target_id],
            );
            channelId = post.rows[0]?.channel_id ?? null;
          }

          if (!channelId) {
            throw conflict(
              'This case is not about a channel, so a channel action does not apply to it.',
            );
          }

          const channel = await loadChannelTarget(client, channelId);
          if (!channel) throw notFound('Channel');

          const applied = await applyChannelAction(client, actor, channel, {
            ...body.channelAction,
            caseId: kase.id,
          });
          channelActionId = applied.id;
        }

        // --- Record the decision ------------------------------------------
        await client.query(
          `INSERT INTO admin.case_decisions
             (case_id, decided_by, decided_by_label, outcome, reason_code, note,
              enforcement_action_id, reporter_message, requires_second_review)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          [
            kase.id,
            actor.id,
            `${actor.displayName} <${actor.email}>`,
            body.outcome,
            body.enforcement?.reasonCode ??
              body.channelAction?.reasonCode ??
              kase.primary_reason_code,
            body.note,
            actionId,
            body.reporterMessage ?? null,
            // §6.4 four-eyes on precedent-setting outcomes. A channel takedown
            // qualifies for the same reason a permanent ban does: it is
            // terminal and it is visible to everyone who subscribed.
            body.enforcement?.type === 'ban_permanent' ||
              body.channelAction?.type === 'takedown',
          ],
        );

        const actioned = body.outcome === 'action_taken';

        await client.query(
          `UPDATE admin.cases
              SET status = $2, resolved_at = NOW(),
                  locked_by = NULL, locked_at = NULL, lock_expires_at = NULL
            WHERE id = $1`,
          [kase.id, actioned ? 'resolved' : 'dismissed'],
        );

        // §6.3 reporter reputation: accuracy is report-to-action rate.
        await client.query(`SELECT admin.update_reporter_reputation($1, $2)`, [kase.id, actioned]);

        // §6.4 reporter feedback loop, in generic terms. Closing the loop
        // measurably improves report quality, and costs one row per reporter.
        const notified = await client.query(
          `INSERT INTO admin.notification_outbox (user_id, kind, payload)
           SELECT DISTINCT r.reporter_id, 'report_outcome',
                  jsonb_build_object(
                    'outcome', $2::text,
                    'reason_category', $3::text,
                    'message', $4::text)
             FROM admin.reports r
            WHERE r.case_id = $1 AND r.reporter_id IS NOT NULL
           RETURNING id`,
          [
            kase.id,
            actioned ? 'action_taken' : 'no_violation',
            kase.primary_category,
            body.reporterMessage ??
              (actioned
                ? 'We reviewed your report and took action.'
                : 'We reviewed your report and did not find a violation of our policies.'),
          ],
        );

        await client.query(
          `UPDATE admin.reports SET outcome_notified_at = NOW() WHERE case_id = $1`,
          [kase.id],
        );

        await writeAudit(client, actor, {
          action: 'moderation.case.decided',
          targetType: 'case',
          targetId: kase.id,
          targetLabel: kase.case_ref,
          permission: 'reports.resolve',
          note: body.note,
          before: { status: kase.status },
          after: {
            outcome: body.outcome,
            enforcementActionId: actionId,
            channelActionId,
            reportCount: kase.report_count,
          },
        });

        await client.query(`SELECT admin.bump_transparency_counter('case_decided', $1)`, [
          body.outcome,
        ]);

        return {
          caseId: kase.id,
          outcome: body.outcome,
          enforcementActionId: actionId,
          channelActionId,
          reportersNotified: notified.rowCount ?? 0,
        };
      });
    },
  );

  // -------------------------------------------------------------------------
  // Escalate
  // -------------------------------------------------------------------------
  app.post(
    '/cases/:id/escalate',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['moderation'],
        summary: 'Escalate a case to a higher tier',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({ note: z.string().trim().min(10).max(1000) }),
        response: { 200: z.object({ caseId: z.string(), escalatedAt: z.date() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'reports.escalate');

      return withTransaction(async (client) => {
        const { rows } = await client.query<{
          id: string; case_ref: string; status: string; escalated_at: Date | null;
        }>(
          `UPDATE admin.cases
              SET status = 'escalated', escalated_at = NOW(),
                  escalated_by = $2, escalation_note = $3,
                  locked_by = NULL, lock_expires_at = NULL,
                  assigned_to = NULL
            WHERE id = $1 AND status NOT IN ('resolved', 'dismissed')
            RETURNING id, case_ref, status, escalated_at`,
          [request.params.id, actor.id, request.body.note],
        );

        const updated = rows[0];
        if (!updated) throw conflict('That case is already closed, or does not exist.');

        await writeAudit(client, actor, {
          action: 'moderation.case.escalated',
          targetType: 'case',
          targetId: updated.id,
          targetLabel: updated.case_ref,
          permission: 'reports.escalate',
          note: request.body.note,
        });

        return { caseId: updated.id, escalatedAt: updated.escalated_at! };
      });
    },
  );
}
