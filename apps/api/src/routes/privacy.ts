import { getPool, withTransaction } from '@neveroff-console/db';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { writeAudit } from '../audit.js';
import { conflict, notFound, validationFailed } from '../errors.js';
import { actorOf } from '../plugins/auth.js';
import { assertInScope, requireBreakGlass, requirePermission } from '../rbac.js';

/**
 * Privacy, consent, retention and data subject rights (§8).
 *
 * The parts of §8 that are genuinely load-bearing are enforced in the database
 * (migration 0004): consent gates telemetry inserts, legal holds block erasure,
 * and telemetry payloads carrying message content are rejected. What lives here
 * is the operator surface over those guarantees — reading them, configuring
 * them, and recording who changed what.
 */

const DATA_CLASSES = [
  'raw_events', 'aggregates', 'evidence_snapshots', 'tickets', 'audit_log',
  'enforcement_actions', 'admin_messages', 'consent_records', 'sessions', 'notifications',
] as const;

export default async function privacyRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  // -------------------------------------------------------------------------
  // Consent
  // -------------------------------------------------------------------------
  app.get(
    '/consent/definitions',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['privacy'],
        summary: 'Consent definitions and the exact wording shown to users',
        response: {
          200: z.array(
            z.object({
              key: z.string(),
              version: z.number(),
              label: z.string(),
              wording: z.string(),
              required: z.boolean(),
              effectiveFrom: z.date(),
              grantedCount: z.number(),
              declinedCount: z.number(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'privacy.dsr.view');

      const { rows } = await getPool().query(
        `SELECT d.key, d.version, d.label, d.wording, d.required, d.effective_from,
                (SELECT count(*) FROM admin.current_consent c
                  WHERE c.consent_key = d.key AND c.granted)      AS granted_count,
                (SELECT count(*) FROM admin.current_consent c
                  WHERE c.consent_key = d.key AND NOT c.granted)  AS declined_count
           FROM admin.consent_definitions d
          ORDER BY d.key, d.version DESC`,
      );

      return rows.map((r) => ({
        key: r.key,
        version: Number(r.version),
        label: r.label,
        wording: r.wording,
        required: r.required,
        effectiveFrom: r.effective_from,
        grantedCount: Number(r.granted_count),
        declinedCount: Number(r.declined_count),
      }));
    },
  );

  app.get(
    '/consent/:userId',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['privacy'],
        summary: 'A user’s consent history',
        params: z.object({ userId: z.string().uuid() }),
        response: {
          200: z.object({
            current: z.array(
              z.object({ key: z.string(), granted: z.boolean(), recordedAt: z.date(), version: z.number() }),
            ),
            history: z.array(
              z.object({
                key: z.string(),
                granted: z.boolean(),
                version: z.number(),
                recordedAt: z.date(),
                source: z.string(),
                wordingShown: z.string(),
              }),
            ),
            telemetryCollected: z.boolean(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'privacy.dsr.view');

      const { userId } = request.params;
      const pool = getPool();

      const dir = await pool.query<{ country: string | null }>(
        `SELECT country FROM admin.user_directory WHERE id = $1`,
        [userId],
      );
      if (!dir.rows[0]) throw notFound('User');
      assertInScope(actor, { country: dir.rows[0].country });

      const [current, history, analyticsConsent] = await Promise.all([
        pool.query(
          `SELECT consent_key, granted, recorded_at, consent_version
             FROM admin.current_consent WHERE user_id = $1`,
          [userId],
        ),
        pool.query(
          `SELECT consent_key, granted, consent_version, recorded_at, source, wording_shown
             FROM admin.consent_records WHERE user_id = $1 ORDER BY recorded_at DESC LIMIT 200`,
          [userId],
        ),
        pool.query<{ has: boolean }>(`SELECT admin.has_consent($1, 'analytics') AS has`, [userId]),
      ]);

      return {
        current: current.rows.map((r) => ({
          key: r.consent_key,
          granted: r.granted,
          recordedAt: r.recorded_at,
          version: Number(r.consent_version),
        })),
        history: history.rows.map((r) => ({
          key: r.consent_key,
          granted: r.granted,
          version: Number(r.consent_version),
          recordedAt: r.recorded_at,
          source: r.source,
          wordingShown: r.wording_shown,
        })),
        // Not a UI toggle: this is what the database will actually permit.
        telemetryCollected: analyticsConsent.rows[0]?.has ?? false,
      };
    },
  );

  // -------------------------------------------------------------------------
  // Retention
  // -------------------------------------------------------------------------
  app.get(
    '/retention',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['privacy'],
        summary: 'Retention policy per data class',
        response: {
          200: z.array(
            z.object({
              dataClass: z.string(),
              ttlDays: z.number().nullable(),
              minTtlDays: z.number(),
              description: z.string(),
              enabled: z.boolean(),
              lastPurgeAt: z.date().nullable(),
              lastPurgeRows: z.number().nullable(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'privacy.dsr.view');

      const { rows } = await getPool().query(
        `SELECT data_class, ttl_days, min_ttl_days, description, enabled,
                last_purge_at, last_purge_rows
           FROM admin.retention_policies ORDER BY data_class`,
      );

      return rows.map((r) => ({
        dataClass: r.data_class,
        ttlDays: r.ttl_days === null ? null : Number(r.ttl_days),
        minTtlDays: Number(r.min_ttl_days),
        description: r.description,
        enabled: r.enabled,
        lastPurgeAt: r.last_purge_at,
        lastPurgeRows: r.last_purge_rows === null ? null : Number(r.last_purge_rows),
      }));
    },
  );

  app.patch(
    '/retention/:dataClass',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['privacy'],
        summary: 'Change a retention TTL (Super Admin only)',
        params: z.object({ dataClass: z.enum(DATA_CLASSES) }),
        body: z.object({
          ttlDays: z.number().int().min(1).max(3650).nullable(),
          enabled: z.boolean().optional(),
          reason: z.string().trim().min(10).max(500),
          confirmationPhrase: z.string().max(300),
        }),
        response: { 200: z.object({ dataClass: z.string(), ttlDays: z.number().nullable() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'retention.configure');

      const { dataClass } = request.params;

      return withTransaction(async (client) => {
        const { rows } = await client.query<{
          ttl_days: number | null; min_ttl_days: number; enabled: boolean;
        }>(
          `SELECT ttl_days, min_ttl_days, enabled FROM admin.retention_policies
            WHERE data_class = $1 FOR UPDATE`,
          [dataClass],
        );
        const policy = rows[0];
        if (!policy) throw notFound('Retention policy');

        // The floor exists because shortening a TTL destroys evidence an open
        // appeal may still depend on. It is a database constraint too; this is
        // the readable error.
        if (request.body.ttlDays !== null && request.body.ttlDays < policy.min_ttl_days) {
          throw validationFailed(
            `${dataClass} cannot retain for fewer than ${policy.min_ttl_days} days. ` +
              'Shortening below the floor would destroy records still under appeal.',
            { minTtlDays: policy.min_ttl_days },
          );
        }

        await requireBreakGlass(
          client,
          actor,
          {
            permission: 'retention.configure',
            action: 'retention.configure',
            targetType: 'retention',
            targetId: dataClass,
            targetLabel: dataClass,
            payload: { dataClass, ttlDays: request.body.ttlDays },
          },
          {
            confirmationPhrase: request.body.confirmationPhrase,
            justification: request.body.reason,
          },
        );

        await client.query(
          `UPDATE admin.retention_policies
              SET ttl_days = $2, enabled = COALESCE($3, enabled),
                  updated_by = $4, updated_at = NOW()
            WHERE data_class = $1`,
          [dataClass, request.body.ttlDays, request.body.enabled ?? null, actor.id],
        );

        await writeAudit(client, actor, {
          action: 'retention.configured',
          targetType: 'retention',
          targetId: dataClass,
          targetLabel: dataClass,
          permission: 'retention.configure',
          note: request.body.reason,
          before: { ttlDays: policy.ttl_days, enabled: policy.enabled },
          after: { ttlDays: request.body.ttlDays, enabled: request.body.enabled ?? policy.enabled },
        });

        return { dataClass, ttlDays: request.body.ttlDays };
      });
    },
  );

  // -------------------------------------------------------------------------
  // Legal holds
  // -------------------------------------------------------------------------
  app.get(
    '/legal-holds',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['privacy'],
        summary: 'Active and released legal holds',
        querystring: z.object({ active: z.coerce.boolean().default(true) }),
        response: {
          200: z.array(
            z.object({
              id: z.string(),
              subjectType: z.string(),
              subjectId: z.string(),
              reference: z.string(),
              reason: z.string(),
              placedAt: z.date(),
              releasedAt: z.date().nullable(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'legalhold.manage');

      const { rows } = await getPool().query(
        `SELECT id, subject_type, subject_id, reference, reason, placed_at, released_at
           FROM admin.legal_holds
          ${request.query.active ? 'WHERE released_at IS NULL' : ''}
          ORDER BY placed_at DESC LIMIT 200`,
      );

      return rows.map((r) => ({
        id: r.id,
        subjectType: r.subject_type,
        subjectId: r.subject_id,
        reference: r.reference,
        reason: r.reason,
        placedAt: r.placed_at,
        releasedAt: r.released_at,
      }));
    },
  );

  app.post(
    '/legal-holds',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['privacy'],
        summary: 'Place a legal hold, suspending automatic deletion',
        body: z.object({
          subjectType: z.enum(['user', 'channel', 'case', 'message', 'ticket']),
          subjectId: z.string().min(1).max(120),
          reference: z.string().trim().min(1).max(120),
          reason: z.string().trim().min(10).max(1000),
          confirmationPhrase: z.string().max(300),
        }),
        response: { 200: z.object({ id: z.string() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'legalhold.manage');
      const body = request.body;

      return withTransaction(async (client) => {
        await requireBreakGlass(
          client,
          actor,
          {
            permission: 'legalhold.manage',
            action: 'legalhold.place',
            targetType: body.subjectType,
            targetId: body.subjectId,
            targetLabel: `${body.subjectType}:${body.subjectId}`,
            payload: { subjectType: body.subjectType, subjectId: body.subjectId },
          },
          { confirmationPhrase: body.confirmationPhrase, justification: body.reason },
        );

        const { rows } = await client.query<{ id: string }>(
          `INSERT INTO admin.legal_holds
             (subject_type, subject_id, reference, reason, placed_by)
           VALUES ($1, $2, $3, $4, $5) RETURNING id`,
          [body.subjectType, body.subjectId, body.reference, body.reason, actor.id],
        );

        await writeAudit(client, actor, {
          action: 'legal_hold.placed',
          targetType: 'legal_hold',
          targetId: rows[0]!.id,
          targetLabel: `${body.subjectType}:${body.subjectId}`,
          permission: 'legalhold.manage',
          note: body.reason,
          after: { reference: body.reference },
        });

        return { id: rows[0]!.id };
      });
    },
  );

  app.post(
    '/legal-holds/:id/release',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['privacy'],
        summary: 'Release a legal hold',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({ releaseNote: z.string().trim().min(10).max(1000) }),
        response: { 200: z.object({ id: z.string(), releasedAt: z.date() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'legalhold.manage');

      return withTransaction(async (client) => {
        const { rows } = await client.query<{
          id: string; subject_type: string; subject_id: string; released_at: Date | null;
        }>(
          `SELECT id, subject_type, subject_id, released_at
             FROM admin.legal_holds WHERE id = $1 FOR UPDATE`,
          [request.params.id],
        );
        const hold = rows[0];
        if (!hold) throw notFound('Legal hold');
        if (hold.released_at) throw conflict('That hold has already been released.');

        const updated = await client.query<{ released_at: Date }>(
          `UPDATE admin.legal_holds
              SET released_at = NOW(), released_by = $2, release_note = $3
            WHERE id = $1 RETURNING released_at`,
          [hold.id, actor.id, request.body.releaseNote],
        );

        await writeAudit(client, actor, {
          action: 'legal_hold.released',
          targetType: 'legal_hold',
          targetId: hold.id,
          targetLabel: `${hold.subject_type}:${hold.subject_id}`,
          permission: 'legalhold.manage',
          note: request.body.releaseNote,
        });

        return { id: hold.id, releasedAt: updated.rows[0]!.released_at };
      });
    },
  );

  // -------------------------------------------------------------------------
  // Data subject requests
  // -------------------------------------------------------------------------
  app.get(
    '/dsr',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['privacy'],
        summary: 'Data subject requests with SLA state',
        querystring: z.object({
          status: z
            .enum(['received', 'verifying', 'in_progress', 'completed', 'rejected', 'on_hold'])
            .optional(),
          overdue: z.coerce.boolean().optional(),
          limit: z.coerce.number().int().min(1).max(100).default(50),
        }),
        response: {
          200: z.array(
            z.object({
              id: z.string(),
              userId: z.string(),
              username: z.string().nullable(),
              kind: z.string(),
              status: z.string(),
              receivedAt: z.date(),
              slaDueAt: z.date(),
              completedAt: z.date().nullable(),
              overdue: z.boolean(),
              underLegalHold: z.boolean(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'privacy.dsr.view');

      const where: string[] = [];
      const params: unknown[] = [];
      if (request.query.status) {
        params.push(request.query.status);
        where.push(`r.status = $${params.length}`);
      }
      if (request.query.overdue) {
        where.push(`r.sla_due_at <= NOW() AND r.status NOT IN ('completed','rejected')`);
      }

      const { rows } = await getPool().query(
        `SELECT r.id, r.user_id, d.username, r.kind, r.status, r.received_at,
                r.sla_due_at, r.completed_at,
                (r.sla_due_at <= NOW() AND r.status NOT IN ('completed','rejected')) AS overdue,
                admin.is_under_legal_hold('user', r.user_id::text) AS under_legal_hold
           FROM admin.dsr_requests r
           LEFT JOIN admin.user_directory d ON d.id = r.user_id
          ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
          ORDER BY r.sla_due_at ASC
          LIMIT $${params.length + 1}`,
        [...params, request.query.limit],
      );

      return rows.map((r) => ({
        id: r.id,
        userId: r.user_id,
        username: r.username,
        kind: r.kind,
        status: r.status,
        receivedAt: r.received_at,
        slaDueAt: r.sla_due_at,
        completedAt: r.completed_at,
        overdue: r.overdue,
        underLegalHold: r.under_legal_hold,
      }));
    },
  );

  app.patch(
    '/dsr/:id',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['privacy'],
        summary: 'Advance a data subject request',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({
          status: z.enum(['verifying', 'in_progress', 'completed', 'rejected', 'on_hold']),
          verification: z.string().max(300).optional(),
          resolutionNote: z.string().max(2000).optional(),
        }),
        response: { 200: z.object({ id: z.string(), status: z.string() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'privacy.dsr.process');

      const body = request.body;
      if (['completed', 'rejected'].includes(body.status) && !body.resolutionNote) {
        throw validationFailed('A resolution note is required to close a data subject request.');
      }

      return withTransaction(async (client) => {
        const { rows } = await client.query<{
          id: string; user_id: string; kind: string; status: string;
        }>(
          `SELECT id, user_id, kind, status FROM admin.dsr_requests WHERE id = $1 FOR UPDATE`,
          [request.params.id],
        );
        const dsr = rows[0];
        if (!dsr) throw notFound('Data subject request');

        // The legal-hold guard is a database trigger; completing an erasure
        // against a held account raises there. Caught by the app's P0001 handler.
        await client.query(
          `UPDATE admin.dsr_requests
              SET status = $2,
                  verification = COALESCE($3, verification),
                  resolution_note = COALESCE($4, resolution_note),
                  handled_by = $5,
                  completed_at = CASE WHEN $2 IN ('completed','rejected') THEN NOW() ELSE completed_at END
            WHERE id = $1`,
          [dsr.id, body.status, body.verification ?? null, body.resolutionNote ?? null, actor.id],
        );

        await writeAudit(client, actor, {
          action: 'dsr.updated',
          targetType: 'dsr',
          targetId: dsr.id,
          targetLabel: `${dsr.kind} for ${dsr.user_id}`,
          permission: 'privacy.dsr.process',
          note: body.resolutionNote ?? null,
          before: { status: dsr.status },
          after: { status: body.status },
        });

        return { id: dsr.id, status: body.status };
      });
    },
  );

  // -------------------------------------------------------------------------
  // Transparency reporting
  // -------------------------------------------------------------------------
  app.get(
    '/transparency',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['privacy'],
        summary: 'Aggregate statistics suitable for publication (§8)',
        querystring: z.object({
          from: z.coerce.date().optional(),
          to: z.coerce.date().optional(),
        }),
        response: {
          200: z.object({
            periods: z.array(
              z.object({
                period: z.string(),
                metrics: z.array(
                  z.object({ metric: z.string(), dimension: z.string(), count: z.number() }),
                ),
              }),
            ),
            note: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'transparency.generate');

      const { rows } = await getPool().query<{
        period: Date; metric: string; dimension: string; count: string;
      }>(
        `SELECT period, metric, dimension, count
           FROM admin.transparency_counters
          WHERE ($1::date IS NULL OR period >= $1::date)
            AND ($2::date IS NULL OR period <= $2::date)
          ORDER BY period DESC, metric, dimension`,
        [request.query.from ?? null, request.query.to ?? null],
      );

      const byPeriod = new Map<string, Array<{ metric: string; dimension: string; count: number }>>();
      for (const r of rows) {
        const key = r.period.toISOString().slice(0, 7);
        const list = byPeriod.get(key) ?? [];
        list.push({ metric: r.metric, dimension: r.dimension, count: Number(r.count) });
        byPeriod.set(key, list);
      }

      return {
        periods: [...byPeriod.entries()].map(([period, metrics]) => ({ period, metrics })),
        note:
          'These counters are incremented at write time, so they survive erasure requests that ' +
          'remove the underlying records. That is deliberate: published statistics must not ' +
          'silently change when a user exercises their right to deletion.',
      };
    },
  );
}
