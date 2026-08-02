import { getPool } from '@neveroff-console/db';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { actorOf } from '../plugins/auth.js';
import { requirePermission } from '../rbac.js';

/**
 * Audit log reading (§7).
 *
 * Scoping rule: §1.1 reserves "view the full audit log" to the Super Admin.
 * Everyone else holding `audit.view` sees entries about targets inside their
 * own scope, plus their own actions. A Tier 2 lead in DE can review what their
 * moderators did; they cannot browse what a Tier 1 did to an unrelated account.
 */
export default async function auditRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  app.get(
    '/',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['audit'],
        summary: 'Search the immutable audit log',
        querystring: z.object({
          search: z.string().trim().min(1).max(200).optional(),
          actorAdminId: z.string().uuid().optional(),
          targetType: z.string().max(40).optional(),
          targetId: z.string().max(120).optional(),
          action: z.string().max(80).optional(),
          piiOnly: z.coerce.boolean().optional(),
          origin: z.enum(['manual', 'automated', 'system']).optional(),
          from: z.coerce.date().optional(),
          to: z.coerce.date().optional(),
          limit: z.coerce.number().int().min(1).max(200).default(50),
          offset: z.coerce.number().int().min(0).default(0),
        }),
        response: {
          200: z.object({
            rows: z.array(
              z.object({
                id: z.string(),
                occurredAt: z.date(),
                actorLabel: z.string(),
                actorRole: z.string().nullable(),
                origin: z.string(),
                action: z.string(),
                permissionKey: z.string().nullable(),
                targetType: z.string(),
                targetId: z.string().nullable(),
                targetLabel: z.string().nullable(),
                reasonCode: z.string().nullable(),
                note: z.string().nullable(),
                isPiiAccess: z.boolean(),
                ip: z.string().nullable(),
                beforeState: z.unknown().nullable(),
                afterState: z.unknown().nullable(),
              }),
            ),
            total: z.number(),
            scopeLimited: z.boolean(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'audit.view');

      const q = request.query;
      const where: string[] = [];
      const params: unknown[] = [];
      const add = (clause: string, value: unknown): void => {
        params.push(value);
        where.push(clause.replace('?', `$${params.length}`));
      };

      if (q.actorAdminId) add('a.actor_admin_id = ?', q.actorAdminId);
      if (q.targetType) add('a.target_type = ?', q.targetType);
      if (q.targetId) add('a.target_id = ?', q.targetId);
      if (q.action) add('a.action = ?', q.action);
      if (q.origin) add('a.origin = ?', q.origin);
      if (q.piiOnly) where.push('a.is_pii_access');
      if (q.from) add('a.occurred_at >= ?', q.from);
      if (q.to) add('a.occurred_at <= ?', q.to);

      if (q.search) {
        add(
          `to_tsvector('simple',
             coalesce(a.actor_label,'') || ' ' || coalesce(a.action,'') || ' ' ||
             coalesce(a.target_label,'') || ' ' || coalesce(a.target_id,'') || ' ' ||
             coalesce(a.reason_code,'') || ' ' || coalesce(a.note,''))
           @@ plainto_tsquery('simple', ?)`,
          q.search,
        );
      }

      // Scope. The Super Admin is the only role that sees everything (§1.1).
      const scopeLimited = actor.role !== 'super_admin' && actor.scope.countries !== null;
      if (scopeLimited) {
        params.push([...actor.scope.countries!], actor.id);
        const countriesParam = `$${params.length - 1}`;
        const selfParam = `$${params.length}`;
        where.push(
          `(a.actor_admin_id = ${selfParam}
            OR (a.target_type = 'user'
                AND EXISTS (
                  SELECT 1 FROM admin.user_directory d
                   WHERE d.id::text = a.target_id
                     AND d.country IS NOT NULL
                     AND d.country = ANY(${countriesParam}))))`,
        );
      }

      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
      const pool = getPool();

      const [countResult, rowsResult] = await Promise.all([
        pool.query<{ total: string }>(
          `SELECT count(*)::text AS total FROM admin.audit_log a ${whereSql}`,
          params,
        ),
        pool.query(
          `SELECT a.id, a.occurred_at, a.actor_label, a.actor_role, a.origin, a.action,
                  a.permission_key, a.target_type, a.target_id, a.target_label,
                  a.reason_code, a.note, a.is_pii_access, a.ip::text AS ip,
                  a.before_state, a.after_state
             FROM admin.audit_log a
             ${whereSql}
            ORDER BY a.occurred_at DESC, a.id DESC
            LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
          [...params, q.limit, q.offset],
        ),
      ]);

      return {
        rows: rowsResult.rows.map((r) => ({
          id: String(r.id),
          occurredAt: r.occurred_at,
          actorLabel: r.actor_label,
          actorRole: r.actor_role,
          origin: r.origin,
          action: r.action,
          permissionKey: r.permission_key,
          targetType: r.target_type,
          targetId: r.target_id,
          targetLabel: r.target_label,
          reasonCode: r.reason_code,
          note: r.note,
          isPiiAccess: r.is_pii_access,
          ip: r.ip,
          beforeState: r.before_state,
          afterState: r.after_state,
        })),
        total: Number(countResult.rows[0]?.total ?? 0),
        scopeLimited,
      };
    },
  );

  app.get(
    '/integrity',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['audit'],
        summary: 'Verify the audit log hash chain',
        querystring: z.object({ fromId: z.coerce.number().int().min(0).default(0) }),
        response: {
          200: z.object({
            intact: z.boolean(),
            breaks: z.array(
              z.object({
                brokenAtId: z.string(),
                expectedHash: z.string().nullable(),
                storedHash: z.string().nullable(),
                reason: z.string(),
              }),
            ),
            note: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'audit.view');
      if (actor.role !== 'super_admin') {
        // Chain verification reveals the shape of the whole log, including
        // entries a scoped admin cannot read individually.
        requirePermission(actor, 'analytics.export_raw');
      }

      const { rows } = await getPool().query<{
        broken_at_id: string;
        expected_hash: string | null;
        stored_hash: string | null;
        reason: string;
      }>(`SELECT * FROM admin.verify_audit_chain($1)`, [request.query.fromId]);

      return {
        intact: rows.length === 0,
        breaks: rows.map((r) => ({
          brokenAtId: String(r.broken_at_id),
          expectedHash: r.expected_hash,
          storedHash: r.stored_hash,
          reason: r.reason,
        })),
        note:
          'This verifies the hash chain within the database. It detects tampering by anyone ' +
          'who did not also recompute every subsequent hash. It does not defend against an ' +
          'attacker with superuser access — that requires shipping the log to append-only ' +
          'external storage, which the runbook covers as a deployment requirement.',
      };
    },
  );

  app.get(
    '/alerts',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['audit'],
        summary: 'Admin-behaviour anomaly alerts (§7)',
        querystring: z.object({
          open: z.coerce.boolean().default(true),
          limit: z.coerce.number().int().min(1).max(100).default(50),
        }),
        response: {
          200: z.array(
            z.object({
              id: z.string(),
              kind: z.string(),
              severity: z.string(),
              title: z.string(),
              detail: z.string(),
              subjectAdminId: z.string().nullable(),
              evidence: z.unknown(),
              raisedAt: z.date(),
              acknowledgedAt: z.date().nullable(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'audit.view');

      const { rows } = await getPool().query(
        `SELECT id, kind, severity, title, detail, subject_admin_id, evidence,
                raised_at, acknowledged_at
           FROM admin.alerts
          ${request.query.open ? 'WHERE acknowledged_at IS NULL' : ''}
          ORDER BY raised_at DESC
          LIMIT $1`,
        [request.query.limit],
      );

      return rows.map((r) => ({
        id: r.id,
        kind: r.kind,
        severity: r.severity,
        title: r.title,
        detail: r.detail,
        subjectAdminId: r.subject_admin_id,
        evidence: r.evidence,
        raisedAt: r.raised_at,
        acknowledgedAt: r.acknowledged_at,
      }));
    },
  );
}
