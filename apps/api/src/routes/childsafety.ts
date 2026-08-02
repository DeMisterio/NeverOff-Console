import { getPool, withTransaction } from '@neveroff-console/db';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { forbidden, notImplemented } from '../errors.js';
import { actorOf } from '../plugins/auth.js';
import { requirePermission } from '../rbac.js';

/**
 * Child safety pipeline (§6.7) — SCAFFOLD ONLY.
 *
 * What works: the access gate, the isolated case list, and per-view logging.
 * What deliberately does not: hash matching and mandatory authority reporting.
 * Those endpoints return 501 with an explanation rather than silently doing
 * nothing, because a reporting path that appears to work but does not is worse
 * than no path at all — it produces the false belief that a legal obligation
 * has been discharged.
 *
 * Access requires BOTH the childsafety.access atom AND membership of the named
 * allowlist with unexpired training. Neither alone is sufficient, and the
 * allowlist check happens in the database so it cannot be skipped by a route
 * that forgets to call it.
 */

async function assertChildSafetyAccess(adminId: string): Promise<void> {
  const { rows } = await getPool().query<{ authorised: boolean }>(
    `SELECT admin.is_child_safety_authorised($1) AS authorised`,
    [adminId],
  );

  if (!rows[0]?.authorised) {
    throw forbidden(
      'Access to the child safety queue requires membership of the named allowlist with ' +
        'current training, in addition to the permission. Contact the Super Admin.',
      undefined,
      'child_safety_access_denied',
    );
  }
}

export default async function childSafetyRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  app.get(
    '/cases',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['child-safety'],
        summary: 'Isolated child-safety case queue (allowlist required)',
        response: {
          200: z.object({
            rows: z.array(
              z.object({
                id: z.string(),
                caseRef: z.string(),
                reasonCode: z.string(),
                status: z.string(),
                receivedAt: z.date(),
                assignedTo: z.string().nullable(),
              }),
            ),
            notice: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'childsafety.access');
      await assertChildSafetyAccess(actor.id);

      return withTransaction(async (client) => {
        const { rows } = await client.query(
          `SELECT id, case_ref, reason_code, status, received_at, assigned_to
             FROM admin.child_safety_cases
            WHERE closed_at IS NULL
            ORDER BY received_at ASC
            LIMIT 100`,
        );

        // §6.7: every view individually logged, to the isolated log rather than
        // the general audit surface.
        await client.query(
          `INSERT INTO admin.child_safety_access_log
             (case_id, admin_id, admin_label, action, ip, session_id)
           SELECT id, $1, $2, 'list', $3::inet, $4::uuid
             FROM admin.child_safety_cases WHERE closed_at IS NULL`,
          [actor.id, `${actor.displayName} <${actor.email}>`, actor.ip, actor.sessionId],
        );

        return {
          rows: rows.map((r) => ({
            id: r.id,
            caseRef: r.case_ref,
            reasonCode: r.reason_code,
            status: r.status,
            receivedAt: r.received_at,
            assignedTo: r.assigned_to,
          })),
          notice:
            'Every view in this queue is individually logged. This pipeline is scaffolding: ' +
            'hash matching and authority reporting are not implemented and require legal ' +
            'counsel to define before use.',
        };
      });
    },
  );

  app.post(
    '/cases/:id/report-to-authority',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['child-safety'],
        summary: 'NOT IMPLEMENTED — mandatory reporting requires legal sign-off',
        params: z.object({ id: z.string().uuid() }),
        response: { 501: z.object({ error: z.object({ code: z.string(), message: z.string() }) }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'childsafety.access');
      await assertChildSafetyAccess(actor.id);

      throw notImplemented(
        'Mandatory reporting to NCMEC or the local equivalent is not implemented. The content, ' +
          'timing, format and retention obligations are set by statute and vary by jurisdiction, ' +
          'and getting them wrong carries criminal exposure. Engage counsel to define the ' +
          'requirements, then implement against that definition (§6.7, §13). Until then, follow ' +
          'the manual escalation procedure in the operations runbook.',
      );
    },
  );

  app.post(
    '/hash-scan',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['child-safety'],
        summary: 'NOT IMPLEMENTED — hash matching requires a provider agreement',
        response: { 501: z.object({ error: z.object({ code: z.string(), message: z.string() }) }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'childsafety.access');
      await assertChildSafetyAccess(actor.id);

      throw notImplemented(
        'Perceptual hash matching against known-CSAM corpora is not implemented. Access to ' +
          'PhotoDNA or an equivalent database is contractual and jurisdiction-specific. There is ' +
          'deliberately no client code for it (§6.7, §13).',
      );
    },
  );

  app.get(
    '/allowlist',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['child-safety'],
        summary: 'Who may access the child safety pipeline',
        response: {
          200: z.array(
            z.object({
              adminId: z.string(),
              displayName: z.string(),
              trainingRef: z.string(),
              trainingCompletedAt: z.date(),
              expiresAt: z.date(),
              active: z.boolean(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'childsafety.administer');

      const { rows } = await getPool().query(
        `SELECT a.admin_id, u.display_name, a.training_ref, a.training_completed_at,
                a.expires_at,
                (a.revoked_at IS NULL AND a.expires_at > NOW()) AS active
           FROM admin.child_safety_allowlist a
           JOIN admin.admin_users u ON u.id = a.admin_id
          ORDER BY a.added_at DESC`,
      );

      return rows.map((r) => ({
        adminId: r.admin_id,
        displayName: r.display_name,
        trainingRef: r.training_ref,
        trainingCompletedAt: r.training_completed_at,
        expiresAt: r.expires_at,
        active: r.active,
      }));
    },
  );
}
