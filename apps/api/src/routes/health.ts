import { getPool } from '@neveroff-console/db';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

/**
 * Liveness and readiness.
 *
 * §9.3 requires graceful degradation — "moderation stays usable if analytics is
 * down" — so readiness reports per-dependency status rather than a single
 * boolean. A load balancer should keep sending traffic when the analytics store
 * is unhappy but the primary database is fine.
 */
export default async function healthRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  app.get(
    '/health',
    {
      schema: {
        tags: ['auth'],
        summary: 'Liveness probe',
        response: { 200: z.object({ status: z.literal('ok'), uptimeSeconds: z.number() }) },
      },
      config: { rateLimit: false },
    },
    async () => ({ status: 'ok' as const, uptimeSeconds: Math.floor(process.uptime()) }),
  );

  app.get(
    '/ready',
    {
      schema: {
        tags: ['auth'],
        summary: 'Readiness probe with per-dependency status',
        // 503 is declared as well as 200 — a readiness probe that can only
        // describe success is not a readiness probe, and the type provider
        // narrows reply.status() to whatever the schema lists.
        response: {
          200: z.object({
            status: z.enum(['ok', 'degraded']),
            checks: z.array(
              z.object({
                name: z.string(),
                ok: z.boolean(),
                critical: z.boolean(),
                detail: z.string().optional(),
              }),
            ),
          }),
          503: z.object({
            status: z.enum(['ok', 'degraded']),
            checks: z.array(
              z.object({
                name: z.string(),
                ok: z.boolean(),
                critical: z.boolean(),
                detail: z.string().optional(),
              }),
            ),
          }),
        },
      },
      config: { rateLimit: false },
    },
    async (_request, reply) => {
      const checks: Array<{ name: string; ok: boolean; critical: boolean; detail?: string }> = [];

      try {
        await getPool().query('SELECT 1');
        checks.push({ name: 'postgres', ok: true, critical: true });
      } catch (err) {
        checks.push({
          name: 'postgres',
          ok: false,
          critical: true,
          detail: err instanceof Error ? err.message : 'unreachable',
        });
      }

      try {
        const { rows } = await getPool().query<{ count: string }>(
          `SELECT count(*)::text AS count FROM admin.schema_migrations`,
        );
        checks.push({
          name: 'migrations',
          ok: Number(rows[0]?.count ?? 0) > 0,
          critical: true,
          detail: `${rows[0]?.count ?? 0} applied`,
        });
      } catch {
        checks.push({ name: 'migrations', ok: false, critical: true, detail: 'not initialised' });
      }

      const criticalFailure = checks.some((c) => c.critical && !c.ok);
      const status = criticalFailure ? ('degraded' as const) : ('ok' as const);

      return reply.status(criticalFailure ? 503 : 200).send({ status, checks });
    },
  );
}
