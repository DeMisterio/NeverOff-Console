import { getPool, withTransaction } from '@neveroff-console/db';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { writeAudit } from '../audit.js';
import { conflict, notFound, validationFailed } from '../errors.js';
import { actorOf } from '../plugins/auth.js';
import { requirePermission } from '../rbac.js';

/**
 * Automated detection (§6.6).
 *
 * The rule that shapes this file: a rule cannot be created in enforce mode, and
 * promoting one out of shadow requires either meeting a measured quality bar or
 * a written override. §6.6 asks for shadow mode "so you can measure its
 * false-positive rate before enabling enforcement" — a shadow mode you can skip
 * is decoration, so the API makes skipping it a deliberate, recorded act rather
 * than a dropdown.
 */

const RuleBody = z.object({
  name: z.string().trim().min(3).max(120),
  description: z.string().max(1000).optional(),
  surface: z.enum(['direct_message', 'channel_post', 'profile', 'account']),
  signal: z.enum([
    'message_velocity', 'conversation_fanout', 'new_account_mass_dm', 'channel_join_burst',
    'keyword_match', 'regex_match', 'link_domain', 'media_hash',
  ]),
  config: z.record(z.unknown()).default({}),
  action: z.enum(['flag_for_review', 'auto_hide', 'rate_limit', 'notify_moderators', 'auto_escalate']),
  actionConfig: z.record(z.unknown()).default({}),
  reasonCode: z.string().max(80).optional(),
});

const CONTENT_SIGNALS = new Set(['keyword_match', 'regex_match', 'link_domain', 'media_hash']);

export default async function automodRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  // -------------------------------------------------------------------------
  app.get(
    '/rules',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['automod'],
        summary: 'Rules with measured precision and promotion readiness',
        querystring: z.object({ days: z.coerce.number().int().min(1).max(365).default(30) }),
        response: {
          200: z.object({
            rows: z.array(
              z.object({
                id: z.string(),
                name: z.string(),
                description: z.string().nullable(),
                mode: z.string(),
                surface: z.string(),
                signal: z.string(),
                action: z.string(),
                config: z.record(z.unknown()),
                enforcingSince: z.date().nullable(),
                firings: z.number(),
                reviewed: z.number(),
                truePositives: z.number(),
                falsePositives: z.number(),
                precisionPct: z.number().nullable(),
                reviewCoverage: z.number().nullable(),
                readyToEnforce: z.boolean(),
              }),
            ),
            note: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'automod.configure');

      const pool = getPool();
      const [rules, quality] = await Promise.all([
        pool.query(`SELECT * FROM admin.automod_rules ORDER BY created_at DESC`),
        pool.query(`SELECT * FROM admin.automod_rule_quality($1)`, [request.query.days]),
      ]);

      const byId = new Map(quality.rows.map((q) => [q.rule_id, q]));

      return {
        rows: rules.rows.map((r) => {
          const q = byId.get(r.id);
          return {
            id: r.id,
            name: r.name,
            description: r.description,
            mode: r.mode,
            surface: r.surface,
            signal: r.signal,
            action: r.action,
            config: r.config,
            enforcingSince: r.enforcing_since,
            firings: Number(q?.firings ?? 0),
            reviewed: Number(q?.reviewed ?? 0),
            truePositives: Number(q?.true_positives ?? 0),
            falsePositives: Number(q?.false_positives ?? 0),
            precisionPct: q?.precision_pct === null || q?.precision_pct === undefined
              ? null : Number(q.precision_pct),
            reviewCoverage: q?.review_coverage === null || q?.review_coverage === undefined
              ? null : Number(q.review_coverage),
            readyToEnforce: Boolean(q?.ready_to_enforce),
          };
        }),
        note:
          'Precision is measured against reviewed firings only. Recall is deliberately absent — ' +
          'it needs a ground truth of everything a rule should have caught, and the misses are ' +
          'by definition the things nobody flagged. A fabricated recall figure would be worse ' +
          'than none.',
      };
    },
  );

  // -------------------------------------------------------------------------
  app.post(
    '/rules',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['automod'],
        summary: 'Create a rule. Always starts in shadow mode.',
        body: RuleBody,
        response: { 200: z.object({ id: z.string(), mode: z.literal('shadow') }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'automod.configure');
      const body = request.body;

      // Refused here as well as by a CHECK constraint, so the error explains
      // itself rather than surfacing as a constraint violation.
      if (CONTENT_SIGNALS.has(body.signal) && body.surface === 'direct_message') {
        throw validationFailed(
          'Content rules cannot target private messages. They are end-to-end encrypted, so the ' +
            'server holds ciphertext and this rule could never fire. Use a behavioural signal ' +
            '(velocity, fan-out, account age) instead, or scope the rule to channel posts.',
          { signal: body.signal, surface: body.surface },
        );
      }

      return withTransaction(async (client) => {
        const { rows } = await client.query<{ id: string }>(
          `INSERT INTO admin.automod_rules
             (name, description, mode, surface, signal, config, action, action_config,
              reason_code, created_by)
           VALUES ($1, $2, 'shadow', $3, $4, $5, $6, $7, $8, $9)
           RETURNING id`,
          [
            body.name,
            body.description ?? null,
            body.surface,
            body.signal,
            JSON.stringify(body.config),
            body.action,
            JSON.stringify(body.actionConfig),
            body.reasonCode ?? null,
            actor.id,
          ],
        );

        await writeAudit(client, actor, {
          action: 'automod.rule.created',
          targetType: 'automod_rule',
          targetId: rows[0]!.id,
          targetLabel: body.name,
          permission: 'automod.configure',
          after: { ...body, mode: 'shadow' },
          note: 'Created in shadow mode. It records what it would do and does nothing.',
        });

        return { id: rows[0]!.id, mode: 'shadow' as const };
      });
    },
  );

  // -------------------------------------------------------------------------
  app.patch(
    '/rules/:id',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['automod'],
        summary: 'Change a rule’s mode or thresholds',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({
          mode: z.enum(['disabled', 'shadow', 'enforce']).optional(),
          config: z.record(z.unknown()).optional(),
          // Required to promote a rule that has not met the measured bar.
          overrideJustification: z.string().trim().min(20).max(1000).optional(),
        }),
        response: { 200: z.object({ id: z.string(), mode: z.string() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'automod.configure');

      return withTransaction(async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM admin.automod_rules WHERE id = $1 FOR UPDATE`,
          [request.params.id],
        );
        const rule = rows[0];
        if (!rule) throw notFound('Rule');

        const body = request.body;
        const promoting = body.mode === 'enforce' && rule.mode !== 'enforce';

        if (promoting) {
          const quality = await client.query<{ ready_to_enforce: boolean; firings: string; reviewed: string; precision_pct: string | null }>(
            `SELECT firings, reviewed, precision_pct, ready_to_enforce
               FROM admin.automod_rule_quality(30) WHERE rule_id = $1`,
            [rule.id],
          );
          const q = quality.rows[0];

          if (!q?.ready_to_enforce) {
            if (!body.overrideJustification) {
              throw conflict(
                `"${rule.name}" has not met the measured bar for enforcement: ` +
                  `${q?.firings ?? 0} firings, ${q?.reviewed ?? 0} reviewed, ` +
                  `precision ${q?.precision_pct ?? 'unknown'}%. ` +
                  'The bar is 30 firings, 20 reviewed and 95% precision. Review more of its ' +
                  'shadow firings, or supply a written justification to override — which is ' +
                  'recorded against your account.',
                {
                  firings: Number(q?.firings ?? 0),
                  reviewed: Number(q?.reviewed ?? 0),
                  precisionPct: q?.precision_pct,
                },
              );
            }

            // Overriding the bar is allowed but never quiet.
            await client.query(
              `INSERT INTO admin.alerts (kind, severity, title, detail, subject_admin_id, evidence)
               VALUES ('automod_drift', 'high', $1, $2, $3, $4)`,
              [
                `${actor.displayName} enabled enforcement on an unproven rule`,
                `"${rule.name}" was promoted out of shadow without meeting the precision bar. ` +
                  `Justification: ${body.overrideJustification}`,
                actor.id,
                JSON.stringify({
                  rule_id: rule.id,
                  firings: Number(q?.firings ?? 0),
                  precision_pct: q?.precision_pct,
                }),
              ],
            );
          }
        }

        await client.query(
          `UPDATE admin.automod_rules
              SET mode = COALESCE($2, mode),
                  config = COALESCE($3, config),
                  enforcing_since = CASE WHEN $2 = 'enforce' AND enforcing_since IS NULL
                                         THEN NOW() ELSE enforcing_since END
            WHERE id = $1`,
          [rule.id, body.mode ?? null, body.config ? JSON.stringify(body.config) : null],
        );

        await writeAudit(client, actor, {
          action: promoting ? 'automod.rule.enforcing' : 'automod.rule.updated',
          targetType: 'automod_rule',
          targetId: rule.id,
          targetLabel: rule.name,
          permission: 'automod.configure',
          before: { mode: rule.mode, config: rule.config },
          after: { mode: body.mode ?? rule.mode, config: body.config ?? rule.config },
          note: body.overrideJustification ?? null,
        });

        return { id: rule.id, mode: body.mode ?? rule.mode };
      });
    },
  );

  // -------------------------------------------------------------------------
  app.get(
    '/firings',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['automod'],
        summary: 'Firings awaiting human review — this is what precision is measured from',
        querystring: z.object({
          ruleId: z.string().uuid().optional(),
          unreviewedOnly: z.coerce.boolean().default(true),
          limit: z.coerce.number().int().min(1).max(100).default(50),
        }),
        response: {
          200: z.array(
            z.object({
              id: z.string(),
              ruleId: z.string(),
              ruleName: z.string(),
              firedAt: z.date(),
              subjectType: z.string(),
              subjectId: z.string(),
              subjectUserId: z.string().nullable(),
              signals: z.record(z.unknown()),
              modeAtFiring: z.string(),
              actionTaken: z.string().nullable(),
              reviewOutcome: z.string().nullable(),
              explanation: z.string(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'automod.configure');

      const where: string[] = [];
      const params: unknown[] = [];
      if (request.query.ruleId) {
        params.push(request.query.ruleId);
        where.push(`f.rule_id = $${params.length}`);
      }
      if (request.query.unreviewedOnly) where.push('f.review_outcome IS NULL');

      const { rows } = await getPool().query(
        `SELECT f.*, r.name AS rule_name, r.signal
           FROM admin.automod_firings f
           JOIN admin.automod_rules r ON r.id = f.rule_id
          ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
          ORDER BY f.fired_at DESC
          LIMIT $${params.length + 1}`,
        [...params, request.query.limit],
      );

      return rows.map((f) => ({
        id: f.id,
        ruleId: f.rule_id,
        ruleName: f.rule_name,
        firedAt: f.fired_at,
        subjectType: f.subject_type,
        subjectId: f.subject_id,
        subjectUserId: f.subject_user_id,
        signals: f.signals,
        modeAtFiring: f.mode_at_firing,
        actionTaken: f.action_taken,
        reviewOutcome: f.review_outcome,
        // §6.6: every automated action must be explainable. Built from the
        // values recorded at firing time, so it survives a later config change.
        explanation:
          `Rule "${f.rule_name}" fired on signal "${f.signal}" with ` +
          Object.entries(f.signals as Record<string, unknown>)
            .map(([k, v]) => `${k}=${String(v)}`)
            .join(', ') +
          (f.mode_at_firing === 'shadow'
            ? '. Shadow mode: nothing was done to anyone.'
            : `. Action taken: ${f.action_taken ?? 'none'}.`),
      }));
    },
  );

  // -------------------------------------------------------------------------
  app.post(
    '/firings/:id/review',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['automod'],
        summary: 'Judge a firing — this is the sampled human audit (§6.6)',
        params: z.object({ id: z.string().uuid() }),
        body: z.object({
          outcome: z.enum(['true_positive', 'false_positive', 'unclear']),
        }),
        response: { 200: z.object({ id: z.string(), outcome: z.string() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'automod.configure');

      return withTransaction(async (client) => {
        const { rowCount } = await client.query(
          `UPDATE admin.automod_firings
              SET review_outcome = $2, reviewed_by = $3, reviewed_at = NOW()
            WHERE id = $1`,
          [request.params.id, request.body.outcome, actor.id],
        );
        if (rowCount === 0) throw notFound('Firing');

        await writeAudit(client, actor, {
          action: 'automod.firing.reviewed',
          targetType: 'automod_rule',
          targetId: request.params.id,
          targetLabel: request.params.id,
          permission: 'automod.configure',
          after: { outcome: request.body.outcome },
        });

        return { id: request.params.id, outcome: request.body.outcome };
      });
    },
  );

  // -------------------------------------------------------------------------
  app.post(
    '/blocklist',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['automod'],
        summary: 'Add a blocklist entry',
        body: z.object({
          kind: z.enum(['domain', 'keyword', 'media_sha256']),
          value: z.string().trim().min(1).max(300),
          note: z.string().max(500).optional(),
        }),
        response: { 200: z.object({ id: z.string() }) },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'automod.configure');

      return withTransaction(async (client) => {
        const { rows } = await client.query<{ id: string }>(
          `INSERT INTO admin.automod_blocklist (kind, value, note, added_by)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT DO NOTHING
           RETURNING id`,
          [request.body.kind, request.body.value, request.body.note ?? null, actor.id],
        );
        if (!rows[0]) throw conflict('That entry is already on the blocklist.');

        await writeAudit(client, actor, {
          action: 'automod.blocklist.added',
          targetType: 'automod_rule',
          targetId: rows[0].id,
          targetLabel: `${request.body.kind}: ${request.body.value}`,
          permission: 'automod.configure',
          note: request.body.note ?? null,
        });

        return { id: rows[0].id };
      });
    },
  );
}
