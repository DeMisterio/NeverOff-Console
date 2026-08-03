import { getPool, withTransaction } from '@neveroff-console/db';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { writeAudit } from '../audit.js';
import { actorOf } from '../plugins/auth.js';
import { requirePermission } from '../rbac.js';

/**
 * Analytics (§2).
 *
 * Every response carries `dataAsOf` and, where relevant, `basis`. §2.6 asks for
 * a visible "data as of HH:MM" because a cached number with no timestamp is
 * indistinguishable from a live one, and people make decisions on it either way.
 *
 * `basis` is the more important of the two. Metrics derived from client
 * telemetry cover only users who consented to analytics, so they are a sample.
 * Returning them without saying so would mean presenting a partial count as a
 * platform total — which is not a rounding error, it is a wrong number with a
 * confident label.
 */

const GRANULARITIES = ['hour', 'day', 'week', 'month'] as const;

/** Whitelist — never interpolate a caller-supplied value into date_trunc. */
const TRUNC: Record<string, string> = {
  hour: 'hour',
  day: 'day',
  week: 'week',
  month: 'month',
};

function csvEscape(value: unknown): string {
  if (value === null || value === undefined) return '';
  const text = String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function toCsv(rows: Array<Record<string, unknown>>): string {
  if (rows.length === 0) return '';
  const headers = Object.keys(rows[0]!);
  const lines = [headers.join(',')];
  for (const row of rows) {
    lines.push(headers.map((h) => csvEscape(row[h])).join(','));
  }
  return lines.join('\n');
}

export default async function analyticsRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  /** Freshness of the rollups a response was built from. */
  async function rollupFreshness(names: string[]): Promise<string | null> {
    const { rows } = await getPool().query<{ oldest: Date | null }>(
      `SELECT min(last_run_at) AS oldest FROM admin.rollup_state WHERE name = ANY($1)`,
      [names],
    );
    return rows[0]?.oldest ? rows[0].oldest.toISOString() : null;
  }

  // -------------------------------------------------------------------------
  app.get(
    '/overview',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['analytics'],
        summary: 'Headline numbers and the §2.6 real-time strip',
        response: {
          200: z.object({
            now: z.object({
              openCases: z.number(),
              unassignedTickets: z.number(),
              emergencyTickets: z.number(),
              breachingAppeals: z.number(),
              activeRestrictions: z.number(),
            }),
            last24h: z.object({
              messages: z.number(),
              reports: z.number(),
              enforcementActions: z.number(),
              newUsers: z.number(),
            }),
            dataAsOf: z.string().nullable(),
            basis: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'analytics.view');

      const pool = getPool();
      const [live, recent] = await Promise.all([
        // The "now" strip is read live rather than from rollups: it is cheap,
        // it is small, and a stale count of open emergencies is worse than none.
        pool.query<Record<string, string>>(
          `SELECT
             (SELECT count(*)::text FROM admin.cases
               WHERE status NOT IN ('resolved','dismissed'))              AS open_cases,
             (SELECT count(*)::text FROM admin.tickets
               WHERE assigned_to IS NULL AND status NOT IN ('resolved','closed'))
                                                                          AS unassigned_tickets,
             (SELECT count(*)::text FROM admin.tickets
               WHERE is_emergency AND status NOT IN ('resolved','closed')) AS emergency_tickets,
             (SELECT count(*)::text FROM admin.appeals
               WHERE status IN ('pending','under_review') AND sla_due_at <= NOW())
                                                                          AS breaching_appeals,
             (SELECT count(*)::text FROM admin.enforcement_actions
               WHERE reversed_at IS NULL AND type <> 'note'
                 AND (expires_at IS NULL OR expires_at > NOW()))          AS active_restrictions`,
        ),
        pool.query<Record<string, string>>(
          `SELECT
             (SELECT COALESCE(sum(total_messages), 0)::text
                FROM admin.rollup_messages_hourly
               WHERE bucket > NOW() - INTERVAL '24 hours')                AS messages,
             (SELECT count(*)::text FROM admin.reports
               WHERE submitted_at > NOW() - INTERVAL '24 hours')          AS reports,
             (SELECT count(*)::text FROM admin.enforcement_actions
               WHERE issued_at > NOW() - INTERVAL '24 hours' AND type <> 'note')
                                                                          AS actions,
             (SELECT count(*)::text FROM public.profiles
               WHERE created_at > NOW() - INTERVAL '24 hours')            AS new_users`,
        ),
      ]);

      const l = live.rows[0]!;
      const r = recent.rows[0]!;

      return {
        now: {
          openCases: Number(l.open_cases),
          unassignedTickets: Number(l.unassigned_tickets),
          emergencyTickets: Number(l.emergency_tickets),
          breachingAppeals: Number(l.breaching_appeals),
          activeRestrictions: Number(l.active_restrictions),
        },
        last24h: {
          messages: Number(r.messages),
          reports: Number(r.reports),
          enforcementActions: Number(r.actions),
          newUsers: Number(r.new_users),
        },
        dataAsOf: await rollupFreshness(['messages_hourly']),
        basis:
          'Message counts are a census from metadata. Content-type and in-app behaviour ' +
          'metrics are unavailable here because message bodies are end-to-end encrypted.',
      };
    },
  );

  // -------------------------------------------------------------------------
  app.get(
    '/messages',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['analytics'],
        summary: 'Message volume over time, split by surface',
        querystring: z.object({
          granularity: z.enum(GRANULARITIES).default('day'),
          from: z.coerce.date().optional(),
          to: z.coerce.date().optional(),
          compare: z.coerce.boolean().default(false),
        }),
        response: {
          200: z.object({
            series: z.array(
              z.object({
                bucket: z.date(),
                surface: z.string(),
                messages: z.number(),
                uniqueSenders: z.number(),
              }),
            ),
            deliveryFunnel: z.object({
              sent: z.number(),
              delivered: z.number(),
              read: z.number(),
              deliveredRate: z.number().nullable(),
              readRate: z.number().nullable(),
            }),
            previousPeriodTotal: z.number().nullable(),
            dataAsOf: z.string().nullable(),
            basis: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'analytics.view');

      const q = request.query;
      const to = q.to ?? new Date();
      const from = q.from ?? new Date(to.getTime() - 30 * 86_400_000);
      const trunc = TRUNC[q.granularity] ?? 'day';
      const pool = getPool();

      const [series, funnel, previous] = await Promise.all([
        pool.query(
          `SELECT date_trunc('${trunc}', bucket) AS bucket, surface,
                  sum(total_messages)::bigint AS messages,
                  max(unique_senders)::bigint AS unique_senders
             FROM admin.rollup_messages_hourly
            WHERE bucket >= $1 AND bucket <= $2
            GROUP BY 1, 2 ORDER BY 1 ASC, 2 ASC`,
          [from, to],
        ),
        pool.query<{ sent: string; delivered: string; read: string }>(
          `SELECT COALESCE(sum(sent_count), 0)::text AS sent,
                  COALESCE(sum(delivered_count), 0)::text AS delivered,
                  COALESCE(sum(read_count), 0)::text AS read
             FROM admin.rollup_messages_hourly
            WHERE bucket >= $1 AND bucket <= $2`,
          [from, to],
        ),
        q.compare
          ? pool.query<{ total: string }>(
              `SELECT COALESCE(sum(total_messages), 0)::text AS total
                 FROM admin.rollup_messages_hourly
                WHERE bucket >= $1 AND bucket < $2`,
              [new Date(from.getTime() - (to.getTime() - from.getTime())), from],
            )
          : Promise.resolve({ rows: [] as Array<{ total: string }> }),
      ]);

      const f = funnel.rows[0]!;
      const sent = Number(f.sent);
      const delivered = Number(f.delivered);
      const read = Number(f.read);
      // Status is a terminal value per message, so the funnel denominator is
      // every message, not just those still marked 'sent'.
      const total = sent + delivered + read;

      return {
        series: series.rows.map((row) => ({
          bucket: row.bucket,
          surface: row.surface,
          messages: Number(row.messages),
          uniqueSenders: Number(row.unique_senders),
        })),
        deliveryFunnel: {
          sent,
          delivered,
          read,
          deliveredRate: total === 0 ? null : Number(((delivered + read) / total).toFixed(3)),
          readRate: total === 0 ? null : Number((read / total).toFixed(3)),
        },
        previousPeriodTotal:
          previous.rows.length > 0 ? Number(previous.rows[0]!.total) : null,
        dataAsOf: await rollupFreshness(['messages_hourly']),
        basis:
          'Census. Counts come from message metadata, which is not encrypted. Content-type ' +
          'splits are impossible here — the bodies are, and no query recovers them.',
      };
    },
  );

  // -------------------------------------------------------------------------
  app.get(
    '/features',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['analytics'],
        summary: 'Feature adoption, ascending — dead features first (§2.3)',
        querystring: z.object({ days: z.coerce.number().int().min(1).max(365).default(30) }),
        response: {
          200: z.object({
            rows: z.array(
              z.object({
                featureKey: z.string(),
                label: z.string(),
                surface: z.string().nullable(),
                shippedAt: z.date().nullable(),
                uniqueUsers: z.number(),
                totalUses: z.number(),
                pctOfActive: z.number(),
                lastUsedAt: z.date().nullable(),
                isDead: z.boolean(),
              }),
            ),
            deadCount: z.number(),
            dataAsOf: z.string().nullable(),
            basis: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'analytics.view');

      const { rows } = await getPool().query(
        `SELECT * FROM admin.feature_adoption($1)`,
        [request.query.days],
      );

      const mapped = rows.map((r) => ({
        featureKey: r.feature_key,
        label: r.label,
        surface: r.surface,
        shippedAt: r.shipped_at,
        uniqueUsers: Number(r.unique_users),
        totalUses: Number(r.total_uses),
        pctOfActive: Number(r.pct_of_active),
        lastUsedAt: r.last_used_at,
        isDead: r.is_dead,
      }));

      return {
        rows: mapped,
        deadCount: mapped.filter((r) => r.isDead).length,
        dataAsOf: await rollupFreshness(['events_hourly']),
        basis:
          'Sample, not census. Only users who granted analytics consent emit these events, so ' +
          'absolute counts understate real usage. Relative ordering — which is what the dead-' +
          'feature question needs — is unaffected.',
      };
    },
  );

  // -------------------------------------------------------------------------
  app.get(
    '/growth',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['analytics'],
        summary: 'Active users, registrations and retention cohorts',
        querystring: z.object({ days: z.coerce.number().int().min(7).max(365).default(30) }),
        response: {
          200: z.object({
            daily: z.array(
              z.object({
                day: z.date(),
                activeUsers: z.number(),
                newUsers: z.number(),
                activatedUsers: z.number(),
              }),
            ),
            stickiness: z.number().nullable(),
            cohorts: z.array(
              z.object({
                cohortWeek: z.date(),
                cohortSize: z.number(),
                d1: z.number(),
                d7: z.number(),
                d30: z.number(),
              }),
            ),
            dataAsOf: z.string().nullable(),
            basis: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'analytics.view');

      const pool = getPool();
      const [daily, cohorts, ratio] = await Promise.all([
        pool.query(
          `SELECT day, sum(active_users)::bigint AS active_users,
                  sum(new_users)::bigint AS new_users,
                  sum(activated_users)::bigint AS activated_users
             FROM admin.rollup_active_users_daily
            WHERE day > CURRENT_DATE - $1::int
            GROUP BY day ORDER BY day ASC`,
          [request.query.days],
        ),
        pool.query(`SELECT * FROM admin.retention_cohorts(8)`),
        pool.query<{ dau: string; mau: string }>(
          `SELECT
             (SELECT COALESCE(sum(active_users), 0)::text FROM admin.rollup_active_users_daily
               WHERE day = CURRENT_DATE - 1)                       AS dau,
             (SELECT count(DISTINCT sender_id)::text FROM public.messages
               WHERE created_at > NOW() - INTERVAL '30 days')      AS mau`,
        ),
      ]);

      const dau = Number(ratio.rows[0]?.dau ?? 0);
      const mau = Number(ratio.rows[0]?.mau ?? 0);

      return {
        daily: daily.rows.map((r) => ({
          day: r.day,
          activeUsers: Number(r.active_users),
          newUsers: Number(r.new_users),
          activatedUsers: Number(r.activated_users),
        })),
        stickiness: mau === 0 ? null : Number((dau / mau).toFixed(3)),
        cohorts: cohorts.rows.map((r) => ({
          cohortWeek: r.cohort_week,
          cohortSize: Number(r.cohort_size),
          d1: Number(r.d1_retained),
          d7: Number(r.d7_retained),
          d30: Number(r.d30_retained),
        })),
        dataAsOf: await rollupFreshness(['active_users_daily']),
        basis:
          '"Active" means sent a message. Opening the app without sending is invisible without ' +
          'client telemetry, and telemetry is consented-only — so this is a conservative floor, ' +
          'not DAU as a growth team would define it.',
      };
    },
  );

  // -------------------------------------------------------------------------
  app.get(
    '/geography',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['analytics'],
        summary: 'Country table with abuse signals (§2.4)',
        response: {
          200: z.object({
            rows: z.array(
              z.object({
                country: z.string(),
                users: z.number(),
                messages: z.number(),
                reportsFiled: z.number(),
                reportsReceived: z.number(),
                enforcementActions: z.number(),
                banRate: z.number().nullable(),
              }),
            ),
            note: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'analytics.view');

      const { rows } = await getPool().query(
        `WITH user_country AS (
           SELECT DISTINCT ON (user_id) user_id, country
             FROM admin.consent_records
            WHERE country IS NOT NULL
            ORDER BY user_id, recorded_at DESC
         )
         SELECT uc.country,
                count(DISTINCT uc.user_id)::bigint AS users,
                (SELECT count(*) FROM public.messages m
                  WHERE m.sender_id IN (SELECT user_id FROM user_country u2
                                         WHERE u2.country = uc.country))::bigint AS messages,
                (SELECT count(*) FROM admin.reports r
                  WHERE r.reporter_country = uc.country)::bigint AS reports_filed,
                (SELECT count(*) FROM admin.reports r
                   JOIN user_country u3 ON u3.user_id = r.target_owner_id
                  WHERE u3.country = uc.country)::bigint AS reports_received,
                (SELECT count(*) FROM admin.enforcement_actions e
                   JOIN user_country u4 ON u4.user_id = e.user_id
                  WHERE u4.country = uc.country AND e.type <> 'note')::bigint AS actions
           FROM user_country uc
          GROUP BY uc.country
          ORDER BY users DESC`,
      );

      return {
        rows: rows.map((r) => {
          const users = Number(r.users);
          const actions = Number(r.actions);
          return {
            country: r.country,
            users,
            messages: Number(r.messages),
            reportsFiled: Number(r.reports_filed),
            reportsReceived: Number(r.reports_received),
            enforcementActions: actions,
            banRate: users === 0 ? null : Number((actions / users).toFixed(4)),
          };
        }),
        note:
          'Country is derived from the consent record written at registration, at country ' +
          'granularity only. §2.4 forbids storing raw IPs beyond a short security window and ' +
          'forbids displaying a precise location, so there is no finer breakdown to drill into.',
      };
    },
  );

  // -------------------------------------------------------------------------
  app.get(
    '/trust-safety',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['analytics'],
        summary: 'Trust & safety KPIs (§2.5)',
        querystring: z.object({ days: z.coerce.number().int().min(1).max(365).default(30) }),
        response: {
          200: z.object({
            kpis: z.record(z.unknown()),
            moderators: z.array(z.record(z.unknown())),
            interpretation: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'analytics.view');

      const pool = getPool();
      const [kpis, moderators] = await Promise.all([
        pool.query<{ k: Record<string, unknown> }>(
          `SELECT admin.trust_safety_kpis($1) AS k`,
          [request.query.days],
        ),
        // Per-moderator numbers are performance data about a named person.
        // Gated behind audit.view rather than analytics.view so an Analyst,
        // whose role is explicitly "no user records", cannot pull them.
        actor.permissions.has('audit.view')
          ? pool.query(`SELECT * FROM admin.moderator_performance($1)`, [request.query.days])
          : Promise.resolve({ rows: [] as Array<Record<string, unknown>> }),
      ]);

      return {
        kpis: kpis.rows[0]?.k ?? {},
        moderators: moderators.rows,
        interpretation:
          'Appeal overturn rate is the closest thing here to a direct measure of whether ' +
          'decisions are correct. Rising overturn against steady volume means the decisions are ' +
          'getting worse — no other number on this page tells you that. Read report-to-action ' +
          'rate alongside it: a very high rate can mean good reports, or a queue that actions ' +
          'everything put in front of it.',
      };
    },
  );

  // -------------------------------------------------------------------------
  app.get(
    '/export',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['analytics'],
        summary: 'CSV export of an aggregate table (§2.6)',
        querystring: z.object({
          metric: z.enum(['features', 'geography', 'growth', 'moderators']),
          days: z.coerce.number().int().min(1).max(365).default(30),
        }),
      },
    },
    async (request, reply) => {
      const actor = actorOf(request);
      requirePermission(actor, 'analytics.export');

      const pool = getPool();
      let rows: Array<Record<string, unknown>> = [];

      switch (request.query.metric) {
        case 'features':
          rows = (await pool.query(`SELECT * FROM admin.feature_adoption($1)`, [request.query.days])).rows;
          break;
        case 'growth':
          rows = (await pool.query(
            `SELECT day, country, active_users, new_users, activated_users
               FROM admin.rollup_active_users_daily
              WHERE day > CURRENT_DATE - $1::int ORDER BY day`,
            [request.query.days],
          )).rows;
          break;
        case 'moderators':
          requirePermission(actor, 'audit.view');
          rows = (await pool.query(`SELECT * FROM admin.moderator_performance($1)`, [request.query.days])).rows;
          break;
        default:
          rows = (await pool.query(
            `SELECT DISTINCT ON (user_id) country, count(*) OVER (PARTITION BY country) AS users
               FROM admin.consent_records WHERE country IS NOT NULL`,
          )).rows;
      }

      // §8: exports are audit-logged with the row count and the filter used,
      // so "who pulled what" is answerable after the fact.
      await withTransaction((client) =>
        writeAudit(client, actor, {
          action: 'analytics.exported',
          targetType: 'export',
          targetId: request.query.metric,
          targetLabel: `${request.query.metric} (${request.query.days}d)`,
          permission: 'analytics.export',
          after: { rowCount: rows.length, metric: request.query.metric, days: request.query.days },
        }),
      );

      reply
        .header('content-type', 'text/csv; charset=utf-8')
        .header(
          'content-disposition',
          `attachment; filename="neveroff-${request.query.metric}-${new Date().toISOString().slice(0, 10)}.csv"`,
        );
      return toCsv(rows);
    },
  );
}
