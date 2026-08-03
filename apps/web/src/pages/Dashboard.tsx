import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';

import { Badge, Card, Empty, ErrorNote, Field, Select, Spinner } from '../components/ui';
import { StackedBars, StatTile, VizStyles, type StackedPoint } from '../components/viz';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';

/**
 * Analytics dashboard (§2).
 *
 * Every panel states its basis. Message counts are a census from metadata;
 * feature usage is a consented sample. Presenting the second as if it were the
 * first is not a rounding error, it is a wrong number with a confident label,
 * and it is the failure mode this whole page is arranged to avoid.
 */

interface Overview {
  now: {
    openCases: number;
    unassignedTickets: number;
    emergencyTickets: number;
    breachingAppeals: number;
    activeRestrictions: number;
  };
  last24h: { messages: number; reports: number; enforcementActions: number; newUsers: number };
  dataAsOf: string | null;
  basis: string;
}

interface MessageSeries {
  series: Array<{ bucket: string; surface: string; messages: number; uniqueSenders: number }>;
  deliveryFunnel: {
    sent: number; delivered: number; read: number;
    deliveredRate: number | null; readRate: number | null;
  };
  previousPeriodTotal: number | null;
  dataAsOf: string | null;
  basis: string;
}

interface Features {
  rows: Array<{
    featureKey: string; label: string; surface: string | null; shippedAt: string | null;
    uniqueUsers: number; totalUses: number; pctOfActive: number;
    lastUsedAt: string | null; isDead: boolean;
  }>;
  deadCount: number;
  dataAsOf: string | null;
  basis: string;
}

interface TrustSafety {
  kpis: Record<string, unknown>;
  moderators: Array<Record<string, unknown>>;
  interpretation: string;
}

const SURFACES = ['direct', 'group', 'channel'] as const;
const SURFACE_LABELS = ['1:1 chats', 'Group chats', 'Channel posts'];

function asOf(iso: string | null): string {
  if (!iso) return 'never refreshed';
  const d = new Date(iso);
  return `data as of ${d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}`;
}

export function DashboardPage() {
  const { can } = useAuth();
  const [granularity, setGranularity] = useState('day');

  const overview = useQuery<Overview>({
    queryKey: ['analytics-overview'],
    queryFn: () => api.get<Overview>('/api/analytics/overview'),
    refetchInterval: 30_000,
  });

  const messages = useQuery<MessageSeries>({
    queryKey: ['analytics-messages', granularity],
    queryFn: () => api.get<MessageSeries>('/api/analytics/messages', { granularity, compare: true }),
  });

  const features = useQuery<Features>({
    queryKey: ['analytics-features'],
    queryFn: () => api.get<Features>('/api/analytics/features'),
  });

  const ts = useQuery<TrustSafety>({
    queryKey: ['analytics-ts'],
    queryFn: () => api.get<TrustSafety>('/api/analytics/trust-safety'),
  });

  // Pivot the flat series into stacked points, holding surface order fixed.
  // Colour must follow the surface, never its rank — a quiet week for channels
  // must not repaint 1:1 chats.
  const buckets = new Map<string, number[]>();
  for (const row of messages.data?.series ?? []) {
    const key = new Date(row.bucket).toISOString().slice(0, 10);
    const entry = buckets.get(key) ?? [0, 0, 0];
    const index = SURFACES.indexOf(row.surface as (typeof SURFACES)[number]);
    if (index >= 0) entry[index] = row.messages;
    buckets.set(key, entry);
  }
  const chartData: StackedPoint[] = [...buckets.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([label, values]) => ({ label: label.slice(5), values }));

  const total = chartData.reduce((sum, p) => sum + p.values.reduce((a, b) => a + b, 0), 0);
  const previous = messages.data?.previousPeriodTotal ?? null;
  const change = previous && previous > 0 ? ((total - previous) / previous) * 100 : null;

  const kpi = (key: string): string => {
    const value = ts.data?.kpis?.[key];
    if (value === null || value === undefined) return '—';
    return typeof value === 'number' ? value.toLocaleString() : String(value);
  };

  return (
    <div className="space-y-4">
      <VizStyles />

      {/* §2.6 real-time strip. Read live, not from rollups: a stale count of
          open emergencies is worse than no count. */}
      <Card
        title="Now"
        description={overview.data ? asOf(overview.data.dataAsOf) : undefined}
      >
        {overview.isLoading ? (
          <Spinner label="Loading" />
        ) : (
          <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-5">
            <StatTile
              label="Emergency tickets"
              value={overview.data?.now.emergencyTickets ?? 0}
              status={(overview.data?.now.emergencyTickets ?? 0) > 0 ? 'critical' : undefined}
              hint={(overview.data?.now.emergencyTickets ?? 0) > 0 ? 'Needs a human now' : 'None open'}
            />
            <StatTile
              label="Appeals past SLA"
              value={overview.data?.now.breachingAppeals ?? 0}
              status={(overview.data?.now.breachingAppeals ?? 0) > 0 ? 'warning' : undefined}
              hint="Someone is waiting"
            />
            <StatTile label="Open cases" value={overview.data?.now.openCases ?? 0} />
            <StatTile label="Unassigned tickets" value={overview.data?.now.unassignedTickets ?? 0} />
            <StatTile
              label="Active restrictions"
              value={overview.data?.now.activeRestrictions ?? 0}
              hint="Users currently limited"
            />
          </div>
        )}
      </Card>

      <ErrorNote error={overview.error ?? messages.error ?? features.error} />

      {/* §2.1 */}
      <Card
        title="Message volume"
        description={messages.data?.basis}
        actions={
          <div className="flex items-center gap-3">
            {change !== null && (
              <span className="text-xs text-slate-600 dark:text-slate-400">
                {change >= 0 ? '+' : ''}
                {change.toFixed(1)}% vs previous period
              </span>
            )}
            <Field label="" htmlFor="granularity">
              <Select
                id="granularity"
                value={granularity}
                onChange={(e) => setGranularity(e.target.value)}
              >
                <option value="hour">Hourly</option>
                <option value="day">Daily</option>
                <option value="week">Weekly</option>
                <option value="month">Monthly</option>
              </Select>
            </Field>
          </div>
        }
      >
        {messages.isLoading ? (
          <Spinner label="Loading volume" />
        ) : chartData.length === 0 ? (
          <Empty>No message data in this window. Has the rollup worker run?</Empty>
        ) : (
          <>
            <StackedBars
              data={chartData}
              seriesLabels={[...SURFACE_LABELS]}
              title={`Messages by surface — ${asOf(messages.data?.dataAsOf ?? null)}`}
            />

            {/* Delivery funnel is its own figure, not a second y-axis on the
                chart above. Two measures of different scale never share a plot. */}
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <StatTile label="Sent" value={messages.data?.deliveryFunnel.sent.toLocaleString() ?? '0'} />
              <StatTile
                label="Delivered"
                value={messages.data?.deliveryFunnel.delivered.toLocaleString() ?? '0'}
                hint={
                  messages.data?.deliveryFunnel.deliveredRate !== null &&
                  messages.data?.deliveryFunnel.deliveredRate !== undefined
                    ? `${(messages.data.deliveryFunnel.deliveredRate * 100).toFixed(1)}% of all messages`
                    : undefined
                }
              />
              <StatTile
                label="Read"
                value={messages.data?.deliveryFunnel.read.toLocaleString() ?? '0'}
                hint={
                  messages.data?.deliveryFunnel.readRate !== null &&
                  messages.data?.deliveryFunnel.readRate !== undefined
                    ? `${(messages.data.deliveryFunnel.readRate * 100).toFixed(1)}% of all messages`
                    : undefined
                }
              />
            </div>
          </>
        )}
      </Card>

      {/* §2.5 */}
      <Card title="Trust & safety" description={ts.data?.interpretation}>
        {ts.isLoading ? (
          <Spinner label="Loading KPIs" />
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile
              label="Appeal overturn rate"
              value={kpi('appeal_overturn_rate')}
              hint="The clearest signal that decisions are wrong"
              status={
                Number(ts.data?.kpis?.appeal_overturn_rate ?? 0) > 0.3 ? 'warning' : undefined
              }
            />
            <StatTile label="Report → action rate" value={kpi('report_to_action_rate')} />
            <StatTile label="Reports per 1k messages" value={kpi('reports_per_1k_messages')} />
            <StatTile label="Appeal rate" value={kpi('appeal_rate')} />
            <StatTile label="Median time to first touch" value={`${kpi('median_time_to_first_touch_hours')}h`} />
            <StatTile label="p90 time to resolution" value={`${kpi('p90_time_to_resolution_hours')}h`} />
            <StatTile label="Repeat offenders" value={kpi('repeat_offenders')} />
            <StatTile
              label="Automated share of actions"
              value={kpi('automated_share')}
              hint="Automation never issues terminal actions"
            />
          </div>
        )}
      </Card>

      {/* §2.3 — sorted ascending so dead features surface first. */}
      <Card
        title="Feature adoption"
        description={features.data?.basis}
        actions={
          features.data && features.data.deadCount > 0 ? (
            <Badge tone="warn">
              {features.data.deadCount} feature{features.data.deadCount === 1 ? '' : 's'} unused
            </Badge>
          ) : undefined
        }
      >
        {features.isLoading ? (
          <Spinner label="Loading adoption" />
        ) : features.data?.rows.length === 0 ? (
          <Empty>No features catalogued.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm tabular-nums">
              <caption className="sr-only">
                Feature adoption, least used first
              </caption>
              <thead className="border-b border-slate-200 text-xs uppercase text-slate-600 dark:border-slate-800 dark:text-slate-400">
                <tr>
                  <th scope="col" className="py-2 pr-4">Feature</th>
                  <th scope="col" className="py-2 pr-4">Surface</th>
                  <th scope="col" className="py-2 pr-4">Users</th>
                  <th scope="col" className="py-2 pr-4">Uses</th>
                  <th scope="col" className="py-2 pr-4">% of active</th>
                  <th scope="col" className="py-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {features.data?.rows.map((row) => (
                  <tr
                    key={row.featureKey}
                    className="border-b border-slate-100 last:border-0 dark:border-slate-800"
                  >
                    <th scope="row" className="py-2 pr-4 font-normal">
                      {row.label}
                      <span className="block font-mono text-xs text-slate-500">
                        {row.featureKey}
                      </span>
                    </th>
                    <td className="py-2 pr-4">{row.surface ?? '—'}</td>
                    <td className="py-2 pr-4">{row.uniqueUsers.toLocaleString()}</td>
                    <td className="py-2 pr-4">{row.totalUses.toLocaleString()}</td>
                    <td className="py-2 pr-4">{row.pctOfActive}%</td>
                    <td className="py-2">
                      {row.isDead ? (
                        <Badge tone="warn">Unused since launch</Badge>
                      ) : (
                        <span className="text-slate-500 dark:text-slate-400">In use</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {can('analytics.export') && (
        <Card title="Export">
          <p className="mb-3 text-sm text-slate-600 dark:text-slate-400">
            Aggregates only — never raw event rows. Every export is audit-logged with the row
            count and the filter used.
          </p>
          <div className="flex flex-wrap gap-2">
            {['features', 'growth', 'geography'].map((metric) => (
              <a
                key={metric}
                href={`/api/analytics/export?metric=${metric}&days=30`}
                className="rounded-md border border-slate-300 px-3 py-2 text-sm hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800"
              >
                {metric} (CSV)
              </a>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
