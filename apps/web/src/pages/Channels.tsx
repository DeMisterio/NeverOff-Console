import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';

import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorNote,
  Field,
  Input,
  Select,
  Spinner,
  formatRelative,
} from '../components/ui';
import { api } from '../lib/api';

/**
 * Channel directory (§6.5).
 *
 * Sorted by risk — reach × open trouble — rather than by report count. A
 * channel with 100,000 subscribers and one open case matters more than one
 * with forty subscribers and three, and sorting by raw report volume buries
 * exactly the cases that matter.
 */

interface Channel {
  id: string;
  name: string;
  username: string;
  isPublic: boolean;
  subscriberCount: number;
  postCount: number;
  lastPostAt: string | null;
  createdAt: string;
  ownerId: string;
  ownerUsername: string;
  caseCount: number;
  openCaseCount: number;
  actionCount: number;
  riskScore: number;
  restrictionState: Record<string, unknown>;
}

const PAGE_SIZE = 25;

/** Compact summary of the live restriction state, text-first. */
export function RestrictionBadges({ state }: { state: Record<string, unknown> }) {
  const flags: Array<[string, string]> = [
    ['taken_down', 'Taken down'],
    ['frozen', 'Frozen'],
    ['joins_blocked', 'Joins blocked'],
    ['delisted', 'Delisted'],
    ['age_gated', 'Age-gated'],
    ['media_disabled', 'No media'],
    ['links_disabled', 'No links'],
    ['forwarding_disabled', 'No forwarding'],
  ];

  const active = flags.filter(([key]) => state[key] === true);
  const geo = (state.geo_blocked_in as string[] | undefined) ?? [];

  if (active.length === 0 && geo.length === 0) {
    return <span className="text-slate-500 dark:text-slate-400">—</span>;
  }

  return (
    <span className="flex flex-wrap gap-1">
      {active.map(([key, label]) => (
        <Badge key={key} tone="warn">
          {label}
        </Badge>
      ))}
      {geo.length > 0 && <Badge tone="warn">Blocked in {geo.join(', ')}</Badge>}
    </span>
  );
}

export function ChannelsPage() {
  const [search, setSearch] = useState('');
  const [submitted, setSubmitted] = useState('');
  const [sort, setSort] = useState('risk_score');
  const [restricted, setRestricted] = useState('');
  const [offset, setOffset] = useState(0);

  const query = useQuery<{ rows: Channel[]; total: number; scopeApplied: boolean }>({
    queryKey: ['channels', submitted, sort, restricted, offset],
    queryFn: () =>
      api.get('/api/channels', {
        search: submitted || undefined,
        sort,
        restricted: restricted === '' ? undefined : restricted === 'yes',
        limit: PAGE_SIZE,
        offset,
      }),
    placeholderData: keepPreviousData,
  });

  const total = query.data?.total ?? 0;

  return (
    <div className="space-y-4">
      <Card
        title="Channels"
        description={
          query.data?.scopeApplied
            ? 'Filtered to the channels assigned to you.'
            : 'Risk is reach × open cases. One bad channel reaches thousands, so size is part of the score.'
        }
      >
        <form
          className="grid gap-3 sm:grid-cols-3"
          onSubmit={(e) => {
            e.preventDefault();
            setOffset(0);
            setSubmitted(search.trim());
          }}
        >
          <Field label="Search" htmlFor="ch-search" hint="Exact @username, or name prefix.">
            <Input
              id="ch-search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="@handle or name"
            />
          </Field>

          <Field label="Restricted" htmlFor="ch-restricted">
            <Select
              id="ch-restricted"
              value={restricted}
              onChange={(e) => {
                setRestricted(e.target.value);
                setOffset(0);
              }}
            >
              <option value="">Any</option>
              <option value="yes">Under restriction</option>
              <option value="no">Unrestricted</option>
            </Select>
          </Field>

          <Field label="Sort by" htmlFor="ch-sort">
            <Select
              id="ch-sort"
              value={sort}
              onChange={(e) => {
                setSort(e.target.value);
                setOffset(0);
              }}
            >
              <option value="risk_score">Risk</option>
              <option value="subscriber_count">Subscribers</option>
              <option value="open_case_count">Open cases</option>
              <option value="created_at">Newest</option>
            </Select>
          </Field>

          <div className="sm:col-span-3">
            <Button type="submit" variant="primary">
              Apply
            </Button>
          </div>
        </form>
      </Card>

      <ErrorNote error={query.error} />

      <Card
        title={`${total.toLocaleString()} channel${total === 1 ? '' : 's'}`}
        actions={
          <div className="flex items-center gap-2 text-sm">
            <Button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0}>
              Previous
            </Button>
            <Button
              onClick={() => setOffset(offset + PAGE_SIZE)}
              disabled={offset + PAGE_SIZE >= total}
            >
              Next
            </Button>
          </div>
        }
      >
        {query.isLoading ? (
          <Spinner label="Loading channels" />
        ) : query.data?.rows.length === 0 ? (
          <Empty>No channels match these filters.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Channel directory ordered by risk</caption>
              <thead className="border-b border-slate-200 text-xs uppercase text-slate-600 dark:border-slate-800 dark:text-slate-400">
                <tr>
                  <th scope="col" className="py-2 pr-4">Risk</th>
                  <th scope="col" className="py-2 pr-4">Channel</th>
                  <th scope="col" className="py-2 pr-4">Owner</th>
                  <th scope="col" className="py-2 pr-4">Subscribers</th>
                  <th scope="col" className="py-2 pr-4">Cases</th>
                  <th scope="col" className="py-2 pr-4">Last post</th>
                  <th scope="col" className="py-2">Restrictions</th>
                </tr>
              </thead>
              <tbody>
                {query.data?.rows.map((channel) => (
                  <tr
                    key={channel.id}
                    className="border-b border-slate-100 last:border-0 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/50"
                  >
                    <td className="py-2 pr-4 font-mono">{channel.riskScore.toFixed(1)}</td>
                    <td className="py-2 pr-4">
                      <Link
                        to={`/channels/${channel.id}`}
                        className="font-medium text-indigo-700 hover:underline dark:text-indigo-400"
                      >
                        {channel.name}
                      </Link>
                      <span className="block text-xs text-slate-600 dark:text-slate-400">
                        @{channel.username} · {channel.isPublic ? 'public' : 'unlisted'}
                      </span>
                    </td>
                    <td className="py-2 pr-4">
                      <Link
                        to={`/users/${channel.ownerId}`}
                        className="text-indigo-700 hover:underline dark:text-indigo-400"
                      >
                        @{channel.ownerUsername}
                      </Link>
                    </td>
                    <td className="py-2 pr-4">{channel.subscriberCount.toLocaleString()}</td>
                    <td className="py-2 pr-4">
                      {channel.openCaseCount > 0 ? (
                        <Badge tone="warn">{channel.openCaseCount} open</Badge>
                      ) : (
                        <span className="text-slate-500 dark:text-slate-400">
                          {channel.caseCount}
                        </span>
                      )}
                    </td>
                    <td className="py-2 pr-4">{formatRelative(channel.lastPostAt)}</td>
                    <td className="py-2">
                      <RestrictionBadges state={channel.restrictionState} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
