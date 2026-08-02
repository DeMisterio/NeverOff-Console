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
  StatusBadge,
  formatDate,
  formatRelative,
} from '../components/ui';
import { api, type DirectoryUser } from '../lib/api';
import { useAuth } from '../lib/auth';

/**
 * User directory (§3.1).
 *
 * Every filter is applied server-side — including the scope filter — so the
 * count and the pages are consistent. Filtering in the browser would show a
 * scoped moderator a total that includes users they cannot open, which leaks
 * the size of the population outside their remit.
 */

interface DirectoryResponse {
  rows: DirectoryUser[];
  total: number;
  limit: number;
  offset: number;
  scopeApplied: boolean;
}

const STATUSES = [
  'active', 'warned', 'restricted', 'muted', 'shadow_restricted',
  'banned_temporary', 'banned_permanent', 'deleted',
];

const PAGE_SIZE = 25;

export function UsersPage() {
  const { can } = useAuth();
  const [search, setSearch] = useState('');
  const [submittedSearch, setSubmittedSearch] = useState('');
  const [status, setStatus] = useState('');
  const [country, setCountry] = useState('');
  const [sort, setSort] = useState('registered_at');
  const [offset, setOffset] = useState(0);

  const query = useQuery<DirectoryResponse>({
    queryKey: ['users', submittedSearch, status, country, sort, offset],
    queryFn: () =>
      api.get<DirectoryResponse>('/api/users', {
        search: submittedSearch || undefined,
        status: status || undefined,
        country: country || undefined,
        sort,
        limit: PAGE_SIZE,
        offset,
      }),
    placeholderData: keepPreviousData,
  });

  const total = query.data?.total ?? 0;
  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="space-y-4">
      <Card
        title="Users"
        description={
          query.data?.scopeApplied
            ? 'Filtered to your assigned scope. Users outside it are not counted here.'
            : undefined
        }
      >
        <form
          className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"
          onSubmit={(e) => {
            e.preventDefault();
            setOffset(0);
            setSubmittedSearch(search.trim());
          }}
        >
          <Field
            label="Search"
            htmlFor="search"
            hint={
              can('users.search')
                ? 'Exact match on username or user ID; prefix match on display name.'
                : 'Your role cannot search users.'
            }
          >
            <Input
              id="search"
              value={search}
              disabled={!can('users.search')}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="username or user ID"
            />
          </Field>

          <Field label="Status" htmlFor="status">
            <Select
              id="status"
              value={status}
              onChange={(e) => {
                setStatus(e.target.value);
                setOffset(0);
              }}
            >
              <option value="">Any status</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s.replace(/_/g, ' ')}
                </option>
              ))}
            </Select>
          </Field>

          <Field label="Country" htmlFor="country" hint="Two-letter code, e.g. DE">
            <Input
              id="country"
              maxLength={2}
              value={country}
              onChange={(e) => {
                setCountry(e.target.value.toUpperCase());
                setOffset(0);
              }}
            />
          </Field>

          <Field label="Sort by" htmlFor="sort">
            <Select
              id="sort"
              value={sort}
              onChange={(e) => {
                setSort(e.target.value);
                setOffset(0);
              }}
            >
              <option value="registered_at">Registered</option>
              <option value="last_message_at">Last active</option>
              <option value="message_count">Messages sent</option>
              <option value="lifetime_action_count">Enforcement actions</option>
              <option value="username">Username</option>
            </Select>
          </Field>

          <div className="sm:col-span-2 lg:col-span-4">
            <Button type="submit" variant="primary">
              Apply
            </Button>
          </div>
        </form>
      </Card>

      <ErrorNote error={query.error} />

      <Card
        title={`${total.toLocaleString()} user${total === 1 ? '' : 's'}`}
        actions={
          <div className="flex items-center gap-2 text-sm">
            <Button
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              disabled={offset === 0 || query.isFetching}
            >
              Previous
            </Button>
            <span aria-live="polite" className="text-slate-600 dark:text-slate-400">
              Page {page} of {pages}
            </span>
            <Button
              onClick={() => setOffset(offset + PAGE_SIZE)}
              disabled={offset + PAGE_SIZE >= total || query.isFetching}
            >
              Next
            </Button>
          </div>
        }
      >
        {query.isLoading ? (
          <Spinner label="Loading users" />
        ) : query.data && query.data.rows.length === 0 ? (
          <Empty>No users match these filters.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">
                User directory, sorted by {sort.replace(/_/g, ' ')}
              </caption>
              <thead className="border-b border-slate-200 text-xs uppercase text-slate-600 dark:border-slate-800 dark:text-slate-400">
                <tr>
                  <th scope="col" className="py-2 pr-4">User</th>
                  <th scope="col" className="py-2 pr-4">Status</th>
                  <th scope="col" className="py-2 pr-4">Country</th>
                  <th scope="col" className="py-2 pr-4">Trust</th>
                  <th scope="col" className="py-2 pr-4">Messages</th>
                  <th scope="col" className="py-2 pr-4">Actions</th>
                  <th scope="col" className="py-2 pr-4">Last active</th>
                  <th scope="col" className="py-2">Registered</th>
                </tr>
              </thead>
              <tbody>
                {query.data?.rows.map((user) => (
                  <tr
                    key={user.id}
                    className="border-b border-slate-100 last:border-0 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/50"
                  >
                    <td className="py-2 pr-4">
                      <Link
                        to={`/users/${user.id}`}
                        className="font-medium text-indigo-700 hover:underline dark:text-indigo-400"
                      >
                        @{user.username}
                      </Link>
                      {user.displayName && (
                        <span className="ml-2 text-slate-600 dark:text-slate-400">
                          {user.displayName}
                        </span>
                      )}
                      {user.underLegalHold && (
                        <span className="ml-2">
                          <Badge tone="warn">Legal hold</Badge>
                        </span>
                      )}
                    </td>
                    <td className="py-2 pr-4">
                      <StatusBadge status={user.status} />
                    </td>
                    <td className="py-2 pr-4">{user.country ?? '—'}</td>
                    <td className="py-2 pr-4">{user.trustScore ?? '—'}</td>
                    <td className="py-2 pr-4">{user.messageCount.toLocaleString()}</td>
                    <td className="py-2 pr-4">{user.lifetimeActionCount}</td>
                    <td className="py-2 pr-4">{formatRelative(user.lastMessageAt)}</td>
                    <td className="py-2">{formatDate(user.registeredAt)}</td>
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
