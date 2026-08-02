import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useState } from 'react';

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
  formatDate,
} from '../components/ui';
import { api } from '../lib/api';

/**
 * Audit log (§7).
 *
 * Read-only by construction — there is no mutation endpoint to call, because
 * the table rejects UPDATE and DELETE by trigger. The integrity check below
 * verifies the hash chain and is the thing to run when someone asks whether the
 * log can be trusted.
 */

interface AuditRow {
  id: string;
  occurredAt: string;
  actorLabel: string;
  actorRole: string | null;
  origin: string;
  action: string;
  permissionKey: string | null;
  targetType: string;
  targetId: string | null;
  targetLabel: string | null;
  reasonCode: string | null;
  note: string | null;
  isPiiAccess: boolean;
  ip: string | null;
}

const PAGE_SIZE = 50;

export function AuditPage() {
  const [search, setSearch] = useState('');
  const [submitted, setSubmitted] = useState('');
  const [origin, setOrigin] = useState('');
  const [piiOnly, setPiiOnly] = useState(false);
  const [offset, setOffset] = useState(0);

  const query = useQuery<{ rows: AuditRow[]; total: number; scopeLimited: boolean }>({
    queryKey: ['audit', submitted, origin, piiOnly, offset],
    queryFn: () =>
      api.get('/api/audit', {
        search: submitted || undefined,
        origin: origin || undefined,
        piiOnly: piiOnly || undefined,
        limit: PAGE_SIZE,
        offset,
      }),
    placeholderData: keepPreviousData,
  });

  const integrity = useQuery<{ intact: boolean; breaks: unknown[]; note: string }>({
    queryKey: ['audit-integrity'],
    queryFn: () => api.get('/api/audit/integrity'),
    retry: false,
  });

  return (
    <div className="space-y-4">
      {integrity.data && (
        <div
          className={
            'rounded-md border px-3 py-2 text-sm ' +
            (integrity.data.intact
              ? 'border-green-300 bg-green-50 text-green-900 dark:border-green-900 dark:bg-green-950 dark:text-green-200'
              : 'border-red-400 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950 dark:text-red-200')
          }
          role={integrity.data.intact ? undefined : 'alert'}
        >
          {integrity.data.intact
            ? 'Hash chain intact — no entry has been altered or removed.'
            : `Hash chain BROKEN at ${integrity.data.breaks.length} point(s). Treat the log as compromised and investigate immediately.`}
        </div>
      )}

      <Card
        title="Audit log"
        description={
          query.data?.scopeLimited
            ? 'Limited to entries about targets inside your scope, plus your own actions. Only the Super Admin sees the full log.'
            : undefined
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
          <Field label="Search" htmlFor="audit-search">
            <Input
              id="audit-search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="actor, action, target, reason"
            />
          </Field>
          <Field label="Origin" htmlFor="audit-origin">
            <Select id="audit-origin" value={origin} onChange={(e) => setOrigin(e.target.value)}>
              <option value="">Any</option>
              <option value="manual">Manual</option>
              <option value="automated">Automated</option>
              <option value="system">System</option>
            </Select>
          </Field>
          <label className="flex items-center gap-2 pb-2 text-sm sm:pt-6">
            <input
              type="checkbox"
              checked={piiOnly}
              onChange={(e) => setPiiOnly(e.target.checked)}
            />
            Personal-data access only
          </label>
          <div className="sm:col-span-3">
            <Button type="submit" variant="primary">
              Apply
            </Button>
          </div>
        </form>
      </Card>

      <ErrorNote error={query.error} />

      <Card
        title={`${(query.data?.total ?? 0).toLocaleString()} entries`}
        actions={
          <div className="flex items-center gap-2 text-sm">
            <Button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0}>
              Previous
            </Button>
            <Button
              onClick={() => setOffset(offset + PAGE_SIZE)}
              disabled={offset + PAGE_SIZE >= (query.data?.total ?? 0)}
            >
              Next
            </Button>
          </div>
        }
      >
        {query.isLoading ? (
          <Spinner label="Loading audit entries" />
        ) : query.data?.rows.length === 0 ? (
          <Empty>No entries match.</Empty>
        ) : (
          <ul className="space-y-2 text-sm">
            {query.data?.rows.map((row) => (
              <li
                key={row.id}
                className="rounded border border-slate-200 p-3 dark:border-slate-800"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs">{row.action}</span>
                  {row.isPiiAccess && <Badge tone="warn">Personal data</Badge>}
                  {row.origin !== 'manual' && <Badge>{row.origin}</Badge>}
                  <span className="ml-auto text-xs text-slate-600 dark:text-slate-400">
                    {formatDate(row.occurredAt)}
                  </span>
                </div>
                <p className="mt-1">
                  <span className="font-medium">{row.actorLabel}</span>
                  {row.targetLabel && (
                    <>
                      {' → '}
                      <span>{row.targetLabel}</span>
                    </>
                  )}
                </p>
                {row.note && (
                  <p className="mt-1 text-slate-600 dark:text-slate-400">{row.note}</p>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
