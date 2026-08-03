import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorNote,
  Field,
  Select,
  Spinner,
  formatRelative,
} from '../components/ui';
import { api } from '../lib/api';

/**
 * The moderation queue (§6.4).
 *
 * Keyboard-first on purpose. §6.4: "moderators work at volume and mouse-only
 * UIs are a bottleneck." j/k move, Enter opens, and the number keys jump
 * between views. The visible hint row is not decoration — a shortcut nobody
 * knows about is a shortcut nobody uses.
 */

interface QueueCase {
  id: string;
  caseRef: string;
  targetType: string;
  targetId: string;
  targetLabel: string | null;
  targetOwnerId: string | null;
  primaryCategory: string | null;
  primaryReasonCode: string | null;
  status: string;
  priorityScore: number;
  reportCount: number;
  distinctReporterCount: number;
  firstReportedAt: string;
  lastReportedAt: string;
  slaDueAt: string | null;
  overdue: boolean;
  coordinatedSuspected: boolean;
  autoFlagged: boolean;
  lockedByYou: boolean;
  lockedByOther: boolean;
  hasReadableEvidence: boolean;
}

const VIEWS = [
  { key: 'all', label: 'All open' },
  { key: 'unassigned', label: 'Unassigned' },
  { key: 'mine', label: 'Mine' },
  { key: 'escalated', label: 'Escalated' },
  { key: 'aged', label: 'Breaching SLA' },
  { key: 'auto_flagged', label: 'Auto-flagged' },
  { key: 'coordinated', label: 'Suspected brigading' },
] as const;

const CATEGORIES = [
  'spam_scams', 'harassment', 'hate_speech', 'violence', 'adult_sexual',
  'self_harm', 'illegal_goods', 'impersonation', 'misinformation',
  'intellectual_property', 'other',
];

const PAGE_SIZE = 25;

export function QueuePage() {
  const navigate = useNavigate();
  const [view, setView] = useState<string>('all');
  const [category, setCategory] = useState('');
  const [offset, setOffset] = useState(0);
  const [cursor, setCursor] = useState(0);
  const rowRefs = useRef<Array<HTMLTableRowElement | null>>([]);

  const query = useQuery<{ rows: QueueCase[]; total: number; scopeApplied: boolean }>({
    queryKey: ['queue', view, category, offset],
    queryFn: () =>
      api.get('/api/moderation/queue', {
        view,
        category: category || undefined,
        limit: PAGE_SIZE,
        offset,
      }),
    placeholderData: keepPreviousData,
    // The queue moves under you as colleagues claim and close cases.
    refetchInterval: 30_000,
  });

  const rows = query.data?.rows ?? [];

  const move = useCallback(
    (delta: number) => {
      setCursor((current) => {
        const next = Math.max(0, Math.min(rows.length - 1, current + delta));
        rowRefs.current[next]?.scrollIntoView({ block: 'nearest' });
        return next;
      });
    },
    [rows.length],
  );

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      // Never hijack typing.
      const target = event.target as HTMLElement | null;
      if (target && ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)) return;
      if (event.metaKey || event.ctrlKey || event.altKey) return;

      if (event.key === 'j' || event.key === 'ArrowDown') {
        event.preventDefault();
        move(1);
      } else if (event.key === 'k' || event.key === 'ArrowUp') {
        event.preventDefault();
        move(-1);
      } else if (event.key === 'Enter') {
        const selected = rows[cursor];
        if (selected) {
          event.preventDefault();
          navigate(`/queue/${selected.id}`);
        }
      } else if (/^[1-7]$/.test(event.key)) {
        const target = VIEWS[Number(event.key) - 1];
        if (target) {
          setView(target.key);
          setOffset(0);
          setCursor(0);
        }
      }
    };

    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [rows, cursor, move, navigate]);

  const total = query.data?.total ?? 0;

  return (
    <div className="space-y-4">
      <Card
        title="Moderation queue"
        description={
          query.data?.scopeApplied
            ? 'Filtered to your assigned scope. Cases outside it are not counted here.'
            : 'Ordered by priority: category severity × reporters × velocity × reporter accuracy × reported-user trust × audience size.'
        }
      >
        <div className="flex flex-wrap items-end gap-3">
          <nav aria-label="Queue views" className="flex flex-wrap gap-1">
            {VIEWS.map((entry, index) => (
              <button
                key={entry.key}
                type="button"
                onClick={() => {
                  setView(entry.key);
                  setOffset(0);
                  setCursor(0);
                }}
                aria-current={view === entry.key ? 'page' : undefined}
                className={
                  'rounded-md px-3 py-1.5 text-sm font-medium ' +
                  (view === entry.key
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800')
                }
              >
                <span className="mr-1 opacity-60">{index + 1}</span>
                {entry.label}
              </button>
            ))}
          </nav>

          <Field label="Category" htmlFor="queue-category">
            <Select
              id="queue-category"
              value={category}
              onChange={(e) => {
                setCategory(e.target.value);
                setOffset(0);
              }}
            >
              <option value="">Any category</option>
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {c.replace(/_/g, ' ')}
                </option>
              ))}
            </Select>
          </Field>
        </div>

        <p className="mt-3 text-xs text-slate-600 dark:text-slate-400">
          <kbd className="rounded border px-1">j</kbd> /{' '}
          <kbd className="rounded border px-1">k</kbd> move ·{' '}
          <kbd className="rounded border px-1">Enter</kbd> open ·{' '}
          <kbd className="rounded border px-1">1</kbd>–
          <kbd className="rounded border px-1">7</kbd> switch view
        </p>
      </Card>

      <ErrorNote error={query.error} />

      <Card
        title={`${total.toLocaleString()} open case${total === 1 ? '' : 's'}`}
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
          <Spinner label="Loading queue" />
        ) : rows.length === 0 ? (
          <Empty>Nothing in this view. That is a good thing.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Moderation queue ordered by priority</caption>
              <thead className="border-b border-slate-200 text-xs uppercase text-slate-600 dark:border-slate-800 dark:text-slate-400">
                <tr>
                  <th scope="col" className="py-2 pr-4">Priority</th>
                  <th scope="col" className="py-2 pr-4">Case</th>
                  <th scope="col" className="py-2 pr-4">Target</th>
                  <th scope="col" className="py-2 pr-4">Category</th>
                  <th scope="col" className="py-2 pr-4">Reporters</th>
                  <th scope="col" className="py-2 pr-4">Age</th>
                  <th scope="col" className="py-2">Flags</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row, index) => (
                  <tr
                    key={row.id}
                    ref={(el) => {
                      rowRefs.current[index] = el;
                    }}
                    tabIndex={0}
                    onClick={() => navigate(`/queue/${row.id}`)}
                    onFocus={() => setCursor(index)}
                    className={
                      'cursor-pointer border-b border-slate-100 last:border-0 dark:border-slate-800 ' +
                      (index === cursor
                        ? 'bg-indigo-50 dark:bg-indigo-950/40'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-800/50')
                    }
                  >
                    <td className="py-2 pr-4 font-mono">{row.priorityScore.toFixed(1)}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{row.caseRef}</td>
                    <td className="py-2 pr-4">
                      {row.targetLabel ?? `${row.targetType} ${row.targetId.slice(0, 8)}`}
                      <span className="block text-xs text-slate-600 dark:text-slate-400">
                        {row.targetType.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="py-2 pr-4">
                      {row.primaryCategory?.replace(/_/g, ' ') ?? '—'}
                    </td>
                    <td className="py-2 pr-4">
                      {row.distinctReporterCount}
                      {row.reportCount !== row.distinctReporterCount && (
                        <span className="text-slate-600 dark:text-slate-400">
                          {' '}
                          ({row.reportCount} reports)
                        </span>
                      )}
                    </td>
                    <td className="py-2 pr-4">{formatRelative(row.firstReportedAt)}</td>
                    <td className="py-2">
                      <span className="flex flex-wrap gap-1">
                        {row.overdue && <Badge tone="warn">SLA</Badge>}
                        {row.coordinatedSuspected && <Badge tone="warn">Brigading?</Badge>}
                        {row.autoFlagged && <Badge>Auto</Badge>}
                        {row.lockedByOther && <Badge tone="warn">Locked</Badge>}
                        {row.lockedByYou && <Badge>Yours</Badge>}
                        {!row.hasReadableEvidence && row.targetType === 'message' && (
                          <Badge>Encrypted</Badge>
                        )}
                      </span>
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
