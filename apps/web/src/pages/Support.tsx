import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';

import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorNote,
  Select,
  Spinner,
  StatusBadge,
  Textarea,
  formatDate,
  formatRelative,
} from '../components/ui';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';

/**
 * The @support agent console (§5.2).
 *
 * Master-detail in a single view rather than two routes, unlike the rest of the
 * console. Agents work a queue: they read a thread, reply, and move to the next
 * one, and a full page navigation between every ticket is the difference
 * between clearing forty a shift and clearing twenty-five.
 *
 * The emergency banner is unconditional and sits above the tabs. §5.2 asks for
 * "a distinct high-visibility banner", and an urgent ticket hidden behind a tab
 * is an urgent ticket that gets found tomorrow.
 */

interface Ticket {
  id: string;
  ticketRef: string;
  subject: string;
  userId: string;
  username: string | null;
  categoryKey: string;
  status: string;
  priority: string;
  isEmergency: boolean;
  emergencyReason: string | null;
  assignedTo: string | null;
  assignedToLabel: string | null;
  openedAt: string;
  firstResponseDueAt: string;
  resolutionDueAt: string;
  slaBreached: boolean;
  awaitingAgent: boolean;
  messageCount: number;
}

interface TicketDetail {
  ticket: Record<string, unknown>;
  thread: Array<{
    id: string;
    authorType: string;
    authorLabel: string;
    body: string;
    isInternal: boolean;
    sentAt: string;
  }>;
  user: {
    id: string;
    username: string;
    status: string;
    trustScore: number | null;
    lifetimeActionCount: number;
    openCaseCount: number;
    priorTicketCount: number;
  } | null;
  emergencyGuidance: string | null;
}

const TABS = [
  { key: 'all_open', label: 'All open' },
  { key: 'unassigned', label: 'Unassigned' },
  { key: 'mine', label: 'Mine' },
  { key: 'pending_user', label: 'Pending user' },
  { key: 'escalated', label: 'Escalated' },
  { key: 'breaching_sla', label: 'Breaching SLA' },
  { key: 'closed', label: 'Closed' },
] as const;

export function SupportPage() {
  const { can } = useAuth();
  const [tab, setTab] = useState<string>('all_open');
  const [selected, setSelected] = useState<string | null>(null);

  const inbox = useQuery<{ rows: Ticket[]; total: number; emergencyCount: number }>({
    queryKey: ['tickets', tab],
    queryFn: () => api.get('/api/support/tickets', { tab, limit: 50 }),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });

  const emergencyCount = inbox.data?.emergencyCount ?? 0;

  return (
    <div className="space-y-4">
      {emergencyCount > 0 && (
        <div
          role="alert"
          className="rounded-md border-2 border-red-500 bg-red-50 px-4 py-3 text-sm font-medium text-red-900 dark:border-red-600 dark:bg-red-950 dark:text-red-100"
        >
          {emergencyCount} emergency ticket{emergencyCount === 1 ? '' : 's'} open. §5.2 requires a
          human on this path — it must never be handled by automation alone. These sort to the top
          of every tab.
        </div>
      )}

      <Card title="Support">
        <nav aria-label="Inbox tabs" className="flex flex-wrap gap-1">
          {TABS.map((entry) => (
            <button
              key={entry.key}
              type="button"
              onClick={() => {
                setTab(entry.key);
                setSelected(null);
              }}
              aria-current={tab === entry.key ? 'page' : undefined}
              className={
                'rounded-md px-3 py-1.5 text-sm font-medium ' +
                (tab === entry.key
                  ? 'bg-indigo-600 text-white'
                  : 'text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800')
              }
            >
              {entry.label}
            </button>
          ))}
        </nav>
      </Card>

      <ErrorNote error={inbox.error} />

      <div className="grid gap-4 lg:grid-cols-[minmax(320px,1fr)_2fr]">
        <Card title={`${inbox.data?.total ?? 0} ticket(s)`}>
          {inbox.isLoading ? (
            <Spinner label="Loading tickets" />
          ) : inbox.data?.rows.length === 0 ? (
            <Empty>Nothing here.</Empty>
          ) : (
            <ul className="space-y-2">
              {inbox.data?.rows.map((ticket) => (
                <li key={ticket.id}>
                  <button
                    type="button"
                    onClick={() => setSelected(ticket.id)}
                    aria-current={selected === ticket.id ? 'true' : undefined}
                    className={
                      'w-full rounded border p-3 text-left text-sm ' +
                      (selected === ticket.id
                        ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-950/40'
                        : ticket.isEmergency
                          ? 'border-red-400 dark:border-red-700'
                          : 'border-slate-200 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/50')
                    }
                  >
                    <span className="flex flex-wrap items-center gap-2">
                      {ticket.isEmergency && <Badge tone="warn">Emergency</Badge>}
                      {ticket.slaBreached && <Badge tone="warn">SLA</Badge>}
                      <span className="font-mono text-xs">{ticket.ticketRef}</span>
                      <span className="ml-auto text-xs text-slate-600 dark:text-slate-400">
                        {formatRelative(ticket.openedAt)}
                      </span>
                    </span>
                    <span className="mt-1 block font-medium">{ticket.subject}</span>
                    <span className="mt-0.5 block text-xs text-slate-600 dark:text-slate-400">
                      @{ticket.username ?? 'unknown'} · {ticket.categoryKey.replace(/_/g, ' ')} ·{' '}
                      {ticket.status.replace(/_/g, ' ')}
                      {ticket.assignedToLabel && ` · ${ticket.assignedToLabel}`}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>

        {selected ? (
          <TicketPanel ticketId={selected} canReply={can('support.reply')} />
        ) : (
          <Card>
            <Empty>Select a ticket.</Empty>
          </Card>
        )}
      </div>
    </div>
  );
}

function TicketPanel({ ticketId, canReply }: { ticketId: string; canReply: boolean }) {
  const queryClient = useQueryClient();
  const [body, setBody] = useState('');
  const [isInternal, setIsInternal] = useState(false);
  const [setStatus, setSetStatus] = useState('');

  const detail = useQuery<TicketDetail>({
    queryKey: ['ticket', ticketId],
    queryFn: () => api.get<TicketDetail>(`/api/support/tickets/${ticketId}`),
  });

  const macros = useQuery<Array<{ key: string; label: string; body: string; setsStatus: string | null }>>({
    queryKey: ['macros', ticketId],
    queryFn: () => api.get('/api/support/macros', { ticketId }),
  });

  const send = useMutation({
    mutationFn: () =>
      api.post(`/api/support/tickets/${ticketId}/messages`, {
        body,
        isInternal,
        setStatus: setStatus || undefined,
      }),
    onSuccess: () => {
      setBody('');
      setSetStatus('');
      queryClient.invalidateQueries({ queryKey: ['ticket', ticketId] });
      queryClient.invalidateQueries({ queryKey: ['tickets'] });
    },
  });

  if (detail.isLoading) return <Card><Spinner label="Loading ticket" /></Card>;
  if (detail.error) return <Card><ErrorNote error={detail.error} /></Card>;
  if (!detail.data) return <Card><Empty>Not found.</Empty></Card>;

  const { ticket, thread, user, emergencyGuidance } = detail.data;

  return (
    <div className="space-y-4">
      {emergencyGuidance && (
        <div
          role="alert"
          className="rounded-md border-2 border-red-500 bg-red-50 px-4 py-3 text-sm text-red-900 dark:border-red-600 dark:bg-red-950 dark:text-red-100"
        >
          <strong className="block">Emergency path</strong>
          {emergencyGuidance}
        </div>
      )}

      <Card
        title={String(ticket.subject)}
        description={`${String(ticket.ticket_ref)} · ${String(ticket.category_key).replace(/_/g, ' ')} · opened ${formatDate(String(ticket.opened_at))}`}
      >
        {user && (
          <div className="mb-4 flex flex-wrap items-center gap-3 rounded border border-slate-200 p-3 text-sm dark:border-slate-800">
            <Link
              to={`/users/${user.id}`}
              className="font-medium text-indigo-700 hover:underline dark:text-indigo-400"
            >
              @{user.username}
            </Link>
            <StatusBadge status={user.status} />
            <span className="text-slate-600 dark:text-slate-400">
              trust {user.trustScore ?? '—'} · {user.lifetimeActionCount} action(s) ·{' '}
              {user.openCaseCount} open case(s) · {user.priorTicketCount} prior ticket(s)
            </span>
          </div>
        )}

        <ul className="space-y-3">
          {thread.map((message) => (
            <li
              key={message.id}
              className={
                'rounded border p-3 text-sm ' +
                (message.isInternal
                  ? 'border-amber-300 bg-amber-50 dark:border-amber-900 dark:bg-amber-950/40'
                  : message.authorType === 'agent'
                    ? 'border-indigo-200 bg-indigo-50 dark:border-indigo-900 dark:bg-indigo-950/30'
                    : 'border-slate-200 dark:border-slate-800')
              }
            >
              <div className="flex items-center gap-2">
                <span className="font-medium">
                  {message.authorType === 'user' ? 'User' : message.authorLabel}
                </span>
                {message.isInternal && <Badge tone="warn">Internal — user cannot see this</Badge>}
                <span className="ml-auto text-xs text-slate-600 dark:text-slate-400">
                  {formatDate(message.sentAt)}
                </span>
              </div>
              <p className="mt-1 whitespace-pre-wrap">{message.body}</p>
            </li>
          ))}
        </ul>
      </Card>

      {canReply && String(ticket.status) !== 'closed' && (
        <Card title="Reply">
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              send.mutate();
            }}
          >
            {macros.data && macros.data.length > 0 && (
              <Select
                aria-label="Insert a canned response"
                value=""
                onChange={(e) => {
                  const macro = macros.data?.find((m) => m.key === e.target.value);
                  if (macro) {
                    setBody(macro.body);
                    if (macro.setsStatus) setSetStatus(macro.setsStatus);
                  }
                }}
              >
                <option value="">Insert a canned response…</option>
                {macros.data.map((m) => (
                  <option key={m.key} value={m.key}>
                    {m.label}
                  </option>
                ))}
              </Select>
            )}

            <Textarea
              aria-label="Reply body"
              required
              rows={5}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="Write a reply…"
            />

            <div className="flex flex-wrap items-center gap-3">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={isInternal}
                  onChange={(e) => setIsInternal(e.target.checked)}
                />
                Internal note (the user never sees this)
              </label>

              <Select
                aria-label="Set status"
                className="max-w-[220px]"
                value={setStatus}
                onChange={(e) => setSetStatus(e.target.value)}
              >
                <option value="">Leave status as-is</option>
                <option value="pending_user">Waiting on the user</option>
                <option value="pending_agent">Waiting on us</option>
                <option value="escalated">Escalate</option>
                <option value="resolved">Resolve</option>
              </Select>
            </div>

            <ErrorNote error={send.error} />

            <Button type="submit" variant="primary" disabled={send.isPending || !body.trim()}>
              {send.isPending ? 'Sending…' : isInternal ? 'Add note' : 'Send reply'}
            </Button>
          </form>
        </Card>
      )}
    </div>
  );
}
