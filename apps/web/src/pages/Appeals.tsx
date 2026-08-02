import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';

import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorNote,
  Field,
  Select,
  Spinner,
  Textarea,
  formatDate,
  formatRelative,
} from '../components/ui';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';

/**
 * Appeals queue (§4).
 *
 * The one rule that shapes this screen: an appeal may not be decided by the
 * admin who issued the original action. The API returns `reviewableByYou` per
 * row, and rows you cannot decide say so plainly rather than failing when you
 * try. The rule is enforced by a database trigger regardless.
 */

interface Appeal {
  id: string;
  caseRef: string;
  userId: string;
  username: string;
  actionType: string;
  reasonCode: string;
  body: string;
  status: string;
  submittedAt: string;
  slaDueAt: string;
  escalatedAt: string | null;
  issuedByAdminId: string | null;
  reviewableByYou: boolean;
}

export function AppealsPage() {
  const [status, setStatus] = useState('pending');
  const [breaching, setBreaching] = useState(false);

  const query = useQuery<{ rows: Appeal[]; total: number }>({
    queryKey: ['appeals', status, breaching],
    queryFn: () =>
      api.get('/api/enforcement/appeals', {
        status: status || undefined,
        breachingSla: breaching || undefined,
      }),
  });

  return (
    <div className="space-y-4">
      <Card title="Appeals">
        <div className="flex flex-wrap items-end gap-3">
          <Field label="Status" htmlFor="appeal-status">
            <Select id="appeal-status" value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">All</option>
              <option value="pending">Pending</option>
              <option value="under_review">Under review</option>
              <option value="upheld">Upheld</option>
              <option value="overturned">Overturned</option>
              <option value="partially_upheld">Partially upheld</option>
            </Select>
          </Field>
          <label className="flex items-center gap-2 pb-2 text-sm">
            <input
              type="checkbox"
              checked={breaching}
              onChange={(e) => setBreaching(e.target.checked)}
            />
            Breaching SLA only
          </label>
        </div>
      </Card>

      <ErrorNote error={query.error} />

      {query.isLoading ? (
        <Spinner label="Loading appeals" />
      ) : query.data?.rows.length === 0 ? (
        <Card>
          <Empty>Nothing in this queue.</Empty>
        </Card>
      ) : (
        <div className="space-y-3">
          {query.data?.rows.map((appeal) => (
            <AppealCard key={appeal.id} appeal={appeal} />
          ))}
        </div>
      )}
    </div>
  );
}

function AppealCard({ appeal }: { appeal: Appeal }) {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [outcome, setOutcome] = useState('upheld');
  const [decisionNote, setDecisionNote] = useState('');

  const decide = useMutation({
    mutationFn: () =>
      api.post(`/api/enforcement/appeals/${appeal.id}/decide`, { outcome, decisionNote }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['appeals'] }),
  });

  const overdue = new Date(appeal.slaDueAt).getTime() < Date.now();
  const open = appeal.status === 'pending' || appeal.status === 'under_review';

  return (
    <Card
      title={`${appeal.caseRef} — ${appeal.actionType.replace(/_/g, ' ')}`}
      description={`${appeal.reasonCode} · submitted ${formatDate(appeal.submittedAt)}`}
      actions={
        <div className="flex items-center gap-2">
          {overdue && open && <Badge tone="warn">SLA breached</Badge>}
          {appeal.escalatedAt && <Badge tone="warn">Escalated</Badge>}
          <Badge>{appeal.status.replace(/_/g, ' ')}</Badge>
        </div>
      }
    >
      <p className="mb-3 text-sm">
        <Link
          to={`/users/${appeal.userId}`}
          className="text-indigo-700 hover:underline dark:text-indigo-400"
        >
          @{appeal.username}
        </Link>
        <span className="ml-2 text-slate-600 dark:text-slate-400">
          due {formatRelative(appeal.slaDueAt)}
        </span>
      </p>

      <blockquote className="mb-4 border-l-2 border-slate-300 pl-3 text-sm italic dark:border-slate-700">
        {appeal.body}
      </blockquote>

      {!open ? null : !appeal.reviewableByYou ? (
        <p className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200">
          {appeal.issuedByAdminId
            ? 'You issued the action being appealed, so you cannot decide it. §4 requires an independent reviewer.'
            : 'Your role cannot decide appeals.'}
        </p>
      ) : (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            decide.mutate();
          }}
        >
          <Field label="Outcome" htmlFor={`outcome-${appeal.id}`}>
            <Select
              id={`outcome-${appeal.id}`}
              value={outcome}
              onChange={(e) => setOutcome(e.target.value)}
            >
              <option value="upheld">Uphold the original decision</option>
              <option value="overturned">Overturn — lift the action</option>
              <option value="partially_upheld">Partially uphold</option>
            </Select>
          </Field>

          <Field
            label="Decision note"
            htmlFor={`note-${appeal.id}`}
            hint="Recorded on the case. The user is told the outcome, not this text."
          >
            <Textarea
              id={`note-${appeal.id}`}
              required
              minLength={10}
              rows={3}
              value={decisionNote}
              onChange={(e) => setDecisionNote(e.target.value)}
            />
          </Field>

          <ErrorNote error={decide.error} />

          <Button
            type="submit"
            variant="primary"
            disabled={decide.isPending || (outcome !== 'upheld' && !can('users.unban'))}
          >
            {decide.isPending ? 'Recording…' : 'Record decision'}
          </Button>
          {outcome !== 'upheld' && !can('users.unban') && (
            <p className="text-xs text-slate-600 dark:text-slate-400">
              Overturning lifts the action, which needs the reverse-enforcement permission.
            </p>
          )}
        </form>
      )}
    </Card>
  );
}
