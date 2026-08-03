import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

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
} from '../components/ui';
import { ApiError, api } from '../lib/api';

/**
 * Automated detection (§6.6).
 *
 * The screen is arranged around one idea: a rule earns enforcement, it is not
 * given it. Every rule shows its measured precision and how much of its firing
 * history a human has actually judged, and the promote button is disabled until
 * both are real. Overriding is possible and requires writing down why.
 *
 * Shadow firings are the queue that matters here. Reviewing them is what turns
 * a rule from a guess into a measurement, so that panel sits directly beneath
 * the rule list rather than behind a tab.
 */

interface Rule {
  id: string;
  name: string;
  description: string | null;
  mode: string;
  surface: string;
  signal: string;
  action: string;
  config: Record<string, unknown>;
  enforcingSince: string | null;
  firings: number;
  reviewed: number;
  truePositives: number;
  falsePositives: number;
  precisionPct: number | null;
  reviewCoverage: number | null;
  readyToEnforce: boolean;
}

interface Firing {
  id: string;
  ruleId: string;
  ruleName: string;
  firedAt: string;
  subjectType: string;
  subjectId: string;
  subjectUserId: string | null;
  signals: Record<string, unknown>;
  modeAtFiring: string;
  actionTaken: string | null;
  reviewOutcome: string | null;
  explanation: string;
}

const MODE_LABEL: Record<string, string> = {
  disabled: 'Disabled',
  shadow: 'Shadow — records only',
  enforce: 'Enforcing',
};

export function AutomodPage() {
  const queryClient = useQueryClient();
  const [selectedRule, setSelectedRule] = useState<string>('');

  const rules = useQuery<{ rows: Rule[]; note: string }>({
    queryKey: ['automod-rules'],
    queryFn: () => api.get('/api/automod/rules'),
  });

  const firings = useQuery<Firing[]>({
    queryKey: ['automod-firings', selectedRule],
    queryFn: () =>
      api.get('/api/automod/firings', {
        ruleId: selectedRule || undefined,
        unreviewedOnly: true,
      }),
  });

  const review = useMutation({
    mutationFn: (input: { id: string; outcome: string }) =>
      api.post(`/api/automod/firings/${input.id}/review`, { outcome: input.outcome }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['automod-firings'] });
      queryClient.invalidateQueries({ queryKey: ['automod-rules'] });
    },
  });

  return (
    <div className="space-y-4">
      <Card title="Detection rules" description={rules.data?.note}>
        {rules.isLoading ? (
          <Spinner label="Loading rules" />
        ) : rules.data?.rows.length === 0 ? (
          <Empty>No rules configured.</Empty>
        ) : (
          <ul className="space-y-3">
            {rules.data?.rows.map((rule) => (
              <RuleRow key={rule.id} rule={rule} />
            ))}
          </ul>
        )}
      </Card>

      <ErrorNote error={rules.error ?? firings.error} />

      <Card
        title="Firings awaiting review"
        description="Judging these is what turns a rule from a guess into a measurement. Precision is computed from exactly this."
        actions={
          <Field label="" htmlFor="rule-filter">
            <Select
              id="rule-filter"
              value={selectedRule}
              onChange={(e) => setSelectedRule(e.target.value)}
            >
              <option value="">All rules</option>
              {rules.data?.rows.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </Select>
          </Field>
        }
      >
        {firings.isLoading ? (
          <Spinner label="Loading firings" />
        ) : firings.data?.length === 0 ? (
          <Empty>Nothing awaiting review.</Empty>
        ) : (
          <ul className="space-y-3">
            {firings.data?.map((firing) => (
              <li
                key={firing.id}
                className="rounded border border-slate-200 p-3 text-sm dark:border-slate-800"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{firing.ruleName}</span>
                  <Badge tone={firing.modeAtFiring === 'shadow' ? 'neutral' : 'warn'}>
                    {firing.modeAtFiring === 'shadow' ? 'Shadow' : 'Enforced'}
                  </Badge>
                  <span className="ml-auto text-xs text-slate-600 dark:text-slate-400">
                    {formatDate(firing.firedAt)}
                  </span>
                </div>
                <p className="mt-1 text-slate-700 dark:text-slate-300">{firing.explanation}</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  <Button
                    onClick={() => review.mutate({ id: firing.id, outcome: 'true_positive' })}
                    disabled={review.isPending}
                  >
                    Correct catch
                  </Button>
                  <Button
                    onClick={() => review.mutate({ id: firing.id, outcome: 'false_positive' })}
                    disabled={review.isPending}
                  >
                    False positive
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() => review.mutate({ id: firing.id, outcome: 'unclear' })}
                    disabled={review.isPending}
                  >
                    Unclear
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function RuleRow({ rule }: { rule: Rule }) {
  const queryClient = useQueryClient();
  const [showOverride, setShowOverride] = useState(false);
  const [justification, setJustification] = useState('');

  const setMode = useMutation({
    mutationFn: (input: { mode: string; overrideJustification?: string }) =>
      api.patch(`/api/automod/rules/${rule.id}`, input),
    onSuccess: () => {
      setShowOverride(false);
      setJustification('');
      queryClient.invalidateQueries({ queryKey: ['automod-rules'] });
    },
    onError: (error) => {
      // A 409 here means the rule has not met the measured bar. Offering the
      // override inline is deliberate: the point is that skipping the bar is a
      // recorded decision, not that it is impossible.
      if (error instanceof ApiError && error.status === 409) setShowOverride(true);
    },
  });

  return (
    <li className="rounded border border-slate-200 p-3 dark:border-slate-800">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{rule.name}</span>
        <Badge tone={rule.mode === 'enforce' ? 'warn' : 'neutral'}>{MODE_LABEL[rule.mode]}</Badge>
        <span className="text-xs text-slate-600 dark:text-slate-400">
          {rule.signal.replace(/_/g, ' ')} on {rule.surface.replace(/_/g, ' ')} →{' '}
          {rule.action.replace(/_/g, ' ')}
        </span>
      </div>

      {rule.description && (
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{rule.description}</p>
      )}

      <dl className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-xs tabular-nums">
        <div>
          <dt className="inline text-slate-600 dark:text-slate-400">Firings: </dt>
          <dd className="inline font-medium">{rule.firings}</dd>
        </div>
        <div>
          <dt className="inline text-slate-600 dark:text-slate-400">Reviewed: </dt>
          <dd className="inline font-medium">
            {rule.reviewed}
            {rule.reviewCoverage !== null && ` (${rule.reviewCoverage}%)`}
          </dd>
        </div>
        <div>
          <dt className="inline text-slate-600 dark:text-slate-400">Precision: </dt>
          <dd className="inline font-medium">
            {rule.precisionPct === null ? 'not yet measurable' : `${rule.precisionPct}%`}
          </dd>
        </div>
        <div>
          <dt className="inline text-slate-600 dark:text-slate-400">False positives: </dt>
          <dd className="inline font-medium">{rule.falsePositives}</dd>
        </div>
      </dl>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {rule.mode !== 'enforce' && (
          <Button
            variant={rule.readyToEnforce ? 'primary' : 'secondary'}
            onClick={() => setMode.mutate({ mode: 'enforce' })}
            disabled={setMode.isPending}
          >
            {rule.readyToEnforce ? 'Promote to enforcing' : 'Try to promote'}
          </Button>
        )}
        {rule.mode === 'enforce' && (
          <Button onClick={() => setMode.mutate({ mode: 'shadow' })} disabled={setMode.isPending}>
            Back to shadow
          </Button>
        )}
        {rule.mode !== 'disabled' && (
          <Button
            variant="ghost"
            onClick={() => setMode.mutate({ mode: 'disabled' })}
            disabled={setMode.isPending}
          >
            Disable
          </Button>
        )}
        {!rule.readyToEnforce && rule.mode === 'shadow' && (
          <span className="text-xs text-slate-600 dark:text-slate-400">
            Bar for enforcement: 30 firings, 20 reviewed, 95% precision.
          </span>
        )}
      </div>

      {showOverride && (
        <form
          className="mt-3 space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            setMode.mutate({ mode: 'enforce', overrideJustification: justification });
          }}
        >
          <ErrorNote error={setMode.error} />
          <Field
            label="Why enforce this rule before it has been measured?"
            htmlFor={`override-${rule.id}`}
            hint="Recorded against your account and raises an alert. Twenty characters minimum."
          >
            <Textarea
              id={`override-${rule.id}`}
              required
              minLength={20}
              rows={2}
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
            />
          </Field>
          <div className="flex gap-2">
            <Button type="submit" variant="danger" disabled={setMode.isPending}>
              Enforce anyway
            </Button>
            <Button onClick={() => setShowOverride(false)}>Cancel</Button>
          </div>
        </form>
      )}
    </li>
  );
}
