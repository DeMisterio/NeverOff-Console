import { LADDER, SELECTABLE_REASONS } from '@neveroff-console/shared';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';

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
  Textarea,
  formatDate,
  formatRelative,
} from '../components/ui';
import { ApiError, api } from '../lib/api';
import { useAuth } from '../lib/auth';

/**
 * Case detail and the decision panel (§6.4), with the §6.8 wellbeing
 * protections.
 *
 * Evidence is not rendered when the page loads. Two reasons, and both matter:
 * for a private message it is decrypted conversation someone volunteered, and
 * reading it is an audited event — so it should be a deliberate act, not a side
 * effect of opening a case. And for graphic categories, a moderator who has to
 * click to reveal keeps some control over when they look at it.
 */

interface CaseDetail {
  case: Record<string, unknown>;
  priority: { total: number; components: Array<Record<string, unknown>> };
  reports: Array<{
    id: string;
    reasonCode: string;
    reporterNote: string | null;
    outcomePreference: string;
    submittedAt: string;
    reporterId: string | null;
    reporterAccuracy: number | null;
  }>;
  evidence: Array<{
    id: string;
    source: string;
    capturedAt: string;
    hasContent: boolean;
    hasContext: boolean;
    requiresBlur: boolean;
    mediaSha256: string | null;
    mediaMimeType: string | null;
  }>;
  relatedCases: Array<{
    id: string;
    caseRef: string;
    relation: string;
    status: string;
    targetLabel: string | null;
  }>;
  ownerHistory: Array<{
    id: string;
    type: string;
    reasonCode: string;
    issuedAt: string;
    active: boolean;
  }>;
  evidenceNotice: string;
}

export function CaseDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { can } = useAuth();

  const query = useQuery<CaseDetail>({
    queryKey: ['case', id],
    queryFn: () => api.get<CaseDetail>(`/api/moderation/cases/${id}`),
    enabled: Boolean(id),
  });

  const claim = useMutation({
    mutationFn: () => api.post<{ claimed: boolean; heldBy: string | null }>(
      `/api/moderation/cases/${id}/claim`,
    ),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['case', id] }),
  });

  // Claiming on open is what makes locking actually prevent duplicate work —
  // a lock nobody takes protects nothing.
  useEffect(() => {
    if (id && can('reports.triage')) claim.mutate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  if (query.isLoading) return <Spinner label="Loading case" />;
  if (query.error) return <ErrorNote error={query.error} />;
  if (!query.data) return <Empty>Not found.</Empty>;

  const detail = query.data;
  const kase = detail.case as Record<string, string | number | boolean | null>;

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-lg font-semibold">
              {String(kase.case_ref)}
              <span className="ml-3 font-normal text-slate-600 dark:text-slate-400">
                {String(kase.target_label ?? kase.target_type)}
              </span>
            </h1>
            <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-slate-600 dark:text-slate-400">
              <Badge>{String(kase.status)}</Badge>
              <span>{String(kase.primary_category ?? 'uncategorised').replace(/_/g, ' ')}</span>
              <span>·</span>
              <span>{String(kase.distinct_reporter_count)} reporters</span>
              <span>·</span>
              <span>first reported {formatRelative(String(kase.first_reported_at))}</span>
              {kase.coordinated_suspected ? <Badge tone="warn">Suspected brigading</Badge> : null}
            </p>
            {kase.target_owner_id ? (
              <p className="mt-1 text-sm">
                <Link
                  to={`/users/${String(kase.target_owner_id)}`}
                  className="text-indigo-700 hover:underline dark:text-indigo-400"
                >
                  Open the reported account →
                </Link>
              </p>
            ) : null}
          </div>
          <div className="flex items-center gap-2">
            {claim.data && !claim.data.claimed && (
              <Badge tone="warn">Held by {claim.data.heldBy}</Badge>
            )}
            <Button onClick={() => navigate('/queue')}>← Queue</Button>
          </div>
        </div>

        {kase.escalation_note ? (
          <div
            role="alert"
            className="mt-3 rounded-md border border-amber-400 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200"
          >
            {String(kase.escalation_note)}
          </div>
        ) : null}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card
          title={`Priority ${detail.priority.total}`}
          description="Why this case is where it is in the queue."
        >
          <ul className="space-y-2 text-sm">
            {detail.priority.components.map((component) => (
              <li
                key={String(component.key)}
                className="flex items-baseline justify-between gap-4 border-b border-slate-100 pb-2 last:border-0 dark:border-slate-800"
              >
                <span>
                  <span className="font-medium">{String(component.label)}</span>
                  <span className="block text-xs text-slate-600 dark:text-slate-400">
                    {String(component.detail)}
                  </span>
                </span>
                <span
                  className={
                    'font-mono ' +
                    (Number(component.factor) < 1 ? 'text-amber-700 dark:text-amber-400' : '')
                  }
                >
                  ×{String(component.factor)}
                </span>
              </li>
            ))}
          </ul>
          {kase.coordination_signals &&
          Array.isArray(kase.coordination_signals) &&
          (kase.coordination_signals as unknown[]).length > 0 ? (
            <div className="mt-3 rounded border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200">
              <strong>Coordination signals.</strong> Priority is deliberately reduced — manufactured
              volume should not float to the top of the queue.
              <ul className="mt-1 list-inside list-disc">
                {(kase.coordination_signals as Array<{ signal: string; detail: string }>).map(
                  (s) => (
                    <li key={s.signal}>{s.detail}</li>
                  ),
                )}
              </ul>
            </div>
          ) : null}
        </Card>

        <Card title="Reported account history">
          {detail.ownerHistory.length === 0 ? (
            <Empty>No prior enforcement.</Empty>
          ) : (
            <ul className="space-y-2 text-sm">
              {detail.ownerHistory.map((h) => (
                <li key={h.id} className="flex items-center justify-between gap-2">
                  <span>
                    {LADDER[h.type as keyof typeof LADDER]?.label ?? h.type}
                    {h.active && (
                      <span className="ml-2">
                        <Badge tone="warn">In force</Badge>
                      </span>
                    )}
                  </span>
                  <span className="text-slate-600 dark:text-slate-400">
                    {formatDate(h.issuedAt)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title={`${detail.reports.length} report(s)`}>
        <ul className="space-y-2 text-sm">
          {detail.reports.map((report) => (
            <li
              key={report.id}
              className="rounded border border-slate-200 p-3 dark:border-slate-800"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs">{report.reasonCode}</span>
                <Badge>{report.outcomePreference.replace(/_/g, ' ')}</Badge>
                {report.reporterAccuracy !== null && (
                  <Badge tone={report.reporterAccuracy < 0.3 ? 'warn' : 'neutral'}>
                    reporter accuracy {(report.reporterAccuracy * 100).toFixed(0)}%
                  </Badge>
                )}
                <span className="ml-auto text-xs text-slate-600 dark:text-slate-400">
                  {formatDate(report.submittedAt)}
                </span>
              </div>
              {report.reporterNote && <p className="mt-1">{report.reporterNote}</p>}
            </li>
          ))}
        </ul>
      </Card>

      <EvidencePanel caseId={id!} evidence={detail.evidence} notice={detail.evidenceNotice} />

      {detail.relatedCases.length > 0 && (
        <Card title="Related cases" description="Same reported account, or the same media hash.">
          <ul className="space-y-1 text-sm">
            {detail.relatedCases.map((related) => (
              <li key={related.id}>
                <Link
                  to={`/queue/${related.id}`}
                  className="text-indigo-700 hover:underline dark:text-indigo-400"
                >
                  {related.caseRef}
                </Link>
                <span className="ml-2 text-slate-600 dark:text-slate-400">
                  {related.relation.replace(/_/g, ' ')} · {related.status}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <DecisionPanel
        caseId={id!}
        hasOwner={Boolean(kase.target_owner_id)}
        onDone={() => navigate('/queue')}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------

function EvidencePanel({
  caseId,
  evidence,
  notice,
}: {
  caseId: string;
  evidence: CaseDetail['evidence'];
  notice: string;
}) {
  const [revealed, setRevealed] = useState<Record<string, string | null>>({});
  const [greyscale, setGreyscale] = useState(true);

  const reveal = useMutation({
    mutationFn: (evidenceId: string) =>
      api.post<{ contentText: string | null; notice: string }>(
        `/api/moderation/cases/${caseId}/evidence/${evidenceId}`,
      ),
  });

  return (
    <Card
      title="Evidence"
      description={notice}
      actions={
        <label className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            checked={greyscale}
            onChange={(e) => setGreyscale(e.target.checked)}
          />
          Greyscale
        </label>
      }
    >
      {evidence.length === 0 ? (
        <Empty>No evidence was captured.</Empty>
      ) : (
        <ul className="space-y-3">
          {evidence.map((item) => (
            <li
              key={item.id}
              className={
                'rounded border border-slate-200 p-3 text-sm dark:border-slate-800 ' +
                (greyscale ? 'grayscale' : '')
              }
            >
              <div className="flex flex-wrap items-center gap-2">
                <Badge>
                  {item.source === 'reporter_submitted' ? 'Submitted by reporter' : 'Captured'}
                </Badge>
                {item.requiresBlur && <Badge tone="warn">Graphic — hidden by default</Badge>}
                {item.mediaSha256 && (
                  <span className="font-mono text-xs text-slate-600 dark:text-slate-400">
                    {item.mediaSha256.slice(0, 16)}…
                  </span>
                )}
                <span className="ml-auto text-xs text-slate-600 dark:text-slate-400">
                  {formatDate(item.capturedAt)}
                </span>
              </div>

              {!item.hasContent ? (
                <p className="mt-2 text-slate-600 dark:text-slate-400">
                  Metadata only — no readable content.
                </p>
              ) : revealed[item.id] !== undefined ? (
                <pre className="mt-2 whitespace-pre-wrap rounded bg-slate-100 p-2 text-sm dark:bg-slate-800">
                  {revealed[item.id] ?? '(empty)'}
                </pre>
              ) : (
                <div className="mt-2">
                  <Button
                    onClick={async () => {
                      const result = await reveal.mutateAsync(item.id);
                      setRevealed((current) => ({ ...current, [item.id]: result.contentText }));
                    }}
                    disabled={reveal.isPending}
                  >
                    {item.requiresBlur ? 'Reveal (graphic)' : 'Reveal content'}
                  </Button>
                  <span className="ml-2 text-xs text-slate-600 dark:text-slate-400">
                    Recorded against your account.
                  </span>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      <ErrorNote error={reveal.error} />
    </Card>
  );
}

function DecisionPanel({
  caseId,
  hasOwner,
  onDone,
}: {
  caseId: string;
  hasOwner: boolean;
  onDone: () => void;
}) {
  const { can, me } = useAuth();
  const [outcome, setOutcome] = useState('no_violation');
  const [note, setNote] = useState('');
  const [reporterMessage, setReporterMessage] = useState('');
  const [withEnforcement, setWithEnforcement] = useState(false);
  const [actionType, setActionType] = useState('warning');
  const [reasonCode, setReasonCode] = useState(SELECTABLE_REASONS[0]?.code ?? '');
  const [days, setDays] = useState(7);
  const [confirmationPhrase, setConfirmationPhrase] = useState('');
  const [expectedPhrase, setExpectedPhrase] = useState<string | null>(null);

  const spec = LADDER[actionType as keyof typeof LADDER];
  const available = Object.values(LADDER)
    .filter((s) => can(s.requiredPermission))
    .sort((a, b) => a.severity - b.severity);

  const decide = useMutation({
    mutationFn: () =>
      api.post(`/api/moderation/cases/${caseId}/decide`, {
        outcome: withEnforcement ? 'action_taken' : outcome,
        note,
        reporterMessage: reporterMessage || undefined,
        enforcement: withEnforcement
          ? {
              type: actionType,
              reasonCode,
              note,
              expiresAt:
                spec?.duration === 'none'
                  ? null
                  : new Date(Date.now() + days * 86_400_000).toISOString(),
              contentRemovalScope: 'none',
              breakGlass: confirmationPhrase ? { confirmationPhrase } : undefined,
            }
          : undefined,
      }),
    onSuccess: onDone,
    onError: (error) => {
      if (error instanceof ApiError && error.needsBreakGlass) {
        setExpectedPhrase((error.details?.expectedPhrase as string) ?? null);
      }
    },
  });

  const escalate = useMutation({
    mutationFn: () => api.post(`/api/moderation/cases/${caseId}/escalate`, { note }),
    onSuccess: onDone,
  });

  if (!can('reports.resolve')) {
    return (
      <Card title="Decision">
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Your role can triage and escalate but not close cases.
        </p>
        {can('reports.escalate') && (
          <form
            className="mt-3 space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              escalate.mutate();
            }}
          >
            <Field label="Escalation note" htmlFor="esc-note">
              <Textarea
                id="esc-note"
                required
                minLength={10}
                rows={3}
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </Field>
            <ErrorNote error={escalate.error} />
            <Button type="submit" variant="primary" disabled={escalate.isPending}>
              Escalate
            </Button>
          </form>
        )}
      </Card>
    );
  }

  const banCap = me?.maxBanDays ?? null;
  const capExceeded =
    withEnforcement && actionType === 'ban_temporary' && banCap !== null && banCap > 0 && days > banCap;

  return (
    <Card title="Decision" description="Closing a case notifies every reporter of the outcome.">
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          decide.mutate();
        }}
      >
        <div className="grid gap-4 lg:grid-cols-2">
          <Field label="Outcome" htmlFor="outcome">
            <Select
              id="outcome"
              value={withEnforcement ? 'action_taken' : outcome}
              disabled={withEnforcement}
              onChange={(e) => setOutcome(e.target.value)}
            >
              <option value="no_violation">No violation found</option>
              <option value="insufficient_evidence">Insufficient evidence</option>
              <option value="duplicate">Duplicate</option>
              <option value="out_of_scope">Out of scope</option>
            </Select>
          </Field>

          <div className="flex items-end">
            <label className="flex items-center gap-2 pb-2 text-sm">
              <input
                type="checkbox"
                checked={withEnforcement}
                disabled={!hasOwner}
                onChange={(e) => setWithEnforcement(e.target.checked)}
              />
              Apply enforcement to the reported account
              {!hasOwner && (
                <span className="text-xs text-slate-600 dark:text-slate-400">
                  (no resolvable account)
                </span>
              )}
            </label>
          </div>
        </div>

        {withEnforcement && (
          <div className="grid gap-4 rounded border border-slate-200 p-3 lg:grid-cols-3 dark:border-slate-800">
            <Field label="Action" htmlFor="case-action" hint={spec?.description}>
              <Select
                id="case-action"
                value={actionType}
                onChange={(e) => setActionType(e.target.value)}
              >
                {available.map((s) => (
                  <option key={s.type} value={s.type}>
                    {s.label}
                  </option>
                ))}
              </Select>
            </Field>

            <Field label="Reason" htmlFor="case-reason">
              <Select
                id="case-reason"
                value={reasonCode}
                onChange={(e) => setReasonCode(e.target.value)}
              >
                {SELECTABLE_REASONS.map((r) => (
                  <option key={r.code} value={r.code}>
                    {r.code}
                  </option>
                ))}
              </Select>
            </Field>

            {spec?.duration !== 'none' && (
              <Field
                label="Days"
                htmlFor="case-days"
                hint={banCap === null ? 'No cap on your role.' : `Up to ${banCap} days.`}
                error={capExceeded ? `Exceeds your ${banCap}-day limit.` : undefined}
              >
                <Input
                  id="case-days"
                  type="number"
                  min={1}
                  max={3650}
                  value={days}
                  onChange={(e) => setDays(Number(e.target.value))}
                />
              </Field>
            )}
          </div>
        )}

        <Field
          label="Decision note"
          htmlFor="decision-note"
          hint="Read on appeal. Not shown to the reporter or the reported user."
        >
          <Textarea
            id="decision-note"
            required
            minLength={10}
            rows={3}
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </Field>

        <Field
          label="Message to reporters (optional)"
          htmlFor="reporter-message"
          hint="Generic terms only. Leave blank to send the standard wording."
        >
          <Input
            id="reporter-message"
            maxLength={500}
            value={reporterMessage}
            onChange={(e) => setReporterMessage(e.target.value)}
          />
        </Field>

        {expectedPhrase && (
          <Field
            label="Type this phrase to confirm"
            htmlFor="case-phrase"
            hint={`Exactly: ${expectedPhrase}`}
          >
            <Input
              id="case-phrase"
              value={confirmationPhrase}
              onChange={(e) => setConfirmationPhrase(e.target.value)}
            />
          </Field>
        )}

        <ErrorNote error={decide.error} />
        <ErrorNote error={escalate.error} />

        <div className="flex flex-wrap gap-2">
          <Button
            type="submit"
            variant={withEnforcement ? 'danger' : 'primary'}
            disabled={decide.isPending || capExceeded}
          >
            {decide.isPending ? 'Recording…' : 'Close case'}
          </Button>
          {can('reports.escalate') && (
            <Button
              type="button"
              onClick={() => escalate.mutate()}
              disabled={escalate.isPending || note.trim().length < 10}
            >
              Escalate instead
            </Button>
          )}
        </div>
      </form>
    </Card>
  );
}
