import { LADDER, SELECTABLE_REASONS, RESTRICTABLE_FEATURES } from '@neveroff-console/shared';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';

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
  Textarea,
  formatDate,
} from '../components/ui';
import { ApiError, api, type UserProfileResponse } from '../lib/api';
import { useAuth } from '../lib/auth';

/**
 * User profile and the §3.3 enforcement panel.
 *
 * The action form only offers rungs the signed-in admin actually holds the
 * permission for, and the duration picker is capped at their role's limit.
 * Both are re-checked server-side; doing it here as well means a Tier 3
 * moderator is not repeatedly offered a permanent ban button that always fails.
 */

const ACTION_TYPES = Object.values(LADDER)
  .slice()
  .sort((a, b) => a.severity - b.severity);

export function UserDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { can, maxBanDays } = useAuthWithCap();
  const queryClient = useQueryClient();

  const query = useQuery<UserProfileResponse>({
    queryKey: ['user', id],
    queryFn: () => api.get<UserProfileResponse>(`/api/users/${id}`),
    enabled: Boolean(id),
  });

  if (query.isLoading) return <Spinner label="Loading profile" />;
  if (query.error) return <ErrorNote error={query.error} />;
  if (!query.data) return <Empty>Not found.</Empty>;

  const { user, trustScore, enforcementHistory, appeals, ownedChannels, piiAvailable } = query.data;
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['user', id] });

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-lg font-semibold">
              @{user.username}
              {user.displayName && (
                <span className="ml-2 font-normal text-slate-600 dark:text-slate-400">
                  {user.displayName}
                </span>
              )}
            </h1>
            <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-slate-600 dark:text-slate-400">
              <StatusBadge status={user.status} />
              <span>{user.country ?? 'Country unknown'}</span>
              <span>·</span>
              <span>Registered {formatDate(user.registeredAt)}</span>
              <span>·</span>
              <span>{user.messageCount.toLocaleString()} messages</span>
              {user.underLegalHold && <Badge tone="warn">Under legal hold</Badge>}
            </p>
            {user.nextExpiryAt && (
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                Next restriction expires {formatDate(user.nextExpiryAt)}
              </p>
            )}
          </div>
          <Link to="/users" className="text-sm text-indigo-700 hover:underline dark:text-indigo-400">
            ← Back to directory
          </Link>
        </div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card
          title={`Trust score: ${trustScore.total}/100`}
          description="Every contributing factor is listed. There is no hidden term."
        >
          <ul className="space-y-2 text-sm">
            <li className="flex items-baseline justify-between gap-4 border-b border-slate-100 pb-2 dark:border-slate-800">
              <span className="text-slate-600 dark:text-slate-400">Baseline</span>
              <span className="font-mono">{trustScore.baseline}</span>
            </li>
            {trustScore.components.map((component) => (
              <li
                key={component.key}
                className="flex items-baseline justify-between gap-4 border-b border-slate-100 pb-2 last:border-0 dark:border-slate-800"
              >
                <span>
                  <span className="font-medium">{component.label}</span>
                  <span className="block text-xs text-slate-600 dark:text-slate-400">
                    {component.detail}
                  </span>
                </span>
                <span
                  className={
                    'font-mono ' +
                    (component.points < 0
                      ? 'text-red-700 dark:text-red-400'
                      : 'text-green-700 dark:text-green-400')
                  }
                >
                  {component.points > 0 ? '+' : ''}
                  {component.points}
                </span>
              </li>
            ))}
          </ul>
        </Card>

        <PersonalDataCard userId={user.id} available={piiAvailable} canView={can('users.view_pii')} />
      </div>

      <EnforcementPanel
        userId={user.id}
        username={user.username}
        maxBanDays={maxBanDays}
        onDone={refresh}
      />

      <Card title="Safety history" description="Every action ever taken against this account.">
        {enforcementHistory.length === 0 ? (
          <Empty>No enforcement history.</Empty>
        ) : (
          <ul className="space-y-3">
            {enforcementHistory.map((record) => (
              <li
                key={record.id}
                className="rounded border border-slate-200 p-3 text-sm dark:border-slate-800"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">
                    {LADDER[record.type as keyof typeof LADDER]?.label ?? record.type}
                  </span>
                  {record.active ? (
                    <Badge tone="warn">In force</Badge>
                  ) : (
                    <Badge>{record.reversedAt ? 'Reversed' : 'Expired'}</Badge>
                  )}
                  {record.origin === 'automated' && <Badge>Automated</Badge>}
                  <span className="ml-auto font-mono text-xs text-slate-600 dark:text-slate-400">
                    {record.caseRef}
                  </span>
                </div>
                <p className="mt-1 text-slate-600 dark:text-slate-400">
                  {record.reasonCode} · issued by {record.issuedByLabel} on{' '}
                  {formatDate(record.issuedAt)}
                  {record.expiresAt && ` · expires ${formatDate(record.expiresAt)}`}
                </p>
                <p className="mt-1">{record.note}</p>
                {record.reversalReason && (
                  <p className="mt-1 text-slate-600 dark:text-slate-400">
                    Reversed: {record.reversalReason}
                  </p>
                )}
                {record.active && can('users.unban') && (
                  <ReverseButton actionId={record.id} onDone={refresh} />
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Appeals">
          {appeals.length === 0 ? (
            <Empty>No appeals.</Empty>
          ) : (
            <ul className="space-y-2 text-sm">
              {appeals.map((appeal) => (
                <li key={appeal.id} className="flex items-center justify-between gap-2">
                  <span>{appeal.status.replace(/_/g, ' ')}</span>
                  <span className="text-slate-600 dark:text-slate-400">
                    submitted {formatDate(appeal.submittedAt)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Channels owned" description="Repeat violations escalate to the owner (§6.5).">
          {ownedChannels.length === 0 ? (
            <Empty>Owns no channels.</Empty>
          ) : (
            <ul className="space-y-2 text-sm">
              {ownedChannels.map((channel) => (
                <li key={channel.id} className="flex items-center justify-between gap-2">
                  <span>
                    {channel.name}{' '}
                    <span className="text-slate-600 dark:text-slate-400">@{channel.username}</span>
                  </span>
                  <span className="text-slate-600 dark:text-slate-400">
                    {channel.subscriberCount.toLocaleString()} subscribers
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------

function useAuthWithCap() {
  const auth = useAuth();
  return { ...auth, maxBanDays: auth.me?.maxBanDays ?? 0 };
}

function PersonalDataCard({
  userId,
  available,
  canView,
}: {
  userId: string;
  available: boolean;
  canView: boolean;
}) {
  const [reason, setReason] = useState('');
  const [data, setData] = useState<Record<string, unknown> | null>(null);

  const reveal = useMutation({
    mutationFn: () =>
      api.post<Record<string, unknown>>(`/api/users/${userId}/personal-data`, { reason }),
    onSuccess: setData,
  });

  if (!canView || !available) {
    return (
      <Card title="Personal data">
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Your role does not include standing access to personal data. Request a case-scoped reveal
          from a Moderation Lead if a case genuinely requires it.
        </p>
      </Card>
    );
  }

  return (
    <Card
      title="Personal data"
      description="This access is recorded in the audit log against your account."
    >
      {data ? (
        <dl className="space-y-2 text-sm">
          {Object.entries(data)
            .filter(([key]) => key !== 'notice' && key !== 'consent')
            .map(([key, value]) => (
              <div key={key} className="flex justify-between gap-4">
                <dt className="text-slate-600 dark:text-slate-400">{key}</dt>
                <dd className="font-mono">{String(value ?? '—')}</dd>
              </div>
            ))}
          <p className="pt-2 text-xs text-slate-600 dark:text-slate-400">
            {String(data.notice ?? '')}
          </p>
        </dl>
      ) : (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            reveal.mutate();
          }}
        >
          <Field
            label="Why do you need this?"
            htmlFor="pii-reason"
            hint="Recorded verbatim. Name the case."
          >
            <Input
              id="pii-reason"
              required
              minLength={5}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </Field>
          <ErrorNote error={reveal.error} />
          <Button type="submit" disabled={reveal.isPending}>
            Reveal and record
          </Button>
        </form>
      )}
    </Card>
  );
}

function ReverseButton({ actionId, onDone }: { actionId: string; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');

  const reverse = useMutation({
    mutationFn: () => api.post(`/api/enforcement/actions/${actionId}/reverse`, { reason }),
    onSuccess: () => {
      setOpen(false);
      onDone();
    },
  });

  if (!open) {
    return (
      <Button className="mt-2" onClick={() => setOpen(true)}>
        Lift this action
      </Button>
    );
  }

  return (
    <form
      className="mt-2 space-y-2"
      onSubmit={(e) => {
        e.preventDefault();
        reverse.mutate();
      }}
    >
      <Field label="Why are you lifting this?" htmlFor={`reverse-${actionId}`}>
        <Textarea
          id={`reverse-${actionId}`}
          required
          minLength={10}
          rows={2}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
      </Field>
      <ErrorNote error={reverse.error} />
      <div className="flex gap-2">
        <Button type="submit" variant="primary" disabled={reverse.isPending}>
          Confirm
        </Button>
        <Button onClick={() => setOpen(false)}>Cancel</Button>
      </div>
    </form>
  );
}

function EnforcementPanel({
  userId,
  username,
  maxBanDays,
  onDone,
}: {
  userId: string;
  username: string;
  maxBanDays: number | null;
  onDone: () => void;
}) {
  const { can } = useAuth();
  const [type, setType] = useState('warning');
  const [reasonCode, setReasonCode] = useState(SELECTABLE_REASONS[0]?.code ?? '');
  const [note, setNote] = useState('');
  const [days, setDays] = useState(7);
  const [features, setFeatures] = useState<string[]>([]);
  const [rateLimit, setRateLimit] = useState(10);
  const [removalScope, setRemovalScope] = useState('none');
  const [confirmationPhrase, setConfirmationPhrase] = useState('');
  const [expectedPhrase, setExpectedPhrase] = useState<string | null>(null);

  // Only rungs this admin can actually apply.
  const available = ACTION_TYPES.filter((spec) => can(spec.requiredPermission));
  const spec = LADDER[type as keyof typeof LADDER];

  const apply = useMutation({
    mutationFn: () => {
      const expiresAt =
        spec.duration === 'none'
          ? null
          : new Date(Date.now() + days * 86_400_000).toISOString();

      return api.post(`/api/enforcement/users/${userId}/actions`, {
        type,
        reasonCode,
        note,
        expiresAt,
        restrictedFeatures: type === 'feature_restriction' ? features : undefined,
        rateLimitPerMinute: type === 'rate_limit' ? rateLimit : undefined,
        contentRemovalScope: removalScope,
        breakGlass: confirmationPhrase ? { confirmationPhrase } : undefined,
      });
    },
    onSuccess: () => {
      setNote('');
      setConfirmationPhrase('');
      setExpectedPhrase(null);
      onDone();
    },
    onError: (error) => {
      // 428 carries the exact phrase the server expects. Showing it is not a
      // weakness: the friction is in having to consciously retype the target's
      // name, not in guessing a secret.
      if (error instanceof ApiError && error.needsBreakGlass) {
        setExpectedPhrase((error.details?.expectedPhrase as string) ?? null);
      }
    },
  });

  if (available.length === 0) {
    return (
      <Card title="Enforcement">
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Your role cannot take enforcement action.
        </p>
      </Card>
    );
  }

  const banCapExceeded =
    type === 'ban_temporary' && maxBanDays !== null && maxBanDays > 0 && days > maxBanDays;

  return (
    <Card
      title="Take action"
      description={`Applies to @${username}. Every action is audit-logged and reversible.`}
    >
      <form
        className="grid gap-4 lg:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          apply.mutate();
        }}
      >
        <Field label="Action" htmlFor="action-type" hint={spec?.description}>
          <Select id="action-type" value={type} onChange={(e) => setType(e.target.value)}>
            {available.map((option) => (
              <option key={option.type} value={option.type}>
                {option.label}
              </option>
            ))}
          </Select>
        </Field>

        <Field label="Reason" htmlFor="reason-code">
          <Select
            id="reason-code"
            value={reasonCode}
            onChange={(e) => setReasonCode(e.target.value)}
          >
            {SELECTABLE_REASONS.map((reason) => (
              <option key={reason.code} value={reason.code}>
                {reason.code} (policy {reason.policyClause})
              </option>
            ))}
          </Select>
        </Field>

        {spec?.duration !== 'none' && (
          <Field
            label="Duration (days)"
            htmlFor="days"
            hint={
              maxBanDays === null
                ? 'Your role has no duration cap.'
                : `Your role can issue up to ${maxBanDays} days.`
            }
            error={banCapExceeded ? `Exceeds your ${maxBanDays}-day limit.` : undefined}
          >
            <Input
              id="days"
              type="number"
              min={1}
              max={3650}
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
            />
          </Field>
        )}

        {type === 'feature_restriction' && (
          <fieldset className="space-y-1">
            <legend className="text-sm font-medium">Features to disable</legend>
            {RESTRICTABLE_FEATURES.map((feature) => (
              <label key={feature} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={features.includes(feature)}
                  onChange={(e) =>
                    setFeatures((current) =>
                      e.target.checked
                        ? [...current, feature]
                        : current.filter((f) => f !== feature),
                    )
                  }
                />
                {feature.replace(/_/g, ' ')}
              </label>
            ))}
          </fieldset>
        )}

        {type === 'rate_limit' && (
          <Field label="Messages per minute" htmlFor="rate">
            <Input
              id="rate"
              type="number"
              min={1}
              max={600}
              value={rateLimit}
              onChange={(e) => setRateLimit(Number(e.target.value))}
            />
          </Field>
        )}

        <div className="lg:col-span-2">
          <Field
            label="Decision note"
            htmlFor="note"
            hint="Read by whoever reviews an appeal. Not shown to the user."
          >
            <Textarea
              id="note"
              required
              minLength={10}
              rows={3}
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
          </Field>
        </div>

        <Field
          label="Remove content"
          htmlFor="removal"
          hint="§4: content stays visible by default. Removal is irreversible — messages are end-to-end encrypted and cannot be restored."
        >
          <Select
            id="removal"
            value={removalScope}
            onChange={(e) => setRemovalScope(e.target.value)}
          >
            <option value="none">Keep all content</option>
            <option value="last_24h">Remove last 24 hours</option>
            <option value="last_30d">Remove last 30 days</option>
            <option value="all">Remove everything</option>
          </Select>
        </Field>

        {expectedPhrase && (
          <div className="lg:col-span-2">
            <Field
              label="Type this phrase to confirm"
              htmlFor="phrase"
              hint={`Exactly: ${expectedPhrase}`}
            >
              <Input
                id="phrase"
                value={confirmationPhrase}
                onChange={(e) => setConfirmationPhrase(e.target.value)}
              />
            </Field>
          </div>
        )}

        <div className="lg:col-span-2">
          <ErrorNote error={apply.error} />
        </div>

        <div className="lg:col-span-2">
          <Button
            type="submit"
            variant={spec?.severity && spec.severity >= 60 ? 'danger' : 'primary'}
            disabled={apply.isPending || banCapExceeded}
          >
            {apply.isPending ? 'Applying…' : `Apply ${spec?.label ?? type}`}
          </Button>
        </div>
      </form>
    </Card>
  );
}
