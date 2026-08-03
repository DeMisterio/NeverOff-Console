import { CHANNEL_LADDER, SELECTABLE_REASONS } from '@neveroff-console/shared';
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
  Textarea,
  formatDate,
} from '../components/ui';
import { ApiError, api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { RestrictionBadges } from './Channels';

/**
 * Channel detail and the §6.5 action ladder.
 *
 * The ladder is presented in severity order with each rung's description
 * visible, because the choice between "block new joins" and "take down" is the
 * whole judgement and a bare dropdown of ten verbs does not help anyone make it.
 */

interface ChannelDetail {
  channel: {
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
  };
  actions: Array<{
    id: string;
    type: string;
    caseRef: string;
    reasonCode: string;
    note: string;
    issuedByLabel: string;
    issuedAt: string;
    expiresAt: string | null;
    countries: string[] | null;
    reversedAt: string | null;
    reversalReason: string | null;
    active: boolean;
  }>;
  growth: Array<{ capturedAt: string; subscriberCount: number }>;
  ownerAccountability: {
    channelsOwned: number;
    channelsActioned: number;
    takedowns: number;
    totalReach: number;
  } | null;
}

const LADDER = Object.values(CHANNEL_LADDER).sort((a, b) => a.severity - b.severity);

export function ChannelDetailPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const { can } = useAuth();

  const query = useQuery<ChannelDetail>({
    queryKey: ['channel', id],
    queryFn: () => api.get<ChannelDetail>(`/api/channels/${id}`),
    enabled: Boolean(id),
  });

  if (query.isLoading) return <Spinner label="Loading channel" />;
  if (query.error) return <ErrorNote error={query.error} />;
  if (!query.data) return <Empty>Not found.</Empty>;

  const { channel, actions, ownerAccountability } = query.data;
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['channel', id] });

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-lg font-semibold">
              {channel.name}
              <span className="ml-2 font-normal text-slate-600 dark:text-slate-400">
                @{channel.username}
              </span>
            </h1>
            <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-slate-600 dark:text-slate-400">
              <span>{channel.subscriberCount.toLocaleString()} subscribers</span>
              <span>·</span>
              <span>{channel.postCount} posts</span>
              <span>·</span>
              <span>{channel.isPublic ? 'public' : 'unlisted'}</span>
              <span>·</span>
              <span>created {formatDate(channel.createdAt)}</span>
            </p>
            <p className="mt-1 text-sm">
              Owner{' '}
              <Link
                to={`/users/${channel.ownerId}`}
                className="text-indigo-700 hover:underline dark:text-indigo-400"
              >
                @{channel.ownerUsername}
              </Link>
            </p>
            <div className="mt-2">
              <RestrictionBadges state={channel.restrictionState} />
            </div>
          </div>
          <Link to="/channels" className="text-sm text-indigo-700 hover:underline dark:text-indigo-400">
            ← All channels
          </Link>
        </div>
      </Card>

      {ownerAccountability && ownerAccountability.channelsActioned >= 2 && (
        <div
          role="alert"
          className="rounded-md border border-amber-400 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200"
        >
          <strong>Owner accountability (§6.5).</strong> @{channel.ownerUsername} owns{' '}
          {ownerAccountability.channelsOwned} channel(s), {ownerAccountability.channelsActioned} of
          which have been actioned, with {ownerAccountability.takedowns} takedown(s) and{' '}
          {ownerAccountability.totalReach.toLocaleString()} total reach. Repeated violations across
          channels are grounds for action against the owner rather than only the channels — though
          this can also be what a large community that is hard to moderate looks like.
        </div>
      )}

      <ChannelActionPanel channelId={channel.id} channelName={channel.name} onDone={refresh} />

      <Card title="Restriction history">
        {actions.length === 0 ? (
          <Empty>No actions have been taken against this channel.</Empty>
        ) : (
          <ul className="space-y-3">
            {actions.map((action) => (
              <li
                key={action.id}
                className="rounded border border-slate-200 p-3 text-sm dark:border-slate-800"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">
                    {CHANNEL_LADDER[action.type as keyof typeof CHANNEL_LADDER]?.label ??
                      action.type}
                  </span>
                  {action.active ? (
                    <Badge tone="warn">In force</Badge>
                  ) : (
                    <Badge>{action.reversedAt ? 'Reversed' : 'Expired'}</Badge>
                  )}
                  {action.countries && action.countries.length > 0 && (
                    <Badge>{action.countries.join(', ')}</Badge>
                  )}
                  <span className="ml-auto font-mono text-xs text-slate-600 dark:text-slate-400">
                    {action.caseRef}
                  </span>
                </div>
                <p className="mt-1 text-slate-600 dark:text-slate-400">
                  {action.reasonCode} · {action.issuedByLabel} · {formatDate(action.issuedAt)}
                  {action.expiresAt && ` · expires ${formatDate(action.expiresAt)}`}
                </p>
                <p className="mt-1">{action.note}</p>
                {action.reversalReason && (
                  <p className="mt-1 text-slate-600 dark:text-slate-400">
                    Lifted: {action.reversalReason}
                  </p>
                )}
                {action.active && can('channels.restrict') && (
                  <ReverseChannelAction actionId={action.id} onDone={refresh} />
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function ReverseChannelAction({ actionId, onDone }: { actionId: string; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');

  const reverse = useMutation({
    mutationFn: () => api.post(`/api/channels/actions/${actionId}/reverse`, { reason }),
    onSuccess: () => {
      setOpen(false);
      onDone();
    },
  });

  if (!open) {
    return (
      <Button className="mt-2" onClick={() => setOpen(true)}>
        Lift this restriction
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
      <Field label="Why are you lifting this?" htmlFor={`rev-${actionId}`}>
        <Textarea
          id={`rev-${actionId}`}
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

function ChannelActionPanel({
  channelId,
  channelName,
  onDone,
}: {
  channelId: string;
  channelName: string;
  onDone: () => void;
}) {
  const { can } = useAuth();
  const [type, setType] = useState('warn_owner');
  const [reasonCode, setReasonCode] = useState(SELECTABLE_REASONS[0]?.code ?? '');
  const [note, setNote] = useState('');
  const [days, setDays] = useState(7);
  const [countries, setCountries] = useState('');
  const [confirmationPhrase, setConfirmationPhrase] = useState('');
  const [expectedPhrase, setExpectedPhrase] = useState<string | null>(null);
  const [breakGlassRequired, setBreakGlassRequired] = useState(false);

  const available = LADDER.filter((spec) => can(spec.requiredPermission));
  const spec = CHANNEL_LADDER[type as keyof typeof CHANNEL_LADDER];

  const apply = useMutation({
    mutationFn: () =>
      api.post(`/api/channels/${channelId}/actions`, {
        type,
        reasonCode,
        note,
        expiresAt:
          spec?.duration === 'none' ? null : new Date(Date.now() + days * 86_400_000).toISOString(),
        countries: spec?.needsCountries
          ? countries.split(',').map((c) => c.trim().toUpperCase()).filter(Boolean)
          : undefined,
        breakGlass: confirmationPhrase ? { confirmationPhrase } : undefined,
      }),
    onSuccess: () => {
      setNote('');
      setConfirmationPhrase('');
      setExpectedPhrase(null);
      setBreakGlassRequired(false);
      onDone();
    },
    onError: (error) => {
      if (error instanceof ApiError && error.needsBreakGlass) {
        const phrase = error.details?.expectedPhrase as string | undefined;
        if (phrase) setExpectedPhrase(phrase);
        else setBreakGlassRequired(true);
      }
    },
  });

  if (available.length === 0) {
    return (
      <Card title="Channel actions">
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Your role cannot restrict channels.
        </p>
      </Card>
    );
  }

  return (
    <Card
      title="Take action"
      description={`Applies to ${channelName}. Every action is audit-logged and reversible.`}
    >
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          apply.mutate();
        }}
      >
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">Action</legend>
          {available.map((option) => (
            <label
              key={option.type}
              className={
                'flex cursor-pointer gap-3 rounded border p-3 ' +
                (type === option.type
                  ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-950/40'
                  : 'border-slate-200 dark:border-slate-800')
              }
            >
              <input
                type="radio"
                name="channel-action"
                className="mt-1"
                checked={type === option.type}
                onChange={() => setType(option.type)}
              />
              <span>
                <span className="block text-sm font-medium">
                  {option.label}
                  {option.breakGlass === 'second_admin' && (
                    <span className="ml-2">
                      <Badge tone="warn">Needs a second admin</Badge>
                    </span>
                  )}
                </span>
                <span className="block text-xs text-slate-600 dark:text-slate-400">
                  {option.description}
                </span>
              </span>
            </label>
          ))}
        </fieldset>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Reason" htmlFor="ch-reason">
            <Select id="ch-reason" value={reasonCode} onChange={(e) => setReasonCode(e.target.value)}>
              {SELECTABLE_REASONS.map((r) => (
                <option key={r.code} value={r.code}>
                  {r.code} (policy {r.policyClause})
                </option>
              ))}
            </Select>
          </Field>

          {spec?.duration !== 'none' && (
            <Field label="Duration (days)" htmlFor="ch-days" hint="Leave as-is for a short review window.">
              <Input
                id="ch-days"
                type="number"
                min={1}
                max={3650}
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
              />
            </Field>
          )}

          {spec?.needsCountries && (
            <Field
              label="Countries"
              htmlFor="ch-countries"
              hint="Comma-separated ISO codes. §8 prefers geo-blocking over global removal where the content is lawful elsewhere."
            >
              <Input
                id="ch-countries"
                value={countries}
                onChange={(e) => setCountries(e.target.value)}
                placeholder="DE, FR"
              />
            </Field>
          )}
        </div>

        <Field
          label="Decision note"
          htmlFor="ch-note"
          hint="Read on appeal — channel owners get the same appeal path as individuals."
        >
          <Textarea
            id="ch-note"
            required
            minLength={10}
            rows={3}
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </Field>

        {expectedPhrase && (
          <Field label="Type this phrase to confirm" htmlFor="ch-phrase" hint={`Exactly: ${expectedPhrase}`}>
            <Input
              id="ch-phrase"
              value={confirmationPhrase}
              onChange={(e) => setConfirmationPhrase(e.target.value)}
            />
          </Field>
        )}

        {breakGlassRequired && (
          <div className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200">
            This action needs a second admin to approve it. Raise an approval request from the
            enforcement screen, have a colleague approve it, then come back.
          </div>
        )}

        <ErrorNote error={apply.error} />

        <Button
          type="submit"
          variant={spec && spec.severity >= 60 ? 'danger' : 'primary'}
          disabled={apply.isPending}
        >
          {apply.isPending ? 'Applying…' : `Apply ${spec?.label ?? type}`}
        </Button>

        {spec?.notifiesMembers && (
          <p className="text-xs text-slate-600 dark:text-slate-400">
            Every subscriber will be notified, with the reason. People who joined in good faith
            deserve to know why a channel they follow has changed.
          </p>
        )}
      </form>
    </Card>
  );
}
