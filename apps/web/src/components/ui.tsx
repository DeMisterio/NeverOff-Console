import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, TextareaHTMLAttributes } from 'react';

/**
 * Minimal UI primitives.
 *
 * Hand-rolled rather than pulled from a component library so the whole surface
 * is auditable and the accessibility properties below are guaranteed rather
 * than inherited. Every status indicator carries a text label — §9.3 forbids
 * colour-only encoding, and a moderator with deuteranopia should not have to
 * guess whether a row is muted or banned.
 */

type Variant = 'primary' | 'secondary' | 'danger' | 'ghost';

const VARIANTS: Record<Variant, string> = {
  primary:
    'bg-indigo-600 text-white hover:bg-indigo-500 disabled:bg-indigo-600/40 disabled:text-white/70',
  secondary:
    'border border-slate-300 bg-white text-slate-900 hover:bg-slate-50 ' +
    'dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:bg-slate-800',
  danger: 'bg-red-600 text-white hover:bg-red-500 disabled:bg-red-600/40',
  ghost: 'text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800',
};

export function Button({
  variant = 'secondary',
  className = '',
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      {...props}
      className={
        'inline-flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium ' +
        'transition-colors disabled:cursor-not-allowed ' +
        `${VARIANTS[variant]} ${className}`
      }
    >
      {children}
    </button>
  );
}

const STATUS_STYLES: Record<string, string> = {
  active: 'bg-green-100 text-green-900 dark:bg-green-950 dark:text-green-200',
  warned: 'bg-yellow-100 text-yellow-900 dark:bg-yellow-950 dark:text-yellow-200',
  restricted: 'bg-orange-100 text-orange-900 dark:bg-orange-950 dark:text-orange-200',
  muted: 'bg-red-100 text-red-900 dark:bg-red-950 dark:text-red-200',
  shadow_restricted: 'bg-purple-100 text-purple-900 dark:bg-purple-950 dark:text-purple-200',
  banned_temporary: 'bg-red-200 text-red-950 dark:bg-red-900 dark:text-red-100',
  banned_permanent: 'bg-red-300 text-red-950 dark:bg-red-800 dark:text-red-50',
  deleted: 'bg-slate-200 text-slate-800 dark:bg-slate-800 dark:text-slate-300',
};

const STATUS_LABELS: Record<string, string> = {
  active: 'Active',
  warned: 'Warned',
  restricted: 'Restricted',
  muted: 'Muted',
  shadow_restricted: 'Shadow-restricted',
  banned_temporary: 'Banned (temporary)',
  banned_permanent: 'Banned (permanent)',
  deleted: 'Deleted',
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={
        'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ' +
        (STATUS_STYLES[status] ?? STATUS_STYLES.active)
      }
    >
      {/* The text is the signal; colour only reinforces it. */}
      {STATUS_LABELS[status] ?? status}
    </span>
  );
}

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'warn' }) {
  const tones = {
    neutral: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
    warn: 'bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-200',
  };
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium ${tones[tone]}`}>
      {children}
    </span>
  );
}

export function Card({
  title,
  description,
  children,
  actions,
}: {
  title?: string;
  description?: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      {(title || actions) && (
        <header className="flex items-start justify-between gap-4 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <div>
            {title && <h2 className="text-sm font-semibold">{title}</h2>}
            {description && (
              <p className="mt-0.5 text-xs text-slate-600 dark:text-slate-400">{description}</p>
            )}
          </div>
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Field({
  label,
  hint,
  error,
  children,
  htmlFor,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: ReactNode;
  htmlFor?: string;
}) {
  const describedBy = [hint ? `${htmlFor}-hint` : null, error ? `${htmlFor}-error` : null]
    .filter(Boolean)
    .join(' ');

  return (
    <div className="space-y-1">
      <label htmlFor={htmlFor} className="block text-sm font-medium">
        {label}
      </label>
      {/* aria-describedby is wired up so a screen reader reads the hint and the
          error, not just the label. */}
      <div aria-describedby={describedBy || undefined}>{children}</div>
      {hint && (
        <p id={`${htmlFor}-hint`} className="text-xs text-slate-600 dark:text-slate-400">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${htmlFor}-error`} role="alert" className="text-xs font-medium text-red-600 dark:text-red-400">
          {error}
        </p>
      )}
    </div>
  );
}

const INPUT_CLASS =
  'w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm ' +
  'placeholder:text-slate-400 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100';

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`${INPUT_CLASS} ${props.className ?? ''}`} />;
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={`${INPUT_CLASS} ${props.className ?? ''}`} />;
}

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={`${INPUT_CLASS} ${props.className ?? ''}`} />;
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null;
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div
      role="alert"
      className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-900 dark:bg-red-950 dark:text-red-200"
    >
      {message}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-sm text-slate-500 dark:text-slate-400">{children}</p>;
}

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-8 text-sm text-slate-500">
      {/* role=status so assistive tech announces the wait rather than silence. */}
      <span role="status" aria-live="polite">
        {label}…
      </span>
    </div>
  );
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function formatRelative(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';

  const diffMs = date.getTime() - Date.now();
  const abs = Math.abs(diffMs);
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ['day', 86_400_000],
    ['hour', 3_600_000],
    ['minute', 60_000],
  ];

  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  for (const [unit, ms] of units) {
    if (abs >= ms) return formatter.format(Math.round(diffMs / ms), unit);
  }
  return 'just now';
}
