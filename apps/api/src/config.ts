import { z } from 'zod';

/**
 * Environment configuration, validated once at boot.
 *
 * Everything is parsed and checked here so a missing secret is a startup
 * failure with a readable message, not a 500 three hours later when the first
 * admin tries to log in. Secrets have minimum-length checks because a short
 * SESSION_SECRET is the kind of thing that gets set to "changeme" in a hurry
 * and never revisited.
 */

const csv = (value: string | undefined): string[] =>
  (value ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),

  API_PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  API_HOST: z.string().default('127.0.0.1'),
  WEB_ORIGIN: z.string().url('WEB_ORIGIN must be a full URL, e.g. http://localhost:5173'),

  SESSION_SECRET: z
    .string()
    .min(32, 'SESSION_SECRET must be at least 32 characters. Generate one with: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'base64url\'))"'),
  TOTP_ENCRYPTION_KEY: z
    .string()
    .min(32, 'TOTP_ENCRYPTION_KEY must be at least 32 characters.'),

  SESSION_IDLE_TIMEOUT_MINUTES: z.coerce.number().int().min(1).max(1440).default(30),
  SESSION_ABSOLUTE_TIMEOUT_HOURS: z.coerce.number().int().min(1).max(168).default(12),

  ADMIN_IP_ALLOWLIST: z.string().optional(),

  // Policy knobs the spec left as placeholders.
  MAX_BAN_DAYS_T2: z.coerce.number().int().min(0).default(30),
  BULK_THRESHOLD: z.coerce.number().int().min(1).default(50),
  APPEAL_SLA_HOURS: z.coerce.number().int().min(1).default(72),

  // Enforcement write-back. Optional so the console still boots for local
  // development without Firebase credentials; user notifications are then
  // recorded as pending rather than silently dropped.
  SUPABASE_URL: z.string().url().optional().or(z.literal('')),
  SUPABASE_SERVICE_ROLE_KEY: z.string().optional(),
  FIREBASE_PROJECT_ID: z.string().optional(),
  FIREBASE_CLIENT_EMAIL: z.string().optional(),
  FIREBASE_PRIVATE_KEY: z.string().optional(),
});

export type RawConfig = z.infer<typeof schema>;

export interface Config extends RawConfig {
  readonly isProduction: boolean;
  readonly ipAllowlist: string[];
  readonly pushEnabled: boolean;
  readonly cookieName: string;
  readonly csrfCookieName: string;
}

function build(): Config {
  const parsed = schema.safeParse(process.env);

  if (!parsed.success) {
    const lines = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`);
    throw new Error(`Invalid environment configuration:\n${lines.join('\n')}\n`);
  }

  const raw = parsed.data;
  const pushEnabled = Boolean(
    raw.FIREBASE_PROJECT_ID && raw.FIREBASE_CLIENT_EMAIL && raw.FIREBASE_PRIVATE_KEY,
  );

  if (raw.NODE_ENV === 'production' && !pushEnabled) {
    // Not fatal, but a production console that cannot tell a user why they were
    // banned is failing a §4 requirement, so say so loudly at boot.
    console.warn(
      '[config] Firebase credentials are not configured. Users will NOT be notified of ' +
        'enforcement actions or expiries. §4 requires that they are.',
    );
  }

  return {
    ...raw,
    isProduction: raw.NODE_ENV === 'production',
    ipAllowlist: csv(raw.ADMIN_IP_ALLOWLIST),
    pushEnabled,
    cookieName: 'neveroff_console_session',
    csrfCookieName: 'neveroff_console_csrf',
  };
}

let cached: Config | undefined;

export function getConfig(): Config {
  cached ??= build();
  return cached;
}

/** Test hook: force a re-read after mutating process.env. */
export function resetConfigCache(): void {
  cached = undefined;
}
