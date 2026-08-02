/**
 * API client.
 *
 * Two things it does that matter:
 *
 *   - Echoes the CSRF cookie back as a header on every mutating request. The
 *     session cookie is httpOnly and SameSite=Strict; the CSRF cookie is
 *     deliberately readable so this can complete the double-submit.
 *   - Surfaces the server's error message rather than a generic one. The API
 *     writes errors for the admin reading them ("Your role can issue bans up to
 *     30 days; this one is 90"), and swallowing that in favour of "Request
 *     failed" throws away the only useful part.
 */

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'ApiError';
  }

  /** 428 — the action needs a typed phrase or a second admin's approval. */
  get needsBreakGlass(): boolean {
    return this.code === 'break_glass_required';
  }
}

function readCookie(name: string): string | undefined {
  const match = document.cookie.match(new RegExp(`(^|;\\s*)${name}=([^;]*)`));
  return match?.[2] ? decodeURIComponent(match[2]) : undefined;
}

const MUTATING = new Set(['POST', 'PATCH', 'PUT', 'DELETE']);

export interface RequestOptions {
  method?: string;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null | string[]>;
  signal?: AbortSignal;
}

function buildUrl(path: string, query?: RequestOptions['query']): string {
  const url = new URL(path, window.location.origin);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === '') continue;
      if (Array.isArray(value)) {
        for (const item of value) url.searchParams.append(key, String(item));
      } else {
        url.searchParams.set(key, String(value));
      }
    }
  }
  return url.pathname + url.search;
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET';
  const headers: Record<string, string> = {};

  if (options.body !== undefined) headers['content-type'] = 'application/json';

  if (MUTATING.has(method)) {
    const csrf = readCookie('neveroff_console_csrf');
    if (csrf) headers['x-csrf-token'] = csrf;
  }

  const response = await fetch(buildUrl(path, options.query), {
    method,
    headers,
    // Without this the session cookie is not sent at all.
    credentials: 'same-origin',
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal: options.signal,
  });

  if (response.status === 204) return undefined as T;

  const payload = await response.json().catch(() => null);

  if (!response.ok) {
    const error = (payload as { error?: { code?: string; message?: string; details?: Record<string, unknown> } })
      ?.error;
    throw new ApiError(
      response.status,
      error?.code ?? 'internal',
      error?.message ?? `Request failed with status ${response.status}.`,
      error?.details,
    );
  }

  return payload as T;
}

export const api = {
  get: <T>(path: string, query?: RequestOptions['query']) => request<T>(path, { query }),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PATCH', body }),
  delete: <T>(path: string, body?: unknown) => request<T>(path, { method: 'DELETE', body }),
};

// ---------------------------------------------------------------------------
// Shared response shapes
// ---------------------------------------------------------------------------

export interface Me {
  id: string;
  email: string;
  displayName: string;
  role: string;
  roleLabel: string;
  rank: number;
  permissions: string[];
  scope: {
    countries: string[] | null;
    languages: string[] | null;
    channelIds: string[] | null;
    reportCategories: string[] | null;
  };
  maxBanDays: number | null;
}

export interface DirectoryUser {
  id: string;
  username: string;
  displayName: string | null;
  avatarUrl: string | null;
  country: string | null;
  registeredAt: string;
  status: string;
  blocksAccess: boolean;
  blocksSending: boolean;
  restrictedFeatures: string[];
  nextExpiryAt: string | null;
  activeActionCount: number;
  lifetimeActionCount: number;
  appealCount: number;
  messageCount: number;
  lastMessageAt: string | null;
  ownedChannelCount: number;
  underLegalHold: boolean;
  trustScore: number | null;
}

export interface TrustComponent {
  key: string;
  label: string;
  points: number;
  max: number;
  detail: string;
}

export interface EnforcementRecord {
  id: string;
  type: string;
  caseRef: string;
  reasonCode: string;
  note: string;
  issuedByLabel: string;
  issuedAt: string;
  expiresAt: string | null;
  reversedAt: string | null;
  reversalReason: string | null;
  autoLifted: boolean;
  origin: string;
  active: boolean;
}

export interface UserProfileResponse {
  user: DirectoryUser;
  trustScore: {
    total: number;
    baseline: number;
    known: boolean;
    components: TrustComponent[];
  };
  enforcementHistory: EnforcementRecord[];
  appeals: Array<{
    id: string;
    actionId: string;
    status: string;
    submittedAt: string;
    reviewedAt: string | null;
    slaDueAt: string;
  }>;
  ownedChannels: Array<{
    id: string;
    name: string;
    username: string;
    subscriberCount: number;
    isPublic: boolean;
  }>;
  piiAvailable: boolean;
}
