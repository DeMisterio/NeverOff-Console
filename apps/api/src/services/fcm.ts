import { createSign } from 'node:crypto';

import { getConfig } from '../config.js';

/**
 * Firebase Cloud Messaging v1.
 *
 * Deliberately mirrors what supabase/functions/push-notify/index.ts already
 * does in the NeverOff repo — same service account, same OAuth exchange, same
 * data-only message shape — so enforcement notifications arrive through exactly
 * the path the app already handles rather than a second, subtly different one.
 *
 * Messages are data-only, carrying reason codes rather than rendered text. The
 * app localises from its own string resources, which is what makes §4's "in the
 * user's language" work without the server knowing the user's locale.
 */

interface TokenCache {
  token: string;
  expiresAt: number;
}

let cached: TokenCache | undefined;

function base64Url(input: Buffer | string): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

async function getAccessToken(): Promise<string> {
  const config = getConfig();

  // 60s of slack so a token cannot expire between the check and the request.
  if (cached && cached.expiresAt > Date.now() + 60_000) return cached.token;

  const clientEmail = config.FIREBASE_CLIENT_EMAIL;
  const privateKey = config.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');
  if (!clientEmail || !privateKey) {
    throw new Error('Firebase credentials are not configured.');
  }

  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = base64Url(
    JSON.stringify({
      iss: clientEmail,
      scope: 'https://www.googleapis.com/auth/firebase.messaging',
      aud: 'https://oauth2.googleapis.com/token',
      exp: now + 3600,
      iat: now,
    }),
  );

  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  const signature = base64Url(signer.sign(privateKey));
  const assertion = `${header}.${payload}.${signature}`;

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
  });

  const data = (await response.json()) as {
    access_token?: string;
    expires_in?: number;
    error_description?: string;
    error?: string;
  };

  if (!data.access_token) {
    throw new Error(`FCM OAuth failed: ${data.error_description ?? data.error ?? 'unknown'}`);
  }

  cached = {
    token: data.access_token,
    expiresAt: Date.now() + (data.expires_in ?? 3600) * 1000,
  };
  return cached.token;
}

export interface PushResult {
  readonly ok: boolean;
  readonly error?: string;
  /** The device token is dead; stop retrying and clear it. */
  readonly tokenInvalid?: boolean;
}

export async function sendDataMessage(
  deviceToken: string,
  data: Record<string, string>,
): Promise<PushResult> {
  const config = getConfig();
  if (!config.pushEnabled) {
    return { ok: false, error: 'Firebase is not configured on this deployment.' };
  }

  try {
    const accessToken = await getAccessToken();
    const url = `https://fcm.googleapis.com/v1/projects/${config.FIREBASE_PROJECT_ID}/messages:send`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ message: { token: deviceToken, data } }),
    });

    if (response.ok) return { ok: true };

    const body = (await response.json().catch(() => ({}))) as {
      error?: { status?: string; message?: string };
    };
    const status = body.error?.status ?? String(response.status);

    // UNREGISTERED means the app was uninstalled or the token rotated. Retrying
    // that forever just fills the outbox with permanent failures.
    const tokenInvalid = status === 'UNREGISTERED' || status === 'INVALID_ARGUMENT';

    return {
      ok: false,
      error: `${status}: ${body.error?.message ?? 'FCM rejected the message'}`,
      tokenInvalid,
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/** Flatten a notification payload to the string map FCM requires. */
export function toDataPayload(
  kind: string,
  payload: Record<string, unknown>,
): Record<string, string> {
  const out: Record<string, string> = { type: 'enforcement', kind };
  for (const [key, value] of Object.entries(payload)) {
    if (value === null || value === undefined) continue;
    out[key] = typeof value === 'string' ? value : JSON.stringify(value);
  }
  return out;
}
