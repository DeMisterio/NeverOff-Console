import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';

import { getConfig } from '../config.js';

/**
 * TOTP (RFC 6238), implemented directly against node:crypto.
 *
 * Written out rather than pulled from a package for two reasons: it is about
 * sixty lines of well-specified arithmetic, and the replay-prevention rule
 * below has to be integrated with the database anyway, which every library
 * leaves to the caller. Fewer dependencies in the authentication path is worth
 * more than the lines saved.
 *
 * Two properties beyond plain RFC 6238:
 *
 *   - Secrets are encrypted at rest with AES-256-GCM under TOTP_ENCRYPTION_KEY.
 *     A leaked database backup alone does not yield working second factors.
 *   - `verify` returns the time step that matched, and the caller must reject
 *     any step less than or equal to the last one accepted for that admin. Without
 *     that, a code observed over someone's shoulder stays valid for the rest of
 *     its 30-second window — and a 30-second replay window is a real attack, not
 *     a theoretical one, on a console that can ban every user on the platform.
 */

const DIGITS = 6;
const PERIOD_SECONDS = 30;
/** Codes from one step either side are accepted, covering ~±30s of clock skew. */
const DRIFT_STEPS = 1;

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(input: string): Buffer {
  const cleaned = input.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;

  for (const char of cleaned) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error('Invalid base32 character in TOTP secret.');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function hotp(key: Buffer, counter: bigint): string {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(counter);

  const digest = createHmac('sha1', key).update(counterBuffer).digest();
  // Dynamic truncation, RFC 4226 §5.4.
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);

  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

export function currentStep(at: Date = new Date()): bigint {
  return BigInt(Math.floor(at.getTime() / 1000 / PERIOD_SECONDS));
}

export function generateSecret(): string {
  // 20 bytes = 160 bits, the RFC 4226 recommendation and what authenticator
  // apps expect for SHA-1.
  return base32Encode(randomBytes(20));
}

export function generateCode(secret: string, at: Date = new Date()): string {
  return hotp(base32Decode(secret), currentStep(at));
}

export interface VerifyResult {
  readonly valid: boolean;
  /** The step that matched. Persist it; reject anything <= it next time. */
  readonly step: bigint | null;
}

/**
 * @param lastAcceptedStep the admin's `totp_last_step`, or null if never used.
 */
export function verifyCode(
  secret: string,
  code: string,
  lastAcceptedStep: bigint | null,
  at: Date = new Date(),
): VerifyResult {
  const trimmed = code.replace(/\s+/g, '');
  if (!/^\d{6}$/.test(trimmed)) return { valid: false, step: null };

  const key = base32Decode(secret);
  const now = currentStep(at);

  for (let drift = -DRIFT_STEPS; drift <= DRIFT_STEPS; drift += 1) {
    const step = now + BigInt(drift);

    // Replay guard. A code from a step already used — or older — is refused
    // even though it is arithmetically correct.
    if (lastAcceptedStep !== null && step <= lastAcceptedStep) continue;

    const expected = Buffer.from(hotp(key, step));
    const supplied = Buffer.from(trimmed);
    if (expected.length === supplied.length && timingSafeEqual(expected, supplied)) {
      return { valid: true, step };
    }
  }

  return { valid: false, step: null };
}

/** otpauth:// URI for the enrolment QR code. */
export function enrolmentUri(secret: string, accountEmail: string, issuer = 'NeverOff Console'): string {
  const label = encodeURIComponent(`${issuer}:${accountEmail}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(PERIOD_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// ---------------------------------------------------------------------------
// Encryption at rest
// ---------------------------------------------------------------------------

/**
 * Fixed salt. The input is already a high-entropy secret from the environment,
 * not a user password, so the salt is only here to domain-separate this key
 * from any other use of TOTP_ENCRYPTION_KEY. Per-record salts would need to be
 * stored alongside and would buy nothing.
 */
const KDF_SALT = 'neveroff-console/totp/v1';

function encryptionKey(): Buffer {
  return scryptSync(getConfig().TOTP_ENCRYPTION_KEY, KDF_SALT, 32);
}

export function encryptSecret(secret: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString('base64');
}

export function decryptSecret(stored: string): string {
  const raw = Buffer.from(stored, 'base64');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ciphertext = raw.subarray(28);

  const decipher = createDecipheriv('aes-256-gcm', encryptionKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

/** Human-transcribable: no ambiguous characters, grouped for readability. */
const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function generateRecoveryCodes(count = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i += 1) {
    const bytes = randomBytes(10);
    let code = '';
    for (const byte of bytes) {
      code += RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length];
    }
    codes.push(`${code.slice(0, 5)}-${code.slice(5, 10)}`);
  }
  return codes;
}

export function normaliseRecoveryCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z0-9]/g, '');
}
