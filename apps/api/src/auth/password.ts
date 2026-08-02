import { Algorithm, hash, verify } from '@node-rs/argon2';

import { validationFailed } from '../errors.js';

/**
 * Argon2id password hashing.
 *
 * Parameters follow the OWASP Password Storage Cheat Sheet's Argon2id baseline
 * (19 MiB, 2 iterations, 1 lane). Memory cost is the parameter that matters
 * against GPU cracking; keep it if you tune anything else.
 *
 * @node-rs/argon2 ships prebuilt binaries, so there is no native toolchain
 * requirement on Windows — a real consideration given where this is developed.
 */

const OPTIONS = {
  algorithm: Algorithm.Argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
} as const;

export async function hashPassword(plain: string): Promise<string> {
  return hash(plain, OPTIONS);
}

export async function verifyPassword(stored: string, supplied: string): Promise<boolean> {
  try {
    return await verify(stored, supplied, OPTIONS);
  } catch {
    // A malformed stored hash must read as "wrong password", never as a crash
    // that could distinguish a corrupted record from a bad guess.
    return false;
  }
}

/**
 * Deliberately not a complexity-class checker.
 *
 * Composition rules ("one uppercase, one symbol") push people towards
 * Password1! and are no longer recommended by NIST SP 800-63B. Length plus a
 * check against the obvious candidates does more, and every admin account is
 * behind mandatory TOTP anyway.
 */
const OBVIOUS = new Set([
  'password', 'password1', 'passw0rd', 'letmein', 'welcome', 'admin', 'administrator',
  'qwerty', '12345678', '123456789', 'iloveyou', 'changeme', 'neveroff', 'neveroff1',
]);

export function assertPasswordAcceptable(password: string, context: { email: string; displayName: string }): void {
  if (password.length < 12) {
    throw validationFailed('Password must be at least 12 characters.');
  }
  if (password.length > 200) {
    throw validationFailed('Password must be at most 200 characters.');
  }

  const lowered = password.toLowerCase();

  if (OBVIOUS.has(lowered)) {
    throw validationFailed('That password appears on every breach list. Choose another.');
  }

  const localPart = context.email.split('@')[0]?.toLowerCase() ?? '';
  if (localPart.length >= 3 && lowered.includes(localPart)) {
    throw validationFailed('Password must not contain your email address.');
  }

  const nameParts = context.displayName.toLowerCase().split(/\s+/).filter((p) => p.length >= 3);
  if (nameParts.some((part) => lowered.includes(part))) {
    throw validationFailed('Password must not contain your name.');
  }

  // Catches "aaaaaaaaaaaa" and "abababababab" — long but trivially guessable.
  if (new Set(password).size < 5) {
    throw validationFailed('Password is too repetitive. Use a longer, more varied passphrase.');
  }
}
