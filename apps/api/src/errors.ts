/**
 * Typed API errors.
 *
 * Two rules that matter more than the shapes:
 *
 *   1. An authorisation failure never reveals whether the target exists. A
 *      Tier 3 moderator probing user IDs they cannot see must get the same
 *      response whether the ID is real or invented, otherwise the 403/404 split
 *      becomes an enumeration oracle. `forbidden()` is therefore what scope
 *      failures return, and lookups outside scope raise it too rather than 404.
 *
 *   2. Error messages are written for the admin reading them at 3am. "Requires
 *      users.ban.permanent" beats "Forbidden".
 */

export type ErrorCode =
  | 'unauthenticated'
  | 'mfa_required'
  | 'forbidden'
  | 'out_of_scope'
  | 'not_found'
  | 'validation_failed'
  | 'conflict'
  | 'break_glass_required'
  | 'break_glass_invalid'
  | 'rate_limited'
  | 'legal_hold'
  | 'not_implemented'
  | 'internal';

export class ApiError extends Error {
  readonly statusCode: number;
  readonly code: ErrorCode;
  readonly details?: Record<string, unknown>;
  /** Set when the failure is itself security-relevant and must be alerted on. */
  readonly securityEvent?: string;

  constructor(
    statusCode: number,
    code: ErrorCode,
    message: string,
    options: { details?: Record<string, unknown>; securityEvent?: string } = {},
  ) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = options.details;
    this.securityEvent = options.securityEvent;
  }

  toResponse(): { error: { code: ErrorCode; message: string; details?: Record<string, unknown> } } {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.details ? { details: this.details } : {}),
      },
    };
  }
}

export const unauthenticated = (message = 'Sign in to continue.'): ApiError =>
  new ApiError(401, 'unauthenticated', message);

export const mfaRequired = (message = 'Two-factor authentication is required.'): ApiError =>
  new ApiError(401, 'mfa_required', message);

export const forbidden = (
  message: string,
  details?: Record<string, unknown>,
  securityEvent?: string,
): ApiError => new ApiError(403, 'forbidden', message, { details, securityEvent });

export const outOfScope = (): ApiError =>
  new ApiError(403, 'out_of_scope', 'That record is outside your assigned scope.');

export const notFound = (what = 'Record'): ApiError =>
  new ApiError(404, 'not_found', `${what} not found.`);

export const validationFailed = (
  message: string,
  details?: Record<string, unknown>,
): ApiError => new ApiError(422, 'validation_failed', message, { details });

export const conflict = (message: string, details?: Record<string, unknown>): ApiError =>
  new ApiError(409, 'conflict', message, { details });

export const breakGlassRequired = (
  message: string,
  details: Record<string, unknown>,
): ApiError => new ApiError(428, 'break_glass_required', message, { details });

export const breakGlassInvalid = (message: string): ApiError =>
  new ApiError(400, 'break_glass_invalid', message);

export const underLegalHold = (message: string): ApiError =>
  new ApiError(423, 'legal_hold', message);

export const notImplemented = (message: string): ApiError =>
  new ApiError(501, 'not_implemented', message);

export function isApiError(err: unknown): err is ApiError {
  return err instanceof ApiError;
}
