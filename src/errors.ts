/**
 * Failure modes of the auth layer.
 *
 * Every path that can reject a caller returns one of these codes. They are
 * deliberately coarser than the internal reason: `INVALID_CREDENTIALS` covers
 * both "no such identity" and "wrong secret", because distinguishing them at
 * the API boundary hands an attacker an account-enumeration oracle.
 *
 * The internal reason still reaches the logs — see `AuthError.detail`.
 */
export type AuthErrorCode =
  | "INVALID_CREDENTIALS"
  | "INVALID_TOKEN"
  | "TOKEN_EXPIRED"
  | "TOKEN_REVOKED"
  | "SESSION_INVALID"
  | "OTP_NOT_FOUND"
  | "OTP_EXPIRED"
  | "OTP_INCORRECT"
  | "OTP_ATTEMPTS_EXCEEDED"
  | "OTP_NOT_VERIFIED"
  | "IDENTIFIER_TAKEN"
  | "RATE_LIMITED"
  | "MISCONFIGURED";

/** HTTP status that best matches each failure, for callers that speak HTTP. */
const HTTP_STATUS: Record<AuthErrorCode, number> = {
  INVALID_CREDENTIALS: 401,
  INVALID_TOKEN: 401,
  TOKEN_EXPIRED: 401,
  TOKEN_REVOKED: 401,
  SESSION_INVALID: 401,
  OTP_NOT_FOUND: 404,
  OTP_EXPIRED: 410,
  OTP_INCORRECT: 401,
  OTP_ATTEMPTS_EXCEEDED: 429,
  OTP_NOT_VERIFIED: 401,
  IDENTIFIER_TAKEN: 409,
  RATE_LIMITED: 429,
  MISCONFIGURED: 500,
};

export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly status: number;
  /** Operator-facing reason. Safe to log, never to return to the caller. */
  readonly detail?: string;
  /** Seconds to wait, set on RATE_LIMITED. */
  readonly retryAfterSeconds?: number;

  constructor(
    code: AuthErrorCode,
    options: { detail?: string; retryAfterSeconds?: number } = {},
  ) {
    super(code);
    this.name = "AuthError";
    this.code = code;
    this.status = HTTP_STATUS[code];
    this.detail = options.detail;
    this.retryAfterSeconds = options.retryAfterSeconds;
  }

  /**
   * The shape safe to send over the wire. `detail` is deliberately absent.
   */
  toPublicJSON(): { error: AuthErrorCode; retryAfterSeconds?: number } {
    return this.retryAfterSeconds === undefined
      ? { error: this.code }
      : { error: this.code, retryAfterSeconds: this.retryAfterSeconds };
  }
}

export function isAuthError(value: unknown): value is AuthError {
  return value instanceof AuthError;
}
