/**
 * The storage port.
 *
 * Everything this library persists goes through this interface. Implement it
 * over whatever you already run — Postgres, MySQL, SQLite, DynamoDB — and the
 * auth logic is unchanged. A reference Postgres schema lives in
 * `adapters/postgres/schema.sql`.
 *
 * Two methods carry the security of the whole system and MUST be atomic:
 *
 *   · `consumeRefreshToken` — must succeed for exactly one caller when two
 *     requests present the same refresh token concurrently.
 *   · `consumeVerifiedOtp`  — same, for a verified one-time code.
 *
 * Implementing either as read-then-write leaves a race that turns a
 * single-use credential into a reusable one. In SQL, both are a single
 * conditional `UPDATE`/`DELETE ... RETURNING`; the row count is the answer.
 */

/** Auth-relevant state of an identity. Never include the credential hash. */
export interface UserAuthState {
  userId: string;
  /**
   * Monotonic counter. Bumping it invalidates every access token and refresh
   * token issued before the bump.
   */
  tokenVersion: number;
}

export interface NewRefreshToken {
  userId: string;
  /** SHA-256 of the token. The token itself is never stored. */
  tokenHash: string;
  tokenVersion: number;
  expiresAt: Date;
  /** Optional session provenance, for a "your sessions" screen. */
  userAgent?: string | null;
  ipAddress?: string | null;
}

export interface StoredRefreshToken {
  id: string;
  userId: string;
  tokenVersion: number;
  expiresAt: Date;
  revokedAt: Date | null;
}

export interface NewOtp {
  /** Phone number, email, or whatever you send the code to. */
  identifier: string;
  /** Keyed hash of the code. The code itself is never stored. */
  codeHash: string;
  expiresAt: Date;
}

export interface StoredOtp {
  id: string;
  identifier: string;
  codeHash: string;
  expiresAt: Date;
  attempts: number;
  verified: boolean;
}

export interface RateLimitDecision {
  allowed: boolean;
  /** Hits recorded in the current window, this one included. */
  currentCount: number;
  remaining: number;
  /** Seconds until the window rolls over. Zero when allowed. */
  retryAfterSeconds: number;
}

export interface AuthStore {
  // ---- identities -------------------------------------------------------

  /**
   * Returns null when the identity does not exist. Verification treats null as
   * a rejection, so deleting a user immediately invalidates their tokens.
   */
  getUserAuthState(userId: string): Promise<UserAuthState | null>;

  /** Increments and returns the new token version. */
  bumpTokenVersion(userId: string): Promise<number>;

  // ---- refresh tokens ---------------------------------------------------

  insertRefreshToken(record: NewRefreshToken): Promise<void>;

  findRefreshTokenByHash(tokenHash: string): Promise<StoredRefreshToken | null>;

  /**
   * Atomically mark a refresh token as consumed.
   *
   * MUST return true for at most one caller. Returning true twice for the same
   * token id defeats rotation entirely.
   *
   * SQL shape:
   *   UPDATE refresh_tokens
   *      SET revoked_at = $now, replaced_by_hash = $next
   *    WHERE id = $id AND revoked_at IS NULL
   *  RETURNING id;
   */
  consumeRefreshToken(
    id: string,
    replacedByHash: string,
    now: Date,
  ): Promise<boolean>;

  /** Revoke every live refresh token of a user. Used on credential change. */
  revokeAllRefreshTokens(userId: string, now: Date): Promise<void>;

  // ---- one-time codes ---------------------------------------------------

  /** Replaces any pending code for the same identifier. */
  putOtp(record: NewOtp): Promise<void>;

  findOtpByIdentifier(identifier: string): Promise<StoredOtp | null>;

  incrementOtpAttempts(id: string): Promise<void>;

  markOtpVerified(id: string): Promise<void>;

  deleteOtp(id: string): Promise<void>;

  /**
   * Atomically consume a code that has already been marked verified.
   *
   * MUST return true for at most one caller, and only when the row is both
   * verified and unexpired. This is what stops a verified code from being
   * replayed into two account creations.
   *
   * SQL shape:
   *   DELETE FROM otp_codes
   *    WHERE identifier = $id AND verified = true AND expires_at > $now
   *  RETURNING id;
   */
  consumeVerifiedOtp(identifier: string, now: Date): Promise<boolean>;

  // ---- rate limiting ----------------------------------------------------

  /**
   * Record one hit against `key` and report whether it is allowed.
   *
   * MUST be atomic across processes — an in-memory counter in a serverless
   * runtime limits one warm instance, not your endpoint. See the SQL function
   * in the reference adapter.
   */
  hitRateLimit(
    key: string,
    windowSeconds: number,
    maxHits: number,
  ): Promise<RateLimitDecision>;
}
