/**
 * In-memory AuthStore. For tests and for reading the interface in one page.
 *
 * NOT for production, and not only for the obvious reason that it forgets
 * everything on restart: it is atomic solely because JavaScript runs one task
 * at a time. Across two processes, none of the guarantees below hold. The
 * reason the Postgres adapter pushes `consumeRefreshToken`, `consumeVerifiedOtp`
 * and the limiter into single SQL statements is that the runtime stops doing
 * this work for you the moment there is more than one of you.
 */

import type {
  AuthStore,
  NewOtp,
  NewRefreshToken,
  RateLimitDecision,
  StoredOtp,
  StoredRefreshToken,
  UserAuthState,
} from "../../src/store.ts";

interface RefreshRow extends StoredRefreshToken {
  tokenHash: string;
  replacedByHash: string | null;
  lastUsedAt: Date | null;
}

interface CounterRow {
  hits: number;
  windowStart: number;
  windowEnd: number;
}

export class MemoryAuthStore implements AuthStore {
  readonly users = new Map<
    string,
    UserAuthState & { identifier: string; credentialHash: string | null }
  >();
  private readonly refreshTokens = new Map<string, RefreshRow>();
  private readonly otps = new Map<string, StoredOtp>();
  private readonly counters = new Map<string, CounterRow>();
  private sequence = 0;

  constructor(private readonly now: () => number = Date.now) {}

  private nextId(prefix: string): string {
    this.sequence += 1;
    return `${prefix}_${this.sequence}`;
  }

  // ---- test helpers -------------------------------------------------------

  createUser(identifier: string, credentialHash: string | null = null): UserAuthState {
    const userId = this.nextId("user");
    const state = { userId, tokenVersion: 1, identifier, credentialHash };
    this.users.set(userId, state);
    return { userId, tokenVersion: 1 };
  }

  findUserByIdentifier(identifier: string) {
    for (const user of this.users.values()) {
      if (user.identifier === identifier) return user;
    }
    return null;
  }

  setCredentialHash(userId: string, hash: string): void {
    const user = this.users.get(userId);
    if (user) user.credentialHash = hash;
  }

  deleteUser(userId: string): void {
    this.users.delete(userId);
  }

  // ---- identities ---------------------------------------------------------

  getUserAuthState(userId: string): Promise<UserAuthState | null> {
    const user = this.users.get(userId);
    return Promise.resolve(
      user ? { userId: user.userId, tokenVersion: user.tokenVersion } : null,
    );
  }

  bumpTokenVersion(userId: string): Promise<number> {
    const user = this.users.get(userId);
    if (!user) return Promise.resolve(0);
    user.tokenVersion += 1;
    return Promise.resolve(user.tokenVersion);
  }

  // ---- refresh tokens -----------------------------------------------------

  insertRefreshToken(record: NewRefreshToken): Promise<void> {
    const id = this.nextId("rt");
    this.refreshTokens.set(id, {
      id,
      userId: record.userId,
      tokenHash: record.tokenHash,
      tokenVersion: record.tokenVersion,
      expiresAt: record.expiresAt,
      revokedAt: null,
      replacedByHash: null,
      lastUsedAt: null,
    });
    return Promise.resolve();
  }

  findRefreshTokenByHash(tokenHash: string): Promise<StoredRefreshToken | null> {
    for (const row of this.refreshTokens.values()) {
      if (row.tokenHash === tokenHash) {
        return Promise.resolve({
          id: row.id,
          userId: row.userId,
          tokenVersion: row.tokenVersion,
          expiresAt: row.expiresAt,
          revokedAt: row.revokedAt,
        });
      }
    }
    return Promise.resolve(null);
  }

  consumeRefreshToken(id: string, replacedByHash: string, now: Date): Promise<boolean> {
    const row = this.refreshTokens.get(id);
    // The `revokedAt === null` guard is the whole point — it is the in-memory
    // equivalent of `WHERE revoked_at IS NULL` in the UPDATE.
    if (!row || row.revokedAt !== null) return Promise.resolve(false);
    row.revokedAt = now;
    row.lastUsedAt = now;
    row.replacedByHash = replacedByHash || null;
    return Promise.resolve(true);
  }

  revokeAllRefreshTokens(userId: string, now: Date): Promise<void> {
    for (const row of this.refreshTokens.values()) {
      if (row.userId === userId && row.revokedAt === null) {
        row.revokedAt = now;
        row.lastUsedAt = now;
      }
    }
    return Promise.resolve();
  }

  liveRefreshTokenCount(userId: string): number {
    let count = 0;
    for (const row of this.refreshTokens.values()) {
      if (row.userId === userId && row.revokedAt === null) count += 1;
    }
    return count;
  }

  // ---- one-time codes -----------------------------------------------------

  putOtp(record: NewOtp): Promise<void> {
    this.otps.set(record.identifier, {
      id: this.nextId("otp"),
      identifier: record.identifier,
      codeHash: record.codeHash,
      expiresAt: record.expiresAt,
      attempts: 0,
      verified: false,
    });
    return Promise.resolve();
  }

  findOtpByIdentifier(identifier: string): Promise<StoredOtp | null> {
    return Promise.resolve(this.otps.get(identifier) ?? null);
  }

  incrementOtpAttempts(id: string): Promise<void> {
    for (const row of this.otps.values()) {
      if (row.id === id) row.attempts += 1;
    }
    return Promise.resolve();
  }

  markOtpVerified(id: string): Promise<void> {
    for (const row of this.otps.values()) {
      if (row.id === id) row.verified = true;
    }
    return Promise.resolve();
  }

  deleteOtp(id: string): Promise<void> {
    for (const [key, row] of this.otps) {
      if (row.id === id) this.otps.delete(key);
    }
    return Promise.resolve();
  }

  consumeVerifiedOtp(identifier: string, now: Date): Promise<boolean> {
    const row = this.otps.get(identifier);
    if (!row || !row.verified || row.expiresAt <= now) return Promise.resolve(false);
    this.otps.delete(identifier);
    return Promise.resolve(true);
  }

  // ---- rate limiting ------------------------------------------------------

  hitRateLimit(
    key: string,
    windowSeconds: number,
    maxHits: number,
  ): Promise<RateLimitDecision> {
    const nowMs = this.now();
    const windowStart = Math.floor(nowMs / 1000 / windowSeconds) * windowSeconds * 1000;
    const windowEnd = windowStart + windowSeconds * 1000;
    const bucketKey = `${key}:${windowSeconds}:${windowStart}`;

    const existing = this.counters.get(bucketKey);
    const hits = existing ? existing.hits + 1 : 1;
    this.counters.set(bucketKey, { hits, windowStart, windowEnd });

    const allowed = hits <= maxHits;
    return Promise.resolve({
      allowed,
      currentCount: hits,
      remaining: Math.max(maxHits - hits, 0),
      retryAfterSeconds: allowed ? 0 : Math.max(1, Math.ceil((windowEnd - nowMs) / 1000)),
    });
  }
}
