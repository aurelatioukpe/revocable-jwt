/**
 * Session lifecycle: issue, verify, rotate, revoke.
 *
 * The pairing this module implements is the point of the library:
 *
 *   · a short-lived ACCESS token, stateless, carrying a `tv` claim;
 *   · a long-lived REFRESH token, opaque, single-use, stored as a hash.
 *
 * `tv` gives O(1) revocation of every token a user holds. The refresh table
 * gives per-session control. Neither alone is enough — see README.
 */

import { AuthError } from "./errors.ts";
import {
  sha256Hex,
  signToken,
  type TokenClaims,
  type VerifyOptions,
  verifySignature,
} from "./jwt.ts";
import type { AuthStore } from "./store.ts";

export interface TokenConfig {
  /** HMAC secret for access tokens. At least 32 bytes. */
  secret: string;
  accessTtlSeconds: number;
  refreshTtlSeconds: number;
  /** Entropy of the opaque refresh token. 32 bytes is already generous. */
  refreshTokenBytes?: number;
  clockToleranceSeconds?: number;
  /** Override the clock. Tests only. */
  now?: () => number;
}

export interface IssuedSession {
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: Date;
  refreshExpiresAt: Date;
}

export interface SessionContext {
  userAgent?: string | null;
  ipAddress?: string | null;
}

const DEFAULT_REFRESH_TOKEN_BYTES = 32;

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * An opaque, high-entropy refresh token.
 *
 * Deliberately not a JWT. A refresh token is looked up in storage on every
 * use, so it gains nothing from being self-describing — and a JWT here would
 * leak its claims to anyone who reads the client's storage.
 */
export function createRefreshToken(bytes = DEFAULT_REFRESH_TOKEN_BYTES): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

/**
 * Issue a fresh pair for an already-authenticated identity.
 *
 * Callers are responsible for having verified a credential first. This is the
 * step both `login` and `register` end with.
 */
export async function issueSession(
  store: AuthStore,
  config: TokenConfig,
  userId: string,
  extraClaims: Record<string, unknown> = {},
  context: SessionContext = {},
): Promise<IssuedSession> {
  const now = config.now ?? Date.now;

  const user = await store.getUserAuthState(userId);
  if (!user) {
    throw new AuthError("INVALID_CREDENTIALS", { detail: "unknown user at issue" });
  }

  const accessToken = await signToken(
    { ...extraClaims, sub: userId, tv: user.tokenVersion },
    config.secret,
    config.accessTtlSeconds,
    now,
  );

  const refreshToken = createRefreshToken(config.refreshTokenBytes);
  const refreshExpiresAt = new Date(now() + config.refreshTtlSeconds * 1000);

  await store.insertRefreshToken({
    userId,
    tokenHash: await sha256Hex(refreshToken),
    tokenVersion: user.tokenVersion,
    expiresAt: refreshExpiresAt,
    userAgent: context.userAgent ?? null,
    ipAddress: context.ipAddress ?? null,
  });

  return {
    accessToken,
    refreshToken,
    accessExpiresAt: new Date(now() + config.accessTtlSeconds * 1000),
    refreshExpiresAt,
  };
}

/**
 * Verify an access token, including revocation.
 *
 * Two checks, in this order:
 *   1. signature and time claims — cryptography, no I/O;
 *   2. `tv` against the stored version — one indexed read.
 *
 * The store is a required argument rather than an optional one. That is a
 * deliberate API choice: an optional store makes "forgot to pass it" a silent
 * downgrade to no revocation at all, and the call still returns a valid-looking
 * identity. Here, skipping revocation is not expressible.
 *
 * Fails closed on a missing user: if the row is gone, the token is rejected.
 */
export async function verifyAccessToken(
  token: string,
  store: AuthStore,
  config: Pick<TokenConfig, "secret" | "clockToleranceSeconds" | "now">,
): Promise<TokenClaims> {
  const verifyOptions: VerifyOptions = {
    clockToleranceSeconds: config.clockToleranceSeconds,
    now: config.now,
  };

  const claims = await verifySignature(token, config.secret, verifyOptions);

  const user = await store.getUserAuthState(claims.sub);
  if (!user) {
    throw new AuthError("TOKEN_REVOKED", { detail: "user no longer exists" });
  }
  if (user.tokenVersion !== claims.tv) {
    throw new AuthError("TOKEN_REVOKED", {
      detail: `tv ${claims.tv} != stored ${user.tokenVersion}`,
    });
  }

  return claims;
}

/**
 * Exchange a refresh token for a new pair, invalidating the old one.
 *
 * Rotation is what makes a 90-day refresh token defensible: the window in
 * which a stolen token is useful ends the moment either party uses it.
 *
 * The consume step is atomic and its result is the authorisation. If two
 * requests race with the same token, exactly one gets `true`; the loser is
 * rejected rather than silently issued a second live session.
 *
 * Note what is NOT done here: detecting reuse of an already-consumed token and
 * revoking the whole family. That is the stricter posture, and it is one query
 * away — see README, "What this does not do".
 */
export async function rotateSession(
  refreshToken: string,
  store: AuthStore,
  config: TokenConfig,
  extraClaims: Record<string, unknown> = {},
  context: SessionContext = {},
): Promise<IssuedSession> {
  const now = config.now ?? Date.now;
  const nowDate = new Date(now());

  const presentedHash = await sha256Hex(refreshToken);
  const stored = await store.findRefreshTokenByHash(presentedHash);

  // One message for "no such token", "already used" and "expired". The client
  // has the same recourse in all three cases — log in again — and telling them
  // apart only helps someone probing stolen tokens.
  if (!stored) {
    throw new AuthError("SESSION_INVALID", { detail: "unknown refresh token" });
  }
  if (stored.revokedAt !== null) {
    throw new AuthError("SESSION_INVALID", { detail: "refresh token already consumed" });
  }
  if (stored.expiresAt <= nowDate) {
    throw new AuthError("SESSION_INVALID", { detail: "refresh token expired" });
  }

  const user = await store.getUserAuthState(stored.userId);
  if (!user) {
    throw new AuthError("SESSION_INVALID", { detail: "user no longer exists" });
  }

  // A refresh token issued before a global revocation is dead too. Without
  // this check, `tv` would only stop access tokens, and a holder could mint a
  // current one from a stale refresh token.
  if (user.tokenVersion !== stored.tokenVersion) {
    await store.consumeRefreshToken(stored.id, "", nowDate);
    throw new AuthError("SESSION_INVALID", { detail: "refresh token predates revocation" });
  }

  const nextRefreshToken = createRefreshToken(config.refreshTokenBytes);
  const nextRefreshHash = await sha256Hex(nextRefreshToken);

  const consumed = await store.consumeRefreshToken(stored.id, nextRefreshHash, nowDate);
  if (!consumed) {
    // Lost the race against a concurrent refresh. The winner holds the new
    // pair; issuing another here would leave two live sessions from one token.
    throw new AuthError("SESSION_INVALID", { detail: "concurrent rotation lost" });
  }

  const accessToken = await signToken(
    { ...extraClaims, sub: user.userId, tv: user.tokenVersion },
    config.secret,
    config.accessTtlSeconds,
    now,
  );

  const refreshExpiresAt = new Date(now() + config.refreshTtlSeconds * 1000);
  await store.insertRefreshToken({
    userId: user.userId,
    tokenHash: nextRefreshHash,
    tokenVersion: user.tokenVersion,
    expiresAt: refreshExpiresAt,
    userAgent: context.userAgent ?? null,
    ipAddress: context.ipAddress ?? null,
  });

  return {
    accessToken,
    refreshToken: nextRefreshToken,
    accessExpiresAt: new Date(now() + config.accessTtlSeconds * 1000),
    refreshExpiresAt,
  };
}

/**
 * Revoke everything a user holds, everywhere, at once.
 *
 * Bumping the version invalidates outstanding access tokens without touching
 * them — they carry the old number and will fail their next verification. The
 * refresh rows are revoked in the same breath so nothing can be exchanged for
 * a new pair in the meantime.
 *
 * Call this on: password or PIN change, "sign out of all devices", suspected
 * compromise, role downgrade, and account deactivation.
 */
export async function revokeAllSessions(
  store: AuthStore,
  userId: string,
  now: () => number = Date.now,
): Promise<number> {
  const nextVersion = await store.bumpTokenVersion(userId);
  await store.revokeAllRefreshTokens(userId, new Date(now()));
  return nextVersion;
}
