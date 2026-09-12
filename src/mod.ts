/**
 * revocable-jwt — stateless access tokens you can actually revoke.
 *
 * Reference implementation. Read it, take the parts you need, understand the
 * trade-offs it documents. See README before importing it into anything that
 * holds real accounts.
 */

export { AuthError, type AuthErrorCode, isAuthError } from "./errors.ts";

export {
  bearerFrom,
  hmacSha256Hex,
  sha256Hex,
  type SignableClaims,
  signToken,
  timingSafeEqualHex,
  type TokenClaims,
  type VerifyOptions,
  verifySignature,
} from "./jwt.ts";

export {
  createRefreshToken,
  type IssuedSession,
  issueSession,
  revokeAllSessions,
  rotateSession,
  type SessionContext,
  type TokenConfig,
  verifyAccessToken,
} from "./tokens.ts";

export {
  consumeOtp,
  generateCode,
  hashCode,
  issueOtp,
  type OtpConfig,
  verifyOtp,
} from "./otp.ts";

export {
  clientAddress,
  DEFAULT_RULES,
  enforceRateLimit,
  type RateLimitRule,
} from "./ratelimit.ts";

export { type CredentialHasher, pbkdf2Hasher, verifyCredential } from "./credentials.ts";

export type {
  AuthStore,
  NewOtp,
  NewRefreshToken,
  RateLimitDecision,
  StoredOtp,
  StoredRefreshToken,
  UserAuthState,
} from "./store.ts";
