/**
 * One-time codes.
 *
 * Sized for the constraint that matters: a numeric code a person reads off a
 * lock screen and types with a thumb. That caps the entropy at roughly 20 bits,
 * so the security does not come from the code — it comes from the attempt
 * ceiling and the short life. Everything here follows from that.
 */

import { AuthError } from "./errors.ts";
import { hmacSha256Hex, timingSafeEqualHex } from "./jwt.ts";
import type { AuthStore } from "./store.ts";

export interface OtpConfig {
  /**
   * Secret keying the stored code hashes. Separate from the JWT secret: they
   * have different rotation schedules and different blast radii.
   */
  secret: string;
  digits?: number;
  ttlSeconds?: number;
  maxAttempts?: number;
  /** Override the clock. Tests only. */
  now?: () => number;
}

const DEFAULT_DIGITS = 6;
const DEFAULT_TTL_SECONDS = 180;
const DEFAULT_MAX_ATTEMPTS = 3;

/**
 * A uniformly distributed numeric code.
 *
 * `Math.random()` is unusable here: it is not a CSPRNG, and its internal state
 * is recoverable from a handful of observed outputs — an attacker who can
 * request codes to a number they control could then predict codes issued to
 * numbers they do not.
 *
 * Rejection sampling avoids modulo bias. Taking `value % 10**digits` over the
 * full 32-bit range would make the lowest codes marginally more likely, since
 * the range does not divide evenly; we discard draws past the last whole
 * multiple instead.
 */
export function generateCode(digits = DEFAULT_DIGITS): string {
  if (digits < 4 || digits > 9) {
    throw new AuthError("MISCONFIGURED", { detail: "digits must be 4..9" });
  }
  const range = 10 ** digits;
  const ceiling = Math.floor(0xffffffff / range) * range;

  const buffer = new Uint32Array(1);
  let draw: number;
  do {
    crypto.getRandomValues(buffer);
    draw = buffer[0];
  } while (draw >= ceiling);

  return String(draw % range).padStart(digits, "0");
}

/**
 * Hash a code for storage, keyed to both the server secret and the identifier.
 *
 * Why a keyed hash rather than bcrypt or argon2: the search space is a million
 * values, so no work factor makes brute force impractical — a cost high enough
 * to matter would be high enough to make your own verification a denial of
 * service. The attempt counter is the real defence. What the hash must do is
 * stop a leaked database from handing over every code in flight, and a keyed
 * HMAC does that without a dependency.
 *
 * Binding the identifier into the input means a hash lifted from one row
 * cannot be replayed against another.
 */
export function hashCode(code: string, identifier: string, secret: string): Promise<string> {
  return hmacSha256Hex(`${identifier}:${code}`, secret);
}

/**
 * Create and store a code. Returns the plaintext so the caller can send it —
 * this library does not know or care about your delivery channel.
 *
 * The caller is responsible for rate limiting before calling this. Issuing a
 * code costs money on every SMS gateway, and an unlimited issue endpoint is
 * both an account-enumeration oracle and a way to run your balance to zero.
 */
export async function issueOtp(
  store: AuthStore,
  config: OtpConfig,
  identifier: string,
): Promise<{ code: string; expiresAt: Date }> {
  const now = config.now ?? Date.now;
  const code = generateCode(config.digits ?? DEFAULT_DIGITS);
  const expiresAt = new Date(now() + (config.ttlSeconds ?? DEFAULT_TTL_SECONDS) * 1000);

  await store.putOtp({
    identifier,
    codeHash: await hashCode(code, identifier, config.secret),
    expiresAt,
  });

  return { code, expiresAt };
}

/**
 * Check a submitted code and, on success, mark it verified.
 *
 * Verification and consumption are two steps on purpose. A user verifies once,
 * then completes a flow — register, reset a credential — that may take several
 * seconds and can fail for unrelated reasons. Deleting the code on verification
 * would force them back through delivery on every such failure. The code is
 * spent later, atomically, by `consumeVerifiedOtp`.
 */
export async function verifyOtp(
  store: AuthStore,
  config: OtpConfig,
  identifier: string,
  submittedCode: string,
): Promise<void> {
  const now = config.now ?? Date.now;
  const maxAttempts = config.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;

  const record = await store.findOtpByIdentifier(identifier);
  if (!record) {
    throw new AuthError("OTP_NOT_FOUND");
  }

  if (record.expiresAt <= new Date(now())) {
    await store.deleteOtp(record.id);
    throw new AuthError("OTP_EXPIRED");
  }

  if (record.attempts >= maxAttempts) {
    // Burn it. Leaving an exhausted code in place lets an attacker keep the
    // identifier locked by never letting a fresh one be issued.
    await store.deleteOtp(record.id);
    throw new AuthError("OTP_ATTEMPTS_EXCEEDED");
  }

  const submitted = String(submittedCode).replace(/\D/g, "");
  const candidate = await hashCode(submitted, identifier, config.secret);

  if (!timingSafeEqualHex(candidate, record.codeHash)) {
    await store.incrementOtpAttempts(record.id);
    throw new AuthError("OTP_INCORRECT");
  }

  await store.markOtpVerified(record.id);
}

/**
 * Spend a verified code. Returns nothing and throws if there was none.
 *
 * Every flow that trusts "this identifier was proven" must call this, and must
 * treat its success as the authorisation. Checking `verified` with a read and
 * acting on it separately is the bug this exists to prevent: two concurrent
 * requests both read `verified = true`, and one verified code becomes two
 * account creations, or a credential reset plus a login.
 */
export async function consumeOtp(
  store: AuthStore,
  identifier: string,
  now: () => number = Date.now,
): Promise<void> {
  const consumed = await store.consumeVerifiedOtp(identifier, new Date(now()));
  if (!consumed) {
    throw new AuthError("OTP_NOT_VERIFIED");
  }
}
