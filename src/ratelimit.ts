/**
 * Rate limiting, on two axes at once.
 *
 * Limiting by identifier alone lets one host walk a list of numbers, a few
 * tries each, and never trip a counter. Limiting by IP alone punishes everyone
 * behind a shared NAT — which, in much of the world, is most of a city. Both
 * together bound the two attacks that matter: hammering one account, and
 * spraying many.
 *
 * The counters live in the store rather than in memory. In a serverless
 * runtime an in-process counter limits one warm instance, and the platform
 * will happily give an attacker a cold one.
 */

import { AuthError } from "./errors.ts";
import type { AuthStore } from "./store.ts";

export interface RateLimitRule {
  /** Namespace, normally the endpoint: "login", "otp:issue". */
  scope: string;
  windowSeconds: number;
  /** Ceiling for a single identifier — a phone number, an email. */
  maxPerIdentifier: number;
  /** Ceiling for a single source address. Set higher; NAT is real. */
  maxPerAddress: number;
}

/** Sensible starting points. Tune them against your own traffic, not a blog. */
export const DEFAULT_RULES = {
  /** Issuing a code costs money on every gateway. Keep this tight. */
  otpIssue: {
    scope: "otp:issue",
    windowSeconds: 900,
    maxPerIdentifier: 5,
    maxPerAddress: 10,
  },
  otpVerify: {
    scope: "otp:verify",
    windowSeconds: 900,
    maxPerIdentifier: 10,
    maxPerAddress: 10,
  },
  login: {
    scope: "login",
    windowSeconds: 900,
    maxPerIdentifier: 10,
    maxPerAddress: 20,
  },
  /**
   * Refresh is easy to forget: it is public, it accepts a bearer secret, and
   * rotation makes it a natural target for someone testing stolen tokens. The
   * key is the address — the holder of an unknown token has no identity yet.
   */
  refresh: {
    scope: "refresh",
    windowSeconds: 900,
    maxPerIdentifier: 60,
    maxPerAddress: 60,
  },
  credentialReset: {
    scope: "credential:reset",
    windowSeconds: 900,
    maxPerIdentifier: 5,
    maxPerAddress: 5,
  },
} as const satisfies Record<string, RateLimitRule>;

/**
 * Apply both axes. Throws `RATE_LIMITED` with a retry hint on the first breach.
 *
 * The identifier is checked first so that a legitimate user behind a saturated
 * address still learns their own limit is intact — and so that a wide spray
 * does not mask a targeted attack in the logs.
 */
export async function enforceRateLimit(
  store: AuthStore,
  rule: RateLimitRule,
  identifier: string,
  address: string | null | undefined,
): Promise<void> {
  const identifierDecision = await store.hitRateLimit(
    `${rule.scope}:id:${identifier}`,
    rule.windowSeconds,
    rule.maxPerIdentifier,
  );
  if (!identifierDecision.allowed) {
    throw new AuthError("RATE_LIMITED", {
      detail: `${rule.scope} identifier ceiling`,
      retryAfterSeconds: identifierDecision.retryAfterSeconds,
    });
  }

  const source = address?.trim() || "unknown";
  const addressDecision = await store.hitRateLimit(
    `${rule.scope}:ip:${source}`,
    rule.windowSeconds,
    rule.maxPerAddress,
  );
  if (!addressDecision.allowed) {
    throw new AuthError("RATE_LIMITED", {
      detail: `${rule.scope} address ceiling`,
      retryAfterSeconds: addressDecision.retryAfterSeconds,
    });
  }
}

/**
 * First address in an `X-Forwarded-For` chain.
 *
 * Trust this only behind a proxy that overwrites the header. Exposed directly,
 * it is caller-supplied and a limiter keyed on it limits nothing.
 */
export function clientAddress(headers: Headers): string {
  const forwarded = headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first;
  }
  return "unknown";
}
