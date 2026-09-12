/**
 * HS256 JWT, built on WebCrypto alone.
 *
 * There is no dependency here on purpose: the whole of JWT signing and
 * verification is roughly a hundred lines, and every runtime this library
 * targets — Deno, Node 18+, Bun, Cloudflare Workers — ships WebCrypto. A
 * library would add supply-chain surface for code you can read in one sitting.
 */

import { AuthError } from "./errors.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** What a caller supplies. `iat` and `exp` are set by `signToken`. */
export interface SignableClaims {
  /** Subject — the user id. */
  sub: string;
  /**
   * Token version. The revocation mechanism: it is compared against the
   * version stored on the user row at every verification. See README.
   */
  tv: number;
  /** Anything else you want in the token: role, scope, tenant. */
  [claim: string]: unknown;
}

/** A verified token's claims. */
export interface TokenClaims extends SignableClaims {
  /** Issued at, seconds since epoch. */
  iat: number;
  /** Expires at, seconds since epoch. */
  exp: number;
}

export interface VerifyOptions {
  /**
   * Tolerance in seconds for `exp` and `iat`, absorbing clock drift between
   * the signing and verifying hosts. Keep it small; it widens the window in
   * which an expired token is still accepted.
   */
  clockToleranceSeconds?: number;
  /** Override the clock. Tests only. */
  now?: () => number;
}

const DEFAULT_CLOCK_TOLERANCE_SECONDS = 30;

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="));
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function hmacKey(secret: string, usage: "sign" | "verify"): Promise<CryptoKey> {
  if (!secret) {
    throw new AuthError("MISCONFIGURED", { detail: "signing secret is empty" });
  }
  // 32 bytes is the output size of SHA-256; a shorter secret weakens the MAC
  // without any warning from the runtime, so refuse it here.
  if (encoder.encode(secret).length < 32) {
    throw new AuthError("MISCONFIGURED", {
      detail: "signing secret must be at least 32 bytes",
    });
  }
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    [usage],
  );
}

/**
 * Sign a set of claims. `iat` and `exp` are set here; anything already present
 * in `claims` is preserved, so callers can add `role`, `scope`, and so on.
 */
export async function signToken(
  claims: SignableClaims,
  secret: string,
  ttlSeconds: number,
  now: () => number = Date.now,
): Promise<string> {
  const issuedAt = Math.floor(now() / 1000);
  const payload: TokenClaims = {
    ...claims,
    iat: issuedAt,
    exp: issuedAt + ttlSeconds,
  };

  const header = base64urlEncode(
    encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })),
  );
  const body = base64urlEncode(encoder.encode(JSON.stringify(payload)));
  const signingInput = `${header}.${body}`;

  const key = await hmacKey(secret, "sign");
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, encoder.encode(signingInput)),
  );

  return `${signingInput}.${base64urlEncode(signature)}`;
}

/**
 * Verify a token's signature and time claims.
 *
 * This does NOT check revocation — a valid signature only proves the token was
 * issued by us and has not expired. Revocation lives in `verifyAccessToken`
 * (see tokens.ts), which additionally compares `tv` against stored state.
 * Splitting the two keeps the cryptographic step free of I/O, and makes it
 * impossible to check the signature while silently skipping revocation.
 */
export async function verifySignature(
  token: string,
  secret: string,
  options: VerifyOptions = {},
): Promise<TokenClaims> {
  const now = options.now ?? Date.now;
  const tolerance = options.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE_SECONDS;

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new AuthError("INVALID_TOKEN", { detail: "malformed token" });
  }
  const [headerB64, payloadB64, signatureB64] = parts;

  // Pin the algorithm before touching the signature. A verifier that trusts
  // the header's `alg` is the classic algorithm-confusion bug: `none` strips
  // the signature entirely, and an asymmetric algorithm can be downgraded to
  // HMAC using the public key as the shared secret. We accept exactly one.
  let header: { alg?: unknown; typ?: unknown };
  try {
    header = JSON.parse(decoder.decode(base64urlDecode(headerB64)));
  } catch {
    throw new AuthError("INVALID_TOKEN", { detail: "unreadable header" });
  }
  if (header.alg !== "HS256") {
    throw new AuthError("INVALID_TOKEN", { detail: `rejected alg ${String(header.alg)}` });
  }

  const key = await hmacKey(secret, "verify");
  // crypto.subtle.verify compares in constant time; do not reimplement this
  // with a string equality on a recomputed signature.
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    base64urlDecode(signatureB64),
    encoder.encode(`${headerB64}.${payloadB64}`),
  );
  if (!valid) {
    throw new AuthError("INVALID_TOKEN", { detail: "signature mismatch" });
  }

  let claims: TokenClaims;
  try {
    claims = JSON.parse(decoder.decode(base64urlDecode(payloadB64)));
  } catch {
    throw new AuthError("INVALID_TOKEN", { detail: "unreadable payload" });
  }

  if (typeof claims.sub !== "string" || !claims.sub) {
    throw new AuthError("INVALID_TOKEN", { detail: "missing sub" });
  }
  if (typeof claims.tv !== "number" || !Number.isFinite(claims.tv)) {
    throw new AuthError("INVALID_TOKEN", { detail: "missing tv" });
  }

  const nowSeconds = Math.floor(now() / 1000);
  if (typeof claims.exp !== "number" || nowSeconds >= claims.exp + tolerance) {
    throw new AuthError("TOKEN_EXPIRED", { detail: "exp elapsed" });
  }
  // A token issued in the future is either clock drift or a forged `iat`.
  if (typeof claims.iat === "number" && claims.iat - tolerance > nowSeconds) {
    throw new AuthError("INVALID_TOKEN", { detail: "iat in the future" });
  }

  return claims;
}

/** Extract a bearer token from an Authorization header. */
export function bearerFrom(header: string | null | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1].trim() : null;
}

/** SHA-256, hex encoded. Used for refresh-token lookup keys. */
export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/** HMAC-SHA256, hex encoded. Used to key OTP hashes to a server secret. */
export async function hmacSha256Hex(value: string, secret: string): Promise<string> {
  const key = await hmacKey(secret, "sign");
  const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return Array.from(new Uint8Array(mac))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/** Length-independent comparison for hex digests of equal expected length. */
export function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
