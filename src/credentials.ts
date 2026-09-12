/**
 * Long-lived secrets: passwords, and the short PINs that replace them where
 * typing a password on a phone is the thing that loses you the user.
 *
 * Unlike a one-time code, this hash sits in the database for years. Here the
 * work factor is the defence, and it has to hurt.
 *
 * The default below is PBKDF2-HMAC-SHA256, because it is the only password KDF
 * WebCrypto exposes and this library carries no dependencies. It is not the
 * best available: **prefer argon2id, or scrypt, if you can take a dependency**.
 * `CredentialHasher` exists so you can swap it without touching anything else.
 */

import { timingSafeEqualHex } from "./jwt.ts";

export interface CredentialHasher {
  hash(secret: string): Promise<string>;
  /** Must tolerate any format this hasher has ever produced. */
  verify(secret: string, stored: string): Promise<boolean>;
  /**
   * True when `stored` was produced with parameters weaker than current
   * policy, so the caller can transparently re-hash on next successful login.
   */
  needsRehash(stored: string): boolean;
}

const PBKDF2_ITERATIONS = 210_000; // OWASP guidance for PBKDF2-HMAC-SHA256.
const SALT_BYTES = 16;
const KEY_BITS = 256;

const encoder = new TextEncoder();

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function derive(secret: string, salt: Uint8Array, iterations: number): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    key,
    KEY_BITS,
  );
  return toHex(new Uint8Array(bits));
}

/**
 * Encoded as `pbkdf2$sha256$<iterations>$<salt hex>$<hash hex>`.
 *
 * The parameters travel with the hash so that raising the iteration count
 * later does not lock out every existing user — old hashes still verify under
 * their own settings, and `needsRehash` flags them for upgrade.
 */
export const pbkdf2Hasher: CredentialHasher = {
  async hash(secret: string): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const digest = await derive(secret, salt, PBKDF2_ITERATIONS);
    return `pbkdf2$sha256$${PBKDF2_ITERATIONS}$${toHex(salt)}$${digest}`;
  },

  async verify(secret: string, stored: string): Promise<boolean> {
    const parts = stored.split("$");
    if (parts.length !== 5 || parts[0] !== "pbkdf2" || parts[1] !== "sha256") return false;

    const iterations = Number.parseInt(parts[2], 10);
    if (!Number.isFinite(iterations) || iterations <= 0) return false;

    const digest = await derive(secret, fromHex(parts[3]), iterations);
    return timingSafeEqualHex(digest, parts[4]);
  },

  needsRehash(stored: string): boolean {
    const parts = stored.split("$");
    if (parts.length !== 5 || parts[0] !== "pbkdf2") return true;
    return Number.parseInt(parts[2], 10) < PBKDF2_ITERATIONS;
  },
};

/**
 * Verify a credential and report whether the stored hash should be upgraded.
 *
 * The upgrade path matters more than it looks. Systems accrete hash formats —
 * a weak early scheme, then bcrypt, then something current — and the only
 * moment you hold the plaintext is a successful login. Re-hashing there
 * migrates the population without a reset email to every user.
 *
 * Two rules when you add a legacy branch here:
 *   · verify the legacy format in constant time as well;
 *   · never let "stored hash is in an unknown format" fall through to success.
 */
export async function verifyCredential(
  hasher: CredentialHasher,
  secret: string,
  stored: string | null | undefined,
): Promise<{ valid: boolean; shouldRehash: boolean }> {
  if (!stored) {
    // Still spend the time. Returning instantly for an identity with no
    // credential set tells an attacker that the identity exists but is
    // unconfigured — and how long a real verification takes.
    await hasher.hash(secret);
    return { valid: false, shouldRehash: false };
  }

  const valid = await hasher.verify(secret, stored);
  return { valid, shouldRehash: valid && hasher.needsRehash(stored) };
}
