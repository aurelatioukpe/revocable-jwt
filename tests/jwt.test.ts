import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { AuthError } from "../src/errors.ts";
import { bearerFrom, signToken, verifySignature } from "../src/jwt.ts";

const SECRET = "a".repeat(32);

function encodeSegment(value: unknown): string {
  return btoa(JSON.stringify(value))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

Deno.test("round-trips claims and sets iat/exp", async () => {
  const token = await signToken({ sub: "user_1", tv: 3, role: "admin" }, SECRET, 60);
  const claims = await verifySignature(token, SECRET);

  assertEquals(claims.sub, "user_1");
  assertEquals(claims.tv, 3);
  assertEquals(claims.role, "admin");
  assertEquals(claims.exp - claims.iat, 60);
});

Deno.test("rejects a token signed with a different secret", async () => {
  const token = await signToken({ sub: "user_1", tv: 1 }, SECRET, 60);
  const error = await assertRejects(
    () => verifySignature(token, "b".repeat(32)),
    AuthError,
  );
  assertEquals(error.code, "INVALID_TOKEN");
});

Deno.test("rejects alg: none — the unsigned-token attack", async () => {
  // An attacker strips the signature and claims the token needs none. A
  // verifier that reads `alg` from the header and dispatches on it accepts
  // this. We pin HS256 before touching the signature, so it never gets there.
  const header = encodeSegment({ alg: "none", typ: "JWT" });
  const payload = encodeSegment({
    sub: "admin",
    tv: 1,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 600,
  });

  const error = await assertRejects(
    () => verifySignature(`${header}.${payload}.`, SECRET),
    AuthError,
  );
  assertEquals(error.code, "INVALID_TOKEN");
});

Deno.test("rejects an algorithm downgrade to RS256", async () => {
  // The mirror image: a verifier that trusts the header would try to validate
  // an asymmetric signature, and in the classic bug validates it with the
  // public key treated as an HMAC secret.
  const header = encodeSegment({ alg: "RS256", typ: "JWT" });
  const payload = encodeSegment({
    sub: "admin",
    tv: 1,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 600,
  });

  await assertRejects(
    () => verifySignature(`${header}.${payload}.signature`, SECRET),
    AuthError,
  );
});

Deno.test("rejects a payload edited after signing", async () => {
  const token = await signToken({ sub: "user_1", tv: 1 }, SECRET, 60);
  const [header, , signature] = token.split(".");
  const forged = encodeSegment({
    sub: "user_2",
    tv: 1,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60,
  });

  const error = await assertRejects(
    () => verifySignature(`${header}.${forged}.${signature}`, SECRET),
    AuthError,
  );
  assertEquals(error.code, "INVALID_TOKEN");
});

Deno.test("rejects an expired token, and honours clock tolerance", async () => {
  const issuedAt = Date.now();
  const token = await signToken({ sub: "user_1", tv: 1 }, SECRET, 60, () => issuedAt);

  // 61s later: past exp, but inside the default 30s tolerance.
  const claims = await verifySignature(token, SECRET, { now: () => issuedAt + 61_000 });
  assertEquals(claims.sub, "user_1");

  // 100s later: past exp and past tolerance.
  const error = await assertRejects(
    () => verifySignature(token, SECRET, { now: () => issuedAt + 100_000 }),
    AuthError,
  );
  assertEquals(error.code, "TOKEN_EXPIRED");
});

Deno.test("refuses a secret shorter than the MAC output", async () => {
  const error = await assertRejects(
    () => signToken({ sub: "user_1", tv: 1 }, "too-short", 60),
    AuthError,
  );
  assertEquals(error.code, "MISCONFIGURED");
});

Deno.test("requires sub and tv", async () => {
  const now = Math.floor(Date.now() / 1000);
  const header = encodeSegment({ alg: "HS256", typ: "JWT" });

  // Correctly signed, but missing tv: without it there is nothing to compare
  // against stored state, so revocation would silently not apply.
  const payload = encodeSegment({ sub: "user_1", iat: now, exp: now + 60 });
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${header}.${payload}`)),
  );
  const encoded = btoa(String.fromCharCode(...signature))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const error = await assertRejects(
    () => verifySignature(`${header}.${payload}.${encoded}`, SECRET),
    AuthError,
  );
  assertEquals(error.code, "INVALID_TOKEN");
});

Deno.test("parses bearer headers and ignores anything else", () => {
  assertEquals(bearerFrom("Bearer abc.def.ghi"), "abc.def.ghi");
  assertEquals(bearerFrom("bearer abc.def.ghi"), "abc.def.ghi");
  assertEquals(bearerFrom("Basic dXNlcjpwYXNz"), null);
  assertEquals(bearerFrom(null), null);
  assertEquals(bearerFrom(""), null);
});
