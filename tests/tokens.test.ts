import { assertEquals, assertNotEquals, assertRejects } from "jsr:@std/assert@1";
import { MemoryAuthStore } from "../adapters/memory/store.ts";
import { AuthError } from "../src/errors.ts";
import {
  issueSession,
  revokeAllSessions,
  rotateSession,
  verifyAccessToken,
} from "../src/tokens.ts";

const CONFIG = {
  secret: "s".repeat(32),
  accessTtlSeconds: 600,
  refreshTtlSeconds: 86_400,
};

function setup() {
  const store = new MemoryAuthStore();
  const user = store.createUser("+22900000000");
  return { store, userId: user.userId };
}

Deno.test("an issued access token verifies", async () => {
  const { store, userId } = setup();
  const session = await issueSession(store, CONFIG, userId, { role: "parent" });

  const claims = await verifyAccessToken(session.accessToken, store, CONFIG);
  assertEquals(claims.sub, userId);
  assertEquals(claims.role, "parent");
  assertEquals(claims.tv, 1);
});

Deno.test("bumping the token version kills a live access token", async () => {
  const { store, userId } = setup();
  const session = await issueSession(store, CONFIG, userId);

  // Valid right up to the bump.
  await verifyAccessToken(session.accessToken, store, CONFIG);

  await revokeAllSessions(store, userId);

  // The token itself is untouched and its signature still checks out — it is
  // the version comparison that now fails. This is the whole mechanism.
  const error = await assertRejects(
    () => verifyAccessToken(session.accessToken, store, CONFIG),
    AuthError,
  );
  assertEquals(error.code, "TOKEN_REVOKED");
});

Deno.test("a deleted user's token stops working", async () => {
  const { store, userId } = setup();
  const session = await issueSession(store, CONFIG, userId);

  store.deleteUser(userId);

  // Fail closed. A verifier that treats "no such row" as "nothing to compare"
  // keeps honouring tokens for accounts that no longer exist.
  const error = await assertRejects(
    () => verifyAccessToken(session.accessToken, store, CONFIG),
    AuthError,
  );
  assertEquals(error.code, "TOKEN_REVOKED");
});

Deno.test("rotation issues a new pair and burns the old refresh token", async () => {
  const { store, userId } = setup();
  const first = await issueSession(store, CONFIG, userId);

  const second = await rotateSession(first.refreshToken, store, CONFIG);
  assertNotEquals(second.refreshToken, first.refreshToken);

  await verifyAccessToken(second.accessToken, store, CONFIG);

  const error = await assertRejects(
    () => rotateSession(first.refreshToken, store, CONFIG),
    AuthError,
  );
  assertEquals(error.code, "SESSION_INVALID");
});

Deno.test("two concurrent rotations of one token: exactly one wins", async () => {
  const { store, userId } = setup();
  const session = await issueSession(store, CONFIG, userId);

  const results = await Promise.allSettled([
    rotateSession(session.refreshToken, store, CONFIG),
    rotateSession(session.refreshToken, store, CONFIG),
  ]);

  const fulfilled = results.filter((r) => r.status === "fulfilled");
  const rejected = results.filter((r) => r.status === "rejected");

  // The atomic consume is what makes this a guarantee rather than a race the
  // scheduler usually happens to win.
  assertEquals(fulfilled.length, 1);
  assertEquals(rejected.length, 1);
  assertEquals(store.liveRefreshTokenCount(userId), 1);
});

Deno.test("a refresh token predating a revocation cannot mint a new pair", async () => {
  const { store, userId } = setup();
  const session = await issueSession(store, CONFIG, userId);

  await revokeAllSessions(store, userId);

  // Without the version check on refresh, `tv` would stop access tokens only,
  // and the holder of a stale refresh token could mint a current one.
  const error = await assertRejects(
    () => rotateSession(session.refreshToken, store, CONFIG),
    AuthError,
  );
  assertEquals(error.code, "SESSION_INVALID");
});

Deno.test("an expired refresh token is refused", async () => {
  const store = new MemoryAuthStore();
  const { userId } = store.createUser("+22911111111");
  const issuedAt = Date.now();

  const session = await issueSession(
    store,
    { ...CONFIG, refreshTtlSeconds: 60, now: () => issuedAt },
    userId,
  );

  const error = await assertRejects(
    () =>
      rotateSession(session.refreshToken, store, {
        ...CONFIG,
        now: () => issuedAt + 120_000,
      }),
    AuthError,
  );
  assertEquals(error.code, "SESSION_INVALID");
});

Deno.test("an unknown refresh token is refused like a spent one", async () => {
  const { store } = setup();

  // Same code and message for unknown, spent and expired: telling them apart
  // is an oracle for anyone testing stolen tokens.
  const error = await assertRejects(
    () => rotateSession("not-a-real-token", store, CONFIG),
    AuthError,
  );
  assertEquals(error.code, "SESSION_INVALID");
});

Deno.test("revoking all sessions closes every device at once", async () => {
  const { store, userId } = setup();
  const phone = await issueSession(store, CONFIG, userId, {}, { userAgent: "phone" });
  const tablet = await issueSession(store, CONFIG, userId, {}, { userAgent: "tablet" });

  assertEquals(store.liveRefreshTokenCount(userId), 2);

  await revokeAllSessions(store, userId);

  assertEquals(store.liveRefreshTokenCount(userId), 0);
  for (const session of [phone, tablet]) {
    await assertRejects(() => verifyAccessToken(session.accessToken, store, CONFIG), AuthError);
    await assertRejects(() => rotateSession(session.refreshToken, store, CONFIG), AuthError);
  }
});

Deno.test("a new session after revocation carries the new version", async () => {
  const { store, userId } = setup();
  await issueSession(store, CONFIG, userId);

  const version = await revokeAllSessions(store, userId);
  assertEquals(version, 2);

  const fresh = await issueSession(store, CONFIG, userId);
  const claims = await verifyAccessToken(fresh.accessToken, store, CONFIG);
  assertEquals(claims.tv, 2);
});
