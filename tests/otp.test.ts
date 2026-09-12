import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { MemoryAuthStore } from "../adapters/memory/store.ts";
import { AuthError } from "../src/errors.ts";
import { consumeOtp, generateCode, issueOtp, verifyOtp } from "../src/otp.ts";
import { pbkdf2Hasher, verifyCredential } from "../src/credentials.ts";

const OTP_CONFIG = { secret: "o".repeat(32), ttlSeconds: 180, maxAttempts: 3 };
const PHONE = "+22900000000";

Deno.test("codes are the requested length and numeric", () => {
  for (let i = 0; i < 200; i += 1) {
    const code = generateCode(6);
    assertEquals(code.length, 6);
    assertEquals(/^\d{6}$/.test(code), true);
  }
});

Deno.test("codes are spread across the range, not clustered", () => {
  // A weak smoke test for modulo bias and for a broken generator: with 2000
  // draws over a million values, every leading digit should appear, and no
  // single one should take more than a third of the sample.
  const leading = new Map<string, number>();
  for (let i = 0; i < 2000; i += 1) {
    const digit = generateCode(6)[0];
    leading.set(digit, (leading.get(digit) ?? 0) + 1);
  }
  assertEquals(leading.size, 10);
  for (const count of leading.values()) {
    assertEquals(count < 2000 / 3, true);
  }
});

Deno.test("the plaintext code never reaches storage", async () => {
  const store = new MemoryAuthStore();
  const { code } = await issueOtp(store, OTP_CONFIG, PHONE);

  const stored = await store.findOtpByIdentifier(PHONE);
  assertEquals(stored?.codeHash.includes(code), false);
  assertEquals(stored?.codeHash.length, 64); // hex SHA-256
});

Deno.test("the right code verifies, then can be consumed once", async () => {
  const store = new MemoryAuthStore();
  const { code } = await issueOtp(store, OTP_CONFIG, PHONE);

  await verifyOtp(store, OTP_CONFIG, PHONE, code);
  await consumeOtp(store, PHONE);

  // Second consume: this is the replay that turns one verified code into two
  // account creations when the check is a read instead of an atomic delete.
  const error = await assertRejects(() => consumeOtp(store, PHONE), AuthError);
  assertEquals(error.code, "OTP_NOT_VERIFIED");
});

Deno.test("an unverified code cannot be consumed", async () => {
  const store = new MemoryAuthStore();
  await issueOtp(store, OTP_CONFIG, PHONE);

  const error = await assertRejects(() => consumeOtp(store, PHONE), AuthError);
  assertEquals(error.code, "OTP_NOT_VERIFIED");
});

Deno.test("wrong codes burn attempts, and the ceiling destroys the code", async () => {
  const store = new MemoryAuthStore();
  const { code } = await issueOtp(store, OTP_CONFIG, PHONE);
  const wrong = code === "000000" ? "111111" : "000000";

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const error = await assertRejects(
      () => verifyOtp(store, OTP_CONFIG, PHONE, wrong),
      AuthError,
    );
    assertEquals(error.code, "OTP_INCORRECT");
  }

  // Fourth try: the record is gone rather than merely locked, so the correct
  // code no longer works either. Leaving an exhausted row in place would let
  // an attacker pin the identifier by blocking new issues.
  const exhausted = await assertRejects(
    () => verifyOtp(store, OTP_CONFIG, PHONE, code),
    AuthError,
  );
  assertEquals(exhausted.code, "OTP_ATTEMPTS_EXCEEDED");

  assertEquals(await store.findOtpByIdentifier(PHONE), null);
});

Deno.test("an expired code is refused and cleaned up", async () => {
  const issuedAt = Date.now();
  const store = new MemoryAuthStore(() => issuedAt);
  const { code } = await issueOtp(store, { ...OTP_CONFIG, now: () => issuedAt }, PHONE);

  const error = await assertRejects(
    () => verifyOtp(store, { ...OTP_CONFIG, now: () => issuedAt + 200_000 }, PHONE, code),
    AuthError,
  );
  assertEquals(error.code, "OTP_EXPIRED");
  assertEquals(await store.findOtpByIdentifier(PHONE), null);
});

Deno.test("a verified code expires before it is consumed", async () => {
  const issuedAt = Date.now();
  const store = new MemoryAuthStore(() => issuedAt);
  const { code } = await issueOtp(store, { ...OTP_CONFIG, now: () => issuedAt }, PHONE);

  await verifyOtp(store, { ...OTP_CONFIG, now: () => issuedAt }, PHONE, code);

  // Verification does not freeze the clock: a flow that stalls past the TTL
  // has to start over.
  const error = await assertRejects(
    () => consumeOtp(store, PHONE, () => issuedAt + 200_000),
    AuthError,
  );
  assertEquals(error.code, "OTP_NOT_VERIFIED");
});

Deno.test("a code hash is bound to its identifier", async () => {
  const store = new MemoryAuthStore();
  const { code } = await issueOtp(store, OTP_CONFIG, PHONE);
  await issueOtp(store, OTP_CONFIG, "+22999999999");

  // The same digits sent to another identifier must not validate, even though
  // the code space is small enough that collisions are routine.
  const error = await assertRejects(
    () => verifyOtp(store, OTP_CONFIG, "+22999999999", code),
    AuthError,
  );
  assertEquals(["OTP_INCORRECT", "OTP_NOT_FOUND"].includes(error.code), true);
});

Deno.test("credentials verify, and reject the wrong secret", async () => {
  const stored = await pbkdf2Hasher.hash("1234");

  assertEquals((await verifyCredential(pbkdf2Hasher, "1234", stored)).valid, true);
  assertEquals((await verifyCredential(pbkdf2Hasher, "4321", stored)).valid, false);
  assertEquals(pbkdf2Hasher.needsRehash(stored), false);
});

Deno.test("an identity with no credential fails without short-circuiting", async () => {
  const result = await verifyCredential(pbkdf2Hasher, "1234", null);
  assertEquals(result.valid, false);
});

Deno.test("a hash from a weaker policy is flagged for upgrade", () => {
  assertEquals(pbkdf2Hasher.needsRehash("pbkdf2$sha256$1000$aabb$ccdd"), true);
  assertEquals(pbkdf2Hasher.needsRehash("$2b$10$legacybcryptvalue"), true);
  assertEquals(pbkdf2Hasher.needsRehash("garbage"), true);
});
