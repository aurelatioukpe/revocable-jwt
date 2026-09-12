/**
 * The whole flow, wired up. Run it, curl it, read it — it is the fastest way
 * to see how the pieces fit.
 *
 *   deno run --allow-net --allow-env examples/server.ts
 *
 * It uses the in-memory store, so everything vanishes on restart, and it
 * prints one-time codes to the console instead of sending them. Both are
 * stand-ins for the two things you must supply yourself: a real store, and a
 * delivery channel.
 */

import { MemoryAuthStore } from "../adapters/memory/store.ts";
import {
  AuthError,
  bearerFrom,
  clientAddress,
  consumeOtp,
  DEFAULT_RULES,
  enforceRateLimit,
  isAuthError,
  issueOtp,
  issueSession,
  pbkdf2Hasher,
  revokeAllSessions,
  rotateSession,
  verifyAccessToken,
  verifyCredential,
  verifyOtp,
} from "../src/mod.ts";

const JWT_SECRET = Deno.env.get("AUTH_JWT_SECRET") ?? "dev-only-secret-of-at-least-32-bytes!!";
const OTP_SECRET = Deno.env.get("AUTH_OTP_SECRET") ?? "dev-only-otp-secret-32-bytes-minimum!!";

const tokenConfig = {
  secret: JWT_SECRET,
  accessTtlSeconds: 15 * 60,
  refreshTtlSeconds: 30 * 24 * 3600,
};
const otpConfig = { secret: OTP_SECRET, digits: 6, ttlSeconds: 180, maxAttempts: 3 };

const store = new MemoryAuthStore();

/**
 * Stand-in for your SMS or email provider.
 *
 * Two rules wherever you implement this for real:
 *   · never log the code — this line is a placeholder, not a pattern;
 *   · distinguish failure reasons. "Invalid number" is the caller's mistake,
 *     "no credit" is an operational emergency, "provider down" is transient
 *     and worth a retry. Collapsing them into one error makes an outage
 *     undiagnosable from the logs.
 *
 * And if delivery fails, delete the pending code before answering. Reporting
 * success for a code that never left leaves the user waiting for a message
 * that is not coming, and blocks them from requesting another.
 */
function deliverCode(identifier: string, code: string): Promise<boolean> {
  console.log(`[dev] code for ${identifier}: ${code}`);
  return Promise.resolve(true);
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });

function fail(error: unknown): Response {
  if (isAuthError(error)) {
    // The detail goes to the operator; the caller gets the code alone.
    if (error.detail) console.warn(`[auth] ${error.code}: ${error.detail}`);
    return json(error.toPublicJSON(), error.status);
  }
  console.error("[auth] unhandled", error);
  return json({ error: "INTERNAL" }, 500);
}

async function handler(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const address = clientAddress(request.headers);
  const body = request.method === "POST" ? await request.json().catch(() => ({})) : {};

  try {
    switch (`${request.method} ${url.pathname}`) {
      // ---- 1. ask for a code ---------------------------------------------
      case "POST /auth/otp": {
        const identifier = String(body.identifier ?? "");
        if (!identifier) return json({ error: "IDENTIFIER_REQUIRED" }, 400);

        // Before issuing, not after. Every code costs money to send, and an
        // unlimited issue endpoint is both an enumeration oracle and a way to
        // drain your gateway balance.
        await enforceRateLimit(store, DEFAULT_RULES.otpIssue, identifier, address);

        const { code } = await issueOtp(store, otpConfig, identifier);

        if (!await deliverCode(identifier, code)) {
          const pending = await store.findOtpByIdentifier(identifier);
          if (pending) await store.deleteOtp(pending.id);
          return json({ error: "DELIVERY_FAILED" }, 502);
        }

        // The same answer whether or not the identifier is known. Anything
        // else turns this endpoint into a membership check.
        return json({ ok: true });
      }

      // ---- 2. prove you received it --------------------------------------
      case "POST /auth/otp/verify": {
        const identifier = String(body.identifier ?? "");
        await enforceRateLimit(store, DEFAULT_RULES.otpVerify, identifier, address);
        await verifyOtp(store, otpConfig, identifier, String(body.code ?? ""));
        return json({ ok: true });
      }

      // ---- 3. create an account ------------------------------------------
      case "POST /auth/register": {
        const identifier = String(body.identifier ?? "");
        const secret = String(body.pin ?? "");
        if (!identifier || !/^\d{4,6}$/.test(secret)) {
          return json({ error: "INVALID_INPUT" }, 400);
        }

        // Spending the verified code IS the authorisation to proceed. Reading
        // a `verified` flag and acting on it separately lets two concurrent
        // requests both pass, and one proven identifier becomes two accounts.
        await consumeOtp(store, identifier);

        if (store.findUserByIdentifier(identifier)) {
          return json({ error: "IDENTIFIER_TAKEN" }, 409);
        }

        const created = store.createUser(identifier);
        store.setCredentialHash(created.userId, await pbkdf2Hasher.hash(secret));

        const session = await issueSession(
          store,
          tokenConfig,
          created.userId,
          { role: "user" },
          { userAgent: request.headers.get("user-agent"), ipAddress: address },
        );
        return json(session, 201);
      }

      // ---- 4. log in -------------------------------------------------------
      case "POST /auth/login": {
        const identifier = String(body.identifier ?? "");
        const secret = String(body.pin ?? "");
        await enforceRateLimit(store, DEFAULT_RULES.login, identifier, address);

        const user = store.findUserByIdentifier(identifier);
        const check = await verifyCredential(pbkdf2Hasher, secret, user?.credentialHash);

        // One answer for "no such identity" and "wrong secret", and the same
        // amount of work done in both cases.
        if (!user || !check.valid) {
          throw new AuthError("INVALID_CREDENTIALS", { detail: "login rejected" });
        }

        // The only moment the plaintext is in hand. Upgrade the stored hash
        // here and a population migrates itself, with no reset email.
        if (check.shouldRehash) {
          store.setCredentialHash(user.userId, await pbkdf2Hasher.hash(secret));
        }

        const session = await issueSession(
          store,
          tokenConfig,
          user.userId,
          { role: "user" },
          { userAgent: request.headers.get("user-agent"), ipAddress: address },
        );
        return json(session);
      }

      // ---- 5. stay logged in ---------------------------------------------
      case "POST /auth/refresh": {
        // Public, and it accepts a bearer secret — so it needs a limiter as
        // much as login does. Keyed on the address: whoever presents an
        // unrecognised token has no identity yet.
        await enforceRateLimit(store, DEFAULT_RULES.refresh, address, address);

        const session = await rotateSession(
          String(body.refreshToken ?? ""),
          store,
          tokenConfig,
          { role: "user" },
          { userAgent: request.headers.get("user-agent"), ipAddress: address },
        );
        return json(session);
      }

      // ---- 6. a protected route -------------------------------------------
      case "GET /me": {
        const token = bearerFrom(request.headers.get("authorization"));
        if (!token) return json({ error: "INVALID_TOKEN" }, 401);

        const claims = await verifyAccessToken(token, store, tokenConfig);
        return json({ userId: claims.sub, role: claims.role, tokenVersion: claims.tv });
      }

      // ---- 7. sign out everywhere -----------------------------------------
      case "POST /auth/revoke-all": {
        const token = bearerFrom(request.headers.get("authorization"));
        if (!token) return json({ error: "INVALID_TOKEN" }, 401);

        const claims = await verifyAccessToken(token, store, tokenConfig);
        const version = await revokeAllSessions(store, claims.sub);

        // The caller's own token is dead as of this response — including the
        // one that authorised the call.
        return json({ ok: true, tokenVersion: version });
      }

      default:
        return json({ error: "NOT_FOUND" }, 404);
    }
  } catch (error) {
    return fail(error);
  }
}

if (import.meta.main) {
  console.log("listening on http://localhost:8000");
  console.log('try: curl -XPOST localhost:8000/auth/otp -d \'{"identifier":"+22900000000"}\'');
  Deno.serve({ port: 8000 }, handler);
}

export { handler };
