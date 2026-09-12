-- Reference schema for the Postgres adapter.
--
-- Three tables and one function. The function is not a convenience: it is
-- where the rate limiter's atomicity lives, and doing it in application code
-- reintroduces the race it exists to close.

-- ---------------------------------------------------------------------------
-- Identities
-- ---------------------------------------------------------------------------
-- Your own users table almost certainly exists already. The only column this
-- library requires is token_version; add it to what you have rather than
-- adopting this table wholesale.

CREATE TABLE IF NOT EXISTS auth_users (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identifier     text NOT NULL UNIQUE,       -- phone, email, whatever you log in with
  credential_hash text,                      -- null until a credential is set
  -- Monotonic. Bumping it invalidates every token issued before the bump.
  -- NOT NULL with a default so that a row can never be ambiguous: a null here
  -- would have to be treated as "some version", and every such guess is a
  -- silent hole in revocation.
  token_version  integer NOT NULL DEFAULT 1,
  created_at     timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Refresh tokens
-- ---------------------------------------------------------------------------
-- One row per issued refresh token, alive or spent. Keeping spent rows is what
-- lets you detect reuse of a rotated token later; prune them on age, not on
-- use.

CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  -- SHA-256 of the token. The token itself never touches the database: a dump
  -- of this table must not be a set of live credentials.
  token_hash      text NOT NULL UNIQUE,
  -- The version current when this token was issued. Compared on every refresh
  -- so a global revocation kills refresh tokens too, not just access tokens.
  token_version   integer NOT NULL DEFAULT 1,
  expires_at      timestamptz NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_used_at    timestamptz,
  revoked_at      timestamptz,
  -- Hash of the token that replaced this one. Turns the table into a chain,
  -- which is what you walk to revoke a whole family on detected reuse.
  replaced_by_hash text,
  -- Provenance, for a "your active sessions" screen. Not used for decisions:
  -- both are client-supplied and neither is a second factor.
  user_agent      text,
  ip_address      text
);

CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_user
  ON auth_refresh_tokens (user_id);

-- Partial index: lookups only ever care about live rows, and spent ones
-- accumulate. Keeps the index proportional to active sessions, not to history.
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_live
  ON auth_refresh_tokens (expires_at)
  WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- One-time codes
-- ---------------------------------------------------------------------------
-- At most one pending code per identifier. The unique constraint is what makes
-- "issue a new code" a clean upsert instead of a delete-then-insert that can
-- interleave with a verification.

CREATE TABLE IF NOT EXISTS auth_otp_codes (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identifier  text NOT NULL UNIQUE,
  -- Keyed HMAC of the code, bound to the identifier. See src/otp.ts for why
  -- this is not bcrypt.
  code_hash   text NOT NULL,
  expires_at  timestamptz NOT NULL,
  attempts    integer NOT NULL DEFAULT 0,
  verified    boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_otp_codes_expires
  ON auth_otp_codes (expires_at);

-- ---------------------------------------------------------------------------
-- Rate limit counters
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS auth_rate_limit_counters (
  rate_key       text NOT NULL,
  window_seconds integer NOT NULL CHECK (window_seconds > 0),
  window_start   timestamptz NOT NULL,
  hits           integer NOT NULL DEFAULT 1 CHECK (hits >= 0),
  expires_at     timestamptz NOT NULL,
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (rate_key, window_seconds, window_start)
);

CREATE INDEX IF NOT EXISTS idx_auth_rate_limit_expires
  ON auth_rate_limit_counters (expires_at);

-- ---------------------------------------------------------------------------
-- The limiter
-- ---------------------------------------------------------------------------
-- Fixed window, incremented atomically.
--
-- INSERT ... ON CONFLICT DO UPDATE ... RETURNING is one statement, so the
-- read-modify-write happens under a row lock. The obvious application-level
-- version — SELECT the count, compare, UPDATE — lets N concurrent requests all
-- read the same value and all decide they are under the ceiling.
--
-- Fixed windows admit a burst of up to 2x the ceiling across a boundary. That
-- is acceptable for abuse control and is the reason this is a limiter and not
-- a quota. If you need the stricter guarantee, a sliding window over a small
-- ring of sub-windows is the next step up; it costs more rows and more reads.

CREATE OR REPLACE FUNCTION auth_check_rate_limit(
  p_key            text,
  p_window_seconds integer,
  p_max_hits       integer
)
RETURNS TABLE (
  allowed             boolean,
  current_count       integer,
  remaining           integer,
  retry_after_seconds integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_now          timestamptz := now();
  v_window_start timestamptz;
  v_window_end   timestamptz;
  v_hits         integer;
BEGIN
  IF p_key IS NULL OR length(trim(p_key)) = 0 THEN
    RAISE EXCEPTION 'p_key is required';
  END IF;
  IF p_window_seconds IS NULL OR p_window_seconds <= 0 THEN
    RAISE EXCEPTION 'p_window_seconds must be > 0';
  END IF;
  IF p_max_hits IS NULL OR p_max_hits <= 0 THEN
    RAISE EXCEPTION 'p_max_hits must be > 0';
  END IF;

  -- Align every caller onto the same window boundaries, so two processes
  -- counting the same key agree on which bucket they are in.
  v_window_start := to_timestamp(
    floor(extract(epoch FROM v_now) / p_window_seconds)::bigint * p_window_seconds
  );
  v_window_end := v_window_start + make_interval(secs => p_window_seconds);

  INSERT INTO auth_rate_limit_counters AS c
    (rate_key, window_seconds, window_start, hits, expires_at, updated_at)
  VALUES
    (p_key, p_window_seconds, v_window_start, 1, v_window_end, v_now)
  ON CONFLICT (rate_key, window_seconds, window_start) DO UPDATE
    SET hits = c.hits + 1, updated_at = EXCLUDED.updated_at
  RETURNING c.hits INTO v_hits;

  -- Opportunistic sweep. A scheduled job is cleaner; this keeps the table from
  -- growing without bound in deployments that have nowhere to put one.
  IF random() < 0.01 THEN
    DELETE FROM auth_rate_limit_counters
     WHERE expires_at < v_now - interval '1 hour';
  END IF;

  RETURN QUERY SELECT
    (v_hits <= p_max_hits),
    v_hits,
    greatest(p_max_hits - v_hits, 0),
    CASE WHEN v_hits <= p_max_hits THEN 0
         ELSE greatest(1, ceil(extract(epoch FROM (v_window_end - v_now)))::integer)
    END;
END;
$$;

-- Only the application role may call it. Left open, it is a write primitive
-- for anyone who can reach the database.
REVOKE ALL ON FUNCTION auth_check_rate_limit(text, integer, integer) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- The two statements that must stay atomic
-- ---------------------------------------------------------------------------
-- Reproduced here because they are the contract from src/store.ts, and because
-- the temptation to "simplify" them into a read plus a write is the single
-- most likely way to break this system.
--
--   consumeRefreshToken:
--     UPDATE auth_refresh_tokens
--        SET revoked_at = $3, last_used_at = $3, replaced_by_hash = $2
--      WHERE id = $1 AND revoked_at IS NULL
--    RETURNING id;
--     -- zero rows back means someone else already spent it. Reject.
--
--   consumeVerifiedOtp:
--     DELETE FROM auth_otp_codes
--      WHERE identifier = $1 AND verified = true AND expires_at > $2
--    RETURNING id;
--     -- zero rows back means unverified, expired, or already spent. Reject.
