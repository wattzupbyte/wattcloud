-- Restricted enrollment schema (version 1).
-- Embedded via include_str!("enrollment_schema.sql") in enrollment.rs.
-- WAL + synchronous=NORMAL + busy_timeout=5000 are set by EnrollmentStore::open().
--
-- Phase 1 lays down the tables + a schema_meta row. Phase 2 wires the actual
-- endpoints that read/write them. Putting the schema in now keeps migrations
-- additive and lets the restricted-mode /relay/info handler answer truthfully
-- about whether a bootstrap has happened.

CREATE TABLE IF NOT EXISTS schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '1');

-- Authorized devices — one row per device that may act against this relay
-- when WATTCLOUD_ENROLLMENT_MODE=restricted. `is_owner=1` gates admin actions
-- (invite mint, device revoke). `last_seen_hour` is bucketed to UTC hour to
-- avoid fine-grained timing metadata (matches the stats-hash privacy posture).
CREATE TABLE IF NOT EXISTS authorized_devices (
  device_id       TEXT    PRIMARY KEY,      -- UUID v4
  pubkey          BLOB    NOT NULL UNIQUE,  -- ed25519 (32B); reserved for phase 2
  label           TEXT    NOT NULL DEFAULT '',
  is_owner        INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,         -- unix secs
  last_seen_hour  INTEGER NOT NULL,         -- floor(unix_secs / 3600)
  revoked_at      INTEGER                   -- NULL = active; non-NULL = revoked
);

-- Invite codes — mint by an owner, consume by an invitee at /relay/admin/redeem.
-- `code_hash` is HMAC-SHA256(relay_signing_key, code_bytes); the plaintext code
-- is only ever transported inside the one-time reveal modal. Single-use:
-- `used_by` + `used_at` are set atomically on first successful redemption.
CREATE TABLE IF NOT EXISTS invite_codes (
  id          TEXT    PRIMARY KEY,           -- UUID v4
  code_hash   BLOB    NOT NULL UNIQUE,
  label       TEXT    NOT NULL DEFAULT '',
  issued_by   TEXT    NOT NULL,              -- device_id of an owner
  created_at  INTEGER NOT NULL,              -- unix secs
  expires_at  INTEGER NOT NULL,              -- unix secs
  used_by     TEXT,                          -- device_id of the redeemer
  used_at     INTEGER,                       -- unix secs
  FOREIGN KEY (issued_by) REFERENCES authorized_devices(device_id)
);

CREATE INDEX IF NOT EXISTS idx_invites_expires_at ON invite_codes(expires_at);

-- Bootstrap token — at most one row, ever. Generated on first start in
-- restricted mode when `authorized_devices` is empty, consumed by the owner
-- via /relay/admin/claim, then wiped. `id` check enforces singleton.
CREATE TABLE IF NOT EXISTS bootstrap_token (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  token_hash  BLOB    NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
