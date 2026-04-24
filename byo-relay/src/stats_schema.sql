-- BYO usage statistics schema (version 1).
-- Embedded via include_str!("stats_schema.sql") in stats.rs.
-- WAL + synchronous=NORMAL + busy_timeout=5000 are set by StatsStore::open().

CREATE TABLE IF NOT EXISTS schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '1');

-- Workhorse counter table.  Every scalar metric folds into here.
-- PK = (date, kind, provider, error_class, share_variant) → one row per distinct
-- combination per day.  Unknown / empty dimensions are stored as ''.
CREATE TABLE IF NOT EXISTS counters (
  bucket_date   TEXT    NOT NULL,        -- 'YYYY-MM-DD' UTC
  event_kind    TEXT    NOT NULL,        -- vault_unlock|vault_lock|vault_save|
                                         -- upload|download|error|
                                         -- share_create|share_resolve|share_revoke|
                                         -- relay_bandwidth_sftp|relay_bandwidth_share
  provider_type TEXT    NOT NULL DEFAULT '',
  error_class   TEXT    NOT NULL DEFAULT '',
  share_variant TEXT    NOT NULL DEFAULT '',
  count         INTEGER NOT NULL DEFAULT 0,
  bytes_sum     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket_date, event_kind, provider_type, error_class, share_variant)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_counters_date ON counters(bucket_date);

-- Provider-mix dedup: one row per (day, device, provider) — INSERT OR IGNORE.
-- device_id_hash is HMAC-SHA256(STATS_HMAC_KEY, device_id): 32 bytes.
CREATE TABLE IF NOT EXISTS device_day_provider (
  bucket_date    TEXT NOT NULL,
  device_id_hash BLOB NOT NULL,
  provider_type  TEXT NOT NULL,
  PRIMARY KEY (bucket_date, device_id_hash, provider_type)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_ddp_date_prov
  ON device_day_provider(bucket_date, provider_type);

-- Vault-size histogram: one row per (day, device, provider).
-- INSERT OR REPLACE: latest snapshot per day wins.
CREATE TABLE IF NOT EXISTS device_day_size (
  bucket_date       TEXT    NOT NULL,
  device_id_hash    BLOB    NOT NULL,
  provider_type     TEXT    NOT NULL,
  file_count_bucket INTEGER NOT NULL,   -- floor(log2(max(1, file_count)))
  vault_size_bucket INTEGER NOT NULL,   -- floor(log2(max(1, ciphertext_bytes)))
  PRIMARY KEY (bucket_date, device_id_hash, provider_type)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_dds_date ON device_day_size(bucket_date);
