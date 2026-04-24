// byo-admin — CLI for BYO usage statistics + enrollment recovery.
//
// Usage:
//   byo-admin log   --granularity {daily|weekly|monthly|yearly}
//                   [--from YYYY-MM-DD] [--to YYYY-MM-DD]
//   byo-admin clear [--yes]
//   byo-admin regenerate-bootstrap-token
//                   [--enrollment-db PATH] [--token-path PATH]
//                   [--signing-key KEY | --signing-key-file PATH]
//                   [--ttl-secs N]
//
// Opens the relevant SQLite file directly (WAL, so concurrent reads do not
// block a running byo-relay).

use byo_relay::enrollment::EnrollmentStore;
use byo_relay::enrollment_admin::{
    generate_bootstrap_token, hash_bootstrap_token, BOOTSTRAP_TOKEN_FILE_DEFAULT,
};
use byo_relay::stats::StatsStore;
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "byo-admin",
    about = "BYO usage statistics + enrollment admin CLI"
)]
struct Cli {
    /// Path to the stats SQLite database.
    #[arg(
        long,
        env = "STATS_DB_PATH",
        default_value = "/var/lib/byo-relay/stats.sqlite3"
    )]
    db: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print aggregated usage statistics.
    Log {
        /// Time granularity: daily, weekly, monthly, yearly.
        #[arg(long, default_value = "daily")]
        granularity: String,

        /// Start date (inclusive), format YYYY-MM-DD.
        #[arg(long)]
        from: Option<String>,

        /// End date (inclusive), format YYYY-MM-DD.
        #[arg(long)]
        to: Option<String>,
    },
    /// Destructively wipe all stats rows (leaves schema intact).
    Clear {
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Mint a fresh bootstrap token so a new device can claim ownership.
    /// Existing owner devices are left alone — this is a non-destructive
    /// recovery path for an operator who's lost web access. Print the
    /// plaintext token to stdout; the HMAC hash goes to the enrollment DB.
    RegenerateBootstrapToken {
        /// Path to the enrollment SQLite DB.
        #[arg(
            long,
            env = "ENROLLMENT_DB_PATH",
            default_value = "/var/lib/byo-relay/enrollment.sqlite3"
        )]
        enrollment_db: PathBuf,

        /// Where to drop the plaintext token file (mode 0644). The relay's
        /// startup path writes the same file when it auto-mints at boot.
        #[arg(
            long,
            env = "BOOTSTRAP_TOKEN_PATH",
            default_value = BOOTSTRAP_TOKEN_FILE_DEFAULT
        )]
        token_path: PathBuf,

        /// HMAC signing key. Falls back to `--signing-key-file` which
        /// defaults to the env-driven RELAY_SIGNING_KEY if set.
        #[arg(long, env = "RELAY_SIGNING_KEY")]
        signing_key: Option<String>,

        /// Path to read the signing key from (alternative to --signing-key).
        #[arg(long)]
        signing_key_file: Option<PathBuf>,

        /// Token lifetime in seconds. Default 24 h.
        #[arg(long, default_value_t = 24 * 60 * 60)]
        ttl_secs: i64,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Log {
            granularity,
            from,
            to,
        } => {
            // Open read-only — log never mutates the database.
            let store = StatsStore::open_readonly(&cli.db).unwrap_or_else(|e| {
                eprintln!("error: cannot open {} (read-only): {e}", cli.db);
                std::process::exit(1);
            });
            cmd_log(&store, &granularity, from.as_deref(), to.as_deref());
        }
        Command::Clear { yes } => {
            let store = StatsStore::open(&cli.db).unwrap_or_else(|e| {
                eprintln!("error: cannot open {}: {e}", cli.db);
                std::process::exit(1);
            });
            cmd_clear(&store, yes);
        }
        Command::RegenerateBootstrapToken {
            enrollment_db,
            token_path,
            signing_key,
            signing_key_file,
            ttl_secs,
        } => {
            cmd_regenerate_bootstrap_token(
                &enrollment_db,
                &token_path,
                signing_key.as_deref(),
                signing_key_file.as_deref(),
                ttl_secs,
            );
        }
    }
}

// ── regenerate-bootstrap-token ────────────────────────────────────────────────

fn cmd_regenerate_bootstrap_token(
    enrollment_db: &std::path::Path,
    token_path: &std::path::Path,
    signing_key_inline: Option<&str>,
    signing_key_file: Option<&std::path::Path>,
    ttl_secs: i64,
) {
    // Resolve the signing key: inline > file. Same base64-first / raw-bytes
    // fallback as the relay's Config parser so operators don't have to
    // second-guess encoding.
    let signing_key =
        resolve_signing_key(signing_key_inline, signing_key_file).unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        });

    let store = EnrollmentStore::open(enrollment_db).unwrap_or_else(|e| {
        eprintln!(
            "error: cannot open enrollment DB {}: {e}",
            enrollment_db.display()
        );
        std::process::exit(1);
    });

    let token = generate_bootstrap_token();
    let hash = hash_bootstrap_token(&signing_key, &token);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let expires_at = now.saturating_add(ttl_secs);

    if let Err(e) = store.set_bootstrap_token(&hash, now, expires_at) {
        eprintln!("error: failed to persist bootstrap token: {e}");
        std::process::exit(1);
    }

    // Write the plaintext file for the claim-token wrapper to read (the
    // prod `/usr/local/bin/wattcloud` dispatcher or the dev Makefile's
    // `make claim-token` target — both just `cat` this file and `rm` it).
    // Best-effort: if the dir isn't writable (mis-configured service
    // user, read-only fs) fall back to stdout.
    if let Some(parent) = token_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    match std::fs::write(token_path, &token) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(token_path, std::fs::Permissions::from_mode(0o644));
            }
            println!("Bootstrap token minted: {}", token_path.display());
            println!();
            println!("Read + consume with either:");
            println!("  sudo wattcloud claim-token   (prod install)");
            println!("  make claim-token             (make dev / repo clone)");
        }
        Err(e) => {
            eprintln!(
                "warning: couldn't write {} ({e}) — printing token once below.",
                token_path.display()
            );
            println!();
            println!("{token}");
        }
    }
}

/// Read the signing key from inline arg, then file, then error.
/// Same base64 / raw-bytes fallback as the relay's own parser so a key
/// copy/pasted from `/etc/wattcloud/wattcloud.env` works either way.
fn resolve_signing_key(
    inline: Option<&str>,
    file: Option<&std::path::Path>,
) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let raw = match (inline, file) {
        (Some(s), _) if !s.is_empty() => s.to_string(),
        (_, Some(p)) => std::fs::read_to_string(p)
            .map_err(|e| format!("cannot read signing key from {}: {e}", p.display()))?,
        _ => {
            return Err(
                "signing key not provided; pass --signing-key, --signing-key-file, \
                 or set RELAY_SIGNING_KEY in the environment"
                    .to_string(),
            );
        }
    };

    let trimmed = raw.trim();
    let key = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .unwrap_or_else(|_| trimmed.as_bytes().to_vec());
    if key.len() < 32 {
        return Err(format!(
            "signing key must be at least 32 bytes (got {})",
            key.len()
        ));
    }
    Ok(key)
}

// ── log ───────────────────────────────────────────────────────────────────────

fn cmd_log(store: &StatsStore, granularity: &str, from: Option<&str>, to: Option<&str>) {
    let valid = ["daily", "weekly", "monthly", "yearly"];
    if !valid.contains(&granularity) {
        eprintln!("error: --granularity must be one of: daily, weekly, monthly, yearly");
        std::process::exit(1);
    }

    let counters = store
        .aggregate_counters(granularity, from, to)
        .unwrap_or_else(|e| {
            eprintln!("error: query failed: {e}");
            std::process::exit(1);
        });
    let mix = store
        .aggregate_provider_mix(granularity, from, to)
        .unwrap_or_else(|e| {
            eprintln!("error: query failed: {e}");
            std::process::exit(1);
        });

    if counters.is_empty() && mix.is_empty() {
        println!("No stats found for the given range.");
        return;
    }

    // ── Counters table ────────────────────────────────────────────────────────
    if !counters.is_empty() {
        println!("\n=== Event Counters ({granularity}) ===\n");

        let col_period = col_width(counters.iter().map(|r| r.period.as_str()), "Period");
        let col_kind = col_width(counters.iter().map(|r| r.event_kind.as_str()), "Event");
        let col_provider = col_width(
            counters.iter().map(|r| r.provider_type.as_str()),
            "Provider",
        );
        let col_error = col_width(counters.iter().map(|r| r.error_class.as_str()), "Error");
        let col_variant = col_width(counters.iter().map(|r| r.share_variant.as_str()), "Variant");

        print_row(
            col_period,
            col_kind,
            col_provider,
            col_error,
            col_variant,
            "Period",
            "Event",
            "Provider",
            "Error",
            "Variant",
            "Count",
            "Bytes",
        );
        print_sep(col_period, col_kind, col_provider, col_error, col_variant);

        for r in &counters {
            let bytes_fmt = format_bytes(r.bytes_sum as u64);
            print_row(
                col_period,
                col_kind,
                col_provider,
                col_error,
                col_variant,
                &r.period,
                &r.event_kind,
                &r.provider_type,
                &r.error_class,
                &r.share_variant,
                &r.count.to_string(),
                &bytes_fmt,
            );
        }
    }

    // ── Provider mix table ────────────────────────────────────────────────────
    if !mix.is_empty() {
        println!("\n=== Provider Mix ({granularity}) ===\n");

        let col_period = col_width(mix.iter().map(|r| r.period.as_str()), "Period");
        let col_provider = col_width(mix.iter().map(|r| r.provider_type.as_str()), "Provider");

        println!(
            "{:<col_period$}  {:<col_provider$}  {:>12}",
            "Period", "Provider", "Devices"
        );
        println!("{:-<col_period$}  {:-<col_provider$}  {:->12}", "", "", "");
        for r in &mix {
            println!(
                "{:<col_period$}  {:<col_provider$}  {:>12}",
                r.period, r.provider_type, r.device_count
            );
        }
    }

    println!();
}

fn col_width<'a>(values: impl Iterator<Item = &'a str>, header: &str) -> usize {
    values.map(|s| s.len()).max().unwrap_or(0).max(header.len())
}

#[allow(clippy::too_many_arguments)]
fn print_row(
    cp: usize,
    ck: usize,
    cv: usize,
    ce: usize,
    cv2: usize,
    period: &str,
    kind: &str,
    provider: &str,
    error: &str,
    variant: &str,
    count: &str,
    bytes: &str,
) {
    println!(
        "{:<cp$}  {:<ck$}  {:<cv$}  {:<ce$}  {:<cv2$}  {:>10}  {:>12}",
        period, kind, provider, error, variant, count, bytes
    );
}

fn print_sep(cp: usize, ck: usize, cv: usize, ce: usize, cv2: usize) {
    println!(
        "{:-<cp$}  {:-<ck$}  {:-<cv$}  {:-<ce$}  {:-<cv2$}  {:->10}  {:->12}",
        "", "", "", "", "", "", ""
    );
}

/// Human-readable byte size.
fn format_bytes(b: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    if b == 0 {
        return "-".to_string();
    }
    let mut val = b as f64;
    let mut unit_idx = 0;
    while val >= 1024.0 && unit_idx + 1 < UNITS.len() {
        val /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{b} B")
    } else {
        format!("{:.1} {}", val, UNITS[unit_idx])
    }
}

// ── clear ─────────────────────────────────────────────────────────────────────

fn cmd_clear(store: &StatsStore, yes: bool) {
    if !yes {
        print!("This will permanently delete ALL stats rows. Continue? [y/N] ");
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        if input.trim().to_lowercase() != "y" {
            println!("Aborted.");
            return;
        }
    }
    store.clear_all().unwrap_or_else(|e| {
        eprintln!("error: clear failed: {e}");
        std::process::exit(1);
    });
    println!("Stats cleared.");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use byo_relay::stats::{RawEvent, StatsStore};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn seed_store() -> StatsStore {
        let store = StatsStore::open(":memory:").unwrap();
        let hmac_key = b"test_hmac_key_32_bytes_minimum!!";
        let h = StatsStore::hash_device(hmac_key, "5f3b1234-1234-1234-1234-1234567890ab");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let events = vec![
            RawEvent {
                kind: "vault_unlock".into(),
                ts: Some(now),
                provider_type: None,
                error_class: None,
                share_variant: None,
                bytes: None,
                file_count_bucket: None,
                vault_size_bucket: None,
            },
            RawEvent {
                kind: "upload".into(),
                ts: Some(now),
                provider_type: Some("gdrive".into()),
                bytes: Some(10 * 1024 * 1024),
                error_class: None,
                share_variant: None,
                file_count_bucket: None,
                vault_size_bucket: None,
            },
            RawEvent {
                kind: "share_create".into(),
                ts: Some(now),
                share_variant: Some("B2".into()),
                provider_type: None,
                error_class: None,
                bytes: None,
                file_count_bucket: None,
                vault_size_bucket: None,
            },
        ];
        store.apply_batch(&h, &events, now).unwrap();
        store
    }

    #[test]
    fn format_bytes_zero() {
        assert_eq!(format_bytes(0), "-");
    }

    #[test]
    fn format_bytes_bytes() {
        assert_eq!(format_bytes(500), "500 B");
    }

    #[test]
    fn format_bytes_mib() {
        let b = 10 * 1024 * 1024;
        assert_eq!(format_bytes(b), "10.0 MiB");
    }

    #[test]
    fn log_daily_non_empty() {
        let store = seed_store();
        let counters = store.aggregate_counters("daily", None, None).unwrap();
        assert!(!counters.is_empty());
        let upload = counters.iter().find(|r| r.event_kind == "upload").unwrap();
        assert_eq!(upload.count, 1);
        assert_eq!(upload.bytes_sum, 10 * 1024 * 1024);
        assert_eq!(upload.provider_type, "gdrive");
    }

    #[test]
    fn log_provider_mix() {
        let store = seed_store();
        let mix = store.aggregate_provider_mix("daily", None, None).unwrap();
        assert!(!mix.is_empty());
        assert_eq!(mix[0].provider_type, "gdrive");
        assert_eq!(mix[0].device_count, 1);
    }

    #[test]
    fn clear_wipes_all() {
        let store = seed_store();
        store.clear_all().unwrap();
        assert!(store
            .aggregate_counters("daily", None, None)
            .unwrap()
            .is_empty());
        assert!(store
            .aggregate_provider_mix("daily", None, None)
            .unwrap()
            .is_empty());
    }
}
