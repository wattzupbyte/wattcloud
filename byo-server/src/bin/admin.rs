// byo-admin — CLI for BYO usage statistics.
//
// Usage:
//   byo-admin log   --granularity {daily|weekly|monthly|yearly}
//                   [--from YYYY-MM-DD] [--to YYYY-MM-DD]
//   byo-admin clear [--yes]
//
// Opens the stats.sqlite3 file directly (WAL, so concurrent reads do not
// block a running byo-server).

use byo_server::stats::StatsStore;
use clap::{Parser, Subcommand};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "byo-admin", about = "BYO usage statistics admin CLI")]
struct Cli {
    /// Path to the stats SQLite database.
    #[arg(long, env = "STATS_DB_PATH", default_value = "/var/lib/byo-server/stats.sqlite3")]
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
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Log { granularity, from, to } => {
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
    }
}

// ── log ───────────────────────────────────────────────────────────────────────

fn cmd_log(store: &StatsStore, granularity: &str, from: Option<&str>, to: Option<&str>) {
    let valid = ["daily", "weekly", "monthly", "yearly"];
    if !valid.contains(&granularity) {
        eprintln!("error: --granularity must be one of: daily, weekly, monthly, yearly");
        std::process::exit(1);
    }

    let counters = store.aggregate_counters(granularity, from, to).unwrap_or_else(|e| {
        eprintln!("error: query failed: {e}");
        std::process::exit(1);
    });
    let mix = store.aggregate_provider_mix(granularity, from, to).unwrap_or_else(|e| {
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
        let col_provider = col_width(counters.iter().map(|r| r.provider_type.as_str()), "Provider");
        let col_error = col_width(counters.iter().map(|r| r.error_class.as_str()), "Error");
        let col_variant = col_width(counters.iter().map(|r| r.share_variant.as_str()), "Variant");

        print_row(
            col_period, col_kind, col_provider, col_error, col_variant,
            "Period", "Event", "Provider", "Error", "Variant", "Count", "Bytes",
        );
        print_sep(col_period, col_kind, col_provider, col_error, col_variant);

        for r in &counters {
            let bytes_fmt = format_bytes(r.bytes_sum as u64);
            print_row(
                col_period, col_kind, col_provider, col_error, col_variant,
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
        println!(
            "{:-<col_period$}  {:-<col_provider$}  {:->12}",
            "", "", ""
        );
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
    cp: usize, ck: usize, cv: usize, ce: usize, cv2: usize,
    period: &str, kind: &str, provider: &str, error: &str, variant: &str,
    count: &str, bytes: &str,
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use byo_server::stats::{RawEvent, StatsStore};
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
        assert!(store.aggregate_counters("daily", None, None).unwrap().is_empty());
        assert!(store.aggregate_provider_mix("daily", None, None).unwrap().is_empty());
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
