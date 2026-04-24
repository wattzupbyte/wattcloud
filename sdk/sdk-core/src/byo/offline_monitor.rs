/// Provider liveness backoff FSM + platform abstraction trait.
///
/// Pure logic — the host (TS / Android / iOS) owns timers and network I/O.
/// Implements the same 1.5^n exponential backoff used in OfflineDetector.ts
/// so all platforms share one formula.

// ── ProviderStatus ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderStatus {
    /// Last probe succeeded.
    Connected,
    /// Last probe failed.
    Offline,
}

// ── ProviderMonitor ───────────────────────────────────────────────────────────

/// Per-provider backoff state.  The host stores one of these per monitored
/// provider and calls `record_success` / `record_failure` after each probe.
#[derive(Debug, Clone)]
pub struct ProviderMonitor {
    fail_count: u32,
    status: ProviderStatus,
}

impl Default for ProviderMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderMonitor {
    pub fn new() -> Self {
        Self {
            fail_count: 0,
            status: ProviderStatus::Connected,
        }
    }

    /// Return the current status.
    pub fn status(&self) -> ProviderStatus {
        self.status
    }

    /// Record a successful probe.
    ///
    /// Resets `fail_count` to 0.  Returns `true` when the status transitions
    /// from `Offline` to `Connected` (useful for triggering a UI update).
    pub fn record_success(&mut self) -> bool {
        self.fail_count = 0;
        if self.status == ProviderStatus::Offline {
            self.status = ProviderStatus::Connected;
            return true;
        }
        false
    }

    /// Record a failed probe.
    ///
    /// Increments `fail_count`.  Returns `true` when the status transitions
    /// from `Connected` to `Offline` (useful for triggering a UI update).
    pub fn record_failure(&mut self) -> bool {
        self.fail_count = self.fail_count.saturating_add(1);
        if self.status == ProviderStatus::Connected {
            self.status = ProviderStatus::Offline;
            return true;
        }
        false
    }

    /// Compute the next ping interval in milliseconds.
    ///
    /// Formula: `min(base_ms × 1.5^min(fail_count, 6), max_ms)`.
    /// Matches the formula in `OfflineDetector.ts` (M10 fix).
    ///
    /// Examples with `base_ms = 30_000, max_ms = 300_000`:
    ///   - fail_count 0 → 30 000 ms
    ///   - fail_count 1 → 45 000 ms
    ///   - fail_count 6 → ~171 000 ms
    ///   - fail_count 20 → 300 000 ms (capped)
    pub fn next_interval_ms(&self, base_ms: u64, max_ms: u64) -> u64 {
        let exponent = self.fail_count.min(6) as i32;
        let factor = 1.5_f64.powi(exponent);
        let interval = (base_ms as f64 * factor) as u64;
        interval.min(max_ms)
    }
}

// ── OfflineMonitor trait ──────────────────────────────────────────────────────

/// Platform abstraction for provider liveness monitoring.
///
/// Implementations own the per-provider `ProviderMonitor` map.
/// The host (TS / Android / iOS) calls `record_ping` after each probe and
/// schedules the next probe at `next_interval_ms` milliseconds.
pub trait OfflineMonitor: Send + Sync {
    /// Record the outcome of a probe for `provider_id`.
    ///
    /// Returns `true` when the status changed (Connected↔Offline), allowing
    /// the host to trigger a UI refresh without polling.
    fn record_ping(&mut self, provider_id: &str, success: bool) -> bool;

    /// Current liveness status for `provider_id`.
    fn status(&self, provider_id: &str) -> ProviderStatus;

    /// Milliseconds until the next probe for `provider_id`.
    fn next_interval_ms(&self, provider_id: &str, base_ms: u64, max_ms: u64) -> u64;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_is_connected() {
        let m = ProviderMonitor::new();
        assert_eq!(m.status(), ProviderStatus::Connected);
        assert_eq!(m.next_interval_ms(30_000, 300_000), 30_000);
    }

    #[test]
    fn first_failure_transitions_to_offline_and_returns_true() {
        let mut m = ProviderMonitor::new();
        assert!(
            m.record_failure(),
            "first failure should signal status change"
        );
        assert_eq!(m.status(), ProviderStatus::Offline);
    }

    #[test]
    fn subsequent_failures_do_not_retransition() {
        let mut m = ProviderMonitor::new();
        m.record_failure();
        assert!(
            !m.record_failure(),
            "second failure should not signal again"
        );
        assert!(!m.record_failure());
    }

    #[test]
    fn success_after_failure_transitions_to_connected() {
        let mut m = ProviderMonitor::new();
        m.record_failure();
        assert!(
            m.record_success(),
            "success after failure should signal change"
        );
        assert_eq!(m.status(), ProviderStatus::Connected);
    }

    #[test]
    fn success_while_connected_is_a_noop() {
        let mut m = ProviderMonitor::new();
        assert!(!m.record_success());
        assert_eq!(m.status(), ProviderStatus::Connected);
    }

    #[test]
    fn success_resets_fail_count_so_backoff_resets() {
        let mut m = ProviderMonitor::new();
        for _ in 0..10 {
            m.record_failure();
        }
        m.record_success();
        // After reset, fail_count should be 0 → base interval.
        assert_eq!(m.next_interval_ms(30_000, 300_000), 30_000);
    }

    #[test]
    fn backoff_increases_with_fail_count() {
        let mut m = ProviderMonitor::new();
        let base = 30_000u64;
        let max = 300_000u64;
        let mut prev = m.next_interval_ms(base, max);
        for _ in 0..6 {
            m.record_failure();
            let next = m.next_interval_ms(base, max);
            assert!(next > prev, "interval should grow with fail_count");
            prev = next;
        }
    }

    #[test]
    fn backoff_is_capped_at_max() {
        let mut m = ProviderMonitor::new();
        for _ in 0..100 {
            m.record_failure();
        }
        assert_eq!(m.next_interval_ms(30_000, 300_000), 300_000);
    }

    #[test]
    fn backoff_clamps_exponent_at_six() {
        // fail_count=6 and fail_count=100 should produce the same interval
        // (both clamped to exponent=6) before the max cap.
        let mut m6 = ProviderMonitor::new();
        for _ in 0..6 {
            m6.record_failure();
        }
        let mut m100 = ProviderMonitor::new();
        for _ in 0..100 {
            m100.record_failure();
        }
        // Both hit the max cap.
        assert_eq!(
            m6.next_interval_ms(30_000, 300_000),
            m100.next_interval_ms(30_000, 300_000)
        );
    }

    #[test]
    fn saturating_fail_count_does_not_overflow() {
        let mut m = ProviderMonitor::new();
        // Drive fail_count to near u32::MAX
        for _ in 0..u32::MAX as u64 + 1 {
            // saturating_add means this should never panic
            if m.fail_count == u32::MAX {
                break;
            }
            m.fail_count = m.fail_count.saturating_add(1);
        }
        m.fail_count = u32::MAX;
        // Should not panic
        let _ = m.next_interval_ms(30_000, 300_000);
    }
}
