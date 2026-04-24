// StatsSink trait + in-memory ring-buffer implementation.
//
// Sync by design: recording an event must never block a user operation.
// The host (WASM / Android) calls `record` from hot paths; `drain` is called
// by the uploader when it decides to flush.

use std::collections::VecDeque;
use std::sync::Mutex;

use super::events::StatsEvent;

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Sync sink for statistics events. Implementations must be `Send + Sync` and
/// must never panic (consistent with `#![deny(clippy::unwrap_used)]`).
pub trait StatsSink: Send + Sync {
    /// Queue a single event.  Drop-oldest if the buffer is at capacity.
    fn record(&self, event: StatsEvent);

    /// Atomically drain up to `max` events in FIFO order.
    fn drain(&self, max: usize) -> Vec<StatsEvent>;

    /// Current queue depth (used by the uploader for back-pressure decisions).
    fn len(&self) -> usize;

    /// Returns `true` if the queue is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─── NoopStatsSink ────────────────────────────────────────────────────────────

/// A sink that discards all events.  Used as a zero-cost default before the
/// WASM/Android layer has initialised the real sink.
pub struct NoopStatsSink;

impl StatsSink for NoopStatsSink {
    fn record(&self, _event: StatsEvent) {}
    fn drain(&self, _max: usize) -> Vec<StatsEvent> {
        vec![]
    }
    fn len(&self) -> usize {
        0
    }
}

// ─── InMemoryStatsSink ────────────────────────────────────────────────────────

/// Bounded in-memory FIFO ring buffer.
///
/// When the buffer is at `cap`, the **oldest** event is dropped to make room
/// for the new one (lossy by design — stats are best-effort).
pub struct InMemoryStatsSink {
    inner: Mutex<VecDeque<StatsEvent>>,
    cap: usize,
}

impl InMemoryStatsSink {
    /// Create a new sink with the given capacity.
    ///
    /// `cap` must be > 0; values of 0 are silently treated as 1.
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            inner: Mutex::new(VecDeque::with_capacity(cap.min(1024))),
            cap,
        }
    }
}

impl StatsSink for InMemoryStatsSink {
    fn record(&self, event: StatsEvent) {
        let Ok(mut q) = self.inner.lock() else { return };
        if q.len() >= self.cap {
            q.pop_front(); // drop oldest
        }
        q.push_back(event);
    }

    fn drain(&self, max: usize) -> Vec<StatsEvent> {
        let Ok(mut q) = self.inner.lock() else {
            return vec![];
        };
        let take = max.min(q.len());
        q.drain(..take).collect()
    }

    fn len(&self) -> usize {
        self.inner.lock().map(|q| q.len()).unwrap_or(0)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::byo::stats::events::StatsEvent;

    fn unlock(ts: u64) -> StatsEvent {
        StatsEvent::VaultUnlock { ts }
    }

    #[test]
    fn noop_does_nothing() {
        let s = NoopStatsSink;
        s.record(unlock(1));
        assert!(s.drain(10).is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn in_memory_basic_fifo() {
        let s = InMemoryStatsSink::new(10);
        s.record(unlock(1));
        s.record(unlock(2));
        s.record(unlock(3));
        assert_eq!(s.len(), 3);
        let drained = s.drain(2);
        assert_eq!(drained.len(), 2);
        // FIFO: first inserted is first out.
        assert!(matches!(drained[0], StatsEvent::VaultUnlock { ts: 1 }));
        assert!(matches!(drained[1], StatsEvent::VaultUnlock { ts: 2 }));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn in_memory_drop_oldest_on_overflow() {
        let s = InMemoryStatsSink::new(3);
        s.record(unlock(1));
        s.record(unlock(2));
        s.record(unlock(3));
        // Buffer full; inserting 4 must drop ts=1.
        s.record(unlock(4));
        assert_eq!(s.len(), 3);
        let drained = s.drain(10);
        let timestamps: Vec<u64> = drained
            .iter()
            .map(|e| match e {
                StatsEvent::VaultUnlock { ts } => *ts,
                _ => 0,
            })
            .collect();
        assert_eq!(timestamps, vec![2, 3, 4]);
    }

    #[test]
    fn drain_returns_at_most_max() {
        let s = InMemoryStatsSink::new(100);
        for i in 0..50 {
            s.record(unlock(i));
        }
        let d = s.drain(5);
        assert_eq!(d.len(), 5);
        assert_eq!(s.len(), 45);
    }

    #[test]
    fn drain_all_when_max_exceeds_len() {
        let s = InMemoryStatsSink::new(100);
        s.record(unlock(1));
        s.record(unlock(2));
        let d = s.drain(1000);
        assert_eq!(d.len(), 2);
        assert!(s.is_empty());
    }

    #[test]
    fn cap_zero_treated_as_one() {
        let s = InMemoryStatsSink::new(0);
        s.record(unlock(1));
        s.record(unlock(2));
        // Only one slot; ts=1 is dropped, ts=2 stays.
        let d = s.drain(10);
        assert_eq!(d.len(), 1);
        assert!(matches!(d[0], StatsEvent::VaultUnlock { ts: 2 }));
    }
}
