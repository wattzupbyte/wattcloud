#![no_main]
use libfuzzer_sys::fuzz_target;
use sdk_core::byo::ShardEnvelope;

fuzz_target!(|data: &[u8]| {
    // Must never panic — only return Ok or Err
    let _ = ShardEnvelope::from_bytes(data);
});
