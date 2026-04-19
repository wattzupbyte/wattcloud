#![no_main]
use libfuzzer_sys::fuzz_target;
use sdk_core::byo::vault_format::VaultHeader;

fuzz_target!(|data: &[u8]| {
    // Must never panic — only return Ok or Err
    let _ = VaultHeader::parse(data);
});
