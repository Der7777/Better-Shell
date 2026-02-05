#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    better_shell::fuzz_parse_bytes(data);
});
