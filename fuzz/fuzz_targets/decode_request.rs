#![no_main]

use libfuzzer_sys::fuzz_target;

// Exercises exactly the decode path `handle_connection` in `src/server.rs`
// runs on a request line once it's off the socket: a UTF-8 check, then
// `decode_request`. Arbitrary bytes must only ever produce an `Err` here —
// never a panic, and never an unbounded hang (the JSON and `Request`
// shapes involved have no recursive or unbounded-loop structure, so a
// hang would itself be a finding, not an expected outcome of a bad input).
//
// The socket's own request-size cap (`MAX_REQUEST_LEN` in `src/server.rs`)
// lives at the read layer, above this function, and only ever makes a line
// shorter before it reaches `decode_request` — so it's out of scope for
// this target, which fuzzes the parser on lines of any length libFuzzer
// chooses to generate.
fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        let _ = kpa::proto::decode_request(line);
    }
});
