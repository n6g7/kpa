#![no_main]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use libfuzzer_sys::fuzz_target;

// Exercises exactly the decode path `handle_connection` in `src/server.rs`
// runs on a request line once it's off the socket: a UTF-8 check, then
// `decode_request`. Arbitrary bytes must only ever produce an `Err` here —
// never a panic, and never an unbounded hang (the JSON and `Request`
// shapes involved have no recursive or unbounded-loop structure, so a
// hang would itself be a finding, not an expected outcome of a bad input).
//
// The first byte picks how the rest becomes a line, so that the `password`
// field gets inputs a byte-level mutator would rarely build on its own:
//
// - `0`: the rest is a `password` value's raw text, spliced between the
//   quotes of an otherwise valid `unlock`. Escapes, quotes and invalid
//   base64 all land in the field.
// - `1`: the rest is a password, base64-encoded into an `unlock`. Any
//   password up to `MAX_PASSWORD_LEN` UTF-8 bytes must decode back to
//   exactly itself; anything else must be refused.
// - anything else: the whole input is the line.
//
// The socket's own request-size cap (`MAX_REQUEST_LEN` in `src/server.rs`)
// lives at the read layer, above this function, and only ever makes a line
// shorter before it reaches `decode_request` — so it's out of scope for
// this target, which fuzzes the parser on lines of any length libFuzzer
// chooses to generate.
fuzz_target!(|data: &[u8]| {
    match data.split_first() {
        Some((0, raw)) => {
            if let Ok(raw) = std::str::from_utf8(raw) {
                let _ = kpa::proto::decode_request(&unlock(raw));
            }
        }
        Some((1, password)) => {
            let decoded = kpa::proto::decode_request(&unlock(&STANDARD.encode(password)));
            let expected = std::str::from_utf8(password)
                .ok()
                .filter(|text| text.len() <= kpa::proto::MAX_PASSWORD_LEN);
            match (decoded, expected) {
                (Ok(request), Some(text)) => {
                    let kpa::proto::Op::Unlock(unlock) = request.op else {
                        panic!("an unlock decoded as another op");
                    };
                    let password = unlock.password.expect("the password was dropped");
                    assert_eq!(password.as_zeroizing().as_str(), text);
                }
                (Err(_), None) => {}
                (Ok(_), None) => panic!("an unusable password was accepted"),
                (Err(err), Some(_)) => panic!("a usable password was refused: {err:?}"),
            }
        }
        _ => {
            if let Ok(line) = std::str::from_utf8(data) {
                let _ = kpa::proto::decode_request(line);
            }
        }
    }
});

fn unlock(password: &str) -> String {
    format!(r#"{{"v":1,"op":"unlock","db":"personal","password":"{password}"}}"#)
}
