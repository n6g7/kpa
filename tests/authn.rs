//! Classifying a real client: the `kpa` binary connects to a listener here,
//! and the test reads the peer's cgroup the way the daemon does. Where the
//! client lands depends on the test runner (a desktop terminal, an SSH
//! login, a CI service), so this checks that the peer is the client and
//! that `of_peer` agrees with the pure classifier on it. The classifier's
//! cases are table-tested in `src/authn.rs`.

use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};

use kpa::authn::{self, Origin};

#[test]
fn a_local_client_is_classified_by_its_own_cgroup() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("sock");
    let listener = UnixListener::bind(&socket).unwrap();

    // The client sends its request and waits for an answer that never
    // comes, so it is still alive while its cgroup is read.
    let mut client = Command::new(env!("CARGO_BIN_EXE_kpa"))
        .arg("--socket")
        .arg(&socket)
        .arg("status")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (stream, _) = listener.accept().unwrap();

    let own = std::fs::read_to_string(format!("/proc/{}/cgroup", client.id())).unwrap();
    let peer = authn::peer_cgroup(&stream).expect("the peer's cgroup");
    assert_eq!(peer, own, "the peer is the client process");

    let uid = rustix::process::geteuid().as_raw();
    let session = "1";
    let origin = authn::of_peer(&stream, uid, Some(session));
    assert_eq!(origin, authn::classify(&own, uid, Some(session)));
    eprintln!(
        "the test client classifies as {origin:?}, in {}",
        own.trim()
    );
    assert_eq!(authn::of_peer(&stream, uid, None), Origin::Outside);

    drop(stream);
    let _ = client.kill();
    let _ = client.wait();
}
