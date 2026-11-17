//! Classifying a real client: the `kpa` binary connects to a listener here,
//! and the test reads the peer's cgroup the way the daemon does. Where the
//! client lands depends on the test runner (a desktop terminal, an SSH
//! login, a CI service), so this checks that the peer is the client and
//! that the requester built from the stream carries it. The classifier's
//! cases are table-tested in `src/authz.rs`.

use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};

use kpa::authn::Requester;
use kpa::authz;
use kpa::session_watch::DisplaySession;

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
    let requester = Requester::of(&stream).expect("the peer's identity");
    assert_eq!(
        requester.cgroup.as_deref(),
        Some(own.as_str()),
        "the peer is the client process"
    );
    let display_session = DisplaySession::Unlocked {
        id: "1".to_string(),
        active: true,
    };
    eprintln!(
        "the test client is on the desktop: {}, in {}",
        authz::on_desktop(&requester, &display_session),
        own.trim()
    );
    assert!(!authz::on_desktop(&requester, &DisplaySession::None));

    drop(stream);
    let _ = client.kill();
    let _ = client.wait();
}
