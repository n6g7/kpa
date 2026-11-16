//! Showing the daemon's answer: the one place that decides between its raw
//! JSON line and a text view of it.
//!
//! A command with a text view hands [`run`] its op and a function from the
//! typed answer to text. Everything else is shared: the sentence a failure
//! becomes, the exit status, and the escaping of what reaches the terminal.

use std::fmt;
use std::path::Path;
use std::process::ExitCode;

use kpa::output::{print_escaped, report_error};
use kpa::proto::{self, ErrorCode, Op, Request};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::client::{print_and_exit, report_client_error, send_request};

/// How a command's answer is shown, from `--json`.
#[derive(Clone, Copy)]
pub(super) enum Format {
    /// The daemon's response line, as it came.
    Json,
    /// The command's own view, and a failure as a sentence.
    Text,
}

/// Sends `op` and shows the answer. In text mode `show` turns the typed
/// answer into the text to print, which goes to the terminal escaped
/// (`output::print_escaped`) whatever it holds. Either way the exit status
/// follows the answer's `ok`.
pub(super) fn run<T: DeserializeOwned>(
    socket_path: &Path,
    op: Op,
    format: Format,
    show: impl FnOnce(T) -> String,
) -> ExitCode {
    let request = Request {
        v: proto::VERSION,
        op,
    };
    let line = match send_request(socket_path, &request) {
        Ok(line) => line,
        Err(err) => return report_client_error(err),
    };
    if let Format::Json = format {
        return print_and_exit(&line);
    }
    match parse_reply(&line) {
        Ok(typed) => {
            print_escaped(&show(typed));
            ExitCode::SUCCESS
        }
        Err(sentence) => {
            report_error(sentence);
            ExitCode::FAILURE
        }
    }
}

/// What a response line is: the daemon refusing the request, or the answer
/// a command asked for. A failure line always carries `error` and a success
/// line never does, so trying `Failure` first can't mistake one for the
/// other, even for an answer whose fields are all optional.
#[derive(Deserialize)]
#[serde(untagged)]
enum Reply<T> {
    Failure(Failure),
    Success(T),
}

/// The fields of a failure response (`docs/design.md` § Protocol).
#[derive(Deserialize)]
struct Failure {
    error: ErrorCode,
    db: Option<String>,
    detail: Option<String>,
}

/// The typed answer in `line`, or the sentence for why there is none.
fn parse_reply<T: DeserializeOwned>(line: &str) -> Result<T, String> {
    match serde_json::from_str::<Reply<T>>(line) {
        Ok(Reply::Success(answer)) => Ok(answer),
        Ok(Reply::Failure(failure)) => Err(failure.to_string()),
        Err(_) => Err("the daemon's answer was not one this kpa understands".to_string()),
    }
}

/// A failure as a sentence, with what to do about it where there is
/// something to do. The code's wire spelling stands in for one without a
/// sentence of its own.
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let db = self.db.as_deref().unwrap_or("?");
        match self.error {
            ErrorCode::UnknownDb => write!(f, "no database named {db:?} is configured"),
            ErrorCode::Locked => {
                write!(
                    f,
                    "database {db:?} is locked; run `kpa unlock {db}` and try again"
                )
            }
            ErrorCode::Stale => write!(
                f,
                "database {db:?} changed on disk and was locked; unlock it again"
            ),
            code => {
                let code = serde_json::to_value(code).ok();
                let code = code.as_ref().and_then(|code| code.as_str()).unwrap_or("?");
                match &self.detail {
                    Some(detail) => write!(f, "the daemon refused the request ({code}): {detail}"),
                    None => write!(f, "the daemon refused the request ({code})"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    /// An answer whose every field is optional, which any JSON object fits.
    #[derive(Deserialize, Debug)]
    struct Anything {
        #[serde(default)]
        #[allow(dead_code)]
        db: Option<String>,
    }

    fn failed(line: &str) -> String {
        parse_reply::<Anything>(line).expect_err("a failure")
    }

    #[test]
    fn a_failure_is_never_taken_for_an_answer() {
        assert_eq!(
            failed(r#"{"v":1,"ok":false,"error":"locked","db":"personal"}"#),
            "database \"personal\" is locked; run `kpa unlock personal` and try again"
        );
        assert!(parse_reply::<Anything>(r#"{"v":1,"ok":true}"#).is_ok());
    }

    #[test]
    fn each_failure_is_a_sentence() {
        assert_eq!(
            failed(r#"{"v":1,"ok":false,"error":"unknown_db","db":"x"}"#),
            "no database named \"x\" is configured"
        );
        assert_eq!(
            failed(
                r#"{"v":1,"ok":false,"error":"stale","db":"x","detail":"database changed on disk"}"#
            ),
            "database \"x\" changed on disk and was locked; unlock it again"
        );
        assert_eq!(
            failed(r#"{"v":1,"ok":false,"error":"prompt_cancelled"}"#),
            "the daemon refused the request (prompt_cancelled)"
        );
        assert_eq!(
            failed(r#"{"v":1,"ok":false,"error":"version_mismatch","detail":"client sent v2"}"#),
            "the daemon refused the request (version_mismatch): client sent v2"
        );
    }

    #[test]
    fn an_unreadable_line_is_not_an_answer() {
        assert_eq!(
            failed("not json"),
            "the daemon's answer was not one this kpa understands"
        );
    }
}
