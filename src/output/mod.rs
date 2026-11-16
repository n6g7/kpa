//! What the CLI writes to a terminal. Everything printed on stdout or stderr
//! goes through `escape_for_terminal`, because the text it carries (entry
//! titles, usernames, group names, and any input echoed back in an error)
//! comes from the database or the user and must not be able to drive the
//! terminal. [`Table`] lays such text out in columns.
//!
//! Knows nothing of the protocol or of any subsystem: text in, text out.

mod escape;
mod table;

pub use escape::{escape_for_terminal, escape_one_line};
pub use table::Table;

/// Prints `text` to stdout with no trailing newline added, escaped.
pub fn print_escaped(text: &str) {
    print!("{}", escape_for_terminal(text));
}

/// Prints `error: <message>` to stderr, with the message escaped.
pub fn report_error(message: impl std::fmt::Display) {
    eprintln!("error: {}", escape_for_terminal(&message.to_string()));
}
