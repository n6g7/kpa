//! CLI dispatch.
//!
//! Just `probe` for now — the real `serve`/client split (`docs/design.md`
//! § Components) lands in step 2, at which point `probe` is deleted per the
//! plan (`docs/plan.md` step 2: "`probe` deleted").

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use kpa::vault;

#[derive(Parser)]
#[command(name = "kpa", about = "A small read-only KeePass agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Throwaway: open a .kdbx and print each entry's title, one per line.
    /// Exists only to prove `keepass` opens a real database before the
    /// socket protocol is built around it (docs/plan.md step 1).
    Probe {
        /// Path to the .kdbx file to open.
        path: PathBuf,

        /// Optional keyfile to unlock with, alongside (or instead of) the
        /// password prompt.
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
}

/// Errors `main` can print. A thin wrapper rather than `Box<dyn Error>` so
/// the `?` operator stays usable in `run()` without losing the "why" —
/// matches the "no `.unwrap()`/`.expect()`, use `Result` throughout" rule.
#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("reading password: {0}")]
    PasswordPrompt(#[from] std::io::Error),

    #[error("{0}")]
    Vault(#[from] vault::VaultError),
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), AppError> {
    let cli = Cli::parse();

    match cli.command {
        Command::Probe { path, keyfile } => probe(&path, keyfile.as_deref()),
    }
}

fn probe(path: &Path, keyfile: Option<&Path>) -> Result<(), AppError> {
    let password = rpassword::prompt_password("Password: ")?;
    // An empty response means "no password" rather than "password is the
    // empty string" — the only way to reach a keyfile-only database (the
    // fixture's `fixture-kf.kdbx`) from an interactive prompt that always
    // asks. `vault::open` still errors cleanly (EmptyKey, surfaced as
    // `Corrupt`) if both password and keyfile end up absent.
    let password = if password.is_empty() {
        None
    } else {
        Some(password.as_str())
    };

    let db = vault::open(path, password, keyfile)?;

    for entry in vault::list_entries(&db) {
        println!("{}", entry.title.as_deref().unwrap_or("(untitled)"));
    }

    Ok(())
}
