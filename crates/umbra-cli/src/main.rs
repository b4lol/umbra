//! `umbra` — the Umbra command-line front end.
//!
//! Unix philosophy (ADR-022): do one thing well, pipe-friendly
//! `stdin`/`stdout`, Rule of Silence (successful commands print only the
//! requested data; diagnostics go to `stderr`).

mod cli;
mod tui;

use std::process::ExitCode;

use crate::cli::run;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("umbra: {err}");
            ExitCode::FAILURE
        }
    }
}
