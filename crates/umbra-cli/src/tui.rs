//! Security-focused terminal UI (TODO A.4, `ratatui`).
//!
//! Skeleton scope: a single static screen, `q` to quit. Session rendering,
//! Scratch-to-Reveal masking, and Wayland-only enforcement land with the
//! A.4 hardening pass.

use core::time::Duration;

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use thiserror::Error;

/// TUI error type.
#[derive(Debug, Error)]
pub enum TuiError {
    /// Terminal mode or backend failure.
    #[error("terminal failure")]
    Terminal,
}

/// Runs the TUI until the user quits with `q`.
///
/// # Errors
///
/// Returns [`TuiError::Terminal`] if raw mode or the backend cannot be
/// initialized or restored.
pub fn run() -> Result<(), TuiError> {
    enable_raw_mode().map_err(|_e| TuiError::Terminal)?;
    let entered = std::io::stdout().execute(EnterAlternateScreen).is_ok();
    let backend = CrosstermBackend::new(std::io::stdout());
    let terminal = Terminal::new(backend);
    let mut terminal = match terminal {
        Ok(term) => term,
        Err(_e) => {
            restore(entered);
            return Err(TuiError::Terminal);
        }
    };

    let outcome = event_loop(&mut terminal);

    restore(entered);
    outcome
}

/// Draws and polls events until `q` is pressed.
fn event_loop(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<(), TuiError> {
    loop {
        terminal
            .draw(|frame| {
                let banner =
                    Line::from("Umbra TUI — no active session (v1.0 MVP skeleton, TODO A.4)");
                let hint = Line::from("Press 'q' to quit.");
                frame.render_widget(Paragraph::new(vec![banner, hint]), frame.area());
            })
            .map_err(|_e| TuiError::Terminal)?;

        if event::poll(Duration::from_millis(200)).map_err(|_e| TuiError::Terminal)?
            && let Ok(Event::Key(key)) = event::read()
            && key.kind == KeyEventKind::Press
            && matches!(key.code, KeyCode::Char('q'))
        {
            return Ok(());
        }
    }
}

/// Restores terminal state on every exit path.
fn restore(entered: bool) {
    if entered {
        let _ = std::io::stdout().execute(LeaveAlternateScreen);
    }
    let _ = disable_raw_mode();
}
