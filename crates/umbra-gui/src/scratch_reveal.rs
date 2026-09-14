//! Scratch-to-Reveal (TODO B.3): masks sensitive on-screen text behind
//! an opaque surface, revealed as the user drags across it. Split into
//! two halves:
//!
//! - [`RevealState`] (this module, always compiled): a pure,
//!   grid-based coverage tracker with zero GTK dependency — fully
//!   hermetically testable.
//! - `build_scratch_reveal` (`#[cfg(feature = "gui")]`, added in a
//!   later task in this same plan): the actual `gtk4::DrawingArea` +
//!   `gtk4::GestureDrag` + cairo wiring around it.
//!
//! # Honest scope
//!
//! `RevealState`'s coverage/threshold logic below is fully
//! hermetically tested. The GTK/cairo widget wiring is compiled and
//! clippy-checked but NOT exercised by any automated test — there is
//! no live Wayland display with synthetic pointer input available in
//! this project's test environment, the same honest-scope caveat this
//! codebase already applies to `mesh_live.rs`/`tui_live.rs`.

/// Fraction of grid cells that must be revealed before the whole
/// surface snaps to fully revealed (a common scratch-card UX
/// convention — the user need not scratch every pixel).
pub const REVEAL_THRESHOLD: f64 = 0.4;

/// A grid-based coverage tracker for one scratch-to-reveal surface.
/// `columns * rows` cells, row-major, each either revealed or not.
#[derive(Debug, Clone)]
pub struct RevealState {
    /// Grid width in cells (at least 1; see [`RevealState::new`]).
    columns: usize,
    /// Grid height in cells (at least 1; see [`RevealState::new`]).
    rows: usize,
    /// `columns * rows` cells, row-major: cell `(column, row)` lives
    /// at index `row * columns + column`.
    revealed: Vec<bool>,
}

impl RevealState {
    /// Builds a tracker with `columns * rows` cells, all initially
    /// unrevealed. Both dimensions are clamped to at least 1 (a
    /// zero-sized grid would make every coverage calculation
    /// meaningless, not merely empty).
    #[must_use]
    pub fn new(columns: usize, rows: usize) -> Self {
        let columns = columns.max(1);
        let rows = rows.max(1);
        Self {
            columns,
            rows,
            revealed: vec![false; columns.saturating_mul(rows)],
        }
    }

    /// Marks every cell within `radius_cells` (grid-cell units) of the
    /// cell containing canvas point `(x, y)` as revealed. `canvas_width`/
    /// `canvas_height` convert pixel coordinates to a grid cell. Clamps
    /// silently (never panics) for a point outside `[0, canvas_width) x
    /// [0, canvas_height)`, a non-positive canvas size, or a negative
    /// `radius_cells`.
    pub fn scratch_at(
        &mut self,
        x: f64,
        y: f64,
        canvas_width: f64,
        canvas_height: f64,
        radius_cells: f64,
    ) {
        if canvas_width <= 0.0 || canvas_height <= 0.0 {
            return;
        }
        let radius_cells = radius_cells.max(0.0);
        let column_width = canvas_width / self.columns as f64;
        let row_height = canvas_height / self.rows as f64;
        if column_width <= 0.0 || row_height <= 0.0 {
            return;
        }
        // Upper-clamp to the dimension itself (not `dim - 1.0`):
        // `center_column`/`center_row` are continuous "cell index +
        // fractional position" coordinates ranging over `[0, dim)`,
        // not `[0, dim - 1]`. Clamping to `dim - 1.0` would collapse
        // every point in the LAST row/column down toward that cell's
        // own left/top edge instead of its true position — and for a
        // single-row or single-column grid (`dim == 1`), it collapses
        // the entire valid range to the single point `0.0`, so a
        // point dead-center in that row/column (true position `0.5`)
        // reads as `0.0`, landing 0.5 cells away from its own cell's
        // center and making a small `radius_cells` never reveal it.
        let center_column = (x / column_width).clamp(0.0, self.columns as f64);
        let center_row = (y / row_height).clamp(0.0, self.rows as f64);

        let min_column = (center_column - radius_cells).floor().max(0.0) as usize;
        let max_column =
            ((center_column + radius_cells).ceil() as usize).min(self.columns.saturating_sub(1));
        let min_row = (center_row - radius_cells).floor().max(0.0) as usize;
        let max_row =
            ((center_row + radius_cells).ceil() as usize).min(self.rows.saturating_sub(1));

        for row in min_row..=max_row {
            for column in min_column..=max_column {
                // Compare against the CELL'S OWN CENTER (column + 0.5,
                // row + 0.5) in the same continuous coordinate system
                // `center_column`/`center_row` are computed in — not
                // the bare integer index. Comparing against the raw
                // index would make a scratch in the MIDDLE of a cell
                // measure as 0.5 cells away from that cell (since
                // `center_column`/`center_row` are themselves already
                // fractional-within-the-cell), so a small radius would
                // never reveal the cell the user is actually pointing
                // at — backwards from the intended feel.
                let dx = (column as f64 + 0.5) - center_column;
                let dy = (row as f64 + 0.5) - center_row;
                let index = row.saturating_mul(self.columns).saturating_add(column);
                if dx.hypot(dy) <= radius_cells
                    && let Some(cell) = self.revealed.get_mut(index)
                {
                    *cell = true;
                }
            }
        }
    }

    /// Whether the specific cell at `(column, row)` is individually
    /// revealed. `false` for an out-of-range cell (never panics).
    #[must_use]
    pub fn is_cell_revealed(&self, column: usize, row: usize) -> bool {
        if column >= self.columns || row >= self.rows {
            return false;
        }
        let index = row.saturating_mul(self.columns).saturating_add(column);
        self.revealed.get(index).copied().unwrap_or(false)
    }

    /// Fraction of cells revealed so far, in `[0.0, 1.0]`.
    #[must_use]
    pub fn coverage(&self) -> f64 {
        if self.revealed.is_empty() {
            return 0.0;
        }
        let revealed_count = self.revealed.iter().filter(|cell| **cell).count();
        revealed_count as f64 / self.revealed.len() as f64
    }

    /// `coverage() >= `[`REVEAL_THRESHOLD`].
    #[must_use]
    pub fn is_fully_revealed(&self) -> bool {
        self.coverage() >= REVEAL_THRESHOLD
    }

    /// Number of grid columns (for the draw func to iterate cells).
    #[must_use]
    pub fn columns(&self) -> usize {
        self.columns
    }

    /// Number of grid rows (for the draw func to iterate cells).
    #[must_use]
    pub fn rows(&self) -> usize {
        self.rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_has_zero_coverage_and_is_not_revealed() {
        let state = RevealState::new(16, 4);
        assert_eq!(state.coverage(), 0.0);
        assert!(!state.is_fully_revealed());
        assert!(!state.is_cell_revealed(0, 0));
    }

    #[test]
    fn scratching_reveals_nearby_cells() {
        let mut state = RevealState::new(16, 4);
        // Center of a 300x40 canvas, small radius — should reveal at
        // least the center cell.
        state.scratch_at(150.0, 20.0, 300.0, 40.0, 1.0);
        let center_column = 8; // 150 / (300/16) = 8
        let center_row = 2; // 20 / (40/4) = 2
        assert!(state.is_cell_revealed(center_column, center_row));
        assert!(state.coverage() > 0.0);
    }

    #[test]
    fn coverage_crosses_threshold_and_is_fully_revealed() {
        let mut state = RevealState::new(4, 2); // 8 cells total
        // Scratching with a large radius from the center reveals every
        // cell in one call — coverage should hit 1.0, well past the
        // 0.4 threshold.
        state.scratch_at(50.0, 10.0, 100.0, 20.0, 10.0);
        assert_eq!(state.coverage(), 1.0);
        assert!(state.is_fully_revealed());
    }

    #[test]
    fn threshold_boundary() {
        let mut state = RevealState::new(10, 1); // 10 cells
        // Reveal exactly 4 of 10 cells (0.4 coverage) — right at the
        // threshold, should count as fully revealed (>=, not >).
        for column in 0..4 {
            state.scratch_at((column as f64 + 0.5) * 10.0, 5.0, 100.0, 10.0, 0.0);
        }
        assert_eq!(state.coverage(), 0.4);
        assert!(state.is_fully_revealed());
    }

    #[test]
    fn degenerate_inputs_never_panic() {
        let mut state = RevealState::new(0, 0); // clamped to 1x1
        state.scratch_at(f64::NAN, f64::NAN, 0.0, 0.0, -5.0);
        state.scratch_at(-100.0, -100.0, 100.0, 100.0, 1.0);
        state.scratch_at(1e9, 1e9, 100.0, 100.0, 1.0);
        let _ = state.coverage();
        let _ = state.is_cell_revealed(999, 999);
    }
}
