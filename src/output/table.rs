//! A table of untrusted text: a fixed header over rows, each column padded
//! to its widest cell.

use std::fmt::Write as _;

use super::escape_one_line;

/// Longest escaped cell, in bytes.
const MAX_CELL_LEN: usize = 128;

/// Rows under a header. A cell goes through [`escape_one_line`] as it is
/// added, so no text a row is given can drive the terminal or leave its
/// column, and widths are measured on what is printed.
pub struct Table<const N: usize> {
    header: [&'static str; N],
    rows: Vec<[String; N]>,
}

impl<const N: usize> Table<N> {
    pub fn new(header: [&'static str; N]) -> Table<N> {
        Table {
            header,
            rows: Vec::new(),
        }
    }

    pub fn row(&mut self, cells: [&str; N]) {
        self.rows
            .push(cells.map(|cell| escape_one_line(cell, MAX_CELL_LEN)));
    }

    /// The header and the rows, one line each, columns two spaces apart.
    /// The last column is not padded. Widths count characters: a wide
    /// character (CJK, say) can still throw a column off by a cell.
    pub fn render(&self) -> String {
        let mut widths = self.header.map(|cell| cell.chars().count());
        for row in &self.rows {
            for (width, cell) in widths.iter_mut().zip(row) {
                *width = (*width).max(cell.chars().count());
            }
        }

        let mut out = String::new();
        let mut line = |cells: [&str; N]| {
            for (i, (cell, width)) in cells.iter().zip(widths).enumerate() {
                if i + 1 == N {
                    out.push_str(cell);
                } else {
                    let _ = write!(out, "{cell:<width$}  ");
                }
            }
            out.push('\n');
        };
        line(self.header);
        for row in &self.rows {
            line(row.each_ref().map(String::as_str));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_are_padded_to_the_widest_cell_and_the_last_is_not() {
        let mut table = Table::new(["TYPE", "ENTRY"]);
        table.row(["ssh-ed25519", "a"]);
        table.row(["ssh-rsa", "bb"]);

        assert_eq!(
            table.render(),
            "TYPE         ENTRY\nssh-ed25519  a\nssh-rsa      bb\n"
        );
    }

    /// Cells are measured after escaping, so text full of newlines, tabs and
    /// control characters stays on its line and under its header.
    #[test]
    fn hostile_cells_stay_in_their_column() {
        let mut table = Table::new(["A", "B"]);
        for cell in ["x\ny", "t\tt", "\u{9b}c\u{202e}", "plain"] {
            table.row([cell, "end"]);
        }

        let text = table.render();

        assert_eq!(text.lines().count(), 5, "{text}");
        let column = text.lines().next().and_then(|h| h.find('B')).expect("B");
        for line in text.lines().skip(1) {
            assert!(line.is_ascii(), "{line:?}");
            assert_eq!(line.get(column..), Some("end"), "{text}");
        }
    }

    #[test]
    fn a_long_cell_is_capped() {
        let mut table = Table::new(["A"]);
        table.row([&"t".repeat(10_000)]);
        assert!(table.render().len() < 200);
    }
}
