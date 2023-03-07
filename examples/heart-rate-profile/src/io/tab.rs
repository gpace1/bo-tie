//! user Tab key processing
use super::commands::Command;
use super::{Input, StdoutLocker};
use crate::io::commands::{InputKind, KnownArgData};
use std::io;
use std::io::Write;
use std::str::SplitWhitespace;

struct TabTerm {
    highlighted_index: usize,
    rows_used: usize,
}

impl TabTerm {
    fn clear_displayed(&mut self, stdout_locker: &mut StdoutLocker) -> std::io::Result<()> {
        self.rows_used = 0;

        crossterm::execute!(
            stdout_locker,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::FromCursorDown)
        )
    }
}

pub struct Tab {
    displayed_input: String,
    tab_terminal: TabTerm,
}

impl Tab {
    pub fn new() -> Self {
        let highlighted_index = 0;
        let displayed_input = String::new();
        let rows_used = 0;

        let tab_terminal = TabTerm {
            highlighted_index,
            rows_used,
        };

        Tab {
            displayed_input,
            tab_terminal,
        }
    }

    pub(super) fn clear_tab_input(&mut self, stdout_locker: &mut StdoutLocker) -> io::Result<()> {
        self.displayed_input = String::new();

        if self.tab_terminal.rows_used > 0 {
            let column = crossterm::cursor::position()?.0;

            crossterm::execute!(
                stdout_locker,
                crossterm::cursor::MoveToNextLine(1),
                crossterm::terminal::Clear(crossterm::terminal::ClearType::FromCursorDown),
                crossterm::cursor::MoveToPreviousLine(1),
                crossterm::cursor::MoveToColumn(column),
            )?;
        }

        self.tab_terminal.rows_used = 0;

        Ok(())
    }

    pub(super) fn reset_tab_input(&mut self, to: &Input) {
        self.displayed_input = to.iter().collect();
        self.tab_terminal.highlighted_index = 0;
    }

    pub(super) fn on_tab<'a>(
        &mut self,
        inputs: &'a [InputKind],
        stdout_locker: &mut StdoutLocker,
        known_arg_data: &KnownArgData,
    ) -> io::Result<Option<String>> {
        self.tab_terminal.rows_used = 0;

        let displayed_input = &mut self.displayed_input.split_whitespace();

        let mut tab_match = TabMatch {
            inputs,
            tab_terminal: &mut self.tab_terminal,
        };

        let ret = tab_match.print_matches(stdout_locker, displayed_input, known_arg_data)?;

        if self.tab_terminal.rows_used != 0 {
            crossterm::execute!(
                stdout_locker,
                crossterm::cursor::MoveToPreviousLine(self.tab_terminal.rows_used as u16)
            )?;
        }

        Ok(ret)
    }
}

enum CommandOrArg<'a> {
    Command(&'a Command),
    Arg(String),
}

pub struct TabMatch<'a, 'b> {
    inputs: &'a [InputKind],
    tab_terminal: &'b mut TabTerm,
}

impl<'a> TabMatch<'a, '_> {
    const BACKGROUND_COLOR: crossterm::style::SetBackgroundColor =
        crossterm::style::SetBackgroundColor(crossterm::style::Color::Green);

    fn print_matches(
        &mut self,
        stdout_locker: &mut StdoutLocker,
        displayed_input: &mut SplitWhitespace,
        known_arg_data: &KnownArgData,
    ) -> io::Result<Option<String>> {
        self.tab_terminal.clear_displayed(stdout_locker)?;

        let first_displayed = displayed_input.next().unwrap_or_default();

        let mut matched_inputs = self
            .inputs
            .iter()
            .filter_map(|input| match input {
                InputKind::Commands(commands) => Some(Box::new(commands.iter().filter_map(|cmd| {
                    if cmd.name.starts_with(first_displayed) {
                        Some(CommandOrArg::Command(cmd))
                    } else {
                        None
                    }
                })) as Box<dyn Iterator<Item = CommandOrArg>>),
                InputKind::Known(known) => Some(Box::new(
                    (known.tab_arg)(known_arg_data)
                        .into_iter()
                        .filter_map(|arg| arg.starts_with(first_displayed).then_some(CommandOrArg::Arg(arg))),
                ) as Box<dyn Iterator<Item = CommandOrArg>>),
                _ => None,
            })
            .flatten();

        let first = matched_inputs.next();

        let second = matched_inputs.next();

        if first.is_none() {
            Ok(None)
        } else if second.is_none() {
            match first.unwrap() {
                CommandOrArg::Command(command) => {
                    let mut tab_match = TabMatch {
                        inputs: command.args,
                        tab_terminal: self.tab_terminal,
                    };

                    Ok(Some(
                        command.name.to_string()
                            + " "
                            + &tab_match
                                .print_matches(stdout_locker, displayed_input, known_arg_data)?
                                .unwrap_or(String::new()),
                    ))
                }
                CommandOrArg::Arg(arg) => Ok(Some(arg)),
            }
        } else {
            let mut printed_rows = 0;
            let mut returned = None;
            let mut count = 0;

            let mut iter = first
                .into_iter()
                .chain(second.into_iter().chain(matched_inputs))
                .inspect(|_| count += 1)
                .enumerate()
                .peekable();

            while iter.peek().is_some() {
                stdout_locker.move_to_next_line()?;

                if let Some(ret) = self.print_row(stdout_locker, &mut iter)? {
                    returned = Some(ret);
                };

                printed_rows += 1;
            }

            self.tab_terminal.rows_used = printed_rows;

            self.tab_terminal.highlighted_index = (self.tab_terminal.highlighted_index + 1) % count;

            Ok(returned)
        }
    }

    fn print_row<I>(
        &self,
        stdout_locker: &mut StdoutLocker,
        matched_inputs: &mut std::iter::Peekable<I>,
    ) -> io::Result<Option<String>>
    where
        I: Iterator<Item = (usize, CommandOrArg<'a>)>,
    {
        let mut current_column = 0;

        let mut returned = None;

        let window_columns = crossterm::terminal::size()?.0;

        crossterm::execute!(
            stdout_locker,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
        )?;

        while let Some((index, coa)) = matched_inputs.peek() {
            let tab_completion = match coa {
                CommandOrArg::Command(command) => command.name,
                CommandOrArg::Arg(arg) => &arg,
            };

            let char_count = tab_completion.chars().count();

            if current_column + char_count <= window_columns.into() {
                if self.highlight_selected(stdout_locker, *index)? {
                    returned = Some(tab_completion.to_string());
                }

                write!(stdout_locker, "{}", tab_completion)?;

                self.remove_highlight(stdout_locker, *index)?;

                if current_column + char_count + 1 <= window_columns.into() {
                    write!(stdout_locker, " ")?;

                    current_column += 1;
                }

                current_column += char_count;

                matched_inputs.next();
            } else {
                break;
            }
        }

        Ok(returned)
    }

    #[inline]
    fn highlight_selected(&self, stdout_locker: &mut StdoutLocker, index: usize) -> std::io::Result<bool> {
        if index == self.tab_terminal.highlighted_index {
            crossterm::execute!(stdout_locker, Self::BACKGROUND_COLOR)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[inline]
    fn remove_highlight(&self, stdout_locker: &mut StdoutLocker, index: usize) -> std::io::Result<()> {
        if index == self.tab_terminal.highlighted_index {
            crossterm::execute!(stdout_locker, crossterm::style::ResetColor)?;
        }

        Ok(())
    }
}
