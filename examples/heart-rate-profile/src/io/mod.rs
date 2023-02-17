//! IO with the user
//!
//! Terminal input and output is handled within this module. None of the code here is needed to show
//! how the library works, this is purely for user interaction with the example.
//!
//! Pairing authentication is dealt with in the [`authentication`] module.

use bo_tie::host::sm::pairing::PairingFailedReason;
use bo_tie::BluetoothDeviceAddress;
use crossterm::style::{Color, ResetColor, SetForegroundColor};
use std::io;
use std::io::Write;
use std::str::SplitWhitespace;
use std::time::Duration;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

const ORANGE: Color = Color::Rgb { r: 255, g: 153, b: 0 };

/// Chunk the description to the DESCRIPTION_WIDTH while moving words to the next line if
/// they are to be split by the maximum width.
fn pretty_string_chunks(string: &'static str, to: usize) -> impl Iterator<Item = &'static str> {
    let mut last_space_index = 0;

    let mut last_end_index = 0;

    let mut chars_from_space = 0;

    let mut chunked_chars = 0;

    string.char_indices().enumerate().filter_map(move |(cnt, (index, c))| {
        if c == ' ' {
            last_space_index = index;
            chars_from_space = 0;
        } else {
            chars_from_space += 1;
        }

        if cnt == chunked_chars + to {
            let start = last_end_index;

            let end = if last_space_index < last_end_index {
                last_end_index = index + c.len_utf8();
                last_end_index
            } else {
                last_end_index = last_space_index + ' '.len_utf8();
                last_space_index
            };

            chunked_chars = cnt - chars_from_space;

            Some(&string[start..end])
        } else if index + c.len_utf8() == string.len() {
            // reached end
            Some(&string[last_end_index..string.len()])
        } else {
            None
        }
    })
}

struct Command {
    name: &'static str,
    description: &'static str,
    args_description: &'static str,
    sub_commands: &'static [SubCommand],
    job: fn(&mut UserInOut, &Command, &mut SplitWhitespace) -> io::Result<Option<UserAction>>,
}

impl Command {
    fn pretty_chunk_description(&self, to: usize) -> impl Iterator<Item = &'static str> {
        pretty_string_chunks(self.description, to)
    }
}

struct SubCommand {
    name: &'static str,
    description: &'static str,
    args_description: &'static str,
    job: fn(&mut UserInOut, &mut SplitWhitespace) -> io::Result<Option<UserAction>>,
}

impl SubCommand {
    fn pretty_chunk_description(&self, to: usize) -> impl Iterator<Item = &'static str> {
        pretty_string_chunks(self.description, to)
    }
}

/// User Input/Output Processing
pub struct UserInOut {
    stdout: io::Stdout,
    user_input: String,
    status: Status,
    receiver: UnboundedReceiver<crossterm::event::Event>,
    task_cancel: std::sync::mpsc::SyncSender<()>,
}

impl UserInOut {
    const MAIN_COMMANDS: &'static [Command] = &[
        Command {
            name: "help",
            description: "Display this help information.",
            args_description: "",
            sub_commands: &[],
            job: Self::print_help,
        },
        Command {
            name: "advertise",
            description: "Enable or disable advertising. This command must be called with one of \
                its sub commands.",
            args_description: "",
            job: Self::find_sub_command,
            sub_commands: &[
                SubCommand {
                    name: "discoverable",
                    description: "Start advertising as a discoverable device. Any device will be \
                        able to connect to the example, so discoverable advertising should only \
                        enabled when initially connecting an non-bonded device.",
                    args_description: "",
                    job: Self::advertise_discoverable,
                },
                SubCommand {
                    name: "private",
                    description: "Enable advertising for bonded devices. Only devices that have \
                        previously bonded and exchanged identity resolving keys with this example \
                        can connect. If privacy is implemented in the host, and non bonded devices \
                        that do connect will be promptly disconnected.",
                    args_description: "",
                    job: Self::advertise_private,
                },
                SubCommand {
                    name: "off",
                    description: "Disable advertising. No devices will be able to connect to this \
                        example.",
                    args_description: "",
                    job: Self::advertise_off,
                },
            ],
        },
        Command {
            name: "pair",
            description: "Control pairing to another device.",
            args_description: "",
            job: Self::find_sub_command,
            sub_commands: &[
                SubCommand {
                    name: "reject",
                    description: "Reject the device(s) trying to pair. If specified with the \
                        argument \"all\" then every devices trying to pair is rejected.",
                    args_description: "[ADDRESS... | all]",
                    job: Self::pairing_reject,
                },
                SubCommand {
                    name: "accept",
                    description: "Accept a pairing request of a device.",
                    args_description: "ADDRESS",
                    job: Self::pairing_accept,
                },
            ],
        },
        Command {
            name: "status",
            description: "Show the status of this example",
            args_description: "",
            sub_commands: &[],
            job: Self::print_status,
        },
        Command {
            name: "exit",
            description: "Exit this example. Advertising will be disabled and any currently \
                connected devices will be disconnected",
            args_description: "",
            sub_commands: &[],
            job: Self::exit,
        },
        Command {
            name: "quit",
            description: r#"same as command "exit""#,
            args_description: "",
            sub_commands: &[],
            job: Self::exit,
        },
    ];

    const NUMBER_COMPARISON_COMMANDS: &'static [Command] = &[
        Command {
            name: "help",
            description: "show this help information for number comparison authentication.",
            args_description: "",
            sub_commands: &[],
            job: Self::number_comparison_help,
        },
        Command {
            name: "yes",
            description: "Validate that the same number is displayed on both devices.",
            args_description: "",
            sub_commands: &[],
            job: Self::number_comparison_yes,
        },
        Command {
            name: "no",
            description: "Invalidate the numbers displayed on both devices. This can also be used \
                to just cancel the pairing between the two devices.",
            args_description: "",
            sub_commands: &[],
            job: Self::number_comparison_no,
        },
        Command {
            name: "exit",
            description: "Cancel the number comparison and exit the example. Advertising will be \
                disabled and any currently connected devices will be disconnected.",
            args_description: "",
            sub_commands: &[],
            job: Self::exit,
        },
    ];

    const PASSKEY_INPUT_COMMANDS: &'static [Command] = &[
        Command {
            name: "help",
            description: "show this help information for number comparison authentication.",
            args_description: "",
            sub_commands: &[],
            job: Self::passkey_input_help,
        },
        Command {
            name: "[PASSKEY]",
            description: "The six digit passkey displayed on the other device. Pairing will fail \
                if what entered number does not match the passkey displayed on the other device",
            args_description: "",
            sub_commands: &[],
            job: Self::passkey_input_silly_help,
        },
        Command {
            name: "cancel",
            description: "Cancel the passkey authentication and disconnect the device",
            args_description: "",
            sub_commands: &[],
            job: Self::passkey_cancel,
        },
        Command {
            name: "exit",
            description: "Cancel the passkey input and exit the example. Advertising will be \
                disabled and any currently connected devices will be disconnected.",
            args_description: "",
            sub_commands: &[],
            job: Self::exit,
        },
    ];

    const PASSKEY_OUTPUT_COMMANDS: &'static [Command] = &[
        Command {
            name: "cancel",
            description: "Cancel the passkey authentication and disconnect the device",
            args_description: "",
            sub_commands: &[],
            job: Self::passkey_cancel,
        },
        Command {
            name: "exit",
            description: "Cancel the passkey input and exit the example. Advertising will be \
                disabled and any currently connected devices will be disconnected.",
            args_description: "",
            sub_commands: &[],
            job: Self::exit,
        },
    ];

    pub fn new() -> Self {
        let next_prompt = NextPrompt::new();

        let status = Status {
            next_prompt,
            advertising_status: AdvertisingStatus::Off,
            authentication_kind: None,
            current_pair: None,
        };

        let (sender, receiver) = unbounded_channel();

        let user_input = String::new();

        let task_cancel = spawn_user_input_task(sender);

        let stdout = io::stdout();

        UserInOut {
            stdout,
            user_input,
            status,
            receiver,
            task_cancel,
        }
    }

    fn process_key_event(&mut self, event: crossterm::event::Event) -> Option<String> {
        use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

        match event {
            Event::Key(KeyEvent {
                code: KeyCode::Char('c'),
                modifiers: KeyModifiers::CONTROL,
                ..
            }) => Some("exit".to_string()),
            Event::Key(KeyEvent {
                code: KeyCode::Char(key),
                ..
            }) => {
                self.user_input.push(key);
                None
            }
            Event::Key(KeyEvent {
                code: KeyCode::Enter, ..
            }) => Some(core::mem::take(&mut self.user_input)),
            _ => None,
        }
    }

    fn prompt_main(&mut self) -> io::Result<()> {
        match self.status.advertising_status {
            AdvertisingStatus::Discoverable => {
                crossterm::execute!(self.stdout, SetForegroundColor(Color::Red))?;

                write!(self.stdout, "[HRP-discoverable]")
            }
            AdvertisingStatus::Private => {
                crossterm::execute!(self.stdout, SetForegroundColor(Color::Green))?;

                write!(self.stdout, "[HRP-private]")
            }
            AdvertisingStatus::Off => {
                crossterm::execute!(self.stdout, SetForegroundColor(Color::DarkGreen))?;

                write!(self.stdout, "[HRP]")
            }
        }
    }

    fn prompt_authentication(&mut self) -> io::Result<()> {
        crossterm::execute!(self.stdout, SetForegroundColor(ORANGE))?;

        match self.status.authentication_kind {
            Some(AuthenticationKind::NumberComparison) => {
                write!(self.stdout, "[number-comparison")?;

                crossterm::execute!(self.stdout, SetForegroundColor(Color::Yellow))?;

                write!(self.stdout, " {} ", self.status.current_pair.unwrap())?;

                crossterm::execute!(self.stdout, SetForegroundColor(ORANGE))?;

                write!(self.stdout, "]")
            }
            Some(AuthenticationKind::PasskeyInput) => {
                write!(self.stdout, "[passkey-input")?;

                crossterm::execute!(self.stdout, SetForegroundColor(Color::Yellow))?;

                write!(self.stdout, " {} ", self.status.current_pair.unwrap())?;

                crossterm::execute!(self.stdout, SetForegroundColor(ORANGE))?;

                write!(self.stdout, "]")
            }
            Some(AuthenticationKind::PasskeyOutput) => {
                write!(self.stdout, "[passkey-output")?;

                crossterm::execute!(self.stdout, SetForegroundColor(Color::Yellow))?;

                write!(self.stdout, " {} ", self.status.current_pair.unwrap())?;

                crossterm::execute!(self.stdout, SetForegroundColor(ORANGE))?;

                write!(self.stdout, "]")
            }
            None => panic!("prompted authentication with no authentication"),
        }
    }

    fn prompt(&mut self) -> io::Result<()> {
        match self.status.next_prompt.next() {
            Prompt::None => return Ok(()),
            Prompt::Main => self.prompt_main()?,
            Prompt::Authentication => self.prompt_authentication()?,
        }

        crossterm::execute!(io::stdout(), ResetColor)?;

        write!(self.stdout, ">>> ")?;

        self.stdout.flush()
    }

    fn print_unknown_command(&mut self, input: &str) -> io::Result<()> {
        crossterm::execute!(self.stdout, ResetColor)?;

        write!(self.stdout, "unknown command ")?;

        crossterm::execute!(self.stdout, SetForegroundColor(Color::Red))?;

        writeln!(self.stdout, "{}", input)?;

        crossterm::execute!(io::stdout(), ResetColor)?;

        write!(self.stdout, "for a list of commands type ")?;

        crossterm::execute!(self.stdout, SetForegroundColor(Color::Blue))?;

        writeln!(self.stdout, "help")?;

        self.stdout.flush()
    }

    pub fn init_greeting(&mut self) -> io::Result<()> {
        crossterm::execute!(self.stdout, SetForegroundColor(Color::Green))?;

        writeln!(self.stdout, "Bluetooth LE Heart Rate Profile Example")?;

        crossterm::execute!(self.stdout, ResetColor)?;

        write!(self.stdout, "for a list of commands type ")?;

        crossterm::execute!(self.stdout, SetForegroundColor(Color::Blue))?;

        writeln!(self.stdout, "help")?;

        self.stdout.flush()
    }

    /// Scrape user input
    ///
    /// The input currently entered by the user is taken and saved, the line is then cleared.
    async fn scrape_user_input(&mut self) -> io::Result<()> {
        self.status.next_prompt.input_erased();

        crossterm::terminal::enable_raw_mode()?;

        while let Ok(Some(event)) = tokio::time::timeout(Duration::from_millis(100), self.receiver.recv()).await {
            // this should not ever return Some, but in
            // case it does the input is mapped back.
            self.process_key_event(event).map(|input| self.user_input = input);
        }

        let current = crossterm::cursor::position()?;

        crossterm::execute!(
            io::stdout(),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
            crossterm::cursor::MoveTo(0, current.1)
        )?;

        crossterm::terminal::disable_raw_mode()?;

        Ok(())
    }

    /// Clear user input
    ///
    /// The input currently entered by the user is taken and dropped, the line is then cleared.
    async fn clear_user_input(&mut self) -> io::Result<()> {
        self.status.next_prompt.input_erased();

        crossterm::terminal::enable_raw_mode()?;

        while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100), self.receiver.recv()).await {}

        let current = crossterm::cursor::position()?;

        crossterm::execute!(
            io::stdout(),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
            crossterm::cursor::MoveTo(0, current.1)
        )?;

        crossterm::terminal::disable_raw_mode()?;

        Ok(())
    }

    pub async fn on_connection(&mut self, address: BluetoothDeviceAddress, status: ConnectedStatus) -> io::Result<()> {
        self.scrape_user_input().await?;

        match status {
            ConnectedStatus::New => {
                crossterm::execute!(self.stdout, SetForegroundColor(Color::Yellow))?;

                write!(self.stdout, "<connected>")?;

                crossterm::execute!(self.stdout, ResetColor)?;

                writeln!(self.stdout, " new device {}", address)?;
            }
            ConnectedStatus::Bonded => {
                crossterm::execute!(self.stdout, SetForegroundColor(Color::Green))?;

                write!(self.stdout, "<connected>")?;

                crossterm::execute!(self.stdout, ResetColor)?;

                writeln!(self.stdout, " previously bonded {}", address)?;
            }
        }

        self.stdout.flush()
    }

    /// Callback for an unauthenticated connection
    ///
    /// When in [host implemented privacy mode] any devices can connect but only those that have
    /// gone through an authenticated pairing process and bonded will be allowed to access the ATT
    /// server. Any other device will cause this method to be called and have the '<unauthenticated
    /// connected>' message appear.
    pub async fn on_unauthenticated_connection(&mut self, address: BluetoothDeviceAddress) -> io::Result<()> {
        self.scrape_user_input().await?;

        crossterm::execute!(io::stdout(), SetForegroundColor(Color::Red))?;

        write!(self.stdout, "<unauthenticated connected>")?;

        crossterm::execute!(io::stdout(), ResetColor)?;

        writeln!(self.stdout, " {address} ...action taken: disconnected")?;

        self.stdout.flush()
    }

    pub async fn on_request_pairing(&mut self, address: BluetoothDeviceAddress) -> io::Result<()> {
        self.scrape_user_input().await?;

        crossterm::execute!(io::stdout(), SetForegroundColor(Color::Yellow))?;

        writeln!(self.stdout, "<pairing request>")?;

        crossterm::execute!(io::stdout(), ResetColor)?;

        writeln!(self.stdout, "{address}")?;

        self.stdout.flush()
    }

    pub async fn on_pairing_failed(
        &mut self,
        address: BluetoothDeviceAddress,
        reason: PairingFailedReason,
    ) -> io::Result<()> {
        self.scrape_user_input().await?;

        crossterm::execute!(io::stdout(), SetForegroundColor(Color::Red))?;

        write!(self.stdout, "<pairing failed>")?;

        crossterm::execute!(io::stdout(), ResetColor)?;

        writeln!(self.stdout, " {address} ...reason: {reason}")?;

        self.stdout.flush()?;

        Ok(())
    }

    pub async fn on_number_comparison(&mut self, number: String) -> io::Result<()> {
        self.scrape_user_input().await?;

        self.status.next_prompt.prompt_authentication();

        crossterm::execute!(io::stdout(), SetForegroundColor(Color::Magenta))?;

        write!(self.stdout, "<authentication>")?;

        crossterm::execute!(io::stdout(), ResetColor)?;

        write!(self.stdout, " does ")?;

        crossterm::execute!(io::stdout(), SetForegroundColor(Color::Blue))?;

        write!(self.stdout, "{number}")?;

        writeln!(self.stdout, " match the number displayed on the other device? [Y/n]")?;

        self.stdout.flush()
    }

    pub async fn on_passkey_input(&mut self) -> io::Result<()> {
        self.scrape_user_input().await?;

        self.status.next_prompt.prompt_authentication();

        crossterm::execute!(io::stdout(), SetForegroundColor(Color::Magenta))?;

        write!(self.stdout, "<authentication>")?;

        crossterm::execute!(io::stdout(), ResetColor)?;

        writeln!(self.stdout, " enter the passkey displayed on the other device")?;

        self.stdout.flush()
    }

    pub async fn on_passkey_output(&mut self, passkey: String) -> io::Result<()> {
        self.scrape_user_input().await?;

        self.status.next_prompt.prompt_authentication();

        crossterm::execute!(io::stdout(), SetForegroundColor(Color::Magenta))?;

        write!(self.stdout, "<authentication>")?;

        crossterm::execute!(io::stdout(), ResetColor)?;

        write!(self.stdout, " enter the passkey ")?;

        crossterm::execute!(io::stdout(), SetForegroundColor(Color::Blue))?;

        write!(self.stdout, "{passkey}")?;

        crossterm::execute!(io::stdout(), ResetColor)?;

        writeln!(self.stdout, " into the other device")?;

        self.stdout.flush()
    }

    pub async fn on_bonded(&mut self, address: BluetoothDeviceAddress) -> io::Result<()> {
        self.scrape_user_input().await?;

        crossterm::execute!(io::stdout(), SetForegroundColor(Color::Green))?;

        write!(self.stdout, "<bonded>")?;

        crossterm::execute!(io::stdout(), ResetColor)?;

        writeln!(self.stdout, " {address}")?;

        self.stdout.flush()
    }

    /// Shutdown the User I/O
    pub async fn shutdown_io(mut self) -> io::Result<()> {
        self.task_cancel.send(()).unwrap();

        self.stdout.flush()
    }

    /// Print the help information for a command
    fn print_command_help(&mut self, command: &Command) -> io::Result<()> {
        const COMMAND_WIDTH: usize = 30;
        const DESCRIPTION_WITH: usize = 80 - 2 - COMMAND_WIDTH;

        let mut displayed_command = if !command.sub_commands.is_empty() {
            command.name.to_string() + " COMMAND "
        } else {
            command.name.to_string() + " "
        };

        displayed_command.extend(std::iter::repeat('-').take(COMMAND_WIDTH - displayed_command.len()));

        let mut opt_displayed_command = Some(displayed_command);

        command
            .pretty_chunk_description(DESCRIPTION_WITH)
            .try_for_each(|description_chunk| {
                writeln!(
                    self.stdout,
                    "{0:<1$} {2:<3$}",
                    opt_displayed_command.take().unwrap_or_default(),
                    COMMAND_WIDTH,
                    description_chunk,
                    DESCRIPTION_WITH
                )
            })?;

        for sub_command in command.sub_commands {
            let mut sub_command_name = sub_command.name.to_string() + " " + sub_command.args_description + " ";

            let mut opt_sub_command_name = Some(sub_command_name);

            sub_command
                .pretty_chunk_description(DESCRIPTION_WITH)
                .try_for_each(|description_chunk| {
                    writeln!(
                        self.stdout,
                        "   {0:<1$} {2:<3$}",
                        opt_sub_command_name.take().unwrap_or_default(),
                        COMMAND_WIDTH - 3,
                        description_chunk,
                        DESCRIPTION_WITH
                    )
                })?;
        }

        Ok(())
    }

    fn print_help(&mut self, _: &Command, _: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        crossterm::execute!(self.stdout, ResetColor)?;

        writeln!(self.stdout, "list of commands:\n")?;

        for command in Self::MAIN_COMMANDS {
            self.print_command_help(command)?;
        }

        self.stdout.flush()?;

        Ok(None)
    }

    fn find_sub_command(&mut self, command: &Command, input: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        crossterm::execute!(self.stdout, ResetColor)?;

        macro_rules! help {
            () => {{
                write!(
                    self.stdout,
                    r#"for the list of sub commands of "{}" type "#,
                    command.name
                )?;

                crossterm::execute!(self.stdout, SetForegroundColor(Color::Blue))?;

                writeln!(self.stdout, "help")?;
            }};
        }

        match input.next() {
            None => {
                writeln!(self.stdout, r#"command "{}" must have a sub command"#, command.name)?;

                help!();

                Ok(None)
            }
            Some(sub_name) => match command.sub_commands.iter().find(|sub| sub.name == sub_name) {
                None => {
                    writeln!(self.stdout, "unknown sub command {}", sub_name)?;

                    help!();

                    Ok(None)
                }
                Some(sub_command) => (sub_command.job)(self, input),
            },
        }
    }

    fn print_status(&mut self, _: &Command, _: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        crossterm::execute!(self.stdout, ResetColor)?;

        writeln!(self.stdout, "device status: ")?;

        write!(self.stdout, "advertising: ")?;

        match self.status.advertising_status {
            AdvertisingStatus::Discoverable => {
                crossterm::execute!(self.stdout, SetForegroundColor(Color::Red))?;

                writeln!(self.stdout, "discoverable")?;
            }
            AdvertisingStatus::Private => {
                crossterm::execute!(self.stdout, SetForegroundColor(Color::Cyan))?;

                writeln!(self.stdout, "private")?;
            }
            AdvertisingStatus::Off => {
                crossterm::execute!(self.stdout, SetForegroundColor(Color::Black))?;

                writeln!(self.stdout, "private")?;
            }
        }

        write!(self.stdout, "connected devices:")?;

        crossterm::execute!(self.stdout, SetForegroundColor(Color::Yellow))?;

        write!(self.stdout, " todo")?;

        self.stdout.flush()?;

        Ok(None)
    }

    fn exit(&mut self, _: &Command, _: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        Ok(Some(UserAction::Exit))
    }

    fn number_comparison_help(&mut self, _: &Command, _: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        crossterm::execute!(self.stdout, ResetColor)?;

        writeln!(self.stdout, "list of commands:\n")?;

        for command in Self::NUMBER_COMPARISON_COMMANDS {
            self.print_command_help(command)?;
        }

        self.stdout.flush()?;

        Ok(None)
    }

    fn number_comparison_yes(&mut self, _: &Command, _: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        self.status.next_prompt.prompt_main();

        let current = self.status.current_pair.take().unwrap();

        Ok(Some(UserAction::NumberComparisonYes(current)))
    }

    fn number_comparison_no(&mut self, _: &Command, _: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        self.status.next_prompt.prompt_main();

        let current = self.status.current_pair.take().unwrap();

        Ok(Some(UserAction::NumberComparisonNo(current)))
    }

    fn passkey_input_help(&mut self, _: &Command, _: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        crossterm::execute!(self.stdout, ResetColor)?;

        writeln!(self.stdout, "list of commands:\n")?;

        for command in Self::PASSKEY_INPUT_COMMANDS {
            self.print_command_help(command)?;
        }

        self.stdout.flush()?;

        Ok(None)
    }

    fn passkey_input_silly_help(&mut self, _: &Command, _: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        crossterm::execute!(self.stdout, ResetColor)?;

        write!(self.stdout, "expected a six digit number like ")?;

        crossterm::execute!(self.stdout, SetForegroundColor(Color::Cyan))?;

        write!(self.stdout, "123456")?;

        crossterm::execute!(self.stdout, ResetColor)?;

        writeln!(self.stdout, " not literally the word \"[𝘗𝘈𝘚𝘚𝘒𝘌𝘠]\"")?;

        self.stdout.flush()?;

        Ok(None)
    }

    fn passkey_cancel(&mut self, _: &Command, _: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        self.status.next_prompt.prompt_main();

        let current = self.status.current_pair.take().unwrap();

        Ok(Some(UserAction::PasskeyCancel(current)))
    }

    async fn passkey_user_input(&mut self, passkey_str: &str) -> io::Result<Option<UserAction>> {
        if passkey_str.chars().count() == 6 && passkey_str.chars().all(|char| char.is_digit(10)) {
            self.status.next_prompt.prompt_main();

            let current = self.status.current_pair.take().unwrap();

            let mut passkey = <[char; 6]>::default();

            passkey_str.chars().zip(passkey.iter_mut()).for_each(|(l, r)| *r = l);

            Ok(Some(UserAction::PasskeyInput(passkey, current)))
        } else if passkey_str.chars().all(|c| !c.is_digit(10)) {
            self.print_unknown_command(passkey_str)?;

            Ok(None)
        } else if passkey_str.chars().count() != 6 {
            self.scrape_user_input().await.unwrap();

            crossterm::execute!(self.stdout, ResetColor)?;

            writeln!(
                self.stdout,
                "A passkey must consist of six digits. If the other device is displaying less than \
                six digits, enter in the passkey padded with zeros (e.g. 1234 becomes 001234)."
            )?;

            self.stdout.flush()?;

            Ok(None)
        } else {
            crossterm::execute!(self.stdout, ResetColor)?;

            writeln!(
                self.stdout,
                "A passkey must consist of six digits. Characters within the passkey were not a \
                digit."
            )?;

            self.stdout.flush()?;

            Ok(None)
        }
    }

    fn passkey_output_cancel(&mut self, _: &Command, _: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        self.status.next_prompt.prompt_main();

        let current = self.status.current_pair.take().unwrap();

        Ok(Some(UserAction::PasskeyCancel(current)))
    }

    fn advertise_discoverable(&mut self, _: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        self.status.advertising_status = AdvertisingStatus::Discoverable;

        Ok(Some(UserAction::AdvertiseDiscoverable))
    }

    fn advertise_private(&mut self, _: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        self.status.advertising_status = AdvertisingStatus::Private;

        Ok(Some(UserAction::AdvertisePrivate))
    }

    fn advertise_off(&mut self, _: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        self.status.advertising_status = AdvertisingStatus::Off;

        Ok(Some(UserAction::StopAdvertising))
    }

    fn pairing_reject(&mut self, input: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        crossterm::execute!(self.stdout, ResetColor)?;

        let mut rejected = Vec::new();

        for arg in input {
            if arg == "all" {
                return Ok(Some(UserAction::PairingRejectAll));
            }

            if let Ok(address) = arg.parse::<BluetoothDeviceAddress>() {
                rejected.push(address);
            } else {
                writeln!(self.stdout, "{} is not a valid address", arg)?;

                writeln!(self.stdout, "Expected an address in the format of XX:XX:XX:XX:XX:XX")?;
            }
        }

        if rejected.is_empty() {
            writeln!(self.stdout, r"subcommand reject must have at least one argument")?;

            Ok(None)
        } else {
            Ok(Some(UserAction::PairingReject(rejected)))
        }
    }

    fn pairing_accept(&mut self, input: &mut SplitWhitespace) -> io::Result<Option<UserAction>> {
        if let Some(address) = input
            .next()
            .and_then(|input| input.parse::<BluetoothDeviceAddress>().ok())
        {
            Ok(Some(UserAction::PairingAccept(address)))
        } else {
            writeln!(
                self.stdout,
                "sub command accept must have a bluetooth address as an argument (e.g. \
                \"pairing accept 4b:8f:02:33:97:17\")"
            )?;

            Ok(None)
        }
    }

    pub async fn device_not_pairing(&mut self, address: BluetoothDeviceAddress) -> io::Result<()> {
        self.scrape_user_input().await?;

        crossterm::execute!(self.stdout, ResetColor)?;

        writeln!(
            self.stdout,
            "cannot pair with device {address} because it is not or no longer trying to pair"
        )?;

        self.stdout.flush()
    }

    pub async fn device_not_connected_for_pairing(&mut self, address: BluetoothDeviceAddress) -> io::Result<()> {
        self.scrape_user_input().await?;

        crossterm::execute!(self.stdout, ResetColor)?;

        writeln!(
            self.stdout,
            "cannot pair with device {address} because it is not connected to this example"
        )?;

        self.stdout.flush()
    }

    fn process_simple_command(
        &mut self,
        mut user_input: SplitWhitespace,
        of: &[Command],
    ) -> io::Result<Option<UserAction>> {
        let command = user_input.next();

        match command {
            None | Some("") => Ok(None),
            Some(cmd_name) => match of.iter().find(|cmd| cmd.name == cmd_name) {
                None => {
                    self.print_unknown_command(cmd_name)?;

                    Ok(None)
                }
                Some(command) => {
                    if let Some(user_action) = (command.job)(self, command, &mut user_input)? {
                        Ok(Some(user_action))
                    } else {
                        Ok(None)
                    }
                }
            },
        }
    }

    async fn process_authentication_command(
        &mut self,
        user_input: SplitWhitespace<'_>,
    ) -> io::Result<Option<UserAction>> {
        match self.status.authentication_kind {
            None => unreachable!(),
            Some(AuthenticationKind::NumberComparison) => {
                self.process_simple_command(user_input, Self::NUMBER_COMPARISON_COMMANDS)
            }
            Some(AuthenticationKind::PasskeyOutput) => {
                self.process_simple_command(user_input, Self::PASSKEY_OUTPUT_COMMANDS)
            }
            Some(AuthenticationKind::PasskeyInput) => self.process_passkey_input_command(user_input).await,
        }
    }

    async fn process_passkey_input_command(
        &mut self,
        mut user_input: SplitWhitespace<'_>,
    ) -> io::Result<Option<UserAction>> {
        let command = user_input.next();

        match command {
            None | Some("") => Ok(None),
            Some(cmd_name) => match Self::PASSKEY_INPUT_COMMANDS.iter().find(|cmd| cmd.name == cmd_name) {
                None => {
                    self.passkey_user_input(cmd_name).await?;

                    Ok(None)
                }
                Some(command) => {
                    if let Some(user_action) = (command.job)(self, command, &mut user_input)? {
                        Ok(Some(user_action))
                    } else {
                        Ok(None)
                    }
                }
            },
        }
    }

    pub async fn await_user(&mut self) -> io::Result<UserAction> {
        crossterm::execute!(self.stdout, ResetColor)?;

        loop {
            self.prompt()?;

            let input = loop {
                match self.receiver.recv().await {
                    None => break "exit".to_string(),
                    Some(event) => {
                        if let Some(input) = self.process_key_event(event) {
                            break input;
                        }
                    }
                }
            };

            let user_input = input.trim().split_whitespace();

            if let Some(user_action) = match self.status.next_prompt.current {
                Prompt::None => unreachable!(),
                Prompt::Main => self.process_simple_command(user_input, Self::MAIN_COMMANDS)?,
                Prompt::Authentication => self.process_authentication_command(user_input).await?,
            } {
                break Ok(user_action);
            }
        }
    }
}

struct Status {
    next_prompt: NextPrompt,
    advertising_status: AdvertisingStatus,
    authentication_kind: Option<AuthenticationKind>,
    current_pair: Option<BluetoothDeviceAddress>,
}

#[derive(Copy, Clone)]
enum AdvertisingStatus {
    Discoverable,
    Private,
    Off,
}

struct ConnectedDevice {
    address: BluetoothDeviceAddress,
    status: ConnectedStatus,
}

#[derive(Copy, Clone)]
pub enum ConnectedStatus {
    New,
    Bonded,
}

impl std::fmt::Display for ConnectedStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConnectedStatus::New => f.write_str("new device (neither bonded and nor requesting pairing)"),
            ConnectedStatus::Bonded => f.write_str("bonded"),
        }
    }
}

struct NextPrompt {
    repeat: bool,
    current: Prompt,
}

impl NextPrompt {
    fn new() -> Self {
        NextPrompt {
            repeat: true,
            current: Prompt::Main,
        }
    }

    fn next(&mut self) -> Prompt {
        if core::mem::take(&mut self.repeat) {
            self.current
        } else {
            Prompt::None
        }
    }

    fn input_erased(&mut self) {
        self.repeat = true
    }

    fn prompt_main(&mut self) {
        self.current = Prompt::Main
    }

    fn prompt_authentication(&mut self) {
        self.current = Prompt::Authentication
    }
}

/// The status of the user prompt
///
/// This is used to:
/// 1) not repeatedly display the prompt when [`await_user`] is called.
/// 2) display the correct prompt.  
#[derive(PartialEq, Eq, Copy, Clone)]
enum Prompt {
    None,
    Main,
    Authentication,
}

enum AuthenticationKind {
    NumberComparison,
    PasskeyInput,
    PasskeyOutput,
}

#[derive(Clone, Debug)]
pub enum UserAction {
    AdvertiseDiscoverable,
    AdvertisePrivate,
    NumberComparisonYes(BluetoothDeviceAddress),
    NumberComparisonNo(BluetoothDeviceAddress),
    PairingRejectAll,
    PairingReject(Vec<BluetoothDeviceAddress>),
    PairingAccept(BluetoothDeviceAddress),
    PasskeyCancel(BluetoothDeviceAddress),
    PasskeyInput([char; 6], BluetoothDeviceAddress),
    StopAdvertising,
    Exit,
}

fn spawn_user_input_task(sender: UnboundedSender<crossterm::event::Event>) -> std::sync::mpsc::SyncSender<()> {
    use crossterm::event::{poll, read, Event, KeyCode, KeyEvent};

    let (cancel_sender, cancel_receiver) = std::sync::mpsc::sync_channel(0);

    std::thread::spawn(move || loop {
        if poll(Duration::from_millis(50)).unwrap() {
            match read().unwrap() {
                e @ Event::Key(KeyEvent {
                    code: KeyCode::Char(_) | KeyCode::Enter,
                    ..
                }) => sender.send(e).unwrap(),
                _ => (),
            }
        } else if let Ok(_) = cancel_receiver.try_recv() {
            break;
        }
    });

    cancel_sender
}
