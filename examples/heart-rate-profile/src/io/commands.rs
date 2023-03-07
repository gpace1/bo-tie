//! Commands for the user to input

use crate::io::UserInputThread;
use bo_tie::BluetoothDeviceAddress;
use std::io::{self, Write};
use std::str::SplitWhitespace;

pub const MAIN_COMMANDS: &'static [InputKind] = &[InputKind::Commands(&[
    Command {
        name: "help",
        description: "Display this help information.",
        args_description: "",
        args: &[],
        job: print_help,
    },
    Command {
        name: "advertise",
        description: "Enable or disable advertising.",
        args_description: "",
        job: parse_command_args,
        args: &[InputKind::Commands(&[
            Command {
                name: "discoverable",
                description: "Start advertising as a discoverable device. Any device will be \
                        able to connect to the example, so discoverable advertising should only \
                        enabled when initially connecting an non-bonded device.",
                args_description: "",
                args: &[],
                job: advertise_discoverable,
            },
            Command {
                name: "private",
                description: "Enable advertising for bonded devices. Only devices that have \
                        previously bonded and exchanged identity resolving keys with this example \
                        can connect. If privacy is implemented in the host, and non bonded devices \
                        that do connect will be promptly disconnected.",
                args_description: "",
                args: &[],
                job: advertise_private,
            },
            Command {
                name: "off",
                description: "Disable advertising. No devices will be able to connect to this \
                        example.",
                args_description: "",
                args: &[],
                job: advertise_off,
            },
        ])],
    },
    Command {
        name: "pair",
        description: "Control pairing to another device.",
        args_description: "",
        job: parse_command_args,
        args: &[
            InputKind::Commands(&[Command {
                name: "reject",
                description: "Reject the device(s) trying to pair.",
                args_description: "[ADDRESS... | all]",
                args: &[InputKind::Commands(&[Command {
                    name: "all",
                    description: "Reject all devices requesting to pair with this example",
                    args_description: "",
                    args: &[],
                    job: pairing_reject_all,
                }])],
                job: pairing_reject,
            }]),
            InputKind::Known(KnownArg {
                format: "[ADDRESS]",
                format_description: "A Bluetooth Device Address (e.g. 12:34:56:78:ab:cd)",
                tab_arg: get_pairing_devices,
                parse: parse_pairing_address,
                job: pairing_accept,
            }),
        ],
    },
    Command {
        name: "status",
        description: "Show the status of this example",
        args_description: "",
        args: &[],
        job: print_status,
    },
    Command {
        name: "bonded",
        description: "bonded devices",
        args_description: "",
        args: &[InputKind::Commands(&[
            Command {
                name: "list",
                description: "List all bonded devices",
                args_description: "",
                args: &[],
                job: show_bonded_devices,
            },
            Command {
                name: "delete",
                description: "delete bonding information",
                args_description: "[ADDRESS|all]",
                args: &[
                    InputKind::Commands(&[Command {
                        name: "all",
                        description: "delete all bonded devices",
                        args_description: "",
                        args: &[],
                        job: delete_all_bonded_devices,
                    }]),
                    InputKind::Known(KnownArg {
                        format: "[ADDRESS]",
                        format_description: "A Bluetooth Device Address (e.g. 12:34:56:78:ab:cd)",
                        tab_arg: get_bonded_devices,
                        parse: parse_bonded_devices,
                        job: delete_bonded_device,
                    }),
                ],
                job: parse_command_args,
            },
        ])],
        job: parse_command_args,
    },
    Command {
        name: "exit",
        description: "Exit this example. Advertising will be disabled and any currently \
                connected devices will be disconnected",
        args_description: "",
        args: &[],
        job: exit,
    },
    Command {
        name: "quit",
        description: r#"same as command "exit""#,
        args_description: "",
        args: &[],
        job: exit,
    },
])];

pub const NUMBER_COMPARISON_COMMANDS: &'static [InputKind] = &[InputKind::Commands(&[
    Command {
        name: "help",
        description: "show this help information for number comparison authentication.",
        args_description: "",
        args: &[],
        job: number_comparison_help,
    },
    Command {
        name: "yes",
        description: "Validate that the same number is displayed on both devices.",
        args_description: "",
        args: &[],
        job: number_comparison_yes,
    },
    Command {
        name: "no",
        description: "Invalidate the numbers displayed on both devices. This can also be used \
                to just cancel the pairing between the two devices.",
        args_description: "",
        args: &[],
        job: number_comparison_no,
    },
    Command {
        name: "exit",
        description: "Cancel the number comparison and exit the example. Advertising will be \
                disabled and any currently connected devices will be disconnected.",
        args_description: "",
        args: &[],
        job: exit,
    },
])];

pub const PASSKEY_INPUT_COMMANDS: &'static [InputKind] = &[
    InputKind::Commands(&[
        Command {
            name: "help",
            description: "show this help information for number comparison authentication.",
            args_description: "",
            args: &[],
            job: passkey_input_help,
        },
        Command {
            name: "[PASSKEY]",
            description: "The six digit passkey displayed on the other device. Pairing will fail \
                if what entered number does not match the passkey displayed on the other device",
            args_description: "",
            args: &[],
            job: passkey_input_silly_help,
        },
        Command {
            name: "cancel",
            description: "Cancel the passkey authentication and disconnect the device",
            args_description: "",
            args: &[],
            job: passkey_cancel,
        },
        Command {
            name: "exit",
            description: "Cancel the passkey input and exit the example. Advertising will be \
                disabled and any currently connected devices will be disconnected.",
            args_description: "",
            args: &[],
            job: exit,
        },
    ]),
    InputKind::Unknown(UnknownArg {
        format: "[PASSKEY]",
        format_description: "The six digit passkey displayed on the other device",
        parse: parse_passkey,
        job: passkey_input,
    }),
];

pub const PASSKEY_OUTPUT_COMMANDS: &'static [InputKind] = &[InputKind::Commands(&[
    Command {
        name: "cancel",
        description: "Cancel the passkey authentication and disconnect the device",
        args_description: "",
        args: &[],
        job: passkey_cancel,
    },
    Command {
        name: "exit",
        description: "Cancel the passkey input and exit the example. Advertising will be \
                disabled and any currently connected devices will be disconnected.",
        args_description: "",
        args: &[],
        job: exit,
    },
])];

pub struct Command {
    pub(super) name: &'static str,
    pub(super) description: &'static str,
    pub(super) args_description: &'static str,
    pub(super) args: &'static [InputKind],
    pub(super) job: fn(&mut UserInputThread, &Command, &mut SplitWhitespace) -> io::Result<bool>,
}

impl Command {
    fn pretty_chunk_description(&self, to: usize) -> impl Iterator<Item = &'static str> {
        pretty_string_chunks(self.description, to)
    }

    fn print_sub_commands(
        &self,
        uit: &mut UserInputThread,
        command_width: usize,
        description_width: usize,
    ) -> io::Result<()> {
        let sub_command_name = self.name.to_string() + " " + self.args_description + " ";

        let mut opt_sub_command_name = Some(sub_command_name);

        self.pretty_chunk_description(description_width)
            .try_for_each(|description_chunk| {
                writeln!(
                    uit.stdout_locker,
                    "   {0:<1$} {2:<3$}",
                    opt_sub_command_name.take().unwrap_or_default(),
                    command_width - 3,
                    description_chunk,
                    description_width
                )
            })
    }

    fn print_help(&self, uit: &mut UserInputThread, command_width: usize, description_width: usize) -> io::Result<()> {
        let mut displayed_command = if self.args.is_empty() {
            self.name.to_string()
        } else if self.args.len() == 1 {
            match &self.args[0] {
                InputKind::Commands(sub_commands) => {
                    if sub_commands.is_empty() {
                        self.name.to_string()
                    } else {
                        self.name.to_string() + "COMMAND"
                    }
                }
                InputKind::Known(known) => self.name.to_string() + known.format,
                InputKind::Unknown(unknown) => self.name.to_string() + unknown.format,
            }
        } else {
            self.args
                .iter()
                .fold(self.name.to_string() + " [", |mix, arg| match arg {
                    InputKind::Commands(commands) => commands.iter().fold(mix, |mix, c| mix + c.name + "|"),
                    InputKind::Known(k) => mix + k.format + "|",
                    InputKind::Unknown(u) => mix + u.format + "|",
                })
                + "]"
        };

        displayed_command.extend(std::iter::repeat('-').take(command_width - displayed_command.len()));

        let mut opt_displayed_command = Some(displayed_command);

        self.pretty_chunk_description(description_width)
            .try_for_each(|description_chunk| {
                writeln!(
                    uit.stdout_locker,
                    "{0:<1$} {2:<3$}",
                    opt_displayed_command.take().unwrap_or_default(),
                    command_width,
                    description_chunk,
                    description_width
                )
            })?;

        for arg in self.args {
            match arg {
                InputKind::Commands(commands) => commands
                    .iter()
                    .try_for_each(|c| c.print_sub_commands(uit, command_width, description_width))?,
                InputKind::Known(k) => k.print_as_args(uit, command_width, description_width)?,
                InputKind::Unknown(u) => u.print_as_args(uit, command_width, description_width)?,
            }
        }

        Ok(())
    }
}

pub struct KnownArg {
    pub(super) format: &'static str,
    pub(super) format_description: &'static str,
    pub(super) tab_arg: fn(&KnownArgData) -> Vec<String>,
    pub(super) parse: fn(&str) -> bool,
    pub(super) job: fn(&mut UserInputThread, &mut SplitWhitespace) -> io::Result<bool>,
}

impl KnownArg {
    fn pretty_chunk_description(&self, to: usize) -> impl Iterator<Item = &'static str> {
        pretty_string_chunks(self.format_description, to)
    }

    fn print_as_args(
        &self,
        uit: &mut UserInputThread,
        command_width: usize,
        description_width: usize,
    ) -> io::Result<()> {
        let displayed_format = "{".to_string() + self.format + "}";

        let mut opt_displayed_format = Some(displayed_format);

        self.pretty_chunk_description(description_width)
            .try_for_each(|description_chunk| {
                writeln!(
                    uit.stdout_locker,
                    "   {0:<1$} {2:<3$}",
                    opt_displayed_format.take().unwrap_or_default(),
                    command_width - 3,
                    description_chunk,
                    description_width
                )
            })
    }

    fn print(&self, uit: &mut UserInputThread, command_width: usize, description_width: usize) -> io::Result<()> {
        let displayed_format = "{".to_string() + self.format + "}";

        let mut opt_displayed_format = Some(displayed_format);

        self.pretty_chunk_description(description_width)
            .try_for_each(|description_chunk| {
                writeln!(
                    uit.stdout_locker,
                    "{0:<1$} {2:<3$}",
                    opt_displayed_format.take().unwrap_or_default(),
                    command_width,
                    description_chunk,
                    description_width
                )
            })
    }
}

pub struct KnownArgData {
    requesting_pairing: Vec<BluetoothDeviceAddress>,
    bonded: Vec<BluetoothDeviceAddress>,
}

impl KnownArgData {
    pub fn new(bonded: Vec<BluetoothDeviceAddress>) -> Self {
        let requesting_pairing = Vec::new();

        KnownArgData {
            requesting_pairing,
            bonded,
        }
    }

    pub fn set_requesting_pairing(&mut self, requesting: Vec<BluetoothDeviceAddress>) {
        self.requesting_pairing = requesting
    }

    pub fn set_bonded(&mut self, bonded: Vec<BluetoothDeviceAddress>) {
        self.bonded = bonded
    }
}

pub struct UnknownArg {
    pub(super) format: &'static str,
    pub(super) format_description: &'static str,
    pub(super) parse: fn(&str) -> bool,
    pub(super) job: fn(&mut UserInputThread, &mut SplitWhitespace) -> io::Result<bool>,
}

impl UnknownArg {
    fn pretty_chunk_description(&self, to: usize) -> impl Iterator<Item = &'static str> {
        pretty_string_chunks(self.format_description, to)
    }

    fn print_as_args(
        &self,
        uit: &mut UserInputThread,
        command_width: usize,
        description_width: usize,
    ) -> io::Result<()> {
        let displayed_format = "[".to_string() + self.format + "]";

        let mut opt_displayed_format = Some(displayed_format);

        self.pretty_chunk_description(description_width)
            .try_for_each(|description_chunk| {
                writeln!(
                    uit.stdout_locker,
                    "   {0:<1$} {2:<3$}",
                    opt_displayed_format.take().unwrap_or_default(),
                    command_width - 3,
                    description_chunk,
                    description_width
                )
            })
    }

    fn print(&self, uit: &mut UserInputThread, command_width: usize, description_width: usize) -> io::Result<()> {
        let displayed_format = "[".to_string() + self.format + "]";

        let mut opt_displayed_format = Some(displayed_format);

        self.pretty_chunk_description(description_width)
            .try_for_each(|description_chunk| {
                writeln!(
                    uit.stdout_locker,
                    "{0:<1$} {2:<3$}",
                    opt_displayed_format.take().unwrap_or_default(),
                    command_width,
                    description_chunk,
                    description_width
                )
            })
    }
}

pub enum InputKind {
    Commands(&'static [Command]),
    Known(KnownArg),
    Unknown(UnknownArg),
}

macro_rules! match_exec {
    ($input_kind:expr, $uit:expr, $first_input:expr, $split_input:expr) => {
        match $input_kind {
            InputKind::Commands(commands) => {
                for command in *commands {
                    if command.name == $first_input {
                        // skip the first input for commands.
                        $split_input.next();

                        return (command.job)($uit, command, $split_input);
                    }
                }
            }
            InputKind::Known(known) => {
                if (known.parse)($first_input) {
                    return (known.job)($uit, $split_input);
                }
            }
            InputKind::Unknown(unknown) => {
                if (unknown.parse)($first_input) {
                    return (unknown.job)($uit, $split_input);
                }
            }
        }
    };
}

impl InputKind {
    fn print_help(&self, uit: &mut UserInputThread) -> io::Result<()> {
        const COMMAND_WIDTH: usize = 30;
        const DESCRIPTION_WITH: usize = 80 - 2 - COMMAND_WIDTH;

        match self {
            InputKind::Commands(commands) => commands
                .iter()
                .try_for_each(|c| c.print_help(uit, COMMAND_WIDTH, DESCRIPTION_WITH)),
            InputKind::Known(k) => k.print(uit, COMMAND_WIDTH, DESCRIPTION_WITH),
            InputKind::Unknown(u) => u.print(uit, COMMAND_WIDTH, DESCRIPTION_WITH),
        }
    }

    pub(super) fn exec_input(
        uit: &mut UserInputThread,
        input_kinds: &[InputKind],
        displayed_input: String,
    ) -> io::Result<bool> {
        let mut split_input = displayed_input.split_whitespace();

        if let Some(first) = split_input.clone().next() {
            for kind in input_kinds {
                match_exec!(kind, uit, first, &mut split_input)
            }

            uit.print_on_next_line(format_args!(
                "Unknown input \"{}\". For a list of commands type 'help'",
                first
            ))?;
        }

        Ok(false)
    }
}

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

#[derive(Clone, Debug)]
pub enum FromUserInput {
    AdvertiseDiscoverable,
    AdvertisePrivate,
    NumberComparisonYes,
    NumberComparisonNo,
    PairingRejectAll,
    PairingReject(Vec<BluetoothDeviceAddress>),
    PairingAccept(BluetoothDeviceAddress),
    PasskeyCancel,
    PasskeyInput([char; 6]),
    StopAdvertising,
    DeleteAllBonded,
    DeleteBonded(BluetoothDeviceAddress),
    Exit,
}

fn print_invalid_command(uit: &mut UserInputThread, args: std::fmt::Arguments<'_>) -> io::Result<bool> {
    uit.print_on_next_line(format_args!("{}", args))?;

    Ok(false)
}

fn parse_command_args(uit: &mut UserInputThread, this: &Command, args: &mut SplitWhitespace) -> io::Result<bool> {
    if let Some(first_arg) = args.clone().next() {
        for arg in this.args {
            match_exec!(arg, uit, first_arg, args)
        }

        uit.print_on_next_line(format_args!(
            "unknown argument '{first_arg}' to command '{}'",
            this.name
        ))?;

        Ok(false)
    } else {
        uit.print_on_next_line(format_args!("command '{}' requires an argument", this.name))?;

        Ok(false)
    }
}

fn print_help(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.print_on_next_line(format_args!("list of commands:\n"))?;

    for input in MAIN_COMMANDS {
        input.print_help(uit)?;
    }

    Ok(false)
}

fn advertise_discoverable(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.from_ui.send(FromUserInput::AdvertiseDiscoverable).unwrap();

    Ok(false)
}

fn advertise_private(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.from_ui.send(FromUserInput::AdvertisePrivate).unwrap();

    Ok(false)
}

fn advertise_off(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.from_ui.send(FromUserInput::StopAdvertising).unwrap();

    Ok(false)
}

fn pairing_reject(uit: &mut UserInputThread, _: &Command, inputs: &mut SplitWhitespace) -> io::Result<bool> {
    let mut rejected = Vec::new();

    for input in inputs {
        if let Ok(address) = BluetoothDeviceAddress::try_from(input) {
            rejected.push(address);
        } else {
            return print_invalid_command(uit, format_args!(r#""{}" is not a valid address"#, input));
        }
    }

    if rejected.is_empty() {
        return print_invalid_command(
            uit,
            format_args!(r#"command "pair reject" requires at least one Bluetooth device address"#),
        );
    }

    uit.from_ui.send(FromUserInput::PairingReject(rejected)).unwrap();

    Ok(false)
}

fn pairing_reject_all(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.from_ui.send(FromUserInput::PairingRejectAll).unwrap();

    Ok(false)
}

fn get_pairing_devices(data: &KnownArgData) -> Vec<String> {
    data.requesting_pairing
        .iter()
        .map(|address| address.to_string())
        .collect()
}

fn parse_pairing_address(input: &str) -> bool {
    BluetoothDeviceAddress::try_from(input).is_ok()
}

fn pairing_accept(uit: &mut UserInputThread, inputs: &mut SplitWhitespace) -> io::Result<bool> {
    let address = BluetoothDeviceAddress::try_from(inputs.next().unwrap()).unwrap();

    uit.from_ui.send(FromUserInput::PairingAccept(address)).unwrap();

    Ok(false)
}

fn print_status(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.print_on_next_line(format_args!("status unsupported"))?;

    Ok(false)
}

fn exit(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.from_ui.send(FromUserInput::Exit).unwrap();

    Ok(true)
}

fn number_comparison_help(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.print_on_next_line(format_args!("list of commands:\n"))?;

    for input in NUMBER_COMPARISON_COMMANDS {
        input.print_help(uit)?;
    }

    Ok(false)
}

fn number_comparison_yes(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.from_ui.send(FromUserInput::NumberComparisonYes).unwrap();

    Ok(false)
}

fn number_comparison_no(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.from_ui.send(FromUserInput::NumberComparisonNo).unwrap();

    Ok(false)
}

fn passkey_input_help(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.print_on_next_line(format_args!("list of commands:\n"))?;

    for input in PASSKEY_INPUT_COMMANDS {
        input.print_help(uit)?;
    }

    Ok(false)
}

fn passkey_input_silly_help(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.print_on_next_line(format_args!(
        r#"expected a six digit number like "123456" not literally the input "[𝘗𝘈𝘚𝘚𝘒𝘌𝘠]""#
    ))?;

    Ok(false)
}

fn passkey_cancel(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.from_ui.send(FromUserInput::PasskeyCancel).unwrap();

    Ok(false)
}

fn parse_passkey(input: &str) -> bool {
    input.chars().count() == 6 && input.chars().all(|c| c.is_digit(10))
}

fn passkey_input(uit: &mut UserInputThread, input: &mut SplitWhitespace) -> io::Result<bool> {
    let mut passkey: [char; 6] = Default::default();

    input
        .next()
        .unwrap()
        .chars()
        .enumerate()
        .for_each(|(index, c)| passkey[index] = c);

    uit.from_ui.send(FromUserInput::PasskeyInput(passkey)).unwrap();

    Ok(false)
}

fn show_bonded_devices(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    const CHARS_PER_ADDRESS: usize = 12 + 5;

    uit.print_on_next_line(format_args!(""))?;

    uit.known_arg_data.bonded.iter().try_for_each(|address| {
        let cursor_column: usize = crossterm::cursor::position()?.0.into();
        let window_columns: usize = crossterm::terminal::size()?.0.into();

        if cursor_column == 0 || cursor_column + CHARS_PER_ADDRESS <= window_columns {
            if cursor_column + CHARS_PER_ADDRESS + 1 <= window_columns {
                write!(uit.stdout_locker, "{} ", address)?;
            } else {
                writeln!(uit.stdout_locker, "{}", address)?;
            }
        } else {
            writeln!(uit.stdout_locker)?;

            write!(uit.stdout_locker, "{} ", address)?;
        }

        Ok::<_, io::Error>(())
    })?;

    Ok(false)
}

fn delete_all_bonded_devices(uit: &mut UserInputThread, _: &Command, _: &mut SplitWhitespace) -> io::Result<bool> {
    uit.from_ui.send(FromUserInput::DeleteAllBonded).unwrap();

    Ok(false)
}

fn get_bonded_devices(known: &KnownArgData) -> Vec<String> {
    known.bonded.iter().map(|address| address.to_string()).collect()
}

fn parse_bonded_devices(input: &str) -> bool {
    BluetoothDeviceAddress::try_from(input).is_ok()
}

fn delete_bonded_device(uit: &mut UserInputThread, inputs: &mut SplitWhitespace) -> io::Result<bool> {
    let to_delete = BluetoothDeviceAddress::try_from(inputs.next().unwrap()).unwrap();

    uit.from_ui.send(FromUserInput::DeleteBonded(to_delete)).unwrap();

    Ok(false)
}
