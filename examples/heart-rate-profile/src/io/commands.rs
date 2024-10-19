//! Commands for the user to input

use crate::io::{MainToUserInput, Mode, Output};
use bo_tie::BluetoothDeviceAddress;
use clap::error::ErrorKind;
use clap::{ArgMatches, Args, CommandFactory, Error, FromArgMatches, Parser, Subcommand};
use std::fmt::format;
use std::io;
use std::str::SplitWhitespace;
use std::thread::current;
use std::time::Duration;

// pub const MAIN_COMMANDS: &'static [InputKind] = &[InputKind::Commands(&[
//     Command {
//         name: "help",
//         description: "Display this help information.",
//         args_description: "",
//         args: &[],
//         job: print_help,
//     },
//     Command {
//         name: "advertise",
//         description: "Enable or disable advertising.",
//         args_description: "",
//         job: parse_command_args,
//         args: &[InputKind::Commands(&[
//             Command {
//                 name: "discoverable",
//                 description: "Start advertising as a discoverable device. Any device will be \
//                         able to connect to the example, so discoverable advertising should only \
//                         enabled when initially connecting an non-bonded device.",
//                 args_description: "",
//                 args: &[],
//                 job: advertise_discoverable,
//             },
//             Command {
//                 name: "private",
//                 description: "Enable advertising for bonded devices. Only devices that have \
//                         previously bonded and exchanged identity resolving keys with this example \
//                         can connect. If privacy is implemented in the host, and non bonded devices \
//                         that do connect will be promptly disconnected.",
//                 args_description: "",
//                 args: &[],
//                 job: advertise_private,
//             },
//             Command {
//                 name: "off",
//                 description: "Disable advertising. No devices will be able to connect to this \
//                         example.",
//                 args_description: "",
//                 args: &[],
//                 job: advertise_off,
//             },
//         ])],
//     },
//     Command {
//         name: "pair",
//         description: "Control pairing to another device.",
//         args_description: "",
//         job: parse_command_args,
//         args: &[
//             InputKind::Commands(&[Command {
//                 name: "reject",
//                 description: "Reject the device(s) trying to pair.",
//                 args_description: "[ADDRESS... | all]",
//                 args: &[InputKind::Commands(&[Command {
//                     name: "all",
//                     description: "Reject all devices requesting to pair with this example",
//                     args_description: "",
//                     args: &[],
//                     job: pairing_reject_all,
//                 }])],
//                 job: pairing_reject,
//             }]),
//             InputKind::Known(KnownArg {
//                 format: "[ADDRESS]",
//                 format_description: "A Bluetooth Device Address (e.g. 12:34:56:78:ab:cd)",
//                 tab_arg: get_pairing_devices,
//                 parse: parse_pairing_address,
//                 job: pairing_accept,
//             }),
//         ],
//     },
//     Command {
//         name: "status",
//         description: "Show the status of this example",
//         args_description: "",
//         args: &[],
//         job: print_status,
//     },
//     Command {
//         name: "bonded",
//         description: "bonded devices",
//         args_description: "",
//         args: &[InputKind::Commands(&[
//             Command {
//                 name: "list",
//                 description: "List all bonded devices",
//                 args_description: "",
//                 args: &[],
//                 job: show_bonded_devices,
//             },
//             Command {
//                 name: "delete",
//                 description: "delete bonding information",
//                 args_description: "[ADDRESS|all]",
//                 args: &[
//                     InputKind::Commands(&[Command {
//                         name: "all",
//                         description: "delete all bonded devices",
//                         args_description: "",
//                         args: &[],
//                         job: delete_all_bonded_devices,
//                     }]),
//                     InputKind::Known(KnownArg {
//                         format: "[ADDRESS]",
//                         format_description: "A Bluetooth Device Address (e.g. 12:34:56:78:ab:cd)",
//                         tab_arg: get_bonded_devices,
//                         parse: parse_bonded_devices,
//                         job: delete_bonded_device,
//                     }),
//                 ],
//                 job: parse_command_args,
//             },
//         ])],
//         job: parse_command_args,
//     },
//     Command {
//         name: "exit",
//         description: "Exit this example. Advertising will be disabled and any currently \
//                 connected devices will be disconnected",
//         args_description: "",
//         args: &[],
//         job: exit,
//     },
//     Command {
//         name: "quit",
//         description: r#"same as command "exit""#,
//         args_description: "",
//         args: &[],
//         job: exit,
//     },
// ])];
//
// pub const NUMBER_COMPARISON_COMMANDS: &'static [InputKind] = &[InputKind::Commands(&[
//     Command {
//         name: "help",
//         description: "show this help information for number comparison authentication.",
//         args_description: "",
//         args: &[],
//         job: number_comparison_help,
//     },
//     Command {
//         name: "yes",
//         description: "Validate that the same number is displayed on both devices.",
//         args_description: "",
//         args: &[],
//         job: number_comparison_yes,
//     },
//     Command {
//         name: "no",
//         description: "Invalidate the numbers displayed on both devices. This can also be used \
//                 to just cancel the pairing between the two devices.",
//         args_description: "",
//         args: &[],
//         job: number_comparison_no,
//     },
//     Command {
//         name: "exit",
//         description: "Cancel the number comparison and exit the example. Advertising will be \
//                 disabled and any currently connected devices will be disconnected.",
//         args_description: "",
//         args: &[],
//         job: exit,
//     },
// ])];
//
// pub const PASSKEY_INPUT_COMMANDS: &'static [InputKind] = &[
//     InputKind::Commands(&[
//         Command {
//             name: "help",
//             description: "show this help information for number comparison authentication.",
//             args_description: "",
//             args: &[],
//             job: passkey_input_help,
//         },
//         Command {
//             name: "[PASSKEY]",
//             description: "The six digit passkey displayed on the other device. Pairing will fail \
//                 if what entered number does not match the passkey displayed on the other device",
//             args_description: "",
//             args: &[],
//             job: passkey_input_silly_help,
//         },
//         Command {
//             name: "cancel",
//             description: "Cancel the passkey authentication and disconnect the device",
//             args_description: "",
//             args: &[],
//             job: passkey_cancel,
//         },
//         Command {
//             name: "exit",
//             description: "Cancel the passkey input and exit the example. Advertising will be \
//                 disabled and any currently connected devices will be disconnected.",
//             args_description: "",
//             args: &[],
//             job: exit,
//         },
//     ]),
//     InputKind::Unknown(UnknownArg {
//         format: "[PASSKEY]",
//         format_description: "The six digit passkey displayed on the other device",
//         parse: parse_passkey,
//         job: passkey_input,
//     }),
// ];
//
// pub const PASSKEY_OUTPUT_COMMANDS: &'static [InputKind] = &[InputKind::Commands(&[
//     Command {
//         name: "cancel",
//         description: "Cancel the passkey authentication and disconnect the device",
//         args_description: "",
//         args: &[],
//         job: passkey_cancel,
//     },
//     Command {
//         name: "exit",
//         description: "Cancel the passkey input and exit the example. Advertising will be \
//                 disabled and any currently connected devices will be disconnected.",
//         args_description: "",
//         args: &[],
//         job: exit,
//     },
// ])];

#[derive(Parser, Debug)]
#[command(about = "Heart Rate Profile Example")]
#[command(
    long_about = "This is an example Heart Rate Profile. It generates a heart rate to be \
    transmitted using GATT notifications to a Client. Before that can happen, a peripheral \
    Bluetooth LE device must connect, bond, and then enable GATT notifications for the heart rate."
)]
struct Cli {}

#[derive(Parser, Debug)]
#[command(multicall = true)]
pub struct Repl {
    #[command(subcommand)]
    command: ReplCommands,
}

#[derive(clap::Subcommand, Debug)]
enum ReplCommands {
    Advertise {
        #[command(subcommand)]
        command: AdvertiseCommands,
    },
    Pair {
        #[command(subcommand)]
        command: PairingCommands,
    },
    Bonded {
        #[command(subcommand)]
        command: BondedCommands,
    },
    #[command(visible_alias = "quit")]
    Exit,
}

#[derive(clap::Subcommand, Debug)]
enum AdvertiseCommands {
    /// Start advertising as a connectible, discoverable device
    ///
    /// Any other Bluetooth LE device will be able to connect to the example. Discoverable
    /// advertising should only be enabled when initially connecting with your peripheral device.
    Discoverable,
    /// Private advertising
    ///
    /// This will enable advertising with a resolvable private address. Only peripheral devices that
    /// have previously bonded and exchanged an identity resolving key will be able to successfully
    /// connect with this device.
    Private,
    /// Turn advertising off
    ///
    /// Other devices will not be able to connect to this device. This does not affect any active
    /// connections with this device.
    Off,
}

#[derive(Subcommand, Debug)]
enum PairingCommands {
    RejectAll,
    Reject { device_addresses: Vec<String> },
    Accept { device_address: String },
}

#[derive(Subcommand, Debug)]
enum BondedCommands {
    List,
    #[group(required = true, multiple = false)]
    Delete {
        #[arg(long)]
        all: bool,
        #[clap(num_args = 1..)]
        identities: Vec<BluetoothDeviceAddress>,
    },
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

enum Input {
    Line,
    Paste,
    Tab,
    NoOp,
}

impl Input {
    fn on_in_event(buffer: &mut String) -> io::Result<Self> {
        use crossterm::event::*;

        if poll(Duration::from_millis(250))? {
            match read()? {
                Event::Paste(data) => {
                    buffer.push_str(&data);

                    Ok(Input::Paste)
                }
                Event::Key(key_event) => match key_event {
                    KeyEvent {
                        code: KeyCode::Tab,
                        kind: KeyEventKind::Press,
                        ..
                    } => Ok(Input::Tab),
                    KeyEvent {
                        code: KeyCode::Enter | KeyCode::Char('\n'),
                        ..
                    } => Ok(Input::Line),
                    KeyEvent {
                        code: KeyCode::Char(c), ..
                    } => {
                        buffer.push(c);

                        Ok(Input::NoOp)
                    }
                    _ => Ok(Input::NoOp),
                },
                _ => Ok(Input::NoOp),
            }
        } else {
            Ok(Input::NoOp)
        }
    }
}

/// Logging type for logging to the screen
pub(crate) struct Logs(pub(crate) std::sync::mpsc::Sender<String>);

impl io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Ok(log) = String::from_utf8(buf.to_vec()) {
            self.0.send(log).ok();
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum PrintData {
    Output(String),
    PartialInput(String),
    NoOp,
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
    ListBonded,
    DeleteAllBonded,
    DeleteBonded(BluetoothDeviceAddress),
    Exit,
}

#[derive(Parser)]
#[command(multicall = true)]
struct NumberComparison {
    #[command(subcommand)]
    input: NumberComparisonInput,
}

#[derive(Subcommand)]
enum NumberComparisonInput {
    Yes,
    No,
}

#[derive(Parser)]
#[command(multicall = true)]
struct PasskeyInput {
    passkey: String,
}

macro_rules! print_prompt {
    ($mode:expr) => {
        match $mode {
            Mode::NumberComparison(_) | Mode::PasskeyInput | Mode::PasskeyOutput(_) => {
                crossterm::style::Print("auth> ")
            }
            _ => crossterm::style::Print("#> "),
        }
    };
}

pub fn repl(
    init_mode: Mode,
    to_ui: std::sync::mpsc::Receiver<MainToUserInput>,
    log_receiver: std::sync::mpsc::Receiver<String>,
    from_ui: tokio::sync::mpsc::UnboundedSender<FromUserInput>,
) {
    let mut current_mode = init_mode;

    let mut input_buffer = String::new();

    let mut log_buffer = String::new();

    crossterm::queue!(io::stdout(), print_prompt!(&current_mode)).unwrap();

    'task: loop {
        if cfg!(feature = "log") {
            while let Ok(log_data) = log_receiver.try_recv() {
                print_log(&current_mode, &log_data, &mut log_buffer, &input_buffer)
            }
        }

        while let Ok(message) = to_ui.try_recv() {
            match message {
                MainToUserInput::Exit => {
                    // flush any logs
                    if cfg!(feature = "log") {
                        while let Ok(log_data) = log_receiver.try_recv() {
                            print_log(&current_mode, &log_data, &mut log_buffer, &input_buffer)
                        }
                    }

                    break 'task;
                }
                MainToUserInput::Output(output) => print_output(&current_mode, output, &input_buffer),
                MainToUserInput::Mode(mode) => {
                    current_mode = mode;

                    print_mode_change(&current_mode, &input_buffer)
                }
                MainToUserInput::PairingDevices(_) => {}
                MainToUserInput::BondedDevices(_) => {}
            }
        }

        match Input::on_in_event(&mut input_buffer).unwrap() {
            Input::NoOp => {}
            Input::Tab => {}
            Input::Line => process_input(&current_mode, &core::mem::take(&mut input_buffer), &from_ui),
            Input::Paste => {
                let end: usize = input_buffer
                    .chars()
                    .rev()
                    .take_while(|c| c.ne(&'\n'))
                    .map(|c| c.len_utf8())
                    .sum();

                let retained = input_buffer.split_off(input_buffer.len() - end);

                let removed = std::mem::replace(&mut input_buffer, retained);

                removed
                    .split("\n")
                    .for_each(|line| process_input(&current_mode, line, &from_ui));
            }
        }

        crossterm::queue!(io::stdout(), crossterm::cursor::Show).unwrap();

        io::Write::flush(&mut io::stdout()).unwrap();
    }

    crossterm::queue!(io::stdout(), crossterm::cursor::Show).unwrap();

    io::Write::flush(&mut io::stdout()).unwrap();
}

fn process_input(mode: &Mode, input: &str, from_ui: &tokio::sync::mpsc::UnboundedSender<FromUserInput>) {
    if input.trim().is_empty() {
        print_blank_prompt(mode);
        return;
    }

    match mode {
        Mode::Discoverable | Mode::Private | Mode::Silent => process_normal(input, from_ui),

        Mode::NumberComparison(_) => process_number_comparison(input, from_ui),

        Mode::PasskeyInput => process_passkey_input(input, from_ui),

        Mode::PasskeyOutput(_) => Ok(()),
    }
    .unwrap_or_else(|e| {
        print_error(mode, &e);
    });
}

fn process_normal(input: &str, from_ui: &tokio::sync::mpsc::UnboundedSender<FromUserInput>) -> Result<(), String> {
    let args = shlex::split(input).ok_or("error: invalid quoting")?;

    let repl = Repl::try_parse_from(args).map_err(|e| e.to_string())?;

    match repl.command {
        ReplCommands::Advertise {
            command: AdvertiseCommands::Discoverable,
        } => from_ui.send(FromUserInput::AdvertiseDiscoverable).unwrap(),
        ReplCommands::Advertise {
            command: AdvertiseCommands::Private,
        } => from_ui.send(FromUserInput::AdvertisePrivate).unwrap(),
        ReplCommands::Advertise {
            command: AdvertiseCommands::Off,
        } => from_ui.send(FromUserInput::StopAdvertising).unwrap(),
        ReplCommands::Pair {
            command: PairingCommands::RejectAll,
        } => from_ui.send(FromUserInput::PairingRejectAll).unwrap(),
        ReplCommands::Pair {
            command: PairingCommands::Reject { device_addresses },
        } => {
            let bluetooth_addresses = device_addresses.iter().try_fold(Vec::new(), |mut v, address| {
                let bluetooth_address = BluetoothDeviceAddress::try_from(address.as_str())
                    .map_err(|_| format!("{address} is not a valid Bluetooth device address)"))?;

                v.push(bluetooth_address);

                Ok::<_, String>(v)
            })?;

            from_ui.send(FromUserInput::PairingReject(bluetooth_addresses)).unwrap()
        }
        ReplCommands::Pair {
            command: PairingCommands::Accept { device_address },
        } => {
            let bluetooth_address = BluetoothDeviceAddress::try_from(device_address.as_str())
                .map_err(|_| format!("{device_address} is not a valid Bluetooth device address)"))?;

            from_ui.send(FromUserInput::PairingAccept(bluetooth_address)).unwrap();
        }
        ReplCommands::Bonded {
            command: BondedCommands::List,
        } => from_ui.send(FromUserInput::ListBonded).unwrap(),
        ReplCommands::Bonded {
            command: BondedCommands::Delete { all: true, .. },
        } => from_ui.send(FromUserInput::DeleteAllBonded).unwrap(),
        ReplCommands::Bonded {
            command: BondedCommands::Delete { identities, .. },
        } => identities
            .iter()
            .for_each(|identity| from_ui.send(FromUserInput::DeleteBonded(*identity)).unwrap()),
        ReplCommands::Exit => from_ui.send(FromUserInput::Exit).unwrap(),
    }

    Ok(())
}

fn process_number_comparison(
    input: &str,
    from_ui: &tokio::sync::mpsc::UnboundedSender<FromUserInput>,
) -> Result<(), String> {
    let args = shlex::split(input).ok_or("error: invalid quoting")?;

    let numb_comp = NumberComparison::try_parse_from(args).map_err(|e| e.to_string())?;

    match numb_comp.input {
        NumberComparisonInput::Yes => from_ui.send(FromUserInput::NumberComparisonYes).unwrap(),
        NumberComparisonInput::No => from_ui.send(FromUserInput::NumberComparisonNo).unwrap(),
    }

    Ok(())
}

fn process_passkey_input(
    input: &str,
    from_ui: &tokio::sync::mpsc::UnboundedSender<FromUserInput>,
) -> Result<(), String> {
    let args = shlex::split(input).ok_or("error: invalid quoting")?;

    let passkey_input = PasskeyInput::try_parse_from(args).map_err(|e| e.to_string())?;

    let passkey: [char; 6] = passkey_input
        .passkey
        .chars()
        .collect::<Vec<_>>()
        .as_slice()
        .try_into()
        .map_err(|_| "expecting a 6 digit passkey")?;

    if passkey.iter().any(|c| !c.is_digit(10)) {
        return Err("passkey must only consist of digits".to_string());
    }

    from_ui.send(FromUserInput::PasskeyInput(passkey)).unwrap();

    Ok(())
}

fn print_log(mode: &Mode, log_data: &str, log_buffer: &mut String, input: &str) {
    log_data.chars().for_each(|char| {
        if char != '\n' {
            log_buffer.push(char);
        } else {
            let line = std::mem::take(log_buffer);

            let trimmed = line.trim();

            if !trimmed.is_empty() {
                print_above_input(mode, trimmed, input)
            }
        }
    })
}

macro_rules! maybe_scroll_up_1 {
    () => {
        if crossterm::cursor::position().unwrap().1 == (crossterm::terminal::size().unwrap().1 - 1) {
            crossterm::terminal::ScrollUp(1)
        } else {
            crossterm::terminal::ScrollUp(0)
        }
    };
}

fn print_blank_prompt(mode: &Mode) {
    crossterm::queue!(io::stdout(), crossterm::cursor::Hide, print_prompt!(mode)).unwrap();
}

fn print_error(mode: &Mode, message: &str) {
    crossterm::queue!(
        io::stdout(),
        crossterm::cursor::Hide,
        crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
        crossterm::cursor::MoveToColumn(0),
        crossterm::style::Print(message),
        maybe_scroll_up_1!(),
        crossterm::cursor::MoveToNextLine(1),
        print_prompt!(mode)
    )
    .unwrap()
}

fn print_above_input(mode: &Mode, to_print: &str, input: &str) {
    crossterm::queue!(
        io::stdout(),
        crossterm::cursor::Hide,
        crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
        crossterm::cursor::MoveToColumn(2),
        crossterm::style::Print(to_print),
        maybe_scroll_up_1!(),
        crossterm::cursor::MoveToNextLine(1),
        print_prompt!(mode),
        crossterm::style::Print(input)
    )
    .unwrap()
}

fn print_output(mode: &Mode, output: Output, input: &str) {
    crossterm::queue!(
        io::stdout(),
        crossterm::cursor::Hide,
        crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
        crossterm::cursor::MoveToColumn(0),
    )
    .unwrap();

    output.queue_print_to(&mut io::stdout());

    crossterm::queue!(
        io::stdout(),
        crossterm::cursor::Hide,
        maybe_scroll_up_1!(),
        crossterm::cursor::MoveToNextLine(1),
        print_prompt!(mode),
        crossterm::style::Print(input)
    )
    .unwrap()
}

fn print_mode_change(mode: &Mode, input: &str) {
    match mode {
        Mode::Silent => crossterm::queue!(
            io::stdout(),
            crossterm::cursor::Hide,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
            crossterm::cursor::MoveToColumn(0),
            crossterm::style::Print(format!("{{advertising off}}")),
            crossterm::style::ResetColor,
            maybe_scroll_up_1!(),
            crossterm::cursor::MoveToNextLine(1),
            print_prompt!(mode),
            crossterm::style::Print(input)
        )
        .unwrap(),
        Mode::Private => crossterm::queue!(
            io::stdout(),
            crossterm::cursor::Hide,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
            crossterm::cursor::MoveToColumn(0),
            crossterm::style::SetForegroundColor(crossterm::style::Color::Green),
            crossterm::style::Print(format!("{{advertising privately}}")),
            crossterm::style::ResetColor,
            maybe_scroll_up_1!(),
            crossterm::cursor::MoveToNextLine(1),
            print_prompt!(mode),
            crossterm::style::Print(input)
        )
        .unwrap(),
        Mode::Discoverable => crossterm::queue!(
            io::stdout(),
            crossterm::cursor::Hide,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
            crossterm::cursor::MoveToColumn(0),
            crossterm::style::SetForegroundColor(crossterm::style::Color::Red),
            crossterm::style::Print(format!("{{advertising discoverable}}")),
            crossterm::style::ResetColor,
            maybe_scroll_up_1!(),
            crossterm::cursor::MoveToNextLine(1),
            print_prompt!(mode),
            crossterm::style::Print(input)
        )
        .unwrap(),
        Mode::NumberComparison(n) => crossterm::queue!(
            io::stdout(),
            crossterm::cursor::Hide,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
            crossterm::cursor::MoveToColumn(0),
            crossterm::style::ResetColor,
            crossterm::style::Print("does the number"),
            crossterm::style::SetForegroundColor(crossterm::style::Color::Green),
            crossterm::style::Print(format!("{n}")),
            crossterm::style::ResetColor,
            crossterm::style::Print("match the number on the other device (y/n)?"),
            maybe_scroll_up_1!(),
            crossterm::cursor::MoveToNextLine(1),
            print_prompt!(mode),
            crossterm::style::Print(input)
        )
        .unwrap(),
        Mode::PasskeyOutput(o) => crossterm::queue!(
            io::stdout(),
            crossterm::cursor::Hide,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
            crossterm::cursor::MoveToColumn(0),
            crossterm::style::Print(r#"enter the passkey ""#),
            crossterm::style::SetForegroundColor(crossterm::style::Color::Green),
            crossterm::style::Print(o),
            crossterm::style::ResetColor,
            crossterm::style::Print("into the other device?"),
            maybe_scroll_up_1!(),
            crossterm::cursor::MoveToNextLine(1),
            print_prompt!(mode),
            crossterm::style::Print(input)
        )
        .unwrap(),
        Mode::PasskeyInput => crossterm::queue!(
            io::stdout(),
            crossterm::cursor::Hide,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
            crossterm::cursor::MoveToColumn(0),
            crossterm::style::Print("enter the passkey displayed on the other device?"),
            maybe_scroll_up_1!(),
            crossterm::cursor::MoveToNextLine(1),
            print_prompt!(mode),
            crossterm::style::Print(input)
        )
        .unwrap(),
    }
}
