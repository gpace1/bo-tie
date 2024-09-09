mod commands;

use bo_tie::host::sm::pairing::PairingFailedReason;
use bo_tie::host::sm::IdentityAddress;
use bo_tie::BluetoothDeviceAddress;
pub use commands::FromUserInput;
use commands::Logs;
use crossterm::{event, style};
use std::io::{self, Write};

const ORANGE: style::Color = style::Color::Rgb {
    r: 0xff,
    g: 0xa5,
    b: 0x00,
};

pub enum MainToUserInput {
    Exit,
    Output(Output),
    Mode(Mode),
    PairingDevices(Vec<BluetoothDeviceAddress>),
    BondedDevices(Vec<IdentityAddress>),
}

pub struct Output {
    header_color: style::Color,
    header: String,
    message: String,
}

impl Output {
    pub fn on_connection(status: crate::connection::ConnectedStatus) -> Self {
        match status {
            crate::connection::ConnectedStatus::New(address) => Output {
                header_color: style::Color::Yellow,
                header: "new device connected".into(),
                message: format!("Device {address} has connected"),
            },
            crate::connection::ConnectedStatus::Bonded(identity) => Output {
                header_color: style::Color::Green,
                header: "device connected".into(),
                message: format!("Device {} has reconnected", identity.get_address()),
            },
        }
    }

    pub fn on_pairing_request(address: BluetoothDeviceAddress) -> Self {
        Output {
            header_color: ORANGE,
            header: "pairing request".into(),
            message: format!(
                "Device {address} is requesting to pair with this device\n\
            To accept pairing to this device, enter the command `pair accept {address}`"
            ),
        }
    }

    pub fn on_bonding_complete(address: BluetoothDeviceAddress, identity: IdentityAddress) -> Self {
        Output {
            header_color: style::Color::Green,
            header: "bonding complete".into(),
            message: format!(
                "Device {address} has bonded with this heart rate example; from now on this device \
                will be labeled by its identity address {}",
                identity.get_address()
            ),
        }
    }

    pub fn on_identity_change(old_identity: IdentityAddress, new_identity: IdentityAddress) -> Self {
        let old_address = old_identity.get_address();
        let new_address = new_identity.get_address();

        Output {
            header_color: ORANGE,
            header: "identity change".into(),
            message: format!("device has changed its identity from {old_address} to {new_address}"),
        }
    }

    pub fn on_pairing_complete(address: BluetoothDeviceAddress) -> Self {
        Output {
            header_color: style::Color::Yellow,
            header: "Pairing complete".into(),
            message: format!("device {address} has successfully paired with this example"),
        }
    }

    pub fn on_pairing_failed(address: BluetoothDeviceAddress, reason: PairingFailedReason) -> Self {
        Output {
            header_color: style::Color::Red,
            header: "Pairing failed".into(),
            message: format!("pairing with device {address} failed because {reason}"),
        }
    }

    pub fn on_unauthenticated_connection(address: BluetoothDeviceAddress) -> Self {
        Output {
            header_color: style::Color::Red,
            header: "unauthenticated connection".into(),
            message: format!(
                "Device {address} has connected, but it was unidentified and so the example has \
                 disconnected it."
            ),
        }
    }

    pub fn device_not_pairing(address: BluetoothDeviceAddress) -> Self {
        Output {
            header_color: style::Color::Red,
            header: "no pairing".into(),
            message: format!(
                "device {address} is not trying to pair, or its pairing request has \
                timed out"
            ),
        }
    }

    pub fn device_is_disconnected(address: BluetoothDeviceAddress) -> Self {
        Output {
            header_color: style::Color::Red,
            header: "disconnected".into(),
            message: format!("The operation cannot be performed as device {address} has disconnected"),
        }
    }

    pub fn device_disconnected(address: BluetoothDeviceAddress) -> Self {
        Output {
            header_color: style::Color::Green,
            header: "disconnection".into(),
            message: format!("Device {address} has disconnected"),
        }
    }

    pub fn queue_print_to<W: Write>(&self, w: &mut W) {
        crossterm::queue!(
            w,
            style::SetForegroundColor(self.header_color),
            style::Print(format!("<{}> ", self.header)),
            style::ResetColor,
            style::Print(&self.message)
        )
        .unwrap()
    }
}

pub enum Mode {
    Silent,
    Private,
    Discoverable,
    NumberComparison(String),
    PasskeyOutput(String),
    PasskeyInput,
}

struct UserKeyAction {
    key: event::KeyCode,
    task: Box<dyn FnMut() -> io::Result<bool> + Send>,
}

impl UserKeyAction {
    fn insert_into(self, list: &mut Vec<UserKeyAction>) {
        match list.binary_search_by(|key_action| key_action.key.partial_cmp(&self.key).unwrap()) {
            Err(index) => list.insert(index, self),
            Ok(index) => list[index] = self,
        }
    }

    fn get_mut_from(key: char, list: &mut [UserKeyAction]) -> Option<&mut UserKeyAction> {
        list.binary_search_by(|key_action| key_action.key.partial_cmp(&event::KeyCode::Char(key)).unwrap())
            .ok()
            .and_then(|index| list.get_mut(index))
    }
}

pub struct UserInput {
    on_ctrl: Vec<UserKeyAction>,
    on_alt: Vec<UserKeyAction>,
    on_shift: Vec<UserKeyAction>,
    to_ui_tx: std::sync::mpsc::Sender<MainToUserInput>,
    to_ui_rx: std::sync::mpsc::Receiver<MainToUserInput>,
    log_receiver: std::sync::mpsc::Receiver<String>,
    from_ui_tx: tokio::sync::mpsc::UnboundedSender<FromUserInput>,
    bonded: Vec<BluetoothDeviceAddress>,
}

impl UserInput {
    /// Create a new `UserInput`
    ///
    /// This returns a new `UserInput` with a receiver of commands executed by the user.
    pub fn new() -> (Self, tokio::sync::mpsc::UnboundedReceiver<FromUserInput>) {
        let (log_sender, log_receiver) = std::sync::mpsc::channel();

        if cfg!(feature = "log") {
            let level = simplelog::LevelFilter::Trace;
            let trace = simplelog::Config::default();
            let logs = Logs(log_sender.clone());

            simplelog::WriteLogger::init(level, trace, logs).unwrap();
        }

        let (to_ui_tx, to_ui_rx) = std::sync::mpsc::channel();
        let (from_ui_tx, from_ui_rx) = tokio::sync::mpsc::unbounded_channel();

        let on_ctrl = Vec::new();
        let on_alt = Vec::new();
        let on_shift = Vec::new();

        let bonded = Vec::new();

        let this = Self {
            on_ctrl,
            on_alt,
            on_shift,
            to_ui_tx,
            to_ui_rx,
            log_receiver,
            from_ui_tx,
            bonded,
        };

        (this, from_ui_rx)
    }

    /// Get the sender for messages from Main to the UI
    pub fn get_sender_to_ui(&self) -> std::sync::mpsc::Sender<MainToUserInput> {
        self.to_ui_tx.clone()
    }

    pub fn set_bonded_devices(&mut self, bonded: Vec<BluetoothDeviceAddress>) {
        self.bonded = bonded;
    }

    /// Add a closure to be called upon a key pressed with ctrl
    ///
    /// When `key` is pressed with the ctrl key the provided closure will be called. There may only
    /// be one closure per key-ctrl combination, calling this a second time will override the
    /// prior closure.
    ///
    /// The return of the closure is a boolean contained by the result type of `std::io`. If the
    /// closure returns `Ok(true)` or an error the user input thread will exit.
    #[allow(dead_code)]
    pub fn set_with_ctrl<F>(&mut self, key: char, f: F)
    where
        F: FnMut() -> io::Result<bool> + Send + 'static,
    {
        Self::set_combination_key(key, f, &mut self.on_ctrl);
    }

    /// Add a closure to be called upon a key pressed with ctrl
    ///
    /// When `key` is pressed with the ctrl key the provided closure will be called. There may only
    /// be one closure per key-ctrl combination, calling this a second time will override the
    /// prior closure.
    ///
    /// The return of the closure is a boolean contained by the result type of `std::io`. If the
    /// closure returns `Ok(true)` or an error the user input thread will exit.
    #[allow(dead_code)]
    pub fn set_with_shift<F>(&mut self, key: char, f: F)
    where
        F: FnMut() -> io::Result<bool> + Send + 'static,
    {
        Self::set_combination_key(key, f, &mut self.on_ctrl);
    }

    /// Add a closure to be called upon a key pressed with ctrl
    ///
    /// When `key` is pressed with the ctrl key the provided closure will be called. There may only
    /// be one closure per key-ctrl combination, calling this a second time will override the
    /// prior closure.
    ///
    /// The return of the closure is a boolean contained by the result type of `std::io`. If the
    /// closure returns `Ok(true)` or an error the user input thread will exit.
    #[allow(dead_code)]
    pub fn set_with_alt<F>(&mut self, key: char, f: F)
    where
        F: FnMut() -> io::Result<bool> + Send + 'static,
    {
        Self::set_combination_key(key, f, &mut self.on_ctrl);
    }

    /// Spawn the user input thread
    ///
    /// The spawned thread processes user input in raw terminal mode, along with applying some other
    /// terminal customizations. If this thread were to be killed the terminal configuration would
    /// be kept and this is almost always undesirable to the end user (usually it requires a restart
    /// of the entire terminal). The returned [`JoinHandle`] is used to ensure that the thread is
    /// gracefully exited before the program exits.
    ///
    /// Either [`join`] or [`exit`] should be called on the returned `JoinHandle`. Dropping the
    /// handle does nothing and the terminal is liable to being left in a bad state if the program
    /// ends before the user input thread exits.  
    ///
    /// ```
    /// use autocomplete::UserInput;
    ///
    /// # let commands = Vec::new();
    /// let io = UserInput::new(commands);
    ///
    /// # || {
    /// // spawn the user input thread and join with it
    /// io.spawn().join()?;
    /// # };
    /// ```
    pub fn spawn(self) -> JoinHandle {
        let exit_sender = self.get_sender_to_ui();

        let thread_handle =
            std::thread::spawn(move || commands::repl(Mode::Silent, self.to_ui_rx, self.log_receiver, self.from_ui_tx));

        JoinHandle {
            exit_sender,
            thread_handle,
        }
    }

    fn set_combination_key<F>(key: char, f: F, list: &mut Vec<UserKeyAction>)
    where
        F: FnMut() -> io::Result<bool> + Send + 'static,
    {
        let key = event::KeyCode::Char(key);

        let task = Box::new(f);

        let user_key_action = UserKeyAction { key, task };

        user_key_action.insert_into(list)
    }
}

/// The handle to the user input thread
///
/// This join handle must be used to join with the user input thread. See the method [`spawn`] of
/// `UserInput` for details and why this must be used.
#[must_use]
pub struct JoinHandle {
    exit_sender: std::sync::mpsc::Sender<MainToUserInput>,
    thread_handle: std::thread::JoinHandle<()>,
}

impl JoinHandle {
    /// Exit the user input thread
    ///
    /// This sends an exit signal to the user input thread and then waits to joins with the thread.  
    pub fn exit(self) {
        self.exit_sender.send(MainToUserInput::Exit).ok();

        self.join()
    }

    /// Join with the user input thread
    ///
    /// This is equivalent to the `join` method of [`std::thread::JoinHandle`]
    pub fn join(self) {
        if let Err(e) = self.thread_handle.join() {
            std::panic::resume_unwind(e)
        }
    }
}
