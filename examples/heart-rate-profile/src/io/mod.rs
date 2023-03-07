mod commands;
mod tab;

use bo_tie::host::sm::pairing::PairingFailedReason;
use bo_tie::host::sm::IdentityAddress;
use bo_tie::BluetoothDeviceAddress;
pub use commands::FromUserInput;
use crossterm::{cursor, event, style, terminal};
use std::io::{self, Write};
use std::rc::Rc;
use std::time::Duration;

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
    BondedDevices(Vec<BluetoothDeviceAddress>),
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
            message: format!("Device {address} is requesting to pair with this device"),
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
    from_ui_tx: tokio::sync::mpsc::UnboundedSender<FromUserInput>,
    bonded: Vec<BluetoothDeviceAddress>,
}

impl UserInput {
    /// Create a new `UserInput`
    ///
    /// This returns a new `UserInput` with a receiver of commands executed by the user.
    pub fn new() -> (Self, tokio::sync::mpsc::UnboundedReceiver<FromUserInput>) {
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

        let thread_handle = std::thread::spawn(move || UserInputThread::new(self).thread());

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

struct StdoutLocker {
    stdout: io::Stdout,
    lock: Option<io::StdoutLock<'static>>,
}

impl StdoutLocker {
    fn new() -> Self {
        let stdout = io::stdout();
        let lock = None;

        StdoutLocker { stdout, lock }
    }

    fn lock(&mut self) -> io::Result<()> {
        self.unlock()?;

        self.lock = Some(self.stdout.lock());

        Ok(())
    }

    fn unlock(&mut self) -> io::Result<()> {
        if let Some(mut lock) = self.lock.take() {
            lock.flush()?;
        } else {
            self.stdout.flush()?;
        }

        Ok(())
    }

    fn move_to_next_line(&mut self) -> io::Result<()> {
        if terminal::size()?.1 - 1 == cursor::position()?.1 {
            crossterm::execute!(self, terminal::ScrollUp(1),)?;
        }

        crossterm::execute!(self, cursor::MoveToNextLine(1))
    }
}

impl Write for StdoutLocker {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(lock) = self.lock.as_mut() {
            lock.write(buf)
        } else {
            io::stdout().write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(lock) = self.lock.as_mut() {
            lock.flush()
        } else {
            io::stdout().flush()
        }
    }
}

#[derive(Clone)]
struct Input {
    saved: Rc<Vec<char>>,
    modified: Rc<Vec<char>>,
}

impl Input {
    fn new() -> Self {
        let saved = Rc::default();
        let modified = Rc::clone(&saved);

        Input { saved, modified }
    }

    /// Save the input of the user
    fn save_input(&mut self) {
        self.saved = self.modified.clone();
    }

    /// Reset the input to the saved version
    fn reset(&mut self) {
        self.modified = self.saved.clone();
    }
}

impl core::ops::Deref for Input {
    type Target = Vec<char>;

    fn deref(&self) -> &Self::Target {
        &self.modified
    }
}

impl core::ops::DerefMut for Input {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Rc::make_mut(&mut self.modified)
    }
}

#[allow(dead_code)]
struct UserInputThread {
    mode: Mode,
    to_ui: std::sync::mpsc::Receiver<MainToUserInput>,
    from_ui: tokio::sync::mpsc::UnboundedSender<FromUserInput>,
    stdout_locker: StdoutLocker,
    inputs: Vec<Input>,
    inputs_negative_index: usize,
    on_ctrl: Vec<UserKeyAction>,
    on_alt: Vec<UserKeyAction>,
    on_shift: Vec<UserKeyAction>,
    insert_mode: bool,
    tab: tab::Tab,
    known_arg_data: commands::KnownArgData,
}

macro_rules! displayed_input {
    ($this:expr) => {
        $this.inputs[$this.inputs.len() - $this.inputs_negative_index]
    };
}

macro_rules! displayed_mut_input {
    ($this:expr) => {{
        let len = $this.inputs.len();

        &mut $this.inputs[len - $this.inputs_negative_index]
    }};
}

macro_rules! on_key_combo {
    ($this:expr, $character:expr, $list:expr) => {{
        let mut exit = false;

        if let Some(key_action) = UserKeyAction::get_mut_from($character, &mut $list) {
            $this.stdout_locker.move_to_next_line()?;

            terminal::disable_raw_mode()?;

            $this.stdout_locker.unlock()?;

            exit = (key_action.task)()?;

            $this.stdout_locker.flush()?;

            if !exit {
                $this.stdout_locker.lock()?;

                $this.reprint_input_line()?;
            }
        }

        Ok(exit)
    }};
}

impl UserInputThread {
    const INSERT_CURSOR: cursor::SetCursorStyle = cursor::SetCursorStyle::BlinkingBar;

    const OVERTYPE_CURSOR: cursor::SetCursorStyle = cursor::SetCursorStyle::BlinkingUnderScore;

    fn new(user_input: UserInput) -> Self {
        let to_ui = user_input.to_ui_rx;
        let from_ui = user_input.from_ui_tx;
        let stdout_locker = StdoutLocker::new();
        let inputs = vec![Input::new()];
        let inputs_negative_index = 1;
        let on_ctrl = user_input.on_ctrl;
        let on_alt = user_input.on_alt;
        let on_shift = user_input.on_shift;
        let insert_mode = true;
        let tab = tab::Tab::new();
        let mode = Mode::Silent;
        let known_arg_data = commands::KnownArgData::new(user_input.bonded);

        UserInputThread {
            mode,
            to_ui,
            from_ui,
            stdout_locker,
            inputs,
            inputs_negative_index,
            on_ctrl,
            on_alt,
            on_shift,
            insert_mode,
            tab,
            known_arg_data,
        }
    }

    fn print_on_next_line(&mut self, args: std::fmt::Arguments) -> io::Result<()> {
        self.stdout_locker.move_to_next_line()?;

        write!(self.stdout_locker, "{}", args)
    }

    fn thread(self) {
        self.run().unwrap()
    }

    fn run(mut self) -> io::Result<()> {
        self.print_prompt()?;

        crossterm::execute!(self.stdout_locker, Self::INSERT_CURSOR)?;

        loop {
            while let Ok(msg) = self.to_ui.try_recv() {
                if self.process_from_main(msg)? {
                    break;
                }
            }

            self.stdout_locker.flush()?;

            self.stdout_locker.lock()?;

            terminal::enable_raw_mode()?;

            let exit = event::poll(Duration::from_micros(100))? && self.process_event()?;

            terminal::disable_raw_mode()?;

            self.stdout_locker.unlock()?;

            if exit {
                break;
            } else {
                if !cfg!(feature = "log") {
                    std::thread::yield_now();
                } else {
                    // logging gets a bit output heavy
                    std::thread::sleep(Duration::from_millis(10))
                }
            }
        }

        writeln!(self.stdout_locker)?;

        crossterm::execute!(self.stdout_locker, cursor::SetCursorStyle::DefaultUserShape)
    }

    fn process_from_main(&mut self, msg: MainToUserInput) -> io::Result<bool> {
        match msg {
            MainToUserInput::Exit => return Ok(true),
            MainToUserInput::Output(output) => self.output_info(output)?,
            MainToUserInput::Mode(mode) => self.change_mode(mode)?,
            MainToUserInput::PairingDevices(pairing) => self.known_arg_data.set_requesting_pairing(pairing),
            MainToUserInput::BondedDevices(bonded) => self.known_arg_data.set_bonded(bonded),
        }

        Ok(false)
    }

    fn process_input(&mut self) -> io::Result<bool> {
        let displayed_input = displayed_input!(self).iter().collect::<String>();

        match self.mode {
            Mode::Silent | Mode::Private | Mode::Discoverable => {
                commands::InputKind::exec_input(self, commands::MAIN_COMMANDS, displayed_input)
            }
            Mode::NumberComparison(_) => {
                commands::InputKind::exec_input(self, commands::NUMBER_COMPARISON_COMMANDS, displayed_input)
            }
            Mode::PasskeyOutput(_) => {
                commands::InputKind::exec_input(self, commands::PASSKEY_OUTPUT_COMMANDS, displayed_input)
            }
            Mode::PasskeyInput => {
                commands::InputKind::exec_input(self, commands::PASSKEY_INPUT_COMMANDS, displayed_input)
            }
        }
    }

    fn print_prompt(&mut self) -> io::Result<()> {
        match self.mode {
            Mode::Silent => self.prompt_silent(),
            Mode::Private => self.prompt_private(),
            Mode::Discoverable => self.prompt_discoverable(),
            Mode::NumberComparison(_) => self.prompt_number_comparison(),
            Mode::PasskeyOutput(_) | Mode::PasskeyInput => self.prompt_passkey(),
        }
    }

    const SILENT_PROMPT: &'static str = "[silent]# ";
    const PRIVATE_PROMPT: &'static str = "[private]# ";
    const DISCOVERABLE_PROMPT: &'static str = "[discoverable]# ";
    const NUMBER_COMPARISON_PROMPT: &'static str = "[authenticate-numb-comp]# ";
    const PASSKEY_PROMPT: &'static str = "[authenticate-passkey]# ";

    fn prompt_silent(&mut self) -> io::Result<()> {
        crossterm::execute!(self.stdout_locker, style::ResetColor)?;

        write!(self.stdout_locker, "{}", Self::SILENT_PROMPT)
    }

    fn prompt_private(&mut self) -> io::Result<()> {
        crossterm::execute!(self.stdout_locker, style::SetForegroundColor(style::Color::Green))?;

        write!(self.stdout_locker, "{}", Self::PRIVATE_PROMPT)?;

        crossterm::execute!(self.stdout_locker, style::ResetColor)
    }

    fn prompt_discoverable(&mut self) -> io::Result<()> {
        crossterm::execute!(self.stdout_locker, style::SetForegroundColor(style::Color::Red))?;

        write!(self.stdout_locker, "{}", Self::DISCOVERABLE_PROMPT)?;

        crossterm::execute!(self.stdout_locker, style::ResetColor)
    }

    fn prompt_number_comparison(&mut self) -> io::Result<()> {
        crossterm::execute!(self.stdout_locker, style::SetForegroundColor(style::Color::Yellow))?;

        write!(self.stdout_locker, "{}", Self::NUMBER_COMPARISON_PROMPT)?;

        crossterm::execute!(self.stdout_locker, style::ResetColor)
    }

    fn print_number_comparison(&mut self, number: &String) -> io::Result<()> {
        let column = cursor::position()?.0;

        crossterm::execute!(
            self.stdout_locker,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
            crossterm::cursor::MoveToColumn(0),
            crossterm::style::SetForegroundColor(style::Color::DarkYellow)
        )?;

        write!(self.stdout_locker, "<authenticate> ")?;

        crossterm::execute!(self.stdout_locker, crossterm::style::ResetColor)?;

        write!(self.stdout_locker, "does the number ")?;

        crossterm::execute!(
            self.stdout_locker,
            crossterm::style::SetForegroundColor(style::Color::DarkYellow)
        )?;

        write!(self.stdout_locker, "{}", number)?;

        crossterm::execute!(self.stdout_locker, crossterm::style::ResetColor)?;

        write!(self.stdout_locker, " match the number displayed on the other device?")?;

        crossterm::execute!(
            self.stdout_locker,
            crossterm::terminal::ScrollUp(1),
            crossterm::cursor::MoveToNextLine(1),
            crossterm::cursor::MoveToColumn(column),
        )?;

        self.reprint_input_line()
    }

    fn prompt_passkey(&mut self) -> io::Result<()> {
        crossterm::execute!(self.stdout_locker, style::SetForegroundColor(style::Color::Yellow))?;

        write!(self.stdout_locker, "{}", Self::PASSKEY_PROMPT)?;

        crossterm::execute!(self.stdout_locker, style::ResetColor)
    }

    fn print_passkey_output(&mut self, passkey: &String) -> io::Result<()> {
        let column = cursor::position()?.0;

        crossterm::execute!(
            self.stdout_locker,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
            crossterm::cursor::MoveToColumn(0),
            crossterm::style::SetForegroundColor(style::Color::DarkYellow)
        )?;

        write!(self.stdout_locker, "<authenticate> ")?;

        crossterm::execute!(self.stdout_locker, crossterm::style::ResetColor)?;

        write!(self.stdout_locker, "enter the passkey '")?;

        crossterm::execute!(
            self.stdout_locker,
            crossterm::style::SetForegroundColor(style::Color::DarkYellow)
        )?;

        write!(self.stdout_locker, "{}", passkey)?;

        crossterm::execute!(self.stdout_locker, crossterm::style::ResetColor)?;

        write!(self.stdout_locker, "'match the number displayed on the other device?")?;

        crossterm::execute!(
            self.stdout_locker,
            crossterm::terminal::ScrollUp(1),
            crossterm::cursor::MoveToNextLine(1),
            crossterm::cursor::MoveToColumn(column),
        )?;

        self.reprint_input_line()
    }

    fn prompt_length(&self) -> usize {
        match self.mode {
            Mode::Silent => Self::SILENT_PROMPT.chars().count(),
            Mode::Private => Self::PRIVATE_PROMPT.chars().count(),
            Mode::Discoverable => Self::DISCOVERABLE_PROMPT.chars().count(),
            Mode::NumberComparison(_) => Self::NUMBER_COMPARISON_PROMPT.chars().count(),
            Mode::PasskeyOutput(_) => Self::PASSKEY_PROMPT.chars().count(),
            Mode::PasskeyInput => Self::PASSKEY_PROMPT.chars().count(),
        }
    }

    fn reprint_input_line(&mut self) -> io::Result<()> {
        crossterm::execute!(
            self.stdout_locker,
            terminal::Clear(terminal::ClearType::CurrentLine),
            cursor::MoveToColumn(0)
        )?;

        self.print_prompt()?;

        for input in displayed_input!(self).iter() {
            write!(self.stdout_locker, "{}", input)?;
        }

        Ok(())
    }

    fn change_mode(&mut self, mode: Mode) -> io::Result<()> {
        match &mode {
            Mode::NumberComparison(number) => self.print_number_comparison(number)?,
            Mode::PasskeyOutput(passkey) => self.print_passkey_output(passkey)?,
            _ => (),
        }

        self.mode = mode;

        crossterm::execute!(
            self.stdout_locker,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine)
        )?;

        self.reprint_input_line()
    }

    fn output_info(&mut self, output: Output) -> io::Result<()> {
        let column = cursor::position()?.0;

        crossterm::execute!(
            self.stdout_locker,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
            crossterm::cursor::MoveToColumn(0),
            crossterm::style::SetForegroundColor(output.header_color)
        )?;

        write!(self.stdout_locker, "<{}> ", output.header)?;

        crossterm::execute!(self.stdout_locker, crossterm::style::ResetColor)?;

        write!(self.stdout_locker, "{}", output.message)?;

        crossterm::execute!(
            self.stdout_locker,
            crossterm::terminal::ScrollUp(1),
            crossterm::cursor::MoveToNextLine(1),
            crossterm::cursor::MoveToColumn(column),
        )?;

        self.reprint_input_line()
    }

    fn process_event(&mut self) -> io::Result<bool> {
        match crossterm::event::read()? {
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Backspace,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            }) => self.on_backspace(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Enter,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            }) => self.on_enter(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Left,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            }) => self.on_left(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Right,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            }) => self.on_right(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Up,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_up(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Down,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            }) => self.on_down(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Home,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_home(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::End,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_end(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::PageUp,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_page_up(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::PageDown,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_page_down(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Tab,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_tab(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::BackTab,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_back_tab(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Delete,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            }) => self.on_delete(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Insert,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_insert(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::F(number),
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_f_key(number),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Char(character),
                kind: event::KeyEventKind::Press,
                modifiers: event::KeyModifiers::CONTROL,
                ..
            }) => self.on_ctrl_char(character),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Char(character),
                kind: event::KeyEventKind::Press,
                modifiers: event::KeyModifiers::ALT,
                ..
            }) => self.on_alt_char(character),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Char(character),
                kind: event::KeyEventKind::Press,
                modifiers: event::KeyModifiers::SHIFT,
                ..
            }) => self.on_shift_char(character),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Char(character),
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            }) => self.on_char(character),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Null,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_null(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Esc,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_esc(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::CapsLock,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_caps_lock(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::NumLock,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_num_lock(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::PrintScreen,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_print_screen(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Pause,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_pause(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Menu,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_menu(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::KeypadBegin,
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_keypad_begin(),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Media(media_key_code),
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_media(media_key_code),
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Modifier(modifier_key_code),
                kind: event::KeyEventKind::Press,
                ..
            }) => self.on_modifier(modifier_key_code),
            _ => Ok(false),
        }
    }

    fn on_backspace(&mut self) -> io::Result<bool> {
        let cursor_column: usize = cursor::position()?.0.into();

        let input_start = self.prompt_length();

        if input_start < cursor_column {
            let input_position = cursor_column - input_start - 1;

            displayed_mut_input!(self).remove(input_position);

            self.tab.reset_tab_input(&displayed_input!(self));

            self.reprint_input_line()?;

            crossterm::execute!(self.stdout_locker, cursor::MoveToColumn(cursor_column as u16 - 1))?;
        }

        Ok(false)
    }

    fn on_enter(&mut self) -> io::Result<bool> {
        if displayed_input!(self)
            .iter()
            .skip_while(|c| c.is_whitespace())
            .next()
            .is_none()
        {
            self.stdout_locker.move_to_next_line()?;

            self.print_prompt()?;

            Ok(false)
        } else {
            self.tab.clear_tab_input(&mut self.stdout_locker)?;

            terminal::disable_raw_mode()?;

            if !self.process_input()? {
                if self.inputs_negative_index != 1 {
                    let latest = displayed_input!(self).clone();

                    let index = self.inputs.len() - 1;

                    self.inputs[index] = latest;
                }

                self.inputs_negative_index = 1;

                displayed_mut_input!(self).save_input();

                self.inputs.iter_mut().for_each(|i| i.reset());

                self.inputs.push(Input::new());

                terminal::enable_raw_mode()?;

                if cursor::position()?.0 != 0 {
                    // move to the next line if the cursor is
                    // at the first column.
                    self.stdout_locker.move_to_next_line()?;
                }

                self.print_prompt()?;

                Ok(false)
            } else {
                Ok(true)
            }
        }
    }

    fn on_left(&mut self) -> io::Result<bool> {
        let cursor_column: usize = cursor::position()?.0.into();

        if cursor_column > self.prompt_length() {
            crossterm::execute!(self.stdout_locker, cursor::MoveLeft(1))?;
        }

        Ok(false)
    }

    fn on_right(&mut self) -> io::Result<bool> {
        let cursor_column: usize = cursor::position()?.0.into();

        if cursor_column < self.prompt_length() + displayed_input!(self).len() {
            crossterm::execute!(self.stdout_locker, cursor::MoveRight(1))?;
        }

        Ok(false)
    }

    fn on_up(&mut self) -> io::Result<bool> {
        if self.inputs_negative_index != self.inputs.len() {
            self.inputs_negative_index += 1;

            self.reprint_input_line()?;
        }

        Ok(false)
    }

    fn on_down(&mut self) -> io::Result<bool> {
        if self.inputs_negative_index > 1 {
            self.inputs_negative_index -= 1;

            self.reprint_input_line()?;
        }

        Ok(false)
    }

    fn on_home(&mut self) -> io::Result<bool> {
        let home_index = self.prompt_length() as u16;

        crossterm::execute!(self.stdout_locker, cursor::MoveToColumn(home_index))?;

        Ok(false)
    }

    fn on_end(&mut self) -> io::Result<bool> {
        let end_index = (self.prompt_length() + displayed_input!(self).len()) as u16;

        crossterm::execute!(self.stdout_locker, cursor::MoveToColumn(end_index))?;

        Ok(false)
    }

    fn on_page_up(&mut self) -> io::Result<bool> {
        Ok(false)
    }

    fn on_page_down(&mut self) -> io::Result<bool> {
        Ok(false)
    }

    fn on_tab(&mut self) -> io::Result<bool> {
        if let Some(input) = self
            .tab
            .on_tab(commands::MAIN_COMMANDS, &mut self.stdout_locker, &self.known_arg_data)?
        {
            **displayed_mut_input!(self) = input.chars().collect::<Vec<_>>();
        }

        self.reprint_input_line()?;

        Ok(false)
    }

    fn on_back_tab(&mut self) -> io::Result<bool> {
        Ok(false)
    }

    fn on_delete(&mut self) -> io::Result<bool> {
        let cursor_column: usize = cursor::position()?.0.into();

        if cursor_column < self.prompt_length() + displayed_input!(self).len() {
            let delete_position = cursor_column - self.prompt_length();

            displayed_mut_input!(self).remove(delete_position);

            crossterm::execute!(
                self.stdout_locker,
                terminal::Clear(terminal::ClearType::CurrentLine),
                cursor::MoveToColumn(0)
            )?;

            self.reprint_input_line()?;

            crossterm::execute!(self.stdout_locker, cursor::MoveToColumn(cursor_column as u16))?;

            self.tab.reset_tab_input(&displayed_input!(self))
        }

        Ok(false)
    }

    fn on_insert(&mut self) -> io::Result<bool> {
        if self.insert_mode {
            // go into overtype mode

            crossterm::execute!(self.stdout_locker, Self::OVERTYPE_CURSOR, cursor::Show)?;
        } else {
            // go into insert mode

            crossterm::execute!(self.stdout_locker, Self::INSERT_CURSOR, cursor::Show)?;
        }

        self.insert_mode = !self.insert_mode;

        self.reprint_input_line()?;

        Ok(false)
    }

    fn on_f_key(&mut self, _number: u8) -> io::Result<bool> {
        Ok(false)
    }

    fn on_char(&mut self, character: char) -> io::Result<bool> {
        let cursor_column: usize = cursor::position()?.0.into();

        if self.prompt_length() + displayed_input!(self).len() <= cursor_column {
            displayed_mut_input!(self).push(character);

            self.reprint_input_line()?;
        } else if self.insert_mode {
            let prompt_len = self.prompt_length();

            displayed_mut_input!(self).insert(cursor_column - prompt_len, character);

            self.reprint_input_line()?;

            crossterm::execute!(self.stdout_locker, cursor::MoveToColumn(cursor_column as u16))?;
        } else {
            let prompt_len = self.prompt_length();

            displayed_mut_input!(self)[cursor_column - prompt_len] = character;

            self.reprint_input_line()?;

            crossterm::execute!(self.stdout_locker, cursor::MoveToColumn(cursor_column as u16 + 1))?;
        }

        self.tab.reset_tab_input(&displayed_input!(self));

        Ok(false)
    }

    fn on_ctrl_char(&mut self, character: char) -> io::Result<bool> {
        on_key_combo!(self, character, &mut self.on_ctrl)
    }

    fn on_shift_char(&mut self, character: char) -> io::Result<bool> {
        on_key_combo!(self, character, &mut self.on_shift)
    }

    fn on_alt_char(&mut self, character: char) -> io::Result<bool> {
        on_key_combo!(self, character, &mut self.on_shift)
    }

    #[inline]
    fn on_null(&mut self) -> io::Result<bool> {
        Ok(false)
    }

    #[inline]
    fn on_esc(&mut self) -> io::Result<bool> {
        // Most of the time escape loses focus in the terminal,
        // so the detection of this will do noting.
        Ok(false)
    }

    /*
     * The following keys require enhanced terminal codes so
     * these methods are effectively the same as stubs.
     */

    #[inline]
    fn on_caps_lock(&mut self) -> io::Result<bool> {
        Ok(false)
    }

    #[inline]
    fn on_num_lock(&mut self) -> io::Result<bool> {
        Ok(false)
    }

    #[inline]
    fn on_print_screen(&mut self) -> io::Result<bool> {
        Ok(false)
    }

    #[inline]
    fn on_pause(&mut self) -> io::Result<bool> {
        Ok(false)
    }

    #[inline]
    fn on_menu(&mut self) -> io::Result<bool> {
        Ok(false)
    }

    #[inline]
    fn on_keypad_begin(&mut self) -> io::Result<bool> {
        Ok(false)
    }

    #[inline]
    fn on_media(&mut self, _: event::MediaKeyCode) -> io::Result<bool> {
        Ok(false)
    }

    #[inline]
    fn on_modifier(&mut self, _: event::ModifierKeyCode) -> io::Result<bool> {
        Ok(false)
    }
}
