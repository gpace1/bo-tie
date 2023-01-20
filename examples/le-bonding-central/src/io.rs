//! IO methods
//!
//! These methods are not important in *showing* an example of how to create a LE central, but they
//! necessary to provide user interaction for the example. None of the code here is relevant in
//! understanding how to use `bo-tie`.
//!
//! # Unix & Windows
//! [`crossterm`] is used for processing terminal I/O.
//!
//! [`crossterm`]: https://docs.rs/crossterm/latest/crossterm/

use crossterm::event::KeyModifiers;
use std::ops::RangeInclusive;
use std::sync::mpsc;
use tokio::sync::oneshot;

macro_rules! ok_or_return {
    ($result:expr, $sender:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                $sender.send(Err(e)).unwrap();
                return;
            }
        }
    };
}

struct InputTaskCallback<T> {
    task_success: oneshot::Receiver<crossterm::Result<T>>,
    task_cancel: Option<mpsc::SyncSender<()>>,
}

impl<T> InputTaskCallback<T> {
    fn new(task_done: oneshot::Receiver<crossterm::Result<T>>, task_cancel: mpsc::SyncSender<()>) -> Self {
        InputTaskCallback {
            task_success: task_done.into(),
            task_cancel: task_cancel.into(),
        }
    }
}

impl<T: Unpin> std::future::Future for InputTaskCallback<T> {
    type Output = Result<crossterm::Result<T>, oneshot::error::RecvError>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();

        let poll = core::pin::Pin::new(&mut this.task_success).poll(cx);

        // drop cancel
        if poll.is_ready() {
            this.task_cancel.take();
        }

        poll
    }
}

impl<T> Drop for InputTaskCallback<T> {
    fn drop(&mut self) {
        self.task_cancel.take().map(|cancel| cancel.send(()).unwrap());
    }
}

#[cfg(any(unix, windows))]
pub fn exit_signal() -> impl std::future::Future {
    use crossterm::event::{poll, read, Event, KeyCode, KeyEvent, KeyEventKind};

    let (ctrl_c_sender, ctrl_c_receiver) = oneshot::channel::<crossterm::Result<()>>();
    let (cancel_sender, cancel_receiver) = mpsc::sync_channel::<()>(0);

    std::thread::spawn(move || loop {
        if ok_or_return!(poll(core::time::Duration::from_millis(50)), ctrl_c_sender) {
            match ok_or_return!(read(), ctrl_c_sender) {
                Event::Key(KeyEvent {
                    code: KeyCode::Char('c'),
                    modifiers: KeyModifiers::CONTROL,
                    kind: KeyEventKind::Press,
                    ..
                }) => {
                    ctrl_c_sender.send(Ok(())).unwrap();
                    break;
                }
                _ => continue,
            }
        } else if let Ok(_) = cancel_receiver.try_recv() {
            break;
        }
    });

    async move {
        InputTaskCallback::new(ctrl_c_receiver, cancel_sender)
            .await
            .expect("cannot read input")
    }
}

/// Print an advertising result
#[cfg(any(unix, windows))]
pub fn on_advertising_result(number: usize, name: &str) {
    println!("{}) {}", number, name);
}

/// Create a future for detection of the escape key
#[cfg(any(unix, windows))]
pub fn detect_enter() -> impl std::future::Future<Output = bool> {
    use crossterm::event::{poll, read, Event, KeyCode, KeyEvent};

    println!("press enter to stop scanning");

    let (sender, receiver) = oneshot::channel::<crossterm::Result<bool>>();
    let (cancel_sender, cancel_receiver) = mpsc::sync_channel::<()>(0);

    std::thread::spawn(move || loop {
        if ok_or_return!(poll(std::time::Duration::from_millis(50)), sender) {
            match ok_or_return!(read(), sender) {
                Event::Key(KeyEvent {
                    code: KeyCode::Enter, ..
                }) => {
                    sender.send(Ok(true)).unwrap();
                    break;
                }
                Event::Key(KeyEvent {
                    code: KeyCode::Char('c'),
                    modifiers: KeyModifiers::CONTROL,
                    ..
                }) => {
                    sender.send(Ok(false)).unwrap();
                    break;
                }
                _ => continue,
            }
        } else {
            if let Ok(_) = cancel_receiver.try_recv() {
                break;
            }
        }
    });

    async move {
        InputTaskCallback::new(receiver, cancel_sender)
            .await
            .unwrap()
            .expect("cannot read input")
    }
}

#[cfg(not(any(unix, windows)))]
pub fn detect_escape() -> impl std::future::Future {
    compile_error!("cannot detect keys on this system")
}

#[cfg(any(unix, windows))]
pub fn select_device(range: RangeInclusive<usize>) -> impl std::future::Future<Output = Option<usize>> {
    use crossterm::event::{poll, read, Event, KeyCode, KeyEvent, KeyEventKind};
    use std::io::Write;

    println!("input the number of the device to connect to");

    let (sender, receiver) = oneshot::channel::<crossterm::Result<Option<usize>>>();
    let (cancel_sender, cancel_receiver) = mpsc::sync_channel::<()>(0);

    let mut message = String::new();

    std::thread::spawn(move || loop {
        if ok_or_return!(poll(std::time::Duration::from_millis(50)), sender) {
            match ok_or_return!(read(), sender) {
                Event::Key(KeyEvent {
                    code: KeyCode::Char('c'),
                    modifiers: KeyModifiers::CONTROL,
                    ..
                }) => {
                    sender.send(Ok(None)).unwrap();
                    break;
                }
                Event::Key(KeyEvent {
                    code: KeyCode::Char(char),
                    kind: KeyEventKind::Press,
                    ..
                }) => {
                    message.push(char);
                }
                Event::Key(KeyEvent {
                    code: KeyCode::Enter, ..
                }) => match <usize>::from_str_radix(&message, 10) {
                    Ok(val) if range.contains(&val) => {
                        sender.send(Ok(Some(val))).unwrap();
                        break;
                    }
                    _ => {
                        message.clear();
                        write!(
                            std::io::stdout(),
                            "please enter a valid number between {} and {}",
                            range.start(),
                            range.end()
                        )
                        .unwrap()
                    }
                },
                _ => continue,
            }
        } else {
            if let Ok(_) = cancel_receiver.try_recv() {
                break;
            }
        }
    });

    async move {
        InputTaskCallback::new(receiver, cancel_sender)
            .await
            .unwrap()
            .expect("cannot read input")
    }
}

fn await_yes_no_input() -> impl std::future::Future<Output = Option<String>> {
    use crossterm::event::{poll, read, Event, KeyCode, KeyEvent, KeyEventKind};

    let (input_sender, input_receiver) = oneshot::channel::<crossterm::Result<Option<String>>>();
    let (cancel_sender, cancel_receiver) = mpsc::sync_channel::<()>(0);

    let mut input = String::new();

    std::thread::spawn(move || loop {
        if ok_or_return!(poll(core::time::Duration::from_millis(50)), input_sender) {
            let event = ok_or_return!(read(), input_sender);
            match event {
                Event::Key(KeyEvent {
                    code: KeyCode::Char('c'),
                    modifiers: KeyModifiers::CONTROL,
                    kind: KeyEventKind::Press,
                    ..
                }) => {
                    input_sender.send(Ok(None)).unwrap();
                    break;
                }
                Event::Key(KeyEvent {
                    code: KeyCode::Enter, ..
                }) => {
                    input_sender.send(Ok(Some(input))).unwrap();
                    break;
                }
                Event::Key(KeyEvent {
                    code: KeyCode::Char(key),
                    kind: KeyEventKind::Press,
                    ..
                }) => input.push(key),
                _ => continue,
            }
        } else if let Ok(_) = cancel_receiver.try_recv() {
            break;
        }
    });

    async move {
        InputTaskCallback::new(input_receiver, cancel_sender)
            .await
            .expect("cannot read input")
            .expect("crossterm error")
    }
}

/// Number Comparison
async fn number_comparison_input() -> Option<bool> {
    let input = await_yes_no_input().await?;

    if "y" == input.to_lowercase() || "yes" == input.to_lowercase() {
        Some(true)
    } else if "n" == input.to_lowercase() || "no" == input.to_lowercase() {
        Some(false)
    } else {
        println!("invalid input '{}', defaulting to rejecting number comparison", input);
        Some(false)
    }
}

fn await_passkey() -> impl std::future::Future<Output = Option<Vec<char>>> {
    use crossterm::event::{poll, read, Event, KeyCode, KeyEvent, KeyEventKind};

    let (input_sender, input_receiver) = oneshot::channel::<crossterm::Result<Option<Vec<char>>>>();
    let (cancel_sender, cancel_receiver) = mpsc::sync_channel::<()>(0);

    std::thread::spawn(move || {
        let mut buffer = Vec::new();

        loop {
            if ok_or_return!(poll(core::time::Duration::from_millis(50)), input_sender) {
                match ok_or_return!(read(), input_sender) {
                    Event::Key(KeyEvent {
                        code: KeyCode::Char('c'),
                        modifiers: KeyModifiers::CONTROL,
                        kind: KeyEventKind::Press,
                        ..
                    }) => {
                        input_sender.send(Ok(None)).unwrap();
                        break;
                    }
                    Event::Key(KeyEvent {
                        code: KeyCode::Char(digit),
                        ..
                    }) => {
                        buffer.push(digit);
                    }
                    Event::Key(KeyEvent {
                        code: KeyCode::Enter,
                        kind: KeyEventKind::Press,
                        ..
                    }) => {
                        input_sender.send(Ok(Some(buffer))).unwrap();
                        break;
                    }
                    _ => continue,
                }
            } else if let Ok(_) = cancel_receiver.try_recv() {
                break;
            }
        }

        crossterm::execute!(std::io::stdout(), crossterm::event::PopKeyboardEnhancementFlags).unwrap();
    });

    async move {
        InputTaskCallback::new(input_receiver, cancel_sender)
            .await
            .expect("cannot read input")
            .expect("crossterm error")
    }
}

/// Message to the user about how the passkey should be entered
pub fn passkey_input_message(passkey_input: &bo_tie::host::sm::initiator::PasskeyInput) {
    if passkey_input.is_passkey_input_on_both() {
        println!("create a six digit passkey and enter it into both devices")
    } else {
        println!("enter the six digit passkey displayed on the other device")
    }
}

/// Read the passkey
pub fn process_passkey(input: Vec<char>) -> Option<[char; 6]> {
    if input.len() == 6 && input.iter().all(|c| c.is_digit(10)) {
        let mut passkey: [char; 6] = Default::default();

        passkey.iter_mut().zip(input.into_iter()).for_each(|(c, d)| *c = d);

        Some(passkey)
    } else {
        let passkey = input.into_iter().collect::<String>();

        println!(
            "passkey {passkey} is not a valid passkey. A passkey must consist of exactly six \
            digits"
        );

        None
    }
}

/// User Authentication (or exit)
pub enum UserAuthentication {
    NumberComparison(bool),
    PasskeyInput(Vec<char>),
    Exit,
}

/// Await for Authentication from the user
///
/// When the user needs to either confirm a number comparison or enter a passkey, this will await
/// the input from the user
///
/// # Note
/// This also awaits for 'ctrl-c' keypress from the user
pub async fn user_authentication_input(
    number_comparison: &Option<bo_tie::host::sm::initiator::NumberComparison>,
    passkey_input: &Option<bo_tie::host::sm::initiator::PasskeyInput>,
) -> UserAuthentication {
    match (number_comparison, passkey_input) {
        (None, None) => {
            exit_signal().await;
            UserAuthentication::Exit
        }
        (Some(_), None) => match number_comparison_input().await {
            Some(accepted) => UserAuthentication::NumberComparison(accepted),
            None => UserAuthentication::Exit,
        },
        (None, Some(_)) => match await_passkey().await {
            Some(passkey) => UserAuthentication::PasskeyInput(passkey),
            None => UserAuthentication::Exit,
        },
        (Some(_), Some(_)) => unreachable!(),
    }
}
