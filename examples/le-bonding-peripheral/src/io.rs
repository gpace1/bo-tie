//! IO with the user
use std::sync::mpsc;
use tokio::sync::oneshot;

/// Signal setup
///
/// This sets up the signal handling and returns a future for awaiting the reception of a signal.
#[cfg(unix)]
pub fn setup_sig() -> impl std::future::Future {
    println!("awaiting for 'ctrl-C' (or SIGINT) to stop example");

    tokio::signal::ctrl_c()
}

/// Stub for signal setup
///
/// This is a generic fallback that returns future that will forever pend. This method should try
/// to be avoided unless it is intended that the device running the example will be power cycled.
#[cfg(not(unix))]
pub fn setup_sig() -> impl std::future::Future {
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    core::future::pending::<()>()
}

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

fn await_input() -> impl std::future::Future<Output = String> {
    use crossterm::event::{poll, read, Event, KeyCode, KeyEvent, KeyEventKind};

    let (input_sender, input_receiver) = oneshot::channel::<crossterm::Result<String>>();
    let (cancel_sender, cancel_receiver) = mpsc::sync_channel::<()>(0);

    let mut input = String::new();

    std::thread::spawn(move || loop {
        if ok_or_return!(poll(core::time::Duration::from_millis(50)), input_sender) {
            match ok_or_return!(read(), input_sender) {
                Event::Key(KeyEvent {
                    code: KeyCode::Char(key),
                    kind: KeyEventKind::Press,
                    ..
                }) => input.push(key),
                Event::Key(KeyEvent {
                    code: KeyCode::Enter, ..
                }) => {
                    input_sender.send(Ok(input)).unwrap();
                    break;
                }
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
pub async fn number_comparison(number_comparison: &mut Option<bo_tie::host::sm::responder::NumberComparison>) -> bool {
    if let Some(_) = number_comparison.as_mut() {
        let input = await_input().await;

        if "y" == input.to_lowercase() || "yes" == input.to_lowercase() {
            true
        } else if "n" == input.to_lowercase() || "no" == input.to_lowercase() {
            false
        } else {
            println!("invalid input, defaulting to rejecting number comparison");
            false
        }
    } else {
        std::future::pending().await
    }
}

fn await_passkey() -> impl std::future::Future<Output = Vec<char>> {
    use crossterm::event::{poll, read, Event, KeyCode, KeyEvent, KeyEventKind};

    let (input_sender, input_receiver) = oneshot::channel::<crossterm::Result<Vec<char>>>();
    let (cancel_sender, cancel_receiver) = mpsc::sync_channel::<()>(0);

    std::thread::spawn(move || {
        let mut buffer = Vec::new();

        loop {
            if ok_or_return!(poll(core::time::Duration::from_millis(50)), input_sender) {
                match ok_or_return!(read(), input_sender) {
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
                        input_sender.send(Ok(buffer)).unwrap();
                        break;
                    }
                    _ => continue,
                }
            } else if let Ok(_) = cancel_receiver.try_recv() {
                break;
            }
        }
    });

    async move {
        InputTaskCallback::new(input_receiver, cancel_sender)
            .await
            .expect("cannot read input")
            .expect("crossterm error")
    }
}

/// Message to the user about how the passkey should be entered
pub fn passkey_input_message(passkey_input: &bo_tie::host::sm::responder::PasskeyInput) {
    if passkey_input.is_passkey_input_on_both() {
        println!("create a six digit passkey and enter it into both devices")
    } else {
        println!("enter the six digit passkey displayed on the other device")
    }
}

/// Await for key presses from the user
///
/// This will await for a keypresses from the user until the user presses enter.
///
/// # `inactive`
/// input `inactive` is used to turn keypress into a
pub async fn get_passkey(inactive: bool) -> Vec<char> {
    if inactive {
        core::future::pending().await
    } else {
        await_passkey().await
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
