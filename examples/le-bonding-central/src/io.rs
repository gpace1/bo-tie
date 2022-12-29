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

use crossterm::cursor;
use std::ops::RangeInclusive;
use std::sync::mpsc;
use tokio::sync::oneshot;

/// Spawn a task for handling terminal I/O
macro_rules! term_raw_mode_task {
    ($sender:expr, $($job:tt)*) => {
        std::thread::spawn(move || {
            macro_rules! ok_or_break {
                ($result:expr) => {
                    match $result {
                        Ok(v) => v,
                        Err(e) => {
                            $sender.send(Err(e)).unwrap();
                            break;
                        }
                    }
                };
            }

            if let Err(e) = crossterm::terminal::enable_raw_mode() {
                $sender.send(Err(e)).unwrap();
                return
            }

            $($job)*

            crossterm::terminal::disable_raw_mode().unwrap()
        })
    };
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

#[cfg(any(unix, windows))]
pub fn exit_signal() -> impl std::future::Future {
    use crossterm::event::{poll, read, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

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

/// Process an advertising result
#[cfg(any(unix, windows))]
pub fn on_advertising_result(number: usize, name: &str) {
    use std::io::Write;

    let mut stdout = std::io::stdout();

    crossterm::execute!(stdout, cursor::MoveToColumn(0)).unwrap();

    write!(stdout, "{}) {}", number, name).unwrap();

    stdout.flush().unwrap();

    if crossterm::terminal::size().unwrap().1 - 1 == cursor::position().unwrap().1 {
        crossterm::execute!(stdout, crossterm::terminal::ScrollUp(1)).unwrap();
    }

    crossterm::execute!(stdout, cursor::MoveDown(1), cursor::MoveToColumn(0)).unwrap();
}

/// Create a future for detection of the escape key
#[cfg(any(unix, windows))]
pub fn detect_escape() -> impl std::future::Future<Output = bool> {
    use crossterm::event::{poll, read, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    println!("press the escape key to stop scanning");

    let (sender, receiver) = oneshot::channel::<crossterm::Result<bool>>();
    let (cancel_sender, cancel_receiver) = mpsc::sync_channel::<()>(0);

    term_raw_mode_task!(
        sender,
        loop {
            if ok_or_break!(poll(std::time::Duration::from_millis(50))) {
                match ok_or_break!(read()) {
                    Event::Key(KeyEvent {
                        code: KeyCode::Esc,
                        kind: KeyEventKind::Press,
                        ..
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
        }
    );

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
    use crossterm::cursor::{MoveDown, MoveToColumn};
    use crossterm::event::{poll, read, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
    use std::io::Write;

    println!("input the number of the device to connect to");

    let (sender, receiver) = oneshot::channel::<crossterm::Result<Option<usize>>>();
    let (cancel_sender, cancel_receiver) = mpsc::sync_channel::<()>(0);

    term_raw_mode_task!(sender,
        let mut buffer = String::new();

        macro_rules! output_buffer {
            () => {{
                let mut stdout = std::io::stdout();

                crossterm::execute!(&mut stdout, crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine), MoveToColumn(0)).unwrap();

                write!(&mut stdout, "{}", buffer).unwrap();

                stdout.flush().unwrap();
            }}
        }

        loop {
            if ok_or_break!(poll(std::time::Duration::from_millis(50))) {
                match ok_or_break!(read()) {
                    Event::Key(KeyEvent {
                        code: KeyCode::Char('c'),
                        modifiers: KeyModifiers::CONTROL,
                        ..
                    }) => {
                        sender.send(Ok(None)).unwrap();
                        break;
                    },
                    Event::Key(KeyEvent {
                        code: KeyCode::Char(c),
                        kind: KeyEventKind::Press | KeyEventKind::Repeat,
                        ..
                    }) => {
                        buffer.push(c);

                        output_buffer!()
                    },
                    Event::Key(KeyEvent {
                        code: KeyCode::Backspace,
                        kind: KeyEventKind::Press | KeyEventKind::Repeat,
                        ..
                    }) => {
                        buffer.pop();

                        output_buffer!()
                    }
                    Event::Key(KeyEvent {
                        code: KeyCode::Enter,
                        kind: KeyEventKind::Press,
                        ..
                    }) => {
                        let mut stdout = std::io::stdout();

                        if crossterm::terminal::size().unwrap().1 - 1 == cursor::position().unwrap().1 {
                            crossterm::execute!(stdout, crossterm::terminal::ScrollUp(1)).unwrap();
                        }

                        ok_or_break!(crossterm::execute!(stdout, MoveDown(1), MoveToColumn(0)));

                        if let Ok(value) = buffer.parse() {
                            if range.contains(&value) {
                                sender.send(Ok(Some(value))).unwrap();
                                break;
                            }
                        }

                        buffer.clear();

                        write!(stdout, "please enter a valid number between {} and {}", range.start(), range.end()).unwrap();

                        stdout.flush().unwrap();

                        if crossterm::terminal::size().unwrap().1 - 1 == cursor::position().unwrap().1 {
                            crossterm::execute!(stdout, crossterm::terminal::ScrollUp(1)).unwrap();
                        }

                        ok_or_break!(crossterm::execute!(stdout, MoveDown(1), MoveToColumn(0)));
                    }
                    _ => continue,
                }
            } else {
                if let Ok(_) = cancel_receiver.try_recv() {
                    break;
                }
            }
        }
    );

    async move {
        InputTaskCallback::new(receiver, cancel_sender)
            .await
            .unwrap()
            .expect("cannot read input")
    }
}
