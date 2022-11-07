use std::ops::RangeInclusive;

/// IO methods
///
/// These methods are not important in *showing* an example of how to create a LE central, but they
/// necessary to provide user interaction for the example.
///
/// # Unix & Windows
/// [`crossterm`] is used for processing terminal I/O.
///
/// [`crossterm`]: https://docs.rs/crossterm/latest/crossterm/

/// Create a future for detection of the escape key
#[cfg(any(unix, windows))]
pub fn detect_escape() -> impl std::future::Future {
    use crossterm::event::{read, Event, KeyCode, KeyEvent};

    println!("press the escape key to stop scanning");

    let (sender, receiver) = tokio::sync::oneshot::channel::<crossterm::Result<()>>();

    std::thread::spawn(move || loop {
        match read() {
            Err(e) => {
                sender.send(Err(e)).unwrap();
                return;
            }
            Ok(io) => {
                if let Event::Key(KeyEvent { code: KeyCode::Esc, .. }) = io {
                    sender.send(Ok(())).unwrap();
                    return;
                }
            }
        }
    });

    async move { receiver.await.unwrap().expect("cannot read input") }
}

#[cfg(not(any(unix, windows)))]
pub fn detect_escape() -> impl std::future::Future {
    compile_error!("cannot detect keys on this system")
}

#[cfg(any(unix, windows))]
pub fn select_device(range: RangeInclusive<usize>) -> impl std::future::Future<Output = usize> {
    use std::io;

    println!("input the number of the device to connect to");

    let (sender, receiver) = tokio::sync::oneshot::channel::<io::Result<usize>>();

    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut buffer = String::new();

        loop {
            match stdin.read_line(&mut buffer) {
                Err(e) => {
                    sender.send(Err(e)).unwrap();
                    return;
                }
                Ok(_) => {
                    if let Ok(v) = buffer.parse::<usize>() {
                        if range.contains(&v) {
                            sender.send(Ok(v)).unwrap();
                            return;
                        }
                    }
                }
            }
        }
    });

    async move { receiver.await.unwrap().expect("cannot read input") }
}
