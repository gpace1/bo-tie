/// Signal setup
///
/// This sets up the signal handling and returns a future for awaiting the reception of a signal.
#[cfg(unix)]
pub fn setup_sig() -> impl core::future::Future {
    println!("awaiting for 'ctrl-C' (or SIGINT) to stop example");

    tokio::signal::ctrl_c()
}

/// Stub for signal setup
///
/// This is a generic fallback that returns future that will forever pend. This method should try
/// to be avoided unless it is intended that the device running the example will be power cycled.
#[cfg(not(unix))]
pub fn setup_sig() -> impl core::future::Future {
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    struct ForeverPend;

    impl Future for ForeverPend {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }
}
