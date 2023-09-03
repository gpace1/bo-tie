//! bo-tie-att integration tests
//!
//! These are tests of the bo-tie-att crate that require the implementation of a `L2CAP` in order to
//! execute.

use std::future::Future;

/// A simple rendezvous implementation
///
/// Unlike a barrier, a `Rendezvous` only works between two tasks and only clears when every task
/// is awaiting the `Rendezvous` at the same time (a barrier increases its clear count the moment
/// it is polled, which can cause issues with something like the `select!` macro).
pub struct Rendezvous {
    sender: tokio::sync::oneshot::Sender<()>,
    receiver: tokio::sync::oneshot::Receiver<()>,
}

impl Rendezvous {
    /// Rendezvous with the other task
    ///
    /// The return is the output value by the other `Rendezvous`'s task.
    pub async fn rendez(self) {
        self.sender.send(()).ok();

        self.receiver.await.expect("other Rendezvous dropped")
    }
}

pub fn rendezvous() -> (Rendezvous, Rendezvous) {
    let (sender_1, receiver_1) = tokio::sync::oneshot::channel();
    let (sender_2, receiver_2) = tokio::sync::oneshot::channel();

    (
        Rendezvous {
            sender: sender_1,
            receiver: receiver_2,
        },
        Rendezvous {
            sender: sender_2,
            receiver: receiver_1,
        },
    )
}
