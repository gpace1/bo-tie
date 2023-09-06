//! Spoofs of Physical Links
//!
//! These are used to create spoofs for a physical link.

use bo_tie_l2cap::pdu::L2capFragment;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};

/// A physical link spoof
///
/// This is used for spoofing the physical link that interacts with the L2CAP implementation within
/// bo-tie. It can be created via the `PhysicalLinkBuilder`.
pub struct PhysicalLink {
    max_tx_size: usize,
    sender: UnboundedSender<(bool, Vec<u8>)>,
    receiver: Pin<Arc<Mutex<UnboundedReceiver<(bool, Vec<u8>)>>>>,
}

impl PhysicalLink {
    /// Create two linked `PhysicalLink`s
    ///
    /// This creates two `PhysicalLink`s that a 'linked together'. Sending on one physical link will
    /// cause a reception on the other.
    ///
    /// Input `max_tx_size` is the maximum allowable size of the data transferred
    pub fn new_connection(max_tx_size: usize) -> (Self, Self) {
        let (sender_a, receiver_a) = futures::channel::mpsc::unbounded();
        let (sender_b, receiver_b) = futures::channel::mpsc::unbounded();

        let physical_link_a = PhysicalLink {
            max_tx_size,
            sender: sender_a,
            receiver: Arc::pin(Mutex::new(receiver_b)),
        };

        let physical_link_b = PhysicalLink {
            max_tx_size,
            sender: sender_b,
            receiver: Arc::pin(Mutex::new(receiver_a)),
        };

        (physical_link_a, physical_link_b)
    }

    /// Create an unliked `PhysicalLink`
    ///
    /// This returns a `PhysicalLink` and closures that can be used to directly send and receive
    /// packets from the physical link.
    ///
    /// # Inputs
    /// The `max_tx_size` is the maximum size that can be sent by the returned `PhysicalLink`.
    /// However the returned *sender* does not check if the fragment data is larger than this value.
    ///
    /// # Outputs
    /// `new_unliked` outputs a `PhysicalLink`, a *sender* closure, and a *receiver* closure in that
    /// order.
    ///
    /// ## PhysicalLink
    /// The physical link's internal sender and receiver are tied to the returned receiver and
    /// sender, respectively.
    ///
    /// ## Sender
    /// This closure is used to send fragments to the receiver of the `PhysicalLink`.
    ///
    /// ### Panic
    /// The sender closure will panic if the `PhysicalLink` is dropped.
    ///
    /// ## Receiver
    /// This closure is used to *immediately* get fragments 'sent' using the `PhysicalLink`. If
    /// there is no data within the channel the closure will return `None`.
    ///
    /// ### Panic
    /// The receiver closure will panic if the `PhysicalLink` is dropped.
    pub fn new_false_connection(
        max_tx_size: usize,
    ) -> (
        Self,
        impl Fn(L2capFragment<Vec<u8>>),
        impl FnMut() -> Option<L2capFragment<Vec<u8>>>,
    ) {
        let (sender_a, mut receiver_a) = futures::channel::mpsc::unbounded();
        let (sender_b, receiver_b) = futures::channel::mpsc::unbounded();

        let physical_link = PhysicalLink {
            max_tx_size,
            sender: sender_a,
            receiver: Arc::pin(Mutex::new(receiver_b)),
        };

        let sender_fn = move |fragment: L2capFragment<Vec<u8>>| {
            let is_start = fragment.is_start_fragment();
            let data = fragment.into_inner();

            sender_b.unbounded_send((is_start, data)).expect("failed to send data")
        };

        let receiver_fn = move || {
            receiver_a
                .try_next()
                .transpose()
                .expect("channel is closed")
                .ok()
                .map(|(is_start, data)| L2capFragment::new(is_start, data))
        };

        (physical_link, sender_fn, receiver_fn)
    }

    /// Create an injection
    ///
    /// This creates an injection closure to directly send fragments using the sender held by this
    /// PhysicalLink.
    ///
    /// # Output
    /// The output is a closure that will send fragments on the same channel that this
    /// `PhysicalLink` sends fragments on.
    ///
    /// # Panic
    /// The returned closure will panic if the channel was closed.
    pub fn get_injection(&self) -> impl Fn(L2capFragment<Vec<u8>>) {
        let sender = self.sender.clone();

        move |fragment| {
            let is_start = fragment.is_start_fragment();
            let data = fragment.into_inner();

            sender.unbounded_send((is_start, data)).expect("channel is closed")
        }
    }

    /// Borrow the Receiver
    ///
    /// This will borrow the receiver out of the `PhysicalLink`.
    ///
    /// While the receiver is borrowed, this `PhysicalLink` will always pend when users of this
    /// physical link try to receive data.
    ///
    /// The borrow will last until the return is dropped.
    ///
    /// # Panic
    /// This will panic if this is called to create multiple `BorrowedReceiver`s. The previously
    /// created `BorrowedReceiver` must be dropped before this method can be called again.
    pub fn borrow_receiver(&self) -> BorrowedReceiver {
        BorrowedReceiver::new(self.receiver.clone())
    }
}

impl bo_tie_l2cap::PhysicalLink for PhysicalLink {
    type SendFut<'a> = Pin<Box<dyn Future<Output = Result<(), Self::SendErr>> + Send + 'a>>;

    type SendErr = anyhow::Error;

    type RecvFut<'a> =
        Pin<Box<dyn Future<Output = Option<Result<L2capFragment<Self::RecvData>, Self::RecvErr>>> + Send + 'a>>;

    type RecvData = std::vec::IntoIter<u8>;

    type RecvErr = anyhow::Error;

    fn max_transmission_size(&self) -> usize {
        self.max_tx_size
    }

    fn send<'s, T>(&'s mut self, fragment: L2capFragment<T>) -> Self::SendFut<'s>
    where
        T: 's + IntoIterator<Item = u8>,
    {
        let max_len = self.max_tx_size;

        let is_start = fragment.is_start_fragment();

        let data: Vec<u8> = fragment.into_inner().into_iter().collect();

        assert!(
            data.len() <= max_len,
            "the fragment data length is larger than the maximum allowed transmission size"
        );

        let send = async move {
            futures::SinkExt::send(&mut self.sender, (is_start, data)).await?;

            Ok(())
        };

        Box::pin(send)
    }

    fn recv(&mut self) -> Self::RecvFut<'_> {
        struct InjectedReceiver<'a>(&'a Mutex<UnboundedReceiver<(bool, Vec<u8>)>>);

        impl Future for InjectedReceiver<'_> {
            type Output = Option<(bool, Vec<u8>)>;

            fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
                let this = self.get_mut();

                match this.0.try_lock() {
                    Ok(mut rx) => futures::StreamExt::poll_next_unpin(&mut *rx, cx),
                    _ => std::task::Poll::Pending,
                }
            }
        }

        let recv = async {
            let recv = InjectedReceiver(&mut self.receiver).await;

            let maybe_fragment = recv.map(|(is_start, data)| L2capFragment::new(is_start, data.into_iter()));

            Ok::<_, anyhow::Error>(maybe_fragment).transpose()
        };

        Box::pin(recv)
    }
}

pub struct BorrowedReceiver {
    lock: MutexGuard<'static, UnboundedReceiver<(bool, Vec<u8>)>>,
    _receiver: Pin<Arc<Mutex<UnboundedReceiver<(bool, Vec<u8>)>>>>,
}

impl BorrowedReceiver {
    fn new(receiver: Pin<Arc<Mutex<UnboundedReceiver<(bool, Vec<u8>)>>>>) -> Self {
        let lock_local = receiver.lock().expect("failed to acquire lock");

        let lock = unsafe { std::mem::transmute(lock_local) };

        Self {
            _receiver: receiver,
            lock,
        }
    }

    /// Await for the next L2CAP Fragment
    pub async fn recv(&mut self) -> L2capFragment<Vec<u8>> {
        let (is_start, data) = futures::StreamExt::next(&mut *self.lock)
            .await
            .expect("channel is closed");

        L2capFragment::new(is_start, data)
    }
}
