//! Host integration test framework

use bo_tie_core::buffer::stack::{LinearBuffer, LinearBufferError, LinearBufferIter};
use bo_tie_core::buffer::TryExtend;
use bo_tie_l2cap::pdu::L2capFragment;
use bo_tie_l2cap::PhysicalLink;
use std::fmt::{Display, Formatter};
use std::future::{Future, IntoFuture};
use std::pin::{pin, Pin};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// A loop between to connected physical links
pub struct PhysicalLinkLoop<const BUFFER_SIZE: usize> {
    a_data: Arc<Mutex<Option<L2capFragment<LinearBuffer<BUFFER_SIZE, u8>>>>>,
    b_data: Arc<Mutex<Option<L2capFragment<LinearBuffer<BUFFER_SIZE, u8>>>>>,
    a_waker: Arc<Mutex<Option<Waker>>>,
    b_waker: Arc<Mutex<Option<Waker>>>,
    closed: Arc<Mutex<bool>>,
}

impl Default for PhysicalLinkLoop<32> {
    fn default() -> Self {
        PhysicalLinkLoop::<32>::new()
    }
}

impl<const BUFFER_SIZE: usize> PhysicalLinkLoop<BUFFER_SIZE> {
    pub fn new() -> Self {
        let a_data = Arc::new(Mutex::new(None));
        let b_data = Arc::new(Mutex::new(None));
        let a_waker = Arc::new(Mutex::new(None));
        let b_waker = Arc::new(Mutex::new(None));
        let closed = Arc::new(Mutex::new(false));

        PhysicalLinkLoop {
            a_data,
            b_data,
            a_waker,
            b_waker,
            closed,
        }
    }

    /// Get the test scaffold for this physical link loop
    pub fn test_scaffold(&mut self) -> TestScaffold<'_, (), (), BUFFER_SIZE> {
        TestScaffold::new(self)
    }
}

impl<const BUFFER_SIZE: usize> core::fmt::Debug for PhysicalLinkLoop<BUFFER_SIZE> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        f.debug_struct("PhysicalLinkLoop")
            .field("a_data", &self.a_data)
            .field("b_data", &self.b_data)
            .field("a_waker", &"..")
            .field("b_waker", &"..")
            .finish()
    }
}

/// One end of a physical link loop
///
/// This is returned by [`PhysicalLinkLoop::channel`]
pub struct PhysicalLinkLoopEnd<const BUFFER_SIZE: usize> {
    data: Arc<Mutex<Option<L2capFragment<LinearBuffer<BUFFER_SIZE, u8>>>>>,
    peer_data: Arc<Mutex<Option<L2capFragment<LinearBuffer<BUFFER_SIZE, u8>>>>>,
    waker: Arc<Mutex<Option<Waker>>>,
    peer_waker: Arc<Mutex<Option<Waker>>>,
    closed: Arc<Mutex<bool>>,
}

impl<const BUFFER_SIZE: usize> core::fmt::Debug for PhysicalLinkLoopEnd<BUFFER_SIZE> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        f.debug_struct("PhysicalLinkLoop")
            .field("data", &self.data)
            .field("peer_data", &self.peer_data)
            .field("waker", &"..")
            .field("peer_waker", &"..")
            .finish()
    }
}

impl<const BUFFER_SIZE: usize> Drop for PhysicalLinkLoopEnd<BUFFER_SIZE> {
    fn drop(&mut self) {
        *self.closed.lock().unwrap() = true
    }
}

pub struct PhysicalLinkLoopEndSendFut<'a, const BUFFER_SIZE: usize> {
    end: &'a mut PhysicalLinkLoopEnd<BUFFER_SIZE>,
    data: LinearBuffer<BUFFER_SIZE, u8>,
    is_start_fragment: bool,
}

impl<const BUFFER_SIZE: usize> Future for PhysicalLinkLoopEndSendFut<'_, BUFFER_SIZE> {
    type Output = Result<(), LinearBufferError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let mut end_data = this.end.data.lock().unwrap();

        if end_data.is_some() {
            *this.end.waker.lock().unwrap() = Some(cx.waker().clone());

            Poll::Pending
        } else {
            let fragment = L2capFragment::new(this.is_start_fragment, core::mem::take(&mut this.data));

            *end_data = Some(fragment);

            this.end.peer_waker.lock().unwrap().take().map(|waker| waker.wake());

            Poll::Ready(Ok(()))
        }
    }
}

#[derive(Debug)]
pub enum PhysicalLinkLoopEndSendFutError {
    Buffer(LinearBufferError),
    ReceiverClosed,
}

impl Display for PhysicalLinkLoopEndSendFutError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            PhysicalLinkLoopEndSendFutError::Buffer(buffer) => Display::fmt(buffer, f),
            PhysicalLinkLoopEndSendFutError::ReceiverClosed => f.write_str("physical link receiver closed"),
        }
    }
}

pub struct PhysicalLinkLoopEndRecvFut<'a, const BUFFER_SIZE: usize> {
    end: &'a mut PhysicalLinkLoopEnd<BUFFER_SIZE>,
}

impl<const BUFFER_SIZE: usize> Future for PhysicalLinkLoopEndRecvFut<'_, BUFFER_SIZE> {
    type Output = Option<Result<L2capFragment<LinearBufferIter<BUFFER_SIZE, u8>>, core::convert::Infallible>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let mut end_data = this.end.peer_data.lock().unwrap();

        if end_data.is_none() {
            *this.end.waker.lock().unwrap() = Some(cx.waker().clone());

            if *this.end.closed.lock().unwrap() {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        } else {
            this.end.peer_waker.lock().unwrap().take().map(|w| w.wake());

            let fragment = Ok(end_data
                .take()
                .map(|f| L2capFragment::new(f.is_start_fragment(), f.into_inner().into_iter())))
            .transpose();

            Poll::Ready(fragment)
        }
    }
}

impl<'i, const BUFFER_SIZE: usize> PhysicalLink for PhysicalLinkLoopEnd<BUFFER_SIZE> {
    type SendFut<'a> = PhysicalLinkLoopEndSendFut<'a, BUFFER_SIZE> where Self: 'a;
    type SendErr = LinearBufferError;
    type RecvFut<'a> = PhysicalLinkLoopEndRecvFut<'a, BUFFER_SIZE> where Self: 'a;
    type RecvData = LinearBufferIter<BUFFER_SIZE, u8>;
    type RecvErr = core::convert::Infallible;

    fn max_transmission_size(&self) -> u16 {
        BUFFER_SIZE as u16
    }

    fn send<T>(&mut self, fragment: L2capFragment<T>) -> Self::SendFut<'_>
    where
        T: IntoIterator<Item = u8>,
    {
        let mut data = LinearBuffer::default();

        let is_start_fragment = fragment.is_start_fragment();

        data.try_extend(fragment.into_inner()).expect("invalid fragment length");

        PhysicalLinkLoopEndSendFut {
            end: self,
            data,
            is_start_fragment,
        }
    }

    fn recv(&mut self) -> Self::RecvFut<'_> {
        PhysicalLinkLoopEndRecvFut { end: self }
    }
}

/// Scaffold for a peer-to-peer test
///
/// This is used for created a tested and a verifying peer-to-peer pseudo-link
#[must_use]
pub struct TestScaffold<'a, T, V, const BUFFER_SIZE: usize> {
    link_loop: &'a PhysicalLinkLoop<BUFFER_SIZE>,
    tested: T,
    verify: V,
}

impl<'a, const BUFFER_SIZE: usize> TestScaffold<'a, (), (), BUFFER_SIZE> {
    fn new(link_loop: &'a mut PhysicalLinkLoop<BUFFER_SIZE>) -> Self {
        let tested = ();
        let verify = ();

        TestScaffold {
            link_loop,
            tested,
            verify,
        }
    }
}

impl<'a, T, V, const BUFFER_SIZE: usize> TestScaffold<'a, T, V, BUFFER_SIZE> {
    /// Set the future to be tested
    ///
    /// # Note
    /// It is fine if the future returned by the input `f` never polls to completion. It is OK to do
    /// something like this:
    ///
    /// ```
    /// # use bo_tie_host_tests::PhysicalLinkLoop;
    /// # use core::future;
    /// # tokio_test::block_on(async {
    /// PhysicalLinkLoop::default()
    ///     .test_scaffold()
    ///     // this never polls to completion and that is OK!
    ///     .set_tested(|_| future::pending::<()>())
    ///     .set_verify(|_| async { assert_ne!(1, 2) })
    ///     .run()
    ///     .await
    /// # });
    /// ```
    pub fn set_tested<Fun, Fut>(self, f: Fun) -> TestScaffold<'a, Fut, V, BUFFER_SIZE>
    where
        Fun: FnOnce(PhysicalLinkLoopEnd<BUFFER_SIZE>) -> Fut,
        Fut: IntoFuture,
        Fut::IntoFuture: Send,
    {
        let end = PhysicalLinkLoopEnd {
            data: self.link_loop.a_data.clone(),
            peer_data: self.link_loop.b_data.clone(),
            waker: self.link_loop.a_waker.clone(),
            peer_waker: self.link_loop.b_waker.clone(),
            closed: self.link_loop.closed.clone(),
        };

        let link_loop = self.link_loop;

        let tested = f(end);

        let verify = self.verify;

        TestScaffold {
            link_loop,
            tested,
            verify,
        }
    }

    /// Set the future to verify the tested
    ///
    /// The future returned by input `f` must poll to completion.
    pub fn set_verify<Fun, Fut>(self, f: Fun) -> TestScaffold<'a, T, Fut, BUFFER_SIZE>
    where
        Fun: FnOnce(PhysicalLinkLoopEnd<BUFFER_SIZE>) -> Fut,
        Fut: IntoFuture,
        Fut::IntoFuture: Send,
    {
        let end = PhysicalLinkLoopEnd {
            data: self.link_loop.b_data.clone(),
            peer_data: self.link_loop.a_data.clone(),
            waker: self.link_loop.b_waker.clone(),
            peer_waker: self.link_loop.a_waker.clone(),
            closed: self.link_loop.closed.clone(),
        };

        let link_loop = self.link_loop;

        let tested = self.tested;

        let verify = f(end);

        TestScaffold {
            link_loop,
            tested,
            verify,
        }
    }

    /// Run the tests
    pub async fn run(self)
    where
        T: IntoFuture,
        V: IntoFuture,
    {
        let mut tested = pin!(async {
            self.tested.await;

            core::future::pending::<()>().await
        });

        let mut verify = pin!(self.verify.into_future());

        core::future::poll_fn(|context| {
            if tested.as_mut().poll(context).is_ready() {
                unreachable!("unexpected output of tested")
            } else if verify.as_mut().poll(context).is_ready() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}
