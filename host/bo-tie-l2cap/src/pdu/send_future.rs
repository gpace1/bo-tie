//! Flow Control Send Future
//!
//! Fragmentation is done by slicing up a L2CAP pdu into pre-allocated buffers sized to fit either
//! the MTU of the connection or the Controller's maximum data transfer size (probably specified
//! within the HCI).

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

const BUFFERS_EXPECT: &'static str = "input 'buffers' returned None";

pub struct BufferedFragmentsFuture<T, D, B, F, S> {
    fragments_iter: T,
    data_iter: Option<D>,
    buffer_iter: B,
    state: State<F, S>,
}

impl<T, D, B, F, S> BufferedFragmentsFuture<T, D, B, F, S> {
    pub fn new<'a, I, P, C>(
        fragmentation_size: usize,
        pdu: &'a P,
        buffers: I,
    ) -> Result<Self, crate::pdu::FragmentationError>
    where
        T: Iterator<Item = D> + 'a,
        D: 'a,
        I: IntoIterator<IntoIter = B>,
        B: Iterator<Item = F>,
        F: Future<Output = C>,
        P: crate::pdu::FragmentL2capPdu<FragmentIterator<'a> = T, DataIter<'a> = D> + ?Sized,
    {
        assert_ne!(fragmentation_size, 0, "the size of a fragment cannot be zero");

        let mut fragments_iter = pdu.as_fragments(fragmentation_size)?;

        let data_iter = fragments_iter.next();

        let mut buffer_iter = buffers.into_iter();

        let first_buffer = buffer_iter.next().expect("failed to acquire buffer future");

        let state = if data_iter.is_some() {
            State::AcquireBuffer(first_buffer)
        } else {
            State::Complete // ¯\_(ツ)_/¯
        };

        Ok(Self {
            fragments_iter,
            data_iter,
            buffer_iter,
            state,
        })
    }
}

impl<T, D, B, F, C, E> Future for BufferedFragmentsFuture<T, D, B, F, C::IntoFuture>
where
    T: Iterator<Item = D>,
    D: Iterator<Item = u8>,
    B: Iterator<Item = F>,
    F: Future<Output = C>,
    C: crate::TryExtend<u8> + core::future::IntoFuture<Output = Result<(), E>>,
{
    type Output = Result<(), E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // No generics except for F and C are moved. Using `get_unchecked_mut`
        // is safe because both types F and C are moved only before they have
        // been polled and are dropped once they have polled to completion.

        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match &mut this.state {
                State::AcquireBuffer(future) => match unsafe { Pin::new_unchecked(future) }.poll(cx) {
                    Poll::Ready(mut current) => {
                        current
                            .try_extend(this.data_iter.as_mut().into_iter().flatten())
                            .expect("buffer is too small for fragment");

                        this.state = State::FinishCurrent(current.into_future())
                    }
                    Poll::Pending => break Poll::Pending,
                },
                State::FinishCurrent(current) => match unsafe { Pin::new_unchecked(current) }.poll(cx)? {
                    Poll::Ready(_) => match this.fragments_iter.next() {
                        None => this.state = State::Complete,
                        data_iter => {
                            let future = this.buffer_iter.next().expect(BUFFERS_EXPECT);

                            this.data_iter = data_iter;

                            this.state = State::AcquireBuffer(future);
                        }
                    },
                    Poll::Pending => break Poll::Pending,
                },
                State::Complete => break Poll::Ready(Ok(())),
            }
        }
    }
}

/// States used to describe the current operation when polling a `AsSlicedPacketFuture`
enum State<F, S> {
    AcquireBuffer(F),
    FinishCurrent(S),
    Complete,
}
