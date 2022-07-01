use super::BasicInfoFrame;
use core::future::Future;
use core::ops::AddAssign;
use core::pin::Pin;
use core::task::{Context, Poll};

const BUFFERS_EXPECT: &'static str = "input 'buffers' returned None";

pub struct AsSlicedPacketFuture<I, D, F, C, S> {
    mtu: usize,
    byte_count: usize,
    iter: I,
    len: [u8; 2],
    channel_id: [u8; 2],
    data: D,
    state: State<C, F, S>,
}

impl<I, D, F, C, S> AsSlicedPacketFuture<I, D, F, C, S> {
    pub fn new<T>(mtu: usize, frame: BasicInfoFrame<D>, into_iterator: T) -> Self
    where
        T: IntoIterator<IntoIter = I>,
        I: Iterator<Item = F>,
        F: Future<Output = C>,
        D: core::ops::Deref<Target = [u8]>,
    {
        use core::convert::TryInto;

        let byte_count = 0;

        let len: u16 = frame.data.len().try_into().expect("Couldn't convert into u16");

        let len = len.to_le_bytes();

        let channel_id = frame.channel_id.to_val().to_le_bytes();

        let data = frame.data;

        let mut iter = into_iterator.into_iter();

        let first = iter.next().unwrap();

        // The first state is to acquire the first buffer from the buffer iter.
        let state = State::AcquireBuffer(first, 0, State::length);

        Self {
            mtu,
            byte_count,
            iter,
            len,
            channel_id,
            data,
            state,
        }
    }
}

macro_rules! try_extend_current {
    ($this:expr, $current:expr, $val:expr) => {
        if $this.mtu < $this.byte_count {
            if let Err(_) = $current.try_extend_one($val) {
                $this.byte_count = 0;
                Err(())
            } else {
                Ok(())
            }
        } else {
            Err(())
        }
    };
}

impl<I, D, F, C, E> Future for AsSlicedPacketFuture<I, D, F, C, C::IntoFuture>
where
    I: Iterator<Item = F>,
    D: core::ops::Deref<Target = [u8]>,
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
                State::AcquireBuffer(future, index, to_next) => match unsafe { Pin::new_unchecked(future) }.poll(cx) {
                    Poll::Ready(current) => this.state = to_next(current, *index),
                    Poll::Pending => break Poll::Pending,
                },
                State::FinishCurrent(current, index, to_next) => {
                    match unsafe { Pin::new_unchecked(current) }.poll(cx)? {
                        Poll::Ready(_) => {
                            let future = this.iter.next().expect(BUFFERS_EXPECT);

                            this.state = State::AcquireBuffer(future, *index, *to_next);
                        }
                        Poll::Pending => break Poll::Pending,
                    }
                }
                State::Length(current, index) => {
                    if let Some(val) = this.len.get(*index).copied() {
                        match try_extend_current!(this, current, val) {
                            Ok(_) => this.state.next_index(),
                            Err(_) => {
                                let (current, index) = match core::mem::replace(&mut this.state, State::Complete) {
                                    State::Length(current, index) => (current, index),
                                    _ => unreachable!(),
                                };

                                this.state = State::FinishCurrent(current.into_future(), index, State::length)
                            }
                        }
                    } else {
                        match core::mem::replace(&mut this.state, State::TEMPORARY) {
                            State::Length(current, _) => this.state = State::ChannelId(current, 0),
                            _ => unreachable!(),
                        }
                    }
                }
                State::ChannelId(current, index) => {
                    if let Some(val) = this.channel_id.get(*index).copied() {
                        match try_extend_current!(this, current, val) {
                            Ok(_) => this.state.next_index(),
                            Err(_) => {
                                let (current, index) = match core::mem::replace(&mut this.state, State::Complete) {
                                    State::ChannelId(current, index) => (current, index),
                                    _ => unreachable!(),
                                };

                                this.state = State::FinishCurrent(current.into_future(), index, State::channel_id)
                            }
                        }
                    } else {
                        match core::mem::replace(&mut this.state, State::TEMPORARY) {
                            State::ChannelId(current, _) => this.state = State::Data(current, 0),
                            _ => unreachable!(),
                        }
                    }
                }
                State::Data(current, index) => {
                    if let Some(val) = this.data.get(*index).copied() {
                        match try_extend_current!(this, current, val) {
                            Ok(_) => this.state.next_index(),
                            Err(_) => {
                                let (current, index) = match core::mem::replace(&mut this.state, State::Complete) {
                                    State::Data(current, index) => (current, index),
                                    _ => unreachable!(),
                                };

                                this.state = State::FinishCurrent(current.into_future(), index, State::data)
                            }
                        }
                    } else {
                        this.state = State::Complete
                    }
                }
                State::Complete => break Poll::Ready(Ok(())),
            }
        }
    }
}

enum State<C, F, S> {
    AcquireBuffer(F, usize, fn(C, usize) -> Self),
    FinishCurrent(S, usize, fn(C, usize) -> Self),
    Length(C, usize),
    ChannelId(C, usize),
    Data(C, usize),
    Complete,
}

impl<C, F, S> State<C, F, S> {
    const TEMPORARY: Self = State::Complete;

    /// Go to the next index
    ///
    /// # Panic
    /// If `next_index` is called an enum other than `Length`, `ChannelId`, or `Data`.
    fn next_index(&mut self) {
        match self {
            State::Length(_, index) => index.add_assign(1),
            State::ChannelId(_, index) => index.add_assign(1),
            State::Data(_, index) => index.add_assign(1),
            _ => panic!("next_index called on an invalid State"),
        }
    }

    /// Create a Length enum
    fn length(current: C, index: usize) -> Self {
        Self::Length(current, index)
    }

    /// Create a ChannelId enum
    fn channel_id(current: C, index: usize) -> Self {
        Self::ChannelId(current, index)
    }

    /// Create a Data enum
    fn data(current: C, index: usize) -> Self {
        Self::Data(current, index)
    }
}
