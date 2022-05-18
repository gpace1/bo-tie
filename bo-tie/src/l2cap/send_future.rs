use super::BasicInfoFrame;
use core::future::Future;
use core::ops::AddAssign;
use core::pin::Pin;
use core::task::{Context, Poll};

const BUFFERS_EXPECT: &'static str = "input 'buffers' returned None";

pub struct AsSlicedPacketFuture<I, F, D> {
    iter: I,
    len: [u8; 2],
    channel_id: [u8; 2],
    data: alloc::vec::Vec<u8>,
    current_buffer: Option<D>,
    state: State<D, F>,
}

impl<I, F, D> AsSlicedPacketFuture<I, F, D> {
    pub async fn new<T>(frame: BasicInfoFrame, into_iterator: T) -> Self
    where
        T: IntoIterator<IntoIter = I>,
        I: Iterator<Item = F>,
    {
        use core::convert::TryInto;

        let len: u16 = frame.data.len().try_into().expect("Couldn't convert into u16");

        let len = len.to_le_bytes();

        let channel_id = frame.channel_id.to_val().to_le_bytes();

        let data = frame.data;

        let current_buffer = None;

        let mut iter = into_iterator.into_iter();

        let first = iter.next().await;

        // The first state is to acquire the first buffer from the buffer iter.
        let state = State::AcquireBuffer(first, 0, State::length);

        Self {
            iter,
            len,
            channel_id,
            data,
            current_buffer,
            state,
        }
    }
}

impl<I, F, D, E> Future for AsSlicedPacketFuture<I, F, D>
where
    I: Iterator<Item = F>,
    F: Future<Output = D>,
    D: crate::TryExtend<u8> + Future<Output = Result<(), E>>,
{
    type Output = Result<(), E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // This is safe as types F and C are only moved before
        // they're polled and after they're polled to completion
        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match this.state {
                State::AcquireBuffer(ref mut future, index, to_next) => match Pin::new(future).poll(cx) {
                    Poll::Ready(current) => {
                        this.current_buffer = Some(current);

                        this.state = to_next(this.current_buffer.as_mut().unwrap(), index)
                    }
                    Poll::Pending => break Poll::Pending,
                },
                State::FinishCurrent(current, index, to_next) => {
                    match Pin::new(unsafe { current.as_mut().unwrap() }).poll(cx)? {
                        Poll::Ready(_) => {
                            let future = self.iter.next().expect(BUFFERS_EXPECT);

                            this.state = State::AcquireBuffer(future, index, to_next);
                        }
                        Poll::Pending => break Poll::Pending,
                    }
                }
                State::Length(current, index) => {
                    if index < this.len.len() {
                        match unsafe { current.as_mut().unwrap() }.try_extend_one(this.len[index]) {
                            Ok(_) => this.state.next_index(),
                            Err(_) => this.state = State::FinishCurrent(current, index, State::length),
                        }
                    } else {
                        this.state = State::ChannelId(current, 0)
                    }
                }
                State::ChannelId(current, index) => {
                    if index < this.channel_id.len() {
                        match unsafe { current.as_mut().unwrap() }.try_extend_one(this.channel_id[index]) {
                            Ok(_) => this.state.next_index(),
                            Err(_) => this.state = State::FinishCurrent(current, index, State::channel_id),
                        }
                    } else {
                        this.state = State::Data(current, 0)
                    }
                }
                State::Data(current, index) => {
                    if index < this.data.len() {
                        match unsafe { current.as_mut().unwrap() }.try_extend_one(this.data[index]) {
                            Ok(_) => this.state.next_index(),
                            Err(_) => this.state = State::FinishCurrent(current, index, State::data),
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

enum State<C, F> {
    AcquireBuffer(F, usize, fn(*mut C, usize) -> Self),
    FinishCurrent(*mut C, usize, fn(*mut C, usize) -> Self),
    Length(*mut C, usize),
    ChannelId(*mut C, usize),
    Data(*mut C, usize),
    Complete,
}

impl<C, F> State<C, F> {
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
    fn length(current: *mut C, index: usize) -> Self {
        Self::Length(current, index)
    }

    /// Create a ChannelId enum
    fn channel_id(current: *mut C, index: usize) -> Self {
        Self::ChannelId(current, index)
    }

    /// Create a Data enum
    fn data(current: *mut C, index: usize) -> Self {
        Self::Data(current, index)
    }
}
