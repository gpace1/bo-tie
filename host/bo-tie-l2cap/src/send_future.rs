use crate::BasicInfoFrame;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

const BUFFERS_EXPECT: &'static str = "input 'buffers' returned None";

pub struct AsSlicedPacketFuture<I, D, F, C, S> {
    max_size: usize,
    byte_count: usize,
    iter: I,
    len: [u8; 2],
    channel_id: [u8; 2],
    data: D,
    state: State<C, F, S>,
}

impl<I, D, F, C, S> AsSlicedPacketFuture<I, D, F, C, S> {
    pub fn new<T>(max_size: usize, frame: BasicInfoFrame<D>, into_iterator: T) -> Self
    where
        T: IntoIterator<IntoIter = I>,
        I: Iterator<Item = F>,
        F: Future<Output = C>,
        D: core::ops::Deref<Target = [u8]>,
    {
        assert_ne!(max_size, 0, "the maximum transfer unit cannot be zero");

        let byte_count = 0;

        let len: Result<u16, _> = frame.payload.len().try_into();

        let len = len.map(|val| val.to_le_bytes());

        let channel_id = frame.channel_id.to_cid().to_le_bytes();

        let data = frame.payload;

        let mut iter = into_iterator.into_iter();

        let first = iter.next().unwrap();

        let (len, state) = match len {
            Ok(val) => {
                // The first state is to acquire the first buffer from the buffer iter.

                (val, State::AcquireBuffer(first, 0, State::length))
            }
            Err(_) => {
                // length is larger than the maximum of a u16
                ([0; 2], State::DataTooLarge)
            }
        };

        Self {
            max_size,
            byte_count,
            iter,
            len,
            channel_id,
            data,
            state,
        }
    }
}

macro_rules! greedy_extend_current {
    ($this:expr, $current:expr, $index:expr, $item_size:expr, $item:expr) => {
        if $item_size - $index < $this.max_size - $this.byte_count {
            $current
                .try_extend($item.get($index..).unwrap().iter().copied())
                .unwrap();

            $this.byte_count += $item_size - $index;

            // true returned to indicate that the current item is finished
            true
        } else {
            let end = $this.max_size - $this.byte_count + $index;

            $current
                .try_extend($item.get($index..end).unwrap().iter().copied())
                .unwrap();

            $index += $this.max_size - $this.byte_count;

            // false returned to indicate that the item was not completed
            false
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
    type Output = Result<(), Error<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // No generics except for F and C are moved. Using `get_unchecked_mut`
        // is safe because both types F and C are moved only before they have
        // been polled and are dropped once they have polled to completion.

        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match &mut this.state {
                State::DataTooLarge => return Poll::Ready(Err(Error::DataTooLarge)),
                State::AcquireBuffer(future, index, to_next) => {
                    this.byte_count = 0;

                    match unsafe { Pin::new_unchecked(future) }.poll(cx) {
                        Poll::Ready(current) => this.state = to_next(current, *index),
                        Poll::Pending => break Poll::Pending,
                    }
                }
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
                    if greedy_extend_current!(this, current, *index, this.len.len(), this.len) {
                        match core::mem::replace(&mut this.state, State::TEMPORARY) {
                            State::Length(current, _) => this.state = State::ChannelId(current, 0),
                            _ => unreachable!(),
                        }
                    } else {
                        let (current, index) = match core::mem::replace(&mut this.state, State::TEMPORARY) {
                            State::Length(current, index) => (current, index),
                            _ => unreachable!(),
                        };

                        this.state = State::FinishCurrent(current.into_future(), index, State::length)
                    }
                }
                State::ChannelId(current, index) => {
                    if greedy_extend_current!(this, current, *index, this.channel_id.len(), this.channel_id) {
                        match core::mem::replace(&mut this.state, State::TEMPORARY) {
                            State::ChannelId(current, _) => this.state = State::Data(current, 0),
                            _ => unreachable!(),
                        }
                    } else {
                        let (current, index) = match core::mem::replace(&mut this.state, State::TEMPORARY) {
                            State::ChannelId(current, index) => (current, index),
                            _ => unreachable!(),
                        };

                        this.state = State::FinishCurrent(current.into_future(), index, State::channel_id)
                    }
                }
                State::Data(current, index) => {
                    if greedy_extend_current!(this, current, *index, this.data.len(), this.data) {
                        let (current, _) = match core::mem::replace(&mut this.state, State::TEMPORARY) {
                            State::Data(current, index) => (current, index),
                            _ => unreachable!(),
                        };

                        this.state = State::Complete(current.into_future())
                    } else {
                        let (current, index) = match core::mem::replace(&mut this.state, State::TEMPORARY) {
                            State::Data(current, index) => (current, index),
                            _ => unreachable!(),
                        };

                        this.state = State::FinishCurrent(current.into_future(), index, State::data)
                    }
                }
                State::Complete(s) => {
                    break unsafe { Pin::new_unchecked(s) }
                        .poll(cx)
                        .map(|ready| ready.map_err(|e| Error::User(e)))
                }
            }
        }
    }
}

/// States used to describe the current operation when polling a `AsSlicedPacketFuture`
///
/// # States
/// These states are used for describing the current operation being done when polling. They are
/// needed as polling to completion need a state machine
///
/// ### DataTooLarge
/// This meta-state is used for returning an error whenever the data to be transferred is larger
/// than the maximum transfer size of the connection channel.
///
/// ### AcquireBuffer
/// The process of acquiring a buffer is done via a future, so this state is used to mark the
/// operation while the future for acquiring the buffer is polled to completion. The first tuple
/// field is the future polled to acquire the buffer, while the second and third field are for
/// moving onto the next state. When calling the third field, the second field is used as the second
/// input. The third field is called after the first filed is polled to completion.
///
/// ### FinishCurrent
/// `FinishCurrent` is used for completing the process of sending data to the connected device. The
/// first field is the future used for sending the data, the next two fields are fed to
/// the state `AcquireBuffer`. `AcquireBuffer` always comes after `FinishCurrent`.
///
/// ### Length
/// This is used for processing the length field of a L2CAP PDU.  
///
/// ### ChannelId
/// This is for processing the channel identifier field of a L2CAP PDU.
///
/// ### Data
/// This is for processing the data (a.k.a. the payload) of a L2CAP PDU.
///
/// ### Complete
/// The last buffer is polled to completion
enum State<C, F, S> {
    DataTooLarge,
    AcquireBuffer(F, usize, fn(C, usize) -> Self),
    FinishCurrent(S, usize, fn(C, usize) -> Self),
    Length(C, usize),
    ChannelId(C, usize),
    Data(C, usize),
    Complete(S),
}

impl<C, F, S> State<C, F, S> {
    /// A temporary state
    ///
    /// This "temporary" state is not used when evaluating the operation to be performed. It's used
    /// as a between state for replacing one state with another when fields of the replaced state
    /// are also moved to the new state.
    const TEMPORARY: Self = State::DataTooLarge;

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

/// Send future error
#[derive(PartialEq)]
pub enum Error<E> {
    DataTooLarge,
    User(E),
}

impl<E> From<E> for Error<E> {
    fn from(e: E) -> Self {
        Error::User(e)
    }
}

impl<E: core::fmt::Debug> core::fmt::Debug for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::DataTooLarge => f.write_str(
                "data cannot fit within a L2CAP basic info \
                frame, it must be fragmented by a higher protocol",
            ),
            Error::User(e) => core::fmt::Debug::fmt(e, f),
        }
    }
}

impl<E: core::fmt::Display> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::DataTooLarge => f.write_str(
                "data cannot fit within a L2CAP basic info \
                frame, it must be fragmented by a higher protocol",
            ),
            Error::User(e) => core::fmt::Display::fmt(e, f),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error> std::error::Error for Error<E> {}
