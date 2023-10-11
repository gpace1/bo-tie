//! L2CAP Basic Frame Implementation

use crate::channel::id::ChannelIdentifier;
use crate::pdu::{FragmentL2capPdu, FragmentationError, RecombineL2capPdu};
use bo_tie_core::buffer::TryExtend;

/// Basic information frame
///
/// The simplest PDU of L2CAP is the basic information frame (B-frame). A B-frame consists of just
/// the length of the payload, the channel identifier, and the payload. The maximum size of a
/// payload is 65535 bytes and the minimum is 0 but channel identifiers will usually define a
/// minimum size and two connected devices will generally agree on a different maximum transfer
/// size.
#[derive(Debug, Clone)]
pub struct BasicFrame<T> {
    channel_id: ChannelIdentifier,
    payload: T,
}

impl<T> BasicFrame<T> {
    /// The number of bytes within a Basic Info frame header.
    pub const HEADER_SIZE: usize = 4;

    /// Create a new `BasicInfoFrame`
    pub fn new(payload: T, channel_id: ChannelIdentifier) -> Self {
        BasicFrame { channel_id, payload }
    }

    /// Get the channel identifier for this `BasicInfoFrame`
    pub fn get_channel_id(&self) -> ChannelIdentifier {
        self.channel_id
    }

    /// Get the payload within this `BasicInfoFrame`
    pub fn get_payload(&self) -> &T {
        &self.payload
    }
}

impl<T> FragmentL2capPdu for BasicFrame<T>
where
    T: IntoIterator<Item = u8>,
    T::IntoIter: ExactSizeIterator,
{
    type FragmentIterator = FragmentationIterator<T::IntoIter>;

    fn into_fragments(self, fragmentation_size: usize) -> Result<Self::FragmentIterator, FragmentationError> {
        let payload = self.payload.into_iter();

        if fragmentation_size == 0 {
            Err(FragmentationError::FragmentationSizeIsZero)
        } else if payload.len() <= <u16>::MAX.into() {
            Ok(FragmentationIterator::new(self.channel_id, payload, fragmentation_size))
        } else {
            Err(FragmentationError::DataForTypeIsTooLarge)
        }
    }
}

impl<T> RecombineL2capPdu for BasicFrame<T>
where
    T: TryExtend<u8> + Default,
{
    type RecombineError = RecombineError;
    type RecombineMeta = ();
    type PayloadRecombiner<'a> = BasicFrameRecombiner<T>;

    fn recombine(payload_length: u16, channel_id: ChannelIdentifier, _: &mut ()) -> Self::PayloadRecombiner<'_> {
        BasicFrameRecombiner::new(payload_length.into(), channel_id)
    }
}

impl core::fmt::Display for BasicFrame<alloc::vec::Vec<u8>> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "Basic Info Frame {{ channel id: {}, payload: {:x?} }}",
            self.channel_id, self.payload
        )
    }
}

impl<T> From<BasicFrame<T>> for alloc::vec::Vec<u8>
where
    T: core::ops::Deref<Target = [u8]>,
{
    fn from(frame: BasicFrame<T>) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::with_capacity(BasicFrame::<T>::HEADER_SIZE + frame.payload.len());

        v.extend_from_slice(&(frame.payload.len() as u16).to_le_bytes());

        v.extend_from_slice(&frame.channel_id.to_val().to_le_bytes());

        v.extend_from_slice(&frame.payload);

        v
    }
}

/// Basic Frame Errors
///
/// These are errors that can occur when trying to translate raw data into a L2CAP basic information
/// frame.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum BasicFrameError<E> {
    /// Raw data is too small for an ACL frame
    RawDataTooSmall,
    /// Specified payload length didn't match the actual payload length
    PayloadLengthIncorrect,
    /// Invalid Channel Id
    InvalidChannelId,
    /// Expected A start Fragment
    ExpectedStartFragment,
    /// The connection has closed
    ConnectionClosed,
    /// Buffer error
    TryExtendError(E),
    Other(&'static str),
}

impl<E: core::fmt::Display> core::fmt::Display for BasicFrameError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            BasicFrameError::RawDataTooSmall => write!(f, "Raw data is too small for an ACL frame"),
            BasicFrameError::PayloadLengthIncorrect => write!(
                f,
                "Specified payload length didn't \
                match the actual payload length"
            ),
            BasicFrameError::InvalidChannelId => write!(f, "Invalid Channel Id"),
            BasicFrameError::ExpectedStartFragment => write!(
                f,
                "Expected start fragment, received a \
                continuation fragment"
            ),
            BasicFrameError::ConnectionClosed => write!(
                f,
                "The connection has closed between the host and the \
                remote device"
            ),
            BasicFrameError::TryExtendError(reason) => write!(f, "buffer failure, {}", reason),
            BasicFrameError::Other(reason) => f.write_str(reason),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error> std::error::Error for BasicFrameError<E> {}

impl<E> BasicFrameError<E> {
    #[doc(hidden)]
    pub fn to_infallible(self) -> BasicFrameError<core::convert::Infallible> {
        match self {
            BasicFrameError::RawDataTooSmall => BasicFrameError::RawDataTooSmall,
            BasicFrameError::PayloadLengthIncorrect => BasicFrameError::PayloadLengthIncorrect,
            BasicFrameError::InvalidChannelId => BasicFrameError::InvalidChannelId,
            BasicFrameError::ExpectedStartFragment => BasicFrameError::ExpectedStartFragment,
            BasicFrameError::ConnectionClosed => BasicFrameError::ConnectionClosed,
            BasicFrameError::TryExtendError(_) => panic!("unexpected try extend error"),
            BasicFrameError::Other(o) => BasicFrameError::Other(o),
        }
    }
}

impl BasicFrameError<core::convert::Infallible> {
    #[doc(hidden)]
    pub fn from_infallible<E>(self) -> BasicFrameError<E> {
        match self {
            BasicFrameError::RawDataTooSmall => BasicFrameError::RawDataTooSmall,
            BasicFrameError::PayloadLengthIncorrect => BasicFrameError::PayloadLengthIncorrect,
            BasicFrameError::InvalidChannelId => BasicFrameError::InvalidChannelId,
            BasicFrameError::ExpectedStartFragment => BasicFrameError::ExpectedStartFragment,
            BasicFrameError::ConnectionClosed => BasicFrameError::ConnectionClosed,
            BasicFrameError::Other(o) => BasicFrameError::Other(o),
            _ => unreachable!(),
        }
    }
}

pub struct FragmentationIterator<T: Iterator> {
    channel_id: ChannelIdentifier,
    payload: core::iter::Peekable<core::iter::Fuse<T>>,
    len: usize,
    header_count: usize,
    fragmentation_size: usize,
}

impl<T: Iterator + ExactSizeIterator> FragmentationIterator<T> {
    fn new(channel_id: ChannelIdentifier, payload: T, fragmentation_size: usize) -> Self {
        let payload = payload.fuse().peekable();

        let len = payload.len();

        let header_count = 0;

        Self {
            channel_id,
            payload,
            len,
            header_count,
            fragmentation_size,
        }
    }
}

impl<T> crate::pdu::FragmentIterator for FragmentationIterator<T>
where
    T: Iterator<Item = u8>,
{
    type Item<'a> = DataIter<'a, core::iter::Peekable<core::iter::Fuse<T>>> where Self: 'a;

    fn next(&mut self) -> Option<Self::Item<'_>> {
        self.payload.peek().is_some().then(|| {
            let data_iter = DataIter {
                channel_id: self.channel_id,
                payload: &mut self.payload,
                len: self.len,
                header_count: &mut self.header_count,
                fragmentation_size: self.fragmentation_size,
                byte: 0,
            };

            data_iter
        })
    }
}

pub struct DataIter<'a, T> {
    channel_id: ChannelIdentifier,
    payload: &'a mut T,
    len: usize,
    header_count: &'a mut usize,
    fragmentation_size: usize,
    byte: usize,
}

impl<T> Iterator for DataIter<'_, T>
where
    T: Iterator<Item = u8>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.byte == self.fragmentation_size {
            return None;
        }

        self.byte += 1;
        *self.header_count = self.header_count.checked_add(1).unwrap_or(<usize>::MAX);

        match self.header_count {
            1 => Some((self.len as u16).to_le_bytes()[0]),
            2 => Some((self.len as u16).to_le_bytes()[1]),
            3 => Some(self.channel_id.to_val().to_le_bytes()[0]),
            4 => Some(self.channel_id.to_val().to_le_bytes()[1]),
            _ => self.payload.next(),
        }
    }
}

/// Recombiner of fragments into a Basic Frame PDU
pub struct BasicFrameRecombiner<T> {
    payload_len: usize,
    channel_id: ChannelIdentifier,
    byte_count: usize,
    payload: Option<T>,
}

impl<T> BasicFrameRecombiner<T> {
    /// Create a new `BasicFrameRecombiner` with a default payload
    fn new(payload_len: usize, channel_id: ChannelIdentifier) -> Self
    where
        T: Default,
    {
        let byte_count = 0;
        let payload = T::default().into();

        BasicFrameRecombiner {
            payload_len,
            channel_id,
            byte_count,
            payload,
        }
    }
}

impl<P> crate::pdu::RecombinePayloadIncrementally for BasicFrameRecombiner<P>
where
    P: TryExtend<u8>,
{
    type Pdu = BasicFrame<P>;
    type RecombineError = RecombineError;

    fn add<T>(&mut self, payload_fragment: T) -> Result<Option<Self::Pdu>, Self::RecombineError>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        let payload_iter = payload_fragment.into_iter();

        if self.byte_count + payload_iter.len() <= self.payload_len {
            self.byte_count += payload_iter.len();

            self.payload
                .as_mut()
                .unwrap()
                .try_extend(payload_iter)
                .map_err(|_| RecombineError::BufferTooSmall)?;

            if self.payload_len == self.byte_count {
                let b_frame = BasicFrame::new(self.payload.take().unwrap(), self.channel_id);

                Ok(Some(b_frame))
            } else {
                Ok(None)
            }
        } else {
            Err(RecombineError::PayloadLargerThanStatedLength)
        }
    }
}

/// Basic Frame Recombination Error
///
/// This error is returned by the implementation of the method
/// [`RecombinePayloadIncrementally::add`] for [`BasicFrameRecombiner`]
///
/// [`RecombinePayloadIncrementally::add`]: crate::pdu::RecombinePayloadIncrementally::add
#[derive(Debug)]
pub enum RecombineError {
    BufferTooSmall,
    PayloadLargerThanStatedLength,
}

impl core::fmt::Display for RecombineError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            RecombineError::BufferTooSmall => f.write_str("buffer is too small to fit PDU"),
            RecombineError::PayloadLargerThanStatedLength => {
                f.write_str("payload is larger than the payload length field")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecombineError {}
