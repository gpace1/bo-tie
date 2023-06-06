//! L2CAP Basic Frame Implementation

use crate::channels;
use crate::channels::ChannelIdentifier;
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
    channel_id: channels::ChannelIdentifier,
    payload: T,
}

impl<T> BasicFrame<T> {
    /// The number of bytes within a Basic Info frame header.
    pub const HEADER_SIZE: usize = 4;

    /// Create a new `BasicInfoFrame`
    pub fn new(payload: T, channel_id: channels::ChannelIdentifier) -> Self {
        BasicFrame { channel_id, payload }
    }

    /// Get the channel identifier for this `BasicInfoFrame`
    pub fn get_channel_id(&self) -> channels::ChannelIdentifier {
        self.channel_id
    }

    /// Get the payload within this `BasicInfoFrame`
    pub fn get_payload(&self) -> &T {
        &self.payload
    }
}

impl<T> FragmentL2capPdu for BasicFrame<T>
where
    T: core::ops::Deref<Target = [u8]>,
{
    type FragmentIterator = FragmentationIterator<T>;

    fn into_fragments(self, fragmentation_size: usize) -> Result<Self::FragmentIterator, FragmentationError> {
        if fragmentation_size == 0 {
            Err(FragmentationError::FragmentationSizeIsZero)
        } else if self.payload.len() <= <u16>::MAX.into() {
            Ok(FragmentationIterator::new(self, fragmentation_size))
        } else {
            Err(FragmentationError::DataForTypeIsTooLarge)
        }
    }
}

impl<T> RecombineL2capPdu for BasicFrame<T>
where
    T: TryExtend<u8> + Default,
{
    type RecombineError = <T as TryExtend<u8>>::Error;
    type RecombineMeta = ();

    fn recombine<I>(channel_id: ChannelIdentifier, payload: I, _: &mut ()) -> Result<Self, Self::RecombineError>
    where
        Self: Sized,
        I: Iterator<Item = u8> + ExactSizeIterator,
    {
        let mut buffer = T::default();

        buffer.try_extend(payload)?;

        Ok(BasicFrame::new(buffer, channel_id))
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

impl<T> From<BasicFrame<T>> for Vec<u8>
where
    T: core::ops::Deref<Target = [u8]>,
{
    fn from(frame: BasicFrame<T>) -> Vec<u8> {
        let mut v = Vec::with_capacity(BasicFrame::<T>::HEADER_SIZE + frame.payload.len());

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

pub struct FragmentationIterator<T> {
    b_frame: BasicFrame<T>,
    fragmentation_size: usize,
    offset: usize,
}

impl<T> FragmentationIterator<T> {
    fn new(b_frame: BasicFrame<T>, fragmentation_size: usize) -> Self {
        let offset = 0;

        Self {
            b_frame,
            fragmentation_size,
            offset,
        }
    }
}

impl<T> crate::pdu::FragmentIterator for FragmentationIterator<T>
where
    T: core::ops::Deref<Target = [u8]>,
{
    type Item<'a> = DataIter<'a, T> where Self: 'a;

    fn next(&mut self) -> Option<Self::Item<'_>> {
        (self.offset < self.b_frame.get_payload().len() + BasicFrame::<T>::HEADER_SIZE).then(|| {
            let data_iter = DataIter {
                b_frame: &self.b_frame,
                fragmentation_size: self.fragmentation_size,
                offset: self.offset,
                byte: 0,
            };

            self.offset += self.fragmentation_size;

            data_iter
        })
    }
}

pub struct DataIter<'a, T> {
    b_frame: &'a BasicFrame<T>,
    fragmentation_size: usize,
    offset: usize,
    byte: usize,
}

impl<T> Iterator for DataIter<'_, T>
where
    T: core::ops::Deref<Target = [u8]>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.byte >= self.fragmentation_size {
            return None;
        }

        let current_byte = self.byte;

        self.byte += 1;

        match self.offset + current_byte {
            0 => Some((self.b_frame.get_payload().len() as u16).to_le_bytes()[0]),
            1 => Some((self.b_frame.get_payload().len() as u16).to_le_bytes()[1]),
            2 => Some(self.b_frame.get_channel_id().to_val().to_le_bytes()[0]),
            3 => Some(self.b_frame.get_channel_id().to_val().to_le_bytes()[1]),
            i => self.b_frame.payload.get(i - BasicFrame::<T>::HEADER_SIZE).copied(),
        }
    }
}
