//! L2CAP control frame implementation

use crate::channels::{AclCid, ChannelIdentifier, LeCid};
use crate::pdu::{FragmentIterator, FragmentL2capPdu, FragmentationError, RecombineL2capPdu};
use bo_tie_core::buffer::TryExtend;
use core::num::{NonZeroU16, NonZeroU8};

/// Control Frame
///
/// Control frames (C-frames) are used for sending signaling packets between two devices connected
/// via L2CAP. A `ControlFrame` can be created from one of the signaling data types within the
/// [`signals`] module.
pub(crate) struct ControlFrame<T> {
    channel_id: ChannelIdentifier,
    payload: T,
}

impl<T> ControlFrame<T> {
    /// Create a new `ControlFrame`
    ///
    /// # Panic
    /// There must be a signalling channel associated with the logical link `L`.
    pub fn new(payload: T, channel_id: ChannelIdentifier) -> Self {
        match channel_id {
            ChannelIdentifier::Acl(AclCid::SignalingChannel) | ChannelIdentifier::Le(LeCid::LeSignalingChannel) => (),
            _ => panic!("invalid signalling channel {channel_id}"),
        }

        ControlFrame { channel_id, payload }
    }

    /// Try to create a signaling packet from a slice of bytes
    ///
    /// The input `data` must be a slice of bytes containing a complete control frame.
    ///
    /// # Requirements
    /// * The length of the input `data` must be > 4
    /// * The length field in the input `data` must be less than or equal to the length of the
    ///   payload field. Any bytes beyond the payload in `data` are ignored.
    /// * The channel id field must be valid for the signaling message.
    pub fn try_from_slice<L>(data: &[u8]) -> Result<T, ControlFrameError>
    where
        L: crate::link_flavor::LinkFlavor,
        T: crate::signals::TryIntoSignal,
    {
        if data.len() >= 4 {
            let len: usize = <u16>::from_le_bytes([data[0], data[1]]).into();

            let raw_channel_id = <u16>::from_le_bytes([data[2], data[3]]);

            if T::correct_channel(raw_channel_id) {
                Err(ControlFrameError::InvalidChannelId)
            } else if len == data[4..].len() {
                T::try_from::<L>(&data[4..]).map_err(|e| ControlFrameError::SignalError(e))
            } else {
                Err(ControlFrameError::PayloadLengthIncorrect)
            }
        } else {
            Err(ControlFrameError::RawDataTooSmall)
        }
    }

    pub fn into_payload(self) -> T {
        self.payload
    }
}

impl<T> FragmentL2capPdu for ControlFrame<T>
where
    T: IntoIterator<Item = u8>,
    T::IntoIter: ExactSizeIterator,
{
    type FragmentIterator = FragmentationIterator<T::IntoIter>;

    fn into_fragments(self, fragmentation_size: usize) -> Result<Self::FragmentIterator, FragmentationError> {
        if fragmentation_size == 0 {
            Err(FragmentationError::FragmentationSizeIsZero)
        } else {
            Ok(FragmentationIterator::new(self, fragmentation_size))
        }
    }
}

impl<T> RecombineL2capPdu for ControlFrame<T>
where
    T: TryExtend<u8> + Default,
{
    type RecombineMeta = ();
    type RecombineError = RecombineError;
    type PayloadRecombiner<'a> = ControlFrameRecombiner<T>;

    fn recombine(
        payload_length: u16,
        channel_id: ChannelIdentifier,
        _: &mut Self::RecombineMeta,
    ) -> Self::PayloadRecombiner<'_> {
        ControlFrameRecombiner::new(payload_length.into(), channel_id)
    }
}

/// Control Frame Errors
///
/// These are errors that can occur when trying to translate raw data into a L2CAP signal frame.
#[derive(Debug, Clone, Copy)]
pub enum ControlFrameError {
    /// Raw data is too small for an ACL frame
    RawDataTooSmall,
    /// Specified payload length didn't match the actual payload length
    PayloadLengthIncorrect,
    InvalidChannelId,
    /// Invalid Channel Ids used for Connection
    InvalidChannelConnectionIds {
        id: NonZeroU8,
        local: Option<NonZeroU16>,
        source: Option<NonZeroU16>,
    },
    /// Signal Conversion Error
    SignalError(crate::signals::SignalError),
}

impl core::fmt::Display for ControlFrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ControlFrameError::RawDataTooSmall => write!(f, "raw data is too small for a control frame"),
            ControlFrameError::PayloadLengthIncorrect => {
                write!(f, "the payload length field didn't match the actual payload length")
            }
            ControlFrameError::InvalidChannelId => f.write_str("invalid channel id"),
            ControlFrameError::InvalidChannelConnectionIds {
                id,
                local: Some(local),
                source: Some(source),
            } => write!(
                f,
                "invalid local ({}) and/or source ({}) channel ids for signal with identifier {}",
                local, source, id
            ),
            ControlFrameError::InvalidChannelConnectionIds {
                id, local: Some(local), ..
            } => {
                write!(
                    f,
                    "invalid local ({}) channel id for signal with identifier {}",
                    local, id
                )
            }
            ControlFrameError::InvalidChannelConnectionIds {
                id,
                source: Some(source),
                ..
            } => write!(
                f,
                "invalid source ({}) channel id for signal with identifier {}",
                source, id
            ),
            ControlFrameError::InvalidChannelConnectionIds { id, .. } => {
                write!(f, "invalid channel ids for signal with identifier {}", id)
            }
            ControlFrameError::SignalError(e) => write!(f, "cannot convert control frame to signal, {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ControlFrameError {}

pub struct FragmentationIterator<T> {
    iterator: T,
    channel_id: ChannelIdentifier,
    fragmentation_size: usize,
    offset: usize,
}

impl<T> FragmentationIterator<T> {
    fn new<C>(c_frame: ControlFrame<C>, fragmentation_size: usize) -> Self
    where
        T: Iterator,
        C: IntoIterator<IntoIter = T>,
    {
        let iterator = c_frame.payload.into_iter();

        let offset = 0;

        let channel_id = c_frame.channel_id;

        Self {
            iterator,
            channel_id,
            fragmentation_size,
            offset,
        }
    }
}

impl<T> FragmentIterator for FragmentationIterator<T>
where
    T: Iterator<Item = u8> + ExactSizeIterator,
{
    type Item<'a> = DataIter<'a, T> where Self: 'a;

    fn next(&mut self) -> Option<Self::Item<'_>> {
        (self.iterator.len() != 0).then(|| {
            let data_iter = DataIter {
                channel_id: self.channel_id,
                iterator: &mut self.iterator,
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
    channel_id: ChannelIdentifier,
    iterator: &'a mut T,
    fragmentation_size: usize,
    offset: usize,
    byte: usize,
}

impl<T> Iterator for DataIter<'_, T>
where
    T: Iterator<Item = u8> + ExactSizeIterator,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.byte >= self.fragmentation_size {
            return None;
        }

        let current_byte = self.byte;

        self.byte += 1;

        match self.offset + current_byte {
            0 => Some((self.iterator.len() as u16).to_le_bytes()[0]),
            1 => Some((self.iterator.len() as u16).to_le_bytes()[1]),
            2 => Some(self.channel_id.to_val().to_le_bytes()[0]),
            3 => Some(self.channel_id.to_val().to_le_bytes()[1]),
            _ => self.iterator.next(),
        }
    }
}

pub(crate) struct ControlFrameRecombiner<T> {
    payload_len: usize,
    channel_id: ChannelIdentifier,
    byte_count: usize,
    payload: Option<T>,
}

impl<T> ControlFrameRecombiner<T> {
    /// Create a new `BasicFrameRecombiner` with a default payload
    fn new(payload_len: usize, channel_id: ChannelIdentifier) -> Self
    where
        T: Default,
    {
        let byte_count = 0;
        let payload = T::default().into();

        ControlFrameRecombiner {
            payload_len,
            channel_id,
            byte_count,
            payload,
        }
    }
}

impl<P> crate::pdu::RecombinePayloadIncrementally for ControlFrameRecombiner<P>
where
    P: TryExtend<u8>,
{
    type Pdu = ControlFrame<P>;
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
                let c_frame = ControlFrame {
                    payload: self.payload.take().unwrap(),
                    channel_id: self.channel_id,
                };

                Ok(Some(c_frame))
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
/// This error is returned by the implementation of the method [`FragmentL2capPdu::recombine`] for
/// `BasicFrame`
#[derive(Debug)]
pub enum RecombineError {
    BufferTooSmall,
    PayloadLargerThanStatedLength,
}

impl core::fmt::Display for RecombineError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            RecombineError::BufferTooSmall => {
                f.write_str("buffer too small to contain a basic frame's information payload")
            }
            RecombineError::PayloadLargerThanStatedLength => {
                f.write_str("payload is larger than payload length field in basic header")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecombineError {}
