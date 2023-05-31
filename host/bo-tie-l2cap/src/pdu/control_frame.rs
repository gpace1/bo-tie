//! L2CAP control frame implementation

use crate::channels::ChannelIdentifier;
use crate::pdu::{FragmentL2capPdu, FragmentationError, RecombineL2capPdu};
use bo_tie_core::buffer::TryExtend;

/// Control Frame
///
/// Control frames (C-frames) are used for sending signaling packets between two devices connected
/// via L2CAP. A `ControlFrame` can be created from one of the signaling data types within the
/// [`signals`] module.
pub struct ControlFrame<T> {
    channel_id: ChannelIdentifier,
    payload: T,
}

impl<T> ControlFrame<T> {
    const HEADER_SIZE: usize = 4;

    /// Create a new `ControlFrame` for an ACL-U connection
    pub(crate) fn new_acl(payload: T) -> Self {
        let channel_id = ChannelIdentifier::Acl(crate::channels::AclCid::SignalingChannel);

        ControlFrame { channel_id, payload }
    }

    /// Create a new `ControlFrame` for a LE-U connection
    pub(crate) fn new_le(payload: T) -> Self {
        let channel_id = ChannelIdentifier::Le(crate::channels::LeCid::LeSignalingChannel);

        ControlFrame { channel_id, payload }
    }

    /// Create a complete L2CAP Control Frame
    ///
    /// The return is a complete L2CAP control frame packet contained within the type `P`.
    ///
    /// # Panic
    /// The buffer type `P` must be able to contain the minimum payload size within a control frame.
    /// If not then this method may panic when trying to create a packet. See the *signaling packets
    /// formats* section of the *Logical Link Control and Adaption Protocol* part of the *Host*
    /// volume for the minimum required supported buffer size of `P`.
    pub(crate) fn into_packet<P>(self) -> P
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
        P: TryExtend<u8> + Default,
    {
        let mut p = P::default();

        let payload_iter = self.payload.into_iter();

        let len = <u16>::try_from(payload_iter.len()).unwrap();

        p.try_extend(len.to_le_bytes()).expect("failed to extend buffer");

        p.try_extend(self.channel_id.to_val().to_le_bytes())
            .expect("failed to extend buffer");

        p.try_extend(payload_iter).expect("failed to extend buffer");

        p
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
    pub(crate) fn try_from_slice(data: &[u8]) -> Result<T, ControlFrameError>
    where
        T: crate::signals::TryIntoSignal,
    {
        if data.len() >= 4 {
            let len: usize = <u16>::from_le_bytes([data[0], data[1]]).into();

            let raw_channel_id = <u16>::from_le_bytes([data[2], data[3]]);

            if T::correct_channel(raw_channel_id) {
                Err(ControlFrameError::InvalidChannelId)
            } else if len == data[4..].len() {
                T::try_from(&data[4..]).map_err(|e| ControlFrameError::SignalError(e))
            } else {
                Err(ControlFrameError::PayloadLengthIncorrect)
            }
        } else {
            Err(ControlFrameError::RawDataTooSmall)
        }
    }
}

impl<T> FragmentL2capPdu for ControlFrame<T>
where
    T: core::ops::Deref<Target = [u8]>,
{
    type DataIter<'a> = DataIter<'a, T> where Self: 'a;
    type FragmentIterator<'a> = FragmentationIterator<'a, T> where Self: 'a;

    fn as_fragments(&self, fragmentation_size: usize) -> Result<Self::FragmentIterator<'_>, FragmentationError> {
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
    type RecombineError = <T as TryExtend<u8>>::Error;
    type RecombineMeta = ();

    fn recombine<I>(
        channel_id: ChannelIdentifier,
        mut bytes: I,
        _: &mut Self::RecombineMeta,
    ) -> Result<Self, Self::RecombineError>
    where
        Self: Sized,
        I: Iterator<Item = u8> + ExactSizeIterator,
    {
        let mut payload = T::default();

        payload.try_extend(bytes)?;

        Ok(ControlFrame { channel_id, payload })
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
    /// Invalid Channel Id
    InvalidChannelId,
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
            ControlFrameError::InvalidChannelId => write!(f, "invalid channel id"),
            ControlFrameError::SignalError(e) => write!(f, "cannot convert control frame to signal, {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ControlFrameError {}

pub struct FragmentationIterator<'a, T> {
    c_frame: &'a ControlFrame<T>,
    fragmentation_size: usize,
    offset: usize,
}

impl<'a, T> FragmentationIterator<'a, T> {
    fn new(c_frame: &'a ControlFrame<T>, fragmentation_size: usize) -> Self {
        let offset = 0;

        Self {
            c_frame,
            fragmentation_size,
            offset,
        }
    }
}

impl<'a, T> Iterator for FragmentationIterator<'a, T>
where
    T: core::ops::Deref<Target = [u8]>,
{
    type Item = DataIter<'a, T>;

    fn next(&mut self) -> Option<Self::Item> {
        (self.offset < self.c_frame.payload.len() + ControlFrame::<T>::HEADER_SIZE).then(|| {
            let data_iter = DataIter {
                c_frame: self.c_frame,
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
    c_frame: &'a ControlFrame<T>,
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
            0 => Some((self.c_frame.payload.len() as u16).to_le_bytes()[0]),
            1 => Some((self.c_frame.payload.len() as u16).to_le_bytes()[1]),
            2 => Some(self.c_frame.channel_id.to_val().to_le_bytes()[0]),
            3 => Some(self.c_frame.channel_id.to_val().to_le_bytes()[1]),
            i => self.c_frame.payload.get(i - ControlFrame::<T>::HEADER_SIZE).copied(),
        }
    }
}
