//! L2CAP Credit Based Frame Implementation
//!
//! Credit-Based frames are used as a L2CAP layer flow control for units of service data (SDU).
//! Service data (data from a higher layered protocol) is fragmented into one or more chunks sent
//! over multiple L2CAP credit based frame PDUs.
//!
//! Before credit based frames can be sent (or received) two devices must form a *L2CAP connection*
//! using the L2CAP signaling commands for the appropriate credit based connection (LE or Enhanced).
//! The parameters determine the maximum size of each credit based L2CAP PDU, the dynamically
//! allocated channel for the connection, the number of credits, and the MTU of the SDU.

use crate::channel::id::ChannelIdentifier;
use crate::pdu::{
    FragmentIterator, FragmentL2capPdu, FragmentationError, PacketsError, RecombineL2capPdu, SduPacketsIterator,
};
use bo_tie_core::buffer::TryExtend;

/// Credit-Based SDU
///
/// This is a wrapper around the Service Data Unit (SDU) that is transferred over one or more credit
/// based frames.
///
/// # Setup
/// Before service data can be sent through a credit based flow control (for both LE Credit Based
/// flow control and enhanced credit based flow control) a L2CAP connection (different from the
/// connection created by the Link Manager) must be established via the appropriate L2CAP signaling
/// commands. These signalling commands are out of the co
pub struct CreditBasedSdu<T> {
    channel_id: ChannelIdentifier,
    sdu: T,
    mps: u16,
}

impl<T> CreditBasedSdu<T> {
    /// The maximum size of the SDU in octets.
    pub const MAX_SDU_SIZE: usize = 65533;

    /// Create a new `CreditBasedFrames`
    ///
    /// # Note
    /// Method `new` does not validate that the `data` is not larger than the *maximum PDU payload
    /// size* of the credit based connection.
    pub fn new(sdu: T, channel_id: ChannelIdentifier, mps: u16) -> Self {
        CreditBasedSdu { channel_id, sdu, mps }
    }

    /// Get the channel identifier
    pub fn get_channel_id(&self) -> ChannelIdentifier {
        self.channel_id
    }

    /// Get the SDU within this `CreditBasedFrames`
    pub fn get_data(&self) -> &T {
        &self.sdu
    }

    /// Get the Maximum PDU size
    pub fn get_mps(&self) -> u16 {
        self.mps
    }
}

impl<T> crate::pdu::FragmentL2capSdu for CreditBasedSdu<T>
where
    T: IntoIterator<Item = u8>,
    T::IntoIter: ExactSizeIterator,
{
    type PacketsIterator = PacketsIterator<T::IntoIter>;

    fn into_packets(self) -> Result<Self::PacketsIterator, PacketsError> {
        let sdu = self.sdu.into_iter();

        if self.mps == 0 {
            Err(PacketsError::PayloadZeroSized)
        } else if sdu.len() > CreditBasedSdu::<T>::MAX_SDU_SIZE {
            Err(PacketsError::SduTooLarge)
        } else {
            Ok(PacketsIterator::new(self.channel_id, self.mps.into(), sdu))
        }
    }
}

pub struct PacketsIterator<T: Iterator> {
    channel_id: ChannelIdentifier,
    sdu: core::iter::Peekable<core::iter::Fuse<T>>,
    mps: usize,
    first: bool,
}

impl<T: Iterator> PacketsIterator<T> {
    fn new(channel_id: ChannelIdentifier, mps: usize, sdu: T) -> Self {
        let first = true;

        let sdu = sdu.fuse().peekable();

        Self {
            channel_id,
            sdu,
            mps,
            first,
        }
    }

    /// Get the number of bytes left of the SDU
    ///
    /// The return is the number of bytes yet to be iterated over of the SDU.
    ///
    /// # Note
    /// This value is also relative to the bytes that were iterated  
    pub fn get_remaining_count(&self) -> usize
    where
        T: ExactSizeIterator,
    {
        self.sdu.len()
    }

    /// Returns true if there is no more packets output by this iterator
    pub fn is_complete(&self) -> bool
    where
        T: ExactSizeIterator,
    {
        self.sdu.len() == 0
    }
}

impl<T> SduPacketsIterator for PacketsIterator<T>
where
    T: Iterator<Item = u8> + ExactSizeIterator,
{
    type Frame<'a> = CreditBasedFrame<SduSubIter<'a, T>> where Self: 'a;

    fn next(&mut self) -> Option<Self::Frame<'_>> {
        self.sdu.peek().is_some().then(|| {
            if self.first {
                self.first = false;

                let max_amount = self.mps.checked_sub(2).unwrap_or_default();

                let amount = core::cmp::min(self.sdu.len(), max_amount);

                let sdu_size = self.sdu.len() as u16;

                let channel_id = self.channel_id;

                let sub_iter = SduSubIter {
                    packets_iterator: self,
                    amount,
                };

                CreditBasedFrame::new_first(sdu_size, channel_id, sub_iter)
            } else {
                let amount = core::cmp::min(self.sdu.len(), self.mps);

                let channel_id = self.channel_id;

                let sub_iter = SduSubIter {
                    packets_iterator: self,
                    amount,
                };

                CreditBasedFrame::new_subsequent(channel_id, sub_iter)
            }
        })
    }
}

pub struct SduSubIter<'a, T: Iterator> {
    packets_iterator: &'a mut PacketsIterator<T>,
    amount: usize,
}

impl<T: Iterator<Item = u8>> Iterator for SduSubIter<'_, T> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.amount != 0 {
            self.amount -= 1;

            self.packets_iterator.sdu.next()
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.packets_iterator.sdu.size_hint() {
            (_, None) => (0, None),
            (low, Some(up)) => {
                let size = core::cmp::min(up, self.amount);

                if low == up {
                    // exact sized
                    (size, Some(size))
                } else {
                    (0, Some(size))
                }
            }
        }
    }
}

impl<T> ExactSizeIterator for SduSubIter<'_, T>
where
    T: Iterator<Item = u8> + ExactSizeIterator,
{
    fn len(&self) -> usize {
        core::cmp::min(self.packets_iterator.sdu.len(), self.amount)
    }
}

/// Basic Frame Errors
///
/// These are errors that can occur when trying to translate raw data into a L2CAP basic information
/// frame.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum CreditBasedFrameError<E> {
    /// Raw data is too small for an ACL frame
    RawDataTooSmall,
    /// Specified payload length field didn't match the payload length within a single frame
    PayloadLengthIncorrect,
    /// The service data length field did not match the total length of service data
    ServiceDataLengthIncorrect,
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

impl<E: core::fmt::Display> core::fmt::Display for CreditBasedFrameError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            CreditBasedFrameError::RawDataTooSmall => write!(f, "raw data is too small for an ACL frame"),
            CreditBasedFrameError::PayloadLengthIncorrect => {
                f.write_str("payload length field didn't match the actual payload length")
            }
            CreditBasedFrameError::ServiceDataLengthIncorrect => {
                f.write_str("service data length field didn't match the actual service data length")
            }
            CreditBasedFrameError::InvalidChannelId => write!(f, "Invalid Channel Id"),
            CreditBasedFrameError::ExpectedStartFragment => {
                f.write_str("Expected start fragment, received a continuation fragment")
            }
            CreditBasedFrameError::ConnectionClosed => {
                f.write_str("The connection has closed between the host and the  remote device")
            }
            CreditBasedFrameError::TryExtendError(reason) => write!(f, "buffer failure, {}", reason),
            CreditBasedFrameError::Other(reason) => f.write_str(reason),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error> std::error::Error for CreditBasedFrameError<E> {}

/// L2CAP Credit Based PDU
///
/// This is the PDU that is used for sending a Credit Based Frame.
pub struct CreditBasedFrame<P> {
    channel_id: ChannelIdentifier,
    sdu_len: Option<u16>,
    payload: P,
}

impl<P> CreditBasedFrame<P> {
    /// The number of bytes within a credit based frame header.
    ///
    /// # Note
    /// This is only true for the *first* header
    pub const HEADER_SIZE: usize = 6;

    /// The number of bytes within subsequent credit based packets
    pub const SUBSEQUENT_HEADER_SIZE: usize = 4;

    /// Get the channel identifier
    pub fn get_channel_id(&self) -> ChannelIdentifier {
        self.channel_id
    }

    /// Get the payload
    pub fn get_payload(&self) -> &P {
        &self.payload
    }

    /// Convert this `CreditBasedFrame` into its payload.
    pub fn into_payload(self) -> P {
        self.payload
    }

    /// Get the SDU length
    ///
    /// Only the first L2CAP PDU carries the SDU length. If this happens to be the first PDU then
    /// the SDU length is returned.
    pub fn get_sdu_length(&self) -> Option<u16> {
        self.sdu_len
    }

    /// Create a new `CreditBasedFrame` for the first frame
    pub(crate) fn new_first(sdu_size: u16, channel_id: ChannelIdentifier, payload: P) -> Self {
        Self {
            channel_id,
            sdu_len: Some(sdu_size),
            payload,
        }
    }

    /// Create a new `CreditBasedFrame` for a subsequent frame
    pub(crate) fn new_subsequent(channel_id: ChannelIdentifier, payload: P) -> Self {
        Self {
            channel_id,
            sdu_len: None,
            payload,
        }
    }

    /// (Todo remove method) mapping a credit based frame
    ///
    /// This maps the payload type to a `Vec::IntoIter<Item = u8>`
    ///
    /// This is used to mitigate a rust compile error (which is probably a rust bug) in the code.
    pub(crate) fn map_to_vec_iter(self) -> CreditBasedFrame<alloc::vec::IntoIter<u8>>
    where
        P: IntoIterator<Item = u8>,
    {
        CreditBasedFrame {
            channel_id: self.channel_id,
            sdu_len: self.sdu_len,
            payload: self.payload.into_iter().collect::<alloc::vec::Vec<u8>>().into_iter(),
        }
    }
}

impl<'a> CreditBasedFrame<&'a [u8]> {
    fn try_len_from(bytes: &'a [u8]) -> Result<usize, CreditBasedFrameError<core::convert::Infallible>> {
        Ok(<u16>::from_le_bytes([
            *bytes.get(0).ok_or(CreditBasedFrameError::RawDataTooSmall)?,
            *bytes.get(1).ok_or(CreditBasedFrameError::RawDataTooSmall)?,
        ])
        .into())
    }

    fn try_channel_id_from<L>(
        bytes: &'a [u8],
    ) -> Result<ChannelIdentifier, CreditBasedFrameError<core::convert::Infallible>>
    where
        L: crate::link_flavor::LinkFlavor,
    {
        L::try_channel_from_raw(<u16>::from_le_bytes([
            *bytes.get(2).ok_or(CreditBasedFrameError::RawDataTooSmall)?,
            *bytes.get(3).ok_or(CreditBasedFrameError::RawDataTooSmall)?,
        ]))
        .ok_or(CreditBasedFrameError::InvalidChannelId)
    }

    fn try_first_from<L>(bytes: &'a [u8]) -> Result<Self, CreditBasedFrameError<core::convert::Infallible>>
    where
        L: crate::link_flavor::LinkFlavor,
    {
        let len: usize = Self::try_len_from(bytes)?;

        let channel_id = Self::try_channel_id_from::<L>(bytes)?;

        let sdu_len = <u16>::from_le_bytes([
            *bytes.get(4).ok_or(CreditBasedFrameError::RawDataTooSmall)?,
            *bytes.get(5).ok_or(CreditBasedFrameError::RawDataTooSmall)?,
        ])
        .into();

        let payload = &bytes[5..];

        if payload.len() == len {
            let frame = CreditBasedFrame {
                channel_id,
                sdu_len,
                payload,
            };

            Ok(frame)
        } else {
            Err(CreditBasedFrameError::PayloadLengthIncorrect)
        }
    }

    /// Try to create the first credit based frame from a LE channel.
    ///
    /// The first credit based for of a SDU contains the *SDU Length* field, where as all subsequent
    /// k-frames do not contain this field. This tries to create a `CreditBasedFrame` for a LE-U
    /// channel.
    pub fn try_le_first_from(bytes: &'a [u8]) -> Result<Self, CreditBasedFrameError<core::convert::Infallible>> {
        Self::try_first_from::<crate::LeULink>(bytes)
    }

    /// Try to create the first credit based frame from an ACL channel
    ///
    /// The first credit based for of a SDU contains the *SDU Length* field, where as all subsequent
    /// k-frames do not contain this field. This tries to create a `CreditBasedFrame` for an ACL-U
    /// channel.
    pub fn try_acl_first_from(bytes: &'a [u8]) -> Result<Self, CreditBasedFrameError<core::convert::Infallible>> {
        Self::try_first_from::<crate::AclULink>(bytes)
    }

    /// Try to create a subsequent credit based frame from a LE channel.
    ///
    /// Credit based frames Frames after the first frame for a SDU do not contain the *SDU Length*
    /// field. This tries to create a subsequent `CreditBasedFrame` for a LE-U channel.
    pub fn try_le_subsequent_from(bytes: &'a [u8]) -> Result<Self, CreditBasedFrameError<core::convert::Infallible>> {
        Self::try_first_from::<crate::LeULink>(bytes)
    }

    /// Try to create a subsequent credit based frame from an ACL channel
    ///
    /// Credit based frames Frames after the first frame for a SDU do not contain the *SDU Length*
    /// field. This tries to create a subsequent `CreditBasedFrame` for a ACL-U channel.
    pub fn try_acl_subsequent_from(bytes: &'a [u8]) -> Result<Self, CreditBasedFrameError<core::convert::Infallible>> {
        Self::try_first_from::<crate::AclULink>(bytes)
    }

    /// Try to create a 'subsequent'
    pub fn try_subsequent_from<L>(bytes: &'a [u8]) -> Result<Self, CreditBasedFrameError<core::convert::Infallible>>
    where
        L: crate::link_flavor::LinkFlavor,
    {
        let len: usize = Self::try_len_from(bytes)?;

        let channel_id = Self::try_channel_id_from::<L>(bytes)?;

        let sdu_len = None;

        let payload = &bytes[5..];

        if payload.len() == len {
            let frame = CreditBasedFrame {
                channel_id,
                sdu_len,
                payload,
            };

            Ok(frame)
        } else {
            Err(CreditBasedFrameError::PayloadLengthIncorrect)
        }
    }

    /// Convert this into a `CreditBasedFrame` containing a buffered payload
    pub fn into_buffered<B>(self) -> Result<CreditBasedFrame<B>, CreditBasedFrameError<B::Error>>
    where
        B: TryExtend<u8> + Default,
    {
        self.into_buffered_with(B::default())
    }

    /// Convert this into a `CreditBasedFrame` containing the payload in `buffer`
    ///
    /// The payload will be put within buffer and returned as part of the returned
    /// `CreditBasedFrame`.
    pub fn into_buffered_with<B>(self, mut buffer: B) -> Result<CreditBasedFrame<B>, CreditBasedFrameError<B::Error>>
    where
        B: TryExtend<u8>,
    {
        buffer
            .try_extend(self.payload.into_iter().copied())
            .map_err(|e| CreditBasedFrameError::TryExtendError(e))?;

        Ok(CreditBasedFrame {
            channel_id: self.channel_id,
            sdu_len: self.sdu_len,
            payload: buffer,
        })
    }
}

impl<P> FragmentL2capPdu for CreditBasedFrame<P>
where
    P: Iterator<Item = u8> + ExactSizeIterator,
{
    type FragmentIterator = FragmentationIterator<P>;

    fn into_fragments(self, fragmentation_size: usize) -> Result<Self::FragmentIterator, FragmentationError> {
        let len = self.payload.len() + if self.sdu_len.is_some() { 2 } else { 0 };

        if len <= <u16>::MAX.into() {
            Ok(FragmentationIterator::new(self, fragmentation_size))
        } else {
            Err(FragmentationError::FragmentationSizeIsZero)
        }
    }
}

impl<P> RecombineL2capPdu for CreditBasedFrame<P>
where
    P: Default + TryExtend<u8>,
{
    type RecombineError = RecombineError;
    type RecombineMeta<'a> = &'a mut RecombineMeta;
    type RecombineBuffer = P;
    type PayloadRecombiner<'a> = CreditBasedFrameRecombiner<'a, P> where P: 'a;

    fn recombine<'a>(
        payload_length: u16,
        channel_id: ChannelIdentifier,
        buffer: &'a mut Self::RecombineBuffer,
        meta: Self::RecombineMeta<'a>,
    ) -> Self::PayloadRecombiner<'a> {
        CreditBasedFrameRecombiner::new(buffer, payload_length.into(), channel_id, meta)
    }
}

pub struct FragmentationIterator<T: Iterator> {
    channel_id: ChannelIdentifier,
    sdu_len: Option<u16>,
    payload: core::iter::Peekable<core::iter::Fuse<T>>,
    fragmentation_size: usize,
    header_byte_state: usize,
}

impl<'a, T: Iterator> FragmentationIterator<T> {
    fn new<I>(k_frame: CreditBasedFrame<I>, fragmentation_size: usize) -> Self
    where
        I: IntoIterator<IntoIter = T>,
    {
        let channel_id = k_frame.channel_id;

        let sdu_len = k_frame.sdu_len;

        let payload = k_frame.payload.into_iter().fuse().peekable();

        // see the implementation of Iterator on DataIter
        // for why these values are picked as the initial
        // header_byte_state.
        let header_byte_state = if k_frame.sdu_len.is_none() { 6 } else { 0 };

        Self {
            channel_id,
            sdu_len,
            payload,
            fragmentation_size,
            header_byte_state,
        }
    }
}

impl<T> FragmentIterator for FragmentationIterator<T>
where
    T: Iterator<Item = u8> + ExactSizeIterator,
{
    type Item<'a> = DataIter<'a, T> where Self: 'a;

    fn next(&mut self) -> Option<Self::Item<'_>> {
        self.payload.peek().is_some().then(|| DataIter {
            fragmentation_iter: self,
            byte: 0,
        })
    }
}

pub struct DataIter<'a, T: Iterator> {
    fragmentation_iter: &'a mut FragmentationIterator<T>,
    byte: usize,
}

impl<T> Iterator for DataIter<'_, T>
where
    T: Iterator<Item = u8> + ExactSizeIterator,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.byte >= self.fragmentation_iter.fragmentation_size {
            return None;
        }

        self.byte += 1;

        self.fragmentation_iter.header_byte_state = self
            .fragmentation_iter
            .header_byte_state
            .checked_add(1)
            .unwrap_or(<usize>::MAX);

        // The `header_byte_state` is used to determine what
        // credit based frame is sent. Depending on the state
        // this iterator either outputs a k-frame with a sdu
        // length or a k-frame without one.
        //
        // 1..=6  => PDU header with sdu length
        // 7..=10 => PDU header without sdu length
        // 10..   => PDU payload bytes
        match self.fragmentation_iter.header_byte_state {
            1 => Some(((self.fragmentation_iter.payload.len() + 2) as u16).to_le_bytes()[0]),
            2 => Some(((self.fragmentation_iter.payload.len() + 2) as u16).to_le_bytes()[1]),
            3 | 9 => Some(self.fragmentation_iter.channel_id.to_val().to_le_bytes()[0]),
            4 | 10 => Some(self.fragmentation_iter.channel_id.to_val().to_le_bytes()[1]),
            5 => Some(self.fragmentation_iter.sdu_len.unwrap().to_le_bytes()[0]),
            6 => {
                self.fragmentation_iter.header_byte_state += 4;

                Some(self.fragmentation_iter.sdu_len.unwrap().to_le_bytes()[1])
            }
            7 => Some((self.fragmentation_iter.payload.len() as u16).to_le_bytes()[0]),
            8 => Some((self.fragmentation_iter.payload.len() as u16).to_le_bytes()[1]),
            _ => self.fragmentation_iter.payload.next(),
        }
    }
}

/// Credit-Based PDU recombination error
///
/// This error is returned by the implementation of the method [`FragmentL2capPdu::recombine`] for
/// `CreditBasedFrame`
///
/// # Note
/// This error can occur for the first frame if the *information payload* plus the *SDU length*
/// field (two bytes) is larger than the MPS.
///
/// [`FragmentL2capPdu::recombine`]: CreditBasedFrame::recombine
#[derive(Debug, Copy, Clone)]
pub enum RecombineError {
    MissingSduLength,
    BufferTooSmall,
    PayloadLargerThanMps,
}

impl core::fmt::Display for RecombineError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            RecombineError::MissingSduLength => f.write_str("credit based frame does not contain a SDU length field"),
            RecombineError::BufferTooSmall => {
                f.write_str("buffer too small to contain a credit based frame's information payload")
            }
            RecombineError::PayloadLargerThanMps => {
                f.write_str("received credit based frame larger than the agreed upon MPS")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecombineError {}

/// Meta information required for recombining Credit Based Frames.
pub struct RecombineMeta {
    pub first: bool,
    pub maximum_payload_size: u16,
}

/// A recombiner of fragments into a Credit Based PDU.
pub struct CreditBasedFrameRecombiner<'a, P> {
    payload_len: usize,
    channel_id: ChannelIdentifier,
    meta: &'a mut RecombineMeta,
    sdu_state: SduState,
    byte_count: usize,
    payload: &'a mut P,
}

impl<'a, P> CreditBasedFrameRecombiner<'a, P> {
    fn new(payload: &'a mut P, len: usize, channel_id: ChannelIdentifier, meta: &'a mut RecombineMeta) -> Self
    where
        P: Default,
    {
        CreditBasedFrameRecombiner {
            payload_len: len,
            channel_id,
            meta,
            sdu_state: SduState::None,
            byte_count: 0,
            payload,
        }
    }

    /// Recombine the SDU Length
    ///
    /// This is used to recombine the SDU length field (from two bytes). Once it has constructed the
    /// SDU length it will return `Some(())` (`Option` is used over `bool` as it works well with the
    /// try operator). Further calling this method will have no effect on the input `payload` and
    /// the method will always return `Some(())`.  
    fn recombine_sdu_len<T>(&mut self, payload: &mut T) -> Option<()>
    where
        T: Iterator<Item = u8>,
    {
        loop {
            match self.sdu_state {
                SduState::None => self.sdu_state = SduState::First(payload.next()?),
                SduState::First(first) => {
                    self.byte_count += 2;

                    self.sdu_state = SduState::Complete(<u16>::from_le_bytes([first, payload.next()?]))
                }
                SduState::Complete(_) => break Some(()),
            }
        }
    }

    /// Get the SDU length field
    ///
    /// `None` is returned if the SDU length was never processed or never existed.
    fn get_sdu_len(&self) -> Option<u16> {
        match self.sdu_state {
            SduState::Complete(val) => Some(val),
            _ => None,
        }
    }

    /// Update the Payload Byte Count
    ///
    /// This updates the count for the number of bytes within the PDU payload.
    fn extend_payload<T>(&mut self, payload: T) -> Result<(), RecombineError>
    where
        P: TryExtend<u8>,
        T: Iterator<Item = u8> + ExactSizeIterator,
    {
        if self.byte_count + payload.len() > self.meta.maximum_payload_size.into() {
            Err(RecombineError::PayloadLargerThanMps)
        } else {
            self.byte_count += payload.len();

            self.payload
                .try_extend(payload)
                .map_err(|_| RecombineError::BufferTooSmall)?;

            Ok(())
        }
    }

    /// Recombine the first Credit Based PDU of the SDU
    ///
    /// This will return a `CreditBasedFrame` when input `payload` contains the last byte of a
    /// Credit Based PDU.
    ///
    /// This method shall not be called again for this `CreditBasedFrameRecombiner` after a
    /// `CreditBasedFrame` is returned.
    ///
    /// # Errors
    /// * [`RecombineError::BufferTooSmall`]: Buffer `P` is too small for the PDU. The size of the
    ///   buffer should be larger than the MPS.
    /// * [`RecombineError::PayloadLargerThanMps`]: The payload ended up being larger than the
    ///   agreed MPS for the credit based channel.
    fn recombine_first<T>(&mut self, payload: T) -> Result<Option<CreditBasedFrame<P>>, RecombineError>
    where
        P: TryExtend<u8> + Default,
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        let mut payload_iter = payload.into_iter();

        if self.recombine_sdu_len(&mut payload_iter).is_some() {
            self.extend_payload(payload_iter)?;

            if self.payload_len == self.byte_count {
                let sdu_size = self.get_sdu_len().unwrap(); // unwrap will never panic

                let payload = core::mem::take(self.payload);

                let k_frame = CreditBasedFrame::new_first(sdu_size, self.channel_id, payload);

                Ok(Some(k_frame))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Recombine Subsequent Credit Based PDUs of the SDU
    ///
    /// After the first PDU, all subsequent PDUs for a SDU do not contain the *SDU length field*.
    /// This will return a `CreditBasedFrame` when input `payload` contains the last byte of a
    /// Credit Based PDU.
    ///
    /// This method shall not be called again for this `CreditBasedFrameRecombiner` after a
    /// `CreditBasedFrame` is returned.
    fn recombine_subsequent<T>(&mut self, payload: T) -> Result<Option<CreditBasedFrame<P>>, RecombineError>
    where
        P: TryExtend<u8> + Default,
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        self.extend_payload(payload.into_iter())?;

        if self.payload_len == self.byte_count {
            let payload = core::mem::take(self.payload);

            let k_frame = CreditBasedFrame::new_subsequent(self.channel_id, payload);

            Ok(Some(k_frame))
        } else {
            Ok(None)
        }
    }
}

impl<P> crate::pdu::RecombinePayloadIncrementally for CreditBasedFrameRecombiner<'_, P>
where
    P: TryExtend<u8> + Default,
{
    type Pdu = CreditBasedFrame<P>;
    type RecombineBuffer = P;
    type RecombineError = RecombineError;

    fn add<T>(&mut self, payload: T) -> Result<Option<Self::Pdu>, Self::RecombineError>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        if self.meta.first {
            self.recombine_first(payload)
        } else {
            self.recombine_subsequent(payload)
        }
    }
}

/// State for combining the SDU field
///
/// This is used by `CreditBasedFrameRecombiner` for combing non basic header bytes into the SDU
/// Length field.
enum SduState {
    None,
    First(u8),
    Complete(u16),
}
