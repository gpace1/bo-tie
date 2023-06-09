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

use crate::channels::ChannelIdentifier;
use crate::pdu::{FragmentIterator, FragmentL2capPdu, FragmentationError, PacketsError, RecombineL2capPdu};
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
    T: core::ops::Deref<Target = [u8]>,
{
    type Pdu<'a> = CreditBasedFrame<SduSubSlice<'a, T>> where Self: 'a;

    type PacketsIterator<'a> = PacketsIterator<'a, T> where Self: 'a;

    fn as_packets(&self) -> Result<Self::PacketsIterator<'_>, PacketsError> {
        if self.mps == 0 {
            Err(PacketsError::PayloadZeroSized)
        } else if self.sdu.len() > CreditBasedSdu::<T>::MAX_SDU_SIZE {
            Err(PacketsError::SduTooLarge)
        } else {
            Ok(PacketsIterator { sdu: self, offset: 0 })
        }
    }
}

pub struct PacketsIterator<'a, T> {
    sdu: &'a CreditBasedSdu<T>,
    offset: usize,
}

impl<'a, T> Iterator for PacketsIterator<'a, T>
where
    T: core::ops::Deref<Target = [u8]>,
{
    type Item = CreditBasedFrame<SduSubSlice<'a, T>>;

    fn next(&mut self) -> Option<Self::Item> {
        use core::cmp::min;

        if self.offset < self.sdu.sdu.len() {
            if self.offset == 0 {
                // the first packet contains the SDU length
                let sdu_len = (self.sdu.sdu.len() as u16).into();

                let end = min(
                    self.offset + <usize>::from(self.sdu.mps).checked_sub(2).unwrap_or_default(),
                    self.offset + self.sdu.sdu.len(),
                );

                let payload = SduSubSlice {
                    t: &self.sdu.sdu,
                    start: self.offset,
                    end,
                };

                self.offset += end;

                Some(CreditBasedFrame {
                    channel_id: self.sdu.channel_id,
                    sdu_len,
                    payload,
                })
            } else {
                // subsequent packets do not contain the SDU length
                let sdu_len = None;

                let end = min(
                    self.offset + <usize>::from(self.sdu.mps),
                    self.offset + self.sdu.sdu.len(),
                );

                let payload = SduSubSlice {
                    t: &self.sdu.sdu,
                    start: self.offset,
                    end,
                };

                self.offset += end;

                Some(CreditBasedFrame {
                    channel_id: self.sdu.channel_id,
                    sdu_len,
                    payload,
                })
            }
        } else {
            None
        }
    }
}

pub struct SduSubSlice<'a, T> {
    t: &'a T,
    start: usize,
    end: usize,
}

impl<T> core::ops::Deref for SduSubSlice<'_, T>
where
    T: core::ops::Deref<Target = [u8]>,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.t[self.start..self.end]
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
        L: crate::private::Link,
    {
        L::channel_from_raw(<u16>::from_le_bytes([
            *bytes.get(2).ok_or(CreditBasedFrameError::RawDataTooSmall)?,
            *bytes.get(3).ok_or(CreditBasedFrameError::RawDataTooSmall)?,
        ]))
        .ok_or(CreditBasedFrameError::InvalidChannelId)
    }

    fn try_first_from<L>(bytes: &'a [u8]) -> Result<Self, CreditBasedFrameError<core::convert::Infallible>>
    where
        L: crate::private::Link,
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

    /// Try to create a 'subsequent'
    pub fn try_subsequent_from<L>(bytes: &'a [u8]) -> Result<Self, CreditBasedFrameError<core::convert::Infallible>>
    where
        L: crate::private::Link,
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

    /// Try to create the first credit based frame from a LE channel.
    ///
    /// The first credit based for of a SDU contains the *SDU Length* field, where as all subsequent
    /// k-frames do not contain this field. This tries to create a `CreditBasedFrame` for a LE-U
    /// channel.
    pub fn try_le_first_from(bytes: &'a [u8]) -> Result<Self, CreditBasedFrameError<core::convert::Infallible>> {
        Self::try_first_from::<crate::LeU>(bytes)
    }

    /// Try to create the first credit based frame from an ACL channel
    ///
    /// The first credit based for of a SDU contains the *SDU Length* field, where as all subsequent
    /// k-frames do not contain this field. This tries to create a `CreditBasedFrame` for an ACL-U
    /// channel.
    pub fn try_acl_first_from(bytes: &'a [u8]) -> Result<Self, CreditBasedFrameError<core::convert::Infallible>> {
        Self::try_first_from::<crate::AclU>(bytes)
    }

    /// Try to create a subsequent credit based frame from a LE channel.
    ///
    /// Credit based frames Frames after the first frame for a SDU do not contain the *SDU Length*
    /// field. This tries to create a subsequent `CreditBasedFrame` for a LE-U channel.
    pub fn try_le_subsequent_from(bytes: &'a [u8]) -> Result<Self, CreditBasedFrameError<core::convert::Infallible>> {
        Self::try_first_from::<crate::LeU>(bytes)
    }

    /// Try to create a subsequent credit based frame from an ACL channel
    ///
    /// Credit based frames Frames after the first frame for a SDU do not contain the *SDU Length*
    /// field. This tries to create a subsequent `CreditBasedFrame` for a ACL-U channel.
    pub fn try_acl_subsequent_from(bytes: &'a [u8]) -> Result<Self, CreditBasedFrameError<core::convert::Infallible>> {
        Self::try_first_from::<crate::AclU>(bytes)
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
    P: core::ops::Deref<Target = [u8]>,
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
    type RecombineMeta = RecombineMeta;

    fn recombine<T>(
        channel_id: ChannelIdentifier,
        mut bytes: T,
        meta: &mut Self::RecombineMeta,
    ) -> Result<Self, Self::RecombineError>
    where
        Self: Sized,
        T: Iterator<Item = u8> + ExactSizeIterator,
    {
        // check that the length is not larger than the mps
        if bytes.len() > meta.mps.into() {
            return Err(RecombineError::PayloadLargerThanMps);
        }

        // the first frame has the SDU length field
        let sdu_len = if meta.first {
            meta.first = false;

            <u16>::from_le_bytes([
                bytes.next().ok_or(RecombineError::MissingSduLength)?,
                bytes.next().ok_or(RecombineError::MissingSduLength)?,
            ])
            .into()
        } else {
            None
        };

        let mut payload = P::default();

        payload.try_extend(bytes).map_err(|_| RecombineError::BufferTooSmall)?;

        Ok(Self {
            channel_id,
            sdu_len,
            payload,
        })
    }
}

pub struct FragmentationIterator<T> {
    k_frame: CreditBasedFrame<T>,
    fragmentation_size: usize,
    offset: usize,
}

impl<'a, T> FragmentationIterator<T> {
    fn new(k_frame: CreditBasedFrame<T>, fragmentation_size: usize) -> Self {
        let offset = 0;

        Self {
            k_frame,
            fragmentation_size,
            offset,
        }
    }
}

impl<T> FragmentIterator for FragmentationIterator<T>
where
    T: core::ops::Deref<Target = [u8]>,
{
    type Item<'a> = DataIter<'a, T> where Self: 'a;

    fn next(&mut self) -> Option<Self::Item<'_>> {
        (self.offset < self.k_frame.get_payload().len() + CreditBasedFrame::<T>::HEADER_SIZE).then(|| {
            let data_iter = DataIter {
                k_frame: &self.k_frame,
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
    k_frame: &'a CreditBasedFrame<T>,
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

        match (self.offset + current_byte, self.k_frame.sdu_len) {
            (0, _) => Some((self.k_frame.get_payload().len() as u16).to_le_bytes()[0]),
            (1, _) => Some((self.k_frame.get_payload().len() as u16).to_le_bytes()[1]),
            (2, _) => Some(self.k_frame.get_channel_id().to_val().to_le_bytes()[0]),
            (3, _) => Some(self.k_frame.get_channel_id().to_val().to_le_bytes()[1]),
            (4, Some(sdu_len)) => Some(sdu_len.to_le_bytes()[0]),
            (5, Some(sdu_len)) => Some(sdu_len.to_le_bytes()[1]),
            (i, Some(_)) => self.k_frame.payload.get(i - 6).copied(),
            (i, None) => self.k_frame.payload.get(i - 4).copied(),
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
                f.write_str("buffer too small to contain credit based frame information payload")
            }
            RecombineError::PayloadLargerThanMps => {
                f.write_str("received credit based frame larger than the agreed upon MPS")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecombineError {}

pub struct RecombineMeta {
    first: bool,
    mps: u16,
}
