//! L2CAP Protocol Data Unit (PDU) implementation
//!
//! These are types that are used for the implementation of L2CAP data transfer. Besides the direct
//! implementation of the PDU structures listed under the *Data Packet Format* section of the
//! *Logical Link Control and Adaption Protocol* part of the *Host* volume in the Bluetooth
//! Specification, data flow control is also implemented.

pub mod basic_frame;
mod control_frame;
pub mod credit_frame;
mod send_future;

use crate::channels::ChannelIdentifier;
pub use basic_frame::BasicFrame;
use bo_tie_core::buffer::TryExtend;
pub(crate) use control_frame::ControlFrame;
pub use control_frame::ControlFrameError;
pub use send_future::BufferedFragmentsFuture;

/// L2CAP PDU Fragmentation
///
/// The purpose of this trait is to facilitate fragmentation for protocols **below** L2CAP.
pub trait FragmentL2capPdu {
    type DataIter<'a>: Iterator<Item = u8>
    where
        Self: 'a;

    type FragmentIterator<'a>: Iterator<Item = Self::DataIter<'a>>
    where
        Self: 'a;

    /// Create fragments of this L2CAP PDU
    ///
    /// This is used by Bluetooth protocol below the L2CAP layer to fragment this L2CAP PDU to an
    /// appropriate size for it.
    ///
    /// The return is an iterator over fragments of this PDU. Input `fragmentation_size` determines
    /// the maximum size of a fragment output when iterating the returned `FragmentIterator`.
    ///
    /// # Errors
    /// 1) The input `fragmentation_size` is zero.
    /// 2) The payload within is L2CAP PDU is larger than the maximum transfer size for the L2CAP
    ///    PDU. This error occurs as the length of the payload may not be validated until this
    ///    method is called.
    fn as_fragments(&self, fragmentation_size: usize) -> Result<Self::FragmentIterator<'_>, FragmentationError>;
}

/// L2CAP PDU Recombination
///
/// The purpose of this trait is to facilitate the recombination of fragments received from
/// protocols **below** L2CAP.
pub trait RecombineL2capPdu {
    /// Information required in order to recombine fragments into a PDU
    type RecombineMeta;

    /// Error when trying to recombine fragments.
    type RecombineError;

    /// Recombine fragments into this PDU
    ///
    /// This is used to recombine L2CAP PDU fragments of this L2CAP PDU.
    ///
    /// The input `payload` is the part of the L2CAP data packet that is *not* part of the L2CAP
    /// basic header. `payload` is not the same as the *information payload* except for
    /// [`BasicFrame`].
    ///
    /// The length of `payload` is equivalent to the length within the *PDU length* field.
    ///
    /// # Meta
    /// This extra information may be required when the PDU format is not consistent. An example of
    /// this is a [`CreditBasedFrame`] where only the first frame of a SDU contains the *SDU length*
    /// field. The meta is *created* through its default implementation, but it may have been
    /// modified at some point before this method is called.
    ///
    /// # Errors
    /// Errors should be returned if the payload contains incorrect or missing fields or the L2CAP
    /// data is larger than can be handled by the implementation (such as the *information payload*
    /// is larger than can be buffered).
    ///
    /// # Note
    /// The L2CAP basic header consists of the L2CAP *PDU length* and the *channel ID* fields. These
    /// make up the first four bytes of every L2CAP data type.
    fn recombine<T>(
        channel_id: ChannelIdentifier,
        payload: T,
        meta: &mut Self::RecombineMeta,
    ) -> Result<Self, Self::RecombineError>
    where
        Self: Sized,
        T: Iterator<Item = u8> + ExactSizeIterator;
}

/// Extension traits of [`FragmentL2capPdu`]
pub trait FragmentL2capPduExt: FragmentL2capPdu {
    /// Fragment the L2CAP PDU(s) with buffers.
    ///
    /// This is used to fragment a single L2CAP PDU (not the SDU) into a size that can be handled by
    /// a lower layer, which is usually Controller. The information payload can be up to 65535
    /// octets (a.k.a 2^16 - 1) which is generally much greater than even the total buffer space
    /// within the Controller.
    ///
    /// `into_fragments` returns a future for converting this into fragments the size of which
    /// are specified by the input `fragmentation_size`. Fragments are placed into self-resolving
    /// buffers acquired from the input `buffers_iterator`. Each buffer is filled with the data of
    /// this `BasicInfoFrame` and then self-resolved before the next buffer is acquired.
    ///
    /// # Buffering
    /// As fragments cannot be stored within the implementation of `L2capPdu`, they must be placed
    /// within a buffer provided by the callee. When a new fragment is ready to be sent, it is
    /// placed within an buffer acquired by the called of `info_fragments`. These buffers may come
    /// from a finite pool of buffers and the method is implemented to await until one is available.
    ///
    /// Buffer awaiting is done via the `buffers_iterator`. `buffers_iterator` must be an endlessly
    /// repeating iterator over futures used for acquiring a buffer. The purpose of the future is
    /// for awaiting when there are no buffers currently available. This can occur on systems that
    /// have finite number of buffers available to be used by multiple connections.
    ///
    /// The buffer type (which is the generic `C`) is self completing. Once a buffer is acquired, it
    /// is filled with bytes until either it returns an error when trying to extend (via its
    /// implementation of [`TryExtend`]) or the number of bytes within it is equal to
    /// `fragmentation_size`. The buffer is then self-resolved by converted it into a future with is
    /// awaited until it is polled to completion. Within `bo-tie` this future is used for sending
    /// the data to the connected device, but this is outside the scope of `into_fragments` so there
    /// is no requirement that this is what the future must do.
    fn send_as_fragments<I, F, C, E>(
        &self,
        fragmentation_size: usize,
        buffers_iterator: I,
    ) -> Result<
        BufferedFragmentsFuture<Self::FragmentIterator<'_>, Self::DataIter<'_>, I::IntoIter, F, C::IntoFuture>,
        FragmentationError,
    >
    where
        I: IntoIterator<Item = F>,
        F: core::future::Future<Output = C>,
        C: TryExtend<u8> + core::future::IntoFuture<Output = Result<(), E>>,
    {
        BufferedFragmentsFuture::new(fragmentation_size, self, buffers_iterator)
    }
}

impl<T> FragmentL2capPduExt for T where T: FragmentL2capPdu {}

/// L2CAP Service Data Unit (SDU) Fragmentation
///
/// This is used to convert L2CAP types that contain a SDU into the respective L2CAP data PDUs. A
/// SDU is a fancy acronym for data that comes from a protocol at a higher layer than L2CAP. Unlike
/// [`FragmentL2capPdu`], this is used to fragment higher layered data into L2CAP PDUs.
pub trait FragmentL2capSdu {
    type Pdu<'a>: FragmentL2capPdu
    where
        Self: 'a;

    type PacketsIterator<'a>: Iterator<Item = Self::Pdu<'a>>
    where
        Self: 'a;

    /// Convert the SDU type into L2CAP PDUs
    ///
    /// # Error
    /// The SDU) cannot be larger than the maximum transfer size for the L2CAP SDU transfer type. If
    /// this error occurs the SDU must be fragmented by a higher layer protocol into smaller SDUs.
    fn as_packets(&self) -> Result<Self::PacketsIterator<'_>, PacketsError>;
}

/// Error for converting a frame type into one or more packets.
pub enum IntoPacketError<E> {
    TryFromU16Error,
    TryExtendError(E),
}

impl<E: core::fmt::Debug> core::fmt::Debug for IntoPacketError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            IntoPacketError::TryFromU16Error => f.write_str(
                "data cannot fit within a L2CAP basic info \
                frame, it must be fragmented by a higher protocol",
            ),
            IntoPacketError::TryExtendError(e) => core::fmt::Debug::fmt(e, f),
        }
    }
}

impl<E: core::fmt::Display> core::fmt::Display for IntoPacketError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            IntoPacketError::TryFromU16Error => f.write_str(
                "data cannot fit within a L2CAP basic info \
                frame, it must be fragmented by a higher protocol",
            ),
            IntoPacketError::TryExtendError(e) => core::fmt::Display::fmt(e, f),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error> std::error::Error for IntoPacketError<E> {}

impl<E> From<E> for IntoPacketError<E> {
    fn from(e: E) -> Self {
        IntoPacketError::TryExtendError(e)
    }
}

/// Error returned by [`as_fragments`] of `FragmentL2capPdu`
#[derive(Debug, Copy, Clone)]
pub enum FragmentationError {
    FragmentationSizeIsZero,
    DataForTypeIsTooLarge,
}

impl core::fmt::Display for FragmentationError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            FragmentationError::FragmentationSizeIsZero => f.write_str("fragmentation size is zero"),
            FragmentationError::DataForTypeIsTooLarge => f.write_str("payload or SDU is too large"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FragmentationError {}

/// Error returned by [`as_packets`] of `FragmentL2capSdu`
#[derive(Debug, Copy, Clone)]
pub enum PacketsError {
    SduTooLarge,
    PayloadZeroSized,
}

impl core::fmt::Display for PacketsError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            PacketsError::SduTooLarge => f.write_str("SDU too large to be fragmented by L2CAP"),
            PacketsError::PayloadZeroSized => f.write_str("PDU payload sized to zero"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PacketsError {}
