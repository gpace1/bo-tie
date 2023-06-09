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
pub(crate) use control_frame::ControlFrame;
pub use control_frame::ControlFrameError;
pub use send_future::{SendBufferedFuture, SendFuture};

/// L2CAP PDU Fragmentation
///
/// The purpose of this trait is to facilitate fragmentation for protocols **below** L2CAP.
pub trait FragmentL2capPdu: Sized {
    /// Type for iterating over fragments
    ///
    /// This type is an iterator of iterators. Each output of this iterator is a complete fragment,
    /// in iterator form, of the whole PDU. Fragments are output in the order of least significant
    /// to most significant fragment.
    type FragmentIterator: FragmentIterator;

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
    fn into_fragments(self, fragmentation_size: usize) -> Result<Self::FragmentIterator, FragmentationError>;
}

pub trait FragmentL2capPduExt: FragmentL2capPdu {
    /// Convert this into a `Vec`
    ///
    /// This converts this PDU into the returned `Vec`. The bytes within the `Vec` will be in the
    /// correct format for transmission to a connected device.
    fn into_vec(self) -> alloc::vec::Vec<u8> {
        let mut vec = alloc::vec::Vec::new();

        let mut iter = self.into_fragments(<u16>::MAX as usize).unwrap();

        while let Some(fragment) = iter.next() {
            vec.extend(fragment)
        }

        vec
    }
}

impl<T> FragmentL2capPduExt for T where T: FragmentL2capPdu {}

/// Trait for iterating over fragments of a PDU
///
/// See type [`FragmentIterator`] of `FragmentL2capPdu`
///
/// [`FragmentIterator`]: FragmentL2capPdu::FragmentIterator
pub trait FragmentIterator {
    type Item<'a>: Iterator<Item = u8>
    where
        Self: 'a;

    fn next(&mut self) -> Option<Self::Item<'_>>;
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
