//! L2CAP Protocol Data Unit (PDU) implementation
//!
//! These are types that are used for the implementation of L2CAP data transfer. Besides the direct
//! implementation of the PDU structures listed under the *Data Packet Format* section of the
//! *Logical Link Control and Adaption Protocol* part of the *Host* volume in the Bluetooth
//! Specification, data flow control is also implemented.

pub mod basic_frame;
pub(crate) mod control_frame;
pub mod credit_frame;

use crate::channel::id::ChannelIdentifier;
pub use basic_frame::BasicFrame;
use bo_tie_core::buffer::TryExtend;
pub use control_frame::{ControlFrame, ControlFrameError};
pub use credit_frame::CreditBasedSdu;

/// A L2CAP PDU Fragment
///
/// Fragmentation is required as the physical link may use a smaller maximum transmission size than
/// the L2CAP layer. A single L2CAP PDU will be converted into one or more `L2capFragment`s, with
/// the first fragment marked as the 'starting fragment'. L2CAP fragments are either created from or
/// recombined into L2CAP PDUs by the logical link implementations within this library.
///
/// # Fragmentation Requirements
/// 1) A `L2capFragment` only contains data from a single L2CAP PDU.
/// 2) Whenever a fragment is sent to or received from the physical layer, all fragments are
///    expected to be in the data order of the L2CAP PDU they recombine into.
///
/// ## Sent Fragments
/// Just before a L2CAP PDU is sent to the physical layer, it is broken into one or more fragments.
/// Each fragment is sent one at a time to the physical layer, and the physical layer is allowed to
/// block whenever any fragment is sent.
///
/// ## Received Fragments
/// As fragments are received from the physical link, they are recombined into L2CAP PDUs by the
/// logical link implementations within this library. The PDU length information within the basic
/// header (of every L2CAP PDU) is used to determine how many `L2capFragment`s need to be received
/// before the L2CAP PDU is complete.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct L2capFragment<T> {
    pub(crate) start_fragment: bool,
    pub(crate) data: T,
}

impl<T> L2capFragment<T> {
    /// Crate a new 'ACLDataFragment'
    pub fn new(start_fragment: bool, data: T) -> Self {
        Self { start_fragment, data }
    }

    pub fn is_start_fragment(&self) -> bool {
        self.start_fragment
    }

    pub fn get_data(&self) -> &T {
        &self.data
    }

    pub fn get_mut_data(&mut self) -> &mut T {
        &mut self.data
    }

    pub fn into_inner(self) -> T {
        self.data
    }
}

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
/// This is used for creating a recombiner that will convert [`L2capFragment`] data into the
/// implementor of this trait.
///
/// ```
/// # use bo_tie_core::buffer::stack::LinearBuffer;
/// # use bo_tie_l2cap::cid::{ChannelIdentifier, LeCid};
/// # use bo_tie_l2cap::pdu::{BasicFrame, L2capFragment, RecombineL2capPdu, RecombinePayloadIncrementally};
/// # use bo_tie_l2cap::PhysicalLink;
/// # async fn doc_test<F>(next_fragment: F) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     F: Fn() -> core::future::Ready<L2capFragment<Vec<u8>>>,
/// # {
/// # let mut fragment = L2capFragment::new(true, Vec::new());
/// # fn process_basic_header(fragment: &mut L2capFragment<Vec<u8>>) -> (u16, ChannelIdentifier) {
/// #     (0, ChannelIdentifier::Le(LeCid::AttributeProtocol))
/// # }
/// let recombine_buffer = &mut Vec::new();
///
/// let recombine_meta = ();
///
/// // For simplicity, pretend that `process_basic_header` never fails; it
/// // is just a stub method to show the prerequisite for calling recombine.  
/// let (payload_length, channel_identifier) = process_basic_header(&mut fragment);
///
/// let mut recombiner = BasicFrame::recombine(
///     payload_length,
///     channel_identifier,
///     recombine_buffer,
///     recombine_meta
/// );
///
/// loop {
///     if let Some(pdu) = recombiner.add(fragment.into_inner())? {
///         break pdu
///     }
///
///     fragment = next_fragment().await;
/// }
/// # ; Ok(())
/// # }
/// ```
///
/// ## Prerequisite
///
/// [`recombine`] requires the payload length and channel identifier in order to create the
/// recombiner. These are the two fields of the L2CAP basic header which means that the basic header
/// must be received (and processed) before a recombiner can be created.
///
/// [`recombine`](RecombineL2capPdu::recombine)
pub trait RecombineL2capPdu {
    /// Information required in order to recombine fragments into a PDU
    type RecombineMeta<'a>
    where
        Self: 'a;

    /// Error when trying to recombine fragments.
    type RecombineError;

    /// Buffer type used for recombination
    type RecombineBuffer<'a>
    where
        Self: 'a;

    /// The type for recombining fragments into a PDU
    type PayloadRecombiner<'a>: RecombinePayloadIncrementally<Pdu = Self, RecombineError = Self::RecombineError>
    where
        Self: 'a;

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
    /// This extra information that is required for every PDU except for the Basic Frame. This
    /// information is used to fill out extra fields within the
    ///
    /// # Errors
    /// Errors should be returned if the payload contains incorrect or missing fields or the L2CAP
    /// data is larger than can be handled by the implementation (such as the *information payload*
    /// is larger than can be buffered).
    ///
    /// # Note
    /// The L2CAP basic header consists of the L2CAP *PDU length* and the *channel ID* fields. These
    /// make up the first four bytes of every L2CAP data type.
    fn recombine<'a>(
        payload_length: u16,
        channel_id: ChannelIdentifier,
        buffer: Self::RecombineBuffer<'a>,
        meta: Self::RecombineMeta<'a>,
    ) -> Self::PayloadRecombiner<'a>;
}

/// L2CAP PDU Recombination into a referenced Buffer
///
/// The only difference from [`RecombineL2capPdu`] is that the `PayloadRecombiner` type does not
/// store a reference to the buffer or meta information. This makes this more tricky to use but its
/// main advantage is that it can be stored along with the buffer.
///
/// ## Prerequisite
///
/// The prerequisites for `RecombineL2capPdu` also apply for `RecombineL2capPduIntoRef`
///
/// # Note
///
/// This is not implemented for a ControlFrame because the implementation of `RecombineL2capPdu`
/// does not require
pub trait RecombineL2capPduIntoRef<B, M> {
    /// Error when trying to recombine fragments.
    type RecombineError;

    /// The type for recombining fragments into a PDU
    type PayloadRecombiner: RecombinePayloadIncrementallyIntoRef<
        B,
        M,
        Pdu = Self,
        RecombineError = Self::RecombineError,
    >;

    /// Recombine fragments into this PDU
    ///
    /// See the equivalent [`RecombineL2capPdu::recombine`].
    fn recombine_into_ref(payload_length: u16, channel_id: ChannelIdentifier) -> Self::PayloadRecombiner;
}

/// A trait for recombining L2CAP fragments
///
/// This is used to incrementally add [`L2capFragment`] data to an internal buffer until a complete
/// PDU is stored. The only requirement is that the fragments must be added in order. Everything
/// else is handled by the implementation. Once the PDU is formed it is then taken from the buffer
/// and returned
///
/// [`L2capFragments`]: L2capFragment
pub trait RecombinePayloadIncrementally {
    type Pdu: Sized;

    type RecombineError;

    /// Add more payload bytes to the PDU
    ///
    /// Once the complete PDU is formed it is output by this method. This method shall not be called
    /// again after a PDU is returned.
    fn add<T>(&mut self, payload_fragment: T) -> Result<Option<Self::Pdu>, Self::RecombineError>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator;
}

/// A trait for recombining L2CAP fragments into a referenced buffer
///
/// This is equivalent to [`RecombinePayloadIncrementally`] except the implementation does not own
/// the buffer nor meta, and instead they are an input to the `add` method. This puts the onus on
/// the user to ensure the buffer and meta have not changed between calls to `add`.
///
/// See `RecombineL2capPduIntoRef` for example details.
pub trait RecombinePayloadIncrementallyIntoRef<B, M> {
    type Pdu: Sized;

    type RecombineError;

    fn add_into_ref<T>(
        &mut self,
        payload_fragment: T,
        buffer: &mut B,
        recombine_meta: &mut M,
    ) -> Result<Option<Self::Pdu>, Self::RecombineError>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
        B: TryExtend<u8> + Default;
}

/// L2CAP Service Data Unit (SDU) Fragmentation
///
/// This is used to convert L2CAP types that contain a SDU into the respective L2CAP data PDUs. A
/// SDU is a fancy acronym for data that comes from a protocol at a higher layer than L2CAP. Unlike
/// [`FragmentL2capPdu`], this is used to fragment higher layered data into L2CAP PDUs.
pub trait FragmentL2capSdu {
    type PacketsIterator: SduPacketsIterator;

    /// Convert the SDU type into L2CAP PDUs
    ///
    /// # Error
    /// The SDU) cannot be larger than the maximum transfer size for the L2CAP SDU transfer type. If
    /// this error occurs the SDU must be fragmented by a higher layer protocol into smaller SDUs.
    fn into_packets(self) -> Result<Self::PacketsIterator, PacketsError>;
}

/// Iterator over packets of a SDU
///
/// See type [`PacketsIterator`] of `FragmentL2capSdu`
///
/// [`PacketsIterator`]: FragmentL2capSdu::PacketsIterator
pub trait SduPacketsIterator {
    type Frame<'a>: FragmentL2capPdu
    where
        Self: 'a;

    fn next(&mut self) -> Option<Self::Frame<'_>>;
}

/// Error returned by [`into_fragments`] of `FragmentL2capPdu`
///
/// [`into_fragments`]: FragmentL2capPdu::into_fragments
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

/// Error returned by [`into_packets`] of `FragmentL2capSdu`
///
/// [`into_packets`]: FragmentL2capSdu::into_packets
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
