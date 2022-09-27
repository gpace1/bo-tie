//! Link Link Control and Adaption Protocol
//!
//! This is an implementation of the Link Link Control and Adaption Protocol (L2CAP). L2CAP is the
//! base protocol for all other host protocols of Bluetooth. Its main purpose is for data managing
//! and control between the host, the protocols below the host layer (usually this is the HCI
//! layer), and connected devices.
//!    

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub mod send_future;
#[cfg(feature = "unstable")]
pub mod signals;

use alloc::vec::Vec;
use bo_tie_util::buffer::TryExtend;
use core::future::Future;

/// A trait containing a constant for the smallest maximum transfer unit for a logical link
pub trait MinimumMtu {
    const MIN_MTU: usize;
}

/// LE-U L2CAP logical link type
///
/// This is a marker type for a LE-U L2CAP logical link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LeU;

impl MinimumMtu for LeU {
    const MIN_MTU: usize = 23;
}

/// ACL-U L2CAP logical link type
///
/// This is a marker type for a ACL-U L2CAP logical link. This is not the MTU for ACL-U with support
/// for the Extended Flow Rate feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ACLU;

impl MinimumMtu for ACLU {
    const MIN_MTU: usize = 48;
}

/// Channel Identifier
///
/// Channel Identifiers are used by the L2CAP to associate the data with a given channel. Channels
/// are a numeric identifier for a protocol or an association of protocols that are part of L2CAP or
/// a higher layer (such as the Attribute (ATT) protocol).
///
/// # Specification Reference
/// See Bluetooth Specification V5 | Vol 3, Part A Section 2.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChannelIdentifier {
    NullIdentifier,
    /// ACL-U identifiers
    ACL(ACLUserChannelIdentifier),
    /// LE-U identifiers
    LE(LEUserChannelIdentifier),
}

impl ChannelIdentifier {
    /// Convert to the numerical value
    ///
    /// The returned value is in *native byte order*
    pub fn to_val(&self) -> u16 {
        match self {
            ChannelIdentifier::NullIdentifier => 0,
            ChannelIdentifier::ACL(ci) => ci.to_val(),
            ChannelIdentifier::LE(ci) => ci.to_val(),
        }
    }

    /// Try to convert a raw value into a LE-U channel identifier
    pub fn le_try_from_raw(val: u16) -> Result<Self, ()> {
        LEUserChannelIdentifier::try_from_raw(val).map(|c| c.into())
    }

    /// Try to convert a raw value into a ACL-U channel identifier
    pub fn acl_try_from_raw(val: u16) -> Result<Self, ()> {
        ACLUserChannelIdentifier::try_from_raw(val).map(|c| c.into())
    }
}

impl From<LEUserChannelIdentifier> for ChannelIdentifier {
    fn from(le: LEUserChannelIdentifier) -> Self {
        ChannelIdentifier::LE(le)
    }
}

impl From<ACLUserChannelIdentifier> for ChannelIdentifier {
    fn from(acl: ACLUserChannelIdentifier) -> Self {
        ChannelIdentifier::ACL(acl)
    }
}

/// Dynamically created L2CAP channel
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DynChannelId<T> {
    channel_id: u16,
    _p: core::marker::PhantomData<T>,
}

impl<T> DynChannelId<T> {
    fn new(channel_id: u16) -> Self {
        DynChannelId {
            channel_id,
            _p: core::marker::PhantomData,
        }
    }

    /// Get the value of the dynamic channel identifier
    pub fn get_val(&self) -> u16 {
        self.channel_id
    }
}

impl DynChannelId<LeU> {
    pub const LE_BOUNDS: core::ops::RangeInclusive<u16> = 0x0040..=0x007F;

    /// Create a new Dynamic Channel identifier for the LE-U CID name space
    ///
    /// This will return the enum
    /// [`DynamicallyAllocated`](../enum.LeUserChannelIdentifier.html#variant.DynamicallyAllocated)
    /// with the `channel_id` if the id is within the bounds of
    /// [`LE_LOWER`](#const.LE_LOWER) and
    /// [`LE_UPPER`](#const.LE_UPPER). If the input is not between those bounds, then an error is
    /// returned containing the infringing input value.
    pub fn new_le(channel_id: u16) -> Result<LEUserChannelIdentifier, u16> {
        if Self::LE_BOUNDS.contains(&channel_id) {
            Ok(LEUserChannelIdentifier::DynamicallyAllocated(DynChannelId::new(
                channel_id,
            )))
        } else {
            Err(channel_id)
        }
    }
}

impl DynChannelId<ACLU> {
    pub const ACL_BOUNDS: core::ops::RangeInclusive<u16> = 0x0040..=0xFFFF;

    pub fn new_acl(channel_id: u16) -> Result<ACLUserChannelIdentifier, u16> {
        if Self::ACL_BOUNDS.contains(&channel_id) {
            Ok(ACLUserChannelIdentifier::DynamicallyAllocated(DynChannelId::new(
                channel_id,
            )))
        } else {
            Err(channel_id)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ACLUserChannelIdentifier {
    SignalingChannel,
    ConnectionlessChannel,
    AmpManagerProtocol,
    BrEdrSecurityManager,
    AmpTestManager,
    DynamicallyAllocated(DynChannelId<ACLU>),
}

impl ACLUserChannelIdentifier {
    fn to_val(&self) -> u16 {
        match self {
            ACLUserChannelIdentifier::SignalingChannel => 0x1,
            ACLUserChannelIdentifier::ConnectionlessChannel => 0x2,
            ACLUserChannelIdentifier::AmpManagerProtocol => 0x3,
            ACLUserChannelIdentifier::BrEdrSecurityManager => 0x7,
            ACLUserChannelIdentifier::AmpTestManager => 0x3F,
            ACLUserChannelIdentifier::DynamicallyAllocated(ci) => ci.get_val(),
        }
    }

    fn try_from_raw(val: u16) -> Result<Self, ()> {
        match val {
            0x1 => Ok(ACLUserChannelIdentifier::SignalingChannel),
            0x2 => Ok(ACLUserChannelIdentifier::ConnectionlessChannel),
            0x3 => Ok(ACLUserChannelIdentifier::AmpManagerProtocol),
            0x7 => Ok(ACLUserChannelIdentifier::BrEdrSecurityManager),
            0x3F => Ok(ACLUserChannelIdentifier::AmpTestManager),
            val if DynChannelId::<ACLU>::ACL_BOUNDS.contains(&val) => {
                Ok(ACLUserChannelIdentifier::DynamicallyAllocated(DynChannelId::new(val)))
            }
            _ => Err(()),
        }
    }
}

/// LE User (LE-U) Channel Identifiers
///
/// These are the channel identifiers for a LE
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LEUserChannelIdentifier {
    /// Channel for the Attribute Protocol
    ///
    /// This channel is used for the attribute protocol, which also means that all GATT data will
    /// be sent through this channel.
    AttributeProtocol,
    /// Channel signaling
    ///
    /// See the Bluetooth Specification V5 | Vol 3, Part A Section 4
    LowEnergyL2CAPSignalingChannel,
    /// Security Manager Protocol
    SecurityManagerProtocol,
    /// Dynamically allocated channel identifiers
    ///
    /// These are channels that are dynamically allocated through the "Credit Based Connection
    /// Request" procedure defined in See Bluetooth Specification V5 | Vol 3, Part A Section 4.22
    ///
    /// To make a `DynamicallyAllocated` variant, use the function
    /// [`new_le`](../DynChannelId/index.html)
    /// of the struct `DynChannelId`
    DynamicallyAllocated(DynChannelId<LeU>),
}

impl LEUserChannelIdentifier {
    fn to_val(&self) -> u16 {
        match self {
            LEUserChannelIdentifier::AttributeProtocol => 0x4,
            LEUserChannelIdentifier::LowEnergyL2CAPSignalingChannel => 0x5,
            LEUserChannelIdentifier::SecurityManagerProtocol => 0x6,
            LEUserChannelIdentifier::DynamicallyAllocated(dyn_id) => dyn_id.channel_id,
        }
    }

    fn try_from_raw(val: u16) -> Result<Self, ()> {
        match val {
            0x4 => Ok(LEUserChannelIdentifier::AttributeProtocol),
            0x5 => Ok(LEUserChannelIdentifier::LowEnergyL2CAPSignalingChannel),
            0x6 => Ok(LEUserChannelIdentifier::SecurityManagerProtocol),
            _ if DynChannelId::<LeU>::LE_BOUNDS.contains(&val) => {
                Ok(LEUserChannelIdentifier::DynamicallyAllocated(DynChannelId::new(val)))
            }
            _ => Err(()),
        }
    }
}

/// Basic Frame Errors
///
/// These are errors that can occur when trying to translate raw data into a L2CAP basic information
/// frame.
#[derive(Debug, Clone, Copy)]
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

impl<E> BasicFrameError<E> {
    // A temporary method until buffering
    fn to_infallible(self) -> BasicFrameError<core::convert::Infallible> {
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

/// Basic information frame
///
/// The simplest PDU of L2CAP is the basic information frame (B-frame). A B-frame consists of just
/// the length of the payload, the channel identifier, and the payload. The maximum size of a
/// payload is 65535 bytes and the minimum is 0 but channel identifiers will usually define a
/// minimum size and two connected devices will generally agree on a different maximum transfer
/// size.
#[derive(Debug, Clone)]
pub struct BasicInfoFrame<T> {
    channel_id: ChannelIdentifier,
    payload: T,
}

impl<T> BasicInfoFrame<T> {
    /// The number of bytes within a Basic Info frame header.
    pub const HEADER_SIZE: usize = 4;

    /// Create a new `BasicInfoFrame`
    ///
    /// The channel identifier field
    pub fn new(payload: T, channel_id: ChannelIdentifier) -> Self {
        BasicInfoFrame { channel_id, payload }
    }

    /// Get the channel identifier for this `BasicInfoFrame`
    pub fn get_channel_id(&self) -> ChannelIdentifier {
        self.channel_id
    }

    /// Get the payload within this `BasicInfoFrame`
    pub fn get_payload(&self) -> &T {
        &self.payload
    }

    /// Fragment a `BasicInfoFrame` data packet using multiple buffers
    ///
    /// This fragments a `BasicInfoFrame` packet into multiple buffers output by `fut_buffers_iter`.
    /// `fut_buffers_iter` is an iterator over futures that return a buffer. There must be enough
    /// buffers to contain the entire packet, but the intention of iterating of futures is for
    /// `into_fragments` to await for more buffers to be available.
    ///
    /// The buffer type is consumed into a future after a fragment is put into it. It is up to the
    /// user of `into_fragments` to define what that future does. The purpose of the future within
    /// `bo-tie` is to send the buffer to the interface.
    pub fn into_fragments<I, F, C, E>(
        self,
        mtu: usize,
        fut_buffers_iter: I,
    ) -> send_future::AsSlicedPacketFuture<I::IntoIter, T, F, C, C::IntoFuture>
    where
        T: core::ops::Deref<Target = [u8]>,
        I: IntoIterator<Item = F>,
        F: Future<Output = C>,
        C: TryExtend<u8> + core::future::IntoFuture<Output = Result<(), E>>,
    {
        send_future::AsSlicedPacketFuture::new(mtu, self, fut_buffers_iter)
    }

    /// Create a `BasicInfoFrame` from a slice of bytes
    ///
    /// The input must be a slice of bytes containing a complete L2CAP data packet.
    ///
    /// # Requirements
    /// * The length of the input `data` must be >= 4
    /// * The length field in the input `data` must be less than or equal to the length of the
    ///   payload field. Any bytes beyond the payload in `data` are ignored.
    /// * The channel id field must be valid
    pub fn try_from_slice(data: &[u8]) -> Result<Self, BasicFrameError<<T as TryExtend<u8>>::Error>>
    where
        T: core::ops::Deref<Target = [u8]> + Extend<u8> + Default,
    {
        Self::try_from_slice_with_buffer(data, Default::default())
    }

    /// Try to create a `BasicInfoFrame` from a slice of bytes and a buffer
    ///
    /// The input `data` must be a slice of bytes containing a complete basic info frame. Input
    /// `buffer` must be able to contain the payload of `data`.
    ///
    /// # Requirements
    /// * The length of the input `data` must be >= 4
    /// * The length field in the input `data` must be less than or equal to the length of the
    ///   payload field. Any bytes beyond the payload in `data` are ignored.
    /// * The channel id field must be valid
    fn try_from_slice_with_buffer(data: &[u8], mut buffer: T) -> Result<Self, BasicFrameError<T::Error>>
    where
        T: core::ops::Deref<Target = [u8]> + TryExtend<u8>,
    {
        if data.len() >= 4 {
            let len: usize = <u16>::from_le_bytes([data[0], data[1]]).into();

            let raw_channel_id = <u16>::from_le_bytes([data[2], data[3]]);

            let payload = &data[4..];

            if len <= payload.len() {
                buffer
                    .try_extend(payload[..len].iter().cloned())
                    .map_err(|e| BasicFrameError::TryExtendError(e))
                    .and_then(|_| {
                        Ok(Self {
                            channel_id: ChannelIdentifier::LE(
                                LEUserChannelIdentifier::try_from_raw(raw_channel_id)
                                    .or(Err(BasicFrameError::InvalidChannelId))?,
                            ),
                            payload: buffer,
                        })
                    })
            } else {
                Err(BasicFrameError::PayloadLengthIncorrect)
            }
        } else {
            Err(BasicFrameError::RawDataTooSmall)
        }
    }
}

impl<T> From<BasicInfoFrame<T>> for Vec<u8>
where
    T: core::ops::Deref<Target = [u8]>,
{
    fn from(frame: BasicInfoFrame<T>) -> Vec<u8> {
        let mut v = Vec::with_capacity(BasicInfoFrame::<T>::HEADER_SIZE + frame.payload.len());

        v.extend_from_slice(&(frame.payload.len() as u16).to_le_bytes());

        v.extend_from_slice(&frame.channel_id.to_val().to_le_bytes());

        v.extend_from_slice(&frame.payload);

        v
    }
}

/// A Complete or Fragmented L2CAP PDU
///
/// A L2CAP PDU may be larger than the maximum buffer size of the controller, or maximum transfer
/// size of the connection. A `L2capFragment` is either a complete `L2CAP` PDU or a part of one.
///
/// Fragmentation and defragmentation is done by the implementation of [`ConnectionChannel`] and
/// [`ConnectionChannelExt`].
///
/// A `L2capFragment` only contains a flag to indicate if it is the start fragment and raw data
/// of the L2CAP PDU. There is no distinction for what kind of L2CAP PDU it is and no fragment order
/// information (besides the start flag). It is up to the user to ensure that fragments are
/// delivered from the starting one to the ending one in order.
pub struct L2capFragment<T> {
    start_fragment: bool,
    data: T,
}

impl<T> L2capFragment<T> {
    /// Crate a new 'ACLDataFragment'
    pub fn new(start_fragment: bool, data: T) -> Self {
        Self { start_fragment, data }
    }

    /// Get the length of the payload as specified in the ACL data
    ///
    /// This returns None if this packet does not contain the length field
    fn get_acl_len(&self) -> Option<usize>
    where
        T: core::ops::Deref<Target = [u8]>,
    {
        if self.start_fragment && self.data.len() > 2 {
            Some(<u16>::from_le_bytes([self.data[0], self.data[1]]) as usize)
        } else {
            None
        }
    }

    pub fn is_start_fragment(&self) -> bool {
        self.start_fragment
    }

    pub fn fragment_data(&self) -> &T {
        &self.data
    }
}

/// A L2CAP Logical Link Connection channel
///
/// A connection channel is used for sending and receiving L2CAP data packets between the Host and
/// the Bluetooth Controller. It is used for both ACL-U and LE-U logical links.
///
/// A `ConnectionChannel` is designed for asynchronous operations. Both sending and receiving of
/// L2CAP packets are designed around the availability of the buffers within the Bluetooth
/// controller.
///
/// # TODO
/// Until fragment serialization is added to the library, sending and receiving is done with
/// `BasicInfoFrame<Vec<u8>>`. Later on the signatures of `send` and (possibly) `receive` (more
/// likely the receive methods of [`ConnectionChannelExt`]) will have the generic `<T: xxx>` added
/// to them, where `xxx` is a trait for fragmented serialization or deserialization. This way,
/// instead of submitting a vector of bytes, a type is submitted that can be turned into fragments.
/// However this *idea* is currently tentative.
pub trait ConnectionChannel {
    /// The buffer type for sent L2CAP fragments
    ///
    /// This buffer is for containing the raw data of a L2CAP packet sent by the future returned
    /// from the method `send`.
    type SendBuffer: core::ops::Deref<Target = [u8]> + TryExtend<u8>;

    /// Sending future
    ///
    /// This is the future returned by [`send`](ConnectionChannel::send).
    type SendFut<'a>: Future<Output = Result<(), Self::SendFutErr>>
    where
        Self: 'a;

    /// Sending error
    ///
    /// This is the error type for the output of the future [`SendFut`](ConnectionChannel::SendFut)
    type SendFutErr: core::fmt::Debug;

    /// The buffer type for received L2CAP fragments
    ///
    /// This buffer is for containing the raw data of a L2CAP packet received by the future returned
    /// from the method `recv`.
    type RecvBuffer: core::ops::Deref<Target = [u8]> + TryExtend<u8>;

    /// Receiving future
    ///
    /// This is the future returned by [`receive`](ConnectionChannel::receive).
    type RecvFut<'a>: Future<
        Output = Option<
            Result<L2capFragment<Self::RecvBuffer>, BasicFrameError<<Self::RecvBuffer as TryExtend<u8>>::Error>>,
        >,
    >
    where
        Self: 'a;

    /// Send a L2CAP PDU to the Controller
    ///
    /// This attempts to sends [`BasicInfoFrame`] to the controller. The pdu must be complete as
    /// the implementor of a `ConnectionChannel` will perform any necessary flow control and
    /// fragmentation of `data` before sending raw packets to the controller.
    ///
    /// # TODO
    /// Input data is of type `BasicInfoFrame<Vec<u8>>` but it will eventually be changed to
    /// `BasicInfoFrame<Self::Buffer>` or something similar.
    fn send(&self, data: BasicInfoFrame<Vec<u8>>) -> Self::SendFut<'_>;

    /// Set the MTU for `send`
    ///
    /// This is used as the maximum transfer unit of sent L2CAP data payloads. This value must be
    /// larger than equal to the minimum for the logical link, but smaller than or equal to the
    /// maximum MTU this implementation of `ConnectionChannel` can support (you can get this value
    /// with a call to `max_mut`). An ACL-U logical link has a minimum MTU of 48 and a LE-U logical
    /// link has a minimum MTU of 23. If `mtu` is invalid it will not change the current MTU for the
    /// connection channel.
    fn set_mtu(&mut self, mtu: u16);

    /// Get the current MTU
    fn get_mtu(&self) -> usize;

    /// Get the maximum MTU this `ConnectionChannel` can support
    ///
    /// This is the maximum MTU value that higher layer protocols can use to call `set_mtu` with.
    fn max_mtu(&self) -> usize;

    /// Get the minimum MTU for the logical Link
    ///
    /// This will return 48 if this is a ACL-U logical link or 23 if this is a LE-U logical link
    fn min_mtu(&self) -> usize;

    /// Await the reception of a L2CAP PDU fragment
    ///
    /// `receive` is a method intended to be implemented and not used. Reception of fragments should
    /// be done with one of the methods within [`ConnectionChannelExt`]. `receive` returns a future
    /// to get the next L2CAP PDU *fragment* for this connection. The receive methods within
    /// `ConnectionChannelExt` return futures for a *complete* L2CAP PDU.
    ///
    /// The returned future of `receive` will either output the next fragment or await until the
    /// controller sends a fragment to this connection. If the controller has sent multiple
    /// fragments to this connection then they are output in order by the awaits on the futures
    /// returned by multiple calls to `receive`. These extensions within the  trait
    /// `ConnectionChannelExt` repeatedly call `receive` to create futures to await for fragments
    /// until the fragments can be combined into one complete L2CAP PDU.  
    ///
    /// ## Implementing
    /// A fragment is returned instead of a complete L2CAP PDU as every controller has limited to
    /// how many bytes it can have in a payload. A controller's maximum payload is determined by the
    /// size of the ACL data buffers within it it. This method must work for every controller, and
    /// nearly no controller a 64k sized data buffer to contain the maximum size of a L2CAP PDU.
    /// Many buffers can only handle a fragment within the tens of bytes (for example many
    /// controllers that support HCI and LE will use the minimum HCI data payload size of 23 bytes
    /// for a LE connection).
    ///
    /// ### Ordering
    /// While it is required by the Bluetooth Specification, the controller is expected to send
    /// fragmented data in the order in which it is fragmented. It is intended for an implementation
    /// of of `receive` to be able to assume that fragments from the controller are received in the
    /// order in which they were fragmented. The futures returned by the extension methods within
    /// [`ConnectionChannelExt`] perform no check to determine the order in which fragments are
    /// received. Even the type `L2capFragment` does not contain information to put fragments into
    /// the correct order for fragmentation.
    ///
    /// If it is known that the controller will possibly send unordered fragments the implementation
    /// of this `ConnectionChannel` must be able to queue up and re-order fragments received from
    /// the controller. The future returned by `receive` will then output the first fragment from
    /// the reorder queue.
    fn receive(&mut self) -> Self::RecvFut<'_>;
}

/// Extension method for a [`ConnectionChannel`]
///
/// Anything that implements `ConnectionChannel` will also `ConnectionChannelExt`.
pub trait ConnectionChannelExt: ConnectionChannel {
    /// A receiver for complete [`BasicInfoFrame`] L2CAP PDU.
    ///
    /// This returns a [`ConChanFutureRx`] that will return a `BasicInfoFrame` once it has polled to
    /// completion.
    fn receive_b_frame(&mut self) -> ConChanFutureRx<'_, Self> {
        ConChanFutureRx::new(self)
    }
}

impl<T> ConnectionChannelExt for T where T: ConnectionChannel {}

/// A future for asynchronously waiting for received packets from the connected device
///
/// This struct is created via the function [`ConnectionChannelExt::receive_b_frame`]
/// in the trait [`ConnectionChannel`].
///
/// This implements [`Future`](core::future::Future) for polling
/// the Bluetooth Controller to obtain complete [`BasicInfoFrame`] L2CAP data packets. If the
/// controller sends fragments to the host, `ConChanFutureRx` will combine these fragment packets
/// into a `BasicInfoFrame` before polling to completion.
pub struct ConChanFutureRx<'a, C>
where
    C: ?Sized + ConnectionChannel,
{
    // todo: raw pointers (and associated unsafety) can probably be converted to references when rust issue #100135 is closed
    connection_channel: *mut C,
    _p: core::marker::PhantomData<&'a C>,
    receive_future: Option<C::RecvFut<'a>>,
    full_acl_data: Vec<BasicInfoFrame<Vec<u8>>>,
    carryover_fragments: Vec<u8>,
    length: Option<usize>,
}

impl<'a, C> ConChanFutureRx<'a, C>
where
    C: ?Sized + ConnectionChannel,
{
    // The size of the L2CAP data header
    const HEADER_SIZE: usize = 4;

    /// Create a new `ConChanFutureRx`
    pub(crate) fn new(connection_channel: &'a mut C) -> Self {
        Self {
            connection_channel: connection_channel as *mut _,
            _p: core::marker::PhantomData,
            receive_future: None,
            full_acl_data: Vec::new(),
            carryover_fragments: Vec::new(),
            length: None,
        }
    }

    /// Get the complete, de-fragmented, received ACL Data
    ///
    /// This is useful when resulting `poll` may contain many complete packets, but still returns
    /// `Poll::Pending` because there were also incomplete fragments received. This should be used
    /// when
    pub fn get_received_packets(&mut self) -> Vec<BasicInfoFrame<Vec<u8>>> {
        core::mem::replace(&mut self.full_acl_data, Vec::new())
    }

    /// Drop all fragments
    ///
    /// **This will drop all stored fragments**. This should only be used when polling returns an
    /// error. However any fully assembled L2CAP packets are not touched by this function and they
    /// can be retrieved with the method
    /// [`get_received_packets`](ConChanFutureRx::get_received_packets). Once this is called, it is
    /// likely that polling will return multiple
    /// [`ExpectedStartFragment`](BasicFrameError::ExpectedStartFragment)
    /// errors before complete L2CAP packets are returned again.
    ///
    /// The malformed L2CAP packet that caused the error is not retrievable and is effectively lost.
    /// The payload is considered junk if a fragment causes an error, as returned errors generally
    /// mean that the length of L2CAP packet is incorrect. It would be unsafe to convert the payload
    /// into any valid higher level protocol packet. However and error can occur if an invalid
    /// channel identifier is used. There is no special consideration for L2CAP packets with an
    /// invalid channel identifier, so make sure only valid channel identifiers are used.
    ///
    /// # Note
    /// This function doesn't need to be called if polling returns the error
    /// [`ExpectedStartFragment`](BasicFrameError::ExpectedStartFragment), but only because there are
    /// no fragments to be dropped.
    pub fn drop_fragments(&mut self) {
        let _dropped = core::mem::replace(&mut self.carryover_fragments, Vec::new());
    }

    /// Process a fragment
    ///
    /// This validate the fragment before adding it the the data to eventually be returned by the
    /// future.
    fn process<T>(&mut self, fragment: &mut L2capFragment<T>) -> Result<(), BasicFrameError<core::convert::Infallible>>
    where
        T: core::ops::Deref<Target = [u8]> + TryExtend<u8>,
    {
        // Return if `fragment` is an empty fragment, as empty fragments can be ignored.
        if fragment.data.len() == 0 {
            return Ok(());
        }

        if self.carryover_fragments.is_empty() {
            // As there are no carryover fragments, `fragment` is expected to be the start of a
            // new L2CAP packet.

            if !fragment.is_start_fragment() {
                return Err(BasicFrameError::ExpectedStartFragment);
            }

            match fragment.get_acl_len() {
                // Check if `fragment` is a complete L2CAP payload
                Some(l) if (l + Self::HEADER_SIZE) <= fragment.data.len() => {
                    // todo use a buffer instead of Vec::new()
                    match BasicInfoFrame::try_from_slice_with_buffer(&fragment.data, Vec::new()) {
                        Ok(data) => self.full_acl_data.push(data),
                        Err(e) => return Err(e),
                    }
                }

                // The Length field in `fragment` is available, but `fragment` is just the starting
                // fragment of a L2CAP packet split into multiple fragments.
                len @ Some(_) => {
                    self.carryover_fragments.extend_from_slice(&fragment.data);
                    self.length = len;
                }

                // Length field is unavailable or incomplete, its debatable if this case ever
                // happens, but `fragment` is definitely not a L2CAP complete packet.
                None => self.carryover_fragments.extend_from_slice(&fragment.data),
            }
        } else {
            // `fragment` is a continuing (not starting) fragment of a fragmented L2CAP payload

            self.carryover_fragments.extend_from_slice(&fragment.data);

            let acl_len = match self.length {
                None => {
                    // Fold the first two bytes of the received data into a length fields. As this
                    // is the second fragment (with a data length greater than 1) received, the
                    // length of `carryover_fragments` is guaranteed to be at least 2.

                    let len_bytes =
                        self.carryover_fragments
                            .iter()
                            .take(2)
                            .enumerate()
                            .fold([0u8; 2], |mut a, (i, &v)| {
                                a[i] = v;
                                a
                            });

                    let len = <u16>::from_le_bytes(len_bytes) as usize;

                    self.length = Some(len);

                    len
                }
                Some(len) => len,
            };

            // Assemble the carryover fragments into a complete L2CAP packet if the length of the
            // fragments matches (or is greater than) the total length of the payload.
            if (acl_len + Self::HEADER_SIZE) <= self.carryover_fragments.len() {
                match BasicInfoFrame::try_from_slice_with_buffer(&self.carryover_fragments, Vec::new()) {
                    Ok(data) => {
                        self.full_acl_data.push(data);
                        self.carryover_fragments.clear();
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        Ok(())
    }
}

impl<C> Future for ConChanFutureRx<'_, C>
where
    C: ?Sized + ConnectionChannel,
    C::SendBuffer: core::ops::Deref<Target = [u8]> + TryExtend<u8>,
{
    type Output = Result<Vec<BasicInfoFrame<Vec<u8>>>, BasicFrameError<core::convert::Infallible>>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> core::task::Poll<Self::Output> {
        use core::task::Poll;

        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match this.receive_future {
                None => this.receive_future = Some(unsafe { &mut *this.connection_channel }.receive()),
                Some(ref mut receive_future) => {
                    // receive_future is not moved until it is dropped after
                    // polling is complete, so using `Pin::new_unchecked` is
                    // safe to use here.

                    match unsafe { core::pin::Pin::new_unchecked(receive_future) }.poll(cx) {
                        Poll::Pending => break Poll::Pending,
                        Poll::Ready(None) => break Poll::Ready(Err(BasicFrameError::ConnectionClosed)),
                        Poll::Ready(Some(Err(e))) => break Poll::Ready(Err(e.to_infallible())),
                        Poll::Ready(Some(Ok(mut fragment))) => {
                            this.receive_future = None;

                            match this.process(&mut fragment) {
                                Ok(_) => {
                                    if this.carryover_fragments.is_empty() && !this.full_acl_data.is_empty() {
                                        // Break iff there are complete L2CAP packets

                                        let data = core::mem::replace(&mut this.full_acl_data, Vec::new());

                                        break Poll::Ready(Ok(data));
                                    }
                                }
                                Err(e) => break Poll::Ready(Err(e)),
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Protocol and Service Multiplexers
///
/// This is a wrapper around the numerical number of the PSM. There are two ways to create a `Psm`.
/// One way is to convert one of the enumerations of
/// [`PsmAssignedNum`](PsmAssignedNum)
/// into this, the other way is to create a dynamic PSM with the function
/// [`new_dyn`](#method.new_dyn).
pub struct Psm {
    val: u16,
}

impl Psm {
    /// Get the value of the PSM
    ///
    /// The returned value is in *native byte order*
    pub fn to_val(&self) -> u16 {
        self.val
    }

    /// Create a new *dynamic* PSM
    ///
    /// This will create a dynamic PSM if the input `dyn_psm` is within the acceptable range of
    /// dynamically allocated PSM values (see the Bluetooth core spec | Vol 3, Part A).
    ///
    /// # Note
    /// For now extended dynamic PSM's are not supported as I do not know how to support them (
    /// see
    /// [`DynPsmIssue`](DynPsmIssue) for why)
    pub fn new_dyn(dyn_psm: u16) -> Result<Self, DynPsmIssue> {
        match dyn_psm {
            _ if dyn_psm <= 0x1000 => Err(DynPsmIssue::NotDynamicRange),
            _ if dyn_psm & 0x1 == 0 => Err(DynPsmIssue::NotOdd),
            _ if dyn_psm & 0x100 != 0 => Err(DynPsmIssue::Extended),
            _ => Ok(Psm { val: dyn_psm }),
        }
    }
}

impl From<PsmAssignedNum> for Psm {
    fn from(pan: PsmAssignedNum) -> Psm {
        let val = match pan {
            PsmAssignedNum::Sdp => 0x1,
            PsmAssignedNum::Rfcomm => 0x3,
            PsmAssignedNum::TcsBin => 0x5,
            PsmAssignedNum::TcsBinCordless => 0x7,
            PsmAssignedNum::Bnep => 0xf,
            PsmAssignedNum::HidControl => 0x11,
            PsmAssignedNum::HidInterrupt => 0x13,
            PsmAssignedNum::Upnp => 0x15,
            PsmAssignedNum::Avctp => 0x17,
            PsmAssignedNum::Avdtp => 0x19,
            PsmAssignedNum::AvctpBrowsing => 0x1b,
            PsmAssignedNum::UdiCPlane => 0x1d,
            PsmAssignedNum::Att => 0x1f,
            PsmAssignedNum::ThreeDsp => 0x21,
            PsmAssignedNum::LePsmIpsp => 0x23,
            PsmAssignedNum::Ots => 0x25,
        };

        Psm { val }
    }
}

/// Protocol and Service Multiplexers assigned numbers
///
/// The enumartions defined in `PsmAssignedNum` are those listed in the Bluetooth SIG assigned
/// numbers.
pub enum PsmAssignedNum {
    /// Service Disconvery Protocol
    Sdp,
    /// RFCOMM
    Rfcomm,
    /// Telephony Control Specification
    TcsBin,
    /// Telephony Control Specification ( Dordless )
    TcsBinCordless,
    /// Network Encapsulation Protocol
    Bnep,
    /// Human Interface Device ( Control )
    HidControl,
    /// Human Interface Device ( Interrupt )
    HidInterrupt,
    /// ESDP(?)
    Upnp,
    /// Audio/Video Control Transport Protocol
    Avctp,
    /// Audio/Video Distribution Transport Protocol
    Avdtp,
    /// Audio/Video Remote Control Profile
    AvctpBrowsing,
    /// Unrestricted Digital Information Profile
    UdiCPlane,
    /// Attribute Protocol
    Att,
    /// 3D Synchronization Profile
    ThreeDsp,
    /// Internet Protocol Support Profile
    LePsmIpsp,
    /// Object Transfer Service
    Ots,
}

/// The issue with the provided PSM value
///
/// ### NotDynamicRange
/// Returned when the PSM is within the assigned number range of values. Dynamic values need to be
/// larger then 0x1000.
///
/// ### NotOdd
/// All PSM values must be odd, the value provided was even
///
/// ### Extended
/// The least signaficant bit of the most significant byte (aka bit 8) must be 0 unless you want
/// an extended PSM (but I don't know what that is as I don't want to pay 200 sweedish dubloons
/// for ISO 3309 to find out what that is). For now extended PSM is not supported.
pub enum DynPsmIssue {
    NotDynamicRange,
    NotOdd,
    Extended,
}

impl core::fmt::Display for DynPsmIssue {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            DynPsmIssue::NotDynamicRange => write!(f, "Dynamic PSM not within allocated range"),
            DynPsmIssue::NotOdd => write!(f, "Dynamic PSM value is not odd"),
            DynPsmIssue::Extended => write!(f, "Dynamic PSM has extended bit set"),
        }
    }
}
