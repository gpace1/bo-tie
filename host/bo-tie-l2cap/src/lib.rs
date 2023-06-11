//! Link Link Control and Adaption Protocol
//!
//! This is an implementation of the Link Link Control and Adaption Protocol (L2CAP). L2CAP is the
//! base protocol for all other host protocols of Bluetooth. Its main purpose is for data managing
//! and control between the host, the protocols below the host layer (usually this is the HCI
//! layer), and connected devices.
//!  
//! # Logical Links Types
//! Logical links are how data is transferred via a physical link from one host to another host.
//! There are two kings of logical links, ACL-U for a BR/ERD physical link and LE-U for a LE
//! physical link. This library breaks these up these two into for *types* of logical links as each
//! type has different requirements per the Bluetooth Specification.
//!
//! [`AclU`], [`AclUExt`], [`Apb`], and [`LeU`] are the four 'types' of logical links defined within
//! this library. `AclU`, `AclUExt`, `Apb` are ACL-U logical links and `LeU` is a LE-U logical link.
//! Each type differs in the Minimum supported Maximum Transmission Unit (MTU) and channel mapping
//! (as assigned by the Bluetooth SIG).
//!
//! The most often used case for a logical link type is mapping raw data to a L2CAP data type. A
//! raw channel value cannot be converted into a valid channel until the logical link type is
//! defined

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub mod channels;
pub mod pdu;
pub mod signals;

use crate::channels::{AclCid, ChannelIdentifier, LeCid};
use alloc::vec::Vec;
use bo_tie_core::buffer::TryExtend;
use core::future::Future;

mod private {
    use crate::channels::ChannelIdentifier;

    /// A trait for a logical link type
    ///
    /// Every logical link type of this library implements `LinkType`. For explanation on what a
    /// *logical link type* is see the [library level] documentation.
    ///
    /// Use the trait [`LinkTypeExt`] if you would like to call these methods directly.
    ///
    /// [library level]: crate
    pub trait LinkType {
        /// The supported Maximum Transmission Unit (MTU)
        ///
        /// Every device must be able to support a MTU up to this value for this logical link type.
        /// However, this does not mean two devices cannot use a smaller MTU negotiated at a higher
        /// layer.
        ///
        /// # Note
        /// This is returned by the method [`get_min_supported_mtu`] of `LinkTypePort`.
        ///
        /// [`get_min_supported_mtu`]: crate::LinkTypePort::get_min_supported_mtu
        const MIN_SUPPORTED_MTU: u16;

        /// Try to get the channel identifier from its value
        ///
        /// Channels differ depending on the logical link of the connection. This will map the value
        /// to the correct channel identifier for this logical link.
        fn try_channel_from_raw(val: u16) -> Option<ChannelIdentifier>;

        /// Get the channel identifier for the signaling channel
        ///
        /// The signalling channel for this logical link is returned if there is a signalling
        /// channel.
        fn get_signaling_channel() -> Option<ChannelIdentifier>;
    }
}

/// Porting trait for methods of `LinkType`
///
/// As [`LinkType`] is a 'private' trait, this trait can be imported to call the methods of
/// `LinkType`.
///
/// [`LinkType`]: private::LinkType
pub trait LinkTypePort: private::LinkType {
    /// Get the minimum supported Maximum Transmission Unit (MTU)
    ///
    /// Every device must be able to support a MTU up to this value for this logical link type.
    /// However, this does not mean two devices cannot use a smaller MTU negotiated at a higher
    /// layer.
    fn get_min_supported_mtu() -> u16 {
        Self::MIN_SUPPORTED_MTU
    }

    /// Try to get the channel identifier from its value
    ///
    /// Channels differ depending on the logical link of the connection. This will map the value
    /// to the correct channel identifier for this logical link.
    fn try_channel_from_raw(val: u16) -> Option<ChannelIdentifier> {
        <Self as private::LinkType>::try_channel_from_raw(val)
    }

    /// Get the Channel Identifier of this Signalling Channel
    ///
    /// `None` is returned if there is no signalling channel for this logical link type.
    fn get_signalling_channel() -> Option<ChannelIdentifier> {
        <Self as private::LinkType>::get_signaling_channel()
    }
}

impl<T> LinkTypePort for T where T: private::LinkType {}

/// ACL-U L2CAP logical link type
///
/// This is a marker type for an ACL-U L2CAP logical link that does not support the extended flow
/// Specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AclU;

impl private::LinkType for AclU {
    const MIN_SUPPORTED_MTU: u16 = 48;

    fn try_channel_from_raw(val: u16) -> Option<ChannelIdentifier> {
        AclCid::try_from_raw(val).map(|id| ChannelIdentifier::Acl(id)).ok()
    }

    fn get_signaling_channel() -> Option<ChannelIdentifier> {
        Some(ChannelIdentifier::Acl(AclCid::SignalingChannel))
    }
}

/// ACL-U L2CAP logical link type supporting Extended Flow Specification
///
/// This is a marker type for an ACL-U L2CAP logical link that supports the extended flow
/// specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AclUExt;

impl private::LinkType for AclUExt {
    const MIN_SUPPORTED_MTU: u16 = 672;

    fn try_channel_from_raw(val: u16) -> Option<ChannelIdentifier> {
        AclCid::try_from_raw(val).map(|id| ChannelIdentifier::Acl(id)).ok()
    }

    fn get_signaling_channel() -> Option<ChannelIdentifier> {
        Some(ChannelIdentifier::Acl(AclCid::SignalingChannel))
    }
}

/// APB-U L2CAP logical link type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Apb;

impl private::LinkType for Apb {
    const MIN_SUPPORTED_MTU: u16 = 48;

    fn try_channel_from_raw(val: u16) -> Option<ChannelIdentifier> {
        channels::ApbCid::try_from_raw(val)
            .map(|id| ChannelIdentifier::Apb(id))
            .ok()
    }

    fn get_signaling_channel() -> Option<ChannelIdentifier> {
        None
    }
}

/// LE-U L2CAP logical link type
///
/// This is a marker type for a LE-U L2CAP logical link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LeU;

impl private::LinkType for LeU {
    const MIN_SUPPORTED_MTU: u16 = 23;

    fn try_channel_from_raw(val: u16) -> Option<ChannelIdentifier> {
        LeCid::try_from_raw(val).map(|id| ChannelIdentifier::Le(id)).ok()
    }

    fn get_signaling_channel() -> Option<ChannelIdentifier> {
        Some(ChannelIdentifier::Le(LeCid::LeSignalingChannel))
    }
}

/// A L2CAP PDU Fragment
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

    /// Get the value of length field in the basic header
    ///
    /// This returns `None` if it cannot be determined if this packet has the PDU length field.
    fn get_len_field(&self) -> Option<usize>
    where
        T: core::ops::Deref<Target = [u8]>,
    {
        if self.start_fragment && self.data.len() > 2 {
            Some(<u16>::from_le_bytes([self.data[0], self.data[1]]) as usize)
        } else {
            None
        }
    }

    /// Get the value of the channel identifier
    ///
    /// This returns `None` if the packet cannot be determined to have the channel ID field
    fn get_channel_id<L>(&self) -> Option<ChannelIdentifier>
    where
        L: private::LinkType,
        T: core::ops::Deref<Target = [u8]>,
    {
        if self.start_fragment {
            L::try_channel_from_raw(<u16>::from_le_bytes([
                self.data.get(2).copied()?,
                self.data.get(3).copied()?,
            ]))
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
    /// The logical link used for this Connection.
    type LogicalLinkType: private::LinkType;

    /// Sending future
    ///
    /// This is the future returned by [`send`](ConnectionChannel::send).
    type SendFut<'a>: Future<Output = Result<(), Self::SendErr>>
    where
        Self: 'a;

    /// Sending error
    ///
    /// This is the error type for the output of the future [`SendFut`]
    ///
    /// [`SendFut`](ConnectionChannel::SendFut)
    type SendErr;

    /// The buffer type for received L2CAP fragments
    ///
    /// This buffer is for containing the raw data of a L2CAP packet received by the future returned
    /// from the method `recv`.
    type RecvBuffer: core::ops::Deref<Target = [u8]> + TryExtend<u8>;

    /// Error returned by a Receive future
    type RecvErr;

    /// Receiving future
    ///
    /// This is the future returned by [`receive`].
    ///
    /// [`receive`](ConnectionChannel::receive_fragment)
    type RecvFut<'a>: Future<Output = Result<L2capFragment<Self::RecvBuffer>, Self::RecvErr>>
    where
        Self: 'a;

    /// Get the fragmentation size
    ///
    /// This is the size in which sent and receive packets are fragmented to. This should match the
    /// maximum size of payload portion for the underlying protocol's data packet.
    fn fragmentation_size(&self) -> usize;

    /// Send a L2CAP fragment to the Controller
    ///
    /// This is used to send a L2CAP fragment to the connected device.
    fn send_fragment<T>(&self, fragment: L2capFragment<T>) -> Self::SendFut<'_>
    where
        T: IntoIterator<Item = u8>;

    /// Await the reception of a L2CAP PDU fragment
    ///
    /// Lower layers are unlikely to be able to pass complete L2CAP PDU frames to the L2CAP
    /// protocol. The future returned by `receive` will output these fragments.
    ///
    /// It is not recommended to directly call `receive`. `receive` is intended to be a base
    /// method for the futures returned by the receive methods of [`ConnectionChannelExt`]. These
    /// futures have built in fragmentation recombination to output either a complete PDU or SDU.
    ///
    /// ## Implementing
    /// The returned `RecvFut` outputs a [`L2capFragment`]. In order to recombine fragments, they
    /// must be output by all instances of `RecvFut` in order in which they are received from the
    /// lower layer. This is why is not recommended for `RecvFut` to be `Sync`.
    fn receive_fragment(&mut self) -> Self::RecvFut<'_>;
}

/// Extension method for a [`ConnectionChannel`]
///
/// Anything that implements `ConnectionChannel` will also `ConnectionChannelExt`.
pub trait ConnectionChannelExt: ConnectionChannel {
    /// Send a L2CAP PDU
    ///
    /// The input `pdu` will be sent to the connected device. Unlike method [`send_fragment`], this
    /// extension method returns a future that, if required, will fragment the `pdu` and send the
    /// individual fragments using the `send_fragment` method.
    ///
    /// # Note
    /// The returned `SendFuture` implements `IntoFuture` instead of directly implementing `Future`.
    fn send<T>(&self, pdu: T) -> pdu::SendFuture<Self, T>
    where
        T: pdu::FragmentL2capPdu,
    {
        pdu::SendFuture::new(self, pdu)
    }

    /// A receiver for a complete [`BasicFrame`] L2CAP PDU.
    ///
    /// This returns a [`ReceiveL2capPdu`] that will output a L2CAP Basic Frame PDU.
    fn receive_b_frame(&mut self) -> ReceiveL2capPdu<'_, Self, pdu::BasicFrame<Vec<u8>>> {
        ReceiveL2capPdu::new(self, ())
    }
}

impl<T> ConnectionChannelExt for T where T: ConnectionChannel {}

/// Receiver of a L2CAP PDU
///
/// This future awaits the reception of a complete L2CAP PDU from a lower layer. See the methods of
/// [`ConnectionChannelExt`] for where this is used.
pub struct ReceiveL2capPdu<'a, C, T>
where
    C: ?Sized + ConnectionChannel,
    T: pdu::RecombineL2capPdu,
{
    connection_channel: &'a mut C,
    receive_future: Option<C::RecvFut<'a>>,
    partial_assembly: Vec<u8>,
    pdu_len: Option<usize>,
    recombine_meta: T::RecombineMeta,
    pd: core::marker::PhantomData<T>,
}

impl<'a, C, T> ReceiveL2capPdu<'a, C, T>
where
    C: ?Sized + ConnectionChannel,
    T: pdu::RecombineL2capPdu,
{
    /// The size of the 'basic header' (the part of the header
    /// containing the 'PDU length' and 'channel id' fields).
    const BASIC_HEADER_SIZE: usize = 4;

    /// Create a new `ConChanFutureRx`
    pub(crate) fn new(connection_channel: &'a mut C, recombine_meta: T::RecombineMeta) -> Self {
        Self {
            connection_channel,
            receive_future: None,
            partial_assembly: Vec::new(),
            pdu_len: None,
            recombine_meta,
            pd: core::marker::PhantomData,
        }
    }

    /// Process the first fragment
    ///
    /// This method is used by the method [`process_fragment`]
    ///
    /// [`process_fragment`]: ReceiveL2capPdu::process_fragment
    fn process_first_fragment<F>(
        &mut self,
        fragment: &L2capFragment<F>,
    ) -> Result<Option<T>, FragmentError<T::RecombineError, C::RecvErr>>
    where
        F: core::ops::Deref<Target = [u8]>,
    {
        // As there are no carryover fragments, `fragment` is expected to be the start of a
        // new L2CAP packet.
        if !fragment.is_start_fragment() {
            return Err(FragmentError::ExpectedStartFragment);
        }

        match fragment.get_len_field() {
            // Check if `fragment` is a complete L2CAP payload
            Some(payload_len) if (payload_len + Self::BASIC_HEADER_SIZE) <= fragment.data.len() => {
                let channel_id = fragment
                    .get_channel_id::<C::LogicalLinkType>()
                    .ok_or(FragmentError::InvalidChannelIdentifier)?;

                let payload = fragment.data[Self::BASIC_HEADER_SIZE..].iter().copied();

                return T::recombine(channel_id, payload, &mut self.recombine_meta)
                    .map(|t| t.into())
                    .map_err(|e| FragmentError::Recombine(e));
            }

            // The Length field in `fragment` is available, but `fragment` is just the starting
            // fragment of a L2CAP packet split into multiple fragments.
            len @ Some(_) => {
                self.partial_assembly.extend_from_slice(&fragment.data);
                self.pdu_len = len;
            }

            // Length field is unavailable or incomplete, its debatable if this case ever
            // happens, but `fragment` is definitely not a L2CAP complete packet.
            None => self.partial_assembly.extend_from_slice(&fragment.data),
        }

        Ok(None)
    }

    /// Process a continuing fragment
    ///
    /// This method is used by the method [`process_fragment`]
    ///
    /// [`process_fragment`]: ReceiveL2capPdu::process_fragment
    fn process_continuing_fragment<F>(
        &mut self,
        fragment: &L2capFragment<F>,
    ) -> Result<Option<T>, FragmentError<T::RecombineError, C::RecvErr>>
    where
        F: core::ops::Deref<Target = [u8]>,
    {
        self.partial_assembly.extend_from_slice(&fragment.data);

        let payload_len = match self.pdu_len {
            None => {
                if self.partial_assembly.len() < 2 {
                    // not enough bytes to determine the PDU length field
                    return Ok(None);
                } else {
                    let pdu_len: usize =
                        <u16>::from_le_bytes([self.partial_assembly[0], self.partial_assembly[1]]).into();

                    self.pdu_len = pdu_len.into();

                    pdu_len
                }
            }
            Some(len) => len,
        };

        // Assemble the carryover fragments into a complete L2CAP packet if the length of the
        // fragments matches (or is greater than) the total length of the payload.
        if (payload_len + Self::BASIC_HEADER_SIZE) <= self.partial_assembly.len() {
            let channel_id = <C::LogicalLinkType as private::LinkType>::try_channel_from_raw(<u16>::from_le_bytes([
                self.partial_assembly[2],
                self.partial_assembly[3],
            ]))
            .ok_or(FragmentError::InvalidChannelIdentifier)?;

            let payload = core::mem::take(&mut self.partial_assembly).into_iter();

            T::recombine(channel_id, payload, &mut self.recombine_meta)
                .map(|t| t.into())
                .map_err(|e| FragmentError::Recombine(e))
        } else {
            Ok(None)
        }
    }

    /// Process a fragment into an eventual L2CAP PDU
    ///
    /// As fragments are received, first they must be recombined into a complete PDU. This will
    /// do one of three things when returning `Ok(_)`:
    ///
    /// 1) immediately return if fragment is an 'empty' fragment.
    /// 2) add the fragment to the `carryover_fragments` field.
    /// 3) Construct the complete L2CAP PDU.
    fn process_fragment<F>(
        &mut self,
        fragment: &L2capFragment<F>,
    ) -> Result<Option<T>, FragmentError<T::RecombineError, C::RecvErr>>
    where
        F: core::ops::Deref<Target = [u8]>,
    {
        // Return if `fragment` is an empty fragment, as empty fragments can be ignored.
        if fragment.data.len() == 0 {
            return Ok(None);
        }

        if self.partial_assembly.is_empty() {
            self.process_first_fragment(fragment)
        } else {
            self.process_continuing_fragment(fragment)
        }
    }
}

impl<C, T> Future for ReceiveL2capPdu<'_, C, T>
where
    C: ?Sized + ConnectionChannel,
    T: pdu::RecombineL2capPdu,
{
    type Output = Result<T, FragmentError<T::RecombineError, C::RecvErr>>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> core::task::Poll<Self::Output> {
        use core::task::Poll;

        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match this.receive_future {
                None => {
                    // this decouples the lifetime.
                    //
                    // connection_channel will not be touched until
                    // after `receive_future` is dropped.
                    let receive_future = unsafe { &mut *(this.connection_channel as *mut C) }.receive_fragment();

                    this.receive_future = receive_future.into()
                }
                Some(ref mut receive_future) => {
                    // receive_future is not moved until it is dropped after
                    // polling is complete, so using `Pin::new_unchecked` is
                    // safe to use here.

                    match unsafe { core::pin::Pin::new_unchecked(receive_future) }.poll(cx) {
                        Poll::Pending => break Poll::Pending,
                        Poll::Ready(Err(e)) => break Poll::Ready(Err(FragmentError::Receive(e))),
                        Poll::Ready(Ok(fragment)) => {
                            this.receive_future = None;

                            break match this.process_fragment(&fragment) {
                                Ok(Some(t)) => Poll::Ready(Ok(t)),
                                Ok(None) => Poll::Pending,
                                Err(e) => Poll::Ready(Err(e)),
                            };
                        }
                    }
                }
            }
        }
    }
}

/// Error concerning an L2CAP fragment
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FragmentError<Rc, Rx> {
    ExpectedStartFragment,
    InvalidChannelIdentifier,
    Recombine(Rc),
    Receive(Rx),
}

impl<Rc: core::fmt::Display, Rx: core::fmt::Display> core::fmt::Display for FragmentError<Rc, Rx> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            FragmentError::ExpectedStartFragment => f.write_str("expected start fragment"),
            FragmentError::InvalidChannelIdentifier => f.write_str("invalid channel identifier for this logical link"),
            FragmentError::Recombine(e) => write!(f, "failed to recombine fragments, {}", e),
            FragmentError::Receive(e) => write!(f, "receive error, {}", e),
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
