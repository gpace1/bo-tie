//! Link Link Control and Adaption Protocol
//!
//! This is an implementation of the Link Link Control and Adaption Protocol (L2CAP). L2CAP is the
//! base protocol for all other host protocols of Bluetooth. Its main purpose is for data managing
//! and control between the host, the protocols below the host layer (usually this is the HCI
//! layer), and connected devices.
//!    

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub mod channels;
pub mod pdu;
pub mod signals;

use crate::channels::ChannelIdentifier;
use alloc::vec::Vec;
use bo_tie_core::buffer::TryExtend;
use core::future::Future;

/// A trait containing a constant for the smallest maximum transfer unit for a logical link
pub trait MinimumMtu {
    const MIN_MTU: usize;
}

mod private {
    /// A trait for a logical link type
    ///
    /// `None` is returned if `val` is not a valid Channel ID for the link type.
    pub trait Link {
        fn channel_from_raw(val: u16) -> Option<super::channels::ChannelIdentifier>;
    }
}

/// ACL-U L2CAP logical link type
///
/// This is a marker type for an ACL-U L2CAP logical link that does not support the extended flow
/// Specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AclU;

impl MinimumMtu for AclU {
    const MIN_MTU: usize = 48;
}

impl private::Link for AclU {
    fn channel_from_raw(val: u16) -> Option<ChannelIdentifier> {
        channels::AclCid::try_from_raw(val)
            .map(|id| ChannelIdentifier::Acl(id))
            .ok()
    }
}

/// ACL-U L2CAP logical link type supporting Extended Flow Specification
///
/// This is a marker type for an ACL-U L2CAP logical link that supports the extended flow
/// specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AclUExt;

impl MinimumMtu for AclUExt {
    const MIN_MTU: usize = 672;
}

impl private::Link for AclUExt {
    fn channel_from_raw(val: u16) -> Option<ChannelIdentifier> {
        channels::AclCid::try_from_raw(val)
            .map(|id| ChannelIdentifier::Acl(id))
            .ok()
    }
}

/// APB-U L2CAP logical link type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Apb;

impl private::Link for Apb {
    fn channel_from_raw(val: u16) -> Option<ChannelIdentifier> {
        channels::ApbCid::try_from_raw(val)
            .map(|id| ChannelIdentifier::Apb(id))
            .ok()
    }
}

/// LE-U L2CAP logical link type
///
/// This is a marker type for a LE-U L2CAP logical link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LeU;

impl MinimumMtu for LeU {
    const MIN_MTU: usize = 23;
}

impl private::Link for LeU {
    fn channel_from_raw(val: u16) -> Option<ChannelIdentifier> {
        channels::LeCid::try_from_raw(val)
            .map(|id| ChannelIdentifier::Le(id))
            .ok()
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
        L: private::Link,
        T: core::ops::Deref<Target = [u8]>,
    {
        if self.start_fragment {
            L::channel_from_raw(<u16>::from_le_bytes([
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
    type LogicalLink: private::Link;

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
    /// This is the error type for the output of the future [`SendFut`]
    ///
    /// [`SendFut`](ConnectionChannel::SendFut)
    type SendFutErr;

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
    /// [`receive`](ConnectionChannel::receive)
    type RecvFut<'a>: Future<Output = Result<L2capFragment<Self::RecvBuffer>, Self::RecvErr>>
    where
        Self: 'a;

    /// Send a L2CAP PDU to the Controller
    ///
    /// This attempts to sends [`BasicFrame`] to the controller. The pdu must be complete as
    /// the implementor of a `ConnectionChannel` will perform any necessary flow control and
    /// fragmentation of `data` before sending raw packets to the controller.
    fn send<T>(&self, data: T) -> Self::SendFut<'_>
    where
        T: pdu::FragmentL2capPdu;

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
    fn receive(&mut self) -> Self::RecvFut<'_>;
}

/// Extension method for a [`ConnectionChannel`]
///
/// Anything that implements `ConnectionChannel` will also `ConnectionChannelExt`.
pub trait ConnectionChannelExt: ConnectionChannel {
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
    fragments: Vec<u8>,
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
            fragments: Vec::new(),
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
                    .get_channel_id::<C::LogicalLink>()
                    .ok_or(FragmentError::InvalidChannelIdentifier)?;

                let payload = fragment.data[Self::BASIC_HEADER_SIZE..].iter().copied();

                return T::recombine(channel_id, payload, &mut self.recombine_meta)
                    .map(|t| t.into())
                    .map_err(|e| FragmentError::Recombine(e));
            }

            // The Length field in `fragment` is available, but `fragment` is just the starting
            // fragment of a L2CAP packet split into multiple fragments.
            len @ Some(_) => {
                self.fragments.extend_from_slice(&fragment.data);
                self.pdu_len = len;
            }

            // Length field is unavailable or incomplete, its debatable if this case ever
            // happens, but `fragment` is definitely not a L2CAP complete packet.
            None => self.fragments.extend_from_slice(&fragment.data),
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
        self.fragments.extend_from_slice(&fragment.data);

        let payload_len = match self.pdu_len {
            None => {
                if self.fragments.len() < 2 {
                    // not enough bytes to determine the PDU length field
                    return Ok(None);
                } else {
                    let pdu_len: usize = <u16>::from_le_bytes([self.fragments[0], self.fragments[1]]).into();

                    self.pdu_len = pdu_len.into();

                    pdu_len
                }
            }
            Some(len) => len,
        };

        // Assemble the carryover fragments into a complete L2CAP packet if the length of the
        // fragments matches (or is greater than) the total length of the payload.
        if (payload_len + Self::BASIC_HEADER_SIZE) <= self.fragments.len() {
            let channel_id = <C::LogicalLink as private::Link>::channel_from_raw(<u16>::from_le_bytes([
                self.fragments[2],
                self.fragments[3],
            ]))
            .ok_or(FragmentError::InvalidChannelIdentifier)?;

            let payload = core::mem::take(&mut self.fragments).into_iter();

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

        if self.fragments.is_empty() {
            self.process_first_fragment(fragment)
        } else {
            self.process_continuing_fragment(fragment)
        }
    }
}

impl<C, T> Future for ReceiveL2capPdu<'_, C, T>
where
    C: ?Sized + ConnectionChannel,
    C::SendBuffer: core::ops::Deref<Target = [u8]> + TryExtend<u8>,
    T: pdu::RecombineL2capPdu,
{
    type Output = Result<T, FragmentError<T::RecombineError, C::RecvErr>>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> core::task::Poll<Self::Output> {
        use core::task::Poll;

        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match this.receive_future {
                None => {
                    // this decouples the lifetime, connection_channel
                    // will not be touched until after `receive_future`
                    // is dropped.
                    let receive_future = unsafe { &mut *(this.connection_channel as *mut C) }.receive();

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
#[derive(Debug, Copy, Clone)]
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
