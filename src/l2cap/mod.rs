//! L2CAP protocol

pub mod signals;

/// Logical Link Control and Adaption protocol (L2CAP)
use core::future::Future;
use alloc::{
    vec::Vec,
};

/// LE-U L2CAP logical link type
///
/// This is a marker type for a LE-U L2CAP logical link.
#[derive(Debug,Clone,Copy,PartialEq,Eq,PartialOrd,Ord)]
pub struct LeU;

/// ACL-U L2CAP logical link type
///
/// This is a marker type for a ACL-U L2CAP logical link.
#[derive(Debug,Clone,Copy,PartialEq,Eq,PartialOrd,Ord)]
pub struct AclU;

/// Channel Identifier
///
/// Channel Identifiers are used by the L2CAP to associate the data with a given channel. Channels
/// are a numeric identifer for a protocol or an association of protocols that are part of L2CAP or
/// a higher layer (such as the Attribute (ATT) protocl).
///
/// # Specification Reference
/// See Bluetooth Specification V5 | Vol 3, Part A Section 2.1
#[derive(Debug,Clone,Copy,PartialEq,Eq,PartialOrd,Ord)]
pub enum ChannelIdentifier {
    NullIdentifier,
    /// ACL-U identifiers
    ACL(AclUserChannelIdentifier),
    /// LE-U identifiers
    LE(LeUserChannelIdentifier)
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
        LeUserChannelIdentifier::try_from_raw(val).map(|c| c.into())
    }

    /// Try to convert a raw value into a ACL-U channel identifier
    pub fn acl_try_from_raw(val: u16) -> Result<Self, ()> {
        AclUserChannelIdentifier::try_from_raw(val).map(|c| c.into())
    }
}

impl From<LeUserChannelIdentifier> for ChannelIdentifier {
    fn from( le: LeUserChannelIdentifier ) -> Self {
        ChannelIdentifier::LE(le)
    }
}

impl From<AclUserChannelIdentifier> for ChannelIdentifier {
    fn from( acl: AclUserChannelIdentifier ) -> Self {
        ChannelIdentifier::ACL(acl)
    }
}

/// Dynamically created L2CAP channel
#[derive(Debug,Clone,Copy,PartialEq,Eq,PartialOrd,Ord)]
pub struct DynChannelId<T> {
    channel_id: u16,
    _p: core::marker::PhantomData<T>
}

impl<T> DynChannelId<T> {
    fn new(channel_id: u16) -> Self {
        DynChannelId { channel_id, _p: core::marker::PhantomData }
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
    pub fn new_le(channel_id: u16) -> Result<LeUserChannelIdentifier, u16> {
        if Self::LE_BOUNDS.contains(&channel_id) {
            Ok(LeUserChannelIdentifier::DynamicallyAllocated(DynChannelId::new(channel_id)))
        } else {
            Err(channel_id)
        }
    }
}

impl DynChannelId<AclU> {

    pub const ACL_BOUNDS: core::ops::RangeInclusive<u16> = 0x0040..=0xFFFF;

    pub fn new_acl( channel_id: u16 ) -> Result<AclUserChannelIdentifier, u16> {
        if Self::ACL_BOUNDS.contains(&channel_id) {
            Ok( AclUserChannelIdentifier::DynamicallyAllocated( DynChannelId::new(channel_id) ) )
        } else {
            Err( channel_id )
        }
    }
}

#[derive(Debug,Clone,Copy,PartialEq,Eq,PartialOrd,Ord)]
enum AclUserChannelIdentifier {
    SignalingChannel,
    ConnectionlessChannel,
    AmpManagerProtocol,
    BrEdrSecurityManager,
    AmpTestManager,
    DynamicallyAllocated(DynChannelId<AclU>),
}

impl AclUserChannelIdentifier {

    fn to_val(&self) -> u16 {
        match self {
            AclUserChannelIdentifier::SignalingChannel => 0x1,
            AclUserChannelIdentifier::ConnectionlessChannel => 0x2,
            AclUserChannelIdentifier::AmpManagerProtocol => 0x3,
            AclUserChannelIdentifier::BrEdrSecurityManager => 0x7,
            AclUserChannelIdentifier::AmpTestManager => 0x3F,
            AclUserChannelIdentifier::DynamicallyAllocated(ci) => ci,
        }
    }

    fn try_from_raw(val: u16) -> Result<Self, ()> {
        match val {
            0x1  => Ok(AclUserChannelIdentifier::SignalingChannel),
            0x2  => Ok(AclUserChannelIdentifier::ConnectionlessChannel),
            0x3  => Ok(AclUserChannelIdentifier::AmpManagerProtocol),
            0x7  => Ok(AclUserChannelIdentifier::BrEdrSecurityManager),
            0x3F => Ok(AclUserChannelIdentifier::AmpTestManager),
            val if DynChannelId::<AclU>::ACL_BOUNDS.contains(&val) =>
                Ok(AclUserChannelIdentifier::DynamicallyAllocated( DynChannelId::new(val) )),
            _ => Err(())
        }
    }
}

/// LE User (LE-U) Channel Identifiers
///
/// These are the channel identifiers for a LE
#[derive(Debug,Clone,Copy,PartialEq,Eq,PartialOrd,Ord)]
pub enum LeUserChannelIdentifier {
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
    DynamicallyAllocated(DynChannelId<LeU>)
}

impl LeUserChannelIdentifier {

    fn to_val(&self) -> u16 {
        match self {
            LeUserChannelIdentifier::AttributeProtocol => 0x4,
            LeUserChannelIdentifier::LowEnergyL2CAPSignalingChannel => 0x5,
            LeUserChannelIdentifier::SecurityManagerProtocol => 0x6,
            LeUserChannelIdentifier::DynamicallyAllocated(dyn_id) => dyn_id.channel_id,
        }
    }

    fn try_from_raw(val: u16) -> Result<Self, ()>  {
        match val {
            0x4 => Ok( LeUserChannelIdentifier::AttributeProtocol ),
            0x5 => Ok( LeUserChannelIdentifier::LowEnergyL2CAPSignalingChannel ),
            0x6 => Ok( LeUserChannelIdentifier::SecurityManagerProtocol),
            _ if DynChannelId::<LeU>::LE_BOUNDS.contains(&val) =>
                Ok( LeUserChannelIdentifier::DynamicallyAllocated( DynChannelId::new(val) ) ),
            _ => Err(()),
        }
    }
}

/// L2CAP Manager
///
/// For the most part L2CAP doesn't play a significant role in higher layer protocols besides
/// establishing a baseline configuration for the logical link layer that isn't already configured
/// through either the Host Controller Interface or via direct link to the controller. Each
/// `L2capManager` should be considered valid only for the lifetime of a connection, and is up to
/// peer device if a past manager is still correct upon reconnection.
///
/// The L2capManager keeps track of the configuration parameters, both recognized and hinted, to
/// form L2CAP data packets. When an `L2capManager` is created the configuration is set to the
/// defaults for the type of Link Layer (either ACL-U or LE-U).
pub struct L2capManager<CType> {
    peer_mtu: usize,
    signaling_cid: ChannelIdentifier,
    p_chan: core::marker::PhantomData<CType>,
}

impl L2capManager<LeU> {
    /// Create a new `L2capManager` for a Bluetooth LE-U connection
    ///
    /// The configuration will be set to the default values for a LE-U connection.
    pub fn new_le() -> Self {
        Self {
            peer_mtu: LeU::MTU,
            signaling_cid: ChannelIdentifier::LE(
                LeUserChannelIdentifier::LowEnergyL2CAPSignalingChannel
            ),
            p_chan: core::marker::PhantomData,
        }
    }
}

impl<C> L2capManager<C> {

    /// Set the peers L2CAP MTU
    ///
    /// This is a 'bottom level' MTU, any protocol above the L2CAP will have this as an upward
    /// bound of MTU. Higher layer protocols may fragment their data and send it with a smaller MTU.
    ///
    /// This is used to manually set the MTU for L2CAP PDUs instead of relying on peer device to
    /// specify it's MTU with a configuration request signalling packet. It is only recommended to
    /// use this when this peer device is not going to inform this device of its MTU through the
    /// L2CAP, and the MTU is not the default for the Link Layer type (ACL-U or LE-U).
    ///
    /// Be aware that the `mtu` cannot exceed the maximum packet size supported by the Link
    /// Controller, either by the limit specified in the specification (see V 5.0 | Vol 6, Part B,
    /// Section 2.4), or the limit of this device's Bluetooth Controller (such as the PDU size limit
    /// in a controllers transmit buffer). The Bluetooth Controller may fragment the data or return
    /// an error if it is sent a L2CAP PDU that is too large for it to handle. This function will
    /// not verify that the provided `mtu` is larger than the supported MTU by the controller.
    ///
    /// # Note
    /// If the mtu specified is less than the minimum for the type of L2CAP (either ACL-U or LE-U)
    /// it will be defaulted to that value. The minimum for a ACL-U is 48 bytes and the minimum for
    /// LE-U is 23 bytes
    ///
    /// When using the HCI, the L2CAP MTU can be found using the *Read Buffer Size* or *LE Read
    /// Buffer Size* commands.
    pub fn set_peer_mtu(&mut self, mtu: u16) {
        self.peer_mtu = core::cmp::max(mtu.into(), C::MTU);
    }
}

/// Acl Data Errors
#[derive(Debug)]
pub enum AclDataError {
    /// Raw data is too small for an ACL frame
    RawDataTooSmall,
    /// Specified payload length didn't match the actual payload length
    PayloadLengthIncorrect,
    /// Invalid Channel Id
    InvalidChannelId,
    /// Expected A start Fragment
    ExpectedStartFragment
}

impl core::fmt::Display for AclDataError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            AclDataError::RawDataTooSmall => write!(f, "Raw data is too small for an ACL frame"),
            AclDataError::PayloadLengthIncorrect => write!(f, "Specified payload length didn't \
                match the actual payload length"),
            AclDataError::InvalidChannelId => write!(f, "Invalid Channel Id"),
            AclDataError::ExpectedStartFragment => write!(f, "Expected start fragment, received a \
                continuation fragment"),
        }
    }
}

/// The suggested MTU as part of an `AclData`
///
/// `AclData` can contain a suggested MTU for a connection channel. Its used for a higher level
/// protocol (than L2CAP) to have the data sent with a smaller MTU than the MTU set for the
/// `ConnectionChannel`. Instead of fragmentation being being determined by the MTU for the
/// `ConnectionChannel`, this `AclData`'s MTU would be used to determined if fragmentation is
/// needed. *Be aware that it is not a requirement of implementors of a `ConnectionChannel` to use a
/// `AclData`'s MTU over the connection channels MTU*, but this library's implementations of
/// `ConnectionChannel` do take into account this MTU when deciding if fragmentation is necessary.
///
/// # Channel
/// Use the MTU defined for the channel
///
/// # Minimum
/// Use the minimum MTU specified for the logical link Type. This is 48 bytes for ACL-U and 23
/// bytes for LE-U.
///
/// # Mtu
/// Usage this MTU. However if the MTU value is less than the the minimum MTU for the logical link
/// or larger than the channel's MTU, it will not be used.
#[derive(Clone,Copy)]
pub enum AclDataSuggestedMtu {
    Channel,
    Minimum,
    Mtu(usize),
}

impl Default for AclDataSuggestedMtu {
    fn default() -> Self {
        AclDataSuggestedMtu::Channel
    }
}

/// Connection-oriented channel data
///
/// `AclData` is a *Basic* L2CAP data packet for asynchronous connection-oriented data sent to and
/// from a connected device. `AclData` is always a complete packet, it contains the entire payload.
/// As a consequence `AclData` may be larger than the MTU for the connection channel. The
/// implementor of a
/// [`ConnectionChannel`](crate::l2cap::ConnectionChannel) will fragment the data within it's
/// implementation of `send`, and a
/// [`ConChanFutureRx](crate::l2cap::ConChanFutureRx) will assemble received fragments into
/// `AclData`.
///
/// There is an optional MTU just for this `AclData`. Its used for a higher level protocol (than
/// L2CAP) to have the data sent with a smaller MTU than the MTU set for the `ConnectionChannel`.
/// Instead of fragmentation being being determined by the MTU for the `ConnectionChannel`, this
/// `AclData`'s MTU would be used to determined if fragmentation is needed. *Be aware that
/// it is not a requirement of implementors of a `ConnectionChannel` to use a `AclData`'s MTU over
/// the connection channels MTU*, but this library's implementations of `ConnectionChannel` do take
/// into account this MTU when deciding if fragmentation is necessary.
#[derive(Debug,Clone)]
pub struct AclData {
    channel_id: ChannelIdentifier,
    data: Vec<u8>,
    mtu: AclDataSuggestedMtu,
}

impl AclData {

    /// Create a new `AclData`
    ///
    /// The channel identifier field
    pub fn new( payload: Vec<u8>, channel_id: ChannelIdentifier) -> Self {
        AclData {
            channel_id,
            data: payload,
            mtu: AclDataSuggestedMtu::default(),
        }
    }

    /// Use a specific maximum transfer unit for transferring this data
    ///
    /// This is a *request* to use the specified `mtu` for transferring this data to the connected
    /// device. It is up to the implementation of the
    /// [`ConnectionChannel`](crate::l2cap::ConnectionChannel) whether or not to use this MTU.
    /// However `ConnectionChannel` implementations should prefer to use this MTU so long as the mtu
    /// is not larger than the MTU agreed upon of the connected device nor smaller than the minimum
    /// MTU for the Link type (ACL-U or LE-U).
    ///
    /// If `mtu` is `None` then this data will be transferred with the minimum MTU for the logical
    /// link. This is 48 bytes for ACL-U and 23 bytes for LE-U.
    pub fn use_mtu<Mtu: Into<Option<u16>>>(&mut self, mtu: Mtu) {
        self.mtu = match mtu.into() {
            None    => AclDataSuggestedMtu::Minimum,
            Some(v) => AclDataSuggestedMtu::Mtu(v.into()),
        }
    }

    pub fn get_channel_id(&self) -> ChannelIdentifier { self.channel_id }

    pub fn get_payload(&self) -> &[u8] { &self.data }

    /// This create a complete L2CAP data packet in its raw form
    ///
    /// This packet is ready to be transmitted
    pub fn into_raw_data(&self) -> Vec<u8> {
        use core::convert::TryInto;

        let mut v = Vec::new();

        let len: u16 = self.data.len().try_into().expect("Couldn't convert into u16");

        v.extend_from_slice( &len.to_le_bytes() );

        v.extend_from_slice( &self.channel_id.to_val().to_le_bytes() );

        v.extend_from_slice( &self.data );

        v
    }

    /// Create an AclData struct from a complete raw L2CAP data packet
    ///
    /// The input must be a slice of bytes containing a complete L2CAP data packet.
    ///
    /// # Requirements
    /// * The length of the raw data must be >= 4
    /// * The length value in the raw data must be less than or equal to the length of the payload
    ///   portion of the raw data. Any bytes beyond
    /// * The channel id must be valid
    pub fn from_raw_complete_data(data: &[u8]) -> Result<Self, AclDataError> {
        if data.len() >= 4 {
            let len = <u16>::from_le_bytes( [data[0], data[1]] ) as usize;
            let raw_channel_id = <u16>::from_le_bytes( [data[2], data[3]] );
            let payload = &data[4..];

            if len <= payload.len() {
                Ok( Self {
                    channel_id: ChannelIdentifier::LE(
                        LeUserChannelIdentifier::try_from_raw(raw_channel_id).or(Err(AclDataError::InvalidChannelId))?
                    ),
                    data: payload[..len].to_vec(),
                })
            } else {
                Err( AclDataError::PayloadLengthIncorrect )
            }
        }
        else {
            Err( AclDataError::RawDataTooSmall )
        }
    }

    /// Get the MTU (if any) packaged with this ACL data
    pub fn get_mtu(&self) -> AclDataSuggestedMtu {
        self.mtu
    }
}

/// A Complete or Fragmented Acl Data
///
/// Packets sent between the Master and Slave may be fragmented and need to be combined into a
/// complete [`AclData`]. Multiple AclDataFragments, when in order and complete, can be combined
/// into a single 'AclData' through the use of 'FromIterator' for AclData.
pub struct AclDataFragment {
    start_fragment: bool,
    data: Vec<u8>
}

impl AclDataFragment {

    /// Crate a 'AclDataFragment'
    pub(crate) fn new(start_fragment: bool, data: Vec<u8>) -> Self {
        Self {start_fragment, data}
    }

    /// Get the length of the payload as specified in the ACL data
    ///
    /// This returns None if this packet doesn't contain the full length field
    pub fn get_acl_len(&self) -> Option<usize> {
        if self.start_fragment && self.data.len() > 2 {
            Some( <u16>::from_le_bytes([ self.data[0], self.data[1] ]) as usize )
        } else {
            None
        }
    }

    pub fn is_start_fragment(&self) -> bool { self.start_fragment }

    pub fn fragment_data(&self) -> &[u8] { &self.data }
}

/// Create a `L2capPdu` from an `AclData` where the size may be larger then the MTU.
///
/// # Note
/// If mtu is smaller then 
/// [`MINIMUM_LE_U_FRAGMENT_START_SIZE`](crate::hci::HciAclData::MINIMUM_LE_U_FRAGMENT_START_SIZE)
/// then it is sent as that size to the controller over the Host Controller Interface for LE-U.
impl<Mtu> From<(AclData, Mtu)> for L2capPdu where Mtu: Into<Option<usize>>
{
    fn from((acl_data, mtu): (AclData, Mtu)) -> Self {
        Self {
            data: acl_data.into_raw_data(),
            mtu: mtu.into()
        }
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
/// A `ConnectionChannel` can be created from the
/// [`HostInterface`](crate::hci::HostInterface), but it can also be implemented directly for
/// systems that do not support a host controller interface.
pub trait ConnectionChannel {

    /// Send a L2CAP PDU to the Controller
    ///
    /// This attempts to sends a L2CAP data packet to the controller. The pdu must be complete as
    /// the implementor of a `ConnectionChannel` will perform any necessary flow control and
    /// fragmentation of `data` before sending raw packets to the controller.
    ///
    /// The implementor of a `ConnectionChannel` is strongly suggested to use the
    /// [`AclDataSuggestedMtu`](crate::l2cap::AclDataSuggestedMtu) included with an `AclData` for
    /// fragmentation of the data. Implementors of `ConnectionChannel` within this library already
    /// use the `AclDataSuggestedMtu` in the implementation of `send`.
    fn send(&self, data: AclData) -> SendFut;

    /// Set the MTU for `send`
    ///
    /// This is used as the maximum transfer unit of a sent L2CAP data payload. This value must be
    /// larger than the minimum for the logical link. An ACL-U logical link has a minimum MTU of 48
    /// and a LE-U logical link has a minimum MTU of 23. If `mtu` is smaller than the minimum MTU it
    /// will not change the current MTU for the connection channel.
    fn set_mtu(&mut self, mtu: u16);

    /// Get the maximum MTU the Bluetooth controller can handle
    ///
    /// It is not enforced if this mtu
    fn max_mtu_hint(&self) -> usize;

    /// Try to receive a PDU from the controller
    ///
    /// It is recommended to use
    /// [`future_receiver`](crate::l2cap::ConnectionChannel::future_receiver) over this method.
    ///
    /// This attempts to receive one or more packets from an underlying implementation. If there is
    /// nothing to be received then the provided waker will be used for waking any awaiting contexts
    /// when data is ready to be received.
    ///
    /// Receive doesn't return `AclData` but instead returns `AclDataFragments`. What is returned
    /// is what was received from an over-the-air link layer packet, which can be a fragment
    /// of a complete `AclData`. `receive` does not perform stitching of these fragments into
    /// the a L2CAP pdu, however it does guarantee that *the order in which fragments are returned
    /// was the order in which they were received*.
    ///
    /// Use the function `future_receiver` to return a future that can be awaited for *complete*
    /// ACL data.
    fn receive(&self, waker: &core::task::Waker) -> Option<Vec<AclDataFragment>>;

    /// A futures receiver for complete `AclData`
    ///
    /// This is used to return a structure that can asynchronously receive from a Bluetooth
    /// controller and process the received fragments into complete `AclData`. A `ConChanFutureRx`
    /// is expected to be awoken multiple times as more fragmented `AclData` is received. As
    /// fragments are received, they will be stitched together until they are made into a completed
    /// packet. When all fragments can be made into a completed the future will finally return
    /// `Poll::Ready`.
    ///
    /// The future utilizes the `receive` method to get ACL data fragments from the controller.
    /// These fragments are expected to be contiguous as per the requirements for `receive`, however
    /// this does not guarantee that these fragments can be made into complete `AclData`. If data
    /// cannot be converted into a fragment, then the future will return an error. These fragments
    /// and any other fragments received are lost when an error occurs.
    ///
    /// Please do not infrequently poll a `ConChanFutureRx`. Infrequent polling occurs when this
    /// future as polled at a much slower rate then the ACL data received. Polling infrequently may
    /// cause the future to return `Poll::Pending` much more often, and it is recommended to always
    /// use `.await` as that guarantees the fastest poll to completion of this future. With
    /// infrequent polling, the time taken for to poll to completion changes from the time taken to
    /// receive a complete ACL PDU to the time taken for stitching fragments into multiple ACL
    /// PDUs. This occurs because the likelihood of having incomplete fragmented data left over
    /// from a poll call is proportionally increased to the number of fragments returned by a call
    /// to `receive`. The only exception to this is when you know that all packets will be sent as
    /// complete packets, but this can only occur when the maximum payload is set to the minimum for
    /// the given Bluetooth type, BR/EDR or LE, for L2CAP.
    fn future_receiver(&self) -> ConChanFutureRx<'_, Self> {
        ConChanFutureRx {
            cc: self,
            full_acl_data: Vec::new(),
            carryover_fragments: Vec::new(),
            length: None,
        }
    }
}

/// Future for polling to await the sending of data *to the controller*
///
/// This future is used for awaiting the sending of ACL data to the controller. When to await is
/// determined by a lower layer implementation as when polled a `SendFut` just determines to return
/// `Ready(..)` from an internal flag.
///
/// Usually there are only two types of 'lower layers' below the `SendFut`, a flow controller or the
/// trivial case. The trivial case is where there is no monitoring or keeping track of a Bluetooth
/// controller's data buffers. A flow controller is just the opposite. It is designed to not send
/// data that would cause the buffers of the controller to go beyond their capacity. The trivial
/// case will usually be implemented to never await, as `SendFut` will be created with the internal
/// flag as true. As for the flow controller, generally it will only await when sending data will
/// overrun a controller's buffer. The flow controller will use a `SendFut` the same way as the
/// trivial case when there is space for the data within the controllers buffers.
pub struct SendFut( Option<core::task::Waker>, pub bool);

impl SendFut {
    /// Create a new `SendFut`
    ///
    /// Input `ready` is a boolean to indicate if the future is ready to return 'Poll::Ready(())'.
    /// Creating a `SendFut` with `ready` as `true` will mean that this future will never await.
    pub fn new(ready: bool) -> Self {
        SendFut(None, ready)
    }

    /// Mark the future as ready to send
    ///
    /// This should only be used by a lower layer to have the next poll of this future return ready
    /// to the awaiting context.
    pub fn ready(&mut self) { self.1 = true }
}

impl Future for SendFut {
    type Output = ();

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        let this = self.get_mut();

        if this.1 {
            core::task::Poll::Ready(())
        } else {
            this.0 = Some(cx.waker().clone());

            core::task::Poll::Pending
        }
    }
}

/// A future for asynchronously waiting for received packets from the connected device
///
/// This struct is created via the function [`future_receiver`](ConnectionChannel::future_receiver)
/// in the trait [`ConnectionChannel`].
///
/// This implements [`Future`](https://doc.rust-lang.org/core/future/trait.Future.html) for polling
/// the Bluetooth Controller to obtain complete [`AclData`] (L2CAP data packets). `ConChanFutureRx`
/// is effectively a packet defragmenter for packets received by the controller.
///
/// # How It Works
/// When poll is called, the function will receive all the available ACL data fragments from the
/// backend driver and try to assemble the packets into complete ACL data.
///
/// If all fragments received can be converted into complete L2CAP packets, then `Poll::Ready` is
/// returned will all the packets.
///
/// When the all fragments cannot be converted into complete ACL Packets, then `Poll::Pending` is
/// returned, and the completed packets along with the incomplete fragments are saved for the next
/// poll. Upon polling again, if the newly received fragments can be assembled with the saved
/// fragments to make complete L2CAP packets then `Poll::Ready` is returned with all the L2CAP
/// packets (saved and newly assembled).  Otherwise `Poll::Pending` is returned and the process
/// repeats itself.
pub struct ConChanFutureRx<'a, C> where C: ?Sized {
    cc: &'a C,
    full_acl_data: Vec<AclData>,
    carryover_fragments: Vec<u8>,
    length: Option<usize>,
}

impl<'a, C> ConChanFutureRx<'a, C> where C: ?Sized {

    /// Get the complete, de-fragmented, received ACL Data
    ///
    /// This is useful when resulting `poll` may contain many complete packets, but still returns
    /// `Poll::Pending` because there were also incomplete fragments received. This should be used
    /// when
    pub fn get_received_packets(&mut self) -> Vec<AclData> {
        core::mem::replace(&mut self.full_acl_data, Vec::new() )
    }

    /// Drop all fragments
    ///
    /// **This will drop stored all fragments**. This should only be used when polling returns an
    /// error (with exceptions, see the [Note](#Note)). All assembled L2CAP packets are untouched by
    /// this function and can be retrieved with `get_received_packets`.
    ///
    /// Once this is called, it is likely that polling will return multiple
    /// [`ExpectedStartFragment`](AclDataError::ExpectedStartFragment)
    /// errors before complete L2CAP packets are returned again.
    ///
    /// # Note
    /// This function doesn't need to be called if polling returns the error
    /// [`ExpectedStartFragment`](AclDataError::ExpectedStartFragment).
    pub fn drop_fragments(&mut self) {
        let _dropped = core::mem::replace(&mut self.carryover_fragments, Vec::new() );
    }
}

impl<'a,C> Future for ConChanFutureRx<'a,C>
where C: ConnectionChannel
{
    type Output = Result<Vec<AclData>, AclDataError>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> core::task::Poll<Self::Output> {

        // The size of the L2CAP data header
        const HEADER_SIZE:usize = 4;

        use core::task::Poll;

        let this = self.get_mut();

        loop {
            if let Some(ret) = match this.cc.receive(cx.waker()) {
                None => return Poll::Pending,
                Some(fragments) => {
                    match fragments.into_iter().try_for_each( |mut f| {
        
                        // Continue `try_for_each` if f is an empty fragment, empty fragments can
                        // be ignored.
                        if f.data.len() == 0 { return Ok(()) }
        
                        if this.carryover_fragments.is_empty()
                        {
                            if !f.is_start_fragment() {
                                return Err(AclDataError::ExpectedStartFragment)
                            }

                            match f.get_acl_len() {
                                Some(l) if (l + HEADER_SIZE) <= f.data.len() => {
                                    match AclData::from_raw_data(&f.data) {
                                        Ok(data) => this.full_acl_data.push(data),
                                        Err(e) => return Err(e)
                                    }
                                },
                                len @ Some(_) => {
                                    this.carryover_fragments.append(&mut f.data);
                                    this.length = len;
                                },
                                None => {
                                    this.carryover_fragments.append(&mut f.data);
                                },
                            }
                        } else {
                            this.carryover_fragments.append(&mut f.data);
        
                            let acl_len = match this.length {
                                None => {
                                    // There will always be at least 2 items to take because a starting
                                    // fragment and a proceeding fragment have been received and empty
                                    // fragments are not added to `self.carryover_fragments`.
                                    let len_bytes = this.carryover_fragments.iter()
                                        .take(2)
                                        .enumerate()
                                        .fold([0u8;2], |mut a, (i, &v)| { a[i] = v; a });
        
                                    let len = <u16>::from_le_bytes(len_bytes) as usize;
        
                                    this.length = Some(len);
        
                                    len
                                },
                                Some(len) => len,
                            };
        
                            if (acl_len + HEADER_SIZE) <= this.carryover_fragments.len() {
                                match AclData::from_raw_data(&this.carryover_fragments) {
                                    Ok(data) => {
                                        this.full_acl_data.push(data);
                                        this.carryover_fragments.clear();
                                    },
                                    Err(e) => return Err(e),
                                }
                            }
                        }
        
                        Ok(())
                    }) {
                        // Body of match statement

                        Ok(_) => {
                            if this.carryover_fragments.is_empty() &&
                                !this.full_acl_data.is_empty()
                            {
                                Some( Ok(core::mem::replace(&mut this.full_acl_data, Vec::new())) )
                            } else {
                                None
                            }
                        },
                        Err(e) => Some( Err(e) )
                    }
                }
            } { 
                // Block of `if Some(ret) = match ...`
                return Poll::Ready(ret);

                // Loop continues if None is returned by match statement
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
pub struct Psm { val: u16 }

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
    /// dynamically allocated PSM values (see the Bluetooth core spec v 5.0 | Vol 3, Part A).
    ///
    /// # Note
    /// For now extended dynamic PSM's are not supported as I do not know how to support them (
    /// see
    /// [`DynPsmIssue`](DynPsmIssue) for why)
    pub fn new_dyn( dyn_psm: u16 ) -> Result<Self, DynPsmIssue> {
        match dyn_psm {
            _ if dyn_psm <= 0x1000 => Err( DynPsmIssue::NotDynamicRange ),
            _ if dyn_psm & 0x1 == 0 => Err( DynPsmIssue::NotOdd ),
            _ if dyn_psm & 0x100 != 0 => Err( DynPsmIssue::Extended ),
            _ => Ok( Psm { val: dyn_psm } )
        }
    }
}

impl From<PsmAssignedNum> for Psm {
    fn from( pan: PsmAssignedNum ) -> Psm {

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
            DynPsmIssue::NotDynamicRange =>
                write!(f, "Dynamic PSM not within allocated range"),
            DynPsmIssue::NotOdd =>
                write!(f, "Dynamic PSM value is not odd"),
            DynPsmIssue::Extended =>
                write!(f, "Dynamic PSM has extended bit set"),
        }
    }
}
