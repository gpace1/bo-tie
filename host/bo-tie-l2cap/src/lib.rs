//! Link Link Control and Adaption Protocol
//!
//! This is an implementation of the Link Link Control and Adaption Protocol (L2CAP). L2CAP is the
//! base protocol for all other host protocols of Bluetooth. Its main purpose is for data managing
//! and control between the host, the protocols below the host layer (usually this is the HCI
//! layer), and connected devices.
//!  
//! # Logical Links Flavors
//! There are two distinct types of logical links, ACL-U for a BR/ERD physical link and LE-U for a
//! LE physical link. The Bluetooth Specification further defines different configuration for these
//! logical links (well only for the ACL-U link) depending on the configuration or implementation of
//! either the physical link or how the higher protocol use the link. To manage this, this crate
//! has 'broken up' these two logical links into logical links *flavors*.
//!
//! [`AclULink`], [`AclUExtLink`], [`ApbLink`], and [`LeULink`] are the four 'flavors' of logical
//! links defined within this library. `AclULink`, `AclUExtLink`, `ApbLink` are flavors of ACL-U
//! logical links and `LeULink` is the lone flavor for a LE-U logical link. Each type has their own
//! supported Maximum Transmission Unit (MTU) and channel mapping (as assigned by the Bluetooth SIG)
//! requirements.
//!
//! Every flavor implements the [`LinkFlavor`] trait. This trait is for ensuring channel mapping is
//! correct for the flavor and for defining the required supported MTU.
//!
//! ```
//! # use bo_tie_l2cap::link_flavor::{AclUExtLink, AclULink, LeULink, LinkFlavor};
//! # use bo_tie_l2cap::channel::id::{AclCid, ChannelIdentifier};
//!
//! // The `LinkFlavor` trait is mainly used for validating
//! // raw channel identifiers
//!
//! // att channel
//! assert!(LeULink::try_channel_from_raw(0x4).is_some());
//!
//! // invalid channel
//! assert!(LeULink::try_channel_from_raw(0xFFFF).is_none());
//!
//!
//! // The `SUPPORTED_MTU` constant is the required supported MTU
//! assert!(672, AclUExtLink::SUPPORTED_MTU);
//!
//!
//! // `LinkFlavor` also has a method to get the signalling channel
//! assert_eq!(
//!     Some(ChannelIdentifier::Acl(AclCid::SignalingChannel)),
//!     AclULink::get_signaling_channel()
//! );
//! ```
//!
//! [`LinkFlavor`]: link_flavor::LinkFlavor

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;
extern crate core;

pub mod channel;
pub mod link_flavor;
pub mod pdu;
pub mod signals;

use crate::channel::id::{ChannelIdentifier, LeCid};
use crate::channel::SharedPhysicalLink;
pub use crate::channel::{BasicFrameChannel, CreditBasedChannel, SignallingChannel};
use core::future::Future;
use link_flavor::{AclULink, LeULink};
use pdu::L2capFragment;

/// The Different Types of Logical Links
///
/// Bluetooth defines two kinds of host level logical links. [ACL-U] is the logical link for a
/// BR/EDR physical link
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum LogicalLinkKind {
    /// Asynchronous Connection-oriented logical link (ACL-U)
    ///
    /// This is the logical link that maps to either a Basic Rate or Enhanced Data Rate physical
    /// link.
    Acl,
    /// Low Energy logical link (LE-U)
    ///
    /// This logical link maps to a Low Energy physical link.
    Le,
}

/// A Physical Link
///
/// The L2CAP implementation needs to map a logical link its corresponding physical link. This trait
/// must be implemented by a lower layer (than L2CAP) for each physical link supported by the
/// Controller.
pub trait PhysicalLink {
    /// Sending Future
    ///
    /// This future is used to await the transmission of data. It shall poll to completion when the
    /// lower layer can accept another L2CAP fragment.
    ///
    /// If something goes wrong when sending, the future shall complete and output an
    /// [`Err(Self::SendErr)`].
    ///
    /// [`Err(Self::SendErr)`]: PhysicalLink::SendErr
    type SendFut<'a>: Future<Output = Result<(), Self::SendErr>>
    where
        Self: 'a;

    /// Send Error
    ///
    /// This is an error generated by the lower layer whenever the future returned by `send` cannot
    /// be successfully polled to completed.
    type SendErr;

    /// Reception Future
    ///
    /// This futures must be implemented to await for the reception of L2CAP fragments over the
    /// physical link. The future shall only output when a new L2CAP fragment should be sent to the
    /// L2CAP layer or an error occurs.
    ///
    /// If something goes wrong when awaiting or receiving, the future shall complete and output
    /// an [`Err(Self::RecvErr)`].
    ///
    /// [`Err(Self::RecvErr)`]: PhysicalLink::RecvErr
    type RecvFut<'a>: Future<Output = Option<Result<L2capFragment<Self::RecvData>, Self::RecvErr>>>
    where
        Self: 'a;

    /// Received L2CAP Data
    ///
    /// `RecvData` shall be an iterator over data of a *single* physical link packet. The bytes of
    /// the data are also be in the order in which they are received by the linked device.
    ///
    /// # Note
    /// The implementation does not need to verify or check that the payload contains valid L2CAP
    /// data.
    type RecvData: Iterator<Item = u8> + ExactSizeIterator;

    /// Receive Error
    ///
    /// This is an error generated by the lower layer whenever the future returned by `recv` cannot
    /// successfully output received L2CAP fragment.
    type RecvErr;

    /// This is the maximum transmission size supported by the physical link
    ///
    /// This should return the maximum amount of payload data that the physical link can transmit
    /// within one of its PDUs.
    fn max_transmission_size(&self) -> usize;

    /// Send to the Physical Link
    ///
    /// This is used by the L2CAP layer for sending fragmented L2CAP PDUs over the physical link.
    /// The maximum size of the fragment is determined by the return of the method
    /// [`max_transmission_size`].
    ///
    /// # Flow Control
    /// Flow control shall be implemented within the future returned by `send`. The future shall
    /// await until it has successfully sent the L2CAP fragment.
    ///
    /// # 'Sent'
    /// What 'sent' means is subjective to the implementation. For an HCI implementation it could
    /// mean that the data has been sent to the Controller. For a single system implementation it
    /// may mean that the data has fully transmitted to the peer device.
    fn send<'s, T>(&'s mut self, fragment: L2capFragment<T>) -> Self::SendFut<'s>
    where
        T: 's + IntoIterator<Item = u8>;

    /// Receive From the Physical Link
    ///
    /// This returns a future for awaiting the reception of the physical link's PDU from the peer
    /// device. It shall be implemented to return a future that will output the payload of a
    /// received physical link PDU.
    ///
    /// # Output
    /// The output of `recv` is a future that returns a result within an option. The future's output
    /// is either `None` to indicate the peer disconnected, a `L2capFragment`, or an error that
    /// occurred when receiving.
    ///
    /// # Queued PDUs
    /// It is up to the implementation on how many physical link PDUs can be queued. Most
    /// implementations do not provide any queuing. Queuing is only relevant for supporting
    /// applications that may occasionally take inordinate amounts of time between calling `recv`.
    /// In a truly bad scenario, the host should be using flow control implemented in the L2CAP or
    /// higher layers to manage the reception of L2CAP PDUs.
    fn recv(&mut self) -> Self::RecvFut<'_>;
}

/// Trait for a Logical Links
///
/// This trait is used to mark a type as a L2CAP logical. It is not intended to be implemented by
/// types outside the bounds of `bo-tie-l2cap`.
///
/// Its only method is `get_shared_link` which is used to return a [`SharedPhysicalLink`]. This
/// return is used to ensure that multiple channels can be 'selected' within one async context. See
/// the library level doc for details on this.
pub trait LogicalLink {
    type PhysicalLink: PhysicalLink;
    type UnusedChannelResponse: channel::UnusedChannelResponse;
    type Flavor: link_flavor::LinkFlavor;

    fn get_shared_link(&self) -> &SharedPhysicalLink<Self::PhysicalLink, Self::UnusedChannelResponse>;
}

/// A LE-U Logical Link
pub struct LeULogicalLink<P: PhysicalLink> {
    shared_link: SharedPhysicalLink<P, Self>,
}

impl<P: PhysicalLink> LeULogicalLink<P> {
    /// Create a new `LogicalLink`
    pub fn new(physical_link: P) -> Self {
        let shared_link = SharedPhysicalLink::new(physical_link);

        Self { shared_link }
    }

    /// Get what kind of Logical Link this is
    pub fn get_kind(&self) -> LogicalLinkKind {
        LogicalLinkKind::Le
    }

    /// Get the Signalling Channel
    ///
    /// This returns the channel for sending signalling commands over a LE-U logical link. There can
    /// only be one active signalling channel at a time. If a new signalling channel object needs to
    /// be created, any previously created signalling channel must be dropped.
    ///
    /// # Panic
    /// A panic will occur if a signalling channel already exists for this logical link.
    pub fn get_signalling_channel(&self) -> SignallingChannel<'_, Self> {
        let channel_id = ChannelIdentifier::Le(LeCid::LeSignalingChannel);

        SignallingChannel::new(channel_id, &self)
    }

    /// Get the Channel for the Attribute Protocol
    ///
    /// This returns the channel used for sending and receiving Attribute Protocol PDUs. There can
    /// only be one active channel for the ATT protocol at a time. If a new channel object for the
    /// ATT protocol needs to be created, any previously created channel must be dropped.
    ///
    /// # Panic
    /// A panic will occur if a channel already exists for the ATT protocol.
    pub fn get_att_channel(&self) -> BasicFrameChannel<'_, Self> {
        let channel_id = ChannelIdentifier::Le(LeCid::AttributeProtocol);

        BasicFrameChannel::new(channel_id, &self)
    }

    /// Get the Channel for the Security Manager Protocol
    ///
    /// This returns the channel used for sending and receiving Attribute Protocol PDUs. There can
    /// only be one active channel for the ATT protocol at a time. If a new channel object for the
    /// ATT protocol needs to be created, any previously created channel must be dropped.
    ///
    /// # Panic
    /// A panic will occur if a channel already exists for the ATT protocol.
    pub fn get_sm_channel(&self) -> BasicFrameChannel<'_, Self> {
        let channel_id = ChannelIdentifier::Le(LeCid::SecurityManagerProtocol);

        BasicFrameChannel::new(channel_id, &self)
    }
}

impl<P: PhysicalLink> LogicalLink for LeULogicalLink<P> {
    type PhysicalLink = P;
    type UnusedChannelResponse = Self;

    type Flavor = LeULink;

    fn get_shared_link(&self) -> &SharedPhysicalLink<Self::PhysicalLink, Self::UnusedChannelResponse> {
        &self.shared_link
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
    /// [`DynPsmIssue`](PsmIssue) for why)
    pub fn new_dyn(dyn_psm: u16) -> Result<Self, PsmIssue> {
        match dyn_psm {
            _ if dyn_psm <= 0x1000 => Err(PsmIssue::NotDynamicRange),
            _ if dyn_psm & 0x1 == 0 => Err(PsmIssue::NotOdd),
            _ if dyn_psm & 0x100 != 0 => Err(PsmIssue::Extended),
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
pub enum PsmIssue {
    NotDynamicRange,
    NotOdd,
    Extended,
}

impl core::fmt::Display for PsmIssue {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            PsmIssue::NotDynamicRange => write!(f, "Dynamic PSM not within allocated range"),
            PsmIssue::NotOdd => write!(f, "Dynamic PSM value is not odd"),
            PsmIssue::Extended => write!(f, "Dynamic PSM has extended bit set"),
        }
    }
}
