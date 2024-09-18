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
//! assert_eq!(672, AclUExtLink::SUPPORTED_MTU);
//!
//!
//! // `LinkFlavor` also has a method to get the signalling channel
//! assert_eq!(
//!     Some(ChannelIdentifier::Acl(AclCid::SignalingChannel)),
//!     AclULink::get_signaling_channel()
//! );
//! ```
//!
//! [`AclULink`]: link_flavor::AclULink
//! [`AclUExtLink`]: link_flavor::AclUExtLink
//! [`ApbLink`]: link_flavor::ApbLink
//! [`LeULink`]: link_flavor::LeULink
//! [`LinkFlavor`]: link_flavor::LinkFlavor

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;
mod channel;
pub mod link_flavor;
mod logical_link_private;
pub mod pdu;
pub mod signals;

use crate::channel::id::{ChannelIdentifier, DynChannelId, LeCid};
use crate::channel::signalling::ReceivedLeUSignal;
pub use crate::channel::{BasicFrameChannel, CreditBasedChannel, SignallingChannel};
use crate::channel::{InvalidChannel, LeUChannelBuffer, PduRecombineAddError, PduRecombineAddOutput};
use crate::link_flavor::LinkFlavor;
use crate::logical_link_private::LeULogicalLinkHandle;
use crate::pdu::{BasicFrame, FragmentIterator, FragmentL2capPdu};
use bo_tie_core::buffer::TryExtend;
use core::future::Future;
use link_flavor::{AclULink, LeULink};
use logical_link_private::LogicalLinkPrivate;
use pdu::L2capFragment;

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
    // todo: change this into `SendFut<'a, I>` where `I: 'a`. The method `send` will also be changed
    //  to return `SendFut<'s, T::IntoIter>`. For now this is not done as there are erroneous errors
    //  generated by the compiler in regards to the generic `I` and it implementing `Iterator`. Once
    //  those are fixed then `SendFut` will change.
    type SendFut<'a>: Future<Output = Result<(), Self::SendErr>>
    where
        Self: 'a;

    /// Send Error
    ///
    /// This is an error generated by the lower layer whenever the future returned by `send` cannot
    /// be successfully polled to completed.
    type SendErr: core::fmt::Debug;

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
    type RecvErr: core::fmt::Debug;

    /// This is the maximum transmission size supported by the physical link
    ///
    /// This should return the maximum amount of payload data that the physical link can transmit
    /// within one of its PDUs.
    fn max_transmission_size(&self) -> u16;

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
    ///
    /// [`max_transmission_size`]: PhysicalLink::max_transmission_size
    fn send<T>(&mut self, fragment: L2capFragment<T>) -> Self::SendFut<'_>
    where
        T: IntoIterator<Item = u8>;

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

trait PhysicalLinkExt: PhysicalLink {
    /// Send a PDU
    ///
    /// This is an extension method for sending a PDU.
    ///
    /// # No SDU support
    /// This is for only sending a PDU. Any higher layer data type must be fragmented down to the
    /// PDU size of the channel.
    ///
    /// # Panic
    /// This will panic if `fragmentation_size` is invalid (the channel is expected to verify any
    /// user set fragmentation size). The conditions for it to be invalid depend on the
    /// implementation of [`FragmentL2capPdu`].
    async fn send_pdu<T>(&mut self, pdu: T, fragmentation_size: usize) -> Result<(), Self::SendErr>
    where
        T: FragmentL2capPdu,
    {
        let mut fragments = pdu.into_fragments(fragmentation_size).unwrap();

        let mut is_first = true;

        while let Some(fragment_data) = fragments.next() {
            let fragment = L2capFragment::new(is_first, fragment_data);

            is_first = false;

            self.send(fragment).await?;
        }

        Ok(())
    }
}

impl<T> PhysicalLinkExt for T where T: PhysicalLink {}

/// A Logical Link
///
/// This is a marker trait for a Logical Link. This is used by channel types to interact with the
/// logical link that created them.
#[allow(private_interfaces)]
pub trait LogicalLink: LogicalLinkPrivate {}

impl<T> LogicalLink for T where T: LogicalLinkPrivate {}

/// A LE-U Logical Link
///
/// This is the logical link for two devices connected via Bluetooth LE. Channels can be created for
/// the link through the methods `LeULogicalLink`.
///
/// A `LeULogicalLink` requires a `PhysicalLink` to be created. This `PhysicalLink` is a trait that
/// is either directly implemented by the physical layer or some interface to the physical layer
/// (typically a host controller interface (HCI) implementation).
///
/// ```
/// # use tokio::select;
/// # use bo_tie_l2cap::{PhysicalLink, LeULogicalLink};
/// async fn le_u_doc<P: PhysicalLink>(physical_link: P) {
/// let le_link = LeULogicalLink::new(physical_link, &mut Vec::new());
///
/// loop {
///     select! {
///         
///     }
/// }
/// # }
/// ```
///
/// ## Channels
/// Channels are used to sending and receiving data between two linked devices. Fixed channels are
/// directly created via a method of a `LeULogicalLink`, but dynamically allocated channels must be
/// created through a connection process initiated using the signalling channel.
///
/// ### Fixed Channels
/// Fixed channels are assigned by the Bluetooth SIG and are either defined within the Bluetooth
/// Specification or the assigned numbers document (but as of right now the list within the assigned
/// numbers document is empty). There is no special process to establish a fixed channel at the
/// L2CAP layer, so any fixed channel can be created using the appropriate method of
/// `LeULogicalLink`.
///
/// ```
/// # use bo_tie_l2cap::{LeULogicalLink, PhysicalLink};
/// # async fn example<P: PhysicalLink>(le_u_logical_link: LeULogicalLink<P>) {
/// // create the signalling and ATT channels
///
/// let signalling_channel = le_u_logical_link.get_signalling_channel();
///
/// let att_channel = le_u_logical_link.get_att_channel();
/// # }
/// ```
///
/// ### Dynamic Channels
/// Dynamic channels must be created using the signalling channel. There is a L2CAP connection
/// process that goes through the establishing of the channel identities (and any other information
/// used for the connection) of the dynamically allocated channels.
///
/// ```
/// # use bo_tie_l2cap::{LeULogicalLink, PhysicalLink};
/// # use bo_tie_l2cap::channel::signalling::ReceivedLeUSignal;
/// # use bo_tie_l2cap::signals::packets::{LeCreditMps, LeCreditMtu, SimplifiedProtocolServiceMultiplexer};
/// # async fn example<P: PhysicalLink>(le_u_logical_link: LeULogicalLink<P>)
/// # where  
/// #     <P as PhysicalLink>::SendErr: std::fmt::Debug,
/// #     <P as PhysicalLink>::RecvErr: std::fmt::Debug,
/// # {
/// // This is the process for initializing a LE credit based
/// // channel. This channel uses a dynamically allocated CID,
/// // so it must go through a L2CAP connection process before
/// // it can be created.
///
/// let mut signalling_channel = le_u_logical_link.get_signalling_channel();
///
/// // request the creation of a LE credit based channel
/// let request = signalling_channel
///     .request_le_credit_connection(
///         SimplifiedProtocolServiceMultiplexer::new_dyn(0x80),
///         LeCreditMtu::new_min(),
///         LeCreditMps::new_min(),
///         10,
///     )
///     .await
///     .expect("failed to send request");
///
/// // Process the response from the linked peer device and
/// // create a new credit_based_channel.
/// let credit_based_channel = match signalling_channel
///     .receive()
///     .await
///     .expect("failed to get response")
/// {
///     ReceivedLeUSignal::LeCreditBasedConnectionResponse(response) => response
///         .create_le_credit_connection(&request, &le_u_logical_link)
///         .expect("linked device rejected LE credit based connection request"),
///
///     ReceivedLeUSignal::CommandRejectRsp(response) => {
///          panic!("LE credit based channels not supported by the linked device")
///     }
///     _ => panic!("received unexpected signal"),
/// };
/// # }
/// ```
pub struct LeULogicalLink<P, B, const DYN_CHANNELS: usize = 0> {
    physical_link: P,
    basic_header_processor: channel::BasicHeaderProcessor,
    channels: alloc::vec::Vec<LeUChannelBuffer<B>>,
}

/// The number of channels that have a defined channel for a LE-U link within the Bluetooth Spec.
const LE_STATIC_CHANNEL_COUNT: usize = 3;

/// Index for the ATT channel within a `LeULogicalLink::channels`
const LE_LINK_ATT_CHANNEL_INDEX: usize = 0;

/// Index for the Signalling channel within a `LeULogicalLink::channels`
const LE_LINK_SIGNALLING_CHANNEL_INDEX: usize = 1;

/// Index for the Signalling channel within a `LeULogicalLink::channels`
const LE_LINK_SM_CHANNEL_INDEX: usize = 2;

impl<P, B> LeULogicalLink<P, B> {
    /// Create a new `LogicalLink`
    pub fn new(physical_link: P) -> Self {
        let basic_header_processor = channel::BasicHeaderProcessor::init();
        let channels = core::iter::repeat_with(|| LeUChannelBuffer::Unused)
            .take(LE_STATIC_CHANNEL_COUNT)
            .collect();

        Self {
            physical_link,
            basic_header_processor,
            channels,
        }
    }

    fn convert_dyn_index(&self, dyn_channel_id: DynChannelId<LeULink>) -> usize {
        3 + (dyn_channel_id.get_val() - *DynChannelId::<LeULink>::LE_BOUNDS.start()) as usize
    }

    /// Await for the next link event
    ///
    /// ## *Flow Control Credit Indication* Signal Processing
    ///
    /// `next` has the processing of the *flow control credit indication* L2CAP signal built into
    /// its returned future. Normally `next` will output a [`CreditIndication`] containing the
    /// number of credits given and the affected channel. However, before the channel is returned
    pub async fn next(&mut self) -> Result<Next<impl LogicalLink + '_>, LeULogicalLinkNextError<P, B>>
    where
        P: PhysicalLink,
        B: TryExtend<u8> + Default + IntoIterator<Item = u8>,
        B::IntoIter: ExactSizeIterator,
    {
        let mut expect_first_fragment = true;

        'outer: loop {
            let mut fragment = self
                .physical_link
                .recv()
                .await
                .ok_or(LeULogicalLinkNextError::Disconnected)?
                .map_err(|e| LeULogicalLinkNextError::ReceiveError(e))?;

            if expect_first_fragment && !fragment.start_fragment {
                return Err(LeULogicalLinkNextError::ExpectedStartingFragment);
            }

            let Some(basic_header) = self.basic_header_processor.process::<LeULink, _>(&mut fragment)? else {
                expect_first_fragment = false;

                continue 'outer;
            };

            expect_first_fragment = true;

            let mut unused = LeUChannelBuffer::Unused;

            let (index, mut recombiner) = match basic_header.channel_id {
                ChannelIdentifier::Le(LeCid::AttributeProtocol) => {
                    let recombiner = self.channels[LE_LINK_ATT_CHANNEL_INDEX].new_recombiner(&basic_header);

                    (LE_LINK_ATT_CHANNEL_INDEX, recombiner)
                }
                ChannelIdentifier::Le(LeCid::LeSignalingChannel) => {
                    let recombiner = self.channels[LE_LINK_SIGNALLING_CHANNEL_INDEX].new_recombiner(&basic_header);

                    (LE_LINK_SIGNALLING_CHANNEL_INDEX, recombiner)
                }
                ChannelIdentifier::Le(LeCid::SecurityManagerProtocol) => {
                    let recombiner = self.channels[LE_LINK_SM_CHANNEL_INDEX].new_recombiner(&basic_header);

                    (LE_LINK_SM_CHANNEL_INDEX, recombiner)
                }
                ChannelIdentifier::Le(LeCid::DynamicallyAllocated(dyn_channel_id)) => {
                    let index = self.convert_dyn_index(dyn_channel_id);

                    let recombiner = self
                        .channels
                        .get_mut(index)
                        .unwrap_or(&mut unused)
                        .new_recombiner(&basic_header);

                    (index, recombiner)
                }
                _ => (<usize>::MAX, unused.new_recombiner(&basic_header)),
            };

            'recombine: loop {
                match recombiner.add(&mut fragment.data) {
                    Err(e) => {
                        break 'outer match e {
                            PduRecombineAddError::AlreadyFinished => {
                                Err(LeULogicalLinkNextError::Internal("already finished"))
                            }
                            PduRecombineAddError::BasicChannel(e) => {
                                Err(LeULogicalLinkNextError::RecombineBasicFrame(e))
                            }
                            PduRecombineAddError::SignallingChannel(e) => {
                                Err(LeULogicalLinkNextError::RecombineControlFrame(e))
                            }
                            PduRecombineAddError::CreditBasedChannel(e) => {
                                Err(LeULogicalLinkNextError::RecombineCreditBasedFrame(e))
                            }
                        }
                    }
                    Ok(PduRecombineAddOutput::Ongoing) => {
                        fragment = self
                            .physical_link
                            .recv()
                            .await
                            .ok_or(LeULogicalLinkNextError::Disconnected)?
                            .map_err(|e| LeULogicalLinkNextError::ReceiveError(e))?;

                        if fragment.is_start_fragment() {
                            return Err(LeULogicalLinkNextError::UnexpectedStartingFragment);
                        }
                    }
                    Ok(PduRecombineAddOutput::DumpComplete) => break 'recombine,
                    Ok(PduRecombineAddOutput::BasicFrame(pdu)) => {
                        let handle = LeULogicalLinkHandle::new(self, index);

                        let channel = BasicFrameChannel::new(basic_header.channel_id, handle);

                        break 'outer Ok(Next::BasicFrame { pdu, channel });
                    }
                    Ok(PduRecombineAddOutput::ControlFrame(signal)) => {
                        // If this is a credit indication for an active credit based channel,
                        // return a Next::CreditIndication instead of a Next::ControlFrame.
                        if let ReceivedLeUSignal::FlowControlCreditIndication(credit_ind) = signal {
                            let channel_id = credit_ind.get_cid();

                            let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(id)) = channel_id else {
                                unreachable!("the channel ID should already be validated")
                            };

                            let index = self.convert_dyn_index(id);

                            let Some(LeUChannelBuffer::CreditBasedChannel { data: channel_data }) =
                                self.channels.get_mut(index)
                            else {
                                // ignore the credit indication
                                continue 'outer;
                            };

                            let credits = credit_ind.get_credits();

                            channel_data.add_peer_credits(credits);

                            let handle = LeULogicalLinkHandle::new(self, index);

                            let credits_given = credits.into();

                            let channel = CreditBasedChannel::new(basic_header.channel_id, handle);

                            break 'outer Ok(Next::CreditIndication { credits_given, channel });
                        } else {
                            let handle = LeULogicalLinkHandle::new(self, index);

                            let channel = SignallingChannel::new(basic_header.channel_id, handle);

                            break 'outer Ok(Next::ControlFrame { signal, channel });
                        }
                    }
                    Ok(PduRecombineAddOutput::CreditBasedFrame(pdu)) => {
                        let LeUChannelBuffer::CreditBasedChannel { data } = &mut self.channels[index] else {
                            unreachable!()
                        };

                        let Some(sdu) = data
                            .process_pdu(pdu)
                            .map_err(|e| LeULogicalLinkNextError::BufferOverflow(e))?
                        else {
                            continue 'outer;
                        };

                        let handle = LeULogicalLinkHandle::new(self, index);

                        let channel = CreditBasedChannel::new(basic_header.channel_id, handle);

                        break 'outer Ok(Next::ServiceData { sdu, channel });
                    }
                }
            }
        }
    }
}

/// The output of the future returned by [`LeULogicalLink::next`]
pub enum Next<L: LogicalLink> {
    BasicFrame {
        pdu: BasicFrame<L::Buffer>,
        channel: BasicFrameChannel<L>,
    },
    ControlFrame {
        signal: ReceivedLeUSignal,
        channel: SignallingChannel<L>,
    },
    ServiceData {
        sdu: L::Buffer,
        channel: CreditBasedChannel<L>,
    },
    CreditIndication {
        credits_given: usize,
        channel: CreditBasedChannel<L>,
    },
}

/// The error type returned by the method [`LeULogicalLink::next`]
pub enum LeULogicalLinkNextError<P: PhysicalLink, B: TryExtend<u8>> {
    ReceiveError(P::RecvErr),
    ExpectedStartingFragment,
    UnexpectedStartingFragment,
    Disconnected,
    BufferOverflow(B::Error),
    InvalidChannel(InvalidChannel),
    Internal(&'static str),
    RecombineBasicFrame(pdu::basic_frame::RecombineError),
    RecombineControlFrame(channel::signalling::ConvertSignalError),
    RecombineCreditBasedFrame(pdu::credit_frame::RecombineError),
}

impl<P, B> core::fmt::Debug for LeULogicalLinkNextError<P, B>
where
    P: PhysicalLink,
    B: TryExtend<u8>,
    P::RecvErr: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::ReceiveError(e) => f.debug_tuple(stringify!(ReceiveError)).field(e).finish(),
            Self::ExpectedStartingFragment => f.debug_tuple(stringify!(ExpectedStartingFragment)).finish(),
            Self::UnexpectedStartingFragment => f.debug_tuple(stringify!(UnexpectedStartingFragment)).finish(),
            Self::Disconnected => f.debug_tuple(stringify!(Disconnected)).finish(),
            Self::BufferOverflow(e) => f.debug_tuple(stringify!(BufferOverflow)).field(e).finish(),
            Self::InvalidChannel(c) => f.debug_tuple(stringify!(InvalidChannel)).field(c).finish(),
            Self::Internal(e) => f.debug_tuple(stringify!(Internal)).field(e).finish(),
            Self::RecombineBasicFrame(e) => f.debug_tuple(stringify!(RecombineBasicFrame)).field(e).finish(),
            Self::RecombineControlFrame(e) => f.debug_tuple(stringify!(RecombineControlFrame)).field(e).finish(),
            Self::RecombineCreditBasedFrame(e) => {
                f.debug_tuple(stringify!(RecombineCreditBasedFrame)).field(e).finish()
            }
        }
    }
}

impl<P: PhysicalLink, B: TryExtend<u8>> core::fmt::Display for LeULogicalLinkNextError<P, B>
where
    <P as PhysicalLink>::RecvErr: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            LeULogicalLinkNextError::ReceiveError(r) => write!(f, "receive error: {r}"),
            LeULogicalLinkNextError::ExpectedStartingFragment => {
                f.write_str("expected a starting fragment to start the PDU")
            }
            LeULogicalLinkNextError::UnexpectedStartingFragment => {
                f.write_str("unexpected starting L2CAP fragment when expecting continuing fragments for a PDU")
            }
            LeULogicalLinkNextError::Disconnected => f.write_str("disconnected"),
            LeULogicalLinkNextError::BufferOverflow(o) => write!(f, "buffer overflow: {o}"),
            LeULogicalLinkNextError::InvalidChannel(c) => write!(f, "invalid channel: {c}"),
            LeULogicalLinkNextError::Internal(i) => f.write_str(i),
            LeULogicalLinkNextError::RecombineBasicFrame(r) => write!(f, "recombine basic frame error: {r}"),
            LeULogicalLinkNextError::RecombineControlFrame(r) => write!(f, "recombine control frame error: {r}"),
            LeULogicalLinkNextError::RecombineCreditBasedFrame(r) => {
                write!(f, "recombine credit based frame error: {r}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl<P: PhysicalLink, B: TryExtend<u8>> std::error::Error for LeULogicalLinkNextError<P, B> where
    <P as PhysicalLink>::RecvErr: core::fmt::Display
{
}

impl<P: PhysicalLink, B: TryExtend<u8>> From<InvalidChannel> for LeULogicalLinkNextError<P, B> {
    fn from(error: InvalidChannel) -> Self {
        LeULogicalLinkNextError::InvalidChannel(error)
    }
}

/// Protocol and Service Multiplexers
///
/// This is a wrapper around the numerical number of the PSM. There are two ways to create a `Psm`.
/// One way is to convert one of the enumerations of
/// [`PsmAssignedNum`] into this, the other way is to create a dynamic PSM with the function
/// [`new_dyn`].
///
/// [`new_dyn`]: Psm::new_dyn
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
