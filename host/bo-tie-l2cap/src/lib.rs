//! Logical Link Control and Adaptation Protocol (L2CAP) Implementation
//!
//! This library specifically deals with the L2CAP layer of the Bluetooth Specification. L2CAP is
//! a middling layer so it the implementation needs to interface with the lower layers while
//! providing data integrity to the higher layers. The main job of all this is to manage data
//! fragmentation. Whenever data is sent from a higher layer to the L2CAP layer, the job of the
//! L2CAP implementation is to fragment the date into acceptable sizes by the lower layers.
//! Similarly, data from the lower layers needs to be recombined into data fit for the higher
//! layers.
//!
//! The rules and configuration for how data is processed by the L2CAP layer depend on the logical
//! link implementation and the logical link 'flavor'. 'flavor' is not something defined by this
//! library and not *directly* defined the Bluetooth Specification, but it's required for various
//! implementation details and signalling channel restrictions.
//!
//! Logical links' control the data transport and channel allocations. In order to create a logical
//! link it needs to be tied to the lower layers via the [`PhysicalLink`] trait. From the
//! perspective of the logical layer, the `PhysicalLink` is the direct I/O to the radio. In reality
//! the implementation is most likely a driver of the data transport toward the hardware of the
//! controller. The `PhysicalLink` trait has no differentiation between BR/EDR and LE, so its up to
//! you to ensure the right physical link implementation is used with the correct logical link.
//!
//! # LE-U Logical Link
//!
//! This interface between the LE physical layers and the LE host layers is done via the
//! [`LeULogicalLink`] type.
//!
//! ### `LeULogicalLink` Builder
//!
//! A `LeULogicalLink` must be constructed through its [`builder`](LeULogicalLink::builder) due to
//! buffering types that need to be set. If you look at the wrapping `impl` for `builder`, it has
//! the strange type of `LeULogicalLink<P, UnusedBuffer, UnusedBuffer>`. The generics of
//! `LeULogicalLink` are the `PhysicalLink`, the PDU buffer, and the SDU buffer in that order.
//! Technically both the PDU buffer and SDU buffer are optional, although in practice the PDU buffer
//! is usually defined. `UnusedBuffer` is essentially a marker type that returns an error whenever
//! it is attempted to be used as a buffer. The PDU buffer type needs to be redefined if the
//! Attribute, Security Manager, or dynamic channels are enabled or used. The SDU buffer type needs
//! to be redefined if dynamic channels are going to be used. The easiest way to do this is with the
//! `use_vec_*` methods of the builder.
//!
//! ```
//! # use bo_tie_l2cap::{LeULogicalLink, PhysicalLink};
//! # fn doc_test<P: PhysicalLink>(physical_link: P) {
//! let le_logical_link = LeULogicalLink::builder(physical_link)
//!     .enable_attribute_channel() // fixed channels can be enabled by the builder
//!     .enable_signalling_channel()
//!     .enable_security_manager_channel()
//!     .use_vec_buffer() // sets the PDU buffer as `Vec`
//!     .use_vec_sdu_buffer() // sets the SDU buffer as `Vec`
//!     .build();
//! # }
//! ```
//!
//! If you want to use a different type the `use_owned_*` methods used with a turbofish `::<_>` will
//! change the buffer type to a custom type.
//!
//! ```
//! # use bo_tie_l2cap::{LeULogicalLink, PhysicalLink};
//! # type MyOwnedBufferType = bo_tie_core::buffer::stack::LinearBuffer<0, u8>;
//! # fn doc_test<P: PhysicalLink>(physical_link: P) {
//! let le_logical_link = LeULogicalLink::builder(physical_link)
//!     .use_owned_buffer::<MyOwnedBufferType>()
//!     .use_owned_sdu_buffer::<MyOwnedBufferType>()
//!     .build();
//! # }
//! ```
//!
//! ### Channels
//!
//! Channels must be enabled before they can be used. They can either be enabled by the builder or
//! enabled/disabled by the `LeULogicalLink`. Once enabled the channel can be sent to and received
//! from.
//!
//! There is two ways to acquire a channel from a `LeULogicalLink`. The most obvious way is to use
//! the get methods. Fixed channels have their own get method, and dynamic channels can be acquired
//! via their channel identifier.
//!
//! ```
//! # use bo_tie_core::buffer::TryExtend;
//! # use bo_tie_l2cap::{LeULogicalLink, PhysicalLink};
//! # fn doc_test<P: PhysicalLink, B: TryExtend<u8> + Default, S>(mut le_logical_link: LeULogicalLink<P, B, S>) {
//! le_logical_link.enable_att_channel();
//!
//! // get methods return `None` if the channel is disabled
//! let att_channel = le_logical_link.get_att_channel().unwrap();
//! # }
//! ```
//!
//! Unfortunately dynamic channels are more complicated than just calling an enable method and begin
//! using them. There is a setup process to establishing a dynamic channel, see the dynamic channel
//! subsection for details.
//!
//! The other way to get a channel is after data is received for the channel. The next section goes
//! over that.
//!
//! ### Data Reception
//!
//! Data is received from another device using the future returned by the method
//! [`next`](LeULogicalLink::next). This future is a bit of a heavy processor, but its main purpose
//! is for recombining fragments into a complete L2CAP PDU or SDU and returning the data along with
//! the channel the data is for, with some exceptions.
//!
//! ```
//! # use bo_tie_core::buffer::stack::LinearBuffer;
//! # use bo_tie_l2cap::{LeULogicalLink, LeULogicalLinkNextError, LeUNext, PhysicalLink};
//! # async fn doc_test<P: PhysicalLink>(mut le_logical_link: LeULogicalLink<P, LinearBuffer<0, u8>, LinearBuffer<0, u8>>) -> Result<(), LeULogicalLinkNextError<P, LinearBuffer<0, u8>, LinearBuffer<0, u8>>> {
//! le_logical_link.enable_att_channel();
//! le_logical_link.enable_security_manager_channel();
//!
//! match le_logical_link.next().await? {
//!     LeUNext::AttributeChannel { pdu, channel } => {
//!         // process attribute protocol data
//!     },
//!     LeUNext::SecurityManagerChannel { pdu, channel } => {
//!         // process security manager protocol data
//!     },
//!     _ => unreachable!()
//! }
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;
mod channel;
pub mod link_flavor;
mod logical_link_private;
pub mod pdu;
pub mod signals;

use bo_tie_core::buffer::TryExtend;
use channel::id::{ChannelIdentifier, DynChannelId, LeCid};
use channel::signalling::ReceivedLeUSignal;
pub use channel::{
    id as cid, signalling, BasicFrameChannel, CreditBasedChannel, CreditServiceData, SendSduError, SignallingChannel,
};
use channel::{InvalidChannel, LeUChannelType, PduRecombineAddError, PduRecombineAddOutput};
use core::future::Future;
use link_flavor::LinkFlavor;
use link_flavor::{AclULink, LeULink};
use logical_link_private::LogicalLinkPrivate;
use logical_link_private::{LeULogicalLinkHandle, UnusedBuffer};
use pdu::L2capFragment;
use pdu::{BasicFrame, FragmentIterator, FragmentL2capPdu};

/// A Physical Link
///
/// The L2CAP implementation needs to map a logical link its corresponding physical link. This trait
/// must be implemented by a lower layer (than L2CAP) for each physical link supported by the
/// Controller.
pub trait PhysicalLink {
    /// Sending Future
    ///
    /// This future is used to await the transmission of data. It shall poll to completion when the
    /// lower layer can accept another L2CAP fragment. However, if something goes wrong when
    /// sending, the future shall complete and output an error.
    type SendFut<'a>: Future<Output = Result<(), Self::SendErr>>
    where
        Self: 'a;

    /// Send Error
    ///
    /// This error is returned by the lower layer whenever the future returned by [`send`] fails.
    ///
    /// [`send`]: PhysicalLink::send
    type SendErr: core::fmt::Debug;

    /// Reception Future
    ///
    /// This futures must be implemented to await for the reception of L2CAP fragments over the
    /// physical link. The future shall only output when a new L2CAP fragment should be sent to the
    /// L2CAP layer or an error occurs. However, if something goes wrong when awaiting or receiving,
    /// then the future shall complete and output an error.
    type RecvFut<'a>: Future<Output = Option<Result<L2capFragment<Self::RecvData>, Self::RecvErr>>>
    where
        Self: 'a;

    /// Received L2CAP Data
    ///
    /// `RecvData` is an exact-sized iterator over data of a *single* fragment of L2CAP data. The
    /// bytes of the data must be in the order in which they are received by the physical layer.
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

/// Builder for a `LeULogicalLink`
///
/// The main purpose of this is for setting the physical link and configuring the channels to be
/// used by built `LeULogicalLink`.
///
/// This can be created via the [`LeULogicalLink::builder`] method.
pub struct LeULogicalLinkBuilder<P, B, S> {
    physical_link: P,
    pdu_buffer: Option<B>,
    sdu_buffer: Option<S>,
    att_channel_enabled: bool,
    sig_channel_enabled: bool,
    sm_channel_enabled: bool,
    unused_responses: bool,
}

impl<P, B, S> LeULogicalLinkBuilder<P, B, S> {
    fn new(physical_link: P) -> Self {
        let pdu_buffer = None;
        let sdu_buffer = None;
        let att_channel_enabled = false;
        let sig_channel_enabled = false;
        let sm_channel_enabled = false;
        let unused_responses = false;

        LeULogicalLinkBuilder {
            physical_link,
            pdu_buffer,
            sdu_buffer,
            att_channel_enabled,
            sig_channel_enabled,
            sm_channel_enabled,
            unused_responses,
        }
    }

    /// Set the physical link
    ///
    /// The physical link is the interface to the radio layers for transmission and reception of
    /// LE-U pdu fragments. This is required to be called in order to use this link for sending or
    /// receiving to a connected device.
    pub fn set_physical_link<T>(self, physical_link: T) -> LeULogicalLinkBuilder<T, B, S> {
        LeULogicalLinkBuilder {
            physical_link,
            pdu_buffer: self.pdu_buffer,
            sdu_buffer: self.sdu_buffer,
            att_channel_enabled: self.att_channel_enabled,
            sig_channel_enabled: self.sig_channel_enabled,
            sm_channel_enabled: self.sm_channel_enabled,
            unused_responses: self.unused_responses,
        }
    }

    /// Set an owned buffer for storing a PDU
    ///
    /// This is used to set the type for buffering a PDU. The buffer is used to store fragments
    /// until the complete PDU is received. In order to call this method, a ‘turbofish’: `::<>`
    /// containing the buffering type is required.
    pub fn use_owned_buffer<T>(self) -> LeULogicalLinkBuilder<P, T, S>
    where
        T: TryExtend<u8> + Default + IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        LeULogicalLinkBuilder {
            physical_link: self.physical_link,
            pdu_buffer: None,
            sdu_buffer: self.sdu_buffer,
            att_channel_enabled: self.att_channel_enabled,
            sig_channel_enabled: self.sig_channel_enabled,
            sm_channel_enabled: self.sm_channel_enabled,
            unused_responses: self.unused_responses,
        }
    }

    /// Use a `Vec` for buffering a PDU
    ///
    /// This is equivalent to calling `.use_owned_buffer::<Vec<u8>>()`
    pub fn use_vec_buffer(self) -> LeULogicalLinkBuilder<P, alloc::vec::Vec<u8>, S> {
        self.use_owned_buffer()
    }

    /// Set an owned buffer for storing a SDU
    ///
    /// L2CAP connection channels (such as credit based channels) transfer data via a service data
    /// unit (SDU). The main point of a SDU is to be able to transfer data over multiple PDUs. Each
    /// connection channel must have its own buffer as PDUs of a SDU may not all be sent together by
    /// the linked peer device.
    pub fn use_owned_sdu_buffer<T>(self) -> LeULogicalLinkBuilder<P, B, T>
    where
        T: TryExtend<u8> + Default,
    {
        LeULogicalLinkBuilder {
            physical_link: self.physical_link,
            pdu_buffer: self.pdu_buffer,
            sdu_buffer: None,
            att_channel_enabled: self.att_channel_enabled,
            sig_channel_enabled: self.sig_channel_enabled,
            sm_channel_enabled: self.sm_channel_enabled,
            unused_responses: self.unused_responses,
        }
    }

    /// Use `Vec` for buffering SDUs
    ///
    /// This is equivalent to calling `.use_owned_sdu_buffer::<Vec<u8>>()`
    pub fn use_vec_sdu_buffer(self) -> LeULogicalLinkBuilder<P, B, alloc::vec::Vec<u8>> {
        self.use_owned_sdu_buffer()
    }

    /// Enable the Attribute Channel
    pub fn enable_attribute_channel(mut self) -> LeULogicalLinkBuilder<P, B, S> {
        self.att_channel_enabled = true;
        self
    }

    /// Enable the Signalling Channel
    pub fn enable_signalling_channel(mut self) -> Self {
        self.sig_channel_enabled = true;
        self
    }

    /// Enable the Security Manager Channel
    pub fn enable_security_manager_channel(mut self) -> Self {
        self.sm_channel_enabled = true;
        self
    }

    /// Enable unused responses
    ///
    /// This enables a default response for unenabled fixed channels of this logical link.
    ///
    /// The actual response is relevant to the fixed channel.
    pub fn enable_unused_fixed_channel_response(mut self) -> Self {
        self.unused_responses = true;
        self
    }

    /// Build the `LeULogicalLink`
    pub fn build(self) -> LeULogicalLink<P, B, S>
    where
        B: Default,
    {
        let physical_link = self.physical_link;

        let basic_header_processor = channel::BasicHeaderProcessor::init();

        let mut channels: alloc::vec::Vec<LeUChannelType<S>> = core::iter::repeat_with(|| LeUChannelType::Unused)
            .take(LE_STATIC_CHANNEL_COUNT)
            .collect();

        if self.att_channel_enabled {
            channels[LE_LINK_ATT_CHANNEL_INDEX] = LeUChannelType::BasicChannel
        }

        if self.sig_channel_enabled {
            channels[LE_LINK_SIGNALLING_CHANNEL_INDEX] = LeUChannelType::SignallingChannel
        }

        if self.sm_channel_enabled {
            channels[LE_LINK_SM_CHANNEL_INDEX] = LeUChannelType::BasicChannel
        }

        let unused_responses = self.unused_responses;

        let pdu_buffer = B::default();

        LeULogicalLink {
            physical_link,
            pdu_buffer,
            basic_header_processor,
            channels,
            unused_responses,
        }
    }
}

/// A LE-U Logical Link
///
/// This is the logical link for two devices connected via Bluetooth LE. Channels can be created for
/// the link through the methods `LeULogicalLink`.
///
/// A `LeULogicalLink` requires a `PhysicalLink` to be created. This `PhysicalLink` is a trait that
/// is either directly implemented by the physical layer or some interface to the physical layer
/// (typically a host controller interface (HCI) implementation).
#[derive(Debug)]
pub struct LeULogicalLink<P, B, S> {
    physical_link: P,
    pdu_buffer: B,
    basic_header_processor: channel::BasicHeaderProcessor,
    channels: alloc::vec::Vec<LeUChannelType<S>>,
    unused_responses: bool,
}

/// The number of channels that have a defined channel for a LE-U link within the Bluetooth Spec.
const LE_STATIC_CHANNEL_COUNT: usize = 3;

/// The number of dynamic channels available for a LE-U link
const LE_DYNAMIC_CHANNEL_COUNT: usize =
    1 + (*DynChannelId::<LeULink>::LE_BOUNDS.end() - *DynChannelId::<LeULink>::LE_BOUNDS.start()) as usize;

/// Index for the ATT channel within a `LeULogicalLink::channels`
const LE_LINK_ATT_CHANNEL_INDEX: usize = 0;

/// Index for the Signalling channel within a `LeULogicalLink::channels`
const LE_LINK_SIGNALLING_CHANNEL_INDEX: usize = 1;

/// Index for the Signalling channel within a `LeULogicalLink::channels`
const LE_LINK_SM_CHANNEL_INDEX: usize = 2;

impl<P> LeULogicalLink<P, UnusedBuffer, UnusedBuffer> {
    /// Get a builder for a `LogicalLink`
    ///
    /// # Panic
    /// This panics if the maximum transfer size of the physical link is zero
    pub fn builder(physical_link: P) -> LeULogicalLinkBuilder<P, UnusedBuffer, UnusedBuffer>
    where
        P: PhysicalLink,
    {
        assert_ne!(
            0,
            physical_link.max_transmission_size(),
            "the maximum transmission size of the physical link cannot be zero"
        );

        LeULogicalLinkBuilder::new(physical_link)
    }
}

impl<P, B, S> LeULogicalLink<P, B, S> {
    /// Enable the Attribute protocol channel
    pub fn enable_att_channel(&mut self) {
        self.channels[LE_LINK_ATT_CHANNEL_INDEX] = LeUChannelType::BasicChannel;
    }

    /// Disable the Attribute protocol channel
    pub fn disable_att_channel(&mut self) {
        self.channels[LE_LINK_ATT_CHANNEL_INDEX] = LeUChannelType::Unused
    }

    /// Get the Attribute Channel
    ///
    /// The Attribute channel is returned if it was enabled.
    pub fn get_att_channel(&mut self) -> Option<BasicFrameChannel<LeULogicalLinkHandle<'_, P, B, S>>>
    where
        P: PhysicalLink,
        B: Default,
    {
        if let LeUChannelType::BasicChannel { .. } = &self.channels[LE_LINK_ATT_CHANNEL_INDEX] {
            let handle = LeULogicalLinkHandle::new(self, LE_LINK_ATT_CHANNEL_INDEX);

            Some(BasicFrameChannel::new(
                ChannelIdentifier::Le(LeCid::AttributeProtocol),
                handle,
            ))
        } else {
            None
        }
    }

    /// Enable the signalling channel
    pub fn enable_signalling_channel(&mut self) {
        self.channels[LE_LINK_SIGNALLING_CHANNEL_INDEX] = LeUChannelType::SignallingChannel;
    }

    /// Disable the signalling channel
    pub fn disable_signalling_channel(&mut self) {
        self.channels[LE_LINK_SIGNALLING_CHANNEL_INDEX] = LeUChannelType::Unused
    }

    /// Get the Signalling Channel
    ///
    /// The Signalling channel is returned if it was enabled.
    pub fn get_signalling_channel(&mut self) -> Option<SignallingChannel<LeULogicalLinkHandle<'_, P, B, S>>>
    where
        P: PhysicalLink,
        B: Default,
    {
        if let LeUChannelType::SignallingChannel = &self.channels[LE_LINK_SIGNALLING_CHANNEL_INDEX] {
            let handle = LeULogicalLinkHandle::new(self, LE_LINK_SIGNALLING_CHANNEL_INDEX);

            Some(SignallingChannel::new(
                ChannelIdentifier::Le(LeCid::LeSignalingChannel),
                handle,
            ))
        } else {
            None
        }
    }

    /// Enable the Security Manager channel
    pub fn enable_security_manager_channel(&mut self) {
        self.channels[LE_LINK_SM_CHANNEL_INDEX] = LeUChannelType::BasicChannel
    }

    /// Disable the Security Manager channel
    pub fn disable_security_manager_channel(&mut self) {
        self.channels[LE_LINK_SM_CHANNEL_INDEX] = LeUChannelType::Unused
    }

    /// Get the Security Manager Channel
    ///
    /// This Security Manager channel is returned if it was enabled.
    pub fn get_security_manager_channel(&mut self) -> Option<BasicFrameChannel<LeULogicalLinkHandle<'_, P, B, S>>>
    where
        P: PhysicalLink,
        B: Default,
    {
        if let LeUChannelType::BasicChannel { .. } = &self.channels[LE_LINK_SM_CHANNEL_INDEX] {
            let handle = LeULogicalLinkHandle::new(self, LE_LINK_SM_CHANNEL_INDEX);

            Some(BasicFrameChannel::new(
                ChannelIdentifier::Le(LeCid::SecurityManagerProtocol),
                handle,
            ))
        } else {
            None
        }
    }

    /// Get a Credit Based Channel
    ///
    /// This returns a Credit Based channel if a connection for the channel has been established.
    ///
    /// # Note
    /// `None` is also returned if `channel_identifier` is not a valid channel ID for a credit based
    /// channel.
    pub fn get_credit_based_channel(
        &mut self,
        channel_identifier: ChannelIdentifier,
    ) -> Option<CreditBasedChannel<LeULogicalLinkHandle<'_, P, B, S>>>
    where
        P: PhysicalLink,
        B: Default,
    {
        let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(dyn_channel_id)) = channel_identifier else {
            return None;
        };

        let index = self.convert_dyn_index(dyn_channel_id);

        if let Some(LeUChannelType::CreditBasedChannel { .. }) = self.channels.get(index) {
            let handle = LeULogicalLinkHandle::new(self, index);

            Some(CreditBasedChannel::new(channel_identifier, handle))
        } else {
            None
        }
    }

    /// Enable/Disable unused responses
    ///
    /// This is used to enable or disable the unused response for the fixed channels of a LE-U link.
    /// The unused responses are disabled by default, so this method must be called in enable them.  
    ///
    /// Fixed channels *should* have a default response event if they are not used. This can be done
    /// either by enabling all the fixed channels and handling a default response yourself or by
    /// calling this method with input `enable` as true.
    ///
    /// If this is called with `true` the following responses are sent back when a disabled fixed
    /// channel receives data.
    ///
    /// | Channel                  | Response |
    /// | --- | --- |
    /// | Attribute Channel        | ATT_ERROR_RSP with error code 'Request Not Supported` |
    /// | Signalling Channel       | L2CAP_COMMAND_REJECT_RSP with reason 'Command not Understood' |
    /// | Security Manager Channel | 'Pairing Failed' with reason 'Pairing Not Supported' |
    ///
    /// These responses are only send for **disabled channels**, as soon as one of
    /// [`enable_att_channel`], [`enable_signalling_channel`], [`enable_security_manager_channel`],
    /// is called the associated channel will no longer be responded with a default response.
    ///
    /// [`next`]: LeULogicalLink::next
    /// [`enable_att_channel`]: LeULogicalLink::enable_att_channel
    /// [`enable_signalling_channel`]: LeULogicalLink::enable_signalling_channel
    /// [`enable_security_manager_channel`]: LeULogicalLink::enable_security_manager_channel
    pub fn unused_responses(&mut self, enable: bool) {
        self.unused_responses = enable
    }

    fn convert_dyn_index(&self, dyn_channel_id: DynChannelId<LeULink>) -> usize {
        3 + (dyn_channel_id.get_val() - *DynChannelId::<LeULink>::LE_BOUNDS.start()) as usize
    }

    /// Receive the next event from the LE-U logical link
    ///
    /// This returns a future for waiting until the logical link is ready to transfer an event to
    /// the higher layers.  
    ///
    /// # Events
    ///
    /// Events are defined by this `method`. An event occurs whenever the logical link is ready to
    /// give data it has to a higher layer. The following are events output by the `next` future.
    ///
    /// ## Complete PDU or SDU data
    ///
    /// Upon the reception of data from the Bluetooth protocol layers below the L2CAP layer, `next`
    /// will take the data and recombine it into a complete PDU or SDU depending on the data type
    /// used by channel. It will then output it with the channel and data type.
    ///
    /// ## *Flow Control Credit Indication* Signal Processing
    ///
    /// `next` has the processing of the *flow control credit indication* L2CAP signal built into
    /// its returned future. Normally `next` will output a [`CreditIndication`] containing the
    /// number of credits given and the affected channel. However, before the channel is returned
    pub async fn next(&mut self) -> Result<LeUNext<'_, P, B, S>, LeULogicalLinkNextError<P, B, S>>
    where
        P: PhysicalLink,
        B: TryExtend<u8> + Default + IntoIterator<Item = u8>,
        B::IntoIter: ExactSizeIterator,
        S: TryExtend<u8> + Default,
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

            let mut unused = LeUChannelType::Unused;

            let (index, mut recombiner) = match basic_header.channel_id {
                ChannelIdentifier::Le(LeCid::AttributeProtocol) => {
                    let recombiner =
                        self.channels[LE_LINK_ATT_CHANNEL_INDEX].new_recombiner(&mut self.pdu_buffer, &basic_header);

                    (LE_LINK_ATT_CHANNEL_INDEX, recombiner)
                }
                ChannelIdentifier::Le(LeCid::LeSignalingChannel) => {
                    let recombiner = self.channels[LE_LINK_SIGNALLING_CHANNEL_INDEX]
                        .new_recombiner(&mut self.pdu_buffer, &basic_header);

                    (LE_LINK_SIGNALLING_CHANNEL_INDEX, recombiner)
                }
                ChannelIdentifier::Le(LeCid::SecurityManagerProtocol) => {
                    let recombiner =
                        self.channels[LE_LINK_SM_CHANNEL_INDEX].new_recombiner(&mut self.pdu_buffer, &basic_header);

                    (LE_LINK_SM_CHANNEL_INDEX, recombiner)
                }
                ChannelIdentifier::Le(LeCid::DynamicallyAllocated(dyn_channel_id)) => {
                    let index = self.convert_dyn_index(dyn_channel_id);

                    let recombiner = self
                        .channels
                        .get_mut(index)
                        .unwrap_or(&mut unused)
                        .new_recombiner(&mut self.pdu_buffer, &basic_header);

                    (index, recombiner)
                }
                _ => (<usize>::MAX, unused.new_recombiner(&mut self.pdu_buffer, &basic_header)),
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
                            .ok_or_else(|| LeULogicalLinkNextError::Disconnected)?
                            .map_err(|e| LeULogicalLinkNextError::ReceiveError(e))?;

                        if fragment.is_start_fragment() {
                            return Err(LeULogicalLinkNextError::UnexpectedStartingFragment);
                        }
                    }
                    Ok(PduRecombineAddOutput::DumpComplete) => break 'recombine,
                    Ok(PduRecombineAddOutput::UnusedComplete(unused)) => {
                        if self.unused_responses {
                            self.physical_link
                                .send_pdu(unused, self.physical_link.max_transmission_size().into())
                                .await
                                .map_err(|e| LeULogicalLinkNextError::SendUnusedError(e))?;
                        }

                        break 'recombine;
                    }
                    Ok(PduRecombineAddOutput::BasicFrame(pdu)) => {
                        let handle = LeULogicalLinkHandle::new(self, index);

                        let channel = BasicFrameChannel::new(basic_header.channel_id, handle);

                        match basic_header.channel_id {
                            ChannelIdentifier::Le(LeCid::AttributeProtocol) => {
                                break 'outer Ok(LeUNext::AttributeChannel { pdu: pdu, channel })
                            }
                            ChannelIdentifier::Le(LeCid::SecurityManagerProtocol) => {
                                break 'outer Ok(LeUNext::SecurityManagerChannel { pdu, channel })
                            }
                            _ => unreachable!(),
                        }
                    }
                    Ok(PduRecombineAddOutput::ControlFrame(signal)) => {
                        match &signal {
                            ReceivedLeUSignal::FlowControlCreditIndication(credit_ind) => {
                                // If this is a credit indication for an active credit based channel,
                                // return a Next::CreditIndication instead of a Next::ControlFrame.
                                let channel_id = credit_ind.get_cid();

                                let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(id)) = channel_id else {
                                    unreachable!("the channel ID should already be validated")
                                };

                                let index = self.convert_dyn_index(id);

                                let Some(LeUChannelType::CreditBasedChannel { data: channel_data }) =
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

                                break 'outer Ok(LeUNext::CreditIndication { credits_given, channel });
                            }
                            _ => {
                                let handle = LeULogicalLinkHandle::new(self, index);

                                let channel = SignallingChannel::new(basic_header.channel_id, handle);

                                break 'outer Ok(LeUNext::SignallingChannel { signal, channel });
                            }
                        }
                    }
                    Ok(PduRecombineAddOutput::CreditBasedFrame(pdu)) => {
                        let LeUChannelType::CreditBasedChannel { data } = &mut self.channels[index] else {
                            unreachable!()
                        };

                        let Some(sdu) = data
                            .process_pdu(pdu)
                            .map_err(|e| LeULogicalLinkNextError::SduBufferOverflow(e))?
                        else {
                            continue 'outer;
                        };

                        let handle = LeULogicalLinkHandle::new(self, index);

                        let channel = CreditBasedChannel::new(basic_header.channel_id, handle);

                        break 'outer Ok(LeUNext::CreditBasedChannel { sdu, channel });
                    }
                }
            }
        }
    }
}

/// The output of the future returned by [`LeULogicalLink::next`]
#[derive(Debug)]
pub enum LeUNext<'a, P, B, S> {
    AttributeChannel {
        pdu: BasicFrame<B>,
        channel: BasicFrameChannel<LeULogicalLinkHandle<'a, P, B, S>>,
    },
    SignallingChannel {
        signal: ReceivedLeUSignal,
        channel: SignallingChannel<LeULogicalLinkHandle<'a, P, B, S>>,
    },
    SecurityManagerChannel {
        pdu: BasicFrame<B>,
        channel: BasicFrameChannel<LeULogicalLinkHandle<'a, P, B, S>>,
    },
    CreditBasedChannel {
        sdu: S,
        channel: CreditBasedChannel<LeULogicalLinkHandle<'a, P, B, S>>,
    },
    CreditIndication {
        credits_given: usize,
        channel: CreditBasedChannel<LeULogicalLinkHandle<'a, P, B, S>>,
    },
}

/// The error type returned by the method [`LeULogicalLink::next`]
pub enum LeULogicalLinkNextError<P: PhysicalLink, B: TryExtend<u8>, S: TryExtend<u8>> {
    ReceiveError(P::RecvErr),
    SendUnusedError(P::SendErr),
    ExpectedStartingFragment,
    UnexpectedStartingFragment,
    Disconnected,
    PduBufferOverflow(B::Error),
    SduBufferOverflow(S::Error),
    InvalidChannel(InvalidChannel),
    Internal(&'static str),
    RecombineBasicFrame(pdu::basic_frame::RecombineError),
    RecombineControlFrame(channel::signalling::ConvertSignalError),
    RecombineCreditBasedFrame(pdu::credit_frame::RecombineError),
}

impl<P, B, S> core::fmt::Debug for LeULogicalLinkNextError<P, B, S>
where
    P: PhysicalLink,
    B: TryExtend<u8>,
    S: TryExtend<u8>,
    P::RecvErr: core::fmt::Debug,
    P::SendErr: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::ReceiveError(e) => f.debug_tuple(stringify!(ReceiveError)).field(e).finish(),
            Self::SendUnusedError(e) => f.debug_tuple(stringify!(SendUnusedError)).field(e).finish(),
            Self::ExpectedStartingFragment => f.debug_tuple(stringify!(ExpectedStartingFragment)).finish(),
            Self::UnexpectedStartingFragment => f.debug_tuple(stringify!(UnexpectedStartingFragment)).finish(),
            Self::Disconnected => f.debug_tuple(stringify!(Disconnected)).finish(),
            Self::PduBufferOverflow(e) => f.debug_tuple(stringify!(PduBufferOverflow)).field(e).finish(),
            Self::SduBufferOverflow(e) => f.debug_tuple(stringify!(SduBufferOverflow)).field(e).finish(),
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

impl<P, B, S> core::fmt::Display for LeULogicalLinkNextError<P, B, S>
where
    P: PhysicalLink,
    P::RecvErr: core::fmt::Display,
    P::SendErr: core::fmt::Display,
    B: TryExtend<u8>,
    S: TryExtend<u8>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            LeULogicalLinkNextError::ReceiveError(r) => write!(f, "receive error: {r}"),
            LeULogicalLinkNextError::SendUnusedError(s) => {
                write!(f, "failed to send rejection response for unused channel: {s}")
            }
            LeULogicalLinkNextError::ExpectedStartingFragment => {
                f.write_str("expected a starting fragment to start the PDU")
            }
            LeULogicalLinkNextError::UnexpectedStartingFragment => {
                f.write_str("unexpected starting L2CAP fragment when expecting continuing fragments for a PDU")
            }
            LeULogicalLinkNextError::Disconnected => f.write_str("disconnected"),
            LeULogicalLinkNextError::PduBufferOverflow(o) => write!(f, "PDU buffer overflow: {o}"),
            LeULogicalLinkNextError::SduBufferOverflow(o) => write!(f, "SDU buffer overflow: {o}"),
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
impl<P, B, S> std::error::Error for LeULogicalLinkNextError<P, B, S>
where
    P: PhysicalLink,
    P::RecvErr: core::fmt::Display + core::fmt::Debug,
    P::SendErr: core::fmt::Display + core::fmt::Debug,
    B: TryExtend<u8>,
    S: TryExtend<u8>,
{
}

impl<P, B, S> From<InvalidChannel> for LeULogicalLinkNextError<P, B, S>
where
    P: PhysicalLink,
    B: TryExtend<u8>,
    S: TryExtend<u8>,
{
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
/// larger than 0x1000.
///
/// ### NotOdd
/// All PSM values must be odd, the value provided was even
///
/// ### Extended
/// The least significant bit of the most significant byte (aka bit 8) must be 0 unless you want
/// an extended PSM (but I don't know what that is as I don't want to pay for ISO 3309 to find out
/// what that is). For now extended PSM is not supported.
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

/// tests require
#[cfg(test)]
mod tests {
    use crate::{LE_DYNAMIC_CHANNEL_COUNT, LE_STATIC_CHANNEL_COUNT};

    #[test]
    fn check_channel_ranges() {
        assert_eq!(3, LE_STATIC_CHANNEL_COUNT);

        assert_eq!(0x40, LE_DYNAMIC_CHANNEL_COUNT);
    }
}
