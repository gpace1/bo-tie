//! Signalling Channel implementation

use crate::channels::{AclCid, ChannelIdentifier, LeCid};
use crate::connection_channel::{CreditBasedChannel, HeadedFragment, MaybeRecvError, SharedPhysicalLink};
use crate::pdu::control_frame::RecombineError;
use crate::pdu::{
    ControlFrame, FragmentIterator, FragmentL2capPdu, L2capFragment, RecombineL2capPdu, RecombinePayloadIncrementally,
};
use crate::signals::packets::{
    CommandRejectResponse, FlowControlCreditInd, LeCreditBasedConnectionRequest, LeCreditBasedConnectionResponse,
    LeCreditMps, LeCreditMtu, Signal, SignalCode,
};
use crate::{LeULogicalLink, PhysicalLink};
use bo_tie_core::buffer::stack::LinearBuffer;
use bo_tie_core::buffer::TryExtend;
use core::fmt::Formatter;
use std::num::NonZeroU8;

/// A Signalling Channel
///
/// L2CAP has two Signalling Channels, one for an ACL-U logical link and one for a LE-U logical
/// link. This type is used for either of the two.
///
/// For a LE-U logical link, a Signalling Channel can be created via the [`get_signalling_channel`]
/// method of `LeULogicalLink`
///
/// [`get_signalling_channel`]: crate::LeULogicalLink::get_signalling_channel
pub struct SignallingChannel<'a, P: PhysicalLink> {
    channel_id: ChannelIdentifier,
    link_lock: &'a SharedPhysicalLink<P>,
    awaiting_response: bool,
}

impl<'a, P: PhysicalLink> SignallingChannel<'a, P> {
    pub(crate) fn new(channel_id: ChannelIdentifier, link_lock: &'a SharedPhysicalLink<P>) -> Self {
        assert!(link_lock.add_channel(channel_id), "channel already exists");

        let awaiting_response = false;

        Self {
            channel_id,
            link_lock,
            awaiting_response,
        }
    }
}

impl<P: PhysicalLink> SignallingChannel<'_, P> {
    /// Get fragmentation size of L2CAP PDUs
    ///
    /// This returns the maximum payload of the underlying [`PhysicalLink`] of this connection
    /// channel. Every L2CAP PDU is fragmented to this in both sending a receiving of L2CAP data.
    pub fn fragmentation_size(&self) -> usize {
        unsafe { &*self.link_lock.physical_link.get() }.max_transmission_size()
    }

    async fn send_fragment<T>(&mut self, fragment: L2capFragment<T>) -> Result<(), P::SendErr>
    where
        T: IntoIterator<Item = u8>,
    {
        let mut fragment = Some(L2capFragment {
            start_fragment: fragment.start_fragment,
            data: fragment.data.into_iter(),
        });

        core::future::poll_fn(move |_| self.link_lock.maybe_send(self.channel_id, fragment.take().unwrap()))
            .await
            .await
    }

    async fn receive_fragment(&mut self) -> Result<HeadedFragment<P::RecvData>, MaybeRecvError<P::RecvErr>> {
        let mut poll = Some(
            match core::future::poll_fn(|_| self.link_lock.maybe_recv(self.channel_id))
                .await
                .await
            {
                Ok(f) => f,
                Err(e) => {
                    self.link_lock.clear_owner();

                    return Err(e);
                }
            },
        );

        Ok(core::future::poll_fn(move |_| poll.take().unwrap()).await)
    }

    /// Send a Signal
    ///
    /// This is used to send a L2CAP Basic Frame PDU from the Host to a linked device. This method
    /// may be called by protocol at a higher layer than L2CAP.
    async fn send(&mut self, c_frame: impl FragmentL2capPdu) -> Result<(), P::SendErr> {
        let mut is_first = true;

        let mut fragments_iter = c_frame.into_fragments(self.fragmentation_size()).unwrap();

        while let Some(data) = fragments_iter.next() {
            let fragment = L2capFragment::new(is_first, data);

            is_first = false;

            self.send_fragment(fragment).await?;
        }

        // clear owner as the full PDU was sent
        self.link_lock.clear_owner();

        Ok(())
    }

    /// Receive a Signal on this Channel
    ///
    /// This awaits for a signal to be received by this channel. The output `ReceivedSignal` is an
    /// enum of the signal type that was received.
    ///
    /// ```
    /// # use std::future::Future;
    /// use bo_tie_l2cap::{LeULogicalLink, SignallingChannel};
    /// use bo_tie_l2cap::connection_channel::signalling::ReceivedSignal;
    ///
    /// # fn link<P: bo_tie_l2cap::PhysicalLink>(link: LeULogicalLink<P>) -> impl Future + Send {
    /// # async move {
    ///     let mut signalling_channel = link.get_signalling_channel();
    ///
    ///     // maybe put this in a loop
    ///     match signalling_channel.receive().await? {
    ///         ReceivedSignal::UnknownSignal(_, rsp) => {
    ///             rsp.send_rejection(&mut signalling_channel).await?;
    ///         }
    ///         
    ///         // process other signals
    ///         
    ///         _ => (), // ignored signals
    ///     }
    /// # }}
    /// ```
    pub async fn receive(&mut self) -> Result<ReceivedSignal, ReceiveSignalError<P>> {
        let fragment = self.receive_fragment().await?;

        if !fragment.fragment.is_start_fragment() {
            self.link_lock.clear_owner();

            return Err(ReceiveSignalError::ExpectedFirstFragment);
        }

        let mut recombiner =
            ControlFrame::<ReceiveSignalRecombineBuilder>::recombine(fragment.length, fragment.channel_id, &mut ());

        let c_frame = if let Some(c_frame) = recombiner.add(fragment.fragment.data).map_err(|e| {
            self.link_lock.clear_owner();

            e
        })? {
            c_frame
        } else {
            loop {
                let fragment = self.receive_fragment().await?;

                if fragment.fragment.is_start_fragment() {
                    self.link_lock.clear_owner();

                    return Err(ReceiveSignalError::UnexpectedFirstFragment);
                }

                if let Some(c_frame) = recombiner.add(fragment.fragment.data)? {
                    self.link_lock.clear_owner();

                    break c_frame;
                }
            }
        };

        let received_signal = match self.channel_id {
            ChannelIdentifier::Acl(AclCid::SignalingChannel) => {
                ReceivedSignal::try_from::<crate::AclULinkType>(c_frame.into_payload())?
            }
            ChannelIdentifier::Le(LeCid::LeSignalingChannel) => {
                ReceivedSignal::try_from::<crate::LeULinkType>(c_frame.into_payload())?
            }
            _ => unreachable!(),
        };

        Ok(received_signal)
    }

    /// Initialize a LE Credit Based Connection
    ///
    /// This will send the request to create a LE credit based connection with the linked device. A
    /// connection is not completed until a response is received via the method [`receive`].
    pub async fn init_le_credit_connection(
        &mut self,
        request: &LeCreditBasedConnectionRequest,
    ) -> Result<(), P::SendErr> {
        self.awaiting_response = true;

        let control_frame = request.as_control_frame(self.channel_id);

        self.send(control_frame).await
    }
}

impl<P: PhysicalLink> Drop for SignallingChannel<'_, P> {
    fn drop(&mut self) {
        self.link_lock.remove_channel(self.channel_id)
    }
}

/// Signal received from the linked device
#[non_exhaustive]
pub enum ReceivedSignal {
    /// `UnknownSignal` is used when a signal that cannot be interpreted by this L2CAP
    /// implementation is received by this device.
    ///
    /// # Fields
    /// `u8` => the signal that was not understood.
    /// `Request<CommandRejectResponse>` => This is always a command reject response containing the
    ///    *command not understood* reason. This response is generated by this L2CAP signalling
    ///    implementation in response to the unknown signal and not actually received.
    UnknownSignal(u8, Request<CommandRejectResponse>),
    CommandRejectRsp(Response<CommandRejectResponse>),
    LeCreditBasedConnectionRequest(Request<LeCreditBasedConnectionRequest>),
    LeCreditBasedConnectionResponse(Response<LeCreditBasedConnectionResponse>),
    FlowControlCreditIndication(FlowControlCreditInd),
}

impl ReceivedSignal {
    fn try_from<L>(builder: ReceiveSignalRecombineBuilder) -> Result<Self, ConvertSignalError>
    where
        L: crate::private::LinkType,
    {
        match &builder {
            ReceiveSignalRecombineBuilder::Init => Err(ConvertSignalError::IncompleteSignal),
            ReceiveSignalRecombineBuilder::Unknown(unknown) => {
                let signal_code = *unknown.header.get(0).unwrap();

                let command_reject = CommandRejectResponse::new_command_not_understood(
                    unknown.get_identifier().ok_or(ConvertSignalError::IncompleteSignal)?,
                );

                let request = Request::new(command_reject);

                Ok(ReceivedSignal::UnknownSignal(signal_code, request))
            }
            ReceiveSignalRecombineBuilder::CommandRejectRsp(raw) => {
                CommandRejectResponse::try_from_raw_control_frame::<L>(raw)
                    .map(|s| ReceivedSignal::CommandRejectRsp(Response::new(s)))
                    .map_err(|_| ConvertSignalError::InvalidFormat(SignalCode::CommandRejectResponse))
            }
            ReceiveSignalRecombineBuilder::LeCreditBasedConnectionRequest(raw) => {
                LeCreditBasedConnectionRequest::try_from_raw_control_frame(raw)
                    .map(|s| ReceivedSignal::LeCreditBasedConnectionRequest(Request::new(s)))
                    .map_err(|_| ConvertSignalError::InvalidFormat(SignalCode::LeCreditBasedConnectionRequest))
            }
            ReceiveSignalRecombineBuilder::LeCreditBasedConnectionResponse(raw) => {
                LeCreditBasedConnectionResponse::try_from_raw_control_frame(raw)
                    .map(|s| ReceivedSignal::LeCreditBasedConnectionResponse(Response::new(s)))
                    .map_err(|_| ConvertSignalError::InvalidFormat(SignalCode::LeCreditBasedConnectionResponse))
            }
            ReceiveSignalRecombineBuilder::FlowControlCreditIndication(raw) => {
                FlowControlCreditInd::try_from_raw_control_frame(raw)
                    .map(|s| ReceivedSignal::FlowControlCreditIndication(s))
                    .map_err(|_| ConvertSignalError::InvalidFormat(SignalCode::FlowControlCreditIndication))
            }
        }
    }
}

/// Receive Error
///
/// This error is returned by the method [`receive`] of `SignallingChannel`.
///
/// [`receive`]: SignallingChannel::receive
#[derive(Debug)]
pub enum ReceiveSignalError<P: PhysicalLink> {
    RecvErr(P::RecvErr),
    InvalidChannel(crate::connection_channel::InvalidChannel),
    Convert(ConvertSignalError),
    Recombine(RecombineError),
    ExpectedFirstFragment,
    UnexpectedFirstFragment,
}

impl<P: PhysicalLink> core::fmt::Display for ReceiveSignalError<P>
where
    P::RecvErr: core::fmt::Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            ReceiveSignalError::RecvErr(e) => write!(f, "failed to receive signal, {e}"),
            ReceiveSignalError::InvalidChannel(c) => core::fmt::Display::fmt(c, f),
            ReceiveSignalError::Convert(c) => core::fmt::Display::fmt(c, f),
            ReceiveSignalError::Recombine(r) => core::fmt::Display::fmt(r, f),
            ReceiveSignalError::ExpectedFirstFragment => f.write_str("expected first fragment of PDU"),
            ReceiveSignalError::UnexpectedFirstFragment => f.write_str("unexpected first fragment of PDU"),
        }
    }
}

impl<P: PhysicalLink> From<MaybeRecvError<P::RecvErr>> for ReceiveSignalError<P> {
    fn from(value: MaybeRecvError<P::RecvErr>) -> Self {
        match value {
            MaybeRecvError::RecvError(e) => ReceiveSignalError::RecvErr(e),
            MaybeRecvError::InvalidChannel(c) => ReceiveSignalError::InvalidChannel(c),
        }
    }
}

impl<P: PhysicalLink> From<ConvertSignalError> for ReceiveSignalError<P> {
    fn from(value: ConvertSignalError) -> Self {
        ReceiveSignalError::Convert(value)
    }
}

impl<P: PhysicalLink> From<RecombineError> for ReceiveSignalError<P> {
    fn from(value: RecombineError) -> Self {
        ReceiveSignalError::Recombine(value)
    }
}

#[cfg(feature = "std")]
impl<P: PhysicalLink> std::error::Error for ReceiveSignalError<P> where
    ReceiveSignalError<P>: core::fmt::Debug + core::fmt::Display
{
}

/// A recombine builder for a `ReceivedSignal`
///
/// This is used whenever a control signal is [received] to convert the transmission data into a
/// signal type.
///
/// # Enumerations
/// [received]: SignallingChannel::receive
#[derive(Default)]
enum ReceiveSignalRecombineBuilder {
    // state used before the signalling code is received
    #[default]
    Init,
    // Used for a error condition where the L2CAP signalling packet is 'unknown'
    Unknown(UnknownSignal),
    CommandRejectRsp(LinearBuffer<8, u8>),
    LeCreditBasedConnectionRequest(LinearBuffer<14, u8>),
    LeCreditBasedConnectionResponse(LinearBuffer<14, u8>),
    FlowControlCreditIndication(LinearBuffer<8, u8>),
}

impl ReceiveSignalRecombineBuilder {
    fn first_byte(&mut self, first: u8) {
        match SignalCode::try_from_code(first) {
            Ok(SignalCode::CommandRejectResponse) => *self = Self::CommandRejectRsp([first].into()),
            Ok(SignalCode::LeCreditBasedConnectionRequest) => {
                *self = Self::LeCreditBasedConnectionRequest([first].into())
            }
            Ok(SignalCode::LeCreditBasedConnectionResponse) => {
                *self = Self::LeCreditBasedConnectionResponse([first].into())
            }
            Ok(SignalCode::FlowControlCreditIndication) => *self = Self::FlowControlCreditIndication([first].into()),
            Err(_) | Ok(_) => *self = Self::Unknown(UnknownSignal::new(first)),
        }
    }
}

impl TryExtend<u8> for ReceiveSignalRecombineBuilder {
    type Error = ConvertSignalError;

    fn try_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = u8>,
    {
        for byte in iter {
            match self {
                Self::Init => self.first_byte(byte),
                Self::Unknown(unknown) => unknown.process(byte)?,
                Self::CommandRejectRsp(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
                Self::LeCreditBasedConnectionRequest(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
                Self::LeCreditBasedConnectionResponse(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
                Self::FlowControlCreditIndication(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
            }
        }

        Ok(())
    }
}

/// Error when converting received data into a signal
#[derive(Debug)]
pub enum ConvertSignalError {
    ReceivedSignalTooLong,
    IncompleteSignal,
    InvalidFormat(SignalCode),
}

impl core::fmt::Display for ConvertSignalError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("the received signal is invalid")?;

        match self {
            ConvertSignalError::ReceivedSignalTooLong => f.write_str(", more bytes received than expected"),
            ConvertSignalError::IncompleteSignal => f.write_str(", signal is incomplete"),
            ConvertSignalError::InvalidFormat(code) => write!(f, ", invalid format for signal {code}"),
        }
    }
}

struct UnknownSignal {
    header: LinearBuffer<4, u8>,
    expected_len: usize,
    bytes_received: usize,
}

impl UnknownSignal {
    fn new(code: u8) -> Self {
        let header = [code].into();
        let expected_len = 0;
        let bytes_received = 0;

        Self {
            header,
            expected_len,
            bytes_received,
        }
    }

    fn process(&mut self, byte: u8) -> Result<(), ConvertSignalError> {
        match self.header.len() {
            0..=2 => {
                self.header.try_push(byte).unwrap();

                Ok(())
            }
            3 => {
                self.header.try_push(byte).unwrap();

                let expected_len =
                    <u16>::from_le_bytes([*self.header.get(2).unwrap(), *self.header.get(3).unwrap()]).into();

                self.expected_len = expected_len;

                Ok(())
            }
            _ => {
                self.bytes_received += 1;

                if self.bytes_received > self.expected_len {
                    Err(ConvertSignalError::ReceivedSignalTooLong)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn get_identifier(&self) -> Option<NonZeroU8> {
        self.header.get(1).copied().and_then(|v| NonZeroU8::new(v))
    }
}

/// A Request Signal from the Linked Device
///
/// This is returned whenever a request is received by a Signalling Channel. Depending on the type
/// of request (`T`) there are different operations done.
pub struct Request<T> {
    request: T,
}

impl<T> Request<T> {
    /// Create a new `Request`
    pub fn new(request: T) -> Self {
        Self { request }
    }

    /// Reject the request on the basis of the command is not understood
    ///
    /// If ever a request is either not implemented or not used by the application, this can be used
    /// as a 'catch all' for those signals from the linked device.
    pub async fn reject_as_not_understood<P>(
        self,
        signalling_channel: &mut SignallingChannel<'_, P>,
    ) -> Result<(), P::SendErr>
    where
        P: PhysicalLink,
        T: Signal,
    {
        let rejection = CommandRejectResponse::new_command_not_understood(self.request.get_identifier());

        let c_frame = rejection.as_control_frame(signalling_channel.channel_id);

        signalling_channel.send(c_frame).await
    }

    /// Get the inner request
    pub fn into_inner(self) -> T {
        self.request
    }
}

impl Request<CommandRejectResponse> {
    /// Send the command rejection response
    pub async fn send_rejection<P: PhysicalLink>(
        self,
        signalling_channel: &mut SignallingChannel<'_, P>,
    ) -> Result<(), P::SendErr> {
        let c_frame = self.request.as_control_frame(signalling_channel.channel_id);

        signalling_channel.send(c_frame).await
    }
}

impl Request<LeCreditBasedConnectionRequest> {
    /// Create a LE Credit Based Connection
    ///
    /// This will send a *LE create a [`CreditBasedChannel`]
    ///
    /// # Panic
    /// This method will panic if there are no more dynamic channels that can be allocated for a
    /// LE-U logical link.
    pub fn create_le_credit_based_connection<P: PhysicalLink>(
        &self,
        link: &LeULogicalLink<P>,
        initial_credits: u16,
    ) -> LeCreditBasedConnectionResponseBuilder<'_> {
        let destination_dyn_cid = link
            .shared_link
            .new_le_dyn_channel()
            .expect("failed to create a dynamic channel");

        LeCreditBasedConnectionResponseBuilder {
            request: &self.request,
            destination_dyn_cid,
            mtu: self.request.mtu.get(),
            mps: self.request.mps.get(),
            initial_credits,
        }
    }

    /// Reject a LE credit based connection request
    pub async fn reject_le_credit_based_connection<P: PhysicalLink>(
        &self,
        signal_channel: &mut SignallingChannel<'_, P>,
        reason: crate::signals::packets::LeCreditBasedConnectionResponseError,
    ) -> Result<(), P::SendErr> {
        let response = LeCreditBasedConnectionResponse::new_rejected(self.request.identifier, reason);

        signal_channel
            .send(response.as_control_frame(signal_channel.channel_id))
            .await
    }
}

/// Builder used for creating a *LE Credit Based Connection Response*
pub struct LeCreditBasedConnectionResponseBuilder<'a> {
    request: &'a LeCreditBasedConnectionRequest,
    destination_dyn_cid: crate::channels::DynChannelId<crate::LeULinkType>,
    mtu: u16,
    mps: u16,
    initial_credits: u16,
}

impl LeCreditBasedConnectionResponseBuilder<'_> {
    /// Get the destination channel
    ///
    /// This channel is selected as the destination channel as part of calling the method
    /// [`create_le_credit_based_connection`].
    ///
    /// [`create_le_credit_based_connection`]
    pub fn get_destination_channel(&self) -> ChannelIdentifier {
        ChannelIdentifier::Le(LeCid::DynamicallyAllocated(self.destination_dyn_cid))
    }

    /// Get the initial credits
    ///
    /// This returns the initial credits that were used to create this
    /// `LeCreditBasedConnectionResponseBuilder`
    pub fn get_initial_credits(&self) -> u16 {
        self.initial_credits
    }

    /// Set the maximum payload size (MPS)
    ///
    /// This sets the MPS within the *LE Credit Based Connection Response* only if it is smaller
    /// than the request's MPS.
    pub fn set_responded_mps(&mut self, mps: u16) {
        self.mps = core::cmp::min(mps, self.request.mps.get())
    }

    /// Set the maximum transmission size (MPS)
    ///
    /// This sets the MTS within the *LE Credit Based Connection Response* only if it is smaller
    /// than the request's MTS.
    pub fn set_responded_mts(&mut self, mtu: u16) {
        self.mtu = core::cmp::min(mtu, self.request.mtu.get())
    }

    /// Send the response and create the connection
    ///
    /// This sends the response to the peer device and returns a [`CreditBasedChannel`] for the new
    /// connection.
    pub async fn send_response<'a, P: PhysicalLink>(
        self,
        signals_channel: &mut SignallingChannel<'a, P>,
    ) -> Result<CreditBasedChannel<'a, P>, P::SendErr> {
        use core::cmp::min;

        let response = LeCreditBasedConnectionResponse {
            identifier: self.request.identifier,
            destination_dyn_cid: self.destination_dyn_cid,
            mtu: LeCreditMtu::new(self.mtu),
            mps: LeCreditMps::new(self.mps),
            initial_credits: self.initial_credits,
            result: Ok(()),
        };

        signals_channel
            .send(response.as_control_frame(signals_channel.channel_id))
            .await?;

        let this_channel_id = ChannelIdentifier::Le(LeCid::DynamicallyAllocated(self.destination_dyn_cid));

        let peer_channel_id = self.request.get_source_cid();

        let maximum_packet_size = min(self.mps, self.request.mps.get()).into();

        let maximum_transmission_size = min(self.mtu, self.request.mtu.get()).into();

        let initial_peer_credits = self.request.initial_credits.into();

        let new_channel = CreditBasedChannel::new(
            this_channel_id,
            peer_channel_id,
            &signals_channel.link_lock,
            maximum_packet_size,
            maximum_transmission_size,
            initial_peer_credits,
        );

        Ok(new_channel)
    }
}

/// A response signal from the linked device
pub struct Response<T> {
    response: T,
}

impl<T> Response<T> {
    /// Create a new `Response`
    pub fn new(response: T) -> Self {
        Response { response }
    }

    /// Get the response
    pub fn into_inner(self) -> T {
        self.response
    }
}

impl Response<LeCreditBasedConnectionResponse> {
    /// Create a connection from the LE Credit Based Connection Response
    ///
    /// In order to configure the credit based channel, the request originally sent to the peer
    /// device is needed in order to create the [`CreditBasedChannel`]
    pub fn create_le_credit_connection<'a, P: PhysicalLink>(
        &self,
        request: &LeCreditBasedConnectionRequest,
        link: &'a LeULogicalLink<P>,
    ) -> CreditBasedChannel<'a, P> {
        let this_channel_id = request.get_source_cid();

        let peer_channel_id = self.response.get_destination_cid();

        let maximum_packet_size = core::cmp::min(self.response.mps.get(), request.mps.get()).into();

        let maximum_transmission_size = core::cmp::min(self.response.mtu.get(), request.mtu.get()).into();

        let initial_peer_credits = self.response.initial_credits.into();

        CreditBasedChannel::new(
            this_channel_id,
            peer_channel_id,
            &link.shared_link,
            maximum_packet_size,
            maximum_transmission_size,
            initial_peer_credits,
        )
    }
}
