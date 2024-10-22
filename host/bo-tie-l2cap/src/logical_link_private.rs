use crate::channel::id::{ChannelIdentifier, DynChannelId, LeCid};
use crate::channel::{DynChannelState, DynChannelStateInner, LeUChannelType};
use crate::link_flavor::{LeULink, LinkFlavor};
use crate::{
    CreditBasedChannel, LeULogicalLink, PhysicalLink, SignallingChannel, LE_DYNAMIC_CHANNEL_COUNT,
    LE_LINK_SIGNALLING_CHANNEL_INDEX, LE_STATIC_CHANNEL_COUNT,
};
use bo_tie_core::buffer::TryExtend;

/// Marker type for an unused buffer
#[derive(Debug, Default)]
pub struct UnusedBuffer;

impl<I> TryExtend<I> for UnusedBuffer {
    type Error = PhantomBufferError;

    fn try_extend<T>(&mut self, _: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = I>,
    {
        Err(PhantomBufferError)
    }
}

impl IntoIterator for UnusedBuffer {
    type Item = u8;

    type IntoIter = core::array::IntoIter<u8, 0>;

    fn into_iter(self) -> Self::IntoIter {
        [].into_iter()
    }
}

/// Error type for [`UnusedBuffer`]
#[derive(Debug)]
pub struct PhantomBufferError;

impl core::fmt::Display for PhantomBufferError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("tried to use marker type `UnusedBuffer` as a real buffer")
    }
}

#[doc(hidden)]
pub trait LogicalLinkPrivate: Sized {
    type PhysicalLink: PhysicalLink;

    type PduBuffer: Default;

    type SduBuffer;

    type LinkFlavor: LinkFlavor;

    /// Reserve a dynamic channel
    ///
    /// This is used for reserve a dynamic channel ID upon initiating a dynamic channel.
    ///
    /// Dynamic channels require a procedure to establish the channel between the endpoints of the
    /// link. This is used after a request for the creation of the channel to ensure that no other
    /// concurrent request also tries taking the channel. The channel doesn't actually exist yet,
    /// and `establish_dyn_channel` needs to be called in order to use it.
    ///
    /// # Error
    /// An error is returned if all dynamic channels for the logical link are currently used by
    /// either established channels or reservations.
    fn reserve_dyn_channel(&mut self) -> Result<ChannelIdentifier, NewDynChannelError>;

    /// Establish a dynamic channel
    ///
    /// This is used to establish a dynamic channel.
    ///
    /// After this is called the dynamic channel now exists (as far as this device is concerned) and
    /// data can be sent or received over the channel.
    ///
    /// # Input
    /// This takes a state. The state is either two different things, either a reserved or newly
    /// established dynamic channel. If the input is of the reserved variety, then the channel
    /// reservation must exist within the logical link.
    ///
    /// # Errors
    /// * An error is returned if all dynamic channels for the logical link are currently used by
    ///   either established channels or reservations.
    /// * There is no associated reservation provided for the reservation state.
    fn establish_dyn_channel(&mut self, state: DynChannelState) -> Result<ChannelIdentifier, NewDynChannelError>
    where
        Self::SduBuffer: Default;

    /// Remove a dynamic channel
    ///
    /// This attempts to remove the dynamic channel from this `LogicalLink`. If the channel exists
    /// within this `LogicalLink` it will be deleted and this method will return true. If the
    /// channel does not exist then nothing happens and this method returns false.
    ///
    /// # Channel Must Be Closed
    /// Any closure procedure required for removing the channel must be done before this method is
    /// called. Once this method is called the logical link will no longer process data fragments
    /// sent and received over the channel.
    ///
    /// # Panic
    /// This will panic if `id` is not a dynamically allocated channel identifier
    fn remove_dyn_channel(&mut self, id: ChannelIdentifier) -> Option<LeUChannelType<Self::SduBuffer>>;

    /// Used when this device initiates a disconnect of a dynamic channel
    ///
    /// This must be called (instead of `remove_dyn_channel`) to protect against a race condition
    /// where this device and the linked device both send a disconnect request at the same time.
    /// Internally this changes the state of the connection channel to
    /// [`LeUChannelType::PendingDisconnect`].
    ///
    /// # Clearing the State
    ///
    /// Clearing the `PendingDisconnect` state can only be done once the disconnect response is
    /// received. So it falls on the logical link implementation to clear this state upon receiving
    /// the response.
    fn initiated_disconnect_of_dyn_channel(&mut self, id: ChannelIdentifier)
        -> Option<LeUChannelType<Self::SduBuffer>>;

    /// Get a dynamic channel by its identifier
    fn get_dyn_channel(&mut self, id: ChannelIdentifier) -> Option<&LeUChannelType<Self::SduBuffer>>;

    /// Do something with the signalling channel
    ///
    /// # Panic
    /// This panics if the signalling channel is not enabled.
    fn with_signalling_channel<F, T>(self, f: F) -> T
    where
        F: FnOnce(SignallingChannel<Self>) -> T;

    /// Get a credit based channel
    fn get_credit_based_channel(self, cid: ChannelIdentifier) -> Option<CreditBasedChannel<Self>>;

    /// Get a reference to the physical link
    fn get_physical_link(&self) -> &Self::PhysicalLink;

    /// Get a mutable reference to the physical link
    fn get_mut_physical_link(&mut self) -> &mut Self::PhysicalLink;

    /// Get the channel buffer
    fn get_channel_data(&self) -> &LeUChannelType<Self::SduBuffer>;

    /// Get a mutable reference to the buffer
    fn get_mut_channel_data(&mut self) -> &mut LeUChannelType<Self::SduBuffer>;
}

#[derive(Debug)]
enum NewDynChannelErrorReason {
    AllCreditBasedDynChannelsAreUsed { total_dyn_channel_count: usize },
    InvalidReserveChannel(ChannelIdentifier),
}

impl core::fmt::Display for NewDynChannelErrorReason {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            NewDynChannelErrorReason::AllCreditBasedDynChannelsAreUsed {
                total_dyn_channel_count,
            } => {
                write!(
                    f,
                    "the link cannot allocate another credit based channel as it has reached its \
                    maximum number of them (the total number of dynamic channels for this link is \
                    {total_dyn_channel_count})"
                )
            }
            NewDynChannelErrorReason::InvalidReserveChannel(id) => write!(f, "reserve channel {id:?} is invalid"),
        }
    }
}

#[doc(hidden)]
pub struct NewDynChannelError(NewDynChannelErrorReason);

impl core::fmt::Debug for NewDynChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.0, f)
    }
}

impl core::fmt::Display for NewDynChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NewDynChannelError {}

/// A handle to a logical link for a channel
#[derive(Debug)]
pub struct LeULogicalLinkHandle<'a, P, B, S> {
    logical_link: &'a mut LeULogicalLink<P, B, S>,
    index: usize,
}

impl<'a, P, B, S> LeULogicalLinkHandle<'a, P, B, S> {
    pub(crate) fn new(logical_link: &'a mut LeULogicalLink<P, B, S>, index: usize) -> Self {
        Self { logical_link, index }
    }

    fn occupy_next_dyn_channel(&mut self, buff: LeUChannelType<S>) -> Result<ChannelIdentifier, NewDynChannelError> {
        if self.logical_link.channels.len() < LE_STATIC_CHANNEL_COUNT + LE_DYNAMIC_CHANNEL_COUNT {
            let index = self.logical_link.channels.len();

            self.logical_link.channels.push(buff);

            Ok(self.index_to_channel(index))
        } else {
            self.logical_link.channels[LE_STATIC_CHANNEL_COUNT..]
                .iter()
                .enumerate()
                .find_map(|(i, channel)| match channel {
                    LeUChannelType::Unused => Some(i),
                    _ => None,
                })
                .map(|index| {
                    self.logical_link.channels[index] = buff;

                    self.index_to_channel(index)
                })
                .ok_or_else(|| {
                    let total_dyn_channel_count = (*DynChannelId::<LeULink>::LE_BOUNDS.end()
                        - *DynChannelId::<LeULink>::LE_BOUNDS.start())
                    .into();

                    let e = NewDynChannelErrorReason::AllCreditBasedDynChannelsAreUsed {
                        total_dyn_channel_count,
                    };

                    NewDynChannelError(e)
                })
        }
    }

    fn index_to_channel(&self, index: usize) -> ChannelIdentifier {
        ChannelIdentifier::Le(
            DynChannelId::new_le(
                (index - LE_STATIC_CHANNEL_COUNT) as u16 + *DynChannelId::<LeULink>::LE_BOUNDS.start(),
            )
            .unwrap(),
        )
    }

    fn channel_to_index(&self, channel: ChannelIdentifier) -> Option<usize> {
        let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(dynamic_id)) = channel else {
            return None;
        };

        self.logical_link.convert_dyn_index(dynamic_id).into()
    }
}

impl<P: PhysicalLink, B: Default, S> LogicalLinkPrivate for LeULogicalLinkHandle<'_, P, B, S> {
    type PhysicalLink = P;
    type PduBuffer = B;

    type SduBuffer = S;

    type LinkFlavor = LeULink;

    fn reserve_dyn_channel(&mut self) -> Result<ChannelIdentifier, NewDynChannelError> {
        self.occupy_next_dyn_channel(LeUChannelType::Reserved)
    }

    fn establish_dyn_channel(
        &mut self,
        dyn_channel_builder: DynChannelState,
    ) -> Result<ChannelIdentifier, NewDynChannelError>
    where
        Self::SduBuffer: Default,
    {
        match &dyn_channel_builder.inner {
            DynChannelStateInner::ReserveCreditBasedChannel { reserved_id, .. } => {
                let channel = *reserved_id;

                let index = self
                    .channel_to_index(*reserved_id)
                    .ok_or_else(|| NewDynChannelError(NewDynChannelErrorReason::InvalidReserveChannel(channel)))?;

                self.logical_link.channels.insert(index, dyn_channel_builder.into());

                Ok(channel)
            }
            DynChannelStateInner::EstablishedCreditBasedChannel { .. } => {
                self.occupy_next_dyn_channel(dyn_channel_builder.into())
            }
        }
    }

    fn remove_dyn_channel(&mut self, id: ChannelIdentifier) -> Option<LeUChannelType<Self::SduBuffer>> {
        if let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(channel_id)) = id {
            let index = (channel_id.get_val() - *DynChannelId::LE_BOUNDS.start()) as usize + LE_STATIC_CHANNEL_COUNT;

            self.logical_link.remove_dyn_channel(index).into()
        } else {
            None
        }
    }

    fn initiated_disconnect_of_dyn_channel(
        &mut self,
        id: ChannelIdentifier,
    ) -> Option<LeUChannelType<Self::SduBuffer>> {
        if let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(channel_id)) = id {
            let index = (channel_id.get_val() - *DynChannelId::LE_BOUNDS.start()) as usize + LE_STATIC_CHANNEL_COUNT;

            let peer_channel_id = match self.get_dyn_channel(id) {
                Some(LeUChannelType::CreditBasedChannel { data }) => data.get_peer_channel_id(),
                _ => unreachable!(),
            };

            self.logical_link
                .initiated_disconnect_of_dyn_channel(index, peer_channel_id)
                .into()
        } else {
            None
        }
    }

    fn get_dyn_channel(&mut self, id: ChannelIdentifier) -> Option<&LeUChannelType<Self::SduBuffer>> {
        if let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(dyn_channel_id)) = id {
            let index = self.logical_link.convert_dyn_index(dyn_channel_id);

            self.logical_link.channels.get(index)
        } else {
            None
        }
    }

    fn with_signalling_channel<F, T>(mut self, f: F) -> T
    where
        F: FnOnce(SignallingChannel<Self>) -> T,
    {
        self.index = LE_LINK_SIGNALLING_CHANNEL_INDEX;

        let channel = SignallingChannel::new(ChannelIdentifier::Le(LeCid::LeSignalingChannel), self);

        f(channel)
    }

    fn get_credit_based_channel(mut self, cid: ChannelIdentifier) -> Option<CreditBasedChannel<Self>> {
        let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(dyn_channel_id)) = cid else {
            return None;
        };

        let index = self.logical_link.convert_dyn_index(dyn_channel_id);

        if let Some(LeUChannelType::CreditBasedChannel { .. }) = self.logical_link.channels.get(index) {
            self.index = index;

            Some(CreditBasedChannel::new(cid, self))
        } else {
            None
        }
    }

    fn get_physical_link(&self) -> &P {
        &self.logical_link.physical_link
    }

    fn get_mut_physical_link(&mut self) -> &mut P {
        &mut self.logical_link.physical_link
    }

    fn get_channel_data(&self) -> &LeUChannelType<Self::SduBuffer> {
        &self.logical_link.channels[self.index]
    }

    fn get_mut_channel_data(&mut self) -> &mut LeUChannelType<Self::SduBuffer> {
        &mut self.logical_link.channels[self.index]
    }
}
