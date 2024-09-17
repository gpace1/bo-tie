use crate::channel::id::{ChannelIdentifier, DynChannelId, LeCid};
use crate::channel::{ChannelBuffer, CreditBasedChannelData, DynChannelState};
use crate::link_flavor::{LeULink, LinkFlavor};
use crate::{
    LeULogicalLink, PhysicalLink, SignallingChannel, LE_LINK_SIGNALLING_CHANNEL_INDEX, LE_STATIC_CHANNEL_COUNT,
};
use bo_tie_core::buffer::TryExtend;

#[doc(hidden)]
pub trait LogicalLinkPrivate: Sized {
    type PhysicalLink: PhysicalLink;

    type Buffer: TryExtend<u8> + Default;

    type LinkFlavor: LinkFlavor;

    /// Add a new dynamic channel
    ///
    /// This attempts to create a new dynamic channel on this `LogicalLink`.
    ///
    /// # Panic
    /// This will panic if `id` is not a dynamically allocated channel identifier
    fn new_dyn_channel(&mut self, state: DynChannelState) -> Result<ChannelIdentifier, NewDynChannelError>;

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
    fn remove_dyn_channel(&mut self, id: ChannelIdentifier) -> bool;

    /// Get a dynamic channel by its identifier
    fn get_dyn_channel(&mut self, id: ChannelIdentifier) -> Option<&ChannelBuffer<Self::Buffer>>;

    /// Get the signalling channel
    ///
    /// This returns the channel used for siding `L2CAP` control frames to the linked device. This
    /// returns `None` if this logical link does not have a signalling channel.
    fn get_signalling_channel(&mut self) -> Option<SignallingChannel<Self>>;

    /// Get a reference to the physical link
    fn get_physical_link(&self) -> &Self::PhysicalLink;

    /// Get a mutable reference to the physical link
    fn get_mut_physical_link(&mut self) -> &mut Self::PhysicalLink;

    /// Take the last received PDU
    ///
    /// This returns the last received PDU unless no PDU received or the PDU has already been taken
    /// by a call to this method. After this is called, subsequent calls will always return `None`.
    /// This method is intended to be used after a call to `receive` by the logical link.
    fn take_last_received(&mut self) -> Option<Self::Buffer>
    where
        Self::Buffer: Default;

    /// Get the channel buffer
    fn get_channel_buffer(&self) -> &ChannelBuffer<Self::Buffer>;

    /// Get a mutable reference to the buffer
    fn get_mut_channel_buffer(&mut self) -> &mut ChannelBuffer<Self::Buffer>;
}

#[derive(Debug)]
enum NewDynChannelErrorReason {
    AllCreditBasedDynChannelsAreUsed { dyn_channel_count: usize },
}

impl core::fmt::Display for NewDynChannelErrorReason {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            NewDynChannelErrorReason::AllCreditBasedDynChannelsAreUsed { dyn_channel_count } => {
                write!(
                    f,
                    "the link cannot allocate another credit based channel as it has reached its \
                    maximum number of them ({dyn_channel_count})"
                )
            }
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

// impl<T: LogicalLinkPrivate> LogicalLinkPrivate for &mut T {
//     type PhysicalLink = T::PhysicalLink;
//     type Buffer = T::Buffer;
//     type LinkFlavor = T::LinkFlavor;
//
//     fn new_dyn_channel(&mut self, state: DynChannelState) -> Option<ChannelIdentifier> {
//         (&**self).new_dyn_channel(state)
//     }
//
//     fn remove_dyn_channel(&mut self, id: ChannelIdentifier) -> bool {
//         (&**self).remove_dyn_channel(id)
//     }
//
//     fn get_dyn_channel(&mut self, id: ChannelIdentifier) -> Option<&ChannelBuffer<Self::Buffer>> {
//         (&**self).get_dyn_channel(id)
//     }
//
//     fn get_signalling_channel(&mut self) -> Option<SignallingChannel<Self>> {
//         (&**self).get_signalling_channel()
//     }
//
//     fn get_physical_link(&self) -> &Self::PhysicalLink {
//         (&**self).get_physical_link()
//     }
//
//     fn get_mut_physical_link(&mut self) -> &mut Self::PhysicalLink {
//         (&**self).get_mut_physical_link()
//     }
//
//     fn take_last_received(&mut self) -> Option<Self::Buffer>
//     where
//         Self::Buffer: Default,
//     {
//         (&**self).take_last_received()
//     }
//
//     fn get_channel_buffer(&self) -> &ChannelBuffer<Self::Buffer> {
//         (&**self).get_channel_buffer()
//     }
//
//     fn get_mut_channel_buffer(&mut self) -> &mut ChannelBuffer<Self::Buffer> {
//         todo!()
//     }
// }

pub(crate) struct LeULogicalLinkHandle<'a, P, B> {
    logical_link: &'a mut LeULogicalLink<P, B>,
    index: usize,
    receive_data_taken: bool,
}

impl<'a, P, B> LeULogicalLinkHandle<'a, P, B> {
    pub(crate) fn new(logical_link: &'a mut LeULogicalLink<P, B>, index: usize) -> Self {
        let receive_data_taken = false;

        Self {
            logical_link,
            index,
            receive_data_taken,
        }
    }
}

impl<P, B> LogicalLinkPrivate for LeULogicalLinkHandle<'_, P, B>
where
    P: PhysicalLink,
    B: TryExtend<u8> + Default,
{
    type PhysicalLink = P;
    type Buffer = B;

    type LinkFlavor = LeULink;

    fn new_dyn_channel(
        &mut self,
        dyn_channel_builder: DynChannelState,
    ) -> Result<ChannelIdentifier, NewDynChannelError> {
        self.logical_link.channels[LE_STATIC_CHANNEL_COUNT..]
            .iter()
            .enumerate()
            .find_map(|(i, channel)| {
                if let ChannelBuffer::Unused = channel {
                    Some(i)
                } else {
                    None
                }
            })
            .map(|index| {
                self.logical_link.channels[index] = dyn_channel_builder.into();

                ChannelIdentifier::Le(
                    DynChannelId::new_le(
                        (index - LE_STATIC_CHANNEL_COUNT) as u16 + *DynChannelId::<LeULink>::LE_BOUNDS.start(),
                    )
                    .unwrap(),
                )
            })
            .ok_or_else(|| {
                let dyn_channel_count =
                    (*DynChannelId::<LeULink>::LE_BOUNDS.end() - *DynChannelId::<LeULink>::LE_BOUNDS.start()).into();

                let e = NewDynChannelErrorReason::AllCreditBasedDynChannelsAreUsed { dyn_channel_count };

                NewDynChannelError(e)
            })
    }

    fn remove_dyn_channel(&mut self, id: ChannelIdentifier) -> bool {
        if let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(channel_id)) = id {
            let index = (channel_id.get_val() - *DynChannelId::LE_BOUNDS.start()) as usize + LE_STATIC_CHANNEL_COUNT;

            if let ChannelBuffer::Unused = self.logical_link.channels[index] {
                false
            } else {
                self.logical_link.channels[index] = ChannelBuffer::Unused;

                true
            }
        } else {
            false
        }
    }

    fn get_dyn_channel(&mut self, id: ChannelIdentifier) -> Option<&ChannelBuffer<Self::Buffer>> {
        if let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(dyn_channel_id)) = id {
            let index = self.logical_link.get_dyn_index(dyn_channel_id);

            self.logical_link.channels.get(index)
        } else {
            None
        }
    }

    fn get_signalling_channel(&mut self) -> Option<SignallingChannel<Self>> {
        let handle = LeULogicalLinkHandle::new(&mut self.logical_link, LE_LINK_SIGNALLING_CHANNEL_INDEX);

        Some(SignallingChannel::new(
            ChannelIdentifier::Le(LeCid::LeSignalingChannel),
            handle,
        ))
    }

    fn get_physical_link(&self) -> &P {
        &self.logical_link.physical_link
    }

    fn get_mut_physical_link(&mut self) -> &mut P {
        &mut self.logical_link.physical_link
    }

    fn take_last_received(&mut self) -> Option<B>
    where
        Self::Buffer: Default,
    {
        if !self.receive_data_taken {
            self.receive_data_taken = true;

            let buffer = match &mut self.logical_link.channels[self.index] {
                ChannelBuffer::Unused | ChannelBuffer::Reserved => unreachable!(),
                ChannelBuffer::AttributeChannel { buffer } => buffer,
                ChannelBuffer::SignallingChannel { buffer } => buffer,
                ChannelBuffer::CreditBasedChannel {
                    data: CreditBasedChannelData { buffer, .. },
                } => buffer,
            };

            Some(core::mem::take(buffer))
        } else {
            None
        }
    }

    fn get_channel_buffer(&self) -> &ChannelBuffer<B> {
        &self.logical_link.channels[self.index]
    }

    fn get_mut_channel_buffer(&mut self) -> &mut ChannelBuffer<Self::Buffer> {
        &mut self.logical_link.channels[self.index]
    }
}
