//! Logical Link Flavors
//!
//! There are two defined logical links, ACL-U and LE-U, however they can have different
//! configuration information depending on the 'flavor' of the logical link. A flavor is something
//! defined by this library in order to correctly map L2CAP data and channels to the correct meta
//! information associated with them.
//!
//! A flavor has four major things associated with it.
//! 1) (implied) the logical link they are for.
//! 2) the minimum supported MTU of the payload or SDU.
//! 3) the valid channel identifier ranges
//! 4) the signalling channel (if any).
//!
//! # Logical Link
//! A flavor is for labeling the further parameters of how the current logical link or channel is
//! acting in regards to the other device(s) connected via a physical link. If a channel is defined
//! to use the [`AclULink`] flavor it has different requirements than if it used the [`ApbLink`]
//! flavor.
//!
//! When data is sent or received, a channel will use the flavor to set or validate (respectively)
//! that the channeling information of the L2CAP PDUs.
//!
//! # Minimum Supported MTU
//! Flavors have different supported MTU values. It can be helpful to upper layers to understand
//! the minimum MTU for a L2CAP connection based on the link flavor of the channel.
//!
//! # Identifier Ranges
//! Channel identifier values depend on the link flavor. Different link flavors have different valid
//! channel identifier values even if the flavors are part of the same logical link kind.
//!
//! # Signalling Channel
//! Most flavors have an associated signalling channel, but not all of them. This is used to get the
//! signalling channel identifier of the link flavor.

use crate::channel::id::{AclCid, ChannelIdentifier, LeCid};

/// A trait for a logical link type
///
/// Every logical link type of this library implements `LinkType`. For explanation on what a
/// *logical link type* is see the [library level] documentation.
///
/// Use the trait [`LinkTypeExt`] if you would like to call these methods directly.
///
/// [library level]: crate
pub trait LinkFlavor {
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

/// ACL-U L2CAP logical link type
///
/// This is a marker type for an ACL-U L2CAP logical link that does not support the extended flow
/// Specification.
///
/// This is used to mark the operation of logical link. When a channel uses this type of logical
/// link, it operates as a regular ACL-U logical link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AclULink;

impl LinkFlavor for AclULink {
    const MIN_SUPPORTED_MTU: u16 = 48;

    fn try_channel_from_raw(val: u16) -> Option<ChannelIdentifier> {
        AclCid::try_from_raw(val).map(|id| ChannelIdentifier::Acl(id)).ok()
    }

    fn get_signaling_channel() -> Option<ChannelIdentifier> {
        Some(ChannelIdentifier::Acl(AclCid::SignalingChannel))
    }
}

/// ACL-U L2CAP logical link type supporting the *Extended Flow Specification*
///
/// This is a marker type for an ACL-U L2CAP logical link that supports the extended flow
/// specification.
///
/// This is used to mark the operation of logical link. When a channel uses this type of logical
/// link, it operates as a ACL-U logical link with support for the the extended flow specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AclUExtLink;

impl LinkFlavor for AclUExtLink {
    const MIN_SUPPORTED_MTU: u16 = 672;

    fn try_channel_from_raw(val: u16) -> Option<ChannelIdentifier> {
        AclCid::try_from_raw(val).map(|id| ChannelIdentifier::Acl(id)).ok()
    }

    fn get_signaling_channel() -> Option<ChannelIdentifier> {
        Some(ChannelIdentifier::Acl(AclCid::SignalingChannel))
    }
}

/// APB-U L2CAP logical link type
///
/// This is a marker type for an ACL-U L2CAP logical link that uses broadcast packets.
///
/// This is used to mark the operation of logical link. When a channel uses this type of logical
/// link, it operates as a ACL-U logical link for unreliable broadcast packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApbLink;

impl LinkFlavor for ApbLink {
    const MIN_SUPPORTED_MTU: u16 = 48;

    fn try_channel_from_raw(val: u16) -> Option<ChannelIdentifier> {
        crate::channel::id::ApbCid::try_from_raw(val)
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
///
/// This is used to mark the operation of logical link. When a channel uses this type of logical
/// link, it operates as a Le-U logical link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LeULink;

impl LinkFlavor for LeULink {
    const MIN_SUPPORTED_MTU: u16 = 23;

    fn try_channel_from_raw(val: u16) -> Option<ChannelIdentifier> {
        LeCid::try_from_raw(val).map(|id| ChannelIdentifier::Le(id)).ok()
    }

    fn get_signaling_channel() -> Option<ChannelIdentifier> {
        Some(ChannelIdentifier::Le(LeCid::LeSignalingChannel))
    }
}
