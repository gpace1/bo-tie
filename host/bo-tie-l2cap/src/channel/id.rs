//! L2CAP Channels Definitions

use crate::link_flavor::{AclUExtLink, AclULink, LeULink};
use core::cmp::Ordering;

/// Channel Identifier
///
/// Channel Identifiers are used by the L2CAP to associate the data with a given channel. Channels
/// are a numeric identifier for a protocol or an association of protocols that are part of L2CAP or
/// a higher layer (such as the Attribute (ATT) protocol).
///
/// # Specification Reference
/// See Bluetooth Specification V5 | Vol 3, Part A Section 2.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChannelIdentifier {
    /// ACL-U identifiers
    Acl(AclCid),
    /// APB-U identifiers
    Apb(ApbCid),
    /// LE-U identifiers
    Le(LeCid),
}

impl ChannelIdentifier {
    /// Convert this `ChannelIdentifier` to its numerical value
    pub fn to_val(&self) -> u16 {
        match self {
            ChannelIdentifier::Acl(ci) => ci.to_cid(),
            ChannelIdentifier::Apb(ci) => ci.to_cid(),
            ChannelIdentifier::Le(ci) => ci.to_cid(),
        }
    }

    /// Try to convert a raw value into an ACL-U channel identifier
    pub fn acl_try_from_raw(val: u16) -> Result<Self, ()> {
        AclCid::try_from_raw(val).map(|c| c.into())
    }

    /// Try to convert a raw value into an APB-U channel identifier
    pub fn apb_try_from_raw(val: u16) -> Result<Self, ()> {
        ApbCid::try_from_raw(val).map(|c| c.into())
    }

    /// Try to convert a raw value into a LE-U channel identifier
    pub fn le_try_from_raw(val: u16) -> Result<Self, ()> {
        LeCid::try_from_raw(val).map(|c| c.into())
    }
}

impl core::fmt::Display for ChannelIdentifier {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ChannelIdentifier::Acl(id) => write!(f, "ACL-U {}", id),
            ChannelIdentifier::Apb(id) => write!(f, "APB-U {}", id),
            ChannelIdentifier::Le(id) => write!(f, "LE-U {}", id),
        }
    }
}

impl From<AclCid> for ChannelIdentifier {
    fn from(acl: AclCid) -> Self {
        ChannelIdentifier::Acl(acl)
    }
}

impl From<ApbCid> for ChannelIdentifier {
    fn from(apb: ApbCid) -> Self {
        ChannelIdentifier::Apb(apb)
    }
}

impl From<LeCid> for ChannelIdentifier {
    fn from(le: LeCid) -> Self {
        ChannelIdentifier::Le(le)
    }
}

impl From<DynChannelId<LeULink>> for ChannelIdentifier {
    fn from(id: DynChannelId<LeULink>) -> Self {
        ChannelIdentifier::Le(LeCid::DynamicallyAllocated(id))
    }
}

impl From<DynChannelId<AclULink>> for ChannelIdentifier {
    fn from(id: DynChannelId<AclULink>) -> Self {
        ChannelIdentifier::Acl(AclCid::DynamicallyAllocated(id))
    }
}

/// Dynamically created L2CAP channel
#[derive(Debug)]
pub struct DynChannelId<T> {
    channel_id: u16,
    _p: core::marker::PhantomData<T>,
}

impl<T> Clone for DynChannelId<T> {
    fn clone(&self) -> Self {
        DynChannelId {
            channel_id: self.channel_id,
            _p: core::marker::PhantomData,
        }
    }
}

impl<T> Copy for DynChannelId<T> {}

impl<T> PartialEq for DynChannelId<T> {
    fn eq(&self, other: &Self) -> bool {
        self.channel_id.eq(&other.channel_id)
    }
}

impl<T> Eq for DynChannelId<T> {}

impl<T> PartialOrd for DynChannelId<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.channel_id.partial_cmp(&other.channel_id)
    }
}

impl<T> Ord for DynChannelId<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.channel_id.cmp(&other.channel_id)
    }
}

impl<T> core::hash::Hash for DynChannelId<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.channel_id.hash(state)
    }
}

impl<T> DynChannelId<T> {
    /// Create a new `DynChannelId`
    ///
    /// # Note
    /// `channel_val` is not checked for whether it is a valid dynamic channel value.
    pub(crate) fn new_unchecked(channel_val: u16) -> Self {
        DynChannelId {
            channel_id: channel_val,
            _p: core::marker::PhantomData,
        }
    }

    /// Get the value of the dynamic channel identifier
    pub fn get_val(&self) -> u16 {
        self.channel_id
    }
}

impl DynChannelId<LeULink> {
    pub const LE_BOUNDS: core::ops::RangeInclusive<u16> = 0x0040..=0x007F;

    /// Create a new `LeCid` for a dynamic channel
    ///
    /// This returns a [`LeCid`] so long as `channel_id` is within the range of `0x40..=0x007F`.
    pub fn new_le(channel_id: u16) -> Result<LeCid, u16> {
        Self::new_dyn_le(channel_id).map(|dyn_channel| LeCid::DynamicallyAllocated(dyn_channel))
    }

    /// Create a new `DynChannelId<LeULink>`
    ///
    /// This returns a `DynChannelId<LeULink>` so long as `channel_id` is within the range of
    /// `0x40..=0x007F`.
    pub fn new_dyn_le(channel_id: u16) -> Result<DynChannelId<LeULink>, u16> {
        if Self::LE_BOUNDS.contains(&channel_id) {
            Ok(DynChannelId::new_unchecked(channel_id))
        } else {
            Err(channel_id)
        }
    }
}

impl DynChannelId<AclULink> {
    pub const ACL_BOUNDS: core::ops::RangeInclusive<u16> = 0x0040..=0xFFFF;

    /// Create a new `AclCid` for a dynamic channel
    ///
    /// This returns an [`AclCid`] so long as `channel_id` is within the range of `0x40..=0xFFFF`.
    pub fn new_acl(channel_id: u16) -> Result<AclCid, u16> {
        Self::new_dyn_acl(channel_id).map(|dyn_channel| AclCid::DynamicallyAllocated(dyn_channel))
    }

    /// Create a new `DynChannelId<AclULink>`
    ///
    /// This returns a `DynChannelId<AclULink>` so long as `channel_id` is within the range of
    /// `0x40..=0xFFFF`.
    pub fn new_dyn_acl(channel_id: u16) -> Result<DynChannelId<AclULink>, u16> {
        if Self::ACL_BOUNDS.contains(&channel_id) {
            Ok(DynChannelId::new_unchecked(channel_id))
        } else {
            Err(channel_id)
        }
    }
}

impl From<DynChannelId<AclULink>> for DynChannelId<AclUExtLink> {
    fn from(channel: DynChannelId<AclULink>) -> Self {
        DynChannelId {
            channel_id: channel.channel_id,
            _p: core::marker::PhantomData,
        }
    }
}

impl<T> core::fmt::Display for DynChannelId<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.channel_id, f)
    }
}

/// ACL User (ACL-U) Channel Identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AclCid {
    SignalingChannel,
    ConnectionlessChannel,
    BrEdrSecurityManager,
    DynamicallyAllocated(DynChannelId<AclULink>),
}

impl AclCid {
    pub fn to_cid(&self) -> u16 {
        match self {
            AclCid::SignalingChannel => 0x1,
            AclCid::ConnectionlessChannel => 0x2,
            AclCid::BrEdrSecurityManager => 0x7,
            AclCid::DynamicallyAllocated(ci) => ci.get_val(),
        }
    }

    pub fn try_from_raw(val: u16) -> Result<Self, ()> {
        match val {
            0x1 => Ok(AclCid::SignalingChannel),
            0x2 => Ok(AclCid::ConnectionlessChannel),
            0x7 => Ok(AclCid::BrEdrSecurityManager),
            val if DynChannelId::<AclULink>::ACL_BOUNDS.contains(&val) => {
                Ok(AclCid::DynamicallyAllocated(DynChannelId::new_unchecked(val)))
            }
            _ => Err(()),
        }
    }
}

impl core::fmt::Display for AclCid {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            AclCid::SignalingChannel => f.write_str("signaling channel"),
            AclCid::ConnectionlessChannel => f.write_str("connectionless channel"),
            AclCid::BrEdrSecurityManager => f.write_str("BR/EDR security manager"),
            AclCid::DynamicallyAllocated(id) => write!(f, "dynamically allocated channel ({})", id),
        }
    }
}

/// APB User (APB-U) Channel Identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApbCid {
    ConnectionlessChannel,
}

impl ApbCid {
    pub fn to_cid(&self) -> u16 {
        0x2
    }

    pub fn try_from_raw(val: u16) -> Result<Self, ()> {
        match val {
            0x2 => Ok(ApbCid::ConnectionlessChannel),
            _ => Err(()),
        }
    }
}

impl core::fmt::Display for ApbCid {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ApbCid::ConnectionlessChannel => f.write_str("connectionless channel"),
        }
    }
}

/// LE User (LE-U) Channel Identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeCid {
    /// Channel for the Attribute Protocol
    ///
    /// This channel is used for the attribute protocol, which also means that all GATT data will
    /// be sent through this channel.
    AttributeProtocol,
    /// LE Signaling Channel
    LeSignalingChannel,
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
    DynamicallyAllocated(DynChannelId<LeULink>),
}

impl LeCid {
    pub fn to_cid(&self) -> u16 {
        match self {
            LeCid::AttributeProtocol => 0x4,
            LeCid::LeSignalingChannel => 0x5,
            LeCid::SecurityManagerProtocol => 0x6,
            LeCid::DynamicallyAllocated(dyn_id) => dyn_id.channel_id,
        }
    }

    pub fn try_from_raw(val: u16) -> Result<Self, ()> {
        match val {
            0x4 => Ok(LeCid::AttributeProtocol),
            0x5 => Ok(LeCid::LeSignalingChannel),
            0x6 => Ok(LeCid::SecurityManagerProtocol),
            _ if DynChannelId::<LeULink>::LE_BOUNDS.contains(&val) => {
                Ok(LeCid::DynamicallyAllocated(DynChannelId::new_unchecked(val)))
            }
            _ => Err(()),
        }
    }
}

impl core::fmt::Display for LeCid {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            LeCid::AttributeProtocol => f.write_str("attribute protocol"),
            LeCid::LeSignalingChannel => f.write_str("LE L2CAP signaling channel"),
            LeCid::SecurityManagerProtocol => f.write_str("security manager protocol"),
            LeCid::DynamicallyAllocated(id) => write!(f, "dynamically allocated channel ({})", id),
        }
    }
}
