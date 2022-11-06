//! The Host Controller Interface
//!

pub mod commands;
pub use bo_tie_hci_util::events;

#[cfg(feature = "l2cap")]
pub use bo_tie_hci_host::l2cap::LeL2cap;
pub use bo_tie_hci_host::{
    AclBroadcastFlag, AclPacketBoundary, CommandError, Connection, ConnectionKind, HciAclData, Host, Next,
};
#[doc(inline)]
pub use bo_tie_hci_util::channel;
pub use bo_tie_hci_util::local_channel::local_dynamic::{LocalChannelReserve, LocalChannelReserveBuilder};
#[cfg(feature = "unstable")]
pub use bo_tie_hci_util::local_channel::local_stack::{LocalStackChannelReserve, LocalStackChannelReserveData};
pub use bo_tie_hci_util::ConnectionHandle;
pub use bo_tie_hci_util::{ChannelReserve, HostChannelEnds};

#[cfg(feature = "async-std")]
pub use bo_tie_hci_util::channel::async_std_unbounded;
#[cfg(feature = "futures-rs")]
pub use bo_tie_hci_util::channel::futures_unbounded;
#[cfg(feature = "tokio")]
pub use bo_tie_hci_util::channel::tokio_unbounded;
