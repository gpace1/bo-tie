//! The Host Controller Interface
//!

pub mod commands;
pub use bo_tie_hci_util::events;

pub use bo_tie_hci_host::{AclBroadcastFlag, AclPacketBoundary, Connection, ConnectionKind, HciAclData, Host, Next};
pub use bo_tie_hci_util::channel::{ChannelReserve, ChannelReserveBuilder};
pub use bo_tie_hci_util::local_channel::local_dynamic::{LocalChannelReserve, LocalChannelReserveBuilder};
#[cfg(feature = "unstable")]
pub use bo_tie_hci_util::local_channel::local_stack::{LocalStackChannelReserve, LocalStackChannelReserveData};
pub use bo_tie_hci_util::ConnectionHandle;

#[cfg(feature = "async-std")]
pub use bo_tie_hci_util::channel::async_std_unbounded;
#[cfg(feature = "futures-rs")]
pub use bo_tie_hci_util::channel::futures_unbounded;
#[cfg(feature = "tokio")]
pub use bo_tie_hci_util::channel::tokio_unbounded;
