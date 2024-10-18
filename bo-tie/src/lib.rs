//! A Bluetooth Library
//!
//! The primary purpose of bo-tie is to provide a middling layer between the architecture specific
//! and user-friendly libraries for Bluetooth. bo-tie is also intended to be used in environments
//! where only [`core`](https://doc.rust-lang.org/core/) and
//! [`alloc`](https://doc.rust-lang.org/alloc/) are available.
//!
//! The primary way of interfacing to the controller is through the [`hci`] (Host Controller
//! Interface). All commands, events, *and* data (ACL, SCO/eSCO) go through this interface.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(test), no_std)]

#[cfg(feature = "hci")]
pub mod hci;
#[cfg(any(
    feature = "l2cap",
    feature = "gap",
    feature = "att",
    feature = "gatt",
    feature = "sm",
))]
pub mod host;

pub use bo_tie_core::errors::Error;
pub use bo_tie_core::{BluetoothDeviceAddress, DeviceFeatures, Features, LeDeviceFeatures, LeFeatures};
pub use bo_tie_core::buffer::TryExtend;
