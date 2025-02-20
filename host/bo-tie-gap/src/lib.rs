#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub use bo_tie_core::BluetoothDeviceAddress;

pub mod assigned;
pub mod eir;
pub mod oob_block;
pub mod scan;
pub mod security;
pub mod time_consts;
