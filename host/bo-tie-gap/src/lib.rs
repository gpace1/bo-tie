#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub use bo_tie_core::BluetoothDeviceAddress;

pub mod assigned;
pub mod eir;
pub mod oob_block;
pub mod scan;
pub mod security;
pub mod time_consts;
