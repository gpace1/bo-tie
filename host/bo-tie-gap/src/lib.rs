#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub use bo_tie_util::BluetoothDeviceAddress;

pub mod assigned;
pub mod eir;
pub mod oob_block;
pub mod scan;
pub mod security;
