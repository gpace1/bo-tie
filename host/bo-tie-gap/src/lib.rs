//! Generic Access Protocol
//!
//! This crate contains some of the implementation of the Generic Access Protocol (GAP). Most of
//! GAP is data standardization, labeling, and conformity so there is not much of substance here
//! besides various types. Mose of the specification of GAP is applied within the protocols that
//! it refers to, but there is some things that are unique to GAP
//!
//! # Extended Inquiry Response or Advertising Data
//! The [`assigned`] module contains the numbers and data formats assigned by the SIG for an
//! Extended Inquiry Response (EIR), Advertising Data (AD), or a Security Manager's out of band
//! data. The Bluetooth Specification within GAP only provides for the high level data format (which
//! is a type identifier followed by the data). The SIG has assigned numbers to the types and also
//! formalized the associated data formats for various kinds of information. Only some of these data
//! formats are implemented within `assigned`.
//!
//! ```
//! # use bo_tie_gap::assigned;
//! use assigned::{flags, local_name};
//! // advertising data example
//!
//! let mut ad_flags = flags::Flags::new();
//!
//! ad_flags.get_core(flags::CoreFlags::LELimitedDiscoverableMode).enable();
//! ad_flags.get_core(flags::CoreFlags::BREDRNotSupported).enable();
//!
//! let local_name = local_name::LocalName::new("advertising example", None);
//!
//! let buffer = &mut [0u8; 30];
//!
//! let mut sequencer = assigned::Sequence::new(buffer);
//!
//! sequencer.try_add(&ad_flags).unwrap();
//!
//! sequencer.try_add(&local_name).unwrap();
//!
//! let expected_advertising_data: [u8; 24] = [
//!     // flags advertising data. the type is 0x1 and the data is 0x5
//!     0x2, 0x1, 0x5,
//!     
//!     // a complete local name. the type is 0x9 and followed by "advertising example"
//!     0x14, 0x9, 0x61, 0x64, 0x76, 0x65, 0x72, 0x74, 0x69, 0x73, 0x69,
//!     0x6e, 0x67, 0x20, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
//! ];
//!
//! assert_eq!(&expected_advertising_data, &sequencer[..24])
//! ```

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub use bo_tie_util::BluetoothDeviceAddress;

pub mod assigned;
pub mod eir;
pub mod oob_block;
pub mod scan;
