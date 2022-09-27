//! Host Controller Interface Commands
//!
//! These are the commands listed under Vol 4, Part E, section 7 of the Bluetooth Core
//! Specifications. The modules match the sub sections header names except for *Events* which is
//! elevated to be within the [parent] module.
//!
//! [parent]: super

#[cfg(feature = "le")]
pub mod cb;
#[cfg(feature = "le")]
pub mod info_params;
#[cfg(feature = "le")]
pub mod le;
#[cfg(feature = "le")]
pub mod link_control;
pub mod link_policy;
#[cfg(feature = "le")]
pub mod status_prams;
pub mod testing;
