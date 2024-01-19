//! Bindings that could not be generated with `rust-bindgen`
//!
//! Generally these things are here because the `rust-bindgen` could not generate them from the
//! header files.

macro_rules! bit {
    ($bit:literal) => {
        1 << $bit
    };
}

pub(crate) const MGMT_SETTING_POWERED: u32 = bit!(0);
pub(crate) const MGMT_SETTING_CONNECTABLE: u32 = bit!(1);
pub(crate) const MGMT_SETTING_FAST_CONNECTABLE: u32 = bit!(2);
pub(crate) const MGMT_SETTING_DISCOVERABLE: u32 = bit!(3);
pub(crate) const MGMT_SETTING_BONDABLE: u32 = bit!(4);
pub(crate) const MGMT_SETTING_LINK_SECURITY: u32 = bit!(5);
pub(crate) const MGMT_SETTING_SSP: u32 = bit!(6);
pub(crate) const MGMT_SETTING_BREDR: u32 = bit!(7);
pub(crate) const MGMT_SETTING_HS: u32 = bit!(8);
pub(crate) const MGMT_SETTING_LE: u32 = bit!(9);
pub(crate) const MGMT_SETTING_ADVERTISING: u32 = bit!(10);
pub(crate) const MGMT_SETTING_SECURE_CONN: u32 = bit!(11);
pub(crate) const MGMT_SETTING_DEBUG_KEYS: u32 = bit!(12);
pub(crate) const MGMT_SETTING_PRIVACY: u32 = bit!(13);
pub(crate) const MGMT_SETTING_CONFIGURATION: u32 = bit!(14);
pub(crate) const MGMT_SETTING_STATIC_ADDRESS: u32 = bit!(15);
pub(crate) const MGMT_SETTING_PHY_CONFIGURATION: u32 = bit!(16);
pub(crate) const MGMT_SETTING_WIDEBAND_SPEECH: u32 = bit!(17);
pub(crate) const MGMT_SETTING_CIS_CENTRAL: u32 = bit!(18);
pub(crate) const MGMT_SETTING_CIS_PERIPHERAL: u32 = bit!(19);
pub(crate) const MGMT_SETTING_ISO_BROADCASTER: u32 = bit!(20);
pub(crate) const MGMT_SETTING_ISO_SYNC_RECEIVER: u32 = bit!(21);
