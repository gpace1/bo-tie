//! The host protocols

#[cfg(feature = "att")]
#[doc(inline)]
pub use bo_tie_att as att;

#[doc(inline)]
#[cfg(feature = "gap")]
pub use bo_tie_gap as gap;

#[cfg(feature = "gatt")]
#[doc(inline)]
pub use bo_tie_gatt as gatt;

#[cfg(feature = "l2cap")]
#[doc(inline)]
pub use bo_tie_l2cap as l2cap;

#[cfg(feature = "sm")]
#[doc(inline)]
pub use bo_tie_sm as sm;

pub use bo_tie_host_util::{Uuid, UuidVersion};
