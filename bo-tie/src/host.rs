//! The host protocols

#[doc(inline)]
pub use bo_tie_att as att;
#[doc(inline)]
pub use bo_tie_gap as gap;
#[doc(inline)]
pub use bo_tie_gatt as gatt;
#[doc(inline)]
pub use bo_tie_l2cap as l2cap;
#[doc(inline)]
pub use bo_tie_sm as sm;

pub use bo_tie_host_util::{Uuid, UuidVersion};
