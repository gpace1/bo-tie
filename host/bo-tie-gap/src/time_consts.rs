//! Time constants from the appendix
//!
//! These constants are defined by the specification in Vol. 3, Part C, Appendix A.

/// The period between regenerating a resolvable private address (`TGAP(private_addr_int)`)
///
/// This constant defines the time period a device is allowed to use a generated resolvable private
/// address in its advertising packets. Every application that uses host based privacy must set a
/// timer with this constant as the duration to change the resolvable private address after it times
/// out. A controller must do something similar if it implements the privacy feature. For more
/// information see the *Privacy feature* GAP subsection (Vol 3, Part C, Sec. 10.7).
pub const PRIVATE_ADDRESS_INTERVAL: core::time::Duration = core::time::Duration::from_secs(15 * 60);
