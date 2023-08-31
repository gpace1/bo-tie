//! Host integration test framework
//!
//! This library of `bo-tie-host-tests` contains the spoofing and stub frameworks to test the host
//! defined implementation of bo-tie.
//!
//! Tests are implemented within the rust files outside of folder `std`. See the manifest for the
//! actual integration tests.
mod physical_link;

use bo_tie_l2cap::pdu::L2capFragment;
use bo_tie_l2cap::LeULogicalLink;
pub use physical_link::PhysicalLink;

/// Create a spoofed LE logical link
///
/// This returns two `LeULogicalLink`s that are "connected" to each other. When one sends L2CAP data
/// the other will receive that data.
///
/// The input `max_tx_size` is the maximum transmission size *of both physical links*.
pub fn create_le_link(max_tx_size: usize) -> (LeULogicalLink<PhysicalLink>, LeULogicalLink<PhysicalLink>) {
    let (phy_link_a, phy_link_b) = PhysicalLink::new_connection(max_tx_size);

    let le_link_a = LeULogicalLink::new(phy_link_a);
    let le_link_b = LeULogicalLink::new(phy_link_b);

    (le_link_a, le_link_b)
}

/// Create a spoofed *false* connected LE logical link
///
/// This creates a single `LeULogicalLink` and 'connects'  to the sender and receiver also returned.
///
/// The return of `create_le_false_link` is the logical link, a sender, and a receiver in that
/// order. The sender and receiver are closures for directly injecting fragments into the physical
/// link. Calling the send closure will induce a reception of that fragment by the physical link and
/// calling the recv closure will receive a fragment sent by the physical link.
///
/// The input `max_tx_size` is the maximum transmission size of the created physical link, however 
/// it is not the maximum size for the sender closure (there is no max size for this closure).
/// 
/// If the receiver is called and there is no data in channel to the logical link, then `None` is 
/// returned by the closure.
/// 
/// # Panics
/// There is no panic calling this method, but the returned sender and receiver will panic if 
/// called and the logical link has been dropped.
pub fn create_le_false_link(
    max_tx_size: usize,
) -> (
    LeULogicalLink<PhysicalLink>,
    impl Fn(L2capFragment<Vec<u8>>),
    impl FnMut() -> Option<L2capFragment<Vec<u8>>>,
) {
    let (phy_link_a, sender, receiver) = PhysicalLink::new_false_connection(max_tx_size);

    (LeULogicalLink::new(phy_link_a), sender, receiver)
}
