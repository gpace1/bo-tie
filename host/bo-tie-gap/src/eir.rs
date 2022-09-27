//! Extended Inquiry Response
//!
//! Extended Inquiry Response data structures.

pub use crate::assigned::EirOrAdStruct as EirStruct;
pub use crate::assigned::Sequence;
use crate::assigned::{EirOrAdIterator, Error};

/// Iterator of extended inquiry responses
///
/// This iterator is used to convert a payload of EIR data structures into singular EIR structures.
///
/// ```
/// # use bo_tie_gap::eir::EirStructIter;
/// let raw_eir_data = &[16, 9, 69, 73, 82, 32, 100, 111, 99, 32, 101, 120, 97, 109, 112, 108, 101, 3, 77, 32, 11];
///
/// let mut iter = EirStructIter::new(raw_eir_data);
///
/// assert!(iter.next().is_some());
/// assert!(iter.next().is_some());
/// assert!(iter.next().is_none());
/// ```
#[derive(Debug, Copy, Clone)]
#[repr(transparent)]
pub struct EirStructIter<'a> {
    iter: EirOrAdIterator<'a>,
}

impl<'a> EirStructIter<'a> {
    /// Create an EirStructItr
    ///
    /// Input `eir_data` is expected to be a slice of extended inquiry response data (see the
    /// Bluetooth Specification Vol 3, Part C, section 8)
    pub fn new(eir_data: &'a [u8]) -> Self {
        let iter = EirOrAdIterator::new(eir_data);

        EirStructIter { iter }
    }
}

impl<'a> Iterator for EirStructIter<'a> {
    type Item = Result<EirStruct<'a>, Error>;

    /// This will panic if somehow the EIR Data lengths are incorrect within the entire Extended
    /// Inquiry Response Data Message processed by this iterator
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}
