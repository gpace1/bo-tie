//! Bluetooth LE scanning

/// An iterator over a scanned advertiser's data
///
/// This iterator can be used to iterate over the Advertising Data structures within a received
/// advertiser's data.
///
/// # Note
/// This is an alias of [`EirOrAdIterator`](crate::gap::assigned::EirOrAdIterator).
pub type ScanIterator<'a> = crate::gap::assigned::EirOrAdIterator<'a>;

/// Scanned AD Structure
///
/// # Note
/// This is an alias of [`EirOrAdStruct`](crate::gap::assigned::EirOrAdStruct). It can be used in
/// place of the item type for [`ScanIterator`].
pub type ScannedAdStruct<'a> = crate::gap::assigned::EirOrAdStruct<'a>;
