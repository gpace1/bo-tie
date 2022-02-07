//! Out of band data block type
//!
//! This is used to encapsulate data sent as part of the out of band process in either Simple
//! Pairing, or Secure Connections

use crate::gap::assigned::{EirOrAdStruct, IntoStruct};
use alloc::vec::Vec;

/// The minimum length for an OOB data block
const MIN_LEN: usize = 8;

/// Builder of a OOB data block
pub struct OobDataBlockBuilder {
    address: crate::BluetoothDeviceAddress,
}

impl OobDataBlockBuilder {
    /// Create a new `OobDataBlockBuilder`
    pub fn new(address: crate::BluetoothDeviceAddress) -> Self {
        OobDataBlockBuilder { address }
    }

    /// Create the OOB data block
    ///
    /// This takes an iterator of types that implement [`IntoRaw`](crate::gap::assigned::IntoRaw).
    /// These are considered 'optional' as part of the OOB data block specification, but higher
    /// layer protocols usually have specific types that need to be sent.
    ///
    /// # Note
    /// An OOB data block is made up of extended inquiry response (EIR) structures which happen to
    /// be the exact same thing as an advertising data (AD) structure. They just happen to be used
    /// in either an extended inquiry response (which is part of BR/EDR) or an out of band data
    /// block.
    ///
    /// # Panic
    /// An overflow will occur if data within the iterator generates a payload greater than
    /// (u16::MAX - 8) bytes.
    pub fn build<'a, I>(&self, optional: &'a I) -> alloc::vec::Vec<u8>
    where
        I: 'a + ?Sized,
        &'a I: IntoIterator<Item = &'a &'a dyn IntoStruct>,
    {
        let optional_size: usize = optional
            .into_iter()
            .map(|d| match d.data_len() {
                Ok(len) => len,
                Err(len) => len,
            })
            .sum();

        let size = MIN_LEN + optional_size;

        assert!(size <= <u16>::MAX as usize, "Out of Band data block is too large");

        let mut data = Vec::new();

        data.resize(size, 0);

        // set the length
        data[0..2].copy_from_slice(&(size as u16).to_le_bytes());

        // set the address
        data[2..8].copy_from_slice(&self.address);

        let mut sequence = crate::gap::assigned::Sequence::new(&mut data[MIN_LEN..]);

        // add the EIR (extended inquiry response) structures (same format as an AD structure)
        for item in optional.into_iter() {
            sequence = sequence.try_add(*item).unwrap();
        }

        data
    }
}

/// An Extended Inquiry Response Structure
pub type ExtendedInquiryResponseStruct<'a> = EirOrAdStruct<'a>;

/// OOB data block
///
/// This is used for processing an OOB data block.
pub struct OobDataBlockIter {
    address: crate::BluetoothDeviceAddress,
    raw: alloc::vec::Vec<u8>,
}

impl OobDataBlockIter {
    /// Create a new `OobDataBlockIter`
    ///
    /// This takes the raw OOB data block.
    pub fn new(mut raw: alloc::vec::Vec<u8>) -> Self {
        let mut len_arr = [0; 2];

        len_arr.copy_from_slice(&raw[..2]);

        let len: usize = <u16>::from_le_bytes(len_arr).into();

        raw.truncate(len);

        let mut address = crate::BluetoothDeviceAddress::default();

        address.copy_from_slice(&raw[2..MIN_LEN]);

        OobDataBlockIter { address, raw }
    }

    pub fn get_address(&self) -> crate::BluetoothDeviceAddress {
        self.address
    }

    /// Iterator over the EIR Data
    ///
    /// This iterates over the EIR data structures within the OOB data block.
    pub fn iter(&self) -> impl Iterator<Item = ExtendedInquiryResponseStruct<'_>> {
        struct EirIterator<'a>(&'a [u8]);

        impl<'a> Iterator for EirIterator<'a> {
            type Item = ExtendedInquiryResponseStruct<'a>;

            fn next(&mut self) -> Option<Self::Item> {
                ExtendedInquiryResponseStruct::try_new(self.0)
                    .ok()
                    .flatten()
                    .map(|(eir, rest)| {
                        self.0 = rest;
                        eir
                    })
            }
        }

        EirIterator(&self.raw[MIN_LEN..])
    }
}
