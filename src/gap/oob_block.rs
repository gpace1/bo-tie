//! Out of band data block type
//!
//! This is used to encapsulate data sent as part of the out of band process in either Simple
//! Pairing, or Secure Connections

use crate::gap::assigned::IntoRaw;

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
    /// # Panic
    /// An overflow will occur if data within the iterator generates a payload greater than
    /// (u16::MAX - 8) bytes.
    pub fn build<'a, I>(&self, optional: I) -> alloc::vec::Vec<u8>
    where
        I: IntoIterator<Item = &'a &'a dyn IntoRaw>,
    {
        let mut data = [0; MIN_LEN].to_vec();

        let mut len = MIN_LEN;

        // set the address
        data[2..].copy_from_slice(&self.address);

        for raw_ad in optional.into_iter().map(|i| i.into_raw()) {
            len += raw_ad.len();

            debug_assert!(len < <u16>::MAX.into());

            data.extend(raw_ad);
        }

        // set the total length in the data block. This will panic if the length gets too large.
        data[0..2].copy_from_slice(&<u16>::to_le_bytes(len as u16));

        data
    }
}

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

    /// Iterator over the EIR Data (or AD)
    ///
    /// This iterators over the EIR data structures within the OOB data block. The return is a pair
    /// containing the assigned number and the data.
    ///
    /// # Note
    /// 1) EIR data structures are in the same format as advertising data
    /// 2) This provides no validation of the raw data.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &[u8])> {
        struct EirIterator<'a>(&'a [u8]);

        impl<'a> Iterator for EirIterator<'a> {
            type Item = (u8, &'a [u8]);

            fn next(&mut self) -> Option<Self::Item> {
                if self.0.len() == 0 {
                    None
                } else {
                    let data_len: usize = self.0[0].into();

                    let ad_len = 1 + data_len;

                    // Prevent panics by short circuiting the iterator if the length is invalid or 0
                    if ad_len <= self.0.len() && ad_len > 0 {
                        let ret_type = self.0[1];
                        let ret_vec = &self.0[2..ad_len];

                        self.0 = &self.0[ad_len..];

                        Some((ret_type, ret_vec))
                    } else {
                        self.0 = &[];

                        None
                    }
                }
            }
        }

        EirIterator(&self.raw[MIN_LEN..])
    }
}
