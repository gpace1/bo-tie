//! Types for the GAP service

use bo_tie_att::{TransferFormatError, TransferFormatInto, TransferFormatTryFrom};

#[derive(PartialEq)]
pub struct PreferredConnectionParameters {
    pub interval_min: u16,
    pub interval_max: u16,
    pub latency: u16,
    pub timeout: u16,
}

impl TransferFormatTryFrom for PreferredConnectionParameters {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        if raw.len() != 8 {
            return Err(TransferFormatError::bad_size(
                "preferred connection parameters",
                8,
                raw.len(),
            ));
        }

        let interval_min = <u16>::from_le_bytes([raw[0], raw[1]]);
        let interval_max = <u16>::from_le_bytes([raw[2], raw[3]]);
        let latency = <u16>::from_le_bytes([raw[4], raw[5]]);
        let timeout = <u16>::from_le_bytes([raw[6], raw[7]]);

        Ok(PreferredConnectionParameters {
            interval_min,
            interval_max,
            latency,
            timeout,
        })
    }
}

impl TransferFormatInto for PreferredConnectionParameters {
    fn len_of_into(&self) -> usize {
        8
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[0..2].copy_from_slice(&self.interval_min.to_le_bytes());

        into_ret[2..4].copy_from_slice(&self.interval_max.to_le_bytes());

        into_ret[4..6].copy_from_slice(&self.latency.to_le_bytes());

        into_ret[6..8].copy_from_slice(&self.timeout.to_le_bytes());
    }
}
