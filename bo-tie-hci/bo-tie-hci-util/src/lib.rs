//! Common items for the host controller interface
//!
//! This crate carries the parts of the HCI that are used by multiple HCI crates.

pub mod events;

use core::fmt;
use core::iter::Iterator;

macro_rules! is_bit_set {
    ( $bits:ident, ($indx:expr,$bit:expr), $enum:tt) => {
        if ($bits[$indx] & (1 << $bit)) != 0 {
            Some($enum)
        } else {
            None
        }
    };
}

/// The connection handle
///
/// This is used as an identifier of a connection by both the host and interface. Its created by the
/// controller when a connection is established between this device and another device.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ConnectionHandle {
    handle: u16,
}

impl fmt::Display for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.handle)
    }
}

impl fmt::Binary for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:b}", self.handle)
    }
}

impl fmt::LowerHex for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.handle)
    }
}

impl fmt::Octal for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:o}", self.handle)
    }
}

impl fmt::UpperHex for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:X}", self.handle)
    }
}

impl AsRef<u16> for ConnectionHandle {
    fn as_ref(&self) -> &u16 {
        &self.handle
    }
}

impl ConnectionHandle {
    pub const MAX: u16 = 0x0EFF;

    const ERROR: &'static str = "Raw connection handle value larger then the maximum (0x0EFF)";

    pub fn get_raw_handle(&self) -> u16 {
        self.handle
    }
}

impl core::convert::TryFrom<u16> for ConnectionHandle {
    type Error = &'static str;

    fn try_from(raw: u16) -> Result<Self, Self::Error> {
        if raw <= ConnectionHandle::MAX {
            Ok(ConnectionHandle { handle: raw })
        } else {
            Err(Self::ERROR)
        }
    }
}

impl core::convert::TryFrom<[u8; 2]> for ConnectionHandle {
    type Error = &'static str;

    fn try_from(raw: [u8; 2]) -> Result<Self, Self::Error> {
        let raw_val = <u16>::from_le_bytes(raw);

        core::convert::TryFrom::<u16>::try_from(raw_val)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EncryptionLevel {
    Off,
    E0,
    AESCCM,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ExtendedFeatures {
    SecureSimplePairingHostSupport,
    LeSupportedByHost,
    SimultaneousLEAndBREDRToSameDeviceCapableByHost,
    SecureConnectionsHostSupport,
    ConnectionlessSlaveBroadcastMasterOperation,
    ConnectionlessSlaveBroadcastSlaveOperation,
    SynchronizationTrain,
    SynchronizationScan,
    InquiryResponseNotificationEvent,
    GeneralizedInterlacedScan,
    CoarseClockAdjustment,
    SecureConnectionsControllerSupport,
    Ping,
    TrainNudging,
    SlotAvailabilityMask,
}

impl ExtendedFeatures {
    fn from_page_1(bit_pos: (u8, u8), bits: &[u8]) -> Option<Self> {
        use self::ExtendedFeatures::*;

        match bit_pos {
            (0, 0) => is_bit_set!(bits, (0, 0), SecureSimplePairingHostSupport),
            (0, 1) => is_bit_set!(bits, (0, 1), LeSupportedByHost),
            (0, 2) => is_bit_set!(bits, (0, 2), SimultaneousLEAndBREDRToSameDeviceCapableByHost),
            (0, 3) => is_bit_set!(bits, (0, 3), SecureConnectionsHostSupport),
            _ => None,
        }
    }

    fn from_page_2(bit_pos: (u8, u8), bits: &[u8]) -> Option<Self> {
        use self::ExtendedFeatures::*;

        match bit_pos {
            (0, 0) => is_bit_set!(bits, (0, 0), ConnectionlessSlaveBroadcastMasterOperation),
            (0, 1) => is_bit_set!(bits, (0, 1), ConnectionlessSlaveBroadcastSlaveOperation),
            (0, 2) => is_bit_set!(bits, (0, 2), SynchronizationTrain),
            (0, 3) => is_bit_set!(bits, (0, 3), SynchronizationScan),
            (0, 4) => is_bit_set!(bits, (0, 4), InquiryResponseNotificationEvent),
            (0, 5) => is_bit_set!(bits, (0, 5), GeneralizedInterlacedScan),
            (0, 6) => is_bit_set!(bits, (0, 6), CoarseClockAdjustment),
            (1, 0) => is_bit_set!(bits, (1, 0), SecureConnectionsControllerSupport),
            (1, 1) => is_bit_set!(bits, (1, 1), Ping),
            (1, 2) => is_bit_set!(bits, (1, 2), SlotAvailabilityMask),
            (1, 3) => is_bit_set!(bits, (1, 3), TrainNudging),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub struct EnabledFeaturesIter {
    bit_index: (u8, u8),
    raw: [u8; 8],
}

impl EnabledFeaturesIter {
    pub(crate) fn from(raw: [u8; 8]) -> Self {
        EnabledFeaturesIter {
            bit_index: (0, 0),
            raw: raw,
        }
    }

    /// Resets the iterator back to the beginning of the feature list
    pub fn reset(&mut self) {
        self.bit_index = (0, 0)
    }
}

impl Iterator for EnabledFeaturesIter {
    type Item = Features;

    fn next(&mut self) -> ::core::option::Option<Self::Item> {
        for indx in self.bit_index.0..(::core::mem::size_of_val(&self.raw) as u8) {
            for bit in self.bit_index.1..8 {
                let feature_option = Features::from_bit((indx, bit), &self.raw);

                if feature_option.is_some() {
                    self.bit_index = (indx + (bit + 1) / 8, (bit + 1) % 8);
                    return feature_option;
                }
            }
        }
        self.bit_index = (8, 8);
        None
    }
}

impl fmt::Debug for EnabledFeaturesIter {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> Result<(), ::core::fmt::Error> {
        write!(f, "Enabled features: [")?;

        let mut features = self.clone();

        // in case self.bit_index != (0,0)
        features.reset();

        for ref feature in features {
            write!(f, "{:?}", feature)?;
        }

        write!(f, "]")
    }
}

#[derive(Clone, Copy)]
pub struct EnabledExtendedFeaturesItr {
    bit_index: (u8, u8),
    raw: [u8; 2],
    page: u8,
}

impl EnabledExtendedFeaturesItr {
    /// Create extended features itr from raw and page number
    ///
    /// This will panic if the raw size isn't large enough for the page number or the page
    /// number isn't the value 1 or 2
    pub(crate) fn from(raw: &[u8], page: u8) -> Self {
        let raw_arr = match page {
            1 => [raw[0], 0u8],
            2 => [raw[0], raw[1]],
            _ => panic!("Page value is not 1 or 2"),
        };

        EnabledExtendedFeaturesItr {
            bit_index: (0, 0),
            raw: raw_arr,
            page: page,
        }
    }

    /// Resets the iterator back to the beginning of the feature list
    pub fn reset(&mut self) {
        self.bit_index = (0, 0)
    }
}

impl Iterator for EnabledExtendedFeaturesItr {
    type Item = ExtendedFeatures;

    fn next(&mut self) -> ::core::option::Option<Self::Item> {
        // Yea the match here is stupid as of v5 bluetooth. In the future page 1 or page 2 may
        // contain enought features to have a byte count different from the page number.
        for indx in self.bit_index.0..match self.page {
            1 => 1,
            2 => 2,
            _ => panic!(),
        } {
            for bit in self.bit_index.1..8 {
                let feature_option = match self.page {
                    1 => ExtendedFeatures::from_page_1((indx, bit), &self.raw),
                    2 => ExtendedFeatures::from_page_2((indx, bit), &self.raw),
                    _ => panic!(),
                };

                if feature_option.is_some() {
                    self.bit_index = (indx + (bit + 1) / 8, (bit + 1) % 8);
                    return feature_option;
                }
            }
        }
        self.bit_index = match self.page {
            1 => (1, 8),
            2 => (2, 8),
            _ => panic!(),
        };
        None
    }
}

impl fmt::Debug for EnabledExtendedFeaturesItr {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> Result<(), ::core::fmt::Error> {
        write!(f, "Enabled features: [")?;

        let mut features = self.clone();

        // in case self.bit_index != (0,0)
        features.reset();

        for ref feature in features {
            write!(f, "{:?}", feature)?;
        }

        write!(f, "]")
    }
}

#[derive(Debug, Clone)]
pub struct ExtendedInquiryResponseDataItr {
    /// Size is from spec. (v5 vol3, part C sec. 8)
    data: [u8; 240],
    indexer: usize,
}

impl ExtendedInquiryResponseDataItr {
    /// # Panics
    /// This will panic if raw_slice.len() != 240
    pub(crate) fn from(raw_slice: &[u8]) -> Self {
        let mut e = ExtendedInquiryResponseDataItr {
            data: [0u8; 240],
            indexer: 0,
        };
        e.data.copy_from_slice(raw_slice);
        e
    }
}

impl Iterator for ExtendedInquiryResponseDataItr {
    type Item = ::alloc::boxed::Box<[u8]>; // TODO convert to data types (from CSSv7)

    /// This will panic if somehow the EIR Data lengths are incorrect within the entire Extended
    /// Inquiry Response Data Message processed by this iterator
    fn next(&mut self) -> Option<Self::Item> {
        if (self.indexer < self.data.len()) && (self.data[self.indexer] != 0) {
            let eir_len = self.data[self.indexer] as usize;

            let data_index = self.indexer + 1;

            self.indexer += eir_len + 1;

            Some(self.data[data_index..eir_len].to_vec().into_boxed_slice())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_features_iter_test() {
        use self::Features::*;

        let features = [
            ThreeSlotPackets,
            FiveSlotPackets,
            Encryption,
            SlotOffset,
            TimingAccuracy,
            RoleSwitch,
            HoldMode,
            SniffMode,
            PowerControlRequests,
            HV2Packets,
            HV3Packets,
            PagingParameterNegotiation,
            FlowControlLag(2),
            BroadcastEncryption,
            EV4Packets,
            AFHCapableSlave,
            BREDRNotSupported,
            LESupportedController,
            InquiryTXPowerLevel,
        ];

        let raw = [0xFF, 0x32, 0xA2, 0x00, 0x65, 0x00, 0x00, 0x02];

        for feature in EnabledFeaturesIter::from(raw) {
            assert!(
                features.iter().find(|&&x| x == feature).is_some(),
                "Didn't find feature {:?} in list",
                feature
            );
        }
    }

    #[test]
    fn string_address_test() {
        let string_address = "4A:bc:19:3:99:C0";

        let numeric_address = [0x4au8, 0xbc, 0x19, 0x3, 0x99, 0xc0];
    }
}
