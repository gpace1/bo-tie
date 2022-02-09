//! LE specific common items
//!
//! These are things that are common across multiple modules in `hci/le`.

use crate::hci::common::BoundsErr;
use core::convert::From;

/// The valid address types for this HCI command
///
/// - PublicDeviceAddress
///     A bluetooth public address
/// - RandomDeviceAddress
///     A bluetooth random address
/// - DevicesSendingAnonymousAdvertisements
///     A device sending advertisement packets without an address
pub enum AddressType {
    PublicDeviceAddress,
    RandomDeviceAddress,
    DevicesSendingAnonymousAdvertisements,
}

impl AddressType {
    pub fn to_value(&self) -> u8 {
        match *self {
            AddressType::PublicDeviceAddress => 0x00u8,
            AddressType::RandomDeviceAddress => 0x01u8,
            AddressType::DevicesSendingAnonymousAdvertisements => 0xFFu8,
        }
    }
}

/// Own Address Type
///
/// Default is a Public Address.
///
/// # Notes
/// These are the full explanation for the last two enumerations (as copied from
/// the core 5.0 specification):
/// - RPAFromLocalIRKPA -> Controller generates Resolvable Private Address based on
///     the local IRK from the resolving list. If the resolving list contains no
///     matching entry, use the public address.
/// - RPAFromLocalIRKRA -> Controller generates Resolvable Private Address based on
///     the local IRK from the resolving list. If the resolving list contains no
///     matching entry, use the random address from LE_Set_Random_Address.
#[cfg_attr(test, derive(Debug))]
pub enum OwnAddressType {
    PublicDeviceAddress,
    RandomDeviceAddress,
    RPAFromLocalIRKOrPA,
    RPAFromLocalIRKOrRA,
}

impl OwnAddressType {
    pub(in crate::hci) fn into_val(&self) -> u8 {
        match *self {
            OwnAddressType::PublicDeviceAddress => 0x00,
            OwnAddressType::RandomDeviceAddress => 0x01,
            OwnAddressType::RPAFromLocalIRKOrPA => 0x02,
            OwnAddressType::RPAFromLocalIRKOrRA => 0x03,
        }
    }
}

impl Default for OwnAddressType {
    fn default() -> Self {
        OwnAddressType::PublicDeviceAddress
    }
}

#[cfg_attr(test, derive(Debug))]
pub struct Frequency {
    val: u8,
}

impl Frequency {
    /// Maximum frequency value
    pub const MAX: usize = 2480;

    /// Minimum frequency value
    pub const MIN: usize = 2402;

    /// Creates a new Frequency object
    ///
    /// The value (N) passed to the adapter follows the following equation:
    ///
    /// # Error
    /// The value is less then MIN or greater than MAX. MIN or MAX is returned
    /// depending on which bound is violated.
    pub fn new(mega_hz: usize) -> Result<Frequency, usize> {
        if mega_hz < Frequency::MIN {
            Err(Frequency::MIN)
        } else if mega_hz > Frequency::MAX {
            Err(Frequency::MAX)
        } else {
            Ok(Frequency {
                val: ((mega_hz - 2402) / 2) as u8,
            })
        }
    }

    pub(in crate::hci) fn get_val(&self) -> u8 {
        self.val
    }
}

pub struct IntervalRange<T>
where
    T: PartialEq + PartialOrd,
{
    pub low: T,
    pub hi: T,
    pub micro_sec_conv: u64,
}

impl<T> IntervalRange<T>
where
    T: PartialEq + PartialOrd,
{
    pub fn contains(&self, val: &T) -> bool {
        self.low <= *val && *val <= self.hi
    }
}

impl From<IntervalRange<u16>> for IntervalRange<core::time::Duration> {
    fn from(raw: IntervalRange<u16>) -> Self {
        IntervalRange {
            low: core::time::Duration::from_micros(raw.low as u64 * raw.micro_sec_conv),
            hi: core::time::Duration::from_micros(raw.hi as u64 * raw.micro_sec_conv),
            micro_sec_conv: raw.micro_sec_conv,
        }
    }
}

macro_rules! interval {
    ( $(#[ $expl:meta ])* $name:ident, $raw_low:expr, $raw_hi:expr,
        SpecDef, $raw_default:expr, $micro_sec_conv:expr ) =>
    {
        make_interval!(
            $(#[ $expl ])*
            $name,
            $raw_low,
            $raw_hi,
            #[doc = "This is a Bluetooth Specification defined default value"],
            $raw_default,
            $micro_sec_conv
        );
    };
    ( $(#[ $expl:meta ])* $name:ident, $raw_low:expr, $raw_hi:expr,
        ApiDef, $raw_default:expr, $micro_sec_conv:expr ) =>
    {
        make_interval!(
            $(#[ $expl ])*
            $name,
            $raw_low,
            $raw_hi,
            #[doc = "This is a default value defined by the API, the Bluetooth Specification"]
            #[doc = "does not specify a default for this interval"],
            $raw_default,
            $micro_sec_conv
        );
    }
}

macro_rules! make_interval {
    ( $(#[ $expl:meta ])*
        $name:ident,
        $raw_low:expr,
        $raw_hi:expr,
        $(#[ $raw_default_note:meta ])*,
        $raw_default:expr,
        $micro_sec_conv:expr) =>
    {
        $(#[ $expl ])*
        #[cfg_attr(test,derive(Debug))]
        pub struct $name {
            interval: u16,
        }

        impl $name {

            const RAW_RANGE: crate::hci::le::common::IntervalRange<u16> = crate::hci::le::common::IntervalRange{
                low: $raw_low,
                hi: $raw_hi,
                micro_sec_conv: $micro_sec_conv,
            };

            /// Create an interval from a raw value
            ///
            /// # Error
            /// The value is out of bounds.
            pub fn try_from_raw( raw: u16 ) -> Result<Self, &'static str> {
                if $name::RAW_RANGE.contains(&raw) {
                    Ok($name{
                        interval: raw,
                    })
                }
                else {
                    Err(concat!("Raw value out of range: ", $raw_low, "..=", $raw_hi))
                }
            }

            /// Create an advertising interval from a Duration
            ///
            /// # Error
            /// the value is out of bounds.
            pub fn try_from_duration( duration: core::time::Duration ) -> Result<Self, &'static str>
            {
                let duration_range = crate::hci::le::common::IntervalRange::<core::time::Duration>::from($name::RAW_RANGE);

                if duration_range.contains(&duration) {
                    Ok( $name {
                        interval: (duration.as_secs() * (1000000 / $micro_sec_conv)) as u16 +
                            (duration.subsec_micros() / $micro_sec_conv as u32) as u16,
                    })
                }
                else {
                    Err(concat!("Duration out of range: ",
                        stringify!( ($raw_low * $micro_sec_conv) ),
                        "us..=",
                        stringify!( ($raw_hi * $micro_sec_conv) ),
                        "us"))
                }
            }

            /// Get the raw value of the interval
            pub fn get_raw_val(&self) -> u16 { self.interval }

            /// Get the value of the interval as a `Duration`
            pub fn get_duration(&self) -> core::time::Duration {
                core::time::Duration::from_micros(
                    (self.interval as u64) * $micro_sec_conv
                )
            }
        }

        impl Default for $name {

            /// Creates an Interval with the default value for the interval
            ///
            $(#[ $raw_default_note ])*
            fn default() -> Self {
                $name{
                    interval: $raw_default,
                }
            }
        }
    };
}

interval!(
    #[derive(Debug, Clone, Copy)]
    ConnectionInterval,
    0x0006,
    0x0C80,
    ApiDef,
    0x0006,
    1250
);

pub struct ConnectionEventLength {
    pub minimum: u16,
    pub maximum: u16,
}

impl ::core::default::Default for ConnectionEventLength {
    fn default() -> Self {
        Self {
            minimum: 0,
            maximum: 0xFFFF,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LEAddressType {
    PublicDeviceAddress,
    RandomDeviceAddress,
    PublicIdentityAddress,
    RandomIdentityAddress,
}

impl LEAddressType {
    pub(crate) fn from(raw: u8) -> Self {
        match raw {
            0x00 => LEAddressType::PublicDeviceAddress,
            0x01 => LEAddressType::RandomDeviceAddress,
            0x02 => LEAddressType::PublicIdentityAddress,
            0x03 => LEAddressType::RandomIdentityAddress,
            _ => panic!("Unknown {}", raw),
        }
    }

    pub(crate) fn into_raw(&self) -> u8 {
        match *self {
            LEAddressType::PublicDeviceAddress => 0x0,
            LEAddressType::RandomDeviceAddress => 0x1,
            LEAddressType::PublicIdentityAddress => 0x2,
            LEAddressType::RandomIdentityAddress => 0x3,
        }
    }
}

/// A list of all possible features for Bluetooth v5
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum LEFeatures {
    LEEncryption,
    ConnectionParametersRequestProcedure,
    ExtendedRejectIndication,
    SlaveInitiatedFeaturesExchange,
    LEPing,
    LEDataPacketLengthExtension,
    LLPrivacy,
    ExtendedScannerFilterPolicies,
    LE2MPHY,
    StableModulationIndexTransmitter,
    StableModulationIndexReceiver,
    LECodedPHY,
    LEExtendedAdvertising,
    LEPeriodicAdvertising,
    ChannelSelectionAlgorithm2,
    LEPowerClass1,
    MinimumNumberOfUsedChannelsProcedure,
}

impl LEFeatures {
    fn from_bit(bit_pos: (u8, u8), bits: &[u8]) -> Option<LEFeatures> {
        use LEFeatures::*;

        match bit_pos {
            (0, 0) => is_bit_set!(bits, (0, 0), LEEncryption),
            (0, 1) => is_bit_set!(bits, (0, 1), ConnectionParametersRequestProcedure),
            (0, 2) => is_bit_set!(bits, (0, 2), ExtendedRejectIndication),
            (0, 3) => is_bit_set!(bits, (0, 3), SlaveInitiatedFeaturesExchange),
            (0, 4) => is_bit_set!(bits, (0, 4), LEPing),
            (0, 5) => is_bit_set!(bits, (0, 5), LEDataPacketLengthExtension),
            (0, 6) => is_bit_set!(bits, (0, 6), LLPrivacy),
            (0, 7) => is_bit_set!(bits, (0, 7), ExtendedScannerFilterPolicies),
            (1, 0) => is_bit_set!(bits, (1, 0), LE2MPHY),
            (1, 1) => is_bit_set!(bits, (1, 1), StableModulationIndexTransmitter),
            (1, 2) => is_bit_set!(bits, (1, 2), StableModulationIndexReceiver),
            (1, 3) => is_bit_set!(bits, (1, 3), LECodedPHY),
            (1, 4) => is_bit_set!(bits, (1, 4), LEExtendedAdvertising),
            (1, 5) => is_bit_set!(bits, (1, 5), LEPeriodicAdvertising),
            (1, 6) => is_bit_set!(bits, (1, 6), ChannelSelectionAlgorithm2),
            (1, 7) => is_bit_set!(bits, (1, 7), LEPowerClass1),
            (2, 0) => is_bit_set!(bits, (2, 0), MinimumNumberOfUsedChannelsProcedure),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct EnabledLeFeaturesItr {
    raw: [u8; 8],
    bit_index: (u8, u8),
}

impl EnabledLeFeaturesItr {
    pub(crate) fn from(raw: [u8; 8]) -> Self {
        EnabledLeFeaturesItr { bit_index: (0, 0), raw }
    }

    /// Resets the iterator back to the beginning of the feature list
    pub fn reset(&mut self) {
        self.bit_index = (0, 0)
    }
}

impl Iterator for EnabledLeFeaturesItr {
    type Item = LEFeatures;

    fn next(&mut self) -> core::option::Option<Self::Item> {
        // Yea the match here is stupid as of v5 bluetooth. In the future page 1 or page 2 may
        // contain enough features to have a byte count different from the page number.
        for index in self.bit_index.0..(::core::mem::size_of_val(&self.raw) as u8) {
            for bit in self.bit_index.1..8 {
                if let Some(feature_option) = LEFeatures::from_bit((index, bit), &self.raw) {
                    self.bit_index = (index + (bit + 1) / 8, (bit + 1) % 8);
                    return Some(feature_option);
                }
            }
        }
        self.bit_index = (8, 8);
        None
    }
}

impl core::fmt::Debug for EnabledLeFeaturesItr {
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
pub struct ExtendedAdvertisingAndScanResponseData {
    data: alloc::vec::Vec<u8>,
}

impl ExtendedAdvertisingAndScanResponseData {
    pub(crate) fn from<T>(data: T) -> Self
    where
        T: Into<alloc::vec::Vec<u8>>,
    {
        Self { data: data.into() }
    }

    /// Iterate over the advertising data structures
    pub fn iter(&self) -> crate::gap::assigned::EirOrAdIterator {
        crate::gap::assigned::EirOrAdIterator::from(self.data.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct SupervisionTimeout {
    timeout: u16,
}

impl SupervisionTimeout {
    const CNV: u64 = 10; // unit: milliseconds
    pub const MIN: u16 = 0x000A;
    pub const MAX: u16 = 0x0C80;

    pub(crate) fn from(raw: u16) -> Self {
        debug_assert!(raw >= Self::MIN && raw <= Self::MAX);

        SupervisionTimeout { timeout: raw }
    }

    pub fn try_from_raw(val: u16) -> Result<Self, BoundsErr<u16>> {
        Ok(SupervisionTimeout {
            timeout: BoundsErr::check(val, Self::MIN, Self::MAX)?,
        })
    }

    /// Create an advertising interval from a Duration
    ///
    /// # Error
    /// the value is out of bounds.
    pub fn try_from_duration(duration: core::time::Duration) -> Result<Self, &'static str> {
        let min = core::time::Duration::from_millis(Self::MIN as u64 * Self::CNV);
        let max = core::time::Duration::from_millis(Self::MAX as u64 * Self::CNV);

        if duration >= min && duration <= max {
            Ok(SupervisionTimeout {
                timeout: (duration.as_secs() * (1000 / Self::CNV)) as u16
                    + (duration.subsec_millis() / Self::CNV as u32) as u16,
            })
        } else {
            Err(concat!(
                "Duration out of range: ",
                stringify!( ($raw_low * $micro_sec_conv) ),
                "us..=",
                stringify!( ($raw_hi * $micro_sec_conv) ),
                "us"
            ))
        }
    }

    pub fn as_duration(&self) -> core::time::Duration {
        core::time::Duration::from_millis((self.timeout as u64) * Self::CNV)
    }

    pub fn get_timeout(&self) -> u16 {
        self.timeout
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionLatency {
    latency: u16,
}

impl ConnectionLatency {
    const MAX: u16 = 0x01F3;

    pub(crate) fn from(raw: u16) -> Self {
        debug_assert!(raw <= Self::MAX);

        ConnectionLatency { latency: raw }
    }

    /// Try to create an ConnectionLatency
    ///
    /// Must be a value less than or equal to 0x01F3
    ///
    /// # Error
    /// The parameter is greater then 0x01F3
    pub fn try_from(raw: u16) -> Result<Self, &'static str> {
        if raw <= Self::MAX {
            Ok(Self { latency: raw })
        } else {
            Err("Connection Latency cannot be greater than 0x01F3")
        }
    }

    // Get the latency value
    pub fn get_latency(&self) -> u16 {
        self.latency
    }
}
