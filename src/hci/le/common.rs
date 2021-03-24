//! `hci` common items
//!
//! These are things that are common to multiple modules in `hci`.

use core::convert::From;

/// The valid address types for this HCI command
///
/// - PublicDeviceAddress
///     A bluetooth public address
/// - RandomDeviceAddress
///     A bluetooth random address
/// - DevicesSendingAnonymousAdvertisements
///     A device sending advertisment packets without an address
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
    RPAFromLocalIRKPA,
    RPAFromLocalIRKRA,
}

impl OwnAddressType {
    pub(super) fn into_val(&self) -> u8 {
        match *self {
            OwnAddressType::PublicDeviceAddress => 0x00,
            OwnAddressType::RandomDeviceAddress => 0x01,
            OwnAddressType::RPAFromLocalIRKPA => 0x02,
            OwnAddressType::RPAFromLocalIRKRA => 0x03,
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

    pub(in super::super) fn get_val(&self) -> u8 {
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
            #[doc("This is a Bluetooth Specification defined default value")],
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
            #[doc("This is a default value defined by the API, the Bluetooth Specification")]
            #[doc("does not specify a default for this interval")],
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
