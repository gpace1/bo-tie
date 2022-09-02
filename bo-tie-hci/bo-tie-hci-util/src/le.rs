//! HCI Utilites specific to LE
//!
//! These utilities are specific to HCI LE events and LE commands.

/// The valid address types for whitelists
///
/// - PublicDeviceAddress
///     A bluetooth public address
/// - RandomDeviceAddress
///     A bluetooth random address
/// - DevicesSendingAnonymousAdvertisements
///     A device sending advertisement packets without an address
pub enum WhiteListedAddressType {
    PublicDeviceAddress,
    RandomDeviceAddress,
    DevicesSendingAnonymousAdvertisements,
}

impl WhiteListedAddressType {
    pub fn to_value(&self) -> u8 {
        match *self {
            WhiteListedAddressType::PublicDeviceAddress => 0x00u8,
            WhiteListedAddressType::RandomDeviceAddress => 0x01u8,
            WhiteListedAddressType::DevicesSendingAnonymousAdvertisements => 0xFFu8,
        }
    }
}

/// Own Address Type
///
/// Default is a Public Address.
///
/// # Notes
/// These are the full explanation for the last two enumerations (as copied from
/// the core specification):
/// - RPAFromLocalIRKPA -> Controller generates Resolvable Private Address based on
///     the local IRK from the resolving list. If the resolving list contains no
///     matching entry, use the public address.
/// - RPAFromLocalIRKRA -> Controller generates Resolvable Private Address based on
///     the local IRK from the resolving list. If the resolving list contains no
///     matching entry, use the random address from LE_Set_Random_Address.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum OwnAddressType {
    PublicDeviceAddress,
    RandomDeviceAddress,
    RPAFromLocalIRKOrPA,
    RPAFromLocalIRKOrRA,
}

impl OwnAddressType {
    pub fn val(self) -> u8 {
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

#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
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
    /// The value is less then [`MIN`](Frequency::MIN) or greater than [`MAX`](Frequency::MAX).
    /// `MIN` or `MAX` is returned depending on which bound is violated.
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

    /// Get the value
    ///
    /// This returns the value used to represent the frequency.
    pub fn raw_val(&self) -> u8 {
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
        $raw_low:literal,
        $raw_hi:literal,
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

            const RAW_RANGE: IntervalRange<u16> = IntervalRange{
                low: $raw_low,
                hi: $raw_hi,
                micro_sec_conv: $micro_sec_conv,
            };

            /// Try to create a `
            #[doc = stringify!($name)]
            /// ` from a raw u16 value
            ///
            /// # Error
            /// Input `raw` is either greater than
            #[doc = stringify!($raw_hi)]
            /// or the value is less than
            #[doc = stringify!($raw_low)]
            /// .
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
                let duration_range = IntervalRange::<core::time::Duration>::from($name::RAW_RANGE);

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
pub enum AddressType {
    PublicDeviceAddress,
    RandomDeviceAddress,
    PublicIdentityAddress,
    RandomIdentityAddress,
}

impl AddressType {
    /// Try to create a `SupervisionTimeout` from a raw u8 value
    ///
    /// # Error
    /// Input `raw` is not a valid identifier for an address type
    pub(crate) fn try_from_raw(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(AddressType::PublicDeviceAddress),
            0x01 => Ok(AddressType::RandomDeviceAddress),
            0x02 => Ok(AddressType::PublicIdentityAddress),
            0x03 => Ok(AddressType::RandomIdentityAddress),
            _ => Err(alloc::format!("Unknown {}", raw)),
        }
    }

    pub(crate) fn into_raw(&self) -> u8 {
        match *self {
            AddressType::PublicDeviceAddress => 0x0,
            AddressType::RandomDeviceAddress => 0x1,
            AddressType::PublicIdentityAddress => 0x2,
            AddressType::RandomIdentityAddress => 0x3,
        }
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
    ///
    /// This iterates over the AD structures that were present within the scanned advertising data.
    /// The type [`EirOrAdStruct`] output by the iterator can be converted into either an assigned
    /// data type (see the Supplement to the Bluetooth Core Specification) or a custom extended
    /// inquiry response data type.
    ///
    /// [`EirOrAdStruct`]: bo_tie_gap::EirOrAdStruct
    #[cfg(feature = "gap")]
    pub fn iter(&self) -> bo_tie_gap::assigned::EirOrAdIterator {
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

    /// Try to create a `SupervisionTimeout` from a raw u16 value
    ///
    /// # Error
    /// Input `raw` is either greater than 0x0C80 or the value is less than 0x000A.
    pub fn try_from_raw(raw: u16) -> Result<Self, &'static str> {
        if raw < Self::MIN {
            Err("Supervision timeout below minimum")
        } else if raw > Self::MAX {
            Err("Supervision timeout above maximum")
        } else {
            Ok(SupervisionTimeout { timeout: raw })
        }
    }

    /// Create an advertising interval from a Duration
    ///
    /// # Error
    /// the value is either greater than 0x0C80 or the value is less than 0x000A.
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

    /// Try to create a `ConnectionLatency` from a raw u16 value
    ///
    /// Must be a value less than or equal to 0x01F3
    ///
    /// # Error
    /// The input `raw` is greater then 0x01F3
    pub fn try_from_raw(raw: u16) -> Result<Self, &'static str> {
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
