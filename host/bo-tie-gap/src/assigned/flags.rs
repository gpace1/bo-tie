//! Advertising Data: Flags
//!

use super::*;

/// The list of Flags defined in the Core Specification Supplement
///
/// These are the labels for the flags in the Flag data type within the Core Specification
/// Supplement. They can be used to get a `Flag` data type with the method [`Flags::get_mut_flag`].
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Ord, PartialOrd)]
#[non_exhaustive]
pub enum FlagLabel {
    /// LE limited discoverable mode
    LeLimitedDiscoverableMode,
    /// LE general discoverable mode
    LeGeneralDiscoverableMode,
    /// BR/EDR not supported
    BrEdrNotSupported,
    /// The controller supports simultaneous BR/EDR and LE to the same device
    ControllerSupportsSimultaneousLeAndBrEdr,
    /// The host supports simultaneous BR/EDR and LE to the same device.
    #[deprecated(note = "this was depreciated in the Bluetooth Core Specification Supplement")]
    HostSupportsSimultaneousLeAndBrEdr,
}

impl core::fmt::Display for FlagLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            FlagLabel::LeLimitedDiscoverableMode => f.write_str("le limited discoverable mode"),
            FlagLabel::LeGeneralDiscoverableMode => f.write_str("le general discoverable mode"),
            FlagLabel::BrEdrNotSupported => f.write_str("BR/EDR edr not supported"),
            FlagLabel::ControllerSupportsSimultaneousLeAndBrEdr => {
                f.write_str("this controller is capable of simultaneous LE and BR/EDR to the same device")
            }
            #[allow(deprecated)]
            FlagLabel::HostSupportsSimultaneousLeAndBrEdr => {
                f.write_str("this host supports simultaneous LE and BR/EDR")
            }
        }
    }
}

impl FlagLabel {
    fn get_position(&self) -> usize {
        match *self {
            FlagLabel::LeLimitedDiscoverableMode => 0,
            FlagLabel::LeGeneralDiscoverableMode => 1,
            FlagLabel::BrEdrNotSupported => 2,
            FlagLabel::ControllerSupportsSimultaneousLeAndBrEdr => 3,
            #[allow(deprecated)]
            FlagLabel::HostSupportsSimultaneousLeAndBrEdr => 4,
        }
    }

    fn from_position(raw: usize) -> Self {
        match raw {
            0 => FlagLabel::LeLimitedDiscoverableMode,
            1 => FlagLabel::LeGeneralDiscoverableMode,
            2 => FlagLabel::BrEdrNotSupported,
            3 => FlagLabel::ControllerSupportsSimultaneousLeAndBrEdr,
            #[allow(deprecated)]
            4 => FlagLabel::HostSupportsSimultaneousLeAndBrEdr,
            _ => panic!("Position beyond core flags"),
        }
    }
}

/// A flag in the `Flags` structure
///
/// This is use d to enable/disable flags retrieved from a `Flags` data type. By default
/// a newly created flag is false, but calling `get` on a flags instance doesn't
/// guarantee that the flag is newly created. `enable`, `disable`, or `set` should be
/// called to explicitly set the state of the flag.
///
/// The highest position *enabled* flag will determine the actual length of the data
/// for the resulting transmission of Flags data.
///
/// ```rust
/// # use bo_tie_gap::assigned::flags;
/// let mut flags = flags::Flags::new();
///
/// // enable the bluetooth specified flag 'LE limited discoverable mode'
/// flags.get_mut_flag(flags::FlagLabel::LeLimitedDiscoverableMode).enable();
/// ```
#[derive(Eq, Debug, Clone)]
pub struct Flag {
    position: usize,
    enabled: bool,
}

impl Flag {
    fn new(position: usize) -> Flag {
        let enabled = false;

        Flag { position, enabled }
    }

    /// Get the label for this flag
    pub fn label(&self) -> FlagLabel {
        FlagLabel::from_position(self.position)
    }

    /// Set the state of the flag to enabled
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Set the state of the flag to disabled
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Set the state of the flag to `state`
    pub fn set(&mut self, state: bool) {
        self.enabled = state
    }

    /// Check if the flag is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the bit position of the flag
    pub fn bit_pos(&self) -> usize {
        self.position
    }
}

impl Ord for Flag {
    fn cmp(&self, other: &Flag) -> ::core::cmp::Ordering {
        self.position.cmp(&other.position)
    }
}

impl PartialOrd for Flag {
    fn partial_cmp(&self, other: &Flag) -> Option<::core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Flag {
    fn eq(&self, other: &Flag) -> bool {
        self.position == other.position
    }
}

/// AD flags type
///
/// This is the set of flags that are used
#[derive(Debug)]
pub struct Flags {
    set: [Flag; 5],
}

impl Flags {
    const ASSIGNED_TYPE: AssignedTypes = AssignedTypes::Flags;

    /// Creates a flags object with no enabled flag
    pub fn new() -> Self {
        Flags {
            set: core::array::from_fn(|index| Flag::new(index)),
        }
    }

    /// Get a flag by its label
    pub fn get_mut_flag(&mut self, core: FlagLabel) -> &mut Flag {
        &mut self.set[core.get_position()]
    }

    /// Get an iterator over the flags in Flags
    pub fn iter(&self) -> core::slice::Iter<Flag> {
        self.set.iter()
    }

    fn get_len(&self) -> u8 {
        if self.iter().any(|flag| flag.is_enabled()) {
            2
        } else {
            1
        }
    }
}

impl IntoStruct for Flags {
    fn data_len(&self) -> Result<usize, usize> {
        Ok(self.get_len().into())
    }

    fn convert_into<'a>(&self, b: &'a mut [u8]) -> Result<EirOrAdStruct<'a>, ConvertError> {
        if b.len() < self.data_len().unwrap() + HEADER_SIZE {
            Err(ConvertError::OutOfSpace {
                required: self.data_len().unwrap() + HEADER_SIZE,
                remaining: b.len(),
            })
        } else {
            let mut interim = StructIntermediate::new(b, Self::ASSIGNED_TYPE.val())?;

            let mut octet_count = 0;

            // this is a trick to ensure interim.next() is
            // not called when there are no flags enabled.
            let mut current_byte = &mut 0u8;

            for flag in self.iter().filter(|flag| flag.is_enabled()) {
                let octet = flag.position / 8;
                let bit = flag.position % 8;

                while octet_count <= octet {
                    octet_count += 1;
                    current_byte = interim.next().unwrap();
                }

                *current_byte |= 1 << bit
            }

            Ok(interim.finish())
        }
    }
}

impl IntoIterator for Flags {
    type Item = u8;
    type IntoIter = FlagsBytesIter;

    fn into_iter(self) -> Self::IntoIter {
        FlagsBytesIter(self, 0)
    }
}

impl TryFromStruct<'_> for Flags {
    fn try_from_struct(st: EirOrAdStruct<'_>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut flags = Flags::new();

        if st.get_type() == Self::ASSIGNED_TYPE.val() {
            'outer: for (index, byte) in st.get_data().iter().enumerate() {
                for pos in (0..<u8>::BITS as usize).filter(|bit_pos| 1 << *bit_pos & *byte != 0) {
                    let Some(flag) = flags.set.get_mut(pos + index * 8) else {
                        break 'outer;
                    };

                    flag.enable();
                }
            }

            Ok(flags)
        } else {
            Err(Error::IncorrectAssignedType)
        }
    }
}

/// Iterator over the bytes of the [`Flags`] type
///
/// This is returned by the [`IntoIterator`] implementation for `Flags`
pub struct FlagsBytesIter(Flags, usize);

impl Iterator for FlagsBytesIter {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        self.1 += 1;

        match self.1 {
            1 => self.0.get_len().into(),
            2 => Flags::ASSIGNED_TYPE.val().into(),
            i => {
                let bit_position = i - 3;

                self.0
                    .set
                    .get(bit_position * 8..(bit_position + 1) * 8)
                    .or_else(|| self.0.set.get(bit_position * 8..))?
                    .iter()
                    .filter(|flag| flag.is_enabled())
                    .fold(0u8, |byte, flag| 1 << (flag.position % 8) | byte)
                    .into()
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn into_raw_test() {
        let mut flags = Flags::new();

        flags.get_mut_flag(FlagLabel::LeLimitedDiscoverableMode).enable();

        assert_eq!(2, flags.data_len().unwrap());

        let mut buffer = Vec::new();

        buffer.resize(HEADER_SIZE + flags.data_len().unwrap(), 0);

        let ad_struct = flags.convert_into(&mut buffer).unwrap();

        assert_eq!(&[3u8, 1, 1, 1 << 2], ad_struct.into_inner());
    }

    #[test]
    fn from_raw_test() {
        let d_type = AssignedTypes::Flags.val();

        let raw = &[4u8, d_type, 3u8, 8u8, 7u8];

        let packet = EirOrAdStruct::try_new(raw).unwrap().unwrap().0;

        let mut flags = Flags::try_from_struct(packet).unwrap();

        assert!(flags.get_mut_flag(FlagLabel::LeLimitedDiscoverableMode).is_enabled());
        assert!(flags.get_mut_flag(FlagLabel::LeGeneralDiscoverableMode).is_enabled());
    }

    #[test]
    fn iter() {
        let mut flags = Flags::new();

        flags.get_mut_flag(FlagLabel::LeLimitedDiscoverableMode).disable();
        flags.get_mut_flag(FlagLabel::LeGeneralDiscoverableMode).enable();
        flags.get_mut_flag(FlagLabel::BrEdrNotSupported).set(true);
        flags
            .get_mut_flag(FlagLabel::ControllerSupportsSimultaneousLeAndBrEdr)
            .enable();
        #[allow(deprecated)]
        flags
            .get_mut_flag(FlagLabel::HostSupportsSimultaneousLeAndBrEdr)
            .enable();

        let raw: Vec<u8> = flags.into_iter().collect();

        assert_eq!(&*raw, &[2, AssignedTypes::Flags.val(), 0b11110u8]);
    }
}
