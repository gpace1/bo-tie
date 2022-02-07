//! Advertising Data: Flags
//!

use super::*;
use alloc::collections::BTreeSet;
use core::cell::Cell;

pub enum CoreFlags {
    /// LE limited discoverable mode
    LELimitedDiscoverableMode,
    /// LE general discoverable mode
    LEGeneralDiscoverableMode,
    /// BR/EDR not supported
    BREDRNotSupported,
    /// The controller supports simultanious BR/EDR and LE to the same device
    ControllerSupportsSimultaniousLEAndBREDR,
    /// The host supports simultanious BR/EDR and LE to the same device.
    HostSupportsSimultaniousLEAndBREDR,
}

impl CoreFlags {
    /// The number of bits that are required for the core flags & reserved flags
    #[inline]
    fn get_bit_cnt() -> usize {
        8
    }

    fn get_position(&self) -> usize {
        match *self {
            CoreFlags::LELimitedDiscoverableMode => 0,
            CoreFlags::LEGeneralDiscoverableMode => 1,
            CoreFlags::BREDRNotSupported => 2,
            CoreFlags::ControllerSupportsSimultaniousLEAndBREDR => 3,
            CoreFlags::HostSupportsSimultaniousLEAndBREDR => 4,
        }
    }

    fn from_position(raw: usize) -> Self {
        match raw {
            0 => CoreFlags::LELimitedDiscoverableMode,
            1 => CoreFlags::LEGeneralDiscoverableMode,
            2 => CoreFlags::BREDRNotSupported,
            3 => CoreFlags::ControllerSupportsSimultaniousLEAndBREDR,
            4 => CoreFlags::HostSupportsSimultaniousLEAndBREDR,
            _ => panic!("Position beyond core flags"),
        }
    }
}

pub enum FlagType {
    Core(CoreFlags),
    User(usize),
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
/// # use bo_tie::gap::assigned::flags;
/// let mut flags = flags::Flags::new();
///
/// // enable the bluetooth specified flag 'LE limited discoverable mode'
/// flags.get_core(flags::CoreFlags::LELimitedDiscoverableMode).enable();
///
/// // enable a user specific flag
/// flags.get_user(0).enable();
/// ```
#[derive(Eq, Debug, Clone)]
pub struct Flag {
    position: usize,
    enabled: Cell<bool>,
}

impl Flag {
    fn new(position: usize, state: bool) -> Flag {
        Flag {
            position,
            enabled: Cell::new(state),
        }
    }

    /// Set the state of the flag to enabled
    pub fn enable(&self) {
        self.enabled.set(true);
    }

    /// Set the state of the flag to disabled
    pub fn disable(&self) {
        self.enabled.set(false);
    }

    /// Set the state of the flag to `state`
    pub fn set(&self, state: bool) {
        self.enabled.set(state)
    }

    /// Get the state of the flag
    pub fn get(&self) -> bool where {
        self.enabled.get()
    }

    pub fn pos(&self) -> FlagType {
        if self.position < CoreFlags::get_bit_cnt() {
            FlagType::Core(CoreFlags::from_position(self.position))
        } else {
            FlagType::User(self.position - CoreFlags::get_bit_cnt())
        }
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

#[derive(Debug)]
pub struct Flags {
    set: BTreeSet<Flag>,
}

impl Flags {
    const ASSIGNED_TYPE: AssignedTypes = AssignedTypes::Flags;

    /// Creates a flags object with no enabled flag
    pub fn new() -> Self {
        Flags { set: BTreeSet::new() }
    }

    fn get(&mut self, flag: Flag) -> &Flag {
        if !self.set.contains(&flag) {
            self.set.insert(flag.clone());
        }

        self.set.get(&flag).unwrap()
    }

    /// Get a user flag for a given position
    ///
    /// Get a flag in the user defined region after the core flags. A value of zero is the
    /// first user defined flag. Positions are the relative bit position in the flags data
    /// type after the Bluetooth Supplement specifed flags (and reserved flags). Try to
    /// keep the flag positions stacked towards zero as `pos` / 8 is the number of
    /// bytes for the user flags that will need to be allocated for this flags data when
    /// transmitting.
    pub fn get_user(&mut self, pos: usize) -> &Flag {
        self.get(Flag {
            position: pos + CoreFlags::get_bit_cnt(),
            enabled: Cell::new(false),
        })
    }

    /// Get a core flag for a given position
    ///
    /// Get a flag in the core defined region before the use r flags.
    pub fn get_core(&mut self, core: CoreFlags) -> &Flag {
        self.get(Flag {
            position: core.get_position(),
            enabled: Cell::new(false),
        })
    }

    /// Get an iterator over the flags in Flags
    pub fn iter(&self) -> ::alloc::collections::btree_set::Iter<Flag> {
        self.set.iter()
    }
}

impl IntoStruct for Flags {
    fn data_len(&self) -> Result<usize, usize> {
        Ok(self.set.iter().map(|f| f.position / 8).max().unwrap_or_default())
    }

    fn convert_into<'a>(&self, b: &'a mut [u8]) -> Option<EirOrAdStruct<'a>> {
        let mut raw = StructIntermediate::new(b, Self::ASSIGNED_TYPE.val())?;

        let mut current_count = 0;
        let mut current_byte = raw.next()?;

        // Iterate over only the currently enabled flags
        for ref flag in self.set.iter().filter(|flag| flag.enabled.get()) {
            let octet = flag.position / 8;
            let bit = flag.position % 8;

            // Skip until the octet is reached
            while current_count < octet {
                current_count += 1;
                current_byte = raw.next()?;
            }

            *current_byte |= 1 << bit;
        }

        raw.finish()
    }
}

impl TryFromStruct<'_> for Flags {
    fn try_from_struct(st: EirOrAdStruct<'_>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if st.get_type() == Self::ASSIGNED_TYPE.val() {
            let mut set = BTreeSet::new();

            for octet in 0..st.get_data().len() {
                for bit in 0..8 {
                    if 0 != st.get_data()[octet] & (1 << bit) {
                        set.insert(Flag::new(octet * 8 + (bit as usize), true));
                    }
                }
            }

            Ok(Flags { set })
        } else {
            Err(Error::IncorrectAssignedType)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn into_raw_test() {
        let mut flags = Flags::new();

        flags.get_core(CoreFlags::LELimitedDiscoverableMode).enable();
        flags.get_user(2).enable();

        let raw = flags.into_raw();

        assert_eq!(alloc::vec![3u8, 1, 1, 1 << 2], raw);
    }

    #[test]
    fn from_raw_test() {
        let d_type = AssignedTypes::Flags.val();

        let packet = [4u8, d_type, 3u8, 8u8, 7u8];

        let mut flags = Flags::try_from_raw(&packet[1..]).unwrap();

        assert!(flags.get_core(CoreFlags::LELimitedDiscoverableMode).get());
        assert!(flags.get_core(CoreFlags::LEGeneralDiscoverableMode).get());
        assert!(flags.get_user(3).get());
        assert!(flags.get_user(8).get());
        assert!(flags.get_user(9).get());
        assert!(flags.get_user(10).get());
    }
}
