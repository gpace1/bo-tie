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
/// This is use d to enable/disable flags retreived from a `Flags` data type. By default
/// a newly created flag is false, but calling `get` on a flags instance doesn't
/// gaurentee that the flag is newly created. `enable`, `disable`, or `set` should be
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
    val: Cell<bool>,
}

impl Flag {
    fn new(position: usize, state: bool) -> Flag {
        Flag {
            position,
            val: Cell::new(state),
        }
    }

    /// Set the state of the flag to enabled
    pub fn enable(&self) {
        self.val.set(true);
    }

    /// Set the state of the flag to disabled
    pub fn disable(&self) {
        self.val.set(false);
    }

    /// Set the state of the flag to `state`
    pub fn set(&self, state: bool) {
        self.val.set(state)
    }

    /// Get the state of the flag
    pub fn get(&self) -> bool where {
        self.val.get()
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
    const AD_TYPE: AssignedTypes = AssignedTypes::Flags;

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
            val: Cell::new(false),
        })
    }

    /// Get a core flag for a given position
    ///
    /// Get a flag in the core defined region before the use r flags.
    pub fn get_core(&mut self, core: CoreFlags) -> &Flag {
        self.get(Flag {
            position: core.get_position(),
            val: Cell::new(false),
        })
    }

    /// Get an iterator over the flags in Flags
    pub fn iter(&self) -> ::alloc::collections::btree_set::Iter<Flag> {
        self.set.iter()
    }
}

impl IntoRaw for Flags {
    fn into_raw(&self) -> alloc::vec::Vec<u8> {
        let mut raw = new_raw_type(Self::AD_TYPE.val());

        // The first two octets are number of flag octets and ad type, so the '+ 2' is to
        // compensate for that)
        let flag_data_offset = 2;

        // Iterate over only the currently enabled flags
        for ref flag in self.set.iter().filter(|flag| flag.val.get()) {
            let octet = flag.position / 8;
            let bit = flag.position % 8;

            // Fillout the vec until the octet is reached
            while raw.len() <= (octet + flag_data_offset) {
                raw.push(0);
            }

            raw[octet + flag_data_offset] |= 1 << bit;
        }

        // Set the length
        set_len(&mut raw);

        raw
    }
}

impl TryFromRaw for Flags {
    fn try_from_raw(raw: &[u8]) -> Result<Flags, Error> {
        let mut set = BTreeSet::new();

        from_raw! { raw, AssignedTypes::Flags, {
            let data = &raw[1..];

            for octet in 0..data.len() {
                for bit in 0..8 {
                    if 0 != data[octet] & (1 << bit) {
                        set.insert(Flag::new( octet * 8 + (bit as usize), true ));
                    }
                }
            }

            Flags {
                set: set
            }
        }}
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
