//! Bluetooth Security Manager
//!
//! The Security Manager is used to manage the pairing process and key distribution between two
//! connected devices. A [`SecurityManager`](crate::sm::SecurityManager) is used to contain
//! the keys generated and used for encrypting messages between this device and the devices it is
//! currently or was connected to.
//!
//! For each connection either a ['MasterSecurityManager'] or a ['SlaveSecurityManager'] is created
//! based on the role of this device in the connection. The `MasterSecurityManager` can be used for
//! initializing the pairing process and for re-establishing encryption to the slave device.
//! `SlaveSecurityManger` is used by the slave device as the responder to pairing requests.
//!
//! # Async
//! Both the `Async` and non-`Async` prepended Managers utilize asynchronous operations for I/O
//! to the Bluetooth Radio. What the `Async` versions do is further use the Bluetooth Controller for
//! the encryption calculations that require either AES or the generation of a elliptic curve
//! Diffie-Hellman key pair.
//!
//! The ['AsyncMasterSecurityManager'] and ['AsyncSlaveSecurityManager'] are versions of
//! ['MasterSecurityManager'] or a ['SlaveSecurityManager'] which can be used when it desired for
//! the controller to perform the encryption of the cleartext and to generate the Diffie-Hellman
//! Key, but make sure that the controller supports both of these Host Controller Interface commands
//! ( See the Bluetooth Specification v5.0 | Vol 2, Part E, sections 7.8.22-26 and 7.8.37). These
//! may not
//!
//! # Note
//! This module uses the following crates for parts of the encryption process.
//! * ['aes'](https://crates.io/crates/aes)
//! * ['ring'](https://crates.io/crates/ring)
//!
//! The assumption was made that these crates are adequate for their required usage within this
//! module, but no formal process was used to validate them for use with this library.
//! ['MasterSecurityManagerAsync'] and ['AsyncSlaveSecurityManager'] can be used if you don't trust
//! these crates, but they do require that the adequate functionality be present on the Bluetooth
//! Controller.
//!
//! # Temporary Note
//! For now passkey pairing is not supported. Only Numeric Comparison and Out Of Band are supported

use alloc::vec::Vec;
use serde::{Serialize, Deserialize};
use crate::l2cap::AclData;

pub mod toolbox;
pub mod pairing;
pub mod encrypt_info;
pub mod responder;
pub mod initiator;

const L2CAP_LEGACY_MTU: usize = 23;
const L2CAP_SECURE_CONNECTIONS_MTU: usize = 65;

//const ENCRYPTION_KEY_MIN_SIZE: usize = 7;
const ENCRYPTION_KEY_MAX_SIZE: usize = 16;

pub const L2CAP_CHANNEL_ID: crate::l2cap::ChannelIdentifier =
    crate::l2cap::ChannelIdentifier::LE(crate::l2cap::LeUserChannelIdentifier::SecurityManagerProtocol);

#[derive(Debug, Clone)]
pub enum Error {
    /// Incorrect Size
    Size,
    /// Incorrect Format
    Format,
    /// Incorrect Value
    Value,
    /// Incorrect Security Manager Command
    IncorrectCommand(CommandType),
    /// Feature is unsupported
    UnsupportedFeature,
    /// Pairing Failed
    PairingFailed(pairing::PairingFailedReason),
    /// The operation required encryption, but it is unknown if the connection is encrypted
    UnknownIfLinkIsEncrypted,
    /// Incorrect L2CAP channel ID
    IncorrectL2capChannelId,
}

#[derive(Debug,PartialEq,Eq,Clone,Copy)]
pub enum CommandType {
    PairingRequest,
    PairingResponse,
    PairingConfirm,
    PairingRandom,
    PairingFailed,
    EncryptionInformation,
    MasterIdentification,
    IdentityInformation,
    IdentityAddressInformation,
    SigningInformation,
    SecurityRequest,
    PairingPublicKey,
    PairingDHKeyCheck,
    PairingKeyPressNotification,
}

impl CommandType {
    fn into_val(self) -> u8 {
        match self {
            CommandType::PairingRequest => 0x1,
            CommandType::PairingResponse => 0x2,
            CommandType::PairingConfirm => 0x3,
            CommandType::PairingRandom => 0x4,
            CommandType::PairingFailed => 0x5,
            CommandType::EncryptionInformation => 0x6,
            CommandType::MasterIdentification => 0x7,
            CommandType::IdentityInformation => 0x8,
            CommandType::IdentityAddressInformation => 0x9,
            CommandType::SigningInformation => 0xa,
            CommandType::SecurityRequest => 0xb,
            CommandType::PairingPublicKey => 0xc,
            CommandType::PairingDHKeyCheck => 0xd,
            CommandType::PairingKeyPressNotification => 0xe,
        }
    }

    fn try_from_val(val: u8) -> Result<Self, Error> {
        match val {
            0x1 => Ok( CommandType::PairingRequest ),
            0x2 => Ok( CommandType::PairingResponse ),
            0x3 => Ok( CommandType::PairingConfirm ),
            0x4 => Ok( CommandType::PairingRandom ),
            0x5 => Ok( CommandType::PairingFailed ),
            0x6 => Ok( CommandType::EncryptionInformation ),
            0x7 => Ok( CommandType::MasterIdentification ),
            0x8 => Ok( CommandType::IdentityInformation ),
            0x9 => Ok( CommandType::IdentityAddressInformation ),
            0xa => Ok( CommandType::SigningInformation ),
            0xb => Ok( CommandType::SecurityRequest ),
            0xc => Ok( CommandType::PairingPublicKey ),
            0xd => Ok( CommandType::PairingDHKeyCheck ),
            0xe => Ok( CommandType::PairingKeyPressNotification ),
            _   => Err( Error::Value)
        }
    }
}

impl core::convert::TryFrom<&'_ AclData> for CommandType {
    type Error = Error;

    /// Try to get the CommandType from AclData
    ///
    /// This rigidly checks the AclData to get the CommandType. If the channel identifier is
    /// incorrect, the payload does not have a valid value for the command field, or the payload
    /// length is incorrect, an error is returned.
    fn try_from(acl_data: &'_ AclData) -> Result<Self, Self::Error> {

        if acl_data.get_channel_id() != L2CAP_CHANNEL_ID {
            return Err(Error::IncorrectL2capChannelId)
        }

        let possible_type = CommandType::try_from_val(
            *acl_data.get_payload().get(0).ok_or_else(|| Error::Size)? )?;

        let correct_packet_len = match possible_type {
            CommandType::PairingRequest |
            CommandType::PairingResponse => 7,
            CommandType::PairingConfirm |
            CommandType::PairingRandom => 17,
            CommandType::PairingFailed => 2,
            CommandType::EncryptionInformation => 17,
            CommandType::MasterIdentification => 11,
            CommandType::IdentityInformation => 17,
            CommandType::IdentityAddressInformation => 8,
            CommandType::SigningInformation => 17,
            CommandType::SecurityRequest => 2,
            CommandType::PairingPublicKey => 65,
            CommandType::PairingDHKeyCheck => 17,
            CommandType::PairingKeyPressNotification => 2,
        };

        if correct_packet_len == acl_data.get_payload().len() {
            Ok(possible_type)
        } else {
            Err(Error::Size)
        }
    }
}

/// Command Data
///
/// A trait for converting to or from the data format sent over the radio as specified in the
/// Bluetooth Specification Security Manager Protocol (V.5.0 | Vol 3, Part H
trait CommandData where Self: Sized {

    /// Convert into the interface formatted command data
    fn into_icd(self) -> Vec<u8>;

    /// Convert from the interface formatted command data
    ///
    /// If `icd` is incorrectly formatted or sized an `Err` is returned.
    fn try_from_icd(icd: &[u8]) -> Result<Self, Error>;
}

struct Command<D> {
    command_type: CommandType,
    data: D,
}

impl<D> Command<D> {
    fn new( command_type: CommandType, data: D) -> Self {
        Command { command_type, data }
    }
}

impl<D> CommandData for Command<D> where D: CommandData {

    fn into_icd(self) -> Vec<u8> {
        let mut data_v = self.data.into_icd();

        let mut rec = Vec::with_capacity(1 + data_v.len());

        rec.push(self.command_type.into_val());

        rec.append(&mut data_v);

        rec
    }

    fn try_from_icd(icd : &[u8] ) -> Result<Self, Error> {
        if icd.len() == 0 {
            Err(Error::Size)
        } else {
            Ok( Command {
                command_type: CommandType::try_from_val(icd[0])?,
                data: D::try_from_icd(&icd[1..])?
            } )
        }
    }
}

#[derive(Debug)]
enum KeyGenerationMethod {
    /// Out of Bound
    Oob,
    PassKeyEntry,
    JustWorks,
    /// Numeric comparison
    NumbComp,
}

impl KeyGenerationMethod {

    /// Used to determine the pairing method to be executed between the initiator and responder
    ///
    /// # Note
    /// `is_legacy` must be false as the security manager doesn't support legacy. It is only left
    /// here in case that changes (which is unlikely).
    fn determine_method (
        initiator_oob_data: pairing::OOBDataFlag,
        responder_oob_data: pairing::OOBDataFlag,
        initiator_io_capability: pairing::IOCapability,
        responder_io_capability: pairing::IOCapability,
        is_legacy: bool,
    ) -> Self
    {
        use pairing::{IOCapability, OOBDataFlag};

        // This match should match Table 2.8 in the Bluetooth Specification v5.0 | Vol 3, Part H,
        // section 2.3.5.1
        match (initiator_oob_data, responder_oob_data) {

            ( OOBDataFlag::AuthenticationDataFromRemoteDevicePresent,
                OOBDataFlag::AuthenticationDataFromRemoteDevicePresent) =>
                KeyGenerationMethod::Oob,

            (_,_) => match (initiator_io_capability, responder_io_capability) {

                (IOCapability::DisplayOnly, IOCapability::KeyboardOnly) |
                (IOCapability::DisplayOnly, IOCapability::KeyboardDisplay) =>
                    KeyGenerationMethod::PassKeyEntry,

                (IOCapability::DisplayWithYesOrNo, IOCapability::DisplayWithYesOrNo) if !is_legacy =>
                    KeyGenerationMethod::NumbComp,

                (IOCapability::DisplayWithYesOrNo, IOCapability::KeyboardOnly) =>
                    KeyGenerationMethod::PassKeyEntry,

                (IOCapability::DisplayWithYesOrNo, IOCapability::KeyboardDisplay) =>
                    if is_legacy {
                        KeyGenerationMethod::PassKeyEntry
                    } else {
                        KeyGenerationMethod::NumbComp
                    }

                (IOCapability::KeyboardOnly, IOCapability::DisplayOnly) |
                (IOCapability::KeyboardOnly, IOCapability::DisplayWithYesOrNo) |
                (IOCapability::KeyboardOnly, IOCapability::KeyboardOnly) |
                (IOCapability::KeyboardOnly, IOCapability::KeyboardDisplay) =>
                    KeyGenerationMethod::PassKeyEntry,

                (IOCapability::KeyboardDisplay, IOCapability::DisplayOnly) |
                (IOCapability::KeyboardDisplay, IOCapability::KeyboardOnly) =>
                    KeyGenerationMethod::PassKeyEntry,

                (IOCapability::KeyboardDisplay, IOCapability::DisplayWithYesOrNo) |
                (IOCapability::KeyboardDisplay, IOCapability::KeyboardDisplay) =>
                    if is_legacy {
                        KeyGenerationMethod::PassKeyEntry
                    } else {
                        KeyGenerationMethod::NumbComp
                    }

                (_,_) => KeyGenerationMethod::JustWorks
            }
        }
    }
}

/// Data that is gathered in the process of pairing
///
/// This data is unique for each pairing attempt and must be dropped after a successful or failed
/// pairing attempt.
struct PairingData {
    /// The current pairing method
    key_gen_method: KeyGenerationMethod,
    /// The public key generated by this device
    public_key: toolbox::PubKey,
    /// The private key generated by this device
    private_key: Option<toolbox::PriKey>,
    /// Initiator IOcap information. This must match the exact bits sent over from the master, even
    /// if the bits are not valid for their field.
    initiator_io_cap: [u8;3],
    /// This IOcap information
    responder_io_cap: [u8;3],
    /// Nonce value
    ///
    /// This will change multiple times for passkey, but is static for just works or number
    /// comparison
    nonce: u128,
    /// The peer nonce
    ///
    /// This will change multiple times for passkey, but is static for just works or number
    /// comparison
    peer_nonce: Option<u128>,
    /// The public key received from the remote device
    peer_public_key: Option<toolbox::PeerPubKey>,
    /// The Diffie-Hellman secret key generated via Elliptic Curve Crypto
    secret_key: Option<toolbox::DHSecret>,
    /// Responder pairing confirm
    responder_pairing_confirm: Option<u128>,
    /// Mac Key
    mac_key: Option<u128>,
    /// The database key
    db_keys: Option<KeyDBEntry>,
}

/// Peer device Keying information
///
/// This contains all the keys that are generated by the security manager. It contains the
/// encryption keys used by this device for communication with a specific peer device. However the
/// keys can only be reused for a known, but currently unidentified device if a `KeyDBEntry`
/// contains either the peer devices Identity Resolving Key (IRK) or the peers address.
///
/// Each `KeyDBEntry` can store the Long Term Key (LTK), a unique Connection Signature Resolving Key
/// (CSRK), a unique Identity Resolving Key (IRK), the peer devices CSRK, the peer's IRK, the
/// peer address, and the CSRK counters. All of the keys and addresses are optional, but if a CSRK
/// exists its corresponding counter will also be present.
///
/// This device may use a static IRK and CSRK to a given peer device. There can be only one static
/// IRK and CSRK per `SecurityManager`, but any number of `KeyDBEntry`s can use them. If a static
/// CSRK is used, the sign counter for this `KeyDBEntry` can only be used through the connection to
/// the peer device.
#[derive(Clone,Serialize,Deserialize,Default)]
pub struct KeyDBEntry {
    /// The Long Term Key (private key)
    ///
    /// If this is `None` then the connection cannot be encrypted
    ltk: Option<u128>,

    /// This Connection Signature Resolving Key (CSRK) and sign counter
    csrk: Option<(u128, u32)>,

    /// This device's Identity Resolving Key
    irk: Option<u128>,

    /// The peer device's Connection Signature Resolving Key and sign counter
    peer_csrk: Option<(u128, u32)>,

    /// The peer's Identity Resolving Key (IRK)
    peer_irk: Option<u128>,

    /// The peer's public or static random address
    peer_addr: Option<BluAddr>
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum BluAddr {
    Public(crate::BluetoothDeviceAddress),
    StaticRandom(crate::BluetoothDeviceAddress)
}

impl KeyDBEntry {

    /// Construct a new `KeyDBEntry` with no keys
    pub fn new() -> Self {
        KeyDBEntry::default()
    }

    /// Returns a boolean indicating if the key entry can be added to a keys database
    ///
    /// For a `KeyDBEntry` to be databaseable, it needs to have either a peer address or a peer irk.
    /// If neither is available, then there would be no way to associate any of the rest of the keys
    /// in a `KeyDBEntry` to a device when the `KeyDBEntry` is retrieved from a database.
    #[inline]
    pub fn is_databaseable(&self) -> bool {
        self.peer_addr != None || self.peer_irk != None
    }

    /// Compare entries by the peer keys irk and addr
    fn cmp_entry_by_keys<'a,I,A>(&self, peer_irk: I, peer_addr: A) -> core::cmp::Ordering
        where I: Into<Option<&'a u128>> + 'a,
              A: Into<Option<&'a BluAddr>> + 'a,
    {
        use core::cmp::Ordering;

        match (self.peer_irk.as_ref(), peer_irk.into(), self.peer_addr.as_ref(), peer_addr.into()) {
            (Some(this),Some(other), _, _) =>
                this.cmp(other),
            (Some(_), None, _, _) =>
                Ordering::Less,
            (None, Some(_), _, _) =>
                Ordering::Greater,
            (None, None, Some(this), Some(other)) =>
                this.cmp(other),
            (None,None,Some(_), None) =>
                Ordering::Less,
            (None,None,None,Some(_)) =>
                Ordering::Greater,
            (None, None, None, None) =>
                Ordering::Equal
        }
    }

    /// Compare two entries
    ///
    /// This can be used for sorting entries by the peer IRK and peer addresses. This is *not* the
    /// same as the
    /// [partial_cmp](https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html#tymethod.partial_cmp)
    /// implementation for `PartialOrd` as that implementation uses all keys in a `KeyDBEntry` to
    /// perform a comparison.
    ///
    /// The comparison has precedence to the peer IRK. If both `self` and `other` contain an IRK for
    /// the peer value, then the result of comparing those two IRKs is returned. When `self` has an
    /// peer IRK and `other` does not, `Less` is returned. Likewise `Greater` is
    /// returned when `self` does not have a peer IRK and `other` does.
    ///
    /// If neither `self` nor `other` have a peer IRK then the same ordering calculation is made
    /// with the peer addresses. If both have an address then the comparison result is returned. If
    /// `self` has an address but `other` does not then `Less` is returned. If `self` does not have
    /// a peer address but `other` does have a peer address, `Greater` is returned.
    ///
    /// If both `self` and `other` do not have a peer IRK nor a peer Address, `Equal` is returned.
    ///
    /// This chart may provide a better explanation of the returned comparison.
    ///
    /// | `self` IRK | `other` IRK | `self` address | `other` address |  return  |
    /// |:----------:|:-----------:|:--------------:|:---------------:|:--------:|
    /// |   Some(A)  |   Some(B)   |        -       |        -        | A.cmp(B) |
    /// |   Some(A)  |     None    |        -       |        -        |   Less   |
    /// |    None    |   Some(B)   |        -       |        -        |  Greater |
    /// |    None    |     None    |     Some(C)    |     Some(D)     | C.cmp(D) |
    /// |    None    |     None    |     Some(C)    |       None      |   Less   |
    /// |    None    |     None    |      None      |     Some(D)     |  Greater |
    /// |    None    |     None    |      None      |       None      |   Equal  |
    pub fn compare_entry(&self, other: &Self) -> core::cmp::Ordering {
        self.cmp_entry_by_keys(other.peer_irk.as_ref(), other.peer_addr.as_ref())
    }

    /// Get the peer devices Identity Resolving Key
    pub fn get_peer_irk(&self) -> Option<u128> { self.peer_irk }

    /// Get the peer devices Connection Signature Resolving Key
    pub fn get_peer_csrk(&self) -> Option<u128> { self.peer_csrk.map(|(c,_)| c) }

    /// Get the saved Connection Signature Resolving Key Sign Counter
    pub fn get_peer_csrk_cnt(&self) -> Option<u32> { self.csrk.map(|(_,c)| c) }

    /// Get the peer devices address
    ///
    /// Returns a bluetooth device address along with a flag to indicate if the address is a public.
    /// If the flag is false then the address is a static random address.
    pub fn get_peer_addr(&self) -> Option<(bool, crate::BluetoothDeviceAddress)> {
        self.peer_addr.clone().map(|addr| {
            match addr {
                BluAddr::Public(addr) => (true, addr),
                BluAddr::StaticRandom(addr) => (true, addr),
            }
        })
    }

    /// Get the Identity Resolving Key
    ///
    /// If this is `None` then this connection uses the static IRK of the `SecurityManager`.
    pub fn get_irk(&self) -> Option<u128> { self.irk }

    /// Get the Connection Signature Resolving Key
    ///
    /// If this is `None` then the connection uses the static CSRK of the `SecurityManager`.
    pub fn get_csrk(&self) -> Option<u128> { self.csrk.map(|(c,_)| c) }

    /// Get the saved Connection Signature Resolving Key Sign Counter
    pub fn get_csrk_cnt(&self) -> Option<u32> { self.csrk.map(|(_,c)| c)}

    /// Get the Long Term Key
    ///
    /// This is the secret key used to establish (or reestablish) an encryption between this device
    /// and the peer device.
    ///
    /// If this is `None` then encryption cannot be established. This may happen when encryption
    /// cannot be established to the peer device, but the peer's IRK or CSRK is known.
    pub fn get_ltk(&self) -> Option<u128> { self.ltk }
}

/// The Encryption Key "database"
///
/// This contains a sorted list of `KeyDBEntry` sorted by the peer irk and peer address values.
#[derive(serde::Serialize, serde::Deserialize)]
struct KeyDB {
    entries: Vec<KeyDBEntry>,
}

impl KeyDB {

    /// Create a new `KeyDB` from a vector of `KeyDBEntry`
    ///
    /// # Panic
    /// All entries must have either a peer IRK or a peer Address set. A KeyDBEntry can be checked
    /// to be valid if [`is_databaseable`](KeyDBEntry::is_databaseable) returns true.
    fn new(mut entries: Vec<KeyDBEntry>) -> Self {

        entries.sort_by(|rhs, lhs| rhs.compare_entry(lhs) );

        Self { entries }
    }

    /// Get the keys associated with the provided `irk` and/or `address`.
    ///
    /// Return the keys associated with the specified `irk` and/or `address`. `None` is
    /// returned if there is no entry associated with the given keys.
    fn get<'s, 'a, I,A>(&'s self, irk: I, address: A) -> Option<&'s KeyDBEntry>
    where I: Into<Option<&'a u128>>,
          A: Into<Option<&'a BluAddr>>,
    {
        let i = irk.into();
        let a = address.into();
        let entries = &self.entries;

        self.entries.binary_search_by(|entry| entry.cmp_entry_by_keys(i, a) )
            .ok()
            .map_or(None, |idx| entries.get(idx) )
    }

    /// Add the keys with the provided KeyDBEntry
    ///
    /// This will override keys that have the same ordering information ( the same
    /// [`peer_irk`](KeyDBEntry::peer_irk) and [`peer_addr'](KeyDBEntry::peer_addr) ). If the entry
    /// does not meed the requirements for 'peer_irk' and 'peer_addr', this will function will do
    /// nothing.
    fn add(&mut self, entry: KeyDBEntry) {
        if entry.is_databaseable() {
            match self.entries.binary_search_by(|in_entry| in_entry.compare_entry(&entry) ) {
                Ok(idx)  => self.entries[idx] = entry,
                Err(idx) => self.entries.insert(idx, entry),
            }
        }
    }

    fn iter(&self) -> impl core::iter::Iterator<Item = &KeyDBEntry> {
        self.entries.iter()
    }

    fn remove<'a, I,A>(&'a mut self, irk: I, address: A) -> bool
    where I: Into<Option<&'a u128>>,
          A: Into<Option<&'a BluAddr>>,
    {
        let i = irk.into();
        let a = address.into();

        self.entries.binary_search_by(|entry| entry.cmp_entry_by_keys(i, a) )
            .ok()
            .map_or(false, |idx| { self.entries.remove(idx); true } )
    }
}

impl Default for KeyDB {

    /// Create an empty KeyDB
    fn default() -> Self {
        KeyDB::new( Vec::new() )
    }
}

/// A simple Security Manager
///
/// The `SecurityManager` contains a database of encryption keys for with previously bonded
/// devices. Its main purpose is for saving bonding information and to retrieve the correct
/// encryption keys upon successful identification of the peer device.
///
/// This 'database' is nothing more than a glorified list of `KeyDBEntry`
/// sorted by the
/// [compare_entry](crate::sm::KeyDBEntry::compare_entry)
/// function. The database is mainly used for either retrieving keys by the peer device's Identity
/// Resolving Key and/or the Identity Address.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct SecurityManager {
    keys_db: KeyDB,
    static_irk: Option<u128>,
    static_csrk: Option<u128>,
}

impl SecurityManager {

    pub fn new(keys: Vec<KeyDBEntry>) -> Self {
        SecurityManager {
            keys_db: KeyDB::new(keys),
            static_irk: None,
            static_csrk: None,
        }
    }

    /// Get an iterator over the keys
    pub fn iter(&self) -> impl Iterator<Item = &KeyDBEntry> {
       self.keys_db.iter()
    }

    /// Assign a static Identity Resolving Key (IRK)
    ///
    /// Assign's the value as the static IRK for this device and a returns it. A IRK is generated if
    /// `None` is the input.
    ///
    /// The static IRK is used when a unique IRK is not generated by the bonding procedure. However
    /// a this function must be called to set (or generate) a static IRK before it is used.
    pub fn set_static_irk<I>( &mut self, irk: I ) -> u128 where I: Into<Option<u128>> {
        match irk.into() {
            None => {
                let v = toolbox::rand_u128();
                self.static_irk = Some(v);
                v
            }
            Some(v) => {
                self.static_irk = Some(v);
                v
            }
        }
    }

    /// Assign a static Connection Signature Resolving Key (CSRK)
    ///
    /// Assign's the value as the static CSRK for this device and a returns it. A CSRK is generated
    /// if `None` is the input.
    ///
    /// The static CSRK is used when a unique CSRK is not generated by the bonding procedure.
    /// However a this function must be called to set (or generate) a static CSRK before it is used.
    pub fn set_static_csrk<I>( &mut self, irk: I ) -> u128 where I: Into<Option<u128>> {
        match irk.into() {
            None => {
                let v = toolbox::rand_u128();
                self.static_csrk = Some(v);
                v
            }
            Some(v) => {
                self.static_csrk = Some(v);
                v
            }
        }
    }


    /// Returns an iterator to resolve a resolvable private address from all peer devices'
    /// Identity Resolving Key (IRK) in the keys database.
    ///
    /// The return is an iterator that will try to resolve `addr` with a known peer IRK on each
    /// iteration. If the address is resolved by a peer's IRK, the `KeyDBEntry` that contains the
    /// matching IRK is returned. The easiest way to use this function is to just combine it with
    /// the [`find_map`](https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.find_map)
    /// iterator method.
    /// ```
    /// # let security_manager = bo_tie::sm::SecurityManager::default();
    /// # let resolvable_private_address = [0u8;6];
    ///
    /// let keys = security_manager.resolve_rpa_iter.find_map(|keys_opt| keys_opt);
    /// ```
    pub fn resolve_rpa_itr(&self, addr: crate::BluetoothDeviceAddress)
    -> impl core::iter::Iterator<Item = Option<KeyDBEntry>> + '_
    {
        let hash = [addr[0], addr[1], addr[2] ];
        let prand = [addr[3], addr[4], addr[5]];

        self.keys_db.entries.iter()
            .take_while(|e| e.peer_irk.is_some() )
            .map(move |e| e.peer_irk.and_then( |irk|
                if toolbox::ah( irk, prand ) == hash { Some(e.clone()) } else { None }
            )
        )
    }

    /// Add (or replace) keys in the database
    ///
    /// This will add the keys to the database **if** input `keys` contains a peer identity
    /// resolving key or a peer address. If there is a `KeyDBEntry` in the database that contains
    /// the same peer IRK and peer address, that entry is overwritten.
    ///
    /// This function will return true if `keys` was added to the database.
    pub fn add_keys(&mut self, keys: KeyDBEntry) -> bool {
        match keys {
            KeyDBEntry { peer_irk: Some(_), .. } | KeyDBEntry { peer_addr: Some(_), .. } => {
                self.keys_db.add(keys);
                true
            }
            _ => false
        }
    }

    /// Remove keys in the database
    ///
    /// Removes the entry that matches `keys` in the database
    pub fn remove_keys(&mut self, keys: &KeyDBEntry) -> bool {
        self.keys_db.remove(keys.peer_irk.as_ref(), keys.peer_addr.as_ref())
    }

    /// Get a specific `KeyDBEntry` from its peer IRK and peer Address
    pub fn get_keys<I,A>(&self, peer_irk: I, peer_addr: A, peer_addr_is_pub: bool)
    -> Option<&KeyDBEntry>
    where I: Into<Option<u128>>,
          A: Into<Option<crate::BluetoothDeviceAddress>>
    {
        let peer_addr = peer_addr.into().map(|addr| if peer_addr_is_pub {
                BluAddr::Public(addr)
            } else {
                BluAddr::StaticRandom(addr)
            });

        self.keys_db.get(peer_irk.into().as_ref(), peer_addr.as_ref())
    }
}

trait GetXOfP256Key {
    fn x(&self) -> [u8;32];
}

impl GetXOfP256Key for [u8;64] {
    fn x(&self) -> [u8;32] {
        let mut x = [0u8; 32];

        x.copy_from_slice(&self[..32]);

        x
    }
}
