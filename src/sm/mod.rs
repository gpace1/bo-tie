//! Bluetooth Security Manager
//!
//! The Security Manager is used to manage the pairing process and key distribution (bonding)
//! between two connected devices. There are seperate Security Managers for the initiating device
//! and for the responding (non-initiating) device. These Security Managers can be found in the
//! [`initiator`](initiator) and [`responder`](responder) modules. Both Security Managers are
//! connection instance specific. They're only valid for a single connection and for the lifetime of
//! that connection. The only purpose of the Security Managers are to manage the Security Manager
//! protocol to achieve pairing and bonding, keys generated from pairing and bonding must be
//! retreived and stored from the Security Managers in a seperate data base.
//!
//! [`SecurityManagerKeys`](SecurityManagerKeys) is a very basic keys database is provided by this
//! module, but it does not need to be used for keys management with this library. Keys can be
//! retreived from the Security Managers after bonding has been completed (the secure key (LTK) is
//! retreivable after pairing is completed).
//!
//! ## Pairing Methods
//!
//! # Just Works
//! Just works is the simplest form of pairing as it provides no security against a man in the
//! middle attack. Both Security Managers support Just Works pairing by default.
//!
//! # Number compareson
//! Not implemented yet.
//!
//! # Passkey
//! Not implemented yet.
//!
//! # Out of Band
//! Out of band pairing is done by using a man in the middle protected data connection that is out
//! of scope for the Bluetooth connection between the two devices. It is one of the methods of
//! pairing to prevent  
//!
//! OOB data is sent though a method outside of the Bluetooth logical link use to initialize
//! pairing, but the builders for the initializer or responder Security Managers must explicitly
//! enable it. The main problem with OOB is that the interface is out of scope for this library (and
//! the Bluetooth Spec.). When enabling OOB, the methods for sending or receiving data over the OOB
//! interface must be provided. For Secure Connection, only one of these methods is required, but
//! it is recommended to implement at least the receiver if you do not trust the Security Manager
//! implementation of the the peer Device. This is because the confirm value (the validation that
//! public keys are not compromised by a man in the middle attack) is only checked when a Securty
//! Manager receives OOB data.
//!
//! ```
//! # // example initialization boilerplate
//! # let this_address = bo_tie::BluetoothDeviceAddress::default();
//! # let peer_address = bo_tie::BluetoothDeviceAddress::default();
//! # struct StubConnectionChannel;
//! # impl bo_tie::l2cap::ConnectionChannel for StubConnectionChannel {
//! #     type SendFut = futures::future::Ready<Result<(), Self::SendFutErr>>;
//! #     type SendFutErr = usize;
//! #     fn send(&self,data: AclData) -> Self::SendFut { unimplemented!() }
//! #     fn set_mtu(&self,mtu: u16) { unimplemented!() }
//! #     fn get_mtu(&self) -> usize { unimplemented!() }
//! #     fn max_mtu(&self) -> usize { unimplemented!() }
//! #     fn min_mtu(&self) -> usize { unimplemented!() }
//! #     fn receive(&self,waker: &Waker) -> Option<Vec<AclDataFragment>> { unimplemented!() }
//! # }
//! # let connection_channel = StubConnectionChannel;
//! // An example of setting up a receiver that support oob
//!
//! use bo_tie::sm::responder::SlaveSecurityManagerBuilder;
//! use bo_tie::sm::BuildOutOfBand;
//! use bo_tie::l2cap::{AclData, ConnectionChannel, AclDataFragment};
//! use std::task::Waker;
//! use std::future::Future;
//!
//! async fn send(data: &[u8]) {
//!     todo!("your method for sending")
//! }
//!
//! async fn receive() -> Vec<u8> {
//!     todo!("your method for receiving")
//! }
//!
//! let security_manager = SlaveSecurityManagerBuilder::new(
//!         &connection_channel,
//!         &this_address,
//!         &peer_address,
//!         false,
//!         false
//!     )
//!     .use_oob(send, receive)
//!     .build();
//! ```
//!
// todo: this talks about how to integrate HCI calculated ECDH and AES
// //! # HCI
// //! Both the `Async` and non-`Async` prepended Managers utilize asynchronous operations for I/O
// //! to the Bluetooth Radio. What the `Async` versions do is further use the Bluetooth Controller for
// //! the encryption calculations that require either AES or the generation of a elliptic curve
// //! Diffie-Hellman key pair.
// //!
// //! The ['AsyncMasterSecurityManager'] and ['AsyncSlaveSecurityManager'] are versions of
// //! ['MasterSecurityManager'] or a ['SlaveSecurityManager'] which can be used when it desired for
// //! the controller to perform the encryption of the cleartext and to generate the Diffie-Hellman
// //! Key, but make sure that the controller supports both of these Host Controller Interface commands
// //! ( See the Bluetooth Specification v5.0 | Vol 2, Part E, sections 7.8.22-26 and 7.8.37). These
// //! may not
// //!
//!
//! # Note
//! This module uses the following crates for parts of the encryption process.
//! * ['aes'](https://lib.rs/crates/aes)
//! * ['p256'](https://lib.rs/crates/p256)

use crate::l2cap::AclData;
use alloc::vec::Vec;
use core::future::Future;
use serde::{Deserialize, Serialize};

pub mod encrypt_info;
pub mod initiator;
pub mod pairing;
pub mod responder;
pub mod toolbox;

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
    /// Send related error
    DataSend(alloc::string::String),
    /// ACL Data related
    AclData(crate::l2cap::AclDataError),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
            0x1 => Ok(CommandType::PairingRequest),
            0x2 => Ok(CommandType::PairingResponse),
            0x3 => Ok(CommandType::PairingConfirm),
            0x4 => Ok(CommandType::PairingRandom),
            0x5 => Ok(CommandType::PairingFailed),
            0x6 => Ok(CommandType::EncryptionInformation),
            0x7 => Ok(CommandType::MasterIdentification),
            0x8 => Ok(CommandType::IdentityInformation),
            0x9 => Ok(CommandType::IdentityAddressInformation),
            0xa => Ok(CommandType::SigningInformation),
            0xb => Ok(CommandType::SecurityRequest),
            0xc => Ok(CommandType::PairingPublicKey),
            0xd => Ok(CommandType::PairingDHKeyCheck),
            0xe => Ok(CommandType::PairingKeyPressNotification),
            _ => Err(Error::Value),
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
            return Err(Error::IncorrectL2capChannelId);
        }

        let possible_type = CommandType::try_from_val(*acl_data.get_payload().get(0).ok_or_else(|| Error::Size)?)?;

        let correct_packet_len = match possible_type {
            CommandType::PairingRequest | CommandType::PairingResponse => 7,
            CommandType::PairingConfirm | CommandType::PairingRandom => 17,
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
trait CommandData
where
    Self: Sized,
{
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
    fn new(command_type: CommandType, data: D) -> Self {
        Command { command_type, data }
    }
}

impl<D> CommandData for Command<D>
where
    D: CommandData,
{
    fn into_icd(self) -> Vec<u8> {
        let mut data_v = self.data.into_icd();

        let mut rec = Vec::with_capacity(1 + data_v.len());

        rec.push(self.command_type.into_val());

        rec.append(&mut data_v);

        rec
    }

    fn try_from_icd(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 0 {
            Err(Error::Size)
        } else {
            Ok(Command {
                command_type: CommandType::try_from_val(icd[0])?,
                data: D::try_from_icd(&icd[1..])?,
            })
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum PairingMethod {
    /// Out of Bound
    Oob(OobDirection),
    PassKeyEntry,
    JustWorks,
    /// Numeric comparison
    NumbComp,
}

impl PairingMethod {
    /// Used to determine the pairing method to be executed between the initiator and responder
    /// under the secure connection process.
    ///
    /// # Note
    /// `is_legacy` must be false as the security manager doesn't support legacy. It is only left
    /// here in case that changes (which is unlikely).
    fn determine_method_secure_connection(
        initiator_oob_data: pairing::OOBDataFlag,
        responder_oob_data: pairing::OOBDataFlag,
        initiator_io_capability: pairing::IOCapability,
        responder_io_capability: pairing::IOCapability,
        is_legacy: bool,
    ) -> Self {
        use pairing::{
            IOCapability::*, OOBDataFlag::AuthenticationDataFromRemoteDevicePresent as Present,
            OOBDataFlag::AuthenticationDataNotPresent as Unavailable,
        };

        // This match should match Table 2.8 in the Bluetooth Specification v5.0 | Vol 3, Part H,
        // section 2.3.5.1
        match (initiator_oob_data, responder_oob_data) {
            (Present, Present) => PairingMethod::Oob(OobDirection::BothSendOob),

            (Present, Unavailable) => PairingMethod::Oob(OobDirection::OnlyResponderSendsOob),

            (Unavailable, Present) => PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob),

            (_, _) => match (initiator_io_capability, responder_io_capability) {
                (DisplayOnly, KeyboardOnly) | (DisplayOnly, KeyboardDisplay) => PairingMethod::PassKeyEntry,

                (DisplayWithYesOrNo, DisplayWithYesOrNo) if !is_legacy => PairingMethod::NumbComp,

                (DisplayWithYesOrNo, KeyboardOnly) => PairingMethod::PassKeyEntry,

                (DisplayWithYesOrNo, KeyboardDisplay) => {
                    if is_legacy {
                        PairingMethod::PassKeyEntry
                    } else {
                        PairingMethod::NumbComp
                    }
                }

                (KeyboardOnly, DisplayOnly)
                | (KeyboardOnly, DisplayWithYesOrNo)
                | (KeyboardOnly, KeyboardOnly)
                | (KeyboardOnly, KeyboardDisplay) => PairingMethod::PassKeyEntry,

                (KeyboardDisplay, DisplayOnly) | (KeyboardDisplay, KeyboardOnly) => PairingMethod::PassKeyEntry,

                (KeyboardDisplay, DisplayWithYesOrNo) | (KeyboardDisplay, KeyboardDisplay) => {
                    if is_legacy {
                        PairingMethod::PassKeyEntry
                    } else {
                        PairingMethod::NumbComp
                    }
                }

                (_, _) => PairingMethod::JustWorks,
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum OobDirection {
    OnlyResponderSendsOob,
    OnlyInitiatorSendsOob,
    BothSendOob,
}
/// Data that is gathered in the process of pairing
///
/// This data is unique for each pairing attempt and must be dropped after a successful or failed
/// pairing attempt.
struct PairingData {
    /// The current pairing method
    pairing_method: PairingMethod,
    /// The public key generated by this device
    public_key: toolbox::PubKey,
    /// The private key generated by this device
    private_key: Option<toolbox::PriKey>,
    /// Initiator IOcap information. This must match the exact bits sent over from the master, even
    /// if the bits are not valid for their field.
    initiator_io_cap: [u8; 3],
    /// This IOcap information
    responder_io_cap: [u8; 3],
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
    peer_public_key: Option<toolbox::PubKey>,
    /// The Diffie-Hellman secret key generated via Elliptic Curve Crypto
    secret_key: Option<toolbox::DHSharedSecret>,
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
///
/// # Equality, Ordering, and Hashing
/// Comparisons and hashing are implemented for `KeyDBEntry`, but only the identity address and
/// identity resolving key are used within those calculations. Only these two values are used for
/// identifying the usage of the rest of the keys in a Security Manager.
#[derive(Clone, Serialize, Deserialize, Default)]
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
    peer_addr: Option<BluAddr>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
enum BluAddr {
    Public(crate::BluetoothDeviceAddress),
    StaticRandom(crate::BluetoothDeviceAddress),
}

impl KeyDBEntry {
    /// Construct a new `KeyDBEntry` with no keys
    pub fn new() -> Self {
        KeyDBEntry::default()
    }

    /// Compare entries by the peer keys irk and addr
    fn cmp_entry_by_keys<'a, I, A>(&self, peer_irk: I, peer_addr: A) -> core::cmp::Ordering
    where
        I: Into<Option<&'a u128>> + 'a,
        A: Into<Option<&'a BluAddr>> + 'a,
    {
        use core::cmp::Ordering;

        match (
            self.peer_irk.as_ref(),
            peer_irk.into(),
            self.peer_addr.as_ref(),
            peer_addr.into(),
        ) {
            (Some(this), Some(other), _, _) => this.cmp(other),
            (Some(_), None, _, _) => Ordering::Less,
            (None, Some(_), _, _) => Ordering::Greater,
            (None, None, Some(this), Some(other)) => this.cmp(other),
            (None, None, Some(_), None) => Ordering::Less,
            (None, None, None, Some(_)) => Ordering::Greater,
            (None, None, None, None) => Ordering::Equal,
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
    pub fn get_peer_irk(&self) -> Option<u128> {
        self.peer_irk
    }

    /// Get the peer devices Connection Signature Resolving Key
    pub fn get_peer_csrk(&self) -> Option<u128> {
        self.peer_csrk.map(|(c, _)| c)
    }

    /// Get the saved Connection Signature Resolving Key Sign Counter
    pub fn get_peer_csrk_cnt(&self) -> Option<u32> {
        self.csrk.map(|(_, c)| c)
    }

    /// Get the peer devices address
    ///
    /// Returns a bluetooth device address along with a flag to indicate if the address is a public.
    /// If the flag is false then the address is a static random address.
    pub fn get_peer_addr(&self) -> Option<(bool, crate::BluetoothDeviceAddress)> {
        self.peer_addr.clone().map(|addr| match addr {
            BluAddr::Public(addr) => (true, addr),
            BluAddr::StaticRandom(addr) => (true, addr),
        })
    }

    /// Get the Identity Resolving Key
    ///
    /// If this is `None` then this connection uses the static IRK of the `SecurityManager`.
    pub fn get_irk(&self) -> Option<u128> {
        self.irk
    }

    /// Get the Connection Signature Resolving Key
    ///
    /// If this is `None` then the connection uses the static CSRK of the `SecurityManager`.
    pub fn get_csrk(&self) -> Option<u128> {
        self.csrk.map(|(c, _)| c)
    }

    /// Get the saved Connection Signature Resolving Key Sign Counter
    pub fn get_csrk_cnt(&self) -> Option<u32> {
        self.csrk.map(|(_, c)| c)
    }

    /// Get the Long Term Key
    ///
    /// This is the secret key used to establish (or reestablish) an encryption between this device
    /// and the peer device.
    ///
    /// If this is `None` then encryption cannot be established. This may happen when encryption
    /// cannot be established to the peer device, but the peer's IRK or CSRK is known.
    pub fn get_ltk(&self) -> Option<u128> {
        self.ltk
    }
}

impl PartialEq for KeyDBEntry {
    fn eq(&self, other: &Self) -> bool {
        self.compare_entry(other).is_eq()
    }
}

impl Eq for KeyDBEntry {}

impl PartialOrd for KeyDBEntry {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.compare_entry(other))
    }
}

impl Ord for KeyDBEntry {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.compare_entry(other)
    }
}

impl core::hash::Hash for KeyDBEntry {
    fn hash<H>(&self, state: &mut H)
    where
        H: core::hash::Hasher,
    {
        (self.peer_addr, self.irk).hash(state)
    }
}

/// The Bonding Keys "database"
///
/// This is a simple `database` for storing bonding information of previously bonded devices. It is
/// just a vector of `KeyDBEntry`s sorted by the identity address. `KeyDBEntry`s without an identity
/// address are also resolvable but only if they contain an identity resolving key (IRK).
///
/// # Panics
/// Trying to add `KeyDBEntry`s without an identity address or identity resolving key will incur a
/// panic.
#[derive(serde::Serialize, serde::Deserialize)]
struct KeyDB {
    entries: Vec<KeyDBEntry>,
}

impl KeyDB {
    /// Create a new `KeyDB` from a vector of `KeyDBEntry`
    fn new(mut entries: Vec<KeyDBEntry>) -> Self {
        entries.sort_by(|rhs, lhs| rhs.compare_entry(lhs));

        Self { entries }
    }

    /// Get the keys associated with the provided `irk` and/or `address`.
    ///
    /// Return the keys associated with the specified `irk` and/or `address`. `None` is
    /// returned if there is no entry associated with the given keys.
    fn get<'s, 'a, I, A>(&'s self, irk: I, address: A) -> Option<&'s KeyDBEntry>
    where
        I: Into<Option<&'a u128>>,
        A: Into<Option<&'a BluAddr>>,
    {
        let i = irk.into();
        let a = address.into();
        let entries = &self.entries;

        self.entries
            .binary_search_by(|entry| entry.cmp_entry_by_keys(i, a))
            .ok()
            .map_or(None, |idx| entries.get(idx))
    }

    /// Add the keys with the provided KeyDBEntry
    ///
    /// This will override keys that have the same identity address and IRK.
    fn add(&mut self, entry: KeyDBEntry) {
        match self.entries.binary_search_by(|in_entry| in_entry.compare_entry(&entry)) {
            Ok(idx) => self.entries[idx] = entry,
            Err(idx) => self.entries.insert(idx, entry),
        }
    }

    fn iter(&self) -> impl core::iter::Iterator<Item = &KeyDBEntry> {
        self.entries.iter()
    }

    fn remove<'a, I, A>(&'a mut self, irk: I, address: A) -> bool
    where
        I: Into<Option<&'a u128>>,
        A: Into<Option<&'a BluAddr>>,
    {
        let i = irk.into();
        let a = address.into();

        self.entries
            .binary_search_by(|entry| entry.cmp_entry_by_keys(i, a))
            .ok()
            .map_or(false, |idx| {
                self.entries.remove(idx);
                true
            })
    }
}

impl Default for KeyDB {
    /// Create an empty KeyDB
    fn default() -> Self {
        KeyDB::new(Vec::new())
    }
}

/// A simple Security Manager keys database
///
/// A `SecurityManagerKeys` contains a database of encryption keys for with previously bonded
/// devices. Its main purpose is for saving bonding information and to retrieve the correct
/// encryption keys upon successful identification of the peer device.
///
/// This 'database' is nothing more than a glorified list of `KeyDBEntry`
/// sorted using the
/// [compare_entry](crate::sm::KeyDBEntry::compare_entry)
/// method.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct SecurityManagerKeys {
    keys_db: KeyDB,
}

impl SecurityManagerKeys {
    pub fn new(keys: Vec<KeyDBEntry>) -> Self {
        SecurityManagerKeys {
            keys_db: KeyDB::new(keys),
        }
    }

    /// Get an iterator over the keys
    pub fn iter(&self) -> impl Iterator<Item = &KeyDBEntry> {
        self.keys_db.iter()
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
    /// # let security_manager = bo_tie::sm::SecurityManagerKeys::default();
    /// # let resolvable_private_address = [0u8;6];
    ///
    /// security_manager.resolve_rpa_itr(resolvable_private_address).find_map(|keys_opt| keys_opt);
    /// ```
    ///
    /// # Note
    /// If you know the identity address of the device to be connected, then this method is
    /// *probably* not needed. Most controllers can handle resolving a private address for a single
    /// connectible device. See the HCI methods within the module
    /// [`privacy`](crate::hci::le::privacy).
    pub fn resolve_rpa_itr(
        &self,
        addr: crate::BluetoothDeviceAddress,
    ) -> impl core::iter::Iterator<Item = Option<KeyDBEntry>> + '_ {
        let hash = [addr[0], addr[1], addr[2]];
        let prand = [addr[3], addr[4], addr[5]];

        self.keys_db
            .entries
            .iter()
            .take_while(|e| e.peer_irk.is_some())
            .map(move |e| {
                e.peer_irk.and_then(|irk| {
                    if toolbox::ah(irk, prand) == hash {
                        Some(e.clone())
                    } else {
                        None
                    }
                })
            })
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
            _ => false,
        }
    }

    /// Remove keys in the database
    ///
    /// Removes the entry that matches `keys` in the database
    pub fn remove_keys(&mut self, keys: &KeyDBEntry) -> bool {
        self.keys_db.remove(keys.peer_irk.as_ref(), keys.peer_addr.as_ref())
    }

    /// Get a specific `KeyDBEntry` from its peer IRK and peer Address
    pub fn get_keys<I, A>(&self, peer_irk: I, peer_addr: A, peer_addr_is_pub: bool) -> Option<&KeyDBEntry>
    where
        I: Into<Option<u128>>,
        A: Into<Option<crate::BluetoothDeviceAddress>>,
    {
        let peer_addr = peer_addr.into().map(|addr| {
            if peer_addr_is_pub {
                BluAddr::Public(addr)
            } else {
                BluAddr::StaticRandom(addr)
            }
        });

        self.keys_db.get(peer_irk.into().as_ref(), peer_addr.as_ref())
    }
}

trait GetXOfP256Key {
    fn x(&self) -> [u8; 32];
}

impl GetXOfP256Key for [u8; 64] {
    fn x(&self) -> [u8; 32] {
        let mut x = [0u8; 32];

        x.copy_from_slice(&self[..32]);

        x
    }
}

/// Error for method [`OutOfBandMethodBuilder::build`](OutOfBandMethodBuilder::build)
///
/// When initializing bi-directional OOB support for a Security Manager, a method for sending
/// and a method for receiving must be set. If either of these methods are not set, then this error
/// is returned when trying to build a Security Manager.
///
/// # Note
/// If it was the intention not to set the method, then when constructing a Security Manager look
/// for the `build_with
pub enum OobBuildError {
    Send,
    Receive,
}

impl core::fmt::Debug for OobBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        <Self as core::fmt::Display>::fmt(self, f)
    }
}

impl core::fmt::Display for OobBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            OobBuildError::Send => f.write_str("Send method not set for OOB data"),
            OobBuildError::Receive => f.write_str("Receive method not set for OOB data"),
        }
    }
}

/// Out of Band pairing method setup
///
/// Security Managers that implement this trait can be used as the out-of-band (OOB) process for
/// pairing. Any communication process that is outside of the direct Bluetooth communication between
/// the two pairing devices can be considered a valid OOB. However the OOB link must have
/// man in the middle protection in order for the OOB method to be secure form of pairing.
///
/// # Bidirectional confirm validation
/// The methods [`set_send_method`](OutOfBandMethodBuilder::set_send_method) and
/// [`set_receive_method`]((OutOfBandMethodBuilder::set_receive_method) determine how data is sent
/// and received through the OOB interface. Both of them must be called before an
/// [`OutOfBandSlaveSecurityManager`] can be built with [`build`]. The method `set_send_method` is
/// used to set a factory function for generating a future to process sending data over the OOB
/// interface. Correspondingly `set_receive_method` is for setting the factory function for
/// generating a future for receiving data over the OOB interface.
///
/// # Single Direction confirm validation
/// If it is desired to only support one direction of OOB data transfer, the methods
/// [`only_send_oob`](OutOfBandMethodBuilder::only_send_oob) and
/// [`only_receive_oob`](OutOfBandMethodBuilder::only_receive_oob) can be used for facilitate this,
/// however it is recommended to only use these methods when the OOB interface only supports a
/// single direction of data transfer. Using these methods will mean that the initiator must support
/// the counterpart direction of data transfer or OOB authentication will fail.
pub trait BuildOutOfBand: core::ops::DerefMut<Target = Self::Builder> {
    type Builder;
    type SecurityManager;

    fn build(self) -> Self::SecurityManager;
}

/// Out of Band pairing method setup
///
/// Security Managers that implement this trait can be used as the out-of-band (OOB) process for
/// pairing. Any communication process that is outside of the direct Bluetooth communication between
/// the two pairing devices can be considered a valid OOB. However the OOB link must have
/// man in the middle protection in order for the OOB method to be secure form of pairing.
///
/// # Bidirectional confirm validation
/// The methods [`set_send_method`](OutOfBandMethodBuilder::set_send_method) and
/// [`set_receive_method`]((OutOfBandMethodBuilder::set_receive_method) determine how data is sent
/// and received through the OOB interface. Both of them must be called before an
/// [`OutOfBandSlaveSecurityManager`] can be built with [`build`]. The method `set_send_method` is
/// used to set a factory function for generating a future to process sending data over the OOB
/// interface. Correspondingly `set_receive_method` is for setting the factory function for
/// generating a future for receiving data over the OOB interface.
///
/// # Single Direction confirm validation
/// If it is desired to only support one direction of OOB data transfer, the methods
/// [`only_send_oob`](OutOfBandMethodBuilder::only_send_oob) and
/// [`only_receive_oob`](OutOfBandMethodBuilder::only_receive_oob) can be used for facilitate this,
/// however it is recommended to only use these methods when the OOB interface only supports a
/// single direction of data transfer. Using these methods will mean that the initiator must support
/// the counterpart direction of data transfer or OOB authentication will fail.
pub struct OutOfBandMethodBuilder<B, S, R> {
    builder: B,
    send_method: S,
    receive_method: R,
}

impl<B, S, R> OutOfBandMethodBuilder<B, S, R>
where
    S: for<'a> OutOfBandSend<'a>,
    R: OutOfBandReceive,
{
    fn new(builder: B, send_method: S, receive_method: R) -> Self {
        OutOfBandMethodBuilder {
            builder,
            send_method,
            receive_method,
        }
    }
}

impl<B, S, R> core::ops::Deref for OutOfBandMethodBuilder<B, S, R> {
    type Target = B;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

impl<B, S, R> core::ops::DerefMut for OutOfBandMethodBuilder<B, S, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.builder
    }
}

/// The trait to used by a Security Manager send data over an out of band (OOB) interface
///
/// This is auto implemented for anything that implements `Fn(&[u8]) -> impl Future`.
pub trait OutOfBandSend<'a> {
    type Future: Future + 'a;

    fn can_send() -> bool;

    fn send(&self, data: &'a [u8]) -> Self::Future;
}

impl<'a, S, F> OutOfBandSend<'a> for S
where
    S: Fn(&'a [u8]) -> F,
    F: Future + 'a,
{
    type Future = F;

    fn can_send() -> bool {
        true
    }

    fn send(&self, data: &'a [u8]) -> Self::Future {
        self(data)
    }
}

impl OutOfBandSend<'_> for () {
    type Future = UnusedOobInterface<()>;

    fn can_send() -> bool {
        false
    }

    fn send(&self, _: &[u8]) -> Self::Future {
        panic!("Tried to send OOB data on a nonexistent interface")
    }
}

/// The trait to used by a Security Manager send data over an out of band (OOB) interface
///
/// This is auto implemented for anything that implements `Fn() -> impl Future<Output = Vec<u8>>`.
pub trait OutOfBandReceive {
    type Future: Future<Output = Vec<u8>>;

    fn can_receive() -> bool;

    fn receive(&self) -> Self::Future;
}

impl<R, F> OutOfBandReceive for R
where
    R: Fn() -> F,
    F: Future<Output = Vec<u8>>,
{
    type Future = F;

    fn can_receive() -> bool {
        true
    }

    fn receive(&self) -> Self::Future {
        self()
    }
}

impl OutOfBandReceive for () {
    type Future = UnusedOobInterface<Vec<u8>>;

    fn can_receive() -> bool {
        false
    }

    fn receive(&self) -> Self::Future {
        panic!("Tried to receive OOB data on a nonexistent interface")
    }
}

/// Future used as the return for an unavailable OOB interface
#[doc(hidden)]
pub struct UnusedOobInterface<V>(core::marker::PhantomData<V>);

impl<V> Future for UnusedOobInterface<V> {
    type Output = V;
    fn poll(self: core::pin::Pin<&mut Self>, _: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        unreachable!()
    }
}
