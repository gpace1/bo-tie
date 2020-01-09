//! Bluetooth Security Manager
//!
//! The Security Manager is used to manage the pairing process and key distribution between two
//! connected devices. A [`SecurityManager`](crate::hci::sm::SecurityManager) is used to contain 
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
use core::future::Future;
use serde::{Serialize, Deserialize};

use crate::l2cap::ConnectionChannel;

pub mod toolbox;
pub mod pairing;
pub mod encrypt_info;
pub mod responder;
pub mod initiator;
mod lazy_encrypt;

const L2CAP_LEGACY_MTU: usize = 23;
const L2CAP_SECURE_CONNECTIONS_MTU: usize = 65;

const ENCRYPTION_KEY_MIN_SIZE: usize = 7;
const ENCRYPTION_KEY_MAX_SIZE: usize = 16;

const SECURITY_MANAGER_L2CAP_CHANNEL_ID: crate::l2cap::ChannelIdentifier =
    crate::l2cap::ChannelIdentifier::LE(crate::l2cap::LeUserChannelIdentifier::SecurityManagerProtocol);

#[derive(Debug)]
pub enum Error {
    Size,
    Format,
    IncorrectValue,
    IncorrectCommand(CommandType),
    UnsupportedFeature,
    PairingFailed(pairing::PairingFailedReason),
    EncryptionFailed(alloc::boxed::Box<dyn core::fmt::Debug>),
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
            _   => Err( Error::IncorrectValue )
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

/// The Encryption Key "database"
///
/// This contains the keys that were previously generated. `entries` is sorted by the `peer_irk`
/// and `peer_addr` members of each `KeyDBEntry`. The sort is designed to have all the `KeyDBEntry`s
/// with a peer IRK to be less then all the `KeyDBEntry`s without a peer IRK.
///
/// # Usage
/// Please only use the functions labeled with the `pub` keyword.
struct KeyDB {
    entries: Vec<KeyDBEntry>,
}

impl KeyDB {

    /// Create a new `KeyDB` from a vector of `KeyDBEntry`
    ///
    /// # Panic
    /// All entries must have either a peer IRK or a peer Address set.
    pub fn new(mut entries: Vec<KeyDBEntry>) -> Self {

        entries.sort_by(|rhs, lhs| rhs.cmp_entry(lhs) );

        Self { entries }
    }

    /// Get the keys associated with the provided `irk` and/or `address`.
    ///
    /// Return the keys associated with the specified `irk` and/or `address`. `None` is
    /// returned if there is no entry associated with the given keys.
    pub fn get<'s, 'a, I,A>(&'s mut self, irk: I, address: A) -> Option<&'s KeyDBEntry>
    where I: Into<Option<&'a u128>> + 'a,
          A: Into<Option<&'a BluAddr>> + 'a,
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
    /// Inserts the KeyDBEntry into the database if there is no other entry with the same peer IRK
    /// and peer Address. The entry is not inserted if both the peer IRK and peer Address are `None`
    ///
    /// Returns a reference to the inserted KeyDBEntry or `None` if `entry` didn't have the
    /// required keys or an entry with the same `peer_irk` and `peer_addr` is already in the
    /// database.
    pub fn insert_and_get(&mut self, entry: KeyDBEntry) -> Option<&mut KeyDBEntry> {
        if entry.peer_addr == None && entry.peer_irk == None {
            return None
        } else {
            self.entries.binary_search_by(|in_entry| in_entry.cmp_entry(&entry) )
                .err()
                .and_then( move |idx| { self.entries.insert(idx, entry); self.entries.get_mut(idx) } )
        }
    }

    pub fn iter(&self) -> impl core::iter::Iterator<Item = &KeyDBEntry> {
        self.entries.iter()
    }

    pub fn remove<I,A>(&mut self, irk: I, address: A) -> bool
    where I: for<'a> Into<Option<&'a u128>>,
          A: for<'a> Into<Option<&'a BluAddr>>,
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

/// An entry in the Keys Database
///
/// Entries in the database are ordered by a peer devices Identity Resolving Key (IRK) or the \
/// Address given in the Identity Address Information Command. A `KeyDBEntry` is not required to
/// have both an IRK and an Address, but it must have one of them.
///
/// Each KeyDBEntry stores the Long Term Key (LTK), a unique Connection Signature Resolving Key
/// (CSRK), a unique Identity Resolving Key (IRK), the peer devices CSRK, the peer's IRK, the
/// address, and the CSRK counters. All of these keys are optional with the exception that either
/// the peer's IRK or the peer's address must exist.
///
/// This device may use a static IRK and CSRK to a given peer device. There can be only one static
/// IRK and CSRK per `SecurityManager`, but any number of `KeyDBEntry`s can use them. If a static
/// CSRK is used, the sign counter for this `KeyDBEntry` can only be used through the connection to
/// the peer device.
#[derive(Clone,Serialize,Deserialize)]
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

impl KeyDBEntry {

    /// Compare entries by the peer keys irk and addr
    ///
    /// # Panic
    /// If both `peer_irk` and `peer_addr` are `None` or both `self.peer_irk` and `self.peer_addr`
    /// are `None`.
    fn cmp_entry_by_keys<'a,I,A>(&self, peer_irk: I, peer_addr: A) -> core::cmp::Ordering
    where I: Into<Option<&'a u128>> + 'a,
          A: Into<Option<&'a BluAddr>> + 'a,
    {
        use core::cmp::Ordering;

        match (self.peer_irk.as_ref(), peer_irk.into(), self.peer_addr.as_ref(), peer_addr.into()) {
            (Some(this),Some(other), _, _) =>
                this.cmp(other),
            (None, None, Some(this), Some(other)) =>
                this.cmp(other),
            (Some(_), None, _, Some(_)) =>
                Ordering::Less,
            (None, Some(_), Some(_), _) =>
                Ordering::Greater,
            (None, _, None, _) |
            (_, None, _, None) =>
                Ordering::Equal
        }
    }

    fn cmp_entry(&self, other: &Self) -> core::cmp::Ordering {
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum BluAddr {
    Public(crate::BluetoothDeviceAddress),
    StaticRandom(crate::BluetoothDeviceAddress)
}

/// The Security Manager
///
/// The security manager is the top level container of keys
#[derive(Default)]
pub struct SecurityManager {
    key_db: KeyDB,
    static_irk: Option<u128>,
    static_csrk: Option<u128>,
}

impl SecurityManager {

    const SMALLEST_PACKET_SIZE: usize = 1;

    pub fn new(keys: Vec<KeyDBEntry>) -> Self {
        SecurityManager {
            key_db: KeyDB::new(keys),
            static_irk: None,
            static_csrk: None,
        }
    }

    /// Get all peer Identity Resolving Keys stored in the Key Database
    pub fn get_peer_irks(&self) -> impl core::iter::Iterator<Item = u128> + '_{
        self.key_db.iter().filter_map(|entry| entry.peer_irk )
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
    /// The return is an iterator that will try to resolve `addr` with a peer IRK on each iteration.
    /// If the address is resolved by a peer's IRK, the `KeyDBEntry` that contains the matching IRK
    /// is returned. The easiest way to use this function is to just combine it with the
    /// [`find_map`](https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.find_map)
    /// iterator method.
    ///
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

        self.key_db.entries.iter()
            .take_while(|e| e.peer_irk.is_some() )
            .map(move |e| e.peer_irk.and_then( |irk|
                if toolbox::ah( irk, prand ) == hash { Some(e.clone()) } else { None }
            )
        )
    }

    pub fn new_slave_builder<'a, C>(
        &'a self,
        channel: &'a C,
        master_address: &'a crate::BluetoothDeviceAddress,
        is_master_address_random: bool,
        this_address: &'a crate::BluetoothDeviceAddress,
        is_this_address_random: bool,
    )
    -> responder::SlaveSecurityManagerBuilder<'a, C>
    where C: ConnectionChannel
    {
        responder::SlaveSecurityManagerBuilder::new(
            self,
            channel,
            master_address,
            this_address,
            is_master_address_random,
            is_this_address_random,
        )
    }

    pub fn new_master_security_manager_builder<C>(&self, _channel: &C)
    -> initiator::MasterSecurityManagerBuilder<'_, C>
    where C: ConnectionChannel
    {
        unimplemented!()
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

/// Lazy Encryption
///
/// This can be used to encrypt a connection between a master and slave.
pub struct LazyEncrypt<'a, R, C> {
    ltk: u128,
    irk: u128,
    csrk: u128,
    peer_irk: Option<u128>,
    peer_csrk: Option<u128>,
    connection_channel: &'a C,
    role: R,
}

impl<'a, R, C> LazyEncrypt<'a, R, C> where C: ConnectionChannel {

    fn send<Cmd,P>(&self, command: Cmd)
        where Cmd: Into<Command<P>>,
              P: CommandData
    {
        use crate::l2cap::AclData;

        let acl_data = AclData::new( command.into().into_icd(), SECURITY_MANAGER_L2CAP_CHANNEL_ID);

        self.connection_channel.send((acl_data, L2CAP_LEGACY_MTU));
    }

    /// Get the Long Term Key
    ///
    /// This is the secret key shared between the Master and Slave device use by the cypher for
    /// encrypting data. If this key is leaked to an unintended party, they will be able to access
    /// the
    pub fn get_ltk(&self) -> u128 {
        self.ltk
    }

    /// Get the Identity Resolving Key
    ///
    /// The Identity Resolving Key is a way to re-connect to a device using a semi-anonymous random
    /// address.
    ///
    /// # Note
    /// If you wish to send this key to the other party without the help of `LazyEncrypt`, make sure
    /// the connection is encrypted.
    pub fn get_irk(&self) -> u128 {
        self.irk
    }

    /// Create a new resolvable private address
    ///
    /// This will create a new resolvable private address from the generated irk value.
    pub fn new_rpa(&self) -> crate::BluetoothDeviceAddress {

        let mut addr = crate::BluetoothDeviceAddress::default();

        let mut prand = toolbox::rand_u24();

        // required nonrandom bits of prand see the specification (V. 5.0 | Vol 6, Part B, Section
        // 1.3.2.2)
        prand[2] = 0b_0100_0000;

        let hash = toolbox::ah(self.irk, prand);

        addr[..3].copy_from_slice(&hash);
        addr[3..].copy_from_slice(&prand);

        addr
    }

    /// Get the Identity Resolving Key of the Peer Device or `None` if the peer has not sent an IRK.
    pub fn get_peer_irk(&self) -> Option<u128> {
        self.peer_irk
    }

    /// Get the Connection Signature Resolving Key
    ///
    /// The Connection Signature Resolving Key is used for authentication of data
    ///
    /// # Note
    /// If you wish to send this key to the other party without the help of `LazyEncrypt`, make sure
    /// the connection is encrypted.
    pub fn get_csrk(&self) -> u128 {
        self.csrk
    }

    /// Get the Connection Signature Resolving Key of the Peer Device or `None` if the peer has not
    /// sent an CSRK.
    pub fn get_peer_csrk(&self) -> Option<u128> {
        self.peer_csrk
    }

    /// Get the role of the device in the security manager
    pub fn get_role(&self) -> R where R: Copy {
        self.role
    }
}

impl<'a, C> LazyEncrypt<'a, Master, C> {

    /// Use the Host Controller Interface to start encrypting the Bluetooth LE connection
    ///
    /// This returns a future that will setup encryption of the connection channel associated with
    /// the provided `connection_handle` once it is polled to completion.
    ///
    /// Only the AES cypher is considered "encrypted" by this procedure. An error will be returned
    /// if the controller decides to use the E0 cypher for encryption. A timeout can also be
    /// provided for waiting on the encryption events to be sent from the controller to the host.
    ///
    /// # Note
    /// This will set the event mask for the Host Controller Interface to the events
    /// ['DisconnectionComplete'](crate::hci::events::Events::DisconnectionComplete),
    /// ['EncryptionChange'](crate::hci::events::Events::EncryptionChange),
    /// and
    /// ['EncryptionKeyRefreshComplete'](crate::hci::events::Events::EncryptionKeyRefreshComplete),
    /// These events are needed by the returned future, and can only be masked away once it is
    /// polled to completion.
    pub fn hci_le_start_encryption<'z, HCI, D>(
        self,
        hci: &'z crate::hci::HostInterface<HCI>,
        connection_handle: crate::hci::common::ConnectionHandle,
        encryption_timeout: D,
    ) -> impl Future<Output=Result<(), Error>> + 'z
    where HCI: crate::hci::HostControllerInterface + 'static,
            D: Into<Option<core::time::Duration>> + 'z,
         <HCI as crate::hci::HostControllerInterface>::ReceiveEventError:  Unpin,
    {
        use crate::hci::cb::set_event_mask::EventMask;

        let event_mask = [
            EventMask::DisconnectionComplete,
            EventMask::EncryptionChange,
            EventMask::EncryptionKeyRefreshComplete,
        ];

        lazy_encrypt::new_lazy_encrypt_master_future(event_mask, self.ltk, hci, connection_handle, encryption_timeout)
    }

    /// Switch the roll form `Master` to `Slave`
    ///
    /// This switches the role flag in `LazyEncrypt`, no actual connection role is change by this
    /// function. This function should be called when the device changes from the Master to the
    /// Slave.
    ///
    /// # Note
    /// This is not an inexpensive operation, equivalent (or worse) in performance to a clone
    /// operation.
    pub fn switch_role(self) -> LazyEncrypt<'a, Slave, C> {
        LazyEncrypt {
            ltk: self.ltk,
            irk: self.irk,
            csrk: self.csrk,
            peer_irk: self.peer_irk,
            peer_csrk: self.peer_csrk,
            connection_channel: self.connection_channel,
            role: Slave,
        }
    }
}

impl<'a, C> LazyEncrypt<'a, Slave, C> {

    /// Switch the roll form `Slave` to `Master`
    ///
    /// This switches the role flag in `LazyEncrypt`, no actual connection role is change by this
    /// function. This function should be called when the device changes from the Slave to the
    /// Master.
    ///
    /// # Note
    /// This is not an inexpensive operation, equivalent (or worse) in performance to a clone
    /// operation.
    pub fn switch_role(self) -> LazyEncrypt<'a, Master, C> {
        LazyEncrypt {
            ltk: self.ltk,
            irk: self.irk,
            csrk: self.csrk,
            peer_irk: self.peer_irk,
            peer_csrk: self.peer_csrk,
            connection_channel: self.connection_channel,
            role: Master,
        }
    }

    /// Await encryption from the `Master` using the Host Controller Interface
    ///
    /// Encryption is started (and changed) by the Master device. The slave device must await for
    /// the event ['LongTermKeyRequest'](crate::hci::events::LEMeta::LongTermKeyRequest) that is
    /// sent from the controller to request the LE LTK.
    pub fn hci_await_encrypt<'z, HCI, D>(
        &self,
        hci: &'z crate::hci::HostInterface<HCI>,
        connection_handle: crate::hci::common::ConnectionHandle,
        await_timeout: D,
    ) -> impl Future<Output=Result<(), Error>> + 'z
    where HCI: crate::hci::HostControllerInterface + 'static,
            D: Into<Option<core::time::Duration>> + 'z,
         <HCI as crate::hci::HostControllerInterface>::ReceiveEventError: 'static + Unpin
    {
        use crate::hci::cb::set_event_mask::EventMask;
        use crate::hci::events::LEMeta;

        let event_mask = [ EventMask::LEMeta ];
        let le_event_mask = [LEMeta::LongTermKeyRequest];

        let mask = (event_mask, le_event_mask);

        lazy_encrypt::new_await_encrypt_slave_future(self.ltk, mask, hci, connection_handle, await_timeout)
    }
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Master;

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Slave;