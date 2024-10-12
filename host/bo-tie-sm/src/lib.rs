//! Bluetooth Security Manager
//!
//! The Security Manager is used to manage the pairing process and key distribution (bonding)
//! between two connected devices. There are separate Security Managers for the initiating device
//! and for the responding (non-initiating) device. These Security Managers can be found in the
//! [`initiator`](initiator) and [`responder`](responder) modules. Both Security Managers are
//! connection instance specific. They're only valid for a single connection and for the lifetime of
//! that connection. The only purpose of the Security Managers are to manage the Security Manager
//! protocol to achieve pairing and bonding, keys generated from pairing and bonding must be
//! retrieved and stored from the Security Managers in a separate data base.
//!
//! [`SecurityManagerKeys`](SecurityManagerKeys) is a very basic keys database is provided by this
//! module, but it does not need to be used for keys management with this library. Keys can be
//! retrieved from the Security Managers after bonding has been completed (the secure key (LTK) is
//! retrievable after pairing is completed).
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
//! # let this_address = bo_tie_core::BluetoothDeviceAddress::zeroed();
//! # let peer_address = bo_tie_core::BluetoothDeviceAddress::zeroed();
//! # struct StubConnectionChannel;
//! # impl ConnectionChannel for StubConnectionChannel {
//! #     type SendBuffer = Vec<u8>;
//! #     type SendFut<'a> = std::pin::Pin<Box<dyn Future<Output=Result<(), bo_tie_l2cap::send_future::Error<Self::SendErr>>>>>;
//! #     type SendErr = usize;
//! #     type RecvBuffer = Vec<u8>;
//! #     type RecvFut<'a> = std::pin::Pin<Box<dyn Future<Output=Option<Result<L2capFragment<Self::RecvBuffer>, bo_tie_l2cap::BasicFrameError<<Self::RecvBuffer as bo_tie_core::buffer::TryExtend<u8>>::Error>>>>>>;
//! #     fn send(&self, data: BasicFrame<Vec<u8>>) -> Self::SendFut<'_> { unimplemented!() }
//! #     fn set_mtu(&mut self,mtu: u16) { unimplemented!() }
//! #     fn get_mtu(&self) -> usize { unimplemented!() }
//! #     fn max_mtu(&self) -> usize { unimplemented!() }
//! #     fn min_mtu(&self) -> usize { unimplemented!() }
//! #     fn receive_fragment(&mut self) -> Self::RecvFut<'_> { unimplemented!() }
//! # }
//! # let connection_channel = StubConnectionChannel;
//! // An example of setting up a receiver that support oob
//!
//! use bo_tie_sm::responder::SecurityManagerBuilder;
//! use bo_tie_l2cap::{BasicFrame, ConnectionChannel, L2capFragment};
//! use std::task::Waker;
//! use std::future::Future;
//!
//! async fn oob_send(data: &[u8]) {
//!     // send out of band data
//! }
//!
//! async fn oob_receive() -> Vec<u8> {
//!     // receive out of band data
//! # Vec::new()
//! }
//!
//! let security_manager = SecurityManagerBuilder::new(
//!         this_address,
//!         peer_address,
//!         false,
//!         false
//!     )
//!     .set_oob_sender(oob_send)
//!     .set_oob_receiver(oob_receive)
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

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
/* Note:
 * Until type_alias_impl_trait is stabilized, all tests-scaffold must run on the nightly channel
 */
#![cfg_attr(all(test, feature = "std"), feature(type_alias_impl_trait))]

extern crate alloc;

use alloc::vec::Vec;

pub use bo_tie_core::BluetoothDeviceAddress;
pub use bo_tie_l2cap as l2cap;

use crate::pairing::KeyDistributions;
use bo_tie_l2cap::pdu::BasicFrame;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod encrypt_info;
pub mod initiator;
pub mod pairing;
pub mod responder;
pub mod toolbox;

// /// The encryption key minimum size
// ///
// /// Note:
// /// This may be forever left out as it is cryptographically unsafe to reduce the key size.
// const ENCRYPTION_KEY_MIN_SIZE: usize = 7;

/// The maximum encryption key size
///
/// This is the size of the encryption key in bytes. It is also the default key size as the larger
/// the key size the harder it is to crack encryption.
const ENCRYPTION_KEY_MAX_SIZE: usize = 16;

/// The L2CAP channel identifier for the Security Manager
pub const LE_U_CHANNEL_ID: l2cap::cid::ChannelIdentifier =
    l2cap::cid::ChannelIdentifier::Le(l2cap::cid::LeCid::SecurityManagerProtocol);

/// General error within the Security Manager Protocol
#[derive(Debug, Clone)]
pub enum Error {
    /// Incorrect Size
    Size,
    /// Incorrect Format
    Format,
    /// Incorrect Value
    Value,
    /// Incorrect Security Manager Command
    IncorrectCommand {
        expected: Option<CommandType>,
        received: CommandType,
    },
    /// Feature is unsupported
    UnsupportedFeature,
    /// The operation required encryption, but it is unknown if the connection is encrypted. The
    /// security manager must be told that a link is encrypted with the method `set_encrypted`.
    UnknownIfLinkIsEncrypted,
    /// Incorrect L2CAP channel ID
    IncorrectL2capChannelId,
    /// The operation requires this device to be paired with the connected device.
    OperationRequiresPairing,
    /// The input or operation is no longer valid to the scope of pairing
    Invalid,
    /// The Security Manager is configured to not support pairing
    PairingUnsupported,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Size => f.write_str("size"),
            Error::Format => f.write_str("format"),
            Error::Value => f.write_str("value"),
            Error::IncorrectCommand { expected, received } => {
                write!(f, "incorrect command: {received}")?;

                if let Some(expected) = expected {
                    write!(f, ", expected command: {expected}")
                } else {
                    f.write_str(" as no command was expected")
                }
            }
            Error::UnsupportedFeature => f.write_str("unsupported feature"),
            Error::UnknownIfLinkIsEncrypted => f.write_str("unknown if connection is encrypted"),
            Error::IncorrectL2capChannelId => {
                f.write_str("incorrect channel identifier for the security manager protocol")
            }
            Error::OperationRequiresPairing => f.write_str("operation requires pairing"),
            Error::Invalid => f.write_str("the operation is no longer valid"),
            Error::PairingUnsupported => f.write_str("the Security Manager is not configured to support pairing"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[derive(Debug)]
pub enum SecurityManagerError<S> {
    Error(Error),
    Sender(S),
}

impl<S> core::fmt::Display for SecurityManagerError<S>
where
    S: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            SecurityManagerError::Error(e) => core::fmt::Display::fmt(e, f),
            SecurityManagerError::Sender(s) => core::fmt::Display::fmt(s, f),
        }
    }
}

impl<S> From<Error> for SecurityManagerError<S> {
    fn from(e: Error) -> Self {
        SecurityManagerError::Error(e)
    }
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

impl core::fmt::Display for CommandType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            CommandType::PairingRequest => f.write_str("pairing request"),
            CommandType::PairingResponse => f.write_str("pairing response"),
            CommandType::PairingConfirm => f.write_str("pairing confirm"),
            CommandType::PairingRandom => f.write_str("pairing random"),
            CommandType::PairingFailed => f.write_str("pairing failed"),
            CommandType::EncryptionInformation => f.write_str("encryption information"),
            CommandType::MasterIdentification => f.write_str("master identification"),
            CommandType::IdentityInformation => f.write_str("identity information"),
            CommandType::IdentityAddressInformation => f.write_str("identity address information"),
            CommandType::SigningInformation => f.write_str("signing information"),
            CommandType::SecurityRequest => f.write_str("security request"),
            CommandType::PairingPublicKey => f.write_str("pairing public key"),
            CommandType::PairingDHKeyCheck => f.write_str("pairing Diffie Hellman key check"),
            CommandType::PairingKeyPressNotification => f.write_str("pairing key press notification"),
        }
    }
}

impl TryFrom<&'_ BasicFrame<Vec<u8>>> for CommandType {
    type Error = Error;

    fn try_from(acl_data: &'_ BasicFrame<Vec<u8>>) -> Result<Self, Self::Error> {
        if acl_data.get_channel_id() != LE_U_CHANNEL_ID {
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
/// A trait for converting to or from the format within a Security Manager Command PDU
trait CommandData
where
    Self: Sized,
{
    /// Convert into command data
    fn into_command_format(self) -> bo_tie_core::buffer::stack::LinearBuffer<65, u8>;

    /// Try to convert from command data
    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error>;
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
    fn into_command_format(self) -> bo_tie_core::buffer::stack::LinearBuffer<65, u8> {
        let mut data = self.data.into_command_format();

        data.try_insert(self.command_type.into_val(), 0).unwrap();

        data
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 0 {
            Err(Error::Size)
        } else {
            Ok(Command {
                command_type: CommandType::try_from_val(icd[0])?,
                data: D::try_from_command_format(&icd[1..])?,
            })
        }
    }
}

/// Direction of the passkey
///
/// Either both devices enter a passkey or one device displays the passkey and the other device
/// enters the passkey.
#[derive(Debug, Clone, Copy, PartialEq)]
enum PasskeyDirection {
    ResponderDisplaysInitiatorInputs,
    InitiatorDisplaysResponderInputs,
    InitiatorAndResponderInput,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PairingMethod {
    /// Out of Bound
    Oob(OobDirection),
    PassKeyEntry(PasskeyDirection),
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
    fn determine_method(
        initiator_oob_data: pairing::OobDataFlag,
        responder_oob_data: pairing::OobDataFlag,
        initiator_io_capability: pairing::IoCapability,
        responder_io_capability: pairing::IoCapability,
        is_legacy: bool,
    ) -> Self {
        use pairing::{
            IoCapability::*, OobDataFlag::AuthenticationDataFromRemoteDevicePresent as Present,
            OobDataFlag::AuthenticationDataNotPresent as Unavailable,
        };

        match (
            initiator_oob_data,
            responder_oob_data,
            initiator_io_capability,
            responder_io_capability,
            is_legacy,
        ) {
            (Present, Present, _, _, _) => PairingMethod::Oob(OobDirection::BothSendOob),
            (Present, Unavailable, _, _, _) => PairingMethod::Oob(OobDirection::OnlyResponderSendsOob),
            (Unavailable, Present, _, _, _) => PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob),
            (_, _, DisplayOnly, DisplayOnly, _) => PairingMethod::JustWorks,
            (_, _, DisplayOnly, DisplayWithYesOrNo, _) => PairingMethod::JustWorks,
            (_, _, DisplayOnly, KeyboardOnly, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::InitiatorDisplaysResponderInputs)
            }
            (_, _, DisplayOnly, NoInputNoOutput, _) => PairingMethod::JustWorks,
            (_, _, DisplayOnly, KeyboardDisplay, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::InitiatorDisplaysResponderInputs)
            }
            (_, _, DisplayWithYesOrNo, DisplayOnly, _) => PairingMethod::JustWorks,
            (_, _, DisplayWithYesOrNo, DisplayWithYesOrNo, false) => PairingMethod::NumbComp,
            (_, _, DisplayWithYesOrNo, DisplayWithYesOrNo, true) => PairingMethod::JustWorks,
            (_, _, DisplayWithYesOrNo, KeyboardOnly, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::InitiatorDisplaysResponderInputs)
            }
            (_, _, DisplayWithYesOrNo, NoInputNoOutput, _) => PairingMethod::JustWorks,
            (_, _, DisplayWithYesOrNo, KeyboardDisplay, false) => PairingMethod::NumbComp,
            (_, _, DisplayWithYesOrNo, KeyboardDisplay, true) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::InitiatorDisplaysResponderInputs)
            }
            (_, _, KeyboardOnly, DisplayOnly, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::ResponderDisplaysInitiatorInputs)
            }
            (_, _, KeyboardOnly, DisplayWithYesOrNo, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::ResponderDisplaysInitiatorInputs)
            }
            (_, _, KeyboardOnly, KeyboardOnly, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::InitiatorAndResponderInput)
            }
            (_, _, KeyboardOnly, NoInputNoOutput, _) => PairingMethod::JustWorks,
            (_, _, KeyboardOnly, KeyboardDisplay, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::ResponderDisplaysInitiatorInputs)
            }
            (_, _, NoInputNoOutput, _, _) => PairingMethod::JustWorks,
            (_, _, KeyboardDisplay, DisplayOnly, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::ResponderDisplaysInitiatorInputs)
            }
            (_, _, KeyboardDisplay, DisplayWithYesOrNo, false) => PairingMethod::NumbComp,
            (_, _, KeyboardDisplay, DisplayWithYesOrNo, true) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::ResponderDisplaysInitiatorInputs)
            }
            (_, _, KeyboardDisplay, KeyboardOnly, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::InitiatorDisplaysResponderInputs)
            }
            (_, _, KeyboardDisplay, NoInputNoOutput, _) => PairingMethod::JustWorks,
            (_, _, KeyboardDisplay, KeyboardDisplay, false) => PairingMethod::NumbComp,
            (_, _, KeyboardDisplay, KeyboardDisplay, true) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::InitiatorDisplaysResponderInputs)
            }
        }
    }

    fn is_just_works(self) -> bool {
        if let PairingMethod::JustWorks = self {
            true
        } else {
            false
        }
    }
}

/// Data that is gathered in the process of pairing
///
/// This data is unique for each pairing attempt and must be dropped after a successful or failed
/// pairing attempt.
struct PairingData {
    /// Unique identifier of the instance of the pairing data
    instance: usize,
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
    /// Responder Random
    responder_random: u128,
    /// Initiator random
    initiator_random: u128,
    /// The public key received from the remote device
    peer_public_key: Option<toolbox::PubKey>,
    /// The Diffie-Hellman secret key generated via Elliptic Curve Crypto
    secret_key: Option<toolbox::DHSharedSecret>,
    /// The peers pairing confirm value
    peer_confirm: Option<u128>,
    /// Mac Key
    ///
    /// The initiator needs to hold the mac key until the responder sends its dh-key check.
    mac_key: Option<u128>,
    /// Long term key
    ///
    /// This is the unvalidated LTK held by the initiator until the dh-key check is send by the
    /// responder.
    ltk: Option<u128>,
    /// Passkey - A six digit number
    passkey: Option<u32>,
    /// Round of the passkey confirm checks.
    ///
    /// Passkey checks are done 20 times for each bit of the passkey (6 digits equates to 20 bits).
    /// This is always a value between 0 and 20.
    passkey_round: usize,
    /// Number comparison validation
    ///
    /// Used by the responder to check if number comparison has completed on this device by the
    /// user before validating the initiators DH Key check value and then sending its DH Key check
    /// value. Not used by other authentications.
    number_comp_validated: bool,
    /// Initiators DHKey Check value
    ///
    /// Used to store the initiators DH Key check if it is received before number comparison is
    /// validated on this device.
    initiator_dh_key_check: Option<u128>,
    /// Bonding keys to be sent to the peer Security Manager
    sent_bonding_keys: &'static [pairing::KeyDistributions],
    /// Bonding keys to be received from the peer Security Manager
    recv_bonding_keys: &'static [pairing::KeyDistributions],
}

/// The identity address of an device
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum IdentityAddress {
    Public(BluetoothDeviceAddress),
    StaticRandom(BluetoothDeviceAddress),
}

impl IdentityAddress {
    /// Get the identity address
    pub fn get_address(&self) -> BluetoothDeviceAddress {
        match self {
            IdentityAddress::Public(address) => *address,
            IdentityAddress::StaticRandom(address) => *address,
        }
    }

    /// Check if the identity address is a public device address
    pub fn is_public(&self) -> bool {
        match self {
            IdentityAddress::Public(_) => true,
            IdentityAddress::StaticRandom(_) => false,
        }
    }

    /// Check if the identity address is a random device address
    pub fn is_random(&self) -> bool {
        !self.is_public()
    }
}

/// Peer device Keying information
///
/// This contains all the keys that are generated by the security manager. It contains the
/// encryption keys used by this device for communication with a specific peer device. However the
/// keys can only be reused for a known, but currently unidentified device if a `Keys`
/// contains either the peer devices Identity Resolving Key (IRK) or the peers address.
///
/// Each `Keys` can store the Long Term Key (LTK), a unique Connection Signature Resolving Key
/// (CSRK), a unique Identity Resolving Key (IRK), the peer devices CSRK, the peer's IRK, the
/// peer address, and the CSRK counters. All of the keys and addresses are optional, but if a CSRK
/// exists its corresponding counter will also be present.
///
/// This device may use a static IRK and CSRK to a given peer device. There can be only one static
/// IRK and CSRK per `SecurityManager`, but any number of `Keys`s can use them. If a static
/// CSRK is used, the sign counter for this `Keys` can only be used through the connection to
/// the peer device.
///
/// # Equality, Ordering, and Hashing
/// Comparisons and hashing are implemented for `Keys`, but these operations only use the
/// identity address within a `Keys` for the calculations.
#[derive(Clone, Copy, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Keys {
    /// Authentication
    is_authenticated: bool,
    /// The Long Term Key (private key)
    ///
    /// If this is `None` then the connection cannot be encrypted
    ltk: Option<u128>,

    /// This Connection Signature Resolving Key (CSRK) and sign counter
    csrk: Option<(u128, u32)>,

    /// This device's Identity Resolving Key
    irk: Option<u128>,

    /// This devices identity address
    identity: Option<IdentityAddress>,

    /// The peer device's Connection Signature Resolving Key and sign counter
    peer_csrk: Option<(u128, u32)>,

    /// The peer's Identity Resolving Key (IRK)
    peer_irk: Option<u128>,

    /// The peer's identity address
    peer_identity: Option<IdentityAddress>,
}

impl Keys {
    /// Construct a new `Keys` with no keys
    pub fn new() -> Self {
        Keys::default()
    }

    /// Check if these keys were generated with an authenticated device
    pub fn is_authenticated(&self) -> bool {
        self.is_authenticated
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

    /// Get the peer's identity address
    ///
    /// Returns a bluetooth device address along with a flag to indicate if the address is a public.
    /// If the flag is false then the address is a static random address.
    pub fn get_peer_identity(&self) -> Option<IdentityAddress> {
        self.peer_identity.clone()
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

    /// Get the identity address of this device
    pub fn get_identity(&self) -> Option<IdentityAddress> {
        self.identity
    }
}

impl PartialEq for Keys {
    fn eq(&self, other: &Self) -> bool {
        self.peer_identity.eq(&other.peer_identity)
    }
}

impl Eq for Keys {}

impl PartialOrd for Keys {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.get_peer_identity().partial_cmp(&other.get_peer_identity())
    }
}

impl Ord for Keys {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.peer_identity.cmp(&other.peer_identity)
    }
}

impl core::hash::Hash for Keys {
    fn hash<H>(&self, state: &mut H)
    where
        H: core::hash::Hasher,
    {
        self.peer_identity.hash(state)
    }
}

/// A Very Simple Bonding Keys "database"
///
/// This is a simple `database` for storing bonding information of previously bonded devices. It is
/// just a vector of [`Keys`]s sorted by peer identity addresses.
///
/// This 'database' is nothing more than an over-glorified sorted vector of `Keys`.
///
/// # Note
/// Since the peer identity address is optionally contained within a [`Keys`], one entry within
/// the 'database' is allowed to not contain a peer identity address.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KeyDB {
    entries: Vec<Keys>,
}

impl KeyDB {
    /// Create a new `KeyDB` from a vector of `Keys`
    pub fn new(mut entries: Vec<Keys>) -> Self {
        entries.sort();

        Self { entries }
    }

    /// Get the keys associated with the input peer identity address.
    ///
    /// If `identity` is `None` then the keys associated to no peer device are returned, if there
    /// are any.
    pub fn get<I, A>(&self, peer_identity: A) -> Option<&Keys>
    where
        I: core::borrow::Borrow<IdentityAddress>,
        A: Into<Option<I>>,
    {
        let identity = peer_identity.into();

        let borrowed = identity.as_ref().map(|identity| identity.borrow());

        self.entries
            .binary_search_by(|entry| entry.peer_identity.as_ref().cmp(&borrowed))
            .ok()
            .and_then(|idx| self.entries.get(idx))
    }

    /// Get a mutable reference to the keys associated with the input peer identity address.
    ///
    /// If `identity` is `None` then the keys associated to no peer device are returned, if there
    /// are any.
    pub fn get_mut<I, A>(&mut self, peer_identity: A) -> Option<&mut Keys>
    where
        I: core::borrow::Borrow<IdentityAddress>,
        A: Into<Option<I>>,
    {
        let identity = peer_identity.into();

        let borrowed = identity.as_ref().map(|identity| identity.borrow());

        self.entries
            .binary_search_by(|entry| entry.peer_identity.as_ref().cmp(&borrowed))
            .ok()
            .and_then(|idx| self.entries.get_mut(idx))
    }

    /// Add the keys with the provided Keys
    ///
    /// Keys are sorted by the peer identity. In order for `keys` to be added, the peer identity
    /// must be unique to all other keys within this `KeyDB`. If `keys` contains a peer identity
    /// address that is already within this `KeyDB` then false is returned. True is returned if the
    /// keys were successfully added. Use method [`get_mut`] to overwrite keys within a `KeyDb`.
    ///
    /// [`get_mut`]: KeyDB::get_mut
    pub fn add(&mut self, keys: Keys) -> bool {
        if let Err(idx) = self.entries.binary_search_by(|keys| keys.cmp(&keys)) {
            self.entries.insert(idx, keys);
            true
        } else {
            false
        }
    }

    /// Iterate through the keys of a `KeyDB`
    pub fn iter(&self) -> impl Iterator<Item = &Keys> {
        self.entries.iter()
    }

    /// Remove the keys associated to a peer
    pub fn remove<I, A>(&mut self, peer_identity: A) -> Option<Keys>
    where
        I: core::borrow::Borrow<IdentityAddress>,
        A: Into<Option<I>>,
    {
        let identity = peer_identity.into();

        let borrowed = identity.as_ref().map(|identity| identity.borrow());

        self.entries
            .binary_search_by(|entry| entry.peer_identity.as_ref().cmp(&borrowed))
            .ok()
            .map(|idx| self.entries.remove(idx))
    }
}

impl Default for KeyDB {
    /// Create an empty KeyDB
    fn default() -> Self {
        KeyDB::new(Vec::new())
    }
}

impl IntoIterator for KeyDB {
    type Item = Keys;
    type IntoIter = alloc::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a> IntoIterator for &'a KeyDB {
    type Item = &'a Keys;
    type IntoIter = core::slice::Iter<'a, Keys>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl<'a> IntoIterator for &'a mut KeyDB {
    type Item = &'a mut Keys;
    type IntoIter = core::slice::IterMut<'a, Keys>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter_mut()
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

/// Builder for Bonding keys distributed by a Security Manager
///
/// This is used to set what keys are distributed during the building process of a Security Manager.
#[derive(Clone, Copy)]
pub struct DistributedBondingKeysBuilder {
    id: bool,
    signing: bool,
    irk: Option<u128>,
    identity: Option<IdentityAddress>,
    csrk: Option<u128>,
}

impl DistributedBondingKeysBuilder {
    fn new() -> Self {
        DistributedBondingKeysBuilder {
            id: false,
            signing: false,
            irk: None,
            identity: None,
            csrk: None,
        }
    }

    /// Enable the distribution of the identity resolving bonding information
    ///
    /// When this is called, this device will distribute an Identity Resolving Key (IRK) and an
    /// Identity Address during the key distribution of bonding. The returned `EnabledIdKeyBuilder`
    /// can be used to set the IRK and Identity Address, or use default values for these identity
    /// information. The default IRK is a randomly generated key, and the default Identity Address
    /// is the address of this device used to build the Security Manager.
    pub fn enable_id(mut self) -> EnabledIdKeysBuilder {
        self.id = true;
        EnabledIdKeysBuilder(self)
    }

    /// Enable the distribution of the connection signature resolving key
    ///
    /// When this is called, this device will distribute a Connection Signature Resolving Key (CSRK)
    /// during the key distribution of bonding. The returned
    pub fn enable_sign(mut self) -> EnabledSigningKeyBuilder {
        self.signing = true;
        EnabledSigningKeyBuilder(self)
    }

    /// Check if any key is sent
    fn any(&self) -> bool {
        self.id || self.signing
    }

    /// Get the keys distributed by this Security Manager
    fn into_keys(self, default_identity: IdentityAddress) -> LocalDistributedKeys {
        let (irk, identity) = if self.id {
            let irk = self.irk.unwrap_or_else(|| toolbox::rand_u128());
            let identity = self.identity.unwrap_or(default_identity);

            (Some(irk), Some(identity))
        } else {
            (None, None)
        };

        let csrk = if self.signing {
            let csrk = self.csrk.unwrap_or_else(|| toolbox::rand_u128());

            Some(csrk)
        } else {
            None
        };

        LocalDistributedKeys { irk, identity, csrk }
    }
}

struct LocalDistributedKeys {
    irk: Option<u128>,
    identity: Option<IdentityAddress>,
    csrk: Option<u128>,
}

impl LocalDistributedKeys {
    fn get_sc_distribution(&self) -> &'static [pairing::KeyDistributions] {
        KeyDistributions::sc_distribution(self.irk.is_some() && self.identity.is_some(), self.csrk.is_some())
    }
}

/// Enabled Identity Keys Builder
///
/// This is returned by the method [`enable_id`] of `EnabledBondingKeysBuilder`.
///
/// [`enable_id`]: DistributedBondingKeysBuilder::enable_id
#[repr(transparent)]
pub struct EnabledIdKeysBuilder(DistributedBondingKeysBuilder);

impl EnabledIdKeysBuilder {
    /// Set the Identity Resolving Key (IRK)
    ///
    /// This will set the IRK that will be sent to the other device during bonding.
    ///
    /// If this method is not called then a randomly generated IRK will be sent to the peer device.
    pub fn set_irk(mut self, irk: u128) -> Self {
        self.0.irk = Some(irk);
        self
    }

    /// Set the identity address
    ///
    /// This sets the address that will be sent as the identity address to the peer device during
    /// bonding.
    ///
    /// If this method is not called then the address of this devices used during pairing will be
    /// the identity address.
    pub fn set_identity(mut self, identity: IdentityAddress) -> Self {
        self.0.identity = Some(identity);
        self
    }

    /// Finish configuring the Identity Keys
    #[must_use]
    pub fn done(self) -> DistributedBondingKeysBuilder {
        self.0
    }
}

impl From<EnabledIdKeysBuilder> for DistributedBondingKeysBuilder {
    fn from(builder: EnabledIdKeysBuilder) -> Self {
        builder.done()
    }
}

/// Enabled Signing Keys Builder
///
/// This is returned by the method [`enable_sign`] of `EnabledBondingKeysBuilder`.
///
/// [`enable_sign`]: DistributedBondingKeysBuilder::enable_sign
#[repr(transparent)]
pub struct EnabledSigningKeyBuilder(DistributedBondingKeysBuilder);

impl EnabledSigningKeyBuilder {
    /// Set the Connection Signature Resolving Key (CSRK)
    ///
    /// This will set the (CSRK) that will be sent to the other device during bonding.
    ///
    /// If this method is not called then a randomly generated CSRK will be sent to the peer device.
    pub fn set_csrk(mut self, csrk: u128) -> Self {
        self.0.csrk = Some(csrk);
        self
    }

    /// Finish configuring the Signing Key
    #[must_use]
    pub fn done(self) -> DistributedBondingKeysBuilder {
        self.0
    }
}

impl From<EnabledSigningKeyBuilder> for DistributedBondingKeysBuilder {
    fn from(builder: EnabledSigningKeyBuilder) -> Self {
        builder.done()
    }
}

/// Builder for Bonding Keys Accepted by a Security Manager
pub struct AcceptedBondingKeysBuilder {
    id: bool,
    signing: bool,
}

impl AcceptedBondingKeysBuilder {
    fn new() -> Self {
        let id = false;
        let signing = false;

        AcceptedBondingKeysBuilder { id, signing }
    }

    /// Allow the Security Manager to accept identity address information
    ///
    /// This enables this Security Manager to accept a Identity Resolving Key (IRK) followed by an
    /// Identity Address from the peer device's Security Manager.
    pub fn enable_id(mut self) -> Self {
        self.id = true;
        self
    }

    /// Allow the Security Manager to accept signing information
    ///
    /// This enables this Security Manager to accept a Connection Signature Resolving Key (CSRK)
    /// from the peer device's Security Manager.
    pub fn enable_signing(mut self) -> Self {
        self.signing = true;
        self
    }

    /// Check if any key is accepted
    pub fn any(&self) -> bool {
        self.id || self.signing
    }
}

/// Error for a Security Manager Builder
#[derive(Copy, Clone, PartialEq)]
pub struct SecurityManagerBuilderError;

impl core::fmt::Debug for SecurityManagerBuilderError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("The Security Manager is configured with no pairing method")
    }
}

impl core::fmt::Display for SecurityManagerBuilderError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)?;
        f.write_str(", if this is the intended operation then do not use a Security Manager")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SecurityManagerBuilderError {}

/// Ability of the device for passkey entry
#[derive(Copy, Clone)]
enum PasskeyAbility {
    None,
    DisplayWithInput,
    InputOnly,
    DisplayOnly,
}

impl PasskeyAbility {
    fn is_enabled(&self) -> bool {
        if let PasskeyAbility::None = self {
            false
        } else {
            true
        }
    }
}

/// Direction of Out Of Band Data
///
/// OOB data can be sent from either both Security Managers or just one of them. This is used to
/// indicate the direction of which out of band data is sent between the two Security Managers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OobDirection {
    OnlyResponderSendsOob,
    OnlyInitiatorSendsOob,
    BothSendOob,
}
