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
//! # let this_address = bo_tie_util::BluetoothDeviceAddress::zeroed();
//! # let peer_address = bo_tie_util::BluetoothDeviceAddress::zeroed();
//! # struct StubConnectionChannel;
//! # impl ConnectionChannel for StubConnectionChannel {
//! #     type SendBuffer = Vec<u8>;
//! #     type SendFut<'a> = std::pin::Pin<Box<dyn Future<Output=Result<(), bo_tie_l2cap::send_future::Error<Self::SendFutErr>>>>>;
//! #     type SendFutErr = usize;
//! #     type RecvBuffer = Vec<u8>;
//! #     type RecvFut<'a> = std::pin::Pin<Box<dyn Future<Output=Option<Result<L2capFragment<Self::RecvBuffer>, bo_tie_l2cap::BasicFrameError<<Self::RecvBuffer as bo_tie_util::buffer::TryExtend<u8>>::Error>>>>>>;
//! #     fn send(&self, data: BasicInfoFrame<Vec<u8>>) -> Self::SendFut<'_> { unimplemented!() }
//! #     fn set_mtu(&mut self,mtu: u16) { unimplemented!() }
//! #     fn get_mtu(&self) -> usize { unimplemented!() }
//! #     fn max_mtu(&self) -> usize { unimplemented!() }
//! #     fn min_mtu(&self) -> usize { unimplemented!() }
//! #     fn receive(&mut self) -> Self::RecvFut<'_> { unimplemented!() }
//! # }
//! # let connection_channel = StubConnectionChannel;
//! // An example of setting up a receiver that support oob
//!
//! use bo_tie_sm::responder::SecurityManagerBuilder;
//! use bo_tie_l2cap::{BasicInfoFrame, ConnectionChannel, L2capFragment};
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

extern crate alloc;
extern crate core;

use alloc::vec::Vec;

pub use bo_tie_l2cap as l2cap;
pub use bo_tie_util::BluetoothDeviceAddress;

use l2cap::BasicInfoFrame;
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
pub const L2CAP_CHANNEL_ID: l2cap::ChannelIdentifier =
    l2cap::ChannelIdentifier::Le(l2cap::LeUserChannelIdentifier::SecurityManagerProtocol);

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
    /// ACL Data related
    ACLData(l2cap::BasicFrameError<core::convert::Infallible>), // temporarily using infallible
    /// The operation requires this device to be paired with the connected device.
    OperationRequiresPairing,
    /// The input or operation is no longer valid to the scope of pairing
    Invalid,
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
            Error::ACLData(e) => write!(f, "invalid ACL basic frame: {}", e),
            Error::OperationRequiresPairing => f.write_str("operation requires pairing"),
            Error::Invalid => f.write_str("the operation is no longer valid"),
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

impl core::convert::TryFrom<&'_ BasicInfoFrame<Vec<u8>>> for CommandType {
    type Error = Error;

    /// Try to get the CommandType from ACLData
    ///
    /// This rigidly checks the ACLData to get the CommandType. If the channel identifier is
    /// incorrect, the payload does not have a valid value for the command field, or the payload
    /// length is incorrect, an error is returned.
    fn try_from(acl_data: &'_ BasicInfoFrame<Vec<u8>>) -> Result<Self, Self::Error> {
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
/// A trait for converting to or from the format within a Security Manager Command PDU
trait CommandData
where
    Self: Sized,
{
    /// Convert into command data
    fn into_command_format(self) -> bo_tie_util::buffer::stack::LinearBuffer<65, u8>;

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
    fn into_command_format(self) -> bo_tie_util::buffer::stack::LinearBuffer<65, u8> {
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
        initiator_io_capability: pairing::IOCapability,
        responder_io_capability: pairing::IOCapability,
        is_legacy: bool,
    ) -> Self {
        use pairing::{
            IOCapability::*, OobDataFlag::AuthenticationDataFromRemoteDevicePresent as Present,
            OobDataFlag::AuthenticationDataNotPresent as Unavailable,
        };

        match (
            initiator_oob_data,
            responder_oob_data,
            responder_io_capability,
            initiator_io_capability,
            is_legacy,
        ) {
            (Present, Present, _, _, _) => PairingMethod::Oob(OobDirection::BothSendOob),
            (Present, Unavailable, _, _, _) => PairingMethod::Oob(OobDirection::OnlyResponderSendsOob),
            (Unavailable, Present, _, _, _) => PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob),
            (_, _, DisplayOnly, DisplayOnly, _) => PairingMethod::JustWorks,
            (_, _, DisplayOnly, DisplayWithYesOrNo, _) => PairingMethod::JustWorks,
            (_, _, DisplayOnly, KeyboardOnly, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::ResponderDisplaysInitiatorInputs)
            }
            (_, _, DisplayOnly, NoInputNoOutput, _) => PairingMethod::JustWorks,
            (_, _, DisplayOnly, KeyboardDisplay, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::ResponderDisplaysInitiatorInputs)
            }
            (_, _, DisplayWithYesOrNo, DisplayOnly, _) => PairingMethod::JustWorks,
            (_, _, DisplayWithYesOrNo, DisplayWithYesOrNo, false) => PairingMethod::NumbComp,
            (_, _, DisplayWithYesOrNo, DisplayWithYesOrNo, true) => PairingMethod::JustWorks,
            (_, _, DisplayWithYesOrNo, KeyboardOnly, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::ResponderDisplaysInitiatorInputs)
            }
            (_, _, DisplayWithYesOrNo, NoInputNoOutput, _) => PairingMethod::JustWorks,
            (_, _, DisplayWithYesOrNo, KeyboardDisplay, false) => PairingMethod::NumbComp,
            (_, _, DisplayWithYesOrNo, KeyboardDisplay, true) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::ResponderDisplaysInitiatorInputs)
            }
            (_, _, KeyboardOnly, DisplayOnly, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::InitiatorDisplaysResponderInputs)
            }
            (_, _, KeyboardOnly, DisplayWithYesOrNo, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::InitiatorDisplaysResponderInputs)
            }
            (_, _, KeyboardOnly, KeyboardOnly, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::InitiatorAndResponderInput)
            }
            (_, _, KeyboardOnly, NoInputNoOutput, _) => PairingMethod::JustWorks,
            (_, _, KeyboardOnly, KeyboardDisplay, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::InitiatorDisplaysResponderInputs)
            }
            (_, _, NoInputNoOutput, _, _) => PairingMethod::JustWorks,
            (_, _, KeyboardDisplay, DisplayOnly, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::InitiatorDisplaysResponderInputs)
            }
            (_, _, KeyboardDisplay, DisplayWithYesOrNo, false) => PairingMethod::NumbComp,
            (_, _, KeyboardDisplay, DisplayWithYesOrNo, true) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::InitiatorDisplaysResponderInputs)
            }
            (_, _, KeyboardDisplay, KeyboardOnly, _) => {
                PairingMethod::PassKeyEntry(PasskeyDirection::ResponderDisplaysInitiatorInputs)
            }
            (_, _, KeyboardDisplay, NoInputNoOutput, _) => PairingMethod::NumbComp,
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

    /// Compare entries by the peer keys irk and addr
    fn cmp_entry_by_keys<'a, I, A>(&self, peer_irk: I, peer_addr: A) -> core::cmp::Ordering
    where
        I: Into<Option<&'a u128>> + 'a,
        A: Into<Option<&'a IdentityAddress>> + 'a,
    {
        use core::cmp::Ordering;

        match (
            self.peer_irk.as_ref(),
            peer_irk.into(),
            self.peer_identity.as_ref(),
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

    /// Compare two Keys
    ///
    /// This can be used for sorting entries by the peer IRK and peer addresses. This is *not* the
    /// same as the
    /// [partial_cmp](https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html#tymethod.partial_cmp)
    /// implementation for `PartialOrd` as that implementation uses all keys in a `Keys` to
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
    pub fn compare_keys(&self, other: &Self) -> core::cmp::Ordering {
        self.cmp_entry_by_keys(other.peer_irk.as_ref(), other.peer_identity.as_ref())
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
        self.compare_keys(&other).into()
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

/// The Bonding Keys "database"
///
/// This is a simple `database` for storing bonding information of previously bonded devices. It is
/// just a vector of `Keys`s sorted by the identity address. `Keys`s without an identity
/// address are also resolvable but only if they contain an identity resolving key (IRK).
///
/// # Panics
/// Trying to add `Keys`s without an identity address or identity resolving key will incur a
/// panic.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
struct KeyDB {
    entries: Vec<Keys>,
}

impl KeyDB {
    /// Create a new `KeyDB` from a vector of `Keys`
    fn new(mut entries: Vec<Keys>) -> Self {
        entries.sort_by(|rhs, lhs| rhs.compare_keys(lhs));

        Self { entries }
    }

    /// Get the keys associated with the provided `irk` and/or `address`.
    ///
    /// Return the keys associated with the specified `irk` and/or `address`. `None` is
    /// returned if there is no entry associated with the given keys.
    fn get<'s, 'a, I, A>(&'s self, irk: I, address: A) -> Option<&'s Keys>
    where
        I: Into<Option<&'a u128>>,
        A: Into<Option<&'a IdentityAddress>>,
    {
        let i = irk.into();
        let a = address.into();
        let entries = &self.entries;

        self.entries
            .binary_search_by(|entry| entry.cmp_entry_by_keys(i, a))
            .ok()
            .map_or(None, |idx| entries.get(idx))
    }

    /// Add the keys with the provided Keys
    ///
    /// This will override keys that have the same identity address and IRK.
    fn add(&mut self, entry: Keys) {
        match self.entries.binary_search_by(|in_entry| in_entry.compare_keys(&entry)) {
            Ok(idx) => self.entries[idx] = entry,
            Err(idx) => self.entries.insert(idx, entry),
        }
    }

    fn iter(&self) -> impl core::iter::Iterator<Item = &Keys> {
        self.entries.iter()
    }

    fn remove<'a, I, A>(&'a mut self, irk: I, address: A) -> bool
    where
        I: Into<Option<&'a u128>>,
        A: Into<Option<&'a IdentityAddress>>,
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
/// This 'database' is nothing more than a glorified list of `Keys`
/// sorted using the
/// [compare_entry](crate::sm::Keys::compare_keys)
/// method.
#[derive(Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityManagerKeys {
    keys_db: KeyDB,
}

impl SecurityManagerKeys {
    pub fn new(keys: Vec<Keys>) -> Self {
        SecurityManagerKeys {
            keys_db: KeyDB::new(keys),
        }
    }

    /// Get an iterator over the keys
    pub fn iter(&self) -> impl Iterator<Item = &Keys> {
        self.keys_db.iter()
    }

    /// Returns an iterator to resolve a resolvable private address from all peer devices'
    /// Identity Resolving Key (IRK) in the keys database.
    ///
    /// The return is an iterator that will try to resolve `addr` with a known peer IRK on each
    /// iteration. If the address is resolved by a peer's IRK, the `Keys` that contains the
    /// matching IRK is returned. The easiest way to use this function is to just combine it with
    /// the [`find_map`](https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.find_map)
    /// iterator method.
    /// ```
    /// # let security_manager = bo_tie_sm::SecurityManagerKeys::default();
    /// # let resolvable_private_address = bo_tie_util::BluetoothDeviceAddress::zeroed();
    ///
    /// security_manager.resolve_rpa_itr(resolvable_private_address).find_map(|keys_opt| keys_opt);
    /// ```
    ///
    /// # Note
    /// If you know the identity address of the device to be connected, then this method is
    /// *probably* not needed. Most controllers can handle resolving a private address for a single
    /// connectible device. See the HCI methods within the module
    /// [`privacy`](crate::hci::le::privacy).
    pub fn resolve_rpa_itr(&self, addr: BluetoothDeviceAddress) -> impl Iterator<Item = Option<Keys>> + '_ {
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
    /// resolving key or a peer address. If there is a `Keys` in the database that contains
    /// the same peer IRK and peer address, that entry is overwritten.
    ///
    /// This function will return true if `keys` was added to the database.
    pub fn add_keys(&mut self, keys: Keys) -> bool {
        match keys {
            Keys { peer_irk: Some(_), .. }
            | Keys {
                peer_identity: Some(_), ..
            } => {
                self.keys_db.add(keys);
                true
            }
            _ => false,
        }
    }

    /// Remove keys in the database
    ///
    /// Removes the entry that matches `keys` in the database
    pub fn remove_keys(&mut self, keys: &Keys) -> bool {
        self.keys_db.remove(keys.peer_irk.as_ref(), keys.peer_identity.as_ref())
    }

    /// Get a specific `Keys` from its peer IRK and peer Address
    pub fn get_keys<I, A>(&self, peer_irk: I, peer_addr: A, peer_addr_is_pub: bool) -> Option<&Keys>
    where
        I: Into<Option<u128>>,
        A: Into<Option<crate::BluetoothDeviceAddress>>,
    {
        let peer_addr = peer_addr.into().map(|addr| {
            if peer_addr_is_pub {
                IdentityAddress::Public(addr)
            } else {
                IdentityAddress::StaticRandom(addr)
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

/// Bonding keys enabled by a Security Manager
pub struct EnabledBondingKeysBuilder {
    irk: bool,
    csrk: bool,
}

impl EnabledBondingKeysBuilder {
    fn new() -> Self {
        EnabledBondingKeysBuilder {
            irk: false,
            csrk: false,
        }
    }

    /// Enable the distribution of the identity resolving key
    pub fn enable_irk(&mut self) -> &mut Self {
        self.irk = true;
        self
    }

    /// Enable the distribution of the connection signature resolving key
    pub fn enable_csrk(&mut self) -> &mut Self {
        self.csrk = true;
        self
    }
}

fn get_keys(ltk: bool, csrk: bool) -> &'static [pairing::KeyDistributions] {
    match (ltk, csrk) {
        (true, true) => &[pairing::KeyDistributions::IdKey, pairing::KeyDistributions::SignKey],
        (true, false) => &[pairing::KeyDistributions::IdKey],
        (false, true) => &[pairing::KeyDistributions::SignKey],
        (false, false) => &[],
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
