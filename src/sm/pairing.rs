//! Pairing methods as specified in the Bluetooth Specification (v5.0 | vol 3, part H, section 3.5)

use super::*;
use super::encrypt_info::AuthRequirements;

/// The IO Capabilities of a device as it relates to the pairing method
#[derive(Debug,Clone,Copy)]
pub enum IOCapability {
    /// The device only contains a display
    DisplayOnly,
    /// The device contains a display with a method for the user to enter yes or no
    DisplayWithYesOrNo,
    /// The device only contains a keyboard
    KeyboardOnly,
    /// The device has no input or output for the user
    NoInputNoOutput,
    /// The device contains a keyboard and a display
    KeyboardDisplay,
}

impl IOCapability {
    pub(super) fn into_val(self) -> u8 {
        match self {
            IOCapability::DisplayOnly => 0x0,
            IOCapability::DisplayWithYesOrNo => 0x1,
            IOCapability::KeyboardOnly => 0x2,
            IOCapability::NoInputNoOutput => 0x3,
            IOCapability::KeyboardDisplay => 0x4,
        }
    }

    fn try_from_val(val: u8) -> Result<Self, Error> {
        match val {
            0x0 => Ok( IOCapability::DisplayOnly ),
            0x1 => Ok( IOCapability::DisplayWithYesOrNo ),
            0x2 => Ok( IOCapability::KeyboardOnly ),
            0x3 => Ok( IOCapability::NoInputNoOutput ),
            0x4 => Ok( IOCapability::KeyboardDisplay ),
            _   => Err( Error::IncorrectValue )
        }
    }
}

#[derive(Debug,Clone,Copy)]
pub enum OOBDataFlag {
    AuthenticationDataNotPresent,
    AuthenticationDataFromRemoteDevicePresent,
}

impl OOBDataFlag {
    pub(super) fn into_val(self) -> u8 {
        match self {
            OOBDataFlag::AuthenticationDataNotPresent => 0x0,
            OOBDataFlag::AuthenticationDataFromRemoteDevicePresent => 0x1,
        }
    }

    fn try_from_val(val: u8) -> Result<Self, Error> {
        match val {
            0x0 => Ok( OOBDataFlag::AuthenticationDataNotPresent ),
            0x1 => Ok( OOBDataFlag::AuthenticationDataFromRemoteDevicePresent ),
            _   => Err( Error::IncorrectValue )
        }
    }
}

/// Type of Key Distributions
///
/// See the security manager key distribution and generation section of the Bluetooth
/// Specification (v5.0 | vol 3, Part H, section 3.6.1)
#[derive(Debug,Clone,Copy)]
pub enum KeyDistributions {
    EncKey,
    IdKey,
    SignKey,
    // LinkKey, // LinkKey is unsupported because BR/EDR is unsupported
}

impl KeyDistributions {

    fn make_key_dist_val( keys: &[KeyDistributions] ) -> u8 {
        keys.iter().fold(0u8, |val, k| {
            match k {
                KeyDistributions::EncKey => val | (1 << 0),
                KeyDistributions::IdKey => val | (1 << 1),
                KeyDistributions::SignKey => val | (1 << 2),
            }
        })
    }

    fn vec_from_val(val: u8) -> Vec<Self> {
        let mut v = Vec::new();

        if 1 == val & (0x1 << 0) { v.push(KeyDistributions::EncKey) }

        if 1 == val & (0x1 << 1) { v.push(KeyDistributions::IdKey) }

        if 1 == val & (0x1 << 2) { v.push(KeyDistributions::SignKey) }

        v
    }
}

const MAX_ENCRYPTION_SIZE_RANGE: core::ops::RangeInclusive<usize> = 7..=16;

pub struct PairingRequest {
    io_capability: IOCapability,
    oob_data_flag: OOBDataFlag,
    auth_req: Vec<AuthRequirements>,
    max_encryption_size: usize,
    initiator_key_distribution: Vec<KeyDistributions>,
    responder_key_distribution: Vec<KeyDistributions>,
}

impl CommandData for PairingRequest {

    fn into_icd(self) -> Vec<u8> {
        alloc::vec![
                self.io_capability.into_val(),
                self.oob_data_flag.into_val(),
                AuthRequirements::make_auth_req_val( &self.auth_req ),
                self.max_encryption_size as u8,
                KeyDistributions::make_key_dist_val( &self.initiator_key_distribution ),
                KeyDistributions::make_key_dist_val( &self.responder_key_distribution )
            ]
    }

    fn try_from_icd(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 6 {
            Ok( Self {
                io_capability: IOCapability::try_from_val(icd[0])?,
                oob_data_flag: OOBDataFlag::try_from_val(icd[1])?,
                auth_req: AuthRequirements::vec_from_val(icd[2]),
                max_encryption_size: if MAX_ENCRYPTION_SIZE_RANGE.contains(&(icd[3] as usize)) {
                    icd[3] as usize
                } else {
                    return Err(Error::IncorrectValue)
                },
                initiator_key_distribution: KeyDistributions::vec_from_val(icd[4]),
                responder_key_distribution: KeyDistributions::vec_from_val(icd[5]),
            })
        } else {
            log::error!("(SM) Failed to generate 'pairing request' from raw data");
            log::trace!("Failed raw data: '{:x?}'", icd);
            Err( Error::Size )
        }
    }
}

impl PairingRequest {

    pub fn get_io_capability(&self) -> IOCapability { self.io_capability }

    pub fn get_oob_data_flag(&self) -> OOBDataFlag { self.oob_data_flag }

    pub fn get_auth_req(&self) -> &[AuthRequirements] { &self.auth_req }

    pub fn get_max_encryption_size(&self) -> usize { self.max_encryption_size }

    pub fn get_initiator_key_distribution(&self) -> &[KeyDistributions] { &self.initiator_key_distribution }

    pub fn get_responder_key_distribution(&self) -> &[KeyDistributions] { &self.responder_key_distribution }

    /// Set the input and output capabilities of the device
    pub fn set_io_capability(&mut self, io_cap: IOCapability ) {
        self.io_capability = io_cap;
    }

    /// Set authentication data
    pub fn set_auth_requirements(&mut self, reqs: Vec<AuthRequirements> ) {
        self.auth_req = reqs
    }

    /// Set the maximum encryption key size
    ///
    /// The encryption key size can be between 7 and 16 octets.
    ///
    /// This function will panic if the key size is not within that range.
    pub fn maximum_encryption_key_size(&mut self, size: usize) {
        if MAX_ENCRYPTION_SIZE_RANGE.contains(&size) {
            self.max_encryption_size = size;
        } else {
            panic!("Encryption key size of '{}' is not within the acceptable range (7..=16)", size);
        }
    }

    /// Set the key distribution / generation for the initiator
    ///
    /// This function takes a list of the types of key distribution / generation types available
    pub fn set_initiator_key_dis_gen(&mut self, dist_gen_types: Vec<KeyDistributions> ) {
        self.initiator_key_distribution = dist_gen_types
    }

    /// Set the key distribution / generation that the initiator is requesting the the Responder
    /// to distribute
    ///
    /// This function takes a list of the types of key distribution / generation types if wants
    /// the responder to distribute.
    pub fn set_responder_key_dis_gen(&mut self, dist_gen_types: Vec<KeyDistributions> ) {
        self.responder_key_distribution = dist_gen_types
    }
}

impl From<PairingRequest> for Command<PairingRequest> {
    fn from(pr: PairingRequest) -> Self {
        Command::new(CommandType::PairingRequest, pr)
    }
}

pub struct PairingResponse {
    io_capability: IOCapability,
    oob_data_flag: OOBDataFlag,
    auth_req: Vec<AuthRequirements>,
    max_encryption_size: usize,
    initiator_key_distribution: Vec<KeyDistributions>,
    responder_key_distribution: Vec<KeyDistributions>,
}

impl CommandData for PairingResponse {

    fn into_icd(self) -> Vec<u8> {
        alloc::vec![
                self.io_capability.into_val(),
                self.oob_data_flag.into_val(),
                AuthRequirements::make_auth_req_val( &self.auth_req ),
                self.max_encryption_size as u8,
                KeyDistributions::make_key_dist_val( &self.initiator_key_distribution ),
                KeyDistributions::make_key_dist_val( &self.responder_key_distribution )
            ]
    }

    fn try_from_icd(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 6 {
            Ok( Self {
                io_capability: IOCapability::try_from_val(icd[0])?,
                oob_data_flag: OOBDataFlag::try_from_val(icd[1])?,
                auth_req: AuthRequirements::vec_from_val(icd[2]),
                max_encryption_size: if MAX_ENCRYPTION_SIZE_RANGE.contains(&(icd[3] as usize)) {
                    icd[3] as usize
                } else {
                    return Err(Error::IncorrectValue)
                },
                initiator_key_distribution: KeyDistributions::vec_from_val(icd[4]),
                responder_key_distribution: KeyDistributions::vec_from_val(icd[5]),
            })
        } else {
            log::error!("(SM) Failed to generate 'pairing response' from raw data");
            log::trace!("Failed raw data: '{:x?}", icd);
            Err( Error::Size )
        }
    }
}

impl PairingResponse {

    pub fn new(
        io_capability: IOCapability,
        oob_data_flag: OOBDataFlag,
        auth_req: Vec<AuthRequirements>,
        max_encryption_size: usize,
        initiator_key_distribution: Vec<KeyDistributions>,
        responder_key_distribution: Vec<KeyDistributions>
    ) -> Self {
        Self {
            io_capability,
            oob_data_flag,
            auth_req,
            max_encryption_size,
            initiator_key_distribution,
            responder_key_distribution,
        }
    }

    pub fn get_io_capability(&self) -> IOCapability { self.io_capability }

    pub fn get_oob_data_flag(&self) -> OOBDataFlag { self.oob_data_flag }

    pub fn get_auth_req(&self) -> &[AuthRequirements] { &self.auth_req }

    pub fn get_max_encryption_size(&self) -> usize { self.max_encryption_size }

    pub fn get_initiator_key_distribution(&self) -> &[KeyDistributions] { &self.initiator_key_distribution }

    pub fn get_responder_key_distribution(&self) -> &[KeyDistributions] { &self.responder_key_distribution }

    /// Set the input and output capabilities of the device
    pub fn set_io_capability(&mut self, io_cap: IOCapability ) {
        self.io_capability = io_cap;
    }

    /// Set authentication data
    pub fn set_auth_requirements(&mut self, reqs: Vec<AuthRequirements> ) {
        self.auth_req = reqs
    }

    /// Set the maximum encryption key size
    ///
    /// The encryption key size can be between 7 and 16 octets.
    ///
    /// This function will panic if the key size is not within that range.
    pub fn maximum_encryption_key_size(&mut self, size: usize) {
        if MAX_ENCRYPTION_SIZE_RANGE.contains(&size) {
            self.max_encryption_size = size;
        } else {
            panic!("Encryption key size of '{}' is not within the acceptable range (7..=16)", size);
        }
    }

    /// Set the key distribution / generation for the initiator
    ///
    /// This function takes a list of the types of key distribution / generation types available
    pub fn set_initiator_key_dis_gen(&mut self, dist_gen_types: Vec<KeyDistributions> ) {
        self.initiator_key_distribution = dist_gen_types
    }

    /// Set the key distribution / generation that the initiator is requesting the the Responder
    /// to distribute
    ///
    /// This function takes a list of the types of key distribution / generation types if wants
    /// the responder to distribute.
    pub fn set_responder_key_dis_gen(&mut self, dist_gen_types: Vec<KeyDistributions> ) {
        self.responder_key_distribution = dist_gen_types
    }
}

impl From<PairingResponse> for Command<PairingResponse> {
    fn from(pr: PairingResponse) -> Self {
        Command::new(CommandType::PairingResponse, pr)
    }
}

pub struct PairingConfirm {
    value: u128
}

impl CommandData for PairingConfirm {

    fn into_icd(self) -> Vec<u8> {
        self.value.to_le_bytes().to_vec()
    }

    fn try_from_icd(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 16 {
            let mut v = [0u8;16];

            v.copy_from_slice(icd);

            Ok( PairingConfirm {
                value: <u128>::from_le_bytes(v)
            })
        } else {
            log::error!("(SM) Failed to generate 'pairing confirm' from raw data");
            log::trace!("(SM) Failed raw data: {:x?}", icd);
            Err( Error::Size )
        }
    }
}

impl PairingConfirm {
    pub fn new(confirm_value: u128) -> Self { PairingConfirm { value: confirm_value } }

    pub fn set_value(&mut self, val: u128) {
        self.value = val
    }

    pub fn get_value(&self) -> u128 {self.value}
}

impl From<PairingConfirm> for Command<PairingConfirm> {
    fn from(pc: PairingConfirm) -> Self {
        Command::new(CommandType::PairingConfirm, pc)
    }
}

pub struct PairingRandom {
    value: u128
}

impl CommandData for PairingRandom {

    fn into_icd(self) -> Vec<u8> {
        self.value.to_le_bytes().to_vec()
    }

    fn try_from_icd(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 16 {
            let mut v = [0u8;16];

            v.copy_from_slice(icd);

            Ok( PairingRandom {
                value: <u128>::from_le_bytes(v)
            })
        } else {
            log::error!("(SM) Failed to generate 'pairing random' from raw data");
            log::trace!("(SM) Failed raw data: {:x?}", icd);
            Err( Error::Size )
        }
    }
}

impl PairingRandom {
    pub fn new(rand: u128) -> Self { PairingRandom { value: rand } }

    pub fn get_value(&self) -> u128 { self.value }

    pub fn set_value(&mut self, val: u128) {
        self.value = val
    }
}

impl From<PairingRandom> for Command<PairingRandom> {
    fn from(pc: PairingRandom) -> Self {
        Command::new(CommandType::PairingRandom, pc)
    }
}

#[derive(Debug,Clone,Copy)]
pub enum PairingFailedReason {
    PasskeyEntryFailed,
    OOBNotAvailable,
    AuthenticationRequirements,
    ConfirmValueFailed,
    PairingNotSupported,
    EncryptionKeySize,
    CommandNotSupported,
    UnspecifiedReason,
    RepeatedAttempts,
    InvalidParameters,
    DHKeyCheckFailed,
    NumericComparisonFailed,
    BrEdrPairingInProgress,
    CrossTransportKeyDerivationGenerationNotAllowed,
}

impl PairingFailedReason {
    fn into_val(self) -> u8 {
        match self {
            PairingFailedReason::PasskeyEntryFailed => 0x1,
            PairingFailedReason::OOBNotAvailable => 0x2,
            PairingFailedReason::AuthenticationRequirements => 0x3,
            PairingFailedReason::ConfirmValueFailed => 0x4,
            PairingFailedReason::PairingNotSupported => 0x5,
            PairingFailedReason::EncryptionKeySize => 0x6,
            PairingFailedReason::CommandNotSupported => 0x7,
            PairingFailedReason::UnspecifiedReason => 0x8,
            PairingFailedReason::RepeatedAttempts => 0x9,
            PairingFailedReason::InvalidParameters => 0xa,
            PairingFailedReason::DHKeyCheckFailed => 0xb,
            PairingFailedReason::NumericComparisonFailed => 0xc,
            PairingFailedReason::BrEdrPairingInProgress => 0xd,
            PairingFailedReason::CrossTransportKeyDerivationGenerationNotAllowed => 0xe,
        }
    }

    fn try_from_val(val: u8) -> Result<Self, Error> {
        match val {
            0x1 => Ok( PairingFailedReason::PasskeyEntryFailed ),
            0x2 => Ok( PairingFailedReason::OOBNotAvailable ),
            0x3 => Ok( PairingFailedReason::AuthenticationRequirements ),
            0x4 => Ok( PairingFailedReason::ConfirmValueFailed ),
            0x5 => Ok( PairingFailedReason::PairingNotSupported ),
            0x6 => Ok( PairingFailedReason::EncryptionKeySize ),
            0x7 => Ok( PairingFailedReason::CommandNotSupported ),
            0x8 => Ok( PairingFailedReason::UnspecifiedReason ),
            0x9 => Ok( PairingFailedReason::RepeatedAttempts ),
            0xa => Ok( PairingFailedReason::InvalidParameters ),
            0xb => Ok( PairingFailedReason::DHKeyCheckFailed ),
            0xc => Ok( PairingFailedReason::NumericComparisonFailed ),
            0xd => Ok( PairingFailedReason::BrEdrPairingInProgress ),
            0xe => Ok( PairingFailedReason::CrossTransportKeyDerivationGenerationNotAllowed ),
            _   => Err( Error::IncorrectValue )
        }
    }
}


pub struct PairingFailed {
    reason: PairingFailedReason
}

impl CommandData for PairingFailed {
    fn into_icd(self) -> Vec<u8> {
        alloc::vec![self.reason.into_val()]
    }

    fn try_from_icd(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 1 {
            Ok( PairingFailed {
                reason: PairingFailedReason::try_from_val(icd[0])?
            })
        } else {
            log::error!("(SM) Failed to generate 'pairing failed' from raw data");
            log::trace!("(SM) Failed raw data: {:x?}", icd);
            Err( Error::Size )
        }
    }
}

impl PairingFailed {
    pub fn new(reason: PairingFailedReason) -> Self { Self {reason} }

    pub fn get_reason(&self) -> PairingFailedReason { self.reason }

    pub fn set_reason(&mut self, reason: PairingFailedReason) {
        self.reason = reason
    }
}

impl From<PairingFailed> for Command<PairingFailed> {
    fn from(pf: PairingFailed) -> Self {
        Command::new(CommandType::PairingFailed, pf)
    }
}

pub struct PairingPubKey {
    x_y: [u8;64],
}

impl CommandData for PairingPubKey {

    fn into_icd(self) -> Vec<u8> {
        self.x_y.to_vec()
    }

    fn try_from_icd(icd: &[u8]) -> Result<Self, Error> {

        if icd.len() == 64 {
            let mut x_y = [0u8;64];

            x_y.copy_from_slice(icd);

            Ok( PairingPubKey { x_y })

        } else {
            log::error!("(SM) Failed to generate 'pairing public key' from raw data");
            log::trace!("(SM) Failed raw data: {:x?}", icd);
            Err( Error::Size )
        }
    }
}

impl PairingPubKey {

    pub fn new(key: [u8;64]) -> Self {
        Self { x_y: key }
    }

    /// Return the public key
    pub fn get_key(&self) -> [u8;64] { self.x_y.clone() }
}

impl From<PairingPubKey> for Command<PairingPubKey> {
    fn from(ppk: PairingPubKey) -> Self {
        Command::new(CommandType::PairingPublicKey, ppk)
    }
}

pub struct PairingDHKeyCheck {
    check: u128
}

impl CommandData for PairingDHKeyCheck {

    fn into_icd(self) -> Vec<u8> {
        self.check.to_le_bytes().to_vec()
    }

    fn try_from_icd(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 16 {
            let mut arr = [0u8; 16];

            arr.copy_from_slice(icd);

            Ok( PairingDHKeyCheck { check: <u128>::from_le_bytes(arr) } )
        } else {
            log::error!("(SM) Failed to generate 'pairing Diffie-Hellman Key check' from raw data");
            log::trace!("(SM) Failed raw data: {:x?}", icd);
            Err( Error::Size )
        }
    }
}

impl PairingDHKeyCheck {
    pub fn new(check: u128) -> Self { PairingDHKeyCheck { check } }

    pub fn get_key_check(&self) -> u128 { self.check }

    pub fn set_key_check(&mut self, check: u128) {
        self.check = check
    }
}

impl From<PairingDHKeyCheck> for Command<PairingDHKeyCheck> {
    fn from(pkc: PairingDHKeyCheck) -> Self {
        Command::new(CommandType::PairingDHKeyCheck, pkc)
    }
}

pub enum KeyPressNotification {
    PasskeyEntryStarted,
    PasskeyDigitEntered,
    PasskeyDigitErased,
    PasskeyCleared,
    PasskeyEntryCompleted,
}

impl CommandData for KeyPressNotification {

    fn into_icd(self) -> Vec<u8> {
        alloc::vec![ self.into_val() ]
    }

    fn try_from_icd(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 1 {
            Ok( Self::try_from_val(icd[0])? )
        } else {
            log::error!("(SM) Failed to generate 'Key Press Notification' from raw data");
            log::trace!("(SM) Failed raw data: {:x?}", icd);
            Err( Error::Size )
        }
    }
}

impl KeyPressNotification {

    fn into_val(self) -> u8 {
        match self {
            KeyPressNotification::PasskeyEntryStarted => 0x0,
            KeyPressNotification::PasskeyDigitEntered => 0x1,
            KeyPressNotification::PasskeyDigitErased => 0x2,
            KeyPressNotification::PasskeyCleared => 0x3,
            KeyPressNotification::PasskeyEntryCompleted => 0x4,
        }
    }

    fn try_from_val(val: u8) -> Result<Self, Error> {
        match val {
            0x0 => Ok( KeyPressNotification::PasskeyEntryStarted ),
            0x1 => Ok( KeyPressNotification::PasskeyDigitEntered ),
            0x2 => Ok( KeyPressNotification::PasskeyDigitErased ),
            0x3 => Ok( KeyPressNotification::PasskeyCleared ),
            0x4 => Ok( KeyPressNotification::PasskeyEntryCompleted ),
            _   => Err( Error::IncorrectValue )
        }
    }
}

impl From<KeyPressNotification> for Command<KeyPressNotification> {
    fn from(kpn: KeyPressNotification) -> Self {
        Command::new(CommandType::PairingKeyPressNotification, kpn)
    }
}
