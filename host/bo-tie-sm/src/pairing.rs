//! Pairing methods as specified in the Bluetooth Specification (v5.0 | vol 3, part H, section 3.5)

use super::encrypt_info::AuthRequirements;
use super::*;
use bo_tie_core::buffer::stack::LinearBuffer;

pub(crate) fn convert_io_cap(
    auth_req: &[encrypt_info::AuthRequirements],
    oob_flag: pairing::OobDataFlag,
    io_cap: pairing::IoCapability,
) -> [u8; 3] {
    [
        encrypt_info::AuthRequirements::make_auth_req_val(auth_req),
        oob_flag.into_val(),
        io_cap.into_val(),
    ]
}

/// The IO Capabilities of a device as it relates to the pairing method
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IoCapability {
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

impl IoCapability {
    pub(crate) fn into_val(self) -> u8 {
        match self {
            IoCapability::DisplayOnly => 0x0,
            IoCapability::DisplayWithYesOrNo => 0x1,
            IoCapability::KeyboardOnly => 0x2,
            IoCapability::NoInputNoOutput => 0x3,
            IoCapability::KeyboardDisplay => 0x4,
        }
    }

    fn try_from_val(val: u8) -> Result<Self, Error> {
        match val {
            0x0 => Ok(IoCapability::DisplayOnly),
            0x1 => Ok(IoCapability::DisplayWithYesOrNo),
            0x2 => Ok(IoCapability::KeyboardOnly),
            0x3 => Ok(IoCapability::NoInputNoOutput),
            0x4 => Ok(IoCapability::KeyboardDisplay),
            _ => Err(Error::Value),
        }
    }

    /// Check if this device has no input or output capability for pairing
    pub fn no_io_capability(self) -> bool {
        if let IoCapability::NoInputNoOutput = self {
            true
        } else {
            false
        }
    }
}

/// Flag if out of band data can be received
///
/// The names match the naming within the specification, but for this library
/// `AuthenticationDataNotPresent` means that authentication data cannot be received and
/// `AuthenticationDataFromRemoteDevicePresent` means that authentication data can be received. This
/// flag is used internally within the security manager.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OobDataFlag {
    AuthenticationDataNotPresent,
    AuthenticationDataFromRemoteDevicePresent,
}

impl OobDataFlag {
    pub(super) fn into_val(self) -> u8 {
        match self {
            OobDataFlag::AuthenticationDataNotPresent => 0x0,
            OobDataFlag::AuthenticationDataFromRemoteDevicePresent => 0x1,
        }
    }

    fn try_from_val(val: u8) -> Result<Self, Error> {
        match val {
            0x0 => Ok(OobDataFlag::AuthenticationDataNotPresent),
            0x1 => Ok(OobDataFlag::AuthenticationDataFromRemoteDevicePresent),
            _ => Err(Error::Value),
        }
    }
}

/// Type of Key Distributions
///
/// See the security manager key distribution and generation section of the Bluetooth
/// Specification (v5.0 | vol 3, Part H, section 3.6.1)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyDistributions {
    EncKey,
    IdKey,
    SignKey,
    LinkKey, // LinkKey is unsupported because BR/EDR is unsupported
}

impl KeyDistributions {
    fn make_key_dist_val(keys: &[KeyDistributions]) -> u8 {
        keys.iter().fold(0u8, |val, k| match k {
            KeyDistributions::EncKey => val | (1 << 0),
            KeyDistributions::IdKey => val | (1 << 1),
            KeyDistributions::SignKey => val | (1 << 2),
            KeyDistributions::LinkKey => val | (1 << 3),
        })
    }

    fn from_val(val: u8) -> &'static [Self] {
        match val & 0xf {
            0xf => &[Self::EncKey, Self::IdKey, Self::SignKey, Self::LinkKey],
            0xe => &[Self::IdKey, Self::SignKey, Self::LinkKey],
            0xd => &[Self::EncKey, Self::SignKey, Self::LinkKey],
            0xc => &[Self::SignKey, Self::LinkKey],
            0xb => &[Self::EncKey, Self::IdKey, Self::LinkKey],
            0xa => &[Self::IdKey, Self::LinkKey],
            0x9 => &[Self::EncKey, Self::LinkKey],
            0x8 => &[Self::LinkKey],
            0x7 => &[Self::EncKey, Self::IdKey, Self::SignKey],
            0x6 => &[Self::IdKey, Self::SignKey],
            0x5 => &[Self::EncKey, Self::SignKey],
            0x4 => &[Self::SignKey],
            0x3 => &[Self::EncKey, Self::IdKey],
            0x2 => &[Self::IdKey],
            0x1 => &[Self::EncKey],
            0x0 => &[],
            _ => unreachable!(),
        }
    }

    /// Intersect two `KeyDistributions` slices
    pub(crate) fn intersect(a: &[Self], b: &[Self]) -> &'static [Self] {
        use KeyDistributions::*;

        let ks: &[Self] = if a.contains(&EncKey) && b.contains(&EncKey) {
            if a.contains(&IdKey) && b.contains(&IdKey) {
                if a.contains(&SignKey) && b.contains(&SignKey) {
                    if a.contains(&LinkKey) && b.contains(&LinkKey) {
                        &[EncKey, IdKey, SignKey, LinkKey]
                    } else {
                        &[EncKey, IdKey, SignKey]
                    }
                } else if a.contains(&LinkKey) && b.contains(&LinkKey) {
                    &[EncKey, IdKey, LinkKey]
                } else {
                    &[EncKey, IdKey]
                }
            } else if a.contains(&SignKey) && b.contains(&SignKey) {
                if a.contains(&LinkKey) && b.contains(&LinkKey) {
                    &[EncKey, SignKey, LinkKey]
                } else {
                    &[EncKey, SignKey]
                }
            } else if a.contains(&LinkKey) && b.contains(&LinkKey) {
                &[EncKey, LinkKey]
            } else {
                &[EncKey]
            }
        } else if a.contains(&IdKey) && b.contains(&IdKey) {
            if a.contains(&SignKey) && b.contains(&SignKey) {
                if a.contains(&LinkKey) && b.contains(&LinkKey) {
                    &[IdKey, SignKey, LinkKey]
                } else {
                    &[IdKey, SignKey]
                }
            } else if a.contains(&LinkKey) && b.contains(&LinkKey) {
                &[IdKey, LinkKey]
            } else {
                &[IdKey]
            }
        } else if a.contains(&SignKey) && b.contains(&SignKey) {
            if a.contains(&LinkKey) && b.contains(&LinkKey) {
                &[SignKey, LinkKey]
            } else {
                &[SignKey]
            }
        } else if a.contains(&LinkKey) && b.contains(&LinkKey) {
            &[LinkKey]
        } else {
            &[]
        };

        ks
    }

    /// Convert booleans into a Key Distribution for Secure Connections Bonding.
    pub(crate) fn sc_distribution(id: bool, sign: bool) -> &'static [KeyDistributions] {
        match (id, sign) {
            (true, true) => &[KeyDistributions::IdKey, KeyDistributions::SignKey],
            (true, false) => &[KeyDistributions::IdKey],
            (false, true) => &[KeyDistributions::SignKey],
            (false, false) => &[],
        }
    }
}

const MAX_ENCRYPTION_SIZE_RANGE: core::ops::RangeInclusive<usize> = 7..=16;

#[derive(Clone)]
pub struct PairingRequest {
    io_capability: IoCapability,
    oob_data_flag: OobDataFlag,
    auth_req: LinearBuffer<{ AuthRequirements::full_depth() }, AuthRequirements>,
    max_encryption_size: usize,
    initiator_key_distribution: &'static [KeyDistributions],
    responder_key_distribution: &'static [KeyDistributions],
    io_cap_f6: [u8; 3],
}

impl CommandData for PairingRequest {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        let mut ret = LinearBuffer::new();

        ret.try_push(self.io_capability.into_val()).unwrap();

        ret.try_push(self.oob_data_flag.into_val()).unwrap();

        ret.try_push(AuthRequirements::make_auth_req_val(&self.auth_req))
            .unwrap();

        ret.try_push(self.max_encryption_size as u8).unwrap();

        ret.try_push(KeyDistributions::make_key_dist_val(&self.initiator_key_distribution))
            .unwrap();

        ret.try_push(KeyDistributions::make_key_dist_val(&self.responder_key_distribution))
            .unwrap();

        ret
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        log::trace!("(SM) received pairing request: {:x?}", icd);
        if icd.len() == 6 {
            Ok(Self {
                io_capability: IoCapability::try_from_val(icd[0])?,
                oob_data_flag: OobDataFlag::try_from_val(icd[1])?,
                auth_req: AuthRequirements::from_val(icd[2]),
                max_encryption_size: if MAX_ENCRYPTION_SIZE_RANGE.contains(&(icd[3] as usize)) {
                    icd[3] as usize
                } else {
                    return Err(Error::Value);
                },
                initiator_key_distribution: KeyDistributions::from_val(icd[4]),
                responder_key_distribution: KeyDistributions::from_val(icd[5]),
                io_cap_f6: [icd[2], icd[1], icd[0]],
            })
        } else {
            log::error!("(SM) failed to generate 'pairing request' from raw data");
            log::trace!("(SM) failed raw data: '{:x?}'", icd);
            Err(Error::Size)
        }
    }
}

impl PairingRequest {
    pub fn new(
        io_capability: IoCapability,
        oob_data_flag: OobDataFlag,
        auth_req: LinearBuffer<{ AuthRequirements::full_depth() }, AuthRequirements>,
        max_encryption_size: usize,
        initiator_key_distribution: &'static [KeyDistributions],
        responder_key_distribution: &'static [KeyDistributions],
    ) -> Self {
        Self {
            io_cap_f6: convert_io_cap(&auth_req, oob_data_flag, io_capability),
            io_capability,
            oob_data_flag,
            auth_req,
            max_encryption_size,
            initiator_key_distribution,
            responder_key_distribution,
        }
    }

    pub fn get_io_capability(&self) -> IoCapability {
        self.io_capability
    }

    pub fn get_oob_data_flag(&self) -> OobDataFlag {
        self.oob_data_flag
    }

    pub fn get_auth_req(&self) -> &[AuthRequirements] {
        &self.auth_req
    }

    pub fn get_max_encryption_size(&self) -> usize {
        self.max_encryption_size
    }

    pub fn get_initiator_key_distribution(&self) -> &'static [KeyDistributions] {
        &self.initiator_key_distribution
    }

    pub fn get_responder_key_distribution(&self) -> &'static [KeyDistributions] {
        &self.responder_key_distribution
    }

    /// Set the input and output capabilities of the device
    pub fn set_io_capability(&mut self, io_cap: IoCapability) {
        self.io_capability = io_cap;
    }

    /// Set authentication data
    ///
    /// Input `reqs` should be a slice of unique authorization requirements.
    pub fn set_authorization_requirements(&mut self, reqs: &[AuthRequirements]) {
        let mut auth_req = LinearBuffer::new();

        for a in reqs {
            if !auth_req.contains(a) {
                auth_req.try_push(*a).unwrap();
            }
        }

        self.auth_req = auth_req
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
            panic!(
                "Encryption key size of '{}' is not within the acceptable range (7..=16)",
                size
            );
        }
    }

    /// Set the key distribution / generation for the initiator
    ///
    /// This function takes a list of the types of key distribution / generation types available
    pub fn set_initiator_key_dis_gen(&mut self, dist_gen_types: &'static [KeyDistributions]) {
        self.initiator_key_distribution = dist_gen_types
    }

    /// Set the key distribution / generation that the initiator is requesting the the Responder
    /// to distribute
    ///
    /// This function takes a list of the types of key distribution / generation types if wants
    /// the responder to distribute.
    pub fn set_responder_key_dis_gen(&mut self, dist_gen_types: &'static [KeyDistributions]) {
        self.responder_key_distribution = dist_gen_types
    }

    /// Get the pres
    ///
    /// This returns the value for the `pres` input of the [`c1`] toolbox function.
    ///
    /// [`c1`]: toolbox::c1
    pub fn get_pres(&self) -> [u8; 7] {
        let mut ret = [0u8; 7];

        ret[0] = CommandType::PairingRequest.into_val();
        ret[1] = self.get_io_capability().into_val();
        ret[2] = self.get_oob_data_flag().into_val();
        ret[3] = AuthRequirements::make_auth_req_val(self.get_auth_req());
        ret[4] = self.get_max_encryption_size() as u8;
        ret[5] = KeyDistributions::make_key_dist_val(self.get_initiator_key_distribution());
        ret[6] = KeyDistributions::make_key_dist_val(self.get_responder_key_distribution());

        ret
    }

    /// Get the IOcap (not the IO capabilities)
    ///
    /// This is the IOcapA/IOcapB value that is used as part of the ['f6'] toolbox function.
    ///
    /// [`f6`] crate::sm::toolbox::f6
    pub fn get_io_cap(&self) -> [u8; 3] {
        self.io_cap_f6.clone()
    }
}

impl From<PairingRequest> for Command<PairingRequest> {
    fn from(pr: PairingRequest) -> Self {
        Command::new(CommandType::PairingRequest, pr)
    }
}

pub struct PairingResponse {
    io_capability: IoCapability,
    oob_data_flag: OobDataFlag,
    auth_req: LinearBuffer<{ AuthRequirements::full_depth() }, AuthRequirements>,
    max_encryption_size: usize,
    initiator_key_distribution: &'static [KeyDistributions],
    responder_key_distribution: &'static [KeyDistributions],
    io_cap_f6: [u8; 3],
}

impl CommandData for PairingResponse {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        let mut ret = LinearBuffer::new();

        ret.try_push(self.io_capability.into_val()).unwrap();

        ret.try_push(self.oob_data_flag.into_val()).unwrap();

        ret.try_push(AuthRequirements::make_auth_req_val(&self.auth_req))
            .unwrap();

        ret.try_push(self.max_encryption_size as u8).unwrap();

        ret.try_push(KeyDistributions::make_key_dist_val(&self.initiator_key_distribution))
            .unwrap();

        ret.try_push(KeyDistributions::make_key_dist_val(&self.responder_key_distribution))
            .unwrap();

        ret
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 6 {
            Ok(Self {
                io_capability: IoCapability::try_from_val(icd[0])?,
                oob_data_flag: OobDataFlag::try_from_val(icd[1])?,
                auth_req: AuthRequirements::from_val(icd[2]),
                max_encryption_size: if MAX_ENCRYPTION_SIZE_RANGE.contains(&(icd[3] as usize)) {
                    icd[3] as usize
                } else {
                    return Err(Error::Value);
                },
                initiator_key_distribution: KeyDistributions::from_val(icd[4]),
                responder_key_distribution: KeyDistributions::from_val(icd[5]),
                io_cap_f6: [icd[2], icd[1], icd[0]],
            })
        } else {
            log::error!("(SM) failed to generate 'pairing response' from raw data");
            log::trace!("(SM) failed raw data: '{:x?}", icd);
            Err(Error::Size)
        }
    }
}

impl PairingResponse {
    pub fn new(
        io_capability: IoCapability,
        oob_data_flag: OobDataFlag,
        auth_req: LinearBuffer<{ AuthRequirements::full_depth() }, AuthRequirements>,
        max_encryption_size: usize,
        initiator_key_distribution: &'static [KeyDistributions],
        responder_key_distribution: &'static [KeyDistributions],
    ) -> Self {
        Self {
            io_cap_f6: convert_io_cap(&auth_req, oob_data_flag, io_capability),
            io_capability,
            oob_data_flag,
            auth_req,
            max_encryption_size,
            initiator_key_distribution,
            responder_key_distribution,
        }
    }

    pub fn get_io_capability(&self) -> IoCapability {
        self.io_capability
    }

    pub fn get_oob_data_flag(&self) -> OobDataFlag {
        self.oob_data_flag
    }

    pub fn get_auth_req(&self) -> &[AuthRequirements] {
        &self.auth_req
    }

    pub fn get_max_encryption_size(&self) -> usize {
        self.max_encryption_size
    }

    pub fn get_initiator_key_distribution(&self) -> &'static [KeyDistributions] {
        &self.initiator_key_distribution
    }

    pub fn get_responder_key_distribution(&self) -> &'static [KeyDistributions] {
        &self.responder_key_distribution
    }

    /// Set the input and output capabilities of the device
    pub fn set_io_capability(&mut self, io_cap: IoCapability) {
        self.io_capability = io_cap;
    }

    /// Set authentication data
    ///
    /// Input `reqs` should be a slice of unique authorization requirements.
    pub fn set_authorization_requirements(&mut self, reqs: &[AuthRequirements]) {
        let mut auth_req = LinearBuffer::new();

        for a in reqs {
            if !auth_req.contains(a) {
                auth_req.try_push(*a).unwrap();
            }
        }

        self.auth_req = auth_req
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
            panic!(
                "Encryption key size of '{}' is not within the acceptable range (7..=16)",
                size
            );
        }
    }

    /// Set the key distribution / generation for the initiator
    ///
    /// This function takes a list of the types of key distribution / generation types available
    pub fn set_initiator_key_dis_gen(&mut self, dist_gen_types: &'static [KeyDistributions]) {
        self.initiator_key_distribution = dist_gen_types
    }

    /// Set the key distribution / generation that the initiator is requesting the the Responder
    /// to distribute
    ///
    /// This function takes a list of the types of key distribution / generation types if wants
    /// the responder to distribute.
    pub fn set_responder_key_dis_gen(&mut self, dist_gen_types: &'static [KeyDistributions]) {
        self.responder_key_distribution = dist_gen_types
    }

    /// Get the preq
    ///
    /// This returns the value for the `preq` input of the [`c1`] toolbox function.
    ///
    /// [`c1`]: toolbox::c1
    pub fn get_preq(&self) -> [u8; 7] {
        let mut ret = [0u8; 7];

        ret[0] = CommandType::PairingResponse.into_val();
        ret[1] = self.get_io_capability().into_val();
        ret[2] = self.get_oob_data_flag().into_val();
        ret[3] = AuthRequirements::make_auth_req_val(self.get_auth_req());
        ret[4] = self.get_max_encryption_size() as u8;
        ret[5] = KeyDistributions::make_key_dist_val(self.get_initiator_key_distribution());
        ret[6] = KeyDistributions::make_key_dist_val(self.get_responder_key_distribution());

        ret
    }

    /// Get the IOcap (not the IO capabilities)
    ///
    /// This is the IOcapA/IOcapB value that is used as part of the ['f6'] toolbox function.
    ///
    /// [`f6`]: crate::sm::toolbox::f6
    pub fn get_io_cap(&self) -> [u8; 3] {
        self.io_cap_f6.clone()
    }
}

impl From<PairingResponse> for Command<PairingResponse> {
    fn from(pr: PairingResponse) -> Self {
        Command::new(CommandType::PairingResponse, pr)
    }
}

pub struct PairingConfirm {
    value: u128,
}

impl CommandData for PairingConfirm {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        LinearBuffer::try_from(*&self.value.to_le_bytes()).unwrap()
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 16 {
            let mut v = [0u8; 16];

            v.copy_from_slice(icd);

            Ok(PairingConfirm {
                value: <u128>::from_le_bytes(v),
            })
        } else {
            log::error!("(SM) failed to generate 'pairing confirm' from raw data");
            log::trace!("(SM) failed raw data: {:x?}", icd);
            Err(Error::Size)
        }
    }
}

impl PairingConfirm {
    pub fn new(confirm_value: u128) -> Self {
        PairingConfirm { value: confirm_value }
    }

    pub fn set_value(&mut self, val: u128) {
        self.value = val
    }

    pub fn get_value(&self) -> u128 {
        self.value
    }
}

impl From<PairingConfirm> for Command<PairingConfirm> {
    fn from(pc: PairingConfirm) -> Self {
        Command::new(CommandType::PairingConfirm, pc)
    }
}

pub struct PairingRandom {
    value: u128,
}

impl CommandData for PairingRandom {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        LinearBuffer::try_from(*&self.value.to_le_bytes()).unwrap()
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 16 {
            let mut v = [0u8; 16];

            v.copy_from_slice(icd);

            Ok(PairingRandom {
                value: <u128>::from_le_bytes(v),
            })
        } else {
            log::error!("(SM) failed to generate 'pairing random' from raw data");
            log::trace!("(SM) failed raw data: {:x?}", icd);
            Err(Error::Size)
        }
    }
}

impl PairingRandom {
    pub fn new(rand: u128) -> Self {
        PairingRandom { value: rand }
    }

    pub fn get_value(&self) -> u128 {
        self.value
    }

    pub fn set_value(&mut self, val: u128) {
        self.value = val
    }
}

impl From<PairingRandom> for Command<PairingRandom> {
    fn from(pc: PairingRandom) -> Self {
        Command::new(CommandType::PairingRandom, pc)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PairingFailedReason {
    PasskeyEntryFailed,
    OobNotAvailable,
    AuthenticationRequirements,
    ConfirmValueFailed,
    PairingNotSupported,
    EncryptionKeySize,
    CommandNotSupported,
    UnspecifiedReason,
    RepeatedAttempts,
    InvalidParameters,
    DhKeyCheckFailed,
    NumericComparisonFailed,
    BrEdrPairingInProgress,
    CrossTransportKeyDerivationGenerationNotAllowed,
}

impl PairingFailedReason {
    fn into_val(self) -> u8 {
        match self {
            PairingFailedReason::PasskeyEntryFailed => 0x1,
            PairingFailedReason::OobNotAvailable => 0x2,
            PairingFailedReason::AuthenticationRequirements => 0x3,
            PairingFailedReason::ConfirmValueFailed => 0x4,
            PairingFailedReason::PairingNotSupported => 0x5,
            PairingFailedReason::EncryptionKeySize => 0x6,
            PairingFailedReason::CommandNotSupported => 0x7,
            PairingFailedReason::UnspecifiedReason => 0x8,
            PairingFailedReason::RepeatedAttempts => 0x9,
            PairingFailedReason::InvalidParameters => 0xa,
            PairingFailedReason::DhKeyCheckFailed => 0xb,
            PairingFailedReason::NumericComparisonFailed => 0xc,
            PairingFailedReason::BrEdrPairingInProgress => 0xd,
            PairingFailedReason::CrossTransportKeyDerivationGenerationNotAllowed => 0xe,
        }
    }

    fn try_from_val(val: u8) -> Result<Self, Error> {
        match val {
            0x1 => Ok(PairingFailedReason::PasskeyEntryFailed),
            0x2 => Ok(PairingFailedReason::OobNotAvailable),
            0x3 => Ok(PairingFailedReason::AuthenticationRequirements),
            0x4 => Ok(PairingFailedReason::ConfirmValueFailed),
            0x5 => Ok(PairingFailedReason::PairingNotSupported),
            0x6 => Ok(PairingFailedReason::EncryptionKeySize),
            0x7 => Ok(PairingFailedReason::CommandNotSupported),
            0x8 => Ok(PairingFailedReason::UnspecifiedReason),
            0x9 => Ok(PairingFailedReason::RepeatedAttempts),
            0xa => Ok(PairingFailedReason::InvalidParameters),
            0xb => Ok(PairingFailedReason::DhKeyCheckFailed),
            0xc => Ok(PairingFailedReason::NumericComparisonFailed),
            0xd => Ok(PairingFailedReason::BrEdrPairingInProgress),
            0xe => Ok(PairingFailedReason::CrossTransportKeyDerivationGenerationNotAllowed),
            _ => Err(Error::Value),
        }
    }
}

impl core::fmt::Display for PairingFailedReason {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            PairingFailedReason::PasskeyEntryFailed => f.write_str("passkey entry failed"),
            PairingFailedReason::OobNotAvailable => f.write_str("out of band data not available"),
            PairingFailedReason::AuthenticationRequirements => f.write_str("authentication requirements not met"),
            PairingFailedReason::ConfirmValueFailed => f.write_str("confirm value check failed"),
            PairingFailedReason::PairingNotSupported => f.write_str("pairing not supported"),
            PairingFailedReason::EncryptionKeySize => f.write_str("invalid encryption key size"),
            PairingFailedReason::CommandNotSupported => f.write_str("security manager command not supported"),
            PairingFailedReason::UnspecifiedReason => f.write_str("unspecified reason"),
            PairingFailedReason::RepeatedAttempts => f.write_str("too many attempts at pairing"),
            PairingFailedReason::InvalidParameters => f.write_str("invalid parameters"),
            PairingFailedReason::DhKeyCheckFailed => f.write_str("Diffie Hellman key check failed"),
            PairingFailedReason::NumericComparisonFailed => f.write_str("numeric comparison failed"),
            PairingFailedReason::BrEdrPairingInProgress => f.write_str("BR/EDR pairing in progress"),
            PairingFailedReason::CrossTransportKeyDerivationGenerationNotAllowed => {
                f.write_str("cross transport key derivation generation not allowed")
            }
        }
    }
}

/// The Pairing Failed Command
pub struct PairingFailed {
    reason: PairingFailedReason,
}

impl CommandData for PairingFailed {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        let mut ret = LinearBuffer::new();

        ret.try_push(self.reason.into_val()).unwrap();

        ret
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 1 {
            Ok(PairingFailed {
                reason: PairingFailedReason::try_from_val(icd[0])?,
            })
        } else {
            log::error!("(SM) failed to generate 'pairing failed' from raw data");
            log::trace!("(SM) failed raw data: {:x?}", icd);
            Err(Error::Size)
        }
    }
}

impl PairingFailed {
    /// Create a new `PairingFailed`
    pub fn new(reason: PairingFailedReason) -> Self {
        Self { reason }
    }

    /// Get the reason for why pairing failed
    pub fn get_reason(&self) -> PairingFailedReason {
        self.reason
    }

    /// Set the reason for why pairing failed
    pub fn set_reason(&mut self, reason: PairingFailedReason) {
        self.reason = reason
    }

    /// Send a `PairingFailed`
    ///
    /// This can be useful when a Security Manager is not implemented. Otherwise it is best to let
    /// a security manager handle sending of `PairingFailed` commands to the other device.
    ///
    /// ```
    /// # use bo_tie_l2cap::{BasicFrameError, BasicFrame, ChannelIdentifier, ConnectionChannelExt, L2capFragment, LeUserChannelIdentifier};
    /// # use bo_tie_l2cap::send_future::Error;
    /// # use bo_tie_sm::L2CAP_CHANNEL_ID;
    /// # use bo_tie_util::buffer::de_vec::DeVec;
    /// # use bo_tie_util::buffer::TryExtend;
    /// # use bo_tie_sm::pairing::{PairingFailed, PairingFailedReason};
    /// # struct CC;
    /// # impl bo_tie_l2cap::ConnectionChannel for CC {
    /// #    type SendBuffer = DeVec<u8>;
    /// #    type SendFut<'a> = std::future::Ready<Result<(), Error<Self::SendFutErr>>>;
    /// #    type SendFutErr = usize;
    /// #    type RecvBuffer = DeVec<u8>;
    /// #    type RecvFut<'a> = std::future::Pending<Option<Result<L2capFragment<Self::RecvBuffer>, BasicFrameError<<Self::RecvBuffer as TryExtend<u8>>::Error>>>>;
    /// #    fn send(&self, data: BasicFrame<Vec<u8>>) -> Self::SendFut<'_> {unimplemented!()}
    /// #    fn set_mtu(&mut self, mtu: u16) {unimplemented!()}
    /// #    fn get_mtu(&self) -> usize {unimplemented!()}
    /// #    fn max_mtu(&self) -> usize {unimplemented!()}
    /// #    fn min_mtu(&self) -> usize {unimplemented!()}
    /// #    fn receive(&mut self) -> Self::RecvFut<'_> {unimplemented!()}
    /// # }
    /// # let mut connection_channel = CC;
    /// # async {
    /// let sm_channel_id = L2CAP_CHANNEL_ID;
    ///
    /// for frame in connection_channel.receive_b_frame().await.unwrap() {
    ///
    ///     if frame.get_channel_id() == sm_channel_id {
    ///         // send an error as this device does
    ///         // not support a security manager.
    ///
    ///         let reason = PairingFailedReason::PairingNotSupported;
    ///
    ///         let command = PairingFailed::new(reason);
    ///
    ///         command.send(&connection_channel).await.unwrap()
    ///     } else {
    ///         /* process other channel */
    ///     }
    /// }
    /// # };
    /// ```
    pub async fn send<C>(self, connection_channel: &C) -> Result<(), bo_tie_l2cap::send_future::Error<C::SendFutErr>>
    where
        C: bo_tie_l2cap::ConnectionChannel,
    {
        let command: Command<_> = self.into();

        let data = command.into_command_format();

        let b_frame = BasicFrame::new(data.to_vec(), L2CAP_CHANNEL_ID);

        connection_channel.send(b_frame).await
    }
}

impl From<PairingFailed> for Command<PairingFailed> {
    fn from(pf: PairingFailed) -> Self {
        Command::new(CommandType::PairingFailed, pf)
    }
}

pub struct PairingPubKey {
    x_y: [u8; 64],
}

impl CommandData for PairingPubKey {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        LinearBuffer::try_from(*&self.x_y).unwrap()
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 64 {
            let mut x_y = [0u8; 64];

            x_y.copy_from_slice(icd);

            Ok(PairingPubKey { x_y })
        } else {
            log::error!("(SM) failed to generate 'pairing public key' from raw data");
            log::trace!("(SM) failed raw data: {:x?}", icd);
            Err(Error::Size)
        }
    }
}

impl PairingPubKey {
    pub fn new(key: [u8; 64]) -> Self {
        Self { x_y: key }
    }

    /// Return the public key
    pub fn get_key(&self) -> [u8; 64] {
        self.x_y.clone()
    }
}

impl From<PairingPubKey> for Command<PairingPubKey> {
    fn from(ppk: PairingPubKey) -> Self {
        Command::new(CommandType::PairingPublicKey, ppk)
    }
}

pub struct PairingDhKeyCheck {
    check: u128,
}

impl CommandData for PairingDhKeyCheck {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        LinearBuffer::try_from(*&self.check.to_le_bytes()).unwrap()
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 16 {
            let mut arr = [0u8; 16];

            arr.copy_from_slice(icd);

            Ok(PairingDhKeyCheck {
                check: <u128>::from_le_bytes(arr),
            })
        } else {
            log::error!("(SM) failed to generate 'pairing Diffie-Hellman Key check' from raw data");
            log::trace!("(SM) failed raw data: {:x?}", icd);
            Err(Error::Size)
        }
    }
}

impl PairingDhKeyCheck {
    pub fn new(check: u128) -> Self {
        PairingDhKeyCheck { check }
    }

    pub fn get_key_check(&self) -> u128 {
        self.check
    }

    pub fn set_key_check(&mut self, check: u128) {
        self.check = check
    }
}

impl From<PairingDhKeyCheck> for Command<PairingDhKeyCheck> {
    fn from(pkc: PairingDhKeyCheck) -> Self {
        Command::new(CommandType::PairingDHKeyCheck, pkc)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum KeyPressNotification {
    PasskeyEntryStarted,
    PasskeyDigitEntered,
    PasskeyDigitErased,
    PasskeyCleared,
    PasskeyEntryCompleted,
}

impl CommandData for KeyPressNotification {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        let mut ret = LinearBuffer::new();

        ret.try_push(self.into_val()).unwrap();

        ret
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 1 {
            Ok(Self::try_from_val(icd[0])?)
        } else {
            log::error!("(SM) failed to generate 'Key Press Notification' from raw data");
            log::trace!("(SM) failed raw data: {:x?}", icd);
            Err(Error::Size)
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
            0x0 => Ok(KeyPressNotification::PasskeyEntryStarted),
            0x1 => Ok(KeyPressNotification::PasskeyDigitEntered),
            0x2 => Ok(KeyPressNotification::PasskeyDigitErased),
            0x3 => Ok(KeyPressNotification::PasskeyCleared),
            0x4 => Ok(KeyPressNotification::PasskeyEntryCompleted),
            _ => Err(Error::Value),
        }
    }
}

impl From<KeyPressNotification> for Command<KeyPressNotification> {
    fn from(kpn: KeyPressNotification) -> Self {
        Command::new(CommandType::PairingKeyPressNotification, kpn)
    }
}
