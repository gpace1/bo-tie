//! Encryption information related Security Manager packets
//!
//! These packets are defined under the Security In Bluetooth Low Energy section of the Bluetooth
//! Specification (v5.0 | Vol 3, Part H, section 3.6)
use super::*;
use bo_tie_core::buffer::stack::LinearBuffer;

#[derive(Debug, Clone, Copy, PartialEq, bo_tie_macros::DepthCount)]
#[non_exhaustive]
pub enum AuthRequirements {
    Bonding,
    ManInTheMiddleProtection,
    Sc,
    KeyPress,
    // CT2 /* Waiting for BR/EDR support */
}

impl AuthRequirements {
    pub(super) fn make_auth_req_val(reqs: &[AuthRequirements]) -> u8 {
        reqs.iter().fold(0u8, |val, r| match r {
            AuthRequirements::Bonding => val | (0b01 << 0),
            AuthRequirements::ManInTheMiddleProtection => val | (1 << 2),
            AuthRequirements::Sc => val | (1 << 3),
            AuthRequirements::KeyPress => val | (1 << 4),
        })
    }

    pub(super) fn from_val(val: u8) -> LinearBuffer<{ Self::full_depth() }, Self> {
        let mut lb = LinearBuffer::new();

        if 1 == val & 0x11 {
            lb.try_push(AuthRequirements::Bonding).unwrap();
        }

        if 1 == (val >> 2) & 0x1 {
            lb.try_push(AuthRequirements::ManInTheMiddleProtection).unwrap();
        }

        if 1 == (val >> 3) & 0x1 {
            lb.try_push(AuthRequirements::Sc).unwrap();
        }

        if 1 == (val >> 4) & 0x1 {
            lb.try_push(AuthRequirements::KeyPress).unwrap();
        }

        lb
    }
}

pub struct EncryptionInformation {
    long_term_key: u128,
}

impl CommandData for EncryptionInformation {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        LinearBuffer::try_from(*&self.long_term_key.to_le_bytes()).unwrap()
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 16 {
            let mut v = [0u8; 16];

            v.copy_from_slice(icd);

            Ok(EncryptionInformation {
                long_term_key: <u128>::from_le_bytes(v),
            })
        } else {
            Err(Error::Size)
        }
    }
}

impl EncryptionInformation {
    pub fn set_long_term_key(&mut self, key: u128) {
        self.long_term_key = key
    }
}

impl From<EncryptionInformation> for Command<EncryptionInformation> {
    fn from(ei: EncryptionInformation) -> Self {
        Command::new(CommandType::EncryptionInformation, ei)
    }
}

pub struct MasterIdentification {
    encryption_diversifier: u16,
    random: u64,
}

impl CommandData for MasterIdentification {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        let ediv = self.encryption_diversifier.to_le_bytes();
        let rand = self.random.to_le_bytes();

        ediv.into_iter()
            .chain(rand.into_iter())
            .fold(LinearBuffer::new(), |mut lb, byte| {
                lb.try_push(byte).unwrap();
                lb
            })
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 10 {
            let mut ediv_a = [0u8; 2];
            let mut rand_a = [0u8; 8];

            ediv_a.copy_from_slice(&icd[..2]);
            rand_a.copy_from_slice(&icd[2..]);

            Ok(MasterIdentification {
                encryption_diversifier: <u16>::from_le_bytes(ediv_a),
                random: <u64>::from_le_bytes(rand_a),
            })
        } else {
            Err(Error::Size)
        }
    }
}

impl MasterIdentification {
    /// Set the Encryption Diversifier (Ediv)
    pub fn set_encryption_diversifier(&mut self, ediv: u16) {
        self.encryption_diversifier = ediv
    }

    /// Set the random value (Rand)
    pub fn set_random(&mut self, rand: u64) {
        self.random = rand
    }
}

impl From<MasterIdentification> for Command<MasterIdentification> {
    fn from(mi: MasterIdentification) -> Self {
        Command::new(CommandType::MasterIdentification, mi)
    }
}

pub struct IdentityInformation {
    irk: u128,
}

impl IdentityInformation {
    pub fn new(irk: u128) -> Self {
        IdentityInformation { irk }
    }

    pub fn get_irk(&self) -> u128 {
        self.irk
    }
}

impl CommandData for IdentityInformation {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        LinearBuffer::try_from(*&self.irk.to_le_bytes()).unwrap()
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 16 {
            let mut v = [0u8; 16];

            v.copy_from_slice(icd);

            Ok(IdentityInformation {
                irk: <u128>::from_le_bytes(v),
            })
        } else {
            Err(Error::Size)
        }
    }
}

impl From<IdentityInformation> for Command<IdentityInformation> {
    fn from(ii: IdentityInformation) -> Self {
        Command::new(CommandType::IdentityInformation, ii)
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
enum AddressType {
    Public,
    StaticRandom,
}

pub struct IdentityAddressInformation {
    addr_type: AddressType,
    address: crate::BluetoothDeviceAddress,
}

impl CommandData for IdentityAddressInformation {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        let mut ret = LinearBuffer::new();

        let addr_type_val = match self.addr_type {
            AddressType::Public => 0,
            AddressType::StaticRandom => 1,
        };

        ret.try_push(addr_type_val).unwrap();

        self.address.0.into_iter().for_each(|byte| ret.try_push(byte).unwrap());

        ret
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 7 {
            let addr_type = match icd[0] {
                0 => AddressType::Public,
                1 => AddressType::StaticRandom,
                _ => return Err(Error::Value),
            };

            let mut address = crate::BluetoothDeviceAddress::zeroed();

            address.copy_from_slice(&icd[1..]);

            Ok(IdentityAddressInformation { addr_type, address })
        } else {
            Err(Error::Size)
        }
    }
}

impl IdentityAddressInformation {
    /// Create a new `IdentityAddressInformation` containing a public address
    pub fn new_pub(address: crate::BluetoothDeviceAddress) -> Self {
        Self {
            addr_type: AddressType::Public,
            address,
        }
    }

    /// Create a new `IdentityAddressInformation` containing a static random device address
    ///
    /// This function doesn't validate that `address` is a valid static device address. The format
    /// of a static random device address can be found in the Bluetooth Specification (v5.0 | Vol 6,
    /// Part B, section 1.3.2.1).
    pub fn new_static_rand(address: crate::BluetoothDeviceAddress) -> Self {
        Self {
            addr_type: AddressType::StaticRandom,
            address,
        }
    }

    pub fn is_address_public(&self) -> bool {
        self.addr_type == AddressType::Public
    }

    pub fn get_address(&self) -> BluetoothDeviceAddress {
        self.address
    }

    pub fn as_identity(&self) -> IdentityAddress {
        match self.addr_type {
            AddressType::Public => IdentityAddress::Public(self.address),
            AddressType::StaticRandom => IdentityAddress::StaticRandom(self.address),
        }
    }
}

impl From<IdentityAddressInformation> for IdentityAddress {
    fn from(iai: IdentityAddressInformation) -> Self {
        match iai.addr_type {
            AddressType::Public => IdentityAddress::Public(iai.address),
            AddressType::StaticRandom => IdentityAddress::StaticRandom(iai.address),
        }
    }
}

impl From<IdentityAddressInformation> for Command<IdentityAddressInformation> {
    fn from(iai: IdentityAddressInformation) -> Self {
        Command::new(CommandType::IdentityAddressInformation, iai)
    }
}

pub struct SigningInformation {
    signature_key: u128,
}

impl CommandData for SigningInformation {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        self.signature_key
            .to_le_bytes()
            .into_iter()
            .fold(LinearBuffer::new(), |mut lb, byte| {
                lb.try_push(byte).unwrap();
                lb
            })
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 16 {
            let mut key_arr = [0u8; 16];

            key_arr.copy_from_slice(&icd);

            Ok(SigningInformation {
                signature_key: <u128>::from_le_bytes(key_arr),
            })
        } else {
            Err(Error::Size)
        }
    }
}

impl SigningInformation {
    pub fn new(csrk: u128) -> Self {
        Self { signature_key: csrk }
    }

    pub fn get_signature_key(&self) -> u128 {
        self.signature_key
    }
}

impl From<SigningInformation> for Command<SigningInformation> {
    fn from(si: SigningInformation) -> Self {
        Command::new(CommandType::SigningInformation, si)
    }
}

pub struct SecurityRequest {
    auth_req: LinearBuffer<{ AuthRequirements::full_depth() }, AuthRequirements>,
}

impl CommandData for SecurityRequest {
    fn into_command_format(self) -> LinearBuffer<65, u8> {
        let mut ret = LinearBuffer::new();

        ret.try_push(AuthRequirements::make_auth_req_val(&self.auth_req))
            .unwrap();

        ret
    }

    fn try_from_command_format(icd: &[u8]) -> Result<Self, Error> {
        if icd.len() == 1 {
            let auth_req = AuthRequirements::from_val(icd[0]);

            Ok(SecurityRequest { auth_req })
        } else {
            Err(Error::Size)
        }
    }
}

impl SecurityRequest {
    /// Create a new SecurityRequest
    ///
    /// The input `auth_req` is the list of Authorization requirements within the Security Request.
    /// This list should only contain unique entries.
    pub fn new(&mut self, auth_req: &[AuthRequirements]) {
        let mut req = LinearBuffer::new();

        for a in auth_req {
            if !req.contains(a) {
                req.try_push(*a).unwrap();
            }
        }

        self.auth_req = req
    }
}

impl From<SecurityRequest> for Command<SecurityRequest> {
    fn from(sr: SecurityRequest) -> Self {
        Command::new(CommandType::SecurityRequest, sr)
    }
}
