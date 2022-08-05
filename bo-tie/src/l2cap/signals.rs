//! Signaling L2CAP Commands
//!
//! L2CAP supports signal packets to provide a L2CAP level configuration. This module contains the
//! various signaling packets that specified in the Bluetooth Specification | Vol 3, Part A
//! sections 4 and 5.

const ACL_U_SIG_CHANNEL_ID: super::ChannelIdentifier =
    super::ChannelIdentifier::ACL(super::ACLUserChannelIdentifier::SignalingChannel);

/// Codes for each Signal Type
///
/// # Note
/// For now only the Signal Codes listed are supported
pub enum SignalCode {
    CommandReject,
}

impl SignalCode {
    fn try_from_raw(val: u8) -> Result<Self, ()> {
        match val {
            0x1 => Ok(SignalCode::CommandReject),
            _ => Err(()),
        }
    }
}

impl From<SignalCode> for u8 {
    fn from(code: SignalCode) -> Self {
        match code {
            SignalCode::CommandReject => 0x1,
        }
    }
}

/// Command Rejection Reason
///
/// Reason for `CommandReject` signaling packet
pub enum CommandRejectReason {
    CommandNotUnderstood,
    SignalingMTUExceeded,
    InvalidCIDInRequest,
}

impl CommandRejectReason {
    /// Convert to the value
    ///
    /// The returned value is in little-endian format
    fn to_val(&self) -> u16 {
        match self {
            CommandRejectReason::CommandNotUnderstood => 0x0u16,
            CommandRejectReason::SignalingMTUExceeded => 0x1u16,
            CommandRejectReason::InvalidCIDInRequest => 0x2u16,
        }
        .to_le()
    }
}

enum CommandRejectData {
    None,
    Mtu(u16),
    RequestedCid(u16, u16),
}

impl CommandRejectData {
    fn len(&self) -> usize {
        match self {
            CommandRejectData::None => 0,
            CommandRejectData::Mtu(_) => 2,
            CommandRejectData::RequestedCid(_, _) => 4,
        }
    }

    fn copy_to_bytes(&self, to: &mut [u8]) {
        match self {
            CommandRejectData::None => (),
            CommandRejectData::Mtu(mtu) => to.copy_from_slice(&mtu.to_le_bytes()),
            CommandRejectData::RequestedCid(local, remote) => {
                to[0..2].copy_from_slice(&local.to_le_bytes());
                to[2..4].copy_from_slice(&remote.to_le_bytes());
            }
        }
    }
}

/// Command Rejection
///
/// This L2CAP signaling packet is sent in response when this device rejects a signaling packet
struct CommandReject {
    rejected_sig_id: SignalCode,
    reason: CommandRejectReason,
    data: CommandRejectData,
}

impl CommandReject {
    pub fn new_command_not_understood(rejected_sig_id: SignalCode) -> Self {
        CommandReject {
            rejected_sig_id,
            reason: CommandRejectReason::CommandNotUnderstood,
            data: CommandRejectData::None,
        }
    }

    pub fn new_signaling_mtu_exceeded(rejected_sig_id: SignalCode, actual_mtu: u16) -> Self {
        CommandReject {
            rejected_sig_id,
            reason: CommandRejectReason::SignalingMTUExceeded,
            data: CommandRejectData::Mtu(actual_mtu),
        }
    }

    pub fn new_invalid_cid_in_request(rejected_sig_id: SignalCode, local_cid: u16, remote_cid: u16) -> Self {
        CommandReject {
            rejected_sig_id,
            reason: CommandRejectReason::InvalidCIDInRequest,
            data: CommandRejectData::RequestedCid(local_cid, remote_cid),
        }
    }

    fn len(&self) -> usize {
        6 + self.data.len()
    }
}

impl From<CommandReject> for super::ACLData {
    fn from(cr: CommandReject) -> Self {
        use core::convert::TryFrom;

        // size of the L2CAP data header + size of the command reject signal
        let mut data = alloc::vec::Vec::with_capacity(cr.len());

        data[0] = SignalCode::CommandReject.into();

        data[1] = cr.rejected_sig_id.into();

        data[2..4].copy_from_slice(&<u16>::try_from(cr.data.len()).unwrap().to_le_bytes());

        data[4..6].copy_from_slice(&cr.reason.to_val().to_le_bytes());

        cr.data.copy_to_bytes(&mut data[6..]);

        super::ACLData::new(data, ACL_U_SIG_CHANNEL_ID)
    }
}
