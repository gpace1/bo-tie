//! HCI Command Opcodes
//!
//! Opcodes are composed of a group identifier and an individual command identifier specific to the
//! group. The group identifier and individual identifier are put together to form the raw opcode
//! value.
//!
//! Instead of using group and command codes to create an opcode, the enum `HciCommand` should be
//! used to create an opcode. `HciCommand` is an enumeration of all the HCI commands, an opcode can
//! be acquired by the method `into_opcode`.
//!
//! ```
//! # use bo_tie_hci_util::opcodes::{HciCommand, ControllerAndBaseband};
//!
//! assert_eq!(0xC03, HciCommand::ControllerAndBaseband(ControllerAndBaseband::Reset).into_opcode());
//! ```

use core::convert::TryFrom;

/// Enumerations of the various HCI command opcodes.
///
/// HciCommands consists of the HCI command groups containing the HCI commands within the group.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HciCommand {
    LinkControl(LinkControl),
    ControllerAndBaseband(ControllerAndBaseband),
    InformationParameters(InformationParameters),
    StatusParameters(StatusParameters),
    LEController(LEController),
}

impl HciCommand {
    /// Get the opcode for this command
    pub const fn into_opcode(self) -> u16 {
        self.into_opcode_pair().into_opcode()
    }

    /// Get the `OpCodePair` for this command
    pub const fn into_opcode_pair(self) -> OpCodePair {
        match self {
            HciCommand::LinkControl(ocf) => ocf.into_opcode_pair(),
            HciCommand::ControllerAndBaseband(ocf) => ocf.into_opcode_pair(),
            HciCommand::InformationParameters(ocf) => ocf.into_opcode_pair(),
            HciCommand::StatusParameters(ocf) => ocf.into_opcode_pair(),
            HciCommand::LEController(ocf) => ocf.into_opcode_pair(),
        }
    }
}

impl core::fmt::Display for HciCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            HciCommand::LinkControl(c) => {
                let opcode = c.into_opcode_pair();

                write!(f, "link control - {} ({:#x}:{:#x})", c, opcode.ogf, opcode.ocf)
            }
            HciCommand::ControllerAndBaseband(c) => {
                let opcode = c.into_opcode_pair();

                write!(
                    f,
                    "controller and baseband - {} ({:#x}:{:#x})",
                    c, opcode.ogf, opcode.ocf
                )
            }
            HciCommand::InformationParameters(c) => {
                let opcode = c.into_opcode_pair();

                write!(
                    f,
                    "information parameters - {} ({:#x}:{:#x})",
                    c, opcode.ogf, opcode.ocf
                )
            }
            HciCommand::StatusParameters(c) => {
                let opcode = c.into_opcode_pair();

                write!(f, "status parameters - {} ({:#x}:{:#x})", c, opcode.ogf, opcode.ocf)
            }
            HciCommand::LEController(c) => {
                let opcode = c.into_opcode_pair();

                write!(f, "LE controller - {} ({:#x}:{:#x})", c, opcode.ogf, opcode.ocf)
            }
        }
    }
}

/// An type for the pair of OGF (OpCode Group Field) and OCF (OpCode Command Field)
///
/// The main use for this is for converting from the `HCICommand` enumeration into the numerical
/// values to be passed over the interface to the controller.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct OpCodePair {
    pub ogf: u16,
    pub ocf: u16,
}

impl OpCodePair {
    /// Get the OpCode Command Field value
    pub fn get_ogf(&self) -> u16 {
        self.ogf
    }

    /// Get the OpCode Group Field value
    pub fn get_ocf(&self) -> u16 {
        self.ocf
    }

    /// Convert the OpCodePair into the opcode
    ///
    /// The returned value is the OpCode used with building a HCI command Packet.
    pub const fn into_opcode(self) -> u16 {
        // The first 10 bits of the OpCode is the OCF field and the last 6 bits is the OGF field.
        ((self.ocf & 0x3FFu16) | (self.ogf << 10)).to_le()
    }

    /// Convert a HCI command packet formatted Op Code into an OpCodePair
    pub const fn from_opcode(val: u16) -> Self {
        let value = <u16>::from_le(val);
        OpCodePair {
            ogf: value >> 10,
            ocf: value & 0x3FFu16,
        }
    }
}

impl From<HciCommand> for OpCodePair {
    fn from(cmd: HciCommand) -> OpCodePair {
        cmd.into_opcode_pair()
    }
}

impl TryFrom<OpCodePair> for HciCommand {
    type Error = alloc::string::String;

    fn try_from(opc_pair: OpCodePair) -> Result<Self, Self::Error> {
        match opc_pair.ogf {
            0x1 => Ok(HciCommand::LinkControl(LinkControl::try_from(opc_pair.ocf)?)),
            0x3 => Ok(HciCommand::ControllerAndBaseband(ControllerAndBaseband::try_from(
                opc_pair.ocf,
            )?)),
            0x4 => Ok(HciCommand::InformationParameters(InformationParameters::try_from(
                opc_pair.ocf,
            )?)),
            0x5 => Ok(HciCommand::StatusParameters(StatusParameters::try_from(opc_pair.ocf)?)),
            0x8 => Ok(HciCommand::LEController(LEController::try_from(opc_pair.ocf)?)),
            _ => Err(alloc::format!("Unknown OpCode Group Field value: 0x{:x}", opc_pair.ogf)),
        }
    }
}

macro_rules! ocf_error {
    () => {
        "OpCode Group Field '{}' doesn't have the Op Code Field 0x{:x}"
    };
}

/// Link control commands
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum LinkControl {
    Disconnect,
    ReadRemoteVersionInformation,
}

impl LinkControl {
    const OGF: u16 = 0x1;

    const fn into_opcode_pair(self) -> OpCodePair {
        use self::LinkControl::*;

        OpCodePair {
            ogf: LinkControl::OGF,
            ocf: match self {
                Disconnect => 0x6,
                ReadRemoteVersionInformation => 0x1d,
            },
        }
    }

    fn try_from(ocf: u16) -> Result<Self, alloc::string::String> {
        match ocf {
            0x6 => Ok(LinkControl::Disconnect),
            0x1d => Ok(LinkControl::ReadRemoteVersionInformation),
            _ => Err(alloc::format!(ocf_error!(), "Link Control", ocf)),
        }
    }
}

impl core::fmt::Display for LinkControl {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            LinkControl::Disconnect => f.write_str("disconnect"),
            LinkControl::ReadRemoteVersionInformation => f.write_str(""),
        }
    }
}

/// Controller and baseband commands
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ControllerAndBaseband {
    SetEventMask,
    Reset,
    ReadTransmitPowerLevel,
}

impl ControllerAndBaseband {
    const OGF: u16 = 0x3;

    const fn into_opcode_pair(self) -> OpCodePair {
        use self::ControllerAndBaseband::*;

        OpCodePair {
            ogf: ControllerAndBaseband::OGF,
            ocf: match self {
                SetEventMask => 0x1,
                Reset => 0x3,
                ReadTransmitPowerLevel => 0x2d,
            },
        }
    }

    fn try_from(ocf: u16) -> Result<Self, alloc::string::String> {
        match ocf {
            0x1 => Ok(ControllerAndBaseband::SetEventMask),
            0x3 => Ok(ControllerAndBaseband::Reset),
            0x2d => Ok(ControllerAndBaseband::ReadTransmitPowerLevel),
            _ => Err(alloc::format!(ocf_error!(), "Controller and Baseband", ocf)),
        }
    }
}

impl core::fmt::Display for ControllerAndBaseband {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ControllerAndBaseband::SetEventMask => f.write_str("set event mask"),
            ControllerAndBaseband::Reset => f.write_str("reset"),
            ControllerAndBaseband::ReadTransmitPowerLevel => f.write_str("read transmit power level"),
        }
    }
}

/// Information parameter commands
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum InformationParameters {
    ReadLocalSupportedVersionInformation,
    ReadLocalSupportedCommands,
    ReadLocalSupportedFeatures,
    #[allow(non_camel_case_types)]
    ReadBD_ADDR,
    ReadBufferSize,
}

impl InformationParameters {
    const OGF: u16 = 0x4;

    const fn into_opcode_pair(self) -> OpCodePair {
        use self::InformationParameters::*;

        OpCodePair {
            ogf: InformationParameters::OGF,
            ocf: match self {
                ReadLocalSupportedVersionInformation => 0x1,
                ReadLocalSupportedCommands => 0x2,
                ReadLocalSupportedFeatures => 0x3,
                ReadBufferSize => 0x5,
                ReadBD_ADDR => 0x9,
            },
        }
    }

    fn try_from(ocf: u16) -> Result<Self, alloc::string::String> {
        match ocf {
            0x1 => Ok(InformationParameters::ReadLocalSupportedVersionInformation),
            0x2 => Ok(InformationParameters::ReadLocalSupportedCommands),
            0x3 => Ok(InformationParameters::ReadLocalSupportedFeatures),
            0x5 => Ok(InformationParameters::ReadBufferSize),
            0x9 => Ok(InformationParameters::ReadBD_ADDR),
            _ => Err(alloc::format!(ocf_error!(), "Information Parameters", ocf)),
        }
    }
}

impl core::fmt::Display for InformationParameters {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            InformationParameters::ReadLocalSupportedVersionInformation => {
                f.write_str("read local supported version information")
            }
            InformationParameters::ReadLocalSupportedCommands => f.write_str("read local supported commands"),
            InformationParameters::ReadLocalSupportedFeatures => f.write_str("read local supported features"),
            InformationParameters::ReadBD_ADDR => f.write_str("read BR_ADDR"),
            InformationParameters::ReadBufferSize => f.write_str("read buffer size"),
        }
    }
}

/// Status parameter commands
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum StatusParameters {
    ReadRSSI,
}

impl StatusParameters {
    const OGF: u16 = 0x5;

    const fn into_opcode_pair(self) -> OpCodePair {
        use self::StatusParameters::*;

        OpCodePair {
            ogf: StatusParameters::OGF,
            ocf: match self {
                ReadRSSI => 0x5,
            },
        }
    }

    fn try_from(ocf: u16) -> Result<Self, alloc::string::String> {
        match ocf {
            0x5 => Ok(StatusParameters::ReadRSSI),
            _ => Err(alloc::format!(ocf_error!(), "Status Parameters", ocf)),
        }
    }
}

impl core::fmt::Display for StatusParameters {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            StatusParameters::ReadRSSI => f.write_str("read RSSI"),
        }
    }
}

/// Bluetooth LE commands
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum LEController {
    SetEventMask,
    ReadBufferSizeV1,
    ReadBufferSizeV2,
    ReadLocalSupportedFeatures,
    SetRandomAddress,
    SetAdvertisingParameters,
    ReadAdvertisingChannelTxPower,
    SetAdvertisingData,
    SetScanResponseData,
    SetAdvertisingEnable,
    SetScanParameters,
    SetScanEnable,
    CreateConnection,
    CreateConnectionCancel,
    ReadFilterListSize,
    ClearFilterList,
    AddDeviceToFilterList,
    RemoveDeviceFromFilterList,
    ConnectionUpdate,
    SetHostChannelClassification,
    ReadChannelMap,
    ReadRemoteFeatures,
    Encrypt,
    Rand,
    StartEncryption,
    LongTermKeyRequestReply,
    LongTermKeyRequestNegativeReply,
    ReadSupportedStates,
    ReceiverTest,
    TransmitterTest,
    TestEnd,
    ReadConnectionParameterRequestReply,
    ReadConnectionParameterRequestNegativeReply,
    SetResolvablePrivateAddressTimeout,
    SetAddressResolutionEnable,
    AddDeviceToResolvingList,
    RemoveDeviceFromResolvingList,
    ClearResolvingList,
    SetPrivacyMode,
}

impl LEController {
    const OGF: u16 = 0x8;

    const fn into_opcode_pair(self) -> OpCodePair {
        use self::LEController::*;

        OpCodePair {
            ogf: LEController::OGF,
            ocf: match self {
                SetEventMask => 0x1,
                ReadBufferSizeV1 => 0x2,
                ReadBufferSizeV2 => 0x60,
                ReadLocalSupportedFeatures => 0x3,
                SetRandomAddress => 0x5,
                SetAdvertisingParameters => 0x6,
                ReadAdvertisingChannelTxPower => 0x7,
                SetAdvertisingData => 0x8,
                SetScanResponseData => 0x9,
                SetAdvertisingEnable => 0xa,
                SetScanParameters => 0xb,
                SetScanEnable => 0xC,
                CreateConnection => 0xD,
                CreateConnectionCancel => 0xe,
                ReadFilterListSize => 0xf,
                ClearFilterList => 0x10,
                AddDeviceToFilterList => 0x11,
                RemoveDeviceFromFilterList => 0x12,
                ConnectionUpdate => 0x13,
                SetHostChannelClassification => 0x14,
                ReadChannelMap => 0x15,
                ReadRemoteFeatures => 0x16,
                Encrypt => 0x17,
                Rand => 0x18,
                StartEncryption => 0x19,
                LongTermKeyRequestReply => 0x1a,
                LongTermKeyRequestNegativeReply => 0x1b,
                ReadSupportedStates => 0x1c,
                ReceiverTest => 0x1d,
                TransmitterTest => 0x1e,
                TestEnd => 0x1f,
                ReadConnectionParameterRequestReply => 0x20,
                ReadConnectionParameterRequestNegativeReply => 0x21,
                SetResolvablePrivateAddressTimeout => 0x2e,
                SetAddressResolutionEnable => 0x2d,
                AddDeviceToResolvingList => 0x27,
                RemoveDeviceFromResolvingList => 0x28,
                ClearResolvingList => 0x29,
                SetPrivacyMode => 0x4e,
            },
        }
    }

    fn try_from(ocf: u16) -> Result<Self, alloc::string::String> {
        match ocf {
            0x1 => Ok(LEController::SetEventMask),
            0x2 => Ok(LEController::ReadBufferSizeV1),
            0x60 => Ok(LEController::ReadBufferSizeV2),
            0x3 => Ok(LEController::ReadLocalSupportedFeatures),
            0x5 => Ok(LEController::SetRandomAddress),
            0x6 => Ok(LEController::SetAdvertisingParameters),
            0x7 => Ok(LEController::ReadAdvertisingChannelTxPower),
            0x8 => Ok(LEController::SetAdvertisingData),
            0x9 => Ok(LEController::SetScanResponseData),
            0xa => Ok(LEController::SetAdvertisingEnable),
            0xb => Ok(LEController::SetScanParameters),
            0xC => Ok(LEController::SetScanEnable),
            0xD => Ok(LEController::CreateConnection),
            0xe => Ok(LEController::CreateConnectionCancel),
            0xf => Ok(LEController::ReadFilterListSize),
            0x10 => Ok(LEController::ClearFilterList),
            0x11 => Ok(LEController::AddDeviceToFilterList),
            0x12 => Ok(LEController::RemoveDeviceFromFilterList),
            0x13 => Ok(LEController::ConnectionUpdate),
            0x14 => Ok(LEController::SetHostChannelClassification),
            0x15 => Ok(LEController::ReadChannelMap),
            0x16 => Ok(LEController::ReadRemoteFeatures),
            0x17 => Ok(LEController::Encrypt),
            0x18 => Ok(LEController::Rand),
            0x19 => Ok(LEController::StartEncryption),
            0x1a => Ok(LEController::LongTermKeyRequestReply),
            0x1b => Ok(LEController::LongTermKeyRequestNegativeReply),
            0x1c => Ok(LEController::ReadSupportedStates),
            0x1d => Ok(LEController::ReceiverTest),
            0x1e => Ok(LEController::TransmitterTest),
            0x1f => Ok(LEController::TestEnd),
            0x20 => Ok(LEController::ReadConnectionParameterRequestReply),
            0x21 => Ok(LEController::ReadConnectionParameterRequestNegativeReply),
            0x2e => Ok(LEController::SetResolvablePrivateAddressTimeout),
            0x2d => Ok(LEController::SetAddressResolutionEnable),
            0x27 => Ok(LEController::AddDeviceToResolvingList),
            0x28 => Ok(LEController::RemoveDeviceFromResolvingList),
            0x29 => Ok(LEController::ClearResolvingList),
            0x4e => Ok(LEController::SetPrivacyMode),
            _ => Err(alloc::format!(ocf_error!(), "LE Controller", ocf)),
        }
    }
}

impl core::fmt::Display for LEController {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            LEController::SetEventMask => f.write_str("set event mask"),
            LEController::ReadBufferSizeV1 => f.write_str("read buffer size (v1)"),
            LEController::ReadBufferSizeV2 => f.write_str("read buffer size (v2)"),
            LEController::ReadLocalSupportedFeatures => f.write_str("read local supported features"),
            LEController::SetRandomAddress => f.write_str("set random address"),
            LEController::SetAdvertisingParameters => f.write_str("set advertising parameters"),
            LEController::ReadAdvertisingChannelTxPower => f.write_str("read advertising channel tx power"),
            LEController::SetAdvertisingData => f.write_str("set advertising data"),
            LEController::SetScanResponseData => f.write_str("set scan response data"),
            LEController::SetAdvertisingEnable => f.write_str("set advertising enable"),
            LEController::SetScanParameters => f.write_str("set scan parameters"),
            LEController::SetScanEnable => f.write_str("set scan enable"),
            LEController::CreateConnection => f.write_str("create connection"),
            LEController::CreateConnectionCancel => f.write_str("create connection cancel"),
            LEController::ReadFilterListSize => f.write_str("read filter list size"),
            LEController::ClearFilterList => f.write_str("clear filter list"),
            LEController::AddDeviceToFilterList => f.write_str("add device to filter list"),
            LEController::RemoveDeviceFromFilterList => f.write_str("remove device from filter list"),
            LEController::ConnectionUpdate => f.write_str("connection update"),
            LEController::SetHostChannelClassification => f.write_str("set host channel classification"),
            LEController::ReadChannelMap => f.write_str("read channel map"),
            LEController::ReadRemoteFeatures => f.write_str("read remote features"),
            LEController::Encrypt => f.write_str("encrypt"),
            LEController::Rand => f.write_str("rand"),
            LEController::StartEncryption => f.write_str("start encryption"),
            LEController::LongTermKeyRequestReply => f.write_str("long term key request reply"),
            LEController::LongTermKeyRequestNegativeReply => f.write_str("long term key request negative reply"),
            LEController::ReadSupportedStates => f.write_str("read supported states"),
            LEController::ReceiverTest => f.write_str("receiver test"),
            LEController::TransmitterTest => f.write_str("transmitter test"),
            LEController::TestEnd => f.write_str("test end"),
            LEController::ReadConnectionParameterRequestReply => f.write_str("read connection parameter request reply"),
            LEController::ReadConnectionParameterRequestNegativeReply => {
                f.write_str("read connection parameter request negative reply")
            }
            LEController::SetResolvablePrivateAddressTimeout => f.write_str("set resolvable private address timeout"),
            LEController::SetAddressResolutionEnable => f.write_str("set address resolution enable"),
            LEController::AddDeviceToResolvingList => f.write_str("add device to resolving list"),
            LEController::RemoveDeviceFromResolvingList => f.write_str("remove device from resolving list"),
            LEController::ClearResolvingList => f.write_str("clear resolving list"),
            LEController::SetPrivacyMode => f.write_str("set privacy mode"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_code_test() {
        let ogf = 0x8;
        let ocf = 0xa;
        let oc = HciCommand::LEController(LEController::SetAdvertisingEnable);

        assert_eq!(oc, HciCommand::try_from(OpCodePair { ogf, ocf }).unwrap());
    }
}
