use core::convert::TryFrom;

#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum HCICommand {
    LinkControl(LinkControl),
    ControllerAndBaseband(ControllerAndBaseband),
    InformationParameters(InformationParameters),
    StatusParameters(StatusParameters),
    LEController(LEController),
}

impl HCICommand {
    pub fn as_opcode_pair(&self) -> OpCodePair {
        match *self {
            HCICommand::LinkControl(ref ocf) => ocf.as_opcode_pair(),
            HCICommand::ControllerAndBaseband(ref ocf) => ocf.as_opcode_pair(),
            HCICommand::InformationParameters(ref ocf) => ocf.as_opcode_pair(),
            HCICommand::StatusParameters(ref ocf) => ocf.as_opcode_pair(),
            HCICommand::LEController(ref ocf) => ocf.as_opcode_pair(),
        }
    }
}

/// An type for the pair of OGF (OpCode Group Field) and OCF (OpCode Command Field)
pub struct OpCodePair {
    pub(crate) ogf: u16,
    pub(crate) ocf: u16,
}

impl OpCodePair {

    /// Get the OpCode Command Field value
    pub fn get_ogf(&self) -> u16 { self.ogf }

    /// Get the OpCode Group Field value
    pub fn get_ocf(&self) -> u16 { self.ocf }

    /// Convert the OpCodePair into the opcode
    ///
    /// The returned value is the OpCode used with building a HCI command Packet.
    pub fn as_opcode(&self) -> u16 {
        // The first 10 bits of the OpCode is the OCF field and the last 6 bits is the OGF field.
        ((self.ocf & 0x3FFu16) | (self.ogf << 10)).to_le()
    }

    /// Convert the HCI command packet Op Code into an OpCodePair
    pub fn from_opcode(val: u16) -> Self {
        let value = <u16>::from_le(val);
        OpCodePair {
            ogf: value >> 10,
            ocf: value & 0x3FFu16,
        }
    }
}

impl TryFrom<OpCodePair> for HCICommand {
    type Error = alloc::string::String;

    fn try_from(opc_pair: OpCodePair) -> Result<Self, Self::Error> {
        match opc_pair.ogf {
            0x1 => Ok(HCICommand::LinkControl( LinkControl::try_from(opc_pair.ocf)? )),
            0x3 => Ok(HCICommand::ControllerAndBaseband( ControllerAndBaseband::try_from(opc_pair.ocf)? )),
            0x4 => Ok(HCICommand::InformationParameters( InformationParameters::try_from(opc_pair.ocf)? )),
            0x5 => Ok(HCICommand::StatusParameters( StatusParameters::try_from(opc_pair.ocf)? )),
            0x8 => Ok(HCICommand::LEController( LEController::try_from(opc_pair.ocf)? )),
            _ => Err(alloc::format!("Unknown OpCode Group Field value: 0x{:x}", opc_pair.ogf)),
        }
    }
}

macro_rules! ocf_error{ () => { "OpCode Group Field '{}' doesn't have the Op Code Field 0x{:x}" }; }

#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum LinkControl {
    Disconnect,
    ReadRemoteVersionInformation,
}

impl LinkControl {
    const OGF: u16 = 0x1;

    #[inline]
    fn as_opcode_pair(&self) -> OpCodePair {
        use self::LinkControl::*;

        OpCodePair {
            ogf: LinkControl::OGF,
            ocf: match *self {
                Disconnect => 0x6,
                ReadRemoteVersionInformation => 0x1d,
            }
        }
    }

    fn try_from(ocf: u16) -> Result< Self, alloc::string::String> {
        match ocf {
            0x6  => Ok(LinkControl::Disconnect),
            0x1d => Ok(LinkControl::ReadRemoteVersionInformation),
            _ => Err(alloc::format!(ocf_error!(), "Link Control", ocf)),
        }
    }
}

#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum ControllerAndBaseband {
    SetEventMask,
    Reset,
    ReadTransmitPowerLevel,
}

impl ControllerAndBaseband {
    const OGF: u16 = 0x3;

    #[inline]
    fn as_opcode_pair(&self) -> OpCodePair {
        use self::ControllerAndBaseband::*;

        OpCodePair {
            ogf: ControllerAndBaseband::OGF,
            ocf: match *self {
                SetEventMask => 0x1,
                Reset => 0x3,
                ReadTransmitPowerLevel => 0x2d,
            }
        }
    }

    fn try_from(ocf: u16) -> Result< Self, alloc::string::String> {
        match ocf {
            0x1  => Ok(ControllerAndBaseband::SetEventMask),
            0x3  => Ok(ControllerAndBaseband::Reset),
            0x2d => Ok(ControllerAndBaseband::ReadTransmitPowerLevel),
            _ => Err(alloc::format!(ocf_error!(), "Controller and Baseband", ocf)),
        }
    }
}

#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum InformationParameters {
    ReadLocalSupportedVersionInformation,
    ReadLocalSupportedCommands,
    ReadLocalSupportedFeatures,
    #[allow(non_camel_case_types)] ReadBD_ADDR,
}

impl InformationParameters {
    const OGF: u16 = 0x4;

    #[inline]
    fn as_opcode_pair(&self) -> OpCodePair {
        use self::InformationParameters::*;

        OpCodePair {
            ogf: InformationParameters::OGF,
            ocf: match *self {
                ReadLocalSupportedVersionInformation => 0x1,
                ReadLocalSupportedCommands => 0x2,
                ReadLocalSupportedFeatures => 0x3,
                ReadBD_ADDR => 0x9,
            }
        }
    }

    fn try_from(ocf: u16) -> Result< Self, alloc::string::String> {
        match ocf {
            0x1 => Ok(InformationParameters::ReadLocalSupportedVersionInformation),
            0x2 => Ok(InformationParameters::ReadLocalSupportedCommands),
            0x3 => Ok(InformationParameters::ReadLocalSupportedFeatures),
            0x9 => Ok(InformationParameters::ReadBD_ADDR),
            _ => Err(alloc::format!(ocf_error!(), "Information Parameters", ocf)),
        }
    }
}

#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum StatusParameters {
    ReadRSSI,
}

impl StatusParameters {
    const OGF: u16 = 0x5;

    #[inline]
    fn as_opcode_pair(&self) -> OpCodePair {
        use self::StatusParameters::*;

        OpCodePair {
            ogf: StatusParameters::OGF,
            ocf: match *self {
                ReadRSSI => 0x5,
            }
        }
    }

    fn try_from(ocf: u16) -> Result< Self, alloc::string::String> {
        match ocf {
            0x5 => Ok(StatusParameters::ReadRSSI),
            _ => Err(alloc::format!(ocf_error!(), "Status Parameters", ocf)),
        }
    }
}

#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum LEController {
    SetEventMask,
    ReadBufferSize,
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
    ReadWhiteListSize,
    ClearWhiteList,
    AddDeviceToWhiteList,
    RemoveDeviceFromWhiteList,
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

    #[inline]
    fn as_opcode_pair( &self ) -> OpCodePair{
        use self::LEController::*;

        OpCodePair {
            ogf: LEController::OGF,
            ocf: match *self {
                SetEventMask => 0x1,
                ReadBufferSize => 0x2,
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
                ReadWhiteListSize => 0xf,
                ClearWhiteList => 0x10,
                AddDeviceToWhiteList => 0x11,
                RemoveDeviceFromWhiteList => 0x12,
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

    fn try_from(ocf: u16) -> Result< Self, alloc::string::String> {
        match ocf {
            0x1  => Ok(LEController::SetEventMask),
            0x2  => Ok(LEController::ReadBufferSize),
            0x3  => Ok(LEController::ReadLocalSupportedFeatures),
            0x5  => Ok(LEController::SetRandomAddress),
            0x6  => Ok(LEController::SetAdvertisingParameters),
            0x7  => Ok(LEController::ReadAdvertisingChannelTxPower),
            0x8  => Ok(LEController::SetAdvertisingData),
            0x9  => Ok(LEController::SetScanResponseData),
            0xa  => Ok(LEController::SetAdvertisingEnable),
            0xb  => Ok(LEController::SetScanParameters),
            0xC  => Ok(LEController::SetScanEnable),
            0xD  => Ok(LEController::CreateConnection),
            0xe  => Ok(LEController::CreateConnectionCancel),
            0xf  => Ok(LEController::ReadWhiteListSize),
            0x10 => Ok(LEController::ClearWhiteList),
            0x11 => Ok(LEController::AddDeviceToWhiteList),
            0x12 => Ok(LEController::RemoveDeviceFromWhiteList),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_code_test() {
        let ogf = 0x8;
        let ocf = 0xa;
        let oc  = HCICommand::LEController(LEController::SetAdvertisingEnable);

        assert_eq!( oc, HCICommand::try_from( OpCodePair{ ogf, ocf } ).unwrap() );
    }
}
