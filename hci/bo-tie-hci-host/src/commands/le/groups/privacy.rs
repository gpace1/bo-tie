//! LE Privacy Commands

/// Identity Address Type
///
/// This is used to label the peer address as either a Public Address or a Static Random Address
#[derive(Debug, Copy, Clone)]
pub enum PeerIdentityAddressType {
    PublicIdentityAddress,
    RandomStaticIdentityAddress,
}

impl PeerIdentityAddressType {
    fn val(&self) -> u8 {
        match self {
            Self::PublicIdentityAddress => 0x0,
            Self::RandomStaticIdentityAddress => 0x1,
        }
    }
}

/// LE Set Address Resolution Enable command
pub mod set_address_resolution_enable {
    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::LEController(opcodes::LEController::SetAddressResolutionEnable);

    struct Parameter {
        enable: bool,
    }

    impl CommandParameter<1> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 1] {
            if self.enable {
                [1]
            } else {
                [0]
            }
        }
    }

    /// Send the LE Set Address Resolution Enable command
    pub async fn send<H: HostChannelEnds>(host: &mut Host<H>, enable: bool) -> Result<(), CommandError<H>> {
        let parameter = Parameter { enable };

        host.send_command_expect_complete(parameter).await
    }
}

/// LE Set Resolvable Private Address Timeout command
pub mod set_resolvable_private_address_timeout {
    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};
    use core::time::Duration;

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::LEController(opcodes::LEController::SetResolvablePrivateAddressTimeout);

    struct Parameter {
        time_out: u16,
    }

    impl CommandParameter<2> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 2] {
            self.time_out.to_le_bytes()
        }
    }

    pub enum RpaTimeoutCommandError<H>
    where
        H: HostChannelEnds,
    {
        TooSmall(Duration),
        TooLarge(Duration),
        CommandError(CommandError<H>),
    }

    impl<H> core::fmt::Debug for RpaTimeoutCommandError<H>
    where
        H: HostChannelEnds,
        CommandError<H>: core::fmt::Debug,
    {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            match self {
                RpaTimeoutCommandError::TooSmall(d) => f.debug_tuple("TooSmall").field(d).finish(),
                RpaTimeoutCommandError::TooLarge(d) => f.debug_tuple("TooLarge").field(d).finish(),
                RpaTimeoutCommandError::CommandError(e) => f.debug_tuple("CommandError").field(e).finish(),
            }
        }
    }

    impl<H> core::fmt::Display for RpaTimeoutCommandError<H>
    where
        H: HostChannelEnds,
        CommandError<H>: core::fmt::Display,
    {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            match self {
                RpaTimeoutCommandError::TooSmall(_) => f.write_str("timeout duration is less than one second"),
                RpaTimeoutCommandError::TooLarge(_) => f.write_str("timeout duration is larger than one hour"),
                RpaTimeoutCommandError::CommandError(c) => core::fmt::Display::fmt(c, f),
            }
        }
    }

    impl<H> From<CommandError<H>> for RpaTimeoutCommandError<H>
    where
        H: HostChannelEnds,
    {
        fn from(ce: CommandError<H>) -> Self {
            Self::CommandError(ce)
        }
    }

    /// Send the LE Set Resolvable Private Address Timeout command
    ///
    /// This is used to set the timeout in the controller to generate a new resolvable private
    /// address. The input `time_out` is within the range of one second to one hour rounded down to
    /// the second. Any value outside of that range cause an error to be returned (see
    /// #Note for the exception)
    ///
    /// # Note
    /// Using the [`Default`](core::default::Default) value of `Duration` for the input `time_out`
    /// will set the resolvable private address timeout to it's default value of 15 minutes.
    pub async fn send<H: HostChannelEnds>(
        host: &mut Host<H>,
        time_out: Duration,
    ) -> Result<(), RpaTimeoutCommandError<H>> {
        let time_out = if time_out == Duration::default() {
            0x384
        } else if time_out < Duration::from_secs(1) {
            return Err(RpaTimeoutCommandError::TooSmall(time_out));
        } else if time_out > Duration::from_secs(60 * 60) {
            return Err(RpaTimeoutCommandError::TooLarge(time_out));
        } else {
            time_out.as_secs() as u16
        };

        let parameter = Parameter { time_out };

        host.send_command_expect_complete(parameter).await.map_err(|e| e.into())
    }
}

/// LE Add Device To Resolving List command
pub mod add_device_to_resolving_list {
    use super::PeerIdentityAddressType;
    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::LEController(opcodes::LEController::AddDeviceToResolvingList);

    /// Parameters for the LE Add Device To Resolving List command
    pub struct Parameter {
        pub peer_identity_address_type: PeerIdentityAddressType,
        pub peer_identity_address: bo_tie_core::BluetoothDeviceAddress,
        pub peer_irk: u128,
        pub local_irk: u128,
    }

    impl CommandParameter<39> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 39] {
            let mut parameter = [0u8; 39];

            parameter[0] = self.peer_identity_address_type.val();

            parameter[1..7].copy_from_slice(&self.peer_identity_address);

            parameter[7..23].copy_from_slice(&self.peer_irk.to_le_bytes());

            parameter[23..].copy_from_slice(&self.local_irk.to_le_bytes());

            parameter
        }
    }

    /// Send the LE Add Device To Resolving List command
    pub async fn send<H: HostChannelEnds>(host: &mut Host<H>, parameter: Parameter) -> Result<(), CommandError<H>> {
        host.send_command_expect_complete(parameter).await
    }
}

/// LE Remove Device To Resolving List command
pub mod remove_device_from_resolving_list {
    use super::PeerIdentityAddressType;
    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::LEController(opcodes::LEController::RemoveDeviceFromResolvingList);

    pub struct Parameter {
        pub peer_identity_address_type: PeerIdentityAddressType,
        pub peer_identity_address: bo_tie_core::BluetoothDeviceAddress,
    }

    impl CommandParameter<7> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 7] {
            let mut parameter = [0u8; 7];

            parameter[0] = self.peer_identity_address_type.val();

            parameter[1..].copy_from_slice(&self.peer_identity_address);

            parameter
        }
    }

    /// Send the LE Remove Device To Resolving List command
    pub async fn send<H: HostChannelEnds>(host: &mut Host<H>, parameter: Parameter) -> Result<(), CommandError<H>> {
        host.send_command_expect_complete(parameter).await
    }
}

/// LE Clear Resolving List command
pub mod clear_resolving_list {
    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::ClearResolvingList);

    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Send the LE Clear Resolving List command
    pub async fn send<H: HostChannelEnds>(host: &mut Host<H>) -> Result<(), CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

/// LE Set Privacy Mode command
pub mod set_privacy_mode {
    use super::PeerIdentityAddressType;
    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::SetPrivacyMode);

    pub enum PrivacyMode {
        NetworkPrivacy,
        DevicePrivacy,
    }

    impl PrivacyMode {
        fn val(&self) -> u8 {
            match self {
                Self::NetworkPrivacy => 0x0,
                Self::DevicePrivacy => 0x1,
            }
        }
    }

    pub struct Parameter {
        pub peer_identity_address_type: PeerIdentityAddressType,
        pub peer_identity_address: bo_tie_core::BluetoothDeviceAddress,
        pub privacy_mode: PrivacyMode,
    }

    impl CommandParameter<8> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 8] {
            let mut parameter = [0u8; 8];

            parameter[0] = self.peer_identity_address_type.val();

            parameter[1..7].copy_from_slice(&self.peer_identity_address);

            parameter[7] = self.privacy_mode.val();

            parameter
        }
    }

    pub async fn send<H: HostChannelEnds>(host: &mut Host<H>, parameter: Parameter) -> Result<(), CommandError<H>> {
        host.send_command_expect_complete(parameter).await
    }
}
