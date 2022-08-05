//! Link Control Commands

/// Query a connected device for its Controller's version information
pub mod read_remote_version_information {

    use crate::hci::common::ConnectionHandle;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::LinkControl(opcodes::LinkControl::ReadRemoteVersionInformation);

    struct CmdParameter(ConnectionHandle);

    impl CommandParameter<2> for CmdParameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 2] {
            self.0.get_raw_handle().to_le_bytes()
        }
    }

    /// Read the version information of the connected device by its connection handle.
    ///
    /// The returned future awaits until the controller responds with a
    /// [`CommandStatus`](events::Events::CommandStatus) event. The event
    /// [`ReadRemoteVersionInformationComplete`](events::Events::ReadRemoteVersionInformationComplete)
    /// must be awaited upon by the `host` to get the version information of the remote controller.
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        connection_handle: ConnectionHandle,
    ) -> Result<impl FlowControlInfo, CommandError<H>> {
        host.send_command_expect_status(CmdParameter(connection_handle)).await
    }
}

/// Disconnect a remote device
pub mod disconnect {
    use crate::hci::common::ConnectionHandle;
    use crate::hci::*;
    use core::convert::TryFrom;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LinkControl(opcodes::LinkControl::Disconnect);

    /// These are the error codes that are given as reasons for disconnecting
    ///
    /// These enumerations are the acceptable error codes to be used as reasons for
    /// triggering the disconnect.
    pub enum DisconnectReason {
        AuthenticationFailure,
        RemoteUserTerminatedConnection,
        RemoteDeviceTerminatedConnectionDueToLowResources,
        RemoteDeviceTerminatedConnectionDueToPowerOff,
        UnsupportedRemoteFeature,
        PairingWithUnitKeyNotSupported,
        UnacceptableConnectionParameters,
    }

    impl DisconnectReason {
        fn try_from_hci_error(error: error::Error) -> Result<DisconnectReason, ConversionError> {
            match error {
                error::Error::AuthenticationFailure => Ok(DisconnectReason::AuthenticationFailure),
                error::Error::RemoteUserTerminatedConnection => Ok(DisconnectReason::RemoteUserTerminatedConnection),
                error::Error::RemoteDeviceTerminatedConnectionDueToLowResources => {
                    Ok(DisconnectReason::RemoteDeviceTerminatedConnectionDueToLowResources)
                }
                error::Error::RemoteDeviceTerminatedConnectionDueToPowerOff => {
                    Ok(DisconnectReason::RemoteDeviceTerminatedConnectionDueToPowerOff)
                }
                error::Error::UnsupportedRemoteFeatureOrUnsupportedLMPFeature => {
                    Ok(DisconnectReason::UnsupportedRemoteFeature)
                }
                error::Error::PairingWithUnitKeyNotSupported => Ok(DisconnectReason::PairingWithUnitKeyNotSupported),
                error::Error::UnacceptableConnectionParameters => {
                    Ok(DisconnectReason::UnacceptableConnectionParameters)
                }
                _ => Err(ConversionError),
            }
        }

        fn get_val(&self) -> u8 {
            match *self {
                DisconnectReason::AuthenticationFailure => 0x05,
                DisconnectReason::RemoteUserTerminatedConnection => 0x13,
                DisconnectReason::RemoteDeviceTerminatedConnectionDueToLowResources => 0x14,
                DisconnectReason::RemoteDeviceTerminatedConnectionDueToPowerOff => 0x15,
                DisconnectReason::UnsupportedRemoteFeature => 0x1A,
                DisconnectReason::PairingWithUnitKeyNotSupported => 0x29,
                DisconnectReason::UnacceptableConnectionParameters => 0x3B,
            }
        }
    }

    impl TryFrom<error::Error> for DisconnectReason {
        type Error = ConversionError;

        fn try_from(value: error::Error) -> Result<Self, Self::Error> {
            DisconnectReason::try_from_hci_error(value)
        }
    }

    /// Error for when an [`Error`](error::Error) cannot be converted into a [`DisconnectReason`]
    pub struct ConversionError;

    impl core::fmt::Debug for DisconnectReason {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            f.write_str("No Disconnect reason for error")
        }
    }

    impl core::fmt::Display for DisconnectReason {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            core::fmt::Debug::fmt(self, f)
        }
    }

    pub struct DisconnectParameters {
        pub connection_handle: ConnectionHandle,
        pub disconnect_reason: DisconnectReason,
    }

    impl CommandParameter<3> for DisconnectParameters {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 3] {
            let [b0, b1] = self.connection_handle.get_raw_handle().to_le_bytes();

            let b2 = self.disconnect_reason.get_val();

            [b0, b1, b2]
        }
    }

    /// Disconnect the device
    ///
    /// The returned future awaits until the controller responds with a
    /// [`CommandStatus`](events::Events::CommandStatus) event. This does not mean the remote device
    /// is disconnected. The event
    /// [`DisconnectionComplete`](events::Events::DisconnectionComplete)
    /// must be awaited upon by the `host` to know the device has disconnected.
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        parameter: DisconnectParameters,
    ) -> Result<impl FlowControlInfo, CommandError<H>> {
        host.send_command_expect_status(parameter).await
    }
}
