//! Link Control Commands

pub mod read_remote_version_information {

    use crate::hci::*;
    use crate::hci::common::ConnectionHandle;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LinkControl(opcodes::LinkControl::ReadRemoteVersionInformation);

    #[repr(packed)]
    #[derive( Clone, Copy)]
    struct CmdParameter {
        _connection_handle: u16
    }

    impl CommandParameter for CmdParameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter { *self }
    }

    impl_command_status_future!();

    #[bo_tie_macros::host_interface(flow_ctrl_bounds= "'static")]
    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, handle: ConnectionHandle)
    -> impl Future<Output=Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where T: HostControllerInterface
    {

        let parameter = CmdParameter {
            _connection_handle: handle.get_raw_handle()
        };

        ReturnedFuture( hci.send_command(parameter, events::Events::CommandStatus ) )
    }
}

// TODO when BR/EDR is enabled move this to a module for common features and import here
pub mod disconnect {
    use crate::hci::*;
    use crate::hci::common::ConnectionHandle;

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

        // TODO implement when HCI error codes are added, and add parameter for the
        // error enumeration name
        pub fn try_from_hci_error( error: error::Error ) -> Result<DisconnectReason, &'static str> {
            match error {
                error::Error::AuthenticationFailure => {
                    Ok(DisconnectReason::AuthenticationFailure)
                }
                error::Error::RemoteUserTerminatedConnection => {
                    Ok(DisconnectReason::RemoteUserTerminatedConnection)
                }
                error::Error::RemoteDeviceTerminatedConnectionDueToLowResources => {
                    Ok(DisconnectReason::RemoteDeviceTerminatedConnectionDueToLowResources)
                }
                error::Error::RemoteDeviceTerminatedConnectionDueToPowerOff => {
                    Ok(DisconnectReason::RemoteDeviceTerminatedConnectionDueToPowerOff)
                }
                error::Error::UnsupportedRemoteFeatureOrUnsupportedLMPFeature => {
                    Ok(DisconnectReason::UnsupportedRemoteFeature)
                }
                error::Error::PairingWithUnitKeyNotSupported => {
                    Ok(DisconnectReason::PairingWithUnitKeyNotSupported)
                }
                error::Error::UnacceptableConnectionParameters => {
                    Ok(DisconnectReason::UnacceptableConnectionParameters)
                }
                _ => {
                    Err("No Disconnect reason for error")
                }
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

    #[repr(packed)]
    #[doc(hidden)]
    pub struct CmdParameter {
        _handle: u16,
        _reason: u8,
    }

    pub struct DisconnectParameters {
        pub connection_handle: ConnectionHandle,
        pub disconnect_reason: DisconnectReason,
    }

    impl CommandParameter for DisconnectParameters {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            CmdParameter {
                _handle: self.connection_handle.get_raw_handle(),
                _reason: self.disconnect_reason.get_val(),
            }
        }
    }

    impl_command_status_future!();

    #[bo_tie_macros::host_interface(flow_ctrl_bounds= "'static")]
    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, dp: DisconnectParameters )
    -> impl Future<Output=Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(dp, events::Events::CommandStatus ) )
    }

}
