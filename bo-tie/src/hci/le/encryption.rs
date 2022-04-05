/// Encrypt 16 bytes of plain text with the provided key
///
/// The controller uses AES-128 to encrypt the data. Once the controller is done encrypting
/// the plain text, the [`Command Complete`](crate::hci::events::Events::CommandComplete) event will
/// return with the cypher text generated.
pub mod encrypt {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::Encrypt);

    #[repr(packed)]
    struct CommandReturn {
        status: u8,
        cypher_text: [u8; 16],
    }

    #[repr(packed)]
    #[derive(Clone)]
    struct Parameter {
        _key: [u8; 16],
        _plain_text: [u8; 16],
    }

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            self.clone()
        }
    }

    pub struct Cypher {
        pub cypher_text: [u8; 16],
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl Cypher {
        fn try_from((packed, cnt): (CommandReturn, u8)) -> Result<Self, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(Self {
                    cypher_text: packed.cypher_text,
                    completed_packets_cnt: cnt.into(),
                })
            } else {
                Err(status)
            }
        }
    }

    impl crate::hci::FlowControlInfo for Cypher {
        fn packet_space(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    impl_get_data_for_command!(COMMAND, CommandReturn, Cypher, error::Error);

    impl_command_complete_future!(Cypher, error::Error);

    /// Send the command to start encrypting the `plain_text`
    ///
    /// The input 'key' should be in native byte order.
    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hci: &'a HostInterface<T>,
        key: u128,
        plain_text: [u8; 16],
    ) -> impl Future<Output = Result<Cypher, impl Display + Debug>> + 'a
    where
        T: PlatformInterface,
    {
        let parameter = Parameter {
            _key: key.to_be_bytes(),
            _plain_text: plain_text,
        };

        ReturnedFuture(hci.send_command(parameter, events::Events::CommandComplete))
    }
}

pub mod long_term_key_request_reply {
    use crate::hci::common::ConnectionHandle;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::LEController(opcodes::LEController::LongTermKeyRequestReply);

    #[repr(packed)]
    struct CommandReturn {
        status: u8,
        handle: u16,
    }

    struct Parameter {
        handle: ConnectionHandle,
        /// Long Term Key
        ltk: u128,
    }

    #[repr(packed)]
    #[allow(dead_code)]
    struct CmdParameter {
        handle: u16,
        ltk: u128,
    }

    impl CommandParameter for Parameter {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            CmdParameter {
                handle: self.handle.get_raw_handle().to_le(),
                ltk: self.ltk.to_le(),
            }
        }
    }

    pub struct Return {
        pub connection_handle: ConnectionHandle,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl Return {
        fn try_from((packed, cnt): (CommandReturn, u8)) -> Result<Self, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(Self {
                    connection_handle: ConnectionHandle::try_from(packed.handle)?,
                    completed_packets_cnt: cnt.into(),
                })
            } else {
                Err(status)
            }
        }
    }

    impl crate::hci::FlowControlInfo for Return {
        fn packet_space(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    impl_get_data_for_command!(COMMAND, CommandReturn, Return, error::Error);

    impl_command_complete_future!(Return, error::Error);

    /// Send the command to Long Term Key
    ///
    /// The input `long_term_key` is the encryption (cypher) secret key and it is in native byte
    /// order
    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hci: &'a HostInterface<T>,
        connection_handle: ConnectionHandle,
        long_term_key: u128,
    ) -> impl Future<Output = Result<Return, impl Display + Debug>> + 'a
    where
        T: PlatformInterface,
    {
        let parameter = Parameter {
            handle: connection_handle,
            ltk: long_term_key,
        };

        ReturnedFuture(hci.send_command(parameter, events::Events::CommandComplete))
    }
}

pub mod long_term_key_request_negative_reply {
    use crate::hci::common::ConnectionHandle;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::LEController(opcodes::LEController::LongTermKeyRequestNegativeReply);

    #[repr(packed)]
    struct CommandReturn {
        status: u8,
        handle: u16,
    }

    struct Parameter {
        handle: ConnectionHandle,
    }

    #[repr(packed)]
    #[allow(dead_code)]
    struct CmdParameter {
        handle: u16,
    }

    impl CommandParameter for Parameter {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            CmdParameter {
                handle: self.handle.get_raw_handle(),
            }
        }
    }

    pub struct Return {
        pub connection_handle: ConnectionHandle,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl Return {
        fn try_from((packed, cnt): (CommandReturn, u8)) -> Result<Self, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(Self {
                    connection_handle: ConnectionHandle::try_from(packed.handle)?,
                    completed_packets_cnt: cnt.into(),
                })
            } else {
                Err(status)
            }
        }
    }

    impl crate::hci::FlowControlInfo for Return {
        fn packet_space(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    impl_get_data_for_command!(COMMAND, CommandReturn, Return, error::Error);

    impl_command_complete_future!(Return, error::Error);

    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hci: &'a HostInterface<T>,
        connection_handle: ConnectionHandle,
    ) -> impl Future<Output = Result<Return, impl Display + Debug>> + 'a
    where
        T: PlatformInterface,
    {
        let parameter = Parameter {
            handle: connection_handle,
        };

        ReturnedFuture(hci.send_command(parameter, events::Events::CommandComplete))
    }
}

pub mod rand {
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::Rand);

    #[repr(packed)]
    struct CommandReturn {
        status: u8,
        random: u64,
    }

    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = ();
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            ()
        }
    }

    pub struct Return {
        pub random_number: u64,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl From<Return> for u64 {
        fn from(ret: Return) -> Self {
            ret.random_number
        }
    }

    impl Return {
        fn try_from((packed, cnt): (CommandReturn, u8)) -> Result<Self, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(Self {
                    random_number: packed.random,
                    completed_packets_cnt: cnt.into(),
                })
            } else {
                Err(status)
            }
        }
    }

    impl crate::hci::FlowControlInfo for Return {
        fn packet_space(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    impl_get_data_for_command!(COMMAND, CommandReturn, Return, error::Error);

    impl_command_complete_future!(Return, error::Error);

    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hci: &'a HostInterface<T>,
    ) -> impl Future<Output = Result<Return, impl Display + Debug>> + 'a
    where
        T: PlatformInterface,
    {
        ReturnedFuture(hci.send_command(Parameter, events::Events::CommandComplete))
    }
}

/// Start or restart encryption of the data
///
/// This will either start encryption or restart the encryption of data by the controller.
///
/// # Events
/// When encryption has been started, the event
/// [Encryption Change](crate::hci::events::Events::EncryptionChange) will be sent from the controller
/// to indicate that data will now be encrypted. If the connection was already encrypted,
/// sending this command will instead cause the controller to issue the
/// [Encryption Key Refresh](crate::hci::events::Events::EncryptionKeyRefreshComplete) event once the
/// encryption is updated.
pub mod enable_encryption {
    use crate::hci::common::ConnectionHandle;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::StartEncryption);

    #[derive(Debug, Clone, Copy)]
    pub struct Parameter {
        pub handle: ConnectionHandle,
        pub random_number: u64,
        pub encrypted_diversifier: u16,
        pub long_term_key: u128,
    }

    #[repr(packed)]
    #[doc(hidden)]
    #[allow(dead_code)]
    pub struct CmdParameter {
        handle: u16,
        rand: u64,
        ediv: u16,
        ltk: u128,
    }

    impl CommandParameter for Parameter {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            CmdParameter {
                handle: self.handle.get_raw_handle(),
                rand: self.random_number,
                ediv: self.encrypted_diversifier,
                ltk: self.long_term_key,
            }
        }
    }

    impl_command_status_future!();

    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hci: &'a HostInterface<T>,
        parameter: Parameter,
    ) -> impl Future<Output = Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where
        T: PlatformInterface,
    {
        ReturnedFuture(hci.send_command(parameter, events::Events::CommandStatus))
    }
}
