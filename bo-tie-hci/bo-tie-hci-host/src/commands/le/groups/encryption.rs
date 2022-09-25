//! LE cryptography commands
//!
//! These commands are for accessing the cryptography hardware within the Bluetooth Controller.

/// Encrypt 16 bytes of plain text with the provided key
///
/// The controller uses AES-128 to encrypt the data. Once the controller is done encrypting
/// the plain text, the [`Command Complete`](crate::hci::events::Events::CommandComplete) event will
/// return with the cypher text generated.
pub mod encrypt {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostInterface, TryFromCommandComplete,
    };

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::Encrypt);

    struct Parameter {
        key: [u8; 16],
        plain_text: [u8; 16],
    }

    impl Parameter {
        /// Create a new `Parameter`
        fn new(key: u128, plain_text: [u8; 16]) -> Self {
            Self {
                // keys for aes (the cypher test function) are big endian
                key: key.to_be_bytes(),
                plain_text,
            }
        }
    }

    impl CommandParameter<32> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 32] {
            let mut parameter = [0u8; 32];

            parameter[..16].copy_from_slice(&self.key);
            parameter[16..].copy_from_slice(&self.plain_text);

            parameter
        }
    }

    pub struct Cypher {
        pub cypher_text: [u8; 16],
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for Cypher {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            if cc.return_parameter[1..].len() == 16 {
                let completed_packets_cnt = cc.number_of_hci_command_packets.into();

                let mut cypher_text = [0u8; 16];

                cypher_text.copy_from_slice(&cc.return_parameter[1..]);

                Ok(Self {
                    cypher_text,
                    completed_packets_cnt,
                })
            } else {
                Err(CCParameterError::InvalidEventParameter)
            }
        }
    }

    /// Send the LE Encrypt command
    ///
    /// # Note
    /// The input 'key' must be in native byte order.
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        key: u128,
        plain_text: [u8; 16],
    ) -> Result<Cypher, CommandError<H>> {
        let parameter = Parameter::new(key, plain_text);

        host.send_command_expect_complete(parameter).await
    }
}

/// LE Rand command
pub mod rand {
    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostInterface, TryFromCommandComplete,
    };

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::Rand);

    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    pub struct Random {
        pub random_number: u64,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl From<Random> for u64 {
        fn from(ret: Random) -> Self {
            ret.random_number
        }
    }

    impl TryFromCommandComplete for Random {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            const U64_SIZE: usize = core::mem::size_of::<u64>();

            check_status!(cc.return_parameter);

            if cc.return_parameter[1..].len() == U64_SIZE {
                let mut rand_bytes = [0u8; U64_SIZE];

                rand_bytes.copy_from_slice(&cc.return_parameter[1..]);

                let random_number = <u64>::from_le_bytes(rand_bytes);

                let completed_packets_cnt = cc.number_of_hci_command_packets.into();

                Ok(Self {
                    random_number,
                    completed_packets_cnt,
                })
            } else {
                Err(CCParameterError::InvalidEventParameter)
            }
        }
    }

    /// Send the LE Rand command
    pub async fn send<H: HostInterface>(host: &mut Host<H>) -> Result<Random, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

/// LE Enable Encryption command
pub mod enable_encryption {
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostInterface, TryFromCommandComplete,
    };
    use bo_tie_hci_util::ConnectionHandle;

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::StartEncryption);

    pub struct Parameter {
        connection_handle: ConnectionHandle,
        random_number: u64,
        encrypted_diversifier: u16,
        long_term_key: u128,
    }

    impl Parameter {
        /// Create a `Parameter` for a Secure Connection
        ///
        /// This `Parameter` is used when the `long_term_key` was generated using a Bluetooth Secure
        /// Connection pairing method.
        pub fn new_sc(connection_handle: ConnectionHandle, long_term_key: u128) -> Self {
            let random_number = 0;

            let encrypted_diversifier = 0;

            Self {
                connection_handle,
                random_number,
                encrypted_diversifier,
                long_term_key,
            }
        }

        /// Create a `Parameter` for legacy encryption
        ///
        /// This `Parameter` is used when the `long_term_key` was generated using a Bluetooth Legacy
        /// pairing method.
        pub fn new_legacy(
            connection_handle: ConnectionHandle,
            random_number: u64,
            encrypted_diversifier: u16,
            long_term_key: u128,
        ) -> Self {
            Self {
                connection_handle,
                random_number,
                encrypted_diversifier,
                long_term_key,
            }
        }
    }

    impl CommandParameter<28> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 28] {
            let mut parameter = [0u8; 28];

            parameter[..2].copy_from_slice(&self.connection_handle.get_raw_handle().to_le_bytes());

            parameter[2..10].copy_from_slice(&self.random_number.to_le_bytes());

            parameter[10..12].copy_from_slice(&self.encrypted_diversifier.to_le_bytes());

            parameter[12..28].copy_from_slice(&self.long_term_key.to_le_bytes());

            parameter
        }
    }

    /// Send the LE Enable Encryption command
    ///
    /// The `parameter` should be created with the method [`Parameter::new_sc`] if a Secure
    /// Connections pairing method was used to create the long term key. Otherwise `parameter` must
    /// be created with method [`Parameter::new_legacy`] when a legacy pairing method was used.
    ///
    /// The returned future awaits until the controller responds with a
    /// [`CommandStatus`](events::Events::CommandStatus) event. When encryption is established to
    /// the connected device, the event
    /// [EncryptionChange](crate::hci::events::Events::EncryptionChange) will be sent from the
    /// controller to indicate that data will now be encrypted. If the connection was already
    /// encrypted, sending this command will instead cause the controller to issue the
    /// [EncryptionKeyRefreshComplete](crate::hci::events::Events::EncryptionKeyRefreshComplete)
    /// event once the encryption is updated.
    pub async fn send<H: HostInterface>(host: &mut Host<H>, parameter: Parameter) -> Result<(), CommandError<H>> {
        host.send_command_expect_status(parameter).await
    }
}

/// LE Long Term Key Request Reply command
pub mod long_term_key_request_reply {
    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostInterface, TryFromCommandComplete,
    };
    use bo_tie_hci_util::ConnectionHandle;

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::LEController(opcodes::LEController::LongTermKeyRequestReply);

    struct Parameter {
        connection_handle: ConnectionHandle,
        long_term_key: u128,
    }

    impl CommandParameter<18> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 18] {
            let mut parameter = [0u8; 18];

            parameter[..2].copy_from_slice(&self.connection_handle.get_raw_handle().to_le_bytes());

            parameter[2..].copy_from_slice(&self.long_term_key.to_le_bytes());

            parameter
        }
    }

    pub struct Return {
        pub connection_handle: ConnectionHandle,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for Return {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            let connection_handle = ConnectionHandle::try_from(<u16>::from_le_bytes([
                *cc.return_parameter
                    .get(1)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(2)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]))
            .map_err(|_| CCParameterError::InvalidEventParameter)?;

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                connection_handle,
                completed_packets_cnt,
            })
        }
    }

    /// Send the LE Long Term Key Request Reply command
    ///
    /// # Note
    /// The input 'long_term_key' must be in native byte order.
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        connection_handle: ConnectionHandle,
        long_term_key: u128,
    ) -> Result<Return, CommandError<H>> {
        let parameter = Parameter {
            connection_handle,
            long_term_key,
        };

        host.send_command_expect_complete(parameter).await
    }
}

/// LE Long Term Key Request Negative Reply Command
pub mod long_term_key_request_negative_reply {
    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostInterface, TryFromCommandComplete,
    };
    use bo_tie_hci_util::ConnectionHandle;

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::LEController(opcodes::LEController::LongTermKeyRequestNegativeReply);

    struct Parameter {
        connection_handle: ConnectionHandle,
    }

    impl CommandParameter<2> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 2] {
            self.connection_handle.get_raw_handle().to_le_bytes()
        }
    }

    pub struct Return {
        pub connection_handle: ConnectionHandle,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for Return {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            let connection_handle = ConnectionHandle::try_from(<u16>::from_le_bytes([
                *cc.return_parameter
                    .get(1)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(2)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]))
            .map_err(|_| CCParameterError::InvalidEventParameter)?;

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                connection_handle,
                completed_packets_cnt,
            })
        }
    }

    /// Send the LE Long Term Key Request Negative Reply Command
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        connection_handle: ConnectionHandle,
    ) -> Result<Return, CommandError<H>> {
        let parameter = Parameter { connection_handle };

        host.send_command_expect_complete(parameter).await
    }
}
