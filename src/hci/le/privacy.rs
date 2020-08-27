//! LE Privace Commands

/// Identity Address Type
///
/// This is used to label the peer address as either a Public Address or a Static Random Address
pub enum PeerIdentityAddressType {
    PublicIdentityAddress,
    RandomStaticIdentityAddress,
}

impl PeerIdentityAddressType {
    fn val(&self) -> u8 {
        match self {
            Self::PublicIdentityAddress => 0x0,
            Self::RandomStaticIdentityAddress => 0x1
        }
    }
}

pub mod set_resolvable_private_address_timeout {
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetResolvablePrivateAddressTimeout);

    #[repr(packed)]
    #[derive(Clone,Copy)]
    struct Parameter {
        time_out: u16
    }

    impl CommandParameter for Parameter {
        type Parameter = u16;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter { self.time_out.to_le() }
    }

    impl_status_return!(COMMAND);

    pub fn send<'a, I: 'static>(hci: &'a HostInterface<I>, time_out: u16)
    -> impl Future<Output=Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where I: HostControllerInterface
    {
        let parameter = Parameter { time_out };

        ReturnedFuture( hci.send_command( parameter, events::Events::CommandComplete ))
    }
}

pub mod set_address_resolution_enable {
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetAddressResolutionEnable);

    struct Parameter {
        enable: bool
    }

    impl CommandParameter for Parameter {
        type Parameter = u8;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter { if self.enable { 1 } else { 0 } }
    }

    impl_status_return!(COMMAND);

    pub fn send<'a, I: 'static>(hci: &'a HostInterface<I>, enable: bool)
    -> impl Future<Output=Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where I: HostControllerInterface
    {
        let parameter = Parameter { enable };

        ReturnedFuture( hci.send_command( parameter, events::Events::CommandComplete ))
    }
}

pub mod add_device_to_resolving_list {
    use crate::hci::*;
    pub use super::PeerIdentityAddressType;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::AddDeviceToResolvingList);

    #[repr(packed)]
    #[doc(hidden)]
    pub struct CmdParameter {
        _ident_type: u8,
        _peer_ident_addr: crate::BluetoothDeviceAddress,
        _peer_irk: u128,
        _local_irk: u128,
    }

    pub struct Parameter {
        pub identity_address_type: PeerIdentityAddressType,
        pub peer_identity_address: crate::BluetoothDeviceAddress,
        pub peer_irk: u128,
        pub local_irk: u128,
    }

    impl CommandParameter for Parameter {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            CmdParameter {
                _ident_type: self.identity_address_type.val(),
                _peer_ident_addr: self.peer_identity_address.clone(),
                _peer_irk: self.peer_irk.to_le(),
                _local_irk: self.local_irk.to_le(),
            }
        }
    }

    impl_status_return!(COMMAND);

    pub fn send<'a, I: 'static>(hci: &'a HostInterface<I>, parameter: Parameter)
    -> impl Future<Output=Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where I: HostControllerInterface
    {
        ReturnedFuture( hci.send_command( parameter, events::Events::CommandComplete ))
    }
}

pub mod remove_device_from_resolving_list {
    use crate::hci::*;
    pub use super::PeerIdentityAddressType;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::RemoveDeviceFromResolvingList);

    #[repr(packed)]
    #[doc(hidden)]
    pub struct CmdParameter {
        _ident_type: u8,
        _address: crate::BluetoothDeviceAddress,
    }

    pub struct Parameter {
        pub identity_address_type: PeerIdentityAddressType,
        pub peer_identity_address: crate::BluetoothDeviceAddress,
    }
    impl CommandParameter for Parameter {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            CmdParameter {
                _ident_type: self.identity_address_type.val(),
                _address: self.peer_identity_address.clone(),
            }
        }
    }

    impl_status_return!(COMMAND);

    pub fn send<'a, I: 'static>(hci: &'a HostInterface<I>, parameter: Parameter)
    -> impl Future<Output=Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where I: HostControllerInterface
    {
        ReturnedFuture( hci.send_command( parameter, events::Events::CommandComplete ))
    }
}

pub mod clear_resolving_list {
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ClearResolvingList);

    #[derive(Clone, Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter { *self }
    }

    impl_status_return!(COMMAND);

    pub fn send<'a, I: 'static>(hci: &'a HostInterface<I>)
    -> impl Future<Output=Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where I: HostControllerInterface
    {
        ReturnedFuture( hci.send_command( Parameter, events::Events::CommandComplete ))
    }
}

pub mod set_privacy_mode {
    use crate::hci::*;
    pub use super::PeerIdentityAddressType;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetPrivacyMode);

    pub enum PrivacyMode {
        NetworkPrivacy,
        DevicePrivacy
    }

    impl PrivacyMode {
        fn val(&self) -> u8 {
            match self {
                Self::NetworkPrivacy => 0x0,
                Self::DevicePrivacy => 0x1,
            }
        }
    }

    #[derive(Clone, Copy)]
    #[doc(hidden)]
    pub struct CmdParameter {
        _ty: u8,
        _addr: crate::BluetoothDeviceAddress,
        _mode: u8,
    }

    pub struct Parameter {
        peer_identity_address_type: PeerIdentityAddressType,
        peer_identity_address: crate::BluetoothDeviceAddress,
        privacy_mode: PrivacyMode,
    }

    impl CommandParameter for Parameter {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            CmdParameter {
                _ty: self.peer_identity_address_type.val(),
                _addr: self.peer_identity_address.clone(),
                _mode: self.privacy_mode.val(),
            }
        }
    }

    impl_status_return!(COMMAND);

    pub fn send<'a, I: 'static>(hci: &'a HostInterface<I>, parameter: Parameter )
    -> impl Future<Output=Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where I: HostControllerInterface
    {
        ReturnedFuture( hci.send_command( parameter, events::Events::CommandComplete ))
    }
}
