//! Status Parameter Commands

pub mod read_rssi {
    use crate::hci::*;
    use crate::hci::common::ConnectionHandle;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::StatusParameters(opcodes::StatusParameters::ReadRSSI);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        handle: u16,
        rssi: i8
    }

    struct Parameter {
        handle: u16
    }

    impl CommandParameter for Parameter {
        type Parameter = u16;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter { self.handle }
    }

    pub struct RSSIInfo {
        pub handle: ConnectionHandle,
        pub rssi: i8
    }

    impl RSSIInfo {
        fn try_from(packed: CmdReturn) -> Result<Self, error::Error > {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok( Self {
                    handle: ConnectionHandle::try_from(packed.handle)?,
                    rssi: packed.rssi
                })
            }
            else {
                Err(status)
            }
        }
    }

    impl_get_data_for_command!(
            COMMAND,
            CmdReturn,
            RSSIInfo,
            error::Error
        );

    impl_command_data_future!(RSSIInfo, error::Error);

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, handle: ConnectionHandle )
                                 -> impl Future<Output=Result<RSSIInfo, impl Display + Debug>> + 'a
        where T: HostControllerInterface
    {
        let parameter = Parameter {
            handle: handle.get_raw_handle()
        };

        ReturnedFuture( hci.send_command(parameter, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }
}