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
        pub rssi: i8,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl RSSIInfo {
        fn try_from((packed,cnt): (CmdReturn,u8)) -> Result<Self, error::Error > {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok( Self {
                    handle: ConnectionHandle::try_from(packed.handle)?,
                    rssi: packed.rssi,
                    completed_packets_cnt: cnt.into(),
                })
            }
            else {
                Err(status)
            }
        }
    }

    impl crate::hci::FlowControlInfo for RSSIInfo {
        fn packet_space(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    impl_get_data_for_command!(
            COMMAND,
            CmdReturn,
            RSSIInfo,
            error::Error
        );

    impl_command_complete_future!(RSSIInfo, error::Error);

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, handle: ConnectionHandle )
    -> impl Future<Output=Result<RSSIInfo, impl Display + Debug>> + 'a
    where T: HostControllerInterface
    {
        let parameter = Parameter {
            handle: handle.get_raw_handle()
        };

        ReturnedFuture( hci.send_command(parameter, events::Events::CommandComplete ) )
    }
}