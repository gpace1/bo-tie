mod advertise;
mod connection;
mod io;
mod security;
mod server;

use crate::io::{ConnectedStatus, UserInOut};
use crate::security::SecurityStage;
use crate::server::HeartRateMeasurementArc;
use bo_tie::hci::channel::SendAndSyncSafeHostChannelEnds;
use bo_tie::hci::commands::le::long_term_key_request_negative_reply;
use bo_tie::hci::commands::link_control::disconnect;
use bo_tie::hci::events::{Events, LeMeta};
use bo_tie::hci::{Connection, ConnectionHandle, Host, HostChannelEnds, Next};
use bo_tie::BluetoothDeviceAddress;

const EXAMPLE_NAME: &'static str = "heart rate profile example";

#[cfg(target_os = "linux")]
macro_rules! create_hci {
    () => {
        // By using `None` with bo_tie_linux::new, the first
        // Bluetooth adapter found is the adapter that is used
        bo_tie_linux::new(None)
    };
}

#[cfg(not(target_os = "linux"))]
macro_rules! create_hci {
    () => {
        compile_error!("unsupported target for this example")
    };
}

/// Handle to an active connection async task
struct ConnectionTaskHandle {
    hci_handle: ConnectionHandle,
    join_handle: tokio::task::JoinHandle<()>,
    to: tokio::sync::mpsc::UnboundedSender<MainToConnection>,
    address: BluetoothDeviceAddress,
    status: ConnectedStatus,
}

/// Messages sent from [`main`] to a connection
#[derive(Debug)]
enum MainToConnection {
    Encryption(bool),
    LtkRequest,
    PairingAccepted,
    PairingRejected,
    AuthenticationInput(AuthenticationInput),
    Exit, // synonymous to disconnect
}

#[derive(Debug)]
pub enum AuthenticationInput {
    Yes,
    No,
    Passkey([char; 6]),
    Cancel,
}

/// Message type sent from a connection to [`main`]
#[derive(Debug)]
struct ConnectionToMain {
    handle: ConnectionHandle,
    kind: ConnectionToMainMessage,
}

#[derive(Debug)]
enum ConnectionToMainMessage {
    LongTermKey(Option<u128>),
    Security(SecurityStage),
}

impl ConnectionToMain {
    async fn process<H>(self, host: &mut Host<H>, uio: &mut UserInOut, hrp: &mut HeartRateProfile)
    where
        H: HostChannelEnds,
    {
        match self.kind {
            ConnectionToMainMessage::LongTermKey(opt_ltk) => {
                hrp.on_long_term_key_response(host, self.handle, opt_ltk).await
            }
            ConnectionToMainMessage::Security(SecurityStage::AwaitUserAcceptPairingRequest) => {
                if let Ok(index) = hrp
                    .connections
                    .binary_search_by(|connection| connection.hci_handle.cmp(&self.handle))
                {
                    let address = hrp.connections[index].address;
                    let handle = hrp.connections[index].hci_handle;

                    if let Err(index) = hrp
                        .pairing
                        .binary_search_by(|pairing_info| pairing_info.0.cmp(&address))
                    {
                        hrp.pairing.insert(index, (address, handle))
                    }

                    uio.on_request_pairing(address).await.unwrap();
                }
            }
            ConnectionToMainMessage::Security(SecurityStage::AuthenticationNumberComparison(num)) => {
                uio.on_number_comparison(num).await.unwrap();
            }
            ConnectionToMainMessage::Security(SecurityStage::AuthenticationPasskeyInput) => {
                uio.on_passkey_input().await.unwrap()
            }
            ConnectionToMainMessage::Security(SecurityStage::AuthenticationPasskeyOutput(passkey)) => {
                uio.on_passkey_output(passkey).await.unwrap();
            }
            ConnectionToMainMessage::Security(SecurityStage::BondingComplete) => {
                if let Ok(index) = hrp
                    .connections
                    .binary_search_by(|connection| connection.hci_handle.cmp(&self.handle))
                {
                    let address = hrp.connections[index].address;

                    uio.on_bonded(address).await.unwrap();
                }
            }
            ConnectionToMainMessage::Security(SecurityStage::PairingComplete) => {
                if let Ok(index) = hrp
                    .connections
                    .binary_search_by(|connection| connection.hci_handle.cmp(&self.handle))
                {
                    let address = &hrp.connections[index].address;

                    if let Ok(index) = hrp
                        .pairing
                        .binary_search_by(|pairing_info| pairing_info.0.cmp(&address))
                    {
                        hrp.pairing.remove(index);
                    }
                }
            }
            ConnectionToMainMessage::Security(SecurityStage::PairingFailed(reason)) => {
                if let Ok(index) = hrp
                    .connections
                    .binary_search_by(|connection| connection.hci_handle.cmp(&self.handle))
                {
                    let address = hrp.connections[index].address;

                    if let Err(index) = hrp
                        .pairing
                        .binary_search_by(|pairing_info| pairing_info.0.cmp(&address))
                    {
                        hrp.pairing.remove(index);
                    }

                    uio.on_pairing_failed(address, reason).await.unwrap();
                }
            }
        }
    }
}

struct HeartRateProfile {
    keys_store: security::KeysStore,
    heart_rate_measurement_arc: HeartRateMeasurementArc,
    privacy: advertise::privacy::Privacy,
    discoverable_address: Option<BluetoothDeviceAddress>,
    connections: Vec<ConnectionTaskHandle>,
    pairing: Vec<(BluetoothDeviceAddress, ConnectionHandle)>,
    from_connection_sender: tokio::sync::mpsc::UnboundedSender<ConnectionToMain>,
    from_connection_receiver: Option<tokio::sync::mpsc::UnboundedReceiver<ConnectionToMain>>,
}

impl HeartRateProfile {
    /// HCI events enabled for the heart rate profile
    const ENABLED_EVENTS: [Events; 5] = [
        Events::DisconnectionComplete,
        Events::EncryptionChangeV1,
        Events::LeMeta(LeMeta::ConnectionComplete),
        Events::LeMeta(LeMeta::LongTermKeyRequest),
        Events::LeMeta(LeMeta::RemoteConnectionParameterRequest),
    ];

    pub async fn new<H: HostChannelEnds>(host: &mut Host<H>) -> Self {
        let privacy = advertise::privacy::Privacy::new(host).await;

        host.mask_events(Self::ENABLED_EVENTS).await.unwrap();

        let (keys_store, discoverable_address) = match security::KeysStore::load_keys() {
            Some(keys) => (keys, None),
            None => (
                security::KeysStore::init(),
                Some(BluetoothDeviceAddress::new_non_resolvable()),
            ),
        };

        let heart_rate_measurement_arc = HeartRateMeasurementArc::new();

        let connections = Vec::new();

        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();

        let pairing = Vec::new();

        Self {
            keys_store,
            heart_rate_measurement_arc,
            privacy,
            discoverable_address,
            connections,
            pairing,
            from_connection_sender: sender,
            from_connection_receiver: receiver.into(),
        }
    }

    pub fn take_connection_receiver(&mut self) -> Option<tokio::sync::mpsc::UnboundedReceiver<ConnectionToMain>> {
        self.from_connection_receiver.take()
    }

    fn get_connection_task(&self, connection_handle: &ConnectionHandle) -> Option<&ConnectionTaskHandle> {
        self.connections
            .binary_search_by(|ct| ct.hci_handle.cmp(connection_handle))
            .map(|index| &self.connections[index])
            .ok()
    }

    async fn on_connection<H: SendAndSyncSafeHostChannelEnds>(
        &mut self,
        host: &mut Host<H>,
        connection: Connection<H::SendAndSyncSafeConnectionChannelEnds>,
        user_io: &mut io::UserInOut,
    ) where
        <H as SendAndSyncSafeHostChannelEnds>::SendAndSyncSafeConnectionChannelEnds: 'static,
    {
        use security::{ConnectionKind, Security};

        let (security, status) = if let Some(identity) = self.privacy.validate(&connection) {
            let keys = self.keys_store.get(identity).await.unwrap().clone();

            let security = Security::new(self.keys_store.clone(), ConnectionKind::Identified(keys));

            let status = ConnectedStatus::Bonded;

            (security, status)
        } else if self.discoverable_address.is_some() {
            let peer_address = connection.get_peer_address();

            let is_random = connection.is_address_random();

            let connection_kind = ConnectionKind::New {
                peer_address,
                is_random,
            };

            let security = Security::new(self.keys_store.clone(), connection_kind);

            let status = ConnectedStatus::New;

            (security, status)
        } else {
            let disconnect_parameters = disconnect::DisconnectParameters {
                connection_handle: connection.get_handle(),
                disconnect_reason: disconnect::DisconnectReason::AuthenticationFailure,
            };

            disconnect::send(host, disconnect_parameters).await.unwrap();

            user_io
                .on_unauthenticated_connection(connection.get_peer_address())
                .await
                .unwrap();

            return;
        };

        user_io
            .on_connection(connection.get_peer_address(), status)
            .await
            .unwrap();

        let server = server::Server::new(self.heart_rate_measurement_arc.clone());

        let (to, from) = tokio::sync::mpsc::unbounded_channel();

        let hci_handle = connection.get_handle();

        let address = connection.get_peer_address();

        let le_l2cap = connection.try_into_le().unwrap();

        let connection_task =
            connection::Connection::new(le_l2cap, security, server, self.from_connection_sender.clone()).run(from);

        let join_handle = tokio::spawn(connection_task);

        let connection_handle = ConnectionTaskHandle {
            hci_handle,
            join_handle,
            to,
            address,
            status,
        };

        match self.connections.binary_search_by(|c| c.hci_handle.cmp(&hci_handle)) {
            Err(index) => self.connections.insert(index, connection_handle),
            Ok(_) => panic!("handle for connection already associated with a connection task"),
        };
    }

    async fn accept_pairing_from(&mut self, address: BluetoothDeviceAddress, user_io: &mut UserInOut) {
        match self.pairing.binary_search_by(|pairing| pairing.0.cmp(&address)) {
            Ok(index) => {
                let handle = &self.pairing[index].1;

                if let Ok(index) = self
                    .connections
                    .binary_search_by(|connection| connection.hci_handle.cmp(&handle))
                {
                    let message = MainToConnection::PairingAccepted;

                    self.connections[index].to.send(message).unwrap();
                } else {
                    user_io.device_not_connected_for_pairing(address).await.unwrap();
                }
            }
            Err(_) => {
                user_io.device_not_pairing(address).await.unwrap();
            }
        }
    }

    async fn exit<H: HostChannelEnds>(&mut self, host: &mut Host<H>) {
        for task in std::mem::take(&mut self.connections) {
            task.to.send(MainToConnection::Exit).unwrap();

            task.join_handle.await.unwrap();

            let disconnect_parameters = disconnect::DisconnectParameters {
                connection_handle: task.hci_handle,
                disconnect_reason: disconnect::DisconnectReason::RemoteUserTerminatedConnection,
            };

            disconnect::send(host, disconnect_parameters).await.unwrap()
        }
    }

    fn authentication_input(&mut self, address: &BluetoothDeviceAddress, ai: AuthenticationInput) {
        if let Ok(index) = self
            .pairing
            .binary_search_by(|pairing_info| pairing_info.0.cmp(address))
        {
            let handle = &self.pairing[index].1;

            let index = self
                .connections
                .binary_search_by(|connection| connection.hci_handle.cmp(handle))
                .unwrap();

            let message = MainToConnection::AuthenticationInput(ai);

            self.connections[index].to.send(message).unwrap();
        }
    }

    fn reject_all_pairing(&mut self) {
        for pairing_info in core::mem::take(&mut self.pairing) {
            if let Ok(index) = self
                .connections
                .binary_search_by(|connection| connection.hci_handle.cmp(&pairing_info.1))
            {
                self.connections[index]
                    .to
                    .send(MainToConnection::PairingRejected)
                    .unwrap();
            }
        }
    }

    fn reject_pairing(&mut self, rejected: &[BluetoothDeviceAddress]) {
        for reject in rejected {
            if let Ok(index) = self
                .pairing
                .binary_search_by(|pairing_info| pairing_info.0.cmp(&reject))
            {
                let handle = &self.connections[index].hci_handle;

                let index = self
                    .connections
                    .binary_search_by(|connection| connection.hci_handle.cmp(handle))
                    .unwrap();

                let message = MainToConnection::PairingRejected;

                self.connections[index].to.send(message).unwrap();
            }
        }
    }

    pub async fn on_user_action<H: HostChannelEnds>(
        &mut self,
        host: &mut Host<H>,
        user_action: io::UserAction,
        user_io: &mut UserInOut,
    ) {
        match user_action {
            io::UserAction::AdvertiseDiscoverable => advertise::discoverable_advertising_setup(host).await,
            io::UserAction::AdvertisePrivate => self.privacy.start_private_advertising(host).await,
            io::UserAction::NumberComparisonYes(address) => {
                self.authentication_input(&address, AuthenticationInput::Yes)
            }
            io::UserAction::NumberComparisonNo(address) => self.authentication_input(&address, AuthenticationInput::No),
            io::UserAction::PairingRejectAll => self.reject_all_pairing(),
            io::UserAction::PairingReject(rejected) => self.reject_pairing(&rejected),
            io::UserAction::PairingAccept(address) => self.accept_pairing_from(address, user_io).await,
            io::UserAction::PasskeyInput(passkey, address) => {
                self.authentication_input(&address, AuthenticationInput::Passkey(passkey))
            }
            io::UserAction::PasskeyCancel(address) => self.authentication_input(&address, AuthenticationInput::Cancel),
            io::UserAction::StopAdvertising => advertise::disable_advertising(host).await,
            io::UserAction::Exit => self.exit(host).await,
        }
    }

    async fn on_disconnect(&mut self, connection_handle: ConnectionHandle) {
        if let Ok(task) = self
            .connections
            .binary_search_by(|task| task.hci_handle.cmp(&connection_handle))
            .map(|index| self.connections.remove(index))
        {
            task.to.send(MainToConnection::Exit).unwrap()
        }
    }

    async fn on_encryption_change(
        &self,
        connection_handle: ConnectionHandle,
        encryption_enabled: bo_tie::hci::events::parameters::EncryptionEnabled,
    ) {
        if let Some(task) = self.get_connection_task(&connection_handle) {
            let encrypted = encryption_enabled.get_for_le().is_aes_ccm();

            let msg = MainToConnection::Encryption(encrypted);

            task.to.send(msg).unwrap()
        }
    }

    async fn on_long_term_key_request<H: HostChannelEnds>(
        &self,
        host: &mut Host<H>,
        connection_handle: ConnectionHandle,
    ) {
        if let Some(task) = self.get_connection_task(&connection_handle) {
            task.to.send(MainToConnection::LtkRequest).unwrap();
        } else {
            long_term_key_request_negative_reply::send(host, connection_handle)
                .await
                .unwrap();

            let disconnect_parameter = disconnect::DisconnectParameters {
                connection_handle,
                disconnect_reason: disconnect::DisconnectReason::RemoteDeviceTerminatedConnectionDueToPowerOff,
            };

            disconnect::send(host, disconnect_parameter).await.unwrap();
        }
    }

    async fn on_long_term_key_response<H: HostChannelEnds>(
        &self,
        host: &mut Host<H>,
        connection_handle: ConnectionHandle,
        ltk: Option<u128>,
    ) {
        use bo_tie::hci::commands::le::long_term_key_request_reply;

        match ltk {
            None => {
                long_term_key_request_negative_reply::send(host, connection_handle)
                    .await
                    .unwrap();
            }
            Some(ltk) => {
                long_term_key_request_reply::send(host, connection_handle, ltk)
                    .await
                    .unwrap();
            }
        }
    }

    async fn on_connection_parameters_request<H: HostChannelEnds>(
        &self,
        host: &mut Host<H>,
        connection_parameters: bo_tie::hci::events::parameters::LeRemoteConnectionParameterRequestData,
    ) {
        use bo_tie::hci::commands::le::remote_connection_parameter_request_reply;

        let parameters = remote_connection_parameter_request_reply::CommandParameters {
            handle: connection_parameters.connection_handle,
            interval_min: connection_parameters.minimum_interval,
            interval_max: connection_parameters.maximum_interval,
            latency: connection_parameters.latency,
            timeout: connection_parameters.timeout,
            ce_len: Default::default(),
        };

        remote_connection_parameter_request_reply::send(host, parameters)
            .await
            .unwrap();
    }

    pub async fn on_hci_next<H: SendAndSyncSafeHostChannelEnds>(
        &mut self,
        host: &mut Host<H>,
        next: Next<H::ConnectionChannelEnds>,
        user_io: &mut io::UserInOut,
    ) where
        <H as SendAndSyncSafeHostChannelEnds>::SendAndSyncSafeConnectionChannelEnds: 'static,
    {
        use bo_tie::hci::events::{EventsData, LeMetaData};

        match next {
            Next::Event(EventsData::DisconnectionComplete(d)) => self.on_disconnect(d.connection_handle).await,
            Next::Event(EventsData::EncryptionChangeV1(e)) => {
                self.on_encryption_change(e.connection_handle, e.encryption_enabled)
                    .await
            }
            Next::Event(EventsData::EncryptionChangeV2(e)) => {
                self.on_encryption_change(e.connection_handle, e.encryption_enabled)
                    .await
            }
            Next::Event(EventsData::LeMeta(LeMetaData::LongTermKeyRequest(r))) => {
                self.on_long_term_key_request(host, r.connection_handle).await
            }
            Next::Event(EventsData::LeMeta(LeMetaData::RemoteConnectionParameterRequest(c))) => {
                self.on_connection_parameters_request(host, c).await
            }
            Next::Event(_) => unreachable!(),
            Next::NewConnection(c) => self.on_connection(host, c, user_io).await,
        }
    }
}

#[tokio::main]
async fn main() {
    #[cfg(feature = "log")]
    {
        use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};

        TermLogger::init(
            LevelFilter::Trace,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        )
        .unwrap();
    }

    let mut user_io = io::UserInOut::new();

    let (ctrl_c_sender, mut ctrl_c_recv) = tokio::sync::mpsc::channel(1);

    ctrlc::set_handler(move || {
        ctrl_c_sender.try_send(()).ok();
    })
    .ok();

    let (interface, host_ends) = create_hci!();

    tokio::spawn(interface.run());

    let host = &mut Host::init(host_ends).await.unwrap();

    let mut hrp = HeartRateProfile::new(host).await;

    let mut connection_receiver = hrp.take_connection_receiver().unwrap();

    user_io.init_greeting().unwrap();

    loop {
        tokio::select! {
            user_action = user_io.await_user() => {
                let user_action = user_action.unwrap();

                if let io::UserAction::Exit = user_action {
                    break
                }

                hrp.on_user_action(host, user_action, &mut user_io).await;
            },

            host_next = host.next() => hrp.on_hci_next(host, host_next.unwrap(), &mut user_io).await,

            message = connection_receiver.recv() => message.unwrap().process(host, &mut user_io, &mut hrp).await,

            _ = ctrl_c_recv.recv() => break,
        }
    }

    advertise::disable_advertising(host).await;

    hrp.on_user_action(host, io::UserAction::Exit, &mut user_io).await;

    user_io.shutdown_io().await.unwrap();
}
