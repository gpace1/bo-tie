mod advertise;
mod connection;
mod io;
mod security;
mod server;

use crate::io::MainToUserInput;
use crate::security::SecurityStage;
use crate::server::HeartRateMeasurementArc;
use bo_tie::hci::channel::{SendAndSyncSafeConnectionChannelEnds, SendAndSyncSafeHostChannelEnds};
use bo_tie::hci::commands::le::long_term_key_request_negative_reply;
use bo_tie::hci::commands::link_control::disconnect;
use bo_tie::hci::events::{Events, LeMeta};
use bo_tie::hci::{Connection, ConnectionHandle, Host, HostChannelEnds, Next};
use bo_tie::host::sm::IdentityAddress;
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
    status: connection::ConnectedStatus,
}

/// Messages sent from [`main`] to a connection
#[derive(Debug)]
enum MainToConnection {
    Encryption(bool),
    LtkRequest,
    PairingAccepted,
    PairingRejected,
    AuthenticationInput(AuthenticationInput),
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
    async fn process<H>(
        self,
        host: &mut Host<H>,
        to_ui: std::sync::mpsc::Sender<MainToUserInput>,
        hrp: &mut HeartRateProfile,
    ) where
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
                    let address = hrp.connections[index].status.get_address();
                    let handle = hrp.connections[index].hci_handle;

                    if let Err(index) = hrp
                        .pairing
                        .binary_search_by(|pairing_info| pairing_info.0.cmp(&address))
                    {
                        hrp.pairing.insert(index, (address, handle))
                    }

                    let pairing_devices = hrp.pairing.iter().map(|(address, _)| *address).collect::<Vec<_>>();

                    to_ui.send(MainToUserInput::PairingDevices(pairing_devices)).unwrap();

                    let output = io::Output::on_pairing_request(address);

                    to_ui.send(MainToUserInput::Output(output)).unwrap();
                }
            }
            ConnectionToMainMessage::Security(SecurityStage::AuthenticationNumberComparison(num)) => {
                if let Ok(index) = hrp
                    .connections
                    .binary_search_by(|connection| connection.hci_handle.cmp(&self.handle))
                {
                    let handle = hrp.connections[index].hci_handle;

                    hrp.authenticating = Some(handle);

                    to_ui
                        .send(MainToUserInput::Mode(io::Mode::NumberComparison(num)))
                        .unwrap();
                }
            }
            ConnectionToMainMessage::Security(SecurityStage::AuthenticationPasskeyInput) => {
                to_ui.send(MainToUserInput::Mode(io::Mode::PasskeyInput)).unwrap();
            }
            ConnectionToMainMessage::Security(SecurityStage::AuthenticationPasskeyOutput(passkey)) => {
                to_ui
                    .send(MainToUserInput::Mode(io::Mode::PasskeyOutput(passkey)))
                    .unwrap();
            }
            ConnectionToMainMessage::Security(SecurityStage::BondingComplete(identity)) => {
                if let Ok(index) = hrp
                    .connections
                    .binary_search_by(|connection| connection.hci_handle.cmp(&self.handle))
                {
                    let connection = &mut hrp.connections[index];

                    match connection.status {
                        connection::ConnectedStatus::New(old_address) => {
                            connection.status = connection::ConnectedStatus::Bonded(identity);

                            let output = io::Output::on_bonding_complete(old_address, identity);

                            to_ui.send(MainToUserInput::Output(output)).unwrap();
                        }
                        connection::ConnectedStatus::Bonded(old_identity) => {
                            hrp.privacy
                                .remove_device_from_resolving_list(host, &old_identity, true)
                                .await;

                            connection.status = connection::ConnectedStatus::Bonded(identity);

                            let output = io::Output::on_identity_change(old_identity, identity);

                            to_ui.send(MainToUserInput::Output(output)).unwrap();
                        }
                    }

                    to_ui
                        .send(MainToUserInput::BondedDevices(hrp.get_bonded_devices().await))
                        .unwrap();
                }
            }
            ConnectionToMainMessage::Security(SecurityStage::PairingComplete) => {
                if let Ok(index) = hrp
                    .connections
                    .binary_search_by(|connection| connection.hci_handle.cmp(&self.handle))
                {
                    let address = hrp.connections[index].status.get_address();

                    if let Ok(index) = hrp
                        .pairing
                        .binary_search_by(|pairing_info| pairing_info.0.cmp(&address))
                    {
                        hrp.pairing.remove(index);
                    }

                    let pairing_devices = hrp.pairing.iter().map(|(address, _)| *address).collect::<Vec<_>>();

                    to_ui.send(MainToUserInput::PairingDevices(pairing_devices)).unwrap();

                    let output = io::Output::on_pairing_complete(address);

                    to_ui.send(MainToUserInput::Output(output)).unwrap();
                }
            }
            ConnectionToMainMessage::Security(SecurityStage::PairingFailed(reason)) => {
                if let Ok(index) = hrp
                    .connections
                    .binary_search_by(|connection| connection.hci_handle.cmp(&self.handle))
                {
                    let address = hrp.connections[index].status.get_address();

                    if let Err(index) = hrp
                        .pairing
                        .binary_search_by(|pairing_info| pairing_info.0.cmp(&address))
                    {
                        hrp.pairing.remove(index);
                    }

                    let pairing_devices = hrp.pairing.iter().map(|(address, _)| *address).collect::<Vec<_>>();

                    to_ui.send(MainToUserInput::PairingDevices(pairing_devices)).unwrap();

                    let output = io::Output::on_pairing_failed(address, reason);

                    to_ui.send(MainToUserInput::Output(output)).unwrap();
                }
            }
        }
    }
}

struct HeartRateProfile {
    keys_store: security::KeysStore,
    heart_rate_measurement_arc: HeartRateMeasurementArc,
    privacy: advertise::privacy::Privacy,
    connections: Vec<ConnectionTaskHandle>,
    pairing: Vec<(BluetoothDeviceAddress, ConnectionHandle)>,
    authenticating: Option<ConnectionHandle>,
    from_connection_sender: tokio::sync::mpsc::UnboundedSender<ConnectionToMain>,
    from_connection_receiver: Option<tokio::sync::mpsc::UnboundedReceiver<ConnectionToMain>>,
    advertising_kind: advertise::Kind,
}

impl HeartRateProfile {
    /// HCI events enabled for the heart rate profile
    const ENABLED_EVENTS: [Events; 4] = [
        Events::DisconnectionComplete,
        Events::EncryptionChangeV1,
        Events::LeMeta(LeMeta::ConnectionComplete),
        Events::LeMeta(LeMeta::LongTermKeyRequest),
        //Events::LeMeta(LeMeta::RemoteConnectionParameterRequest),
    ];

    pub async fn new<H: HostChannelEnds>(host: &mut Host<H>, to_ui: std::sync::mpsc::Sender<MainToUserInput>) -> Self {
        let mut privacy = advertise::privacy::Privacy::new(host).await;

        host.mask_events(Self::ENABLED_EVENTS).await.unwrap();

        let (keys_store, advertising_kind) = match security::KeysStore::load_keys() {
            Some(keys) => {
                if keys.is_empty().await {
                    to_ui.send(MainToUserInput::Mode(io::Mode::Silent)).unwrap();

                    (keys, advertise::Kind::Off)
                } else {
                    for keys in keys.get_all().await.iter() {
                        privacy.add_device_to_resolving_list(host, keys).await
                    }

                    privacy.start_private_advertising(host).await;

                    to_ui.send(MainToUserInput::Mode(io::Mode::Private)).unwrap();

                    (keys, advertise::Kind::Private)
                }
            }
            None => (security::KeysStore::init(), advertise::Kind::Off),
        };

        let heart_rate_measurement_arc = HeartRateMeasurementArc::new();

        let connections = Vec::new();

        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();

        let pairing = Vec::new();

        let authenticating = None;

        Self {
            keys_store,
            heart_rate_measurement_arc,
            privacy,
            connections,
            pairing,
            authenticating,
            from_connection_sender: sender,
            from_connection_receiver: receiver.into(),
            advertising_kind,
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
        to_ui: std::sync::mpsc::Sender<MainToUserInput>,
    ) where
        <H as SendAndSyncSafeHostChannelEnds>::SendAndSyncSafeConnectionChannelEnds: 'static,
    {
        use security::{ConnectionKind, Security};

        if let Some(identity) = self.privacy.validate(&connection) {
            let keys = self.keys_store.get(identity).await.unwrap().clone();

            let security = Security::new(self.keys_store.clone(), ConnectionKind::Identified(keys));

            let status = connection::ConnectedStatus::Bonded(keys.get_peer_identity().unwrap());

            self.privacy
                .remove_device_from_resolving_list(host, &identity, false)
                .await;

            self.create_connection_task(connection, security, status);

            let output = io::Output::on_connection(status);

            to_ui.send(MainToUserInput::Output(output)).unwrap();
        } else if let advertise::Kind::Discoverable(advertising_address) = self.advertising_kind {
            let peer_address = connection.get_peer_address();

            let peer_is_random = connection.is_address_random();

            let connection_kind = ConnectionKind::New {
                advertising_address,
                peer_address,
                peer_is_random,
            };

            let security = Security::new(self.keys_store.clone(), connection_kind);

            let status = connection::ConnectedStatus::New(peer_address);

            self.create_connection_task(connection, security, status);

            let output = io::Output::on_connection(status);

            to_ui.send(MainToUserInput::Output(output)).unwrap();
        } else {
            // Note: this branch will (well... *should*) never be reached when
            // the controller is handling privacy. When privacy is implemented
            // by the host then there may be connections made to unauthenticated
            // devices.

            let disconnect_parameters = disconnect::DisconnectParameters {
                connection_handle: connection.get_handle(),
                disconnect_reason: disconnect::DisconnectReason::AuthenticationFailure,
            };

            disconnect::send(host, disconnect_parameters).await.unwrap();

            let output = io::Output::on_unauthenticated_connection(connection.get_peer_address());

            to_ui.send(MainToUserInput::Output(output)).unwrap();
        };

        // continue advertising, but in private mode
        self.advertising_kind = advertise::Kind::Private;

        self.privacy.start_private_advertising(host).await;

        to_ui.send(MainToUserInput::Mode(io::Mode::Private)).unwrap();
    }

    fn create_connection_task<C>(
        &mut self,
        connection: Connection<C>,
        security: security::Security,
        status: connection::ConnectedStatus,
    ) where
        C: SendAndSyncSafeConnectionChannelEnds + 'static,
    {
        let server = server::Server::new(self.heart_rate_measurement_arc.clone());

        let (to, from) = tokio::sync::mpsc::unbounded_channel();

        let hci_handle = connection.get_handle();

        let le_l2cap = connection.try_into_le().unwrap();

        let connection_task =
            connection::Connection::new(le_l2cap, security, server, self.from_connection_sender.clone()).run(from);

        let join_handle = tokio::spawn(connection_task);

        let connection_handle = ConnectionTaskHandle {
            hci_handle,
            join_handle,
            to,
            status,
        };

        match self.connections.binary_search_by(|c| c.hci_handle.cmp(&hci_handle)) {
            Err(index) => self.connections.insert(index, connection_handle),
            Ok(_) => panic!("handle for connection already associated with a connection task"),
        };
    }

    async fn accept_pairing_from(
        &mut self,
        address: BluetoothDeviceAddress,
        to_ui: std::sync::mpsc::Sender<MainToUserInput>,
    ) {
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
                    let output = io::Output::device_is_disconnected(address);

                    to_ui.send(MainToUserInput::Output(output)).unwrap()
                }
            }
            Err(_) => {
                let output = io::Output::device_not_pairing(address);

                to_ui.send(MainToUserInput::Output(output)).unwrap()
            }
        }
    }

    async fn exit<H: HostChannelEnds>(&mut self, host: &mut Host<H>) {
        for task in std::mem::take(&mut self.connections) {
            let disconnect_parameters = disconnect::DisconnectParameters {
                connection_handle: task.hci_handle,
                disconnect_reason: disconnect::DisconnectReason::RemoteUserTerminatedConnection,
            };

            disconnect::send(host, disconnect_parameters).await.unwrap();

            task.join_handle.await.unwrap();
        }
    }

    fn authentication_input(&mut self, ai: AuthenticationInput, to_ui: std::sync::mpsc::Sender<MainToUserInput>) {
        let handle = self.authenticating.take().unwrap();

        let index = self
            .connections
            .binary_search_by(|connection| connection.hci_handle.cmp(&handle))
            .unwrap();

        let message = MainToConnection::AuthenticationInput(ai);

        self.connections[index].to.send(message).unwrap();

        match self.advertising_kind {
            advertise::Kind::Off => to_ui.send(MainToUserInput::Mode(io::Mode::Silent)).unwrap(),
            advertise::Kind::Discoverable(_) => to_ui.send(MainToUserInput::Mode(io::Mode::Discoverable)).unwrap(),
            advertise::Kind::Private => to_ui.send(MainToUserInput::Mode(io::Mode::Private)).unwrap(),
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
        user_action: io::FromUserInput,
        to_ui: std::sync::mpsc::Sender<MainToUserInput>,
        timeout_tick: &mut advertise::privacy::TimeoutTick,
    ) {
        match user_action {
            io::FromUserInput::AdvertiseDiscoverable => {
                self.advertising_kind = advertise::discoverable_advertising_setup(host).await;

                to_ui.send(MainToUserInput::Mode(io::Mode::Discoverable)).unwrap();
            }
            io::FromUserInput::AdvertisePrivate => {
                *timeout_tick = self.privacy.set_timeout(host, None).await;

                self.privacy.start_private_advertising(host).await;

                self.advertising_kind = advertise::Kind::Private;

                to_ui.send(MainToUserInput::Mode(io::Mode::Private)).unwrap();
            }
            io::FromUserInput::NumberComparisonYes => self.authentication_input(AuthenticationInput::Yes, to_ui),
            io::FromUserInput::NumberComparisonNo => self.authentication_input(AuthenticationInput::No, to_ui),
            io::FromUserInput::PairingRejectAll => self.reject_all_pairing(),
            io::FromUserInput::PairingReject(rejected) => self.reject_pairing(&rejected),
            io::FromUserInput::PairingAccept(address) => self.accept_pairing_from(address, to_ui).await,
            io::FromUserInput::PasskeyInput(passkey) => {
                self.authentication_input(AuthenticationInput::Passkey(passkey), to_ui)
            }
            io::FromUserInput::PasskeyCancel => self.authentication_input(AuthenticationInput::Cancel, to_ui),
            io::FromUserInput::StopAdvertising => {
                self.advertising_kind = advertise::Kind::Off;

                advertise::disable_advertising(host).await;

                to_ui.send(MainToUserInput::Mode(io::Mode::Silent)).unwrap();
            }
            io::FromUserInput::DeleteAllBonded => self.delete_all_bonded(host).await,
            io::FromUserInput::DeleteBonded(address) => self.delete_bonded(host, address).await,
            io::FromUserInput::Exit => self.exit(host).await,
        }
    }

    async fn delete_all_bonded<H: HostChannelEnds>(&mut self, host: &mut Host<H>) {
        self.privacy.clear_resolving_list(host).await;

        self.keys_store.clear_all_keys().await;

        self.keys_store.save_keys().await;
    }

    async fn delete_bonded<H: HostChannelEnds>(&mut self, host: &mut Host<H>, address: BluetoothDeviceAddress) {
        if self.keys_store.delete_key(IdentityAddress::Public(address)).await {
            self.privacy
                .remove_device_from_resolving_list(host, &IdentityAddress::Public(address), true)
                .await;
        } else {
            self.keys_store.delete_key(IdentityAddress::StaticRandom(address)).await;

            self.privacy
                .remove_device_from_resolving_list(host, &IdentityAddress::StaticRandom(address), true)
                .await;
        }

        self.keys_store.save_keys().await;
    }

    async fn on_disconnect<H: HostChannelEnds>(
        &mut self,
        host: &mut Host<H>,
        connection_handle: ConnectionHandle,
        to_ui: std::sync::mpsc::Sender<MainToUserInput>,
    ) {
        if let Ok(index) = self
            .connections
            .binary_search_by(|task| task.hci_handle.cmp(&connection_handle))
        {
            let connection = self.connections.remove(index);

            match connection.status {
                connection::ConnectedStatus::New(address) => {
                    if let Ok(index) = self
                        .pairing
                        .binary_search_by(|pairing_info| pairing_info.0.cmp(&address))
                    {
                        self.pairing.remove(index);

                        let pairing_devices = self.pairing.iter().map(|(address, _)| *address).collect::<Vec<_>>();

                        to_ui.send(MainToUserInput::PairingDevices(pairing_devices)).unwrap();
                    }
                }
                connection::ConnectedStatus::Bonded(identity) => {
                    let keys = self.keys_store.get(identity).await.unwrap();

                    self.privacy.add_device_to_resolving_list(host, &*keys).await;
                }
            }

            let output = io::Output::device_disconnected(connection.status.get_address());

            to_ui.send(MainToUserInput::Output(output)).unwrap();
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
        to_ui: std::sync::mpsc::Sender<MainToUserInput>,
    ) where
        <H as SendAndSyncSafeHostChannelEnds>::SendAndSyncSafeConnectionChannelEnds: 'static,
    {
        use bo_tie::hci::events::{EventsData, LeMetaData};

        match next {
            Next::Event(EventsData::DisconnectionComplete(d)) => {
                self.on_disconnect(host, d.connection_handle, to_ui).await
            }
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
            Next::NewConnection(c) => self.on_connection(host, c, to_ui).await,
        }
    }

    async fn get_bonded_devices(&self) -> Vec<BluetoothDeviceAddress> {
        self.keys_store
            .get_all()
            .await
            .iter()
            .map(|keys| keys.get_peer_identity().unwrap().get_address())
            .collect()
    }
}

/// A generator of random heart rate data
///
/// Normally data would be set after reading a sensor, but this is an example so the heart rate data
/// is just generated.
///
/// BTW I have not bothered to ensure this data makes any sense :).
async fn gen_hart_rate_data(hrd: &HeartRateMeasurementArc) -> tokio::time::Sleep {
    const BASE_HEART_RATE: u16 = 72;

    hrd.set_contact_status(server::ContactStatus::FullContact).await;

    hrd.set_heart_rate(BASE_HEART_RATE).await;

    hrd.increase_energy_expended(2).await;

    let interval = 700u16 + 200u16 % rand::random::<u16>();

    hrd.add_rr_interval(interval).await;

    tokio::time::sleep(std::time::Duration::from_secs(interval.into()))
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

    let (mut user_io, mut from_ui) = io::UserInput::new();

    let to_ui = user_io.get_sender_to_ui();

    user_io.set_with_ctrl('c', || Ok(true));

    let (interface, host_ends) = create_hci!();

    tokio::spawn(interface.run());

    let host = &mut Host::init(host_ends).await.unwrap();

    let mut hrp = HeartRateProfile::new(host, to_ui.clone()).await;

    let mut gen_timer = Box::pin(gen_hart_rate_data(&hrp.heart_rate_measurement_arc).await);

    let mut connection_receiver = hrp.take_connection_receiver().unwrap();

    user_io.set_bonded_devices(hrp.get_bonded_devices().await);

    let ui_join_handle = user_io.spawn();

    let mut timeout_ticker = advertise::privacy::TimeoutTick::default();

    loop {
        tokio::select! {
            from_ui_msg = from_ui.recv() => if let Some(user_command) = from_ui_msg {
                if let io::FromUserInput::Exit = user_command {
                    break
                }

                hrp.on_user_action(host, user_command, to_ui.clone(), &mut timeout_ticker).await;
            } else {
                break
            },

            host_next = host.next() => hrp.on_hci_next(host, host_next.unwrap(), to_ui.clone()).await,

            message = connection_receiver.recv() => message.unwrap().process(host, to_ui.clone(), &mut hrp).await,

            _ = &mut gen_timer => gen_timer = Box::pin(gen_hart_rate_data(&hrp.heart_rate_measurement_arc).await),

            regen = timeout_ticker.tick() => regen.regen(host).await,
        }
    }

    advertise::disable_advertising(host).await;

    hrp.exit(host).await;

    ui_join_handle.exit();
}
