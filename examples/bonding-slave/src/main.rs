//! Bonding in the Slave Role
//!
//! This example demonstrates the code required to connect and bond to a device. After this device
//! is bonded the master can re-connect to the slave using through the *LE Privacy* reconnection
//! process.
//!
//! # Note
//! In order to exit this example, a signal (ctrl-c) needs to be sent. Also

use bo_tie::att::server::BasicQueuedWriter;
use bo_tie::hci;
use bo_tie::hci::common::le::OwnAddressType;
use futures::lock::Mutex;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

#[derive(Default)]
struct AsyncLock(futures::lock::Mutex<()>);

impl<'a> bo_tie::hci::AsyncLock<'a> for AsyncLock {
    type Guard = futures::lock::MutexGuard<'a, ()>;
    type Locker = futures::lock::MutexLockFuture<'a, ()>;

    fn lock(&'a self) -> Self::Locker {
        self.0.lock()
    }
}

#[derive(Clone, Copy)]
struct AddressInfo {
    address: bo_tie::BluetoothDeviceAddress,
    is_pub: bool,
}

#[derive(Default, Clone)]
struct Keys {
    bonding_successful: bool,
    this_irk: Option<u128>,
    peer_irk: Option<u128>,
    peer_address: Option<AddressInfo>,
}

#[derive(Clone)]
struct Bonder {
    hi: Arc<hci::HostInterface<bo_tie_linux::HCIAdapter, AsyncLock>>,
    event_mask: Arc<Mutex<HashSet<hci::cb::set_event_mask::EventMask>>>,
    le_event_mask: Arc<Mutex<HashSet<hci::events::LEMeta>>>,
    handle: Arc<Mutex<Option<hci::common::ConnectionHandle>>>,
    abort_server_handle: Arc<Mutex<Option<futures::future::AbortHandle>>>,
    privacy_info: Arc<Mutex<Keys>>,
    this_address: Result<AddressInfo, bool>,
}

impl Bonder {
    async fn new(use_pub_address: bool) -> Self {
        Bonder {
            hi: hci::HostInterface::new().await,
            handle: Arc::new(Mutex::new(None)),
            event_mask: Arc::new(Mutex::new(HashSet::new())),
            le_event_mask: Arc::new(Mutex::new(HashSet::new())),
            abort_server_handle: Arc::new(Mutex::new(None)),
            privacy_info: Default::default(),
            this_address: Err(use_pub_address),
        }
    }
}

impl Bonder {
    /// Reset the controller
    async fn reset_controller(&self) {
        hci::cb::reset::send(&self.hi).await.unwrap();
    }

    /// Get the address
    ///
    /// # Note
    /// If the address is random, it will be randomly generated and set within the controller (once)
    /// before `get_address` returns the address information. This method needs to be called before
    /// advertising is enabled (or at least a connection occurs).
    async fn get_address(&mut self) -> AddressInfo {
        match self.this_address {
            Ok(address) => address,
            Err(is_pub) => {
                let address_info = if is_pub {
                    let address = *hci::info_params::read_bd_addr::send(&self.hi).await.unwrap();

                    AddressInfo { address, is_pub: true }
                } else {
                    let address = bo_tie::new_static_random_bluetooth_address();

                    hci::le::transmitter::set_random_address::send(&self.hi, address)
                        .await
                        .unwrap();

                    AddressInfo { address, is_pub: false }
                };

                self.this_address = Ok(address_info);

                address_info
            }
        }
    }

    fn is_address_public(&self) -> bool {
        match self.this_address {
            Ok(AddressInfo { is_pub, .. }) => is_pub,
            Err(is_pub) => is_pub,
        }
    }

    /// Enable/Disable the provided events
    async fn set_events(&self, events: &[hci::cb::set_event_mask::EventMask], enable: bool) {
        use hci::cb::set_event_mask::{self, EventMask};

        let events: Vec<EventMask> = {
            let mut gaurd = self.event_mask.lock().await;

            if enable {
                events.iter().for_each(|e| {
                    gaurd.insert(*e);
                });
            } else {
                events.iter().for_each(|e| {
                    gaurd.insert(*e);
                });
            }

            gaurd.iter().copied().collect()
        };

        set_event_mask::send(&self.hi, &events)
            .await
            .expect("failed to set event mask");
    }

    /// Enable/Disable the provided le events
    async fn set_le_events(&self, events: &[hci::events::LEMeta], enable: bool) {
        use hci::events::LEMeta;
        use hci::le::mandatory::set_event_mask;

        let le_events: Vec<LEMeta> = {
            let mut gaurd = self.le_event_mask.lock().await;

            if enable {
                events.iter().for_each(|e| {
                    gaurd.insert(*e);
                });
            } else {
                events.iter().for_each(|e| {
                    gaurd.insert(*e);
                });
            }

            gaurd.iter().copied().collect()
        };

        set_event_mask::send(&self.hi, &le_events)
            .await
            .expect("failed to set le event mask");
    }

    async fn init_events(&self) {
        use hci::cb::set_event_mask::EventMask;
        use hci::events::LEMeta;

        self.set_events(
            &[
                EventMask::DisconnectionComplete,
                EventMask::EncryptionChange,
                EventMask::EncryptionKeyRefreshComplete,
                EventMask::LEMeta,
            ],
            true,
        )
        .await;

        self.set_le_events(
            &[
                LEMeta::ConnectionComplete,
                LEMeta::LongTermKeyRequest,
                LEMeta::RemoteConnectionParameterRequest,
            ],
            true,
        )
        .await;
    }

    /// Starting advertising
    ///
    /// This advertising is for connecting with a bluetooth device that has not been bonded with
    /// this device (or lost bonding information).
    async fn start_advertising(self, advertised_name: &str) {
        use bo_tie::gap::assigned;
        use hci::le::transmitter::{set_advertising_data, set_advertising_enable, set_advertising_parameters};

        let adv_name = assigned::local_name::LocalName::new(advertised_name, false);

        let mut adv_flags = assigned::flags::Flags::new();

        // This is the flag specification for a LE-only, limited discoverable advertising.
        // All core flags are deliberately set here, but the default is disabled.
        adv_flags
            .get_core(assigned::flags::CoreFlags::LELimitedDiscoverableMode)
            .enable();
        adv_flags
            .get_core(assigned::flags::CoreFlags::LEGeneralDiscoverableMode)
            .disable();
        adv_flags
            .get_core(assigned::flags::CoreFlags::BREDRNotSupported)
            .enable();
        adv_flags
            .get_core(assigned::flags::CoreFlags::ControllerSupportsSimultaniousLEAndBREDR)
            .disable();
        adv_flags
            .get_core(assigned::flags::CoreFlags::HostSupportsSimultaniousLEAndBREDR)
            .disable();

        let mut adv_data = set_advertising_data::AdvertisingData::new();

        adv_data.try_push(adv_flags).unwrap();
        adv_data.try_push(adv_name).unwrap();

        set_advertising_enable::send(&self.hi, false).await.unwrap();

        set_advertising_data::send(&self.hi, adv_data).await.unwrap();

        let mut adv_prams = set_advertising_parameters::AdvertisingParameters::default();

        adv_prams.own_address_type = if self.is_address_public() {
            bo_tie::hci::common::le::OwnAddressType::PublicDeviceAddress
        } else {
            bo_tie::hci::common::le::OwnAddressType::RandomDeviceAddress
        };

        set_advertising_parameters::send(&self.hi, adv_prams).await.unwrap();

        set_advertising_enable::send(&self.hi, true).await.unwrap();
    }

    async fn connection_update_request(self) {
        use bo_tie::hci::common::le::ConnectionEventLength;
        use hci::common::{ConnectionInterval, ConnectionLatency, SupervisionTimeout};
        use hci::events::EventsData::LEMeta;
        use hci::events::LEMeta::RemoteConnectionParameterRequest as RCPReq;
        use hci::events::LEMetaData::RemoteConnectionParameterRequest as RCPReqData;
        use hci::le::con_pram_req::remote_connection_parameter_request_reply::{send, CommandParameters};

        loop {
            let event = self.hi.wait_for_event(Some(RCPReq.into())).await;

            match event {
                Ok(LEMeta(RCPReqData(e))) => {
                    let cp = CommandParameters {
                        handle: e.connection_handle,
                        interval_min: ConnectionInterval::try_from(400).unwrap(),
                        interval_max: ConnectionInterval::try_from(400).unwrap(),
                        latency: ConnectionLatency::try_from(0).unwrap(),
                        timeout: SupervisionTimeout::try_from_duration(Duration::from_secs(5)).unwrap(),
                        ce_len: ConnectionEventLength {
                            minimum: 0,
                            maximum: 0xFFFF,
                        },
                    };

                    send(&self.hi, cp)
                        .await
                        .err()
                        .map(|e| eprintln!("LE Connection Parameter Request Reply failed: {:?}", e));
                }
                e => eprintln!("Received unexpected event or error: {:?}", e),
            }
        }
    }

    // For simplicity, I've left the race condition in here. There could be a case where the connection
    // is made and the ConnectionComplete event isn't propicated & processed
    async fn wait_for_connection(&self) -> Result<hci::events::LEConnectionCompleteData, impl std::fmt::Display> {
        use hci::events::LEMeta::ConnectionComplete;
        use hci::events::{EventsData, LEMetaData};
        use hci::le::transmitter::set_advertising_enable;

        println!("Waiting for a connection (timeout is 60 seconds)");

        let evt_rsl = self.hi.wait_for_event(Some(ConnectionComplete.into())).await;

        match evt_rsl {
            Ok(event) => {
                if let EventsData::LEMeta(LEMetaData::ConnectionComplete(event_data)) = event {
                    *self.handle.lock().await = event_data.connection_handle.clone().into();

                    set_advertising_enable::send(&self.hi, false).await.unwrap();

                    Ok(event_data)
                } else {
                    Err(format!("Received the incorrect event {:?}", event))
                }
            }
            Err(e) => Err(format!("Timeout Occured: {:?}", e)),
        }
    }

    async fn disconnect(&self) {
        use hci::le::connection::disconnect;

        if let Some(abort_handle) = self.abort_server_handle.try_lock().and_then(|mut g| g.take()) {
            abort_handle.abort()
        }

        if let Some(connection_handle) = self.handle.try_lock().and_then(|mut g| g.take()) {
            let prams = disconnect::DisconnectParameters {
                connection_handle,
                disconnect_reason: disconnect::DisconnectReason::RemoteUserTerminatedConnection,
            };

            disconnect::send(&self.hi, prams)
                .await
                .err()
                .map(|e| eprintln!("Failed to disconnect: {:?}", e));
        }
    }

    async fn process_acl_data<C>(
        &self,
        connection_channel: &C,
        att_server: &mut bo_tie::gatt::Server<'_, C, BasicQueuedWriter>,
        slave_security_manager: &mut bo_tie::sm::responder::SlaveSecurityManager<'_, C, (), ()>,
    ) -> Option<u128>
    where
        C: bo_tie::l2cap::ConnectionChannel,
    {
        use bo_tie::l2cap::{ChannelIdentifier, LeUserChannelIdentifier};

        let acl_data_vec = connection_channel.future_receiver().await.unwrap();

        let mut ret = None;

        for acl_data in acl_data_vec {
            match acl_data.get_channel_id() {
                ChannelIdentifier::LE(LeUserChannelIdentifier::AttributeProtocol) => {
                    match att_server.process_acl_data(&acl_data).await {
                        Ok(_) => (),
                        Err(e) => eprintln!("Cannot process acl data for ATT, '{}'", e),
                    }
                }
                ChannelIdentifier::LE(LeUserChannelIdentifier::SecurityManagerProtocol) => {
                    match slave_security_manager.process_command(&acl_data).await {
                        Ok(None) => (),
                        Err(e) => eprintln!("Cannot process acl data for SM, '{:?}'", e),
                        Ok(Some(db_entry)) => {
                            ret = db_entry.get_ltk();

                            let peer_address = db_entry
                                .get_peer_addr()
                                .map(|(is_pub, address)| AddressInfo { address, is_pub });

                            // IRKs are not distributed until the link is encrypted (see method
                            // `await_encryption`)
                            *self.privacy_info.lock().await = Keys {
                                bonding_successful: true,
                                this_irk: None,
                                peer_irk: None,
                                peer_address,
                            }
                        }
                    }
                }
                _ => (),
            }
        }

        ret
    }

    async fn await_ltk_request(&self, ch: hci::common::ConnectionHandle) -> bool {
        use hci::events::{EventsData, LEMeta, LEMetaData};
        use hci::le::encryption::long_term_key_request_negative_reply;

        let event = self.hi.wait_for_event(Some(LEMeta::LongTermKeyRequest.into())).await;

        println!("Received Long Term Key Request");

        match event {
            Ok(EventsData::LEMeta(LEMetaData::LongTermKeyRequest(ltk_req))) if ltk_req.connection_handle == ch => true,
            Ok(EventsData::LEMeta(LEMetaData::LongTermKeyRequest(ltk_req))) => {
                long_term_key_request_negative_reply::send(&self.hi, ltk_req.connection_handle)
                    .await
                    .unwrap();
                false
            }
            Ok(e) => {
                eprintln!("Received incorrect event {:?}", e);
                false
            }
            Err(e) => panic!("Event error: {:?}", e),
        }
    }

    async fn send_ltk(&self, ch: hci::common::ConnectionHandle, ltk: Option<u128>) {
        use hci::le::encryption::long_term_key_request_negative_reply;
        use hci::le::encryption::long_term_key_request_reply;

        match ltk {
            Some(ltk) => {
                long_term_key_request_reply::send(&self.hi, ch, ltk).await.unwrap();
            }
            None => {
                long_term_key_request_negative_reply::send(&self.hi, ch).await.unwrap();
            }
        }
    }

    async fn await_encryption(&self, ch: hci::common::ConnectionHandle) -> bool {
        use hci::common::EncryptionLevel::{Off, AESCCM};
        use hci::events::Events::EncryptionChange;
        use hci::events::EventsData::EncryptionChange as EC;
        use hci::events::LEMeta;

        let evnt = self.hi.wait_for_event(EncryptionChange).await;

        match evnt {
            Ok(EC(e_data)) => match (e_data.encryption_enabled.get_for_le(), e_data.connection_handle) {
                (AESCCM, handle) if ch == handle => {
                    // removing connection complete event
                    self.set_le_events(&[LEMeta::ConnectionComplete], false).await;

                    true
                }
                (Off, _) => false,
                (e, h) => {
                    eprintln!("Using encrypt {:?} for handle {:?}, expected {:?}", e, h, ch);
                    false
                }
            },
            _ => {
                eprintln!("Expected EncryptionChange event");
                false
            }
        }
    }

    /// Server loop
    ///
    /// # Note
    /// Does not return
    async fn server_loop(
        mut self,
        local_name: &'static str,
        mut handle: hci::common::ConnectionHandle,
        mut peer_address: bo_tie::BluetoothDeviceAddress,
        mut peer_address_is_random: bool,
    ) {
        use futures::future::FutureExt;
        use hci::common::LEAddressType;
        use hci::events::Events::DisconnectionComplete;

        let connection_channel = self.hi.clone().flow_ctrl_channel(handle, 512);

        let mut gatt_server = gatt_server_init(&connection_channel, local_name);

        let mut ltk = None;
        let mut encrypted = false;
        let mut bonding_information_sent = false;

        let this_address = self.get_address().await;

        'outer: loop {
            let mut slave_sm = bo_tie::sm::responder::SlaveSecurityManagerBuilder::new(
                &connection_channel,
                &peer_address,
                &this_address.address,
                peer_address_is_random,
                !this_address.is_pub,
            )
            .build();

            let mut e = Box::pin(self.await_encryption(handle).fuse());

            let mut l = Box::pin(self.await_ltk_request(handle).fuse());

            let mut d = Box::pin(self.hi.wait_for_event(DisconnectionComplete).fuse());

            'inner: loop {
                let a = self
                    .process_acl_data(&connection_channel, &mut gatt_server, &mut slave_sm)
                    .fuse();

                futures::select! {
                    a_res = Box::pin(a) => ltk = a_res,

                    e_res = e => encrypted = e_res,

                    l_res = l => if l_res { self.send_ltk(handle, ltk).await },

                    d_res = d => match d_res { Err(_) => break 'outer, Ok(_) => break 'inner, },
                };

                slave_sm.set_encrypted(encrypted);

                if encrypted && (bonding_information_sent == false) {
                    println!("Sending IRK and Address to Master");

                    let result_irk = slave_sm.send_irk(None).await;

                    let addr_sent = if this_address.is_pub {
                        slave_sm
                            .send_pub_addr(this_address.address.clone())
                            .await
                            .expect("Cannot send public address on this machine")
                    } else {
                        slave_sm
                            .send_static_rand_addr(this_address.address.clone())
                            .await
                            .expect("Cannot send static random address on this machine")
                    };

                    match (result_irk, addr_sent) {
                        (Ok(irk), true) => {
                            bonding_information_sent = true;
                            self.privacy_info.lock().await.this_irk = Some(irk);
                        }
                        _ => {
                            eprintln!("Failed to send IRK and/or identity address");
                        }
                    }
                }
            }

            println!("Starting LE Private Advertising");

            match self.advertising_and_connect_with_privacy().await {
                None => break 'outer,
                Some(event_data) => {
                    handle = event_data.connection_handle;
                    peer_address = event_data.peer_address;
                    peer_address_is_random = event_data.peer_address_type == LEAddressType::RandomIdentityAddress
                        || event_data.peer_address_type == LEAddressType::RandomDeviceAddress;
                }
            }
        }
    }

    async fn abortable_server_loop(
        self,
        local_name: &'static str,
        handle: hci::common::ConnectionHandle,
        peer_address: bo_tie::BluetoothDeviceAddress,
        peer_address_is_random: bool,
    ) {
        use futures::future::{AbortHandle, Abortable};

        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        *self.abort_server_handle.lock().await = Some(abort_handle);

        let server_loop = self.server_loop(local_name, handle, peer_address, peer_address_is_random);

        Abortable::new(server_loop, abort_registration).await.ok();
    }

    /// Continuing advertising
    ///
    /// This advertising will be used after the master disconnects. Only the master that previously
    /// connected *and bonded* to this device will be able to reestablish a connection.
    async fn advertising_and_connect_with_privacy(&self) -> Option<hci::events::LEEnhancedConnectionCompleteData> {
        println!("Starting Advertising and Connection with privacy");

        match self.privacy_info.lock().await.clone() {
            Keys {
                bonding_successful: true,
                this_irk: Some(this_irk),
                peer_irk,
                peer_address: Some(address_info),
            } => self.reconnect_advertising(this_irk, peer_irk, address_info).await,
            Keys {
                bonding_successful: false,
                ..
            } => {
                eprintln!("Failed bonding with peer device");
                None
            }
            Keys {
                bonding_successful: true,
                this_irk: None,
                ..
            } => {
                eprintln!(
                    "This device has not distributed an IRK to the peer. Advertising cannot be \
                    done with a resolvable private address"
                );
                None
            }
            _ => {
                unreachable!()
            }
        }
    }

    /// Reconnection advertising via private address
    async fn reconnect_advertising(
        &self,
        this_irk: u128,
        peer_irk: Option<u128>,
        peer_address_info: AddressInfo,
    ) -> Option<hci::events::LEEnhancedConnectionCompleteData> {
        use hci::events::EventsData;
        use hci::events::LEMeta::EnhancedConnectionComplete;
        use hci::events::LEMetaData::EnhancedConnectionComplete as ECCData;
        use hci::le::{
            privacy::{
                add_device_to_resolving_list, set_address_resolution_enable, set_privacy_mode,
                set_resolvable_private_address_timeout, PeerIdentityAddressType,
            },
            transmitter::{
                set_advertising_enable,
                set_advertising_parameters::{self, PeerAddressType},
            },
        };

        let resolve_list_param = add_device_to_resolving_list::Parameter {
            identity_address_type: if peer_address_info.is_pub {
                PeerIdentityAddressType::PublicIdentityAddress
            } else {
                PeerIdentityAddressType::RandomStaticIdentityAddress
            },
            peer_identity_address: peer_address_info.address,
            peer_irk: peer_irk.unwrap_or_default(),
            local_irk: this_irk,
        };

        let mut advertise_param = set_advertising_parameters::AdvertisingParameters::default();

        advertise_param.own_address_type = if self.is_address_public() {
            OwnAddressType::RPAFromLocalIRKOrPA
        } else {
            OwnAddressType::RPAFromLocalIRKOrRA
        };

        advertise_param.peer_address = peer_address_info.address;

        advertise_param.peer_address_type = if peer_address_info.is_pub {
            PeerAddressType::PublicAddress
        } else {
            PeerAddressType::RandomAddress
        };

        let privacy_mode_param = set_privacy_mode::Parameter {
            peer_identity_address: peer_address_info.address,
            peer_identity_address_type: if peer_address_info.is_pub {
                PeerIdentityAddressType::PublicIdentityAddress
            } else {
                PeerIdentityAddressType::RandomStaticIdentityAddress
            },
            privacy_mode: set_privacy_mode::PrivacyMode::DevicePrivacy,
        };

        self.set_le_events(&[EnhancedConnectionComplete], true).await;

        set_advertising_enable::send(&self.hi, false).await.unwrap();

        add_device_to_resolving_list::send(&self.hi, resolve_list_param)
            .await
            .unwrap();

        set_resolvable_private_address_timeout::send(&self.hi, core::time::Duration::default())
            .await
            .unwrap();

        set_address_resolution_enable::send(&self.hi, true).await.unwrap();

        set_privacy_mode::send(&self.hi, privacy_mode_param).await.unwrap();

        set_advertising_parameters::send(&self.hi, advertise_param)
            .await
            .unwrap();

        set_advertising_enable::send(&self.hi, true).await.unwrap();

        let event_rslt = self.hi.wait_for_event(Some(EnhancedConnectionComplete.into())).await;

        let event_data_opt = match event_rslt {
            Err(e) => {
                eprintln!("Failed to receive EnhancedConnectionComplete: {:?}", e);
                None
            }
            Ok(EventsData::LEMeta(ECCData(event_data))) => {
                if event_data.status == hci::error::Error::NoError {
                    *self.handle.lock().await = Some(event_data.connection_handle);
                    Some(event_data)
                } else {
                    eprintln!("Received bad enhanced connection: {}", event_data.status);
                    None
                }
            }
            Ok(e) => {
                eprintln!("Received unexpected event: {:?}", e);
                None
            }
        };

        set_advertising_enable::send(&self.hi, false).await.unwrap();

        self.set_le_events(&[EnhancedConnectionComplete], false).await;

        set_address_resolution_enable::send(&self.hi, false).await.unwrap();

        event_data_opt
    }

    async fn remove_bonding_info(&self) {
        use hci::le::privacy::remove_device_from_resolving_list::{send, Parameter};
        use hci::le::privacy::PeerIdentityAddressType;

        if let Keys {
            peer_address: Some(address_info),
            ..
        } = self.privacy_info.lock().await.clone()
        {
            let pram = Parameter {
                identity_address_type: if address_info.is_pub {
                    PeerIdentityAddressType::PublicIdentityAddress
                } else {
                    PeerIdentityAddressType::RandomStaticIdentityAddress
                },
                peer_identity_address: address_info.address,
            };

            if let Err(e) = send(&self.hi, pram).await {
                println!("Failed to remove bonding info: {:?}", e);
            }
        }
    }

    fn setup_signal_handle(self) {
        use hci::le::transmitter::set_advertising_enable;

        simple_signal::set_handler(&[simple_signal::Signal::Int, simple_signal::Signal::Term], move |_| {
            // Cancel advertising if advertising
            if let Err(e) = futures::executor::block_on(set_advertising_enable::send(&self.hi, false)) {
                eprintln!("Failed to stop advertising: {:?}", e);
            }

            futures::executor::block_on(self.disconnect());

            futures::executor::block_on(self.remove_bonding_info());

            println!("Exiting example");

            // Force dropping the `HostInterface`. Not doing this may cause problems with your
            // bluetooth controller if the HCI is not closed cleanly, especially when running
            // with a superuser.
            unsafe {
                let b = Box::from_raw(
                    Arc::into_raw(self.hi.clone()) as *mut hci::HostInterface<bo_tie_linux::HCIAdapter, AsyncLock>
                );

                std::mem::drop(b)
            };

            std::process::exit(0);
        });
    }
}

/// Initialize a basic the GATT Server
fn gatt_server_init<'c, C>(channel: &'c C, local_name: &str) -> bo_tie::gatt::Server<'c, C, BasicQueuedWriter>
where
    C: bo_tie::l2cap::ConnectionChannel,
{
    use bo_tie::{
        att::{AttributePermissions, AttributeRestriction},
        gatt,
    };

    let gsb = gatt::GapServiceBuilder::new(local_name, None);

    let mut server = gatt::ServerBuilder::from(gsb).make_server(channel, BasicQueuedWriter::new(2048));

    server
        .as_mut()
        .give_permissions_to_client(AttributePermissions::Read(AttributeRestriction::None));

    server
}

fn main() {
    use futures::{
        executor::{block_on, ThreadPool},
        task::SpawnExt,
    };
    use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};

    TermLogger::init(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    let local_name = "Bonding Test";

    // Bonder is structure local to this example, its used for enabling privacy after bonding is
    // completed.
    let mut bonder = block_on(Bonder::new(true));

    println!(
        "This address: {}",
        bo_tie::bluetooth_address_into_string(&block_on(bonder.get_address()).address)
    );

    bonder.clone().setup_signal_handle();

    let thread_pool = ThreadPool::new().expect("Failed to create ThreadPool");

    block_on(bonder.reset_controller());

    // Wait for events to be initialized before proceeding to the next steps.
    block_on(bonder.init_events());

    // Connection Update Request will run forever (effectively in the background).
    thread_pool.spawn(bonder.clone().connection_update_request()).unwrap();

    thread_pool
        .spawn(Box::pin(bonder.clone().start_advertising(local_name)))
        .unwrap();

    // Spawn the process to await a connection
    match block_on(bonder.wait_for_connection()) {
        Ok(event_data) => {
            use hci::events::LEConnectionAddressType;

            println!("Device Connected! (use ctrl-c to disconnect and exit)");

            // Start the server
            block_on(bonder.clone().abortable_server_loop(
                local_name,
                event_data.connection_handle,
                event_data.peer_address,
                event_data.peer_address_type == LEConnectionAddressType::RandomDeviceAddress,
            ));
        }
        Err(err) => println!("Error: {}", err),
    };

    println!("ending example");
}
