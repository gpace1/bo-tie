//! Bonding in the Slave Role
//!
//! This example demonstrates the code required to connect and bond to a device. After this device
//! is bonded the master can re-connect to the slave using through the *LE Privacy* reconnection
//! process.
//!
//! # Note
//! In order to exit this example, a signal (ctrl-c) needs to be sent. Also

use bo_tie::hci;
use futures::lock::Mutex;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
struct Bonder {
    hi: Arc<hci::HostInterface<bo_tie_linux::HCIAdapter>>,
    event_mask: Arc<Mutex<HashSet<hci::cb::set_event_mask::EventMask>>>,
    le_event_mask: Arc<Mutex<HashSet<hci::events::LEMeta>>>,
    handle: Arc<Mutex<Option<hci::common::ConnectionHandle>>>,
    abort_server_handle: Arc<Mutex<Option<futures::future::AbortHandle>>>,
    privacy_info: Arc<Mutex<(Option<u128>, Option<u128>, Option<(bool, bo_tie::BluetoothDeviceAddress)>)>>
}

impl Bonder {
    fn new() -> Self {
        Bonder {
            hi: Arc::new(hci::HostInterface::default()),
            handle: Arc::new(Mutex::new(None)),
            event_mask: Arc::new(Mutex::new(HashSet::new())),
            le_event_mask: Arc::new(Mutex::new(HashSet::new())),
            abort_server_handle: Arc::new(Mutex::new(None)),
            privacy_info: Arc::new(Mutex::new((None, None, None))),
        }
    }
}

impl Bonder {

    /// Enable/Disable the provided events
    async fn set_events(&self, events: &[hci::cb::set_event_mask::EventMask], enable: bool) {
        use hci::cb::set_event_mask::{self, EventMask};

        let events: Vec<EventMask> = {
            let mut gaurd = self.event_mask.lock().await;

            if enable {
                events.iter().for_each(|e| { gaurd.insert(*e); } );
            } else {
                events.iter().for_each(|e| { gaurd.insert(*e); } );
            }

            gaurd.iter().copied().collect()
        };

        set_event_mask::send(&self.hi, &events).await.expect("failed to set event mask")
    }

    /// Enable/Disable the provided le events
    async fn set_le_events(&self, events: &[hci::events::LEMeta], enable: bool) {
        use hci::le::mandatory::set_event_mask;
        use hci::events::LEMeta;

        let le_events: Vec<LEMeta> = {
            let mut gaurd = self.le_event_mask.lock().await;

            if enable {
                events.iter().for_each(|e| { gaurd.insert(*e); } );
            } else {
                events.iter().for_each(|e| { gaurd.insert(*e); } );
            }

            gaurd.iter().copied().collect()
        };

        set_event_mask::send(&self.hi, &le_events).await.expect("failed to set le event mask")
    }

    async fn init_events(&self) {
        use hci::cb::set_event_mask::EventMask;
        use hci::events::LEMeta;

        self.set_events( &[
                EventMask::DisconnectionComplete,
                EventMask::EncryptionChange,
                EventMask::EncryptionKeyRefreshComplete,
                EventMask::LEMeta,
            ],
            true
        ).await;

        self.set_le_events( &[
                LEMeta::ConnectionComplete,
                LEMeta::LongTermKeyRequest,
                LEMeta::RemoteConnectionParameterRequest,
            ],
            true
        ).await;
    }

    /// Starting advertising
    ///
    /// This advertising is for connecting with a bluetooth device that has not been bonded with
    /// this device (or lost bonding information).
    async fn start_advertising(
        self,
        advertised_address: bo_tie::BluetoothDeviceAddress,
        advertised_name: &str )
    {
        use hci::le::transmitter:: {
            set_advertising_data,
            set_advertising_parameters,
            set_advertising_enable,
            set_random_address,
        };
        use bo_tie::gap::advertise;

        let adv_name = advertise::local_name::LocalName::new(advertised_name, false);

        let mut adv_flags = advertise::flags::Flags::new();

        // This is the flag specification for a LE-only, limited discoverable advertising.
        // All core flags are deliberately set here, but the default is disabled.
        adv_flags.get_core(advertise::flags::CoreFlags::LELimitedDiscoverableMode).enable();
        adv_flags.get_core(advertise::flags::CoreFlags::LEGeneralDiscoverableMode).disable();
        adv_flags.get_core(advertise::flags::CoreFlags::BREDRNotSupported).enable();
        adv_flags.get_core(advertise::flags::CoreFlags::ControllerSupportsSimultaniousLEAndBREDR).disable();
        adv_flags.get_core(advertise::flags::CoreFlags::HostSupportsSimultaniousLEAndBREDR).disable();

        let mut adv_data = set_advertising_data::AdvertisingData::new();

        adv_data.try_push(adv_flags).unwrap();
        adv_data.try_push(adv_name).unwrap();

        set_advertising_enable::send(&self.hi, false).await.unwrap();

        set_random_address::send(&self.hi, advertised_address).await.unwrap();

        set_advertising_data::send(&self.hi, adv_data).await.unwrap();

        let mut adv_prams = set_advertising_parameters::AdvertisingParameters::default();

        adv_prams.own_address_type = bo_tie::hci::le::common::OwnAddressType::RandomDeviceAddress;

        set_advertising_parameters::send(&self.hi, adv_prams).await.unwrap();

        set_advertising_enable::send(&self.hi, true).await.unwrap();
    }

    async fn connection_update_request(self) {

        use hci::le::con_pram_req::remote_connection_parameter_request_reply::{
            send,
            CommandParameters
        };
        use hci::common::{
            ConnectionInterval,
            ConnectionLatency,
            SupervisionTimeout,
        };
        use hci::le::common::ConnectionEventLength;
        use hci::events::EventsData::LEMeta;
        use hci::events::LEMeta::RemoteConnectionParameterRequest as RCPReq;
        use hci::events::LEMetaData::RemoteConnectionParameterRequest as RCPReqData;

        loop {
            let event = self.hi.wait_for_event(Some(RCPReq.into()), None).await;

            match event {
                Ok(LEMeta(RCPReqData(e))) => {
                    let cp = CommandParameters {
                        handle: e.connection_handle,
                        interval_min: ConnectionInterval::try_from(400).unwrap(),
                        interval_max: ConnectionInterval::try_from(400).unwrap(),
                        latency: ConnectionLatency::try_from(0).unwrap(),
                        timeout: SupervisionTimeout::try_from_duration(Duration::from_secs(5)).unwrap(),
                        ce_len: ConnectionEventLength { minimum: 0, maximum: 0xFFFF },
                    };

                    send(&self.hi, cp).await
                    .err()
                    .map(|e| log::error!("LE Connection Parameter Request Reply failed: {:?}", e) );
                }
                e => log::error!("Received unexpected event or error: {:?}", e)
            }

        }
    }

    // For simplicity, I've left the race condition in here. There could be a case where the connection
    // is made and the ConnectionComplete event isn't propicated & processed
    async fn wait_for_connection(&self)
    -> Result<hci::events::LEConnectionCompleteData, impl std::fmt::Display>
    {
        use hci::events::LEMeta::ConnectionComplete;
        use hci::events::{EventsData,LEMetaData};
        use hci::le::transmitter::set_advertising_enable;

        println!("Waiting for a connection (timeout is 60 seconds)");

        let evt_rsl = self.hi.wait_for_event(Some(ConnectionComplete.into()), Duration::from_secs(60)).await;

        match evt_rsl {
            Ok(event) => {
                if let EventsData::LEMeta(LEMetaData::ConnectionComplete(event_data)) = event {

                    *self.handle.lock().await = event_data.connection_handle.clone().into();

                    set_advertising_enable::send(&self.hi, false).await.unwrap();

                    Ok(event_data)
                }
                else {
                    Err(format!("Received the incorrect event {:?}", event))
                }
            }
            Err(e) => {
                Err(format!("Timeout Occured: {:?}", e))
            }
        }
    }

    async fn disconnect(&self)
    {
        use hci::le::connection::disconnect;

        if let Some(abort_handle) = self.abort_server_handle.try_lock().and_then(|mut g| g.take()) {
            abort_handle.abort()
        }

        if let Some(connection_handle) = self.handle.try_lock().and_then(|mut g| g.take()) {
            let prams = disconnect::DisconnectParameters {
                connection_handle,
                disconnect_reason: disconnect::DisconnectReason::RemoteUserTerminatedConnection,
            };

            disconnect::send(&self.hi, prams).await.err()
                .map(|e| log::error!("Failed to disconnect: {:?}", e));
        }
    }

    async fn process_acl_data<C>(
        &self,
        connection_channel: &C,
        att_server: &mut bo_tie::gatt::Server<'_,C>,
        slave_security_manager: &mut bo_tie::sm::responder::SlaveSecurityManager<'_,C>
    ) -> Option<u128>
    where C: bo_tie::l2cap::ConnectionChannel
    {
        use bo_tie::l2cap::{ChannelIdentifier, LeUserChannelIdentifier};

        let acl_data_vec = connection_channel.future_receiver().await.unwrap();

        let mut ret = None;

        for acl_data in acl_data_vec {
            match acl_data.get_channel_id() {
                ChannelIdentifier::LE(LeUserChannelIdentifier::AttributeProtocol) =>
                    match att_server.process_acl_data(&acl_data) {
                        Ok(_) => (),
                        Err(e) => log::error!("Cannot process acl data for ATT, '{}'", e),
                    }
                ChannelIdentifier::LE(LeUserChannelIdentifier::SecurityManagerProtocol) =>
                    match slave_security_manager.process_command(&acl_data) {
                        Ok(None) => (),
                        Err(e) => log::error!("Cannot process acl data for SM, '{:?}'", e),
                        Ok(Some(db_entry)) => {
                            ret = db_entry.get_ltk();

                            let local_irk = db_entry.get_irk();
                            let peer_irk = db_entry.get_peer_irk();
                            let peer_addr = db_entry.get_peer_addr();

                            *self.privacy_info.lock().await = (local_irk, peer_irk, peer_addr)
                        }
                    }
                _ => (),
            }
        }

        ret
    }

    async fn await_ltk_request(&self, ch: hci::common::ConnectionHandle) -> bool {
        use hci::le::encryption::long_term_key_request_negative_reply;
        use hci::events::{EventsData, LEMeta, LEMetaData};

        let event = self.hi.wait_for_event(Some(LEMeta::LongTermKeyRequest.into()), None).await;

        log::trace!("Received Long Term Key Request");

        match event {
            Ok(EventsData::LEMeta(LEMetaData::LongTermKeyRequest(ltk_req))) if ltk_req.connection_handle == ch => {
                true
            },
            Ok(EventsData::LEMeta(LEMetaData::LongTermKeyRequest(ltk_req))) => {
                long_term_key_request_negative_reply::send(&self.hi, ltk_req.connection_handle).await.unwrap();
                false
            },
            Ok(e) => {
                log::error!("Received incorrect event {:?}", e);
                false
            },
            Err(e) => panic!("Event error: {:?}", e),
        }
    }

    async fn send_ltk(
        &self,
        ch: hci::common::ConnectionHandle,
        ltk: Option<u128>,
    ){
        use hci::le::encryption::long_term_key_request_reply;
        use hci::le::encryption::long_term_key_request_negative_reply;

        match ltk {
            Some(ltk) => { long_term_key_request_reply::send(&self.hi, ch, ltk).await.unwrap(); },
            None => { long_term_key_request_negative_reply::send(&self.hi, ch).await.unwrap(); }
        }
    }

    async fn await_encryption(&self, ch: hci::common::ConnectionHandle) -> bool
    {
        use hci::events::Events::EncryptionChange;
        use hci::events::LEMeta;
        use hci::events::EventsData::EncryptionChange as EC;
        use hci::common::EncryptionLevel::{AESCCM, Off};

        let evnt = self.hi.wait_for_event(EncryptionChange, None).await;

        match evnt {
            Ok(EC(e_data)) =>
                match (e_data.encryption_enabled.get_for_le(), e_data.connection_handle) {
                    (AESCCM, handle) if ch == handle => {

                        // removing connection complete event
                        self.set_le_events(&[LEMeta::ConnectionComplete], false).await;

                        true
                    },
                    (Off, _) => (false),
                    (e, h) => {
                        log::error!("Using encrypt {:?} for handle {:?}, expected {:?}", e, h, ch);
                        false
                    },
                },
            _ => {
                log::error!("Expected EncryptinoChange event");
                false
            }
        }
    }

    /// Server loop
    ///
    /// # Note
    /// Does not return
    async fn server_loop(
        self,
        this_address: bo_tie::BluetoothDeviceAddress,
        local_name: &'static str,
        mut handle: hci::common::ConnectionHandle,
        mut peer_address: bo_tie::BluetoothDeviceAddress,
        mut peer_address_is_random: bool,
    ) {
        use futures::future::FutureExt;
        use hci::events::Events::DisconnectionComplete;
        use hci::common::LEAddressType;

        let connection_channel = self.hi.new_connection_channel(handle);

        let mut gatt_server = gatt_server_init(&connection_channel, local_name);

        let mut ltk = None;
        let mut encrypted = false;
        let mut irk_sent = false;

        'outer: loop {
            let mut slave_sm = bo_tie::sm::responder::SlaveSecurityManagerBuilder::new(
                &connection_channel,
                &peer_address,
                &this_address,
                peer_address_is_random,
                true // this example used a random address for advertising
            )
            .build();

            let mut e = Box::pin( self.await_encryption(handle).fuse() );

            let mut l = Box::pin( self.await_ltk_request(handle).fuse() );

            let mut d = Box::pin( self.hi.wait_for_event(DisconnectionComplete, None).fuse() );

            'inner: loop {
                let a = self.process_acl_data(&connection_channel, &mut gatt_server, &mut slave_sm).fuse();

                futures::select!{
                    a_res = Box::pin(a) => ltk = a_res,

                    e_res = e => encrypted = e_res,

                    l_res = l => if l_res { self.send_ltk(handle, ltk).await },

                    d_res = d => match d_res { Err(_) => break 'outer, Ok(_) => break 'inner, },
                };

                slave_sm.set_encrypted(encrypted);

                if encrypted && irk_sent == false {
                    println!("Sending IRK and Address to Master");

                    if slave_sm.send_irk() && slave_sm.send_static_rand_addr(this_address.clone()) {
                        irk_sent = true;
                    } else {
                        log::error!("Failed to send IRK");
                    }
                }
            }

            println!("Starting LE Private Advertising");

            match self.advertising_and_connect_with_privacy().await {
                None => break 'outer,
                Some(event_data) => {
                    handle = event_data.connection_handle;
                    peer_address = event_data.peer_address;
                    peer_address_is_random =
                        event_data.peer_address_type == LEAddressType::RandomIdentityAddress ||
                        event_data.peer_address_type == LEAddressType::RandomDeviceAddress;
                }
            }
        }
    }

    async fn abortable_server_loop(
        self,
        this_address: bo_tie::BluetoothDeviceAddress,
        local_name: &'static str,
        handle: hci::common::ConnectionHandle,
        peer_address: bo_tie::BluetoothDeviceAddress,
        peer_address_is_random: bool,
    ) {
        use futures::future::{Abortable, AbortHandle};

        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        *self.abort_server_handle.lock().await = Some(abort_handle);

        let server_loop = self.server_loop(
            this_address,
            local_name,
            handle,
            peer_address,
            peer_address_is_random
        );

        Abortable::new( server_loop, abort_registration ).await.ok();
    }

    /// Continuing advertising
    ///
    /// This advertising will be used after the master disconnects. Only the master that previously
    /// connected *and bonded* to this device will be able to reestablish a connection.
    async fn advertising_and_connect_with_privacy(&self)
    -> Option<hci::events::LEEnhancedConnectionCompleteData>
    {
        use hci::le::{
            common::{
                OwnAddressType
            },
            transmitter::{
                set_advertising_enable,
                set_advertising_parameters::{self, PeerAddressType},
            },
            privacy::{
                PeerIdentityAddressType,
                add_device_to_resolving_list,
                set_address_resolution_enable
            }
        };
        use hci::events::LEMeta::EnhancedConnectionComplete;
        use hci::events::EventsData;
        use hci::events::LEMetaData::EnhancedConnectionComplete as ECCData;

        println!("Starting Advertising and Connection with privacy");

        let keys = self.privacy_info.lock().await.clone();

        if let (Some(local_irk), Some(peer_irk), Some((peer_addr_is_pub, peer_addr))) = keys {

            self.set_le_events( &[EnhancedConnectionComplete], true ).await;

            set_advertising_enable::send(&self.hi, false).await.unwrap();

            let resolve_list_param = add_device_to_resolving_list::Parameter {
                identity_address_type: if peer_addr_is_pub {
                        PeerIdentityAddressType::PublicIdentityAddress
                    } else {
                        PeerIdentityAddressType::RandomStaticIdentityAddress
                    },
                peer_identity_address: peer_addr,
                peer_irk,
                local_irk,
            };

            add_device_to_resolving_list::send(&self.hi, resolve_list_param).await.unwrap();

            set_address_resolution_enable::send(&self.hi, true).await.unwrap();

            let mut advertise_param = set_advertising_parameters::AdvertisingParameters::default();

            advertise_param.own_address_type = OwnAddressType::RPAFromLocalIRKRA;

            advertise_param.peer_address = peer_addr;

            advertise_param.peer_address_type = if peer_addr_is_pub {
                PeerAddressType::PublicAddress
            } else {
                PeerAddressType::RandomAddress
            };

            set_advertising_parameters::send(&self.hi, advertise_param).await.unwrap();

            set_advertising_enable::send(&self.hi, true).await.unwrap();

            let event_rslt = self.hi.wait_for_event(Some(EnhancedConnectionComplete.into()), None).await;

            let event_data_opt = match event_rslt
            {
                Err(e) => {
                    log::error!("Failed to receive EnhancedConnectionComplete: {:?}", e);
                    None
                },
                Ok(EventsData::LEMeta(ECCData(event_data))) => {
                    if event_data.status == hci::error::Error::NoError {
                        *self.handle.lock().await = Some(event_data.connection_handle);
                        Some(event_data)
                    } else {
                        log::error!("Received bad enhanced connection: {}", event_data.status);
                        None
                    }
                },
                Ok(e) => {
                    log::error!("Received unexpected event: {:?}", e);
                    None
                },
            };

            set_advertising_enable::send(&self.hi, false).await.unwrap();

            self.set_le_events( &[EnhancedConnectionComplete], false ).await;

            set_address_resolution_enable::send(&self.hi, false).await.unwrap();

            event_data_opt
        } else {
            log::error!("Bonding Information wasn't supplied, make sure to have the master initate bonding");

            None
        }
    }

    async fn remove_bonding_info(&self) {
        use hci::le::privacy::remove_device_from_resolving_list::{send, Parameter};
        use hci::le::privacy::PeerIdentityAddressType;

        if let ( _, _, Some((peer_addr_is_pub, peer_addr)) ) = self.privacy_info.lock().await.clone() {
            let pram = Parameter {
                identity_address_type: if peer_addr_is_pub {
                        PeerIdentityAddressType::PublicIdentityAddress
                    } else {
                        PeerIdentityAddressType::RandomStaticIdentityAddress
                    },
                peer_identity_address: peer_addr
            };

            if let Err(e) = send(&self.hi, pram).await {
                log::debug!("Failed to remove bonding info: {:?}", e);
            }
        }
    }

    fn setup_signal_handle(self)
    {
        use hci::le::transmitter::set_advertising_enable;

        simple_signal::set_handler(&[simple_signal::Signal::Int, simple_signal::Signal::Term],
            move |_| {

                // Cancel advertising if advertising
                if let Err(e) = futures::executor::block_on(set_advertising_enable::send(&self.hi, false)) {
                    log::error!("Failed to stop advertising: {:?}", e);
                }

                futures::executor::block_on(self.disconnect());

                futures::executor::block_on(self.remove_bonding_info());

                println!("Exiting example");

                // Force dropping the `HostInterface`. Not doing this may cause problems with your
                // bluetooth controller if the HCI is not closed cleanly, espically when running
                // with a superuser.
                unsafe {
                    let b = Box::from_raw(Arc::into_raw(self.hi.clone()) as *mut hci::HostInterface<bo_tie_linux::HCIAdapter>);

                    std::mem::drop( b )
                };

                std::process::exit(0);
            }
        );
    }
}

/// Initialize a basic the GATT Server
fn gatt_server_init<'c, C>(channel: &'c C, local_name: &str) -> bo_tie::gatt::Server<'c, C>
where C: bo_tie::l2cap::ConnectionChannel
{
    use bo_tie::{gatt, att};

    let gsb = gatt::GapServiceBuilder::new(local_name, None);

    let mut server = gatt::ServerBuilder::new_with_gap(gsb).make_server(channel, 256);

    server.as_mut().give_permission_to_client(att::AttributePermissions::Read);

    server
}

fn main() {
    use simplelog::{TermLogger, LevelFilter, Config, TerminalMode};
    use futures::task::SpawnExt;

    TermLogger::init( LevelFilter::Trace, Config::default(), TerminalMode::Mixed ).unwrap();

    let local_name = "Bonding Test";

    let advertise_address = [0x70, 0x92, 0x07, 0x23, 0xac, 0xc3];

    // Bonder is structure local to this example
    let bonder = Bonder::new();

    bonder.clone().setup_signal_handle();

    let mut thread_pool = futures::executor::ThreadPool::new().expect("Failed to create ThreadPool");

    println!("This public address: {:x?}", advertise_address);

    // Wait for events to be initialized.
    thread_pool.run( bonder.init_events() );

    // Conection Update Request will run forever (effectively in the background).
    thread_pool.spawn( bonder.clone().connection_update_request() ).unwrap();

    thread_pool.spawn( Box::pin(bonder.clone().start_advertising(advertise_address, local_name)) ).unwrap();

    // `Run` here will wait for a connection to be made before proceeding. `wait_for_connection`
    // will disable advertising also when a connection is made.
    match thread_pool.run( bonder.wait_for_connection() ) {
        Ok(event_data) => {
            use hci::events::LEConnectionAddressType;

            println!("Device Connected! (use ctrl-c to disconnect and exit)");

            thread_pool.run( bonder.clone()
                .abortable_server_loop(
                    advertise_address.clone(),
                    local_name,
                    event_data.connection_handle,
                    event_data.peer_address,
                    event_data.peer_address_type == LEConnectionAddressType::RandomDeviceAddress
                )
            );
        },
        Err(err) => println!("Error: {}", err),
    };

    println!("ending example");
}
