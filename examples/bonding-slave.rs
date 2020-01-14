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
    handle: Arc<Mutex<Option<hci::common::ConnectionHandle>>>
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

    async fn start_advertising<'a>(
        self,
        advertised_address: bo_tie::BluetoothDeviceAddress,
        advertised_name: &'a str )
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
        use hci::events::LEMeta::RemoteConnectionParameterRequest;
        use hci::events::LEMetaData::RemoteConnectionParameterRequest as RCPReqData;

        loop {
            let event = self.hi.wait_for_event(RemoteConnectionParameterRequest.into(), None).await;

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

        let evt_rsl = self.hi.wait_for_event(ConnectionComplete.into(), Duration::from_secs(60)).await;

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

        if let Some(connection_handle) = self.handle.try_lock().and_then(|g| (*g).clone() ) {
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
                    match slave_security_manager.process_command(acl_data.get_payload()) {
                        Ok(None) => (),
                        Err(e) => log::error!("Cannot process acl data for SM, '{:?}'", e),
                        Ok(Some(db_entry)) => ret = db_entry.get_ltk()
                    }
                _ => (),
            }
        }

        ret
    }

    async fn await_ltk_request(&self, ch: hci::common::ConnectionHandle) -> bool {
        use hci::le::encryption::long_term_key_request_negative_reply;
        use hci::events::{EventsData, LEMeta, LEMetaData};

        let event = self.hi.wait_for_event(LEMeta::LongTermKeyRequest.into(), None).await;

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
        connect_complete_data: hci::events::LEConnectionCompleteData,
    ) {
        use futures::future::FutureExt;

        let connection_channel = self.hi.new_le_acl_connection_channel(&connect_complete_data);

        let mut server = gatt_server_init(&connection_channel, local_name);

        let sm = bo_tie::sm::SecurityManager::new(Vec::new());

        let mut slave_sm = sm.new_slave_builder(
            &connection_channel,
            &connect_complete_data.peer_address,
            connect_complete_data.peer_address_type == hci::events::LEConnectionAddressType::RandomDeviceAddress,
            &this_address,
            true // this example used a random address for advertising
        )
        .set_min_and_max_encryption_key_size(16,16).unwrap()
        .create_security_manager();

        let mut ltk = None;
        let mut encrypted = false;
        let mut irk_sent = false;

        let ch = connect_complete_data.connection_handle;

        let mut e = Box::pin( self.await_encryption(ch).fuse() );

        let mut l = Box::pin( self.await_ltk_request(ch).fuse() );

        loop {
            let a = self.process_acl_data(&connection_channel, &mut server, &mut slave_sm).fuse();

            futures::select!{
                a_res = Box::pin(a) => ltk = a_res,

                e_res = e => encrypted = e_res,

                l_res = l => if l_res { self.send_ltk(ch, ltk).await },
            };

            slave_sm.set_encrypted(encrypted);

            if encrypted && irk_sent == false {
                println!("Sending IRK to Master");

                if slave_sm.send_irk() {
                    irk_sent = true;
                } else {
                    log::error!("Failed to send IRK");
                }
            }
        }
    }

    /// This is for handeling signals to the example
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

                println!("Exiting example");

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

    let bonder = Bonder {
        hi: Arc::new(hci::HostInterface::default()),
        handle: Arc::new(Mutex::new(None)),
        event_mask: Arc::new(Mutex::new(HashSet::new())),
        le_event_mask: Arc::new(Mutex::new(HashSet::new())),
    };

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

            thread_pool.spawn( bonder.clone().server_loop(advertise_address,local_name,event_data) ).unwrap();

            println!("Device Connected! (use ctrl-c to disconnect and exit)");

            thread_pool.run(bonder.hi.wait_for_event(hci::events::Events::DisconnectionComplete, None)).ok();
        },
        Err(err) => println!("Error: {}", err),
    };
}
