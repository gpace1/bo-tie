//! Connection state in the slave role example
//!
//! This example shows the basic way to form a connection with this device in the peripheral role.
//!
//! To fully execute this example you'll need another bluetooth enabled device that can run in the
//! central role. If you have an android phone, you can use the 'nRF Connect' app to connect with
//! this example

use bo_tie::hci::{ConnectionHandle, Host, HostChannelEnds};

/// This sets up the advertising for the connection
///
/// After this is executed the controller will be in the advertiser role and can be seen by a
/// scanning device.
async fn advertise_setup<H: HostChannelEnds>(hi: &mut Host<H>, local_name: &str) {
    use bo_tie::hci::commands::le::{set_advertising_data, set_advertising_enable, set_advertising_parameters};
    use bo_tie::host::gap::assigned;

    let adv_name = assigned::local_name::LocalName::new(local_name, None);

    let mut adv_flags = assigned::flags::Flags::new();

    // This is the flag specification for a LE-only, limited discoverable advertising
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
        .get_core(assigned::flags::CoreFlags::ControllerSupportsSimultaneousLEAndBREDR)
        .disable();
    adv_flags
        .get_core(assigned::flags::CoreFlags::HostSupportsSimultaneousLEAndBREDR)
        .disable();

    let mut adv_data = set_advertising_data::AdvertisingData::new();

    adv_data.try_push(adv_flags).unwrap();
    adv_data.try_push(adv_name).unwrap();

    set_advertising_data::send(hi, adv_data).await.unwrap();

    let mut adv_prams = set_advertising_parameters::AdvertisingParameters::default();

    adv_prams.own_address_type = bo_tie::hci::commands::le::OwnAddressType::RandomDeviceAddress;

    set_advertising_parameters::send(hi, adv_prams).await.unwrap();

    set_advertising_enable::send(hi, true).await.unwrap();
}

async fn wait_for_connection<H: bo_tie::hci::channel::SendSafeHostChannelEnds>(
    hi: &mut Host<H>,
) -> bo_tie::hci::LeL2cap<H::SendSafeConnectionChannelEnds> {
    use bo_tie::hci::events::{Events, LeMeta};
    use bo_tie::hci::Next;

    // Mask the 'LE connection complete' event and 'disconnection complete' events.
    // The 'LE connection complete' event is needed so that the controller alerts the
    // host (a.k.a. this application) that a connection was made. The disconnection
    // complete event is needed in case the central device disconnects immediately
    // for some unexpected reason.
    hi.mask_events([
        Events::LeMeta(LeMeta::ConnectionComplete),
        Events::DisconnectionComplete,
    ])
    .await
    .unwrap();

    // All the different connection complete events are returned within `Next::NewConnection`
    // instead of `Next::Event`. The interface async ask needs to send extra information to
    // the host async task to be used to create a connection async task.
    let le_l2cap = if let Next::NewConnection(connection) = hi.next().await.unwrap() {
        connection.try_into_le().ok().expect("failed to create LE connection")
    } else {
        unreachable!("unexpected disconnect event?")
    };

    // Unmask the 'LE connection complete' event as it is no longer needed
    hi.mask_events([Events::DisconnectionComplete]).await.unwrap();

    le_l2cap
}

/// Disconnect from the central
///
/// This sends the disconnect command to the controller with the reason "remote user terminated
/// the connection" (which in this case the *remote user* was you).
async fn disconnect<H: HostChannelEnds>(hi: &mut Host<H>, connection_handle: Option<ConnectionHandle>) {
    use bo_tie::hci::commands::link_control::disconnect;
    use bo_tie::hci::events::Events;
    use bo_tie::hci::Next;

    macro_rules! disconnect {
        ($connection_handle:expr) => {
            async {
                let prams = disconnect::DisconnectParameters {
                    connection_handle: $connection_handle,
                    disconnect_reason: disconnect::DisconnectReason::RemoteUserTerminatedConnection,
                };

                disconnect::send(hi, prams).await.unwrap();
            }
        };
    }

    match connection_handle {
        Some(connection_handle) => disconnect!(connection_handle).await,
        None => {
            // race condition boilerplate
            hi.mask_events(core::iter::empty::<Events>()).await.unwrap();

            // send the disconnection if the controller did send a new connection
            while let Some(next) = hi.try_next().await.unwrap() {
                if let Next::NewConnection(connection) = next {
                    disconnect!(connection.get_handle()).await
                }
            }
        }
    }
}

/// Loop for requests from a GATT client
///
/// It may be required to `serve` a GATT client to form a connection. This will loop on messages
/// from the central device  
///
/// A generic attribute server is not *technically* required for connecting, but many peer devices
/// require some basic implementation of GATT in order to 'complete' their connection process. The
/// returned server will only contain the mandatory `GAP` service.
async fn server_loop<C>(mut connection_channel: C, local_name: &str) -> !
where
    C: bo_tie::host::l2cap::ConnectionChannel,
{
    use bo_tie::host::l2cap::ConnectionChannelExt;
    use bo_tie::host::{att, gatt};

    let gsb = gatt::GapServiceBuilder::new(local_name, None);

    let queue_writer = att::server::BasicQueuedWriter::new(1024);

    let mut server = gatt::ServerBuilder::from(gsb).make_server(queue_writer);

    server.give_permissions_to_client(att::AttributePermissions::Read(att::AttributeRestriction::None));

    loop {
        for l2cap_packet in connection_channel.receive_b_frame().await.unwrap() {
            match server.process_acl_data(&mut connection_channel, &l2cap_packet).await {
                Ok(_) => (),
                Err(e) => println!("Cannot process acl data, '{}'", e),
            }
        }
    }
}

/// Signal setup
///
/// This sets up the signal handling and returns a future for awaiting the reception of a signal.
#[cfg(unix)]
fn setup_sig() -> impl core::future::Future {
    use futures::stream::StreamExt;
    use signal_hook::consts::signal::*;
    use signal_hook_tokio::Signals;

    let mut signals = Signals::new(&[SIGHUP, SIGTERM, SIGINT, SIGQUIT]).unwrap();

    let hook = tokio::spawn(async move { signals.next().await });

    async move {
        println!("awaiting for 'ctrl-C' (or SIGINT) to stop example");

        hook.await
    }
}

/// Stub for signal setup
///
/// This is a generic fallback that returns future that will forever pend. This method should try
/// to be avoided unless it is intended that the device running the example will be power cycled.
#[cfg(not(unix))]
fn setup_sig() -> impl core::future::Future {
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    struct ForeverPend;

    impl Future for ForeverPend {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }
}

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

#[tokio::main]
async fn main() {
    use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};
    use std::cell::Cell;

    let exit_future = setup_sig();

    let local_name = "Connection Test";

    TermLogger::init(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    let (interface, host_ends) = create_hci!();

    tokio::spawn(interface.run());

    let mut host = Host::init(host_ends).await.expect("failed to initialize host");

    let connection_handle: Cell<Option<ConnectionHandle>> = Cell::new(None);

    let task = async {
        advertise_setup(&mut host, local_name).await;

        let connection_channel = wait_for_connection(&mut host).await;

        server_loop(connection_channel, local_name).await
    };

    tokio::select! {
        _ = exit_future => disconnect(&mut host, connection_handle.take()).await,
        _ = task => ()
    }
}
