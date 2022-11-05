#![doc = include_str!("../README.md")]

async fn advertise_setup<T: bo_tie::hci::HostChannelEnds>(
    hi: &mut bo_tie::hci::Host<T>,
    data: bo_tie::hci::commands::le::set_advertising_data::AdvertisingData,
) {
    use bo_tie::hci::commands::le::{set_advertising_data, set_advertising_enable, set_advertising_parameters};

    println!("setting up advertising...");

    set_advertising_data::send(hi, data).await.unwrap();

    println!("{:5>}", "...set advertising data");

    let mut adv_prams = set_advertising_parameters::AdvertisingParameters::default();

    adv_prams.advertising_type = set_advertising_parameters::AdvertisingType::NonConnectableUndirectedAdvertising;

    set_advertising_parameters::send(hi, adv_prams).await.unwrap();

    println!("{:5>}", "...set advertising parameters");

    set_advertising_enable::send(hi, true).await.unwrap();

    println!("{:5>}", "Advertising Enabled!");
}

async fn advertise_teardown<T: bo_tie::hci::HostChannelEnds>(hi: &mut bo_tie::hci::Host<T>) {
    bo_tie::hci::commands::le::set_advertising_enable::send(hi, false)
        .await
        .unwrap();
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
        println!("awaiting for 'ctrl-C' (or SIGINT) to stop advertising");

        hook.await
    }
}

/// Stub for signal setup
///
/// This is a generic fallback that returns future that will forever pend. This method should try
/// to be avoided unless it is intended that the device running the example will be power cycled.
#[cfg(not(unix))]
async fn setup_sig() {}

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

    let exit_future = setup_sig();

    TermLogger::init(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    let (interface, host_ends) = create_hci!();

    // The interface async task must be spawned before any
    // messages are sent or received with the Bluetooth Controller
    // (however it does not a multi-threaded executor to be spawned).
    tokio::spawn(interface.run());

    let mut host = bo_tie::hci::Host::init(host_ends)
        .await
        .expect("failed to initialize host");

    let adv_name = bo_tie::host::gap::assigned::local_name::LocalName::new("Adv Test", None);

    let mut adv_data = bo_tie::hci::commands::le::set_advertising_data::AdvertisingData::new();

    adv_data.try_push(adv_name).unwrap();

    advertise_setup(&mut host, adv_data).await;

    exit_future.await;

    advertise_teardown(&mut host).await;
}
