//! Advertising example
//!
//! This examples sets up the bluetooth device to advertise. The only data sent in each advertising
//! message is just the local name "Advertiser Test". The application will continue to run until
//! the example is sent a signal (e.g. by pressing ctrl-c on a unix system).
//!
//! # Note
//! Super User privileges may be required to interact with your bluetooth peripheral. To do will
//! probably require the full path to cargo. The cargo binary is usually locacted in your home
//! directory at `.cargo/bin/cargo`.

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

fn get_arg_options() -> getopts::Options {
    let mut opts = getopts::Options::new();
    opts.parsing_style(getopts::ParsingStyle::FloatingFrees);
    opts.long_only(false);
    opts.optflag("h", "help", "Print this help menu");
    opts.opt(
        "s",
        "service-uuid",
        "Space-separated 128 bit service uuids to advertise with. The UUIDs must be in the \
            format of XX:XX:XX:XX:XX:XX (From most significant to least significant byte)",
        "UUIDs",
        getopts::HasArg::Yes,
        getopts::Occur::Multi,
    );
    opts
}

fn parse_args(mut args: std::env::Args) -> Option<bo_tie::hci::commands::le::set_advertising_data::AdvertisingData> {
    let options = get_arg_options();

    let program_name = args.next().unwrap();

    let matches = match options.parse(&args.collect::<Vec<_>>()) {
        Ok(all_match) => all_match,
        Err(no_match) => panic!("{}", no_match.to_string()),
    };

    if matches.opt_present("h") {
        print!("{}", options.usage(&format!("Usage: {} [options]", program_name)));
        std::process::exit(0);
    } else {
        let mut advertising_data = bo_tie::hci::commands::le::set_advertising_data::AdvertisingData::new();

        // Add service UUIDs to the advertising data
        let services_128 = matches.opt_strs("s").into_iter().fold(
            bo_tie::host::gap::assigned::service_uuids::new_128(true),
            |mut services, str_uuid| {
                let uuid = bo_tie::host::Uuid::try_from(str_uuid.as_str()).expect("Invalid Uuid");

                services.add(uuid.into());

                services
            },
        );

        if !services_128.as_ref().is_empty() {
            advertising_data.try_push(services_128).expect("Couldn't add services");
        }

        Some(advertising_data)
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

    let mut adv_data = match parse_args(std::env::args()) {
        Some(user_advertising_data) => user_advertising_data,
        None => bo_tie::hci::commands::le::set_advertising_data::AdvertisingData::new(),
    };

    adv_data.try_push(adv_name).unwrap();

    advertise_setup(&mut host, adv_data).await;

    exit_future.await;

    advertise_teardown(&mut host).await;
}
