//! Advertising
//!
//! Advertising is done such that devices can either connect to this example for the first time or
//! reconnect using the LE privacy feature.
//!
//! # Discoverable Advertising
//! Except for initially after the example is run, advertising will only be discoverable upon the
//! user ...
//!
//! # Private Advertising
//! Privacy allows for this device (and the peer device) to authenticate the other device it is
//! connecting to. In order for this to occur both devices must be bonded as an Identity Resolving
//! Key (IRK) must be exchanged between the two devices. This key is used to create resolvable
//! private addresses as part of advertising. If the address cannot be resolved by the peer device
//! then the connection will be rejected.
//!
//! Depending on the features of the Controller, privacy is either implemented in the Bluetooth
//! Controller or by the Host. As part of creating a [`Privacy`] object, the features of the
//! Controller are checked for the feature 'Privacy'. If the feature is enabled, then the Controller
//! will handle privacy, otherwise the equivalent implementation is done within this example as the
//! 'host' implementation.

pub mod privacy;

use bo_tie::hci::commands::le::{
    set_advertising_data, set_advertising_enable, set_advertising_parameters, set_random_address,
    set_scan_response_data, OwnAddressType,
};
use bo_tie::hci::{Host, HostChannelEnds};
use bo_tie::host::gap::assigned;
use bo_tie::BluetoothDeviceAddress;

pub async fn discoverable_advertising_setup<H: HostChannelEnds>(host: &mut Host<H>) -> Kind {
    let discoverable_address = BluetoothDeviceAddress::new_random_non_resolvable();

    let adv_name = assigned::local_name::LocalName::new(crate::EXAMPLE_NAME, ["HRP example", "HRP"]);

    let mut adv_flags = assigned::flags::Flags::new();

    // This is the flag specification for a LE-only, limited discoverable advertising
    adv_flags
        .get_core(assigned::flags::CoreFlags::LeGeneralDiscoverableMode)
        .enable();
    adv_flags
        .get_core(assigned::flags::CoreFlags::BrEdrNotSupported)
        .enable();

    let mut adv_uuids = assigned::service_uuids::new_16(false);

    adv_uuids.add(std::convert::TryFrom::try_from(crate::server::HEART_RATE_SERVICE_UUID).unwrap());

    let mut adv_data = set_advertising_data::AdvertisingData::new();

    adv_data.try_push(adv_flags).unwrap();
    adv_data.try_push(adv_uuids).unwrap();

    let mut scan_data = set_scan_response_data::ScanResponseData::new();

    scan_data.try_push(adv_name).unwrap();

    // this may return an invalid error (set_advertising_enable should
    // not return an error here if the device supports LE transmission)
    // on some devices (because advertising is already be disabled),
    // so the result is okayed instead of unwrapped.
    set_advertising_enable::send(host, false).await.ok();

    set_random_address::send(host, discoverable_address).await.unwrap();

    set_advertising_data::send(host, adv_data).await.unwrap();

    set_scan_response_data::send(host, scan_data).await.unwrap();

    let mut adv_prams = set_advertising_parameters::AdvertisingParameters::default();

    adv_prams.own_address_type = OwnAddressType::RandomDeviceAddress;

    set_advertising_parameters::send(host, adv_prams).await.unwrap();

    set_advertising_enable::send(host, true).await.unwrap();

    Kind::Discoverable(discoverable_address)
}

pub async fn disable_advertising<H: HostChannelEnds>(host: &mut Host<H>) {
    set_advertising_enable::send(host, false).await.ok();
}

#[derive(Copy, Clone)]
pub enum Kind {
    Off,
    Discoverable(BluetoothDeviceAddress),
    Private,
}
