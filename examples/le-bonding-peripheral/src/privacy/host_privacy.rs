//! Privacy implemented by the Host
//!
//! When the Bluetooth Controller does not support the feature *LL Privacy*, the host must implement
//! the feature in order to support privacy.

use bo_tie::hci::{Connection, Host, HostChannelEnds};
use bo_tie::host::sm::{IdentityAddress, Keys};
use bo_tie::BluetoothDeviceAddress;

#[derive(Copy, Clone, PartialEq)]
struct ResolvingInformation {
    identity: IdentityAddress,
    peer_identity: IdentityAddress,
    irk: u128,
    peer_irk: u128,
}

pub struct HostPrivacy {
    // for simplicity this list consists of only one entry
    resolving_list: Option<ResolvingInformation>,
}

impl HostPrivacy {
    pub fn new() -> Self {
        let resolving_list = None;

        HostPrivacy { resolving_list }
    }

    /// Add to the hosts resolving list
    pub fn add_to_resolving_list(&mut self, keys: &Keys) {
        let identity = keys.get_identity().unwrap();
        let irk = keys.get_irk().unwrap();
        let peer_identity = keys.get_peer_identity().unwrap();
        let peer_irk = keys.get_peer_irk().unwrap();

        let resolve_info = ResolvingInformation {
            identity,
            peer_identity,
            irk,
            peer_irk,
        };

        self.resolving_list = Some(resolve_info);
    }

    /// Clear the resolving list information in the Host
    pub fn clear_resolving_list(&mut self) {
        self.resolving_list = None;
    }

    pub fn set_timeout(&mut self, timeout: std::time::Duration) -> RpaInterval {
        let info = self.resolving_list.unwrap();

        RpaInterval {
            interval: tokio::time::interval_at(tokio::time::Instant::now() + timeout, timeout),
            irk: info.irk,
            peer_irk: info.peer_irk,
        }
    }

    /// Configure advertising when the host is performing Privacy
    pub async fn set_advertising_parameters<H: HostChannelEnds>(&mut self, host: &mut Host<H>) {
        let this_irk = self.resolving_list.unwrap().irk;
        let peer_irk = self.resolving_list.unwrap().peer_irk;

        set_advertising_parameters_private(host, this_irk, peer_irk).await
    }

    /// Validate the Connection
    ///
    /// The connecting device must have a valid resolvable private address. Because the Controller
    /// does not perform private address resolving, any device can form a connection to this device
    /// in the controller.
    pub fn validate_connection<C>(&self, connection: Connection<C>) -> Option<Connection<C>> {
        let info = self.resolving_list.unwrap();

        connection.get_peer_address().resolve(info.peer_irk).then(|| connection)
    }
}

async fn set_advertising_parameters_private<H: HostChannelEnds>(host: &mut Host<H>, this_irk: u128, peer_irk: u128) {
    use bo_tie::hci::commands::le::{set_advertising_parameters, set_random_address, OwnAddressType};

    let mut adv_prams = set_advertising_parameters::AdvertisingParameters::default();

    let own_address = BluetoothDeviceAddress::new_resolvable(this_irk);

    let peer_address = BluetoothDeviceAddress::new_resolvable(peer_irk);

    adv_prams.peer_address = peer_address;

    adv_prams.advertising_type =
        set_advertising_parameters::AdvertisingType::ConnectableAndScannableUndirectedAdvertising;

    adv_prams.peer_address_type = set_advertising_parameters::PeerAddressType::RandomAddress;

    adv_prams.own_address_type = OwnAddressType::RandomDeviceAddress;

    set_random_address::send(host, own_address).await.unwrap();

    set_advertising_parameters::send(host, adv_prams).await.unwrap();
}

pub struct RpaInterval {
    interval: tokio::time::Interval,
    irk: u128,
    peer_irk: u128,
}

impl RpaInterval {
    pub async fn tick(&mut self) -> RegenRpa {
        self.interval.tick().await;

        RegenRpa {
            irk: self.irk,
            peer_irk: self.peer_irk,
        }
    }
}

/// Re-generate the advertised Resolvable Private Addresses
///
/// This is returned by
pub struct RegenRpa {
    irk: u128,
    peer_irk: u128,
}

impl RegenRpa {
    pub async fn regen<H: HostChannelEnds>(self, host: &mut Host<H>) {
        use bo_tie::hci::commands::le::set_advertising_enable;

        set_advertising_enable::send(host, false).await.unwrap();

        set_advertising_parameters_private(host, self.irk, self.peer_irk).await;

        set_advertising_enable::send(host, true).await.unwrap();
    }
}
