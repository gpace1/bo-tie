//! Privacy in the Bluetooth Controller

use bo_tie::hci::{Connection, Host, HostChannelEnds};
use bo_tie::host::sm::{IdentityAddress, Keys};

pub struct Controller(Vec<IdentityAddress>);

impl Controller {
    pub fn new() -> Self {
        Controller(Vec::new())
    }

    /// Add a device to the resolving list when using the Bluetooth Controller for privacy
    pub async fn add_device_resolving_list<H: HostChannelEnds>(&mut self, host: &mut Host<H>, keys: &Keys) {
        use bo_tie::hci::commands::le::{
            add_device_to_resolving_list, set_address_resolution_enable, set_privacy_mode,
            set_resolvable_private_address_timeout, PeerIdentityAddressType,
        };

        let peer_identity_address_type = if keys.get_peer_identity().unwrap().is_public() {
            PeerIdentityAddressType::PublicIdentityAddress
        } else {
            PeerIdentityAddressType::RandomStaticIdentityAddress
        };

        let peer_identity_address = keys.get_peer_identity().unwrap().get_address();

        let peer_irk = keys.get_peer_irk().unwrap();

        let local_irk = keys.get_irk().unwrap();

        let parameter = add_device_to_resolving_list::Parameter {
            peer_identity_address_type,
            peer_identity_address,
            peer_irk,
            local_irk,
        };

        add_device_to_resolving_list::send(host, parameter).await.unwrap();

        let privacy_mode = set_privacy_mode::PrivacyMode::NetworkPrivacy;

        let parameter = set_privacy_mode::Parameter {
            peer_identity_address_type,
            peer_identity_address,
            privacy_mode,
        };

        // This is a 5.0+ command so it may not be available.
        // That is fine as 4.2 only supports the equivalent
        // of `NetworkPrivacy`.
        set_privacy_mode::send(host, parameter).await.ok();

        set_resolvable_private_address_timeout::send(host, std::time::Duration::from_secs(60 * 4))
            .await
            .unwrap();

        set_address_resolution_enable::send(host, true).await.unwrap();

        self.0.push(keys.get_peer_identity().unwrap())
    }

    pub fn get_bonded(&self) -> Vec<IdentityAddress> {
        self.0.clone()
    }

    pub async fn remove_device_from_resolving_list<H: HostChannelEnds>(
        &mut self,
        host: &mut Host<H>,
        identity: &IdentityAddress,
    ) {
        use bo_tie::hci::commands::le::remove_device_from_resolving_list::{self, Parameter};
        use bo_tie::hci::commands::le::PeerIdentityAddressType;

        let parameter = Parameter {
            peer_identity_address_type: if identity.is_public() {
                PeerIdentityAddressType::PublicIdentityAddress
            } else {
                PeerIdentityAddressType::RandomStaticIdentityAddress
            },
            peer_identity_address: identity.get_address(),
        };

        remove_device_from_resolving_list::send(host, parameter).await.unwrap();

        if let Some(index) = self.0.iter().position(|i| i == identity) {
            self.0.swap_remove(index);
        }
    }

    /// Clear the resolving list on the Controller
    pub async fn clear_resolving_list<H: HostChannelEnds>(&mut self, host: &mut Host<H>) {
        bo_tie::hci::commands::le::clear_resolving_list::send(host)
            .await
            .unwrap();

        self.0.clear();
    }

    pub async fn set_timeout<H: HostChannelEnds>(&self, host: &mut Host<H>, timeout: std::time::Duration) {
        bo_tie::hci::commands::le::set_resolvable_private_address_timeout::send(host, timeout)
            .await
            .unwrap();
    }

    /// Configure the advertising parameters for when the Bluetooth Controller generates resolvable
    /// private addresses.
    pub async fn start_private_advertising<H: HostChannelEnds>(&self, host: &mut Host<H>) {
        use bo_tie::hci::commands::le::{
            set_advertising_data, set_advertising_enable, set_advertising_parameters, set_scan_response_data,
            OwnAddressType,
        };

        let mut adv_prams = set_advertising_parameters::AdvertisingParameters::default();

        adv_prams.advertising_type =
            set_advertising_parameters::AdvertisingType::ConnectableAndScannableUndirectedAdvertising;

        // this is the key for advertising with a resolvable private address
        adv_prams.own_address_type = OwnAddressType::RpaFromLocalIrkOrRandomAddress;

        set_advertising_enable::send(host, false).await.ok();

        set_advertising_data::send(host, None).await.unwrap();

        set_scan_response_data::send(host, None).await.unwrap();

        set_advertising_parameters::send(host, adv_prams).await.unwrap();

        set_advertising_enable::send(host, true).await.unwrap();
    }

    pub fn get_identified<C>(&self, connection: &Connection<C>) -> IdentityAddress {
        if connection.is_peer_address_random() {
            IdentityAddress::StaticRandom(connection.get_peer_address())
        } else {
            IdentityAddress::Public(connection.get_peer_address())
        }
    }
}
