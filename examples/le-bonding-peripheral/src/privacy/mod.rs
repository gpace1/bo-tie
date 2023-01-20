//! LE Privacy
//!
//! Privacy is a way for two devices to reconnect and re-encrypt without having to go through
//! pairing. When two devices are in a non-connected state, they will use resolvable private
//! addresses to determine what devices to connect to. A resolvable private address requires an
//! identity resolving key to *resolve*, and in doing so authenticate the identity of a connecting
//! or advertising device.
//!
//! There is two major ways to perform privacy in a peripheral. The most common way is to utilize
//! the resolvable private in the Bluetooth Controller to only generate HCI connection events for
//! private address that are successfully resolved. The other way is to have the host perform
//! resolving on all connections and disconnect those whose addresses are not a resolvable private
//! address or do not resolve.
//!
//! ## Controller Implemented Privacy
//! Using the Bluetooth Controller is the easiest way to setup and use Privacy, but the hardware
//! needs to support the LE Privacy feature. For the most part this is not a problem as most LE
//! supported Controllers. The HCI command *[LE Read Local Supported Features]* can be used to check
//! if the Controller supports the feature. The most likely reason for not having LE Privacy is that
//! device was grandfathered from Bluetooth 4.0 (or is a 4.0 or 4.1 device). Lots of devices say
//! they are 5.X compliant whereby they were a 4.0 chip that met the minimum requirements for
//! compliance of 5.X or greater versions of Bluetooth (Privacy as a Controller feature was added in
//! Bluetooth version 4.2).   
//!
//! Setting up the Controller to enable privacy requires the minimum of the commands
//! [LE Add Device To Resolving List] and [LE Set Address Resolution Enable Command]. If the filter
//! list is enabled then [LE Add Device To Filter List] is also required, but the filter list is not
//! used in this example. This example uses the full range of required methods for robustness and to
//! make it easier to be repurposed :). Before Advertising is started the configuration is set to
//! generate a resolvable private address for the advertiser address.
//!
//! ## Host Implement Privacy
//! When the Host is used for privacy in a device it must resolve addresses after a connection has
//! been made between two devices. It also needs to generate the resolvable private address used for
//! advertising. The process is a more complicated then using the Controller. Section 10.7 of the
//! Generic Access Profile (vol 3, part C, section 10.7), section 6 of the LE link layer
//! specification (vol 6, part B, section 6), and section 1.3.2 of the LE link layer specification
//! (vol 6, part B, section 1.3.2) need to be implemented by the Host.
//!
//! ### Resolving
//! A resolvable private address has two parts. The first half of the address is called a `prand`
//! and the last half is the `hash`. `prand` is randomly generated but the `hash` is generated using
//! an identity resolving key and the [`ah`] function. The peer device will use the same identity
//! resolving key to check if the `hash` was generated from the `prand` in the address. This
//! authenticates the address and the central device can then use a previously generated long term
//! key to initiate encryption.
//!
//! As part of bonding both devices must transfer their identity resolving key. This means that both
//! devices hold on to two keys, the peer key and their key. What key is used for creating a
//! resolvable private key depends on what kind of advertising is used by the peripheral device.
//! This is specification defined under the Privacy section of the Link Layer Specification of the
//! Low Energy Controller (Vol 6, Part B, Section 6).
//!
//! [`ah`]: bo_tie::host::sm::toolbox::ah
//! [LE Read Local Supported Features]: bo_tie::hci::commands::le::read_local_supported_features
//! [LE Add Device To Resolving List]: bo_tie::hci::commands::le::add_device_to_resolving_list
//! [LE Add Device To Filter List]: bo_tie::hci::commands::le::add_device_to_filter_list
//! [`b`]: bo_tie::hci::commands::le::remove_device_from_resolving_list

mod controller_privacy;
pub mod host_privacy;

use bo_tie::hci::{Connection, Host, HostChannelEnds};
use bo_tie::host::sm::Keys;
use bo_tie::LeFeatures;

enum PrivacyMode {
    Controller(controller_privacy::Controller),
    Host(host_privacy::HostPrivacy),
}

/// Structure for using Privacy for the selected Controller
///
/// This combines both the Controller Privacy and Host Privacy routines into one type. Controller
/// privacy is always preferred over Host implemented privacy if the Controller supports the feature
/// LE Privacy.
///
/// `Privacy` has two "modes", *controller* and *host*. In *Controller* mode the Bluetooth
/// Controller performs the generation and resolving of resolvable private addresses. In *host* mode
/// this example will do the generation and resolving of resolvable private addresses. The mode is
/// determined by checking if the Bluetooth Controller has the LE feature `LL Privacy`. If it does
/// then *controller* is set as the mode, but if it does not then the mode is *host*.
pub struct Privacy {
    mode: PrivacyMode,
}

impl Privacy {
    /// Create a new `Privacy`
    ///
    /// This first queries the Controller for the LE local features to determine if `LL Privacy` is
    /// available in the controller, then a `Privacy` is created`.
    pub async fn new<H: HostChannelEnds>(host: &mut Host<H>) -> Self {
        use bo_tie::hci::commands::le::read_local_supported_features;

        let features = read_local_supported_features::send(host).await.unwrap();

        let has_privacy_feature = features.iter().any(|feature| feature == LeFeatures::LlPrivacy);

        let mode = if has_privacy_feature {
            PrivacyMode::Controller(controller_privacy::Controller::new())
        } else {
            PrivacyMode::Host(host_privacy::HostPrivacy::new())
        };

        Self { mode }
    }

    /// Add a device to the resolving list
    pub async fn add_device_to_resolving_list<H: HostChannelEnds>(&mut self, host: &mut Host<H>, keys: &Keys) {
        match &mut self.mode {
            PrivacyMode::Controller(c) => c.add_device_resolving_list(host, keys).await,
            PrivacyMode::Host(h) => h.add_to_resolving_list(keys),
        }
    }

    /// Clear all devices from the resolving list
    pub async fn clear_resolving_list<H: HostChannelEnds>(&mut self, host: &mut Host<H>) {
        match &mut self.mode {
            PrivacyMode::Controller(_) => controller_privacy::Controller::clear_resolving_list(host).await,
            PrivacyMode::Host(h) => h.clear_resolving_list(),
        }
    }

    /// Set the timeout
    ///
    /// This sets the timeout for the resolvable private addresses (RPA) within the advertisement.
    /// When the Controller is used it will create a new resolvable private address after the
    /// timeout is complete. If resolvable private address are generated by the host, then
    /// `set_timeout` will return an [`Interval`]. Everytime `Interval` creates a tick, the method
    /// [`host_regen_addresses`] must be called.
    ///
    /// [`host_regen_address`]: Privacy::host_regen_address
    pub async fn set_timeout<H: HostChannelEnds>(
        &mut self,
        host: &mut Host<H>,
        timeout: std::time::Duration,
    ) -> Option<host_privacy::RpaInterval> {
        match &mut self.mode {
            PrivacyMode::Controller(_) => {
                controller_privacy::Controller::set_timeout(host, timeout).await;

                None
            }
            PrivacyMode::Host(h) => Some(h.set_timeout(timeout)),
        }
    }

    /// Setup Advertising with Resolvable Private Addresses
    pub async fn set_advertising_configuration<H: HostChannelEnds>(&mut self, host: &mut Host<H>) {
        match &mut self.mode {
            PrivacyMode::Controller(c) => c.set_advertising_parameters(host).await,
            PrivacyMode::Host(h) => h.set_advertising_parameters(host).await,
        }
    }

    /// Validate a Connection
    ///
    /// In *host* mode this validates the address of the device that initiated the connection is
    /// resolvable. In *controller* mode this is effectively a no-op.
    ///
    /// If the device address cannot be resolved, the connection will be sent the disconnection
    /// command with the error "invalid authorization".
    pub fn validate<C>(&self, connection: Connection<C>) -> Option<Connection<C>> {
        match &self.mode {
            PrivacyMode::Host(h) => h.validate_connection(connection),
            _ => Some(connection),
        }
    }
}
