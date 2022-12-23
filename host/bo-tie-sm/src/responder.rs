//! Responder side of the Security Manager
//!
//! A responder is used by the peripheral device to to 'respond' to the security manager requests of
//! an initiating device.
//!
//! # Builder
//! A responding [`SecurityManger`] must be created from the builder [`SecurityManagerBuilder`]. The
//! builder is used to configure the type of pairing performed and the bonding keys that allowed for
//! distribution by the security manager.  The default configuration is to distribute the identity
//! resolving key during bonding and use *just works* man in the middle (MITM) protection.
//! Unfortunately other forms of MITM protection require access to things outside the scope of the
//! implementation of this library.
//!
//! ```
#![cfg_attr(
    botiedocs,
    doc = r##"
# mod bo_tie::sm {
#    pub use bo_tie_sm::*;
# }
use bo_tie::responder::SecurityManagerBuilder;
"##
)]
#![cfg_attr(
    not(botiedocs),
    doc = r##"
use bo_tie_sm::responder::SecurityManagerBuilder;
"##
)]
//! # use bo_tie_util::BluetoothDeviceAddress;
//! # let this_address = BluetoothDeviceAddress::zeroed();
//! # let peer_address = BluetoothDeviceAddress::zeroed();
//!
//! let security_manager = SecurityManagerBuilder::new(this_address, peer_address, true, true)
//!     .build();
//! ```
//!
//! ### Bonding Keys
//! The responder can distribute and accept an identity resolving key (IRK) and a
//! Connection Signature Resolving Key (CSRK) during bonding. However, the default is to only
//! distribute an IRK and accept no keys from the initiator.
//!
//! The IRK is used for generating a resolvable private address and the CSRK is for signing data
//! that is part of an unencrypted advertising packet, so the only need to accept keys from the
//! initiator is if the roles of the devices could switch.
//!
//! ```
//! # use bo_tie_sm::responder::SecurityManagerBuilder;
//! # use bo_tie_util::BluetoothDeviceAddress;
//! let security_manager_builder = SecurityManagerBuilder::new(BluetoothDeviceAddress::zeroed(), BluetoothDeviceAddress::zeroed(), false, false);
//!
//! // create a security manager that will send an
//! // IRK and CSRK during bonding but only accept
//! // an IRK from the initiator.
//! security_manager_builder.sent_bonding_keys(|keys| {
//!     keys.enable_irk();
//!     keys.enable_csrk();
//! })
//! .accepted_bonding_keys(|keys| {
//!     keys.enable_irk();
//! })
//! .build()
//! # ;
//! ```
//!
//! ### Man in the Middle Protection
//! The builder is used for selecting what MITM protection is supported by the responder. All forms
//! except for just works (which is the same as having no MITM protection) require some form of user
//! or external system input.
//!
//! # Out of Band
//! The out of band MITM protection is the same process as just works, but it uses a secure tunnel
//! outside the Bluetooth connection between the two devices to transfer some of the pairing
//! information. In order for out of band to work it requires the method to also be MITM protected.
//! Using another communication protocol, such as [near field communication], is a common way to
//! perform out of band.
//!
//! In order to use out of band with this security manager, the methods of transferring data must
//! be set as part of the builder pattern of `SecurityManagerBuilder`. The methods
//! [`set_oob_sender`] and [`set_oob_receiver`] are used to register the means to send and receive
//! out of band data by the security manager.
//!
//! ```
//! # use bo_tie_util::BluetoothDeviceAddress;
//! # let this_addr = BluetoothDeviceAddress::zeroed();
//! # let remote_addr = BluetoothDeviceAddress::zeroed();
//! # let security_manager_builder = bo_tie_sm::responder::SecurityManagerBuilder::new(this_addr, remote_addr, false, false);
//! # async fn send_over_nfc(_: &[u8]) {}
//! # async fn receive_from_nfc() -> Vec<u8> { Vec::new() }
//!
//! let security_manager = security_manager_builder
//!     .set_oob_sender(|data: &[u8]| async { send_over_nfc(data).await })
//!     .set_oob_receiver(|| async { receive_from_nfc().await })
//!     .build()
//! # ;
//! ```

use crate::encrypt_info::AuthRequirements;
use crate::l2cap::ConnectionChannel;
use crate::pairing::{IOCapability, KeyDistributions, KeyPressNotification, PairingFailedReason};
use crate::OobDirection;
use crate::{
    encrypt_info, pairing, toolbox, Command, CommandData, CommandType, EnabledBondingKeysBuilder, Error, GetXOfP256Key,
    PairingData, PairingMethod, PasskeyAbility, PasskeyDirection, SecurityManagerError,
};
use alloc::vec::Vec;
use bo_tie_util::buffer::stack::LinearBuffer;
use bo_tie_util::BluetoothDeviceAddress;

macro_rules! error {
    ($connection_channel:ty) => {
        crate::SecurityManagerError<bo_tie_l2cap::send_future::Error<<$connection_channel>::SendFutErr>>
    }
}

/// Used to generate the r value for passkey entry
///
/// See rai/rbi toolbox function [`f4`]
///
/// [`f4`]: toolbox::f4
macro_rules! passkey_r {
    ($passkey:expr, $passkey_round:expr) => {
        if 0 == $passkey & (1 << $passkey_round) {
            0x80
        } else {
            0x81
        }
    };
}

/// A builder for a [`SlaveSecurityManager`]
///
/// This is used to construct a `SlaveSecurityManager`. However building requires the
///
/// ## Bonding
/// By default, bonding is configured to be done with the peer device. If bonding support is not
/// desired, it can be disabled with the method `no_boding`.
///
/// ## Man In The Middle protection
/// By default, a Security Manager created by this builder does not have MITM protection, and will
/// only support the "just works" pairing. In order for Man in the Middle (MITM) protection to be
/// supported by the built Security Manager, at least one kind of operation to prevent MITM
/// protection must be enabled.
///
/// #### Disabling Just Works
/// Just works can be disabled via the method `no_just_works`, however another pairing method must
/// be enabled or `build` will panic.
///
/// #### Out of Band Support
/// Out of Band (OOB) requires the usage of external types to facilitate the passing of out of band
/// data. When a `SecurityManagerBuilder` is created with `new`, OOB functionality is set to be
/// unsupported. At least one of the methods `set_oob_sender` and `set_oob_receiver` must be called
/// to enable the usage of OOB MITM protection.
///
/// The level of security that the OOB method uses is completely out of scope of this builder to be
/// verified by it. You must ensure that the out of band transport used has sufficient MITM
/// protection to provide a successful Authorization.
pub struct SecurityManagerBuilder {
    encryption_key_min: usize,
    encryption_key_max: usize,
    remote_address: crate::BluetoothDeviceAddress,
    this_address: crate::BluetoothDeviceAddress,
    remote_address_is_random: bool,
    this_address_is_random: bool,
    enable_just_works: bool,
    enable_number_comparison: bool,
    enable_passkey: PasskeyAbility,
    oob: Option<OobDirection>,
    can_bond: bool,
    distribute_irk: bool,
    distribute_csrk: bool,
    accept_irk: bool,
    accept_csrk: bool,
    prior_keys: Option<super::Keys>,
    assert_check_mode_one: Option<bo_tie_gap::security::LeSecurityModeOne>,
    assert_check_mode_two: Option<bo_tie_gap::security::LeSecurityModeTwo>,
}

impl SecurityManagerBuilder {
    /// Create a new `SlaveSecurityManagerBuilder`
    pub fn new(
        connected_device_address: crate::BluetoothDeviceAddress,
        this_device_address: crate::BluetoothDeviceAddress,
        is_connected_devices_address_random: bool,
        is_this_device_address_random: bool,
    ) -> Self {
        Self {
            encryption_key_min: super::ENCRYPTION_KEY_MAX_SIZE,
            encryption_key_max: super::ENCRYPTION_KEY_MAX_SIZE,
            remote_address: connected_device_address,
            this_address: this_device_address,
            remote_address_is_random: is_connected_devices_address_random,
            this_address_is_random: is_this_device_address_random,
            enable_just_works: true,
            enable_number_comparison: false,
            enable_passkey: PasskeyAbility::None,
            oob: None,
            can_bond: true,
            distribute_irk: true,
            distribute_csrk: false,
            accept_irk: true,
            accept_csrk: false,
            prior_keys: None,
            assert_check_mode_one: None,
            assert_check_mode_two: None,
        }
    }
}

impl SecurityManagerBuilder {
    /// Set the keys to the peer device if it is already paired
    ///
    /// This assigns the keys that were previously generated. When created, the Security Manager
    /// will be able to return these keys even when pairing has not occurred during the current
    /// connection.
    ///
    /// # Note
    /// No verification is done for `keys`. It is assumed the keys were generated and are valid for
    /// the peer device.
    pub fn set_already_paired(mut self, keys: super::Keys) -> Result<Self, &'static str> {
        if keys.get_ltk().is_some() {
            self.prior_keys = Some(keys);

            Ok(self)
        } else {
            Err("missing long term key")
        }
    }

    /// Use GAP's Security Mode One for the Configuration of the Security Manager
    ///
    /// This method ensures that the Security Manager meets the requirements of the `level` for
    /// Security Mode One.
    ///
    /// Security Mode One defines the requirements for authentication and encryption for data
    /// transfer within a connection. This affects the pairing mode requirements of the Security
    /// Manager for establishing encryption.
    ///
    /// ### `Level1` and `Level2`
    /// Level one corresponds to no security and Level two corresponds to unauthenticated pairing.
    /// As far as creating a Security Manager is concerned these levels are equivalent (level one
    /// just means that use of a Security Manager is optional). When using either enum the Security
    /// Manager will be configured to allow just works pairing.
    ///
    /// If you only want to use `Level1`, then do not use a Security Manager.
    ///
    /// ### `Level3` and `Level4`
    /// Level three and level four are equivalent for this implementation of a Security Manager, as
    /// only Secure Connections is implemented. Level three requires authenticated pairing with
    /// encryption, and level four requires the same security but only using LE Secure Connections.
    ///
    /// Both these enums disable 'just works'. This means that the method [`build`] will panic if
    /// another pairing method is not enabled. Either [`enable_number_comparison`] or
    /// [`enable_passcode_entry`] must be called on this builder whenever using `Level3` or
    /// `Level4`.
    ///
    /// [`build`]: SecurityManagerBuilder::build
    /// [`enable_number_comparison`]: SecurityManagerBuilder::enable_number_comparison
    /// [`enable_passcode_entry`]: SecurityManagerBuilder::enable_passcode_entry
    /// [`enable_number_comparison`]
    pub fn ensure_security_mode_one(mut self, level: bo_tie_gap::security::LeSecurityModeOne) -> Self {
        self.assert_check_mode_one = level.into();
        self
    }

    /// Use GAP's Security Mode Two for the Configuration the Security Manager
    ///
    /// This method ensures that the Security Manager meets the requirements fo the `level` for
    /// Security Mode Two.
    ///
    /// Security Mode two defines the security aspects of signed data. For the Security Manager this
    /// sets the requirements for how the Connection Signature Resolving Key (CSRK) is distributed
    ///
    /// ### Level 1
    /// No affect on the pairing requirements of the Security Manager.
    ///
    /// ### Level 2
    /// If the CSRK is configured to be sent by the method [`sent_bonding_keys`] or received by
    /// [`accepted_bonding_keys`], the pairing method 'just works' will be disabled. Either
    /// [`enable_number_comparison`] or [`enable_passcode_entry`] be called to set the pairing
    /// method, or the method [`build`] will panic.
    ///
    /// If a CSRK is neither sent nor accepted, then this level has no affect on the pairing
    /// requirements of the Security Manager.
    ///
    /// [`sent_bonding_keys`]: SecurityManagerBuilder::sent_bonding_keys
    /// [`accepted_bonding_keys`]: SecurityManagerBuilder::accepted_bonding_keys
    /// [`enable_number_comparison`]: SecurityManagerBuilder::enable_number_comparison
    /// [`enable_passcode_entry`]: SecurityManagerBuilder::enable_passcode_entry
    /// [`build`]: SecurityManagerBuilder::build
    pub fn ensure_security_mode_two(mut self, mode: bo_tie_gap::security::LeSecurityModeTwo) -> Self {
        self.assert_check_mode_two = mode.into();
        self
    }

    /// Disable 'Just Works' Pairing
    ///
    /// Just works pairing requires no authentication to establish encryption. Disabling 'just
    /// works' requires the enabling of either passkey or number comparison pairing (see
    /// [`enable_number_comparison`] or [`enable_passcode_entry`]).
    ///
    /// [`enable_number_comparison`]: SecurityManagerBuilder::enable_number_comparison
    /// [`enable_passcode_entry`]: SecurityManagerBuilder::enable_passcode_entry
    pub fn disable_just_works(mut self) -> Self {
        self.enable_just_works = false;
        self
    }

    /// Enable 'Number Comparison' Pairing.
    ///
    /// Number Comparison requires the Bluetooth application user to confirm that numbers displayed
    /// on both devices are equivalent. This should only be enabled if this device can display six
    /// digits (base 10) and has some way for the user input the equivalent of 'yes' and 'no'.
    pub fn enable_number_comparison(mut self) -> Self {
        self.enable_number_comparison = true;
        self
    }

    /// Enable 'Passkey Entry' Pairing.
    ///
    /// This enabled passkey entry for a device that can both display and input six digits
    /// (base 10). Calling this means passkey entry is enabled for pairing where one device
    /// displays the passkey and the other device has the user inputs the passkey.
    ///
    /// # Notes
    /// * If the initiator has the ability to input a passkey, then this device will be used to
    ///   display the passkey.
    /// * This method overwrites the configuration set by [`enable_passkey_entry`] and
    ///   [`enable_passkey_display`]
    ///
    /// [`enable_passkey_entry`]: SecurityManagerBuilder::enable_passkey_entry
    /// [`enable_passkey_display`]: SecurityManagerBuilder::enable_passkey_display
    pub fn enable_passkey(mut self) -> Self {
        self.enable_passkey = PasskeyAbility::DisplayWithInput;
        self
    }

    /// Enable 'Passkey Entry' Pairing.
    ///
    /// Enable the input of a passkey `entry`. This should be used whenever a passkey can be entered
    /// but six digits (base 10) cannot be displayed.
    ///
    /// # Note
    /// This method overwrites the configuration set by [`enable_passkey`] and
    /// [`enable_passkey_display`]
    ///
    /// [`enable_passkey`]: SecurityManagerBuilder::enable_passkey
    /// [`enable_passkey_display`]: SecurityManagerBuilder::enable_passkey_display
    pub fn enable_passkey_entry(mut self) -> Self {
        self.enable_passkey = PasskeyAbility::InputOnly;
        self
    }

    /// Enable 'Passkey Entry' Pairing.
    ///
    /// Enable the display of a passkey `entry`. This should be used whenever six digits (base 10)
    /// can be displayed but digits cannot be input by the user.
    ///
    /// # Note
    /// This method overwrites the configuration set by [`enable_passkey_entry`] and
    /// [`enable_passkey_display`]
    ///
    /// [`enable_passkey_entry`]: SecurityManagerBuilder::enable_passkey_entry
    /// [`enable_passkey_display`]: SecurityManagerBuilder::enable_passkey_display
    pub fn enable_passkey_display(mut self) -> Self {
        self.enable_passkey = PasskeyAbility::DisplayOnly;
        self
    }

    /// Enable `Out of Band` Pairing
    ///
    /// This will enable the usage of out of band (OOB) pairing. The input `direction` is used for
    /// indicating the direction that OOB data can be sent.
    pub fn enable_oob(mut self, direction: OobDirection) -> Self {
        self.oob = Some(direction);
        self
    }

    /// Disable Bonding
    ///
    /// This creates a Security Manager that will not bond with the peer device after pairing is
    /// completed. Configuration set by [`sent_bonding_keys`] and [`accepted_bonding_keys`] will be
    /// ignored.
    ///
    /// [`sent_bonding_keys`]: SecurityManagerBuilder::sent_bonding_keys
    /// [`accepted_bonding_keys`]: SecurityManagerBuilder::accepted_bonding_keys
    pub fn disable_bonding(mut self) -> Self {
        self.can_bond = false;
        self
    }

    /// Set the bonding keys to be distributed by the responder
    ///
    /// When this method is called, the default configuration for key distribution is overwritten to
    /// disable the distribution of all bonding keys. The return must then be used to selectively
    /// enable what keys are sent by the security manager when bonding.
    ///
    /// By default only the Identity Resolving Key (IRK) is distributed to the initiator. This
    /// method does not need to be called if the default key configuration is desired.
    ///
    /// # Note
    /// This method has no affect if the Security Manager is built without bonding support.
    pub fn sent_bonding_keys<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut EnabledBondingKeysBuilder) -> &mut EnabledBondingKeysBuilder,
    {
        let mut enabled_bonding_keys = EnabledBondingKeysBuilder::new();

        f(&mut enabled_bonding_keys);

        self.distribute_irk = enabled_bonding_keys.irk;
        self.distribute_csrk = enabled_bonding_keys.csrk;

        self
    }

    /// Set the bonding keys to be accepted by this initiator
    ///
    /// When this method is called, the default configuration for key distribution is overwritten to
    /// not accept all bonding all keys. The return must then be used to selectively enable
    /// what keys are sent by the security manager when bonding.
    ///
    /// By default only the Identity Resolving Key (IRK) is accepted from the initiator. This
    /// method does not need to be called if the default key configuration is desired.
    ///
    /// # Note
    /// This method has no affect if the Security Manager is built without bonding support.
    pub fn accepted_bonding_keys<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut EnabledBondingKeysBuilder) -> &mut EnabledBondingKeysBuilder,
    {
        let mut enabled_bonding_keys = EnabledBondingKeysBuilder::new();

        f(&mut enabled_bonding_keys);

        self.accept_irk = enabled_bonding_keys.irk;
        self.accept_csrk = enabled_bonding_keys.csrk;

        self
    }

    /// Create the Authentication Requirements
    ///
    /// # Panic
    /// If the user disallows "just works" and no other paring method can be used.
    fn create_auth_req(
        &self,
    ) -> Result<LinearBuffer<{ AuthRequirements::full_depth() }, AuthRequirements>, crate::SecurityManagerBuilderError>
    {
        let mut auth_req = LinearBuffer::new();

        // mandatory as only Secure Connections (not legacy) is supported
        auth_req.try_push(AuthRequirements::Sc).unwrap();

        if self.can_bond {
            auth_req.try_push(AuthRequirements::Bonding).unwrap();
        }

        if self.enable_number_comparison || self.enable_passkey.is_enabled() || self.oob.is_some() {
            auth_req.try_push(AuthRequirements::ManInTheMiddleProtection).unwrap();
        } else if !self.enable_just_works {
            return Err(crate::SecurityManagerBuilderError);
        }

        if self.enable_passkey.is_enabled() {
            auth_req.try_push(AuthRequirements::KeyPress).unwrap();
        }

        Ok(auth_req)
    }

    /// Create the [`SecurityManager`]
    ///
    /// This will create a `SecurityManager`.
    ///
    /// # Panic
    /// `build` will panic if the configuration does not enable any form of pairing.
    pub fn build(self) -> SecurityManager {
        self.try_build().unwrap()
    }

    /// Try to create the `SlaveSecurityManager`
    ///
    /// This equivalent to [`build`] except an error is returned instead of panicking.
    pub fn try_build(self) -> Result<SecurityManager, crate::SecurityManagerBuilderError> {
        let initiator_key_distribution = super::get_keys(self.accept_irk, self.accept_csrk);

        let responder_key_distribution = super::get_keys(self.distribute_irk, self.distribute_csrk);

        let io_capability = match (self.enable_number_comparison, self.enable_passkey) {
            (_, PasskeyAbility::DisplayWithInput) => IOCapability::KeyboardDisplay,
            (true, _) => IOCapability::DisplayWithYesOrNo,
            (false, PasskeyAbility::DisplayOnly) => IOCapability::DisplayOnly,
            (false, PasskeyAbility::InputOnly) => IOCapability::KeyboardOnly,
            (false, PasskeyAbility::None) => IOCapability::NoInputNoOutput,
        };

        if !self.enable_just_works && io_capability.no_io_capability() {
            return Err(crate::SecurityManagerBuilderError);
        }

        let auth_req = self.create_auth_req()?;

        Ok(SecurityManager {
            io_capability,
            oob: self.oob,
            auth_req,
            allow_just_works: self.enable_just_works,
            encryption_key_size_min: self.encryption_key_min,
            encryption_key_size_max: self.encryption_key_max,
            initiator_key_distribution,
            responder_key_distribution,
            initiator_address: self.remote_address,
            responder_address: self.this_address,
            initiator_address_is_random: self.remote_address_is_random,
            responder_address_is_random: self.this_address_is_random,
            pairing_data: None,
            keys: self.prior_keys,
            link_encrypted: false,
        })
    }
}

pub struct SecurityManager {
    io_capability: IOCapability,
    oob: Option<OobDirection>,
    auth_req: LinearBuffer<{ AuthRequirements::full_depth() }, AuthRequirements>,
    allow_just_works: bool,
    encryption_key_size_min: usize,
    encryption_key_size_max: usize,
    initiator_key_distribution: &'static [KeyDistributions],
    responder_key_distribution: &'static [KeyDistributions],
    initiator_address: BluetoothDeviceAddress,
    responder_address: BluetoothDeviceAddress,
    initiator_address_is_random: bool,
    responder_address_is_random: bool,
    pairing_data: Option<PairingData>,
    keys: Option<super::Keys>,
    link_encrypted: bool,
}

impl SecurityManager {
    /// Indicate if the connection is encrypted
    ///
    /// This is used to indicate to the `SlaveSecurityManager` that it is safe to send bonding keys
    /// to the peer device. This is a deliberate extra step to ensure that the functions `send_irk`,
    /// `send_csrk`, `send_pub_addr`, and `send_rand_addr` are only used when the link is encrypted.
    ///
    /// # Note
    /// Encryption is out of scope of the Security Manager. The majority of devices support
    /// encryption in the Controller, but if not then encryption must be done by a custom lower
    /// layer protocol (between L2CAP and the Security Manager).  
    pub fn set_encrypted(&mut self, is_encrypted: bool) {
        self.link_encrypted = is_encrypted
    }

    /// Get the encryption keys
    ///
    /// This returns the encryption keys, if they exist. Keys will exist after they're generated
    /// once pairing completes, until then this method will return `None`.
    pub fn get_keys(&self) -> Option<&super::Keys> {
        self.keys.as_ref()
    }

    /// Send the Identity Resolving Key
    ///
    /// This will add the IRK to the cypher keys and send it to the other device if the internal
    /// encryption flag is set to true (by the method
    /// [`set_encrypted`](crate::sm::responder::SlaveSecurityManager::set_encrypted)) and pairing
    /// has completed.
    ///
    /// If the input `irk` evaluates to `None` then an IRK is generated before being added and sent.
    ///
    /// The IRK is returned if it was successfully sent to the other device
    pub async fn send_irk<C, Irk>(&mut self, connection_channel: &C, irk: Irk) -> Result<u128, error!(C)>
    where
        C: ConnectionChannel,
        Irk: Into<Option<u128>>,
    {
        if self.link_encrypted {
            let irk = irk.into().unwrap_or_else(|| toolbox::rand_u128());

            if let Some(super::Keys {
                irk: ref mut irk_opt, ..
            }) = self.keys
            {
                *irk_opt = Some(irk)
            }

            self.send(connection_channel, encrypt_info::IdentityInformation::new(irk))
                .await?;

            Ok(irk)
        } else {
            Err(Error::UnknownIfLinkIsEncrypted.into())
        }
    }

    /// Send the Connection Signature Resolving Key
    ///
    /// This will add the CSRK to the cypher keys and send it to the other device if the internal
    /// encryption flag is set to true (by the method
    /// [`set_encrypted`](crate::sm::responder::SlaveSecurityManager::set_encrypted)) and pairing
    /// has completed.
    ///
    /// If the input `csrk` evaluates to `None` then a CSRK is generated before being added and
    /// sent.
    ///
    /// The CSRK is returned if it was successfully sent to the other device
    ///
    /// # Note
    /// There is no input for the sign counter as the CSRK is considered a new value, and thus the
    /// sign counter within the CSRK will always be 0.
    pub async fn send_csrk<C, Csrk>(&mut self, connection_channel: &C, csrk: Csrk) -> Result<u128, error!(C)>
    where
        C: ConnectionChannel,
        Csrk: Into<Option<u128>>,
    {
        if self.link_encrypted {
            let csrk = csrk.into().unwrap_or_else(|| toolbox::rand_u128());

            if let Some(super::Keys {
                csrk: ref mut csrk_opt, ..
            }) = self.keys
            {
                *csrk_opt = Some((csrk, 0));
            }

            self.send(connection_channel, encrypt_info::SigningInformation::new(csrk))
                .await?;

            Ok(csrk)
        } else {
            Err(Error::UnknownIfLinkIsEncrypted.into())
        }
    }

    /// Send the identity address to the peer Device.
    ///
    /// This will send the `identity` address of this device to the peer Device if the internal
    /// encryption flag is set to true by [`set_encrypted`]. If `identity` is `None` then the
    /// address sent will fall back to either the identity within the cypher keys or the address
    /// used when pairing the devices, in that order.
    ///
    /// The identity address will be set in the cypher keys if the cypher keys exist within this
    /// security manager.
    ///
    /// The return is the identity address information sent to the peer device.
    ///
    /// # Error
    /// An error will occur if the encryption flag is not set or an error occurs trying to send the
    /// message to the peer device.
    ///
    /// [`set_encrypted`]: crate::sm::responder::SecurityManager::set_encrypted
    pub async fn send_identity<C, I>(
        &mut self,
        connection_channel: &C,
        identity: I,
    ) -> Result<crate::IdentityAddress, error!(C)>
    where
        C: ConnectionChannel,
        I: Into<Option<crate::IdentityAddress>>,
    {
        let identity = match identity.into() {
            Some(identity) => identity,
            None => {
                if let Some(super::Keys {
                    identity: Some(identity),
                    ..
                }) = self.keys
                {
                    identity
                } else {
                    if self.responder_address_is_random {
                        crate::IdentityAddress::StaticRandom(self.responder_address)
                    } else {
                        crate::IdentityAddress::Public(self.responder_address)
                    }
                }
            }
        };

        if self.link_encrypted {
            self.send(
                connection_channel,
                match identity {
                    crate::IdentityAddress::Public(addr) => encrypt_info::IdentityAddressInformation::new_pub(addr),
                    crate::IdentityAddress::StaticRandom(addr) => {
                        encrypt_info::IdentityAddressInformation::new_static_rand(addr)
                    }
                },
            )
            .await?;

            if let Some(super::Keys {
                identity: ref mut identity_opt,
                ..
            }) = self.keys
            {
                *identity_opt = Some(identity);
            }

            Ok(identity)
        } else {
            Err(Error::UnknownIfLinkIsEncrypted.into())
        }
    }

    async fn send<C, Cmd, P>(&self, connection_channel: &C, command: Cmd) -> Result<(), error!(C)>
    where
        C: ConnectionChannel,
        Cmd: Into<Command<P>>,
        P: CommandData,
    {
        use crate::l2cap::BasicInfoFrame;

        let acl_data = BasicInfoFrame::new(command.into().into_command_format().to_vec(), super::L2CAP_CHANNEL_ID);

        connection_channel
            .send(acl_data)
            .await
            .map_err(|e| SecurityManagerError::Sender(e))
    }

    async fn send_err<C>(&mut self, connection_channel: &C, fail_reason: PairingFailedReason) -> Result<(), error!(C)>
    where
        C: ConnectionChannel,
    {
        self.pairing_data = None;

        self.send(connection_channel, pairing::PairingFailed::new(fail_reason))
            .await
    }

    /// Process an input to the Security Manager
    ///
    async fn process_input<C>(&mut self, connection_channel: &C, input: Input) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        match input {
            Input::KeyPressNotification(k) => self.p_input_keypress_notification(connection_channel, k).await,
            Input::Passkey(k, passkey) => {
                self.p_input_keypress_notification(connection_channel, k).await?;

                Ok(self.p_input_passkey(passkey))
            }
            Input::YesNoInput(yes_no) => self.p_input_number_comparison(connection_channel, yes_no).await,
            Input::OutOfBand {
                address,
                random,
                confirm,
            } => {
                self.p_input_out_of_band(connection_channel, address, random, confirm)
                    .await
            }
        }
    }

    /// Process a keypress notification
    pub async fn p_input_keypress_notification<C>(
        &mut self,
        connection_channel: &C,
        notification: KeyPressNotification,
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        self.send(connection_channel, notification).await?;

        Ok(Status::None)
    }

    /// Process the user's passkey
    pub fn p_input_passkey(&mut self, passkey_val: u32) -> Status {
        match self.pairing_data {
            Some(PairingData { ref mut passkey, .. }) => *passkey = Some(passkey_val),
            _ => (),
        }

        Status::None
    }

    /// Process input of number comparison
    pub async fn p_input_number_comparison<C>(
        &mut self,
        connection_channel: &C,
        is_yes: bool,
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        if !is_yes {
            self.send_err(connection_channel, PairingFailedReason::NumericComparisonFailed)
                .await?;

            Ok(Status::PairingFailed(PairingFailedReason::NumericComparisonFailed))
        } else {
            Ok(Status::None)
        }
    }

    /// Process input out of band data
    ///
    /// This process out of band data that was sent from the initiating Security Manager to this
    /// Security Manager. This will check that the confirm sent by the initiator will match the
    /// calculated value by this Security Manager.
    pub async fn p_input_out_of_band<C>(
        &mut self,
        connection_channel: &C,
        _address: BluetoothDeviceAddress,
        random: u128,
        confirm: u128,
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        match self.pairing_data {
            Some(PairingData {
                pairing_method:
                    PairingMethod::Oob(OobDirection::BothSendOob) | PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob),
                peer_public_key: Some(ref peer_public_key),
                ref mut nonce,
                ..
            }) => {
                // Note: rb (a.k.a. PairingData::responder_random) is already
                // zero if direction is OnlyInitiatorSendsOob

                let pka = GetXOfP256Key::x(peer_public_key);

                if confirm == toolbox::f4(pka, pka, random, 0) {
                    *nonce = toolbox::nonce();

                    Ok(Status::None)
                } else {
                    self.send_err(connection_channel, PairingFailedReason::ConfirmValueFailed)
                        .await?;

                    Ok(Status::PairingFailed(PairingFailedReason::ConfirmValueFailed))
                }
            }
            _ => Ok(Status::None),
        }
    }

    /// Process a command from the initiating Security Manager
    ///
    /// Commands from the initiating Security Manager are processed by this method. The return is
    /// the status of the Security Manager, for more details on the status see the doc for the
    /// [`SecurityManager`].
    pub async fn process_command<C>(
        &mut self,
        connection_channel: &C,
        acl_data: &crate::l2cap::BasicInfoFrame<Vec<u8>>,
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        let command = match CommandType::try_from(acl_data) {
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;
                return Err(e.into());
            }
            Ok(cmd) => cmd,
        };

        let payload = &acl_data.get_payload()[1..];

        match command {
            CommandType::PairingRequest => self.p_pairing_request(connection_channel, payload).await,
            CommandType::PairingConfirm => self.p_pairing_confirm(connection_channel, payload).await,
            CommandType::PairingPublicKey => self.p_pairing_public_key(connection_channel, payload).await,
            CommandType::PairingRandom => self.p_pairing_random(connection_channel, payload).await,
            CommandType::PairingFailed => self.p_pairing_failed(connection_channel, payload).await,
            CommandType::PairingDHKeyCheck => self.p_pairing_dh_key_check(connection_channel, payload).await,
            CommandType::IdentityInformation => self.p_identity_info(connection_channel, payload).await,
            CommandType::IdentityAddressInformation => self.p_identity_address_info(connection_channel, payload).await,
            CommandType::SigningInformation => self.p_signing_info(connection_channel, payload).await,
            CommandType::PairingKeyPressNotification => self.p_keypress_notification(connection_channel, payload).await,
            cmd @ CommandType::MasterIdentification | // Legacy SM, not supported
            cmd @ CommandType::EncryptionInformation | // Legacy SM, not supported
            cmd => self.p_command_not_supported(connection_channel, cmd).await,
        }
    }

    /// Process a command that is not supported by this Security Manager
    async fn p_command_not_supported<C>(
        &mut self,
        connection_channel: &C,
        cmd: CommandType,
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        self.send_err(connection_channel, PairingFailedReason::CommandNotSupported)
            .await?;

        Err(Error::IncorrectCommand(cmd).into())
    }

    /// Process the pairing request
    async fn p_pairing_request<C>(&mut self, connection_channel: &C, data: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing request");

        let request = match pairing::PairingRequest::try_from_command_format(data) {
            Ok(request) => request,
            Err(_) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(Error::IncorrectCommand(CommandType::PairingPublicKey).into());
            }
        };

        if request.get_max_encryption_size() < self.encryption_key_size_min {
            self.send_err(connection_channel, PairingFailedReason::EncryptionKeySize)
                .await?;

            Ok(Status::PairingFailed(PairingFailedReason::EncryptionKeySize).into())
        } else {
            let oob_data_flag = match self.oob {
                Some(OobDirection::BothSendOob | OobDirection::OnlyInitiatorSendsOob) => {
                    pairing::OobDataFlag::AuthenticationDataFromRemoteDevicePresent
                }
                _ => pairing::OobDataFlag::AuthenticationDataNotPresent,
            };

            let response = pairing::PairingResponse::new(
                self.io_capability,
                oob_data_flag,
                self.auth_req.clone(),
                self.encryption_key_size_max,
                self.initiator_key_distribution,
                self.responder_key_distribution,
            );

            let pairing_method = PairingMethod::determine_method(
                request.get_oob_data_flag(),
                response.get_oob_data_flag(),
                request.get_io_capability(),
                response.get_io_capability(),
                false,
            );

            let initiator_io_cap = request.get_io_cap();
            let responder_io_cap = response.get_io_cap();

            self.send(connection_channel, response).await?;

            let (private_key, public_key) = toolbox::ecc_gen();

            if pairing_method.is_just_works() && !self.allow_just_works {
                self.send_err(connection_channel, PairingFailedReason::AuthenticationRequirements)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::AuthenticationRequirements))
            } else {
                log::info!("(SM) pairing Method: {:?}", pairing_method);

                self.pairing_data = Some(PairingData {
                    pairing_method,
                    public_key,
                    private_key: Some(private_key),
                    initiator_io_cap,
                    responder_io_cap,
                    nonce: toolbox::nonce(),
                    peer_public_key: None,
                    secret_key: None,
                    peer_nonce: None,
                    responder_random: 0,
                    initiator_random: 0,
                    mac_key: None,
                    passkey: None,
                    peer_confirm: None,
                    passkey_round: 0,
                });

                Ok(Status::None)
            }
        }
    }

    async fn p_pairing_public_key<C>(&mut self, connection_channel: &C, data: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing public Key");

        let initiator_pub_key = match pairing::PairingPubKey::try_from_command_format(data) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        match self.pairing_data {
            Some(PairingData {
                pairing_method: ref key_gen_method,
                ref public_key,
                ref nonce,
                ref mut private_key,
                ref mut peer_public_key,
                ref mut secret_key,
                ..
            }) => {
                let raw_pub_key = {
                    let key_bytes = public_key.clone().into_command_format();

                    let mut raw_key = [0u8; 64];

                    raw_key.copy_from_slice(&key_bytes);

                    raw_key
                };

                let remote_public_key = initiator_pub_key.get_key();

                log::trace!("(SM) remote public key: {:x?}", remote_public_key.as_ref());

                let peer_pub_key = match toolbox::PubKey::try_from_command_format(&remote_public_key) {
                    Ok(k) => k,
                    Err(e) => {
                        self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                            .await?;

                        return Err(e.into());
                    }
                };

                // Calculate the shared secret key
                let private_key = private_key.take().expect("Private key doesn't exist");

                *secret_key = toolbox::ecdh(private_key, &peer_pub_key).into();

                let confirm_value =
                    toolbox::f4(GetXOfP256Key::x(public_key), GetXOfP256Key::x(&peer_pub_key), *nonce, 0);

                *peer_public_key = peer_pub_key.into();

                // Send the public key of this device
                self.send(connection_channel, pairing::PairingPubKey::new(raw_pub_key))
                    .await?;

                // Process what to do next based on the key generation method
                match key_gen_method {
                    PairingMethod::JustWorks | PairingMethod::NumbComp => {
                        // Send the confirm value
                        self.send(connection_channel, pairing::PairingConfirm::new(confirm_value))
                            .await?;

                        Ok(Status::None)
                    }
                    PairingMethod::Oob(OobDirection::OnlyResponderSendsOob) => {
                        Ok(Status::OutOfBandOutput(OutOfBandOutput::new(self)))
                    }
                    PairingMethod::Oob(OobDirection::BothSendOob) => {
                        Ok(Status::OutOfBandInputOutput(OutOfBandInput, OutOfBandOutput::new(self)))
                    }
                    PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob) => {
                        Ok(Status::OutOfBandInput(OutOfBandInput))
                    }
                    PairingMethod::PassKeyEntry(direction) => match direction {
                        PasskeyDirection::InitiatorDisplaysResponderInputs
                        | PasskeyDirection::InitiatorAndResponderInput => {
                            let passkey_input = PasskeyInput::new(self, connection_channel).await?;

                            Ok(Status::PasskeyInput(passkey_input))
                        }
                        PasskeyDirection::ResponderDisplaysInitiatorInputs => {
                            let passkey_value = toolbox::new_passkey();

                            // rust borrow checker...
                            self.pairing_data.as_mut().unwrap().passkey = Some(passkey_value);

                            Ok(Status::PasskeyOutput(PasskeyOutput::new(passkey_value)))
                        }
                    },
                }
            }
            _ => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Err(Error::IncorrectCommand(CommandType::PairingPublicKey).into())
            }
        }
    }

    async fn p_pairing_confirm<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing confirm");

        let initiator_confirm = match pairing::PairingConfirm::try_from_command_format(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        match self.pairing_data {
            Some(PairingData {
                pairing_method: PairingMethod::PassKeyEntry(_),
                ref mut peer_confirm,
                ref public_key,
                peer_public_key: Some(ref peer_public_key),
                nonce,
                passkey: Some(passkey),
                passkey_round,
                ..
            }) => {
                // Only the passkey pairing method has a confirm values PDU sent by the initiator
                let confirm = initiator_confirm.get_value();

                *peer_confirm = Some(confirm);

                let pka = GetXOfP256Key::x(peer_public_key);

                let pkb = GetXOfP256Key::x(public_key);

                let nb = nonce;

                let rb = passkey_r!(passkey, passkey_round);

                let cb = toolbox::f4(pkb, pka, nb, rb);

                self.send(connection_channel, pairing::PairingConfirm::new(cb)).await?;

                Ok(Status::None)
            }
            Some(PairingData {
                pairing_method: PairingMethod::JustWorks | PairingMethod::NumbComp | PairingMethod::Oob(_),
                ..
            }) => {
                // Neither the Just Works method, Number Comparison, or out of band should have the
                // responder receiving the pairing confirm PDU.
                self.send_err(connection_channel, PairingFailedReason::InvalidParameters)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::InvalidParameters).into())
            }
            _ => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    async fn p_pairing_random<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing random");

        let initiator_random = match pairing::PairingRandom::try_from_command_format(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        match self.pairing_data {
            Some(PairingData {
                pairing_method: PairingMethod::JustWorks | PairingMethod::Oob(_),
                ref mut peer_nonce,
                nonce,
                ..
            }) => {
                *peer_nonce = initiator_random.get_value().into();

                self.send(connection_channel, pairing::PairingRandom::new(nonce))
                    .await?;

                Ok(Status::None)
            }
            Some(PairingData {
                pairing_method: PairingMethod::NumbComp,
                ref mut peer_nonce,
                nonce,
                public_key,
                peer_public_key: Some(peer_public_key),
                ..
            }) => {
                let initiator_nonce = initiator_random.get_value();

                *peer_nonce = initiator_nonce.into();

                self.send(connection_channel, pairing::PairingRandom::new(nonce))
                    .await?;

                let pka = GetXOfP256Key::x(&peer_public_key);

                let pkb = GetXOfP256Key::x(&public_key);

                let na = initiator_nonce;

                let nb = nonce;

                let vb = toolbox::g2(pka, pkb, na, nb);

                let number_comparison = NumberComparison::new(vb);

                Ok(Status::NumberComparison(number_comparison))
            }
            Some(PairingData {
                pairing_method: PairingMethod::PassKeyEntry(_),
                ref mut peer_nonce,
                nonce,
                public_key,
                peer_public_key: Some(peer_public_key),
                passkey: Some(passkey),
                passkey_round,
                peer_confirm: Some(peer_confirm),
                ..
            }) => {
                let initiator_nonce = initiator_random.get_value();

                *peer_nonce = initiator_nonce.into();

                let pka = GetXOfP256Key::x(&peer_public_key);

                let pkb = GetXOfP256Key::x(&public_key);

                let na = initiator_nonce;

                let rb = passkey_r!(passkey, passkey_round);

                if passkey_round >= 20 {
                    // only 20 rounds should be done
                    self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                        .await?;

                    Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason))
                } else if peer_confirm == toolbox::f4(pka, pkb, na, rb) {
                    self.send(connection_channel, pairing::PairingRandom::new(nonce))
                        .await?;

                    // rust borrow checker...
                    self.pairing_data.as_mut().unwrap().nonce = toolbox::nonce();

                    // rust borrow checker...
                    self.pairing_data.as_mut().unwrap().passkey_round += 1;

                    Ok(Status::None)
                } else {
                    self.send_err(connection_channel, PairingFailedReason::ConfirmValueFailed)
                        .await?;

                    Ok(Status::PairingFailed(PairingFailedReason::ConfirmValueFailed))
                }
            }
            _ => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    async fn p_pairing_failed<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing failed");

        let initiator_fail = match pairing::PairingFailed::try_from_command_format(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        self.pairing_data = None;

        Ok(Status::PairingFailed(initiator_fail.get_reason()))
    }

    async fn p_pairing_dh_key_check<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing dh key check");

        let initiator_dh_key_check = match pairing::PairingDHKeyCheck::try_from_command_format(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        match self.pairing_data {
            Some(PairingData {
                ref pairing_method,
                secret_key: Some(ref dh_key),
                nonce,
                peer_nonce: Some(ref peer_nonce),
                initiator_io_cap,
                responder_io_cap,
                responder_random,
                initiator_random,
                ..
            }) => {
                let a_addr = toolbox::PairingAddress::new(&self.initiator_address, self.initiator_address_is_random);

                let b_addr = toolbox::PairingAddress::new(&self.responder_address, self.responder_address_is_random);

                log::trace!("(SM) secret key: {:x?}", dh_key);
                log::trace!("(SM) remote nonce: {:x?}", peer_nonce);
                log::trace!("(SM) this nonce: {:x?}", nonce);
                log::trace!("(SM) remote address: {:x?}", a_addr);
                log::trace!("(SM) this address: {:x?}", b_addr);

                let (mac_key, ltk) = toolbox::f5(*dh_key, *peer_nonce, nonce, a_addr.clone(), b_addr.clone());

                log::trace!("(SM) mac_key: {:x?}", mac_key);
                log::trace!("(SM) ltk: {:x?}", ltk);
                log::trace!("(SM) initiator_io_cap: {:x?}", initiator_io_cap);

                let ea = toolbox::f6(
                    mac_key,
                    *peer_nonce,
                    nonce,
                    initiator_random,
                    initiator_io_cap,
                    a_addr.clone(),
                    b_addr.clone(),
                );

                let received_ea = initiator_dh_key_check.get_key_check();

                if received_ea == ea {
                    log::trace!("(SM) responder_io_cap: {:x?}", responder_io_cap);

                    let eb = toolbox::f6(
                        mac_key,
                        nonce,
                        *peer_nonce,
                        responder_random,
                        responder_io_cap,
                        b_addr,
                        a_addr,
                    );

                    self.send(connection_channel, pairing::PairingDHKeyCheck::new(eb))
                        .await?;

                    self.keys = super::Keys {
                        is_authenticated: !pairing_method.is_just_works(),
                        ltk: ltk.into(),
                        irk: None,
                        csrk: None,
                        peer_irk: None,
                        peer_identity: if self.initiator_address_is_random {
                            super::IdentityAddress::StaticRandom(self.initiator_address)
                        } else {
                            super::IdentityAddress::Public(self.initiator_address)
                        }
                        .into(),
                        peer_csrk: None,
                        identity: if self.responder_address_is_random {
                            super::IdentityAddress::StaticRandom(self.responder_address)
                        } else {
                            super::IdentityAddress::Public(self.responder_address)
                        }
                        .into(),
                    }
                    .into();

                    Ok(Status::PairingComplete)
                } else {
                    self.send_err(connection_channel, PairingFailedReason::DHKeyCheckFailed)
                        .await?;

                    log::trace!("(SM) received ea: {:x?}", received_ea);
                    log::trace!("(SM) calculated ea: {:x?}", ea);

                    Ok(Status::PairingFailed(PairingFailedReason::DHKeyCheckFailed).into())
                }
            }
            _ => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    /// Process a keypress PDU
    async fn p_keypress_notification<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        let _keypress_notification = match KeyPressNotification::try_from_command_format(payload) {
            Ok(keypress_notification) => keypress_notification,
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        Ok(Status::None)
    }

    async fn p_identity_info<'z, C>(&'z mut self, connection_channel: &C, payload: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing peer IRK");

        let identity_info = match encrypt_info::IdentityInformation::try_from_command_format(payload) {
            Ok(ii) => ii,
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        if self.link_encrypted {
            if let Some(ref mut keys) = self.keys {
                keys.peer_irk = Some(identity_info.get_irk());

                if self.initiator_key_distribution.contains(&KeyDistributions::SignKey) && keys.peer_csrk.is_none() {
                    Ok(Status::None)
                } else {
                    Ok(Status::BondingComplete)
                }
            } else {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason).into())
            }
        } else {
            self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                .await?;

            Err(Error::UnknownIfLinkIsEncrypted.into())
        }
    }

    async fn p_identity_address_info<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing peer address info");

        let identity_addr_info = match encrypt_info::IdentityAddressInformation::try_from_command_format(payload) {
            Ok(iai) => iai,
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        if self.link_encrypted {
            if let Some(ref mut keys) = self.keys {
                keys.peer_identity = Some(identity_addr_info.into());

                if self.initiator_key_distribution.contains(&KeyDistributions::IdKey)
                    || self.initiator_key_distribution.contains(&KeyDistributions::SignKey)
                {
                    Ok(Status::None)
                } else {
                    Ok(Status::BondingComplete)
                }
            } else {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason).into());
            }
        } else {
            self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                .await?;

            return Err(Error::UnknownIfLinkIsEncrypted.into());
        }
    }

    async fn p_signing_info<'z, C>(&'z mut self, connection_channel: &C, payload: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing peer signing info (CSRK)");

        let signing_info = match encrypt_info::SigningInformation::try_from_command_format(payload) {
            Ok(si) => si,
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        if self.link_encrypted {
            if let Some(ref mut keys) = self.keys {
                keys.peer_csrk = Some((signing_info.get_signature_key(), 0));

                Ok(Status::BondingComplete)
            } else {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason).into());
            }
        } else {
            self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                .await?;

            return Err(Error::UnknownIfLinkIsEncrypted.into());
        }
    }
}

/// The input of method [`SecurityManager::process_input`]
enum Input {
    YesNoInput(bool),
    KeyPressNotification(KeyPressNotification),
    Passkey(KeyPressNotification, u32),
    OutOfBand {
        address: BluetoothDeviceAddress,
        random: u128,
        confirm: u128,
    },
}

impl Input {
    /// Create an `Input` for 'yes'
    fn yes() -> Self {
        Input::YesNoInput(true)
    }

    /// Create an `Input` for 'no'
    fn no() -> Self {
        Input::YesNoInput(false)
    }

    /// Create an `Input` for a passkey start
    fn passkey_start() -> Self {
        Input::KeyPressNotification(KeyPressNotification::PasskeyEntryStarted)
    }

    /// Create an `Input` for a passkey digit entry
    fn passkey_enter() -> Self {
        Input::KeyPressNotification(KeyPressNotification::PasskeyDigitEntered)
    }

    /// Create an `Input` for erasing a passkey digit
    fn passkey_erase() -> Self {
        Input::KeyPressNotification(KeyPressNotification::PasskeyDigitErased)
    }

    /// Create an `Input` for clearing the passkey
    fn passkey_clear() -> Self {
        Input::KeyPressNotification(KeyPressNotification::PasskeyCleared)
    }

    fn passkey_complete(passkey: u32) -> Self {
        Input::Passkey(KeyPressNotification::PasskeyEntryCompleted, passkey)
    }

    fn oob_data(address: BluetoothDeviceAddress, random: u128, confirm: u128) -> Self {
        Input::OutOfBand {
            address,
            random,
            confirm,
        }
    }
}

/// The return of method `process_command`
///
/// See the method [`SecurityManager::process_command`] for the use of this enum.
pub enum Status {
    None,
    PairingFailed(PairingFailedReason),
    PairingComplete,
    BondingComplete,
    NumberComparison(NumberComparison),
    PasskeyInput(PasskeyInput),
    PasskeyOutput(PasskeyOutput),
    OutOfBandInput(OutOfBandInput),
    OutOfBandOutput(OutOfBandOutput),
    OutOfBandInputOutput(OutOfBandInput, OutOfBandOutput),
}

/// User Input and Output for Number Comparison
///
/// This is returned by [`process_command`] when the Security Manager reaches the point in pairing
/// where it requires the application user to perform number comparison.
///
/// The value can be shown to the application user via the implementation of `Display`.
///
/// [`process`]: SecurityManager::process
pub struct NumberComparison {
    val: u32,
}

impl NumberComparison {
    fn new(val: u32) -> Self {
        // displayed values are only 6 digits
        let val = val % 1_000_000;

        Self { val }
    }

    /// Yes Confirmation From the Application User
    ///
    /// This should be called once the user has confirmed the number comparison value.
    pub async fn yes<C>(
        self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        security_manager.process_input(connection_channel, Input::yes()).await
    }

    /// Yes Confirmation From the Application User
    ///
    /// This should be called once the user has denied the validity of the number comparison value.
    pub async fn no<C>(
        self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        security_manager.process_input(connection_channel, Input::no()).await
    }
}

impl core::fmt::Display for NumberComparison {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:06}", self.val)
    }
}

/// Passkey Input
///
/// This is returned by the Security Manager's [`process_command`] method when it requires a passkey
/// input from the application user.
pub struct PasskeyInput([char; 6], usize);

impl PasskeyInput {
    /// Create a new `PasscodeInput`
    ///
    /// This sends the keypress notification *passkey entry started* before a `PasscodeInput` is
    /// returned.
    async fn new<C>(security_manager: &mut SecurityManager, connection_channel: &C) -> Result<Self, error!(C)>
    where
        C: ConnectionChannel,
    {
        security_manager
            .process_input(connection_channel, Input::passkey_start())
            .await?;

        Ok(Self(Default::default(), 0))
    }

    /// Get the number of digits
    ///
    /// This returns the number of digits that are currently within this `PasscodeInput`.
    pub fn count(&self) -> usize {
        self.1
    }

    /// Add a Character to the Passkey
    ///
    /// This adds a digit character to the passkey. The `security_manager` will send a keypress
    /// notification to the peer device's Security Manager containing *passkey digit entered*.
    ///
    /// # Errors
    /// 1) `digit` must be a base 10 digit character and there must be less than six digits within
    ///    this passcode.
    /// 2) The `connection_channel` is closed and the `security_manager` fails to send the keypress
    ///    notification because.
    pub async fn add<C>(
        &mut self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
        digit: char,
    ) -> Result<(), PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        if self.1 >= 6 {
            Err(PasscodeInputError::TooManyDigits)
        } else if !digit.is_digit(10) {
            Err(PasscodeInputError::NotADigit)
        } else {
            self.0[self.1] = digit;

            self.1 += 1;

            security_manager
                .process_input(connection_channel, Input::passkey_enter())
                .await?;

            Ok(())
        }
    }

    /// Insert a Character Into the Passkey
    ///
    /// This inserts a digit character to the passkey. The digit is inserted at the position
    /// `index`. `index` must less than or equal to the current number of passkey digits within this
    /// `PasskeyInput`. The `security_manager` will send a keypress notification to the peer
    /// device's Security Manager containing *passkey digit entered*.
    ///
    /// # Errors
    /// 1) `digit` must be a base 10 digit character and there must be less than six digits within
    ///    this passcode.
    /// 2) `index` must be a valid position to insert `digit` into the passcode.
    /// 3) The `connection_channel` is closed and the `security_manager` fails to send the keypress
    ///    notification because.
    pub async fn insert<C>(
        &mut self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
        digit: char,
        index: usize,
    ) -> Result<(), PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        if self.1 >= 6 {
            Err(PasscodeInputError::TooManyDigits)
        } else if !digit.is_digit(10) {
            Err(PasscodeInputError::NotADigit)
        } else if index > self.1 {
            Err(PasscodeInputError::IndexOutOfBounds)
        } else {
            self.1 += 1;

            self.0[index..self.1].rotate_right(1);

            self.0[index] = digit;

            security_manager
                .process_input(connection_channel, Input::passkey_enter())
                .await?;

            Ok(())
        }
    }

    /// Remove a Character From the Passkey
    ///
    /// This is used to remove a character from the passkey. This should be called whenever the user
    /// deletes a single character of the passkey. `index` is the position of the digit that was
    /// deleted by the user. The `security_manager` will send a keypress notification to the peer
    /// device's Security Manager containing *passkey digit erased*.
    ///
    /// # Errors
    /// 1) 'index' must be a valid position to remove a `digit` of the passcode
    /// 2) The `connection_channel` is closed and the `security_manager` fails to send the keypress
    ///    notification because.
    pub async fn remove<C>(
        &mut self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
        index: usize,
    ) -> Result<(), PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        if index >= self.1 {
            Err(PasscodeInputError::IndexOutOfBounds)
        } else {
            self.0[index..self.1].rotate_left(1);

            self.1 -= 1;

            security_manager
                .process_input(connection_channel, Input::passkey_erase())
                .await?;

            Ok(())
        }
    }

    /// Clear the passcode
    ///
    /// All digits within this `PasscodeInput` are cleared. The `security_manager` will send a
    /// keypress notification to the peer device's Security Manager containing *passkey cleared*.
    ///
    /// # Error
    /// The `connection_channel` is closed and the `security_manager` fails to send the keypress
    /// notification because.
    pub async fn clear<C>(
        &mut self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
    ) -> Result<(), PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        self.0 = Default::default();
        self.1 = 0;

        security_manager
            .process_input(connection_channel, Input::passkey_clear())
            .await?;

        Ok(())
    }

    /// Complete the passcode
    ///
    /// After the user has entered in all six digits and is satisfied with the input, this method
    /// is used to complete the passcode entry. The `security_manager` will send a keypress
    /// notification to the peer device's Security Manager containing *passkey completed*.
    pub async fn complete<C>(
        self,
        security_manger: &mut SecurityManager,
        connection_channel: &C,
    ) -> Result<Status, PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        if self.1 != 6 {
            Err(PasscodeInputError::NotComplete)
        } else {
            let mut passkey_val = 0;
            let mut mul = 100_000;

            for i in 0..6 {
                passkey_val += self.0[i].to_digit(10).unwrap() * mul;

                mul /= 10;
            }

            security_manger
                .process_input(connection_channel, Input::passkey_complete(passkey_val))
                .await
                .map_err(|e| PasscodeInputError::SecurityManager(e))
        }
    }
}

pub enum PasscodeInputError<E> {
    SecurityManager(E),
    TooManyDigits,
    NotADigit,
    IndexOutOfBounds,
    NotComplete,
}

impl<E> From<E> for PasscodeInputError<E> {
    fn from(e: E) -> Self {
        Self::SecurityManager(e)
    }
}

/// Passcode Output
///
/// This is returned by the Security Manager's [`process_command`] method when a passkey is to be
/// displayed on this device to the application user.
pub struct PasskeyOutput(u32);

impl PasskeyOutput {
    fn new(val: u32) -> PasskeyOutput {
        PasskeyOutput(val % 1_000_000)
    }
}

impl core::fmt::Display for PasskeyOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:06}", self.0)
    }
}

/// Out of Band Output
///
/// This is output that is to be sent through the out of band medium to the peer's Security Manager.
/// It contains the minimum required Security Manager types that must be sent to the peer's Security
/// Manager. More types can be added by pushing the type to this Out of Band input, but there is a
/// total buffer limit of 64 bytes.
///
/// The out of band data always contains the Security Manager types for the Bluetooth address, a
/// random, and a confirm value. Legacy pairing is not implemented so out of band data within an
/// `OutOfBandOutput` will always be these values by default (in legacy pairing the out of band
/// data is just the temporary key).
///
/// # Security Manager Type and Structures
/// A security manager types and structures are no different from the advertising data types and
/// structures listed within the assigned types and Core Specification Supplement.
///
/// # Note
/// The method used for sending out of band data may have requirements for Security Manager types
/// that are not included in the default out of band output. For example [`NFC`] requires the
/// Bluetooth device address and role data types to be part of the Oot of band data.
///
/// [`NFC`]: https://members.nfc-forum.org/apps/group_public/download.php/18688/NFCForum-AD-BTSSP_1_1.pdf
pub struct OutOfBandOutput([u8; 64], usize);

impl OutOfBandOutput {
    /// Create a new `OutOfBandOutput`
    ///
    /// # Panic
    /// This will panic if `security_manager` is not ready to create the out of band data
    fn new(security_manager: &mut SecurityManager) -> Self {
        use bo_tie_gap::assigned::{
            le_device_address::LeDeviceAddress, sc_confirm_value::ScConfirmValue, sc_random_value::ScRandomValue,
            Sequence,
        };

        let mut data = [0u8; 64];

        let pairing_data = security_manager.pairing_data.as_mut().unwrap();

        let rb = toolbox::rand_u128();

        pairing_data.responder_random = rb;

        let pkb = GetXOfP256Key::x(&pairing_data.public_key);

        let address = LeDeviceAddress::from(security_manager.responder_address);

        let random = ScRandomValue::new(rb);

        let confirm = ScConfirmValue::new(toolbox::f4(pkb, pkb, rb, 0));

        let mut sequence = Sequence::new(&mut data);

        sequence.try_add(&address).unwrap();
        sequence.try_add(&random).unwrap();
        sequence.try_add(&confirm).unwrap();

        let len = sequence.count();

        Self(data, len)
    }

    /// Add the role security manager structure to the out of band data
    ///
    /// This is not necessary as far as the Security Manager, but it may be necessary for the
    /// transport that the out of band data is sent through. This is the most commonly required
    /// Security Manager structure so it gets its own method.
    ///
    /// # Error
    /// There must be enough room within the buffer otherwise an error is returned. The value of the
    /// error is the size of the role Security Manager structure.
    pub fn add_role(&mut self) -> Result<(), usize> {
        let mut sequence = self.as_sequence();

        let role = bo_tie_gap::assigned::le_role::LeRole::OnlyPeripheral;

        sequence
            .try_add(&role)
            .map_err(|_| bo_tie_gap::assigned::le_role::LeRole::STRUCT_SIZE)
    }

    /// Get this `OutOfBandOutput` as a [`Sequence`]
    ///
    /// A sequence can be used to add more security manager types to the out of band output.
    ///
    /// [`Sequence`]: bo_tie_gap::assigned::Sequence
    pub fn as_sequence(&mut self) -> bo_tie_gap::assigned::Sequence<'_> {
        bo_tie_gap::assigned::Sequence::new(&mut self.0[self.1..])
    }

    /// Convert the underlying buffer to a `SequenceVec`
    ///
    /// This is necessary if there needs to be more than 64 bytes of data within the out of band
    /// output. A `SequenceVec` can contain
    pub fn to_sequence_vec(self) -> bo_tie_gap::assigned::SequenceVec {
        bo_tie_gap::assigned::SequenceVec::from(self.0)
    }
}

impl core::ops::Deref for OutOfBandOutput {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..self.1]
    }
}

/// Out of Band Input
///
/// This is a marker type for inputting out of band data from the peer device's Security Manager
/// into this Security Manager.
pub struct OutOfBandInput;

impl OutOfBandInput {
    /// Input the Out of Band Data into the Security Manager
    pub async fn input_oob<C>(
        self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
        oob_data: &[u8],
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        use bo_tie_gap::assigned::{
            le_device_address, sc_confirm_value, sc_random_value, AssignedTypes, TryFromStruct,
        };

        macro_rules! error {
            () => {{
                security_manager
                    .send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason));
            }};
        }

        let mut address = None;
        let mut random = None;
        let mut confirm = None;

        for rslt_struct in bo_tie_gap::assigned::EirOrAdIterator::new(oob_data) {
            match rslt_struct {
                Ok(sm_struct) => {
                    if sm_struct.is_assigned_type(AssignedTypes::LEBluetoothDeviceAddress) {
                        match le_device_address::LeDeviceAddress::try_from_struct(sm_struct) {
                            Ok(sm_address) => address = sm_address.into_inner().into(),
                            Err(_) => error!(),
                        }
                    } else if sm_struct.is_assigned_type(AssignedTypes::LESecureConnectionsRandomValue) {
                        match sc_random_value::ScRandomValue::try_from_struct(sm_struct) {
                            Ok(sm_random) => random = sm_random.into_inner().into(),
                            Err(_) => error!(),
                        }
                    } else if sm_struct.is_assigned_type(AssignedTypes::LESecureConnectionsConfirmationValue) {
                        match sc_confirm_value::ScConfirmValue::try_from_struct(sm_struct) {
                            Ok(sm_confirm) => confirm = sm_confirm.into_inner().into(),
                            Err(_) => error!(),
                        }
                    }
                }
                Err(_) => error!(),
            }
        }

        if address.is_some() && random.is_some() && confirm.is_some() {
            let input = Input::oob_data(address.unwrap(), random.unwrap(), confirm.unwrap());

            security_manager.process_input(connection_channel, input).await
        } else {
            error!()
        }
    }
}
