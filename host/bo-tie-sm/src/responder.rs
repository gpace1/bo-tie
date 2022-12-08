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

use super::{
    encrypt_info, pairing, toolbox, Command, CommandData, CommandType, Error, GetXOfP256Key, PairingData, PairingMethod,
};
use crate::l2cap::ConnectionChannel;
use crate::oob::{
    sealed_receiver_type::OobReceiverTypeVariant, ExternalOobReceiver, OobDirection, OobReceiverType, OutOfBandSend,
};
use crate::EnabledBondingKeysBuilder;
use alloc::vec::Vec;

/// A builder for a [`SlaveSecurityManager`]
///
/// This is used to construct a `SlaveSecurityManager`. However building requires the
///
/// # Out of Band Support
/// A `SlaveSecurityManager` will only support OOB if method `use_oob` of this build is called. It
///
pub struct SecurityManagerBuilder<S, R> {
    io_capabilities: pairing::IOCapability,
    encryption_key_min: usize,
    encryption_key_max: usize,
    remote_address: crate::BluetoothDeviceAddress,
    this_address: crate::BluetoothDeviceAddress,
    remote_address_is_random: bool,
    this_address_is_random: bool,
    distribute_irk: bool,
    distribute_csrk: bool,
    accept_irk: bool,
    accept_csrk: bool,
    prior_keys: Option<super::Keys>,
    oob_sender: S,
    oob_receiver: R,
}

impl SecurityManagerBuilder<crate::oob::Unsupported, crate::oob::Unsupported> {
    /// Create a new `SlaveSecurityManagerBuilder`
    pub fn new(
        connected_device_address: crate::BluetoothDeviceAddress,
        this_device_address: crate::BluetoothDeviceAddress,
        is_connected_devices_address_random: bool,
        is_this_device_address_random: bool,
    ) -> Self {
        Self {
            io_capabilities: pairing::IOCapability::NoInputNoOutput,
            encryption_key_min: super::ENCRYPTION_KEY_MAX_SIZE,
            encryption_key_max: super::ENCRYPTION_KEY_MAX_SIZE,
            remote_address: connected_device_address,
            this_address: this_device_address,
            remote_address_is_random: is_connected_devices_address_random,
            this_address_is_random: is_this_device_address_random,
            distribute_irk: true,
            distribute_csrk: false,
            accept_irk: false,
            accept_csrk: false,
            prior_keys: None,
            oob_sender: (),
            oob_receiver: (),
        }
    }
}

impl<S, R> SecurityManagerBuilder<S, R> {
    /// Set the keys to the peer device if it is already paired
    ///
    /// This assigns the keys that were previously generated after a successful pair and bonding.
    /// This method should only be called after the identity of the peer and associated long term
    /// key (LTK) is known. Usually this is through successful resolving the resolvable private
    /// address *of the* peer device.
    pub fn set_already_paired(mut self, keys: super::Keys) -> Result<Self, &'static str> {
        if keys.get_ltk().is_some() {
            self.prior_keys = Some(keys);

            Ok(self)
        } else {
            Err("missing long term key")
        }
    }

    /// Set the bonding keys to be distributed by the responder
    ///
    /// When this method is called, the default configuration for key distribution is overwritten to
    /// disable the distribution of all bonding keys. The return must then be used to selectively
    /// enable what keys are sent by the security manager when bonding.
    ///
    /// # Note
    /// By default only the Identity Resolving Key (IRK) is distributed by the initiator. This
    /// method does not need to be called if the default key configuration is desired.
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
    /// # Note
    /// By default no bonding keys are accepted by this initiator. This method does not need to
    /// be called if the default key configuration is desired.
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

    /// Set the out of band sender
    ///
    /// This method should only be called if this security manager is to support the sending of
    /// pairing data through an out of band method. `out of band` means any method outside of the
    /// Bluetooth connection for pairing done by a security manager. It is up to the user or the two
    /// pairing devices to decide what that entails.
    ///
    /// The out of band `sender` is a function that returns a future. The implementation of that
    /// function and future are left to the user of this security manager.
    ///
    /// ```
    /// # use bo_tie_util::BluetoothDeviceAddress;
    /// # let this_addr = BluetoothDeviceAddress::zeroed();
    /// # let remote_addr = BluetoothDeviceAddress::zeroed();
    /// # let security_manager_builder = bo_tie_sm::responder::SecurityManagerBuilder::new(this_addr, remote_addr, false, false);
    /// # async fn send_over_oob(_: &[u8]) {}
    ///
    /// let security_manager = security_manager_builder.set_oob_sender(|pairing_data: &[u8]| async {
    ///     send_over_oob(pairing_data).await
    /// });
    /// ```
    pub fn set_oob_sender<'a, S2, F>(self, sender: S2) -> SecurityManagerBuilder<S2, R>
    where
        S2: FnMut(&'a [u8]) -> F,
        F: core::future::Future + 'a,
    {
        SecurityManagerBuilder {
            io_capabilities: self.io_capabilities,
            encryption_key_min: self.encryption_key_min,
            encryption_key_max: self.encryption_key_max,
            remote_address: self.remote_address,
            this_address: self.this_address,
            remote_address_is_random: self.remote_address_is_random,
            this_address_is_random: self.this_address_is_random,
            distribute_irk: self.distribute_irk,
            distribute_csrk: self.distribute_csrk,
            accept_irk: self.accept_irk,
            accept_csrk: self.accept_csrk,
            prior_keys: self.prior_keys,
            oob_sender: sender,
            oob_receiver: self.oob_receiver,
        }
    }

    /// Set the out of band receiver
    ///
    /// This method should only be called if this security manager is to support the reception of
    /// pairing data through an out of band method.`out of band` means any method outside of the
    /// Bluetooth connection for pairing done by a security manager. It is up to the user or the two
    /// pairing devices to decide what that entails.
    ///
    /// The out of band `receiver` is a function that returns a future. The implementation of that
    /// function and future are left to the user of this security manager.
    ///
    /// ```
    /// # use bo_tie_util::BluetoothDeviceAddress;
    /// # let this_addr = BluetoothDeviceAddress::zeroed();
    /// # let remote_addr = BluetoothDeviceAddress::zeroed();
    /// # let security_manager_builder = bo_tie_sm::responder::SecurityManagerBuilder::new(this_addr, remote_addr, false, false);
    /// # async fn receive_from_oob() -> Vec<u8> { Vec::new()}
    ///
    /// # let sm =
    /// security_manager_builder.set_oob_receiver(|| async {
    ///     receive_from_oob().await
    /// })
    /// # .build();
    /// ```
    pub fn set_oob_receiver<T>(self, receiver: T) -> SecurityManagerBuilder<S, T>
    where
        T: OobReceiverType,
    {
        SecurityManagerBuilder {
            io_capabilities: self.io_capabilities,
            encryption_key_min: self.encryption_key_min,
            encryption_key_max: self.encryption_key_max,
            remote_address: self.remote_address,
            this_address: self.this_address,
            remote_address_is_random: self.remote_address_is_random,
            this_address_is_random: self.this_address_is_random,
            distribute_irk: self.distribute_irk,
            distribute_csrk: self.distribute_csrk,
            accept_irk: self.accept_irk,
            accept_csrk: self.accept_csrk,
            prior_keys: self.prior_keys,
            oob_sender: self.oob_sender,
            oob_receiver: receiver,
        }
    }

    /// Create the `SlaveSecurityManager`
    ///
    /// # Note
    /// This will create a `SlaveSecurityManager` that does not support the out of band pairing
    /// method.
    pub fn build<'a>(self) -> SecurityManager<S, R>
    where
        S: OutOfBandSend<'a>,
        R: OobReceiverType,
    {
        let auth_req = alloc::vec![
            encrypt_info::AuthRequirements::Bonding,
            encrypt_info::AuthRequirements::ManInTheMiddleProtection,
            encrypt_info::AuthRequirements::Sc,
        ];

        let initiator_key_distribution = super::get_keys(self.accept_irk, self.accept_csrk);

        let responder_key_distribution = super::get_keys(self.distribute_irk, self.distribute_csrk);

        SecurityManager {
            io_capability: self.io_capabilities,
            oob_send: self.oob_sender,
            oob_receive: self.oob_receiver,
            encryption_key_size_min: self.encryption_key_min,
            encryption_key_size_max: self.encryption_key_max,
            auth_req,
            initiator_key_distribution,
            responder_key_distribution,
            initiator_address: self.remote_address,
            responder_address: self.this_address,
            initiator_address_is_random: self.remote_address_is_random,
            responder_address_is_random: self.this_address_is_random,
            pairing_data: None,
            keys: self.prior_keys,
            link_encrypted: false,
        }
    }
}

pub struct SecurityManager<S, R> {
    io_capability: pairing::IOCapability,
    oob_send: S,
    oob_receive: R,
    auth_req: Vec<encrypt_info::AuthRequirements>,
    encryption_key_size_min: usize,
    encryption_key_size_max: usize,
    initiator_key_distribution: &'static [pairing::KeyDistributions],
    responder_key_distribution: &'static [pairing::KeyDistributions],
    initiator_address: crate::BluetoothDeviceAddress,
    responder_address: crate::BluetoothDeviceAddress,
    initiator_address_is_random: bool,
    responder_address_is_random: bool,
    pairing_data: Option<PairingData>,
    keys: Option<super::Keys>,
    link_encrypted: bool,
}

impl<S, R> SecurityManager<S, R> {
    /// Indicate if the connection is encrypted
    ///
    /// This is used to indicate to the `SlaveSecurityManager` that it is safe to send a Key to the
    /// peer device. This is a deliberate extra step to ensure that the functions `send_irk`,
    /// `send_csrk`, `send_pub_addr`, and `send_rand_addr` are only used when the link is encrypted.
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
}

impl<S, R> SecurityManager<S, R> {
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
    pub async fn send_irk<C, Irk>(&mut self, connection_channel: &C, irk: Irk) -> Result<u128, Error>
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
            Err(Error::UnknownIfLinkIsEncrypted)
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
    pub async fn send_csrk<C, Csrk>(&mut self, connection_channel: &C, csrk: Csrk) -> Result<u128, Error>
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
            Err(Error::UnknownIfLinkIsEncrypted)
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
    ) -> Result<crate::IdentityAddress, Error>
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
            Err(Error::UnknownIfLinkIsEncrypted)
        }
    }

    async fn send<C, Cmd, P>(&self, connection_channel: &C, command: Cmd) -> Result<(), Error>
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
            .map_err(|e| Error::DataSend(alloc::format!("{:?}", e)))
    }

    async fn send_err<C>(
        &mut self,
        connection_channel: &C,
        fail_reason: pairing::PairingFailedReason,
    ) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        self.pairing_data = None;

        self.send(connection_channel, pairing::PairingFailed::new(fail_reason))
            .await
    }
}

impl<S, R> SecurityManager<S, R>
where
    S: for<'i> OutOfBandSend<'i>,
    R: OobReceiverType,
{
    /// Process a request from a MasterSecurityManager
    ///
    /// This will return a response to a valid request that can be sent to the Master device.
    /// Errors will be returned if the request is not something that can be processed by the slave
    /// or there was something wrong with the request message.
    ///
    /// This function will return a ['Keys'](crate::sm::Keys) with the newly generated
    /// Long Term Key (LTK). **This key information will only last as long as the master does not
    /// retry pairing or the master causes this responder to return a pairing error to the master**.
    /// *After pairing is complete*, the returned `Keys` will only contain the LTK and the
    /// peer address used during pairing as the peer identity address. The return will be updated
    /// further with peer keys only when `set_encryption` is used to indicate that the connection
    /// is encrypted.
    ///
    /// It is recommended to always keep processing Bluetooth Security Manager packets as the
    /// responder. The host can at any point decide to restart encryption using different keys or
    /// send a `PairingFailed` to indicate that the prior pairing process failed.
    pub async fn process_command<C>(
        &mut self,
        connection_channel: &C,
        acl_data: &crate::l2cap::BasicInfoFrame<Vec<u8>>,
    ) -> Result<Option<&super::Keys>, Error>
    where
        C: ConnectionChannel,
    {
        let command = match CommandType::try_from(acl_data) {
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;
                return Err(e);
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
            cmd @ CommandType::MasterIdentification | // Legacy SM, not supported
            cmd @ CommandType::EncryptionInformation | // Legacy SM, not supported
            cmd => self.p_command_not_supported(connection_channel, cmd).await,
        }
    }

    /// Send the OOB confirm information
    ///
    /// This will create the confirm information and send it to the initiator if the out of band
    /// send function was set. If no sender was set, this method does nothing.
    ///
    /// # Notes
    /// * This method does nothing if OOB sending is not enabled.
    /// * The information generated is wrapped in a OOB data block and then sent to the initiator.
    ///
    /// # Panic
    /// This method will panic if the pairing information and public keys were not already generated
    /// in the pairing process.
    async fn send_oob(&mut self) {
        use bo_tie_gap::assigned::{
            le_device_address::LeDeviceAddress, le_role::LeRole, sc_confirm_value::ScConfirmValue,
            sc_random_value::ScRandomValue, Sequence,
        };

        if S::can_send() {
            let data = &mut [0u8; LeDeviceAddress::STRUCT_SIZE
                + LeRole::STRUCT_SIZE
                + ScRandomValue::STRUCT_SIZE
                + ScConfirmValue::STRUCT_SIZE];

            let ra = toolbox::rand_u128();

            let paring_data = self.pairing_data.as_ref().unwrap();

            let pka = GetXOfP256Key::x(&paring_data.public_key);

            let address = LeDeviceAddress::from(self.initiator_address);

            let role = LeRole::OnlyPeripheral;

            let random = ScRandomValue::new(ra);

            let confirm = ScConfirmValue::new(toolbox::f4(pka, pka, ra, 0));

            let mut sequence = Sequence::new(data);

            sequence.try_add(&address).unwrap();
            sequence.try_add(&role).unwrap();
            sequence.try_add(&random).unwrap();
            sequence.try_add(&confirm).unwrap();

            self.oob_send.send(sequence.into_inner()).await;
        }
    }

    /// Receive OOB information by its type
    ///
    /// This will do one of two things depending on the type of receiver.
    ///
    /// For the `Internal` type of receiver it will await the data and send the nonce once it
    /// receives and validated the OOB data.
    ///
    /// For the `External` it will just return Ok as the user needs to provide the OOB data with
    /// the method `received_oob_data`.
    ///
    /// # Panic
    /// This method will panic if `DoesNotExist` is the receiver type or `pairing_data` is `None`
    async fn by_oob_receiver_type<C>(&mut self, connection_channel: &C) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        match R::receiver_type() {
            OobReceiverTypeVariant::Internal => {
                let confirm_result = self.receive_oob().await;

                self.oob_confirm_result(connection_channel, confirm_result).await
            }
            OobReceiverTypeVariant::External => Ok(()),
            OobReceiverTypeVariant::DoesNotExist => unreachable!(),
        }
    }

    /// Function for the validation result of the confirm value with an OOB data.
    ///
    /// # Panic
    /// Member `pairing_data` must be `Some(_)`.
    async fn oob_confirm_result<C>(&mut self, connection_channel: &C, confirm_result: bool) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        if confirm_result {
            match self.pairing_data {
                Some(PairingData {
                    pairing_method: PairingMethod::Oob(_),
                    ref mut external_oob_confirm_valid,
                    ..
                }) => {
                    *external_oob_confirm_valid = true;

                    Ok(())
                }
                None => unreachable!("Pairing Data cannot be None"),
                _ => Ok(()), // Other pairing methods
            }
        } else {
            self.send_err(connection_channel, pairing::PairingFailedReason::ConfirmValueFailed)
                .await
        }
    }

    /// Receive OOB information from the initiator
    ///
    /// This will await for the OOB data block containing the initiator's confirm information and
    /// return a boolean indicating if the information was verified. If no receive function was set,
    /// this method will return true.
    ///
    /// # Error
    /// An error is returned if the initiator's random and confirm values cannot be converted
    ///
    /// # Panic
    /// This method will panic if the pairing information and public keys were not already generated
    /// in the pairing process.
    async fn receive_oob(&mut self) -> bool {
        use core::borrow::Borrow;

        let data = self.oob_receive.receive().await;

        self.process_received_oob(data.borrow())
    }

    /// Process the received OOB
    ///
    /// This will check the OOB to determine the validity of the raw data and the confirm within the
    /// raw data. True is returned if everything within `raw` is validated.
    fn process_received_oob(&self, raw: &[u8]) -> bool {
        use bo_tie_gap::assigned::{sc_confirm_value, sc_random_value, AssignedTypes, EirOrAdIterator, TryFromStruct};

        let mut ra = None;
        let mut ca = None;

        for ad in EirOrAdIterator::new(raw).silent() {
            const RANDOM_TYPE: u8 = AssignedTypes::LESecureConnectionsRandomValue.val();
            const CONFIRM_TYPE: u8 = AssignedTypes::LESecureConnectionsConfirmationValue.val();

            match ad.get_type() {
                RANDOM_TYPE => ra = sc_random_value::ScRandomValue::try_from_struct(ad).ok(),
                CONFIRM_TYPE => ca = sc_confirm_value::ScConfirmValue::try_from_struct(ad).ok(),
                _ => (),
            }
        }

        if let (Some(ra), Some(ca)) = (ra, ca) {
            let paring_data = self.pairing_data.as_ref().unwrap();

            let pka = GetXOfP256Key::x(paring_data.peer_public_key.as_ref().unwrap());

            if ca.0 == toolbox::f4(pka, pka, ra.0, 0) {
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    async fn p_command_not_supported<C>(
        &mut self,
        connection_channel: &C,
        cmd: CommandType,
    ) -> Result<Option<&super::Keys>, Error>
    where
        C: ConnectionChannel,
    {
        self.send_err(connection_channel, pairing::PairingFailedReason::CommandNotSupported)
            .await?;

        Err(Error::IncorrectCommand(cmd))
    }

    async fn p_pairing_request<C>(&mut self, connection_channel: &C, data: &[u8]) -> Result<Option<&super::Keys>, Error>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing request");

        let request = match pairing::PairingRequest::try_from_command_format(data) {
            Ok(request) => request,
            Err(_) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(Error::IncorrectCommand(CommandType::PairingPublicKey));
            }
        };

        if request.get_max_encryption_size() < self.encryption_key_size_min {
            self.send_err(connection_channel, pairing::PairingFailedReason::EncryptionKeySize)
                .await?;

            Err(Error::PairingFailed(pairing::PairingFailedReason::EncryptionKeySize))
        } else {
            let response = pairing::PairingResponse::new(
                self.io_capability,
                if R::can_receive() {
                    pairing::OOBDataFlag::AuthenticationDataFromRemoteDevicePresent
                } else {
                    pairing::OOBDataFlag::AuthenticationDataNotPresent
                },
                self.auth_req.clone(),
                self.encryption_key_size_max,
                self.initiator_key_distribution,
                self.responder_key_distribution,
            );

            let pairing_method = PairingMethod::determine_method_secure_connection(
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
                responder_pairing_confirm: None,
                mac_key: None,
                external_oob_confirm_valid: false,
            });

            Ok(None)
        }
    }

    async fn p_pairing_public_key<C>(
        &mut self,
        connection_channel: &C,
        data: &[u8],
    ) -> Result<Option<&super::Keys>, Error>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing public Key");

        let initiator_pub_key = match pairing::PairingPubKey::try_from_command_format(data) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e);
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
                        self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                            .await?;

                        return Err(e);
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
                    }
                    PairingMethod::Oob(OobDirection::OnlyResponderSendsOob) => {
                        self.send_oob().await;
                    }
                    PairingMethod::Oob(OobDirection::BothSendOob) => {
                        self.send_oob().await;

                        self.by_oob_receiver_type(connection_channel).await?;
                    }
                    PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob) => {
                        self.by_oob_receiver_type(connection_channel).await?;
                    }
                    PairingMethod::PassKeyEntry => {
                        todo!("Key generation method 'Pass Key Entry' is not supported yet")
                    }
                }

                Ok(None)
            }
            _ => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                Err(Error::IncorrectCommand(CommandType::PairingPublicKey))
            }
        }
    }

    async fn p_pairing_confirm<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<Option<&super::Keys>, Error>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing confirm");

        let _initiator_confirm = match pairing::PairingConfirm::try_from_command_format(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e);
            }
        };

        match self.pairing_data.as_ref() {
            // Only the pairing method Passkey will have confirm values sent through the logical
            // link
            Some(PairingData {
                pairing_method: PairingMethod::PassKeyEntry | PairingMethod::NumbComp | PairingMethod::Oob(_),
                ..
            }) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
            }
            _ => {
                // Neither the Just Works method, Number Comparison, or out of band should have the
                // responder receiving the pairing confirm PDU.
                self.send_err(connection_channel, pairing::PairingFailedReason::InvalidParameters)
                    .await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::InvalidParameters))
            }
        }
    }

    async fn p_pairing_random<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<Option<&super::Keys>, Error>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing random");

        let initiator_random = match pairing::PairingRandom::try_from_command_format(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e);
            }
        };

        match self.pairing_data {
            Some(PairingData {
                pairing_method: PairingMethod::JustWorks | PairingMethod::NumbComp,
                ref mut peer_nonce,
                nonce,
                ..
            }) => {
                *peer_nonce = initiator_random.get_value().into();

                self.send(connection_channel, pairing::PairingRandom::new(nonce))
                    .await?;

                Ok(None)
            }
            Some(PairingData {
                pairing_method:
                    PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob) | PairingMethod::Oob(OobDirection::BothSendOob),
                external_oob_confirm_valid,
                ..
            }) if OobReceiverTypeVariant::External == R::receiver_type() && !external_oob_confirm_valid => {
                self.send_err(connection_channel, pairing::PairingFailedReason::OOBNotAvailable)
                    .await?;

                Err(Error::ExternalOobNotProvided)
            }
            Some(PairingData {
                pairing_method: PairingMethod::Oob(_),
                ref mut peer_nonce,
                nonce,
                ..
            }) => {
                *peer_nonce = initiator_random.get_value().into();

                self.send(connection_channel, pairing::PairingRandom::new(nonce))
                    .await?;

                Ok(None)
            }
            _ => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                Err(Error::UnsupportedFeature)
            }
        }
    }

    async fn p_pairing_failed<'z, C>(
        &'z mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<Option<&'z super::Keys>, Error>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing failed");

        let initiator_fail = match pairing::PairingFailed::try_from_command_format(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e);
            }
        };

        self.pairing_data = None;

        Err(Error::PairingFailed(initiator_fail.get_reason()))
    }

    async fn p_pairing_dh_key_check<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<Option<&super::Keys>, Error>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing dh key check");

        let initiator_dh_key_check = match pairing::PairingDHKeyCheck::try_from_command_format(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e);
            }
        };

        let pd = self.pairing_data.as_ref();

        match pd {
            Some(PairingData {
                secret_key: Some(dh_key),
                nonce,
                peer_nonce: Some(peer_nonce),
                initiator_io_cap,
                responder_io_cap,
                ..
            }) => {
                let a_addr = toolbox::PairingAddress::new(&self.initiator_address, self.initiator_address_is_random);

                let b_addr = toolbox::PairingAddress::new(&self.responder_address, self.responder_address_is_random);

                log::trace!("(SM) secret key: {:x?}", dh_key);
                log::trace!("(SM) remote nonce: {:x?}", peer_nonce);
                log::trace!("(SM) this nonce: {:x?}", nonce);
                log::trace!("(SM) remote address: {:x?}", a_addr);
                log::trace!("(SM) this address: {:x?}", b_addr);

                let (mac_key, ltk) = toolbox::f5(*dh_key, *peer_nonce, *nonce, a_addr.clone(), b_addr.clone());

                log::trace!("(SM) mac_key: {:x?}", mac_key);
                log::trace!("(SM) ltk: {:x?}", ltk);
                log::trace!("(SM) initiator_io_cap: {:x?}", initiator_io_cap);

                let ea = toolbox::f6(
                    mac_key,
                    *peer_nonce,
                    *nonce,
                    0,
                    *initiator_io_cap,
                    a_addr.clone(),
                    b_addr.clone(),
                );

                let received_ea = initiator_dh_key_check.get_key_check();

                if received_ea == ea {
                    log::trace!("(SM) responder_io_cap: {:x?}", responder_io_cap);

                    let eb = toolbox::f6(mac_key, *nonce, *peer_nonce, 0, *responder_io_cap, b_addr, a_addr);

                    self.send(connection_channel, pairing::PairingDHKeyCheck::new(eb))
                        .await?;

                    let keys = &mut self.keys;

                    *keys = super::Keys {
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

                    Ok(keys.as_ref())
                } else {
                    self.send_err(connection_channel, pairing::PairingFailedReason::DHKeyCheckFailed)
                        .await?;

                    log::trace!("(SM) received ea: {:x?}", received_ea);
                    log::trace!("(SM) calculated ea: {:x?}", ea);

                    Err(Error::PairingFailed(pairing::PairingFailedReason::DHKeyCheckFailed))
                }
            }
            _ => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                Err(Error::UnsupportedFeature)
            }
        }
    }

    async fn p_identity_info<'z, C>(
        &'z mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<Option<&'z super::Keys>, Error>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing peer IRK");

        let identity_info = match encrypt_info::IdentityInformation::try_from_command_format(payload) {
            Ok(ii) => ii,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e);
            }
        };

        if self.link_encrypted {
            if let Some(ref mut keys) = self.keys {
                keys.peer_irk = Some(identity_info.get_irk());

                Ok(Some(keys))
            } else {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason));
            }
        } else {
            self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                .await?;

            return Err(Error::UnknownIfLinkIsEncrypted);
        }
    }

    async fn p_identity_address_info<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<Option<&super::Keys>, Error>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing peer address info");

        let identity_addr_info = match encrypt_info::IdentityAddressInformation::try_from_command_format(payload) {
            Ok(iai) => iai,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e);
            }
        };

        if self.link_encrypted {
            if let Some(ref mut keys) = self.keys {
                keys.peer_identity = Some(identity_addr_info.into());

                Ok(Some(keys))
            } else {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason));
            }
        } else {
            self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                .await?;

            return Err(Error::UnknownIfLinkIsEncrypted);
        }
    }

    async fn p_signing_info<'z, C>(
        &'z mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<Option<&'z super::Keys>, Error>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing peer signing info (CSRK)");

        let signing_info = match encrypt_info::SigningInformation::try_from_command_format(payload) {
            Ok(si) => si,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e);
            }
        };

        if self.link_encrypted {
            if let Some(ref mut keys) = self.keys {
                keys.peer_csrk = Some((signing_info.get_signature_key(), 0));

                Ok(Some(keys))
            } else {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason));
            }
        } else {
            self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                .await?;

            return Err(Error::UnknownIfLinkIsEncrypted);
        }
    }
}

impl<S> SecurityManager<S, ExternalOobReceiver>
where
    S: for<'i> OutOfBandSend<'i>,
{
    /// Set the received out of band data
    ///
    /// This method is required to be called when the OOB receiver type is `ExternalOobReceiver`.
    /// Obviously it is not needed if the receiver type something other than `ExternalOobReceiver`
    /// because you cannot call this method.
    ///
    /// This method is tricky as it may only be called at the correct time during the pairing
    /// process with OOB, but the method
    /// [`expecting_oob_data`](SlaveSecurityManager::expecting_oob_data) can be used to get the
    /// correct time to call this method. If any other pairing process is being used, or this is
    /// called at the incorrect time, pairing is canceled and must be restarted by the initiator.
    /// The initiator is also sent the error `OOBNotAvailable`.
    ///
    /// This method must be called after the initiator's pairing public key message is *processed*
    /// but before the pairing random message is *processed*. Note *processed*, it is ok for this
    /// device to receive the pairing random message, but do not call the method
    /// [`process_command`](SlaveSecurityManager::process_command) with the message until after this
    /// method is called. The easiest way to know when this occurs is to call the method
    /// `expecting_oob_data` after processing every security manager message.
    ///
    /// ```
    /// # use std::error::Error;
    /// # use bo_tie_sm::oob::ExternalOobReceiver;
    /// # use std::future::Future;
    /// # use bo_tie_l2cap::{BasicInfoFrame, ChannelIdentifier, ConnectionChannel, ConnectionChannelExt, L2capFragment, LeUserChannelIdentifier};
    /// # use bo_tie_sm::responder::SecurityManagerBuilder;
    /// # use bo_tie_util::BluetoothDeviceAddress;
    /// # let mut security_manager_builder = SecurityManagerBuilder::new(BluetoothDeviceAddress::zeroed(), BluetoothDeviceAddress::zeroed(), false, false);
    /// # struct StubConnectionChannel;
    /// # impl ConnectionChannel for StubConnectionChannel {
    /// #     type SendBuffer = Vec<u8>;
    /// #     type SendFut<'a> = std::pin::Pin<Box<dyn Future<Output=Result<(), bo_tie_l2cap::send_future::Error<Self::SendFutErr>>>>>;
    /// #     type SendFutErr = usize;
    /// #     type RecvBuffer = Vec<u8>;
    /// #     type RecvFut<'a> = std::pin::Pin<Box<dyn Future<Output=Option<Result<L2capFragment<Self::RecvBuffer>, bo_tie_l2cap::BasicFrameError<<Self::RecvBuffer as bo_tie_util::buffer::TryExtend<u8>>::Error>>>>>>;
    /// #     fn send(&self, data: BasicInfoFrame<Vec<u8>>) -> Self::SendFut<'_> { unimplemented!() }
    /// #     fn set_mtu(&mut self,mtu: u16) { unimplemented!() }
    /// #     fn get_mtu(&self) -> usize { unimplemented!() }
    /// #     fn max_mtu(&self) -> usize { unimplemented!() }
    /// #     fn min_mtu(&self) -> usize { unimplemented!() }
    /// #     fn receive(&mut self) -> Self::RecvFut<'_> { unimplemented!() }
    /// # }
    /// # let mut connection_channel = StubConnectionChannel;
    /// # let oob_data = &[];
    /// # async {
    /// # let _r: Result<(), Box<dyn Error>> = async {
    /// const SM_CHANNEL_ID: ChannelIdentifier = ChannelIdentifier::Le(
    ///     LeUserChannelIdentifier::SecurityManagerProtocol
    /// );
    ///    
    /// let mut security_manager = security_manager_builder
    ///     .set_oob_receiver(ExternalOobReceiver)
    ///     .build();
    ///
    /// loop {
    ///     for b_frame in connection_channel.receive_b_frame().await? {
    ///         match b_frame.get_channel_id() {
    ///             SM_CHANNEL_ID => {
    ///                 security_manager.process_command(
    ///                     &connection_channel,
    ///                     &b_frame
    ///                 ).await?;
    ///
    ///                 if security_manager.expecting_oob_data() {
    ///                     security_manager.received_oob_data(
    ///                         &connection_channel,
    ///                         oob_data
    ///                     ).await?;
    ///                 }  
    ///             }
    ///             _ => { /* process other protocols */ }   
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }.await;
    /// # };
    /// ```
    /// # Note
    /// The error `ConfirmValueFailed` can also be returned, but that means that the method was
    /// called at the correct time, just that pairing was going to fail because of the confirm value
    /// check failing.
    pub async fn received_oob_data<C>(&mut self, connection_channel: &C, data: &[u8]) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        match self.pairing_data {
            Some(PairingData {
                pairing_method:
                    PairingMethod::Oob(OobDirection::BothSendOob) | PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob),
                private_key: Some(_),
                peer_public_key: Some(_),
                secret_key: Some(_),
                peer_nonce: None,
                external_oob_confirm_valid: false,
                ..
            }) => {
                self.oob_confirm_result(connection_channel, self.process_received_oob(data))
                    .await
            }
            _ => {
                self.send_err(connection_channel, pairing::PairingFailedReason::OOBNotAvailable)
                    .await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    /// Query the security manager if it is expecting some received OOB data
    ///
    /// This can be used to find the correct time to call the method `received_oob_data`. It is
    /// recommended to call this after every processed security manager message to know the
    /// correct time to call `received_oob_data`.
    pub fn expecting_oob_data(&self) -> bool {
        match self.pairing_data {
            Some(PairingData {
                pairing_method:
                    PairingMethod::Oob(OobDirection::BothSendOob) | PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob),
                private_key: Some(_),
                peer_public_key: Some(_),
                secret_key: Some(_),
                peer_nonce: None,
                external_oob_confirm_valid: false,
                ..
            }) => true,
            _ => false,
        }
    }
}
