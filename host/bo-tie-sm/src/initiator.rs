//! Initiating side of the Security Manager
//!
//! The security manager used by the initiator begins the processing of pairing between the two
//! devices.
//!
//! # Builder
//! An initiating [`SecurityManger`] must be created from the builder [`SecurityManagerBuilder`].
//! The builder is used to configure the type of pairing performed and the bonding keys that allowed
//! for distribution by the security manager. The default builder does not distribute the identity
//! resolving key during bonding and use *just works* man in the middle (MITM) protection.
//! Unfortunately other forms of MITM protection require access to things outside the scope of the
//! implementation of this library.
//!
//! ```
#![cfg_attr(
    botiedocs,
    doc = r##"
# mod bo_tie {
#    mod sm {
#        pub use bo_tie_sm::*;
#    }
# }
use bo_tie::sm::initiator::SecurityManagerBuilder;
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
use crate::oob::sealed_receiver_type::OobReceiverTypeVariant;
use crate::oob::{ExternalOobReceiver, OobDirection, OobReceiverType};
use crate::{EnabledBondingKeysBuilder, IdentityAddress};
use alloc::vec::Vec;
use bo_tie_util::buffer::stack::LinearBuffer;

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
    /// Create a new `MasterSecurityManagerBuilder`
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
            distribute_irk: false,
            distribute_csrk: false,
            accept_irk: true,
            accept_csrk: true,
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
    /// address *by the* peer device.
    pub fn set_already_paired(mut self, keys: super::Keys) -> Result<Self, &'static str> {
        if keys.get_ltk().is_some() {
            self.prior_keys = Some(keys);

            Ok(self)
        } else {
            Err("missing long term key")
        }
    }

    /// Set the bonding keys to be distributed by the initiator
    ///
    /// This is used to specify within the pairing request packet what bonding keys are going to be
    /// distributed by the initiator security manager.
    ///
    /// # Note
    /// By default no bonding keys are distributed by this initiator. This method does not need to
    /// be called if the default key configuration is desired.
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
    /// This is used to specify within the pairing request packet what bonding keys can be received
    /// by the initiator security manager.
    ///
    /// # Note
    /// By default all bonding keys are accepted by this initiator. This method does not need to
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
    /// # let security_manager_builder = bo_tie_sm::initiator::SecurityManagerBuilder::new(this_addr, remote_addr, false, false);
    /// # async fn send_over_oob(a: &[u8]) { panic!("{:?}", a)}
    ///
    /// security_manager_builder.set_oob_sender(|pairing_data: &[u8]| async move {
    ///     let _p = pairing_data;
    /// })
    /// # .build();
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
    /// # let security_manager_builder = bo_tie_sm::initiator::SecurityManagerBuilder::new(this_addr, remote_addr, false, false);
    /// # async fn receive_from_oob() -> Vec<u8> { Vec::new()}
    ///
    /// security_manager_builder.set_oob_receiver(|| async {
    ///     receive_from_oob().await
    /// })
    /// # .build();
    /// ```
    ///
    /// # External to the Security Manager Out of Band Data.
    /// Sometimes the infrastructure for receiving out of band data is not available when a security
    /// manager is created. The marker type [`ExternalOobReceiver`] may be used as the `receiver` to
    /// indicate that the out of band data must be set by the method [`received_oob_data`]. This is
    /// not the ideal method of integrating OOB into the security manager as there is a number of
    /// strict requirements for using that method.
    ///
    /// The main reason why using `ExternalOobReceiver` is not recommended as the approach shown in
    /// the example is a set it and forget it approach.
    ///
    /// [`ExternalOobReceiver`]: crate::oob::ExternalOobReceiver
    /// [`received_oob_data`]: MasterSecurityManager::received_oob_data
    pub fn set_oob_receiver<R2>(self, receiver: R2) -> SecurityManagerBuilder<S, R2>
    where
        R2: OobReceiverType,
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

    /// Create the `MasterSecurityManager`
    ///
    /// # Note
    /// This will create a `MasterSecurityManager` that does not support the out of band pairing
    /// method.
    pub fn build<'a>(self) -> SecurityManager<S, R>
    where
        S: OutOfBandSend<'a>,
        R: OobReceiverType,
    {
        let auth_req = LinearBuffer::new();

        let initiator_key_distribution = super::get_keys(self.distribute_irk, self.distribute_csrk);

        let responder_key_distribution = super::get_keys(self.accept_irk, self.accept_csrk);

        let pairing_request = pairing::PairingRequest::new(
            self.io_capabilities,
            if R::can_receive() {
                pairing::OOBDataFlag::AuthenticationDataFromRemoteDevicePresent
            } else {
                pairing::OOBDataFlag::AuthenticationDataNotPresent
            },
            auth_req,
            self.encryption_key_max,
            initiator_key_distribution,
            responder_key_distribution,
        );

        SecurityManager {
            encryption_key_size_min: self.encryption_key_min,
            encryption_key_size_max: self.encryption_key_max,
            oob_send: self.oob_sender,
            oob_receive: self.oob_receiver,
            pairing_request,
            initiator_address: self.this_address,
            responder_address: self.remote_address,
            initiator_address_is_random: self.this_address_is_random,
            responder_address_is_random: self.remote_address_is_random,
            pairing_data: None,
            keys: self.prior_keys,
            link_encrypted: false,
            pairing_expected_cmd: None,
        }
    }
}

pub struct SecurityManager<S, R> {
    oob_send: S,
    oob_receive: R,
    pairing_request: pairing::PairingRequest,
    encryption_key_size_min: usize,
    encryption_key_size_max: usize,
    initiator_address: crate::BluetoothDeviceAddress,
    responder_address: crate::BluetoothDeviceAddress,
    initiator_address_is_random: bool,
    responder_address_is_random: bool,
    pairing_data: Option<PairingData>,
    keys: Option<super::Keys>,
    link_encrypted: bool,
    pairing_expected_cmd: Option<super::CommandType>,
}

macro_rules! check_channel_id_and {
    ($data:expr, async $job:block ) => {
        if $data.get_channel_id() == super::L2CAP_CHANNEL_ID {
            $job
        } else {
            Err(Error::IncorrectL2capChannelId)
        }
    };
}

impl<S, R> SecurityManager<S, R> {
    /// Indicate if the connection is encrypted
    ///
    /// This is used to indicate to the `MasterSecurityManager` that it is safe to send a Key to the
    /// peer device. This is a deliberate extra step to ensure that the functions `send_irk`,
    /// `send_csrk`, `send_pub_addr`, and `send_rand_addr` are only used when the link is encrypted.
    pub fn set_encrypted(&mut self, is_encrypted: bool) {
        self.link_encrypted = is_encrypted
    }

    /// Get the pairing keys
    ///
    /// Pairing must be completed before these keys are generated
    pub fn get_keys(&self) -> Option<&super::Keys> {
        self.keys.as_ref()
    }
}

impl<S, R> SecurityManager<S, R> {
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

    /// Send the Identity Resolving Key
    ///
    /// This will add the IRK to the cypher keys and send it to the other device if the internal
    /// encryption flag is set to true (by the method [`set_encrypted`]) and pairing has completed.
    ///
    /// If the input `irk` evaluates to `None` then an IRK is generated before being added and sent.
    ///
    /// The IRK is returned if it was successfully sent to the other device.
    ///
    /// [`set_encrypted`]: bo_tie_sm::initiator::SecurityManager::set_encrypted
    pub async fn send_irk<C, Irk>(&mut self, connection_channel: &C, irk: Irk) -> Result<u128, Error>
    where
        C: ConnectionChannel,
        Irk: Into<Option<u128>>,
    {
        if self.link_encrypted {
            let irk = irk.into().unwrap_or(toolbox::rand_u128());

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
    /// encryption flag is set to true (by the method [`set_encrypted`]) and pairing has completed.
    ///
    /// If the input `csrk` evaluates to `None` then a CSRK is generated before being added and
    /// sent.
    ///
    /// The CSRK is returned if it was successfully sent to the other device
    ///
    /// # Note
    /// There is no input for the sign counter as the CSRK is considered a new value, and thus the
    /// sign counter within the CSRK will always be 0.
    ///
    /// [`set_encrypted`]: bo_tie_sm::initiator::SecurityManager::set_encrypted
    pub async fn send_csrk<C, Csrk>(&mut self, connection_channel: &C, csrk: Csrk) -> Result<u128, Error>
    where
        C: ConnectionChannel,
        Csrk: Into<Option<u128>>,
    {
        if self.link_encrypted {
            let csrk = csrk.into().unwrap_or(toolbox::rand_u128());

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
    /// # Error
    /// An error will occur if the encryption flag is not set or an error occurs trying to send the
    /// message to the peer device.
    ///
    /// [`set_encrypted`]: crate::sm::initiator::SecurityManager::set_encrypted
    pub async fn send_identity<C, I>(&mut self, connection_channel: &C, identity: I) -> Result<(), Error>
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

            Ok(())
        } else {
            Err(Error::UnknownIfLinkIsEncrypted)
        }
    }
}

impl<S, R> SecurityManager<S, R>
where
    S: for<'i> OutOfBandSend<'i>,
    R: OobReceiverType,
{
    /// Send the Pairing Request to the slave device
    ///
    /// This sends the pairing request security manage PDU to the slave which will initiate the
    /// pairing process
    async fn send_pairing_request<C>(&mut self, connection_channel: &C) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        self.pairing_data = None;

        self.send(connection_channel, self.pairing_request.clone()).await
    }

    async fn process_pairing_response<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        let response = pairing::PairingResponse::try_from_command_format(payload)?;

        if response.get_max_encryption_size() < self.encryption_key_size_min {
            self.send_err(connection_channel, pairing::PairingFailedReason::EncryptionKeySize)
                .await?;

            Err(Error::PairingFailed(pairing::PairingFailedReason::EncryptionKeySize))
        } else {
            let pairing_method = PairingMethod::determine_method(
                self.pairing_request.get_oob_data_flag(),
                response.get_oob_data_flag(),
                self.pairing_request.get_io_capability(),
                response.get_io_capability(),
                false,
            );

            let initiator_io_cap = self.pairing_request.get_io_cap();
            let responder_io_cap = response.get_io_cap();

            let (private_key, public_key) = toolbox::ecc_gen();

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

            Ok(())
        }
    }

    /// Send the pairing pub key
    ///
    /// After the pairing pub key PDU is sent to the slave, a `ResponseProcessor` is returned that
    /// can be used to process the acl data returned by the server.
    async fn send_pairing_pub_key<C>(&mut self, connection_channel: &C) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        match self.pairing_data {
            Some(PairingData { ref public_key, .. }) => {
                let raw_pub_key = {
                    let key_bytes = public_key.clone().into_command_format();

                    let mut raw_key = [0u8; 64];

                    raw_key.copy_from_slice(&key_bytes);

                    raw_key
                };

                self.send(connection_channel, pairing::PairingPubKey::new(raw_pub_key))
                    .await?;

                Ok(())
            }
            _ => Err(Error::IncorrectCommand(CommandType::PairingPublicKey)),
        }
    }

    async fn process_responder_pub_key<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        let pub_key = pairing::PairingPubKey::try_from_command_format(payload);

        match (&pub_key, &mut self.pairing_data) {
            (
                Ok(peer_pub_key_pdu),
                Some(PairingData {
                    private_key: private_key @ Some(_),
                    peer_public_key,
                    secret_key,
                    ..
                }),
            ) => {
                let remote_pub_key = match toolbox::PubKey::try_from_command_format(&peer_pub_key_pdu.get_key()) {
                    Ok(k) => k,
                    Err(e) => {
                        self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                            .await?;

                        return Err(e);
                    }
                };

                let this_pri_key = private_key.take().unwrap();

                *secret_key = toolbox::ecdh(this_pri_key, &remote_pub_key).into();

                *peer_public_key = remote_pub_key.into();

                Ok(())
            }
            _ => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    /// Wait for responder check
    async fn process_responder_commitment<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        match (
            &pairing::PairingConfirm::try_from_command_format(payload),
            &mut self.pairing_data,
        ) {
            (
                Ok(responder_confirm),
                Some(PairingData {
                    pairing_method: PairingMethod::JustWorks,
                    responder_pairing_confirm,
                    ..
                }),
            )
            | (
                Ok(responder_confirm),
                Some(PairingData {
                    pairing_method: PairingMethod::NumbComp,
                    responder_pairing_confirm,
                    ..
                }),
            ) => {
                *responder_pairing_confirm = responder_confirm.get_value().into();

                log::trace!("(SM) responder Commitment: {:?}", responder_confirm.get_value());

                Ok(())
            }
            (Err(_), _) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                Err(Error::Value)
            }
            _ => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    /// Send the Nonce
    ///
    /// # Panics
    /// This will panic if the pairing response has not been received yet
    async fn send_pairing_random<C>(&mut self, connection_channel: &C) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        match self.pairing_data {
            Some(PairingData { nonce, .. }) => {
                log::trace!("(SM) initiator nonce: {:?}", nonce);

                self.send(connection_channel, pairing::PairingRandom::new(nonce))
                    .await?;

                Ok(())
            }
            _ => return Err(Error::UnsupportedFeature),
        }
    }

    async fn process_responder_random<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        let responder_nonce = match pairing::PairingRandom::try_from_command_format(payload) {
            Ok(pairing_random) => pairing_random.get_value(),
            _ => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(Error::Value);
            }
        };

        log::trace!("(SM) responder Nonce: {:?}", responder_nonce);

        match &mut self.pairing_data {
            Some(PairingData {
                pairing_method: PairingMethod::JustWorks | PairingMethod::NumbComp,
                peer_nonce,
                peer_public_key: Some(peer_public_key),
                public_key,
                responder_pairing_confirm: Some(responder_confirm),
                ..
            }) => {
                let initiator_confirm = toolbox::f4(
                    GetXOfP256Key::x(peer_public_key),
                    GetXOfP256Key::x(public_key),
                    responder_nonce,
                    0,
                );

                *peer_nonce = responder_nonce.into();

                if *responder_confirm == initiator_confirm {
                    Ok(())
                } else {
                    let reason = pairing::PairingFailedReason::ConfirmValueFailed;

                    self.send_err(connection_channel, reason).await?;

                    Err(Error::PairingFailed(reason))
                }
            }
            Some(PairingData {
                pairing_method:
                    PairingMethod::Oob(OobDirection::OnlyResponderSendsOob) | PairingMethod::Oob(OobDirection::BothSendOob),
                external_oob_confirm_valid,
                ..
            }) if OobReceiverTypeVariant::External == R::receiver_type() && !*external_oob_confirm_valid => {
                self.send_err(connection_channel, pairing::PairingFailedReason::OOBNotAvailable)
                    .await?;

                Err(Error::ExternalOobNotProvided)
            }
            Some(PairingData {
                peer_nonce,
                pairing_method: PairingMethod::Oob(_),
                ..
            }) => {
                *peer_nonce = responder_nonce.into();

                Ok(())
            }
            _ => {
                let reason = pairing::PairingFailedReason::UnspecifiedReason;

                self.send_err(connection_channel, reason).await?;

                Err(Error::PairingFailed(reason))
            }
        }
    }

    async fn send_initiator_dh_key_check<C>(&mut self, connection_channel: &C) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        let ltk = match self.pairing_data {
            Some(PairingData {
                pairing_method: PairingMethod::JustWorks,
                secret_key: Some(ref dh_key),
                ref nonce,
                peer_nonce: Some(ref peer_nonce),
                ref initiator_io_cap,
                ref mut mac_key,
                ..
            })
            | Some(PairingData {
                pairing_method: PairingMethod::NumbComp,
                secret_key: Some(ref dh_key),
                ref nonce,
                peer_nonce: Some(ref peer_nonce),
                ref initiator_io_cap,
                ref mut mac_key,
                ..
            }) => {
                let a_addr = toolbox::PairingAddress::new(&self.initiator_address, self.initiator_address_is_random);

                let b_addr = toolbox::PairingAddress::new(&self.responder_address, self.responder_address_is_random);

                let (gen_mac_key, ltk) = toolbox::f5(*dh_key, *nonce, *peer_nonce, a_addr.clone(), b_addr.clone());

                let ea = toolbox::f6(gen_mac_key, *nonce, *peer_nonce, 0, *initiator_io_cap, a_addr, b_addr);

                *mac_key = gen_mac_key.into();

                self.send(connection_channel, pairing::PairingDHKeyCheck::new(ea))
                    .await?;

                ltk
            }
            _ => return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason)),
        };

        self.keys = Some(super::Keys {
            is_authenticated: todo!(),
            ltk: ltk.into(),
            csrk: None,
            irk: None,
            peer_csrk: None,
            peer_irk: None,
            peer_identity: if self.responder_address_is_random {
                IdentityAddress::StaticRandom(self.responder_address)
            } else {
                IdentityAddress::Public(self.responder_address)
            }
            .into(),
            identity: if self.initiator_address_is_random {
                IdentityAddress::StaticRandom(self.initiator_address)
            } else {
                IdentityAddress::Public(self.initiator_address)
            }
            .into(),
        });

        Ok(())
    }

    async fn process_responder_dh_key_check<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        let eb = match pairing::PairingDHKeyCheck::try_from_command_format(payload) {
            Ok(responder_confirm) => responder_confirm,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e);
            }
        };

        let check = match self.pairing_data {
            Some(PairingData {
                pairing_method: PairingMethod::JustWorks,
                ref nonce,
                peer_nonce: Some(ref peer_nonce),
                ref responder_io_cap,
                mac_key: Some(ref mac_key),
                ..
            })
            | Some(PairingData {
                pairing_method: PairingMethod::NumbComp,
                ref nonce,
                peer_nonce: Some(ref peer_nonce),
                ref responder_io_cap,
                mac_key: Some(ref mac_key),
                ..
            }) => {
                let a_addr = toolbox::PairingAddress::new(&self.initiator_address, self.initiator_address_is_random);

                let b_addr = toolbox::PairingAddress::new(&self.responder_address, self.responder_address_is_random);

                let calc_eb = toolbox::f6(*mac_key, *peer_nonce, *nonce, 0, *responder_io_cap, b_addr, a_addr);

                eb.get_key_check() == calc_eb
            }
            _ => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason));
            }
        };

        if check {
            Ok(())
        } else {
            self.send_err(connection_channel, pairing::PairingFailedReason::DHKeyCheckFailed)
                .await?;

            Err(Error::PairingFailed(pairing::PairingFailedReason::DHKeyCheckFailed))
        }
    }

    /// Send the OOB confirm information
    ///
    /// This will create the confirm information and send the information to the responder if the
    /// sender function was set. If no sender was set, this method does nothing.
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

            let role = LeRole::OnlyCentral;

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

    /// Receive OOB information from the responder
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

        let mut rb = None;
        let mut cb = None;

        for ad in EirOrAdIterator::new(raw).silent() {
            const RANDOM_TYPE: u8 = AssignedTypes::LESecureConnectionsRandomValue.val();
            const CONFIRM_TYPE: u8 = AssignedTypes::LESecureConnectionsConfirmationValue.val();

            match ad.get_type() {
                RANDOM_TYPE => rb = sc_random_value::ScRandomValue::try_from_struct(ad).ok(),
                CONFIRM_TYPE => cb = sc_confirm_value::ScConfirmValue::try_from_struct(ad).ok(),
                _ => (),
            }
        }

        if let (Some(rb), Some(ca)) = (rb, cb) {
            let paring_data = self.pairing_data.as_ref().unwrap();

            let pkb = GetXOfP256Key::x(paring_data.peer_public_key.as_ref().unwrap());

            if ca.0 == toolbox::f4(pkb, pkb, rb.0, 0) {
                true
            } else {
                false
            }
        } else {
            false
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
    /// The method returns true if oob data is expected to be received externally from this
    /// security manager.
    ///
    /// # Panic
    /// This method will panic if `DoesNotExist` is the receiver type or `pairing_data` is `None`
    async fn by_oob_receiver_type<C>(&mut self, connection_channel: &C) -> Result<bool, Error>
    where
        C: ConnectionChannel,
    {
        match R::receiver_type() {
            OobReceiverTypeVariant::Internal => {
                let confirm_result = self.receive_oob().await;

                self.oob_confirm_result(connection_channel, confirm_result)
                    .await
                    .map(|_| true)
            }
            OobReceiverTypeVariant::External => Ok(false),
            OobReceiverTypeVariant::DoesNotExist => unreachable!(),
        }
    }

    /// Function for the validation result of the confirm value with an OOB data.
    ///
    /// # Note
    /// If the `confirm_result` is true then this device's nonce is sent to the responder.
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
                    nonce,
                    ref mut external_oob_confirm_valid,
                    ..
                }) => {
                    *external_oob_confirm_valid = true;

                    self.send(connection_channel, pairing::PairingRandom::new(nonce)).await
                }
                None => unreachable!("Pairing Data cannot be None"),
            }
        } else {
            self.send_err(connection_channel, pairing::PairingFailedReason::ConfirmValueFailed)
                .await
        }
    }

    /// Deal with the oob confirm values
    ///
    /// This will return true if once the oob confirm value step is completed. False is only
    /// returned when OOB data is to be externally set by the user.
    async fn oob_confirm<C>(&mut self, connection_channel: &C, oob_direction: OobDirection) -> Result<bool, Error>
    where
        C: ConnectionChannel,
    {
        match oob_direction {
            OobDirection::OnlyInitiatorSendsOob => {
                self.send_oob().await;
                Ok(true)
            }
            OobDirection::OnlyResponderSendsOob => self.by_oob_receiver_type(connection_channel).await,
            OobDirection::BothSendOob => {
                self.send_oob().await;

                self.by_oob_receiver_type(connection_channel).await
            }
        }
    }

    /// Pair to the slave device
    ///
    /// This will start and complete the pairing process to the slave device. Unlike the methods
    /// `start_pairing` and `continue_pairing`, once this has been polled to completion either the
    /// slave device has paired to this device or pairing has failed. The consequence of this is
    /// that it will hold the l2cap connection channel until the pairing process is completed (or
    /// failed). Any received data received that is not part of the security manager specification
    /// are returned along the the generated keys (the long term key) once pairing is completed
    pub async fn pair<C>(
        &mut self,
        connection_channel: &mut C,
    ) -> (
        Result<&mut super::Keys, Error>,
        Vec<crate::l2cap::BasicInfoFrame<Vec<u8>>>,
    )
    where
        C: ConnectionChannel,
    {
        use crate::l2cap::ConnectionChannelExt;

        let mut other_data = alloc::vec::Vec::new();

        if let Err(e) = self.start_pairing(connection_channel).await {
            return (Err(e), other_data);
        }

        'outer: loop {
            match connection_channel.receive_b_frame().await {
                Err(e) => return (Err(super::Error::ACLData(e)), other_data),
                Ok(acl_data_vec) => {
                    for (index, acl_data) in acl_data_vec.iter().enumerate() {
                        match acl_data.get_channel_id() {
                            super::L2CAP_CHANNEL_ID => {
                                match self.continue_pairing(connection_channel, acl_data).await {
                                    Err(e) => return (Err(e), other_data),
                                    Ok(true) => {
                                        other_data.extend_from_slice(&acl_data_vec[(index + 1)..]);

                                        break 'outer;
                                    }
                                    Ok(false) => (),
                                }
                            }
                            _ => other_data.push(acl_data.clone()),
                        }
                    }
                }
            }
        }

        (Ok(self.keys.as_mut().unwrap()), other_data)
    }

    /// Start pairing
    ///
    /// Initiate the pairing process and sends the request for the slave's pairing information.
    /// This function is required to be called before `continue_pairing` can be used to process
    /// and send further Security Manager PDU's to the slave.
    pub async fn start_pairing<C>(&mut self, connection_channel: &C) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        self.pairing_expected_cmd = super::CommandType::PairingResponse.into();

        self.send_pairing_request(connection_channel).await
    }

    /// Continue Pairing
    ///
    /// This is used to continue pairing until pairing is either complete or fails. It must be
    /// called for every received Security Manager ACL data. True is returned once pairing is
    /// completed.
    pub async fn continue_pairing<C>(
        &mut self,
        connection_channel: &C,
        acl_data: &crate::l2cap::BasicInfoFrame<Vec<u8>>,
    ) -> Result<bool, Error>
    where
        C: ConnectionChannel,
    {
        check_channel_id_and!(acl_data, async {
            let (d_type, payload) = acl_data.get_payload().split_at(1);

            match CommandType::try_from_val(d_type[0]) {
                Ok(CommandType::PairingFailed) => {
                    self.pairing_expected_cmd = super::CommandType::PairingFailed.into();

                    Err(Error::PairingFailed(
                        pairing::PairingFailed::try_from_command_format(payload)?.get_reason(),
                    ))
                }
                Ok(cmd) if Some(cmd) == self.pairing_expected_cmd => self.next_step(connection_channel, payload).await,
                Ok(cmd) => {
                    self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                        .await?;

                    Err(Error::IncorrectCommand(cmd))
                }
                Err(e) => {
                    self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                        .await?;

                    Err(e)
                }
            }
        })
    }

    async fn next_step<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<bool, Error>
    where
        C: ConnectionChannel,
    {
        match self.pairing_expected_cmd {
            Some(CommandType::PairingResponse) => {
                match self.process_pairing_response(connection_channel, payload).await {
                    Ok(_) => {
                        self.pairing_expected_cmd = CommandType::PairingPublicKey.into();

                        match self.send_pairing_pub_key(connection_channel).await {
                            Ok(_) => Ok(false),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => self.step_err(e),
                }
            }
            Some(CommandType::PairingPublicKey) => {
                match self.process_responder_pub_key(connection_channel, payload).await {
                    Ok(_) => match self.pairing_data.as_ref().unwrap().pairing_method {
                        PairingMethod::JustWorks | PairingMethod::NumbComp => {
                            self.pairing_expected_cmd = super::CommandType::PairingConfirm.into();

                            Ok(false)
                        }
                        PairingMethod::Oob(direction) => {
                            if self.oob_confirm(connection_channel, direction).await? {
                                self.pairing_expected_cmd = super::CommandType::PairingRandom.into();
                            } else {
                                self.pairing_expected_cmd = None;
                            }

                            Ok(true)
                        }
                        PairingMethod::PassKeyEntry => unimplemented!(),
                    },
                    Err(e) => self.step_err(e),
                }
            }
            Some(CommandType::PairingConfirm) => {
                match self.process_responder_commitment(connection_channel, payload).await {
                    Ok(_) => {
                        self.pairing_expected_cmd = CommandType::PairingRandom.into();

                        match self.send_pairing_random(connection_channel).await {
                            Ok(_) => Ok(false),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => self.step_err(e),
                }
            }
            Some(CommandType::PairingRandom) => {
                match self.process_responder_random(connection_channel, payload).await {
                    Ok(_) => {
                        self.pairing_expected_cmd = CommandType::PairingDHKeyCheck.into();

                        match self.send_initiator_dh_key_check(connection_channel).await {
                            Ok(_) => Ok(false),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => self.step_err(e),
                }
            }
            Some(CommandType::PairingDHKeyCheck) => {
                self.pairing_expected_cmd = None;

                self.process_responder_dh_key_check(connection_channel, payload)
                    .await
                    .map(|_| true)
            }
            _ => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    fn step_err(&mut self, e: Error) -> Result<bool, Error> {
        self.pairing_expected_cmd = None;

        Err(e)
    }

    /// Process "bonding" packets
    ///
    /// Bonding keys are sent from the peer device (hopefully) as soon as encryption is first
    /// established between it and this device. After pairing is completed, any received security
    /// manager packets need to be processed by this method.
    ///
    /// This method is used for processing bonding packets, and assuming the peer device is working
    /// correctly it will only send bonding information when the link is encrypted. **But this
    /// method will return errors when processing those methods if this Security Manager's internal
    /// encryption flag is not set via the method
    /// [`set_encrypted`](MasterSecurityManager::set_encrypted)**. Once this flag is set all
    /// security manager packets with bonding information can be process by this method.
    ///
    /// # Return
    /// When a packet contains either a key or the identity address, this information is stored
    /// within the security manager, and a reference to these set of keys is returned.
    ///
    /// If the peer device sends a [`SecurityRequest`](super::CommandType::PairingRequest) message,
    /// this method will process it and return `None` (the internal encryption flag is not checked
    /// for this specific message).
    ///
    /// # Errors
    ///
    /// ### Always Errors
    /// An error is always returned if any of the pairing specific or legacy key Security Manager
    /// messages are processed by this method (only secure connections is supported by this
    /// library). Trying to process any of following will always cause an error to be returned.
    /// * [`PairingRequest`](super::CommandType::PairingRequest)
    /// * [`PairingResponse`](super::CommandType::PairingResponse)
    /// * [`PairingConfirm`](super::CommandType::PairingConfirm)
    /// * [`PairingRandom`](super::CommandType::PairingRandom)
    /// * [`PairingFailed`](super::CommandType::PairingFailed)
    /// * [`EncryptionInformation`](super::CommandType::EncryptionInformation)
    /// * [`MasterIdentification`](super::CommandType::MasterIdentification)
    /// * [`PairingPublicKey`](super::CommandType::PairingPublicKey)
    /// * [`PairingDHKeyCheck`](super::CommandType::PairingDHKeyCheck)
    /// * [`PairingKeyPressNotification`](super::CommandType::PairingKeyPressNotification)
    ///
    /// ### Require Encryption
    /// The following Security Manager messages will have this method return an error unless the
    /// internal encryption flag is set.
    /// * [`IdentityInformation`](super::CommandType::IdentityInformation)
    /// * [`IdentityAddressInformation`](super::CommandType::IdentityAddressInformation)
    /// * [`SigningInformation`](super::CommandType::SigningInformation)
    pub async fn process_bonding<C>(
        &mut self,
        connection_channel: &C,
        acl_data: &crate::l2cap::BasicInfoFrame<Vec<u8>>,
    ) -> Result<Option<&super::Keys>, Error>
    where
        C: ConnectionChannel,
    {
        macro_rules! bonding_key {
            ($this:expr, $payload:expr, $key:ident, $key_type:ident, $get_key_method:ident) => {
                match (
                    self.link_encrypted,
                    $this.keys.is_some(),
                    encrypt_info::$key_type::try_from_command_format($payload),
                ) {
                    (true, true, Ok(packet)) => {
                        let keys = $this.keys.as_mut().unwrap();

                        keys.$key = Some(packet.$get_key_method());

                        Ok(Some(keys))
                    }
                    (false, _, _) => {
                        self.send_err(
                            connection_channel,
                            pairing::PairingFailedReason::UnspecifiedReason,
                        )
                        .await?;

                        Err(Error::UnknownIfLinkIsEncrypted)
                    }
                    (_, false, _) => {
                        self.send_err(
                            connection_channel,
                            pairing::PairingFailedReason::UnspecifiedReason,
                        )
                        .await?;

                        Err(Error::OperationRequiresPairing)
                    }
                    (_, _, Err(e)) => {
                        self.send_err(
                            connection_channel,
                            pairing::PairingFailedReason::UnspecifiedReason,
                        )
                        .await?;

                        Err(e)
                    }
                }
            };
        }

        check_channel_id_and!(acl_data, async {
            let (d_type, payload) = acl_data.get_payload().split_at(1);

            match CommandType::try_from_val(d_type[0])? {
                CommandType::IdentityInformation => {
                    bonding_key!(self, payload, ltk, IdentityInformation, get_irk)
                }
                CommandType::SigningInformation => {
                    bonding_key!(self, payload, csrk, SigningInformation, to_new_csrk_key)
                }
                CommandType::IdentityAddressInformation => {
                    bonding_key!(self, payload, peer_identity, IdentityAddressInformation, as_blu_addr)
                }
                CommandType::SecurityRequest => Ok(None),
                c => Err(Error::IncorrectCommand(c)),
            }
        })
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
    /// process with OOB, although the method
    /// does make this easier. If [`expecting_oob_data`] any other pairing process is being used, or
    /// this is called at the incorrect time, pairing is canceled and must be restarted by the
    /// responder. The responder is also sent the error `OobNotAvailable`.
    ///
    /// This method must be called after the responder's pairing public key message is *processed*
    /// but before the pairing random message is *processed*. Note *processed*, it is ok for this
    /// device to receive the pairing random message, but do not call the method until after this
    /// method is called. The easiest way to know when this occurs is to call the method
    /// `expecting_oob_data` after processing every security manager message, although this
    /// procedure can be stopped after this method is called.
    ///
    /// # Note
    /// The error `ConfirmValueFailed` can also be returned, but that means that the method was
    /// called at the correct time, just that pairing was going to fail because of the confirm value
    /// check failing.
    ///
    /// [`expecting_oob_data`]:  SecurityManager::expecting_oob_data
    /// [`process_command`]: SecurityManager::continue_pairing
    pub async fn received_oob_data<C>(&mut self, connection_channel: &C, data: Vec<u8>) -> Result<(), Error>
    where
        C: ConnectionChannel,
    {
        match (&mut self.pairing_expected_cmd, &self.pairing_data) {
            (
                expected_command @ None,
                Some(PairingData {
                    pairing_method:
                        PairingMethod::Oob(OobDirection::BothSendOob)
                        | PairingMethod::Oob(OobDirection::OnlyResponderSendsOob),
                    private_key: Some(_),
                    peer_public_key: Some(_),
                    secret_key: Some(_),
                    peer_nonce: None,
                    external_oob_confirm_valid: false,
                    ..
                }),
            ) => {
                *expected_command = super::CommandType::PairingRandom.into();

                self.oob_confirm_result(connection_channel, self.process_received_oob(&data))
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
        match (&self.pairing_expected_cmd, &self.pairing_data) {
            (
                None,
                Some(PairingData {
                    pairing_method:
                        PairingMethod::Oob(OobDirection::BothSendOob)
                        | PairingMethod::Oob(OobDirection::OnlyResponderSendsOob),
                    private_key: Some(_),
                    peer_public_key: Some(_),
                    secret_key: Some(_),
                    peer_nonce: None,
                    external_oob_confirm_valid: false,
                    ..
                }),
            ) => true,
            _ => false,
        }
    }
}
