/// The initiator implementation of a Security Manager
use super::oob::{BuildOutOfBand, OutOfBandMethodBuilder, OutOfBandSend};
use super::{
    encrypt_info, pairing, toolbox, Command, CommandData, CommandType, Error, GetXOfP256Key, PairingData, PairingMethod,
};
use crate::l2cap::ConnectionChannel;
use crate::sm::oob::sealed_receiver_type::OobReceiverTypeVariant;
use crate::sm::oob::{ExternalOobReceiver, OobDirection, OobReceiverType};
use alloc::vec::Vec;

pub struct MasterSecurityManagerBuilder<'a, C> {
    connection_channel: &'a C,
    io_capabilities: pairing::IOCapability,
    encryption_key_min: usize,
    encryption_key_max: usize,
    remote_address: &'a crate::BluetoothDeviceAddress,
    this_address: &'a crate::BluetoothDeviceAddress,
    remote_address_is_random: bool,
    this_address_is_random: bool,
    distribute_ltk: bool,
    distribute_csrk: bool,
    accept_ltk: bool,
    accept_csrk: bool,
    prior_keys: Option<super::Keys>,
}

impl<'a, C> MasterSecurityManagerBuilder<'a, C> {
    /// Create a new `MasterSecurityManagerBuilder`
    pub fn new(
        connection_channel: &'a C,
        connected_device_address: &'a crate::BluetoothDeviceAddress,
        this_device_address: &'a crate::BluetoothDeviceAddress,
        is_connected_devices_address_random: bool,
        is_this_device_address_random: bool,
    ) -> Self {
        Self {
            connection_channel,
            io_capabilities: pairing::IOCapability::NoInputNoOutput,
            encryption_key_min: super::ENCRYPTION_KEY_MAX_SIZE,
            encryption_key_max: super::ENCRYPTION_KEY_MAX_SIZE,
            remote_address: connected_device_address,
            this_address: this_device_address,
            remote_address_is_random: is_connected_devices_address_random,
            this_address_is_random: is_this_device_address_random,
            distribute_ltk: false,
            distribute_csrk: false,
            accept_ltk: true,
            accept_csrk: true,
            prior_keys: None,
        }
    }

    /// Set the keys if the devices are already paired
    ///
    /// Assigns the keys that were previously generated after a successful pair. The long term key
    /// must be present within `keys` (unless `keys` is `None`). *This method allows for bonding
    /// keys to be distributed without having to go through pairing.
    pub fn set_already_paired<K: Into<Option<super::Keys>>>(&mut self, keys: K) -> Result<(), &'static str> {
        self.prior_keys = keys
            .into()
            .map(|keys| {
                if keys.get_ltk().is_some() {
                    Ok(keys)
                } else {
                    Err("Missing LTK")
                }
            })
            .transpose()?;

        Ok(())
    }

    /// Set the bonding keys to be distributed by the initiator
    ///
    /// This is used to specify within the pairing request packet what bonding keys are going to be
    /// distributed by the initiator security manager.
    ///
    /// # Note
    /// By default no bonding keys are distributed by this initiator. This method does not need to
    /// be called if the default key configuration is desired.
    pub fn sent_bonding_keys(
        &'a mut self,
    ) -> impl super::EnabledBondingKeys<'a, MasterSecurityManagerBuilder<'a, C>> + 'a {
        self.distribute_ltk = false;
        self.distribute_csrk = false;

        struct SentKeys<'z, C>(&'z mut MasterSecurityManagerBuilder<'z, C>);

        impl<'z, C> super::EnabledBondingKeys<'z, MasterSecurityManagerBuilder<'z, C>> for SentKeys<'z, C> {
            fn distribute_ltk(&mut self) -> &mut Self {
                self.0.distribute_ltk = true;
                self
            }

            fn distribute_csrk(&mut self) -> &mut Self {
                self.0.distribute_csrk = true;
                self
            }

            fn finish_keys(self) -> &'z mut MasterSecurityManagerBuilder<'z, C> {
                self.0
            }

            fn default(self) -> &'z mut MasterSecurityManagerBuilder<'z, C> {
                self.0.distribute_ltk = false;
                self.0.distribute_csrk = false;
                self.0
            }
        }

        SentKeys(self)
    }

    /// Set the bonding keys to be accepted by this initiator
    ///
    /// This is used to specify within the pairing request packet what bonding keys can be received
    /// by the initiator security manager.
    ///
    /// # Note
    /// By default all bonding keys are accepted by this initiator. This method does not need to
    /// be called if the default key configuration is desired.
    pub fn accepted_bonding_keys(
        &'a mut self,
    ) -> impl super::EnabledBondingKeys<'a, MasterSecurityManagerBuilder<'a, C>> + 'a {
        self.accept_ltk = false;
        self.accept_csrk = false;

        struct ReceivedKeys<'z, C>(&'z mut MasterSecurityManagerBuilder<'z, C>);

        impl<'z, C> super::EnabledBondingKeys<'z, MasterSecurityManagerBuilder<'z, C>> for ReceivedKeys<'z, C> {
            fn distribute_ltk(&mut self) -> &mut Self {
                self.0.accept_ltk = true;
                self
            }

            fn distribute_csrk(&mut self) -> &mut Self {
                self.0.accept_csrk = true;
                self
            }

            fn finish_keys(self) -> &'z mut MasterSecurityManagerBuilder<'z, C> {
                self.0
            }

            fn default(self) -> &'z mut MasterSecurityManagerBuilder<'z, C> {
                self.0.accept_ltk = true;
                self.0.accept_csrk = true;
                self.0
            }
        }

        ReceivedKeys(self)
    }

    /// Enable the usage of out-of-band (OOB) pairing
    ///
    /// This creates an implementor of `BuildOutOfBand` for creating a `MasterSecurityManager` that
    /// will support OOB data transfer.
    pub fn use_oob<'b: 'a, S, R>(
        self,
        send: S,
        receive: R,
    ) -> impl BuildOutOfBand<
        Builder = MasterSecurityManagerBuilder<'a, C>,
        SecurityManager = MasterSecurityManager<'a, C, S, R>,
    > + 'a
    where
        S: for<'i> OutOfBandSend<'i> + 'b,
        R: OobReceiverType + 'b,
    {
        OutOfBandMethodBuilder::new(self, send, receive)
    }

    /// Create the `MasterSecurityManager`
    ///
    /// # Note
    /// This will create a `MasterSecurityManager` that does not support the out of band pairing
    /// method.
    pub fn build(self) -> MasterSecurityManager<'a, C, (), ()> {
        self.make((), ())
    }

    /// Method for making a `MasterSecurityManager`
    ///
    /// This is here to facilitate the tricks done around OOB type implementations.
    fn make<S, R>(self, oob_send: S, oob_receive: R) -> MasterSecurityManager<'a, C, S, R>
    where
        S: for<'i> OutOfBandSend<'i>,
        R: OobReceiverType,
    {
        let auth_req = alloc::vec![
            encrypt_info::AuthRequirements::Bonding,
            encrypt_info::AuthRequirements::ManInTheMiddleProtection,
            encrypt_info::AuthRequirements::Sc,
        ];

        let initiator_key_distribution = super::get_keys(self.distribute_ltk, self.distribute_csrk);

        let responder_key_distribution = super::get_keys(self.accept_ltk, self.accept_csrk);

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

        MasterSecurityManager {
            connection_channel: self.connection_channel,
            encryption_key_size_min: self.encryption_key_min,
            encryption_key_size_max: self.encryption_key_max,
            oob_send,
            oob_receive,
            pairing_request,
            initiator_address: *self.this_address,
            responder_address: *self.remote_address,
            initiator_address_is_random: self.this_address_is_random,
            responder_address_is_random: self.remote_address_is_random,
            pairing_data: None,
            keys: self.prior_keys,
            link_encrypted: false,
            pairing_expected_cmd: None,
        }
    }
}

impl<'a, C, S, R> BuildOutOfBand for OutOfBandMethodBuilder<MasterSecurityManagerBuilder<'a, C>, S, R>
where
    S: for<'i> OutOfBandSend<'i>,
    R: OobReceiverType,
{
    type Builder = MasterSecurityManagerBuilder<'a, C>;
    type SecurityManager = MasterSecurityManager<'a, C, S, R>;

    fn build(self) -> Self::SecurityManager {
        let oob_send = self.send_method;
        let oob_receive = self.receive_method;
        self.builder.make(oob_send, oob_receive)
    }
}

pub struct MasterSecurityManager<'a, C, S, R> {
    connection_channel: &'a C,
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

impl<C, S, R> MasterSecurityManager<'_, C, S, R> {
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

impl<C, S, R> MasterSecurityManager<'_, C, S, R>
where
    C: ConnectionChannel,
{
    async fn send<Cmd, P>(&self, command: Cmd) -> Result<(), Error>
    where
        Cmd: Into<Command<P>>,
        P: CommandData,
    {
        use crate::l2cap::BasicInfoFrame;

        let acl_data = BasicInfoFrame::new(command.into().into_icd(), super::L2CAP_CHANNEL_ID);

        self.connection_channel
            .send(acl_data)
            .await
            .map_err(|e| Error::DataSend(alloc::format!("{:?}", e)))
    }

    async fn send_err(&mut self, fail_reason: pairing::PairingFailedReason) -> Result<(), Error> {
        self.pairing_data = None;

        self.send(pairing::PairingFailed::new(fail_reason)).await
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
    pub async fn send_irk<Irk>(&mut self, irk: Irk) -> Result<u128, Error>
    where
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

            self.send(encrypt_info::IdentityInformation::new(irk)).await?;

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
    pub async fn send_csrk<Csrk>(&mut self, csrk: Csrk) -> Result<u128, Error>
    where
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

            self.send(encrypt_info::SigningInformation::new(csrk)).await?;

            Ok(csrk)
        } else {
            Err(Error::UnknownIfLinkIsEncrypted)
        }
    }

    /// Send the public address to the Master Device.
    ///
    /// This will send `addr` as a Public Device Address to the Master Device if the internal
    /// encryption flag is set to true by [`set_encrypted`](MasterSecurityManager::set_encrypted).
    pub async fn send_pub_addr(&self, addr: crate::BluetoothDeviceAddress) -> Result<bool, Error> {
        if self.link_encrypted {
            self.send(encrypt_info::IdentityAddressInformation::new_pub(addr))
                .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Send the static random address to the Master Device.
    ///
    /// This will send `addr` as a Static Random Device Address to the Master Device if the internal
    /// encryption flag is set to true by [`set_encrypted`](MasterSecurityManager::set_encrypted).
    ///
    /// # Warning
    /// This function doesn't validate that `address` is a valid static device address. The format
    /// of a static random device address can be found in the Bluetooth Specification (v5.0 | Vol 6,
    /// Part B, section 1.3.2.1).
    pub async fn send_static_rand_addr(&self, addr: crate::BluetoothDeviceAddress) -> Result<bool, Error> {
        if self.link_encrypted {
            self.send(encrypt_info::IdentityAddressInformation::new_static_rand(addr))
                .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl<'a, C, S, R> MasterSecurityManager<'a, C, S, R>
where
    C: ConnectionChannel,
    S: for<'i> OutOfBandSend<'i>,
    R: OobReceiverType,
{
    /// Send the Pairing Request to the slave device
    ///
    /// This sends the pairing request security manage PDU to the slave which will initiate the
    /// pairing process
    async fn send_pairing_request(&mut self) -> Result<(), Error> {
        self.pairing_data = None;

        self.send(self.pairing_request.clone()).await
    }

    async fn process_pairing_response(&mut self, payload: &[u8]) -> Result<(), Error> {
        let response = pairing::PairingResponse::try_from_icd(payload)?;

        if response.get_max_encryption_size() < self.encryption_key_size_min {
            self.send_err(pairing::PairingFailedReason::EncryptionKeySize).await?;

            Err(Error::PairingFailed(pairing::PairingFailedReason::EncryptionKeySize))
        } else {
            let pairing_method = PairingMethod::determine_method_secure_connection(
                self.pairing_request.get_oob_data_flag(),
                response.get_oob_data_flag(),
                self.pairing_request.get_io_capability(),
                response.get_io_capability(),
                false,
            );

            let initiator_io_cap = self.pairing_request.get_io_cap();
            let responder_io_cap = response.get_io_cap();

            let (private_key, public_key) = toolbox::ecc_gen().expect("Failed to fill bytes for generated random");

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
    async fn send_pairing_pub_key(&mut self) -> Result<(), Error> {
        match self.pairing_data {
            Some(PairingData { ref public_key, .. }) => {
                let raw_pub_key = {
                    let key_bytes = public_key.clone().into_icd();

                    let mut raw_key = [0u8; 64];

                    raw_key.copy_from_slice(&key_bytes);

                    raw_key
                };

                self.send(pairing::PairingPubKey::new(raw_pub_key)).await?;

                Ok(())
            }
            _ => Err(Error::IncorrectCommand(CommandType::PairingPublicKey)),
        }
    }

    async fn process_responder_pub_key(&mut self, payload: &[u8]) -> Result<(), Error> {
        let pub_key = pairing::PairingPubKey::try_from_icd(payload);

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
                let remote_pub_key = match toolbox::PubKey::try_from_icd(&peer_pub_key_pdu.get_key()) {
                    Ok(k) => k,
                    Err(e) => {
                        self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                        return Err(e);
                    }
                };

                let this_pri_key = private_key.take().unwrap();

                *secret_key = toolbox::ecdh(this_pri_key, &remote_pub_key).into();

                *peer_public_key = remote_pub_key.into();

                Ok(())
            }
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    /// Wait for responder check
    async fn process_responder_commitment(&mut self, payload: &[u8]) -> Result<(), Error> {
        match (&pairing::PairingConfirm::try_from_icd(payload), &mut self.pairing_data) {
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

                log::trace!("Responder Commitment: {:?}", responder_confirm.get_value());

                Ok(())
            }
            (Err(_), _) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                Err(Error::Value)
            }
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    /// Send the Nonce
    ///
    /// # Panics
    /// This will panic if the pairing response has not been received yet
    async fn send_pairing_random(&mut self) -> Result<(), Error> {
        match self.pairing_data {
            Some(PairingData { nonce, .. }) => {
                log::trace!("Initiator nonce: {:?}", nonce);

                self.send(pairing::PairingRandom::new(nonce)).await?;

                Ok(())
            }
            _ => return Err(Error::UnsupportedFeature),
        }
    }

    async fn process_responder_random(&mut self, payload: &[u8]) -> Result<(), Error> {
        let responder_nonce = match pairing::PairingRandom::try_from_icd(payload) {
            Ok(pairing_random) => pairing_random.get_value(),
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(Error::Value);
            }
        };

        log::trace!("Responder Nonce: {:?}", responder_nonce);

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

                    self.send_err(reason).await?;

                    Err(Error::PairingFailed(reason))
                }
            }
            Some(PairingData {
                pairing_method:
                    PairingMethod::Oob(OobDirection::OnlyResponderSendsOob) | PairingMethod::Oob(OobDirection::BothSendOob),
                external_oob_confirm_valid,
                ..
            }) if OobReceiverTypeVariant::External == R::receiver_type() && !*external_oob_confirm_valid => {
                self.send_err(pairing::PairingFailedReason::OOBNotAvailable).await?;

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

                self.send_err(reason).await?;

                Err(Error::PairingFailed(reason))
            }
        }
    }

    async fn send_initiator_dh_key_check(&mut self) -> Result<(), Error> {
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

                self.send(pairing::PairingDHKeyCheck::new(ea)).await?;

                ltk
            }
            _ => return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason)),
        };

        self.keys = Some(super::Keys {
            ltk: ltk.into(),
            csrk: None,
            irk: None,
            peer_csrk: None,
            peer_irk: None,
            peer_addr: None,
        });

        Ok(())
    }

    async fn process_responder_dh_key_check(&mut self, payload: &[u8]) -> Result<(), Error> {
        let eb = match pairing::PairingDHKeyCheck::try_from_icd(payload) {
            Ok(responder_confirm) => responder_confirm,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

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
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason));
            }
        };

        if check {
            Ok(())
        } else {
            self.send_err(pairing::PairingFailedReason::DHKeyCheckFailed).await?;

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
        use crate::gap::assigned::{
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

            Sequence::new(data)
                .try_add(&address)
                .unwrap()
                .try_add(&role)
                .unwrap()
                .try_add(&random)
                .unwrap()
                .try_add(&confirm)
                .unwrap();

            self.oob_send.send(data).await;
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
        let data = self.oob_receive.receive().await;

        self.process_received_oob(data)
    }

    /// Process the received OOB
    ///
    /// This will check the OOB to determine the validity of the raw data and the confirm within the
    /// raw data. True is returned if everything within `raw` is validated.
    fn process_received_oob(&self, raw: Vec<u8>) -> bool {
        use crate::gap::assigned::{sc_confirm_value, sc_random_value, AssignedTypes, EirOrAdIterator, TryFromStruct};

        let mut rb = None;
        let mut cb = None;

        for ad in EirOrAdIterator::new(&raw).silent() {
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
    async fn by_oob_receiver_type(&mut self) -> Result<bool, Error> {
        match R::receiver_type() {
            OobReceiverTypeVariant::Internal => {
                let confirm_result = self.receive_oob().await;

                self.oob_confirm_result(confirm_result).await.map(|_| true)
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
    async fn oob_confirm_result(&mut self, confirm_result: bool) -> Result<(), Error> {
        if confirm_result {
            match self.pairing_data {
                Some(PairingData {
                    nonce,
                    ref mut external_oob_confirm_valid,
                    ..
                }) => {
                    *external_oob_confirm_valid = true;

                    self.send(pairing::PairingRandom::new(nonce)).await
                }
                None => unreachable!("Pairing Data cannot be None"),
            }
        } else {
            self.send_err(pairing::PairingFailedReason::ConfirmValueFailed).await
        }
    }

    /// Deal with the oob confirm values
    ///
    /// This will return true if once the oob confirm value step is completed. False is only
    /// returned when OOB data is to be externally set by the user.
    async fn oob_confirm(&mut self, oob_direction: OobDirection) -> Result<bool, self::Error> {
        match oob_direction {
            OobDirection::OnlyInitiatorSendsOob => {
                self.send_oob().await;
                Ok(true)
            }
            OobDirection::OnlyResponderSendsOob => self.by_oob_receiver_type().await,
            OobDirection::BothSendOob => {
                self.send_oob().await;

                self.by_oob_receiver_type().await
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
    pub async fn pair(
        &'a mut self,
    ) -> (
        Result<&'a mut super::Keys, super::Error>,
        alloc::vec::Vec<crate::l2cap::BasicInfoFrame>,
    ) {
        let mut other_data = alloc::vec::Vec::new();

        if let Err(e) = self.start_pairing().await {
            return (Err(e), other_data);
        }

        'outer: loop {
            let data = self.connection_channel.future_receiver().await;

            match data {
                Err(e) => return (Err(super::Error::ACLData(e)), other_data),
                Ok(acl_data_vec) => {
                    for (index, acl_data) in acl_data_vec.iter().enumerate() {
                        match acl_data.get_channel_id() {
                            super::L2CAP_CHANNEL_ID => match self.continue_pairing(acl_data).await {
                                Err(e) => return (Err(e), other_data),
                                Ok(true) => {
                                    other_data.extend_from_slice(&acl_data_vec[(index + 1)..]);

                                    break 'outer;
                                }
                                Ok(false) => (),
                            },
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
    pub async fn start_pairing(&mut self) -> Result<(), Error> {
        self.pairing_expected_cmd = super::CommandType::PairingResponse.into();

        self.send_pairing_request().await
    }

    /// Continue Pairing
    ///
    /// This is used to continue pairing until pairing is either complete or fails. It must be
    /// called for every received Security Manager ACL data. True is returned once pairing is
    /// completed.
    pub async fn continue_pairing(&mut self, acl_data: &crate::l2cap::BasicInfoFrame) -> Result<bool, super::Error> {
        check_channel_id_and!(acl_data, async {
            let (d_type, payload) = acl_data.get_payload().split_at(1);

            match CommandType::try_from_val(d_type[0]) {
                Ok(CommandType::PairingFailed) => {
                    self.pairing_expected_cmd = super::CommandType::PairingFailed.into();

                    Err(Error::PairingFailed(
                        pairing::PairingFailed::try_from_icd(payload)?.get_reason(),
                    ))
                }
                Ok(cmd) if Some(cmd) == self.pairing_expected_cmd => self.next_step(payload).await,
                Ok(cmd) => {
                    self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                    Err(Error::IncorrectCommand(cmd))
                }
                Err(e) => {
                    self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                    Err(e)
                }
            }
        })
    }

    async fn next_step(&mut self, payload: &[u8]) -> Result<bool, Error> {
        match self.pairing_expected_cmd {
            Some(super::CommandType::PairingResponse) => match self.process_pairing_response(payload).await {
                Ok(_) => {
                    self.pairing_expected_cmd = super::CommandType::PairingPublicKey.into();

                    match self.send_pairing_pub_key().await {
                        Ok(_) => Ok(false),
                        Err(e) => Err(e),
                    }
                }
                Err(e) => self.step_err(e),
            },
            Some(super::CommandType::PairingPublicKey) => match self.process_responder_pub_key(payload).await {
                Ok(_) => match self.pairing_data.as_ref().unwrap().pairing_method {
                    PairingMethod::JustWorks | PairingMethod::NumbComp => {
                        self.pairing_expected_cmd = super::CommandType::PairingConfirm.into();

                        Ok(false)
                    }
                    PairingMethod::Oob(direction) => {
                        if self.oob_confirm(direction).await? {
                            self.pairing_expected_cmd = super::CommandType::PairingRandom.into();
                        } else {
                            self.pairing_expected_cmd = None;
                        }

                        Ok(true)
                    }
                    PairingMethod::PassKeyEntry => unimplemented!(),
                },
                Err(e) => self.step_err(e),
            },
            Some(super::CommandType::PairingConfirm) => match self.process_responder_commitment(payload).await {
                Ok(_) => {
                    self.pairing_expected_cmd = super::CommandType::PairingRandom.into();

                    match self.send_pairing_random().await {
                        Ok(_) => Ok(false),
                        Err(e) => Err(e),
                    }
                }
                Err(e) => self.step_err(e),
            },
            Some(super::CommandType::PairingRandom) => match self.process_responder_random(payload).await {
                Ok(_) => {
                    self.pairing_expected_cmd = super::CommandType::PairingDHKeyCheck.into();

                    match self.send_initiator_dh_key_check().await {
                        Ok(_) => Ok(false),
                        Err(e) => Err(e),
                    }
                }
                Err(e) => self.step_err(e),
            },
            Some(super::CommandType::PairingDHKeyCheck) => {
                self.pairing_expected_cmd = None;

                self.process_responder_dh_key_check(payload).await.map(|_| true)
            }
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

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
    pub async fn process_bonding(
        &mut self,
        acl_data: &crate::l2cap::BasicInfoFrame,
    ) -> Result<Option<&super::Keys>, Error> {
        macro_rules! bonding_key {
            ($this:expr, $payload:expr, $key:ident, $key_type:ident, $get_key_method:ident) => {
                match (
                    self.link_encrypted,
                    $this.keys.is_some(),
                    encrypt_info::$key_type::try_from_icd($payload),
                ) {
                    (true, true, Ok(packet)) => {
                        let keys = $this.keys.as_mut().unwrap();

                        keys.$key = Some(packet.$get_key_method());

                        Ok(Some(keys))
                    }
                    (false, _, _) => {
                        self.send_err(pairing::PairingFailedReason::UnspecifiedReason)
                            .await?;

                        Err(Error::UnknownIfLinkIsEncrypted)
                    }
                    (_, false, _) => {
                        self.send_err(pairing::PairingFailedReason::UnspecifiedReason)
                            .await?;

                        Err(Error::OperationRequiresPairing)
                    }
                    (_, _, Err(e)) => {
                        self.send_err(pairing::PairingFailedReason::UnspecifiedReason)
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
                    bonding_key!(self, payload, peer_addr, IdentityAddressInformation, as_blu_addr)
                }
                CommandType::SecurityRequest => Ok(None),
                c => Err(Error::IncorrectCommand(c)),
            }
        })
    }
}

impl<'a, C, S> MasterSecurityManager<'a, C, S, ExternalOobReceiver>
where
    C: ConnectionChannel,
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
    /// [`expecting_oob_data`](MasterSecurityManager::expecting_oob_data) does make this easier. If
    /// any other pairing process is being used, or this is called at the incorrect time, pairing is
    /// canceled and must be restarted by the responder. The responder is also sent the error
    /// `OOBNotAvailable`.
    ///
    /// This method must be called after the responder's pairing public key message is *processed*
    /// but before the pairing random message is *processed*. Note *processed*, it is ok for this
    /// device to receive the pairing random message, but do not call the method
    /// [`process_command`](MasterSecurityManager::continue_pairing) until after this method is
    /// called. The easiest way to know when this occurs is to call the method `expecting_oob_data`
    /// after processing every security manager message, although this  procedure can be stopped
    /// after this method is called.
    ///
    /// # Note
    /// The error `ConfirmValueFailed` can also be returned, but that means that the method was
    /// called at the correct time, just that pairing was going to fail because of the confirm value
    /// check failing.
    pub async fn received_oob_data(&mut self, data: Vec<u8>) -> Result<(), Error> {
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

                self.oob_confirm_result(self.process_received_oob(data)).await
            }
            _ => {
                self.send_err(pairing::PairingFailedReason::OOBNotAvailable).await?;

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
