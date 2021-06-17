use super::{
    encrypt_info, pairing, toolbox, Command, CommandData, CommandType, Error, KeyGenerationMethod, PairingData,
};
use crate::l2cap::ConnectionChannel;

pub struct MasterSecurityManagerBuilder<'a, C> {
    connection_channel: &'a C,
    io_capabilities: pairing::IOCapability,
    oob_data: Option<u128>,
    encryption_key_min: usize,
    encryption_key_max: usize,
    remote_address: &'a crate::BluetoothDeviceAddress,
    this_address: &'a crate::BluetoothDeviceAddress,
    remote_address_is_random: bool,
    this_address_is_random: bool,
}

impl<'a, C> MasterSecurityManagerBuilder<'a, C> {
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
            oob_data: None,
            encryption_key_min: super::ENCRYPTION_KEY_MAX_SIZE,
            encryption_key_max: super::ENCRYPTION_KEY_MAX_SIZE,
            remote_address: connected_device_address,
            this_address: this_device_address,
            remote_address_is_random: is_connected_devices_address_random,
            this_address_is_random: is_this_device_address_random,
        }
    }

    pub fn build(self) -> MasterSecurityManager<'a, C> {
        let auth_req = alloc::vec![
            encrypt_info::AuthRequirements::Bonding,
            encrypt_info::AuthRequirements::ManInTheMiddleProtection,
            encrypt_info::AuthRequirements::Sc,
        ];

        let key_dist = alloc::vec![pairing::KeyDistributions::IdKey,];

        let pairing_request = pairing::PairingRequest::new(
            self.io_capabilities,
            if self.oob_data.is_some() {
                pairing::OOBDataFlag::AuthenticationDataFromRemoteDevicePresent
            } else {
                pairing::OOBDataFlag::AuthenticationDataNotPresent
            },
            auth_req,
            self.encryption_key_max,
            key_dist.clone(),
            key_dist,
        );

        MasterSecurityManager {
            connection_channel: self.connection_channel,
            // oob_data: self.oob_data,
            // passkey: None,
            encryption_key_size_min: self.encryption_key_min,
            encryption_key_size_max: self.encryption_key_max,
            pairing_request,
            initiator_address: self.this_address,
            responder_address: self.remote_address,
            initiator_address_is_random: self.this_address_is_random,
            responder_address_is_random: self.remote_address_is_random,
            pairing_data: None,
            link_encrypted: false,
            pairing_expected_cmd: None,
        }
    }
}

pub struct MasterSecurityManager<'a, C> {
    connection_channel: &'a C,
    // oob_data: Option<u128>,
    pairing_request: pairing::PairingRequest,
    encryption_key_size_min: usize,
    encryption_key_size_max: usize,
    initiator_address: &'a crate::BluetoothDeviceAddress,
    responder_address: &'a crate::BluetoothDeviceAddress,
    initiator_address_is_random: bool,
    responder_address_is_random: bool,
    pairing_data: Option<PairingData>,
    link_encrypted: bool,
    pairing_expected_cmd: Option<super::CommandType>,
}

impl<C> MasterSecurityManager<'_, C>
where
    C: ConnectionChannel,
{
    async fn send<Cmd, P>(&self, command: Cmd) -> Result<(), Error>
    where
        Cmd: Into<Command<P>>,
        P: CommandData,
    {
        use crate::l2cap::AclData;

        let acl_data = AclData::new(command.into().into_icd(), super::L2CAP_CHANNEL_ID);

        self.connection_channel
            .send(acl_data)
            .await
            .map_err(|e| Error::DataSend(alloc::format!("{:?}", e)))
    }

    async fn send_err(&mut self, fail_reason: pairing::PairingFailedReason) -> Result<(), Error> {
        self.pairing_data = None;

        self.send(pairing::PairingFailed::new(fail_reason)).await
    }

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
            let pairing_method = KeyGenerationMethod::determine_method_secure_connection(
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
                key_gen_method: pairing_method,
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
                db_keys: None,
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
                    key_gen_method: KeyGenerationMethod::JustWorks,
                    responder_pairing_confirm,
                    ..
                }),
            )
            | (
                Ok(responder_confirm),
                Some(PairingData {
                    key_gen_method: KeyGenerationMethod::NumbComp,
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
            Some(PairingData {
                key_gen_method: KeyGenerationMethod::JustWorks,
                nonce,
                ..
            })
            | Some(PairingData {
                key_gen_method: KeyGenerationMethod::NumbComp,
                nonce,
                ..
            }) => {
                log::trace!("Initiator nonce: {:?}", nonce);

                self.send(pairing::PairingRandom::new(nonce)).await?;

                Ok(())
            }
            _ => return Err(Error::UnsupportedFeature),
        }
    }

    async fn process_responder_random(&mut self, payload: &[u8]) -> Result<(), Error> {
        use super::GetXOfP256Key;

        let responder_random = pairing::PairingRandom::try_from_icd(payload);

        let check_result = match (&responder_random, &mut self.pairing_data) {
            (
                Ok(random_pdu),
                Some(PairingData {
                    key_gen_method: KeyGenerationMethod::JustWorks,
                    peer_nonce,
                    peer_public_key: Some(peer_public_key),
                    public_key,
                    responder_pairing_confirm: Some(responder_confirm),
                    ..
                }),
            )
            | (
                Ok(random_pdu),
                Some(PairingData {
                    key_gen_method: KeyGenerationMethod::NumbComp,
                    peer_nonce,
                    peer_public_key: Some(peer_public_key),
                    public_key,
                    responder_pairing_confirm: Some(responder_confirm),
                    ..
                }),
            ) => {
                let responder_nonce = random_pdu.get_value();

                log::trace!("Responder Nonce: {:?}", random_pdu.get_value());

                let initiator_confirm = toolbox::f4(
                    GetXOfP256Key::x(peer_public_key),
                    GetXOfP256Key::x(public_key),
                    responder_nonce,
                    0,
                );

                *peer_nonce = responder_nonce.into();

                *responder_confirm == initiator_confirm
            }
            (Err(_), _) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(Error::Value);
            }
            _ => {
                let reason = pairing::PairingFailedReason::UnspecifiedReason;

                self.send_err(reason).await?;

                return Err(Error::PairingFailed(reason));
            }
        };

        if check_result {
            Ok(())
        } else {
            let reason = pairing::PairingFailedReason::ConfirmValueFailed;

            self.send_err(reason).await?;

            Err(Error::PairingFailed(reason))
        }
    }

    async fn send_initiator_dh_key_check(&mut self) -> Result<(), Error> {
        let ltk = match self.pairing_data {
            Some(PairingData {
                key_gen_method: KeyGenerationMethod::JustWorks,
                secret_key: Some(ref dh_key),
                ref nonce,
                peer_nonce: Some(ref peer_nonce),
                ref initiator_io_cap,
                ref mut mac_key,
                ..
            })
            | Some(PairingData {
                key_gen_method: KeyGenerationMethod::NumbComp,
                secret_key: Some(ref dh_key),
                ref nonce,
                peer_nonce: Some(ref peer_nonce),
                ref initiator_io_cap,
                ref mut mac_key,
                ..
            }) => {
                let a_addr = toolbox::PairingAddress::new(self.initiator_address, self.initiator_address_is_random);

                let b_addr = toolbox::PairingAddress::new(self.responder_address, self.responder_address_is_random);

                let (gen_mac_key, ltk) = toolbox::f5(*dh_key, *nonce, *peer_nonce, a_addr.clone(), b_addr.clone());

                let ea = toolbox::f6(gen_mac_key, *nonce, *peer_nonce, 0, *initiator_io_cap, a_addr, b_addr);

                *mac_key = gen_mac_key.into();

                self.send(pairing::PairingDHKeyCheck::new(ea)).await?;

                ltk
            }
            _ => return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason)),
        };

        self.pairing_data.as_mut().unwrap().db_keys = Some(super::KeyDBEntry {
            ltk: ltk.into(),
            csrk: (toolbox::rand_u128(), 0).into(),
            irk: toolbox::rand_u128().into(),
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
                key_gen_method: KeyGenerationMethod::JustWorks,
                ref nonce,
                peer_nonce: Some(ref peer_nonce),
                ref responder_io_cap,
                mac_key: Some(ref mac_key),
                ..
            })
            | Some(PairingData {
                key_gen_method: KeyGenerationMethod::NumbComp,
                ref nonce,
                peer_nonce: Some(ref peer_nonce),
                ref responder_io_cap,
                mac_key: Some(ref mac_key),
                ..
            }) => {
                let a_addr = toolbox::PairingAddress::new(self.initiator_address, self.initiator_address_is_random);

                let b_addr = toolbox::PairingAddress::new(self.responder_address, self.responder_address_is_random);

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

    /// Indicate if the connection is encrypted
    ///
    /// This is used to indicate to the `MasterSecurityManager` that it is safe to send a Key to the
    /// peer device. This is a deliberate extra step to ensure that the functions `send_irk`,
    /// `send_csrk`, `send_pub_addr`, and `send_rand_addr` are only used when the link is encrypted.
    pub fn set_encrypted(&mut self, is_encrypted: bool) {
        self.link_encrypted = is_encrypted
    }

    /// Send the Identity Resolving Key to the Master Device
    ///
    /// This function will send the IRK to the master device if the internal encryption flag is set
    /// to true by [`set_encrypted`](MasterSecurityManager::set_encrypted)
    /// and an IRK has been generated. An IRK is generated once the return of
    /// [`start_pairing`](MasterSecurityManager::start_pairing)
    /// returns a reference to a [`KeyDBEntry`](super::KeyDBEntry). However, since the return is a
    /// mutable, you can replace the IRK with `None` which would also cause this function to
    /// return false. If the function returns false then the IRK isn't sent to the Master Device.
    pub async fn send_irk(&self) -> Result<bool, Error> {
        if self.link_encrypted {
            if let Some(irk) = self
                .pairing_data
                .as_ref()
                .and_then(|pd| pd.db_keys.as_ref())
                .and_then(|db_key| db_key.irk.clone())
            {
                self.send(encrypt_info::IdentityInformation::new(irk)).await?;

                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// Send the Connection Signature Resolving Key to the Master Device
    ///
    /// This function will send the CSRK to the master device if the internal encryption flag is set
    /// to true by [`set_encrypted`](MasterSecurityManager::set_encrypted)
    /// and an CSRK has been generated. An IRK is generated once the return of
    /// [`start_pairing`](MasterSecurityManager::start_pairing)
    /// returns a reference to a [`KeyDBEntry`](super::KeyDBEntry). However, since the return is a
    /// mutable, you can replace the IRK with `None` which would also cause this function to
    /// return false. If the function returns false then the IRK isn't sent to the Master Device.
    pub async fn send_csrk(&self) -> Result<bool, Error> {
        if self.link_encrypted {
            if let Some(csrk) = self
                .pairing_data
                .as_ref()
                .and_then(|pd| pd.db_keys.as_ref())
                .and_then(|db_key| db_key.csrk.clone())
            {
                self.send(encrypt_info::SigningInformation::new(csrk.0)).await?;

                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
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
            self.send(encrypt_info::IdentityAddressInformation::new_pub(addr))
                .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get the pairing keys
    ///
    /// Pairing must be completed before these keys are generated
    pub fn get_keys(&mut self) -> Option<&mut super::KeyDBEntry> {
        self.pairing_data.as_mut().and_then(|pd| pd.db_keys.as_mut())
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
    /// To continue pairing, the slaves next received security manager PDU needs to be received
    /// and then processed through `continue_pairing`. Pairing is completed when this function
    /// returns true.
    pub async fn continue_pairing(&mut self, l2cap_data: crate::l2cap::AclData) -> Result<bool, super::Error>
    where
        C: ConnectionChannel,
    {
        if l2cap_data.get_channel_id() == super::L2CAP_CHANNEL_ID {
            self.proc_data(l2cap_data.get_payload()).await
        } else {
            Err(Error::IncorrectL2capChannelId)
        }
    }

    async fn proc_data(&mut self, received_data: &[u8]) -> Result<bool, super::Error>
    where
        C: ConnectionChannel,
    {
        let (d_type, payload) = received_data.split_at(1);

        match CommandType::try_from_val(d_type[0]) {
            Ok(cmd) if cmd == CommandType::PairingFailed => {
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
    }

    async fn next_step(&mut self, payload: &[u8]) -> Result<bool, Error>
    where
        C: ConnectionChannel,
    {
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
                Ok(_) => {
                    self.pairing_expected_cmd = super::CommandType::PairingConfirm.into();

                    Ok(false)
                }
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
            _ => Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason)),
        }
    }

    fn step_err(&mut self, e: Error) -> Result<bool, Error> {
        self.pairing_expected_cmd = None;

        Err(e)
    }
}
