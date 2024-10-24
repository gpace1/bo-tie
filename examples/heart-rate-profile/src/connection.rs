//! Connection Task Implementation
//!
//! When a connection is formed, it is processed within its own task. This module contains the
//! [`Connection`] type for setting up and running an async task to manage a single connection.
use crate::security::{Security, SecurityStage};
use crate::server::Server;
use crate::{ConnectionToMain, ConnectionToMainMessage, MainToConnection};
use bo_tie::hci::{ConnectionChannelEnds, ConnectionHandle, LeLink};
use bo_tie::host::l2cap::pdu::BasicFrame;
use bo_tie::host::l2cap::{BasicFrameChannel, LeULogicalLink, LeUNext, LogicalLink, PhysicalLink};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[derive(Copy, Clone)]
pub enum ConnectedStatus {
    New(bo_tie::BluetoothDeviceAddress),
    Bonded(bo_tie::host::sm::IdentityAddress),
}

impl ConnectedStatus {
    pub fn get_address(&self) -> bo_tie::BluetoothDeviceAddress {
        match self {
            ConnectedStatus::New(address) => *address,
            ConnectedStatus::Bonded(identity) => identity.get_address(),
        }
    }
}

pub(crate) struct Connection<P: PhysicalLink> {
    le_l2cap: LeULogicalLink<P, Vec<u8>, Vec<u8>>,
    inner: ConnectionInner,
}

impl<C: ConnectionChannelEnds> Connection<LeLink<C>> {
    const NOTIFICATION_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

    pub fn new_le(
        le_l2cap: LeLink<C>,
        security: Security,
        server: Server,
        to: UnboundedSender<ConnectionToMain>,
    ) -> Self {
        let notification_interval = tokio::time::interval(Self::NOTIFICATION_PERIOD);

        let connection_handle = le_l2cap.get_handle();

        let le_l2cap = LeULogicalLink::builder(le_l2cap)
            .enable_security_manager_channel()
            .enable_attribute_channel()
            .use_vec_sdu_buffer()
            .use_vec_buffer()
            .build();

        let inner = ConnectionInner {
            connection_handle,
            security,
            server,
            to,
            notification_interval,
        };

        Self { le_l2cap, inner }
    }

    pub(crate) async fn run_le(mut self, mut from: UnboundedReceiver<MainToConnection>) {
        loop {
            tokio::select! {
                next = self.le_l2cap.next() => match &mut next.unwrap() {
                    LeUNext::AttributeChannel {pdu, channel} => {
                        self.inner
                            .process_att(channel, pdu)
                            .await
                    }
                    LeUNext::SecurityManagerChannel {pdu, channel} => {
                        self.inner
                            .process_sm(channel, pdu)
                            .await
                    }
                    _ => unreachable!()
                },

                opt_msg = from.recv() => match opt_msg {
                    Some(message) => {
                        let channel = &mut self.le_l2cap.get_security_manager_channel().unwrap();

                        self.inner.process_msg(channel, message).await
                    },
                    None => break, // another way to know the connection closed
                },

                _ = self.inner.notification_interval.tick() => {
                    let channel = &mut self.le_l2cap.get_att_channel().unwrap();

                    self.inner.send_hrd_notification(channel).await
                }
            }
        }

        if let Some(mut bonding_info_guard) = self.inner.security.get_bonding_info().await {
            bonding_info_guard.set_notification_enabled(self.inner.server.is_notifying())
        }
    }
}

struct ConnectionInner {
    connection_handle: ConnectionHandle,
    security: Security,
    server: Server,
    to: UnboundedSender<ConnectionToMain>,
    notification_interval: tokio::time::Interval,
}

impl ConnectionInner {
    async fn process_att<L>(&mut self, att_channel: &mut BasicFrameChannel<L>, packet: &BasicFrame<Vec<u8>>)
    where
        L: LogicalLink,
    {
        self.server.process(att_channel, packet).await
    }

    async fn process_sm<L>(&mut self, sm_channel: &mut BasicFrameChannel<L>, packet: &mut BasicFrame<Vec<u8>>)
    where
        L: LogicalLink,
    {
        if let Some(security_stage) = self.security.process(sm_channel, packet).await {
            self.send_security_stage(security_stage)
        }
    }

    fn send_security_stage(&self, security_stage: SecurityStage) {
        let kind = ConnectionToMainMessage::Security(security_stage);

        let message = ConnectionToMain {
            handle: self.connection_handle,
            kind,
        };

        self.to.send(message).unwrap();
    }

    async fn process_msg<L>(&mut self, sm_channel: &mut BasicFrameChannel<L>, msg: MainToConnection)
    where
        L: LogicalLink,
    {
        match msg {
            MainToConnection::Encryption(is_encrypted) => self.on_encryption(sm_channel, is_encrypted).await,
            MainToConnection::LtkRequest => self.on_ltk_request(),
            MainToConnection::PairingAccepted => self.security.allow_pairing(sm_channel).await,
            MainToConnection::PairingRejected => self.security.reject_pairing(sm_channel).await,
            MainToConnection::AuthenticationInput(ai) => {
                if let Some(security_stage) = self.security.process_authentication(sm_channel, ai).await {
                    self.send_security_stage(security_stage)
                }
            }
        }
    }

    async fn on_encryption<L>(&mut self, sm_channel: &mut BasicFrameChannel<L>, is_encrypted: bool)
    where
        L: LogicalLink,
    {
        if is_encrypted {
            self.security.on_encryption(sm_channel).await;

            self.server.on_encryption();
        } else {
            self.security.on_unsecured();

            self.server.on_unencrypted();
        }
    }

    fn on_ltk_request(&mut self) {
        let handle = self.connection_handle;

        let opt_ltk = self.security.get_ltk();

        let kind = ConnectionToMainMessage::LongTermKey(opt_ltk);

        let message = ConnectionToMain { handle, kind };

        self.to.send(message).unwrap();
    }

    async fn send_hrd_notification<L>(&mut self, att_channel: &mut BasicFrameChannel<L>)
    where
        L: LogicalLink,
    {
        self.server.send_hrd_notification(att_channel).await
    }
}
