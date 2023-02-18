//! Connection Task Implementation
//!
//! When a connection is formed, it is processed within its own task. This module contains the
//! [`Connection`] type for setting up and running an async task to manage a single connection.
use crate::security::{Security, SecurityStage};
use crate::server::Server;
use crate::{ConnectionToMain, ConnectionToMainMessage, MainToConnection};
use bo_tie::hci::channel::SendAndSyncSafeConnectionChannelEnds;
use bo_tie::hci::{ConnectionChannelEnds, LeL2cap};
use bo_tie::host::l2cap::{BasicInfoFrame, ChannelIdentifier, ConnectionChannelExt, LeUserChannelIdentifier};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub(crate) struct Connection<C: ConnectionChannelEnds> {
    le_l2cap: LeL2cap<C>,
    security: Security,
    server: Server,
    to: UnboundedSender<ConnectionToMain>,
}

impl<C: SendAndSyncSafeConnectionChannelEnds> Connection<C> {
    pub fn new(
        le_l2cap: LeL2cap<C>,
        security: Security,
        server: Server,
        to: UnboundedSender<ConnectionToMain>,
    ) -> Self {
        Self {
            le_l2cap,
            security,
            server,
            to,
        }
    }

    pub(crate) async fn run(mut self, mut from: UnboundedReceiver<MainToConnection>) {
        let mut frames = Frames::new();

        loop {
            tokio::select! {
                frame = frames.receive_frame(&mut self.le_l2cap) => match frame {
                    Some(mut frame) => self.process_frame(&mut frame).await,
                    None => break, // connection closed
                },

                msg = from.recv() => self.process_msg(msg.unwrap()).await,
            }
        }
    }

    fn send_security_stage(&self, security_stage: SecurityStage) {
        let kind = ConnectionToMainMessage::Security(security_stage);

        let message = ConnectionToMain {
            handle: self.le_l2cap.get_handle(),
            kind,
        };

        self.to.send(message).unwrap();
    }

    async fn process_frame(&mut self, frame: &mut BasicInfoFrame<Vec<u8>>) {
        match frame.get_channel_id() {
            ChannelIdentifier::Le(LeUserChannelIdentifier::AttributeProtocol) => {
                self.server.process(&mut self.le_l2cap, frame).await
            }
            ChannelIdentifier::Le(LeUserChannelIdentifier::SecurityManagerProtocol) => {
                if let Some(security_stage) = self.security.process(&mut self.le_l2cap, frame).await {
                    self.send_security_stage(security_stage)
                }
            }
            id => eprintln!("received unexpected basic frame with channel identifier {}", id),
        }
    }

    async fn process_msg(&mut self, msg: MainToConnection) {
        match msg {
            MainToConnection::Encryption(is_encrypted) => self.on_encryption(is_encrypted).await,
            MainToConnection::LtkRequest => self.on_ltk_request(),
            MainToConnection::PairingAccepted => self.security.allow_pairing(&self.le_l2cap).await,
            MainToConnection::PairingRejected => self.security.reject_pairing(&self.le_l2cap).await,
            MainToConnection::AuthenticationInput(ai) => {
                if let Some(security_stage) = self.security.process_authentication(&self.le_l2cap, ai).await {
                    self.send_security_stage(security_stage)
                }
            }
        }
    }

    async fn on_encryption(&mut self, is_encrypted: bool) {
        if is_encrypted {
            self.security.on_encryption(&mut self.le_l2cap).await;

            self.server.on_encryption();
        } else {
            self.security.on_unsecured();

            self.server.on_unencrypted();
        }
    }

    fn on_ltk_request(&mut self) {
        let handle = self.le_l2cap.get_handle();
        let opt_ltk = self.security.get_ltk();

        let kind = ConnectionToMainMessage::LongTermKey(opt_ltk);

        let message = ConnectionToMain { handle, kind };

        self.to.send(message).unwrap();
    }
}

struct Frames {
    frames: std::vec::IntoIter<BasicInfoFrame<Vec<u8>>>,
}

impl Frames {
    fn new() -> Self {
        let frames = Vec::new().into_iter();

        Self { frames }
    }

    async fn receive_frame<C: ConnectionChannelEnds>(
        &mut self,
        le_l2cap: &mut LeL2cap<C>,
    ) -> Option<BasicInfoFrame<Vec<u8>>> {
        loop {
            if let Some(frame) = self.frames.next() {
                return Some(frame);
            } else {
                self.frames = le_l2cap.receive_b_frame().await.map(|vec| vec.into_iter()).ok()?
            }
        }
    }
}
