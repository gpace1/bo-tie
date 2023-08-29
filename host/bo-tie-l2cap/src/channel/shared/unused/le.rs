//! Processing of Unused LE channels

use crate::channel::id::{ChannelIdentifier, LeCid};
use crate::channel::shared::unused::{ReceiveDataProcessor, UnusedChannelResponse};
use crate::pdu::{BasicFrame, L2capFragment};
use crate::{LeULogicalLink, PhysicalLink};
use core::num::NonZeroU8;

impl<P: PhysicalLink> UnusedChannelResponse for LeULogicalLink<P> {
    type ReceiveData = UnusedFixedChannelPduData;
    type Response = BasicFrame<UnusedPduResp>;

    fn try_generate_response(request_data: UnusedFixedChannelPduData) -> Option<Self::Response> {
        match request_data.channel_id {
            ChannelIdentifier::Le(LeCid::AttributeProtocol) => {
                let UnusedFixedChannelPduChannelData::Attribute(attribute_data) = request_data.channel_data else {
                    unreachable!()
                };

                let (request, handle) = attribute_data.into_inner()?;

                let rsp = UnusedPduResp::Att(request, handle);

                Some(BasicFrame::new(rsp, request_data.channel_id))
            }
            ChannelIdentifier::Le(LeCid::LeSignalingChannel) => {
                let UnusedFixedChannelPduChannelData::Signalling(signal_data) = request_data.channel_data else {
                    unreachable!()
                };

                let rsp = UnusedPduResp::SigCmd(signal_data.into_inner()?);

                Some(BasicFrame::new(rsp, request_data.channel_id))
            }
            ChannelIdentifier::Le(LeCid::SecurityManagerProtocol) => {
                let rsp = UnusedPduResp::SecurityManager;

                Some(BasicFrame::new(rsp, request_data.channel_id))
            }
            _ => None,
        }
    }

    fn new_request_data(pdu_len: usize, channel_id: ChannelIdentifier) -> Self::ReceiveData {
        UnusedFixedChannelPduData::new(pdu_len, channel_id)
    }
}

/// Data from a received PDU to an unused fixed channel for a LE-U logical link
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct UnusedFixedChannelPduData {
    byte_cnt: usize,
    pdu_len: usize,
    channel_id: ChannelIdentifier,
    channel_data: UnusedFixedChannelPduChannelData,
}

impl UnusedFixedChannelPduData {
    fn new(pdu_len: usize, channel_id: ChannelIdentifier) -> Self {
        let byte_cnt = 0;

        let channel_data = match channel_id {
            ChannelIdentifier::Le(LeCid::AttributeProtocol) => {
                UnusedFixedChannelPduChannelData::Attribute(Default::default())
            }
            ChannelIdentifier::Le(LeCid::LeSignalingChannel) => {
                UnusedFixedChannelPduChannelData::Signalling(Default::default())
            }
            ChannelIdentifier::Le(LeCid::SecurityManagerProtocol) => UnusedFixedChannelPduChannelData::None,
            _ => UnusedFixedChannelPduChannelData::Ignored,
        };

        Self {
            byte_cnt,
            pdu_len,
            channel_id,
            channel_data,
        }
    }
}

impl ReceiveDataProcessor for UnusedFixedChannelPduData {
    type Error = UnusedError;

    fn process<T>(&mut self, mut fragment: L2capFragment<T>) -> Result<bool, Self::Error>
    where
        T: Iterator<Item = u8> + ExactSizeIterator,
    {
        match &mut self.channel_data {
            UnusedFixedChannelPduChannelData::None | UnusedFixedChannelPduChannelData::Ignored => (),
            UnusedFixedChannelPduChannelData::Signalling(sig) => {
                if sig.identifier.is_none() {
                    if let Some(byte) = fragment.data.next() {
                        self.byte_cnt += 1;

                        if let Some(identifier) = NonZeroU8::new(byte) {
                            sig.identifier = Some(identifier)
                        } else {
                            return Err(UnusedError::InvalidSignalIdentifier);
                        }
                    }
                }
            }
            UnusedFixedChannelPduChannelData::Attribute(att) => {
                if self.byte_cnt < 3 {
                    for byte in fragment.data.by_ref() {
                        match self.byte_cnt {
                            0 => att.request_opcode = Some(byte),
                            1 => att.handle_b0 = Some(byte),
                            2 => att.handle_b1 = Some(byte),
                            _ => break,
                        }

                        self.byte_cnt += 1
                    }
                }
            }
        }

        self.byte_cnt += fragment.data.len();

        if self.byte_cnt == self.pdu_len {
            Ok(true)
        } else if self.byte_cnt > self.pdu_len {
            Err(UnusedError::InvalidSignalIdentifier)
        } else {
            Ok(false)
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum UnusedFixedChannelPduChannelData {
    None,
    Signalling(SignallingData),
    Attribute(AttributeData),
    Ignored,
}

#[derive(Copy, Clone, Debug, PartialEq, Default)]
struct SignallingData {
    identifier: Option<NonZeroU8>,
}

impl SignallingData {
    fn into_inner(self) -> Option<NonZeroU8> {
        self.identifier
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Default)]
struct AttributeData {
    request_opcode: Option<u8>,
    handle_b0: Option<u8>,
    handle_b1: Option<u8>,
}

impl AttributeData {
    fn into_inner(self) -> Option<(u8, u16)> {
        match (self.request_opcode, self.handle_b0, self.handle_b1) {
            (Some(op), Some(b0), Some(b1)) => {
                let handle = <u16>::from_le_bytes([b0, b1]);

                Some((op, handle))
            }
            _ => None,
        }
    }
}

/// Iterator over data used in return for
pub enum UnusedPduResp {
    Att(u8, u16),
    SigCmd(NonZeroU8),
    SecurityManager,
}

impl UnusedPduResp {
    #[inline]
    fn next_att(&mut self, cnt: usize) -> Option<u8> {
        let UnusedPduResp::Att(request, handle) = self else {
            unreachable!()
        };

        match cnt {
            0 => Some(0x1), // attribute error response code
            1 => Some(*request),
            2 => Some((*handle).to_le_bytes()[0]),
            3 => Some((*handle).to_le_bytes()[1]),
            4 => Some(0x6), // error code - request not supported
            _ => None,
        }
    }

    #[inline]
    fn next_sig_cmd(&mut self, cnt: usize) -> Option<u8> {
        let UnusedPduResp::SigCmd(non_zero) = self else {
            unreachable!()
        };

        match cnt {
            0 => Some(0x1),
            1 => Some((*non_zero).get()),
            2 => Some(1),
            3 => Some(0),
            4 => Some(0), // reason - command not understood
            _ => None,
        }
    }

    #[inline]
    fn next_sm(&mut self, cnt: usize) -> Option<u8> {
        match cnt {
            0 => Some(0x5), // pairing failed code
            1 => Some(0x5), // reason - pairing not supported
            _ => None,
        }
    }

    fn next(&mut self, cnt: usize) -> Option<u8> {
        match self {
            UnusedPduResp::Att(_, _) => self.next_att(cnt),
            UnusedPduResp::SigCmd(_) => self.next_sig_cmd(cnt),
            UnusedPduResp::SecurityManager => self.next_sm(cnt),
        }
    }
}

impl IntoIterator for UnusedPduResp {
    type Item = u8;
    type IntoIter = UnusedPduRespIter;

    fn into_iter(self) -> Self::IntoIter {
        UnusedPduRespIter { cnt: 0, rsp: self }
    }
}

pub struct UnusedPduRespIter {
    cnt: usize,
    rsp: UnusedPduResp,
}

impl Iterator for UnusedPduRespIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let rsp = self.rsp.next(self.cnt);

        self.cnt += 1;

        rsp
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = match &self.rsp {
            UnusedPduResp::Att(_, _) => 5usize,
            UnusedPduResp::SigCmd(_) => 5,
            UnusedPduResp::SecurityManager => 2,
        }
        .checked_sub(self.cnt)
        .unwrap_or_default();

        (size, Some(size))
    }
}

impl ExactSizeIterator for UnusedPduRespIter {}

#[derive(Debug)]
pub enum UnusedError {
    InvalidSignalIdentifier,
}

impl core::fmt::Display for UnusedError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            UnusedError::InvalidSignalIdentifier => f.write_str("invalid signalling command identifier"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnusedError {}
