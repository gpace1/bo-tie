//! Processing of Unused LE channels

use crate::channel::id::{ChannelIdentifier, LeCid};
use crate::channel::unused::{ReceiveDataProcessor, UnusedChannelResponse};
use crate::channel::BasicHeader;
use crate::pdu::{BasicFrame, L2capFragment};
use crate::{LeULogicalLink, PhysicalLink};
use core::num::NonZeroU8;

impl<P: PhysicalLink, B> UnusedChannelResponse for LeULogicalLink<P, B> {
    type ReceiveProcessor = UnusedFixedChannelPduData;
    type Response = BasicFrame<UnusedPduResp>;

    fn try_generate_response(request_data: UnusedFixedChannelPduData) -> Option<Self::Response> {
        match request_data.channel_id {
            ChannelIdentifier::Le(LeCid::AttributeProtocol) => {
                let UnusedFixedChannelPduChannelData::Attribute(attribute_data) = request_data.channel_data else {
                    // `None` is returned for junked L2CAP data
                    return None;
                };

                let (request, handle) = attribute_data.into_inner()?;

                let rsp = UnusedPduResp::Att(request, handle);

                Some(BasicFrame::new(rsp, request_data.channel_id))
            }
            ChannelIdentifier::Le(LeCid::LeSignalingChannel) => {
                let UnusedFixedChannelPduChannelData::Signalling(signal_data) = request_data.channel_data else {
                    // `None` is returned for junked L2CAP data
                    return None;
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

    fn new_response_data(pdu_len: usize, channel_id: ChannelIdentifier) -> Self::ReceiveProcessor {
        UnusedFixedChannelPduData::new(pdu_len, channel_id)
    }

    fn new_junked_data(pdu_len: usize, bytes_so_far: usize, channel_id: ChannelIdentifier) -> Self::ReceiveProcessor {
        if bytes_so_far == 0 {
            UnusedFixedChannelPduData::new(pdu_len, channel_id)
        } else {
            UnusedFixedChannelPduData::junk(pdu_len, bytes_so_far, channel_id)
        }
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

    fn junk(pdu_len: usize, byte_cnt: usize, channel_id: ChannelIdentifier) -> Self {
        let channel_data = UnusedFixedChannelPduChannelData::Ignored;

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

    fn process<T>(&mut self, _: &BasicHeader, fragment: &mut L2capFragment<T>) -> Result<bool, Self::Error>
    where
        T: Iterator<Item = u8> + ExactSizeIterator,
    {
        match &mut self.channel_data {
            UnusedFixedChannelPduChannelData::None | UnusedFixedChannelPduChannelData::Ignored => (),
            UnusedFixedChannelPduChannelData::Signalling(sig) => {
                for byte in fragment.data.by_ref() {
                    if self.byte_cnt == 1 {
                        sig.identifier =
                            Some(NonZeroU8::try_from(byte).map_err(|_| UnusedError::InvalidSignalIdentifier)?);
                    }

                    self.byte_cnt += 1;
                }
            }
            UnusedFixedChannelPduChannelData::Attribute(att) => {
                for byte in fragment.data.by_ref() {
                    match att.request_opcode {
                        None => att.request_opcode = Some(byte),
                        Some(0x2) => (),
                        Some(0x4 | 0x6 | 0x8 | 0xa | 0xc | 0xe | 0x10 | 0x20) => match self.byte_cnt {
                            1 => att.handle_b0 = Some(byte),
                            2 => {
                                att.handle_b1 = Some(byte);

                                break;
                            }
                            _ => (),
                        },
                        _ => (),
                    }
                    self.byte_cnt += 1
                }
            }
        }

        // determine the end of the L2CAP PDU

        self.byte_cnt += fragment.data.len();

        if self.byte_cnt == self.pdu_len {
            Ok(true)
        } else if self.byte_cnt > self.pdu_len {
            Err(UnusedError::InvalidLength)
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
        self.request_opcode.map(|opcode| {
            let handle = <u16>::from_le_bytes([self.handle_b0.unwrap_or_default(), self.handle_b1.unwrap_or_default()]);

            (opcode, handle)
        })
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
            2 => Some(2),
            3 => Some(0),
            4 => Some(0), // reason - command not understood
            5 => Some(0),
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
            UnusedPduResp::SigCmd(_) => 6,
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
    InvalidLength,
    InvalidSignalIdentifier,
}

impl core::fmt::Display for UnusedError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            UnusedError::InvalidLength => f.write_str("invalid length field in PDU"),
            UnusedError::InvalidSignalIdentifier => f.write_str("invalid signalling command identifier"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnusedError {}
