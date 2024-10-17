//! Processing for Unused Channels
//!
//! Channels are only used when an object is created for them. The client may send a L2CAP PDU if it
//! expects that the channel's implementation exists for this device. If the PDU is for a fixed
//! channel a [`UnusedChannelResponse`] implementation will provide a response equivalent to either
//! *channel is not used* or *channel has no support*. However, a dynamically allocated channels are
//! ignored and produce the [`InvalidChannel`] error.

use crate::channel::id::{ChannelIdentifier, LeCid};
use crate::pdu::{
    BasicFrame, FragmentIterator, FragmentL2capPdu, FragmentationError, RecombineL2capPdu,
    RecombinePayloadIncrementally,
};
use bo_tie_core::buffer::stack::LinearBuffer;
use core::num::NonZeroU8;

pub(crate) enum LeUUnusedChannelResponse {
    Dumped,
    BasicFrame(BasicFrame<LinearBuffer<7, u8>>),
}

impl FragmentL2capPdu for LeUUnusedChannelResponse {
    type FragmentIterator = LeUUnusedChannelResponseFragmentIter;

    fn into_fragments(self, fragmentation_size: usize) -> Result<Self::FragmentIterator, FragmentationError> {
        Ok(match self {
            Self::Dumped => unreachable!(),
            Self::BasicFrame(frame) => LeUUnusedChannelResponseFragmentIter::BasicFrame(
                FragmentL2capPdu::into_fragments(frame, fragmentation_size)?,
            ),
        })
    }
}

pub(crate) enum LeUUnusedChannelResponseFragmentIter {
    BasicFrame(<BasicFrame<LinearBuffer<7, u8>> as FragmentL2capPdu>::FragmentIterator),
}

impl FragmentIterator for LeUUnusedChannelResponseFragmentIter {
    type Item<'a> = LeUUnusedChannelResponseDataIter<'a> where Self: 'a ;

    fn next(&mut self) -> Option<Self::Item<'_>> {
        match self {
            LeUUnusedChannelResponseFragmentIter::BasicFrame(frame_iter) => FragmentIterator::next(frame_iter)
                .map(|data_iter| LeUUnusedChannelResponseDataIter::BasicFrame(data_iter)),
        }
    }
}

pub(crate) enum LeUUnusedChannelResponseDataIter<'a> {
    BasicFrame(<<BasicFrame<LinearBuffer<7, u8>> as FragmentL2capPdu>::FragmentIterator as FragmentIterator>::Item<'a>),
}

impl Iterator for LeUUnusedChannelResponseDataIter<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::BasicFrame(iter) => iter.next(),
        }
    }
}

/// A recombine error
#[derive(Debug)]
pub(crate) struct UnusedRecombineError;

impl RecombineL2capPdu for LeUUnusedChannelResponse {
    type RecombineMeta<'a> = () where Self: 'a ;
    type RecombineError = UnusedRecombineError;
    type RecombineBuffer<'a> = ()  where Self: 'a ;
    type PayloadRecombiner<'a> = LeUUnusedChannelResponseRecombiner;

    fn recombine<'a>(
        payload_length: u16,
        channel_id: ChannelIdentifier,
        _: Self::RecombineBuffer<'a>,
        _: Self::RecombineMeta<'a>,
    ) -> Self::PayloadRecombiner<'a> {
        match channel_id {
            ChannelIdentifier::Le(LeCid::AttributeProtocol) => {
                LeUUnusedChannelResponseRecombiner::new_attribute(payload_length.into())
            }
            ChannelIdentifier::Le(LeCid::LeSignalingChannel) => {
                LeUUnusedChannelResponseRecombiner::new_signalling(payload_length.into())
            }
            ChannelIdentifier::Le(LeCid::SecurityManagerProtocol) => {
                LeUUnusedChannelResponseRecombiner::new_security_manager(payload_length.into())
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct LeUUnusedChannelResponseRecombiner {
    length: usize,
    bytes_received: usize,
    builder: LeUUnusedChannelResponseBuilderType,
}

impl LeUUnusedChannelResponseRecombiner {
    pub(crate) fn get_payload_length(&self) -> usize {
        self.length
    }

    pub(crate) fn get_bytes_received(&self) -> usize {
        self.bytes_received
    }

    fn new_attribute(length: usize) -> Self {
        let bytes_received = 0;

        let builder = LeUUnusedChannelResponseBuilderType::Attribute(AttributeChannelUnusedResponseBuilder::Unknown);

        LeUUnusedChannelResponseRecombiner {
            length,
            bytes_received,
            builder,
        }
    }

    pub(crate) fn converted_attribute<T>(payload_length: usize, received_bytes: T) -> Self
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        let length = payload_length;
        let mut bytes_received = 0;

        let mut att_builder = AttributeChannelUnusedResponseBuilder::Unknown;

        // this should never error no return a response
        assert!(att_builder
            .process(received_bytes.into_iter(), length, &mut bytes_received)
            .unwrap()
            .is_none());

        let builder = LeUUnusedChannelResponseBuilderType::Attribute(att_builder);

        LeUUnusedChannelResponseRecombiner {
            length,
            bytes_received,
            builder,
        }
    }

    fn new_signalling(length: usize) -> Self {
        let bytes_received = 0;
        let command_identifier = None;

        let builder = LeUUnusedChannelResponseBuilderType::Signalling(SignallingChannelUnusedResponseBuilder {
            identifier: command_identifier,
        });

        LeUUnusedChannelResponseRecombiner {
            length,
            bytes_received,
            builder,
        }
    }

    pub(crate) fn converted_signal<T>(payload_length: usize, received_bytes: T) -> Self
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        let length = payload_length;
        let mut bytes_received = 0;

        let mut sig_builder = SignallingChannelUnusedResponseBuilder { identifier: None };

        // this should never error no return a response
        assert!(sig_builder
            .process(received_bytes.into_iter(), length, &mut bytes_received)
            .unwrap()
            .is_none());

        let builder = LeUUnusedChannelResponseBuilderType::Signalling(sig_builder);

        LeUUnusedChannelResponseRecombiner {
            length,
            bytes_received,
            builder,
        }
    }

    fn new_security_manager(length: usize) -> Self {
        let bytes_received = 0;

        let builder = LeUUnusedChannelResponseBuilderType::SecurityManager(SecurityManagerChannelUnusedResponseBuilder);

        LeUUnusedChannelResponseRecombiner {
            length,
            bytes_received,
            builder,
        }
    }

    pub(crate) fn converted_sm<T>(payload_length: usize, received_bytes: T) -> Self
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        let length = payload_length;
        let mut bytes_received = 0;

        let mut sm_builder = SecurityManagerChannelUnusedResponseBuilder;

        // this should never error no return a response
        assert!(sm_builder
            .process(received_bytes.into_iter(), length, &mut bytes_received)
            .unwrap()
            .is_none());

        let builder = LeUUnusedChannelResponseBuilderType::SecurityManager(sm_builder);

        LeUUnusedChannelResponseRecombiner {
            length,
            bytes_received,
            builder,
        }
    }
}

#[derive(Debug)]
enum LeUUnusedChannelResponseBuilderType {
    Attribute(AttributeChannelUnusedResponseBuilder),
    Signalling(SignallingChannelUnusedResponseBuilder),
    SecurityManager(SecurityManagerChannelUnusedResponseBuilder),
}

#[derive(Debug, Copy, Clone)]
enum AttributeHandelState {
    None,
    First(u8),
    Complete(u16),
}

#[derive(Debug)]
enum AttributeChannelUnusedResponseBuilder {
    Unknown,
    Response {
        request_code: NonZeroU8,
        handle_state: AttributeHandelState,
    },
    Dumped,
}

impl AttributeChannelUnusedResponseBuilder {
    fn process<T: Iterator<Item = u8>>(
        &mut self,
        byte_iter: T,
        pdu_length: usize,
        bytes_received: &mut usize,
    ) -> Result<Option<LeUUnusedChannelResponse>, UnusedRecombineError> {
        for byte in byte_iter {
            match self {
                Self::Unknown => {
                    match byte {
                        // the following ATT requests can have an error response
                        0x2 | 0x4 | 0x6 | 0x8 | 0xa | 0xc | 0xe | 0x10 | 0x12 | 0x16 | 0x18 | 0x20 => {
                            let request_code = NonZeroU8::new(byte).unwrap();

                            let handle_state = AttributeHandelState::None;

                            *self = Self::Response {
                                request_code,
                                handle_state,
                            }
                        }
                        _ => *self = Self::Dumped,
                    }
                }
                Self::Response {
                    request_code,
                    handle_state,
                } => {
                    match request_code.get() {
                        // these requests have a handle field
                        0x4 | 0x6 | 0x8 | 0xa | 0xc | 0xe | 0x10 | 0x12 | 0x16 | 0x20 => match *bytes_received {
                            1 => *handle_state = AttributeHandelState::First(byte),
                            2 => {
                                let AttributeHandelState::First(first) = *handle_state else {
                                    unreachable!()
                                };

                                let handle = <u16>::from_le_bytes([first, byte]);

                                *handle_state = AttributeHandelState::Complete(handle);
                            }
                            _ => (),
                        },
                        _ => (),
                    }
                }
                Self::Dumped => (),
            }

            *bytes_received += 1;
        }

        (*bytes_received >= pdu_length)
            .then(|| {
                match self {
                    Self::Unknown | Self::Dumped => Ok(LeUUnusedChannelResponse::Dumped),
                    Self::Response {
                        request_code,
                        handle_state,
                    } => {
                        let code = request_code.get();

                        let AttributeHandelState::Complete(handle) = handle_state else {
                            return Err(UnusedRecombineError);
                        };

                        let [handle_byte_0, handle_byte_1] = handle.to_le_bytes();

                        // 0x1 -> attribute error response code
                        // 0x6 -> error code for 'request not supported'
                        let data = [0x1, code, handle_byte_0, handle_byte_1, 0x6];

                        let lb = LinearBuffer::try_from(data).expect("unused response buffer is too small");

                        let b_frame = BasicFrame::new(lb, ChannelIdentifier::Le(LeCid::AttributeProtocol));

                        Ok(LeUUnusedChannelResponse::BasicFrame(b_frame))
                    }
                }
            })
            .transpose()
    }
}

#[derive(Debug)]
struct SignallingChannelUnusedResponseBuilder {
    identifier: Option<NonZeroU8>,
}

impl SignallingChannelUnusedResponseBuilder {
    fn process<T: Iterator<Item = u8> + ExactSizeIterator>(
        &mut self,
        mut byte_iter: T,
        pdu_length: usize,
        bytes_received: &mut usize,
    ) -> Result<Option<LeUUnusedChannelResponse>, UnusedRecombineError> {
        loop {
            match bytes_received {
                0 => {
                    let Some(_) = byte_iter.next() else { return Ok(None) };
                    *bytes_received += 1
                }
                1 => {
                    let Some(byte) = byte_iter.next() else { return Ok(None) };

                    self.identifier = Some(NonZeroU8::new(byte).ok_or(UnusedRecombineError)?);

                    *bytes_received += 1;
                }
                _ => break *bytes_received += byte_iter.len(),
            }
        }

        (*bytes_received >= pdu_length)
            .then(|| {
                let identifier = self.identifier.ok_or(UnusedRecombineError)?.get();

                // 0x1 -> signalling L2CAP_COMMAND_REJECT_RSP
                // 0x2, 0x0 -> data length
                // 0x0, 0x0 -> reason -- command not understood
                let data = [0x1, identifier, 0x2, 0x0, 0x0, 0x0];

                let lb = LinearBuffer::try_from(data).expect("unused response buffer is too small");

                let b_frame = BasicFrame::new(lb, ChannelIdentifier::Le(LeCid::LeSignalingChannel));

                Ok(LeUUnusedChannelResponse::BasicFrame(b_frame))
            })
            .transpose()
    }
}

#[derive(Debug)]
struct SecurityManagerChannelUnusedResponseBuilder;

impl SecurityManagerChannelUnusedResponseBuilder {
    fn process<T: Iterator<Item = u8> + ExactSizeIterator>(
        &mut self,
        byte_iter: T,
        pdu_length: usize,
        bytes_received: &mut usize,
    ) -> Result<Option<LeUUnusedChannelResponse>, UnusedRecombineError> {
        *bytes_received += byte_iter.len();

        (*bytes_received >= pdu_length)
            .then(|| {
                // 0x5 - pairing failed code
                // 0x5 - reason - pairing not supported
                let data = [0x5, 0x5];

                let lb = LinearBuffer::try_from(data).expect("unused response buffer is too small");

                let b_frame = BasicFrame::new(lb, ChannelIdentifier::Le(LeCid::SecurityManagerProtocol));

                Ok(LeUUnusedChannelResponse::BasicFrame(b_frame))
            })
            .transpose()
    }
}

impl RecombinePayloadIncrementally for LeUUnusedChannelResponseRecombiner {
    type Pdu = LeUUnusedChannelResponse;
    type RecombineError = UnusedRecombineError;

    fn add<T>(&mut self, payload_fragment: T) -> Result<Option<Self::Pdu>, Self::RecombineError>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        let byte_iter = payload_fragment.into_iter();

        match &mut self.builder {
            LeUUnusedChannelResponseBuilderType::Attribute(builder) => {
                builder.process(byte_iter, self.length, &mut self.bytes_received)
            }
            LeUUnusedChannelResponseBuilderType::Signalling(builder) => {
                builder.process(byte_iter, self.length, &mut self.bytes_received)
            }
            LeUUnusedChannelResponseBuilderType::SecurityManager(builder) => {
                builder.process(byte_iter, self.length, &mut self.bytes_received)
            }
        }
    }
}
