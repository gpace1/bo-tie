//! Flow Control Send Future
//!
//! Fragmentation is done by slicing up a L2CAP pdu into pre-allocated buffers sized to fit either
//! the MTU of the connection or the Controller's maximum data transfer size (probably specified
//! within the HCI).

use crate::pdu::FragmentIterator;
use crate::ConnectionChannel;
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use std::future::IntoFuture;

/// Future for sending a PDU
pub struct SendFuture<'a, C: ?Sized, P> {
    connection_channel: &'a C,
    pdu: P,
}

impl<'a, C: ?Sized, P> SendFuture<'a, C, P> {
    pub(crate) fn new(connection_channel: &'a C, pdu: P) -> Self {
        SendFuture {
            connection_channel,
            pdu,
        }
    }
}

impl<'a, C, P> IntoFuture for SendFuture<'a, C, P>
where
    C: ConnectionChannel + ?Sized,
    P: crate::pdu::FragmentL2capPdu + 'a,
{
    type Output = Result<(), C::SendErr>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        let future = async move {
            let mut is_first = true;

            let mut fragments_iter = self
                .pdu
                .into_fragments(self.connection_channel.fragmentation_size())
                .unwrap();

            while let Some(data) = fragments_iter.next() {
                let fragment = crate::L2capFragment::new(is_first, data);

                is_first = false;

                self.connection_channel.send_fragment(fragment).await?;
            }

            Ok(())
        };

        Box::pin(future)
    }
}

/// Future for sending a PDU in buffers
///
/// This is returned by the method [`send_buffered`].
///
/// [`send`]: crate::ConnectionChannelExt::send
pub struct SendBufferedFuture<T, B> {
    fragments_iter: T,
    buffer_iter: B,
}

impl<T, B> SendBufferedFuture<T, B> {
    pub fn new<P, D>(fragmentation_size: usize, pdu: P, buffers: D) -> Result<Self, crate::pdu::FragmentationError>
    where
        P: crate::pdu::FragmentL2capPdu<FragmentIterator = T> + ?Sized,
        D: IntoIterator<IntoIter = B>,
    {
        assert_ne!(fragmentation_size, 0, "the size of a fragment cannot be zero");

        let mut fragments_iter = pdu.into_fragments(fragmentation_size)?;

        let mut buffer_iter = buffers.into_iter();

        Ok(Self {
            fragments_iter,
            buffer_iter,
        })
    }
}

impl<T, D, B, F, C, E> IntoFuture for SendBufferedFuture<T, B>
where
    T: Iterator<Item = D> + 'static,
    D: Iterator<Item = u8>,
    B: Iterator<Item = F> + 'static,
    F: Future<Output = C>,
    C: crate::TryExtend<u8> + IntoFuture<Output = Result<(), E>>,
{
    type Output = Result<(), E>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output>>>;

    fn into_future(mut self) -> Self::IntoFuture {
        let future = async move {
            for fragment in self.fragments_iter {
                let mut buffer = self.buffer_iter.next().unwrap().await;

                buffer
                    .try_extend(fragment.into_iter())
                    .expect("buffer is too small for fragment");

                buffer.into_future().await?;
            }

            Ok(())
        };

        Box::pin(future)
    }
}
