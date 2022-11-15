//! Send safe channel implementation
//!
//! In order to support send safe async tasks the implementor of bo-tie must use send safe channels
//! between the host, interface and connection async tasks. There are no send safe channels within
//! this library so they must be used come from another rust library.

#[cfg(any(feature = "tokio", feature = "async-std"))]
macro_rules! make_error {
    ($name:ident, $($error_name:ident)::*, $sender:ident, $receiver:ident) => {
        /// The send error
        pub enum $name {
            ToHostCmd($($error_name)::*<$crate::ToHostCommandIntraMessage>),
            ToHostGen(
                $($error_name)::*<
                    $crate::ToHostGeneralIntraMessage<
                        super::ConnectionEnds<
                            $sender<$crate::FromConnectionIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>,
                            $receiver<$crate::ToConnectionDataIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>,
                            $receiver<$crate::ToConnectionEventIntraMessage>,
                        >,
                    >,
                >,
            ),
            FromHost($($error_name)::*<$crate::ToInterfaceIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>),
            ToConnectionData($($error_name)::*<$crate::ToConnectionDataIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>),
            ToConnectionEvent($($error_name)::*<$crate::ToConnectionEventIntraMessage>),
            FromConnection($($error_name)::*<$crate::FromConnectionIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>),
        }

        impl std::fmt::Debug for Error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Error::ToHostCmd(e) => std::fmt::Debug::fmt(e, f),
                    Error::ToHostGen(e) => std::fmt::Debug::fmt(e, f),
                    Error::FromHost(e) => std::fmt::Debug::fmt(e, f),
                    Error::ToConnectionData(e) => std::fmt::Debug::fmt(e, f),
                    Error::ToConnectionEvent(e) => std::fmt::Debug::fmt(e, f),
                    Error::FromConnection(e) => std::fmt::Debug::fmt(e, f),
                }
            }
        }

        impl std::fmt::Display for Error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Error::ToHostCmd(e) => std::fmt::Display::fmt(e, f),
                    Error::ToHostGen(e) => std::fmt::Display::fmt(e, f),
                    Error::FromHost(e) => std::fmt::Display::fmt(e, f),
                    Error::ToConnectionData(e) => std::fmt::Display::fmt(e, f),
                    Error::ToConnectionEvent(e) => std::fmt::Display::fmt(e, f),
                    Error::FromConnection(e) => std::fmt::Display::fmt(e, f),
                }
            }
        }

        impl std::error::Error for Error {}

        impl From<$($error_name)::*<$crate::ToHostCommandIntraMessage>> for Error {
            fn from(t: $($error_name)::*<$crate::ToHostCommandIntraMessage>) -> Error {
                Error::ToHostCmd(t)
            }
        }

        impl
            From<
                $($error_name)::*<
                    $crate::ToHostGeneralIntraMessage<
                        super::ConnectionEnds<
                            $sender<$crate::FromConnectionIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>,
                            $receiver<$crate::ToConnectionDataIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>,
                            $receiver<$crate::ToConnectionEventIntraMessage>,
                        >,
                    >,
                >,
            > for Error
        {
            fn from(
                t: $($error_name)::*<
                    $crate::ToHostGeneralIntraMessage<
                        super::ConnectionEnds<
                            $sender<$crate::FromConnectionIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>,
                            $receiver<$crate::ToConnectionDataIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>,
                            $receiver<$crate::ToConnectionEventIntraMessage>,
                        >,
                    >,
                >,
            ) -> Error {
                Error::ToHostGen(t)
            }
        }

        impl From<$($error_name)::*<$crate::ToInterfaceIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>> for Error {
            fn from(t: $($error_name)::*<$crate::ToInterfaceIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>) -> Error {
                Error::FromHost(t)
            }
        }

        impl From<$($error_name)::*<$crate::ToConnectionDataIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>> for Error {
            fn from(t: $($error_name)::*<$crate::ToConnectionDataIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>) -> Error {
                Error::ToConnectionData(t)
            }
        }

        impl From<$($error_name)::*<$crate::ToConnectionEventIntraMessage>> for Error {
            fn from(t: $($error_name)::*<$crate::ToConnectionEventIntraMessage>) -> Error {
                Error::ToConnectionEvent(t)
            }
        }

        impl From<$($error_name)::*<$crate::FromConnectionIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>> for Error {
            fn from(t: $($error_name)::*<$crate::FromConnectionIntraMessage<bo_tie_util::buffer::de_vec::DeVec<u8>>>) -> Error {
                Error::FromConnection(t)
            }
        }
    };
}

mod impl_trait_ext;

pub use impl_trait_ext::{SendSafeChannelReserve, SendSafeConnectionChannelEnds, SendSafeHostChannelEnds};

#[cfg(feature = "tokio")]
mod tokio;

#[cfg(feature = "async-std")]
mod async_std;

#[cfg(feature = "futures-rs")]
mod futures_rs;

#[cfg(feature = "tokio")]
pub use self::tokio::tokio_unbounded;

#[cfg(feature = "async-std")]
pub use self::async_std::async_std_unbounded;

#[cfg(feature = "futures-rs")]
pub use self::futures_rs::futures_unbounded;

use crate::{
    BufferReserve, Channel as ChannelTrait, ChannelReserve as ChannelReserveTrait, ConnectionChannel,
    ConnectionChannelEnds, FlowCtrlReceiver, FromConnectionIntraMessage, HostChannelEnds as HostChannelEndsTrait,
    Receiver, Sender, ToConnectionDataIntraMessage, ToConnectionEventIntraMessage, ToHostCommandIntraMessage,
    ToHostGeneralIntraMessage, ToInterfaceIntraMessage,
};
use crate::{ConnectionHandle, FlowControlId, FromInterface, HostChannel, InterfaceReceivers, TaskId};
use bo_tie_util::buffer::de_vec::{DeVec, TakeFuture};
use bo_tie_util::buffer::BufferExt;
use core::fmt::{Debug, Display, Formatter};

/// Channel ends for a connection async task
///
/// This is the ends of the channels used by a connection async task for sending messages to and
/// from an interface async task.
#[derive(Debug)]
pub struct ConnectionEnds<S, R1, R2> {
    from_connection: S,
    data_to_connection: R1,
    event_to_connection: Option<R2>,
}

impl<'a, S, R1, R2> ConnectionChannelEnds for ConnectionEnds<S, R1, R2>
where
    S: Sender<Message = FromConnectionIntraMessage<DeVec<u8>>> + Clone,
    R1: Receiver<Message = ToConnectionDataIntraMessage<DeVec<u8>>>,
    R2: Receiver<Message = ToConnectionEventIntraMessage>,
{
    type ToBuffer = DeVec<u8>;
    type FromBuffer = DeVec<u8>;
    type TakeBuffer = TakeFuture<DeVec<u8>>;
    type Sender = S;
    type DataReceiver = R1;
    type EventReceiver = R2;

    fn get_sender(&self) -> Self::Sender {
        self.from_connection.clone()
    }

    fn take_buffer<F, B>(&self, front_capacity: F, _: B) -> Self::TakeBuffer
    where
        F: Into<Option<usize>>,
        B: Into<Option<usize>>,
    {
        TakeFuture::new(DeVec::with_front_capacity(front_capacity.into().unwrap_or_default()))
    }

    fn get_data_receiver(&self) -> &Self::DataReceiver {
        &self.data_to_connection
    }

    fn get_mut_data_receiver(&mut self) -> &mut Self::DataReceiver {
        &mut self.data_to_connection
    }

    fn take_event_receiver(&mut self) -> Option<Self::EventReceiver> {
        self.event_to_connection.take()
    }
}

/// A message channel
pub struct Channel<S, R> {
    sender: S,
    _receiver: core::marker::PhantomData<R>,
}

impl<S, R> Channel<S, R> {
    fn new(sender: S) -> Self {
        let _receiver = core::marker::PhantomData;

        Channel { sender, _receiver }
    }
}

impl<S, R, M> ChannelTrait for Channel<S, R>
where
    S: Sender<Message = M> + Clone,
    R: Receiver<Message = M>,
    M: Unpin,
{
    type SenderError = S::Error;
    type Message = M;
    type Sender = S;
    type Receiver = R;

    fn get_sender(&self) -> Self::Sender {
        self.sender.clone()
    }

    fn take_receiver(&self) -> Option<Self::Receiver> {
        None
    }
}

impl<S, R> BufferReserve for Channel<S, R> {
    type Buffer = DeVec<u8>;
    type TakeBuffer = TakeFuture<DeVec<u8>>;

    fn take<F, B>(&self, front_capacity: F, _: B) -> Self::TakeBuffer
    where
        F: Into<Option<usize>>,
        B: Into<Option<usize>>,
    {
        TakeFuture::new(DeVec::with_front_capacity(front_capacity.into().unwrap_or_default()))
    }

    fn reclaim(&mut self, _: Self::Buffer) {}
}

/// Channel ends for a host async task
///
/// These are the ends of the channels used by a host async task for sending messages to and from an
/// interface async task.
pub struct HostChannelEnds<S1, R1, R2, P1, P2, P3> {
    front_capacity: usize,
    back_capacity: usize,
    cmd_sender: S1,
    cmd_rsp_recv: R1,
    gen_recv: R2,
    _p: core::marker::PhantomData<(P1, P2, P3)>,
}

impl<S1, S2, R1, R2, R3, R4> HostChannelEndsTrait for HostChannelEnds<S1, R1, R2, S2, R3, R4>
where
    S1: Sender<Message = ToInterfaceIntraMessage<DeVec<u8>>> + Clone,
    S2: Sender<Message = FromConnectionIntraMessage<DeVec<u8>>> + Clone,
    R1: Receiver<Message = ToHostCommandIntraMessage>,
    R2: Receiver<Message = ToHostGeneralIntraMessage<ConnectionEnds<S2, R3, R4>>>,
    R3: Receiver<Message = ToConnectionDataIntraMessage<DeVec<u8>>>,
    R4: Receiver<Message = ToConnectionEventIntraMessage>,
{
    type ToBuffer = DeVec<u8>;
    type FromBuffer = DeVec<u8>;
    type TakeBuffer = TakeFuture<DeVec<u8>>;
    type Sender = S1;
    type CmdReceiver = R1;
    type GenReceiver = R2;
    type ConnectionChannelEnds = ConnectionEnds<S2, R3, R4>;

    fn driver_buffer_capacities(&self) -> (usize, usize) {
        (self.front_capacity, self.back_capacity)
    }

    fn get_sender(&self) -> Self::Sender {
        self.cmd_sender.clone()
    }

    fn take_buffer<F, B>(&self, front_capacity: F, back_capacity: B) -> Self::TakeBuffer
    where
        F: Into<Option<usize>>,
        B: Into<Option<usize>>,
    {
        TakeFuture::new(DeVec::with_capacity(
            front_capacity.into().unwrap_or_default(),
            back_capacity.into().unwrap_or_default(),
        ))
    }

    fn get_cmd_recv(&self) -> &Self::CmdReceiver {
        &self.cmd_rsp_recv
    }

    fn get_mut_cmd_recv(&mut self) -> &mut Self::CmdReceiver {
        &mut self.cmd_rsp_recv
    }

    fn get_gen_recv(&self) -> &Self::GenReceiver {
        &self.gen_recv
    }

    fn get_mut_gen_recv(&mut self) -> &mut Self::GenReceiver {
        &mut self.gen_recv
    }
}

/// Dedicated senders for messages from the interface async task
struct Outgoing<C, G> {
    to_host_cmd_sender: C,
    to_host_gen_sender: G,
}

/// Senders used by connection async tasks
struct Incoming<S> {
    acl: S,
    sco: S,
    le_acl: S,
    le_iso: S,
}

/// Data for connections
struct ConnectionData<Sd, Se> {
    handle: ConnectionHandle,
    flow_control_id: FlowControlId,
    data_sender: Sd,
    event_sender: Se,
}

/// The channel reserve
///
/// The channel reserve is the type used by an interface async task for interacting with the other
/// async tasks. Its main purpose is holding the ends of the connection channels used for
/// communication with those other tasks.
///
/// A `ChannelReserve` is constructed by a [`ChannelReserveBuilder`].
pub struct ChannelReserve<S1, S2, S3, S4, S5, R1, R2, F1, F2, P1, P2, P3, P4, P5>
where
    R1: Receiver,
    R2: Receiver,
{
    outgoing_senders: Outgoing<S1, S2>,
    incoming_senders: Incoming<S3>,
    flow_ctrl_recv: FlowCtrlReceiver<R1, R2>,
    data_channel_creator: F1,
    event_channel_creator: F2,
    connections: alloc::vec::Vec<ConnectionData<S4, S5>>,
    _p: core::marker::PhantomData<(P1, P2, P3, P4, P5)>,
}

impl<S1, S2, S3, S4, S5, S6, R1, R2, R3, R4, R5, R6, F1, F2>
    ChannelReserve<S1, S2, S4, S5, S6, R3, R4, F1, F2, S3, R1, R2, R5, R6>
where
    R3: Receiver<Message = ToInterfaceIntraMessage<DeVec<u8>>>,
    R4: Receiver<Message = FromConnectionIntraMessage<DeVec<u8>>>,
{
    /// Create a new `ChannelReserve`
    ///
    /// # Inputs
    /// `channel1`: channel for command response events from the interface async task to the host
    ///             async task
    /// `channel2`: channel for general messages from the interface async task to the host async
    ///             task
    /// * `channel3`: channel for commands from the host async task to the interface async task
    /// * `channel4`: channel for messages from a connection async task to the interface async task
    /// * `channel5`: channel for HCI data from the interface async task to a connection async task
    /// * `channel6`: channel for events from the interface async task to a connection async task
    fn new<C1, C2, C3, C4, E>(
        front_capacity: usize,
        back_capacity: usize,
        channel1: C1,
        channel2: C2,
        channel3: C3,
        channel4: C4,
        channel5: F1,
        channel6: F2,
    ) -> (Self, HostChannelEnds<S3, R1, R2, S4, R5, R6>)
    where
        C1: FnOnce() -> (S1, R1),
        C2: FnOnce() -> (S2, R2),
        C3: FnOnce() -> (S3, R3),
        C4: Fn() -> (S4, R4),
        F1: Fn() -> (S5, R5),
        F2: Fn() -> (S6, R6),
        S1: Sender<Error = E, Message = ToHostCommandIntraMessage> + Clone,
        S2: Sender<Error = E, Message = ToHostGeneralIntraMessage<ConnectionEnds<S4, R5, R6>>> + Clone,
        S3: Sender<Error = E, Message = ToInterfaceIntraMessage<DeVec<u8>>> + Clone,
        S4: Sender<Error = E, Message = FromConnectionIntraMessage<DeVec<u8>>> + Unpin + Clone,
        S5: Sender<Error = E, Message = ToConnectionDataIntraMessage<DeVec<u8>>> + Clone,
        S6: Sender<Error = E, Message = ToConnectionEventIntraMessage> + Clone,
        R1: Receiver<Message = ToHostCommandIntraMessage>,
        R2: Receiver<Message = ToHostGeneralIntraMessage<ConnectionEnds<S4, R5, R6>>>,
        R3: Receiver<Message = ToInterfaceIntraMessage<DeVec<u8>>>,
        R4: Receiver<Message = FromConnectionIntraMessage<DeVec<u8>>>,
        R5: Receiver<Message = ToConnectionDataIntraMessage<DeVec<u8>>> + Unpin,
        R6: Receiver<Message = ToConnectionEventIntraMessage> + Unpin,
    {
        let (to_host_cmd_sender, host_cmd_event_recv) = channel1();

        let (to_host_gen_sender, host_gen_recv) = channel2();

        let (host_cmd_sender, cmd_receiver) = channel3();

        let (acl_sender, acl_receiver) = channel4();

        let (sco_sender, sco_receiver) = channel4();

        let (le_acl_sender, le_acl_receiver) = channel4();

        let (le_iso_sender, le_iso_receiver) = channel4();

        let connections = Default::default();

        let host_channel_ends = HostChannelEnds {
            front_capacity,
            back_capacity,
            cmd_sender: host_cmd_sender,
            cmd_rsp_recv: host_cmd_event_recv,
            gen_recv: host_gen_recv,
            _p: core::marker::PhantomData,
        };

        let outgoing_senders = Outgoing {
            to_host_cmd_sender,
            to_host_gen_sender,
        };

        let incoming_senders = Incoming {
            acl: acl_sender,
            sco: sco_sender,
            le_acl: le_acl_sender,
            le_iso: le_iso_sender,
        };

        let interface_receivers = InterfaceReceivers {
            cmd_receiver,
            acl_receiver,
            sco_receiver,
            le_acl_receiver,
            le_iso_receiver,
        };

        let flow_ctrl_recv = FlowCtrlReceiver::new(interface_receivers);

        let _p = core::marker::PhantomData;

        let this = Self {
            outgoing_senders,
            incoming_senders,
            flow_ctrl_recv,
            data_channel_creator: channel5,
            event_channel_creator: channel6,
            connections,
            _p,
        };

        (this, host_channel_ends)
    }
}

impl<S1, S2, S3, S4, S5, S6, R1, R2, R3, R4, R5, R6, F1, F2, E> ChannelReserveTrait
    for ChannelReserve<S1, S2, S4, S5, S6, R3, R4, F1, F2, S3, R1, R2, R5, R6>
where
    S1: Sender<Error = E, Message = ToHostCommandIntraMessage> + Clone,
    S2: Sender<Error = E, Message = ToHostGeneralIntraMessage<ConnectionEnds<S4, R5, R6>>> + Clone,
    S3: Sender<Error = E, Message = ToInterfaceIntraMessage<DeVec<u8>>> + Clone,
    S4: Sender<Error = E, Message = FromConnectionIntraMessage<DeVec<u8>>> + Unpin + Clone,
    S5: Sender<Error = E, Message = ToConnectionDataIntraMessage<DeVec<u8>>> + Clone,
    S6: Sender<Error = E, Message = ToConnectionEventIntraMessage> + Clone,
    R1: Receiver<Message = ToHostCommandIntraMessage>,
    R2: Receiver<Message = ToHostGeneralIntraMessage<ConnectionEnds<S4, R5, R6>>>,
    R3: Receiver<Message = ToInterfaceIntraMessage<DeVec<u8>>>,
    R4: Receiver<Message = FromConnectionIntraMessage<DeVec<u8>>>,
    R5: Receiver<Message = ToConnectionDataIntraMessage<DeVec<u8>>> + Unpin,
    R6: Receiver<Message = ToConnectionEventIntraMessage> + Unpin,
    F1: Fn() -> (S5, R5),
    F2: Fn() -> (S6, R6),
    E: core::fmt::Debug,
{
    type Error = ChannelReserveError;

    type SenderError = E;

    type ToHostCmdChannel = Channel<S1, R1>;

    type ToHostGenChannel = Channel<S2, R2>;

    type FromHostChannel = Channel<S3, R3>;

    type ToConnectionDataChannel = Channel<S5, R5>;

    type ToConnectionEventChannel = Channel<S6, R6>;

    type FromConnectionChannel = Channel<S4, R4>;

    type ConnectionChannelEnds = ConnectionEnds<S4, R5, R6>;

    fn try_remove(&mut self, to_remove: ConnectionHandle) -> Result<(), Self::Error> {
        if let Ok(index) = self
            .connections
            .binary_search_by(|ConnectionData { handle, .. }| handle.cmp(&to_remove))
        {
            self.connections.remove(index);

            Ok(())
        } else {
            Err(ChannelReserveError::ChannelIdDoesNotExist)
        }
    }

    fn add_new_connection(
        &mut self,
        connection_handle: ConnectionHandle,
        flow_control_id: FlowControlId,
    ) -> Result<Self::ConnectionChannelEnds, Self::Error> {
        let index = match self
            .connections
            .binary_search_by(|ConnectionData { handle, .. }| handle.cmp(&connection_handle))
        {
            Err(index) => index,
            Ok(_) => return Err(ChannelReserveError::ChannelIdAlreadyUsed),
        };

        let from_connection = match flow_control_id {
            FlowControlId::Cmd => unreachable!(),
            FlowControlId::Acl => self.incoming_senders.acl.clone(),
            FlowControlId::Sco => self.incoming_senders.sco.clone(),
            FlowControlId::LeAcl => self.incoming_senders.le_acl.clone(),
            FlowControlId::LeIso => self.incoming_senders.le_iso.clone(),
        };

        let (data_from_interface, data_to_connection) = (self.data_channel_creator)();
        let (event_from_interface, event_to_connection) = (self.event_channel_creator)();

        let new_task_ends = ConnectionEnds {
            from_connection,
            data_to_connection,
            event_to_connection: event_to_connection.into(),
        };

        let connection_data = ConnectionData {
            handle: connection_handle,
            flow_control_id,
            data_sender: data_from_interface,
            event_sender: event_from_interface,
        };

        self.connections.insert(index, connection_data);

        Ok(new_task_ends)
    }

    fn get_channel(
        &self,
        id: TaskId,
    ) -> Option<
        FromInterface<
            Self::ToHostCmdChannel,
            Self::ToHostGenChannel,
            Self::ToConnectionDataChannel,
            Self::ToConnectionEventChannel,
        >,
    > {
        match id {
            TaskId::Host(HostChannel::Command) => {
                let channel = Channel::new(self.outgoing_senders.to_host_cmd_sender.clone());

                Some(FromInterface::HostCommand(channel))
            }
            TaskId::Host(HostChannel::General) => {
                let channel = Channel::new(self.outgoing_senders.to_host_gen_sender.clone());

                Some(FromInterface::HostGeneral(channel))
            }
            TaskId::Connection(channel_type @ ConnectionChannel::Data(connection_handle))
            | TaskId::Connection(channel_type @ ConnectionChannel::Event(connection_handle)) => self
                .connections
                .binary_search_by(|ConnectionData { handle, .. }| handle.cmp(&connection_handle))
                .ok()
                .and_then(|index| self.connections.get(index))
                .map(
                    |ConnectionData {
                         data_sender,
                         event_sender,
                         ..
                     }| match channel_type {
                        ConnectionChannel::Data(_) => FromInterface::ConnectionData(Channel::new(data_sender.clone())),
                        ConnectionChannel::Event(_) => {
                            FromInterface::ConnectionEvent(Channel::new(event_sender.clone()))
                        }
                    },
                ),
        }
    }

    fn get_flow_control_id(&self, connection_handle: ConnectionHandle) -> Option<FlowControlId> {
        self.connections
            .binary_search_by(|ConnectionData { handle, .. }| handle.cmp(&connection_handle))
            .ok()
            .and_then(|index| self.connections.get(index))
            .map(|ConnectionData { flow_control_id, .. }| *flow_control_id)
    }

    fn get_flow_ctrl_receiver(
        &mut self,
    ) -> &mut FlowCtrlReceiver<
        <Self::FromHostChannel as ChannelTrait>::Receiver,
        <Self::FromConnectionChannel as ChannelTrait>::Receiver,
    > {
        &mut self.flow_ctrl_recv
    }
}

/// A constructor of a [`ChannelReserve`]
///
/// Constructing a `ChannelReserve` is much less complicated than it seems. If you look at the
/// methods of this struct you'll notice quite a few generics and trait bound requirements. In
/// reality it should be rather strait forward, and there should not be much effort to fulfill these
/// requirements.
///
/// A channel reserve is intended to be constructed from functions that return the sender and
/// receiver of the channel. The generics of `ChannelReserveBuilder` each represent one of these
/// functions. While the trait bounds look complicated to set these functions in the methods
/// [`set_c1`], [`set_c2`], .. , [`set_c5`], in reality the only major difference between the
/// channels is the message sent between them. If you have a channel implementation that meets
/// the following requirements, it can be used as the input for every set method.
///
/// Given a function 'channel' and the pseudo-types 'Sender' and 'Receiver':
/// * `channel` implements `Fn() -> (Sender, Receiver)`
/// * `Sender` implements [`Sender<Message = T>`] where `T` is an unbounded generic
/// * `Receiver` implements [`Receiver<Message = T>`] where `T` is an unbounded generic
///
/// ```
/// # use std::future::Future;
/// # use std::pin::Pin;
/// # use std::task::{Context, Poll};
/// # #[derive(Debug)] struct MySenderError;
/// # struct MySenderFuture<'a, T>(core::marker::PhantomData<&'a T>);
/// # impl<T> Future for MySenderFuture<'_, T> {
/// #     type Output = Result<(), MySenderError>;
/// #     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> { unimplemented!() }
/// # }
/// # struct MySender<T>(core::marker::PhantomData<T>);
/// # impl<T> Clone for MySender<T> { fn clone(&self) -> Self { unimplemented!() } }
/// # struct MyReceiveFuture<'a, T>(core::marker::PhantomData<&'a T>);
/// # impl<T> Future for MyReceiveFuture<'_, T> {
/// #     type Output = Option<T>;
/// #     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> { unimplemented!() }
/// # }
/// # struct MyReceiver<T>(core::marker::PhantomData<T>);
/// use bo_tie_hci_util::{Sender, Receiver};
/// use bo_tie_hci_util::channel::ChannelReserveBuilder;
///
/// impl<T: Unpin> Sender for MySender<T> {
///    type Error = MySenderError;
///     type Message = T;
///     type SendFuture<'a> = MySenderFuture<'a, T> where Self: 'a;
///
///     fn send(&mut self, t: Self::Message) -> Self::SendFuture<'_> {
///         // implement send
/// #       MySenderFuture(core::marker::PhantomData)  
///     }
/// }
///
/// impl<T: Unpin> Receiver for MyReceiver<T> {
///     type Message = T;
///     type ReceiveFuture<'a> = MyReceiveFuture<'a, T> where Self: 'a;
///
///     fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
///         // implement poll_recv
/// #       Poll::Ready(None)
///     }
///
///     fn recv(&mut self) -> Self::ReceiveFuture<'_> {
///         // implement recv
/// #       MyReceiveFuture(core::marker::PhantomData)
///     }
/// }
///
/// fn my_channel<T>() -> (MySender<T>, MyReceiver<T>) {
///     // Your channel implementation
/// #   (MySender(core::marker::PhantomData), MyReceiver(core::marker::PhantomData))
/// }
///
/// // `my_channel` needs to be spammed five times to define
/// // the five different channel types used by a channel
/// // reserve.
/// let my_channel_reserve = ChannelReserveBuilder::new()
///     .set_c1(my_channel)
///     .set_c2(my_channel)
///     .set_c3(my_channel)
///     .set_c4(my_channel)
///     .set_c5(my_channel)
///     .build();
///
/// # let _r = my_channel_reserve;
/// ```
/// [`set_c1`]: ChannelReserveBuilder::set_c1
/// [`set_c2`]: ChannelReserveBuilder::set_c2
/// [`set_c5`]: ChannelReserveBuilder::set_c5
/// [`Sender<Message = T>`]: crate::Sender
/// [`Receiver<Message = T>`]: crate::Receiver
pub struct ChannelReserveBuilder<C1, C2, C3, C4, C5, C6> {
    buffer_front_capacity: usize,
    buffer_back_capacity: usize,
    c1: Option<C1>,
    c2: Option<C2>,
    c3: Option<C3>,
    c4: Option<C4>,
    c5: Option<C5>,
    c6: Option<C6>,
}

impl<C1, C2, C3, C4, C5, C6> ChannelReserveBuilder<C1, C2, C3, C4, C5, C6> {
    /// Create a new `ChannelReserveBuilder`
    ///
    /// The inputs `header_size` and `tail_size` are the maximum sizes of the header and tail the
    /// frame for the interface. For example, UART would have one as the value for `header_max_size`
    /// and zero for `tail_max_size` since the packet indicator is only one byte and there is no
    /// tail for the packet.
    pub fn new(header_max_size: usize, tail_max_size: usize) -> Self {
        Self {
            buffer_front_capacity: header_max_size,
            buffer_back_capacity: tail_max_size,
            c1: None,
            c2: None,
            c3: None,
            c4: None,
            c5: None,
            c6: None,
        }
    }
}

impl<C1, C2, C3, C4, C5, C6, S1, S2, S3, S4, S5, S6, R1, R2, R3, R4, R5, R6, E>
    ChannelReserveBuilder<C1, C2, C3, C4, C5, C6>
where
    C1: FnOnce() -> (S1, R1),
    C2: FnOnce() -> (S2, R2),
    C3: FnOnce() -> (S3, R3),
    C4: Fn() -> (S4, R4),
    C5: Fn() -> (S5, R5),
    C6: Fn() -> (S6, R6),
    S1: Sender<Error = E, Message = ToHostCommandIntraMessage> + Clone,
    S2: Sender<Error = E, Message = ToHostGeneralIntraMessage<ConnectionEnds<S4, R5, R6>>> + Clone,
    S3: Sender<Error = E, Message = ToInterfaceIntraMessage<DeVec<u8>>> + Clone,
    S4: Sender<Error = E, Message = FromConnectionIntraMessage<DeVec<u8>>> + Unpin + Clone,
    S5: Sender<Error = E, Message = ToConnectionDataIntraMessage<DeVec<u8>>> + Clone,
    S6: Sender<Error = E, Message = ToConnectionEventIntraMessage> + Clone,
    R1: Receiver<Message = ToHostCommandIntraMessage>,
    R2: Receiver<Message = ToHostGeneralIntraMessage<ConnectionEnds<S4, R5, R6>>>,
    R3: Receiver<Message = ToInterfaceIntraMessage<DeVec<u8>>>,
    R4: Receiver<Message = FromConnectionIntraMessage<DeVec<u8>>>,
    R5: Receiver<Message = ToConnectionDataIntraMessage<DeVec<u8>>> + Unpin,
    R6: Receiver<Message = ToConnectionEventIntraMessage> + Unpin,
{
    pub fn set_c1(mut self, c1: C1) -> Self {
        self.c1 = Some(c1);
        self
    }

    pub fn set_c2(mut self, c2: C2) -> Self {
        self.c2 = Some(c2);
        self
    }

    pub fn set_c3(mut self, c3: C3) -> Self {
        self.c3 = Some(c3);
        self
    }

    pub fn set_c4(mut self, c4: C4) -> Self {
        self.c4 = Some(c4);
        self
    }

    pub fn set_c5(mut self, c5: C5) -> Self {
        self.c5 = Some(c5);
        self
    }

    pub fn set_c6(mut self, c6: C6) -> Self {
        self.c6 = Some(c6);
        self
    }

    pub fn build(
        self,
    ) -> (
        ChannelReserve<S1, S2, S4, S5, S6, R3, R4, C5, C6, S3, R1, R2, R5, R6>,
        HostChannelEnds<S3, R1, R2, S4, R5, R6>,
    ) {
        // The type checker will enforce these unwraps
        let c1 = self.c1.unwrap();
        let c2 = self.c2.unwrap();
        let c3 = self.c3.unwrap();
        let c4 = self.c4.unwrap();
        let c5 = self.c5.unwrap();
        let c6 = self.c6.unwrap();

        ChannelReserve::new(
            self.buffer_front_capacity,
            self.buffer_back_capacity,
            c1,
            c2,
            c3,
            c4,
            c5,
            c6,
        )
    }
}

#[derive(Debug)]
pub enum ChannelReserveError {
    ChannelIdDoesNotExist,
    ChannelIdAlreadyUsed,
}

impl Display for ChannelReserveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            ChannelReserveError::ChannelIdAlreadyUsed => f.write_str("channel id already used"),
            ChannelReserveError::ChannelIdDoesNotExist => f.write_str("channel for id does not exist"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ChannelReserveError {}
