//! Linked channel reception
//!
//! Because there is a receiver for each channel from an async task, the interface needs to be able
//! to funnel the channels into one source to output for the driver.
//!
//! # Why
//! Normally this would be done via the mechanics of a MPSC channel. Each async task would be given
//! a clone of the sender and there would only need to be one receiver. Unfortunately this cannot be
//! done as flow control to the controller is separated by data streams to it. The controller gives
//! each connection a separate data buffer along with another buffer for HCi commands. So in order
//! to deal with this flow control each connection async task and the host async task are given
//! their own channel to send to the interface task.
//!
//! Each send channel to the interface async task doubles as a flow control device to controller.
//! The controller will "receive" from a channel so long as it knows that the

use crate::hci::interface::{TaskId};


use core::task::Waker;

/// A trait for flow controlling channels
///
/// This is used as part of process to ensure that the interface driver only receives HCI messages
/// when the controller is able to accept them. The implementation of `FlowControlQueues` provides
/// two 'queues' for identifiers of message channels.
pub trait FlowControlQueues {
    fn set_pending(&self, id: TaskId);

    fn set_ready(&self, id: TaskId);

    fn next_ready(&self) -> TaskId;

    fn set_ready_waker(&self, waker: &Waker);
}
