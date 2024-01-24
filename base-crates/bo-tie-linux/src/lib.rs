//! An implementation of an interface for Linux
//!
//! Linux has a driver for the interface to the controller to provide a standard means of
//! communication. This interface interacts with that driver for communication with a Bluetooth
//! controller on the system.
//!
//! Communication with the Bluetooth Controller is done through an interface driver called an
//! 'adapter'. This adapter is labeled by an identifier number unique to your machine. This number
//! is required for creating a `LinuxInterface`. Once a `LinuxInterface` is created it must then be [`run`] by
//! an executor to begin communication with the adapter.
//!
//! Most of the time there is not multiple Bluetooth controllers connected as adapters to a single
//! machine. The implementation of `Default` for `LinuxInterface` will randomly select the first
//! adapter it finds on the machine, which is fine if there is only one Adapter. The same thing is
//! true if `None` is input for method `new`.
//!
//! # Super User
//! One of the more annoying things is that this library requires *capabilities* in order to work.
//! If you try to call `new_user` without having the correct *capabilities* it will panic with the
//! the error `EPERM`. The easiest way around this is to build your application and then run it with
//! `sudo`, but the other way is to give the build the capability `cap_net_admin`.
//!
//! ```
//! // Create a new interface to a Bluetooth Adapter
//! let (interface_task, host_ends) = bo_tie_linux::new_hci(None);
//!
//! let host_task = async move {
//!     bo_tie::hci::Host::init(host_ends);
//!
//!     //.. your task
//! };
//!
//! // This example uses tokio as an executor,
//! // but any executor will work
//! tokio::spawn(interface_task.run());
//! tokio::spawn(host_task);
//! ```
//! [`run`]: LinuxInterface::run
//!

#[cfg(feature = "ctrls_intf")]
pub use crate::device::ControllersInterface;
use bo_tie_core::buffer::Buffer;
use bo_tie_hci_util::{ChannelReserve, HciPacket};
use std::os::fd::RawFd;
use std::sync::Arc;
use tokio::sync::mpsc::{error::SendError, UnboundedReceiver, UnboundedSender};

mod device;

#[derive(Debug, Clone)]
pub struct ArcFileDesc(Arc<std::os::fd::OwnedFd>);

impl std::os::fd::FromRawFd for ArcFileDesc {
    unsafe fn from_raw_fd(raw_fd: RawFd) -> Self {
        ArcFileDesc(Arc::new(std::os::fd::FromRawFd::from_raw_fd(raw_fd)))
    }
}

impl std::os::fd::AsRawFd for ArcFileDesc {
    fn as_raw_fd(&self) -> RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.0)
    }
}

impl std::os::fd::AsFd for ArcFileDesc {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.0)
    }
}

impl From<std::os::fd::OwnedFd> for ArcFileDesc {
    fn from(owned_fd: std::os::fd::OwnedFd) -> Self {
        ArcFileDesc(Arc::new(owned_fd))
    }
}

/// For Epoll, a value is assigned to signify what file descriptor had an event occur.
/// * 0 -> BluetoothController,
/// * 1 -> TaskExit,
/// * else -> Timeout
enum PollEvent {
    BluetoothController,
    TaskExit,
}

impl From<u64> for PollEvent {
    fn from(val: u64) -> Self {
        match val {
            0 => PollEvent::BluetoothController,
            1 => PollEvent::TaskExit,
            _ => panic!("Invalid EPollResult '{}'", val),
        }
    }
}

impl From<PollEvent> for nix::sys::epoll::EpollEvent {
    fn from(epr: PollEvent) -> Self {
        match epr {
            PollEvent::BluetoothController => nix::sys::epoll::EpollEvent::new(nix::sys::epoll::EpollFlags::EPOLLIN, 0),
            PollEvent::TaskExit => nix::sys::epoll::EpollEvent::new(nix::sys::epoll::EpollFlags::EPOLLIN, 1),
        }
    }
}

/// A struct for creating a thread to directly interface with the Bluetooth controller
///
/// This is used to create a thread to be a middle man between the Linux operating system and the the async executor
/// running the application using the bo-tie library.
struct InterfaceThread {
    sender: UnboundedSender<HciPacket<Vec<u8>>>,
    controller_socket: ArcFileDesc,
    _exit_event: ArcFileDesc,
    epoll: nix::sys::epoll::Epoll,
}

impl InterfaceThread {
    /// Spawn self
    fn spawn(self) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            self.task();
        })
    }

    /// Task for processing HCI messages from the controller
    ///
    /// This functions takes that data from the controller and splits it up into different
    /// processors based on the HCI message type. Only Events, ACL data, and Syncronous data messages
    /// have processors since they are the only messages from the controller. This task forever
    /// polls the device id of the adapter to wait for
    ///
    /// This task can only exit by closing the device.
    fn task(self) {
        self.task_inner().expect("linux interface thread panicked")
    }

    fn task_inner(mut self) -> Result<(), Box<dyn std::error::Error>> {
        use nix::sys::epoll;
        use nix::sys::socket::{recv, MsgFlags};

        // Buffer used for receiving data.
        let mut hci_rx_buffer = Vec::with_capacity(1024);

        hci_rx_buffer.resize(1024, 0);

        let epoll_events = &mut [epoll::EpollEvent::empty(); 2];

        loop {
            let event_count = self.epoll.wait(epoll_events, -1)?;

            for epoll_event in &epoll_events[..event_count] {
                match PollEvent::from(epoll_event.data()) {
                    PollEvent::BluetoothController => {
                        // using 'DONTWAIT' as `recv` returning an
                        // error is better than hanging forever.
                        let flags = MsgFlags::MSG_DONTWAIT;

                        let raw_fd = std::os::fd::AsRawFd::as_raw_fd(&self.controller_socket);

                        let rx_len = recv(raw_fd, &mut hci_rx_buffer, flags)?;

                        self.process_received_message(&hci_rx_buffer[..rx_len])?
                    }
                    PollEvent::TaskExit => return Ok(()),
                }
            }
        }
    }

    fn process_received_message(&mut self, msg: &[u8]) -> Result<(), SendError<HciPacket<Vec<u8>>>> {
        // The first byte is the indicator of the message type, next byte is the
        // length of the message, the rest is the hci message
        //
        // Any other values are logged (debug level) and then ignored (including
        // the manufacture specific 0xFF value)
        if let Ok(packet) = bo_tie_hci_interface::uart::PacketIndicator::convert(msg) {
            self.sender.send(packet.map(|slice| slice.to_vec()))
        } else {
            log::debug!("Received unknown packet indicator '{:#x}", msg[0]);

            Ok(())
        }
    }
}

/// Interface to the Linux Bluetooth drivers
///
/// Interfacing with the Bluetooth Controller is done through an interface labeled as an 'adapter'.
/// This adapter is labeled by an identifier number unique to your machine. This number is required
/// for creating a `LinuxInterface`. Once a `LinuxInterface` is created it must then be [`run`] by
/// an executor to begin communication with the adapter.
///
/// Most of the time there is not multiple Bluetooth controllers connected as adapters to a single
/// machine. The implementation of `Default` for `LinuxInterface` will randomly select the first
/// adapter it finds on the machine, which is fine if there is only one Adapter. The same thing is
/// true if `None` is input for method `new`.
///
/// ```
/// // Create a new interface to a Bluetooth Adapter
/// let (interface_task, host_ends) = bo_tie_linux::new_hci(None);
///
/// let host_task = async move {
///     bo_tie::hci::Host::init(host_ends);
///
///     //.. your task
/// };
///
/// // This example uses tokio as an executor,
/// // but any executor will work
/// tokio::spawn(interface_task.run());
/// tokio::spawn(host_task);
/// ```
/// [`run`]: LinuxInterface::run
pub struct LinuxInterface<C> {
    controller_socket: ArcFileDesc,
    exit_event: ArcFileDesc,
    receiver: UnboundedReceiver<HciPacket<Vec<u8>>>,
    interface: bo_tie_hci_interface::Interface<C>,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl<T: ChannelReserve> LinuxInterface<T> {
    /// Run the interface
    ///
    /// This launches the interface to begin processing HCI packets sent to and received from the Bluetooth Controller.
    ///
    /// # Panic
    /// This will panic if something goes wrong with the system calls to Linux.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                received = self.receiver.recv() => {
                    match &received {
                        Some(packet) => if let Err(e) = self.interface.up_send(packet).await {
                            e.try_log().expect("up send error");
                        },
                        None => {
                            // The receiver closed so the interface thread is dead.
                            // Panic if there is an error in the thread handle.
                            self.join_handle.take().unwrap().join().unwrap();

                            unreachable!("unexpected closed receiver")
                        },
                    }
                }
                opt_packet = self.interface.down_send() => {
                    match opt_packet {
                        Some(mut packet) => {
                            self.send_to_controller(&mut packet).expect("linux error");
                        }
                        None => {
                            log::debug!("interface exiting due to host closure");
                            break
                        }
                    }
                }
            }
        }
    }

    /// Send a HCI packet to the controller
    fn send_to_controller(&self, packet: &mut HciPacket<impl Buffer>) -> nix::Result<usize> {
        let raw_fd = std::os::fd::AsRawFd::as_raw_fd(&self.controller_socket);

        // UART packet indication is the same system used by the Linux kernel for labeling HCI packets.
        // This should never fail unless there is an issue within `PacketIndicator`.
        let message =
            bo_tie_hci_interface::uart::PacketIndicator::prepend(packet).expect("failed to prepend packet indicator");

        nix::sys::socket::send(raw_fd, &message, nix::sys::socket::MsgFlags::MSG_DONTWAIT)
    }
}

impl<C> Drop for LinuxInterface<C> {
    fn drop(&mut self) {
        let Some(join_handle) = self.join_handle.take() else {
            return;
        };

        let raw_fd = std::os::fd::AsRawFd::as_raw_fd(&self.exit_event);

        // Send the exit signal.
        nix::unistd::write(raw_fd, &[1u8; 8]).unwrap();

        join_handle.join().expect("failed to close task")
    }
}

/// Create a `LinuxInterface`
///
/// The input `controller_id` is an identifier of a Bluetooth Controller on this Linux machine. Its a unique number
/// assigned to a Bluetooth controller soon after the Linux OS detects the device. If you're familiar with the Bluetooth
/// management interface, the `controller_id` is equivalent to a controller index.
///
/// Using `None` for `controller_id` will use the controller with the ID equivalent to `0`. If you're unsure what
/// controller to choose, either use the `ControllersInterface` or the tools of `bluez` to discover the identifiers of
/// the controllers on the system.
///
/// # Panic
/// This will panic if Bluetooth is not supported or there is no Bluetooth controller for `controller_id` on this
/// machine.
///
/// [`ControllersInterface`]: device::ControllersInterface
pub fn new<T>(
    controller_id: T,
) -> (
    LinuxInterface<bo_tie_hci_util::channel::tokio::UnboundedChannelReserve>,
    bo_tie_hci_util::channel::tokio::UnboundedHostChannelEnds,
)
where
    T: Into<Option<u16>>,
{
    let mut controllers_interface = device::ControllersInterface::new().expect("Bluetooth not supported");

    match controller_id.into() {
        Some(id) => controllers_interface
            .create_interface(id)
            .expect("failed to use controller"),
        None => controllers_interface
            .create_interface(0)
            .expect("failed to use default controller"),
    }
}
