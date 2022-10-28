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

use bo_tie_hci_util::channel::{SendSafeChannelReserve, SendSafeHostChannelEnds};
use bo_tie_hci_util::HciPacket;
use std::error;
use std::fmt;
use std::ops::Drop;
use std::option::Option;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::thread;
use tokio::sync::mpsc::{error::SendError, UnboundedReceiver, UnboundedSender};

mod device;

#[derive(Debug, PartialEq, Eq)]
pub struct FileDescriptor(RawFd);

impl Drop for FileDescriptor {
    fn drop(&mut self) {
        use nix::unistd::close;

        close(self.0).unwrap();
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ArcFileDesc(Arc<FileDescriptor>);

impl From<RawFd> for ArcFileDesc {
    fn from(rfd: RawFd) -> Self {
        ArcFileDesc(Arc::new(FileDescriptor(rfd)))
    }
}

impl ArcFileDesc {
    fn raw_fd(&self) -> RawFd {
        (*self.0).0
    }
}

/// For Epoll, a value is assigned to signify what file descriptor had an event occur.
/// * 0 -> BluetoothController,
/// * 1 -> TaskExit,
/// * else -> Timeout
enum EPollResult {
    BluetoothController,
    TaskExit,
}

impl From<u64> for EPollResult {
    fn from(val: u64) -> Self {
        match val {
            0 => EPollResult::BluetoothController,
            1 => EPollResult::TaskExit,
            _ => panic!("Invalid EPollResult '{}'", val),
        }
    }
}

impl From<EPollResult> for u64 {
    fn from(epr: EPollResult) -> Self {
        match epr {
            EPollResult::BluetoothController => 0,
            EPollResult::TaskExit => 1,
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum Error {
    EventNotSentFromController(String),
    IoError(nix::Error),
    MPSCError(String),
    Timeout,
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(from base-crate: bo-tie-linux) ")?;

        match *self {
            Error::EventNotSentFromController(ref reason) => write!(f, "Event not sent from controller {}", reason),

            Error::IoError(ref errno) => write!(f, "IO error: {}", errno),

            Error::MPSCError(ref msg) => write!(f, "{}", msg),

            Error::Timeout => write!(f, "Timeout Occurred"),

            Error::Other(ref msg) => write!(f, "{}", msg),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::EventNotSentFromController(_) => None,
            Error::IoError(ref errno) => errno.source().clone(),
            Error::MPSCError(_) => None,
            Error::Timeout => None,
            Error::Other(_) => None,
        }
    }
}

impl From<nix::Error> for Error {
    fn from(e: nix::Error) -> Self {
        Error::IoError(e)
    }
}

struct AdapterThread {
    sender: UnboundedSender<HciPacket<Vec<u8>>>,
    adapter_fd: ArcFileDesc,
    exit_fd: ArcFileDesc,
    epoll_fd: ArcFileDesc,
}

impl AdapterThread {
    /// Spawn self
    fn spawn(self) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            self.task();
        })
    }

    /// Ignores the Unix errors EAGAIN and EINTR
    fn ignore_eagain_and_eintr<F, R>(mut func: F) -> Result<R, Error>
    where
        F: FnMut() -> Result<R, Error>,
    {
        loop {
            match func() {
                Err(Error::IoError(nix::Error::EAGAIN)) | Err(Error::IoError(nix::Error::EINTR)) => continue,
                result => break result,
            }
        }
    }

    /// Task for processing HCI messages from the controller
    ///
    /// This functions takes that data from the controller and splits it up into different
    /// processors based on the HCI message type. Only Events, ACL data, and Syncronous data messages
    /// have processors since they are the only messages from the controller. This task forever
    /// polls the device id of the adapter to wait for
    ///
    /// This task can only exit by closing the device.
    fn task(mut self) {
        use nix::sys::epoll;
        use nix::unistd::read;

        // Buffer used for receiving data.
        let mut buffer = [0u8; 1024];

        'task: loop {
            let epoll_events = &mut [epoll::EpollEvent::empty(); 256];

            let event_count = match Self::ignore_eagain_and_eintr(|| {
                epoll::epoll_wait(self.epoll_fd.raw_fd(), epoll_events, -1).map_err(|e| Error::from(e))
            }) {
                Ok(size) => size,
                Err(e) => panic!("Epoll Error: {}", Error::from(e)),
            };

            for epoll_event in epoll_events[..event_count].iter() {
                match EPollResult::from(epoll_event.data()) {
                    EPollResult::BluetoothController => {
                        // received the data
                        let len = match Self::ignore_eagain_and_eintr(|| {
                            read(self.adapter_fd.raw_fd(), &mut buffer).map_err(|e| Error::from(e))
                        }) {
                            Ok(val) => val,
                            Err(e) => panic!(
                                "Cannot read from Bluetooth Controller file descriptor: {}",
                                Error::from(e)
                            ),
                        };

                        if let Err(e) = self.process_received_message(&buffer[..len]) {
                            log::error!("failed to send message from linux driver {}", e);
                            break 'task;
                        }
                    }

                    EPollResult::TaskExit => {
                        // Clear the block for the main task
                        read(self.exit_fd.raw_fd(), &mut [0u8; 8]).unwrap();
                        break 'task;
                    }
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
    adapter_fd: ArcFileDesc,
    exit_fd: ArcFileDesc,
    receiver: UnboundedReceiver<HciPacket<Vec<u8>>>,
    interface: bo_tie_hci_interface::Interface<C>,
}

impl<T: SendSafeChannelReserve> LinuxInterface<T> {
    /// Run the interface
    ///
    /// This launches the interface to begin processing HCI packets sent to and received from the
    /// Bluetooth Controller.
    pub async fn run(mut self) {
        use device::hci::send_to_controller;

        loop {
            tokio::select! {
                received = self.receiver.recv() => {
                    match &received {
                        Some(packet) => if let Err(e) = self.interface.up_send(packet).await {
                            if let Err(e) = e.try_log() {
                                log::error!("up send error: {:?}", e);
                                break
                            };
                        },
                        None => break,
                    }
                }
                opt_packet = self.interface.down_send() => { {}
                    match opt_packet {
                        Some(mut packet) => if let Err(e) = send_to_controller(&self.adapter_fd.0, &mut packet) {
                            log::error!("unix error: {}", e);
                            break
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
}

/// Create a `LinuxInterface` from an ID for the adapter
fn from_adapter_id(
    adapter_id: usize,
) -> (
    LinuxInterface<impl SendSafeChannelReserve>,
    impl SendSafeHostChannelEnds,
) {
    use nix::libc;
    use nix::sys::epoll::{epoll_create1, epoll_ctl, EpollCreateFlags, EpollEvent, EpollFlags, EpollOp};
    use nix::sys::eventfd::{eventfd, EfdFlags};

    use std::convert::TryInto;

    let device_fd = unsafe {
        libc::socket(
            libc::AF_BLUETOOTH,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            device::BTPROTO_HCI,
        )
    };

    if device_fd < 0 {
        panic!("Bluetooth not supported on this system");
    }

    let sa_p = &device::sockaddr_hci {
        hci_family: libc::AF_BLUETOOTH as u16,
        hci_dev: adapter_id as u16,
        hci_channel: device::HCI_CHANNEL_USER as u16,
    } as *const device::sockaddr_hci as *const libc::sockaddr;

    let sa_len = std::mem::size_of::<device::sockaddr_hci>() as libc::socklen_t;

    if let Err(e) = unsafe { device::hci_dev_down(device_fd, adapter_id.try_into().unwrap()) } {
        panic!("Failed to close hci device '{}', {}", adapter_id, e);
    }

    if let Err(e) = unsafe { device::hci_dev_up(device_fd, adapter_id.try_into().unwrap()) } {
        panic!("Failed to open hci device '{}', {}", adapter_id, e);
    }

    if let Err(e) = unsafe { device::hci_dev_down(device_fd, adapter_id.try_into().unwrap()) } {
        panic!("Failed to close hci device '{}', {}", adapter_id, e);
    }

    if unsafe { libc::bind(device_fd, sa_p, sa_len) } < 0 {
        panic!("Failed to bind to HCI: {}", nix::errno::Errno::last());
    }

    let exit_evt_fd = eventfd(0, EfdFlags::EFD_CLOEXEC).expect("eventfd failed");

    let epoll_fd = epoll_create1(EpollCreateFlags::EPOLL_CLOEXEC).expect("epoll_create1 failed");

    epoll_ctl(
        epoll_fd,
        EpollOp::EpollCtlAdd,
        device_fd,
        &mut EpollEvent::new(EpollFlags::EPOLLIN, EPollResult::BluetoothController.into()),
    )
    .expect("epoll_ctl failed");

    epoll_ctl(
        epoll_fd,
        EpollOp::EpollCtlAdd,
        exit_evt_fd,
        &mut EpollEvent::new(EpollFlags::EPOLLIN, EPollResult::TaskExit.into()),
    )
    .expect("epoll_ctl failed");

    let arc_adapter_fd = ArcFileDesc::from(device_fd);
    let arc_exit_fd = ArcFileDesc::from(exit_evt_fd);
    let arc_epoll_fd = ArcFileDesc::from(epoll_fd);

    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();

    let (reserve, host_ends) = bo_tie_hci_util::channel::tokio_unbounded(1, 0);

    let interface = bo_tie_hci_interface::Interface::new(reserve);

    AdapterThread {
        sender,
        adapter_fd: arc_adapter_fd.clone(),
        exit_fd: arc_exit_fd.clone(),
        epoll_fd: arc_epoll_fd,
    }
    .spawn();

    let this = LinuxInterface {
        adapter_fd: arc_adapter_fd,
        exit_fd: arc_exit_fd,
        receiver,
        interface,
    };

    (this, host_ends)
}

impl<C> Drop for LinuxInterface<C> {
    fn drop(&mut self) {
        // Send the exit signal.
        // The value sent doesn't really matter (just that it is 8 bytes, not 0, and not !0 )
        nix::unistd::write(self.exit_fd.raw_fd(), &[1u8; 8]).unwrap();
    }
}

/// Create a `LinuxInterface`
///
/// The input `adapter_id` is the identifier of the adapter for the Bluetooth Controller. If
/// there is only one Bluetooth Controller or any adapter will work `None` can be used to
/// automatically select an adapter.
///
/// # Panic
/// This will panic if there is no Bluetooth adapter or if the `adapter_id` does not exist for
/// this machine.
pub fn new<T>(
    adapter_id: T,
) -> (
    LinuxInterface<impl SendSafeChannelReserve>,
    impl SendSafeHostChannelEnds,
)
where
    T: Into<Option<usize>>,
{
    match adapter_id.into() {
        Some(id) => from_adapter_id(id),
        None => {
            let adapter_id = device::hci::get_dev_id(None).expect("No Bluetooth adapter found on this system");

            from_adapter_id(adapter_id)
        }
    }
}
