//! An implementation of an interface for Linux
//!
//! Linux has a driver for the interface to the controller to provide a standard means of
//! communication. This interface interacts with that driver for communication with a Bluetooth
//! controller on the system.
//!

use bo_tie_hci_util::{ChannelReserve, HciPacket, HciPacketType, HostChannelEnds};
use std::collections::HashMap;
use std::error;
use std::fmt;
use std::future::Future;
use std::ops::Drop;
use std::option::Option;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task;
use std::thread;
use tokio::sync::mpsc::{error::SendError, UnboundedReceiver, UnboundedSender};

macro_rules! log_error_and_panic {
    ($($arg:tt)+) => {{ log::error!( $($arg)+ ); panic!( $($arg)+ ); }}
}

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
    IOError(nix::Error),
    MPSCError(String),
    Timeout,
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(from base-crate: bo-tie-linux) ")?;

        match *self {
            Error::EventNotSentFromController(ref reason) => write!(f, "Event not sent from controller {}", reason),

            Error::IOError(ref errno) => write!(f, "IO error: {}", errno),

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
            Error::IOError(ref errno) => errno.source().clone(),
            Error::MPSCError(_) => None,
            Error::Timeout => None,
            Error::Other(_) => None,
        }
    }
}

impl From<nix::Error> for Error {
    fn from(e: nix::Error) -> Self {
        Error::IOError(e)
    }
}

impl From<nix::errno::Errno> for Error {
    fn from(e: nix::errno::Errno) -> Self {
        Error::IOError(nix::Error::Sys(e))
    }
}

/// Controller Message type
///
/// The way to differentiate between messages over the HCI
enum CtrlMsgType {
    Command,
    Event,
    ACLData,
    SyncData,
    IsoData,
}

impl core::convert::TryFrom<u8> for CtrlMsgType {
    type Error = ();

    fn try_from(raw: u8) -> Result<Self, ()> {
        match raw {
            0x01 => Ok(CtrlMsgType::Command),
            0x02 => Ok(CtrlMsgType::ACLData),
            0x03 => Ok(CtrlMsgType::SyncData),
            0x04 => Ok(CtrlMsgType::Event),
            0x05 => Ok(CtrlMsgType::IsoData),
            _ => Err(()),
        }
    }
}

impl From<CtrlMsgType> for u8 {
    fn from(raw: CtrlMsgType) -> u8 {
        match raw {
            CtrlMsgType::Command => 0x01,
            CtrlMsgType::ACLData => 0x02,
            CtrlMsgType::SyncData => 0x03,
            CtrlMsgType::Event => 0x04,
            CtrlMsgType::IsoData => 0x05,
        }
    }
}

struct AdapterThread<C> {
    sender: UnboundedSender<HciPacket<Vec<u8>>>,
    adapter_fd: ArcFileDesc,
    exit_fd: ArcFileDesc,
    epoll_fd: ArcFileDesc,
}

impl<C: ChannelReserve> AdapterThread<C> {
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
        use nix::errno::Errno;

        loop {
            let result = func();

            if let Err(ref err) = &result {
                if let Error::IOError(nix_err) = err {
                    if let nix::Error::Sys(err_val) = nix_err {
                        if *err_val == Errno::EAGAIN || *err_val == Errno::EINTR {
                            continue;
                        }
                    }
                }
            }
            break result;
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
        use std::convert::TryFrom;

        // The first byte is the indicator of the message type, next byte is the
        // length of the message, the rest is the hci message
        //
        // Any other values are logged (debug level) and then ignored (including
        // the manufacture specific 0xFF value)
        if let Some(Ok(msg)) = msg.get(0).map(CtrlMsgType::try_from) {
            let packet = match msg {
                CtrlMsgType::Command => HciPacket::Command(msg[1..].to_vec()),
                CtrlMsgType::Event => HciPacket::Event(msg[1..].to_vec()),
                CtrlMsgType::ACLData => HciPacket::Acl(msg[1..].to_vec()),
                CtrlMsgType::SyncData => HciPacket::Sco(msg[1..].to_vec()),
                CtrlMsgType::IsoData => HciPacket::Iso(msg[1..].to_vec()),
            };

            self.sender.send(packet)
        } else {
            log::debug!("Received unknown packet indicator type '{:#x}", buffer[0]);

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
/// # use tokio::spawn;
/// use bo_tie_linux::LinuxInterface;
///
/// // There is only one Bluetooth Controller
/// let interface = LinuxInterface::default();
/// ```
/// [`run`]: LinuxInterface::run
#[derive(Clone, Debug)]
pub struct LinuxInterface {
    adapter_fd: ArcFileDesc,
    exit_fd: ArcFileDesc,
    epoll_fd: ArcFileDesc,
    receiver: UnboundedReceiver<HciPacket<Vec<u8>>>,
}

impl LinuxInterface {
    /// Create a `LinuxInterface`
    ///
    /// The input `adapter_id` is the identifier of the adapter for the Bluetooth Controller. If
    /// there is only one Bluetooth Controller or any adapter will work `None` can be used to
    /// automatically select an adapter.
    pub fn new<T>(adapter_id: T) -> Self
    where
        T: Into<Option<usize>>,
    {
        match adapter_id.into() {
            Some(id) => Self::from(id),
            None => Self::default(),
        }
    }

    /// Run the interface
    ///
    /// This begins the
    pub fn run(mut self) -> (impl Future + Send, impl HostChannelEnds) {
        let (reserve, host_ends) = bo_tie_hci_util::channel::tokio_unbounded();

        let mut interface = bo_tie_hci_interface::Interface::new(reserve);

        let task = async move {
            loop {
                tokio::select! {
                    packet = self.receiver.recv() => match &packet {
                        Some(packet) => interface.up_send(packet).await,
                        None => break,
                    }
                    packet = interface.down_send() => {
                        device::hci::send_command(&self.adapter_fd.0, cmd_data)
                            .map(|_| true)
                            .map_err(|e| Error::from(e))
                    }
                }
            }
        };

        (task, host_ends)
    }
}

impl From<usize> for LinuxInterface {
    /// Create a HCIAdapter with the given bluetooth adapter id if an adapter exists
    ///
    /// Call "default" if the device id is unknown or any adapter is acceptable
    ///
    /// # Panics
    /// There is no Bluetooth Adapter with the given device id
    fn from(adapter_id: usize) -> Self {
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

        AdapterThread {
            sender,
            adapter_fd: arc_adapter_fd.clone(),
            exit_fd: arc_exit_fd.clone(),
            epoll_fd: arc_epoll_fd.clone(),
        }
        .spawn();

        LinuxInterface {
            adapter_fd: arc_adapter_fd,
            exit_fd: arc_exit_fd,
            epoll_fd: arc_epoll_fd,
            receiver,
        }
    }
}

/// Create a HCIAdapter object with the first bluetooth adapter returned by the system
///
/// # Panics
/// * No bluetooth adapter exists on the system
/// * The system couldn't allocate another file descriptor for the device
impl Default for LinuxInterface {
    fn default() -> Self {
        let adapter_id = device::hci::get_dev_id(None).expect("No Bluetooth adapter found on this system");

        LinuxInterface::from(adapter_id)
    }
}

impl Drop for LinuxInterface {
    fn drop(&mut self) {
        // Send the exit signal.
        // The value sent doesn't really matter (just that it is 8 bytes, not 0, and not !0 )
        nix::unistd::write(self.exit_fd.raw_fd(), &[1u8; 8]).unwrap();
    }
}
