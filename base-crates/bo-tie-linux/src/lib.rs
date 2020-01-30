#![feature(arbitrary_self_types)]

use bo_tie::hci::{
    events,
    common::ConnectionHandle,
    HciAclData,
};
use std::collections::HashMap;
use std::default;
use std::error;
use std::fmt;
use std::ops::Drop;
use std::option::Option;
use std::pin::Pin;
use std::sync::{Arc,Mutex};
use std::task;
use std::thread;
use std::time::Duration;
use std::os::unix::io::RawFd;

macro_rules! lock {
    ($( $mutex:ident ).*) => {
        $($mutex).*.lock().map_err(|e| Error::MPSCError(e.to_string()))?
    }
}

macro_rules! log_error_and_panic {
    ($($arg:tt)+) => {{ log::error!( $($arg)+ ); panic!( $($arg)+ ); }}
}

mod device;
mod timeout;

#[derive(Debug,PartialEq,Eq)]
pub struct FileDescriptor(RawFd);

impl Drop for FileDescriptor {
    fn drop(&mut self) {
        use nix::unistd::close;

        close(self.0).unwrap();
    }
}

#[derive(Debug,PartialEq,Eq,Clone)]
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

mod event;

/// For Epoll, a value is assigned to signify what file descriptor had an event occur.
/// * 0 -> BluetoothController,
/// * 1 -> TaskExit,
/// * else -> Timeout
enum EPollResult {
    BluetoothController,
    TaskExit,
    Timeout(u64),
}

impl EPollResult {
    const TIMEOUT_ID_START: u64 = 2;

    fn make_timeout_id(timeout_fd: RawFd) -> u64 {
        // The (ch)easy way to make unique id's for the timeouts
        timeout_fd as u64 + Self::TIMEOUT_ID_START
    }
}

impl From<u64> for EPollResult {
    fn from(val: u64) -> Self {
        match val {
            0 => EPollResult::BluetoothController,
            1 => EPollResult::TaskExit,
            _ => EPollResult::Timeout(val),
        }
    }
}

impl From<EPollResult> for u64 {
    fn from(epr: EPollResult) -> Self {
        match epr {
            EPollResult::BluetoothController => 0,
            EPollResult::TaskExit => 1,
            EPollResult::Timeout(val) => val,
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

impl fmt::Display for Error  {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        write!(f, "(from base-crate: bo-tie-linux) ")?;

        match *self {
            Error::EventNotSentFromController(ref reason) =>
                write!(f, "Event not sent from controller {}", reason),

            Error::IOError(ref errno) => write!(f, "IO error: {}", errno ),

            Error::MPSCError(ref msg) => write!(f, "{}", msg ),

            Error::Timeout => write!(f, "Timeout Occurred"),

            Error::Other( ref msg) => write!(f, "{}", msg),
        }
    }
}

impl error::Error for Error  {
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

impl From<nix::Error> for Error  {
    fn from( e: nix::Error ) -> Self {
        Error::IOError(e)
    }
}

impl From<nix::errno::Errno> for Error {
    fn from( e: nix::errno::Errno ) -> Self {
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
}

impl core::convert::TryFrom<u8> for CtrlMsgType {
    type Error = ();

    fn try_from(raw: u8) -> Result<Self, ()> {
        match raw {
            0x01 => Ok(CtrlMsgType::Command),
            0x02 => Ok(CtrlMsgType::ACLData),
            0x03 => Ok(CtrlMsgType::SyncData),
            0x04 => Ok(CtrlMsgType::Event),
            _ => Err(())
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
        }
    }
}


struct AdapterThread {
    adapter_fd: ArcFileDesc,
    exit_fd: ArcFileDesc,
    epoll_fd: ArcFileDesc,
    event_processor: event::EventProcessor,
    timeout_manager: Arc<Mutex<timeout::TimeoutManager>>,
    hci_data_recv: RcvHciAclData,
}

impl AdapterThread {

    /// Spawn self
    fn spawn(self) -> thread::JoinHandle<()> {
        thread::spawn( move || {
            self.task();
        })
    }

    /// Ignores the Unix errors EAGAIN and EINTR
    fn ignore_eagain_and_eintr<F,R>( mut func: F ) -> Result<R, Error>
        where F: FnMut() -> Result<R, Error>
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
            break result
        }
    }

    /// Task for processing HCI messages from the controller
    ///
    /// This functions takes that data from the controller and splits it up into different
    /// processors based on the HCI message type. Only Events, ACL data, and Syncronous data messages
    /// have processors since they are the only messages from the controller. This task forever
    /// polls the device id of the adapter to wait for
    ///
    /// This task can only exit by closing the device or timeout file descriptors.
    fn task(mut self) {
        use nix::sys::epoll;
        use nix::unistd::read;

        // Buffer used for receiving data.
        let mut buffer = [0u8; 1024];

        'task: loop {

            let epoll_events = &mut [epoll::EpollEvent::empty();256];

            let event_count = match Self::ignore_eagain_and_eintr( || {

                epoll::epoll_wait(self.epoll_fd.raw_fd(), epoll_events, -1).map_err(|e| {
                    Error::from(e)
                })

            }) {
                Ok(size) => size,
                Err(e) => panic!("Epoll Error: {}", Error::from(e)),
            };

            for epoll_event in epoll_events[..event_count].iter() {
                match EPollResult::from(epoll_event.data()) {
                    EPollResult:: BluetoothController => {

                        // received the data
                        let len = match Self::ignore_eagain_and_eintr( || {
                            read( self.adapter_fd.raw_fd(), &mut buffer).map_err( |e| { Error::from(e) })
                        }) {
                            Ok(val) => val,
                            Err(e)  => panic!("Cannot read from Bluetooth Controller file descriptor: {}", Error::from(e)),
                        };

                        // The first byte is the indicator of the mssage type, next byte is the length of the
                        // message, the rest is the hci message
                        //
                        // Any other values are logged (debug level) and then ignored (including
                        // the sometimes manufacture specific 0xFF value)
                        if let Ok(msg) = core::convert::TryInto::try_into(buffer[0])
                        {
                            match msg {
                                CtrlMsgType::Command => {
                                    panic!("Received a command message, the HCI adapter task should \
                                        only receive ACL, Syncronous, or Event Data from a controller")
                                },
                                CtrlMsgType::Event => {
                                    log::trace!("Processing received HCI data, type:'Event'");
                                    self.event_processor.process(&buffer[1..len])
                                },
                                CtrlMsgType::ACLData => {
                                    log::trace!("Processing received HCI data, type:'ACL DATA'");
                                    match HciAclData::from_packet(&buffer[1..len]) {
                                        Ok(hci_acl_data) => self.hci_data_recv.add_received(hci_acl_data),
                                        Err(e) => log::error!("Failed to process hci acl packet: {}", e),
                                    }
                                },
                                CtrlMsgType::SyncData => { log::error!("SCO data unimplemented")},
                            }

                            std::thread::yield_now();
                        } else {
                            log::warn!("Received unknown packet indicator type '{:#x}", buffer[0])
                        }
                    },

                    EPollResult::TaskExit => {
                        // Clear the block for the main task
                        read( self.exit_fd.raw_fd(), &mut [0u8;8]).unwrap();
                        break 'task;
                    },

                    EPollResult::Timeout(id) => {
                        let timeout = self.timeout_manager.lock().expect("Missing Timeout").remove(id).unwrap();

                        timeout.trigger().unwrap();
                    },
                }
            }
        }
    }
}

/// Bluetooth Host Controller Interface Adapter
///
/// Interfacing with the Bluetooth radio is done through an interface labeled as an adapter. This
/// is the structure used to handle the Host Controller Interface (HCI) as specified in the
/// Bluetooth specification.
///
/// Each Bluetooth adapter (if there is any) is assigned an identifier (just a number) by your
/// system.
#[derive(Clone,Debug)]
pub struct HCIAdapter {
    adapter_fd: ArcFileDesc,
    exit_fd: ArcFileDesc,
    epoll_fd: ArcFileDesc,
    event_expecter: Arc<Mutex<event::EventExpecter>>,
    timeout_manager: Arc<Mutex<timeout::TimeoutManager>>,
    hci_data_recv: RcvHciAclData,
}

impl From<usize> for HCIAdapter {

    /// Create a HCIAdapter with the given bluetooth adapter id if an adapter exists
    ///
    /// Call "default" if the device id is unknown or any adapter is acceptable
    ///
    /// # Panics
    /// There is no Bluetooth Adapter with the given device id
    fn from( adapter_id: usize ) -> Self {

        use nix::sys::eventfd::{EfdFlags, eventfd};
        use nix::libc;
        use nix::sys::epoll::{
            epoll_create1,
            epoll_ctl,
            EpollCreateFlags,
            EpollOp,
            EpollEvent,
            EpollFlags,
        };

        use std::convert::TryInto;

        let device_fd = unsafe{ libc::socket(libc::AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, device::BTPROTO_HCI) };

        if device_fd < 0 {
            panic!("No Bluetooth Adapter with device id {} exists", adapter_id);
        }

        let sa_p = &device::sockaddr_hci {
            hci_family: libc::AF_BLUETOOTH as u16,
            hci_dev: adapter_id as u16,
            hci_channel: device::HCI_CHANNEL_USER as u16,
        } as *const device::sockaddr_hci as *const libc::sockaddr;

        let sa_len = std::mem::size_of::<device::sockaddr_hci>() as libc::socklen_t;

        if let Err(e) = unsafe{ device::hci_dev_down(device_fd, adapter_id.try_into().unwrap() ) } {
            panic!("Failed to close hci device '{}', {}", adapter_id, e );
        }

        if let Err(e) = unsafe{ device::hci_dev_up(device_fd, adapter_id.try_into().unwrap() ) } {
            panic!("Failed to open hci device '{}', {}", adapter_id, e );
        }

        if let Err(e) = unsafe{ device::hci_dev_down(device_fd, adapter_id.try_into().unwrap() ) } {
            panic!("Failed to close hci device '{}', {}", adapter_id, e );
        }

        if unsafe{ libc::bind(device_fd, sa_p, sa_len) } < 0 {
            panic!("Failed to bind to HCI: {}", nix::errno::Errno::last() );
        }

        let exit_evt_fd = eventfd(0, EfdFlags::EFD_CLOEXEC).expect("eventfd failed");

        let epoll_fd = epoll_create1(EpollCreateFlags::EPOLL_CLOEXEC).expect("epoll_create1 failed");

        epoll_ctl(
            epoll_fd,
            EpollOp::EpollCtlAdd,
            device_fd,
            &mut EpollEvent::new(EpollFlags::EPOLLIN, EPollResult::BluetoothController.into())
        ).expect("epoll_ctl failed");

        epoll_ctl(
            epoll_fd,
            EpollOp::EpollCtlAdd,
            exit_evt_fd,
            &mut EpollEvent::new(EpollFlags::EPOLLIN, EPollResult::TaskExit.into())
        ).expect("epoll_ctl failed");

        let arc_adapter_fd = ArcFileDesc::from(device_fd);
        let arc_exit_fd = ArcFileDesc::from(exit_evt_fd);
        let arc_epoll_fd = ArcFileDesc::from(epoll_fd);

        let (event_expecter, event_processor) = event::EventSetup::setup();

        let to_manager = Arc::new(Mutex::new(timeout::TimeoutManager::new()));

        let data_receiver = RcvHciAclData::new();

        AdapterThread {
            adapter_fd: arc_adapter_fd.clone(),
            exit_fd: arc_exit_fd.clone(),
            epoll_fd: arc_epoll_fd.clone(),
            event_processor,
            timeout_manager: to_manager.clone(),
            hci_data_recv: data_receiver.clone(),
        }
        .spawn();

        HCIAdapter {
            adapter_fd: arc_adapter_fd,
            exit_fd: arc_exit_fd,
            epoll_fd: arc_epoll_fd,
            event_expecter,
            timeout_manager: to_manager,
            hci_data_recv: data_receiver,
        }
    }
}

/// Create a HCIAdapter object with the first bluetooth adapter returned by the system
///
/// # Panics
/// * No bluetooth adapter exists on the system
/// * The system couldn't allocate another file descriptor for the device
impl default::Default for HCIAdapter {

    fn default() -> Self {

        let adapter_id = device::hci::get_dev_id(None)
            .expect("No Bluetooth adapter found on this system");

        HCIAdapter::from(adapter_id)
    }
}

impl Drop for HCIAdapter {

    fn drop(&mut self) {
        // Send the exit signal.
        // The value sent doesn't really matter (just that it is 8 bytes, not 0, and not !0 )
        nix::unistd::write( self.exit_fd.raw_fd(), &[1u8;8]).unwrap();
    }
}

impl bo_tie::hci::HostControllerInterface for HCIAdapter {

    type SendCommandError = Error;
    type ReceiveEventError = Error;

    /// Send a command to the controller
    ///
    /// If there is no error, this function always returns true, which is why the waker parameter
    /// isn't used. Overflowing the Bluetooth Controller buffer is sort of an accomplishment on linux...
    fn send_command<D,W>(&self, cmd_data: &D, _: W) -> Result<bool, Self::SendCommandError>
    where D: bo_tie::hci::CommandParameter,
          W: Into<Option<std::task::Waker>>
    {
        use std::mem::size_of;

        log::debug!("Sending command {:?}", D::COMMAND);

        let oc_pair = D::COMMAND.as_opcode_pair();

        log::trace!("ogf: {:x}", oc_pair.get_ogf());
        log::trace!("ocf: {:x}", oc_pair.get_ocf());
        log::trace!("parameter size: {}", size_of::<D::Parameter>());
        log::trace!("parameter: {:x?}", unsafe { std::slice::from_raw_parts(&cmd_data.get_parameter() as *const D::Parameter as *mut u8, size_of::<D::Parameter>()) });

        // send the command
        device::hci::send_command(&self.adapter_fd.0, cmd_data)
            .map(|_| true)
            .map_err(|e| Error::from(e))
    }

    fn receive_event<P>(&self,
        event: events::Events,
        waker: &task::Waker,
        matcher: Pin<Arc<P>>,
        timeout: Option<Duration>)
    -> Option<Result<events::EventsData, Self::ReceiveEventError>>
    where P: bo_tie::hci::EventMatcher + Send + Sync + 'static
    {
        let timeout_builder = match timeout {
            Some(duration) => match timeout::TimeoutBuilder::new(
                    self.epoll_fd.clone(),
                    duration,
                    self.timeout_manager.clone() )
                {
                    Ok(val) => Some(val),
                    Err(e) => return Some(Err(e)),
                },
            None => None,
        };

        event::EventExpecter::expect_event(
            self.event_expecter.clone(),
            event,
            waker,
            matcher,
            timeout_builder
        )
    }
}

impl bo_tie::hci::HciAclDataInterface for HCIAdapter {

    type SendAclDataError = nix::Error;
    type ReceiveAclDataError = String;

    fn send(&self, data: HciAclData) -> Result<usize, Self::SendAclDataError> {
        use nix::sys::uio;
        use nix::sys::socket;

        let packet_indicator = &[ CtrlMsgType::ACLData.into() ];

        let packet_data = &data.get_packet();

        let io_vec = &[uio::IoVec::from_slice(packet_indicator), uio::IoVec::from_slice(packet_data)];

        let flags = socket::MsgFlags::MSG_DONTWAIT;

        socket::sendmsg(self.adapter_fd.raw_fd(), io_vec, &[], flags, None)
    }

    fn start_receiver(&self, handle: ConnectionHandle) {
        self.hci_data_recv.add_connection_handle(handle, StayAround::Unlimited);
    }

    fn stop_receiver(&self, handle: &ConnectionHandle) {
        self.hci_data_recv.remove_connection_handle(handle);
    }

    fn receive(&self, handle: &ConnectionHandle, waker: &task::Waker)
    -> Option<Result<Vec<HciAclData>, Self::ReceiveAclDataError>>
    {
        self.hci_data_recv.get_received(handle, waker)
    }
}

/// Stay around flag for received data
///
/// This is used to determine the state of the received ACL data. There are 3 states
/// - `Unlimited`: Their is an 'unlimited' number of *saved* packets
/// - `Limited`: A limited number of received packets are saved, after the limit is reached, a
///              new packet causes the oldest packet to be dropped. This is a ring buffer, but
///              `Limited` only stores a few number of packets at a time.
///
///              `Limited` can be upgraded to `Unlimited` without packet loss.
///
///              The associated value with `Limited` is the index of the start of the circle buffer
#[derive(Debug,PartialEq,Eq,Clone,Copy)]
enum StayAround {
    Unlimited,
    Limited,
}

#[derive(Debug)]
enum PacketBuffer {
    /// A circle buffer for limited storage of packets
    ///
    /// The associated `usize` is the index of the start of the ring.
    Limited(Vec<HciAclData>, usize),
    /// Unlimited storage
    Unlimited(Vec<HciAclData>),
}

impl PacketBuffer {

    fn make_unlimited(&mut self) {
        match self {
            Self::Limited(r_buff,start) => {

                *self = if *start == 0 {
                    Self::Unlimited(std::mem::replace(r_buff, Vec::new()))
                } else {
                    let mut v = r_buff.split_off(*start);

                    v.append(r_buff);

                    Self::Unlimited(v)
                }
            },
            _ => (),
        }
    }

    fn into_unlimited(mut self) -> Self {
        self.make_unlimited();
        self
    }

    fn add(&mut self, data: HciAclData) {
        match self {
            Self::Unlimited(ref mut v) => v.push(data),
            Self::Limited(ref mut v, ref mut size) => {
                if v.capacity() == v.len() {
                    v[*size] = data;
                   *size = (*size + 1) % v.len()
                } else {
                    v.push(data);
                }
            }
        }
    }
}

#[derive(Debug)]
struct ConnectionRecvInfo {
    received_packets: PacketBuffer,
    waker: Option<task::Waker>,
}

impl ConnectionRecvInfo {

    const LIMITED_CAPACITY:usize = 100;

    /// Create a new ConnectionRecvInfo
    ///
    /// The `stay` input is used to indicate if this should continue to exist after data is taken
    /// from it. The `stay` flag is used by
    /// [`RcvHciAclData`](RcvHciAclData).
    fn new(stay_around: StayAround) -> Self {
        ConnectionRecvInfo {
            received_packets: match stay_around {
                StayAround::Unlimited => PacketBuffer::Unlimited(Vec::new()),
                StayAround::Limited => PacketBuffer::Limited(Vec::with_capacity(Self::LIMITED_CAPACITY), 0),
            },
            waker: None,
        }
    }

    /// Set the waker
    ///
    /// This will set the waker and upgrade the packet buffer to `Unlimited`
    fn set_waker(&mut self, waker: &task::Waker) {
        self.waker = Some(waker.clone());
        self.received_packets.make_unlimited();
    }

    /// Get the next packet or set the waker
    ///
    /// This either returns all received packets or sets the waker and returns None.
    ///
    /// Regardless of the operation, the packet buffer is upgraded to `Unlimited`
    fn get_data_or_set_waker(&mut self, waker: &task::Waker ) -> Option<Vec<HciAclData>> {

        let recv_packs = match core::mem::replace(
            &mut self.received_packets,
            PacketBuffer::Unlimited(Vec::new()) )
            .into_unlimited()
        {
            PacketBuffer::Unlimited(v) => v,
            _ => panic!("Received unexpected Limited"),
        };

        match recv_packs.len() {
            0 => { self.waker = Some(waker.clone()); None},
            _ => Some(recv_packs)
        }
    }

    /// Add data
    fn add(&mut self, data: HciAclData ) {

        self.received_packets.add(data);

        if let Some(w) = self.waker.take() { w.wake(); }
    }

    fn using_limited_buffer(&self) -> bool {
        match self.received_packets { PacketBuffer::Limited(_,_) => true, _ => false }
    }
}

type AclDataChannels = HashMap<ConnectionHandle, ConnectionRecvInfo>;

/// A structure for managing the reception of hci acl data packets for use with futures
#[derive(Debug,Clone)]
struct RcvHciAclData {
    receive_channels: Arc<Mutex<AclDataChannels>>
}

impl RcvHciAclData {

    fn new() -> Self {
        RcvHciAclData { receive_channels: Arc::new( Mutex::new( AclDataChannels::new() )) }
    }

    /// Add a buffer to associated with `handle` for receiving ACL data
    ///
    /// This will create a buffer that will stay around to collect ACL data packets even when there
    /// is no waker to wake a pending task to receive the received data.
    ///
    /// Only one buffer is set per handle. Calling this multiple of times doesn't drop the buffer,
    /// however it may upgrade the buffer from `Limited` to `Unlimited` (but not the reverse).
    ///
    /// Any previously set waker is dropped.
    ///
    /// If an unlimited buffer already exists for the privided handle it cannot be downgraded
    /// into a limited buffer. The buffer must be removed (with `remove_connection_handle`)
    /// and then a *new* limited buffer can be made with this funciton.
    fn add_connection_handle(&self, handle: ConnectionHandle, flag: StayAround) {
        self.receive_channels.lock().as_mut()
            .map( |rc| if let Some(rcv_info) = rc.get_mut(&handle) {
                    if flag == StayAround::Unlimited {
                        rcv_info.received_packets.make_unlimited()
                    }
                } else {
                    rc.insert(handle, ConnectionRecvInfo::new(flag));
                })
            .or_else( |e| -> Result<_,()> { log_error_and_panic!("Failed to acquire lock: {}", e) })
            .ok();
    }

    /// Remove the buffer associated with `handle`
    ///
    /// This needs to be called to delete the buffer created by `add_connection_handle`
    ///
    /// This should also be called for any buffer that was created by `get_received`, but in not
    /// deleted by another call to `get_received`.
    fn remove_connection_handle(&self, handle: &ConnectionHandle) {
        self.receive_channels.lock().as_mut()
            .and_then( |rc| Ok( rc.remove( &handle) ) )
            .or_else( |e| -> Result<_,()> { log_error_and_panic!("Failed to acquire lock: {}", e) })
            .ok();
    }

    /// Try to get a received packet
    ///
    /// If there is a packet to be received for the provided connection handle, then an HciAclData
    /// packet will be returned. If there are no packets to be received, then no packet is returned
    /// but the provided waker will be used when a packet is ready to be received. Whoever is woken
    /// will need to call this function again to get the received data. If data is returned, the
    /// provided waker is ignored.
    fn get_received( &self, handle: &ConnectionHandle, waker: &task::Waker )
    -> Option< Result<Vec<HciAclData>, String> >
    {
        let mut rc_gaurd = match self.receive_channels.lock() {
            Ok(gaurd) => gaurd,
            Err(e) => log_error_and_panic!("Failed to acquire 'receive_channels' lock: {}", e),
        };

        let opt_data = rc_gaurd.get_mut(handle);

        let mut remove_cri = false;

        let ret = if opt_data.is_some() { // If the buffer exists then check if there is any data
            opt_data.and_then( |ri|
                ri.get_data_or_set_waker( waker )
                    .and_then( |d| {
                        Some(Ok(d))
                    })
                    .and_then( |ret| {
                        remove_cri = ri.using_limited_buffer();
                        Some(ret)
                    })
            )
        } else { // The buffer doesn't exist, so create an Limited buffer
            let mut cri = ConnectionRecvInfo::new(StayAround::Limited);
            cri.set_waker(waker);
            rc_gaurd.insert( *handle, cri);
            None
        };

        // The handle is associated with a temporary buffer so it should be deleted
        if remove_cri { rc_gaurd.remove(handle); }

        ret
    }

    /// Add a received packet
    ///
    /// This is used by the
    /// [`AdapterThread`](AdapterThread)
    /// to add ACL Data packets that were received from the controller.
    fn add_received( &self, packet: HciAclData ) {
        match self.receive_channels.lock().as_mut()
        {
            Ok( rc ) => {

                let handle = *packet.get_handle();

                if let Some(recv_info) = rc.get_mut(&handle) {
                    recv_info.add( packet )
                } else {
                    let mut recv_info = ConnectionRecvInfo::new(StayAround::Limited);

                    recv_info.add( packet );

                    rc.insert(handle, recv_info);
                }
            }
            Err(lock_e) =>
                log_error_and_panic!("Failed to acquire lock: {}", lock_e),
        }
    }
}

/// A token to keep track of what waker (from futres), if any, should be triggered when an event
/// is received from the bluetooth controller
///
/// An instance must be wrapped in Arc-Mutex/RwLock to be multi-thread safe (per the usual)
#[derive(Clone,Debug)]
struct WakerToken {
    waker: Option<task::Waker>,
    waker_triggered: bool,
}

impl WakerToken {

    /// Trigger the waker if there is a waker.
    ///
    /// A trigger flag is set by this method to indicate to the method set_waker that it needs
    /// to immediately call the wake method of its waker paramter.
    fn trigger(&mut self) {

        self.waker_triggered = true;

        if let Some(waker) = self.waker.take() {
            log::debug!("Invoking Context waker");
            waker.wake()
        }
    }

    /// Determine if the trigger method was called or an error occured
    fn triggered(&self) -> bool {
        self.waker_triggered
    }
}

impl From<task::Waker> for WakerToken {

    /// Create a default waker token. No Waker object is supplied so instead the function
    /// triggered must be checked to see if trigger was called.
    fn from(waker: task::Waker) -> Self {
        WakerToken {
            waker: Some(waker),
            waker_triggered: false,
        }
    }
}
