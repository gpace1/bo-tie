//! Linux Bluetooth device functionality controller methods
//!
//! These are functions that are used to control the interface to the bluetooth devices on the
//! system. This isn't a complete implementation of control commands/operations, it is just the
//! functionality used by this library. These are linux specific and have no relation to the
//! bluetooth specification.

use bo_tie_core::buffer::Buffer;
use bo_tie_core::BluetoothDeviceAddress;
use bo_tie_hci_util::HciPacket;

#[allow(non_camel_case_types, dead_code)]
pub(crate) mod bindings;

const HCI_RAW: usize = 6;

fn test_flag(bit: usize, field: &[u32]) -> bool {
    1 == (field[bit >> 5] >> (bit as u32 & 31))
}

/// Get a file descriptor to a bluetooth controller
///
/// This will get a file descriptor for the bluetooth controller with the provided *public
/// address* (the address either hard coded or burned onto the controller). If any bluetooth
/// controller will do, then `None` can be provided to get a controller.
///
/// This will match the first device that does not contain the `HCI_RAW` flag. This flag
/// indicates that the interface is unconfigured and an unconfigured device cannot be bound
/// to with `HCI_CHANNEL_USER`
///
/// # Note
/// This function will scan a maximum 16 devices. Looking at the kernel the limit seems more
/// in line with the PAGE_SCAN, specifically ( PAGE_SCAN * 2 ) / size_of(hci_dev_req) in
/// hci_get_dev_list in /net/bluetooth/hci_core.c. When `const_generics` is stable, this
/// function should be implemented to accept a const generic for the device count.
pub fn get_dev_id<A>(device_address: A) -> Result<usize, nix::Error>
where
    A: Into<Option<BluetoothDeviceAddress>>,
{
    use nix::libc;

    let mut boxed_list = BoxedHciDevListReq::new();

    let sock = unsafe {
        let raw_fd = libc::socket(
            libc::AF_BLUETOOTH,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            bindings::BTPROTO_HCI as i32,
        );

        if raw_fd < 0 {
            return Err(nix::errno::Errno::last().into());
        }

        // Deliberately bind HCI_DEV_NONE as we only want
        // to interface with the linux bluetooth driver.
        let sa_p = &bindings::sockaddr_hci {
            hci_family: libc::AF_BLUETOOTH as u16,
            hci_dev: bindings::HCI_DEV_NONE as std::os::raw::c_ushort,
            hci_channel: bindings::HCI_CHANNEL_RAW as std::os::raw::c_ushort,
        } as *const bindings::sockaddr_hci as *const libc::sockaddr;

        let sa_len = std::mem::size_of::<bindings::sockaddr_hci>() as libc::socklen_t;

        if libc::bind(raw_fd, sa_p, sa_len) < 0 {
            return Err(nix::errno::Errno::last().into());
        }

        crate::FileDescriptor(raw_fd)
    };

    unsafe { hci_get_dev_list(sock.0, &mut boxed_list)? };

    let device_address_opt = device_address.into();

    unsafe { boxed_list.1.as_ref().unwrap() }
        .iter()
        .map(|dev_req| dev_req.dev_id)
        .find_map(|id| {
            let mut dev_info = bindings::hci_dev_info::default();

            dev_info.dev_id = id;

            let di_rslt = unsafe { hci_get_dev_info(sock.0, &mut dev_info) };

            if di_rslt.is_err() || test_flag(HCI_RAW, &[dev_info.flags]) {
                return None;
            }

            match device_address_opt {
                None => Some(<usize>::from(id)),
                Some(addr) if addr.0 == dev_info.bdaddr.b => Some(<usize>::from(id)),
                _ => None,
            }
        })
        .ok_or(nix::errno::Errno::ENODEV)
}

/// Send a HCI packet to the controller
pub fn send_to_controller(dev: &crate::FileDescriptor, packet: &mut HciPacket<impl Buffer>) -> nix::Result<usize> {
    let is_command = if let HciPacket::Command(_) = packet {
        true
    } else {
        false
    };

    // Uart is used here at it is the same system used by linux for labeling HCI packets.
    let message =
        bo_tie_hci_interface::uart::PacketIndicator::prepend(packet).expect("failed to prepend packet indicator");

    if is_command {
        loop {
            match nix::unistd::write(dev.0, &message) {
                Err(nix::Error::EAGAIN) | Err(nix::Error::EINTR) => continue,
                result => break result,
            }
        }
    } else {
        let flags = nix::sys::socket::MsgFlags::MSG_DONTWAIT;

        nix::sys::socket::send(dev.0, &message, flags)
    }
}

///////////
// ioctl structures
////

// ioclt magic for the IOCTL values
const HCI_IOC_MAGIC: u8 = b'H';

const HCI_IOC_HCIDEVUP: u8 = 201;
const HCI_IOC_HCIDEVDOWN: u8 = 202;
const HCI_IOC_HCIGETDEVLIST: u8 = 210;
const HCI_IOC_HCIGETDEVINFO: u8 = 211;

nix::ioctl_write_int!(hci_dev_up, HCI_IOC_MAGIC, HCI_IOC_HCIDEVUP);
nix::ioctl_write_int!(hci_dev_down, HCI_IOC_MAGIC, HCI_IOC_HCIDEVDOWN);

//////
// The following functions cannot use nix's handy ioctl_read! macros because the request code
// does not use the same type as `hci_dev_list_req`

unsafe fn hci_get_dev_list(fd: nix::libc::c_int, boxed_req: &mut BoxedHciDevListReq) -> nix::Result<nix::libc::c_int> {
    use nix::libc::{c_int, c_void};
    use std::mem::size_of;

    let request_code = nix::request_code_read!(HCI_IOC_MAGIC, HCI_IOC_HCIGETDEVLIST, size_of::<c_int>());

    let raw_errno = nix::libc::ioctl(fd, request_code, boxed_req.get_mut_ptr() as *mut c_void);

    nix::errno::Errno::result(raw_errno)
}

unsafe fn hci_get_dev_info(fd: nix::libc::c_int, info: &mut bindings::hci_dev_info) -> nix::Result<nix::libc::c_int> {
    use nix::libc::{c_int, c_void};
    use std::mem::size_of;

    let request_code = nix::request_code_read!(HCI_IOC_MAGIC, HCI_IOC_HCIGETDEVINFO, size_of::<c_int>());

    let raw_errno = nix::libc::ioctl(fd, request_code, info as *mut _ as *mut c_void);

    nix::errno::Errno::result(raw_errno)
}

/// A 'boxxed' `hci_dev_list_req`
struct BoxedHciDevListReq(std::alloc::Layout, *mut bindings::hci_dev_list_req);

impl BoxedHciDevListReq {
    // we're really only looking to use the first one found, so this can be one
    const REQUEST_COUNT: u16 = 1;

    /// Create a new BoxedHciDevListReq
    fn new() -> Self {
        use std::alloc::{alloc, Layout};

        let layout = Layout::new::<u16>()
            .extend(Layout::array::<Self>(Self::REQUEST_COUNT.into()).unwrap())
            .unwrap()
            .0
            .pad_to_align();

        let list = unsafe {
            let list = alloc(layout) as *mut bindings::hci_dev_list_req;

            (*list).dev_num = Self::REQUEST_COUNT;

            for i in 0usize..Self::REQUEST_COUNT.into() {
                (*list)
                    .dev_req
                    .as_mut_ptr()
                    .add(i)
                    .write(bindings::hci_dev_req::default())
            }

            list
        };

        Self(layout, list)
    }

    fn get_mut_ptr(&mut self) -> *mut bindings::hci_dev_list_req {
        self.1
    }
}

impl Drop for BoxedHciDevListReq {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.1 as *mut u8, self.0) }
    }
}

impl bindings::hci_dev_list_req {
    fn iter(&self) -> std::slice::Iter<bindings::hci_dev_req> {
        unsafe { self.dev_req.as_slice(BoxedHciDevListReq::REQUEST_COUNT.into()).iter() }
    }
}

impl Default for bindings::hci_dev_info {
    fn default() -> Self {
        bindings::hci_dev_info {
            dev_id: 0,
            name: Default::default(),
            bdaddr: bindings::bdaddr_t { b: Default::default() },
            flags: 0,
            type_: 0,
            features: Default::default(),
            pkt_type: 0,
            link_policy: 0,
            link_mode: 0,
            acl_mtu: 0,
            acl_pkts: 0,
            sco_mtu: 0,
            sco_pkts: 0,
            stat: bindings::hci_dev_stats {
                err_rx: 0,
                err_tx: 0,
                cmd_tx: 0,
                evt_rx: 0,
                acl_tx: 0,
                acl_rx: 0,
                sco_tx: 0,
                sco_rx: 0,
                byte_rx: 0,
                byte_tx: 0,
            },
        }
    }
}

impl Default for bindings::hci_dev_req {
    fn default() -> Self {
        bindings::hci_dev_req { dev_id: 0, dev_opt: 0 }
    }
}
