//! Linux Bluetooth device functionality controller methods
//!
//! These are functions that are used to control the interface to the bluetooth devices on the
//! system. This isn't a complete implementation of control commands/operations, it is just the
//! functionality used by this library. These are linux specific and have no relation to the
//! bluetooth specification.

pub mod hci {
    use bo_tie_hci_util::HciPacket;
    use bo_tie_util::buffer::Buffer;
    use bo_tie_util::BluetoothDeviceAddress;

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

        let mut hci_dev_list = super::hci_dev_list_req::default();

        let sock = unsafe {
            let raw_fd = libc::socket(
                libc::AF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                super::BTPROTO_HCI,
            );

            if raw_fd < 0 {
                return Err(nix::errno::Errno::last().into());
            }

            // deliberately bind HCI_DEV_NONE as we only want to interface with the linux driver.
            //
            // Note: this is unnecessary, but it makes me feel better to do this :)
            let sa_p = &super::sockaddr_hci {
                hci_family: libc::AF_BLUETOOTH as u16,
                hci_dev: super::HCI_DEV_NONE,
                hci_channel: super::HCI_CHANNEL_RAW,
            } as *const super::sockaddr_hci as *const libc::sockaddr;

            let sa_len = std::mem::size_of::<super::sockaddr_hci>() as libc::socklen_t;

            if libc::bind(raw_fd, sa_p, sa_len) < 0 {
                return Err(nix::errno::Errno::last().into());
            }

            crate::FileDescriptor(raw_fd)
        };

        unsafe { super::hci_get_dev_list(sock.0, &mut hci_dev_list)? };

        let device_address_opt = device_address.into();

        hci_dev_list
            .dev_req
            .iter()
            .map(|dev_req| dev_req.dev_id)
            .find_map(|id| {
                let mut dev_info = super::hci_dev_info::default();

                dev_info.dev_id = id;

                let di_rslt = unsafe { super::hci_get_dev_info(sock.0, &mut dev_info) };

                if di_rslt.is_err() || test_flag(HCI_RAW, &[dev_info.flags]) {
                    return None;
                }

                match device_address_opt {
                    None => Some(<usize>::from(id)),
                    Some(addr) if addr.0 == dev_info.bdaddr => Some(<usize>::from(id)),
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
}

///////////
// c structures and constants taken from include/bluetooth/hci_sock.h
////

pub const BTPROTO_HCI: i32 = 1;

pub const HCI_DEV_NONE: u16 = 0xffff;

/// The default maximum bluetooth device to get the list of
const BLU_DEV_LIST_DEFAULT_CNT: usize = 16;

/// A raw HCI channel
pub const HCI_CHANNEL_RAW: u16 = 0;

/// A user HCI channel
///
/// This channel is slightly more performant as capability checks only done when binding a socket,
/// whereas a raw channel needs to do them for every system call. See [hci_sock.c].
///
/// [hci_sock.c]: https://elixir.bootlin.com/linux/latest/source/net/bluetooth/hci_sock.c
pub const HCI_CHANNEL_USER: u16 = 1;

/// linux c struct sockaddr_hci
///
/// This is taken from include/bluetooth/hci_sock.h
#[repr(C)]
#[derive(Default)]
#[allow(non_camel_case_types)]
pub struct sockaddr_hci {
    pub hci_family: nix::libc::sa_family_t,
    pub hci_dev: u16,
    pub hci_channel: u16,
}

/// linux c struct hci_dev_req
///
/// This is taken from include/bluetooth/hci_sock.h
#[repr(C)]
#[derive(Default)]
#[allow(non_camel_case_types)]
pub struct hci_dev_req {
    dev_id: u16,
    dev_opt: u32,
}

/// linux c struct hci_dev_list_req
///
/// This is taken from include/bluetooth/hci_sock.h
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct hci_dev_list_req {
    dev_num: u16,
    dev_req: [hci_dev_req; BLU_DEV_LIST_DEFAULT_CNT],
}

impl Default for hci_dev_list_req {
    fn default() -> Self {
        hci_dev_list_req {
            dev_num: BLU_DEV_LIST_DEFAULT_CNT as u16,
            dev_req: <[hci_dev_req; BLU_DEV_LIST_DEFAULT_CNT]>::default(),
        }
    }
}

/// linux c struct hci_dev_info
///
/// This is taken from include/bluetooth/hci_sock.h
#[repr(C)]
#[derive(Default)]
#[allow(non_camel_case_types)]
pub struct hci_dev_info {
    dev_id: u16,
    name: [std::os::raw::c_char; 8],
    bdaddr: [u8; 6],
    flags: u32,
    r#type: u8,
    features: [u8; 8],
    pkt_type: u32,
    link_policy: u32,
    link_mod: u32,
    acl_mtu: u16,
    acl_pkts: u16,
    sco_mtu: u16,
    sco_pkts: u16,
    stat: hci_dev_stats,
}

/// linux c struct hci_dev_stats
///
/// This is taken from include/bluetooth/hci_sock.h
#[repr(C)]
#[derive(Default)]
#[allow(non_camel_case_types)]
pub struct hci_dev_stats {
    err_rx: u32,
    err_tx: u32,
    cmd_tx: u32,
    evt_rx: u32,
    acl_tx: u32,
    acl_rx: u32,
    sco_rx: u32,
    byte_rx: u32,
    byte_tx: u32,
}

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

unsafe fn hci_get_dev_list(fd: nix::libc::c_int, req: &mut hci_dev_list_req) -> nix::Result<nix::libc::c_int> {
    use nix::libc::{c_int, c_void};
    use std::mem::size_of;

    let request_code = nix::request_code_read!(HCI_IOC_MAGIC, HCI_IOC_HCIGETDEVLIST, size_of::<c_int>());

    let raw_errno = nix::libc::ioctl(fd, request_code, req as *mut _ as *mut c_void);

    nix::errno::Errno::result(raw_errno)
}

unsafe fn hci_get_dev_info(fd: nix::libc::c_int, info: &mut hci_dev_info) -> nix::Result<nix::libc::c_int> {
    use nix::libc::{c_int, c_void};
    use std::mem::size_of;

    let request_code = nix::request_code_read!(HCI_IOC_MAGIC, HCI_IOC_HCIGETDEVINFO, size_of::<c_int>());

    let raw_errno = nix::libc::ioctl(fd, request_code, info as *mut _ as *mut c_void);

    nix::errno::Errno::result(raw_errno)
}
