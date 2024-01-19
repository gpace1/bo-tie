//! Legacy Linux Bluetooth support
//!
//! Before the implementation of Bluetooth Management Sockets, the way to interact with the kernel
//! for Bluetooth was through the usage of `ioctl` system calls. This implementation is only used
//! for Linux kernel versions earlier than 3.4.

use crate::device::bindings;
use nix::libc;

pub(crate) struct LegacySocket {
    fd: std::os::fd::OwnedFd,
}

impl LegacySocket {
    pub(crate) fn new() -> nix::Result<LegacySocket> {
        let fd = unsafe {
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

            <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw_fd)
        };

        Ok(LegacySocket { fd })
    }

    #[cfg(feature = "ctrls_intf")]
    pub(crate) fn get_index_list(&self) -> nix::Result<Vec<u16>> {
        let raw_socket_fd = std::os::fd::AsRawFd::as_raw_fd(&self.fd);

        let mut boxed_list = BoxedHciDevListReq::new();

        unsafe { hci_get_dev_list(raw_socket_fd, &mut boxed_list)? };

        let indexes = unsafe { boxed_list.1.as_ref().unwrap() }
            .iter()
            .map(|dev_req| dev_req.dev_id)
            .collect();

        Ok(indexes)
    }

    #[cfg(feature = "ctrls_intf")]
    pub(crate) fn get_dev_info(&self, index: u16) -> nix::Result<DeviceInfo> {
        let mut dev_info = bindings::hci_dev_info::default();

        dev_info.dev_id = index;

        let raw_fd = std::os::fd::AsRawFd::as_raw_fd(&self.fd);

        unsafe {
            hci_get_dev_info(raw_fd, &mut dev_info)?;
        }

        Ok(DeviceInfo::new(&dev_info))
    }

    /// Create the socket to the Controller using the 'legacy' way.
    pub(crate) fn make_socket(&mut self, index: u16) -> nix::Result<std::os::fd::OwnedFd> {
        let this_raw_fd = std::os::fd::AsRawFd::as_raw_fd(&self.fd);

        unsafe { hci_dev_down(this_raw_fd, index as std::ffi::c_ulong) }?;

        unsafe { hci_dev_set_raw(this_raw_fd, index as std::ffi::c_ulong) }?;

        let raw_socked_fd = unsafe { libc::socket(libc::AF_BLUETOOTH, libc::SOCK_RAW, bindings::BTPROTO_HCI as i32) };

        let sock_addr_ptr = &bindings::sockaddr_hci {
            hci_family: libc::AF_BLUETOOTH as u16,
            hci_dev: index,
            hci_channel: bindings::HCI_CHANNEL_RAW as u16, // For some early Linux versions this doesn't even exist.
        } as *const bindings::sockaddr_hci as *const libc::sockaddr;

        let sock_addr_len = std::mem::size_of::<bindings::sockaddr_hci>() as libc::socklen_t;

        if unsafe { libc::bind(raw_socked_fd, sock_addr_ptr, sock_addr_len) } < 0 {
            return Err(nix::Error::last());
        }

        let fd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw_socked_fd) };

        Ok(fd)
    }
}

#[cfg(feature = "ctrls_intf")]
pub struct DeviceInfo {
    index: u16,
    address: bo_tie_core::BluetoothDeviceAddress,
    name: String,
    is_raw: bool,
    is_powered: bool,
}

#[cfg(feature = "ctrls_intf")]
impl DeviceInfo {
    /// Create a `DeviceInfo`
    fn new(dev_info: &bindings::hci_dev_info) -> Self {
        let index = dev_info.dev_id;

        let address = bo_tie_core::BluetoothDeviceAddress(dev_info.bdaddr.b);

        let name = if dev_info.name.contains(&0) {
            std::ffi::CStr::from_bytes_until_nul(&dev_info.name.map(|i| i as u8))
                .unwrap()
                .to_str()
                .unwrap_or_default()
                .to_string()
        } else {
            std::str::from_utf8(&dev_info.name.map(|i| i as u8))
                .unwrap_or_default()
                .to_string()
        };

        let is_raw = dev_info.flags & (1 << bindings::HCI_RAW) != 0;

        let is_powered = dev_info.flags & (1 << bindings::HCI_UP) != 0;

        DeviceInfo {
            index,
            address,
            name,
            is_raw,
            is_powered,
        }
    }

    pub(crate) fn get_index(&self) -> u16 {
        self.index
    }

    pub(crate) fn get_address(&self) -> bo_tie_core::BluetoothDeviceAddress {
        self.address
    }

    pub(crate) fn get_name(&self) -> &str {
        &self.name
    }
}

#[cfg(feature = "ctrls_intf")]
impl std::fmt::Display for DeviceInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "index: {}, address: {}, is_raw: {}, is_powered: {}",
            self.index,
            self.address,
            if self.is_raw { true } else { false },
            if self.is_powered { true } else { false }
        )?;

        if !self.name.is_empty() {
            write!(f, " name: {}", self.name)?;
        }

        Ok(())
    }
}

///////////
// ioctl structures
////

// ioclt magic for the IOCTL values
const HCI_IOC_MAGIC: u8 = b'H';

const HCI_IOC_HCIDEVDOWN: u8 = 202;
#[cfg(feature = "ctrls_intf")]
const HCI_IOC_HCIGETDEVLIST: u8 = 210;
#[cfg(feature = "ctrls_intf")]
const HCI_IOC_HCIGETDEVINFO: u8 = 211;
const HCI_IOC_HCISETRAW: u8 = 220;

nix::ioctl_write_int!(hci_dev_down, HCI_IOC_MAGIC, HCI_IOC_HCIDEVDOWN);
nix::ioctl_write_int!(hci_dev_set_raw, HCI_IOC_MAGIC, HCI_IOC_HCISETRAW);

//////
// The following functions cannot use nix's handy ioctl_read! macros because the request code
// does not use the same type as `hci_dev_list_req`

#[cfg(feature = "ctrls_intf")]
unsafe fn hci_get_dev_list(fd: nix::libc::c_int, boxed_req: &mut BoxedHciDevListReq) -> nix::Result<nix::libc::c_int> {
    use nix::libc::{c_int, c_void};
    use std::mem::size_of;

    let request_code = nix::request_code_read!(HCI_IOC_MAGIC, HCI_IOC_HCIGETDEVLIST, size_of::<c_int>());

    let raw_errno = nix::libc::ioctl(fd, request_code, boxed_req.get_mut_ptr() as *mut c_void);

    nix::errno::Errno::result(raw_errno)
}

#[cfg(feature = "ctrls_intf")]
unsafe fn hci_get_dev_info(fd: nix::libc::c_int, info: &mut bindings::hci_dev_info) -> nix::Result<nix::libc::c_int> {
    use nix::libc::{c_int, c_void};
    use std::mem::size_of;

    let request_code = nix::request_code_read!(HCI_IOC_MAGIC, HCI_IOC_HCIGETDEVINFO, size_of::<c_int>());

    let raw_errno = nix::libc::ioctl(fd, request_code, info as *mut _ as *mut c_void);

    nix::errno::Errno::result(raw_errno)
}

/// A boxed `hci_dev_list_req`
#[cfg(feature = "ctrls_intf")]
struct BoxedHciDevListReq(std::alloc::Layout, *mut bindings::hci_dev_list_req);

#[cfg(feature = "ctrls_intf")]
impl BoxedHciDevListReq {
    const REQUEST_COUNT: u16 = 16;

    /// Create a new BoxedHciDevListReq
    fn new() -> Self {
        use std::alloc::{alloc, Layout};

        let layout = Layout::new::<u16>()
            .extend(Layout::array::<bindings::hci_dev_req>(Self::REQUEST_COUNT.into()).unwrap())
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

#[cfg(feature = "ctrls_intf")]
impl Drop for BoxedHciDevListReq {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.1 as *mut u8, self.0) }
    }
}

#[cfg(feature = "ctrls_intf")]
impl bindings::hci_dev_list_req {
    fn iter(&self) -> std::slice::Iter<bindings::hci_dev_req> {
        unsafe { self.dev_req.as_slice(BoxedHciDevListReq::REQUEST_COUNT.into()).iter() }
    }
}

#[cfg(feature = "ctrls_intf")]
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
