//! Linux Bluetooth device functionality controller methods
//!
//! These are functions that are used to control the interface to the bluetooth devices on the
//! system. This isn't a complete implemenation of control commands/operations, it is just the
//! functionality used by this libary. These are linux specific and have no relation to the
//! bluetooth specification.

pub const BTPROTO_HCI: i32 = 1;

/// The default maximum bluetooth device to get the list of
const BLU_DEV_LIST_DEFAULT_CNT: usize = 16;

// pub const HCI_CHANNEL_RAW: i32 = 0; // A raw channel works with the linux hci implementation
pub const HCI_CHANNEL_USER: i32 = 1; // User channel gives total control, but requires hci

pub mod hci {

    const HCI_RAW: usize = 6;

    fn test_flag(bit: usize, field: &[u32]) -> bool {
        1 == (field[bit >> 5] >> (bit as u32 & 31 ))
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
    pub fn get_dev_id<A>(device_address: A ) -> Result<usize, nix::Error>
        where A: Into<Option<bo_tie::BluetoothDeviceAddress>>
    {
        use nix::libc;
        use std::os::raw::c_int;

        let mut hci_dev_list = super::hci_dev_list_req::default();

        let sock = unsafe {
            let raw_fd = libc::socket(libc::AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, super::BTPROTO_HCI);

            if raw_fd < 0 {
                return Err( nix::errno::Errno::last().into() )
            }

            crate::FileDescriptor(raw_fd)
        };

        unsafe { super::hci_get_dev_list(sock.0, &mut hci_dev_list as *mut _ as *mut c_int)? };

        let device_address_opt = device_address.into();

        for dev_req in &hci_dev_list.dev_req[..hci_dev_list.dev_num as usize] {
            let mut dev_info = super::hci_dev_info::default();

            dev_info.dev_id = dev_req.dev_id;

            let di_rslt = unsafe {
                super::hci_get_dev_info(sock.0, &mut dev_info as *mut _ as *mut c_int)
            };

            if di_rslt.is_err() || test_flag(HCI_RAW, &[dev_info.flags]) {
                continue
            }

            match device_address_opt {
                None => return Ok(dev_req.dev_id as usize),
                Some(addr) => if addr == dev_info.bdaddr { return Ok(dev_req.dev_id as usize) },
            }
        }

        Err( nix::errno::Errno::ENODEV.into() )
    }

    /// Send a command to the bluetooth controller
    pub fn send_command<P>(dev: &crate::FileDescriptor, parameter: &P) -> nix::Result<usize>
        where P: bo_tie::hci::CommandParameter
    {
        use nix::Error;
        use nix::errno::Errno;

        let mut command_packet = parameter.as_command_packet();

        // Insert the packet indicator for linux (maybe for alerting the kernel to the hci packet
        // type or used for just UART communication).
        let packet_indicator = bo_tie::hci_transport::uart::HciPacketIndicator::Command.val();

        command_packet.insert(0, packet_indicator);

        loop {
            match nix::unistd::write(dev.0, &command_packet) {
                Err(Error::Sys(Errno::EAGAIN)) | Err(Error::Sys(Errno::EINTR)) => continue,
                result => break result,
            }
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct hci_filter {
    pub type_mask: u32,
    pub event_mask: [u32; 2usize],
    pub opcode: u16,
}

#[repr(C)]
#[derive(Default)]
pub struct sockaddr_hci {
  pub hci_family: nix::libc::sa_family_t,
  pub hci_dev: u16,
  pub hci_channel: u16,
}

#[repr(C)]
#[derive(Default)]
pub struct hci_dev_req {
    dev_id: u16,
    dev_opt: u32,
}

#[repr(C)]
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

#[repr(C)]
#[derive(Default)]
pub struct hci_dev_info {
    dev_id: u16,
    name: [std::os::raw::c_char;8],
    bdaddr: bo_tie::BluetoothDeviceAddress,
    flags: u32,
    r#type: u8,
    features: [u8;8],
    pkt_type: u32,
    link_policy: u32,
    link_mod: u32,
    acl_mtu: u16,
    acl_pkts: u16,
    sco_mtu: u16,
    sco_pkts: u16,
    stat: hci_dev_stats
}

#[repr(C)]
#[derive(Default)]
pub struct hci_dev_stats {
    err_rx: u32,
    err_tx: u32,
    cmd_tx: u32,
    evt_rx: u32,
    acl_tx: u32,
    acl_rx: u32,
    sco_rx: u32,
    byte_rx: u32,
    byte_tx: u32
}

// ioclt magic for the IOCTL values
const HCI_IOC_MAGIC:u8 = b'H';

const HCI_IOC_HCIDEVUP: u8 = 201;
const HCI_IOC_HCIDEVDOWN: u8 = 202;
const HCI_IOC_HCIGETDEVLIST: u8 = 210;
const HCI_IOC_HCIGETDEVINFO: u8 = 211;

nix::ioctl_write_int!(hci_dev_up, HCI_IOC_MAGIC, HCI_IOC_HCIDEVUP);
nix::ioctl_write_int!(hci_dev_down, HCI_IOC_MAGIC, HCI_IOC_HCIDEVDOWN);
nix::ioctl_read!(hci_get_dev_list, HCI_IOC_MAGIC, HCI_IOC_HCIGETDEVLIST, std::os::raw::c_int);
nix::ioctl_read!(hci_get_dev_info, HCI_IOC_MAGIC, HCI_IOC_HCIGETDEVINFO, std::os::raw::c_int);
