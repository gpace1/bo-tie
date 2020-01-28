use std::os::raw::c_void;

// Linux Bluetooth socket constants
// pub const SOL_HCI: u32 = 0;
// pub const HCI_FILTER: u32 = 2;
// const HCI_COMMAND_PKT: u32 = 1;
// pub const HCI_ACLDATA_PKT: u32 = 2;
// pub const HCI_SCODATA_PKT: u32 = 3;
// pub const HCI_EVENT_PKT: u32 = 4;
// pub const HCI_VENDOR_PKT: u32 = 255;

// HCI filter constants from the bluez library
// pub const HCI_FLT_TYPE_BITS: usize = 31;
// const HCI_FLT_EVENT_BITS: u32 = 63;

pub const BTPROTO_HCI: i32 = 1;

pub const HCI_MAX_DEV: usize = 16;

// pub const HCI_CHANNEL_RAW: i32 = 0; // A raw channel works with the linux hci implementation
pub const HCI_CHANNEL_USER: i32 = 1; // User channel gives total control, but requires hci

#[link(name = "bluetooth")]
extern "C" {
    pub fn hci_get_route(bt_dev_addr: *mut bo_tie::BluetoothDeviceAddress) -> i32;
    pub fn hci_send_cmd(dev: i32, ogf: u16, ocf: u16, parameter_len: u8, parameter: *mut c_void) -> i32;
}

pub mod hci {

    pub fn get_route() -> nix::Error { unimplemented!() }

    /// Send a command to the bluetooth controller
    ///
    /// The implementation of `send_command` is based of the `hci_send_cmd` function in bluez
    pub fn send_command<P>(dev: &super::FileDescriptor, parameter: P) -> nix::Result<usize>
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
            match nix::unistd::write(dev.raw_fd(), &command_packet) {
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
    dev_req: [hci_dev_req; HCI_MAX_DEV],
}

impl Default for hci_dev_list_req {
    fn default() -> Self {
        hci_dev_list_req {
            dev_num: HCI_MAX_DEV as u16,
            dev_req: <[hci_dev_req; HCI_MAX_DEV]>::default(),
        }
    }
}

// ioclt workarounds
const HCI_IOC_MAGIC:u8 = b'H';

const HCI_IOC_HCIDEVUP: u8 = 201;
const HCI_IOC_HCIDEVDOWN: u8 = 202;
const HCI_IOC_HCIGETDEVLIST: u8 = 210;

nix::ioctl_write_int!(hci_dev_up, HCI_IOC_MAGIC, HCI_IOC_HCIDEVUP);
nix::ioctl_write_int!(hci_dev_down, HCI_IOC_MAGIC, HCI_IOC_HCIDEVDOWN);
nix::ioctl_read!(hci_get_dev_list, HCI_IOC_MAGIC, HCI_IOC_HCIGETDEVLIST, hci_dev_list_req);
