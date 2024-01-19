//! Interface to a Linux Bluetooth manager socket
//!
//! This is for discovering the currently configured and unconfigured Controllers attach to the Linux machine.

use crate::device;
use crate::device::bindings;
use nix::libc;

macro_rules! to_le_u16 {
    ($val:expr) => {
        <u16>::try_from($val).unwrap().to_le()
    };
}

/// Bluetooth Management Socket
///
/// This is a socket that binds to the HCI *control* channel for manipulating the linux kernel's Bluetooth driver. The
/// control channel has better facilities then the legacy `ioctl` for *managing* the Bluetooth controllers connected to
/// this Linux machine.
///
/// The control channel has its own set of management commands. These can be found within the [`bluez`] library in the
/// file `bluez/doc/mgmt-api.txt`. The Manager socket is first available on version Linux kernel version 3.4, but more
/// commands of the management interface were added in later versions of Linux. The progression of the Bluetooth
/// management interface is also listed in the `mgmt-api.text` document.
pub(crate) struct ManagementSocket {
    fd: std::os::fd::OwnedFd,
    recv_buffer: Box<[u8]>,
    commands: Vec<SomeOfTheManagementCommands>,
}

impl ManagementSocket {
    /// Check if a `ManagementSocket` can be used
    ///
    /// This returns true if a `ManagementSocket`
    pub(crate) fn can_use() -> Result<bool, Box<dyn std::error::Error>> {
        let ret = validate_linux_version()?;

        Ok(ret)
    }

    /// Try to create a new `ManagementSocket`
    ///
    /// This will fail if the Linux operating system does not support Bluetooth management sockets.
    pub(crate) fn new() -> Result<Self, Box<dyn std::error::Error>> {
        validate_linux_version()?;

        let fd = unsafe {
            let raw_fd = libc::socket(
                libc::PF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                bindings::BTPROTO_HCI as i32,
            );

            if raw_fd < 0 {
                return Err(nix::errno::Errno::last().into());
            }

            // Deliberately bind HCI_DEV_NONE as we only want
            // to interface with the linux bluetooth driver.
            let sockaddr_hci_ptr = &bindings::sockaddr_hci {
                hci_family: libc::AF_BLUETOOTH as u16,
                hci_dev: bindings::HCI_DEV_NONE as std::os::raw::c_ushort,
                hci_channel: bindings::HCI_CHANNEL_CONTROL as std::os::raw::c_ushort,
            } as *const bindings::sockaddr_hci as *const libc::sockaddr;

            let sa_len = std::mem::size_of::<bindings::sockaddr_hci>() as libc::socklen_t;

            if libc::bind(raw_fd, sockaddr_hci_ptr, sa_len) < 0 {
                return Err(nix::errno::Errno::last().into());
            }

            <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw_fd)
        };

        let mut recv_buffer = Vec::new();

        let max_len = <u16>::MAX as usize + std::mem::size_of::<bindings::mgmt_hdr>();

        recv_buffer.resize(max_len, 0);

        let recv_buffer = recv_buffer.into_boxed_slice();

        let commands = Vec::new();

        let mut this = ManagementSocket {
            fd,
            recv_buffer,
            commands,
        };

        let commands = this.read_management_supported_commands()?;

        this.commands = commands;

        Ok(this)
    }

    /// Write a command
    ///
    /// This writes command to the Bluetooth manager kernel. Input `command` must be in little endian format and be a
    /// packed structure.
    fn write_command<T>(&mut self, header: &bindings::mgmt_hdr, parameters: &T) -> nix::Result<()> {
        macro_rules! to_byte_slice {
            ($item:expr, $item_type:ty) => {
                unsafe {
                    ::std::slice::from_raw_parts(
                        $item as *const $item_type as *const u8,
                        ::std::mem::size_of::<$item_type>(),
                    )
                }
            };
        }

        let header_bytes = to_byte_slice!(header, bindings::mgmt_hdr);

        let command_bytes = to_byte_slice!(parameters, T);

        let message: Vec<u8> = header_bytes.into_iter().chain(command_bytes).copied().collect();

        let raw_fd = std::os::fd::AsRawFd::as_raw_fd(&self.fd);

        nix::sys::socket::send(raw_fd, &message, nix::sys::socket::MsgFlags::empty())?;

        Ok(())
    }

    /// Read into the `recv_buffer` field
    ///
    /// This awaits for the Bluetooth socket to be ready and returns the next message.
    fn read(&mut self) -> nix::Result<&[u8]> {
        let raw_fd = std::os::fd::AsRawFd::as_raw_fd(&self.fd);

        let read_amount = nix::sys::socket::recv(raw_fd, &mut self.recv_buffer, nix::sys::socket::MsgFlags::empty())?;

        Ok(&self.recv_buffer[..read_amount])
    }

    /// Read for the command complete or command status event
    ///
    /// Many Commands will return a command complete on a success and a command status on a failure. If any other event
    /// is received this is ignored. A command complete event will be translated into `R` using the input `convert` and
    /// then output. A command status will be converted into an error.
    ///
    /// # Panic
    /// This will panic if `convert` panics.
    fn read_command_complete_or_status_event<F, R>(
        &mut self,
        expected_opcode: u16,
        convert: F,
    ) -> Result<R, Box<dyn std::error::Error>>
    where
        F: FnOnce(&[u8]) -> R,
    {
        loop {
            let mut raw_message = self.read()?;

            let Some(header) = bindings::mgmt_hdr::take_from_raw(&mut raw_message) else {
                continue;
            };

            let len: usize = header.len.into();

            if header.opcode == bindings::MGMT_EV_CMD_STATUS.try_into().unwrap() {
                let Some(ev_status) = bindings::mgmt_ev_cmd_status::from_raw(&raw_message) else {
                    continue;
                };

                // this will most likely cause an error to be returned.
                ev_status.check_status()?;
            }

            if header.opcode != bindings::MGMT_EV_CMD_COMPLETE.try_into().unwrap() {
                continue;
            }

            let Some(cmd_complete_header) = bindings::mgmt_ev_cmd_complete::take_empty_from_raw(&mut raw_message)
            else {
                continue;
            };

            if cmd_complete_header.opcode != expected_opcode {
                continue;
            }

            cmd_complete_header.check_status()?;

            break Ok(convert(&raw_message[..len - bindings::mgmt_ev_cmd_complete::MIN_SIZE]));
        }
    }

    /// Read the commands supported by the Bluetooth management interface
    ///
    /// This returns a list of commands supported by the Bluetooth manager in the Linux kernel.
    fn read_management_supported_commands(
        &mut self,
    ) -> Result<Vec<SomeOfTheManagementCommands>, Box<dyn std::error::Error>> {
        let command_header = bindings::mgmt_hdr {
            opcode: to_le_u16!(bindings::MGMT_OP_READ_COMMANDS),
            index: to_le_u16!(bindings::MGMT_INDEX_NONE),
            len: to_le_u16!(0),
        };

        self.write_command(&command_header, &())?;

        self.read_command_complete_or_status_event(bindings::MGMT_OP_READ_COMMANDS as u16, |mut raw| {
            let number_of_commands: usize = <u16>::from_le_bytes([raw[0], raw[1]]).into();

            // not used, this is not needed
            let _number_of_events: usize = <u16>::from_le_bytes([raw[2], raw[3]]).into();

            raw = &raw[4..];

            let mut commands = Vec::with_capacity(number_of_commands);

            for _ in 0..number_of_commands {
                let raw_command = <u16>::from_le_bytes([raw[0], raw[1]]);

                raw = &raw[2..];

                if let Ok(management_command) = SomeOfTheManagementCommands::try_from_raw(raw_command) {
                    commands.push(management_command)
                }
            }

            commands
        })
    }

    /// Read the controller index list
    ///
    /// This returns the list of currently allocated indexes for controllers. Indexes are either used for establishing
    /// raw, user, or monitor Bluetooth sockets or for management commands.
    #[cfg(feature = "ctrls_intf")]
    pub(crate) fn read_controller_index_list(&mut self) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
        let command_header = bindings::mgmt_hdr {
            opcode: to_le_u16!(bindings::MGMT_OP_READ_INDEX_LIST),
            index: to_le_u16!(bindings::MGMT_INDEX_NONE),
            len: to_le_u16!(0),
        };

        self.write_command(&command_header, &())?;

        self.read_command_complete_or_status_event(bindings::MGMT_OP_READ_INDEX_LIST as u16, |mut raw| {
            let num_of_controllers: usize = <u16>::from_le_bytes([raw[0], raw[1]]).into();

            raw = &raw[2..];

            (0..num_of_controllers)
                .map(|_| {
                    let val = <u16>::from_le_bytes([raw[0], raw[1]]);

                    raw = &raw[2..];

                    val
                })
                .collect()
        })
    }

    /// Set the 'powered' state of a controller
    ///
    /// A powered controller can interact via the HCI
    pub(crate) fn set_powered(&mut self, index: u16, powered: bool) -> Result<(), Box<dyn std::error::Error>> {
        let command_header = bindings::mgmt_hdr {
            opcode: to_le_u16!(bindings::MGMT_OP_SET_POWERED),
            index: to_le_u16!(index),
            len: to_le_u16!(1),
        };

        let parameter = if powered { 1u8 } else { 0u8 };

        self.write_command(&command_header, &parameter)?;

        self.read_command_complete_or_status_event(bindings::MGMT_OP_SET_POWERED as u16, |_| ())
    }

    #[cfg(feature = "ctrls_intf")]
    fn read_controller_info_cmd(&mut self, index: u16) -> Result<ControllerInfo, Box<dyn std::error::Error>> {
        let command_header = bindings::mgmt_hdr {
            opcode: to_le_u16!(bindings::MGMT_OP_READ_INFO),
            index: to_le_u16!(index),
            len: to_le_u16!(0),
        };

        self.write_command(&command_header, &())?;

        self.read_command_complete_or_status_event(bindings::MGMT_OP_READ_INFO as u16, |raw| {
            ControllerInfo::from_raw(index, raw)
        })
    }

    #[cfg(feature = "ctrls_intf")]
    fn read_extended_controller_info_cmd(&mut self, index: u16) -> Result<ControllerInfo, Box<dyn std::error::Error>> {
        let command_header = bindings::mgmt_hdr {
            opcode: to_le_u16!(bindings::MGMT_OP_READ_EXT_INFO),
            index: to_le_u16!(index),
            len: to_le_u16!(0),
        };

        self.write_command(&command_header, &())?;

        self.read_command_complete_or_status_event(bindings::MGMT_OP_READ_EXT_INFO as u16, |raw| {
            ControllerInfo::from_raw_extended(index, raw)
        })
    }

    /// Read the management information on a controller
    #[cfg(feature = "ctrls_intf")]
    pub(crate) fn read_controller_info(&mut self, index: u16) -> Result<ControllerInfo, Box<dyn std::error::Error>> {
        if self
            .commands
            .contains(&SomeOfTheManagementCommands::ReadExtendedControllerInformationCommand)
        {
            self.read_extended_controller_info_cmd(index)
        } else {
            self.read_controller_info_cmd(index)
        }
    }

    /// Select the controller to be used
    ///
    /// This sets up the socket for HCI communication with the selected Controller. The socket created uses the
    /// `HCI_USER_CHANNEL`. For explanation on how this channel must be set-up see commit [`23500189d7`] of the linux
    /// kernel.
    ///
    /// [`23500189d7`]: https://github.com/torvalds/linux/commit/23500189d7e03a071f0746f43f2cce875a62c91c
    pub(crate) fn make_socket(&mut self, index: u16) -> Result<std::os::fd::OwnedFd, Box<dyn std::error::Error>> {
        // Need to 'power down' the controller before it a
        // user channel socket is established
        self.set_powered(index, false)?;

        let raw_socket_fd = unsafe {
            libc::socket(
                libc::AF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                device::bindings::BTPROTO_HCI as i32,
            )
        };

        let sock_addr_ptr = &bindings::sockaddr_hci {
            hci_family: libc::AF_BLUETOOTH as u16,
            hci_dev: index as u16,
            hci_channel: bindings::HCI_CHANNEL_RAW as u16,
        } as *const bindings::sockaddr_hci as *const libc::sockaddr;

        let sock_addr_len = std::mem::size_of::<bindings::sockaddr_hci>() as libc::socklen_t;

        if unsafe { libc::bind(raw_socket_fd, sock_addr_ptr, sock_addr_len) } < 0 {
            return Err(nix::Error::last().into());
        }

        let fd = unsafe { std::os::fd::FromRawFd::from_raw_fd(raw_socket_fd) };

        Ok(fd)
    }
}

/// Validate the Linux version for Bluetooth management
///
/// This returns an error if the current Linux version is not greater than or equal to 3.4
fn validate_linux_version() -> nix::Result<bool> {
    let uname_info = nix::sys::utsname::uname()?;

    let kernel_version = uname_info.release().to_str().unwrap_or("{undefined}");

    let mut version_parts = kernel_version.split(".");

    let version_str = version_parts.next().unwrap_or("");

    let release_str = version_parts.next().unwrap_or("");

    let version: usize = str::parse(version_str).unwrap_or(0);

    let release: usize = str::parse(release_str).unwrap_or(0);

    // validate Linux kernel version is at or above v3.4
    if version > 3 || version == 3 && release >= 4 {
        Ok(true)
    } else {
        Ok(false)
    }
}

impl bindings::mgmt_hdr {
    /// The size of the Bluetooth management header
    const SIZE: usize = 6;

    /// Create a `mgmt_hdr` from a raw byte slice
    ///
    /// Input `raw` must start with the header. `None` is returned if there is not enough bytes within the raw message.
    /// `raw` will be modified to have the header removed from itself.
    fn take_from_raw(raw: &mut &[u8]) -> Option<Self> {
        let this = bindings::mgmt_hdr {
            opcode: <u16>::from_le_bytes([*raw.get(0)?, *raw.get(1)?]),
            index: <u16>::from_le_bytes([*raw.get(2)?, *raw.get(3)?]),
            len: <u16>::from_le_bytes([*raw.get(4)?, *raw.get(5)?]),
        };

        *raw = &raw[Self::SIZE..];

        Some(this)
    }
}

impl bindings::mgmt_ev_cmd_complete {
    /// How large a `mgmt_ev_cmd_complete` is without any parameters
    const MIN_SIZE: usize = 3;

    /// Create a empty `mgmt_ev_cmd_complete`
    ///
    /// Input `raw` must start with the header. `None` is returned if there is not enough bytes within the raw message.
    /// `raw` will be modified to have the header removed from itself.
    ///
    /// The returned `mgmt_ev_cmd_complete` will not have any of the return parameters, if there are any.
    fn take_empty_from_raw(raw: &mut &[u8]) -> Option<Self> {
        let this = bindings::mgmt_ev_cmd_complete {
            opcode: <u16>::from_le_bytes([*raw.get(0)?, *raw.get(1)?]),
            status: *raw.get(2)?,
            data: bindings::__IncompleteArrayField::new(),
        };

        *raw = &raw[Self::MIN_SIZE..];

        Some(this)
    }

    /// Check the status
    ///
    /// This checks to ensure the status is `Success`. If it is not `Success` the status is returned as a
    /// `ManagerError`.
    fn check_status(&self) -> Result<(), Box<dyn std::error::Error>> {
        ManagementStatus::try_from_raw(self.status)?;

        Ok(())
    }
}

impl bindings::mgmt_ev_cmd_status {
    /// Create a `mgmt_ev_cmd_status`
    fn from_raw(raw: &[u8]) -> Option<Self> {
        let this = bindings::mgmt_ev_cmd_status {
            opcode: <u16>::from_le_bytes([*raw.get(0)?, *raw.get(1)?]),
            status: *raw.get(2)?,
        };

        Some(this)
    }

    /// Check the status
    ///
    /// This checks to ensure the status is `Success`. If it is not `Success` the status is returned as a
    /// `ManagerError`.
    fn check_status(&self) -> Result<(), Box<dyn std::error::Error>> {
        ManagementStatus::try_from_raw(self.status)?;

        Ok(())
    }
}

/// The status as returned by the Management
///
/// If everything is fine, the Management will return the `Success` status as part of a Command Complete or Command Status
/// event. If one of the other enums is returned it is translated into a `ManagementError` by a `ManagementSocket`.
#[derive(Debug)]
pub enum ManagementStatus {
    Success,
    UnknownCommand,
    NotConnected,
    Failed,
    ConnectFailed,
    AuthenticationFailed,
    NotPaired,
    NoResources,
    Timeout,
    AlreadyConnected,
    Busy,
    Rejected,
    NotSupported,
    InvalidParameters,
    Disconnected,
    NotPowered,
    Cancelled,
    InvalidIndex,
    BlockedByRFKill,
    AlreadyPaired,
    PermissionDenied,
    UnknownCode(u8),
}

impl ManagementStatus {
    /// Create a `ManagementStatus`
    ///
    /// This only returns a `ManagementStatus` if the raw value is equal to `Success`, otherwise an error is returned
    /// containing the Management status.
    pub(crate) fn try_from_raw(raw: u8) -> Result<Self, Self> {
        match raw as u32 {
            bindings::MGMT_STATUS_SUCCESS => Ok(ManagementStatus::Success),
            bindings::MGMT_STATUS_UNKNOWN_COMMAND => Err(ManagementStatus::UnknownCommand.into()),
            bindings::MGMT_STATUS_NOT_CONNECTED => Err(ManagementStatus::NotConnected.into()),
            bindings::MGMT_STATUS_FAILED => Err(ManagementStatus::Failed.into()),
            bindings::MGMT_STATUS_CONNECT_FAILED => Err(ManagementStatus::ConnectFailed.into()),
            bindings::MGMT_STATUS_AUTH_FAILED => Err(ManagementStatus::AuthenticationFailed.into()),
            bindings::MGMT_STATUS_NOT_PAIRED => Err(ManagementStatus::NotPaired.into()),
            bindings::MGMT_STATUS_NO_RESOURCES => Err(ManagementStatus::NoResources.into()),
            bindings::MGMT_STATUS_TIMEOUT => Err(ManagementStatus::Timeout.into()),
            bindings::MGMT_STATUS_ALREADY_CONNECTED => Err(ManagementStatus::AlreadyConnected.into()),
            bindings::MGMT_STATUS_BUSY => Err(ManagementStatus::Busy.into()),
            bindings::MGMT_STATUS_REJECTED => Err(ManagementStatus::Rejected.into()),
            bindings::MGMT_STATUS_NOT_SUPPORTED => Err(ManagementStatus::NotSupported.into()),
            bindings::MGMT_STATUS_INVALID_PARAMS => Err(ManagementStatus::InvalidParameters.into()),
            bindings::MGMT_STATUS_DISCONNECTED => Err(ManagementStatus::Disconnected.into()),
            bindings::MGMT_STATUS_NOT_POWERED => Err(ManagementStatus::NotPowered.into()),
            bindings::MGMT_STATUS_CANCELLED => Err(ManagementStatus::Cancelled.into()),
            bindings::MGMT_STATUS_INVALID_INDEX => Err(ManagementStatus::InvalidIndex.into()),
            bindings::MGMT_STATUS_RFKILLED => Err(ManagementStatus::BlockedByRFKill.into()),
            bindings::MGMT_STATUS_ALREADY_PAIRED => Err(ManagementStatus::AlreadyPaired.into()),
            bindings::MGMT_STATUS_PERMISSION_DENIED => Err(ManagementStatus::PermissionDenied.into()),
            _ => Err(ManagementStatus::UnknownCode(raw).into()),
        }
    }
}

impl std::fmt::Display for ManagementStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Success => f.write_str("success"),
            Self::UnknownCommand => f.write_str("unknown command"),
            Self::NotConnected => f.write_str("not connected"),
            Self::Failed => f.write_str("failed"),
            Self::ConnectFailed => f.write_str("connect failed"),
            Self::AuthenticationFailed => f.write_str("authentication failed"),
            Self::NotPaired => f.write_str("not paired"),
            Self::NoResources => f.write_str("no resources"),
            Self::Timeout => f.write_str("timeout"),
            Self::AlreadyConnected => f.write_str("already connected"),
            Self::Busy => f.write_str("busy"),
            Self::Rejected => f.write_str("rejected"),
            Self::NotSupported => f.write_str("not supported"),
            Self::InvalidParameters => f.write_str("invalid parameters"),
            Self::Disconnected => f.write_str("disconnected"),
            Self::NotPowered => f.write_str("not powered"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::InvalidIndex => f.write_str("invalid index"),
            Self::BlockedByRFKill => f.write_str("blocked by rfkill"),
            Self::AlreadyPaired => f.write_str("already paired"),
            Self::PermissionDenied => f.write_str("permission denied"),
            Self::UnknownCode(v) => write!(f, "status code: {v}"),
        }
    }
}

impl std::error::Error for ManagementStatus {}

/// List of managements commands (that are cared about)
///
/// This is an incomplete list of the management commands. The only commands listed here are those that matter to this
/// bo-tie.
#[derive(Eq, PartialEq)]
enum SomeOfTheManagementCommands {
    ReadManagementSupportedCommandsCommand,
    ReadControllerIndexListCommand,
    ReadControllerInformationCommand,
    ReadUnconfiguredControllerIndexListCommand,
    ReadControllerConfigurationInformationCommand,
    ReadExtendedControllerIndexListCommand,
    ReadExtendedControllerInformationCommand,
}

impl SomeOfTheManagementCommands {
    fn try_from_raw(raw: u16) -> Result<Self, ()> {
        match raw as u32 {
            bindings::MGMT_OP_READ_COMMANDS => Ok(Self::ReadManagementSupportedCommandsCommand),
            bindings::MGMT_OP_READ_INDEX_LIST => Ok(Self::ReadControllerIndexListCommand),
            bindings::MGMT_OP_READ_INFO => Ok(Self::ReadControllerInformationCommand),
            bindings::MGMT_OP_READ_UNCONF_INDEX_LIST => Ok(Self::ReadUnconfiguredControllerIndexListCommand),
            bindings::MGMT_OP_READ_CONFIG_INFO => Ok(Self::ReadControllerConfigurationInformationCommand),
            bindings::MGMT_OP_READ_EXT_INDEX_LIST => Ok(Self::ReadExtendedControllerIndexListCommand),
            bindings::MGMT_OP_READ_EXT_INFO => Ok(Self::ReadExtendedControllerInformationCommand),
            _ => Err(()),
        }
    }
}

/// A list of some of the common manufacture codes
#[cfg(feature = "ctrls_intf")]
enum CommonManufactureCodes {
    EricssonAB,
    NokiaMobilePhones,
    IntelCorp,
    IBMCorp,
    ToshibaCorp,
    Microsoft,
    Motorola,
    InfineonTechnologiesAG,
    TexasInstrumentsInc,
    BroadcomCorporation,
    AtmelCorporation,
    Qualcomm,
    Alcatel,
    HitachiLtd,
    STMicroelectronics,
    SynopsysInc,
    BluetoothSIGInc,
    AppleInc,
    NordicSemiconductorASA,
    HPInc,
    SamsungElectronicsCoLtd,
    Google,
    CypressSemiconductor,
}

#[cfg(feature = "ctrls_intf")]
impl CommonManufactureCodes {
    fn try_from(raw: u16) -> Option<CommonManufactureCodes> {
        match raw {
            0x0 => Some(Self::EricssonAB),
            0x1 => Some(Self::NokiaMobilePhones),
            0x2 => Some(Self::IntelCorp),
            0x3 => Some(Self::IBMCorp),
            0x4 => Some(Self::ToshibaCorp),
            0x5 => Some(Self::Microsoft),
            0x6 => Some(Self::Motorola),
            0x7 => Some(Self::InfineonTechnologiesAG),
            0xD => Some(Self::TexasInstrumentsInc),
            0xF => Some(Self::BroadcomCorporation),
            0x13 => Some(Self::AtmelCorporation),
            0x1D => Some(Self::Qualcomm),
            0x24 => Some(Self::Alcatel),
            0x29 => Some(Self::HitachiLtd),
            0x30 => Some(Self::STMicroelectronics),
            0x31 => Some(Self::SynopsysInc),
            0x3F => Some(Self::BluetoothSIGInc),
            0x41 => Some(Self::AppleInc),
            0x59 => Some(Self::NordicSemiconductorASA),
            0x65 => Some(Self::HPInc),
            0x75 => Some(Self::SamsungElectronicsCoLtd),
            0xE0 => Some(Self::Google),
            0x131 => Some(Self::CypressSemiconductor),
            _ => None,
        }
    }
}

#[cfg(feature = "ctrls_intf")]
impl std::fmt::Display for CommonManufactureCodes {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            CommonManufactureCodes::EricssonAB => f.write_str("Errisson AB"),
            CommonManufactureCodes::NokiaMobilePhones => f.write_str("Nokia Mobile Phones"),
            CommonManufactureCodes::IntelCorp => f.write_str("Intel Corp."),
            CommonManufactureCodes::IBMCorp => f.write_str("IBM Corp."),
            CommonManufactureCodes::ToshibaCorp => f.write_str("Toshiba Corp."),
            CommonManufactureCodes::Microsoft => f.write_str("Microsoft"),
            CommonManufactureCodes::Motorola => f.write_str("Motorola"),
            CommonManufactureCodes::InfineonTechnologiesAG => f.write_str("Infineon Technologies AG"),
            CommonManufactureCodes::TexasInstrumentsInc => f.write_str("Texas Instruments Inc."),
            CommonManufactureCodes::BroadcomCorporation => f.write_str("Broadcom Corporation"),
            CommonManufactureCodes::AtmelCorporation => f.write_str("Atmel Corporation"),
            CommonManufactureCodes::Qualcomm => f.write_str("Qualcom"),
            CommonManufactureCodes::Alcatel => f.write_str("Alcatel"),
            CommonManufactureCodes::HitachiLtd => f.write_str("Hitachi Ltd"),
            CommonManufactureCodes::STMicroelectronics => f.write_str("ST Microelectronics"),
            CommonManufactureCodes::SynopsysInc => f.write_str("Synopsys, Inc"),
            CommonManufactureCodes::BluetoothSIGInc => f.write_str("Bluetooth SIG, Inc"),
            CommonManufactureCodes::AppleInc => f.write_str("Apple Inc."),
            CommonManufactureCodes::NordicSemiconductorASA => f.write_str("Nordic Semiconductor ASA"),
            CommonManufactureCodes::HPInc => f.write_str("HP, Inc."),
            CommonManufactureCodes::SamsungElectronicsCoLtd => f.write_str("Samsung Electronics Co. Ltd."),
            CommonManufactureCodes::Google => f.write_str("Google"),
            CommonManufactureCodes::CypressSemiconductor => f.write_str("Cypress Semiconductor"),
        }
    }
}

/// Information of the Bluetooth Controllers
///
/// This is some of the information list is listed for a Bluetooth controller from a Bluetooth management socket. This
/// library is not intended to be used for configuring or managing the Bluetooth controllers so not all information on
/// a controller is listed here.
#[cfg(feature = "ctrls_intf")]
pub struct ControllerInfo {
    index: u16,
    address: bo_tie_core::BluetoothDeviceAddress,
    company_id: u16,
    info_type: InfoType,
}

#[cfg(feature = "ctrls_intf")]
enum InfoType {
    Basic { class_of_device: [u8; 3], name: String },
    Enhanced(Vec<u8>),
}

#[cfg(feature = "ctrls_intf")]
impl ControllerInfo {
    /// Create a `ControllerInfo` from the return parameters for a controller information command
    ///
    /// # Panic
    /// This will panic if `raw` does not contain the correct controller information
    fn from_raw(index: u16, raw: &[u8]) -> Self {
        let raw_address = &raw[0..6];
        let company_id = <u16>::from_le_bytes([raw[7], raw[8]]);
        let class_of_device = [raw[17], raw[18], raw[19]];
        let name = std::ffi::CStr::from_bytes_until_nul(&raw[20..(20 + 249)])
            .expect("c string")
            .to_str()
            .expect("valid utf-8")
            .to_string();

        let address = bo_tie_core::BluetoothDeviceAddress::try_from(raw_address).unwrap();

        let info_type = InfoType::Basic { class_of_device, name };

        ControllerInfo {
            index,
            address,
            company_id,
            info_type,
        }
    }

    /// Create a `ControllerInfo` from return parameters for an extended controller information command
    ///
    /// # Panic
    /// This will panic if `raw` does not contain the correct *extended* controller information
    fn from_raw_extended(index: u16, raw: &[u8]) -> Self {
        let raw_address = &raw[0..6];
        let company_id = <u16>::from_le_bytes([raw[7], raw[8]]);
        let eir_data_len: usize = <u16>::from_le_bytes([raw[18], raw[19]]).into();
        let eir = raw[20..(20 + eir_data_len)].to_vec();

        let address = bo_tie_core::BluetoothDeviceAddress::try_from(raw_address).unwrap();

        let info_type = InfoType::Enhanced(eir);

        ControllerInfo {
            index,
            address,
            company_id,
            info_type,
        }
    }

    /// Get the controller index
    pub fn get_index(&self) -> u16 {
        self.index
    }

    /// Get the public address of the controller
    pub fn get_address(&self) -> bo_tie_core::BluetoothDeviceAddress {
        self.address
    }

    /// Get the company identifier
    pub fn get_company_identifier(&self) -> u16 {
        self.company_id
    }

    /// Get the assigned name of the Controller
    ///
    /// This is the local name that is exposed to other devices during discovery. This will return an empty string if
    /// a complete local name has not been assigned to the device.
    pub fn get_name(&self) -> &str {
        use bo_tie_gap::assigned::{AssignedTypes, EirOrAdIterator, TryFromStruct};

        match &self.info_type {
            InfoType::Basic { name, .. } => name,
            InfoType::Enhanced(v) => EirOrAdIterator::new(v)
                .silent()
                .find(|eir_struct| eir_struct.is_assigned_type(AssignedTypes::CompleteLocalName))
                .map(|eir_struct| {
                    bo_tie_gap::assigned::local_name::LocalName::try_from_struct(eir_struct)
                        .unwrap()
                        .into_name()
                })
                .unwrap_or_default(),
        }
    }

    /// Get the raw class of the device
    ///
    /// This returns the class of the device if the Bluetooth controller supports BR/EDR.
    pub fn get_raw_class_of_device(&self) -> Option<[u8; 3]> {
        match &self.info_type {
            InfoType::Basic { class_of_device, .. } => Some(*class_of_device),
            InfoType::Enhanced(v) => bo_tie_gap::assigned::EirOrAdIterator::new(v)
                .silent()
                .find(|eir_struct| eir_struct.is_assigned_type(bo_tie_gap::assigned::AssignedTypes::ClassOfDevice))
                .map(|eir_struct| <[u8; 3]>::try_from(eir_struct.get_data()).unwrap()),
        }
    }
}

#[cfg(feature = "ctrls_intf")]
impl std::fmt::Display for ControllerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "index: {:#6x}, company id: {:#6x}", self.index, self.company_id)?;

        if let Some(common_code) = CommonManufactureCodes::try_from(self.company_id) {
            write!(f, " ({}) ", common_code)?;
        } else {
            write!(f, " ")?;
        }

        if !self.get_name().is_empty() {
            write!(f, "local name: {}, ", self.get_name())?;
        }

        if let Some(class_of_device) = self.get_raw_class_of_device() {
            print_class_of_device(&class_of_device, f)?;
        }

        Ok(())
    }
}

#[cfg(feature = "ctrls_intf")]
impl std::fmt::Debug for ControllerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(&self, f)
    }
}

// Something similar will probably be pulling into bo-tie if BR/EDR is ever implemented.
#[cfg(feature = "ctrls_intf")]
fn print_class_of_device(class_of_device: &[u8; 3], f: &mut std::fmt::Formatter) -> std::fmt::Result {
    let major_service_classes = (13..=23)
        .filter(|bit| class_of_device[bit / 8] & (1u8 << bit % 8) != 0)
        .map(|bit| match bit {
            13 => "Limited Discoverable Mode",
            15 => "LE audio",
            16 => "Positioning",
            17 => "Networking",
            18 => "Rendering",
            19 => "Capturing",
            20 => "Object Transfer",
            21 => "Audio",
            22 => "Telephony",
            23 => "Information",
            _ => unreachable!(),
        });

    let major_device_class = match class_of_device[1] & 0x1F {
        0 => "Miscellaneous",
        1 => "Computer",
        2 => "Phone",
        3 => "LAN/Network Access Point",
        4 => "Audio/Video",
        5 => "Peripheral",
        6 => "Imaging",
        7 => "Wearable",
        8 => "Toy",
        9 => "Health",
        0x1F => "Uncategorized",
        _ => "{{undefined}}",
    };

    let minor_device_class = match class_of_device[0] >> 2 {
        0 => "Uncategorized",
        1 => "Desktop Workstation",
        2 => "Server-class Computer",
        3 => "Laptop",
        4 => "Handheld PC/PDA",
        5 => "Palm-size PC/PDA",
        6 => "Wearable Computer",
        7 => "Tablet",
        _ => "{{undefined}}",
    };

    write!(f, "major service classes: [")?;

    for class in major_service_classes {
        write!(f, "{},", class)?;
    }

    write!(
        f,
        "] device class major: {}, device class minor: {}",
        major_device_class, minor_device_class
    )
}
