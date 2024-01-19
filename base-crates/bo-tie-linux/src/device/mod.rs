//! Linux Bluetooth device functionality controller methods
//!
//! These are functions that are used to control the interface to the bluetooth devices on the
//! system. This isn't a complete implementation of control commands/operations, it is just the
//! functionality used by this library. These are linux specific and have no relation to the
//! bluetooth specification.

use crate::{ArcFileDesc, InterfaceThread, LinuxInterface, PollEvent};

#[allow(non_camel_case_types, dead_code)]
pub(crate) mod bindings;
#[allow(non_camel_case_types, dead_code)]
pub(crate) mod bindings_errata;
pub(crate) mod legacy;
mod mgmt;

enum ControllerInterfaceType {
    Legacy(legacy::LegacySocket),
    Management(mgmt::ManagementSocket),
}

/// Interface to the controllers attached to the Linux kernel
///
/// This is used to interact with the kennel for finding out the Bluetooth controllers that are currently registered
/// with it.
pub struct ControllersInterface {
    inner: ControllerInterfaceType,
}

impl ControllersInterface {
    /// Create a new `ControllerInterface`
    pub(crate) fn new() -> Result<ControllersInterface, Box<dyn std::error::Error>> {
        let inner = if mgmt::ManagementSocket::can_use()? {
            let mgmt = mgmt::ManagementSocket::new()?;

            ControllerInterfaceType::Management(mgmt)
        } else {
            let legacy = legacy::LegacySocket::new()?;

            ControllerInterfaceType::Legacy(legacy)
        };

        Ok(ControllersInterface { inner })
    }

    /// Check if this is using legacy mode
    ///
    /// The management interface was added to the Linux kernel v3.4. If this is running on an earlier kernel then the
    /// controller interface will be in legacy mode.
    #[cfg(feature = "ctrls_intf")]
    pub fn in_legacy_mode(&self) -> bool {
        if let ControllerInterfaceType::Legacy(_) = self.inner {
            true
        } else {
            false
        }
    }

    /// Get the indexes of the controller on the system
    #[cfg(feature = "ctrls_intf")]
    pub fn get_controller_info(&mut self) -> Result<Vec<ControllerInformation>, Box<dyn std::error::Error>> {
        match &mut self.inner {
            ControllerInterfaceType::Legacy(l) => l
                .get_index_list()?
                .into_iter()
                .map(|i| l.get_dev_info(i).map(|d| ControllerInformation::from_device_info(d)))
                .try_fold(Vec::new(), |mut v, ci_rslt| {
                    v.push(ci_rslt?);

                    Ok(v)
                })
                .map_err(|e: nix::Error| e.into()),
            ControllerInterfaceType::Management(m) => m
                .read_controller_index_list()?
                .into_iter()
                .map(|i| {
                    m.read_controller_info(i)
                        .map(|c| ControllerInformation::from_controller_info(c))
                })
                .try_fold(Vec::new(), |mut v, ci_rslt| {
                    v.push(ci_rslt?);

                    Ok(v)
                }),
        }
    }

    /// Create an HCI to a controller.
    ///
    /// The input index
    pub(crate) fn create_interface(
        &mut self,
        index: u16,
    ) -> Result<
        (
            LinuxInterface<bo_tie_hci_util::channel::tokio::UnboundedChannelReserve>,
            bo_tie_hci_util::channel::tokio::UnboundedHostChannelEnds,
        ),
        Box<dyn std::error::Error>,
    > {
        use nix::sys::{epoll, eventfd};

        // Create the shared file descriptor to the Bluetooth controller
        let controller_socket = ArcFileDesc::from(match &mut self.inner {
            ControllerInterfaceType::Legacy(l) => l.make_socket(index)?,
            ControllerInterfaceType::Management(m) => m.make_socket(index)?,
        });

        let exit_event = ArcFileDesc::from(eventfd::eventfd(0, eventfd::EfdFlags::empty())?);

        let epoll = epoll::Epoll::new(epoll::EpollCreateFlags::empty())?;

        epoll.add(&controller_socket, PollEvent::BluetoothController.into())?;

        epoll.add(&exit_event, PollEvent::TaskExit.into())?;

        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();

        let (reserve, host_ends) = bo_tie_hci_util::channel::tokio_unbounded(1, 0);

        let interface = bo_tie_hci_interface::Interface::new(reserve);

        let join_handle = InterfaceThread {
            sender,
            controller_socket: controller_socket.clone(),
            _exit_event: exit_event.clone(),
            epoll,
        }
        .spawn()
        .into();

        let this = LinuxInterface {
            controller_socket,
            exit_event,
            receiver,
            interface,
            join_handle,
        };

        Ok((this, host_ends))
    }
}

#[cfg(feature = "ctrls_intf")]
enum ControllerInformationInner {
    Legacy(legacy::DeviceInfo),
    Management(mgmt::ControllerInfo),
}

/// Information on a controller
///
/// This is information that is collected from the Linux kernel about a Bluetooth Controller. If the Bluetooth
/// management interface was used there will be much more information about the controllers on this system, but in
/// legacy mode there should be enough data to support selecting the desired Bluetooth controller.
///
/// ### Legacy Mode
/// Legacy is only used when the kernel does not support the Bluetooth management interface. The management interface
/// has been supported since v3.4 of Linux, so legacy will only be used if the kernel is an earlier version.
#[cfg(feature = "ctrls_intf")]
pub struct ControllerInformation {
    inner: ControllerInformationInner,
}

#[cfg(feature = "ctrls_intf")]
impl ControllerInformation {
    /// Create a `ControllerInformation` from a `legacy::DeviceInfo`
    fn from_device_info(device_info: legacy::DeviceInfo) -> Self {
        let inner = ControllerInformationInner::Legacy(device_info);

        ControllerInformation { inner }
    }

    /// Create a `ControllerInformation` from a 'mgmt::ControllerInfo`
    fn from_controller_info(controller_info: mgmt::ControllerInfo) -> Self {
        let inner = ControllerInformationInner::Management(controller_info);

        ControllerInformation { inner }
    }

    /// Get the ID of the Controller
    ///
    /// This returns the identifier assigned by Linux to a Bluetooth controller.
    pub fn get_index(&self) -> u16 {
        match &self.inner {
            ControllerInformationInner::Legacy(l) => l.get_index(),
            ControllerInformationInner::Management(m) => m.get_index(),
        }
    }

    /// Get the public Address of the Controller
    ///
    /// # Note
    /// This can return an all zero address if the Controller is LE only
    pub fn get_address(&self) -> bo_tie_core::BluetoothDeviceAddress {
        match &self.inner {
            ControllerInformationInner::Legacy(l) => l.get_address(),
            ControllerInformationInner::Management(m) => m.get_address(),
        }
    }

    /// Check if this is legacy information
    ///
    /// This returns a boolean to indicate that the legacy interface for Bluetooth was used for interacting with the
    /// kernel. In legacy mode there is less information shared to the user about the controller.
    ///
    /// This will return true if the Linux kernel version is less than v3.4.
    pub fn is_using_legacy(&self) -> bool {
        if let ControllerInformationInner::Legacy(_) = &self.inner {
            true
        } else {
            false
        }
    }

    /// Get the name of the device
    ///
    /// This returns the assigned name of the device.
    ///
    /// On legacy mode the full name shortened to seven characters, regardless of whether a complete local name or a
    /// shortened local name is assigned.
    pub fn get_name(&self) -> &str {
        match &self.inner {
            ControllerInformationInner::Legacy(l) => l.get_name(),
            ControllerInformationInner::Management(m) => m.get_name(),
        }
    }

    /// Check if the device supports LE

    /// Get the company identifier
    ///
    /// This returns the identifier of the manufacturer. The manufacture's name corresponding to the identifier can be
    /// looked up within the *assigned numbers* document on the Bluetooth SIG website.
    ///
    /// This information is only available via the management interface.
    pub fn get_company_identifier(&self) -> Option<u16> {
        match &self.inner {
            ControllerInformationInner::Legacy(_) => None,
            ControllerInformationInner::Management(m) => Some(m.get_company_identifier()),
        }
    }

    /// Get the class of the device
    ///
    /// This returns the raw class of device for the controller. Information on the meaning of the the returned raw
    /// class of device can be found within the *assigned numbers* document on the Bluetooth SIG website.
    ///
    /// This information is only available if both the controller supports BR/EDR and the managment interface was used.
    pub fn get_raw_class_of_device(&self) -> Option<[u8; 3]> {
        match &self.inner {
            ControllerInformationInner::Legacy(_) => None,
            ControllerInformationInner::Management(m) => m.get_raw_class_of_device(),
        }
    }
}

#[cfg(feature = "ctrls_intf")]
impl std::fmt::Display for ControllerInformation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.inner {
            ControllerInformationInner::Legacy(l) => std::fmt::Display::fmt(&l, f),
            ControllerInformationInner::Management(m) => std::fmt::Display::fmt(&m, f),
        }
    }
}
