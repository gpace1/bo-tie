//! Low Energy (LE) Controller Commands
//!
//! The LE commands are broken up into modules based on the implementation of a Bluetooth LE
//! controller. The organization of commands in modules is based on the *LE Controller Requirements*
//! in the Bluetooth Specification (v5.0) found at 'Vol 2, Part E, section 3.1'.

#[macro_use] pub mod common;
pub mod mandatory;
pub mod transmitter;
pub mod receiver;
pub mod connection;
pub mod encryption;
pub mod con_pram_req;
pub mod privacy;

// LE implementation that is currently TODO
// pub mod br_edr {
//     // TODO does this module make sense?
//     pub mod support {
//         pub fn read_le_host() { unimplemented!() }
//         pub fn write_le_host() { unimplemented!() }
//     }
//     pub mod command {
//         pub fn read_buffer_size() { unimplemented!() }
//     }
// }
//
// pub mod scannable {
//     pub mod command {
//         pub fn set_scan_response_data() { unimplemented!() }
//     }
// }
//
// pub mod connection_parameters_request_procedure {
//     pub mod event {
//         pub fn remote_connection_paramter_request() { unimplemented!() }
//     }
//     pub mod command {
//         pub fn remote_connection_parameter_request_reply() { unimplemented!() }
//         pub fn remote_connection_parameter_request_negative_reply() { unimplemented!() }
//     }
// }
//
// pub mod ping {
//     pub mod event {
//         pub fn authenticated_payload_timeout_expired() { unimplemented!() }
//     }
//     pub mod command {
//         pub fn write_authenticated_payload_timeout() { unimplemented!() }
//         pub fn read_authenticated_payload_timeout() { unimplemented!() }
//         pub fn set_event_mask_page_2() { unimplemented!() }
//     }
// }
//
// pub mod data_packet_length_extension {
//     pub mod event {
//         pub fn data_length_change() { unimplemented!() }
//     }
//     pub mod command {
//         pub fn set_data_length() { unimplemented!() }
//         pub fn read_suggested_default_data_length() { unimplemented!() }
//         pub fn write_suggested_default_data_length() { unimplemented!() }
//     }
// }
//
// pub mod privacy {
//     pub mod event {
//         pub fn directed_advertising_report() { unimplemented!() }
//     }
//     pub mod command {
//         pub fn set_resolvable_private_address_timeout() { unimplemented!() }
//         pub fn set_address_resolution_enable() { unimplemented!() }
//         pub fn add_device_to_resolving_list() { unimplemented!() }
//         pub fn clear_resolving_list() { unimplemented!() }
//         pub fn set_privacy_mode() { unimplemented!() }
//         pub fn read_peer_resolvable_address() { unimplemented!() }
//         pub fn read_local_resolvable_address() { unimplemented!() }
//     }
// }
//
// pub mod phy_2m_or_coded {
//     pub mod event {
//         pub fn phy_update_complete() { unimplemented!() }
//     }
//     pub mod command {
//         pub fn read_phy() { unimplemented!() }
//         pub fn set_default_phy() { unimplemented!() }
//         pub fn set_phy() { unimplemented!() }
//         pub fn enhanced_transmitter_test() { unimplemented!() }
//         pub fn enhanced_receiver_test() { unimplemented!() }
//     }
// }
//
// pub mod extended_advertising {
//     pub mod event {
//         pub fn scan_request_received() { unimplemented!() }
//         pub fn advertising_set_terminated() { unimplemented!() }
//         pub fn scan_timeout() { unimplemented!() }
//         pub fn extended_advertising_report() { unimplemented!() }
//     }
//     pub mod legacy_event {
//         /// Superseded by extended_advertising_report
//         pub fn advertising_report() { unimplemented!() }
//         /// Superseded by exted_advertising_report
//         pub fn direted_advertising_report() { unimplemented!() }
//     }
//     pub mod command {
//         pub fn set_advertising_set_random_address() { unimplemented!() }
//         pub fn set_extended_advertising_parameters() { unimplemented!() }
//         pub fn set_extended_advertising_data() { unimplemented!() }
//         pub fn set_extended_scan_response_data() { unimplemented!() }
//         pub fn set_extended_advertising_enable() { unimplemented!() }
//         pub fn read_maximum_advertising_data_length() { unimplemented!() }
//         pub fn read_number_of_supported_advertising_sets() { unimplemented!() }
//         pub fn remove_advertising_set() { unimplemented!() }
//         pub fn clear_advertisisng_sets() { unimplemented!() }
//         pub fn set_extended_scan_parameters() { unimplemented!() }
//         pub fn set_extended_scan_enable() { unimplemented!() }
//         pub fn extended_create_connection() { unimplemented!() }
//     }
//     pub mod legacy_command {
//         /// Superseded by set_extended_advertising_parameters
//         pub fn set_advertising_parameters() { unimplemented!() }
//         /// No longer used
//         pub fn read_advertising_channel_tx_power() { unimplemented!() }
//         /// Superseded by set_extended_advertising_data
//         pub fn set_advertising_data() { unimplemented!() }
//         /// Superseded by set_extended_advertising_enable
//         pub fn set_scan_parameters() { unimplemented!() }
//         /// Superseded by set_extended_scan_enable
//         pub fn set_scan_enable() { unimplemented!() }
//         /// Superseded by extended_create_connection
//         pub fn extended_create_connection() { unimplemented!() }
//     }
// }
//
// pub mod periodic_advertising {
//     pub mod event {
//         pub fn periodic_advertising_report() { unimplemented!() }
//         pub fn periodic_advertising_sync_established() { unimplemented!() }
//         pub fn periodic_advertising_sync_lost() { unimplemented!() }
//     }
//     pub mod command {
//         pub fn set_periodic_advertising_parameters() { unimplemented!() }
//         pub fn set_periodic_advertising_data() { unimplemented!() }
//         pub fn set_periodic_advertising_enable() { unimplemented!() }
//         pub fn periodic_advertising_create_sync() { unimplemented!() }
//         pub fn periodic_advertising_create_sync_cancel() { unimplemented!() }
//         pub fn periodic_advertising_terminate_sync() { unimplemented!() }
//         pub fn add_device_to_periodic_advertising_list() { unimplemented!() }
//         pub fn remove_device_from_periodic_advertiser_list() { unimplemented!() }
//         pub fn clear_periodic_advertiser_list() { unimplemented!() }
//         pub fn read_periodic_advertiser_list_size() { unimplemented!() }
//     }
// }
//
// pub mod advertising_of_tx_power {
//     pub mod command {
//         pub fn read_rf_path_compensation() { unimplemented!() }
//         pub fn write_rf_path_compensation() { unimplemented!() }
//     }
// }
//
// pub mod channel_selection_algorithm_2 {
//     pub mod event {
//         pub fn chennel_selection_algorithm() { unimplemented!() }
//     }
// }
//
// pub mod other {
//     pub mod event {
//         pub fn data_buffer_overflow() { unimplemented!() }
//         pub fn hardware_error() { unimplemented!() }
//         pub fn read_local_p256_public_key_complete() { unimplemented!() }
//         pub fn generate_dh_key_complete() { unimplemented!() }
//     }
//     pub mod command {
//         pub fn host_buffer_size() { unimplemented!() }
//         pub fn host_number_of_completed_packets() { unimplemented!() }
//         pub fn le_read_transmit_power() { unimplemented!() }
//         pub fn le_read_p256_public_key() { unimplemented!() }
//         pub fn generate_dh_key() { unimplemented!() }
//     }
// }