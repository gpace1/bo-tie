//! Host Controller interface transport layer

/// UART interface
pub mod uart {

    /// Packet Indicator
    ///
    /// The packet indicator is used with UART to indicate the type of packet sent or received on
    /// the interface.
    pub enum HciPacketIndicator {
        Command,
        AclData,
        ScoData,
        Event,
    }

    impl HciPacketIndicator {
        pub fn val(&self) -> u8 {
            match self {
                HciPacketIndicator::Command => 0x01,
                HciPacketIndicator::AclData => 0x02,
                HciPacketIndicator::ScoData => 0x03,
                HciPacketIndicator::Event => 0x04,
            }
        }
    }
}