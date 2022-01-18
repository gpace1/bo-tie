/// LLID Type
///
/// This further breaks up the LLID field into five different types from the three that are
/// listed in the LLID field of the Link Layer
pub enum LLIDType {
    /// l2cap message fragment
    Fragment,
    /// Empty PDU
    Empty,
    /// Start of a fragmented l2cap message
    Start,
    /// Complete l2cap message
    Complete,
    /// Control pdu
    Control
}

/// LLID
enum LLID {
    /// Reserved for future use
    Rfu,
    /// Fragmented l2cap message or empty pdu
    LLDataPduFragEmpty,
    /// Start of fragmented l2cap message or Complete l2cap message,
    LLDataPduStarCompl,
    /// Control PDU
    Control,
}

pub struct DataChannelPdu {
    /// LLID
    llid: LLID,
    /// Next expected sequence number
    nesn: bool,
    /// More Data
    md: bool,
    /// payload
    payload: Vec<u8>,
}
