//! Data iterators for signalling packets

use crate::signals::packets::{
    CommandRejectResponse, DisconnectRequest, DisconnectResponse, FlowControlCreditInd, LeCreditBasedConnectionRequest,
    LeCreditBasedConnectionResponse,
};

/// An iterator over the bytes of a LE credit based connection request PDU
pub struct LeCreditRequestIter {
    req: LeCreditBasedConnectionRequest,
    pos: usize,
}

impl LeCreditRequestIter {
    pub fn new(req: LeCreditBasedConnectionRequest) -> Self {
        let pos = 0;

        LeCreditRequestIter { req, pos }
    }
}

impl Iterator for LeCreditRequestIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = match self.pos {
            0 => Some(LeCreditBasedConnectionRequest::CODE),
            1 => Some(self.req.identifier.get()),
            2 => Some(10),
            3 => Some(0),
            4 => self.req.spsm.0.to_le_bytes().get(0).copied(),
            5 => self.req.spsm.0.to_le_bytes().get(1).copied(),
            6 => self.req.get_source_cid().to_val().to_le_bytes().get(0).copied(),
            7 => self.req.get_source_cid().to_val().to_le_bytes().get(1).copied(),
            8 => self.req.mtu.to_le_bytes().get(0).copied(),
            9 => self.req.mtu.to_le_bytes().get(1).copied(),
            10 => self.req.mps.to_le_bytes().get(0).copied(),
            11 => self.req.mps.to_le_bytes().get(1).copied(),
            12 => self.req.initial_credits.to_le_bytes().get(0).copied(),
            13 => self.req.initial_credits.to_le_bytes().get(1).copied(),
            _ => None,
        };

        self.pos += 1;

        ret
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = 14usize.checked_sub(self.pos).unwrap_or_default();

        (size, Some(size))
    }
}

/// An iterator over the bytes of a command reject response PDU
pub struct CmdRejectRspIter {
    reject: CommandRejectResponse,
    pos: usize,
}

impl ExactSizeIterator for LeCreditRequestIter {}

impl CmdRejectRspIter {
    pub fn new(reject: CommandRejectResponse) -> Self {
        let pos = 0;

        CmdRejectRspIter { reject, pos }
    }
}

impl Iterator for CmdRejectRspIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = match self.pos {
            0 => Some(CommandRejectResponse::CODE),
            1 => Some(self.reject.identifier.get()),

            // using `to_le_bytes` here is kinda dirty without
            // converting to u16, but the logic is the same.
            2 => self.reject.data.len().to_le_bytes().get(0).copied(),
            3 => self.reject.data.len().to_le_bytes().get(1).copied(),
            4 => self.reject.reason.into_val().to_le_bytes().get(0).copied(),
            5 => self.reject.reason.into_val().to_le_bytes().get(1).copied(),
            _ => self.reject.data.iter_pos(self.pos - 6),
        };

        self.pos += 1;

        ret
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = (6 + self.reject.data.len()).checked_sub(self.pos).unwrap_or_default();

        (size, Some(size))
    }
}

impl ExactSizeIterator for CmdRejectRspIter {}

/// An iterator over the bytes of a disconnect request PDU
pub struct DisconnectRequestIter {
    request: DisconnectRequest,
    pos: usize,
}

impl DisconnectRequestIter {
    pub fn new(request: DisconnectRequest) -> Self {
        let pos = 0;

        DisconnectRequestIter { request, pos }
    }
}

impl Iterator for DisconnectRequestIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = match self.pos {
            0 => Some(DisconnectRequest::CODE),
            1 => Some(self.request.identifier.get()),

            // using `to_le_bytes` here is kinda dirty without
            // converting to u16, but the logic is the same.
            2 => 4u16.to_le_bytes().get(0).copied(),
            3 => 4u16.to_le_bytes().get(1).copied(),
            4 => self.request.destination_cid.to_val().to_le_bytes().get(0).copied(),
            5 => self.request.destination_cid.to_val().to_le_bytes().get(1).copied(),
            6 => self.request.source_cid.to_val().to_le_bytes().get(0).copied(),
            7 => self.request.source_cid.to_val().to_le_bytes().get(1).copied(),
            _ => None,
        };

        self.pos += 1;

        ret
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = 8usize.checked_sub(self.pos).unwrap_or_default();

        (size, Some(size))
    }
}

impl ExactSizeIterator for DisconnectRequestIter {}

/// An iterator over the bytes of a disconnect response PDU
pub struct DisconnectResponseIter {
    request: DisconnectResponse,
    pos: usize,
}

impl<'a> DisconnectResponseIter {
    pub fn new(request: DisconnectResponse) -> Self {
        let pos = 0;

        DisconnectResponseIter { request, pos }
    }
}

impl Iterator for DisconnectResponseIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = match self.pos {
            0 => Some(DisconnectRequest::CODE),
            1 => Some(self.request.identifier.get()),

            // using `to_le_bytes` here is kinda dirty without
            // converting to u16, but the logic is the same.
            2 => 4u16.to_le_bytes().get(0).copied(),
            3 => 4u16.to_le_bytes().get(1).copied(),
            4 => self.request.destination_cid.to_val().to_le_bytes().get(0).copied(),
            5 => self.request.destination_cid.to_val().to_le_bytes().get(1).copied(),
            6 => self.request.source_cid.to_val().to_le_bytes().get(0).copied(),
            7 => self.request.source_cid.to_val().to_le_bytes().get(1).copied(),
            _ => None,
        };

        self.pos += 1;

        ret
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = 8usize.checked_sub(self.pos).unwrap_or_default();

        (size, Some(size))
    }
}

impl ExactSizeIterator for DisconnectResponseIter {}

/// An iterator over the bytes of a LE credit based connection response PDU
pub struct LeCreditResponseIter {
    rsp: LeCreditBasedConnectionResponse,
    pos: usize,
}

impl LeCreditResponseIter {
    pub fn new(rsp: LeCreditBasedConnectionResponse) -> Self {
        let pos = 0;

        LeCreditResponseIter { rsp, pos }
    }
}

impl Iterator for LeCreditResponseIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = match self.pos {
            0 => Some(LeCreditBasedConnectionResponse::CODE),
            1 => Some(self.rsp.identifier.get()),
            2 => Some(10),
            3 => Some(0),
            4 => self
                .rsp
                .get_destination_cid()
                .map(|cid| cid.to_val().to_le_bytes().get(0).copied())
                .unwrap_or(Some(0)),
            5 => self
                .rsp
                .get_destination_cid()
                .map(|cid| cid.to_val().to_le_bytes().get(1).copied())
                .unwrap_or(Some(0)),
            6 => self.rsp.mtu.to_le_bytes().get(0).copied(),
            7 => self.rsp.mtu.to_le_bytes().get(1).copied(),
            8 => self.rsp.mps.to_le_bytes().get(0).copied(),
            9 => self.rsp.mps.to_le_bytes().get(1).copied(),
            10 => self.rsp.initial_credits.to_le_bytes().get(0).copied(),
            11 => self.rsp.initial_credits.to_le_bytes().get(1).copied(),
            12 => self.rsp.result.to_val().to_le_bytes().get(0).copied(),
            13 => self.rsp.result.to_val().to_le_bytes().get(1).copied(),
            _ => None,
        };

        self.pos += 1;

        ret
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = 14usize.checked_sub(self.pos).unwrap_or_default();

        (size, Some(size))
    }
}

impl ExactSizeIterator for LeCreditResponseIter {}

pub struct FlowControlCreditIndIter {
    ind: FlowControlCreditInd,
    pos: usize,
}

impl FlowControlCreditIndIter {
    pub fn new(ind: FlowControlCreditInd) -> Self {
        let pos = 0;

        FlowControlCreditIndIter { ind, pos }
    }
}

impl Iterator for FlowControlCreditIndIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = match self.pos {
            0 => Some(FlowControlCreditInd::CODE),
            1 => Some(self.ind.identifier.get()),
            2 => Some(4),
            3 => Some(0),
            4 => self.ind.cid.to_val().to_le_bytes().get(0).copied(),
            5 => self.ind.cid.to_val().to_le_bytes().get(1).copied(),
            6 => self.ind.credits.to_le_bytes().get(0).copied(),
            7 => self.ind.credits.to_le_bytes().get(0).copied(),
            _ => None,
        };

        self.pos += 1;

        ret
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = 14usize.checked_sub(self.pos).unwrap_or_default();

        (size, Some(size))
    }
}

impl ExactSizeIterator for FlowControlCreditIndIter {}
