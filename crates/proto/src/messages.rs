//! Protobuf-compatible message types for the Layer Tree operator protocol.

use prost::Message;

// --- Handshake ---

#[derive(Clone, PartialEq, Message)]
pub struct HandshakeReq {
    #[prost(uint32, tag = "1")]
    pub signer_index: u32,
    /// 33-byte compressed public key.
    #[prost(bytes = "vec", tag = "2")]
    pub pubkey: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct HandshakeResp {
    #[prost(bool, tag = "1")]
    pub accepted: bool,
    #[prost(uint32, tag = "2")]
    pub signer_index: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub pubkey: Vec<u8>,
}

// --- State Signing (2-round MuSig2) ---

#[derive(Clone, PartialEq, Message)]
pub struct Allocation {
    /// 32-byte x-only public key.
    #[prost(bytes = "vec", tag = "1")]
    pub pubkey: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub amount_sats: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProposeStateReq {
    /// 32-byte random session identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub session_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub epoch_id: u64,
    #[prost(uint32, tag = "3")]
    pub state_number: u32,
    #[prost(uint32, tag = "4")]
    pub nsequence: u32,
    #[prost(message, repeated, tag = "5")]
    pub allocations: Vec<Allocation>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProposeStateResp {
    #[prost(bool, tag = "1")]
    pub accepted: bool,
    #[prost(string, tag = "2")]
    pub reject_reason: String,
    /// 66 bytes each, one per transaction.
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub pub_nonces: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SignerNonces {
    #[prost(uint32, tag = "1")]
    pub signer_index: u32,
    /// 66 bytes each.
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub pub_nonces: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SubmitNoncesReq {
    #[prost(bytes = "vec", tag = "1")]
    pub session_id: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub signer_nonces: Vec<SignerNonces>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SubmitNoncesResp {
    #[prost(bool, tag = "1")]
    pub accepted: bool,
    #[prost(string, tag = "2")]
    pub reject_reason: String,
    /// 32 bytes each, one per transaction.
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub partial_sigs: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SignerPartialSigs {
    #[prost(uint32, tag = "1")]
    pub signer_index: u32,
    /// 32 bytes each.
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub partial_sigs: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SubmitPartialSigsReq {
    #[prost(bytes = "vec", tag = "1")]
    pub session_id: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub signer_partial_sigs: Vec<SignerPartialSigs>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SubmitPartialSigsResp {
    #[prost(bool, tag = "1")]
    pub accepted: bool,
    #[prost(string, tag = "2")]
    pub reject_reason: String,
}

// --- Cooperative Refresh ---

#[derive(Clone, PartialEq, Message)]
pub struct DepositInput {
    /// 32-byte txid.
    #[prost(bytes = "vec", tag = "1")]
    pub txid: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub vout: u32,
    #[prost(uint64, tag = "3")]
    pub amount_sats: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct WithdrawalOutput {
    #[prost(bytes = "vec", tag = "1")]
    pub script_pubkey: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub amount_sats: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProposeRefreshReq {
    #[prost(bytes = "vec", tag = "1")]
    pub session_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub epoch_id: u64,
    #[prost(message, repeated, tag = "3")]
    pub deposits: Vec<DepositInput>,
    #[prost(message, repeated, tag = "4")]
    pub withdrawals: Vec<WithdrawalOutput>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProposeRefreshResp {
    #[prost(bool, tag = "1")]
    pub accepted: bool,
    #[prost(string, tag = "2")]
    pub reject_reason: String,
    /// Nonces for refresh tx signing.
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub pub_nonces: Vec<Vec<u8>>,
}
