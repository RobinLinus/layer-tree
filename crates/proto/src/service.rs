//! Service trait definition for operator-to-operator communication.
//!
//! Defines the `PeerService` async trait. The actual gRPC server/client
//! implementations live in the operator crate.

use crate::messages::*;

/// Server-side trait for the operator peer service.
///
/// Implement this trait on your operator server to handle incoming requests
/// from other operators during distributed MuSig2 signing.
///
/// The leader (signer_index=0) drives all signing rounds:
/// 1. `propose_state` — Leader sends allocations, peer returns nonces
/// 2. `submit_nonces` — Leader sends all nonces, peer returns partial sigs
/// 3. `submit_partial_sigs` — Leader sends all partial sigs, peer completes
#[tonic::async_trait]
pub trait PeerService: Send + Sync + 'static {
    /// Initial handshake to verify operator identity.
    async fn handshake(
        &self,
        request: tonic::Request<HandshakeReq>,
    ) -> Result<tonic::Response<HandshakeResp>, tonic::Status>;

    /// Leader proposes a new state. Peer validates and returns nonces.
    async fn propose_state(
        &self,
        request: tonic::Request<ProposeStateReq>,
    ) -> Result<tonic::Response<ProposeStateResp>, tonic::Status>;

    /// Leader distributes collected nonces. Peer returns partial signatures.
    async fn submit_nonces(
        &self,
        request: tonic::Request<SubmitNoncesReq>,
    ) -> Result<tonic::Response<SubmitNoncesResp>, tonic::Status>;

    /// Leader distributes collected partial signatures. Peer completes signing.
    async fn submit_partial_sigs(
        &self,
        request: tonic::Request<SubmitPartialSigsReq>,
    ) -> Result<tonic::Response<SubmitPartialSigsResp>, tonic::Status>;

    /// Leader proposes a cooperative refresh (new epoch).
    async fn propose_refresh(
        &self,
        request: tonic::Request<ProposeRefreshReq>,
    ) -> Result<tonic::Response<ProposeRefreshResp>, tonic::Status>;
}
