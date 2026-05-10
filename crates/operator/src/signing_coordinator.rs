//! Distributed MuSig2 signing coordinator.
//!
//! Manages signing sessions between operators. The leader (signer_index=0)
//! drives signing rounds; other operators validate and respond.

use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::{Amount, OutPoint, Transaction, XOnlyPublicKey};
use musig2::secp::Scalar;
use musig2::{KeyAggContext, LiftedSignature, PartialSignature, PubNonce};
use tokio::sync::Mutex;

use layer_tree_core::signing::{compute_sighash_for_input, SigningError, SigningSession};
use layer_tree_core::state::build_state_transactions;
use layer_tree_core::transactions::{
    build_refresh_with_io, p2tr_script_pubkey, DepositInput, WithdrawalOutput,
};
use layer_tree_core::tree::UserAllocation;
use layer_tree_core::Params;

/// A pending signing session with all context needed to complete it.
pub struct ActiveSession {
    pub session: SigningSession,
    pub epoch_id: u64,
    pub state_number: u32,
    pub nsequence: u16,
    pub allocations: Vec<UserAllocation>,
    pub unsigned_txs: Vec<Transaction>,
}

/// The signing coordinator manages the distributed MuSig2 protocol.
pub struct SigningCoordinator {
    pub signer_index: usize,
    pub n_signers: usize,
    pub secret_key: Scalar,
    pub key_agg_ctx: KeyAggContext,
    pub operator_xonly: XOnlyPublicKey,
    pub params: Params,

    /// Active signing sessions keyed by session_id.
    sessions: HashMap<[u8; 32], ActiveSession>,

    /// Current epoch state.
    pub current_epoch_id: u64,
    pub kickoff_outpoint: Option<OutPoint>,
    pub kickoff_output_amount: Option<Amount>,
}

impl SigningCoordinator {
    pub fn new(
        signer_index: usize,
        n_signers: usize,
        secret_key: Scalar,
        key_agg_ctx: KeyAggContext,
        operator_xonly: XOnlyPublicKey,
        params: Params,
    ) -> Self {
        Self {
            signer_index,
            n_signers,
            secret_key,
            key_agg_ctx,
            operator_xonly,
            params,
            sessions: HashMap::new(),
            current_epoch_id: 0,
            kickoff_outpoint: None,
            kickoff_output_amount: None,
        }
    }

    /// Leader: initiate a new state signing session.
    /// Returns (session_id, our_nonces).
    pub fn propose_state(
        &mut self,
        session_id: [u8; 32],
        epoch_id: u64,
        state_number: u32,
        nsequence: u16,
        allocations: Vec<UserAllocation>,
    ) -> Result<Vec<PubNonce>, SigningError> {
        let kickoff_outpoint = self
            .kickoff_outpoint
            .ok_or(SigningError::WrongState("no kickoff outpoint set"))?;
        let kickoff_output_amount = self
            .kickoff_output_amount
            .ok_or(SigningError::WrongState("no kickoff output amount set"))?;

        let (exit_tree, txs, _prevouts, sighashes) = build_state_transactions(
            kickoff_outpoint,
            kickoff_output_amount,
            &self.operator_xonly,
            &allocations,
            nsequence,
            self.params.root_fee(),
            self.params.split_fee(),
        );
        let _ = exit_tree; // exit tree stored later when signing completes

        let (session, our_nonces) = SigningSession::new(
            self.signer_index,
            self.n_signers,
            sighashes,
            &self.key_agg_ctx,
            &self.secret_key,
        )?;

        self.sessions.insert(
            session_id,
            ActiveSession {
                session,
                epoch_id,
                state_number,
                nsequence,
                allocations,
                unsigned_txs: txs,
            },
        );

        Ok(our_nonces)
    }

    /// Initiate a refresh TX signing session.
    ///
    /// Builds the unsigned refresh TX with deposit inputs and withdrawal outputs,
    /// then starts a MuSig2 session for signing the pool input.
    /// Returns our pub nonces.
    pub fn propose_refresh(
        &mut self,
        session_id: [u8; 32],
        deposits: Vec<DepositInput>,
        withdrawals: Vec<WithdrawalOutput>,
        refresh_fee: Amount,
    ) -> Result<Vec<PubNonce>, SigningError> {
        let pool_outpoint = self
            .kickoff_outpoint
            .ok_or(SigningError::WrongState("no kickoff outpoint set"))?;
        let pool_amount = self
            .kickoff_output_amount
            .ok_or(SigningError::WrongState("no kickoff output amount set"))?;

        let tx = build_refresh_with_io(
            pool_outpoint,
            pool_amount,
            &self.operator_xonly,
            &deposits,
            &withdrawals,
            refresh_fee,
        );

        // Build prevouts for all inputs (pool + deposits)
        let mut all_prevouts = vec![bitcoin::TxOut {
            value: pool_amount,
            script_pubkey: p2tr_script_pubkey(&self.operator_xonly),
        }];
        for dep in &deposits {
            all_prevouts.push(bitcoin::TxOut {
                value: dep.amount,
                script_pubkey: dep.script_pubkey.clone(),
            });
        }

        // Only need sighash for input 0 (pool input, MuSig2 signed)
        let sighash = compute_sighash_for_input(&tx, 0, &all_prevouts);

        let (session, our_nonces) = SigningSession::new(
            self.signer_index,
            self.n_signers,
            vec![sighash],
            &self.key_agg_ctx,
            &self.secret_key,
        )?;

        self.sessions.insert(
            session_id,
            ActiveSession {
                session,
                epoch_id: self.current_epoch_id,
                state_number: 0, // refresh has no state_number
                nsequence: 0,
                allocations: Vec::new(),
                unsigned_txs: vec![tx],
            },
        );

        Ok(our_nonces)
    }

    /// Process received nonces for a session.
    /// Returns our partial sigs if all nonces have been collected.
    pub fn receive_nonces(
        &mut self,
        session_id: &[u8; 32],
        from_signer: usize,
        nonces: Vec<PubNonce>,
    ) -> Result<Option<Vec<PartialSignature>>, SigningError> {
        let active = self
            .sessions
            .get_mut(session_id)
            .ok_or(SigningError::WrongState("unknown session"))?;
        active
            .session
            .receive_nonces(from_signer, nonces, &self.secret_key)
    }

    /// Process received partial signatures for a session.
    /// Returns final signatures if all partial sigs have been collected.
    pub fn receive_partial_sigs(
        &mut self,
        session_id: &[u8; 32],
        from_signer: usize,
        partial_sigs: Vec<PartialSignature>,
    ) -> Result<Option<Vec<LiftedSignature>>, SigningError> {
        let active = self
            .sessions
            .get_mut(session_id)
            .ok_or(SigningError::WrongState("unknown session"))?;
        active
            .session
            .receive_partial_sigs(from_signer, partial_sigs)
    }

    /// Check if a session is complete and retrieve the final signed transactions.
    pub fn take_completed_session(
        &mut self,
        session_id: &[u8; 32],
    ) -> Option<(ActiveSession, Vec<LiftedSignature>)> {
        let active = self.sessions.get(session_id)?;
        if !active.session.is_complete() {
            return None;
        }
        let sigs = active.session.signatures()?.to_vec();
        let active = self.sessions.remove(session_id)?;
        Some((active, sigs))
    }

    /// Check if a session exists.
    pub fn has_session(&self, session_id: &[u8; 32]) -> bool {
        self.sessions.contains_key(session_id)
    }
}

/// Thread-safe coordinator wrapped in Arc<Mutex>.
pub type SharedCoordinator = Arc<Mutex<SigningCoordinator>>;
