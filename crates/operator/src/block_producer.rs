//! Block producer: collects user operations into blocks.
//!
//! The leader batches pending operations (transfers, withdrawals, deposit
//! confirmations) and produces blocks that are proposed to peer operators.

use std::sync::Arc;

use tokio::sync::Mutex;

use layer_tree_core::blockchain::{
    build_block, Block, ChainState, Operation, ValidationError,
};

/// Shared chain state wrapped for async access.
pub type SharedChainState = Arc<Mutex<ChainState>>;

/// The block producer maintains a mempool of pending operations
/// and produces blocks on demand.
pub struct BlockProducer {
    mempool: Vec<Operation>,
}

impl BlockProducer {
    pub fn new() -> Self {
        Self {
            mempool: Vec::new(),
        }
    }

    /// Add a pre-validated operation to the mempool.
    /// The caller (API layer) should have already verified the signature.
    pub fn add_operation(&mut self, op: Operation) {
        self.mempool.push(op);
    }

    /// Number of pending operations.
    pub fn pending_count(&self) -> usize {
        self.mempool.len()
    }

    /// Produce a block from all pending operations.
    /// Validates operations against the current chain state.
    /// Returns the block and new state, or an error if validation fails.
    /// Operations that fail validation are dropped (logged by caller).
    pub fn produce_block(
        &mut self,
        state: &ChainState,
    ) -> Result<Option<(Block, ChainState)>, ValidationError> {
        if self.mempool.is_empty() {
            return Ok(None);
        }

        // Try building with all operations. If any fail, filter them out.
        let ops = std::mem::take(&mut self.mempool);

        match build_block(state, ops.clone()) {
            Ok((block, new_state)) => Ok(Some((block, new_state))),
            Err(_) => {
                // Some operation is invalid. Try them one by one, keeping valid ones.
                let mut valid_ops = Vec::new();
                let mut test_state = state.clone();
                let secp = bitcoin::secp256k1::Secp256k1::verification_only();

                for op in ops {
                    let mut candidate = test_state.clone();
                    // Use a temporary apply to test validity
                    match try_apply_op(&mut candidate, &op, &secp) {
                        Ok(()) => {
                            test_state = candidate;
                            valid_ops.push(op);
                        }
                        Err(_) => {
                            // Drop invalid operation silently
                        }
                    }
                }

                if valid_ops.is_empty() {
                    return Ok(None);
                }

                let (block, new_state) = build_block(state, valid_ops)?;
                Ok(Some((block, new_state)))
            }
        }
    }

    /// Re-queue operations back into the mempool (e.g., after block rejection by peers).
    pub fn requeue(&mut self, ops: Vec<Operation>) {
        // Prepend so they get priority in the next block
        let mut combined = ops;
        combined.append(&mut self.mempool);
        self.mempool = combined;
    }

    /// Drain the mempool (used when resetting after block rejection).
    pub fn clear(&mut self) {
        self.mempool.clear();
    }
}

/// Try applying a single operation to a state (for filtering invalid ops).
fn try_apply_op(
    state: &mut ChainState,
    op: &Operation,
    _secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::VerifyOnly>,
) -> Result<(), ValidationError> {
    let (_, new_state) = build_block(state, vec![op.clone()])?;
    *state = new_state;
    Ok(())
}

/// Thread-safe block producer.
pub type SharedBlockProducer = Arc<Mutex<BlockProducer>>;
