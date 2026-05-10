use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Network, OutPoint};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use layer_tree_core::keys::OperatorSet;
use layer_tree_core::regtest::{KICKOFF_DELAY, NSEQ_START, STEP_SIZE};
use layer_tree_core::state::Epoch;
use layer_tree_core::transactions::p2tr_script_pubkey;
use layer_tree_core::tree::{ExitTree, UserAllocation};
use layer_tree_core::{KICKOFF_FEE, REFRESH_FEE, ROOT_FEE, SPLIT_FEE};
use musig2::secp::Scalar;

const NUM_OPERATORS: usize = 3;
const NUM_USERS: usize = 4;
const USER_BALANCE: u64 = 100_000;

fn main() {
    println!("=== Layer Tree Lifecycle Demo ===\n");
    println!("Demonstrates: epoch refresh invalidates old states,");
    println!("off-chain transfers, and unilateral exit from new epoch.\n");

    // Connect to bitcoind
    let rpc = Client::new(
        "http://127.0.0.1:18443",
        Auth::UserPass("rpcuser".into(), "rpcpassword".into()),
    )
    .expect("Failed to connect to bitcoind. Is it running with -regtest?");

    let wallet_name = "layer_tree_lifecycle";
    match rpc.create_wallet(wallet_name, None, None, None, None) {
        Ok(_) => println!("Created wallet: {}", wallet_name),
        Err(_) => {
            let _ = rpc.load_wallet(wallet_name);
            println!("Loaded existing wallet: {}", wallet_name);
        }
    }

    let rpc = Client::new(
        &format!("http://127.0.0.1:18443/wallet/{}", wallet_name),
        Auth::UserPass("rpcuser".into(), "rpcpassword".into()),
    )
    .unwrap();

    let mining_addr = rpc.get_new_address(None, None).unwrap().assume_checked();
    let _ = rpc.generate_to_address(101, &mining_addr).unwrap();
    println!("Mined 101 blocks for coinbase maturity\n");

    // === Setup: operators and user keys ===
    println!("--- Setup: {} operators, {} users ---", NUM_OPERATORS, NUM_USERS);
    let operators = OperatorSet::generate(NUM_OPERATORS);
    let agg_xonly = operators.aggregate_xonly();
    let secret_keys: Vec<Scalar> = operators.keys.iter().map(|k| k.secret).collect();

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let user_pubkeys: Vec<bitcoin::XOnlyPublicKey> = (0..NUM_USERS)
        .map(|_| {
            let mut bytes = [0u8; 32];
            rand::fill(&mut bytes);
            let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes).expect("valid key");
            bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
                .x_only_public_key()
                .0
        })
        .collect();

    // === Fund pool UTXO ===
    println!("\n--- Fund pool UTXO ---");

    // Compute pool amount from initial allocations
    let initial_allocs: Vec<UserAllocation> = user_pubkeys
        .iter()
        .map(|&pubkey| UserAllocation {
            pubkey,
            amount: Amount::from_sat(USER_BALANCE),
        })
        .collect();

    let dummy_tree = ExitTree::build(
        OutPoint::new(bitcoin::Txid::all_zeros(), 0),
        &initial_allocs,
        &agg_xonly,
        Amount::from_sat(SPLIT_FEE),
    );
    let pool_amount = dummy_tree.required_input_amount
        + Amount::from_sat(ROOT_FEE)
        + Amount::from_sat(KICKOFF_FEE);
    println!("Pool amount: {} sats", pool_amount.to_sat());

    let pool_address = Address::p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(agg_xonly),
        Network::Regtest,
    );
    let pool_txid = rpc
        .send_to_address(&pool_address, pool_amount, None, None, None, None, None, None)
        .expect("Failed to fund pool UTXO");

    let pool_tx = rpc.get_raw_transaction(&pool_txid, None).unwrap();
    let pool_script = p2tr_script_pubkey(&agg_xonly);
    let pool_vout = pool_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == pool_script && o.value == pool_amount)
        .expect("Pool output not found") as u32;
    let pool_outpoint = OutPoint::new(pool_txid, pool_vout);

    let _ = rpc.generate_to_address(1, &mining_addr).unwrap();
    println!("Pool funded: {}:{}", pool_txid, pool_vout);

    // Helper to build allocations with custom balances for user0 and user1
    let make_allocs = |balances: &[u64]| -> Vec<UserAllocation> {
        user_pubkeys
            .iter()
            .enumerate()
            .map(|(i, &pubkey)| UserAllocation {
                pubkey,
                amount: Amount::from_sat(balances[i]),
            })
            .collect()
    };

    let split_fee = Amount::from_sat(SPLIT_FEE);
    let root_fee = Amount::from_sat(ROOT_FEE);

    // =============================================
    // EPOCH 1: 3 states with off-chain transfers
    // =============================================
    println!("\n========== EPOCH 1 ==========");

    let mut epoch1 = Epoch::new(
        pool_outpoint,
        pool_amount,
        agg_xonly,
        KICKOFF_DELAY,
        Amount::from_sat(KICKOFF_FEE),
    );
    epoch1.sign_kickoff(&operators.key_agg_ctx, &secret_keys);

    // State 1: initial (all users 100k)
    epoch1.add_state(
        make_allocs(&[100_000, 100_000, 100_000, 100_000]),
        NSEQ_START, STEP_SIZE, split_fee, root_fee,
        &operators.key_agg_ctx, &secret_keys,
    );
    println!("State 1 (nSeq={}): all users 100k", epoch1.states[0].nsequence);

    // State 2: user0 sends 20k to user1
    epoch1.add_state(
        make_allocs(&[80_000, 120_000, 100_000, 100_000]),
        NSEQ_START, STEP_SIZE, split_fee, root_fee,
        &operators.key_agg_ctx, &secret_keys,
    );
    println!("State 2 (nSeq={}): user0→user1 20k", epoch1.states[1].nsequence);

    // State 3: user0 sends 20k to user2
    epoch1.add_state(
        make_allocs(&[60_000, 120_000, 120_000, 100_000]),
        NSEQ_START, STEP_SIZE, split_fee, root_fee,
        &operators.key_agg_ctx, &secret_keys,
    );
    println!("State 3 (nSeq={}): user0→user2 20k", epoch1.states[2].nsequence);

    // =============================================
    // COOPERATIVE REFRESH → EPOCH 2
    // =============================================
    println!("\n========== COOPERATIVE REFRESH ==========");

    let (signed_refresh, mut epoch2) = epoch1.refresh(
        Amount::from_sat(REFRESH_FEE),
        KICKOFF_DELAY,
        Amount::from_sat(KICKOFF_FEE),
        &operators.key_agg_ctx,
        &secret_keys,
    );
    epoch2.sign_kickoff(&operators.key_agg_ctx, &secret_keys);

    // Broadcast refresh TX (cooperative, no timelock)
    let refresh_txid = rpc
        .send_raw_transaction(&signed_refresh)
        .expect("Failed to broadcast refresh TX");
    println!("Refresh TX broadcast: {}", refresh_txid);
    let _ = rpc.generate_to_address(1, &mining_addr).unwrap();
    println!("Refresh TX confirmed");
    println!(
        "New pool: {} sats (old {} - {} fee)",
        epoch2.pool_amount.to_sat(),
        epoch1.pool_amount.to_sat(),
        REFRESH_FEE,
    );

    // Old epoch's kickoff TX should now be invalid
    println!("\nVerifying epoch 1 is invalidated...");
    match rpc.send_raw_transaction(&epoch1.kickoff_tx) {
        Ok(_) => panic!("Epoch 1 kickoff should be invalid!"),
        Err(_) => println!("  Epoch 1 kickoff: INVALID (pool UTXO spent by refresh)"),
    }

    // =============================================
    // EPOCH 2: 2 states
    // =============================================
    println!("\n========== EPOCH 2 ==========");

    // Epoch 2 allocation budget = epoch 1 budget - refresh_fee
    // Absorb the 200 sat fee reduction into user0's balance
    let epoch2_alloc_budget = NUM_USERS as u64 * USER_BALANCE - REFRESH_FEE;
    println!(
        "Allocation budget: {} sats ({} less than epoch 1)",
        epoch2_alloc_budget, REFRESH_FEE
    );

    // State 1: carry over epoch 1's latest balances, minus refresh fee from user0
    epoch2.add_state(
        make_allocs(&[59_800, 120_000, 120_000, 100_000]),
        NSEQ_START, STEP_SIZE, split_fee, root_fee,
        &operators.key_agg_ctx, &secret_keys,
    );
    println!(
        "State 1 (nSeq={}): user0=59,800 user1=120k user2=120k user3=100k",
        epoch2.states[0].nsequence
    );

    // State 2: user0 sends 20k to user3
    epoch2.add_state(
        make_allocs(&[39_800, 120_000, 120_000, 120_000]),
        NSEQ_START, STEP_SIZE, split_fee, root_fee,
        &operators.key_agg_ctx, &secret_keys,
    );
    println!(
        "State 2 (nSeq={}): user0→user3 20k",
        epoch2.states[1].nsequence
    );

    // =============================================
    // UNILATERAL EXIT FROM EPOCH 2, LATEST STATE
    // =============================================
    println!("\n========== UNILATERAL EXIT (EPOCH 2) ==========");

    // Mine blocks for kickoff timelock
    println!("Mining {} blocks for kickoff timelock...", KICKOFF_DELAY);
    let _ = rpc
        .generate_to_address(KICKOFF_DELAY as u64, &mining_addr)
        .unwrap();

    // Broadcast epoch 2 kickoff
    let kickoff_txid = rpc
        .send_raw_transaction(&epoch2.kickoff_tx)
        .expect("Failed to broadcast epoch 2 kickoff");
    println!("Kickoff TX broadcast: {}", kickoff_txid);
    let _ = rpc.generate_to_address(1, &mining_addr).unwrap();

    // Mine blocks for latest state's nSequence
    let latest = &epoch2.states[1]; // state 2 (latest)
    println!(
        "Mining {} blocks for state 2's nSequence...",
        latest.nsequence
    );
    let _ = rpc
        .generate_to_address(latest.nsequence as u64, &mining_addr)
        .unwrap();

    // Broadcast latest state's root TX
    let root_txid = rpc
        .send_raw_transaction(latest.signed_root_tx())
        .expect("Failed to broadcast root TX");
    println!("Root TX broadcast: {}", root_txid);
    let _ = rpc.generate_to_address(1, &mining_addr).unwrap();

    // User 0 exits
    println!("\nUser 0 broadcasting exit path...");
    let exit_path = latest.signed_exit_path(0);
    for (i, split_tx) in exit_path.iter().enumerate() {
        let txid = rpc
            .send_raw_transaction(*split_tx)
            .unwrap_or_else(|e| panic!("Split TX level {} failed: {}", i, e));
        println!("  Level {} split TX: {}", i, txid);
        let _ = rpc.generate_to_address(1, &mining_addr).unwrap();
    }

    // Verify
    println!("\n--- Verify user 0's UTXO ---");
    let user0_script = p2tr_script_pubkey(&user_pubkeys[0]);
    let last_split = exit_path.last().unwrap();
    let user0_output = last_split
        .output
        .iter()
        .find(|o| o.script_pubkey == user0_script)
        .expect("User 0 output not found");

    println!("User 0 received:  {} sats", user0_output.value.to_sat());
    println!("Expected:         39,800 sats (100k - 40k transfers - 200 refresh fee)");
    assert_eq!(user0_output.value.to_sat(), 39_800);

    println!("\n=== Lifecycle demo completed successfully! ===");
    println!("Epoch 1 → cooperative refresh → Epoch 2 → unilateral exit.");
    println!("Old epoch permanently invalidated by refresh TX.");
}
