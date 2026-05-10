use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Network, OutPoint};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use layer_tree_core::keys::OperatorSet;
use layer_tree_core::signing::{sign_transactions, PrevoutInfo};
use layer_tree_core::transactions::{build_kickoff_tx, build_root_tx, p2tr_script_pubkey};
use layer_tree_core::tree::{ExitTree, UserAllocation};
use layer_tree_core::{KICKOFF_FEE, ROOT_FEE, SPLIT_FEE};
use musig2::secp::Scalar;

const NUM_OPERATORS: usize = 3;
const NUM_USERS: usize = 16;
const USER_BALANCE: u64 = 50_000; // sats per user

// Small regtest parameters
const KICKOFF_DELAY: u16 = 10;
const NSEQ_START: u16 = 20;

fn main() {
    println!("=== Layer Tree Regtest Demo ===\n");

    // Connect to bitcoind
    let rpc = Client::new(
        "http://127.0.0.1:18443",
        Auth::UserPass("rpcuser".into(), "rpcpassword".into()),
    )
    .expect("Failed to connect to bitcoind. Is it running with -regtest?");

    // Create or load wallet
    let wallet_name = "layer_tree_test";
    match rpc.create_wallet(wallet_name, None, None, None, None) {
        Ok(_) => println!("Created wallet: {}", wallet_name),
        Err(_) => {
            // Wallet might already exist, try loading
            let _ = rpc.load_wallet(wallet_name);
            println!("Loaded existing wallet: {}", wallet_name);
        }
    }

    // Use wallet-specific RPC
    let rpc = Client::new(
        &format!("http://127.0.0.1:18443/wallet/{}", wallet_name),
        Auth::UserPass("rpcuser".into(), "rpcpassword".into()),
    )
    .unwrap();

    // Mine initial blocks for maturity
    let mining_addr = rpc.get_new_address(None, None).unwrap().assume_checked();
    let _ = rpc.generate_to_address(101, &mining_addr).unwrap();
    println!("Mined 101 blocks for coinbase maturity\n");

    // === Step 1: Generate operator keys ===
    println!("--- Step 1: Generate {} operator keys ---", NUM_OPERATORS);
    let operators = OperatorSet::generate(NUM_OPERATORS);
    let agg_xonly = operators.aggregate_xonly();
    println!("Aggregate key: {}", agg_xonly);

    // === Step 2: Generate user keys and allocations ===
    println!("\n--- Step 2: Generate {} user allocations ---", NUM_USERS);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let user_keys: Vec<bitcoin::secp256k1::SecretKey> = (0..NUM_USERS)
        .map(|_| {
            let mut bytes = [0u8; 32];
            rand::fill(&mut bytes);
            bitcoin::secp256k1::SecretKey::from_slice(&bytes).expect("valid secret key")
        })
        .collect();
    let allocations: Vec<UserAllocation> = user_keys
        .iter()
        .map(|sk| {
            let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, sk);
            UserAllocation {
                pubkey: pk.x_only_public_key().0,
                amount: Amount::from_sat(USER_BALANCE),
            }
        })
        .collect();
    println!(
        "Each user gets {} sats ({} users total)",
        USER_BALANCE, NUM_USERS
    );

    // === Step 3: Compute required pool amount (bottom-up) ===
    // First build a dummy tree to get the required input amount
    let dummy_outpoint = OutPoint::new(bitcoin::Txid::all_zeros(), 0);
    let dummy_tree = ExitTree::build(
        dummy_outpoint,
        &allocations,
        &agg_xonly,
        Amount::from_sat(SPLIT_FEE),
    );
    let tree_input_amount = dummy_tree.required_input_amount;
    let root_output_amount = tree_input_amount;
    let kickoff_output_amount = root_output_amount + Amount::from_sat(ROOT_FEE);
    let pool_amount = kickoff_output_amount + Amount::from_sat(KICKOFF_FEE);

    println!("\n--- Step 3: Fund pool UTXO ---");
    println!("Tree requires:     {} sats", tree_input_amount.to_sat());
    println!("Root TX output:    {} sats", root_output_amount.to_sat());
    println!("Kickoff TX output: {} sats", kickoff_output_amount.to_sat());
    println!("Pool UTXO amount:  {} sats", pool_amount.to_sat());

    // Fund the pool UTXO
    let pool_address = Address::p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(agg_xonly),
        Network::Regtest,
    );
    let pool_txid = rpc
        .send_to_address(
            &pool_address,
            pool_amount,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("Failed to fund pool UTXO");

    // Find the correct vout
    let pool_tx = rpc.get_raw_transaction(&pool_txid, None).unwrap();
    let pool_script = p2tr_script_pubkey(&agg_xonly);
    let pool_vout = pool_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == pool_script && o.value == pool_amount)
        .expect("Pool output not found") as u32;
    let pool_outpoint = OutPoint::new(pool_txid, pool_vout);

    // Mine to confirm
    let _ = rpc.generate_to_address(1, &mining_addr).unwrap();
    println!("Pool UTXO funded and confirmed: {}:{}", pool_txid, pool_vout);

    // === Step 4: Build transaction chain ===
    println!("\n--- Step 4: Build transaction chain ---");

    // Kickoff TX
    let kickoff_tx = build_kickoff_tx(
        pool_outpoint,
        pool_amount,
        &agg_xonly,
        KICKOFF_DELAY,
        Amount::from_sat(KICKOFF_FEE),
    );
    let kickoff_txid = kickoff_tx.compute_txid();
    let kickoff_outpoint = OutPoint::new(kickoff_txid, 0);
    println!("Kickoff TX built: {} (nSequence={})", kickoff_txid, KICKOFF_DELAY);

    // Root TX
    let root_tx = build_root_tx(
        kickoff_outpoint,
        kickoff_output_amount,
        &agg_xonly,
        NSEQ_START,
        Amount::from_sat(ROOT_FEE),
    );
    let root_txid = root_tx.compute_txid();
    let root_outpoint = OutPoint::new(root_txid, 0);
    println!("Root TX built:    {} (nSequence={})", root_txid, NSEQ_START);

    // Exit tree
    let exit_tree = ExitTree::build(
        root_outpoint,
        &allocations,
        &agg_xonly,
        Amount::from_sat(SPLIT_FEE),
    );
    println!(
        "Exit tree built:  {} levels, {} split txs, {} users",
        exit_tree.levels.len(),
        exit_tree.total_transactions(),
        NUM_USERS,
    );

    // === Step 5: Sign all transactions via batched MuSig2 ===
    println!("\n--- Step 5: Sign all transactions (batched MuSig2) ---");

    let secret_keys: Vec<Scalar> = operators.keys.iter().map(|k| k.secret).collect();

    // Collect all transactions and their prevout info
    let pool_script = p2tr_script_pubkey(&agg_xonly);
    let operator_script = pool_script.clone();

    let mut all_txs: Vec<bitcoin::Transaction> = Vec::new();
    let mut all_prevouts: Vec<PrevoutInfo> = Vec::new();

    // Kickoff TX: spends pool UTXO
    all_txs.push(kickoff_tx);
    all_prevouts.push(PrevoutInfo {
        amount: pool_amount,
        script_pubkey: pool_script.clone(),
    });

    // Root TX: spends kickoff output
    all_txs.push(root_tx);
    all_prevouts.push(PrevoutInfo {
        amount: kickoff_output_amount,
        script_pubkey: operator_script.clone(),
    });

    // Split TXs: each spends its parent's output
    // We need to figure out each split tx's prevout.
    // Level 0 split tx spends root TX output.
    // Level 1+ split txs spend their parent split tx's output.
    for (level_idx, level) in exit_tree.levels.iter().enumerate() {
        for (tx_idx, tx) in level.iter().enumerate() {
            let prevout_amount = if level_idx == 0 {
                root_output_amount
            } else {
                // Parent is at previous level, index = tx_idx / FANOUT
                let parent_tx_idx = tx_idx / layer_tree_core::FANOUT;
                let parent_tx = &exit_tree.levels[level_idx - 1][parent_tx_idx];
                // Find which output of parent this tx spends
                let spent_outpoint = tx.input[0].previous_output;
                parent_tx
                    .output
                    .iter()
                    .enumerate()
                    .find(|(vout, _)| {
                        OutPoint::new(parent_tx.compute_txid(), *vout as u32) == spent_outpoint
                    })
                    .map(|(_, o)| o.value)
                    .expect("split tx input should match parent output")
            };

            all_txs.push(tx.clone());
            all_prevouts.push(PrevoutInfo {
                amount: prevout_amount,
                script_pubkey: operator_script.clone(),
            });
        }
    }

    let n_total = all_txs.len();
    println!("Signing {} transactions...", n_total);

    sign_transactions(
        &mut all_txs,
        &all_prevouts,
        &operators.key_agg_ctx,
        &secret_keys,
    );
    println!("All {} transactions signed successfully!", n_total);

    // Extract signed transactions back
    let signed_kickoff = &all_txs[0];
    let signed_root = &all_txs[1];
    // Split txs start at index 2
    let signed_splits = &all_txs[2..];

    // === Step 6: Unilateral exit demo ===
    println!("\n--- Step 6: Unilateral exit (user 0) ---");

    // Mine blocks to mature the kickoff timelock
    println!(
        "Mining {} blocks to mature kickoff timelock...",
        KICKOFF_DELAY
    );
    let _ = rpc
        .generate_to_address(KICKOFF_DELAY as u64, &mining_addr)
        .unwrap();

    // Broadcast kickoff TX
    let kickoff_txid = rpc
        .send_raw_transaction(signed_kickoff)
        .expect("Failed to broadcast kickoff TX");
    println!("Kickoff TX broadcast: {}", kickoff_txid);

    // Mine 1 block to confirm kickoff
    let _ = rpc.generate_to_address(1, &mining_addr).unwrap();
    println!("Kickoff TX confirmed");

    // Mine blocks to mature root TX timelock
    println!(
        "Mining {} blocks to mature root TX timelock...",
        NSEQ_START
    );
    let _ = rpc
        .generate_to_address(NSEQ_START as u64, &mining_addr)
        .unwrap();

    // Broadcast root TX
    let root_txid = rpc
        .send_raw_transaction(signed_root)
        .expect("Failed to broadcast root TX");
    println!("Root TX broadcast: {}", root_txid);

    // Mine 1 block to confirm root TX
    let _ = rpc.generate_to_address(1, &mining_addr).unwrap();
    println!("Root TX confirmed");

    // Broadcast user 0's exit path through the split tree
    let exit_path = exit_tree.exit_path(0);
    println!(
        "Broadcasting exit path for user 0 ({} split txs)...",
        exit_path.len()
    );

    for (i, exit_tx) in exit_path.iter().enumerate() {
        // Find the corresponding signed tx
        let exit_txid = exit_tx.compute_txid();
        let signed_tx = signed_splits
            .iter()
            .find(|t| t.compute_txid() == exit_txid)
            .expect("signed split tx not found for exit path");

        let txid = rpc
            .send_raw_transaction(signed_tx)
            .unwrap_or_else(|e| panic!("Failed to broadcast split TX level {}: {}", i, e));
        println!("  Level {} split TX broadcast: {}", i, txid);

        // Mine 1 block to confirm
        let _ = rpc.generate_to_address(1, &mining_addr).unwrap();
    }

    // === Step 7: Verify user 0's funds ===
    println!("\n--- Step 7: Verify user 0's UTXO ---");
    let user0_xonly = allocations[0].pubkey;
    let user0_script = p2tr_script_pubkey(&user0_xonly);

    // Check the last split tx's outputs for user 0's output
    let last_split_txid = exit_path.last().unwrap().compute_txid();
    let last_split_signed = signed_splits
        .iter()
        .find(|t| t.compute_txid() == last_split_txid)
        .unwrap();

    let user0_output = last_split_signed
        .output
        .iter()
        .find(|o| o.script_pubkey == user0_script)
        .expect("User 0's output not found in final split tx");

    println!("User 0's UTXO found!");
    println!("  Amount: {} sats", user0_output.value.to_sat());
    println!("  Expected: {} sats", USER_BALANCE);
    assert_eq!(user0_output.value.to_sat(), USER_BALANCE);

    println!("\n=== Demo completed successfully! ===");
    println!("Full unilateral exit path verified on regtest.");
}
