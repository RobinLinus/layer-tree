use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Network, OutPoint};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use layer_tree_core::keys::OperatorSet;
use layer_tree_core::regtest::{KICKOFF_DELAY, NSEQ_START, STEP_SIZE};
use layer_tree_core::state::Epoch;
use layer_tree_core::transactions::p2tr_script_pubkey;
use layer_tree_core::tree::{ExitTree, UserAllocation};
use layer_tree_core::{KICKOFF_FEE, ROOT_FEE, SPLIT_FEE};
use musig2::secp::Scalar;

const NUM_OPERATORS: usize = 3;
const NUM_USERS: usize = 16;
const USER_BALANCE: u64 = 50_000; // sats per user

fn main() {
    println!("=== Layer Tree Stale-State Race Demo ===\n");

    // Connect to bitcoind
    let rpc = Client::new(
        "http://127.0.0.1:18443",
        Auth::UserPass("rpcuser".into(), "rpcpassword".into()),
    )
    .expect("Failed to connect to bitcoind. Is it running with -regtest?");

    // Create or load wallet
    let wallet_name = "layer_tree_stale_state";
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

    // Mine initial blocks for maturity
    let mining_addr = rpc.get_new_address(None, None).unwrap().assume_checked();
    let _ = rpc.generate_to_address(101, &mining_addr).unwrap();
    println!("Mined 101 blocks for coinbase maturity\n");

    // === Step 1: Generate operator keys ===
    println!("--- Step 1: Generate {} operator keys ---", NUM_OPERATORS);
    let operators = OperatorSet::generate(NUM_OPERATORS);
    let agg_xonly = operators.aggregate_xonly();
    let secret_keys: Vec<Scalar> = operators.keys.iter().map(|k| k.secret).collect();
    println!("Aggregate key: {}", agg_xonly);

    // === Step 2: Generate user keys ===
    println!("\n--- Step 2: Generate {} user keys ---", NUM_USERS);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let user_pubkeys: Vec<bitcoin::XOnlyPublicKey> = (0..NUM_USERS)
        .map(|_| {
            let mut bytes = [0u8; 32];
            rand::fill(&mut bytes);
            let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes).expect("valid secret key");
            bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
                .x_only_public_key()
                .0
        })
        .collect();

    // 3 allocation sets representing off-chain transfers:
    // State 1: initial balances (user0=50k, user1=50k)
    // State 2: user0 sends 20k to user1 (user0=30k, user1=70k)
    // State 3: user0 sends 20k more to user1 (user0=10k, user1=90k)
    let make_allocations = |user0_bal: u64, user1_bal: u64| -> Vec<UserAllocation> {
        user_pubkeys
            .iter()
            .enumerate()
            .map(|(i, &pubkey)| UserAllocation {
                pubkey,
                amount: Amount::from_sat(match i {
                    0 => user0_bal,
                    1 => user1_bal,
                    _ => USER_BALANCE,
                }),
            })
            .collect()
    };

    let allocs_1 = make_allocations(50_000, 50_000);
    let allocs_2 = make_allocations(30_000, 70_000);
    let allocs_3 = make_allocations(10_000, 90_000);

    // === Step 3: Compute pool amount and fund it ===
    println!("\n--- Step 3: Fund pool UTXO ---");

    // Use a dummy tree to compute the required pool amount
    let dummy_outpoint = OutPoint::new(bitcoin::Txid::all_zeros(), 0);
    let dummy_tree = ExitTree::build(
        dummy_outpoint,
        &allocs_1,
        &agg_xonly,
        Amount::from_sat(SPLIT_FEE),
    );
    let tree_input = dummy_tree.required_input_amount;
    let root_output = tree_input;
    let kickoff_output = root_output + Amount::from_sat(ROOT_FEE);
    let pool_amount = kickoff_output + Amount::from_sat(KICKOFF_FEE);
    println!("Pool amount: {} sats", pool_amount.to_sat());

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

    // === Step 4: Build epoch with 3 states ===
    println!("\n--- Step 4: Build epoch with 3 states ---");

    let mut epoch = Epoch::new(
        pool_outpoint,
        pool_amount,
        agg_xonly,
        KICKOFF_DELAY,
        Amount::from_sat(KICKOFF_FEE),
    );
    epoch.sign_kickoff(&operators.key_agg_ctx, &secret_keys);

    let split_fee = Amount::from_sat(SPLIT_FEE);
    let root_fee = Amount::from_sat(ROOT_FEE);

    epoch.add_state(
        allocs_1, NSEQ_START, STEP_SIZE, split_fee, root_fee,
        &operators.key_agg_ctx, &secret_keys,
    );
    println!(
        "State 1: nSeq={}, user0=50,000 sats",
        epoch.states[0].nsequence
    );

    epoch.add_state(
        allocs_2, NSEQ_START, STEP_SIZE, split_fee, root_fee,
        &operators.key_agg_ctx, &secret_keys,
    );
    println!(
        "State 2: nSeq={}, user0=30,000 sats",
        epoch.states[1].nsequence
    );

    epoch.add_state(
        allocs_3, NSEQ_START, STEP_SIZE, split_fee, root_fee,
        &operators.key_agg_ctx, &secret_keys,
    );
    println!(
        "State 3: nSeq={}, user0=10,000 sats",
        epoch.states[2].nsequence
    );

    // === Step 5: Demonstrate the stale-state race ===
    println!("\n--- Step 5: Stale-state nSequence race ---");

    // Mine blocks to mature kickoff timelock
    println!(
        "Mining {} blocks for kickoff timelock...",
        KICKOFF_DELAY
    );
    let _ = rpc
        .generate_to_address(KICKOFF_DELAY as u64, &mining_addr)
        .unwrap();

    // Broadcast kickoff TX
    let kickoff_txid = rpc
        .send_raw_transaction(&epoch.kickoff_tx)
        .expect("Failed to broadcast kickoff TX");
    println!("Kickoff TX broadcast: {}", kickoff_txid);
    let _ = rpc.generate_to_address(1, &mining_addr).unwrap();
    println!("Kickoff TX confirmed");

    // Mine exactly state 3's nSequence blocks.
    // State 3 (nSeq=16) matures. State 2 (nSeq=18) and state 1 (nSeq=20) do not.
    let state3_nseq = epoch.states[2].nsequence;
    println!(
        "\nMining {} blocks (state 3's nSequence)...",
        state3_nseq
    );
    let _ = rpc
        .generate_to_address(state3_nseq as u64, &mining_addr)
        .unwrap();

    // Try state 1's root TX — should fail (needs 4 more blocks)
    println!("\nAttempting state 1 root TX (nSeq={})...", epoch.states[0].nsequence);
    match rpc.send_raw_transaction(epoch.states[0].signed_root_tx()) {
        Ok(_) => panic!("State 1 root TX should NOT be mature yet!"),
        Err(_) => println!("  REJECTED (expected): non-BIP68-final"),
    }

    // Try state 2's root TX — should fail (needs 2 more blocks)
    println!("Attempting state 2 root TX (nSeq={})...", epoch.states[1].nsequence);
    match rpc.send_raw_transaction(epoch.states[1].signed_root_tx()) {
        Ok(_) => panic!("State 2 root TX should NOT be mature yet!"),
        Err(_) => println!("  REJECTED (expected): non-BIP68-final"),
    }

    // State 3's root TX — should succeed (nSeq=16, exactly mature)
    println!("Attempting state 3 root TX (nSeq={})...", epoch.states[2].nsequence);
    let root_txid = rpc
        .send_raw_transaction(epoch.states[2].signed_root_tx())
        .expect("Failed to broadcast state 3 root TX");
    println!("  ACCEPTED: {}", root_txid);
    let _ = rpc.generate_to_address(1, &mining_addr).unwrap();
    println!("  State 3 root TX confirmed!");

    // Now states 1 and 2 are permanently invalid (kickoff output spent)
    println!("\nVerifying old states are invalid...");
    match rpc.send_raw_transaction(epoch.states[0].signed_root_tx()) {
        Ok(_) => panic!("State 1 should be permanently invalid!"),
        Err(_) => println!("  State 1: permanently invalid (input spent)"),
    }
    match rpc.send_raw_transaction(epoch.states[1].signed_root_tx()) {
        Ok(_) => panic!("State 2 should be permanently invalid!"),
        Err(_) => println!("  State 2: permanently invalid (input spent)"),
    }

    // === Step 6: User 0 exits via state 3 ===
    println!("\n--- Step 6: User 0 unilateral exit via state 3 ---");

    let state3 = &epoch.states[2];
    let exit_path = state3.signed_exit_path(0);
    println!(
        "Broadcasting exit path ({} split TXs)...",
        exit_path.len()
    );

    for (i, split_tx) in exit_path.iter().enumerate() {
        let txid = rpc
            .send_raw_transaction(*split_tx)
            .unwrap_or_else(|e| panic!("Failed to broadcast split TX level {}: {}", i, e));
        println!("  Level {} split TX: {}", i, txid);
        let _ = rpc.generate_to_address(1, &mining_addr).unwrap();
    }

    // === Step 7: Verify user 0 got state 3's balance ===
    println!("\n--- Step 7: Verify user 0's UTXO ---");

    let user0_script = p2tr_script_pubkey(&user_pubkeys[0]);
    let last_split = exit_path.last().unwrap();
    let user0_output = last_split
        .output
        .iter()
        .find(|o| o.script_pubkey == user0_script)
        .expect("User 0's output not found in final split tx");

    println!("User 0 received:     {} sats", user0_output.value.to_sat());
    println!("Expected (state 3):  10,000 sats");
    assert_eq!(user0_output.value.to_sat(), 10_000);

    println!("\n=== Stale-state race demo completed successfully! ===");
    println!("The latest state (3, nSeq={}) won the nSequence race.", state3_nseq);
    println!("Old states (1, 2) are permanently invalidated.");
}
