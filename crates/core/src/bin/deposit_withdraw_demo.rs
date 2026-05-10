use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Network, OutPoint};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use layer_tree_core::keys::OperatorSet;
use layer_tree_core::regtest::{KICKOFF_DELAY, NSEQ_START, STEP_SIZE};
use layer_tree_core::signing::sign_input_keyspend;
use layer_tree_core::state::Epoch;
use layer_tree_core::transactions::{p2tr_script_pubkey, DepositInput, WithdrawalOutput};
use layer_tree_core::tree::{ExitTree, UserAllocation};
use layer_tree_core::{KICKOFF_FEE, REFRESH_FEE, ROOT_FEE, SPLIT_FEE};
use musig2::secp::Scalar;

const NUM_OPERATORS: usize = 3;
const NUM_USERS: usize = 4;
const USER_BALANCE: u64 = 50_000;

fn main() {
    println!("=== Layer Tree Deposit & Withdrawal Demo ===\n");

    // Connect to bitcoind
    let rpc = Client::new(
        "http://127.0.0.1:18443",
        Auth::UserPass("rpcuser".into(), "rpcpassword".into()),
    )
    .expect("Failed to connect to bitcoind. Is it running with -regtest?");

    let wallet_name = "layer_tree_depwith";
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

    // === Setup ===
    println!("--- Setup: {} operators, {} users ---", NUM_OPERATORS, NUM_USERS);
    let operators = OperatorSet::generate(NUM_OPERATORS);
    let agg_xonly = operators.aggregate_xonly();
    let secret_keys: Vec<Scalar> = operators.keys.iter().map(|k| k.secret).collect();

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let user_keys: Vec<bitcoin::secp256k1::SecretKey> = (0..NUM_USERS)
        .map(|_| {
            let mut bytes = [0u8; 32];
            rand::fill(&mut bytes);
            bitcoin::secp256k1::SecretKey::from_slice(&bytes).expect("valid key")
        })
        .collect();
    let user_pubkeys: Vec<bitcoin::XOnlyPublicKey> = user_keys
        .iter()
        .map(|sk| {
            bitcoin::secp256k1::PublicKey::from_secret_key(&secp, sk)
                .x_only_public_key()
                .0
        })
        .collect();

    // === Fund pool UTXO ===
    println!("\n--- Fund pool UTXO ---");
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

    let pool_address = Address::p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(agg_xonly),
        Network::Regtest,
    );
    let pool_txid = rpc
        .send_to_address(&pool_address, pool_amount, None, None, None, None, None, None)
        .expect("Failed to fund pool");

    let pool_tx = rpc.get_raw_transaction(&pool_txid, None).unwrap();
    let pool_script = p2tr_script_pubkey(&agg_xonly);
    let pool_vout = pool_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == pool_script && o.value == pool_amount)
        .expect("Pool output not found") as u32;
    let pool_outpoint = OutPoint::new(pool_txid, pool_vout);
    let _ = rpc.generate_to_address(1, &mining_addr).unwrap();
    println!("Pool funded: {} sats at {}:{}", pool_amount.to_sat(), pool_txid, pool_vout);

    // === Epoch 1: initial state ===
    println!("\n========== EPOCH 1 ==========");
    let split_fee = Amount::from_sat(SPLIT_FEE);
    let root_fee = Amount::from_sat(ROOT_FEE);

    let mut epoch1 = Epoch::new(
        pool_outpoint,
        pool_amount,
        agg_xonly,
        KICKOFF_DELAY,
        Amount::from_sat(KICKOFF_FEE),
    );
    epoch1.sign_kickoff(&operators.key_agg_ctx, &secret_keys);

    epoch1.add_state(
        initial_allocs,
        NSEQ_START, STEP_SIZE, split_fee, root_fee,
        &operators.key_agg_ctx, &secret_keys,
    );
    println!("State 1: all users have {} sats", USER_BALANCE);

    // === Create deposit UTXO on-chain ===
    println!("\n--- Create deposit UTXO for user 0 ---");
    let deposit_amount = Amount::from_sat(50_000);

    // User 0 has an L1 UTXO they want to deposit
    let depositor_key = &user_keys[0];
    let depositor_xonly = user_pubkeys[0];
    let depositor_address = Address::p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(depositor_xonly),
        Network::Regtest,
    );
    let deposit_txid = rpc
        .send_to_address(
            &depositor_address,
            deposit_amount,
            None, None, None, None, None, None,
        )
        .expect("Failed to create deposit UTXO");

    let deposit_tx = rpc.get_raw_transaction(&deposit_txid, None).unwrap();
    let depositor_script = p2tr_script_pubkey(&depositor_xonly);
    let deposit_vout = deposit_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == depositor_script && o.value == deposit_amount)
        .expect("Deposit output not found") as u32;
    let deposit_outpoint = OutPoint::new(deposit_txid, deposit_vout);

    let _ = rpc.generate_to_address(1, &mining_addr).unwrap();
    println!(
        "Deposit UTXO: {} sats at {}:{}",
        deposit_amount.to_sat(),
        deposit_txid,
        deposit_vout
    );

    // === Build refresh TX with deposit + withdrawal ===
    println!("\n========== REFRESH WITH DEPOSIT + WITHDRAWAL ==========");

    let withdrawal_amount = Amount::from_sat(20_000);
    let withdrawal_script = p2tr_script_pubkey(&user_pubkeys[2]); // user 2 withdraws to L1

    println!("Deposit:    user 0 adds {} sats from L1", deposit_amount.to_sat());
    println!("Withdrawal: user 2 gets {} sats to L1", withdrawal_amount.to_sat());

    let deposits = vec![DepositInput {
        outpoint: deposit_outpoint,
        amount: deposit_amount,
        script_pubkey: depositor_script.clone(),
    }];
    let withdrawals = vec![WithdrawalOutput {
        script_pubkey: withdrawal_script.clone(),
        amount: withdrawal_amount,
    }];

    let (mut refresh_tx, refresh_prevouts, mut epoch2) = epoch1.refresh_with_io(
        &deposits,
        &withdrawals,
        Amount::from_sat(REFRESH_FEE),
        KICKOFF_DELAY,
        Amount::from_sat(KICKOFF_FEE),
        &operators.key_agg_ctx,
        &secret_keys,
    );

    // Sign deposit input (user 0's keyspend)
    sign_input_keyspend(&mut refresh_tx, 1, &refresh_prevouts, depositor_key);

    let new_pool_amount = refresh_tx.output[0].value;
    println!(
        "\nRefresh TX built and signed:"
    );
    println!(
        "  Inputs:  pool ({}) + deposit ({})",
        pool_amount.to_sat(),
        deposit_amount.to_sat()
    );
    println!(
        "  Outputs: new pool ({}) + withdrawal ({})",
        new_pool_amount.to_sat(),
        withdrawal_amount.to_sat()
    );
    println!("  Fee: {} sats", REFRESH_FEE);

    // Broadcast refresh TX
    let refresh_txid = rpc
        .send_raw_transaction(&refresh_tx)
        .expect("Failed to broadcast refresh TX");
    println!("\nRefresh TX broadcast: {}", refresh_txid);
    let _ = rpc.generate_to_address(1, &mining_addr).unwrap();
    println!("Refresh TX confirmed!");

    // Verify withdrawal output is on-chain
    println!("\nVerifying withdrawal...");
    let refresh_confirmed = rpc.get_raw_transaction(&refresh_txid, None).unwrap();
    let withdrawal_out = refresh_confirmed
        .output
        .iter()
        .find(|o| o.script_pubkey == withdrawal_script)
        .expect("Withdrawal output not found");
    println!(
        "  User 2's withdrawal: {} sats on L1",
        withdrawal_out.value.to_sat()
    );
    assert_eq!(withdrawal_out.value, withdrawal_amount);

    // Verify epoch 1 is invalid
    println!("\nVerifying epoch 1 invalidated...");
    match rpc.send_raw_transaction(&epoch1.kickoff_tx) {
        Ok(_) => panic!("Epoch 1 kickoff should be invalid!"),
        Err(_) => println!("  Epoch 1 kickoff: INVALID (pool UTXO spent)"),
    }

    // === Epoch 2: updated allocations ===
    println!("\n========== EPOCH 2 ==========");
    epoch2.sign_kickoff(&operators.key_agg_ctx, &secret_keys);

    // Compute allocation budget for epoch 2
    let epoch2_kickoff_out = epoch2.kickoff_output_amount();
    let epoch2_root_out = epoch2_kickoff_out - root_fee;
    // For 4 users with fanout 4: depth=1, 1 split tx, split_fees = 300
    let epoch2_alloc_budget = epoch2_root_out - Amount::from_sat(SPLIT_FEE);
    println!("Allocation budget: {} sats", epoch2_alloc_budget.to_sat());

    // user0: had 50k + 50k deposit - refresh_fee absorbed = 99,800
    // user1: unchanged 50k
    // user2: had 50k - 20k withdrawal = 30k
    // user3: unchanged 50k
    // Total: 229,800. Let's verify.
    let user0_new = epoch2_alloc_budget.to_sat() - 50_000 - 30_000 - 50_000;
    println!(
        "  user0: {} sats (50k + 50k deposit - {} fee)",
        user0_new, REFRESH_FEE
    );
    println!("  user1: 50,000 sats (unchanged)");
    println!("  user2: 30,000 sats (50k - 20k withdrawal)");
    println!("  user3: 50,000 sats (unchanged)");

    let epoch2_allocs: Vec<UserAllocation> = user_pubkeys
        .iter()
        .enumerate()
        .map(|(i, &pubkey)| UserAllocation {
            pubkey,
            amount: Amount::from_sat(match i {
                0 => user0_new,
                2 => 30_000,
                _ => 50_000,
            }),
        })
        .collect();

    epoch2.add_state(
        epoch2_allocs,
        NSEQ_START, STEP_SIZE, split_fee, root_fee,
        &operators.key_agg_ctx, &secret_keys,
    );

    // === Unilateral exit from epoch 2 ===
    println!("\n========== UNILATERAL EXIT (EPOCH 2) ==========");

    println!("Mining {} blocks for kickoff timelock...", KICKOFF_DELAY);
    let _ = rpc
        .generate_to_address(KICKOFF_DELAY as u64, &mining_addr)
        .unwrap();

    let kickoff_txid = rpc
        .send_raw_transaction(&epoch2.kickoff_tx)
        .expect("Failed to broadcast epoch 2 kickoff");
    println!("Kickoff TX: {}", kickoff_txid);
    let _ = rpc.generate_to_address(1, &mining_addr).unwrap();

    let latest = &epoch2.states[0];
    println!(
        "Mining {} blocks for root TX nSequence...",
        latest.nsequence
    );
    let _ = rpc
        .generate_to_address(latest.nsequence as u64, &mining_addr)
        .unwrap();

    let root_txid = rpc
        .send_raw_transaction(latest.signed_root_tx())
        .expect("Failed to broadcast root TX");
    println!("Root TX: {}", root_txid);
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
    println!("\n--- Final verification ---");
    let user0_script = p2tr_script_pubkey(&user_pubkeys[0]);
    let last_split = exit_path.last().unwrap();
    let user0_output = last_split
        .output
        .iter()
        .find(|o| o.script_pubkey == user0_script)
        .expect("User 0 output not found");

    println!("User 0 received:  {} sats", user0_output.value.to_sat());
    println!(
        "Expected:         {} sats (50k original + 50k deposit - {} refresh fee)",
        user0_new, REFRESH_FEE
    );
    assert_eq!(user0_output.value.to_sat(), user0_new);

    println!("\n=== Deposit & withdrawal demo completed successfully! ===");
    println!("Demonstrated: L1 deposit input + L1 withdrawal output in refresh TX.");
}
