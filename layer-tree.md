## Layer Tree protocol summary

Layer Tree is a Bitcoin L2 built around a shared **pool UTXO** controlled by an **n-of-n MuSig key** held by a set of operators. The operators may be implemented as independently attested TEEs.

Users’ balances are represented by periodically signed **exit trees**. Each exit tree commits to the current allocation of the pool among users. Users can transfer funds offchain, withdraw cooperatively to L1, deposit from L1, or unilaterally exit through the latest available exit tree.

The protocol fundamentally relies on a **1-of-N honest operator assumption** for safety and data availability, while normal operation requires **N-of-N operator cooperation**.

---

## 1. Pool UTXO

At any time, the system has a shared pool UTXO:

```text
pool UTXO_k
```

This UTXO is controlled by an n-of-n MuSig key belonging to the operators.

The pool UTXO represents the aggregate funds of all users currently inside the Layer Tree.

---

## 2. Exit-tree states

For each state, operators sign a package consisting of:

```text
kickoff transaction spending pool UTXO_k
root transaction spending the kickoff output
exit tree distributing balances to users
signatures for the tree
user exit data
fee-bump data / anchor-spend instructions
state number or commitment
```

The off-chain transaction chain has two stages before the exit tree:

```text
pool UTXO_k -> [kickoff TX] -> [root TX] -> exit tree
```

The **kickoff transaction** spends the pool UTXO with a relative timelock of ~1 week (`nSequence = 1008`). It is shared across all states in an epoch — every root transaction spends the same kickoff output. The kickoff TX is only broadcast to trigger a unilateral exit.

The timelock prevents griefing: without it, any user could broadcast the kickoff at any time and force the entire pool on-chain — a low-cost attack with high impact on all other users. The 1-week delay gives operators time to react with a cooperative refresh (which spends the pool UTXO and invalidates the kickoff). In a legitimate halt, users wait ~1 week before the kickoff matures, after which the nSequence race proceeds normally.

```text
input:
  pool UTXO_k (nSequence = 1008, ~1 week)

outputs:
  kickoff output
  optional P2A or anchor output for fees
```

The **root transaction** spends the kickoff output and carries the decreasing `nSequence` timelock. Because BIP68 relative timelocks are measured from the input’s confirmation, the nSequence clock only starts ticking when the kickoff TX confirms — not when the pool UTXO was created. This decouples the timelock ladder from the epoch clock and guarantees that the time advantage between states is always preserved, regardless of how old the pool UTXO is.

```text
input:
  kickoff output (with decreasing nSequence per state)

outputs:
  exit-tree root output (committed to a state number)
  optional P2A or anchor output for fees
```

The exit tree is a tree of pre-signed split transactions. The root transaction’s output is the input to the first level of this tree. Each split transaction has multiple outputs, dividing the aggregate balance further. Leaves are individual user outputs.

Each split transaction must pay a minimum fee, which is pre-committed at signing time. A fanout of 4 (each split transaction has 4 outputs) is likely optimal in terms of total on-chain cost, balancing tree depth against the per-transaction overhead.

```text
                          root tx output
                     /      |       |      \
                split tx  split tx  split tx  split tx
               /||\      /||\      /||\      /||\
              u0..u3    u4..u7   u8..u11  u12..u15
```

Each internal node has a Taproot keyspend path (the n-of-n operator MuSig key), allowing operators to cooperatively shortcut any subtree in a single transaction. The script path contains the pre-signed child outputs. The stale-state mechanism does not require fancy scripts or covenants.

For a tree with N users and fanout F, the depth is log_F(N). Each user’s leaf gives them a unilateral path to claim their balance once the latest root transaction has confirmed and the exit path is followed. Claiming requires publishing log_F(N) intermediate transactions from root to leaf (e.g., with F=4 and N=65,536 users, the depth is 8).

**Cosigning optimization:** All ~2N pre-signed transactions in the exit tree are signed in a single MuSig2 session — just 2 communication rounds (nonce exchange + partial signatures), regardless of tree size. Nonces and partial signatures for every transaction are batched into each round. This means signing a tree for 10,000 users takes the same number of rounds as signing a tree for 10. The per-operator computation (generating partial signatures) is trivially parallelizable. In practice, a small operator set such as 3-of-3 is sufficient, keeping the signing protocol fast and the coordination overhead minimal.

---

## 3. Offchain transfers

Users send funds to each other by submitting transfer requests to the operators.

Operators periodically batch these transfers and sign a new exit tree reflecting the updated balances.

A payment is considered safe only once the receiver has obtained and verified the latest state data proving their new balance and exit path.

A user should not treat an incoming balance as final merely because operators say it exists. The user or their watcher should have:

```text
latest root transaction
their exit branch
required signatures
required scripts / Taproot data
fee-bump instructions if relevant
```

---

## 4. Stale-state defense with decreasing nSequence

Each state has a root transaction spending the kickoff output (see Section 2).

Operators “invalidate” older exit trees by signing newer root transactions with **decreasing BIP68 `nSequence` values**.

With concrete parameters (start = 4032 blocks, step = 4 blocks):

```text
state 1    root TX: nSequence = 4032  (~4 weeks)
state 2    root TX: nSequence = 4028
state 3    root TX: nSequence = 4024
...
state 1008 root TX: nSequence = 4     (~40 minutes)
```

The maximum number of states per epoch is:

```text
max_states = nSequence_start / step_size
           = 4032 / 4
           = 1008 states per ~4-week epoch
```

Lower `nSequence` means the newer root transaction becomes valid earlier.

Old states are not cryptographically revoked. Instead, newer states become eligible for confirmation sooner. Once the newest root transaction confirms, it spends the pool UTXO and makes every older root transaction invalid by UTXO conflict.

The key invariant is:

```text
For every stale state, a newer available root transaction must mature early enough
to confirm before the stale root can confirm.
```

The security argument is straightforward: the latest root transaction matures `step_size` blocks (e.g., 4 blocks / ~40 minutes) before any stale root. Since all root transactions are small (1 input, 1-2 outputs), the fee-bumping race is symmetric in transaction size. But the honest party has a time advantage: the stale root literally cannot enter a block until the fresh root has been eligible for `step_size` blocks. Any watcher can use this window to confirm the latest root.

Because root transactions spend the kickoff output (not the pool UTXO directly), the BIP68 relative timelocks are measured from the kickoff TX's confirmation. The nSequence clock only starts when a unilateral exit is triggered, so the time advantage between states is always fully preserved regardless of how long the epoch has been running.

The emergency race is therefore small and simple:

```text
get the latest root transaction confirmed
```

not:

```text
publish the whole exit tree immediately
```

Once the latest root confirms, the exit tree is final and users can settle through their branches.

---

## 5. Unilateral exit

If operators halt, censor users, or stop signing updates, users fall back to the latest signed state they possess.

The exit flow is:

```text
1. User or watcher waits for the kickoff TX's timelock to mature (~1 week).
2. User or watcher broadcasts the kickoff transaction, spending pool UTXO_k.
3. The kickoff TX confirms. The nSequence clocks on all root TXs start ticking.
4. The latest root transaction matures first (lowest nSequence).
5. User or watcher broadcasts the latest root transaction.
6. The root transaction confirms, spending the kickoff output.
7. All older roots are invalidated by conflict.
8. Users claim funds through the confirmed exit tree.
```

Because the root transaction is very small, unilateral recovery depends mainly on confirming a compact transaction. An optional P2A or anchor output can help with fee bumping.

After the root transaction confirms, users must publish their path through the exit tree to claim their funds. For a tree with N users and fanout F, each user's path requires log_F(N) split transactions from root to leaf. Shared internal nodes only need to be confirmed once — the first user to claim a branch publishes the shared ancestors, and subsequent users in the same subtree reuse them.

Each split transaction pays a minimum fee that was pre-committed at signing time. Split transactions may also include a P2A or anchor output so that the user claiming through it can fee-bump independently. Users pay the fees for their own exit path.

**Gradual unwinding:** The exit tree does not need to be published all at once. Once the root transaction confirms, the exit tree is final — it cannot be revoked or replaced. Users can claim their branches at any time, over hours, days, or weeks. There is no urgency to flood the mempool; each level of the tree can be confirmed before the next is broadcast. This means a mass exit does not require all ~N/F split transactions to compete for block space simultaneously. Users with urgent needs claim first; others can wait for lower fees.

**Mass exit economics:** In a worst-case mass exit (all N users claim on-chain), the total on-chain footprint is approximately N * (F-1)/(F) split transactions. For users with very small balances, the cumulative fees for their exit path may exceed their balance. This is a fundamental property of any shared-UTXO design (channel factories, Ark, coinpools) — not specific to Layer Tree. The cooperative keyspend paths mitigate this in practice: even during partial failures, honest operators can cooperatively collapse subtrees without going fully on-chain.

---

## 6. Refresh transactions

The `nSequence` ladder is finite. Before the relative timelocks are exhausted, operators cooperatively perform an onchain refresh.

In the simplest case:

```text
pool UTXO_k -> pool UTXO_{k+1}
```

The normal refresh transaction is very small:

```text
1 input
1 output
optional P2A / anchor output
```

This reset has two effects:

```text
1. It resets the nSequence ladder.
2. It truly invalidates all prior kickoff and root transactions
   because they spend the old pool UTXO.
```

With the parameters from Section 4 (start = 4032, step = 4), each epoch supports up to 1008 state updates over approximately 4 weeks before a refresh is required.

**User liveness:** After a refresh, all prior exit data references the spent pool UTXO and is permanently invalid. However, under the 1-of-N honest operator assumption, users do not need to be online during every epoch. An honest operator will provide the user with their current exit data whenever they reconnect. A user only loses unilateral exit capability if all N operators refuse to share the latest state — which is a censorship attack, not a liveness failure.

The lifecycle is:

```text
pool UTXO_k
  -> many offchain states with decreasing nSequence roots
  -> small onchain refresh
  -> pool UTXO_{k+1}
  -> new offchain state sequence
```

---

## 7. Cooperative L1 withdrawals

Users can send funds from Layer Tree to normal onchain Bitcoin recipients.

Operators implement this as an early refresh transaction with extra outputs.

Example:

```text
inputs:
  pool UTXO_k

outputs:
  pool UTXO_{k+1}
  withdrawal output 1
  withdrawal output 2
  ...
  optional P2A / anchor output
```

The new pool output represents the remaining L2 balances after withdrawals and fees.

The next exit tree commits to the updated allocation.

Accounting:

```text
new pool value =
  old pool value
  - sum(withdrawal outputs)
  - miner fees
```

Withdrawals are cooperative and can be censored during normal operation. If operators refuse to include a withdrawal, the user can still fall back to unilateral exit after the relevant timeout.

---

## 8. L1 deposits

Users can send onchain funds into Layer Tree by sending bitcoin to an address controlled by the Layer Tree operators.

The operators then add the deposit UTXO as an input to the root transaction or refresh transaction for the next tree.

Deposit transition:

```text
inputs:
  pool UTXO_k
  user deposit UTXO 1
  user deposit UTXO 2
  ...

outputs:
  pool UTXO_{k+1}
  optional withdrawal outputs
  optional P2A / anchor output
```

The new pool output increases by the deposited amount, net of fees.

Accounting with both deposits and withdrawals:

```text
new pool value =
  old pool value
  + sum(deposit inputs)
  - sum(withdrawal outputs)
  - miner fees
```

The next exit tree credits depositors with their corresponding L2 balances.

A deposit should be considered active only after:

```text
the deposit UTXO is included in a signed root/refresh transaction
the user is credited in the new exit tree
the user has obtained and verified their exit data
```

Before that, the deposit is simply an L1 UTXO controlled by the operator set under the protocol’s 1-of-N security model. During this window, the depositor has no unilateral exit protection — their funds are held by the operators without an exit tree leaf. This custodial gap is an accepted tradeoff; it is expected to be short under normal operation.

---

## 9. Data availability

After each update, operators publish the latest state package.

That package includes:

```text
latest root transaction
full exit tree or relevant branches
user leaf data
signatures
scripts / Taproot control data if needed
state number / commitment
fee-bump or anchor-spend instructions
```

Users, wallets, indexers, and watchtowers subscribe to operator publications.

The protocol relies on the assumption that at least one operator publishes the latest valid tree.

The practical safety condition is:

```text
latest state was signed and made available to users/watchers
```

not merely:

```text
latest state was signed
```

If all operators withhold the latest tree before users receive it, users may be forced to fall back to the last state they actually possess.

Because refreshes permanently invalidate prior exit data (Section 6), users need access to the latest state to maintain unilateral exit capability. Under the 1-of-N assumption, an honest operator will provide this data on demand — users do not need to be continuously online. The real risk is all operators colluding to withhold data from a targeted user.

---

## 10. Trust model

Layer Tree fundamentally relies on a **1-of-N honest operator assumption**.

If at least one operator is honest, that operator:

```text
refuses to sign invalid or theft transactions
refuses to sign invalid state transitions
publishes the latest valid tree data
```

The split is:

```text
safety:   1-of-N honest
liveness: N-of-N cooperative
```

Because the pool key is n-of-n MuSig, all operators must cooperate for normal updates, refreshes, deposits, and cooperative withdrawals.

A single offline or malicious operator can halt normal operation. But if at least one operator remains honest and the latest state is available, users can still recover through unilateral exit.

If all N operators collude, they can:

```text
sign a theft transaction
withhold latest tree data
misallocate balances
censor withdrawals or deposits
equivocate about state
```

**State commitment and equivocation detection:** Each root transaction commits to a monotonically increasing state number (e.g., via a Taproot tweak on the exit-tree root output). This makes state ordering verifiable. If a user receives two different exit trees for the same state number, they have cryptographic proof that operators are equivocating. Because all N operators must sign every root transaction (n-of-n MuSig), equivocation requires the cooperation of the entire operator set.

---

## 11. TEE variant

If operators run inside independently attested TEEs, the trust model becomes:

```text
at least 1 of N TEEs is uncompromised, runs the correct code, and publishes data
```

Each TEE should:

```text
hold its MuSig key share internally
only sign valid protocol transitions
verify accounting rules
publish signed state data
refuse theft or invalid exits
```

Users verify remote attestations to know what code controls the signing shares.

In this model, users do not trust human operators with custody. They trust that at least one independent TEE remains correct and available.

A precise description is:

> Layer Tree is non-custodial under a 1-of-N TEE security assumption.

It is not trustless in the pure Bitcoin-script sense, but no single operator, and no majority of operators, can steal funds if at least one TEE remains honest and uncompromised.

---

## 12. Fee and mempool requirements

The protocol’s safety depends on being able to confirm the latest root transaction before stale roots mature.

Because the root transaction is small, the critical transaction is easy to fee-bump compared with publishing a large tree.

Still, the design needs robust handling for:

```text
mempool pinning
CPFP
package relay
P2A / anchor fee bumping
fee spikes
dust outputs
emergency broadcaster incentives
withdrawal fee allocation
deposit fee allocation
```

Every user or watcher should be able to get the latest root transaction confirmed under adversarial fee conditions.

**Fee allocation sketch:**

```text
root transaction fees:
  deducted from pool balance pro-rata across users,
  or reserved in each user's exit leaf

exit tree intermediate tx fees:
  paid by the user claiming through that branch
  (each intermediate tx has a P2A/anchor output)

cooperative withdrawal fees:
  deducted from the withdrawal amount

deposit fees:
  deducted from the credited L2 balance

refresh transaction fees:
  deducted from pool balance pro-rata
```

---

## 13. Complete lifecycle

A typical epoch looks like:

```text
1. Operators control pool UTXO_k with n-of-n MuSig.

2. Users make offchain transfers.

3. Operators periodically sign new exit trees.

4. Each newer root transaction uses a lower nSequence value,
   making it confirmable earlier than older roots.

5. Operators publish the latest root and exit data.

6. Users/watchers verify and store their recovery data.

7. Users may request cooperative L1 withdrawals,
   which are included as outputs in an early refresh.

8. Users may make L1 deposits,
   whose UTXOs are added as inputs to a root/refresh transaction.

9. Before the nSequence ladder is exhausted,
   operators refresh the pool UTXO onchain.

10. The refresh creates pool UTXO_{k+1},
    invalidates old trees, and starts a new epoch.
```

If operators stop cooperating:

```text
1. Users/watchers wait for the kickoff TX's timelock to mature (~1 week).
2. Users/watchers broadcast the kickoff transaction (spends pool UTXO_k).
3. The kickoff confirms. The nSequence clocks start ticking.
4. The latest root transaction matures first.
5. Users/watchers broadcast and fee-bump the latest root transaction.
6. Once it confirms, stale states are dead.
7. Users exit through their branches.
```

---

## 14. Operator rotation

Changing the operator set requires a special refresh transaction that moves the pool UTXO to a new n-of-n MuSig key.

```text
inputs:
  pool UTXO_k (old operator set key)

outputs:
  pool UTXO_{k+1} (new operator set key)
  optional P2A / anchor output
```

Both the old and new operator sets must cooperate to sign the handoff transaction. The old set signs the input (spending the current pool UTXO), and the new set must be ready to sign exit trees for the new epoch.

This is operationally similar to a normal refresh but with a key change. It resets the nSequence ladder and invalidates all prior exit trees, just like a standard refresh.

Operator rotation enables:

```text
adding new operators
removing failed or compromised operators
upgrading TEE hardware or attestation keys
migrating between operator organizations
```

---

## One-paragraph summary

Layer Tree is a Bitcoin L2 based on a shared Taproot pool UTXO controlled by an n-of-n operator MuSig (e.g., 3-of-3 in practice). Operators periodically sign exit trees — trees of pre-signed split transactions (fanout 4 is likely optimal) — that allocate the pool among users. All signatures per tree are produced in just 2 MuSig2 rounds regardless of user count; each split transaction pays a pre-committed minimum fee. Each state consists of a kickoff transaction (spending the pool UTXO) and a root transaction (spending the kickoff output with a decreasing BIP68 `nSequence`). The kickoff TX is shared across all states and has a ~1-week relative timelock to prevent griefing; root TXs use decreasing nSequence values (e.g., starting at 4032 blocks with a step of 4, yielding ~1008 states per ~4-week epoch). Because the nSequence is relative to the kickoff TX's confirmation, the time advantage between states is always fully preserved — the clock only starts when a unilateral exit is triggered. Once the latest root confirms, all older trees are invalidated by UTXO conflict and users can exit through their branches by publishing log_F(N) intermediate transactions. Periodic small refresh transactions move the pool into a new UTXO and reset the sequence ladder. Cooperative withdrawals are refreshes with extra L1 recipient outputs, while deposits are L1 UTXOs sent to the operators and added as inputs to a future root or refresh transaction. Safety and data availability rely on a 1-of-N honest operator or TEE assumption; under this assumption, users can obtain their exit data on demand without needing to be continuously online. Normal liveness requires all N operators to cooperate.
