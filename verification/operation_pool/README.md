# Slashing and voluntary-exit packing: proved valid against the consensus spec

Machine-checked proofs, in Lean 4, that the proposer slashings, the attester slashings and the
voluntary exits packed by `OperationPool::get_slashings_and_exits` are valid for inclusion in the
block. The consensus spec processes, in order and without an error:

- the packed proposer slashings, from the state they were packed on;
- then the packed attester slashings;
- then the packed voluntary exits.

The Rust is translated to Lean by [Charon](https://github.com/AeneasVerif/charon) and
[Aeneas](https://github.com/AeneasVerif/aeneas). The spec is
[EthLib](https://github.com/ethereum/EthLib)'s executable Lean model of the consensus
specification, at the Fulu fork. One Lean project depends on both.

## What is proved

Each theorem is a statement about the real `filter_limit_operations` and `maximum_cover`, and
about the spec's `process_proposer_slashing`, `process_attester_slashing` and
`process_voluntary_exit` (EthLib's `processProposerSlashing`, `processAttesterSlashing` and
`processVoluntaryExit`). Let `s` be the spec state that corresponds to the Lighthouse state the
op pool packs on.

A run of the spec is a fold: `ops.toArray.foldlM (processX config checks) s = .ok s'`. That is
the fold EthLib's `processOperations` makes over each list of a block body before Gloas.

**The main theorem.** `packed_slashings_and_exits_valid`
(`OperationPool/PackedSlashingsAndExitsValid.lean`) follows the body of
`get_slashings_and_exits` call by call:

> `filter_limit_operations` returns the proposer slashings `outP`, and the spec processes them
> in order from `s` and reaches `s₁`. `AttesterSlashingMaxCover::new` builds the covers
> `covers`, with the proposers of `outP` as the set `to_be_slashed`. `maximum_cover` returns the
> covers `outA`, and the spec processes their slashings in order from `s₁` and reaches `s₂`. The
> two `insert_*` functions build the exclusion set `excl` from `outP` and `outA`.
> `filter_limit_operations`, with a filter that rejects the validators of `excl`, returns the
> exits `out`, and the spec processes them in order from `s₂`. No call panics, and each list is
> within its limit.

No hypothesis of this theorem is a run of the spec. Every hypothesis about the state is about
the packing state `s`.

The extracted functions are generic over an iterator, over closures and over a `MaxCover`
implementation. The main theorem states them on concrete instances, and proves the facts that
the generic theorems take as hypotheses about the instances:

- A pool is a slice walked by Aeneas's slice iterator (`OperationPool/Concrete.lean`).
- A filter closure is a model that runs the extracted cores (`OperationPool/Closures.lean`).
  `proposerSlashingFilter` calls the core of `verify_proposer_slashing`. `voluntaryExitFilter`
  calls the two cores of `verify_exit`.
- A cover is `AttesterCover`, a model of `AttesterSlashingMaxCover`. The covers are the ones
  that `attesterCovers` builds: the model of `AttesterSlashingMaxCover::new`, which calls the
  extracted `Validator::is_slashable_at`, on each pool entry.

A closure also makes checks that no extracted core holds. The models take those as functions:
`stillValid` is `signature_is_still_valid`, and `headersOk` is the three checks of
`verify_proposer_slashing` on the two headers. The theorem assumes what each one implies for the
spec, and nothing else about the closures.

The three theorems below are the generic ones the main theorem joins.

**Proposer slashings.** `packed_proposer_slashings_valid`
(`OperationPool/PackedProposerSlashingsValid.lean`):

> The spec's `process_proposer_slashing` succeeds on each packed slashing in order, starting
> from `s`.

**Attester slashings.** `packed_attester_slashings_valid`
(`OperationPool/PackedAttesterSlashingsValid.lean`):

> The spec's `process_attester_slashing` succeeds on each packed slashing in order, starting
> from the state after the packed proposer slashings.

The spec rejects an attester slashing that slashes no validator. A slashing packed earlier in
the block can slash every validator that a later one names. `maximum_cover_spec`
(`OperationPool/MaxCover.lean`) is the fact about the greedy algorithm that rules this out:

> `maximum_cover` does not panic and returns at most `limit` items. Each returned item comes
> from an item the iterator yielded, and that item covers an element that no item picked before
> it covered.

`maximum_cover` is generic, and so is the theorem. It holds for attestation packing too.

**Exits.** `packed_exits_valid_after_slashings` (`OperationPool/PackedExitsValid.lean`):

> The spec's `process_voluntary_exit` succeeds on each packed exit in order, after the packed
> slashings of the block.

### The hypotheses about the state

| Hypothesis | Meaning | Status |
|---|---|---|
| `hfork` | `IsFulu fork`: the fork of `s` is Fulu, or one of the forks that change the blob parameters alone | Assumed |
| `hcorr` | The Lighthouse state corresponds to `s` | Trusted, see below |
| `hrun`, `hgenesis` | A run of slots and blocks (EthLib's `Run`) reaches `s` from a genesis state (`Genesis`). The proof uses one consequence: `balances` has the registry's length | Assumed. EthLib's `reachable_balancesMatch` gives the consequence |
| `hproposer`, `hproposerIn` | `p` is the proposer of the slot, and is a validator in the registry | Assumed. `process_block_header` checks it earlier in the block |
| `htime` | `TimeBound s`: the slot and the earliest exit epoch are below `2^63` | Assumed |
| `hsupply` | `SupplyCap (2^58) s`: the balances add up to `2^58` Gwei at most, and so do the effective balances. The slashed balance recorded for the current epoch is `2^58` Gwei at most | Assumed |
| `hconfig` | `OperationsRoom`: within the two bounds above, a block with as many slashings and exits as the preset allows has room | Proved for mainnet and minimal at Fulu: `operationsRoom_mainnet`, `operationsRoom_minimal` |

`TimeBound`, `SupplyCap` and `OperationsRoom` are defined in `EthLibOps/Bounds.lean`. They
replace the room formulas of the generic theorems, which cover the arithmetic of
`slash_validator` and `initiate_validator_exit` that packing never runs.

- The time bound has two clocks, because the slot does not bound the exit queue: each exit
  moves `earliest_exit_epoch` ahead of the current epoch.
- The supply cap bounds three sums. The proofs use these consequences: no balance and no
  effective balance exceeds the cap, and the slashed balance of the epoch has room for every
  effective balance that is not yet slashed. `2^58` Gwei is about 288 million ETH.
- Neither bound is an invariant of the state transition, since a processed slot moves the slot
  and a deposit adds Gwei. They are therefore separate from what every reachable state has.
- `OperationsRoom` reads constants alone. It counts one exit and one whistleblower reward for
  each proposer slashing and for each validator an attester slashing can name
  (`MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`, `131072` on mainnet), and one exit
  for each voluntary exit, at the block limits of the preset. `hlimits` says that the three
  limits the Rust passes are at most those.
- EthLib anchors reachability at a Phase 0 genesis state, and a run crosses the fork upgrades.
  `Run.invariant` holds from any first state with EthLib's `Invariant`, so a statement from
  another anchor state is a small change.

### Supporting theorems

| Theorem | File | Statement |
|---|---|---|
| `filter_limit_operations_eq` | `OperationPool/FilterLimit.lean` | The packed list is `((pool.filter keep).take limit).map f`; no panic |
| `maximum_cover_spec` | `OperationPool/MaxCover.lean` | Each item `maximum_cover` returns covers an element that no earlier pick covered; no panic |
| `verify_proposer_slashing_validator_checks_ok_iff` | `StateProcessing/VerifyProposerSlashing.lean` | Returns `Ok` exactly when the proposer exists and its record passes `SlashableChecks`; no panic |
| `verify_exit_validator_checks_ok_iff` | `StateProcessing/VerifyExit.lean` | Returns `Ok` exactly when the validator exists and its record passes `ExitChecks`; no panic |
| `verify_exit_pending_balance_ok_iff` | `StateProcessing/VerifyExit.lean` | Returns `Ok` exactly when the pending balance, if computed, is zero; no panic |
| `exclusionSet_covers` | `OperationPool/ExclusionSet.lean` | The exclusion set holds each packed proposer slashing's proposer and each index common to the two attestations of a packed attester slashing |
| `proposerSlashingGates_of_coreOk` | `OperationPool/Bridge/StateCorr.lean` | A proposer the `verify_proposer_slashing` core accepts passes the spec's `ProposerSlashingGates` |
| `exitGates_of_coresOk` | `OperationPool/Bridge/StateCorr.lean` | An exit both `verify_exit` cores accept passes the spec's `ExitGates` |
| `proposerSlashingFilter_spec` | `OperationPool/Closures.lean` | The model of the proposer-slashing filter accepts an entry exactly when the signature is still valid, the headers pass, and the core accepts the proposer; no panic |
| `voluntaryExitFilter_spec` | `OperationPool/Closures.lean` | The model of the exit filter accepts an entry exactly when the validator is outside the exclusion set, the signature is still valid, and both cores accept the exit; no panic |
| `attesterCovers_spec` | `OperationPool/Closures.lean` | Each cover the model of `AttesterSlashingMaxCover::new` builds covers exactly the validators that both attestations name, that `Validator::is_slashable_at` accepts, and that `to_be_slashed` does not hold; no panic |
| `yields_slice` | `OperationPool/Concrete.lean` | Aeneas's slice iterator yields the entries of the slice, in order |
| `AttesterCover.model` | `OperationPool/Concrete.lean` | The model of `AttesterSlashingMaxCover` satisfies `MaxCoverModel` |
| `exclusionSet_ok` | `OperationPool/ExclusionSet.lean` | The two `insert_*` functions do not panic |
| `isSlashableValidator_of_slashableOn` | `OperationPool/Bridge/StateCorr.lean` | A validator `Validator::is_slashable_at` accepts is slashable by the spec's `is_slashable_validator` |
| `packed_exits_valid` | `OperationPool/PackedExitsValid.lean` | The packed exits succeed from any state with the slash frame of the packing state |
| `packed_exits_valid_direct` | `OperationPool/PackedExitsValid.lean` | The packed exits succeed from the packing state itself |

The three generic theorems state the room with one bound `B` on every effective balance:
`exitStep preset B` epochs and `rewardMax preset fork B` Gwei for each validator that exits or is
slashed.

The spec-side theorems are in `EthLibOps/`, a library of this project that imports EthLib alone.
EthLib has the definitions and many lemmas about them, and no theorem that a slashing or an exit
succeeds from its checks. `EthLibOps` proves those.

| Theorem | File | Statement |
|---|---|---|
| `churnQueue_ok`, `initiateValidatorExit_ok_of_room` | `ExitQueue.lean` | `initiate_validator_exit` cannot fail for a validator of the registry when the exit queue has room, and it moves the queue by `exitStep` of the validator's effective balance at most |
| `SlashFrame`, `SlashFrame.trans` | `SlashFrame.lean` | What slashings and exits keep between two states, and the bounds on what they move. Frames compose |
| `slashValidator_ok_frame` | `SlashValidator.lean` | `slash_validator` cannot fail for a validator that is not yet slashed, given the list lengths, the proposer and the rooms. The state after it has the slash frame of the state before it |
| `StateRoom`, `slashValidator_ok_of_frame` | `Room.lean` | The same, on a state that has the slash frame of the state the room is read on |
| `processProposerSlashing_ok_of_frame` | `ProposerSlashings.lean` | A slashing that is well formed, passes `ProposerSlashingGates` and `ProposerSlashingSigned` cannot fail |
| `proposerSlashings_foldlM_ok` | `ProposerSlashings.lean` | Slashings that name pairwise distinct proposers and pass the checks on a state succeed in order |
| `slashCandidates_ok` | `AttesterSlashings.lean` | The walk of `process_attester_slashing` cannot fail, and slashes a validator when one it walks is still slashable |
| `processAttesterSlashing_ok_of_frame` | `AttesterSlashings.lean` | A slashing that passes `AttesterSlashingChecks` and walks one slashable validator cannot fail, given room for every walked validator |
| `attesterSlashings_foldlM_ok` | `AttesterSlashings.lean` | Slashings succeed in order after a run of slashings, when each one walks a validator that is slashable on the start state and that no earlier slashing can slash |
| `mem_slashingIndices` | `AttesterSlashings.lean` | The validators a slashing walks are the validators both attestations name |
| `processVoluntaryExit_ok_of_frame` | `VoluntaryExits.lean` | An exit that passes `ExitGates` and `ExitSigned` cannot fail when the exit queue has room |
| `voluntaryExits_foldlM_ok` | `VoluntaryExits.lean` | Exits that name pairwise distinct validators and pass the gates succeed in order, from any state with the slash frame of the state they pass the gates on |
| `StateRoom.of_bounds`, `OperationsRoom.exits_of_timeBound`, `OperationsRoom.rewards_of_supplyCap` | `Bounds.lean` | Within `TimeBound` and `SupplyCap`, the state has the room a slashing reads, and the exit queue and each balance have room for the operations of a block |
| `operationsRoom_mainnet`, `operationsRoom_minimal` | `Bounds.lean` | `OperationsRoom` holds at Fulu for the block limits of each preset, at a cap of `2^58` Gwei |
| `balancesMatch_of_reachable` | `Bounds.lean` | A state that a run reaches from a genesis state has one balance for each validator. This is EthLib's `reachable_balancesMatch` |

The proofs use these theorems of EthLib, among others: `slashValidator_ok_of_room`,
`slashValidator_ok`, `balance_slashValidator`, `isValidIndexedAttestation_of_keys`,
`isValidIndexedAttestation_lt_size`, `mem_sortedSet`, `getTotalActiveBalance_exists_ok` and
`reachable_balancesMatch`.

No proof uses `sorry`. `lake build Audit` prints the axioms of each theorem: Lean's `propext`,
`Classical.choice` and `Quot.sound`, plus the opaque external declarations listed under "What is
trusted". The `EthLibOps` theorems use the three standard axioms only.

## Why the property holds

Packing checks each operation against the unmodified state. Block processing applies the
operations in order, each one writing the state the next one reads.

For the proposer slashings:

1. Each packed slashing passed `verify_proposer_slashing` on the packing state
   (`filter_limit_operations_eq`, `proposerSlashingFilter_spec`,
   `verify_proposer_slashing_validator_checks_ok_iff`, `proposerSlashingGates_of_coreOk`).
2. The packed slashings name pairwise distinct proposers, and a slashing of one validator leaves
   the checks of the others alone (`SlashFrame`, `proposerSlashings_foldlM_ok`).
3. `slash_validator`, which packing never runs, cannot fail when the exit queue and the
   proposer's balance have room (`slashValidator_ok_frame`).

For the attester slashings, after the proposer slashings:

1. Each `AttesterSlashingMaxCover` covers the validators its slashing can slash on the packing
   state: the validators both attestations name, that are slashable, and that no packed
   proposer slashing names (`attesterCovers_spec`).
2. `maximum_cover` picks only items with a non-zero score, and after each pick it removes what
   the pick covers from every other item that can still be picked. So each picked slashing can
   slash a validator that no slashing picked before it can slash (`maximum_cover_spec`).
3. A slashing changes the record of the validators it slashes and of no other validator
   (`SlashFrame`). That validator is therefore still slashable when its slashing runs, and the
   spec's `slashed_any` assertion holds (`slashCandidates_ok`,
   `attesterSlashings_foldlM_ok`).
4. The checks before the walk read the registry's length, the public keys and the fork. No
   slashing changes them (`SlashFrame.isValidIndexedAttestation`).
5. Each `slash_validator` call of the walk cannot fail when the exit queue and the proposer's
   balance have room (`slashValidator_ok_of_frame`).

For the exits, after the slashings:

1. Each packed exit passed `verify_exit` on the packing state (`filter_limit_operations_eq`,
   `voluntaryExitFilter_spec`, `verify_exit_*_ok_iff`, `exitGates_of_coresOk`).
2. The packed exits name pairwise distinct validators, and an exit of one validator leaves the
   checks of the others alone (`voluntaryExits_foldlM_ok`).
3. No packed exit names a validator the packed slashings can slash (`exclusionSet_covers`), and
   a slashing changes nothing else an exit reads (`SlashFrame`).
4. `initiate_validator_exit`, which packing never runs, cannot fail when the exit queue has
   room (`processVoluntaryExit_ok_of_frame`).

## The Rust that is extracted

Seven functions, each free of `EthSpec`, that Aeneas translates:

| Function | Crate | Role |
|---|---|---|
| `filter_limit_operations` | `operation_pool` | The packing loop, generic over the iterator and the two closures. It packs the proposer slashings and the exits |
| `maximum_cover` | `operation_pool` | The greedy max cover, generic over `T: MaxCover`. It packs the attester slashings and the attestations. Its helpers `best_item_index` and `update_covering_sets` are extracted with it |
| `insert_proposer_slashing_indices` | `operation_pool` | Adds the packed proposer slashings' proposers to the exclusion set |
| `insert_common_attesting_indices` | `operation_pool` | Adds the indices common to an attester slashing's two attestations |
| `verify_proposer_slashing_validator_checks` | `state_processing` | The check of `verify_proposer_slashing` on the proposer's record |
| `verify_exit_validator_checks` | `state_processing` | The checks of `verify_exit` on the validator record |
| `verify_exit_pending_balance` | `state_processing` | The pending-withdrawal check of `verify_exit` |

`Validator::is_slashable_at` and `Validator::is_active_at` are extracted with the cores that
call them. The model of `AttesterSlashingMaxCover::new` calls the first one too.

`maximum_cover` was a chain of iterator adaptors (`filter`, `max_by_key`, `for_each`), for which
the Aeneas library has no model. It is now three written-out loops with the same behaviour: the
same items are kept, the last item with the best score wins a tie as with `max_by_key`, and the
same items are updated. Three changes come with it. The trait `MaxCover` lost the `Clone` bounds
on its associated types: no code used them, and Aeneas gave the four `Clone` clauses of the
trait one field name, which Lean rejects. The gauge update moved to
`metrics::set_max_cover_non_zero_items`, which stays opaque. The selection pass computes each
score once, where `filter` and `max_by_key` computed it twice.

The proposer-slashing filter of `get_slashings_and_exits` calls
`verify_proposer_slashing(.., VerifySignatures::False, ..)`, as the exit filter calls
`verify_exit`. It called `Validator::is_slashable_at` directly before. The result is the same
for a pool entry, and the extracted core is now on the packing path.

`get_slashings_and_exits` already held the validators to be slashed in `to_be_slashed`. The two
`insert_*` functions add the same validators again from the packed slashings alone, so the proof
of the exits does not depend on the max cover. They add the whole intersection of the two
attestations, where the max cover adds its slashable members. A validator in the intersection
that is not slashable is slashed already, not yet active, or withdrawable, and has no valid
exit, so the packed exits are the same on any reachable state.

## What is trusted

Not proved, and to be checked by inspection:

| Item | Where it enters |
|---|---|
| Charon, Aeneas and the Lean kernel | Translation and checking |
| The external models: `HashSet` as a list of distinct values (`with_capacity`, `insert`, `contains`), `metrics::set_max_cover_non_zero_items` as a call that returns, and the opaque external types and hashing functions | `OperationPool/TypesExternal.lean`, `OperationPool/FunsExternal.lean`, `StateProcessing/TypesExternal.lean`, `ExternalTypes.lean` |
| The models of `OperationPool/Concrete.lean` stand for the Rust values. A pool's iterator yields each pool entry once, as the slice iterator does on a slice of the entries. A mapping closure clones the operation of the entry and does not panic | The form of the main theorem: `sliceIntoIter`, `pureFn`, `cloneId` |
| The models of `OperationPool/Closures.lean` compute what the Rust closures compute. Each definition quotes the Rust it models. The two filters are `proposerSlashingFilter` and `voluntaryExitFilter`. `attesterCovers` is what the `flat_map` iterator of `get_attester_slashings` yields, and `attesterCoverNew` is `AttesterSlashingMaxCover::new` with `get_slashable_indices_modular` written out. `proposerIndexSet` is the set `to_be_slashed` that `new` reads | The form of the main theorem |
| The reads of the models are the reads of the Rust. `verify_proposer_slashing<E>`, `verify_exit<E>`, `get_slashable_indices_modular` and `get_effective_balance` read the validator at an index with `state.validators().get(index)`, and the models read `StateView.validatorAt`. The epoch is `state.current_epoch()`, the two constants come from the chain spec, and the pending balance is `get_pending_balance_to_withdraw(index).ok()` | `StateView` |
| `AttesterCover` stands for `AttesterSlashingMaxCover`: the slashing, and `effective_balances` as a list of key and value. Its methods are those of the Rust: `score` is the sum of the values, which wraps as in a release build; `update_covering_set` is `retain` on the keys the picked cover does not have; `clone` returns its argument | `AttesterCover`, `AttesterCover.maxCover` |
| The body of `get_slashings_and_exits` makes the calls of the conclusion, with these arguments: `to_be_slashed` holds the proposers of the packed proposer slashings when the covers are built, the exclusion set is built from the packed slashings, and the exit filter reads that set | The form of the conclusion; `initial`, `indicesA` |
| The three limits are the preset's: `E::MaxProposerSlashings`, `E::max_attester_slashings_electra()` and `E::MaxVoluntaryExits` | `hlimits` |
| An attester slashing of the pool with a signature that is still valid passes the spec's checks before the walk, on the packing state: the two attestations are slashable, and each is a valid indexed attestation (indices not empty, sorted, in the registry, aggregate signature valid). `SigVerifiedOp` is built only after `verify_attester_slashing`, and `signature_is_still_valid` checks the fork versions. Lighthouse does not check again at packing that every attesting index is in the registry of the packing state: `new` looks up the indices that both attestations name, and no other | `hchecksA` (`AttesterSlashingChecks`) |
| `get_attester_slashings` returns, for each picked cover, `convert_to_object(cover.intermediate())` | `toSpecA`, the conclusion |
| The exit pool's `HashMap` is keyed by `message.validator_index`, and the proposer-slashing pool's by `proposer_index()` (`insert_voluntary_exit`, `insert_proposer_slashing`, `persistence.rs`), so the entries name pairwise distinct validators | `hkeys`, `hkeysP` |
| A proposer slashing with headers that pass the three checks of `verify_proposer_slashing<E>` is well formed for the spec: the two headers have the same slot and the same proposer index, and differ. Lighthouse compares the headers field by field, and so does EthLib | `hheadersP` (`headersOk`, `ProposerSlashingWellFormed`) |
| The Lighthouse state corresponds to the spec state: same validator epochs and slashed flags, same current epoch, and a pending balance that was computed without overflow | `hcorr` (`StateCorr`) |
| A proposer slashing or an exit of a pool with a signature that is still valid has valid signatures for the packing state. `SigVerifiedOp` is built only after a signature check, and a validator's public key never changes. For an exit, the Fulu domain is fixed at the Capella fork version. For a proposer slashing, `signature_is_still_valid` checks that the fork version at the header's epoch is the one the signature was checked under | `hsignedE` (`ExitSigned`), `hsignedP` (`ProposerSlashingSigned`) |
| The spec's forms of the packed operations carry the same indices and epochs as the Rust values | `hmessage`, `hindexP`, `hindicesA` |
| EthLib's model is the consensus spec. It is checked against the consensus spec tests. The signature checks are the `SignatureChecks` the theorem is stated for: any pair of check functions, of which `SignatureChecks.bls` is the real one | The spec-side theorems |

Assumptions about the state, by design:

- The packing state is a Fulu state that a run of the spec reaches from a genesis state
  (`hfork`, `hrun`, `hgenesis`). This is where the proof assumes that Lighthouse's state
  transition is the spec's.
- The proposer of the slot is in the registry (`hproposer`, `hproposerIn`). The proof does not
  derive it from the run.
- The state is within the time bound and the supply cap (`htime`, `hsupply`).

## Scope

- **Fork.** The spec side is Fulu: `IsFulu fork`, from the Fulu upgrade and before Gloas. EthLib
  states each rule for every fork, and the proofs here take the Fulu branch. Gloas overrides the
  exit churn, voids builder payments in `slash_validator`, and runs the parent's execution
  requests before the exits; the Gloas filter for those is proved in `../block_production`.
- **The `MaxCover` implementation.** `maximum_cover` is extracted and proved. The methods of
  `AttesterSlashingMaxCover` and its constructor are generic over `EthSpec` and are not
  extracted. `AttesterCover` models the methods, and `attesterCoverNew` models the constructor.
- **The closures.** The three closures of `get_slashings_and_exits` read `BeaconState<E>` and
  are not extracted. Their models call the extracted cores, and the rest of each model is
  written by hand from the Rust.
- **Steps before the operations.** A block runs its header, withdrawals, execution payload,
  RANDAO and eth1 data before the proposer slashings, and its attestations before the exits.
  None of them writes what a slashing or an exit reads, apart from balances, but that is not
  proved here. `SlashFrame` is the interface for adding them.
- **Checked sums.** EthLib raises an error on every sum and product that reaches `2^64`, as the
  pyspec does. The theorems therefore cover the two sums of `slash_validator` that an earlier
  version of this work, on a model that wraps, left out: `epoch + EPOCHS_PER_SLASHINGS_VECTOR`,
  and the slashings entry plus the effective balance. `TimeBound` gives room for the first, and
  the third field of `SupplyCap` for the second.
- **The room EthLib asks for.** `slashValidator_ok_of_room` (EthLib) asks that the proposer's
  balance has room for the whole effective balance of the slashed validator, where the reward
  is a fraction of it. `OperationsRoom` carries that extra `2^58` Gwei.
- **The spec's loops.** Each fold is stated as `ops.toArray.foldlM (processX config checks)`.
  Before Gloas, EthLib's `processOperations` is a sequence of such folds over the lists of the
  block body, with the deposits and the attestations between the slashings and the exits. The
  theorem does not state that sequence.
- **Completeness.** The theorems say every packed operation is valid. They do not say that
  every valid operation is packed, or that the max cover picks a best set of slashings.

## Layout

```
ExternalTypes.lean            opaque external types shared by both crates (hand-written, trusted)
EthLibOps/                    proofs on EthLib's spec alone; no Rust
  ExitQueue.lean              `initiate_validator_exit` succeeds when the exit queue has room
  SlashFrame.lean             what slashings and exits keep, and the bounds on what they move
  SlashValidator.lean         `slash_validator` succeeds and has the slash frame
  Room.lean                   the room read on the packing state; the single steps from a frame
  ProposerSlashings.lean      the proposer slashings of a block succeed
  AttesterSlashings.lean      the attester slashings of a block succeed
  VoluntaryExits.lean         the voluntary exits of a block succeed
  Bounds.lean                 `TimeBound`, `SupplyCap`, `OperationsRoom`; mainnet and minimal
OperationPool/
  Types.lean, Funs.lean       generated from `operation_pool`
  TypesExternal.lean          hand-written models of external types (trusted)
  FunsExternal.lean           hand-written models of external functions (trusted)
  FilterLimit.lean            proof: the packing loop
  MaxCover.lean               proof: the greedy max cover
  ExclusionSet.lean           proof: the exclusion set
  Concrete.lean               slice pools, pure closures and the model of a cover
  Closures.lean               the filter closures and `AttesterSlashingMaxCover::new`, modelled
                              on the extracted cores
  Bridge/Scalars.lean         Rust `u64` to the spec's `UInt64`
  Bridge/StateCorr.lean       the state correspondence; Rust checks to spec gates
  PackedProposerSlashingsValid.lean   the proposer slashings
  PackedAttesterSlashingsValid.lean   the attester slashings, after the proposer slashings
  PackedExitsValid.lean               the exits, after the slashings
  PackedSlashingsAndExitsValid.lean   main theorem: the three kinds, in order
StateProcessing/
  Types.lean, Funs.lean       generated from `state_processing`
  TypesExternal.lean          hand-written opaque external types (trusted)
  VerifyExit.lean             proof: the `verify_exit` cores
  VerifyProposerSlashing.lean proof: the `verify_proposer_slashing` core
Audit.lean                    prints the axioms of the main theorems
extract.sh                    regenerates the generated files
```

The `*_Template.lean` files are generated by Aeneas and list what the hand-written external
files have to provide.

## Dependencies

Both sit under `../deps`, which Git ignores. No script fetches them yet.

- `aeneas-release-2e3d448/`: the Aeneas release `nightly-2026.11.23-2e3d448`, on Lean v4.36.0,
  unpacked from `aeneas-linux-x86_64.tar.gz`. It bundles the `aeneas` and `charon` binaries and
  the Lean library.
- `ethlib/`: a checkout of [EthLib](https://github.com/ethereum/EthLib) at commit `32d394779`,
  on Lean v4.36.0. EthLib is pure Lean and needs no native library.

Aeneas and EthLib both require Mathlib `v4.36.0`, so the project has one copy. EthLib changes
fast: a later commit can rename or restate the theorems that `EthLibOps` uses.

## Regenerating and checking

```sh
./extract.sh       # Rust -> LLBC -> {OperationPool,StateProcessing}/{Types,Funs}.lean
lake build         # checks the generated code, the models and the proofs
lake build Audit   # prints the axioms each main theorem depends on
```

The first build needs the Mathlib cache: `lake exe cache get`. It then builds the part of EthLib
that the proofs import, about 1900 modules, in a few minutes. To check one file,
`lake env lean OperationPool/FilterLimit.lean` takes a few seconds once its imports are built.

The files of `EthLibOps` are Lean modules, as EthLib's are, so that they see what EthLib
exports and nothing else. The files of `OperationPool` import Aeneas, which is not a module
library, and are plain files.

`extract.sh` runs Charon once per crate. Aeneas emits a function of another crate only when an
extracted body calls it, so each crate's functions are extracted from that crate. Neither crate
builds on its own, and the script unifies Cargo features across the workspace to make them
build.
