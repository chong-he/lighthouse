# Proposer-slashing and voluntary-exit packing: proved valid against the consensus spec

Machine-checked proofs, in Lean 4, that the proposer slashings and the voluntary exits packed by
`OperationPool::get_slashings_and_exits` are valid for inclusion in the block:

- the consensus spec processes the packed proposer slashings, in order, without an error, from
  the state they were packed on;
- the consensus spec then processes the packed voluntary exits, in order, without an error,
  after the block's packed slashings.

The Rust is translated to Lean by [Charon](https://github.com/AeneasVerif/charon) and
[Aeneas](https://github.com/AeneasVerif/aeneas). The spec is the Fulu fork of
[Etheorem](https://github.com/etheorem/etheorem), an executable Lean model of the consensus
specification. One Lean project depends on both.

## What is proved

Three main theorems, each a statement about the real `filter_limit_operations` and the spec's
`process_proposer_slashing` and `process_voluntary_exit`. Let `s` be the spec state that
corresponds to the Lighthouse state the op pool packs on.

**Proposer slashings.** `packed_proposer_slashings_valid_uniform`
(`OperationPool/PackedProposerSlashingsValid.lean`):

> `filter_limit_operations` does not panic and returns at most `MAX_PROPOSER_SLASHINGS`
> slashings. The spec's `process_proposer_slashing` succeeds on each of them in order, starting
> from `s`.

**Proposer slashings, then exits.** `packed_exits_valid_after_packed_proposer_slashings`
(`OperationPool/PackedSlashingsAndExitsValid.lean`):

> The packed proposer slashings succeed from `s` and reach `s₁`. If the spec then processes the
> packed attester slashings from `s₁` and reaches `s₂`, and the exit queue of `s₂` has room,
> the spec's `process_voluntary_exit` succeeds on each packed exit in order, starting from `s₂`.

The run of the proposer slashings was a hypothesis of the exit theorem. It is now a conclusion.
The run of the attester slashings is still a hypothesis.

**A block with no attester slashings.** `packed_proposer_slashings_and_exits_valid` (same file):

> The packed proposer slashings succeed from `s` and reach `s₁`, and the packed exits succeed
> from `s₁`.

This theorem has no hypothesis that the spec runs anything. Every hypothesis about the state is
about the packing state `s`.

### The hypotheses about the state

| Hypothesis | Meaning | Status |
|---|---|---|
| `hcorr` | The Lighthouse state corresponds to `s` | Trusted, see below |
| `hsize` | `balances` has the registry's length | Proved for every reachable state: `balances_size_of_reachable` |
| `hproposer` | The proposer of the slot is a validator in the registry | Assumed. `process_block_header` checks it earlier in the block |
| `hexits` | The exit queue has room for the slashings and the exits | Assumed. On mainnet: the earliest exit epoch is at least about `4.6e9` epochs below `2^64` |
| `hrewardsP` | The proposer's balance has room for the whistleblower rewards | Assumed. On mainnet: the balance is below `2^64 - 2^56` Gwei |

The two room hypotheses cover the arithmetic of `slash_validator` and
`initiate_validator_exit`, which packing never runs. `exitStep (2^64 - 1)` bounds the epochs one
exit can take (about `1.4e8` on mainnet), and `(2^64 - 1) / WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA`
bounds one reward (below `2^52` Gwei on mainnet).

### Supporting theorems

| Theorem | File | Statement |
|---|---|---|
| `filter_limit_operations_eq` | `OperationPool/FilterLimit.lean` | The packed list is `((pool.filter keep).take limit).map f`; no panic |
| `verify_proposer_slashing_validator_checks_ok_iff` | `StateProcessing/VerifyProposerSlashing.lean` | Returns `Ok` exactly when the proposer exists and its record passes `SlashableChecks`; no panic |
| `verify_exit_validator_checks_ok_iff` | `StateProcessing/VerifyExit.lean` | Returns `Ok` exactly when the validator exists and its record passes `ExitChecks`; no panic |
| `verify_exit_pending_balance_ok_iff` | `StateProcessing/VerifyExit.lean` | Returns `Ok` exactly when the pending balance, if computed, is zero; no panic |
| `exclusionSet_covers` | `OperationPool/ExclusionSet.lean` | The exclusion set holds each packed proposer slashing's proposer and each index common to the two attestations of a packed attester slashing |
| `proposerSlashingGates_of_coreOk` | `OperationPool/Bridge/StateCorr.lean` | A proposer the `verify_proposer_slashing` core accepts passes the spec's `ProposerSlashingGates` |
| `exitGates_of_coresOk` | `OperationPool/Bridge/StateCorr.lean` | An exit both `verify_exit` cores accept passes the spec's `ExitGates` |
| `balances_size_of_reachable` | `OperationPool/Bridge/Reachable.lean` | The balances of a reachable state have the registry's length |
| `mem_qsort` | `OperationPool/Bridge/QSort.lean` | `Array.qsort` returns a permutation of its input |
| `packed_proposer_slashings_valid` | `OperationPool/PackedProposerSlashingsValid.lean` | The packed proposer slashings succeed, with the room stated per slashing |
| `packed_exits_valid` | `OperationPool/PackedExitsValid.lean` | The packed exits succeed from any state with the exit view of the packing state |
| `packed_exits_valid_after_slashings` | `OperationPool/PackedExitsValid.lean` | The packed exits succeed after slashings whose runs are given |

The spec-side theorems live in Etheorem, on branch `voluntary-exit-proofs`, under
`packages/EthCLSpecs/EthCLSpecs/Proofs/Fulu/`:

| Theorem | File | Statement |
|---|---|---|
| `slashValidator_succeeds` | `ProposerSlashings.lean` | `slash_validator` cannot fail for a validator of the registry, given the list lengths, the proposer and the two rooms |
| `processProposerSlashing_succeeds` | `ProposerSlashings.lean` | A slashing that is well formed, passes `ProposerSlashingGates` and `ProposerSlashingSigned` cannot fail, under the same premises |
| `proposerSlashings_succeed` | `ProposerSlashings.lean` | Slashings that name pairwise distinct proposers and pass the checks on a state succeed in order from it |
| `processVoluntaryExit_succeeds` | `VoluntaryExits.lean` | An exit that passes `ExitGates` and `ExitSigned` cannot fail when the exit queue has room |
| `voluntaryExits_succeed_of_exitView` | `VoluntaryExits.lean` | Exits that name pairwise distinct validators and pass the gates succeed in order, from any state with the same `ExitView` |
| `exitView_of_slashings` | `VoluntaryExits/Slashings.lean` | The proposer and attester slashings of a block keep the exit view for the validators they cannot slash |

No proof uses `sorry`. `./lake.sh build Audit` prints the axioms of each theorem: Lean's
`propext`, `Classical.choice` and `Quot.sound`, plus the opaque external declarations listed
under "What is trusted". The Etheorem theorems use the three standard axioms only.

## Why the property holds

Packing checks each operation against the unmodified state. Block processing applies the
operations in order, each one writing the state the next one reads.

For the proposer slashings:

1. Each packed slashing passed `verify_proposer_slashing` on the packing state
   (`filter_limit_operations_eq`, `verify_proposer_slashing_validator_checks_ok_iff`,
   `proposerSlashingGates_of_coreOk`).
2. The packed slashings name pairwise distinct proposers, and a slashing of one validator leaves
   the checks of the others alone (`SlashFrame`, `proposerSlashings_succeed`).
3. `slash_validator`, which packing never runs, cannot fail when the exit queue and the
   proposer's balance have room (`slashValidator_succeeds`).

For the exits, after the slashings:

1. Each packed exit passed `verify_exit` on the packing state (`filter_limit_operations_eq`,
   `verify_exit_*_ok_iff`, `exitGates_of_coresOk`).
2. The packed exits name pairwise distinct validators, and an exit of one validator leaves the
   checks of the others alone (`voluntaryExits_succeed_of_exitView`).
3. No packed exit names a validator the packed slashings can slash (`exclusionSet_covers`), and
   a slashing changes nothing else an exit reads (`exitView_of_slashings`).
4. `initiate_validator_exit`, which packing never runs, cannot fail when the exit queue has
   room (`processVoluntaryExit_succeeds`).

## The Rust that is extracted

Six functions, each free of `EthSpec`, split out of the real code so that Aeneas can translate
them:

| Function | Crate | Role |
|---|---|---|
| `filter_limit_operations` | `operation_pool` | The packing loop, generic over the iterator and the two closures. It packs the proposer slashings and the exits |
| `insert_proposer_slashing_indices` | `operation_pool` | Adds the packed proposer slashings' proposers to the exclusion set |
| `insert_common_attesting_indices` | `operation_pool` | Adds the indices common to an attester slashing's two attestations |
| `verify_proposer_slashing_validator_checks` | `state_processing` | The check of `verify_proposer_slashing` on the proposer's record |
| `verify_exit_validator_checks` | `state_processing` | The checks of `verify_exit` on the validator record |
| `verify_exit_pending_balance` | `state_processing` | The pending-withdrawal check of `verify_exit` |

The proposer-slashing filter of `get_slashings_and_exits` calls
`verify_proposer_slashing(.., VerifySignatures::False, ..)`, as the exit filter calls
`verify_exit`. It called `Validator::is_slashable_at` directly before. The result is the same
for a pool entry, and the extracted core is now on the packing path.

`get_slashings_and_exits` already held the validators to be slashed in `to_be_slashed`. That set
is exact, but its correctness runs through the max cover over attester slashings. The two
`insert_*` functions add the same validators again from the packed slashings alone, so the proof
does not depend on the max cover. They add the whole intersection of the two attestations, where
the max cover adds its slashable members. A validator in the intersection that is not slashable
is slashed already, not yet active, or withdrawable, and has no valid exit, so the packed exits
are the same on any reachable state.

## What is trusted

Not proved, and to be checked by inspection:

| Item | Where it enters |
|---|---|
| Charon, Aeneas and the Lean kernel | Translation and checking |
| The external models: `HashSet` as a list of distinct values (`with_capacity`, `insert`, `contains`), and the opaque external types and hashing functions | `OperationPool/TypesExternal.lean`, `OperationPool/FunsExternal.lean`, `StateProcessing/TypesExternal.lean`, `ExternalTypes.lean` |
| Each pool's iterator yields each pool entry once | `hinto`, `hyields`, and the `P` forms |
| The exit pool's `HashMap` is keyed by `message.validator_index`, and the proposer-slashing pool's by `proposer_index()` (`insert_voluntary_exit`, `insert_proposer_slashing`, `persistence.rs`), so the entries name pairwise distinct validators | `hkeys`, `hkeysP` |
| The closures of the two packing calls. Exits: the filter is `filter(exit) && signature_is_still_valid && verify_exit(..).is_ok()`. Proposer slashings: `signature_is_still_valid && verify_proposer_slashing(..).is_ok()`. Both mappings clone the operation | `hfilter`, `hmapping`, `hkeep`, and the `P` forms |
| `verify_exit<E>` calls the two cores with the validator at the exit's index, the state's current epoch, the chain spec's constants, and the pending balance when it was computed | `hkeep` (`CoresOk`), `StateView` |
| `verify_proposer_slashing<E>` checks that the two headers have the same slot and the same proposer index and differ, and then calls the core with the validator at that index and the state's current epoch | `hkeepP` (`ProposerCoreOk`, `ProposerSlashingWellFormed`) |
| Two headers that differ have different hash tree roots. Lighthouse compares the headers field by field; Etheorem's model compares their hash tree roots. The two agree unless SHA-256 collides | `hkeepP` (`ProposerSlashingWellFormed.differ`) |
| The Lighthouse state corresponds to the spec state: same validator epochs and slashed flags, same current epoch, and a pending balance that was computed without overflow | `hcorr` (`StateCorr`) |
| An operation in a pool has valid signatures for the packing state. `SigVerifiedOp` is built only after a signature check, and a validator's public key never changes. For an exit, the Fulu domain is fixed at the Capella fork version. For a proposer slashing, `signature_is_still_valid` checks that the fork version at the header's epoch is the one the signature was checked under | `hkeep` (`ExitSigned`), `hkeepP` (`ProposerSlashingSigned`) |
| The call site in `get_slashings_and_exits` builds the exclusion set with the two `insert_*` functions on the packed slashings, and filters the exits with it | `hslice`, `hexcl`, `hkeep` |
| The spec's forms of the packed operations carry the same indices and epochs as the Rust values | `hmessage`, `hindexP`, `hattesters` |
| Etheorem's Fulu model is the consensus spec, with a valid preset and config (`PresetValid`, `ConfigValid`, proved for `mainnet` and `minimal`) | The spec-side theorems |

Assumptions about the state or the run, by design:

- The proposer of the slot is in the registry, and the exit queue and the proposer's balance
  have room (`hproposer`, `hexits`, `hrewardsP`). Etheorem's reachable-state invariants do not
  cover these yet.
- When the block has attester slashings, the spec processes them without an error
  (`hslash₂`), and the exit queue has room after them (`hroom`). Attester-slashing packing is
  not proved here.

## Scope

- **Fork.** The spec side is Fulu. Gloas overrides the exit churn, voids builder payments in
  `slash_validator`, and runs the parent's execution requests before the exits; the Gloas filter
  for those is proved in `../block_production`.
- **Attester slashings.** Their packing runs through the max cover and is not proved. The
  theorems take their run as a hypothesis, or cover a block that has none.
- **Steps before the operations.** A block runs its header, withdrawals, execution payload,
  RANDAO and eth1 data before the proposer slashings, and its attestations before the exits.
  None of them writes what a slashing or an exit reads, apart from balances, but that is not
  proved here. `SlashFrame` and `ExitView` are the interfaces for adding them.
- **Sums that wrap in the model.** Etheorem's `slash_validator` wraps on two sums where the
  pyspec raises: `epoch + EPOCHS_PER_SLASHINGS_VECTOR`, and the slashings entry plus the
  effective balance. The theorems follow the model, so they say nothing about a state where one
  of those sums passes `2^64`. This work found the gap; Etheorem's `DISCREPANCIES.md` records
  it.
- **The spec's loops.** Each fold is stated as `ForM.forM ops process_op`.
  `forIn_voluntaryExits_eq` (Etheorem) proves that the `for` loop over `body.voluntary_exits`
  is that fold. The same fact for the proposer slashings, and the split of `process_operations`
  into its loops, are proved in Etheorem for Gloas (`processOperations_eq_seq`) and not yet
  ported to Fulu.
- **Completeness.** The theorems say every packed operation is valid. They do not say that
  every valid operation is packed.

## Layout

```
ExternalTypes.lean            opaque external types shared by both crates (hand-written, trusted)
OperationPool/
  Types.lean, Funs.lean       generated from `operation_pool`
  TypesExternal.lean          hand-written models of external types (trusted)
  FunsExternal.lean           hand-written models of external functions (trusted)
  FilterLimit.lean            proof: the packing loop
  ExclusionSet.lean           proof: the exclusion set
  Bridge/Scalars.lean         Rust `u64` to the spec's `UInt64`
  Bridge/QSort.lean           `Array.qsort` returns a permutation
  Bridge/StateCorr.lean       the state correspondence; Rust checks to spec gates
  Bridge/Reachable.lean       what Etheorem's reachable-state invariants give
  PackedProposerSlashingsValid.lean   main theorem: proposer slashings
  PackedExitsValid.lean               the exits, after slashings whose runs are given
  PackedSlashingsAndExitsValid.lean   main theorems: proposer slashings, then exits
StateProcessing/
  Types.lean, Funs.lean       generated from `state_processing`
  TypesExternal.lean          hand-written opaque external types (trusted)
  VerifyExit.lean             proof: the `verify_exit` cores
  VerifyProposerSlashing.lean proof: the `verify_proposer_slashing` core
Audit.lean                    prints the axioms of the main theorems
extract.sh                    regenerates the generated files
lake.sh                       runs `lake` for this project
```

The `*_Template.lean` files are generated by Aeneas and list what the hand-written external
files have to provide.

## Dependencies

Both sit under `../deps`, which Git ignores. No script fetches them yet.

- `aeneas-release-5a392f4/`: the Aeneas release `nightly-2026.11.09-5a392f4`, the last one on
  Lean v4.35.0, unpacked from `aeneas-linux-x86_64.tar.gz`. It bundles the `aeneas` and `charon`
  binaries and the Lean library.
- `etheorem-lean4.35/`: a checkout of Etheorem on branch `voluntary-exit-proofs` of
  `github.com/michaelsproul/etheorem`, at a commit that has
  `Proofs/Fulu/ProposerSlashings.lean`. The branch sets `lean-toolchain` to v4.35.0. The
  checkout also needs the vendored native sources, which Etheorem's `just hazmat-*-vendor`
  recipes fetch.

## Regenerating and checking

```sh
./extract.sh          # Rust -> LLBC -> {OperationPool,StateProcessing}/{Types,Funs}.lean
./lake.sh build       # checks the generated code, the models and the proofs
./lake.sh build Audit # prints the axioms each main theorem depends on
```

Use `./lake.sh` in place of `lake`. Etheorem's native libraries link only when Lake starts
inside the Etheorem checkout, and the script takes care of that. To check one file that does not
import Etheorem, `./lake.sh env lean OperationPool/FilterLimit.lean` takes a few seconds. A file
that imports Etheorem has to go through `./lake.sh build <Module>`.

The first build needs the Mathlib cache: `./lake.sh exe cache get`.

`extract.sh` runs Charon once per crate. Aeneas emits a function of another crate only when an
extracted body calls it, so each crate's functions are extracted from that crate. Neither crate
builds on its own, and the script unifies Cargo features across the workspace to make them
build.
