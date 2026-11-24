import OperationPool.Closures
import OperationPool.PackedProposerSlashingsValid
import OperationPool.PackedAttesterSlashingsValid
import OperationPool.PackedExitsValid

/-!
# The packed slashings and voluntary exits of a block are valid together

`OperationPool::get_slashings_and_exits` packs the proposer slashings, the attester slashings
and the voluntary exits of one block. `process_operations` applies them in that order, and each
operation changes the state the next one reads.

`packed_slashings_and_exits_valid` is the main theorem of this project. It follows the body of
`get_slashings_and_exits` call by call, and states that the spec processes what each call
returns: the proposer slashings from the packing state `s`, then the attester slashings, then
the voluntary exits. No step fails.

The spec is EthLib's. Before Gloas its `processOperations` folds `processProposerSlashing`,
`processAttesterSlashing` and `processVoluntaryExit` over the operations of a block body, and
the conclusion states those three folds.

## The form of the statement

The three packing theorems are generic over the iterator, the closures and the `MaxCover`
implementation, and take a hypothesis for each. This theorem states the extracted functions on
concrete instances, for which those hypotheses are proved:

* a pool is a slice (`OperationPool/Concrete.lean`);
* a filter closure is its model on the extracted cores of the `verify_*` functions
  (`proposerSlashingFilter` and `voluntaryExitFilter` of `OperationPool/Closures.lean`);
* a cover is an `AttesterCover`, and the covers are the ones that the model of
  `AttesterSlashingMaxCover::new` builds (`attesterCovers`).

The packing state `s` is a state of the spec at Fulu that a run of slots and blocks reaches from
a genesis state, within `TimeBound` and `SupplyCap (2 ^ 58)`. Those two bounds keep the
arithmetic away from `2 ^ 64`. The constants leave room within them for a block with as many
operations as the preset allows (`OperationsRoom`), and the three limits are at most the
preset's. `operationsRoom_mainnet` and `operationsRoom_minimal` prove that room for the two
presets.

The hypotheses that are not proved from extracted code are the trusted base. `README.md` lists
them.
-/

namespace OperationPool

open EthLib EthLib.Consensus
open EthLibOps
open OperationPool.Bridge
open operation_pool (sliceIntoIter pureFn cloneId AttesterCover)

section

variable {preset : Preset} {fork : Base.Fork} {config : Config} {checks : SignatureChecks}

variable {OpP OpA Im Op X : Type}

/-- A Rust index is one of the indices an attester slashing walks exactly when both Rust lists
of attesting indices hold it. `indices` holds the two Rust lists of the slashing `asl`. -/
theorem mem_slashingIndices_of_indices {asl : AttesterSlashing preset fork}
    {indices : Aeneas.Std.Slice Aeneas.Std.U64 × Aeneas.Std.Slice Aeneas.Std.U64}
    (h : asl.attestation1.attestingIndices.data.toList = indices.1.val.map u64ToSpec ∧
      asl.attestation2.attestingIndices.data.toList = indices.2.val.map u64ToSpec)
    (u : Aeneas.Std.U64) :
    u64ToSpec u ∈ slashingIndices asl ↔ u ∈ indices.1.val ∧ u ∈ indices.2.val := by
  have hmap : ∀ l : List Aeneas.Std.U64, u64ToSpec u ∈ l.map u64ToSpec ↔ u ∈ l := fun l =>
    ⟨fun hu => by
      obtain ⟨x, hx, hxu⟩ := List.mem_map.mp hu
      exact u64ToSpec_inj hxu ▸ hx,
    fun hu => List.mem_map.mpr ⟨u, hu, rfl⟩⟩
  rw [mem_slashingIndices, h.1, h.2, hmap, hmap]

/-- The packed proposer slashings, attester slashings and voluntary exits of a block are valid:
the spec processes them in that order from the packing state `s`, and no step fails.

The data:

* `poolP`, `slashingOf`, `limitP`: the proposer-slashing pool, the mapping closure, and
  `MAX_PROPOSER_SLASHINGS`.
* `poolA`, `slashingOfA`, `limitA`: the attester-slashing pool, the slashing of an entry, and
  `MAX_ATTESTER_SLASHINGS_ELECTRA`.
* `pool`, `exitOf`, `limit`: the exit pool, the mapping closure, and `MAX_VOLUNTARY_EXITS`.
* `stillValidP`, `stillValidA`, `stillValidE`: `signature_is_still_valid` on an entry of each
  pool. `headersOk` is the three checks of `verify_proposer_slashing` on the two headers.
* `initial`: the set `to_be_slashed` when the two `insert_*` functions extend it.
* `toSpecP`, `toSpecA`, `toSpec`: the spec's form of each operation. `indicesA` and `message`
  read the Rust attesting indices and the Rust exit.

The hypotheses:

* `hfork`: the fork of the spec state is Fulu.
* `hindexP`, `hindicesA`, `hmessage`: the spec's forms carry the Rust indices and epochs.
* `hkeysP`, `hkeys`: a pool holds one operation per validator.
* `hconfig`, `hlimits`: the constants leave room for the largest block of the preset, on a state
  that holds `2 ^ 58` Gwei at most, and the three limits are at most the preset's block limits.
* `hcorr`: the state Lighthouse reads corresponds to the spec state `s`.
* `hrun`, `hgenesis`: a run of slots and blocks reaches `s` from the genesis state `g`.
* `hproposer`, `hproposerIn`: `p` is the proposer of the slot of `s`, and is in the registry.
* `htime`, `hsupply`: `s` is within the time bound and a supply cap of `2 ^ 58` Gwei.
* `hheadersP`: a proposer slashing with headers that pass the three checks is well formed.
* `hsignedP`, `hsignedE`: a proposer slashing or an exit with a signature that is still valid
  is signed on `s`.
* `hchecksA`: an attester slashing with a signature that is still valid passes the checks of
  `process_attester_slashing` that run before the walk.

The conclusion follows `get_slashings_and_exits`. No call panics. `outP`, `outA` and `out` are
what the three packing calls return, within their limits. `covers` holds the covers that the
iterator of `get_attester_slashings` yields, built with the proposers of `outP` as the set
`to_be_slashed`. `excl` is the exclusion set built from `outP` and `outA`. The spec processes
`outP` from `s` and reaches `s₁`, the slashings of `outA` from `s₁` and reaches `s₂`, and `out`
from `s₂`. -/
theorem packed_slashings_and_exits_valid (hfork : IsFulu fork)
    (poolP : Aeneas.Std.Slice OpP) (stillValidP : OpP → Bool)
    (headersOk : RProposerSlashing → Bool) (slashingOf : OpP → RProposerSlashing)
    (limitP : Aeneas.Std.Usize)
    (poolA : Aeneas.Std.Slice OpA) (stillValidA : OpA → Bool) (slashingOfA : OpA → Im)
    (limitA : Aeneas.Std.Usize) (label : Aeneas.Std.Str)
    (pool : Aeneas.Std.Slice Op) (stillValidE : Op → Bool) (exitOf : Op → X)
    (limit : Aeneas.Std.Usize)
    (initial : operation_pool.IndexSet)
    (toSpecP : RProposerSlashing → ProposerSlashing)
    (toSpecA : Im → AttesterSlashing preset fork)
    (indicesA : Im → Aeneas.Std.Slice Aeneas.Std.U64 × Aeneas.Std.Slice Aeneas.Std.U64)
    (message : X → RVoluntaryExit) (toSpec : X → SignedVoluntaryExit)
    (hindexP : ∀ r, slashedIndex (toSpecP r) =
      u64ToSpec r.signed_header_1.message.proposer_index)
    (hindicesA : ∀ i,
      (toSpecA i).attestation1.attestingIndices.data.toList =
        (indicesA i).1.val.map u64ToSpec ∧
      (toSpecA i).attestation2.attestingIndices.data.toList =
        (indicesA i).2.val.map u64ToSpec)
    (hmessage : ∀ x,
      (toSpec x).message.validatorIndex = u64ToSpec (message x).validator_index ∧
      (toSpec x).message.epoch = u64ToSpec (message x).epoch)
    (hkeysP : poolP.val.Pairwise fun a b =>
      (slashingOf a).signed_header_1.message.proposer_index ≠
        (slashingOf b).signed_header_1.message.proposer_index)
    (hkeys : pool.val.Pairwise fun a b =>
      (message (exitOf a)).validator_index ≠ (message (exitOf b)).validator_index)
    (hconfig : OperationsRoom preset config fork (2 ^ 58) preset.MAX_PROPOSER_SLASHINGS.toNat
      (parameters preset fork).MAX_ATTESTER_SLASHINGS.toNat preset.MAX_VOLUNTARY_EXITS.toNat)
    (hlimits : limitP.val ≤ preset.MAX_PROPOSER_SLASHINGS.toNat ∧
      limitA.val ≤ (parameters preset fork).MAX_ATTESTER_SLASHINGS.toNat ∧
      limit.val ≤ preset.MAX_VOLUNTARY_EXITS.toNat)
    {view : StateView} {s : BeaconState preset fork}
    (hcorr : StateCorr config hfork.electra view s)
    {g : ForkedBeaconState preset} (hrun : Run config checks g ⟨fork, s⟩)
    (hgenesis : Genesis config checks g)
    {p : ValidatorIndex} (hproposer : getBeaconProposerIndex s = .ok p)
    (hproposerIn : p.toNat < s.validators.data.size)
    (htime : TimeBound hfork.electra s) (hsupply : SupplyCap (2 ^ 58) s)
    (hheadersP : ∀ op ∈ poolP.val, headersOk (slashingOf op) = true →
      ProposerSlashingWellFormed (toSpecP (slashingOf op)))
    (hsignedP : ∀ op ∈ poolP.val, stillValidP op = true →
      ProposerSlashingSigned config checks s (toSpecP (slashingOf op)))
    (hchecksA : ∀ op ∈ poolA.val, stillValidA op = true →
      AttesterSlashingChecks config checks s (toSpecA (slashingOfA op)))
    (hsignedE : ∀ op ∈ pool.val, stillValidE op = true →
      ExitSigned config checks s (toSpec (exitOf op))) :
    ∃ (outP : Aeneas.Std.alloc.vec.Vec RProposerSlashing) (s₁ : BeaconState preset fork)
      (covers : Aeneas.Std.Slice (AttesterCover Im))
      (outA : Aeneas.Std.alloc.vec.Vec (AttesterCover Im)) (s₂ : BeaconState preset fork)
      (excl : operation_pool.IndexSet) (out : Aeneas.Std.alloc.vec.Vec X)
      (s₃ : BeaconState preset fork),
      operation_pool.filter_limit_operations (sliceIntoIter OpP)
        (Aeneas.Std.BuiltinFn OpP Bool) (Aeneas.Std.BuiltinFn OpP RProposerSlashing)
        (cloneId OpP) poolP (proposerSlashingFilter view stillValidP headersOk slashingOf)
        (pureFn slashingOf) limitP = Aeneas.Std.Result.ok outP ∧
      (outP.val.map toSpecP).toArray.foldlM (processProposerSlashing config checks) s =
        .ok s₁ ∧
      attesterCovers view stillValidA slashingOfA indicesA (proposerIndexSet outP.val)
        poolA.val = Aeneas.Std.Result.ok covers.val ∧
      operation_pool.max_cover.maximum_cover (sliceIntoIter (AttesterCover Im))
        (AttesterCover.maxCover Im) covers limitA label = Aeneas.Std.Result.ok outA ∧
      (outA.val.map fun c => toSpecA c.slashing).toArray.foldlM
        (processAttesterSlashing config checks) s₁ = .ok s₂ ∧
      operation_pool.exclusionSet initial (Aeneas.Std.alloc.vec.Vec.deref outP)
        (outA.val.map fun c => indicesA c.slashing) = Aeneas.Std.Result.ok excl ∧
      operation_pool.filter_limit_operations (sliceIntoIter Op)
        (Aeneas.Std.BuiltinFn Op Bool) (Aeneas.Std.BuiltinFn Op X) (cloneId Op) pool
        (voluntaryExitFilter view excl stillValidE fun op => message (exitOf op))
        (pureFn exitOf) limit = Aeneas.Std.Result.ok out ∧
      (out.val.map toSpec).toArray.foldlM (processVoluntaryExit config checks) s₂ = .ok s₃ ∧
      outP.val.length ≤ limitP.val ∧ outA.val.length ≤ limitA.val ∧
        out.val.length ≤ limit.val := by
  -- The state facts the three packing theorems take.
  have hchurn := hconfig.churn
  have hroom := hconfig.mono hlimits.1 hlimits.2.1 hlimits.2.2
  have hstate : StateRoom config (2 ^ 58) p s := StateRoom.of_bounds hconfig
    (balancesMatch_of_reachable hrun hgenesis) hproposer hproposerIn htime hsupply
  have hexits := hroom.exits_of_timeBound htime
  have hrewards := fun b (hb : getBalance s p = .ok b) => hroom.rewards_of_supplyCap hsupply hb
  -- `step` and `reward` stand for the two products, so that the bounds below are linear.
  rw [Nat.add_mul, Nat.add_mul, Nat.mul_assoc] at hexits
  simp only [Nat.add_mul, Nat.mul_assoc] at hrewards
  generalize hstep : exitStep preset (2 ^ 58) = step at hexits
  generalize hreward : rewardMax preset fork (2 ^ 58) = reward at hrewards
  -- The proposer slashings. `keepP` is what the filter computes on an entry.
  choose keepP hkeepP hkeepPiff using
    proposerSlashingFilter_spec view stillValidP headersOk slashingOf
  obtain ⟨outP, s₁, houtP, hlenP, hrunP, hframeP⟩ := packed_proposer_slashings_valid
    (checks := checks)
    (sliceIntoIter OpP) (Aeneas.Std.BuiltinFn OpP Bool)
    (Aeneas.Std.BuiltinFn OpP RProposerSlashing) (cloneId OpP) poolP
    (proposerSlashingFilter view stillValidP headersOk slashingOf) (pureFn slashingOf) limitP
    hfork hchurn rfl (operation_pool.yields_slice poolP) keepP (fun op _ => hkeepP op) slashingOf
    (fun _ _ => rfl) (fun r => r.signed_header_1.message.proposer_index) toSpecP
    (fun op _ => hindexP (slashingOf op)) hkeysP hcorr
    (fun op hop hk => by
      obtain ⟨hvalid, hheaders, hcore⟩ := (hkeepPiff op).mp hk
      exact ⟨hcore, hheadersP op hop hheaders, hsignedP op hop hvalid⟩)
    hstate (by rw [hstep]; omega) (fun b hb => by rw [hreward]; have := hrewards b hb; omega)
  rw [hstep, hreward] at hframeP
  -- The covers. `to_be_slashed` holds the proposers of the packed slashings.
  obtain ⟨coverList, hcoverList, hcoverLen, hcoverFrom⟩ := attesterCovers_spec view stillValidA
    slashingOfA indicesA (proposerIndexSet outP.val) poolA.val
  obtain ⟨covers, rfl⟩ : ∃ covers : Aeneas.Std.Slice (AttesterCover Im),
      covers.val = coverList :=
    ⟨Aeneas.Std.Slice.from coverList (Nat.le_trans hcoverLen poolA.property), by simp⟩
  -- The attester slashings.
  obtain ⟨outA, s₂, houtA, hlenA, _, hrunA, hframeA⟩ := packed_attester_slashings_valid
    (checks := checks)
    (sliceIntoIter (AttesterCover Im)) (AttesterCover.maxCover Im) covers limitA label
    hfork hchurn rfl (operation_pool.yields_slice covers) (by scalar_tac) (AttesterCover.model Im)
    toSpecA hcorr (fun u => u ∈ (proposerIndexSet outP.val).toList)
    (fun a ha u => by
      obtain ⟨op, _, _, hslashing, hcovers⟩ := hcoverFrom a ha
      show a.covers u ↔ u64ToSpec u ∈ slashingIndices (toSpecA a.slashing) ∧ _
      rw [hcovers u, hslashing, mem_slashingIndices_of_indices (hindicesA _)])
    (fun a ha => by
      obtain ⟨op, hop, hvalid, hslashing, _⟩ := hcoverFrom a ha
      show AttesterSlashingChecks config checks s (toSpecA a.slashing)
      rw [hslashing]
      exact hchecksA op hop hvalid)
    hframeP
    (fun u hS => by
      obtain ⟨ps, hps, hidx⟩ := hS
      obtain ⟨r, hr, rfl⟩ := List.mem_map.mp hps
      exact mem_proposerIndexSet.mpr ⟨r, hr, u64ToSpec_inj ((hindexP r).symm.trans hidx)⟩)
    hstate (by rw [hstep]; omega)
    (fun b hb => by rw [hreward]; have := hrewards b hb; omega)
  rw [hstep] at hframeA
  -- The exclusion set, and the exits. `keepE` is what the filter computes on an entry.
  obtain ⟨excl, hexcl⟩ := operation_pool.exclusionSet_ok initial
    (Aeneas.Std.alloc.vec.Vec.deref outP) (outA.val.map fun c => indicesA c.slashing)
  choose keepE hkeepE hkeepEiff using
    voluntaryExitFilter_spec view excl stillValidE fun op => message (exitOf op)
  obtain ⟨out, s₃, hout, hlen, hrun⟩ := packed_exits_valid_after_slashings (checks := checks)
    (sliceIntoIter Op) (Aeneas.Std.BuiltinFn Op Bool) (Aeneas.Std.BuiltinFn Op X) (cloneId Op)
    pool (voluntaryExitFilter view excl stillValidE fun op => message (exitOf op))
    (pureFn exitOf) limit hfork hchurn rfl (operation_pool.yields_slice pool) keepE
    (fun op _ => hkeepE op) exitOf (fun _ _ => rfl) message toSpec
    (fun op _ => hmessage (exitOf op)) hkeys hcorr hexcl (outP.val.map toSpecP)
    (outA.val.map fun c => toSpecA c.slashing)
    (fun ps hps => by
      -- Each spec slashing is the spec form of a packed Rust slashing, with the same proposer.
      obtain ⟨r, hr, rfl⟩ := List.mem_map.mp hps
      exact ⟨r, by simpa [Aeneas.Std.alloc.vec.Vec.deref] using hr, (hindexP r).symm⟩)
    (fun asl hasl => by
      obtain ⟨c, hc, rfl⟩ := List.mem_map.mp hasl
      exact ⟨indicesA c.slashing, List.mem_map.mpr ⟨c, hc, rfl⟩, hindicesA c.slashing⟩)
    hframeA
    (fun op hop hk => by
      obtain ⟨hnot, hvalid, hcores⟩ := (hkeepEiff op).mp hk
      exact ⟨hnot, hcores, hsignedE op hop hvalid⟩)
    hstate.toQueueRoom (by rw [hstep]; omega)
  exact ⟨outP, s₁, covers, outA, s₂, excl, out, s₃, houtP, hrunP, hcoverList, houtA, hrunA,
    hexcl, hout, hrun, hlenP, hlenA, hlen⟩

end

end OperationPool
