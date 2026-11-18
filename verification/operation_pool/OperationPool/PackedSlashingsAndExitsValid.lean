import OperationPool.PackedProposerSlashingsValid
import OperationPool.PackedAttesterSlashingsValid
import OperationPool.PackedExitsValid

/-!
# The packed slashings and voluntary exits of a block are valid together

`OperationPool::get_slashings_and_exits` packs the proposer slashings, the attester slashings
and the voluntary exits of one block. `process_operations` applies them in that order, and each
operation changes the state the next one reads.

`packed_slashings_and_exits_valid` is the main theorem of this project. The spec processes the
packed proposer slashings from the packing state `s`, then the packed attester slashings, then
the packed voluntary exits, and no step fails. No hypothesis is a run of the spec, and every
hypothesis about the state is about `s`.

The theorem joins the three packing proofs:

* `packed_proposer_slashings_valid_uniform`: the proposer slashings succeed from `s`.
* `packed_attester_slashings_valid_uniform`: the attester slashings succeed after them.
* `packed_exits_valid_after_slashings_uniform`: the exits succeed after both.

Two older theorems stay, for callers that have a run of the attester slashings from another
source:

* `packed_exits_valid_after_packed_proposer_slashings`: the packed proposer slashings succeed
  from `s`. After them, if the spec processes the attester slashings, the packed exits succeed.
* `packed_proposer_slashings_and_exits_valid`: the case of a block with no attester slashings.

The hypotheses that are not proved from extracted code are the trusted base. `README.md` lists
them.
-/

namespace OperationPool

open EthCLLib.Spec (HasherTag CryptoBackend)
open EthCLLib.Proofs (runPure)
open EthCLSpecs.Fulu
open EthCLSpecs.Proofs.Fulu
open OperationPool.Bridge

/-- The Rust `ProposerSlashing`, as the extraction of the `operation_pool` crate names it. -/
abbrev RProposerSlashing : Type :=
  operation_pool.types.slashing.proposer_slashing.ProposerSlashing

section

variable [Preset] [Config] [HasherTag] [CryptoBackend] [PresetValid] [ConfigValid]

-- The call of `filter_limit_operations` that packs the proposer slashings.
variable {OpP IP FP GP ItP : Type}
  (iterInstP : Aeneas.Std.core.iter.traits.collect.IntoIterator IP OpP ItP)
  (filterInstP : Aeneas.Std.core.ops.function.Fn FP OpP Bool)
  (mappingInstP : Aeneas.Std.core.ops.function.Fn GP OpP RProposerSlashing)
  (cloneInstP : Aeneas.Std.core.clone.Clone OpP)
  (operationsP : IP) (filterP : FP) (mappingP : GP) (limitP : Aeneas.Std.Usize)

-- The call of `maximum_cover` that packs the attester slashings.
variable {T Obj Im Set IA ItA : Type}
  (iterInstA : Aeneas.Std.core.iter.traits.collect.IntoIterator IA T ItA)
  (instA : operation_pool.max_cover.MaxCover T Obj Im Set)
  (itemsA : IA) (limitA : Aeneas.Std.Usize) (label : Aeneas.Std.Str)

-- The call of `filter_limit_operations` that packs the voluntary exits.
variable {Op X I F G It : Type}
  (iterInst : Aeneas.Std.core.iter.traits.collect.IntoIterator I Op It)
  (filterInst : Aeneas.Std.core.ops.function.Fn F Op Bool)
  (mappingInst : Aeneas.Std.core.ops.function.Fn G Op X)
  (cloneInst : Aeneas.Std.core.clone.Clone Op)
  (operations : I) (filter : F) (mapping : G) (limit : Aeneas.Std.Usize)

/-- The packed proposer slashings succeed from the packing state `s`, and the packed voluntary
exits succeed after the packed slashings of the same block.

The hypotheses with a `P` are those of `packed_proposer_slashings_valid_uniform`, for the call
that packs the proposer slashings. The others are those of `packed_exits_valid`, for the call
that packs the exits. Both calls read the same view of the same state.

The conclusion has two parts. First, the call for the proposer slashings returns `outP`, and the
spec processes `outP` from `s` and reaches `s₁`. Second, take the exclusion set `excl` that
`get_slashings_and_exits` builds from `outP` and the packed attester slashings. If the spec
processes the attester slashings from `s₁` and reaches `s₂`, the exit filter rejects the
validators in `excl`, and the exit queue of `s₂` has room, then the call for the exits returns
`out`, and the spec processes `out` from `s₂`. -/
theorem packed_exits_valid_after_packed_proposer_slashings
    {itP : ItP} {poolP : List OpP}
    (hintoP : iterInstP.into_iter operationsP = Aeneas.Std.Result.ok itP)
    (hyieldsP : operation_pool.Yields iterInstP.iteratorInst itP poolP)
    (keepP : OpP → Bool)
    (hfilterP : ∀ op ∈ poolP, filterInstP.call filterP op = Aeneas.Std.Result.ok (keepP op))
    (slashingOf : OpP → RProposerSlashing)
    (hmappingP : ∀ op ∈ poolP,
      mappingInstP.call mappingP op = Aeneas.Std.Result.ok (slashingOf op))
    (toSpecP : RProposerSlashing → ProposerSlashing)
    (hindexP : ∀ op ∈ poolP, slashedIndex (toSpecP (slashingOf op)) =
      u64ToSpec (slashingOf op).signed_header_1.message.proposer_index)
    (hkeysP : poolP.Pairwise fun a b =>
      (slashingOf a).signed_header_1.message.proposer_index ≠
        (slashingOf b).signed_header_1.message.proposer_index)
    {view : StateView} {s : BeaconState} (hcorr : StateCorr view s)
    (hkeepP : ∀ op ∈ poolP, keepP op = true →
      ProposerCoreOk view (slashingOf op).signed_header_1.message.proposer_index ∧
      ProposerSlashingWellFormed (toSpecP (slashingOf op)) ∧
      ProposerSlashingSigned s (toSpecP (slashingOf op)))
    (hsize : s.balances.val.size = s.validators.val.size)
    (hproposer : (blockProposer s).toNat < s.validators.val.size)
    (hexitsP : exitStart s + limitP.val * exitStep (2 ^ 64 - 1) +
      Const.minValidatorWithdrawabilityDelay.toNat < 2 ^ 64)
    (hrewardsP : (s.balances[(blockProposer s).toNat]!).toNat + limitP.val * ((2 ^ 64 - 1) /
      (UInt64.ofNat Const.whistleblowerRewardQuotientElectra).toNat) < 2 ^ 64)
    {it : It} {pool : List Op}
    (hinto : iterInst.into_iter operations = Aeneas.Std.Result.ok it)
    (hyields : operation_pool.Yields iterInst.iteratorInst it pool)
    (keep : Op → Bool)
    (hfilter : ∀ op ∈ pool, filterInst.call filter op = Aeneas.Std.Result.ok (keep op))
    (exitOf : Op → X)
    (hmapping : ∀ op ∈ pool, mappingInst.call mapping op = Aeneas.Std.Result.ok (exitOf op))
    (message : X → RVoluntaryExit) (toSpec : X → SignedVoluntaryExit)
    (hmessage : ∀ op ∈ pool,
      (toSpec (exitOf op)).message.validatorIndex = u64ToSpec (message (exitOf op)).validator_index ∧
      (toSpec (exitOf op)).message.epoch = u64ToSpec (message (exitOf op)).epoch)
    (hkeys : pool.Pairwise fun a b =>
      (message (exitOf a)).validator_index ≠ (message (exitOf b)).validator_index) :
    ∃ outP s₁,
      operation_pool.filter_limit_operations iterInstP filterInstP mappingInstP cloneInstP
        operationsP filterP mappingP limitP = Aeneas.Std.Result.ok outP ∧
      outP.val.length ≤ limitP.val ∧
      runPure (processProposerSlashings (outP.val.map toSpecP).toArray) s = .ok ((), s₁) ∧
      exitStart s₁ ≤ exitStart s + limitP.val * exitStep (2 ^ 64 - 1) ∧
      ∀ (rustProposerSlashings : Aeneas.Std.Slice RProposerSlashing)
        (initial excl : operation_pool.IndexSet)
        (rustAttesterIndices : List (Aeneas.Std.Slice Aeneas.Std.U64 × Aeneas.Std.Slice Aeneas.Std.U64))
        (attesterSlashings : Array AttesterSlashing) (s₂ : BeaconState),
        rustProposerSlashings.val = outP.val →
        operation_pool.exclusionSet initial rustProposerSlashings rustAttesterIndices =
          Aeneas.Std.Result.ok excl →
        (∀ asl ∈ attesterSlashings, ∃ p ∈ rustAttesterIndices,
          asl.attestation1.attestingIndices.toArray.toList = p.1.val.map u64ToSpec ∧
          asl.attestation2.attestingIndices.toArray.toList = p.2.val.map u64ToSpec) →
        runPure (ForM.forM attesterSlashings
          (processAttesterSlashing (StateTransition := FuluRun))) s₁ = .ok ((), s₂) →
        (∀ op ∈ pool, keep op = true →
          (message (exitOf op)).validator_index ∉ excl.toList ∧
          CoresOk view (message (exitOf op)) ∧
          ExitSigned s (toSpec (exitOf op))) →
        exitStart s₂ + limit.val * exitStep (2 ^ 64 - 1) +
          Const.minValidatorWithdrawabilityDelay.toNat < 2 ^ 64 →
        ∃ out s₃, operation_pool.filter_limit_operations iterInst filterInst mappingInst cloneInst
            operations filter mapping limit = Aeneas.Std.Result.ok out ∧
          out.val.length ≤ limit.val ∧
          runPure (processVoluntaryExits (out.val.map toSpec).toArray) s₂ = .ok ((), s₃) := by
  obtain ⟨outP, s₁, houtP, hlenP, hrunP, hframe⟩ := packed_proposer_slashings_valid_uniform
    iterInstP filterInstP mappingInstP cloneInstP operationsP filterP mappingP limitP hintoP
    hyieldsP keepP hfilterP slashingOf hmappingP
    (fun r => r.signed_header_1.message.proposer_index) toSpecP hindexP hkeysP hcorr hkeepP hsize
    hproposer hexitsP hrewardsP
  -- The packed slashings are the mapped pool entries, so each has the index its spec form has.
  obtain ⟨outP', houtP', hvalP⟩ := operation_pool.filter_limit_operations_eq iterInstP
    filterInstP mappingInstP filterP mappingP limitP cloneInstP operationsP hintoP hyieldsP keepP
    hfilterP slashingOf hmappingP
  have houtEq : outP' = outP := by
    have := houtP'.symm.trans houtP
    simpa using this
  subst houtEq
  have hstart : exitStart s₁ ≤ exitStart s + limitP.val * exitStep (2 ^ 64 - 1) := by
    have h1 := hframe.start
    have h2 := slashExitSteps_le s (outP'.val.map toSpecP)
    have h3 : (outP'.val.map toSpecP).length * exitStep (2 ^ 64 - 1) ≤
        limitP.val * exitStep (2 ^ 64 - 1) :=
      Nat.mul_le_mul_right _ (by simpa using hlenP)
    omega
  refine ⟨outP', s₁, houtP, hlenP, hrunP, hstart, ?_⟩
  intro rustProposerSlashings initial excl rustAttesterIndices attesterSlashings s₂ hslice hexcl
    hattesters hslash₂ hkeep hroom
  refine packed_exits_valid_after_slashings_uniform iterInst filterInst mappingInst cloneInst
    operations filter mapping limit hinto hyields keep hfilter exitOf hmapping message toSpec
    hmessage hkeys hcorr hexcl (outP'.val.map toSpecP).toArray attesterSlashings ?_ hattesters
    hrunP hslash₂ hkeep hroom
  -- Each spec slashing is the spec form of a packed Rust slashing, with the same proposer.
  intro ps hps
  obtain ⟨r, hr, rfl⟩ := List.mem_map.mp (List.mem_toArray.mp hps)
  refine ⟨r, hslice ▸ hr, ?_⟩
  rw [hvalP] at hr
  obtain ⟨op, hop, rfl⟩ := List.mem_map.mp hr
  exact (hindexP op (List.mem_filter.mp (List.mem_of_mem_take hop)).1).symm

/-- The packed proposer slashings and the packed voluntary exits of a block with no attester
slashings are valid: the spec processes the slashings from the packing state `s`, and then the
exits.

No hypothesis is a run of the spec. Every hypothesis about the state is about `s`: the
correspondence `hcorr`, the list lengths `hsize`, the proposer `hproposer`, and the two room
bounds. `hexits` gives the exit queue room for the slashings and the exits together. -/
theorem packed_proposer_slashings_and_exits_valid
    {itP : ItP} {poolP : List OpP}
    (hintoP : iterInstP.into_iter operationsP = Aeneas.Std.Result.ok itP)
    (hyieldsP : operation_pool.Yields iterInstP.iteratorInst itP poolP)
    (keepP : OpP → Bool)
    (hfilterP : ∀ op ∈ poolP, filterInstP.call filterP op = Aeneas.Std.Result.ok (keepP op))
    (slashingOf : OpP → RProposerSlashing)
    (hmappingP : ∀ op ∈ poolP,
      mappingInstP.call mappingP op = Aeneas.Std.Result.ok (slashingOf op))
    (toSpecP : RProposerSlashing → ProposerSlashing)
    (hindexP : ∀ op ∈ poolP, slashedIndex (toSpecP (slashingOf op)) =
      u64ToSpec (slashingOf op).signed_header_1.message.proposer_index)
    (hkeysP : poolP.Pairwise fun a b =>
      (slashingOf a).signed_header_1.message.proposer_index ≠
        (slashingOf b).signed_header_1.message.proposer_index)
    {view : StateView} {s : BeaconState} (hcorr : StateCorr view s)
    (hkeepP : ∀ op ∈ poolP, keepP op = true →
      ProposerCoreOk view (slashingOf op).signed_header_1.message.proposer_index ∧
      ProposerSlashingWellFormed (toSpecP (slashingOf op)) ∧
      ProposerSlashingSigned s (toSpecP (slashingOf op)))
    (hsize : s.balances.val.size = s.validators.val.size)
    (hproposer : (blockProposer s).toNat < s.validators.val.size)
    (hexits : exitStart s + (limitP.val + limit.val) * exitStep (2 ^ 64 - 1) +
      Const.minValidatorWithdrawabilityDelay.toNat < 2 ^ 64)
    (hrewardsP : (s.balances[(blockProposer s).toNat]!).toNat + limitP.val * ((2 ^ 64 - 1) /
      (UInt64.ofNat Const.whistleblowerRewardQuotientElectra).toNat) < 2 ^ 64)
    {it : It} {pool : List Op}
    (hinto : iterInst.into_iter operations = Aeneas.Std.Result.ok it)
    (hyields : operation_pool.Yields iterInst.iteratorInst it pool)
    (keep : Op → Bool)
    (hfilter : ∀ op ∈ pool, filterInst.call filter op = Aeneas.Std.Result.ok (keep op))
    (exitOf : Op → X)
    (hmapping : ∀ op ∈ pool, mappingInst.call mapping op = Aeneas.Std.Result.ok (exitOf op))
    (message : X → RVoluntaryExit) (toSpec : X → SignedVoluntaryExit)
    (hmessage : ∀ op ∈ pool,
      (toSpec (exitOf op)).message.validatorIndex = u64ToSpec (message (exitOf op)).validator_index ∧
      (toSpec (exitOf op)).message.epoch = u64ToSpec (message (exitOf op)).epoch)
    (hkeys : pool.Pairwise fun a b =>
      (message (exitOf a)).validator_index ≠ (message (exitOf b)).validator_index) :
    ∃ outP s₁,
      operation_pool.filter_limit_operations iterInstP filterInstP mappingInstP cloneInstP
        operationsP filterP mappingP limitP = Aeneas.Std.Result.ok outP ∧
      outP.val.length ≤ limitP.val ∧
      runPure (processProposerSlashings (outP.val.map toSpecP).toArray) s = .ok ((), s₁) ∧
      ∀ (rustProposerSlashings : Aeneas.Std.Slice RProposerSlashing)
        (initial excl : operation_pool.IndexSet),
        rustProposerSlashings.val = outP.val →
        operation_pool.exclusionSet initial rustProposerSlashings [] =
          Aeneas.Std.Result.ok excl →
        (∀ op ∈ pool, keep op = true →
          (message (exitOf op)).validator_index ∉ excl.toList ∧
          CoresOk view (message (exitOf op)) ∧
          ExitSigned s (toSpec (exitOf op))) →
        ∃ out s₃, operation_pool.filter_limit_operations iterInst filterInst mappingInst cloneInst
            operations filter mapping limit = Aeneas.Std.Result.ok out ∧
          out.val.length ≤ limit.val ∧
          runPure (processVoluntaryExits (out.val.map toSpec).toArray) s₁ = .ok ((), s₃) := by
  have hmul : (limitP.val + limit.val) * exitStep (2 ^ 64 - 1) =
      limitP.val * exitStep (2 ^ 64 - 1) + limit.val * exitStep (2 ^ 64 - 1) := Nat.add_mul _ _ _
  obtain ⟨outP, s₁, houtP, hlenP, hrunP, hstart, hrest⟩ :=
    packed_exits_valid_after_packed_proposer_slashings iterInstP filterInstP mappingInstP
      cloneInstP operationsP filterP mappingP limitP iterInst filterInst mappingInst cloneInst
      operations filter mapping limit hintoP hyieldsP keepP hfilterP slashingOf hmappingP toSpecP
      hindexP hkeysP hcorr hkeepP hsize hproposer (by omega) hrewardsP hinto hyields keep hfilter
      exitOf hmapping message toSpec hmessage hkeys
  refine ⟨outP, s₁, houtP, hlenP, hrunP, ?_⟩
  intro rustProposerSlashings initial excl hslice hexcl hkeep
  -- A block with no attester slashings: the fold over them leaves the state as it is.
  refine hrest rustProposerSlashings initial excl [] #[] s₁ hslice hexcl (by simp) ?_ hkeep
    (by omega)
  exact EthCLLib.Proofs.runPure_pure _ _

/-- The packed proposer slashings, attester slashings and voluntary exits of a block are valid:
the spec processes them in that order from the packing state `s`, and no step fails.

The hypotheses with a `P` are those of `packed_proposer_slashings_valid_uniform`, for the call of
`filter_limit_operations` that packs the proposer slashings. Those with an `A` are those of
`packed_attester_slashings_valid_uniform`, for the call of `maximum_cover`. The others are those
of `packed_exits_valid`, for the call that packs the exits. The three calls read the same view
of the same state.

Every hypothesis about the state is about `s`:

* `hcorr`: the state Lighthouse reads corresponds to `s`.
* `hsize`: the balances have the registry's length. Every reachable state has this.
* `hproposer`: the proposer of the slot is in the registry.
* `hcap`: `B` bounds the effective balance of every validator.
* `hexits`: the exit queue has room for one exit of each validator the operations can exit.
* `hrewards`: the block proposer's balance has room for each whistleblower reward.

The conclusion follows the order of `get_slashings_and_exits`. Each call reads what the calls
before it returned, so the hypotheses that name an earlier result come after that result:

1. The call for the proposer slashings returns `outP`, and the spec processes `outP` from `s`
   and reaches `s₁`.
2. `hcoverA` states what each `AttesterSlashingMaxCover` covers, given that `to_be_slashed`
   holds the proposers of `outP`. Then `maximum_cover` returns `outA`, and the spec processes
   the slashings of `outA` from `s₁` and reaches `s₂`.
3. Take the exclusion set `excl` that `get_slashings_and_exits` builds from `outP` and `outA`.
   If the exit filter rejects the validators in `excl`, the call for the exits returns `out`,
   and the spec processes `out` from `s₂`. -/
theorem packed_slashings_and_exits_valid
    {itP : ItP} {poolP : List OpP}
    (hintoP : iterInstP.into_iter operationsP = Aeneas.Std.Result.ok itP)
    (hyieldsP : operation_pool.Yields iterInstP.iteratorInst itP poolP)
    (keepP : OpP → Bool)
    (hfilterP : ∀ op ∈ poolP, filterInstP.call filterP op = Aeneas.Std.Result.ok (keepP op))
    (slashingOf : OpP → RProposerSlashing)
    (hmappingP : ∀ op ∈ poolP,
      mappingInstP.call mappingP op = Aeneas.Std.Result.ok (slashingOf op))
    (toSpecP : RProposerSlashing → ProposerSlashing)
    (hindexP : ∀ op ∈ poolP, slashedIndex (toSpecP (slashingOf op)) =
      u64ToSpec (slashingOf op).signed_header_1.message.proposer_index)
    (hkeysP : poolP.Pairwise fun a b =>
      (slashingOf a).signed_header_1.message.proposer_index ≠
        (slashingOf b).signed_header_1.message.proposer_index)
    {view : StateView} {s : BeaconState} (hcorr : StateCorr view s)
    (hkeepP : ∀ op ∈ poolP, keepP op = true →
      ProposerCoreOk view (slashingOf op).signed_header_1.message.proposer_index ∧
      ProposerSlashingWellFormed (toSpecP (slashingOf op)) ∧
      ProposerSlashingSigned s (toSpecP (slashingOf op)))
    (hsize : s.balances.val.size = s.validators.val.size)
    (hproposer : (blockProposer s).toNat < s.validators.val.size)
    {B : Nat} (hcap : ∀ x ∈ s.validators.val, x.effectiveBalance.toNat ≤ B)
    (hexits : exitStart s + (limitP.val +
        limitA.val * (Const.maxValidatorsPerCommittee * Const.maxCommitteesPerSlot) +
        limit.val) * exitStep (2 ^ 64 - 1) +
      Const.minValidatorWithdrawabilityDelay.toNat < 2 ^ 64)
    (hrewards : (s.balances[(blockProposer s).toNat]!).toNat +
      limitP.val * ((2 ^ 64 - 1) / (UInt64.ofNat Const.whistleblowerRewardQuotientElectra).toNat) +
      limitA.val * (Const.maxValidatorsPerCommittee * Const.maxCommitteesPerSlot *
        (B / (UInt64.ofNat Const.whistleblowerRewardQuotientElectra).toNat)) < 2 ^ 64)
    {itA : ItA} {covers : List T}
    (hintoA : iterInstA.into_iter itemsA = Aeneas.Std.Result.ok itA)
    (hyieldsA : operation_pool.Yields iterInstA.iteratorInst itA covers)
    (hlenA : covers.length ≤ Aeneas.Std.Usize.max)
    (m : operation_pool.MaxCoverModel instA Aeneas.Std.U64)
    (toSpecA : Im → AttesterSlashing)
    (hchecksA : ∀ a ∈ covers, AttesterSlashingChecks s (toSpecA (m.im a)))
    {it : It} {pool : List Op}
    (hinto : iterInst.into_iter operations = Aeneas.Std.Result.ok it)
    (hyields : operation_pool.Yields iterInst.iteratorInst it pool)
    (keep : Op → Bool)
    (hfilter : ∀ op ∈ pool, filterInst.call filter op = Aeneas.Std.Result.ok (keep op))
    (exitOf : Op → X)
    (hmapping : ∀ op ∈ pool, mappingInst.call mapping op = Aeneas.Std.Result.ok (exitOf op))
    (message : X → RVoluntaryExit) (toSpec : X → SignedVoluntaryExit)
    (hmessage : ∀ op ∈ pool,
      (toSpec (exitOf op)).message.validatorIndex = u64ToSpec (message (exitOf op)).validator_index ∧
      (toSpec (exitOf op)).message.epoch = u64ToSpec (message (exitOf op)).epoch)
    (hkeys : pool.Pairwise fun a b =>
      (message (exitOf a)).validator_index ≠ (message (exitOf b)).validator_index) :
    ∃ outP s₁,
      operation_pool.filter_limit_operations iterInstP filterInstP mappingInstP cloneInstP
        operationsP filterP mappingP limitP = Aeneas.Std.Result.ok outP ∧
      outP.val.length ≤ limitP.val ∧
      runPure (processProposerSlashings (outP.val.map toSpecP).toArray) s = .ok ((), s₁) ∧
      ((∀ a ∈ covers, ∀ u, m.cov a u ↔
          u64ToSpec u ∈ attesterSlashingIndices (toSpecA (m.im a)) ∧ SlashableOn view u ∧
            ¬ ∃ r ∈ outP.val, r.signed_header_1.message.proposer_index = u) →
        ∃ outA s₂,
          operation_pool.max_cover.maximum_cover iterInstA instA itemsA limitA label =
            Aeneas.Std.Result.ok outA ∧
          outA.val.length ≤ limitA.val ∧
          runPure (processAttesterSlashings
            (outA.val.map fun t => toSpecA (m.im t)).toArray) s₁ = .ok ((), s₂) ∧
          ∀ (rustProposerSlashings : Aeneas.Std.Slice RProposerSlashing)
            (initial excl : operation_pool.IndexSet)
            (rustAttesterIndices :
              List (Aeneas.Std.Slice Aeneas.Std.U64 × Aeneas.Std.Slice Aeneas.Std.U64)),
            rustProposerSlashings.val = outP.val →
            operation_pool.exclusionSet initial rustProposerSlashings rustAttesterIndices =
              Aeneas.Std.Result.ok excl →
            (∀ t ∈ outA.val, ∃ p ∈ rustAttesterIndices,
              (toSpecA (m.im t)).attestation1.attestingIndices.toArray.toList =
                p.1.val.map u64ToSpec ∧
              (toSpecA (m.im t)).attestation2.attestingIndices.toArray.toList =
                p.2.val.map u64ToSpec) →
            (∀ op ∈ pool, keep op = true →
              (message (exitOf op)).validator_index ∉ excl.toList ∧
              CoresOk view (message (exitOf op)) ∧
              ExitSigned s (toSpec (exitOf op))) →
            ∃ out s₃,
              operation_pool.filter_limit_operations iterInst filterInst mappingInst cloneInst
                operations filter mapping limit = Aeneas.Std.Result.ok out ∧
              out.val.length ≤ limit.val ∧
              runPure (processVoluntaryExits (out.val.map toSpec).toArray) s₂ =
                .ok ((), s₃)) := by
  -- The exit queue bound, split between the three kinds of operation.
  have hmul : (limitP.val +
      limitA.val * (Const.maxValidatorsPerCommittee * Const.maxCommitteesPerSlot) + limit.val) *
        exitStep (2 ^ 64 - 1) =
      limitP.val * exitStep (2 ^ 64 - 1) +
        limitA.val * (Const.maxValidatorsPerCommittee * Const.maxCommitteesPerSlot *
          exitStep (2 ^ 64 - 1)) +
        limit.val * exitStep (2 ^ 64 - 1) := by
    rw [Nat.add_mul, Nat.add_mul, Nat.mul_assoc]
  obtain ⟨outP, s₁, houtP, hlenP, hrunP, hframeP⟩ := packed_proposer_slashings_valid_uniform
    iterInstP filterInstP mappingInstP cloneInstP operationsP filterP mappingP limitP hintoP
    hyieldsP keepP hfilterP slashingOf hmappingP
    (fun r => r.signed_header_1.message.proposer_index) toSpecP hindexP hkeysP hcorr hkeepP hsize
    hproposer (by omega) (by omega)
  -- The packed slashings are the mapped pool entries, so each has the index its spec form has.
  obtain ⟨outP', houtP', hvalP⟩ := operation_pool.filter_limit_operations_eq iterInstP
    filterInstP mappingInstP filterP mappingP limitP cloneInstP operationsP hintoP hyieldsP keepP
    hfilterP slashingOf hmappingP
  have houtEq : outP' = outP := by
    have := houtP'.symm.trans houtP
    simpa using this
  subst houtEq
  have hindexOut : ∀ r ∈ outP'.val, slashedIndex (toSpecP r) =
      u64ToSpec r.signed_header_1.message.proposer_index := by
    intro r hr
    rw [hvalP] at hr
    obtain ⟨op, hop, rfl⟩ := List.mem_map.mp hr
    exact hindexP op (List.mem_filter.mp (List.mem_of_mem_take hop)).1
  refine ⟨outP', s₁, houtP, hlenP, hrunP, ?_⟩
  intro hcoverA
  -- The frame of the proposer slashings, with the bounds for `limitP` slashings.
  have hlenP' : (outP'.val.map toSpecP).length ≤ limitP.val := by simpa using hlenP
  have hframeP' := hframeP.mono (fun _ h => h)
    (Nat.le_trans (slashExitSteps_le s (outP'.val.map toSpecP))
      (Nat.mul_le_mul_right (exitStep (2 ^ 64 - 1)) hlenP'))
    (Nat.le_trans (slashRewards_le s (outP'.val.map toSpecP))
      (Nat.mul_le_mul_right _ hlenP'))
  obtain ⟨outA, s₂, houtA, hlenA', _, hrunA, hframeA⟩ := packed_attester_slashings_valid_uniform
    iterInstA instA itemsA limitA label hintoA hyieldsA hlenA m toSpecA hcorr
    (fun u => ∃ r ∈ outP'.val, r.signed_header_1.message.proposer_index = u) hcoverA hchecksA
    hframeP'
    (fun u hS => by
      obtain ⟨ps, hps, hidx⟩ := hS
      obtain ⟨r, hr, rfl⟩ := List.mem_map.mp hps
      exact ⟨r, hr, u64ToSpec_inj ((hindexOut r hr).symm.trans hidx)⟩)
    hsize hproposer hcap (by omega) (by omega)
  refine ⟨outA, s₂, houtA, hlenA', hrunA, ?_⟩
  intro rustProposerSlashings initial excl rustAttesterIndices hslice hexcl hattesters hkeep
  have hstart := hframeA.start
  refine packed_exits_valid_after_slashings_uniform iterInst filterInst mappingInst cloneInst
    operations filter mapping limit hinto hyields keep hfilter exitOf hmapping message toSpec
    hmessage hkeys hcorr hexcl (outP'.val.map toSpecP).toArray
    (outA.val.map fun t => toSpecA (m.im t)).toArray ?_ ?_ hrunP hrunA hkeep (by omega)
  · -- Each spec slashing is the spec form of a packed Rust slashing, with the same proposer.
    intro ps hps
    obtain ⟨r, hr, rfl⟩ := List.mem_map.mp (List.mem_toArray.mp hps)
    exact ⟨r, hslice ▸ hr, (hindexOut r hr).symm⟩
  · intro asl hasl
    obtain ⟨t, ht, rfl⟩ := List.mem_map.mp (List.mem_toArray.mp hasl)
    exact hattesters t ht

end

end OperationPool
