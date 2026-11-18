import OperationPool.PackedProposerSlashingsValid
import OperationPool.PackedExitsValid

/-!
# The packed proposer slashings and voluntary exits are valid together

`OperationPool::get_slashings_and_exits` packs the proposer slashings, the attester slashings
and the voluntary exits of one block. `process_operations` applies them in that order.

`packed_exits_valid_after_slashings` takes the run of the proposer slashings as a hypothesis.
`packed_proposer_slashings_valid` proves that run. The theorems here join the two, so the run
of the proposer slashings is a conclusion.

* `packed_exits_valid_after_packed_proposer_slashings`: the packed proposer slashings succeed
  from the packing state `s`. After them, if the spec processes the packed attester slashings,
  the packed exits succeed. The run of the attester slashings stays a hypothesis.
* `packed_proposer_slashings_and_exits_valid`: the case of a block with no attester slashings.
  No hypothesis is a run of the spec, and every hypothesis about the state is about the packing
  state `s`.

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

end

end OperationPool
