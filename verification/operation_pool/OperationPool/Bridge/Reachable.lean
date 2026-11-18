import EthCLSpecs.Proofs.Fulu.ReachableInvariants

/-!
# What reachability gives the packing theorems

The packing theorems take one hypothesis that Etheorem proves for every reachable state: the
balances have the registry's length. `balances_size_of_reachable` reads it off
`ReachableState.simpleStateInvariants`.

`ReachableState anchors validated nextForkEpoch s` says that `s` is reached from an anchor state
by `process_slots` and `process_block` steps. The premise `hA` asks that each anchor satisfies
`SimpleStateInvariants`.
-/

namespace OperationPool.Bridge

open EthCLLib.Spec (HasherTag CryptoBackend)
open EthCLSpecs.Fulu
open EthCLSpecs.Proofs.Fulu

variable [Preset] [HasherTag] [Config] [CryptoBackend]

/-- The balances of a reachable state have the registry's length. This is the hypothesis `hsize`
of the packing theorems for proposer slashings. -/
theorem balances_size_of_reachable {anchors : Anchors} {validated : Bool} {nextForkEpoch : Epoch}
    (hA : ∀ u, anchors.fulu u → SimpleStateInvariants u) {s : BeaconState}
    (h : ReachableState anchors validated nextForkEpoch s) :
    s.balances.val.size = s.validators.val.size :=
  (h.simpleStateInvariants hA).registrySizes.1

end OperationPool.Bridge
