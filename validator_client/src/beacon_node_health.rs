use crate::beacon_node_fallback::Config;
use serde_derive::{Deserialize, Serialize};
use slot_clock::SlotClock;
use std::cmp::Ordering;
use std::fmt::{Debug, Display, Formatter};
use types::Slot;

// Sync distances between 0 and DEFAULT_SYNC_TOLERANCE are considered `synced`.
// Sync distance tiers are determined by the different modifiers.
//
// The default range is the following:
// Synced: 0..=8
// Small: 9..=16
// Medium: 17..=64
// Large: 65..
const DEFAULT_SYNC_TOLERANCE: Slot = Slot::new(8);
const DEFAULT_SMALL_SYNC_DISTANCE_MODIFIER: Slot = Slot::new(8);
const DEFAULT_MEDIUM_SYNC_DISTANCE_MODIFIER: Slot = Slot::new(48);

type HealthTier = u8;
type SyncDistance = Slot;

/// Helpful enum which is used when pattern matching to determine health tier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum SyncDistanceTier {
    Synced,
    Small,
    Medium,
    Large,
}

/// Contains the different sync distance tiers which are determined at runtime by the
/// `sync_tolerance` CLI flag and the `sync_distance_modifier` flags.
#[derive(Clone, Debug)]
pub struct BeaconNodeSyncDistanceTiers {
    synced: SyncDistance,
    small: SyncDistance,
    medium: SyncDistance,
}

impl BeaconNodeSyncDistanceTiers {
    pub fn from_config(config: &Config) -> Self {
        let synced = config
            .sync_tolerance
            .map(Slot::new)
            .unwrap_or(DEFAULT_SYNC_TOLERANCE);
        let small_mod = config
            .small_sync_distance_modifier
            .map(Slot::new)
            .unwrap_or(DEFAULT_SMALL_SYNC_DISTANCE_MODIFIER);
        let medium_mod = config
            .medium_sync_distance_modifier
            .map(Slot::new)
            .unwrap_or(DEFAULT_MEDIUM_SYNC_DISTANCE_MODIFIER);

        Self {
            synced,
            small: synced + small_mod,
            medium: synced + small_mod + medium_mod,
        }
    }

    /// Takes a given sync distance and determines its tier based on the `sync_tolerance` defined by
    /// the CLI.
    pub fn distance_tier(&self, distance: SyncDistance) -> SyncDistanceTier {
        let distance = distance.as_u64();
        // Add 1 since we are using exclusive ranges.
        let synced = self.synced.as_u64() + 1;
        let small = self.small.as_u64() + 1;
        let medium = self.medium.as_u64() + 1;

        if (0..synced).contains(&distance) {
            SyncDistanceTier::Synced
        } else if (synced..small).contains(&distance) {
            SyncDistanceTier::Small
        } else if (small..medium).contains(&distance) {
            SyncDistanceTier::Medium
        } else {
            SyncDistanceTier::Large
        }
    }
}

impl Default for BeaconNodeSyncDistanceTiers {
    fn default() -> Self {
        Self {
            synced: DEFAULT_SYNC_TOLERANCE,
            small: DEFAULT_SYNC_TOLERANCE + DEFAULT_SMALL_SYNC_DISTANCE_MODIFIER,
            medium: DEFAULT_SYNC_TOLERANCE
                + DEFAULT_SMALL_SYNC_DISTANCE_MODIFIER
                + DEFAULT_MEDIUM_SYNC_DISTANCE_MODIFIER,
        }
    }
}

/// Execution Node health metrics.
///
/// Currently only considers `el_offline`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum ExecutionEngineHealth {
    Healthy,
    Unhealthy,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum IsOptimistic {
    Yes,
    No,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct BeaconNodeHealthTier {
    pub tier: HealthTier,
    pub sync_distance: SyncDistance,
    pub distance_tier: SyncDistanceTier,
}

impl Display for BeaconNodeHealthTier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tier{}({})", self.tier, self.sync_distance)
    }
}

impl Ord for BeaconNodeHealthTier {
    fn cmp(&self, other: &Self) -> Ordering {
        let ordering = self.tier.cmp(&other.tier);
        if ordering == Ordering::Equal {
            if self.distance_tier == SyncDistanceTier::Synced {
                // Don't tie-break on sync distance in these cases.
                // This ensures validator clients don't artificially prefer one node.
                ordering
            } else {
                self.sync_distance.cmp(&other.sync_distance)
            }
        } else {
            ordering
        }
    }
}

impl PartialOrd for BeaconNodeHealthTier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl BeaconNodeHealthTier {
    pub fn new(
        tier: HealthTier,
        sync_distance: SyncDistance,
        distance_tier: SyncDistanceTier,
    ) -> Self {
        Self {
            tier,
            sync_distance,
            distance_tier,
        }
    }
}

/// Beacon Node Health metrics.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct BeaconNodeHealth {
    // The ID of the Beacon Node. This should correspond with its position in the `--beacon-nodes`
    // list. Note that the ID field is used to tie-break nodes with the same health so that nodes
    // with a lower ID are preferred.
    pub id: usize,
    // The slot number of the head.
    pub head: Slot,
    // Whether the node is optimistically synced.
    pub optimistic_status: IsOptimistic,
    // The status of the nodes connected Execution Engine.
    pub execution_status: ExecutionEngineHealth,
    // The overall health tier of the Beacon Node. Used to rank the nodes for the purposes of
    // fallbacks.
    pub health_tier: BeaconNodeHealthTier,
}

impl Ord for BeaconNodeHealth {
    fn cmp(&self, other: &Self) -> Ordering {
        let ordering = self.health_tier.cmp(&other.health_tier);
        if ordering == Ordering::Equal {
            // Tie-break node health by ID.
            self.id.cmp(&other.id)
        } else {
            ordering
        }
    }
}

impl PartialOrd for BeaconNodeHealth {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl BeaconNodeHealth {
    pub fn from_status<T: SlotClock>(
        id: usize,
        head: Slot,
        optimistic_status: IsOptimistic,
        execution_status: ExecutionEngineHealth,
        distance_tiers: &BeaconNodeSyncDistanceTiers,
        slot_clock: &T,
    ) -> Self {
        let sync_distance = BeaconNodeHealth::compute_sync_distance(head, slot_clock);
        let health_tier = BeaconNodeHealth::compute_health_tier(
            sync_distance,
            optimistic_status,
            execution_status,
            distance_tiers,
        );

        Self {
            id,
            head,
            optimistic_status,
            execution_status,
            health_tier,
        }
    }

    pub fn get_id(&self) -> usize {
        self.id
    }

    pub fn get_health_tier(&self) -> BeaconNodeHealthTier {
        self.health_tier
    }

    fn compute_sync_distance<T: SlotClock>(head: Slot, slot_clock: &T) -> SyncDistance {
        // TODO(mac) May be worth distinguishing between nodes that are ahead of the `slot_clock`.
        slot_clock
            .now()
            .map(|head_slot| head_slot.saturating_sub(head))
            .unwrap_or(Slot::max_value())
    }

    fn compute_health_tier(
        sync_distance: SyncDistance,
        optimistic_status: IsOptimistic,
        execution_status: ExecutionEngineHealth,
        sync_distance_tiers: &BeaconNodeSyncDistanceTiers,
    ) -> BeaconNodeHealthTier {
        let sync_distance_tier = sync_distance_tiers.distance_tier(sync_distance);
        let health = (sync_distance_tier, optimistic_status, execution_status);

        match health {
            (SyncDistanceTier::Synced, IsOptimistic::No, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(1, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Small, IsOptimistic::No, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(2, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Synced, IsOptimistic::No, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(3, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Medium, IsOptimistic::No, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(4, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Synced, IsOptimistic::Yes, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(5, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Synced, IsOptimistic::Yes, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(6, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Small, IsOptimistic::No, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(7, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Small, IsOptimistic::Yes, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(8, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Small, IsOptimistic::Yes, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(9, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Large, IsOptimistic::No, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(10, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Medium, IsOptimistic::No, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(11, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Medium, IsOptimistic::Yes, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(12, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Medium, IsOptimistic::Yes, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(13, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Large, IsOptimistic::No, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(14, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Large, IsOptimistic::Yes, ExecutionEngineHealth::Healthy) => {
                BeaconNodeHealthTier::new(15, sync_distance, sync_distance_tier)
            }
            (SyncDistanceTier::Large, IsOptimistic::Yes, ExecutionEngineHealth::Unhealthy) => {
                BeaconNodeHealthTier::new(16, sync_distance, sync_distance_tier)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ExecutionEngineHealth::{Healthy, Unhealthy};
    use super::{
        BeaconNodeHealth, BeaconNodeHealthTier, BeaconNodeSyncDistanceTiers, IsOptimistic,
        SyncDistanceTier,
    };
    use crate::beacon_node_fallback::Config;
    use slot_clock::{SlotClock, TestingSlotClock};
    use std::time::Duration;
    use types::Slot;

    #[test]
    fn all_possible_health_tiers() {
        let current_head = Slot::new(64);

        let config = Config::default();
        let beacon_node_sync_distance_tiers = BeaconNodeSyncDistanceTiers::from_config(&config);

        let slot_clock =
            TestingSlotClock::new(current_head, Duration::from_secs(0), Duration::from_secs(1));

        let mut health_vec = vec![];

        for head_slot in 0..=64 {
            for optimistic_status in &[IsOptimistic::No, IsOptimistic::Yes] {
                for ee_health in &[Healthy, Unhealthy] {
                    let health = BeaconNodeHealth::from_status(
                        0,
                        Slot::new(head_slot),
                        *optimistic_status,
                        *ee_health,
                        &beacon_node_sync_distance_tiers,
                        &slot_clock,
                    );
                    health_vec.push(health);
                }
            }
        }

        for health in health_vec {
            let health_tier = health.get_health_tier();
            let tier = health_tier.tier;
            let distance = health_tier.sync_distance;

            let distance_tier = beacon_node_sync_distance_tiers.distance_tier(distance);

            // Check sync distance.
            if [1, 3, 5, 6].contains(&tier) {
                assert!(distance_tier == SyncDistanceTier::Synced)
            } else if [2, 7, 8, 9].contains(&tier) {
                assert!(distance_tier == SyncDistanceTier::Small);
            } else if [4, 11, 12, 13].contains(&tier) {
                assert!(distance_tier == SyncDistanceTier::Medium);
            } else {
                assert!(distance_tier == SyncDistanceTier::Large);
            }

            // Check optimistic status.
            if [1, 2, 3, 4, 7, 10, 11, 14].contains(&tier) {
                assert_eq!(health.optimistic_status, IsOptimistic::No);
            } else {
                assert_eq!(health.optimistic_status, IsOptimistic::Yes);
            }

            // Check execution health.
            if [3, 6, 7, 9, 11, 13, 14, 16].contains(&tier) {
                assert_eq!(health.execution_status, Unhealthy);
            } else {
                assert_eq!(health.execution_status, Healthy);
            }
        }
    }

    fn new_distance_tier(
        distance: u64,
        distance_tiers: &BeaconNodeSyncDistanceTiers,
    ) -> BeaconNodeHealthTier {
        BeaconNodeHealth::compute_health_tier(
            Slot::new(distance),
            IsOptimistic::No,
            Healthy,
            distance_tiers,
        )
    }

    #[test]
    fn sync_tolerance_default() {
        let distance_tiers = BeaconNodeSyncDistanceTiers::default();

        let synced_low = new_distance_tier(0, &distance_tiers);
        let synced_high = new_distance_tier(8, &distance_tiers);

        let small_low = new_distance_tier(9, &distance_tiers);
        let small_high = new_distance_tier(16, &distance_tiers);

        let medium_low = new_distance_tier(17, &distance_tiers);
        let medium_high = new_distance_tier(64, &distance_tiers);
        let large = new_distance_tier(65, &distance_tiers);

        assert!(synced_low.tier == 1);
        assert!(synced_high.tier == 1);
        assert!(small_low.tier == 2);
        assert!(small_high.tier == 2);
        assert!(medium_low.tier == 4);
        assert_eq!(medium_high.tier, 4);
        assert!(large.tier == 10);
    }

    #[test]
    fn sync_tolerance_from_config() {
        // Config should set the tiers as:
        // synced: 0..=4
        // small: 5..=8
        // medium 9..=12
        // large: 13..
        let config = Config {
            disable_run_on_all: false,
            sync_tolerance: Some(4),
            small_sync_distance_modifier: Some(4),
            medium_sync_distance_modifier: Some(4),
        };
        let distance_tiers = BeaconNodeSyncDistanceTiers::from_config(&config);

        let synced_low = new_distance_tier(0, &distance_tiers);
        let synced_high = new_distance_tier(4, &distance_tiers);

        let small_low = new_distance_tier(5, &distance_tiers);
        let small_high = new_distance_tier(8, &distance_tiers);

        let medium_low = new_distance_tier(9, &distance_tiers);
        let medium_high = new_distance_tier(12, &distance_tiers);

        let large = new_distance_tier(13, &distance_tiers);

        assert!(synced_low.tier == 1);
        assert!(synced_high.tier == 1);
        assert!(small_low.tier == 2);
        assert!(small_high.tier == 2);
        assert!(medium_low.tier == 4);
        assert_eq!(medium_high.tier, 4);
        assert!(large.tier == 10);
    }
}
