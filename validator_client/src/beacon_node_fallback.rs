//! Allows for a list of `BeaconNodeHttpClient` to appear as a single entity which will exhibits
//! "fallback" behaviour; it will try a request on all of the nodes until one or none of them
//! succeed.

use crate::beacon_node_health::{
    BeaconNodeHealth, BeaconNodeSyncDistanceTiers, ExecutionEngineHealth, IsOptimistic,
    SyncDistanceTier,
};
use crate::check_synced::check_node_health;
use crate::http_metrics::metrics::{inc_counter_vec, ENDPOINT_ERRORS, ENDPOINT_REQUESTS};
use environment::RuntimeContext;
use eth2::BeaconNodeHttpClient;
use futures::future;
use parking_lot::RwLock as PLRwLock;
use serde::{Deserialize, Serialize};
use slog::{debug, error, warn, Logger};
use slot_clock::SlotClock;
use std::cmp::Ordering;
use std::fmt;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};
use strum::{EnumString, EnumVariantNames};
use tokio::{sync::RwLock, time::sleep};
use types::{ChainSpec, Config as ConfigSpec, EthSpec, Slot};

/// Message emitted when the VC detects the BN is using a different spec.
const UPDATE_REQUIRED_LOG_HINT: &str = "this VC or the remote BN may need updating";

/// The number of seconds *prior* to slot start that we will try and update the state of fallback
/// nodes.
///
/// Ideally this should be somewhere between 2/3rds through the slot and the end of it. If we set it
/// too early, we risk switching nodes between the time of publishing an attestation and publishing
/// an aggregate; this may result in a missed aggregation. If we set this time too late, we risk not
/// having the correct nodes up and running prior to the start of the slot.
const SLOT_LOOKAHEAD: Duration = Duration::from_secs(2);

/// If the beacon node slot_clock is within 1 slot, this is deemed acceptable. Otherwise the node
/// will be marked as CandidateError::TimeDiscrepancy.
const FUTURE_SLOT_TOLERANCE: Slot = Slot::new(1);

// Configuration for the Beacon Node fallback.
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// Disables publishing http api requests to all beacon nodes for select api calls.
    pub disable_run_on_all: bool,
    /// Sets the number of slots behind the head a beacon node is allowed to be to still be
    /// considered `synced`.
    pub sync_tolerance: Option<u64>,
    /// Sets the size of the range of the `small` sync distance tier. This range starts immediately
    /// after `sync_tolerance`.
    pub small_sync_distance_modifier: Option<u64>,
    /// Sets the size of the range of the `medium` sync distance tier. This range starts immediately
    /// after the `small` range.
    pub medium_sync_distance_modifier: Option<u64>,
}

/// Indicates a measurement of latency between the VC and a BN.
pub struct LatencyMeasurement {
    /// An identifier for the beacon node (e.g. the URL).
    pub beacon_node_id: String,
    /// The round-trip latency, if the BN responded successfully.
    pub latency: Option<Duration>,
}

/// Starts a service that will routinely try and update the status of the provided `beacon_nodes`.
///
/// See `SLOT_LOOKAHEAD` for information about when this should run.
pub fn start_fallback_updater_service<T: SlotClock + 'static, E: EthSpec>(
    context: RuntimeContext<E>,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
) -> Result<(), &'static str> {
    let executor = context.executor;
    if beacon_nodes.slot_clock.is_none() {
        return Err("Cannot start fallback updater without slot clock");
    }

    let future = async move {
        loop {
            beacon_nodes.update_all_candidates().await;

            let sleep_time = beacon_nodes
                .slot_clock
                .as_ref()
                .and_then(|slot_clock| {
                    let slot = slot_clock.now()?;
                    let till_next_slot = slot_clock.duration_to_slot(slot + 1)?;

                    till_next_slot.checked_sub(SLOT_LOOKAHEAD)
                })
                .unwrap_or_else(|| Duration::from_secs(1));

            sleep(sleep_time).await
        }
    };

    executor.spawn(future, "fallback");

    Ok(())
}

#[derive(Debug)]
pub enum Error<E> {
    /// The node was unavailable and we didn't attempt to contact it.
    Unavailable(CandidateError),
    /// We attempted to contact the node but it failed.
    RequestFailed(E),
}

impl<E> Error<E> {
    pub fn request_failure(&self) -> Option<&E> {
        match self {
            Error::RequestFailed(e) => Some(e),
            _ => None,
        }
    }
}

/// The list of errors encountered whilst attempting to perform a query.
pub struct Errors<E>(pub Vec<(String, Error<E>)>);

impl<E: Debug> fmt::Display for Errors<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.0.is_empty() {
            write!(f, "Some endpoints failed, num_failed: {}", self.0.len())?;
        }
        for (i, (id, error)) in self.0.iter().enumerate() {
            let comma = if i + 1 < self.0.len() { "," } else { "" };

            write!(f, " {} => {:?}{}", id, error, comma)?;
        }
        Ok(())
    }
}

/// Reasons why a candidate might not be ready.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub enum CandidateError {
    Uninitialized,
    Offline,
    Incompatible,
    TimeDiscrepancy,
}

#[derive(Debug, Clone)]
pub struct CandidateInfo {
    pub id: usize,
    pub node: String,
    pub health: Option<BeaconNodeHealth>,
}

/// Represents a `BeaconNodeHttpClient` inside a `BeaconNodeFallback` that may or may not be used
/// for a query.
#[derive(Debug)]
pub struct CandidateBeaconNode<E> {
    pub id: usize,
    pub beacon_node: BeaconNodeHttpClient,
    pub health: PLRwLock<Result<BeaconNodeHealth, CandidateError>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> PartialEq for CandidateBeaconNode<E> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.beacon_node == other.beacon_node
    }
}

impl<E: EthSpec> Eq for CandidateBeaconNode<E> {}

impl<E: EthSpec> Ord for CandidateBeaconNode<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (&(self.health()), &(other.health())) {
            (Err(_), Err(_)) => Ordering::Equal,
            (Err(_), _) => Ordering::Greater,
            (_, Err(_)) => Ordering::Less,
            (Ok(health_1), Ok(health_2)) => health_1.cmp(health_2),
        }
    }
}

impl<E: EthSpec> PartialOrd for CandidateBeaconNode<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<E: EthSpec> CandidateBeaconNode<E> {
    /// Instantiate a new node.
    pub fn new(beacon_node: BeaconNodeHttpClient, id: usize) -> Self {
        Self {
            id,
            beacon_node,
            health: PLRwLock::new(Err(CandidateError::Uninitialized)),
            _phantom: PhantomData,
        }
    }

    /// Returns the health of `self`.
    pub fn health(&self) -> Result<BeaconNodeHealth, CandidateError> {
        *self.health.read()
    }

    pub async fn refresh_health<T: SlotClock>(
        &self,
        distance_tiers: &BeaconNodeSyncDistanceTiers,
        slot_clock: Option<&T>,
        spec: &ChainSpec,
        log: &Logger,
    ) -> Result<(), CandidateError> {
        if let Err(e) = self.is_compatible(spec, log).await {
            *self.health.write() = Err(e);
            return Err(e);
        }

        if let Some(slot_clock) = slot_clock {
            match check_node_health(&self.beacon_node, log).await {
                Ok((head, is_optimistic, el_offline)) => {
                    let slot_clock_head = slot_clock.now().ok_or(CandidateError::Uninitialized)?;

                    if head > slot_clock_head + FUTURE_SLOT_TOLERANCE {
                        return Err(CandidateError::TimeDiscrepancy);
                    }
                    let sync_distance = slot_clock_head.saturating_sub(head);

                    // Currently ExecutionEngineHealth is solely determined by online status.
                    let execution_status = if el_offline {
                        ExecutionEngineHealth::Unhealthy
                    } else {
                        ExecutionEngineHealth::Healthy
                    };

                    let optimistic_status = if is_optimistic {
                        IsOptimistic::Yes
                    } else {
                        IsOptimistic::No
                    };

                    let new_health = BeaconNodeHealth::from_status(
                        self.id,
                        sync_distance,
                        head,
                        optimistic_status,
                        execution_status,
                        distance_tiers,
                    );

                    *self.health.write() = Ok(new_health);
                    Ok(())
                }
                Err(e) => {
                    // Set the health as `Err` which is sorted last in the list.
                    *self.health.write() = Err(e);
                    Err(e)
                }
            }
        } else {
            // Slot clock will only be `None` at startup.
            // Assume compatible nodes are available.
            Ok(())
        }
    }

    /// Checks if the node has the correct specification.
    async fn is_compatible(&self, spec: &ChainSpec, log: &Logger) -> Result<(), CandidateError> {
        let config = self
            .beacon_node
            .get_config_spec::<ConfigSpec>()
            .await
            .map_err(|e| {
                error!(
                    log,
                    "Unable to read spec from beacon node";
                    "error" => %e,
                    "endpoint" => %self.beacon_node,
                );
                CandidateError::Offline
            })?
            .data;

        let beacon_node_spec = ChainSpec::from_config::<E>(&config).ok_or_else(|| {
            error!(
                log,
                "The minimal/mainnet spec type of the beacon node does not match the validator \
                client. See the --network command.";
                "endpoint" => %self.beacon_node,
            );
            CandidateError::Incompatible
        })?;

        if beacon_node_spec.genesis_fork_version != spec.genesis_fork_version {
            error!(
                log,
                "Beacon node is configured for a different network";
                "endpoint" => %self.beacon_node,
                "bn_genesis_fork" => ?beacon_node_spec.genesis_fork_version,
                "our_genesis_fork" => ?spec.genesis_fork_version,
            );
            return Err(CandidateError::Incompatible);
        } else if beacon_node_spec.altair_fork_epoch != spec.altair_fork_epoch {
            warn!(
                log,
                "Beacon node has mismatched Altair fork epoch";
                "endpoint" => %self.beacon_node,
                "endpoint_altair_fork_epoch" => ?beacon_node_spec.altair_fork_epoch,
                "hint" => UPDATE_REQUIRED_LOG_HINT,
            );
        } else if beacon_node_spec.bellatrix_fork_epoch != spec.bellatrix_fork_epoch {
            warn!(
                log,
                "Beacon node has mismatched Bellatrix fork epoch";
                "endpoint" => %self.beacon_node,
                "endpoint_bellatrix_fork_epoch" => ?beacon_node_spec.bellatrix_fork_epoch,
                "hint" => UPDATE_REQUIRED_LOG_HINT,
            );
        } else if beacon_node_spec.capella_fork_epoch != spec.capella_fork_epoch {
            warn!(
                log,
                "Beacon node has mismatched Capella fork epoch";
                "endpoint" => %self.beacon_node,
                "endpoint_capella_fork_epoch" => ?beacon_node_spec.capella_fork_epoch,
                "hint" => UPDATE_REQUIRED_LOG_HINT,
            );
        } else if beacon_node_spec.deneb_fork_epoch != spec.deneb_fork_epoch {
            warn!(
                log,
                "Beacon node has mismatched Deneb fork epoch";
                "endpoint" => %self.beacon_node,
                "endpoint_deneb_fork_epoch" => ?beacon_node_spec.deneb_fork_epoch,
                "hint" => UPDATE_REQUIRED_LOG_HINT,
            );
        }

        Ok(())
    }
}

/// A collection of `CandidateBeaconNode` that can be used to perform requests with "fallback"
/// behaviour, where the failure of one candidate results in the next candidate receiving an
/// identical query.
#[derive(Clone, Debug)]
pub struct BeaconNodeFallback<T, E> {
    pub candidates: Arc<RwLock<Vec<CandidateBeaconNode<E>>>>,
    distance_tiers: BeaconNodeSyncDistanceTiers,
    slot_clock: Option<T>,
    broadcast_topics: Vec<ApiTopic>,
    spec: ChainSpec,
    log: Logger,
}

impl<T: SlotClock, E: EthSpec> BeaconNodeFallback<T, E> {
    pub fn new(
        candidates: Vec<CandidateBeaconNode<E>>,
        config: Config,
        broadcast_topics: Vec<ApiTopic>,
        spec: ChainSpec,
        log: Logger,
    ) -> Self {
        let distance_tiers = BeaconNodeSyncDistanceTiers::from_config(&config);
        Self {
            candidates: Arc::new(RwLock::new(candidates)),
            distance_tiers,
            slot_clock: None,
            broadcast_topics,
            spec,
            log,
        }
    }

    /// Used to update the slot clock post-instantiation.
    ///
    /// This is the result of a chicken-and-egg issue where `Self` needs a slot clock for some
    /// operations, but `Self` is required to obtain the slot clock since we need the genesis time
    /// from a beacon node.
    pub fn set_slot_clock(&mut self, slot_clock: T) {
        self.slot_clock = Some(slot_clock);
    }

    /// The count of candidates, regardless of their state.
    pub async fn num_total(&self) -> usize {
        self.candidates.read().await.len()
    }

    /// The count of candidates that are online and compatible, but not necessarily synced.
    pub async fn num_available(&self) -> usize {
        let mut n = 0;
        for candidate in self.candidates.read().await.iter() {
            match candidate.health() {
                Ok(_) | Err(CandidateError::Uninitialized) => n += 1,
                Err(_) => continue,
            }
        }
        n
    }

    // Returns all data required by the VC notifier.
    pub async fn get_notifier_info(&self) -> (Vec<CandidateInfo>, usize, usize) {
        let candidates = self.candidates.read().await;

        let mut candidate_info = Vec::with_capacity(candidates.len());
        let mut num_available = 0;
        let mut num_synced = 0;

        for candidate in candidates.iter() {
            let health = candidate.health();

            match candidate.health() {
                Ok(health) => {
                    if self.distance_tiers.compute_distance_tier(health.health_tier.sync_distance) == SyncDistanceTier::Synced {
                        num_synced += 1;
                    }
                    num_available += 1;
                }
                Err(CandidateError::Uninitialized) => num_available += 1,
                Err(_) => continue,
            }

            candidate_info.push(CandidateInfo { id: candidate.id, node: candidate.beacon_node.to_string(), health: health.ok() });
        }

        (candidate_info, num_available, num_synced)
    }

    /// Loop through ALL candidates in `self.candidates` and update their sync status.
    ///
    /// It is possible for a node to return an unsynced status while continuing to serve
    /// low quality responses. To route around this it's best to poll all connected beacon nodes.
    /// A previous implementation of this function polled only the unavailable BNs.
    pub async fn update_all_candidates(&self) {
        let candidates = self.candidates.read().await;
        let mut futures = Vec::with_capacity(candidates.len());
        let mut nodes = Vec::with_capacity(candidates.len());

        for candidate in candidates.iter() {
            futures.push(candidate.refresh_health(
                &self.distance_tiers,
                self.slot_clock.as_ref(),
                &self.spec,
                &self.log,
            ));
            nodes.push(candidate.beacon_node.to_string());
        }

        // Run all updates concurrently.
        let future_results = future::join_all(futures).await;
        let results = future_results.iter().zip(nodes);

        for (result, node) in results {
            if let Err(e) = result {
                warn!(
                    self.log,
                    "A connected beacon node errored during routine health check.";
                    "error" => ?e,
                    "endpoint" => node,
                );
            }
        }

        drop(candidates);

        // Sort the list to put the healthiest candidate first.
        let mut write = self.candidates.write().await;
        write.sort();
    }

    /// Concurrently send a request to all candidates (regardless of
    /// offline/online) status and attempt to collect a rough reading on the
    /// latency between the VC and candidate.
    pub async fn measure_latency(&self) -> Vec<LatencyMeasurement> {
        let candidates = self.candidates.read().await;
        let futures: Vec<_> = candidates
            .iter()
            .map(|candidate| async {
                let beacon_node_id = candidate.beacon_node.to_string();
                // The `node/version` endpoint is used since I imagine it would
                // require the least processing in the BN and therefore measure
                // the connection moreso than the BNs processing speed.
                //
                // I imagine all clients have the version string availble as a
                // pre-computed string.
                let response_instant = candidate
                    .beacon_node
                    .get_node_version()
                    .await
                    .ok()
                    .map(|_| Instant::now());
                (beacon_node_id, response_instant)
            })
            .collect();

        let request_instant = Instant::now();

        // Send the request to all BNs at the same time. This might involve some
        // queueing on the sending host, however I hope it will avoid bias
        // caused by sending requests at different times.
        future::join_all(futures)
            .await
            .into_iter()
            .map(|(beacon_node_id, response_instant)| LatencyMeasurement {
                beacon_node_id,
                latency: response_instant
                    .and_then(|response| response.checked_duration_since(request_instant)),
            })
            .collect()
    }

    /// Run `func` against each candidate in `self`, returning immediately if a result is found.
    /// Otherwise, return all the errors encountered along the way.
    ///
    /// First this function will try all nodes with a suitable status. If no candidates are suitable
    /// or all the requests fail, it will try updating the status of all unsuitable nodes and
    /// re-running `func` again.
    pub async fn first_success<F, O, Err, R>(&self, func: F) -> Result<O, Errors<Err>>
    where
        F: Fn(BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<O, Err>>,
        Err: Debug,
    {
        let mut errors = vec![];
        let log = &self.log.clone();

        // Run `func` using a `candidate`, returning the value or capturing errors.
        //
        // We use a macro instead of a closure here since it is not trivial to move `func` into a
        // closure.
        macro_rules! try_func {
            ($candidate: ident) => {{
                inc_counter_vec(&ENDPOINT_REQUESTS, &[$candidate.beacon_node.as_ref()]);

                // There exists a race condition where `func` may be called when the candidate is
                // actually not ready. We deem this an acceptable inefficiency.
                match func($candidate.beacon_node.clone()).await {
                    Ok(val) => return Ok(val),
                    Err(e) => {
                        debug!(
                            log,
                            "Request to beacon node failed";
                            "node" => $candidate.beacon_node.to_string(),
                            "error" => ?e,
                        );

                        errors.push(($candidate.beacon_node.to_string(), Error::RequestFailed(e)));
                        inc_counter_vec(&ENDPOINT_ERRORS, &[$candidate.beacon_node.as_ref()]);
                    }
                }
            }};
        }

        // First pass: try `func` on all synced and ready candidates.
        //
        // This ensures that we always choose a synced node if it is available.
        let candidates = self.candidates.read().await;
        for candidate in candidates.iter() {
            try_func!(candidate);
        }

        // There were no candidates already ready and we were unable to make any of them ready.
        Err(Errors(errors))
    }

    /// Run `func` against all candidates in `self`, collecting the result of `func` against each
    /// candidate.
    ///
    /// First this function will try all nodes with a suitable status. If no candidates are suitable
    /// it will try updating the status of all unsuitable nodes and re-running `func` again.
    ///
    /// Note: This function returns `Ok(())` if `func` returned successfully on all beacon nodes.
    /// It returns a list of errors along with the beacon node id that failed for `func`.
    /// Since this ignores the actual result of `func`, this function should only be used for beacon
    /// node calls whose results we do not care about, only that they completed successfully.
    pub async fn broadcast<F, O, Err, R>(&self, func: F) -> Result<(), Errors<Err>>
    where
        F: Fn(BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<O, Err>>,
    {
        let mut results = vec![];

        // Run `func` using a `candidate`, returning the value or capturing errors.
        //
        // We use a macro instead of a closure here since it is not trivial to move `func` into a
        // closure.
        macro_rules! try_func {
            ($candidate: ident) => {{
                inc_counter_vec(&ENDPOINT_REQUESTS, &[$candidate.beacon_node.as_ref()]);

                // There exists a race condition where `func` may be called when the candidate is
                // actually not ready. We deem this an acceptable inefficiency.
                match func($candidate.beacon_node.clone()).await {
                    Ok(val) => results.push(Ok(val)),
                    Err(e) => {
                        results.push(Err((
                            $candidate.beacon_node.to_string(),
                            Error::RequestFailed(e),
                        )));
                        inc_counter_vec(&ENDPOINT_ERRORS, &[$candidate.beacon_node.as_ref()]);
                    }
                }
            }};
        }

        // First pass: try `func` on all synced and ready candidates.
        //
        // This ensures that we always choose a synced node if it is available.
        let candidates = self.candidates.read().await;
        for candidate in candidates.iter() {
            try_func!(candidate);
        }

        let errors: Vec<_> = results.into_iter().filter_map(|res| res.err()).collect();

        if !errors.is_empty() {
            Err(Errors(errors))
        } else {
            Ok(())
        }
    }

    /// Call `func` on first beacon node that returns success or on all beacon nodes
    /// depending on the `topic` and configuration.
    pub async fn request<F, Err, R>(&self, topic: ApiTopic, func: F) -> Result<(), Errors<Err>>
    where
        F: Fn(BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<(), Err>>,
        Err: Debug,
    {
        if self.broadcast_topics.contains(&topic) {
            self.broadcast(func).await
        } else {
            self.first_success(func).await?;
            Ok(())
        }
    }
}

/// Serves as a cue for `BeaconNodeFallback` to tell which requests need to be broadcasted.
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum ApiTopic {
    Attestations,
    Blocks,
    Subscriptions,
    SyncCommittee,
}

impl ApiTopic {
    pub fn all() -> Vec<ApiTopic> {
        use ApiTopic::*;
        vec![Attestations, Blocks, Subscriptions, SyncCommittee]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node_health::BeaconNodeHealthTier;
    use crate::SensitiveUrl;
    use eth2::Timeouts;
    use std::str::FromStr;
    use strum::VariantNames;
    use types::{MainnetEthSpec, Slot};

    type E = MainnetEthSpec;

    #[test]
    fn api_topic_all() {
        let all = ApiTopic::all();
        assert_eq!(all.len(), ApiTopic::VARIANTS.len());
        assert!(ApiTopic::VARIANTS
            .iter()
            .map(|topic| ApiTopic::from_str(topic).unwrap())
            .eq(all.into_iter()));
    }

    #[test]
    fn check_candidate_order() {
        // These fields is irrelvant for sorting. They are set to arbitrary values.
        let head = Slot::new(99);
        let optimistic_status = IsOptimistic::No;
        let execution_status = ExecutionEngineHealth::Healthy;

        fn new_candidate(id: usize) -> CandidateBeaconNode<E> {
            let beacon_node = BeaconNodeHttpClient::new(
                SensitiveUrl::parse(&format!("http://example_{id}.com")).unwrap(),
                Timeouts::set_all(Duration::from_secs(id as u64)),
            );
            CandidateBeaconNode::new(beacon_node, id)
        }

        let candidate_1 = new_candidate(1);
        let expected_candidate_1 = new_candidate(1);
        let candidate_2 = new_candidate(2);
        let expected_candidate_2 = new_candidate(2);
        let candidate_3 = new_candidate(3);
        let expected_candidate_3 = new_candidate(3);
        let candidate_4 = new_candidate(4);
        let expected_candidate_4 = new_candidate(4);
        let candidate_5 = new_candidate(5);
        let expected_candidate_5 = new_candidate(5);
        let candidate_6 = new_candidate(6);
        let expected_candidate_6 = new_candidate(6);

        let synced = SyncDistanceTier::Synced;
        let small = SyncDistanceTier::Small;

        // Despite `health_1` having a larger sync distance, it is inside the `synced` range which
        // does not tie-break on sync distance and so will tie-break on `id` instead.
        let health_1 = BeaconNodeHealth {
            id: 1,
            head,
            optimistic_status,
            execution_status,
            health_tier: BeaconNodeHealthTier::new(1, Slot::new(2), synced),
        };
        let health_2 = BeaconNodeHealth {
            id: 2,
            head,
            optimistic_status,
            execution_status,
            health_tier: BeaconNodeHealthTier::new(2, Slot::new(1), synced),
        };

        // `health_3` and `health_4` have the same health tier and sync distance so should
        // tie-break on `id`.
        let health_3 = BeaconNodeHealth {
            id: 3,
            head,
            optimistic_status,
            execution_status,
            health_tier: BeaconNodeHealthTier::new(3, Slot::new(9), small),
        };
        let health_4 = BeaconNodeHealth {
            id: 4,
            head,
            optimistic_status,
            execution_status,
            health_tier: BeaconNodeHealthTier::new(3, Slot::new(9), small),
        };

        // `health_5` has a smaller sync distance and is outside the `synced` range so should be
        // sorted first. Note the values of `id`.
        let health_5 = BeaconNodeHealth {
            id: 6,
            head,
            optimistic_status,
            execution_status,
            health_tier: BeaconNodeHealthTier::new(4, Slot::new(9), small),
        };
        let health_6 = BeaconNodeHealth {
            id: 5,
            head,
            optimistic_status,
            execution_status,
            health_tier: BeaconNodeHealthTier::new(4, Slot::new(10), small),
        };

        *candidate_1.health.write() = Ok(health_1);
        *candidate_2.health.write() = Ok(health_2);
        *candidate_3.health.write() = Ok(health_3);
        *candidate_4.health.write() = Ok(health_4);
        *candidate_5.health.write() = Ok(health_5);
        *candidate_6.health.write() = Ok(health_6);

        let mut candidates = vec![
            candidate_3,
            candidate_6,
            candidate_5,
            candidate_1,
            candidate_4,
            candidate_2,
        ];
        let expected_candidates = vec![
            expected_candidate_1,
            expected_candidate_2,
            expected_candidate_3,
            expected_candidate_4,
            expected_candidate_5,
            expected_candidate_6,
        ];

        candidates.sort();

        assert_eq!(candidates, expected_candidates);
    }
}
