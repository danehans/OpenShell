// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime provider credential snapshots.

use crate::secrets::SecretResolver;
use crate::{
    endpoint_path::EndpointPathPattern,
    host_pattern::HostPattern,
    proto::{StaticCredentialBinding, StaticCredentialEndpointBinding},
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};

const MAX_RETAINED_CREDENTIAL_GENERATIONS: usize = 8;

/// Immutable build input, never a runtime environment/configuration selector.
/// Absence disables the optional witness before any new transport request.
pub fn fixed_provider_witness_artifact_sha256() -> Option<&'static str> {
    let digest = option_env!("OPENSHELL_PROVIDER_WITNESS_ARTIFACT_SHA256")?;
    (digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some(digest)
}
pub fn fixed_provider_witness_profile() -> Option<String> {
    let artifact = fixed_provider_witness_artifact_sha256()?;
    Some(witness_sha256(format!("openshell.provider-detach.fixed-profile/v1\nartifact-sha256:{artifact}\nargv:--provider-detach-benign-witness-v1\nstdin:eof\nenv:empty\npty:false\n").as_bytes()))
}

/// Bounded typed decoding for Native adapters without adding a second
/// protobuf dependency or permitting arbitrary JSON/command fields.
pub fn decode_provider_witness_arm(
    bytes: &[u8],
) -> Option<crate::proto::ProviderDetachArmRequestV1> {
    use prost::Message;
    if bytes.len() > 8192 {
        return None;
    }
    crate::proto::ProviderDetachArmRequestV1::decode(bytes).ok()
}

pub fn witness_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
pub fn witness_request_digest(request: &crate::proto::ProviderDetachWitnessRequestV1) -> String {
    use prost::Message;
    use sha2::{Digest, Sha256};
    let mut original = request.clone();
    original.request_sha256.clear();
    let mut digest = Sha256::new();
    digest.update(b"openshell.provider-detach.witness-request/v1\n");
    digest.update(original.encode_to_vec());
    format!("{:x}", digest.finalize())
}
pub fn witness_original_key(authority: &str, run: &str, action: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"openshell.provider-detach.original-witness/v1\n");
    for value in [authority, run, action] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    format!("{:x}", hash.finalize())
}

/// Metadata for exactly one fixed-profile operation; never an argv/env request.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessOperation {
    pub prepared_source_incarnation: String,
    pub prepared_source_epoch: u64,
    pub original_key: String,
    pub request_sha256: String,
    pub profile_sha256: String,
    pub installed_arm_sha256: String,
    pub boundary_incarnation: String,
    pub prepared_ticket: String,
    pub supervisor_session: String,
    pub execution_id: String,
    pub deadline_unix_ms: i64,
    pub arm_request: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessCommittedPermit {
    pub source_incarnation: String,
    pub source_epoch: u64,
    pub permit_id: String,
    pub operation: WitnessOperation,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSourceFence {
    pub source_incarnation: String,
    pub epoch: u64,
    pub disabled: bool,
}

#[derive(Debug)]
struct WitnessSourceState {
    incarnation: String,
    epoch: u64,
    usable: bool,
    committed: HashSet<String>,
    latest_wall_time_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessBoundaryCapability {
    pub boundary_incarnation: String,
    pub execution_id: String,
    pub profile_sha256: String,
}

/// Native adapter only: authenticated existing boundary connection, exactly one
/// exchange for prepare/permit/fence, and no generic execution fallback.
#[async_trait::async_trait]
pub trait ProviderWitnessBoundary: Send + Sync + fmt::Debug {
    async fn capability(&self) -> Option<WitnessBoundaryCapability>;
    async fn prepare(&self, operation: WitnessOperation) -> Option<WitnessOperation>;
    async fn permit(&self, permit: WitnessCommittedPermit) -> bool;
    async fn fence(&self, fence: WitnessSourceFence) -> bool;
}

impl fmt::Debug for WitnessOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WitnessOperation(<original-metadata>)")
    }
}
impl fmt::Debug for WitnessCommittedPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WitnessCommittedPermit(<one-shot>)")
    }
}

/// One outer gate shared by live Core handles and OPA for one execution.
/// This is ephemeral authority; the gateway claim is the durable no-replay fence.
#[derive(Debug)]
pub struct WitnessLaunchGate {
    state: Mutex<WitnessSourceState>,
    fences: tokio::sync::watch::Sender<WitnessSourceFence>,
}

/// Borrowed owner-checked evidence of holding the outer gate; not serializable.
pub struct WitnessSourceGuard<'a> {
    owner: &'a WitnessLaunchGate,
    state: MutexGuard<'a, WitnessSourceState>,
}

impl WitnessLaunchGate {
    pub fn new() -> Arc<Self> {
        let incarnation = uuid::Uuid::new_v4().to_string();
        let (fences, _) = tokio::sync::watch::channel(WitnessSourceFence {
            source_incarnation: incarnation.clone(),
            epoch: 1,
            disabled: false,
        });
        Arc::new(Self {
            state: Mutex::new(WitnessSourceState {
                incarnation,
                epoch: 1,
                usable: true,
                committed: HashSet::new(),
                latest_wall_time_ms: 0,
            }),
            fences,
        })
    }

    pub fn lock(&self) -> WitnessSourceGuard<'_> {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.usable = false;
                state.epoch = state.epoch.saturating_add(1);
                self.fences.send_replace(WitnessSourceFence {
                    source_incarnation: state.incarnation.clone(),
                    epoch: state.epoch,
                    disabled: true,
                });
                state
            }
        };
        WitnessSourceGuard { owner: self, state }
    }

    /// A notification, not a stop ACK. Transport runs after releasing the gate.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<WitnessSourceFence> {
        self.fences.subscribe()
    }

    pub fn snapshot(&self) -> WitnessSourceFence {
        let guard = self.lock();
        WitnessSourceFence {
            source_incarnation: guard.state.incarnation.clone(),
            epoch: guard.state.epoch,
            disabled: !guard.state.usable,
        }
    }
}

impl Drop for WitnessSourceGuard<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.state.usable = false;
            self.state.epoch = self.state.epoch.saturating_add(1);
            self.owner.fences.send_replace(WitnessSourceFence {
                source_incarnation: self.state.incarnation.clone(),
                epoch: self.state.epoch,
                disabled: true,
            });
        }
    }
}

impl WitnessSourceGuard<'_> {
    pub fn belongs_to(&self, gate: &Arc<WitnessLaunchGate>) -> bool {
        std::ptr::eq(self.owner, Arc::as_ptr(gate))
    }

    /// R happens before effective publication; exhausted epochs never reset.
    pub fn invalidate(&mut self) {
        match self.state.epoch.checked_add(1) {
            Some(epoch) => self.state.epoch = epoch,
            None => self.state.usable = false,
        }
        self.owner.fences.send_replace(WitnessSourceFence {
            source_incarnation: self.state.incarnation.clone(),
            epoch: self.state.epoch,
            disabled: !self.state.usable,
        });
    }

    pub fn disable(&mut self) {
        self.state.usable = false;
        self.invalidate();
    }

    fn commit(
        &mut self,
        operation: &WitnessOperation,
        now_ms: i64,
    ) -> Option<WitnessCommittedPermit> {
        self.state.latest_wall_time_ms = self.state.latest_wall_time_ms.max(now_ms);
        if !self.state.usable
            || self.state.committed.len() >= 16
            || operation.prepared_source_incarnation != self.state.incarnation
            || operation.prepared_source_epoch != self.state.epoch
            || operation.deadline_unix_ms <= self.state.latest_wall_time_ms
            || self.state.committed.contains(&operation.original_key)
        {
            return None;
        }
        self.state.committed.insert(operation.original_key.clone());
        Some(WitnessCommittedPermit {
            source_incarnation: self.state.incarnation.clone(),
            source_epoch: self.state.epoch,
            permit_id: uuid::Uuid::new_v4().to_string(),
            operation: operation.clone(),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProviderCredentialSnapshot {
    /// Identifies this local installation, including repairs at the same revision.
    pub installation_id: String,
    pub revision: u64,
    pub child_env: HashMap<String, String>,
    pub dynamic_credentials: HashMap<String, crate::proto::ProviderProfileCredential>,
}

/// One atomic workload-facing snapshot and its local installation identity.
///
/// Only the prepared environment crosses an isolation boundary; resolver
/// material remains in the supervisor. The identity distinguishes an empty
/// fail-closed snapshot from a later repair with the same provider revision.
pub struct ChildEnvironmentSnapshot {
    /// Opaque identity of the installed supervisor snapshot.
    pub installation_id: String,
    /// Opaque provider content fingerprint, never an ordered counter.
    pub revision: u64,
    /// Prepared environment used by future workload processes.
    pub environment: HashMap<String, String>,
    /// Complete desired set of non-secret files for this installation.
    pub files: HashMap<String, String>,
}

#[derive(Debug)]
struct ProviderCredentialStateInner {
    current: Arc<ProviderCredentialSnapshot>,
    files: HashMap<String, String>,
    generations: VecDeque<Arc<SecretResolver>>,
    current_resolver: Option<Arc<SecretResolver>>,
    combined_resolver: Option<Arc<SecretResolver>>,
    suppressed_keys: HashSet<String>,
    non_secret_environment_keys: HashSet<String>,
    static_credential_bindings: HashMap<String, CompiledStaticCredentialBinding>,
    known_static_credential_keys: HashSet<String>,
    body_inventory_available: bool,
    known_body_keys: HashSet<String>,
    static_credential_identity_epochs: HashMap<String, StaticCredentialIdentityEpoch>,
    provider_detach: ProviderDetachLocalState,
}

#[derive(Debug)]
struct StaticCredentialIdentityEpoch {
    identity: String,
    revisions: Arc<HashSet<u64>>,
}

#[derive(Debug, Clone)]
struct CompiledStaticCredentialBinding {
    endpoints: Vec<CompiledStaticCredentialEndpointBinding>,
    credential_identity: String,
    workload_credential_handle: String,
    encoded_metadata_len: usize,
}

#[derive(Debug, Clone)]
struct CompiledStaticCredentialEndpointBinding {
    host: HostPattern,
    port: u16,
    path: EndpointPathPattern,
}

#[derive(Debug, Clone)]
pub struct ProviderCredentialState {
    witness_gate: Arc<WitnessLaunchGate>,
    witness_boundary: Arc<OnceLock<Arc<dyn ProviderWitnessBoundary>>>,
    observation_boundary: Arc<OnceLock<Arc<dyn ordinary_observation::Boundary>>>,
    ordinary_observer: Arc<OnceLock<Arc<ordinary_observation::Observer>>>,
    inner: Arc<RwLock<ProviderCredentialStateInner>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticCredentialBindingError {
    message: String,
}

impl fmt::Display for StaticCredentialBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StaticCredentialBindingError {}

/// Native-only association captured while a static provider is installed.
/// It is not serializable and never exposes placeholder strings or key material.
#[derive(Clone)]
pub struct ProviderRevocationSubject {
    provider_id: String,
    installation_id: String,
    revision: u64,
    keys: Vec<String>,
    // Exact child-visible references retained before detachment, never values.
    references: Vec<(String, Vec<CompiledStaticCredentialEndpointBinding>)>,
    metadata_bytes: usize,
}

impl ProviderRevocationSubject {
    /// Association only, not an arm or a refusal. An arbitrary missing token,
    /// another generation or another provider must never become this witness.
    pub fn matches_original_static_bearer(
        &self,
        value: &str,
        host: &str,
        port: u16,
        target: &str,
    ) -> bool {
        let Some(reference) = value.strip_prefix("Bearer ") else {
            return false;
        };
        // A query preference is not a credential witness. Markers anywhere in
        // path/query make this proof shape unsupported, even if policy allows.
        if crate::secrets::contains_reserved_credential_marker(target) {
            return false;
        }
        let path = target.split_once('?').map_or(target, |(path, _)| path);
        let normalized_host = host.to_ascii_lowercase();
        let labels = normalized_host.split('.').collect::<Vec<_>>();
        self.references.iter().any(|(original, endpoints)| {
            original == reference
                && endpoints.iter().any(|endpoint| {
                    static_credential_endpoint_matches(endpoint, &labels, port, path)
                })
        })
    }
}

/// Metadata from the actual installed resolver state, not a network decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRevocationEvidence {
    pub provider_id: String,
    pub before_revision: u64,
    pub revision: u64,
    pub installation_id: String,
    pub unavailable: bool,
}

#[derive(Default)]
struct ProviderDetachLocalState {
    enabled: bool,
    subjects: Vec<Arc<ProviderRevocationSubject>>,
    boot_id: String,
    session_id: String,
    arms: HashMap<String, LocalProviderDetachArm>,
}
#[derive(Clone)]
struct LocalProviderDetachArm {
    seal: crate::proto::ProviderDetachArmSealV1,
    subject: Arc<ProviderRevocationSubject>,
    installation_id: String,
    install_sequence: u64,
    reported_install_time: prost_types::Timestamp,
    server_install_ack: Option<crate::proto::ProviderDetachArmSealV1>,
    policy_current: Arc<dyn Fn() -> bool + Send + Sync>,
    consumed: bool,
    result: i32,
    refusal: Option<crate::proto::ProviderDetachRefusalV1>,
    reserved_bytes: usize,
    result_acknowledged: bool,
}

/// Local outcome only. Unavailable is reported later through authenticated
/// readiness; this enum alone cannot establish a native/controller proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderDetachWitness {
    NotArmed,
    Unavailable,
    NotRefused,
    Invalidated,
}

fn detach_time_ns(t: &prost_types::Timestamp) -> Option<i128> {
    if !(-62_135_596_800..=253_402_300_799).contains(&t.seconds)
        || !(0..1_000_000_000).contains(&t.nanos)
    {
        return None;
    }
    Some(i128::from(t.seconds) * 1_000_000_000 + i128::from(t.nanos))
}
fn detach_arm_time_valid(
    a: &crate::proto::ProviderDetachAttemptV1,
    now: &prost_types::Timestamp,
) -> bool {
    let Some(start) = a.not_before.as_ref().and_then(detach_time_ns) else {
        return false;
    };
    let Some(end) = a.deadline.as_ref().and_then(detach_time_ns) else {
        return false;
    };
    let Some(time) = detach_time_ns(now) else {
        return false;
    };
    start < end && end - start <= 30_000_000_000 && start <= time && time < end
}

impl fmt::Debug for ProviderDetachLocalState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderDetachLocalState")
            .field("enabled", &self.enabled)
            .field("subject_count", &self.subjects.len())
            .finish()
    }
}
fn capture_provider_subject(
    inner: &ProviderCredentialStateInner,
    provider_id: &str,
) -> Option<ProviderRevocationSubject> {
    let id = uuid::Uuid::parse_str(provider_id).ok()?;
    if id.is_nil() || id.to_string() != provider_id {
        return None;
    }
    if !inner.current.dynamic_credentials.is_empty()
        || !inner.body_inventory_available
        || inner.static_credential_bindings.values().any(|b| {
            !b.workload_credential_handle.is_empty()
                || b.credential_identity.starts_with("refresh:")
        })
    {
        return None;
    }
    let prefix = format!("{provider_id}:");
    let mut keys = Vec::new();
    for (key, binding) in &inner.static_credential_bindings {
        if binding.credential_identity.starts_with(&prefix) {
            if !binding.workload_credential_handle.is_empty() {
                return None;
            }
            keys.push(key.clone());
        }
    }
    if keys.is_empty()
        || keys.len() > 64
        || inner.current.revision == 0
        || inner.current.installation_id.is_empty()
    {
        return None;
    }
    keys.sort();
    let mut references = Vec::with_capacity(keys.len());
    let mut metadata_bytes = provider_id.len() + inner.current.installation_id.len() + 8;
    for key in &keys {
        if key.is_empty()
            || key.len() > 128
            || !key
                .bytes()
                .enumerate()
                .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
        {
            return None;
        }
        let reference = inner.current.child_env.get(key)?;
        // Accept only this installation's generated static reference. No
        // refresh/stable handle, inherited raw value or guessed alias.
        if reference
            != &crate::secrets::placeholder_for_env_key_for_revision(key, inner.current.revision)
        {
            return None;
        }
        let binding = inner.static_credential_bindings.get(key)?;
        metadata_bytes = metadata_bytes
            .checked_add(key.len() + reference.len() + binding.encoded_metadata_len)?;
        if metadata_bytes > 256 * 1024 {
            return None;
        }
        let endpoints = &binding.endpoints;
        if endpoints.len() > 64 {
            return None;
        }
        references.push((reference.clone(), endpoints.clone()));
    }
    Some(ProviderRevocationSubject {
        provider_id: provider_id.into(),
        installation_id: inner.current.installation_id.clone(),
        revision: inner.current.revision,
        keys,
        references,
        metadata_bytes,
    })
}
fn retain_current_provider_subjects(inner: &mut ProviderCredentialStateInner) {
    if !inner.provider_detach.enabled {
        return;
    }
    let ids = inner
        .static_credential_bindings
        .values()
        .filter_map(|b| {
            b.credential_identity
                .split_once(':')
                .map(|(id, _)| id.to_string())
        })
        .collect::<HashSet<_>>();
    for id in ids {
        let Some(subject) = capture_provider_subject(inner, &id) else {
            continue;
        };
        if inner.provider_detach.subjects.iter().any(|old| {
            old.provider_id == subject.provider_id
                && old.revision == subject.revision
                && old.installation_id == subject.installation_id
        }) {
            continue;
        }
        let bytes = inner
            .provider_detach
            .subjects
            .iter()
            .map(|old| old.metadata_bytes)
            .sum::<usize>();
        if inner.provider_detach.subjects.len() >= 32
            || bytes.saturating_add(subject.metadata_bytes) > 256 * 1024
        {
            inner.provider_detach = ProviderDetachLocalState::default();
            return;
        }
        inner.provider_detach.subjects.push(Arc::new(subject));
    }
}

impl ProviderCredentialState {
    pub fn install_observation_boundary(
        &self,
        boundary: Arc<dyn ordinary_observation::Boundary>,
    ) -> bool {
        self.observation_boundary.set(boundary).is_ok()
    }
    pub fn ordinary_session_identity(&self) -> Option<(String, String)> {
        let inner = self.inner.read().ok()?;
        if !inner.provider_detach.enabled
            || inner.provider_detach.boot_id.is_empty()
            || inner.provider_detach.session_id.is_empty()
        {
            return None;
        }
        Some((
            inner.provider_detach.boot_id.clone(),
            inner.provider_detach.session_id.clone(),
        ))
    }
    pub fn observation_boundary(&self) -> Option<Arc<dyn ordinary_observation::Boundary>> {
        self.observation_boundary.get().cloned()
    }
    pub fn ordinary_observer(&self) -> Option<Arc<ordinary_observation::Observer>> {
        self.ordinary_observer.get().cloned()
    }
    pub fn install_ordinary_observer(&self, observer: Arc<ordinary_observation::Observer>) -> bool {
        self.ordinary_observer.set(observer).is_ok()
    }
    /// Bind once to this execution's authenticated Native backend. No later
    /// reconnect, alternate backend or unsupported peer replaces the original.
    pub fn install_witness_boundary(&self, boundary: Arc<dyn ProviderWitnessBoundary>) -> bool {
        self.witness_boundary.set(boundary).is_ok()
    }
    pub fn witness_boundary(&self) -> Option<Arc<dyn ProviderWitnessBoundary>> {
        self.witness_boundary.get().cloned()
    }
    /// Bootstrap only, before any clones can observe this credential state.
    /// Live state never swaps its gate independently of existing handles.
    pub fn bind_witness_launch_gate(&mut self, gate: Arc<WitnessLaunchGate>) -> bool {
        if Arc::strong_count(&self.inner) != 1 {
            return false;
        }
        let old = self.witness_gate.lock();
        if !old.state.committed.is_empty() || !old.state.usable {
            return false;
        }
        let Ok(inner) = self.inner.read() else {
            return false;
        };
        if inner.provider_detach.enabled || !inner.provider_detach.arms.is_empty() {
            return false;
        }
        drop(inner);
        drop(old);
        self.witness_gate = gate;
        true
    }
    pub fn witness_launch_gate(&self) -> Arc<WitnessLaunchGate> {
        self.witness_gate.clone()
    }

    /// L is a one-shot authorization commit, never a child-start/refusal proof.
    /// Caller holds matching outer gate and actual OPA publication locks.
    pub fn commit_provider_witness_under_source_gate(
        &self,
        guard: &mut WitnessSourceGuard<'_>,
        operation: &WitnessOperation,
        now_ms: i64,
    ) -> Option<WitnessCommittedPermit> {
        use prost::Message;
        use sha2::{Digest, Sha256};
        if !guard.belongs_to(&self.witness_gate) || operation.arm_request.len() > 8192 {
            return None;
        }
        let digest = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if [
            &operation.original_key,
            &operation.request_sha256,
            &operation.profile_sha256,
            &operation.installed_arm_sha256,
        ]
        .into_iter()
        .any(|v| !digest(v))
            || [&operation.boundary_incarnation, &operation.prepared_ticket]
                .into_iter()
                .any(|v| uuid::Uuid::parse_str(v).is_err())
        {
            return None;
        }
        let request =
            crate::proto::ProviderDetachArmRequestV1::decode(operation.arm_request.as_slice())
                .ok()?;
        let attempt = request.attempt.as_ref()?;
        let now = prost_types::Timestamp {
            seconds: now_ms.div_euclid(1000),
            nanos: i32::try_from(now_ms.rem_euclid(1000) * 1_000_000).ok()?,
        };
        if !detach_arm_time_valid(attempt, &now)
            || attempt.supervisor_session != operation.supervisor_session
            || attempt.execution_id != operation.execution_id
            || detach_time_ns(attempt.deadline.as_ref()?)? / 1_000_000
                != i128::from(operation.deadline_unix_ms)
        {
            return None;
        }
        let inner = self.inner.read().ok()?;
        let arm = inner.provider_detach.arms.get(&request.attempt_id)?;
        let installed = arm.server_install_ack.as_ref()?;
        if !inner.provider_detach.enabled
            || inner.provider_detach.boot_id != attempt.gateway_boot_id
            || inner.provider_detach.session_id != operation.supervisor_session
            || arm.seal.request.as_ref() != Some(&request)
            || arm.installation_id != inner.current.installation_id
            || inner.current.revision != attempt.provider_env_revision
            || format!("{:x}", Sha256::digest(installed.encode_to_vec()))
                != operation.installed_arm_sha256
            || !(arm.policy_current)()
            || arm.consumed
        {
            return None;
        }
        // This does not consume the separate Native credential-refusal witness.
        guard.commit(operation, now_ms)
    }

    /// Capture only a grounded static-provider identity. Refresh handles and
    /// dynamic grants have a different association contract and are unsupported.
    pub fn capture_static_provider_revocation(
        &self,
        provider_id: &str,
    ) -> Option<ProviderRevocationSubject> {
        let inner = self.inner.read().ok()?;
        capture_provider_subject(&inner, provider_id)
    }

    /// Explicit trusted source/configuration switch, default OFF. This changes
    /// observation support only; it grants neither an arm nor an invocation.
    pub fn enable_provider_detach_attempts(&self) {
        let mut source_gate = self.witness_gate.lock();
        source_gate.invalidate();
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");
        inner.provider_detach.enabled = true;
        retain_current_provider_subjects(&mut inner);
    }
    pub fn provider_detach_attempts_enabled(&self) -> bool {
        self.inner
            .read()
            .is_ok_and(|inner| inner.provider_detach.enabled)
    }
    /// Trusted metadata captured before actual install replacement. Ambiguous
    /// same-revision repairs, missing provenance or bounded overflow refuse.
    pub fn retained_provider_revocation_subject(
        &self,
        provider_id: &str,
        before_revision: u64,
    ) -> Option<Arc<ProviderRevocationSubject>> {
        let inner = self.inner.read().ok()?;
        if !inner.provider_detach.enabled {
            return None;
        }
        let mut matches = inner
            .provider_detach
            .subjects
            .iter()
            .filter(|s| s.provider_id == provider_id && s.revision == before_revision);
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(first.clone())
    }

    /// Check membership at the real resolver lock without resolving/copying any
    /// secret value. Old references are fenced by the same known-key deny set
    /// used by `resolver_for_endpoint_with_revision`. In-flight resolver Arcs are
    /// deliberately outside this observation's claim.
    pub fn observe_static_provider_revocation(
        &self,
        subject: &ProviderRevocationSubject,
        expected_revision: u64,
        expected_installation: &str,
    ) -> Option<ProviderRevocationEvidence> {
        let inner = self.inner.read().ok()?;
        if inner.current.revision != expected_revision
            || inner.current.installation_id != expected_installation
            || expected_installation.is_empty()
            || expected_installation == subject.installation_id
            || expected_revision == 0
            || expected_revision == subject.revision
            || !inner.current.dynamic_credentials.is_empty()
            || !inner.body_inventory_available
        {
            return None;
        }
        let prefix = format!("{}:", subject.provider_id);
        let mut available = inner
            .static_credential_bindings
            .values()
            .any(|binding| binding.credential_identity.starts_with(&prefix));
        for key in &subject.keys {
            if !inner.known_static_credential_keys.contains(key) {
                return None;
            }
            if let Some(binding) = inner.static_credential_bindings.get(key) {
                if !binding.credential_identity.starts_with(&prefix) {
                    return None;
                }
                available = true;
            } else if inner.current.child_env.contains_key(key) {
                // A reused or unclassified environment entry is not proof of
                // absence of this provider's native credential authority.
                return None;
            }
        }
        Some(ProviderRevocationEvidence {
            provider_id: subject.provider_id.clone(),
            before_revision: subject.revision,
            revision: expected_revision,
            installation_id: expected_installation.into(),
            unavailable: !available,
        })
    }

    pub fn from_environment(
        revision: u64,
        env: HashMap<String, String>,
        credential_expires_at_ms: HashMap<String, i64>,
        dynamic_credentials: HashMap<String, crate::proto::ProviderProfileCredential>,
    ) -> Self {
        let (child_env, generation_resolver, current_resolver) =
            SecretResolver::from_provider_env_for_current_revision(
                env,
                credential_expires_at_ms,
                revision,
            );
        let snapshot = Arc::new(ProviderCredentialSnapshot {
            installation_id: uuid::Uuid::new_v4().to_string(),
            revision,
            child_env,
            dynamic_credentials,
        });
        let generations: VecDeque<_> = generation_resolver.map(Arc::new).into_iter().collect();
        let current_resolver = current_resolver.map(Arc::new);
        let combined_resolver = merge_resolvers(&generations, current_resolver.as_ref());

        Self {
            witness_gate: WitnessLaunchGate::new(),
            witness_boundary: Arc::new(OnceLock::new()),
            observation_boundary: Arc::new(OnceLock::new()),
            ordinary_observer: Arc::new(OnceLock::new()),
            inner: Arc::new(RwLock::new(ProviderCredentialStateInner {
                current: snapshot.clone(),
                files: HashMap::new(),
                generations,
                current_resolver,
                combined_resolver,
                suppressed_keys: HashSet::new(),
                non_secret_environment_keys: HashSet::new(),
                static_credential_bindings: HashMap::new(),
                body_inventory_available: true,
                known_body_keys: snapshot.child_env.keys().cloned().collect(),
                known_static_credential_keys: HashSet::new(),
                static_credential_identity_epochs: HashMap::new(),
                provider_detach: ProviderDetachLocalState::default(),
            })),
        }
    }

    pub fn from_bound_environment(
        revision: u64,
        env: HashMap<String, String>,
        credential_expires_at_ms: HashMap<String, i64>,
        dynamic_credentials: HashMap<String, crate::proto::ProviderProfileCredential>,
        static_credential_bindings: HashMap<String, StaticCredentialBinding>,
        non_secret_environment_keys: Vec<String>,
    ) -> Result<Self, StaticCredentialBindingError> {
        let static_credential_bindings = compile_static_credential_bindings(
            &env,
            static_credential_bindings,
            &non_secret_environment_keys,
        )?;
        let stable_handles = static_credential_stable_handles(&static_credential_bindings);
        let (child_env, generation_resolver, current_resolver) =
            SecretResolver::from_provider_env_for_current_revision_with_stable_handles(
                env,
                credential_expires_at_ms,
                revision,
                &stable_handles,
            );
        let snapshot = Arc::new(ProviderCredentialSnapshot {
            installation_id: uuid::Uuid::new_v4().to_string(),
            revision,
            child_env,
            dynamic_credentials,
        });
        let generations = generation_resolver.map(Arc::new).into_iter().collect();
        let current_resolver = current_resolver.map(Arc::new);
        let combined_resolver = merge_resolvers(&generations, current_resolver.as_ref());
        let known_static_credential_keys = static_credential_bindings.keys().cloned().collect();
        let mut static_credential_identity_epochs = HashMap::new();
        update_static_credential_identity_epochs(
            &mut static_credential_identity_epochs,
            revision,
            &static_credential_bindings,
        );

        Ok(Self {
            witness_gate: WitnessLaunchGate::new(),
            witness_boundary: Arc::new(OnceLock::new()),
            observation_boundary: Arc::new(OnceLock::new()),
            ordinary_observer: Arc::new(OnceLock::new()),
            inner: Arc::new(RwLock::new(ProviderCredentialStateInner {
                current: snapshot.clone(),
                files: HashMap::new(),
                generations,
                current_resolver,
                combined_resolver,
                suppressed_keys: HashSet::new(),
                non_secret_environment_keys: non_secret_environment_keys.into_iter().collect(),
                static_credential_bindings,
                body_inventory_available: true,
                known_body_keys: snapshot.child_env.keys().cloned().collect(),
                known_static_credential_keys,
                static_credential_identity_epochs,
                provider_detach: ProviderDetachLocalState::default(),
            })),
        })
    }

    /// Build a static provider state from an already-prepared child
    /// environment snapshot.
    ///
    /// The Kubernetes sandbox runtime uses this in the sandbox process:
    /// the supervisor owns provider credential resolvers and sends the
    /// workload-facing env map over a local control channel. The process leaf
    /// must inject that map into child processes without re-placeholderizing it
    /// or holding the gateway-side resolver material.
    pub fn from_child_env_snapshot(revision: u64, child_env: HashMap<String, String>) -> Self {
        let snapshot = Arc::new(ProviderCredentialSnapshot {
            installation_id: uuid::Uuid::new_v4().to_string(),
            revision,
            child_env,
            dynamic_credentials: HashMap::new(),
        });

        Self {
            witness_gate: WitnessLaunchGate::new(),
            witness_boundary: Arc::new(OnceLock::new()),
            observation_boundary: Arc::new(OnceLock::new()),
            ordinary_observer: Arc::new(OnceLock::new()),
            inner: Arc::new(RwLock::new(ProviderCredentialStateInner {
                current: snapshot.clone(),
                files: HashMap::new(),
                generations: VecDeque::new(),
                current_resolver: None,
                combined_resolver: None,
                suppressed_keys: HashSet::new(),
                non_secret_environment_keys: HashSet::new(),
                static_credential_bindings: HashMap::new(),
                body_inventory_available: false,
                known_body_keys: snapshot.child_env.keys().cloned().collect(),
                known_static_credential_keys: HashSet::new(),
                static_credential_identity_epochs: HashMap::new(),
                provider_detach: ProviderDetachLocalState::default(),
            })),
        }
    }

    /// Install an already-prepared child environment snapshot.
    ///
    /// This is intentionally narrower than [`Self::install_environment`]: it
    /// updates only the workload-facing env map and clears resolver state so a
    /// process that does not own gateway/provider resolver material can still
    /// pick up refreshed provider env for future child processes.
    pub fn install_child_env_snapshot(
        &self,
        revision: u64,
        mut child_env: HashMap<String, String>,
    ) -> usize {
        let mut source_gate = self.witness_gate.lock();
        source_gate.invalidate();
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");

        for key in &inner.suppressed_keys {
            child_env.remove(key);
        }

        inner.current = Arc::new(ProviderCredentialSnapshot {
            installation_id: uuid::Uuid::new_v4().to_string(),
            revision,
            child_env,
            dynamic_credentials: HashMap::new(),
        });
        inner.generations.clear();
        inner.current_resolver = None;
        inner.combined_resolver = None;
        inner.non_secret_environment_keys.clear();
        inner.static_credential_bindings.clear();
        inner.known_static_credential_keys.clear();
        inner.static_credential_identity_epochs.clear();
        inner.body_inventory_available = false;
        inner.current.child_env.len()
    }

    pub fn snapshot(&self) -> Arc<ProviderCredentialSnapshot> {
        self.inner
            .read()
            .expect("provider credential state poisoned")
            .current
            .clone()
    }

    pub fn resolver(&self) -> Option<Arc<SecretResolver>> {
        self.inner
            .read()
            .expect("provider credential state poisoned")
            .combined_resolver
            .clone()
    }

    /// Resolve provider placeholders only for credentials bound to this
    /// concrete request endpoint. The view is created from one atomic state
    /// snapshot and shares underlying resolver material.
    #[must_use]
    pub fn resolver_for_endpoint(
        &self,
        host: &str,
        port: u16,
        path: &str,
    ) -> Option<Arc<SecretResolver>> {
        self.resolver_for_endpoint_with_revision(host, port, path).0
    }

    /// Resolve provider placeholders for one endpoint and return the provider
    /// revision observed from the same locked state snapshot.
    ///
    /// Callers that materialize credential-bearing requests asynchronously
    /// use the revision to reject stale material immediately before its first
    /// upstream write.
    #[must_use]
    pub fn resolver_for_endpoint_with_revision(
        &self,
        host: &str,
        port: u16,
        path: &str,
    ) -> (Option<Arc<SecretResolver>>, u64) {
        let (resolver, _, revision) =
            self.resolver_and_body_classifier_for_endpoint(host, port, path);
        (resolver, revision)
    }

    /// Obtain value resolution and body classification from the same revision.
    #[must_use]
    pub fn resolver_and_body_classifier_for_endpoint(
        &self,
        host: &str,
        port: u16,
        path: &str,
    ) -> (
        Option<Arc<SecretResolver>>,
        Option<Arc<crate::secrets::body::BodyCredentialClassifier>>,
        u64,
    ) {
        let request_path = path.split_once('?').map_or(path, |(path, _)| path);
        let request_path = crate::secrets::redact_target_for_policy(request_path);
        let normalized_host = host.to_ascii_lowercase();
        let host_labels = normalized_host.split('.').collect::<Vec<_>>();
        let inner = self
            .inner
            .read()
            .expect("provider credential state poisoned");
        let revision = inner.current.revision;
        let Ok(request_path) = request_path else {
            // Binding authorization must not depend on real credential
            // material. Malformed placeholder syntax cannot be normalized
            // safely, so expose no endpoint-scoped resolver.
            return (None, None, revision);
        };
        let allowed: HashSet<String> = inner
            .static_credential_bindings
            .iter()
            .filter(|(_, binding)| {
                binding.endpoints.iter().any(|endpoint| {
                    static_credential_endpoint_matches(endpoint, &host_labels, port, &request_path)
                })
            })
            .map(|(key, _)| key.clone())
            .collect();
        let classifier = inner.body_inventory_available.then(|| {
            Arc::new(crate::secrets::body::BodyCredentialClassifier::new(
                inner.combined_resolver.as_deref(),
                inner
                    .known_body_keys
                    .union(&inner.known_static_credential_keys)
                    .cloned()
                    .collect(),
                inner.static_credential_bindings.keys().cloned().collect(),
                inner
                    .static_credential_identity_epochs
                    .iter()
                    .filter(|(key, epoch)| {
                        inner
                            .static_credential_bindings
                            .get(*key)
                            .is_some_and(|binding| binding.credential_identity == epoch.identity)
                    })
                    .map(|(key, epoch)| (key.clone(), epoch.revisions.clone()))
                    .collect(),
            ))
        });
        let resolver = inner.combined_resolver.as_ref().map(|resolver| {
            let revision_fallback_allowed_revisions = inner
                .static_credential_identity_epochs
                .iter()
                .filter(|(key, epoch)| {
                    allowed.contains(*key)
                        && inner
                            .static_credential_bindings
                            .get(*key)
                            .is_some_and(|binding| binding.credential_identity == epoch.identity)
                })
                .map(|(key, epoch)| (key.clone(), epoch.revisions.clone()))
                .collect();
            Arc::new(resolver.scoped_to_env_keys(
                &inner.known_static_credential_keys,
                &allowed,
                revision_fallback_allowed_revisions,
            ))
        });
        (resolver, classifier, revision)
    }

    #[must_use]
    pub fn revision(&self) -> u64 {
        self.inner
            .read()
            .expect("provider credential state poisoned")
            .current
            .revision
    }

    /// Remove a key from the credential snapshot's child env.
    ///
    /// Used when a sandbox-side service (e.g., metadata server) fails to start
    /// and the corresponding env var should not be inherited by child processes
    /// or SSH sessions.
    pub fn remove_env_key(&self, key: &str) {
        let mut source_gate = self.witness_gate.lock();
        source_gate.invalidate();
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");
        inner.suppressed_keys.insert(key.to_string());
        let mut env = (*inner.current).clone();
        env.child_env.remove(key);
        env.installation_id = uuid::Uuid::new_v4().to_string();
        inner.current = Arc::new(env);
    }

    /// Return `child_env` with explicitly non-secret config vars resolved.
    ///
    /// The credential pipeline placeholderizes all env values. Workloads need
    /// non-secret configuration, including provider file paths, at process
    /// startup before any HTTP request flows through the proxy. Credential
    /// values remain placeholders.
    ///
    /// Three layers of env var injection:
    /// 1. **Synthetic vars** (`GCE_METADATA_IP`, `METADATA_SERVER_DETECTION`)
    ///    — sandbox-internal config not from user
    ///    input, inserted directly here with real values.
    /// 2. **Classified non-secret keys** — user-provided config and provider
    ///    file paths un-placeholderized so workloads can read them at startup.
    /// 3. Everything else stays as placeholders for proxy-time resolution.
    pub fn child_env_with_gcp_resolved(&self) -> HashMap<String, String> {
        let inner = self
            .inner
            .read()
            .expect("provider credential state poisoned");
        Self::resolve_child_env_snapshot(&inner).1
    }

    /// Return the current revision and its workload-facing environment from
    /// one state snapshot.
    ///
    /// Remote isolation boundaries use the pair as a revisioned update.  The
    /// revision must describe the exact environment sent across the boundary,
    /// so callers must not obtain the two values through separate lock
    /// acquisitions.
    pub fn child_env_snapshot_with_gcp_resolved(
        &self,
    ) -> std::io::Result<(u64, HashMap<String, String>)> {
        let inner = self
            .inner
            .read()
            .map_err(|_| std::io::Error::other("provider credential state poisoned"))?;
        Ok(Self::resolve_child_env_snapshot(&inner))
    }

    /// Capture installation identity and prepared environment under one lock.
    pub fn child_environment_snapshot(&self) -> std::io::Result<ChildEnvironmentSnapshot> {
        let inner = self
            .inner
            .read()
            .map_err(|_| std::io::Error::other("provider credential state poisoned"))?;
        let (revision, environment) = Self::resolve_child_env_snapshot(&inner);
        Ok(ChildEnvironmentSnapshot {
            installation_id: inner.current.installation_id.clone(),
            revision,
            environment,
            files: inner.files.clone(),
        })
    }

    /// Attach the complete file set to a prepared provider snapshot.
    pub fn set_managed_files(&self, files: HashMap<String, String>) {
        let mut source_gate = self.witness_gate.lock();
        source_gate.invalidate();
        self.inner
            .write()
            .expect("provider credential state poisoned")
            .files = files;
    }

    fn resolve_child_env_snapshot(
        inner: &ProviderCredentialStateInner,
    ) -> (u64, HashMap<String, String>) {
        use crate::google_cloud;

        let mut env = inner.current.child_env.clone();

        let has_gcp_metadata = env.contains_key("GCE_METADATA_HOST")
            && inner
                .non_secret_environment_keys
                .contains("GCE_METADATA_HOST");
        if !has_gcp_metadata && inner.non_secret_environment_keys.is_empty() {
            return (inner.current.revision, env);
        }

        if has_gcp_metadata {
            // Synthetic vars: sandbox-internal config that doesn't originate
            // from user input and was never placeholderized.
            env.insert(
                "GCE_METADATA_HOST".to_string(),
                google_cloud::METADATA_LOOPBACK_ADDR.to_string(),
            );
            // Python's google-auth builds its ping URL as http://{GCE_METADATA_IP}
            // so the value must include the port.
            env.insert(
                "GCE_METADATA_IP".to_string(),
                google_cloud::METADATA_LOOPBACK_ADDR.to_string(),
            );
            // Node.js gcp-metadata uses METADATA_SERVER_DETECTION to skip the
            // runtime ping that otherwise fails in sandboxed environments.
            env.insert(
                "METADATA_SERVER_DETECTION".to_string(),
                "assume-present".to_string(),
            );
        }

        // Only explicitly classified non-secret values may be unwrapped.
        if let Some(ref resolver) = inner.combined_resolver {
            for key in &inner.non_secret_environment_keys {
                if !env.contains_key(key) || (has_gcp_metadata && key == "GCE_METADATA_HOST") {
                    continue;
                }
                let placeholder = crate::secrets::placeholder_for_env_key(key);
                if let Some(value) = resolver.resolve_placeholder(&placeholder) {
                    env.insert(key.clone(), value.to_string());
                }
            }
        }

        (inner.current.revision, env)
    }

    /// Compare and install a workload-facing environment snapshot.
    ///
    /// Provider environment revisions are opaque content identities, not
    /// ordered counters. The expected revision rejects a different current
    /// fingerprint. Callers must also fence publication order when a failed
    /// refresh and its repair can share that fingerprint.
    pub fn compare_and_install_child_env_snapshot(
        &self,
        expected_revision: u64,
        revision: u64,
        mut child_env: HashMap<String, String>,
    ) -> std::io::Result<u64> {
        let mut source_gate = self.witness_gate.lock();
        source_gate.invalidate();
        let mut inner = self
            .inner
            .write()
            .map_err(|_| std::io::Error::other("provider credential state poisoned"))?;
        if expected_revision != inner.current.revision {
            return Ok(inner.current.revision);
        }

        // A failed refresh can clear the map without changing its provider
        // fingerprint. A matching expectation must therefore install even an
        // equal revision. Boundary publication ordering fences delayed retries.

        for key in &inner.suppressed_keys {
            child_env.remove(key);
        }
        inner.current = Arc::new(ProviderCredentialSnapshot {
            installation_id: uuid::Uuid::new_v4().to_string(),
            revision,
            child_env,
            dynamic_credentials: HashMap::new(),
        });
        inner.generations.clear();
        inner.current_resolver = None;
        inner.combined_resolver = None;
        inner.non_secret_environment_keys.clear();
        inner.static_credential_bindings.clear();
        inner.known_static_credential_keys.clear();
        inner.static_credential_identity_epochs.clear();
        Ok(revision)
    }

    /// Read current provider configuration only when explicitly classified non-secret.
    ///
    /// Local metadata adapters must not unwrap credential values just because their
    /// environment names match a conventional configuration key.
    pub fn current_non_secret_environment_value(&self, key: &str) -> Option<String> {
        let inner = self
            .inner
            .read()
            .expect("provider credential state poisoned");
        if !inner.non_secret_environment_keys.contains(key) {
            return None;
        }
        let placeholder = inner.current.child_env.get(key)?;
        inner
            .current_resolver
            .as_ref()?
            .resolve_placeholder(placeholder)
            .map(str::to_string)
    }

    /// Return the GCP token placeholder and its remaining lifetime in seconds.
    ///
    /// Searches `google_cloud::TOKEN_ENV_KEYS` in priority order (SA before
    /// ADC) atomically to avoid inconsistency during credential
    /// refresh. Returns `None` if no GCP token is configured or all are
    /// expired. The `expires_in` defaults to 3600 when expiry is unknown.
    pub fn gcp_token_response(&self) -> Option<(String, i64)> {
        const DEFAULT_EXPIRES_IN: i64 = 3600;
        let inner = self
            .inner
            .read()
            .expect("provider credential state poisoned");
        let resolver = inner.current_resolver.as_ref()?;
        for key in crate::google_cloud::TOKEN_ENV_KEYS {
            let Some(placeholder) = inner.current.child_env.get(*key).cloned() else {
                continue;
            };
            if resolver.resolve_placeholder(&placeholder).is_none() {
                continue;
            }
            let expires_in = resolver.expires_at_ms_for_placeholder(&placeholder).map_or(
                DEFAULT_EXPIRES_IN,
                |expires_at_ms| {
                    if expires_at_ms <= 0 {
                        DEFAULT_EXPIRES_IN
                    } else {
                        let now = crate::time::now_ms();
                        expires_at_ms.saturating_sub(now) / 1000
                    }
                },
            );
            if expires_in <= 0 {
                continue;
            }
            return Some((placeholder, expires_in));
        }
        None
    }

    pub fn install_environment(
        &self,
        revision: u64,
        env: HashMap<String, String>,
        credential_expires_at_ms: HashMap<String, i64>,
        dynamic_credentials: HashMap<String, crate::proto::ProviderProfileCredential>,
    ) -> usize {
        let (mut child_env, generation_resolver, current_resolver) =
            SecretResolver::from_provider_env_for_current_revision(
                env,
                credential_expires_at_ms,
                revision,
            );
        let mut source_gate = self.witness_gate.lock();
        source_gate.invalidate();
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");

        inner.provider_detach = ProviderDetachLocalState::default();
        for key in &inner.suppressed_keys {
            child_env.remove(key);
        }

        inner.current = Arc::new(ProviderCredentialSnapshot {
            installation_id: uuid::Uuid::new_v4().to_string(),
            revision,
            child_env,
            dynamic_credentials,
        });
        inner.body_inventory_available = true;
        let body_keys = inner.current.child_env.keys().cloned().collect::<Vec<_>>();
        inner.known_body_keys.extend(body_keys);
        inner.current_resolver = current_resolver.map(Arc::new);

        if let Some(resolver) = generation_resolver {
            inner.generations.push_back(Arc::new(resolver));
            while inner.generations.len() > MAX_RETAINED_CREDENTIAL_GENERATIONS {
                inner.generations.pop_front();
            }
        }
        inner.combined_resolver =
            merge_resolvers(&inner.generations, inner.current_resolver.as_ref());
        inner.non_secret_environment_keys.clear();
        inner.current.child_env.len()
    }

    /// Install one gateway provider-environment snapshot.
    ///
    /// Callers must serialize this operation with other bound-environment
    /// installs and revocations. The sandbox settings refresh loop is the sole
    /// writer today. The internal lock makes each mutation memory-safe, but it
    /// does not establish revision ordering between concurrent snapshots.
    pub fn install_bound_environment(
        &self,
        revision: u64,
        env: HashMap<String, String>,
        credential_expires_at_ms: HashMap<String, i64>,
        dynamic_credentials: HashMap<String, crate::proto::ProviderProfileCredential>,
        static_credential_bindings: HashMap<String, StaticCredentialBinding>,
        non_secret_environment_keys: Vec<String>,
    ) -> Result<usize, StaticCredentialBindingError> {
        let static_credential_bindings = match compile_static_credential_bindings(
            &env,
            static_credential_bindings,
            &non_secret_environment_keys,
        ) {
            Ok(bindings) => bindings,
            Err(error) => {
                self.revoke_static_provider_environment_inner(revision, Some(dynamic_credentials));
                return Err(error);
            }
        };

        let stable_handles = static_credential_stable_handles(&static_credential_bindings);
        let (mut child_env, generation_resolver, current_resolver) =
            SecretResolver::from_provider_env_for_current_revision_with_stable_handles(
                env,
                credential_expires_at_ms,
                revision,
                &stable_handles,
            );
        let mut source_gate = self.witness_gate.lock();
        source_gate.invalidate();
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");

        retain_current_provider_subjects(&mut inner);
        for key in &inner.suppressed_keys {
            child_env.remove(key);
        }
        inner.current = Arc::new(ProviderCredentialSnapshot {
            installation_id: uuid::Uuid::new_v4().to_string(),
            revision,
            child_env,
            dynamic_credentials,
        });
        inner.body_inventory_available = true;
        let body_keys = inner.current.child_env.keys().cloned().collect::<Vec<_>>();
        inner.known_body_keys.extend(body_keys);
        inner.current_resolver = current_resolver.map(Arc::new);
        if static_credential_identities(&inner.static_credential_bindings)
            != static_credential_identities(&static_credential_bindings)
        {
            inner.generations.clear();
        }
        if let Some(resolver) = generation_resolver {
            inner.generations.push_back(Arc::new(resolver));
            while inner.generations.len() > MAX_RETAINED_CREDENTIAL_GENERATIONS {
                inner.generations.pop_front();
            }
        }
        inner.combined_resolver =
            merge_resolvers(&inner.generations, inner.current_resolver.as_ref());
        inner
            .known_static_credential_keys
            .extend(static_credential_bindings.keys().cloned());
        update_static_credential_identity_epochs(
            &mut inner.static_credential_identity_epochs,
            revision,
            &static_credential_bindings,
        );
        inner.non_secret_environment_keys = non_secret_environment_keys.into_iter().collect();
        inner.static_credential_bindings = static_credential_bindings;
        Ok(inner.current.child_env.len())
    }

    /// Install a validated candidate without repeating fallible compilation.
    ///
    /// Existing clones keep observing this live state. Preserve suppressed
    /// environment keys and identity history so refresh cannot restore removed
    /// keys or authorize old placeholders for a different provider. Callers
    /// must serialize installs and revocations, as for bound-environment installs.
    pub fn install_prepared(&self, prepared: &Self) -> usize {
        let mut guard = self.witness_gate.lock();
        self.install_prepared_under_source_gate(prepared, &mut guard)
    }

    pub fn install_prepared_under_source_gate(
        &self,
        prepared: &Self,
        source_gate: &mut WitnessSourceGuard<'_>,
    ) -> usize {
        assert!(
            source_gate.belongs_to(&self.witness_gate),
            "source gate owner mismatch"
        );
        // Release the candidate lock before taking the live lock, including
        // when a caller passes another handle to the same state.
        let (snapshot, generations, current_resolver, bindings, non_secret_keys, files) = {
            let candidate = prepared
                .inner
                .read()
                .expect("provider credential state poisoned");
            (
                (*candidate.current).clone(),
                candidate.generations.clone(),
                candidate.current_resolver.clone(),
                candidate.static_credential_bindings.clone(),
                candidate.non_secret_environment_keys.clone(),
                candidate.files.clone(),
            )
        };
        source_gate.invalidate();
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");
        let mut snapshot = snapshot;
        retain_current_provider_subjects(&mut inner);
        for key in &inner.suppressed_keys {
            snapshot.child_env.remove(key);
        }
        if static_credential_identities(&inner.static_credential_bindings)
            != static_credential_identities(&bindings)
        {
            inner.generations.clear();
        }
        inner.generations.extend(generations);
        while inner.generations.len() > MAX_RETAINED_CREDENTIAL_GENERATIONS {
            inner.generations.pop_front();
        }
        inner.current_resolver = current_resolver;
        inner.combined_resolver =
            merge_resolvers(&inner.generations, inner.current_resolver.as_ref());
        inner
            .known_static_credential_keys
            .extend(bindings.keys().cloned());
        update_static_credential_identity_epochs(
            &mut inner.static_credential_identity_epochs,
            snapshot.revision,
            &bindings,
        );
        inner.static_credential_bindings = bindings;
        inner.non_secret_environment_keys = non_secret_keys;
        inner.files = files;
        inner.body_inventory_available = true;
        inner
            .known_body_keys
            .extend(snapshot.child_env.keys().cloned());
        inner.current = Arc::new(snapshot);
        inner.current.child_env.len()
    }

    /// Atomically remove static provider material after a failed refresh.
    ///
    /// Dynamic token grants retain their independently endpoint-bound state
    /// unless the caller supplies a newer dynamic snapshot. Identity-only
    /// revision membership remains as a tombstone so a later successful
    /// refresh can restore placeholders issued by the same provider identity.
    /// With no resolver or active bindings, the tombstone cannot resolve
    /// credentials while the refresh is failed. A successful empty provider
    /// environment removes it through the normal epoch update path.
    pub fn revoke_static_provider_environment(&self, revision: u64) {
        self.revoke_static_provider_environment_inner(revision, None);
    }

    fn revoke_static_provider_environment_inner(
        &self,
        revision: u64,
        dynamic_credentials: Option<HashMap<String, crate::proto::ProviderProfileCredential>>,
    ) {
        let mut source_gate = self.witness_gate.lock();
        source_gate.invalidate();
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");
        let dynamic_credentials =
            dynamic_credentials.unwrap_or_else(|| inner.current.dynamic_credentials.clone());
        inner.current = Arc::new(ProviderCredentialSnapshot {
            installation_id: uuid::Uuid::new_v4().to_string(),
            revision,
            child_env: HashMap::new(),
            dynamic_credentials,
        });
        inner.generations.clear();
        inner.current_resolver = None;
        inner.combined_resolver = None;
        inner.non_secret_environment_keys.clear();
        inner.static_credential_bindings.clear();
        inner.body_inventory_available = false;
    }
}

fn compile_static_credential_bindings(
    env: &HashMap<String, String>,
    bindings: HashMap<String, StaticCredentialBinding>,
    non_secret_environment_keys: &[String],
) -> Result<HashMap<String, CompiledStaticCredentialBinding>, StaticCredentialBindingError> {
    let non_secret_keys = non_secret_environment_keys
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    if non_secret_keys.len() != non_secret_environment_keys.len() {
        return Err(binding_error(
            "provider environment repeats a non-secret environment key",
        ));
    }
    if bindings.keys().any(|key| non_secret_keys.contains(key)) {
        return Err(binding_error(
            "provider environment classifies a key as both credential and non-secret configuration",
        ));
    }
    if env
        .keys()
        .any(|key| !bindings.contains_key(key) && !non_secret_keys.contains(key))
    {
        return Err(binding_error(
            "provider environment contains an unclassified credential key",
        ));
    }
    if bindings.keys().any(|key| !env.contains_key(key))
        || non_secret_keys.iter().any(|key| !env.contains_key(key))
    {
        return Err(binding_error(
            "provider environment metadata references a missing environment key",
        ));
    }
    for binding in bindings.values() {
        if binding.credential_identity.is_empty() {
            return Err(binding_error(
                "static credential binding has no provider credential identity",
            ));
        }
        if binding.endpoints.is_empty() {
            return Err(binding_error(
                "static credential binding has no authorized endpoints",
            ));
        }
        if !binding.workload_credential_handle.is_empty()
            && !is_valid_workload_credential_handle(&binding.workload_credential_handle)
        {
            return Err(binding_error(
                "static credential binding has an invalid workload credential handle",
            ));
        }
        for endpoint in &binding.endpoints {
            if endpoint.port == 0 || endpoint.port > u32::from(u16::MAX) {
                return Err(binding_error(
                    "static credential binding contains an invalid endpoint",
                ));
            }
        }
    }

    bindings
        .into_iter()
        .map(|(key, binding)| {
            let encoded_metadata_len = prost::Message::encoded_len(&binding);
            let endpoints = binding
                .endpoints
                .into_iter()
                .map(compile_static_credential_endpoint)
                .collect::<Result<_, _>>()?;
            Ok((
                key,
                CompiledStaticCredentialBinding {
                    endpoints,
                    credential_identity: binding.credential_identity,
                    workload_credential_handle: binding.workload_credential_handle,
                    encoded_metadata_len,
                },
            ))
        })
        .collect()
}

fn compile_static_credential_endpoint(
    endpoint: StaticCredentialEndpointBinding,
) -> Result<CompiledStaticCredentialEndpointBinding, StaticCredentialBindingError> {
    let host = HostPattern::new(&endpoint.host)
        .map_err(|_| binding_error("static credential binding contains an invalid endpoint"))?;
    Ok(CompiledStaticCredentialEndpointBinding {
        host,
        port: u16::try_from(endpoint.port)
            .map_err(|_| binding_error("static credential binding contains an invalid endpoint"))?,
        path: EndpointPathPattern::new(&endpoint.path),
    })
}

fn static_credential_identities(
    bindings: &HashMap<String, CompiledStaticCredentialBinding>,
) -> HashMap<&str, &str> {
    bindings
        .iter()
        .map(|(key, binding)| (key.as_str(), binding.credential_identity.as_str()))
        .collect()
}

fn static_credential_stable_handles(
    bindings: &HashMap<String, CompiledStaticCredentialBinding>,
) -> HashMap<String, String> {
    bindings
        .iter()
        .filter(|(_, binding)| !binding.workload_credential_handle.is_empty())
        .map(|(key, binding)| (key.clone(), binding.workload_credential_handle.clone()))
        .collect()
}

fn is_valid_workload_credential_handle(handle: &str) -> bool {
    handle.len() == 64
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn update_static_credential_identity_epochs(
    epochs: &mut HashMap<String, StaticCredentialIdentityEpoch>,
    revision: u64,
    bindings: &HashMap<String, CompiledStaticCredentialBinding>,
) {
    epochs.retain(|key, _| {
        bindings
            .get(key)
            .is_some_and(|binding| binding.workload_credential_handle.is_empty())
    });
    for (key, binding) in bindings {
        if !binding.workload_credential_handle.is_empty() {
            continue;
        }
        match epochs.get_mut(key) {
            Some(epoch) if epoch.identity == binding.credential_identity => {
                Arc::make_mut(&mut epoch.revisions).insert(revision);
            }
            Some(epoch) => {
                epoch.identity.clone_from(&binding.credential_identity);
                epoch.revisions = Arc::new(HashSet::from([revision]));
            }
            None => {
                epochs.insert(
                    key.clone(),
                    StaticCredentialIdentityEpoch {
                        identity: binding.credential_identity.clone(),
                        revisions: Arc::new(HashSet::from([revision])),
                    },
                );
            }
        }
    }
}

fn binding_error(message: &str) -> StaticCredentialBindingError {
    StaticCredentialBindingError {
        message: message.to_string(),
    }
}

fn static_credential_endpoint_matches(
    endpoint: &CompiledStaticCredentialEndpointBinding,
    host_labels: &[&str],
    port: u16,
    path: &str,
) -> bool {
    endpoint.port == port
        && endpoint.host.matches_normalized_labels(host_labels)
        && endpoint.path.matches(path)
}

fn merge_resolvers(
    generations: &VecDeque<Arc<SecretResolver>>,
    current_resolver: Option<&Arc<SecretResolver>>,
) -> Option<Arc<SecretResolver>> {
    SecretResolver::merge(
        generations
            .iter()
            .map(Arc::as_ref)
            .chain(current_resolver.into_iter().map(Arc::as_ref)),
    )
    .map(Arc::new)
}

impl ProviderCredentialState {
    /// Authenticated reporter binding only; a boot/session replacement invalidates
    /// old records without freeing unexpired deduplication/capacity metadata.
    pub fn bind_provider_detach_session(&self, boot: &str, session: &str) {
        let valid =
            |s: &str| uuid::Uuid::parse_str(s).is_ok_and(|id| !id.is_nil() && id.to_string() == s);
        if !valid(boot) || !valid(session) {
            return;
        }
        let mut source_gate = self.witness_gate.lock();
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");
        if !inner.provider_detach.enabled {
            return;
        }
        if inner.provider_detach.boot_id != boot || inner.provider_detach.session_id != session {
            source_gate.invalidate();
            for arm in inner.provider_detach.arms.values_mut() {
                arm.consumed = true;
                arm.result = 4;
                arm.refusal = None;
            }
            inner.provider_detach.boot_id = boot.into();
            inner.provider_detach.session_id = session.into();
        }
    }
    /// Install an exact server-delivered reservation under the current bound
    /// environment and policy generation. No network or execution occurs here.
    /// `policy_current` must be a nonblocking/nonreentrant trusted generation check.
    pub fn install_provider_detach_arm(
        &self,
        seal: &crate::proto::ProviderDetachArmSealV1,
        observation: &crate::proto::ProviderReadinessObservation,
        installation_id: &str,
        next_sequence: u64,
        now: prost_types::Timestamp,
        policy_current: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> bool {
        use prost::Message;
        let Some(q) = seal.request.as_ref() else {
            return false;
        };
        let Some(a) = q.attempt.as_ref() else {
            return false;
        };
        let Some(before) = q.original_action.as_ref().and_then(|q| q.target.as_ref()) else {
            return false;
        };
        let observation_matches = (
            a.supervisor_session.as_str(),
            a.attachment_epoch.as_str(),
            a.config_revision,
            a.provider_env_revision,
            a.native_policy_hash.as_str(),
        ) == (
            observation.session_id.as_str(),
            observation.attachment_epoch.as_str(),
            observation.config_revision,
            observation.provider_env_revision,
            observation.policy_hash.as_str(),
        );
        if seal.hold_generation == 0
            || seal.row_resource_version == 0
            || seal.install_sequence != 0
            || seal.installed_time.is_some()
            || q.encoded_len() > 8192
            || !detach_arm_time_valid(a, &now)
            || next_sequence <= observation.sequence
            || observation.sequence < a.arm_capture_sequence
            || !observation.credentials_installed
            || !observation.policy_active
            || !observation.launch_environment_installed
            || !observation_matches
            || !(policy_current)()
        {
            return false;
        }
        let mut source_gate = self.witness_gate.lock();
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");
        if !(policy_current)()
            || !inner.provider_detach.enabled
            || inner.provider_detach.boot_id != a.gateway_boot_id
            || inner.provider_detach.session_id != a.supervisor_session
            || inner.current.revision != a.provider_env_revision
            || inner.current.installation_id != installation_id
        {
            return false;
        }
        if let Some(old) = inner.provider_detach.arms.get(&q.attempt_id) {
            return old.seal == *seal; // Never renew or reinstall an original record.
        }
        source_gate.invalidate();
        let original_env_revision = before.provider_env_revision;
        let mut originals = inner
            .provider_detach
            .subjects
            .iter()
            .filter(|s| s.provider_id == a.provider_id && s.revision == original_env_revision);
        let Some(subject) = originals.next().cloned() else {
            return false;
        };
        if originals.next().is_some() {
            return false;
        }
        // A known original provider must actually be absent in this installation.
        if inner.static_credential_bindings.values().any(|b| {
            b.credential_identity
                .starts_with(&format!("{}:", a.provider_id))
        }) || !inner.body_inventory_available
            || !inner.current.dynamic_credentials.is_empty()
            || subject.keys.iter().any(|k| {
                !inner.known_static_credential_keys.contains(k)
                    || inner.current.child_env.contains_key(k)
            })
        {
            return false;
        }
        let Some(time) = detach_time_ns(&now) else {
            return false;
        };
        inner.provider_detach.arms.retain(|_, arm| {
            arm.seal
                .request
                .as_ref()
                .and_then(|q| q.attempt.as_ref())
                .and_then(|a| a.deadline.as_ref())
                .and_then(detach_time_ns)
                .is_some_and(|end| time < end)
        });
        if seal.encoded_len().saturating_add(64) > 8192 {
            return false;
        }
        let reserved = seal.encoded_len().saturating_add(64 + 4096);
        if inner.provider_detach.arms.values().any(|old| {
            !old.consumed
                && old
                    .seal
                    .request
                    .as_ref()
                    .and_then(|q| q.attempt.as_ref())
                    .is_some_and(|prior| {
                        prior.hold_id == a.hold_id
                            && prior.supervisor_session == a.supervisor_session
                    })
        }) {
            return false;
        }
        if inner.provider_detach.arms.len() >= 16
            || inner
                .provider_detach
                .arms
                .values()
                .map(|a| a.reserved_bytes)
                .sum::<usize>()
                .saturating_add(reserved)
                > 128 * 1024
        {
            return false;
        }
        inner.provider_detach.arms.insert(
            q.attempt_id.clone(),
            LocalProviderDetachArm {
                seal: seal.clone(),
                subject,
                installation_id: installation_id.into(),
                install_sequence: next_sequence,
                reported_install_time: now,
                server_install_ack: None,
                policy_current,
                consumed: false,
                result: 0,
                refusal: None,
                reserved_bytes: reserved,
                result_acknowledged: false,
            },
        );
        true
    }
    /// Original server acceptance of the install report, not a generic configACK.
    pub fn acknowledge_provider_detach_arm(
        &self,
        seal: &crate::proto::ProviderDetachArmSealV1,
    ) -> bool {
        let Some(q) = seal.request.as_ref() else {
            return false;
        };
        let Some(a) = q.attempt.as_ref() else {
            return false;
        };
        let mut source_gate = self.witness_gate.lock();
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");
        if !inner.provider_detach.enabled
            || inner.provider_detach.boot_id != a.gateway_boot_id
            || inner.provider_detach.session_id != a.supervisor_session
        {
            return false;
        }
        let Some(arm) = inner.provider_detach.arms.get_mut(&q.attempt_id) else {
            return false;
        };
        let Some(time) = seal.installed_time.as_ref().and_then(detach_time_ns) else {
            return false;
        };
        if arm.seal.request != seal.request
            || arm.seal.hold_generation != seal.hold_generation
            || arm.seal.row_resource_version != seal.row_resource_version
            || seal.install_sequence != arm.install_sequence
            || time < detach_time_ns(&arm.reported_install_time).unwrap_or(i128::MAX)
            || !(arm.policy_current)()
        {
            return false;
        }
        if let Some(old) = arm.server_install_ack.as_ref() {
            return old == seal;
        }
        if arm.server_install_ack.as_ref() != Some(seal) {
            source_gate.invalidate();
        }
        arm.server_install_ack = Some(seal.clone());
        true
    }
    /// Produce one bounded original report. Later heartbeats retain the failure
    /// sequence and times; they do not make the event fresh again.
    pub fn provider_detach_report(
        &self,
        session: &str,
        sequence: u64,
        now: &prost_types::Timestamp,
    ) -> Option<crate::proto::ProviderDetachSupervisorReportV1> {
        let mut source_gate = self.witness_gate.lock();
        let mut inner = self.inner.write().ok()?;
        if !inner.provider_detach.enabled {
            return None;
        }
        let boot = inner.provider_detach.boot_id.clone();
        let revision = inner.current.revision;
        let installation = inner.current.installation_id.clone();
        let time = detach_time_ns(now)?;
        if inner.provider_detach.arms.values().any(|arm| {
            arm.seal
                .request
                .as_ref()
                .and_then(|q| q.attempt.as_ref())
                .and_then(|a| a.deadline.as_ref())
                .and_then(detach_time_ns)
                .is_none_or(|end| time >= end)
        }) {
            source_gate.invalidate();
        }
        inner.provider_detach.arms.retain(|_, arm| {
            arm.seal
                .request
                .as_ref()
                .and_then(|q| q.attempt.as_ref())
                .and_then(|a| a.deadline.as_ref())
                .and_then(detach_time_ns)
                .is_some_and(|end| time < end)
        });
        let mut selected = None;
        for (id, arm) in &inner.provider_detach.arms {
            let a = arm.seal.request.as_ref()?.attempt.as_ref()?;
            if a.supervisor_session != session
                || a.gateway_boot_id != boot
                || a.provider_env_revision != revision
                || arm.installation_id != installation
                || !(arm.policy_current)()
            {
                continue;
            }
            let priority = if arm.server_install_ack.is_none() {
                0
            } else if arm.result != 0 && !arm.result_acknowledged {
                1
            } else if arm.result == 0 {
                2
            } else {
                3
            };
            if selected.as_ref().is_none_or(|(old, _)| priority < *old) {
                selected = Some((priority, id.clone()));
            }
        }
        if let Some((_, id)) = selected {
            let arm = inner.provider_detach.arms.get_mut(&id)?;
            let q = arm.seal.request.as_ref()?;
            let mut result = 0;
            let mut refusal = None;
            if arm.server_install_ack.is_some() && sequence > arm.install_sequence {
                result = arm.result;
                if let Some(f) = arm.refusal.as_mut() {
                    if f.sequence == 0 {
                        f.sequence = sequence;
                    }
                    refusal = Some(f.clone());
                }
            }
            return Some(crate::proto::ProviderDetachSupervisorReportV1 {
                supported: true,
                gateway_boot_id: boot,
                attempt_id: q.attempt_id.clone(),
                request_sha256: q.request_sha256.clone(),
                install_sequence: arm.install_sequence,
                installed_time: Some(arm.reported_install_time),
                result,
                refusal,
            });
        }
        Some(crate::proto::ProviderDetachSupervisorReportV1 {
            supported: true,
            gateway_boot_id: boot,
            ..Default::default()
        })
    }
    pub fn acknowledge_provider_detach_report(
        &self,
        report: &crate::proto::ProviderDetachSupervisorReportV1,
    ) {
        if report.result == 0 {
            return;
        }
        let _source_gate = self.witness_gate.lock();
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");
        if let Some(arm) = inner.provider_detach.arms.get_mut(&report.attempt_id)
            && arm.result == report.result
            && arm.refusal == report.refusal
        {
            arm.result_acknowledged = true;
        }
    }

    /// Called at the actual header-materialization boundary with the SAME scoped
    /// resolver/revision. Matching correlation spends an installed arm once;
    /// arbitrary missing references and policy denials cannot create a witness.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the actual request and scoped resolver inputs explicit at the credential boundary"
    )]
    pub fn witness_provider_detach_header(
        &self,
        attempt_id: &str,
        challenge: &str,
        authorization: &str,
        host: &str,
        port: u16,
        target: &str,
        resolver: Option<&SecretResolver>,
        captured_revision: u64,
        now: prost_types::Timestamp,
    ) -> ProviderDetachWitness {
        let mut source_gate = self.witness_gate.lock();
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");
        if !inner.provider_detach.enabled {
            return ProviderDetachWitness::NotArmed;
        }
        let Some(mut arm) = inner.provider_detach.arms.get(attempt_id).cloned() else {
            return ProviderDetachWitness::NotArmed;
        };
        let Some(q) = arm.seal.request.as_ref() else {
            return ProviderDetachWitness::NotArmed;
        };
        let Some(a) = q.attempt.as_ref() else {
            return ProviderDetachWitness::NotArmed;
        };
        if a.challenge != challenge || arm.consumed || arm.server_install_ack.is_none() {
            return ProviderDetachWitness::NotArmed;
        }
        source_gate.invalidate();
        arm.consumed = true;
        let valid = a.gateway_boot_id == inner.provider_detach.boot_id
            && a.supervisor_session == inner.provider_detach.session_id
            && detach_arm_time_valid(a, &now)
            && inner.current.revision == captured_revision
            && captured_revision == a.provider_env_revision
            && inner.current.installation_id == arm.installation_id
            && arm
                .server_install_ack
                .as_ref()
                .and_then(|s| s.installed_time.as_ref())
                .and_then(detach_time_ns)
                .is_some_and(|installed| detach_time_ns(&now).is_some_and(|n| n >= installed))
            && (arm.policy_current)()
            && inner.body_inventory_available
            && inner.current.dynamic_credentials.is_empty()
            && !inner.static_credential_bindings.values().any(|b| {
                b.credential_identity
                    .starts_with(&format!("{}:", a.provider_id))
            })
            && arm.subject.keys.iter().all(|k| {
                inner.known_static_credential_keys.contains(k)
                    && !inner.current.child_env.contains_key(k)
            });
        let outcome = if !valid {
            arm.result = 4;
            ProviderDetachWitness::Invalidated
        } else if !arm
            .subject
            .matches_original_static_bearer(authorization, host, port, target)
            || authorization.len() > 8192
        {
            arm.result = 3;
            ProviderDetachWitness::Invalidated
        } else {
            let header = format!("GET / HTTP/1.1\r\nAuthorization: {authorization}\r\n\r\n");
            match crate::secrets::rewrite_http_header_block(header.as_bytes(), resolver) {
                Ok(materialized) => {
                    drop(materialized);
                    arm.result = 2;
                    ProviderDetachWitness::NotRefused
                }
                Err(error) if error.is_endpoint_mismatch() => {
                    arm.result = 3;
                    ProviderDetachWitness::Invalidated
                }
                Err(_) => {
                    if (arm.policy_current)() {
                        arm.result = 1;
                        arm.refusal = Some(crate::proto::ProviderDetachRefusalV1 {
                            action_id: a.action_id.clone(),
                            target_sha256: a.target_sha256.clone(),
                            attempt_id: q.attempt_id.clone(),
                            challenge: a.challenge.clone(),
                            supervisor_instance: a.supervisor_instance.clone(),
                            supervisor_session: a.supervisor_session.clone(),
                            sequence: 0,
                            attachment_epoch: a.attachment_epoch.clone(),
                            configuration_instance: a.configuration_instance.clone(),
                            config_revision: a.config_revision,
                            provider_env_revision: a.provider_env_revision,
                            unavailable: true,
                            attempted_time: Some(now),
                            observed_time: Some(now),
                        });
                        ProviderDetachWitness::Unavailable
                    } else {
                        arm.result = 4;
                        ProviderDetachWitness::Invalidated
                    }
                }
            }
        };
        inner.provider_detach.arms.insert(attempt_id.into(), arm);
        outcome
    }
}

#[cfg(test)]
mod tests {
    fn witness_operation(gate: &super::WitnessLaunchGate, key: &str) -> super::WitnessOperation {
        let current = gate.snapshot();
        super::WitnessOperation {
            prepared_source_incarnation: current.source_incarnation,
            prepared_source_epoch: current.epoch,
            original_key: key.into(),
            request_sha256: "b".repeat(64),
            profile_sha256: "c".repeat(64),
            installed_arm_sha256: "d".repeat(64),
            boundary_incarnation: uuid::Uuid::new_v4().to_string(),
            prepared_ticket: uuid::Uuid::new_v4().to_string(),
            supervisor_session: uuid::Uuid::new_v4().to_string(),
            execution_id: uuid::Uuid::new_v4().to_string(),
            deadline_unix_ms: 2000,
            arm_request: vec![],
        }
    }
    #[test]
    fn witness_gate_revocation_before_commit_refuses_original() {
        let gate = super::WitnessLaunchGate::new();
        let op = witness_operation(&gate, "original");
        gate.lock().invalidate();
        assert!(gate.lock().commit(&op, 1000).is_none());
        let current = witness_operation(&gate, "fresh");
        assert!(gate.lock().commit(&current, 1000).is_some());
        assert!(gate.lock().commit(&current, 1000).is_none());
    }
    #[test]
    fn witness_gate_commit_before_revocation_keeps_original_permit_distinct() {
        let gate = super::WitnessLaunchGate::new();
        let op = witness_operation(&gate, "original");
        let permit = gate.lock().commit(&op, 1000).unwrap();
        gate.lock().invalidate();
        assert!(permit.source_epoch < gate.snapshot().epoch);
        assert!(gate.lock().commit(&op, 1000).is_none());
        // The earlier permit exists; remote cancellation is a separate fact.
        assert_eq!(permit.operation.original_key, "original");
    }
    #[test]
    fn witness_gate_restart_deadline_quota_and_overflow_never_reopen() {
        let gate = super::WitnessLaunchGate::new();
        let op = witness_operation(&gate, "original");
        let restarted = super::WitnessLaunchGate::new();
        assert!(restarted.lock().commit(&op, 1000).is_none());
        assert!(gate.lock().commit(&op, 2000).is_none());
        assert!(gate.lock().commit(&op, 1000).is_none());
        let gate = super::WitnessLaunchGate::new();
        for n in 0..16 {
            let op = witness_operation(&gate, &format!("original-{n}"));
            assert!(gate.lock().commit(&op, 1000).is_some());
        }
        let op = witness_operation(&gate, "seventeenth");
        assert!(gate.lock().commit(&op, 1000).is_none());
        {
            let mut guard = gate.lock();
            guard.state.epoch = u64::MAX;
            guard.invalidate();
        }
        assert!(gate.snapshot().disabled);
    }
    #[test]
    fn witness_gate_poison_disables_and_foreign_guard_cannot_authorize() {
        let gate = super::WitnessLaunchGate::new();
        let clone = gate.clone();
        let _ = std::thread::spawn(move || {
            let _held = clone.state.lock().unwrap();
            panic!("synthetic gate poison");
        })
        .join();
        assert!(gate.snapshot().disabled);
        let op = witness_operation(&gate, "original");
        assert!(gate.lock().commit(&op, 1000).is_none());
        let other = super::WitnessLaunchGate::new();
        assert!(!gate.lock().belongs_to(&other));
    }

    use super::*;
    use crate::google_cloud;

    #[test]
    fn body_classification_distinguishes_literal_foreign_bound_and_revoked() {
        use crate::secrets::body::BodyCredentialError;
        let state = ProviderCredentialState::from_bound_environment(
            42,
            HashMap::from([("API_KEY".into(), "test-secret".into())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".into(),
                binding("api.github.com", 443, "/allowed/**"),
            )]),
            vec![],
        )
        .unwrap();
        let token = state.snapshot().child_env["API_KEY"].clone();
        for (host, port, path) in [
            ("api.openai.com", 443, "/v1/responses"),
            ("api.github.com", 443, "/allowed/foo"),
            ("api.github.com", 444, "/allowed/foo"),
            ("api.github.com", 443, "/other"),
        ] {
            let (_, classifier, _) =
                state.resolver_and_body_classifier_for_endpoint(host, port, path);
            let classifier = classifier.unwrap();
            assert_eq!(classifier.check(&token), Ok(()));
            assert_eq!(
                classifier.check("sk-OPENSHELL-RESOLVE-ENV-v42_API_KEY"),
                Ok(())
            );
            assert_eq!(classifier.check("openshell:resolve:env:KEY"), Ok(()));
            assert_eq!(classifier.check("sk-OPENSHELL-RESOLVE-ENV-KEY"), Ok(()));
            assert_eq!(
                classifier.check("openshell:resolve:env:v999_API_KEY"),
                Err(BodyCredentialError::KnownUnavailable)
            );
            assert_eq!(
                classifier.check("openshell:resolve:env:API_KEY"),
                Err(BodyCredentialError::KnownUnavailable)
            );
            assert_eq!(
                classifier.check("openshell:resolve:env:sbroken_API_KEY"),
                Err(BodyCredentialError::KnownUnavailable)
            );
        }
        let (_, classifier, _) =
            state.resolver_and_body_classifier_for_endpoint("api.github.com", 443, "/allowed/foo");
        assert_eq!(classifier.unwrap().check(&token), Ok(()));
        assert_eq!(
            state
                .resolver_and_body_classifier_for_endpoint("api.github.com", 443, "/allowed/foo")
                .1
                .unwrap()
                .check("sk-OPENSHELL-RESOLVE-ENV-v42_API_KEY"),
            Ok(())
        );
        state.revoke_static_provider_environment(43);
        assert!(
            state
                .resolver_and_body_classifier_for_endpoint("api.openai.com", 443, "/")
                .1
                .is_none()
        );
        state
            .install_bound_environment(
                44,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                vec![],
            )
            .unwrap();
        let classifier = state
            .resolver_and_body_classifier_for_endpoint("api.openai.com", 443, "/")
            .1
            .unwrap();
        assert_eq!(
            classifier.check(&token),
            Err(BodyCredentialError::KnownUnavailable)
        );
        assert_eq!(classifier.check("openshell:resolve:env:KEY"), Ok(()));
    }

    #[test]
    fn body_classification_rejects_expired_invalid_and_replaced_credentials() {
        use crate::secrets::body::BodyCredentialError;
        for (value, expires) in [("secret", 1), ("bad\r\nvalue", 0)] {
            let state = ProviderCredentialState::from_bound_environment(
                42,
                HashMap::from([("API_KEY".into(), value.into())]),
                HashMap::from([("API_KEY".into(), expires)]),
                HashMap::new(),
                HashMap::from([("API_KEY".into(), binding("api.github.com", 443, "/**"))]),
                vec![],
            )
            .unwrap();
            let token = state.snapshot().child_env["API_KEY"].clone();
            for host in ["api.openai.com", "api.github.com"] {
                let classifier = state
                    .resolver_and_body_classifier_for_endpoint(host, 443, "/")
                    .1
                    .unwrap();
                assert_eq!(
                    classifier.check(&token),
                    Err(BodyCredentialError::KnownUnavailable)
                );
            }
        }
        let handle = "a".repeat(64);
        let state = ProviderCredentialState::from_bound_environment(
            42,
            HashMap::from([("API_KEY".into(), "secret".into())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".into(),
                stable_binding("api.github.com", 443, "/**", &handle),
            )]),
            vec![],
        )
        .unwrap();
        let token = state.snapshot().child_env["API_KEY"].clone();
        let classifier = state
            .resolver_and_body_classifier_for_endpoint("api.openai.com", 443, "/")
            .1
            .unwrap();
        assert_eq!(classifier.check(&token), Ok(()));
        assert_eq!(
            classifier.check(&token.replace(&handle, &"b".repeat(64))),
            Err(BodyCredentialError::KnownUnavailable)
        );
        state
            .install_bound_environment(
                43,
                HashMap::from([("API_KEY".into(), "new-secret".into())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "API_KEY".into(),
                    stable_binding("api.github.com", 443, "/**", &"b".repeat(64)),
                )]),
                vec![],
            )
            .unwrap();
        assert_eq!(
            state
                .resolver_and_body_classifier_for_endpoint("api.openai.com", 443, "/")
                .1
                .unwrap()
                .check(&token),
            Err(BodyCredentialError::KnownUnavailable)
        );
    }

    fn binding(host: &str, port: u32, path: &str) -> StaticCredentialBinding {
        StaticCredentialBinding {
            endpoints: vec![StaticCredentialEndpointBinding {
                host: host.to_string(),
                port,
                path: path.to_string(),
            }],
            credential_identity: "provider-a:API_KEY".to_string(),
            workload_credential_handle: String::new(),
        }
    }

    fn stable_binding(host: &str, port: u32, path: &str, handle: &str) -> StaticCredentialBinding {
        let mut binding = binding(host, port, path);
        binding.credential_identity = format!("refresh:{handle}");
        binding.workload_credential_handle = handle.to_string();
        binding
    }

    fn assert_binding_validation_error(
        env: HashMap<String, String>,
        bindings: HashMap<String, StaticCredentialBinding>,
        non_secret_environment_keys: Vec<String>,
        expected: &str,
    ) {
        let error =
            compile_static_credential_bindings(&env, bindings, &non_secret_environment_keys)
                .expect_err("malformed provider metadata must fail validation");
        assert_eq!(error.to_string(), expected);
    }

    #[test]
    fn rejects_each_malformed_static_credential_binding_shape() {
        let credential_env = || HashMap::from([("API_KEY".to_string(), "secret".to_string())]);
        let credential_binding = || {
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/**"),
            )])
        };

        assert_binding_validation_error(
            HashMap::from([("PROJECT_ID".to_string(), "project".to_string())]),
            HashMap::new(),
            vec!["PROJECT_ID".to_string(), "PROJECT_ID".to_string()],
            "provider environment repeats a non-secret environment key",
        );
        assert_binding_validation_error(
            credential_env(),
            credential_binding(),
            vec!["API_KEY".to_string()],
            "provider environment classifies a key as both credential and non-secret configuration",
        );
        assert_binding_validation_error(
            credential_env(),
            HashMap::new(),
            Vec::new(),
            "provider environment contains an unclassified credential key",
        );
        assert_binding_validation_error(
            HashMap::new(),
            credential_binding(),
            Vec::new(),
            "provider environment metadata references a missing environment key",
        );

        let mut missing_identity = binding("api.example.com", 443, "/**");
        missing_identity.credential_identity.clear();
        assert_binding_validation_error(
            credential_env(),
            HashMap::from([("API_KEY".to_string(), missing_identity)]),
            Vec::new(),
            "static credential binding has no provider credential identity",
        );

        let mut missing_endpoints = binding("api.example.com", 443, "/**");
        missing_endpoints.endpoints.clear();
        assert_binding_validation_error(
            credential_env(),
            HashMap::from([("API_KEY".to_string(), missing_endpoints)]),
            Vec::new(),
            "static credential binding has no authorized endpoints",
        );

        let mut invalid_handle = binding("api.example.com", 443, "/**");
        invalid_handle.workload_credential_handle = "not-an-opaque-handle".to_string();
        assert_binding_validation_error(
            credential_env(),
            HashMap::from([("API_KEY".to_string(), invalid_handle)]),
            Vec::new(),
            "static credential binding has an invalid workload credential handle",
        );

        for (host, port) in [
            ("api.example.com", 0),
            ("api.example.com", u32::from(u16::MAX) + 1),
            ("invalid host", 443),
        ] {
            assert_binding_validation_error(
                credential_env(),
                HashMap::from([("API_KEY".to_string(), binding(host, port, "/**"))]),
                Vec::new(),
                "static credential binding contains an invalid endpoint",
            );
        }
    }

    #[test]
    fn bound_credentials_resolve_only_at_matching_endpoint() {
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("*.example.com", 443, "/v1/**"),
            )]),
            Vec::new(),
        )
        .expect("valid bindings");
        let placeholder = "openshell:resolve:env:v7_API_KEY";

        let allowed = state
            .resolver_for_endpoint("api.example.com", 443, "/v1/messages?stream=true")
            .expect("resolver");
        assert_eq!(allowed.resolve_placeholder(placeholder), Some("secret"));

        for (host, port, path) in [
            ("example.com", 443, "/v1/messages"),
            ("api.example.com", 80, "/v1/messages"),
            ("api.example.com", 443, "/v2/messages"),
        ] {
            let denied = state
                .resolver_for_endpoint(host, port, path)
                .expect("resolver");
            let error = denied
                .rewrite_header_value(placeholder)
                .expect_err("endpoint mismatch must fail closed");
            assert!(error.is_endpoint_mismatch(), "{host}:{port}{path}");
        }
    }

    #[test]
    fn multiple_credentials_resolve_only_at_their_own_endpoints() {
        let mut binding_a = binding("a.example.com", 443, "/a/**");
        binding_a.credential_identity = "provider-a:KEY_A".to_string();
        let mut binding_b = binding("b.example.com", 443, "/b/**");
        binding_b.credential_identity = "provider-b:KEY_B".to_string();
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([
                ("KEY_A".to_string(), "secret-a".to_string()),
                ("KEY_B".to_string(), "secret-b".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                ("KEY_A".to_string(), binding_a),
                ("KEY_B".to_string(), binding_b),
            ]),
            Vec::new(),
        )
        .expect("valid bindings");

        let resolver_a = state
            .resolver_for_endpoint("a.example.com", 443, "/a/check")
            .expect("endpoint A resolver");
        assert_eq!(
            resolver_a.resolve_placeholder("openshell:resolve:env:v7_KEY_A"),
            Some("secret-a")
        );
        assert_eq!(
            resolver_a.resolve_placeholder("openshell:resolve:env:v7_KEY_B"),
            None,
            "credential B must not resolve at endpoint A"
        );

        let resolver_b = state
            .resolver_for_endpoint("b.example.com", 443, "/b/check")
            .expect("endpoint B resolver");
        assert_eq!(
            resolver_b.resolve_placeholder("openshell:resolve:env:v7_KEY_B"),
            Some("secret-b")
        );
        assert_eq!(
            resolver_b.resolve_placeholder("openshell:resolve:env:v7_KEY_A"),
            None,
            "credential A must not resolve at endpoint B"
        );
    }

    #[test]
    fn refresh_replaces_compiled_endpoint_patterns() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("old.example.com", 443, "/v1/**"),
            )]),
            Vec::new(),
        )
        .expect("initial bindings");

        state
            .install_bound_environment(
                2,
                HashMap::from([("API_KEY".to_string(), "new".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "API_KEY".to_string(),
                    binding("new.example.com", 443, "/v2/**"),
                )]),
                Vec::new(),
            )
            .expect("replacement bindings");

        let replacement = state
            .resolver_for_endpoint("new.example.com", 443, "/v2/messages")
            .expect("replacement endpoint resolver");
        assert_eq!(
            replacement.resolve_placeholder("openshell:resolve:env:v2_API_KEY"),
            Some("new")
        );

        let removed = state
            .resolver_for_endpoint("old.example.com", 443, "/v1/messages")
            .expect("restricted resolver");
        let error = removed
            .rewrite_header_value("openshell:resolve:env:v2_API_KEY")
            .expect_err("replaced endpoint binding must no longer authorize the credential");
        assert!(error.is_endpoint_mismatch());
    }

    #[test]
    fn revisioned_path_placeholder_matches_exact_redacted_binding() {
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/bot[CREDENTIAL]/sendMessage"),
            )]),
            Vec::new(),
        )
        .expect("valid bindings");
        let placeholder = "openshell:resolve:env:v7_API_KEY";

        let resolver = state
            .resolver_for_endpoint(
                "api.example.com",
                443,
                &format!("/bot{placeholder}/sendMessage?stream=true"),
            )
            .expect("syntax-redacted path should select the binding");
        assert_eq!(resolver.resolve_placeholder(placeholder), Some("secret"));
    }

    #[test]
    fn provider_alias_path_placeholder_matches_glob_redacted_binding() {
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/v1/*/messages"),
            )]),
            Vec::new(),
        )
        .expect("valid bindings");

        let resolver = state
            .resolver_for_endpoint(
                "api.example.com",
                443,
                "/v1/vendor-OPENSHELL-RESOLVE-ENV-API_KEY/messages",
            )
            .expect("syntax-redacted alias path should select the binding");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v7_API_KEY"),
            Some("secret")
        );
    }

    #[test]
    fn malformed_path_placeholder_exposes_no_endpoint_resolver() {
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/**"),
            )]),
            Vec::new(),
        )
        .expect("valid bindings");

        assert!(
            state
                .resolver_for_endpoint(
                    "api.example.com",
                    443,
                    "/v1/openshell:resolve:env:/messages",
                )
                .is_none(),
            "malformed placeholder syntax must fail closed before path matching"
        );
    }

    #[test]
    fn non_secret_provider_config_is_not_endpoint_scoped() {
        let state = ProviderCredentialState::from_bound_environment(
            3,
            HashMap::from([("GCP_PROJECT_ID".to_string(), "project".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            vec!["GCP_PROJECT_ID".to_string()],
        )
        .expect("classified non-secret environment");
        let resolver = state
            .resolver_for_endpoint("unrelated.example", 1234, "/")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v3_GCP_PROJECT_ID"),
            Some("project")
        );
    }

    #[test]
    fn incomplete_refresh_revokes_previous_credentials_atomically() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/**"),
            )]),
            Vec::new(),
        )
        .expect("initial bindings");

        let dynamic_credentials = HashMap::from([(
            "dynamic".to_string(),
            crate::proto::ProviderProfileCredential::default(),
        )]);
        let result = state.install_bound_environment(
            2,
            HashMap::from([("API_KEY".to_string(), "new".to_string())]),
            HashMap::new(),
            dynamic_credentials,
            HashMap::new(),
            Vec::new(),
        );
        assert!(result.is_err());
        assert!(state.snapshot().child_env.is_empty());
        assert!(state.resolver().is_none());
        assert!(state.snapshot().dynamic_credentials.contains_key("dynamic"));

        state
            .install_bound_environment(
                3,
                HashMap::from([("API_KEY".to_string(), "recovered".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "API_KEY".to_string(),
                    binding("api.example.com", 443, "/**"),
                )]),
                Vec::new(),
            )
            .expect("same-identity recovery");

        let resolver = state
            .resolver_for_endpoint("api.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v1_API_KEY"),
            Some("recovered"),
            "a metadata failure must not permanently strand placeholders from the same provider identity"
        );
    }

    #[test]
    fn failed_fetch_revokes_secrets_then_same_identity_retry_recovers_running_placeholder() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/**"),
            )]),
            Vec::new(),
        )
        .expect("initial bindings");

        state.revoke_static_provider_environment(2);

        assert!(
            state.resolver().is_none(),
            "no static secret resolver may remain active during the failed refresh"
        );
        assert!(
            state
                .resolver_for_endpoint("api.example.com", 443, "/v1")
                .is_none(),
            "an identity tombstone must not authorize requests without active bindings and secrets"
        );

        state
            .install_bound_environment(
                3,
                HashMap::from([("API_KEY".to_string(), "new".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "API_KEY".to_string(),
                    binding("api.example.com", 443, "/**"),
                )]),
                Vec::new(),
            )
            .expect("same-identity retry");

        let resolver = state
            .resolver_for_endpoint("api.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v1_API_KEY"),
            Some("new"),
            "the running process placeholder should recover against the current same-identity secret"
        );
    }

    #[test]
    fn retained_generation_survives_rotation_of_same_provider_credential() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/**"),
            )]),
            Vec::new(),
        )
        .expect("initial bindings");

        state
            .install_bound_environment(
                2,
                HashMap::from([("API_KEY".to_string(), "new".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "API_KEY".to_string(),
                    binding("api.example.com", 443, "/**"),
                )]),
                Vec::new(),
            )
            .expect("rotated bindings");

        let resolver = state
            .resolver_for_endpoint("api.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v1_API_KEY"),
            Some("old")
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v2_API_KEY"),
            Some("new")
        );
    }

    #[test]
    fn stable_handle_resolves_current_token_after_initial_token_expires() {
        let handle = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_millis(),
        )
        .expect("current time fits i64");
        let binding = stable_binding("api.example.com", 443, "/**", handle);
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "expired".to_string())]),
            HashMap::from([("API_KEY".to_string(), now_ms - 1)]),
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), binding.clone())]),
            Vec::new(),
        )
        .expect("initial stable binding");
        let workload_placeholder = state.snapshot().child_env["API_KEY"].clone();
        assert!(workload_placeholder.contains(handle));
        assert_eq!(
            state
                .resolver_for_endpoint("api.example.com", 443, "/v1")
                .expect("resolver")
                .resolve_placeholder(&workload_placeholder),
            None,
            "the expired access token must fail closed"
        );

        state
            .install_bound_environment(
                2,
                HashMap::from([("API_KEY".to_string(), "current".to_string())]),
                HashMap::from([("API_KEY".to_string(), now_ms + 60_000)]),
                HashMap::new(),
                HashMap::from([("API_KEY".to_string(), binding)]),
                Vec::new(),
            )
            .expect("refreshed stable binding");

        assert_eq!(state.snapshot().child_env["API_KEY"], workload_placeholder);
        let resolver = state
            .resolver_for_endpoint("api.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder(&workload_placeholder),
            Some("current")
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v2_API_KEY"),
            None,
            "refresh-managed credentials must not expose revision aliases"
        );
    }

    #[test]
    fn stable_handle_survives_twelve_rotations_and_state_reconstruction() {
        let handle = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let binding = stable_binding("api.example.com", 443, "/**", handle);
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "token-1".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), binding.clone())]),
            Vec::new(),
        )
        .expect("initial stable binding");
        let workload_placeholder = state.snapshot().child_env["API_KEY"].clone();

        for revision in 2..=13 {
            let token = format!("token-{revision}");
            state
                .install_bound_environment(
                    revision,
                    HashMap::from([("API_KEY".to_string(), token.clone())]),
                    HashMap::new(),
                    HashMap::new(),
                    HashMap::from([("API_KEY".to_string(), binding.clone())]),
                    Vec::new(),
                )
                .expect("same-epoch rotation");
            assert_eq!(state.snapshot().child_env["API_KEY"], workload_placeholder);
            assert_eq!(
                state
                    .resolver_for_endpoint("api.example.com", 443, "/v1")
                    .expect("resolver")
                    .resolve_placeholder(&workload_placeholder),
                Some(token.as_str())
            );
        }

        let reconstructed = ProviderCredentialState::from_bound_environment(
            14,
            HashMap::from([("API_KEY".to_string(), "token-14".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), binding)]),
            Vec::new(),
        )
        .expect("reconstructed network supervisor state");
        assert_eq!(
            reconstructed.snapshot().child_env["API_KEY"],
            workload_placeholder
        );
        assert_eq!(
            reconstructed
                .resolver_for_endpoint("api.example.com", 443, "/v1")
                .expect("resolver")
                .resolve_placeholder(&workload_placeholder),
            Some("token-14")
        );
    }

    #[test]
    fn authorization_epoch_or_endpoint_change_revokes_stable_handle() {
        let old_handle = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let new_handle = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                stable_binding("old.example.com", 443, "/v1/**", old_handle),
            )]),
            Vec::new(),
        )
        .expect("old authorization");
        let old_placeholder = state.snapshot().child_env["API_KEY"].clone();

        state
            .install_bound_environment(
                2,
                HashMap::from([("API_KEY".to_string(), "new".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "API_KEY".to_string(),
                    stable_binding("new.example.com", 443, "/v2/**", new_handle),
                )]),
                Vec::new(),
            )
            .expect("replacement authorization");

        let current = state
            .resolver_for_endpoint("new.example.com", 443, "/v2/messages")
            .expect("current resolver");
        assert_eq!(current.resolve_placeholder(&old_placeholder), None);
        assert_eq!(
            current.resolve_placeholder(&state.snapshot().child_env["API_KEY"]),
            Some("new")
        );
        let wrong_endpoint = state
            .resolver_for_endpoint("old.example.com", 443, "/v1/messages")
            .expect("endpoint-scoped resolver");
        let error = wrong_endpoint
            .rewrite_header_value(&state.snapshot().child_env["API_KEY"])
            .expect_err("new handle must not resolve at the old endpoint");
        assert!(error.is_endpoint_mismatch());
    }

    #[test]
    fn aged_generation_falls_back_across_non_monotonic_same_identity_rotations() {
        let state = ProviderCredentialState::from_bound_environment(
            50,
            HashMap::from([("API_KEY".to_string(), "secret-50".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/**"),
            )]),
            Vec::new(),
        )
        .expect("initial bindings");

        for revision in [10, 100, 9, 101, 8, 102, 7, 103, 6] {
            state
                .install_bound_environment(
                    revision,
                    HashMap::from([("API_KEY".to_string(), format!("secret-{revision}"))]),
                    HashMap::new(),
                    HashMap::new(),
                    HashMap::from([(
                        "API_KEY".to_string(),
                        binding("api.example.com", 443, "/**"),
                    )]),
                    Vec::new(),
                )
                .expect("rotated bindings");
        }

        let resolver = state
            .resolver_for_endpoint("api.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v50_API_KEY"),
            Some("secret-6"),
            "an aged-out placeholder may use the current secret across revisions in both numeric directions while its provider identity is unchanged"
        );
    }

    #[test]
    fn replacing_provider_with_reused_key_purges_retained_generation() {
        let state = ProviderCredentialState::from_bound_environment(
            u64::MAX,
            HashMap::from([("API_KEY".to_string(), "provider-a-secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), binding("a.example.com", 443, "/**"))]),
            Vec::new(),
        )
        .expect("initial bindings");
        let mut replacement_binding = binding("b.example.com", 443, "/**");
        replacement_binding.credential_identity = "provider-b:API_KEY".to_string();

        state
            .install_bound_environment(
                1,
                HashMap::from([("API_KEY".to_string(), "provider-b-secret".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([("API_KEY".to_string(), replacement_binding)]),
                Vec::new(),
            )
            .expect("replacement bindings");

        let resolver = state
            .resolver_for_endpoint("b.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder(&format!("openshell:resolve:env:v{}_API_KEY", u64::MAX)),
            None,
            "an opaque revision from another provider identity must fail closed even when it is numerically greater"
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:API_KEY"),
            None,
            "an identityless canonical placeholder must not resolve a replacement provider"
        );
        assert_eq!(
            resolver.resolve_placeholder("vendor-OPENSHELL-RESOLVE-ENV-API_KEY"),
            None,
            "an identityless provider alias must not resolve a replacement provider"
        );
        assert_eq!(
            resolver
                .resolve_current_env_key_checked("API_KEY", "trusted-transform")
                .expect("binding authorizes the endpoint"),
            Some("provider-b-secret"),
            "trusted supervisor transforms may select the current bound credential by key"
        );
    }

    #[test]
    fn failed_refresh_then_replacement_with_reused_key_rejects_old_placeholder() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "provider-a-secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), binding("a.example.com", 443, "/**"))]),
            Vec::new(),
        )
        .expect("initial bindings");
        state.revoke_static_provider_environment(2);

        let mut replacement_binding = binding("b.example.com", 443, "/**");
        replacement_binding.credential_identity = "provider-b:API_KEY".to_string();
        state
            .install_bound_environment(
                3,
                HashMap::from([("API_KEY".to_string(), "provider-b-secret".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([("API_KEY".to_string(), replacement_binding)]),
                Vec::new(),
            )
            .expect("replacement bindings");

        let resolver = state
            .resolver_for_endpoint("b.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v1_API_KEY"),
            None,
            "a placeholder issued before detach must not resolve to a replacement provider"
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:API_KEY"),
            None,
            "an identityless canonical placeholder must not cross a failed refresh into a replacement identity"
        );
        assert_eq!(
            resolver.resolve_placeholder("vendor-OPENSHELL-RESOLVE-ENV-API_KEY"),
            None,
            "an identityless provider alias must not cross a failed refresh into a replacement identity"
        );
    }

    #[test]
    fn successful_empty_environment_clears_failed_refresh_identity_tombstones() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "provider-a-secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), binding("a.example.com", 443, "/**"))]),
            Vec::new(),
        )
        .expect("initial bindings");

        state.revoke_static_provider_environment(2);
        state
            .install_bound_environment(
                3,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
            )
            .expect("successful detached environment");
        state
            .install_bound_environment(
                4,
                HashMap::from([("API_KEY".to_string(), "reattached".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([("API_KEY".to_string(), binding("a.example.com", 443, "/**"))]),
                Vec::new(),
            )
            .expect("reattached environment");

        let resolver = state
            .resolver_for_endpoint("a.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v1_API_KEY"),
            None,
            "a successful empty environment represents detach and must invalidate old membership"
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v4_API_KEY"),
            Some("reattached")
        );
    }

    #[test]
    fn snapshots_use_revision_scoped_placeholders() {
        let state = ProviderCredentialState::from_environment(
            10,
            HashMap::from([("GITHUB_TOKEN".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );
        let first = state.snapshot();
        assert_eq!(
            first.child_env.get("GITHUB_TOKEN").map(String::as_str),
            Some("openshell:resolve:env:v10_GITHUB_TOKEN")
        );

        state.install_environment(
            11,
            HashMap::from([("GITHUB_TOKEN".to_string(), "new".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );
        let second = state.snapshot();
        assert_eq!(
            second.child_env.get("GITHUB_TOKEN").map(String::as_str),
            Some("openshell:resolve:env:v11_GITHUB_TOKEN")
        );

        let resolver = state.resolver().expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v10_GITHUB_TOKEN"),
            Some("old")
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v11_GITHUB_TOKEN"),
            Some("new")
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:GITHUB_TOKEN"),
            Some("new")
        );
        assert_eq!(
            resolver.resolve_placeholder("provider-OPENSHELL-RESOLVE-ENV-GITHUB_TOKEN"),
            Some("new")
        );
    }

    #[test]
    fn empty_refresh_removes_current_aliases_but_retains_revisioned_resolver() {
        let state = ProviderCredentialState::from_environment(
            10,
            HashMap::from([("GITHUB_TOKEN".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );

        state.install_environment(11, HashMap::new(), HashMap::new(), HashMap::new());

        assert!(state.snapshot().child_env.is_empty());
        let resolver = state.resolver().expect("old resolver retained");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v10_GITHUB_TOKEN"),
            Some("old")
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:GITHUB_TOKEN"),
            None
        );
        assert_eq!(
            resolver.resolve_placeholder("provider-OPENSHELL-RESOLVE-ENV-GITHUB_TOKEN"),
            None
        );
    }

    #[test]
    fn expired_retained_generation_does_not_resolve() {
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let state = ProviderCredentialState::from_environment(
            10,
            HashMap::from([("GITHUB_TOKEN".to_string(), "old".to_string())]),
            HashMap::from([("GITHUB_TOKEN".to_string(), now_ms - 1_000)]),
            HashMap::new(),
        );

        state.install_environment(
            11,
            HashMap::from([("GITHUB_TOKEN".to_string(), "new".to_string())]),
            HashMap::from([("GITHUB_TOKEN".to_string(), now_ms + 60_000)]),
            HashMap::new(),
        );

        let resolver = state.resolver().expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v10_GITHUB_TOKEN"),
            None
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v11_GITHUB_TOKEN"),
            Some("new")
        );
    }

    #[test]
    fn child_env_with_gcp_resolved_without_gcp_returns_unchanged() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([("GITHUB_TOKEN".to_string(), "ghp_abc".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );
        let env = state.child_env_with_gcp_resolved();
        assert_eq!(
            env.get("GITHUB_TOKEN").map(String::as_str),
            Some("openshell:resolve:env:v1_GITHUB_TOKEN"),
            "non-GCP env should remain as placeholder"
        );
        assert!(!env.contains_key("GCE_METADATA_HOST"));
        assert!(!env.contains_key("CLAUDE_CODE_USE_VERTEX"));
    }

    #[test]
    fn child_env_resolves_provider_file_path_but_keeps_credentials_placeholderized() {
        let path = "/run/openshell/providers/acme/client.toml";
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([
                ("ACME_CONFIG_FILE".to_string(), path.to_string()),
                ("ACME_TOKEN".to_string(), "secret-token".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "ACME_TOKEN".to_string(),
                binding("api.acme.example", 443, "/**"),
            )]),
            vec!["ACME_CONFIG_FILE".to_string()],
        )
        .expect("classified provider environment");

        let env = state.child_env_with_gcp_resolved();
        assert_eq!(env.get("ACME_CONFIG_FILE").map(String::as_str), Some(path));
        assert_eq!(
            env.get("ACME_TOKEN").map(String::as_str),
            Some("openshell:resolve:env:v1_ACME_TOKEN")
        );
    }

    #[test]
    fn child_env_with_gcp_resolved_overrides_gcp_static_vars() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([
                ("GCE_METADATA_HOST".to_string(), "marker".to_string()),
                (
                    "GCP_ADC_ACCESS_TOKEN".to_string(),
                    "ya29.secret".to_string(),
                ),
                ("GCP_PROJECT_ID".to_string(), "my-project".to_string()),
                ("CLOUD_ML_REGION".to_string(), "us-central1".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "GCP_ADC_ACCESS_TOKEN".to_string(),
                binding("oauth2.googleapis.com", 443, "/**"),
            )]),
            vec![
                "GCE_METADATA_HOST".to_string(),
                "GCP_PROJECT_ID".to_string(),
                "CLOUD_ML_REGION".to_string(),
            ],
        )
        .expect("classified GCP environment");
        let env = state.child_env_with_gcp_resolved();

        assert_eq!(
            env.get("GCE_METADATA_HOST").map(String::as_str),
            Some(google_cloud::METADATA_LOOPBACK_ADDR),
            "GCE_METADATA_HOST should be the loopback address"
        );
        assert!(
            !env.contains_key("CLAUDE_CODE_USE_VERTEX"),
            "inference-specific vars should not be injected"
        );
        assert_eq!(
            env.get("GCP_PROJECT_ID").map(String::as_str),
            Some("my-project"),
            "static config should be resolved to real value"
        );
        assert_eq!(
            env.get("CLOUD_ML_REGION").map(String::as_str),
            Some("us-central1"),
        );

        let token = env.get("GCP_ADC_ACCESS_TOKEN").map(String::as_str).unwrap();
        assert!(
            token.starts_with("openshell:resolve:env:"),
            "GCP_ACCESS_TOKEN must stay as placeholder, got: {token}"
        );
    }

    #[test]
    fn child_env_with_gcp_resolved_handles_missing_config_keys() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([
                ("GCE_METADATA_HOST".to_string(), "marker".to_string()),
                ("GCP_ADC_ACCESS_TOKEN".to_string(), "ya29.tok".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "GCP_ADC_ACCESS_TOKEN".to_string(),
                binding("oauth2.googleapis.com", 443, "/**"),
            )]),
            vec!["GCE_METADATA_HOST".to_string()],
        )
        .expect("classified GCP environment");
        let env = state.child_env_with_gcp_resolved();

        assert_eq!(
            env.get("GCE_METADATA_HOST").map(String::as_str),
            Some(google_cloud::METADATA_LOOPBACK_ADDR),
        );
        assert!(
            !env.contains_key("GCP_PROJECT_ID")
                || env
                    .get("GCP_PROJECT_ID")
                    .unwrap()
                    .starts_with("openshell:resolve:env:"),
            "missing config key should not be injected with a real value"
        );
    }

    #[test]
    fn gcp_token_response_returns_sa_over_adc() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([
                ("GCP_SA_ACCESS_TOKEN".to_string(), "sa-tok".to_string()),
                ("GCP_ADC_ACCESS_TOKEN".to_string(), "adc-tok".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
        );
        let (placeholder, _) = state.gcp_token_response().expect("should find token");
        assert_eq!(
            placeholder, "openshell:resolve:env:v1_GCP_SA_ACCESS_TOKEN",
            "metadata must return the current revision-scoped SA placeholder"
        );
    }

    #[test]
    fn gcp_token_response_falls_back_to_adc() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), "adc-tok".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );
        let (placeholder, _) = state.gcp_token_response().expect("should find ADC token");
        assert_eq!(
            placeholder, "openshell:resolve:env:v1_GCP_ADC_ACCESS_TOKEN",
            "metadata must return the current revision-scoped ADC placeholder"
        );
    }

    #[test]
    fn gcp_token_response_returns_none_without_gcp() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([("GITHUB_TOKEN".to_string(), "ghp_abc".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );
        assert!(state.gcp_token_response().is_none());
    }

    #[test]
    fn gcp_token_response_defaults_expires_in_to_3600() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), "adc-tok".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );
        let (_, expires_in) = state.gcp_token_response().unwrap();
        assert_eq!(
            expires_in, 3600,
            "should default to 3600 when no expiry set"
        );
    }

    #[test]
    fn gcp_token_response_calculates_remaining() {
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), "adc-tok".to_string())]),
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), now_ms + 120_000)]),
            HashMap::new(),
        );
        let (_, expires_in) = state.gcp_token_response().unwrap();
        assert!(
            (110..=120).contains(&expires_in),
            "expected ~120s remaining, got {expires_in}"
        );
    }

    #[test]
    fn gcp_token_response_handles_already_expired_token_without_panic() {
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), "adc-tok".to_string())]),
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), now_ms - 1_000)]),
            HashMap::new(),
        );
        assert!(
            state.gcp_token_response().is_none(),
            "expired token should be skipped rather than panic"
        );
    }

    #[test]
    fn child_env_with_gcp_resolved_resolves_vertex_vars_without_metadata_host() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([
                ("GOOSE_PROVIDER".to_string(), "gcp_vertex_ai".to_string()),
                (
                    "ANTHROPIC_VERTEX_PROJECT_ID".to_string(),
                    "my-vertex-proj".to_string(),
                ),
                ("VERTEX_LOCATION".to_string(), "us-east4".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            vec![
                "GOOSE_PROVIDER".to_string(),
                "ANTHROPIC_VERTEX_PROJECT_ID".to_string(),
                "VERTEX_LOCATION".to_string(),
            ],
        )
        .expect("classified Vertex environment");
        let env = state.child_env_with_gcp_resolved();
        assert_eq!(
            env.get("GOOSE_PROVIDER").map(String::as_str),
            Some("gcp_vertex_ai"),
            "GOOSE_PROVIDER should be resolved to real value"
        );
        assert_eq!(
            env.get("ANTHROPIC_VERTEX_PROJECT_ID").map(String::as_str),
            Some("my-vertex-proj"),
        );
        assert_eq!(
            env.get("VERTEX_LOCATION").map(String::as_str),
            Some("us-east4"),
        );
        assert!(
            !env.contains_key("GCE_METADATA_IP"),
            "metadata synthetic vars should not be injected without GCE_METADATA_HOST"
        );
    }

    #[test]
    fn child_env_with_gcp_resolved_only_unwraps_explicitly_non_secret_config() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([
                (
                    "GOOGLE_CLOUD_PROJECT".to_string(),
                    "initial-project-config".to_string(),
                ),
                (
                    "GCP_PROJECT_ID".to_string(),
                    "visible-project-config".to_string(),
                ),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            vec![
                "GOOGLE_CLOUD_PROJECT".to_string(),
                "GCP_PROJECT_ID".to_string(),
            ],
        )
        .expect("classified GCP environment");

        state
            .install_bound_environment(
                2,
                HashMap::from([
                    (
                        "GOOGLE_CLOUD_PROJECT".to_string(),
                        "bound-project-secret".to_string(),
                    ),
                    (
                        "GCP_PROJECT_ID".to_string(),
                        "visible-project-config".to_string(),
                    ),
                ]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "GOOGLE_CLOUD_PROJECT".to_string(),
                    binding("example.googleapis.com", 443, "/**"),
                )]),
                vec!["GCP_PROJECT_ID".to_string()],
            )
            .expect("refreshed GCP environment");

        let env = state.child_env_with_gcp_resolved();
        assert_eq!(
            env.get("GCP_PROJECT_ID").map(String::as_str),
            Some("visible-project-config"),
            "explicitly non-secret GCP config should be visible to the workload"
        );
        assert_eq!(
            env.get("GOOGLE_CLOUD_PROJECT").map(String::as_str),
            Some("openshell:resolve:env:v2_GOOGLE_CLOUD_PROJECT"),
            "a reserved GCP name classified as a bound credential must stay placeholderized"
        );
    }

    #[test]
    fn prepared_install_retains_placeholders_for_same_provider_identity() {
        let make_state = |revision, secret: &str| {
            ProviderCredentialState::from_bound_environment(
                revision,
                HashMap::from([("API_KEY".to_string(), secret.to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "API_KEY".to_string(),
                    binding("api.example.com", 443, "/**"),
                )]),
                Vec::new(),
            )
            .unwrap()
        };
        let live = make_state(1, "first-secret");
        let old_placeholder = live.snapshot().child_env["API_KEY"].clone();
        live.install_prepared(&make_state(2, "second-secret"));
        let resolver = live
            .resolver_for_endpoint("api.example.com", 443, "/")
            .unwrap();
        assert_eq!(
            resolver.resolve_placeholder(&old_placeholder),
            Some("first-secret")
        );
        assert_eq!(
            resolver.resolve_placeholder(&live.snapshot().child_env["API_KEY"]),
            Some("second-secret"),
        );
    }

    #[test]
    fn prepared_install_restores_body_inventory_after_revocation() {
        let live = ProviderCredentialState::from_environment(
            1,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );
        live.revoke_static_provider_environment(2);
        assert!(!live.inner.read().unwrap().body_inventory_available);
        let candidate = ProviderCredentialState::from_bound_environment(
            3,
            HashMap::from([("NEW_KEY".to_string(), "secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "NEW_KEY".to_string(),
                binding("api.example.com", 443, "/**"),
            )]),
            Vec::new(),
        )
        .unwrap();
        live.install_prepared(&candidate);
        let inner = live.inner.read().unwrap();
        assert!(inner.body_inventory_available);
        assert!(inner.known_body_keys.contains("NEW_KEY"));
    }

    #[test]
    fn prepared_install_preserves_suppression_and_rejects_replaced_identity() {
        let make_state = |revision, identity: &str, secret: &str| {
            let mut binding = binding("api.example.com", 443, "/**");
            binding.credential_identity = identity.to_string();
            ProviderCredentialState::from_bound_environment(
                revision,
                HashMap::from([("API_KEY".to_string(), secret.to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([("API_KEY".to_string(), binding)]),
                Vec::new(),
            )
            .unwrap()
        };
        let live = make_state(1, "first:API_KEY", "first-secret");
        let observer = live.clone();
        let old_placeholder = live.snapshot().child_env["API_KEY"].clone();
        live.remove_env_key("API_KEY");
        let candidate = make_state(2, "second:API_KEY", "second-secret");
        live.install_prepared(&candidate);
        assert_eq!(observer.snapshot().revision, 2);
        assert!(!observer.snapshot().child_env.contains_key("API_KEY"));
        let resolver = observer
            .resolver_for_endpoint("api.example.com", 443, "/")
            .unwrap();
        assert!(resolver.resolve_placeholder(&old_placeholder).is_none());
    }

    #[test]
    fn suppressed_keys_survive_install_environment() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([
                ("GCE_METADATA_HOST".to_string(), "marker".to_string()),
                ("GCP_ADC_ACCESS_TOKEN".to_string(), "tok".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
        );
        state.remove_env_key("GCE_METADATA_HOST");
        assert!(!state.snapshot().child_env.contains_key("GCE_METADATA_HOST"));

        state.install_environment(
            2,
            HashMap::from([
                ("GCE_METADATA_HOST".to_string(), "marker".to_string()),
                ("GCP_ADC_ACCESS_TOKEN".to_string(), "tok2".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
        );
        assert!(
            !state.snapshot().child_env.contains_key("GCE_METADATA_HOST"),
            "suppressed key must not reappear after install_environment"
        );
    }

    #[test]
    fn child_env_snapshot_install_updates_env_without_resolver_material() {
        let state = ProviderCredentialState::from_child_env_snapshot(
            1,
            HashMap::from([
                ("GITHUB_TOKEN".to_string(), "old".to_string()),
                ("GCE_METADATA_HOST".to_string(), "marker".to_string()),
            ]),
        );
        state.remove_env_key("GCE_METADATA_HOST");

        let env_count = state.install_child_env_snapshot(
            2,
            HashMap::from([
                ("GITHUB_TOKEN".to_string(), "new".to_string()),
                ("GCE_METADATA_HOST".to_string(), "marker".to_string()),
            ]),
        );

        let snapshot = state.snapshot();
        assert_eq!(snapshot.revision, 2);
        assert_eq!(env_count, 1);
        assert_eq!(
            snapshot.child_env.get("GITHUB_TOKEN").map(String::as_str),
            Some("new")
        );
        assert!(!snapshot.child_env.contains_key("GCE_METADATA_HOST"));
        assert!(
            state.resolver().is_none(),
            "child-env snapshots must not install provider resolver material"
        );
    }

    #[test]
    fn child_env_snapshot_update_uses_opaque_revision_cas() {
        let state = ProviderCredentialState::from_child_env_snapshot(
            4,
            HashMap::from([("TOKEN".to_string(), "four".to_string())]),
        );

        assert_eq!(
            state
                .compare_and_install_child_env_snapshot(
                    4,
                    6,
                    HashMap::from([("TOKEN".to_string(), "six".to_string())]),
                )
                .unwrap(),
            6
        );
        assert_eq!(
            state
                .compare_and_install_child_env_snapshot(
                    4,
                    5,
                    HashMap::from([("TOKEN".to_string(), "stale".to_string())]),
                )
                .unwrap(),
            6
        );
        assert_eq!(
            state
                .compare_and_install_child_env_snapshot(6, 2, HashMap::new())
                .unwrap(),
            2,
            "opaque revisions may move numerically backwards"
        );

        let (revision, env) = state.child_env_snapshot_with_gcp_resolved().unwrap();
        assert_eq!(revision, 2);
        assert!(env.is_empty(), "an empty snapshot must revoke the old env");
    }

    #[test]
    fn child_environment_repair_replaces_an_empty_map_at_the_same_revision() {
        let state = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
        let failed = state.child_environment_snapshot().unwrap();
        state
            .compare_and_install_child_env_snapshot(
                6,
                6,
                HashMap::from([("TOKEN".to_string(), "reference".to_string())]),
            )
            .unwrap();
        let repaired = state.child_environment_snapshot().unwrap();
        assert_ne!(failed.installation_id, repaired.installation_id);
        assert_eq!(repaired.revision, 6);
        assert_eq!(
            repaired.environment.get("TOKEN").map(String::as_str),
            Some("reference")
        );
    }

    #[test]
    fn poisoned_environment_update_returns_error_without_recovering_state() {
        let state = ProviderCredentialState::from_child_env_snapshot(4, HashMap::new());
        let poison = state.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = poison.inner.write().unwrap();
                panic!("poison state during mutation");
            })
            .join()
            .is_err()
        );
        assert!(
            state
                .compare_and_install_child_env_snapshot(4, 5, HashMap::new())
                .is_err()
        );
        assert!(state.child_env_snapshot_with_gcp_resolved().is_err());
    }

    #[test]
    fn stale_generation_falls_back_to_current_credential_after_retention_window() {
        let state = ProviderCredentialState::from_environment(
            10,
            HashMap::from([("GITHUB_TOKEN".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );

        for revision in 11..20 {
            state.install_environment(
                revision,
                HashMap::from([("GITHUB_TOKEN".to_string(), format!("new-{revision}"))]),
                HashMap::new(),
                HashMap::new(),
            );
        }

        let resolver = state.resolver().expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v10_GITHUB_TOKEN"),
            Some("new-19")
        );
    }

    #[test]
    fn stale_removed_generation_fails_closed_after_retention_window() {
        let state = ProviderCredentialState::from_environment(
            10,
            HashMap::from([("GITHUB_TOKEN".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );

        for revision in 11..20 {
            state.install_environment(
                revision,
                HashMap::from([("OTHER_TOKEN".to_string(), format!("other-{revision}"))]),
                HashMap::new(),
                HashMap::new(),
            );
        }

        let resolver = state.resolver().expect("retained resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v10_GITHUB_TOKEN"),
            None
        );
    }
    #[test]
    fn provider_detach_refusal_uses_installed_membership_not_network_decisions() {
        let provider = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let mut bound = binding("api.example.com", 443, "/**");
        bound.credential_identity = format!("{provider}:API_KEY");
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".into(), "synthetic-test-value".into())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".into(), bound)]),
            Vec::new(),
        )
        .unwrap();
        let subject = state.capture_static_provider_revocation(provider).unwrap();
        let before = state.snapshot();
        assert!(
            state
                .observe_static_provider_revocation(&subject, 1, &before.installation_id)
                .is_none()
        );
        state
            .install_bound_environment(
                2,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
            )
            .unwrap();
        let after = state.snapshot();
        let proof = state
            .observe_static_provider_revocation(&subject, 2, &after.installation_id)
            .unwrap();
        assert!(proof.unavailable);
        assert_eq!(proof.provider_id, provider);
        assert_eq!(proof.before_revision, 1);
        assert!(
            state
                .observe_static_provider_revocation(&subject, 1, &after.installation_id)
                .is_none()
        );
        assert!(
            state
                .observe_static_provider_revocation(&subject, 2, &before.installation_id)
                .is_none()
        );
        // Actual endpoint resolution independently refuses the old reference.
        let endpoint = state.resolver_for_endpoint("api.example.com", 443, "/");
        if let Some(resolver) = endpoint {
            assert!(
                resolver
                    .resolve_placeholder_checked(
                        &crate::secrets::placeholder_for_env_key_for_revision("API_KEY", 1),
                        "test"
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn provider_detach_witness_matches_only_original_installed_bearer_reference() {
        let provider = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let mut bound = binding("api.example.com", 443, "/v1/messages");
        bound.credential_identity = format!("{provider}:API_KEY");
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([("API_KEY".into(), "synthetic-test-value".into())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".into(), bound)]),
            Vec::new(),
        )
        .unwrap();
        let subject = state.capture_static_provider_revocation(provider).unwrap();
        let original = state.snapshot().child_env["API_KEY"].clone();
        assert!(subject.matches_original_static_bearer(
            &format!("Bearer {original}"),
            "api.example.com",
            443,
            "/v1/messages?beta=true"
        ));
        for invalid in [
            "Bearer synthetic-test-value",
            "Bearer openshell:resolve:env:API_KEY",
            "Bearer openshell:resolve:env:v6_API_KEY",
            "Bearer openshell:resolve:env:v7_OTHER_KEY",
            "Bearer openshell:resolve:env:sother_API_KEY",
            "Bearer  openshell:resolve:env:v7_API_KEY",
            "Bearer openshell:resolve:env:v7_API_KEY ",
            "Basic openshell:resolve:env:v7_API_KEY",
        ] {
            assert!(!subject.matches_original_static_bearer(
                invalid,
                "api.example.com",
                443,
                "/v1/messages?beta=true"
            ));
        }
        for (host, port, target) in [
            ("other.example.com", 443, "/v1/messages?beta=true"),
            ("api.example.com", 80, "/v1/messages?beta=true"),
            ("api.example.com", 443, "/v1/models?beta=true"),
            (
                "api.example.com",
                443,
                "/v1/messages?key=openshell:resolve:env:v7_API_KEY",
            ),
        ] {
            assert!(!subject.matches_original_static_bearer(
                &format!("Bearer {original}"),
                host,
                port,
                target
            ));
        }
        // Membership can be retained privately after removal; matching the
        // reference alone still supplies neither arm authority nor a refusal.
        state
            .install_bound_environment(
                8,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
            )
            .unwrap();
        assert!(subject.matches_original_static_bearer(
            &format!("Bearer {original}"),
            "api.example.com",
            443,
            "/v1/messages?beta=true"
        ));
    }

    #[test]
    fn provider_detach_retains_original_subject_across_actual_install_only_when_enabled() {
        let provider = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let mut bound = binding("api.example.com", 443, "/v1/messages");
        bound.credential_identity = format!("{provider}:API_KEY");
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([("API_KEY".into(), "synthetic-value".into())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".into(), bound)]),
            Vec::new(),
        )
        .unwrap();
        assert!(!state.provider_detach_attempts_enabled());
        assert!(
            state
                .retained_provider_revocation_subject(provider, 7)
                .is_none()
        );
        state.enable_provider_detach_attempts();
        state
            .install_bound_environment(
                8,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
            )
            .unwrap();
        let original = state
            .retained_provider_revocation_subject(provider, 7)
            .unwrap();
        assert!(original.matches_original_static_bearer(
            "Bearer openshell:resolve:env:v7_API_KEY",
            "api.example.com",
            443,
            "/v1/messages?beta=true"
        ));
        assert!(
            state
                .retained_provider_revocation_subject(provider, 8)
                .is_none()
        );
        let after = state.snapshot();
        assert!(
            state
                .observe_static_provider_revocation(&original, 8, &after.installation_id)
                .unwrap()
                .unavailable
        );
        state.install_environment(9, HashMap::new(), HashMap::new(), HashMap::new());
        assert!(!state.provider_detach_attempts_enabled());
        assert!(
            state
                .retained_provider_revocation_subject(provider, 7)
                .is_none()
        );
    }

    #[test]
    fn provider_detach_subject_capacity_refuses_without_selecting_an_evicted_original() {
        let mut env = HashMap::new();
        let mut bindings = HashMap::new();
        for i in 0..33 {
            let key = format!("KEY_{i}");
            let mut bound = binding("api.example.com", 443, "/**");
            bound.credential_identity = format!("{i:08x}-aaaa-4aaa-8aaa-aaaaaaaaaaaa:{key}");
            env.insert(key.clone(), "synthetic-value".into());
            bindings.insert(key, bound);
        }
        let state = ProviderCredentialState::from_bound_environment(
            1,
            env,
            HashMap::new(),
            HashMap::new(),
            bindings,
            Vec::new(),
        )
        .unwrap();
        state.enable_provider_detach_attempts();
        assert!(!state.provider_detach_attempts_enabled());
        assert!(
            state
                .inner
                .read()
                .unwrap()
                .provider_detach
                .subjects
                .is_empty()
        );
    }

    // Core unit fixture represents an already authenticated server seal.
    // Full wire/hash/original-hold validation is tested at the server boundary.
    fn local_detach_arm_fixture() -> (
        ProviderCredentialState,
        crate::proto::ProviderDetachArmSealV1,
        crate::proto::ProviderReadinessObservation,
        prost_types::Timestamp,
    ) {
        use crate::proto::*;
        let provider = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let mut bound = binding("api.example.com", 443, "/v1/messages");
        bound.credential_identity = format!("{provider}:API_KEY");
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([("API_KEY".into(), "synthetic-value".into())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".into(), bound)]),
            Vec::new(),
        )
        .unwrap();
        state.enable_provider_detach_attempts();
        state
            .install_bound_environment(
                8,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
            )
            .unwrap();
        let now = prost_types::Timestamp {
            seconds: 1_792_180_001,
            nanos: 0,
        };
        let a = ProviderDetachAttemptV1 {
            schema_version: 1,
            dispatcher_decision_id: "66666666-6666-4666-8666-666666666666".into(),
            action_id: "78b7f3e7-7413-5338-a795-f35973214544".into(),
            intent_sha256: "a".repeat(64),
            target_sha256: "b".repeat(64),
            native_receipt_id: "11111111-1111-4111-8111-111111111111".into(),
            hold_id: "22222222-2222-4222-8222-222222222222".into(),
            authority: "gateway-a".into(),
            gateway_boot_id: "88888888-8888-4888-8888-888888888888".into(),
            workspace: "default".into(),
            sandbox_id: "sandbox-id".into(),
            execution_id: format!("exec-v1:{}", "a".repeat(64)),
            provider_id: provider.into(),
            attachment_epoch: "33333333-3333-4333-8333-333333333333".into(),
            configuration_instance: "config-after".into(),
            config_revision: 9,
            provider_env_revision: 8,
            native_policy_hash: "e".repeat(64),
            native_policy_version: 4,
            supervisor_instance: "44444444-4444-4444-8444-444444444444".into(),
            supervisor_session: "55555555-5555-4555-8555-555555555555".into(),
            arm_capture_sequence: 10,
            challenge: "a".repeat(64),
            not_before: Some(prost_types::Timestamp {
                seconds: now.seconds - 1,
                nanos: 0,
            }),
            deadline: Some(prost_types::Timestamp {
                seconds: now.seconds + 19,
                nanos: 0,
            }),
        };
        let obs = ProviderReadinessObservation {
            session_id: a.supervisor_session.clone(),
            sequence: 10,
            attachment_epoch: a.attachment_epoch.clone(),
            provider_env_revision: 8,
            config_revision: 9,
            policy_hash: a.native_policy_hash.clone(),
            credentials_installed: true,
            policy_active: true,
            launch_environment_installed: true,
            process_instance_id: "99999999-9999-4999-8999-999999999999".into(),
            ..Default::default()
        };
        state.bind_provider_detach_session(&a.gateway_boot_id, &a.supervisor_session);
        let target = ProviderDetachTargetV1 {
            provider_env_revision: 7,
            provider_id: provider.into(),
            ..Default::default()
        };
        let request = ProviderDetachArmRequestV1 {
            original_action: Some(ProviderDetachActionV1 {
                target: Some(target),
                ..Default::default()
            }),
            original_receipt: None,
            attempt: Some(a),
            attempt_id: "5891bfb6-f198-5af2-ad78-cccd52e62f10".into(),
            request_sha256: "b".repeat(64),
        };
        let seal = ProviderDetachArmSealV1 {
            request: Some(request),
            hold_generation: 1,
            row_resource_version: 1,
            install_sequence: 0,
            installed_time: None,
        };
        (state, seal, obs, now)
    }
    #[test]
    fn witness_source_commit_requires_actual_server_arm_and_current_installation() {
        use prost::Message;
        let (state, mut seal, obs, now) = local_detach_arm_fixture();
        let installed = state.snapshot().installation_id.clone();
        assert!(state.install_provider_detach_arm(
            &seal,
            &obs,
            &installed,
            11,
            now,
            Arc::new(|| true)
        ));
        seal.install_sequence = 11;
        seal.installed_time = Some(now);
        let current = state.witness_launch_gate().snapshot();
        let arm = seal.request.as_ref().unwrap();
        let attempt = arm.attempt.as_ref().unwrap();
        let mut op = super::WitnessOperation {
            prepared_source_incarnation: current.source_incarnation,
            prepared_source_epoch: current.epoch,
            original_key: "a".repeat(64),
            request_sha256: "b".repeat(64),
            profile_sha256: "c".repeat(64),
            installed_arm_sha256: super::witness_sha256(&seal.encode_to_vec()),
            boundary_incarnation: uuid::Uuid::new_v4().to_string(),
            prepared_ticket: uuid::Uuid::new_v4().to_string(),
            supervisor_session: attempt.supervisor_session.clone(),
            execution_id: attempt.execution_id.clone(),
            deadline_unix_ms: attempt.deadline.as_ref().unwrap().seconds * 1000,
            arm_request: arm.encode_to_vec(),
        };
        let millis = now.seconds * 1000;
        assert!(
            state
                .commit_provider_witness_under_source_gate(
                    &mut state.witness_launch_gate().lock(),
                    &op,
                    millis
                )
                .is_none()
        );
        assert!(state.acknowledge_provider_detach_arm(&seal));
        assert!(
            state
                .commit_provider_witness_under_source_gate(
                    &mut state.witness_launch_gate().lock(),
                    &op,
                    millis
                )
                .is_none()
        );
        op.prepared_source_epoch = state.witness_launch_gate().snapshot().epoch;
        let permit = state
            .commit_provider_witness_under_source_gate(
                &mut state.witness_launch_gate().lock(),
                &op,
                millis,
            )
            .unwrap();
        assert_eq!(permit.operation, op);
        assert!(
            state
                .commit_provider_witness_under_source_gate(
                    &mut state.witness_launch_gate().lock(),
                    &op,
                    millis
                )
                .is_none()
        );
        // Source commitment did not spend the separate actual Native resolver
        // refusal witness. A process/permit remains a different observation.
        let observed = state
            .provider_detach_report(&obs.session_id, 12, &now)
            .unwrap();
        assert_eq!(observed.result, 0);
    }
    #[test]
    fn witness_gate_binding_is_bootstrap_only_and_actual_writers_invalidate() {
        let mut state = ProviderCredentialState::from_child_env_snapshot(1, HashMap::new());
        let gate = super::WitnessLaunchGate::new();
        assert!(state.bind_witness_launch_gate(gate.clone()));
        let original = gate.snapshot().epoch;
        state.enable_provider_detach_attempts();
        assert!(gate.snapshot().epoch > original);
        assert!(!state.bind_witness_launch_gate(super::WitnessLaunchGate::new()));
        let original = gate.snapshot().epoch;
        state.bind_provider_detach_session(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        );
        assert!(gate.snapshot().epoch > original);
        let clone = state.clone();
        assert!(!state.bind_witness_launch_gate(super::WitnessLaunchGate::new()));
        drop(clone);
    }
    #[test]
    fn provider_detach_arm_requires_actual_install_ack_and_consumes_exact_header_once() {
        let (state, seal, obs, now) = local_detach_arm_fixture();
        let q = seal.request.as_ref().unwrap();
        let a = q.attempt.as_ref().unwrap();
        let installed = state.snapshot().installation_id.clone();
        assert!(state.install_provider_detach_arm(
            &seal,
            &obs,
            &installed,
            11,
            now,
            Arc::new(|| true)
        ));
        assert_eq!(
            state.witness_provider_detach_header(
                &q.attempt_id,
                &a.challenge,
                "Bearer openshell:resolve:env:v7_API_KEY",
                "api.example.com",
                443,
                "/v1/messages?beta=true",
                None,
                8,
                now
            ),
            ProviderDetachWitness::NotArmed
        );
        let report = state
            .provider_detach_report(&obs.session_id, 11, &now)
            .unwrap();
        assert_eq!(report.install_sequence, 11);
        assert_eq!(report.result, 0);
        let mut acknowledged = seal.clone();
        acknowledged.install_sequence = 11;
        acknowledged.installed_time = Some(now);
        assert!(state.acknowledge_provider_detach_arm(&acknowledged));
        assert_eq!(
            state.witness_provider_detach_header(
                &q.attempt_id,
                &a.challenge,
                "Bearer openshell:resolve:env:v7_API_KEY",
                "api.example.com",
                443,
                "/v1/messages?beta=true",
                None,
                8,
                now
            ),
            ProviderDetachWitness::Unavailable
        );
        assert_eq!(
            state.witness_provider_detach_header(
                &q.attempt_id,
                &a.challenge,
                "Bearer openshell:resolve:env:v7_API_KEY",
                "api.example.com",
                443,
                "/v1/messages?beta=true",
                None,
                8,
                now
            ),
            ProviderDetachWitness::NotArmed
        );
        let proof = state
            .provider_detach_report(&obs.session_id, 12, &now)
            .unwrap();
        assert_eq!(proof.result, 1);
        assert_eq!(proof.refusal.as_ref().unwrap().sequence, 12);
        let later = prost_types::Timestamp {
            seconds: now.seconds + 1,
            nanos: 0,
        };
        let retry = state
            .provider_detach_report(&obs.session_id, 13, &later)
            .unwrap();
        assert_eq!(proof, retry);
        assert!(state.install_provider_detach_arm(
            &seal,
            &obs,
            &installed,
            14,
            later,
            Arc::new(|| true)
        ));
        assert_eq!(
            state.witness_provider_detach_header(
                &q.attempt_id,
                &a.challenge,
                "Bearer openshell:resolve:env:v7_API_KEY",
                "api.example.com",
                443,
                "/v1/messages?beta=true",
                None,
                8,
                later
            ),
            ProviderDetachWitness::NotArmed
        );
    }
    #[test]
    fn provider_detach_arm_wrong_subject_spends_without_proof_and_deadline_never_renews() {
        let (state, seal, obs, now) = local_detach_arm_fixture();
        let q = seal.request.as_ref().unwrap();
        let a = q.attempt.as_ref().unwrap();
        let installed = state.snapshot().installation_id.clone();
        assert!(state.install_provider_detach_arm(
            &seal,
            &obs,
            &installed,
            11,
            now,
            Arc::new(|| true)
        ));
        let mut ack = seal.clone();
        ack.install_sequence = 11;
        ack.installed_time = Some(now);
        assert!(state.acknowledge_provider_detach_arm(&ack));
        assert_eq!(
            state.witness_provider_detach_header(
                &q.attempt_id,
                &a.challenge,
                "Bearer openshell:resolve:env:v7_UNRELATED",
                "api.example.com",
                443,
                "/v1/messages?beta=true",
                None,
                8,
                now
            ),
            ProviderDetachWitness::Invalidated
        );
        let report = state
            .provider_detach_report(&obs.session_id, 12, &now)
            .unwrap();
        assert_eq!(report.result, 3);
        assert!(report.refusal.is_none());
        let expiry = a.deadline.unwrap();
        assert!(
            state
                .provider_detach_report(&obs.session_id, 13, &expiry)
                .unwrap()
                .attempt_id
                .is_empty()
        );
        assert!(!state.install_provider_detach_arm(
            &seal,
            &obs,
            &installed,
            14,
            expiry,
            Arc::new(|| true)
        ));
    }

    #[test]
    fn provider_detach_arm_two_consumers_only_one_original_refusal() {
        let (state, seal, obs, now) = local_detach_arm_fixture();
        let q = seal.request.as_ref().unwrap();
        let a = q.attempt.as_ref().unwrap();
        assert!(state.install_provider_detach_arm(
            &seal,
            &obs,
            &state.snapshot().installation_id,
            11,
            now,
            Arc::new(|| true)
        ));
        let mut ack = seal.clone();
        ack.install_sequence = 11;
        ack.installed_time = Some(now);
        assert!(state.acknowledge_provider_detach_arm(&ack));
        let mut threads = Vec::new();
        for _ in 0..32 {
            let state = state.clone();
            let id = q.attempt_id.clone();
            let challenge = a.challenge.clone();
            threads.push(std::thread::spawn(move || {
                state.witness_provider_detach_header(
                    &id,
                    &challenge,
                    "Bearer openshell:resolve:env:v7_API_KEY",
                    "api.example.com",
                    443,
                    "/v1/messages?beta=true",
                    None,
                    8,
                    now,
                )
            }));
        }
        let outcomes = threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == ProviderDetachWitness::Unavailable)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == ProviderDetachWitness::NotArmed)
                .count(),
            31
        );
    }
    #[test]
    fn provider_detach_arm_policy_and_installation_replacement_withhold_original_proof() {
        for replace in [false, true] {
            let (state, seal, obs, now) = local_detach_arm_fixture();
            let q = seal.request.as_ref().unwrap();
            let a = q.attempt.as_ref().unwrap();
            let active = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let check = Arc::clone(&active);
            assert!(state.install_provider_detach_arm(
                &seal,
                &obs,
                &state.snapshot().installation_id,
                11,
                now,
                Arc::new(move || check.load(std::sync::atomic::Ordering::SeqCst))
            ));
            let mut ack = seal.clone();
            ack.install_sequence = 11;
            ack.installed_time = Some(now);
            assert!(state.acknowledge_provider_detach_arm(&ack));
            if replace {
                state
                    .install_bound_environment(
                        8,
                        HashMap::new(),
                        HashMap::new(),
                        HashMap::new(),
                        HashMap::new(),
                        Vec::new(),
                    )
                    .unwrap();
            } else {
                active.store(false, std::sync::atomic::Ordering::SeqCst);
            }
            assert_eq!(
                state.witness_provider_detach_header(
                    &q.attempt_id,
                    &a.challenge,
                    "Bearer openshell:resolve:env:v7_API_KEY",
                    "api.example.com",
                    443,
                    "/v1/messages?beta=true",
                    None,
                    8,
                    now
                ),
                ProviderDetachWitness::Invalidated
            );
            assert!(
                state
                    .provider_detach_report(&obs.session_id, 12, &now)
                    .unwrap()
                    .refusal
                    .is_none()
            );
        }
    }
    #[test]
    fn provider_detach_arm_unexpired_consumed_records_count_toward_capacity() {
        let (state, base, obs, now) = local_detach_arm_fixture();
        let installed = state.snapshot().installation_id.clone();
        let mut originals = Vec::new();
        for i in 0..16 {
            let mut seal = base.clone();
            let q = seal.request.as_mut().unwrap();
            q.attempt_id = uuid::Uuid::new_v4().to_string();
            q.request_sha256 = format!("{i:064x}");
            q.attempt.as_mut().unwrap().dispatcher_decision_id = uuid::Uuid::new_v4().to_string();
            assert!(state.install_provider_detach_arm(
                &seal,
                &obs,
                &installed,
                11,
                now,
                Arc::new(|| true)
            ));
            let mut ack = seal.clone();
            ack.install_sequence = 11;
            ack.installed_time = Some(now);
            assert!(state.acknowledge_provider_detach_arm(&ack));
            let q = seal.request.as_ref().unwrap();
            assert_eq!(
                state.witness_provider_detach_header(
                    &q.attempt_id,
                    &q.attempt.as_ref().unwrap().challenge,
                    "Bearer unrelated",
                    "api.example.com",
                    443,
                    "/v1/messages",
                    None,
                    8,
                    now
                ),
                ProviderDetachWitness::Invalidated
            );
            originals.push(seal);
        }
        let mut extra = base.clone();
        extra.request.as_mut().unwrap().attempt_id = uuid::Uuid::new_v4().to_string();
        assert!(!state.install_provider_detach_arm(
            &extra,
            &obs,
            &installed,
            11,
            now,
            Arc::new(|| true)
        ));
        for original in originals {
            assert!(state.install_provider_detach_arm(
                &original,
                &obs,
                &installed,
                12,
                now,
                Arc::new(|| true)
            ));
        }
        assert_eq!(state.inner.read().unwrap().provider_detach.arms.len(), 16);
        state.bind_provider_detach_session("99999999-9999-4999-8999-999999999999", &obs.session_id);
        assert_eq!(state.inner.read().unwrap().provider_detach.arms.len(), 16);
        assert!(!state.install_provider_detach_arm(
            &base,
            &obs,
            &installed,
            12,
            now,
            Arc::new(|| true)
        ));
    }

    #[test]
    fn provider_detach_refusal_missing_association_is_unsupported() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );
        assert!(
            state
                .capture_static_provider_revocation("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                .is_none()
        );
        assert!(
            state
                .capture_static_provider_revocation("not-a-provider-uuid")
                .is_none()
        );
        assert!(
            state
                .capture_static_provider_revocation("00000000-0000-0000-0000-000000000000")
                .is_none()
        );
    }
    #[test]
    fn provider_detach_refusal_rejects_reused_key_and_attached_provider() {
        let provider = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let mut bound = binding("api.example.com", 443, "/**");
        bound.credential_identity = format!("{provider}:API_KEY");
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".into(), "synthetic".into())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".into(), bound.clone())]),
            Vec::new(),
        )
        .unwrap();
        let subject = state.capture_static_provider_revocation(provider).unwrap();
        state
            .install_bound_environment(
                2,
                HashMap::from([("API_KEY".into(), "synthetic-new".into())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([("API_KEY".into(), bound.clone())]),
                Vec::new(),
            )
            .unwrap();
        let current = state.snapshot();
        assert!(
            !state
                .observe_static_provider_revocation(&subject, 2, &current.installation_id)
                .unwrap()
                .unavailable
        );
        bound.credential_identity = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb:API_KEY".into();
        state
            .install_bound_environment(
                3,
                HashMap::from([("API_KEY".into(), "other-provider".into())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([("API_KEY".into(), bound)]),
                Vec::new(),
            )
            .unwrap();
        let current = state.snapshot();
        assert!(
            state
                .observe_static_provider_revocation(&subject, 3, &current.installation_id)
                .is_none()
        );
    }
}

/// Bounded ordinary-traffic observation. This is metadata accounting, never a
/// traffic permit, model completion assertion, or substitute for source custody.
pub mod ordinary_observation {
    use super::{
        Arc, HashMap, HashSet, Mutex, MutexGuard, ProviderCredentialState,
        ProviderRevocationSubject, fmt, witness_sha256,
    };
    use crate::proto::{
        GetProviderDetachObservationRequest, ProviderDetachAckv1, ProviderObservationCurrentReadV1,
        ProviderObservationCurrentReplyV1, ProviderObservationEventV1, ProviderObservationPhaseV1,
        ProviderObservationRequestV1, ProviderObservationResultV1, ProviderObservationRewriteV1,
        ProviderObservationSnapshotV1, ProviderObservationStateV1, ProviderObservationWindowV1,
        ProviderReadinessObservation, WorkspaceSelector, workspace_selector,
    };
    use prost::Message;
    use std::sync::atomic::{AtomicBool, Ordering};

    pub const LEGACY_PROFILE: &str = "ordinary-sandbox-mediation-static-bearer-v1";
    pub const PROFILE: &str = "ordinary-sandbox-mediation-static-bearer-v2";
    // The legacy ceilings are intentionally unchanged. V2 adds only a bounded
    // complete Arm at its known paths; every stripped envelope still fits v1.
    pub const MAX_RESULT: usize = 16 * 1024;
    pub const MAX_READ: usize = 4096;
    pub const MAX_ARM: usize = 8192;
    pub const MAX_REQUEST_V2: usize = 12_291;
    pub const MAX_READ_V2: usize = 12_293;
    pub const MAX_REPLY_V2: usize = 12_294;
    pub const MAX_RESULT_V2: usize = 32_780;
    pub const MAX_EVENT: usize = 512;
    pub const MAX_EVENTS: usize = 8;
    pub const MAX_WINDOWS: usize = 16;
    pub const EVIDENCE_SCOPE: &str = "original-sandbox-mediation-path/v1";
    pub const WRITER_UNPROVEN: i32 = 1;

    pub fn profile_digest_for(profile: &str) -> Option<String> {
        let descriptor = match profile {
            LEGACY_PROFILE => LEGACY_DESCRIPTOR,
            PROFILE => V2_DESCRIPTOR,
            _ => return None,
        };
        Some(witness_sha256(descriptor.as_bytes()))
    }
    const LEGACY_DESCRIPTOR: &str = "openshell.provider-detach.sandbox-mediation-profile/v1\nordinary-sandbox-mediation-static-bearer-v1\nevidence_scope:original-sandbox-mediation-path/v1\nprocess_writer_identity:unproven\nhttp1:static-authorization-bearer\nstream:true,false,unobserved\nwindow:60s\nevents:8\nevent:512\nresult:16384\ncurrent:original-channel-read-v1\nassociation:retained-original-stream-allocation-v1\n";
    const V2_DESCRIPTOR: &str = "openshell.provider-detach.sandbox-mediation-profile/v2\nordinary-sandbox-mediation-static-bearer-v2\nevidence_scope:original-sandbox-mediation-path/v1\nprocess_writer_identity:unproven\nhttp1:static-authorization-bearer\nstream:true,false,unobserved\nwindow:60s\nevents:8\nevent:512\nrequest:12291\nread:12293\nreply:12294\nresult:32780\narm:8192\nstripped:request4096,read4096,reply4096,result16384\ncurrent:original-channel-read-v1\nassociation:retained-original-stream-allocation-v1\n";
    pub fn profile_digest() -> String {
        profile_digest_for(PROFILE).expect("known compiled ordinary profile")
    }
    pub fn valid_profile(profile: &str, hash: &str) -> bool {
        profile_digest_for(profile).is_some_and(|expected| expected == hash)
    }
    fn v2(profile: &str, hash: &str) -> Option<bool> {
        valid_profile(profile, hash).then_some(profile == PROFILE)
    }
    // These clones are size-only projections, never wire/hash/auth projections.
    fn strip_arm(q: &mut ProviderObservationRequestV1) {
        q.installed_arm = None;
    }
    fn strip_read_arm(q: &mut ProviderObservationCurrentReadV1) {
        if let Some(q) = q
            .selector
            .as_mut()
            .and_then(|s| s.original_request.as_mut())
        {
            strip_arm(q);
        }
    }
    fn strip_result_arms(q: &mut ProviderObservationResultV1) {
        if let Some(q) = q.window.as_mut().and_then(|w| w.request.as_mut()) {
            strip_arm(q);
        }
        if let Some(q) = q
            .current_read
            .as_mut()
            .and_then(|r| r.original_read.as_mut())
        {
            strip_read_arm(q);
        }
    }
    pub fn request_fits(q: &ProviderObservationRequestV1) -> bool {
        let Some(is_v2) = v2(&q.profile_id, &q.profile_sha256) else {
            return false;
        };
        if !is_v2 {
            return q.encoded_len() <= MAX_READ;
        }
        if q.encoded_len() > MAX_REQUEST_V2
            || q.installed_arm
                .as_ref()
                .is_some_and(|a| a.encoded_len() > MAX_ARM)
        {
            return false;
        }
        let mut stripped = q.clone();
        strip_arm(&mut stripped);
        stripped.encoded_len() <= MAX_READ
    }
    pub fn query_fits(q: &GetProviderDetachObservationRequest) -> bool {
        let Some(original) = &q.original_request else {
            return q.encoded_len() <= 8192;
        };
        if !request_fits(original) {
            return false;
        }
        if original.profile_id == LEGACY_PROFILE {
            return q.encoded_len() <= 8192;
        }
        // An original selector must fit inside the already bounded read.
        if q.encoded_len() > MAX_READ_V2 {
            return false;
        }
        let mut stripped = q.clone();
        strip_arm(
            stripped
                .original_request
                .as_mut()
                .expect("checked original"),
        );
        stripped.encoded_len() <= 8192
    }
    pub fn read_fits(q: &ProviderObservationCurrentReadV1) -> bool {
        if q.encoded_len() > MAX_READ_V2 {
            return false;
        }
        if q.selector.as_ref().is_none_or(|s| !query_fits(s)) {
            return false;
        }
        let Some(s) = &q.expected_identity else {
            return false;
        };
        let Some(is_v2) = v2(&s.profile_id, &s.profile_sha256) else {
            return false;
        };
        if let Some(original) = q
            .selector
            .as_ref()
            .and_then(|s| s.original_request.as_ref())
            && (original.profile_id != s.profile_id
                || original.profile_sha256 != s.profile_sha256
                || !request_fits(original))
        {
            return false;
        }
        if !is_v2 {
            return q.encoded_len() <= MAX_READ;
        }
        if q.encoded_len() > MAX_READ_V2 {
            return false;
        }
        let mut stripped = q.clone();
        strip_read_arm(&mut stripped);
        stripped.encoded_len() <= MAX_READ
    }
    pub fn reply_fits(q: &ProviderObservationCurrentReplyV1) -> bool {
        if q.encoded_len() > MAX_REPLY_V2 {
            return false;
        }
        let Some(read) = &q.original_read else {
            return false;
        };
        if !read_fits(read) {
            return false;
        }
        let Some(s) = &read.expected_identity else {
            return false;
        };
        let Some(sample) = &q.sampled_snapshot else {
            return false;
        };
        if sample.profile_id != s.profile_id || sample.profile_sha256 != s.profile_sha256 {
            return false;
        }
        if s.profile_id == LEGACY_PROFILE {
            return q.encoded_len() <= MAX_READ;
        }
        if q.encoded_len() > MAX_REPLY_V2 {
            return false;
        }
        let mut stripped = q.clone();
        strip_read_arm(stripped.original_read.as_mut().expect("checked read"));
        stripped.encoded_len() <= MAX_READ
    }
    fn result_bound(q: &ProviderObservationResultV1, reserve: usize) -> Option<usize> {
        let full = q.encoded_len().checked_add(reserve)?;
        if full > MAX_RESULT_V2 {
            return None;
        }
        let Some(original) = q.window.as_ref().and_then(|w| w.request.as_ref()) else {
            return (full <= MAX_RESULT).then_some(full);
        };
        if !request_fits(original) || q.current_read.as_ref().is_some_and(|r| !reply_fits(r)) {
            return None;
        }
        if original.profile_id == LEGACY_PROFILE {
            return (full <= MAX_RESULT).then_some(full);
        }
        if full > MAX_RESULT_V2 {
            return None;
        }
        let mut stripped = q.clone();
        strip_result_arms(&mut stripped);
        (stripped.encoded_len().checked_add(reserve)? <= MAX_RESULT).then_some(full)
    }
    pub fn result_fits(q: &ProviderObservationResultV1) -> bool {
        result_bound(q, 0).is_some()
    }
    pub fn control_fits(q: &crate::proto::ProviderObservationControlV1) -> bool {
        use crate::proto::provider_observation_control_v1::Payload;
        if q.encoded_len() > MAX_RESULT_V2 + 4 {
            return false;
        }
        let (profile, hash, fits) = match &q.payload {
            Some(Payload::InstallRequest(r)) => (&r.profile_id, &r.profile_sha256, request_fits(r)),
            Some(Payload::CurrentSnapshot(s)) => {
                (&s.profile_id, &s.profile_sha256, valid_snapshot(s))
            }
            Some(Payload::CurrentRead(r)) => {
                let Some(s) = &r.expected_identity else {
                    return false;
                };
                (&s.profile_id, &s.profile_sha256, read_fits(r))
            }
            Some(Payload::CurrentReply(r)) => {
                let Some(s) = &r.sampled_snapshot else {
                    return false;
                };
                (&s.profile_id, &s.profile_sha256, reply_fits(r))
            }
            Some(Payload::Report(r)) => {
                let Some(s) = r.window.as_ref().and_then(|w| w.request.as_ref()) else {
                    return false;
                };
                (&s.profile_id, &s.profile_sha256, result_fits(r))
            }
            None => return false,
        };
        let Some(is_v2) = v2(profile, hash) else {
            return false;
        };
        if !fits {
            return false;
        }
        if !is_v2 {
            return q.encoded_len() <= MAX_RESULT;
        }
        if q.encoded_len() > MAX_RESULT_V2 + 4 {
            return false;
        }
        let mut stripped = q.clone();
        match &mut stripped.payload {
            Some(Payload::InstallRequest(r)) => strip_arm(r),
            Some(Payload::CurrentRead(r)) => strip_read_arm(r),
            Some(Payload::CurrentReply(r)) => {
                if let Some(r) = &mut r.original_read {
                    strip_read_arm(r);
                }
            }
            Some(Payload::Report(r)) => strip_result_arms(r),
            _ => {}
        }
        stripped.encoded_len() <= MAX_RESULT
    }
    pub fn digest<M: Message>(domain: &str, value: &M) -> String {
        let mut raw = domain.as_bytes().to_vec();
        raw.push(b'\n');
        raw.extend(value.encode_to_vec());
        witness_sha256(&raw)
    }
    pub fn request_digest(q: &ProviderObservationRequestV1) -> String {
        let mut q = q.clone();
        q.request_sha256.clear();
        digest("openshell.provider-detach.sandbox-mediation-request/v1", &q)
    }
    pub fn window_digest(q: &ProviderObservationWindowV1) -> String {
        let mut q = q.clone();
        q.window_sha256.clear();
        digest("openshell.provider-detach.sandbox-mediation-window/v1", &q)
    }
    pub fn terminal_digest(q: &ProviderObservationResultV1) -> String {
        let mut q = q.clone();
        q.terminal_sha256.clear();
        q.current_snapshot = None;
        q.detached_ack = None;
        q.current_report_sequence = 0;
        q.ack_window_sha256.clear();
        q.ack_terminal_sha256.clear();
        q.current_read = None;
        digest(
            "openshell.provider-detach.sandbox-mediation-terminal/v1",
            &q,
        )
    }
    /// Size the COMPLETE known-field maximum before original claim/install.
    /// This is byte accounting, not a runtime capacity or spending allocation.
    pub fn install_budget(
        q: &ProviderObservationRequestV1,
        snapshot: &ProviderObservationSnapshotV1,
    ) -> Option<usize> {
        let max_time = prost_types::Timestamp {
            seconds: i64::MAX,
            nanos: i32::MAX,
        };
        let mut live_snapshot = snapshot.clone();
        live_snapshot.current_ingress_sequence = u64::MAX;
        let selector = GetProviderDetachObservationRequest {
            workspace_scope: Some(WorkspaceSelector {
                selection: Some(workspace_selector::Selection::Workspace(
                    q.resource.as_ref()?.workspace.clone(),
                )),
            }),
            original_request: Some(q.clone()),
            resource: None,
        };
        let read = ProviderObservationCurrentReadV1 {
            selector: Some(selector),
            expected_identity: Some(live_snapshot.clone()),
            read_correlation: vec![255; 16],
            read_deadline: Some(max_time),
            window_sha256: "f".repeat(64),
            terminal_sha256: "f".repeat(64),
        };
        let reply = ProviderObservationCurrentReplyV1 {
            original_read: Some(read.clone()),
            sampled_snapshot: Some(live_snapshot.clone()),
            active_attempts: u32::MAX,
            accounting_fault: true,
            sampled_time: Some(max_time),
        };
        if !read_fits(&read) || !reply_fits(&reply) {
            return None;
        }
        let ack = q
            .installed_arm
            .as_ref()
            .and_then(|s| s.request.as_ref())
            .and_then(|r| r.attempt.as_ref())
            .map(|arm| ProviderDetachAckv1 {
                action_id: arm.action_id.clone(),
                target_sha256: arm.target_sha256.clone(),
                native_receipt_id: arm.native_receipt_id.clone(),
                hold_id: arm.hold_id.clone(),
                sandbox_id: arm.sandbox_id.clone(),
                execution_id: arm.execution_id.clone(),
                provider_id: arm.provider_id.clone(),
                attachment_epoch: arm.attachment_epoch.clone(),
                configuration_instance: arm.configuration_instance.clone(),
                config_revision: u64::MAX,
                provider_env_revision: u64::MAX,
                native_policy_hash: arm.native_policy_hash.clone(),
                native_policy_version: u32::MAX,
                supervisor_instance: arm.supervisor_instance.clone(),
                supervisor_session: arm.supervisor_session.clone(),
                sequence: u64::MAX,
                state: "revoked".into(),
                credentials_installed: true,
                policy_active: true,
                launch_environment_acknowledged: true,
                evaluated_time: Some(max_time),
                observed_time: Some(max_time),
            });
        let result = ProviderObservationResultV1 {
            window: Some(ProviderObservationWindowV1 {
                request: Some(q.clone()),
                installed_snapshot: Some(live_snapshot.clone()),
                window_id: "f".repeat(36),
                install_sequence: u64::MAX,
                installed_time: Some(max_time),
                ingress_watermark: u64::MAX,
                window_sha256: "f".repeat(64),
                capture_end: Some(max_time),
            }),
            state: ProviderObservationStateV1::Terminal as i32,
            events: Vec::new(),
            closed_time: Some(max_time),
            terminal_sha256: "f".repeat(64),
            current_snapshot: Some(live_snapshot),
            detached_ack: ack,
            current_report_sequence: u64::MAX,
            ack_window_sha256: "f".repeat(64),
            ack_terminal_sha256: "f".repeat(64),
            current_read: Some(reply),
        };
        result_bound(&result, MAX_EVENTS * (MAX_EVENT + 4))
    }

    pub fn system_now() -> Option<i64> {
        crate::time::timestamp_from_system_time(std::time::SystemTime::now())
            .ok()
            .and_then(|t| time_ms(&t))
    }
    pub fn time_ms(t: &prost_types::Timestamp) -> Option<i64> {
        if !(0..1_000_000_000).contains(&t.nanos) {
            return None;
        }
        t.seconds
            .checked_mul(1000)?
            .checked_add(i64::from(t.nanos / 1_000_000))
    }
    pub fn timestamp(ms: i64) -> prost_types::Timestamp {
        prost_types::Timestamp {
            seconds: ms.div_euclid(1000),
            nanos: i32::try_from(ms.rem_euclid(1000) * 1_000_000).expect("bounded nanoseconds"),
        }
    }
    fn id(s: &str) -> bool {
        uuid::Uuid::parse_str(s).is_ok_and(|v| !v.is_nil() && v.to_string() == s)
    }
    pub fn same_identity(
        a: &ProviderObservationSnapshotV1,
        b: &ProviderObservationSnapshotV1,
    ) -> bool {
        let mut a = a.clone();
        let mut b = b.clone();
        a.current_ingress_sequence = 0;
        b.current_ingress_sequence = 0;
        a == b
    }
    pub fn shape(q: &ProviderObservationRequestV1) -> bool {
        request_fits(q)
            && q.resource.is_some()
            && valid_profile(&q.profile_id, &q.profile_sha256)
            && q.evidence_scope == EVIDENCE_SCOPE
            && id(&q.run_id)
            && id(&q.step_id)
            && id(&q.source_incarnation)
            && id(&q.boundary_incarnation)
            && q.request_sha256 == request_digest(q)
            && q.deadline.as_ref().and_then(time_ms).is_some()
            && match ProviderObservationPhaseV1::try_from(q.phase) {
                Ok(ProviderObservationPhaseV1::Baseline) => {
                    q.installed_arm.is_none() && q.baseline_mediation_path_receipt_sha256.is_empty()
                }
                Ok(ProviderObservationPhaseV1::Detached) => {
                    q.installed_arm.as_ref().is_some_and(|s| {
                        s.install_sequence != 0
                            && s.installed_time.as_ref().and_then(time_ms).is_some()
                            && s.request.as_ref().is_some_and(|r| {
                                id(&r.attempt_id)
                                    && r.request_sha256.len() == 64
                                    && r.attempt.as_ref().is_some_and(|a| a.schema_version == 1)
                            })
                    }) && q.baseline_mediation_path_receipt_sha256.len() == 64
                }
                _ => false,
            }
    }

    /// Authenticated owned sandbox execution, not an individual request writer.
    #[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct OwnedPath {
        pub boundary_incarnation: String,
        pub execution_id: String,
        pub mediation_path_id: String,
    }
    impl fmt::Debug for OwnedPath {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("OwnedPath(<original-mediation>)")
        }
    }
    #[async_trait::async_trait]
    pub trait Boundary: Send + Sync + fmt::Debug {
        /// Original authenticated active boundary only; never recover/reattach.
        async fn path(&self) -> Option<OwnedPath>;
        fn streams(&self) -> Arc<StreamRegistry>;
    }
    pub fn configuration_digest(observation: &ProviderReadinessObservation) -> String {
        let mut o = observation.clone();
        o.session_id.clear();
        o.sequence = 0;
        o.provider_detach = None;
        digest(
            "openshell.provider-detach.sandbox-mediation-configuration/v1",
            &o,
        )
    }
    pub fn path_digest(snapshot: &ProviderObservationSnapshotV1) -> String {
        let mut s = snapshot.clone();
        s.mediation_path_receipt_sha256.clear();
        s.configuration_sha256.clear();
        s.policy_generation = 0;
        s.resolver_generation = 0;
        s.current_ingress_sequence = 0;
        digest("openshell.provider-detach.sandbox-mediation-path/v1", &s)
    }
    pub fn valid_snapshot(s: &ProviderObservationSnapshotV1) -> bool {
        valid_profile(&s.profile_id, &s.profile_sha256)
            && s.evidence_scope == EVIDENCE_SCOPE
            && s.process_writer_attribution == WRITER_UNPROVEN
            && id(&s.mediation_path_id)
            && s.mediation_path_receipt_sha256 == path_digest(s)
    }
    struct StreamLife {
        id: String,
        live: AtomicBool,
        taken: AtomicBool,
        ready: AtomicBool,
        complete: AtomicBool,
        inspected: AtomicBool,
        close_requested: AtomicBool,
        requests: std::sync::atomic::AtomicU32,
        accept_id: String,
        connection_id: String,
        accept_ordinal: u64,
        captured_time: i64,
        ingress_sequence: u64,
        policy: std::sync::atomic::AtomicU64,
    }
    struct StreamEntries {
        entries: HashMap<(usize, u64), Arc<StreamLife>>,
        ordinal: u64,
        fault: bool,
        observer: std::sync::Weak<Observer>,
    }
    /// Backend-private exact allocation membership, never caller provenance.
    ///
    /// Lock order is registry -> observer; no callback, await, or destructor
    /// invoking registry operations is run while either mutex is held.
    pub struct StreamRegistry {
        inner: Mutex<StreamEntries>,
        live: AtomicBool,
    }
    impl fmt::Debug for StreamRegistry {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("StreamRegistry(<retained-original>)")
        }
    }
    impl StreamRegistry {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: Mutex::new(StreamEntries {
                    entries: HashMap::new(),
                    ordinal: 0,
                    fault: false,
                    observer: std::sync::Weak::new(),
                }),
                live: AtomicBool::new(true),
            })
        }
        pub fn invalidate(&self) {
            self.live.store(false, Ordering::Release);
        }
        pub fn is_live(&self) -> bool {
            self.live.load(Ordering::Acquire)
        }
        pub fn observing(&self) -> bool {
            let Some(now) = system_now() else {
                return true;
            };
            let Ok(s) = self.inner.lock() else {
                return true;
            };
            s.observer.upgrade().is_some_and(|o| {
                o.inner.lock().map_or(true, |state| {
                    state.windows.values().any(|w| {
                        w.result
                            .window
                            .as_ref()
                            .and_then(|w| w.request.as_ref())
                            .and_then(|q| q.deadline.as_ref())
                            .and_then(time_ms)
                            .is_none_or(|d| now < d)
                    })
                })
            })
        }

        /// Called only by the trusted backend on its concrete boxed owner.
        /// The owner must hold the returned guard in its Drop-before-free path.
        #[allow(clippy::borrowed_box)] // ownership/allocation identity is the contract
        pub fn register<T: ?Sized>(
            self: &Arc<Self>,
            owner: &Box<T>,
            cookie: u64,
            accept_id: String,
        ) -> Option<StreamOwner> {
            let key = (std::ptr::from_ref(&**owner).cast::<()>() as usize, cookie);
            let mut s = self.inner.lock().ok()?;
            if !self.live.load(Ordering::Acquire)
                || s.fault
                || cookie == 0
                || !id(&accept_id)
                || size_of_val(&**owner) == 0
                || s.entries.len() >= 96
                || s.entries.keys().any(|(address, _)| *address == key.0)
            {
                s.fault = true;
                return None;
            }
            s.ordinal = s.ordinal.checked_add(1)?;
            let ingress_sequence = if let Some(o) = s.observer.upgrade() {
                if let Some(n) = o.note_transport() {
                    n
                } else {
                    s.fault = true;
                    return None;
                }
            } else {
                0
            };
            let life = Arc::new(StreamLife {
                id: uuid::Uuid::new_v4().to_string(),
                live: AtomicBool::new(true),
                taken: AtomicBool::new(false),
                ready: AtomicBool::new(false),
                complete: AtomicBool::new(false),
                inspected: AtomicBool::new(false),
                close_requested: AtomicBool::new(false),
                requests: std::sync::atomic::AtomicU32::new(0),
                accept_id,
                connection_id: uuid::Uuid::new_v4().to_string(),
                accept_ordinal: s.ordinal,
                captured_time: system_now()?,
                ingress_sequence,
                policy: std::sync::atomic::AtomicU64::new(0),
            });
            // Pending membership is visible before asynchronous route evaluation.
            // The observer's serialized counter is advanced under this same
            // registry lock, so a current read cannot miss a new registration.
            s.entries.insert(key, life.clone());
            Some(StreamOwner {
                registry: Arc::downgrade(self),
                key,
                life,
            })
        }
        /// The borrow of the STILL OWNED original Box precedes all wrappers.
        #[allow(clippy::borrowed_box)] // take borrows the still-owned ORIGINAL Box
        pub fn take<T: ?Sized>(self: &Arc<Self>, owner: &Box<T>, cookie: u64) -> Option<PathLease> {
            let key = (std::ptr::from_ref(&**owner).cast::<()>() as usize, cookie);
            let mut s = self.inner.lock().ok()?;
            if !self.live.load(Ordering::Acquire) || s.fault {
                return None;
            }
            let Some(life) = s.entries.get(&key).cloned() else {
                s.fault = true;
                return None;
            };
            if !life.live.load(Ordering::Acquire) || life.taken.swap(true, Ordering::AcqRel) {
                s.fault = true;
                return None;
            }
            Some(PathLease {
                registry: Arc::downgrade(self),
                life,
            })
        }
        fn view<R>(&self, f: impl FnOnce(u32, bool) -> Option<R>) -> Option<R> {
            let s = self.inner.lock().ok()?;
            let pending = s.entries.values().try_fold(0u32, |n, v| {
                let setup = v.live.load(Ordering::Acquire)
                    && (!v.ready.load(Ordering::Acquire) || !v.inspected.load(Ordering::Acquire));
                n.checked_add(u32::from(setup))?
                    .checked_add(v.requests.load(Ordering::Acquire))
            })?;
            let revoked_incomplete = s
                .entries
                .values()
                .any(|v| !v.live.load(Ordering::Acquire) && !v.complete.load(Ordering::Acquire));
            f(
                pending,
                s.fault || revoked_incomplete || !self.live.load(Ordering::Acquire),
            )
        }
        fn attach(&self, observer: &Arc<Observer>) -> bool {
            let Ok(mut s) = self.inner.lock() else {
                return false;
            };
            if !self.live.load(Ordering::Acquire) || s.fault || s.observer.strong_count() != 0 {
                return false;
            }
            s.observer = Arc::downgrade(observer);
            true
        }
        fn revoke(&self, key: (usize, u64), life: &Arc<StreamLife>) {
            // Revocation BEFORE allocation deallocation is independent of mutex
            // availability. Poison therefore cannot leave a live stale lease.
            life.live.store(false, Ordering::Release);
            let removed = self.inner.lock().map_or_else(
                |_| {
                    self.invalidate();
                    None
                },
                |mut s| {
                    if s.entries.get(&key).is_some_and(|v| v.id == life.id) {
                        // A clean byte bridge close is not evidence of an inspected route.
                        if !life.complete.load(Ordering::Acquire)
                            || !life.inspected.load(Ordering::Acquire)
                            || !life.ready.load(Ordering::Acquire)
                            || life.requests.load(Ordering::Acquire) != 0
                        {
                            s.fault = true;
                        }
                        s.entries.remove(&key)
                    } else {
                        None
                    }
                },
            );
            drop(removed); // not under registry lock, no destructor reentry
        }
    }
    /// Owned by the actual stream wrapper, not by registry metadata.
    pub struct StreamOwner {
        registry: std::sync::Weak<StreamRegistry>,
        key: (usize, u64),
        life: Arc<StreamLife>,
    }
    pub struct StreamCompletion {
        life: std::sync::Weak<StreamLife>,
    }
    impl StreamCompletion {
        pub fn complete(&self) {
            if let Some(life) = self.life.upgrade() {
                life.complete.store(true, Ordering::Release);
            }
        }
    }
    impl StreamOwner {
        pub fn completion(&self) -> StreamCompletion {
            StreamCompletion {
                life: Arc::downgrade(&self.life),
            }
        }
        pub fn complete(&self) {
            self.life.complete.store(true, Ordering::Release);
        }
        pub fn revoke(&self) {
            if let Some(r) = self.registry.upgrade() {
                r.revoke(self.key, &self.life);
            } else {
                self.life.live.store(false, Ordering::Release);
            }
        }
    }
    impl Drop for StreamOwner {
        fn drop(&mut self) {
            self.revoke();
        }
    }
    #[derive(Clone)]
    pub struct PathLease {
        registry: std::sync::Weak<StreamRegistry>,
        life: Arc<StreamLife>,
    }
    impl fmt::Debug for PathLease {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("PathLease(<mediation-not-writer>)")
        }
    }
    impl PathLease {
        pub fn live(&self) -> bool {
            self.registry
                .upgrade()
                .is_some_and(|r| r.live.load(Ordering::Acquire))
                && self.life.live.load(Ordering::Acquire)
                && self.life.taken.load(Ordering::Acquire)
        }
        /// Generation is captured by real supervisor authorization, NEVER the
        /// boundary `NetworkConnected.policy_generation` placeholder (currently0).
        pub fn authorized(&self, generation: Option<u64>) -> bool {
            let Some(r) = self.registry.upgrade() else {
                return false;
            };
            let Ok(mut s) = r.inner.lock() else {
                r.invalidate();
                return false;
            };
            let Some(generation) = generation else {
                s.fault = true;
                return false;
            };
            if !self.live() || s.fault {
                s.fault = true;
                return false;
            }
            if self.life.ready.swap(true, Ordering::AcqRel) {
                s.fault = true;
                return false;
            }
            self.life.policy.store(generation, Ordering::Release);
            if let Some(observer) = s.observer.upgrade()
                && self.life.ingress_sequence != 0
                && !observer.finish_transport(self, generation)
            {
                s.fault = true;
                return false;
            }
            true
        }
        pub fn connection_id(&self) -> &str {
            &self.life.connection_id
        }
        pub fn receipt(&self, snapshot: &ProviderObservationSnapshotV1) -> Option<String> {
            if !self.live() || !self.life.ready.load(Ordering::Acquire) || !valid_snapshot(snapshot)
            {
                return None;
            }
            let mut raw = b"openshell.provider-detach.sandbox-mediation-stream/v1\n".to_vec();
            for v in [
                &snapshot.mediation_path_receipt_sha256,
                &self.life.connection_id,
                &self.life.accept_id,
                &snapshot.mediation_path_id,
                &snapshot.source_incarnation,
            ] {
                raw.extend(u32::try_from(v.len()).ok()?.to_be_bytes());
                raw.extend(v.as_bytes());
            }
            raw.extend(self.life.accept_ordinal.to_be_bytes());
            raw.extend(self.life.policy.load(Ordering::Acquire).to_be_bytes());
            Some(witness_sha256(&raw))
        }
    }

    // This context is installed only around the trusted proxy's ORIGINAL
    // connection future. It is not inherited by spawned tasks, supplied by a
    // workload header, or recoverable by a cookie lookup. Request/response
    // functions run in that future; an absent context never yields evidence.
    tokio::task_local! { static CONNECTION: Arc<ConnectionObservation>; }
    struct ConnectionObservation {
        credentials: ProviderCredentialState,
        lease: Option<PathLease>,
        current: Mutex<Option<Arc<RequestObservation>>>,
    }
    pub async fn on_connection<F: Future>(
        credentials: Option<ProviderCredentialState>,
        lease: Option<PathLease>,
        future: F,
    ) -> F::Output {
        match credentials.filter(|v| v.observation_boundary().is_some()) {
            Some(credentials) => {
                CONNECTION
                    .scope(
                        Arc::new(ConnectionObservation {
                            credentials,
                            lease,
                            current: Mutex::new(None),
                        }),
                        future,
                    )
                    .await
            }
            None => future.await,
        }
    }
    /// Called on the first actual HTTP header byte, BEFORE interpretation.
    ///
    /// A transport or unsupported route remains pending if it never reaches
    /// this selected parser. Kernel packet arrival is not the observation edge.
    pub fn request_ingress() {
        let _ = CONNECTION.try_with(|connection| {
            let Ok(mut current) = connection.current.lock() else {
                return;
            };
            if current
                .as_ref()
                .is_some_and(|a| !a.done.load(Ordering::Acquire))
            {
                if let Some(o) = connection.credentials.ordinary_observer() {
                    o.invalidate();
                }
                return;
            }
            let Some(lease) = &connection.lease else {
                if let Some(o) = connection.credentials.ordinary_observer() {
                    o.invalidate();
                }
                return;
            };
            let Some(registry) = lease.registry.upgrade() else {
                return;
            };
            let Ok(mut entries) = registry.inner.lock() else {
                registry.invalidate();
                return;
            };
            if !lease.live() || entries.fault {
                return;
            }
            lease.life.inspected.store(true, Ordering::Release);
            lease.life.complete.store(false, Ordering::Release);
            lease.life.close_requested.store(false, Ordering::Release);
            if lease
                .life
                .requests
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
                .is_err()
            {
                entries.fault = true;
                return;
            }
            let observer = entries.observer.upgrade();
            let Some(now) = system_now() else {
                entries.fault = true;
                return;
            };
            let sequence = observer.as_ref().and_then(|o| o.ingress(now));
            if observer.is_some() && sequence.is_none() {
                entries.fault = true;
            }
            *current = Some(Arc::new(RequestObservation {
                observer,
                lease: lease.clone(),
                sequence: sequence.unwrap_or(0),
                event: Mutex::new(ProviderObservationEventV1 {
                    ingress_sequence: sequence.unwrap_or(0),
                    native_request_id: uuid::Uuid::new_v4().to_string(),
                    native_response_id: uuid::Uuid::new_v4().to_string(),
                    native_connection_id: lease.connection_id().into(),
                    response_sequence: sequence.unwrap_or(0),
                    captured_time: Some(timestamp(now)),
                    route_class: "other_unknown".into(),
                    request_stream_class: "unobserved".into(),
                    rewrite: ProviderObservationRewriteV1::Unsupported as i32,
                    response_origin: "unobserved".into(),
                    http_framing: "unobserved".into(),
                    client_socket_write: "unobserved".into(),
                    attempt_kind: "request".into(),
                    ..Default::default()
                }),
                done: AtomicBool::new(false),
            }));
        });
    }
    /// Clean idle HTTP EOF is distinct from cancelled/uncompleted parsing.
    pub fn request_end_of_stream() {
        let _ = CONNECTION.try_with(|c| {
            if let Some(lease) = &c.lease
                && c.current
                    .lock()
                    .ok()
                    .is_some_and(|v| v.as_ref().is_none_or(|a| a.done.load(Ordering::Acquire)))
                && lease.life.requests.load(Ordering::Acquire) == 0
                && lease.life.inspected.load(Ordering::Acquire)
            {
                lease.life.complete.store(true, Ordering::Release);
            }
        });
    }
    pub fn request_observation() -> Option<Arc<RequestObservation>> {
        CONNECTION
            .try_with(|c| c.current.lock().ok()?.clone())
            .ok()
            .flatten()
    }
    pub struct RequestObservation {
        observer: Option<Arc<Observer>>,
        lease: PathLease,
        sequence: u64,
        event: Mutex<ProviderObservationEventV1>,
        done: AtomicBool,
    }
    impl fmt::Debug for RequestObservation {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("RequestObservation(<native-metadata>)")
        }
    }
    impl RequestObservation {
        pub async fn expected(
            &self,
            authorization: &str,
            host: &str,
            port: u16,
            target: &str,
            generation: u64,
            revision: u64,
        ) -> bool {
            let Some(o) = &self.observer else {
                return false;
            };
            if !self.lease.live() || o.boundary.path().await.as_ref() != Some(&o.path) {
                o.invalidate();
                return false;
            }
            let Some(now) = system_now() else {
                return false;
            };
            let Some(s) = o.lock(now) else {
                return false;
            };
            let matches = s.snapshot.policy_generation == generation
                && s.snapshot.resolver_generation == revision
                && s.windows.values().any(|w| {
                    w.result.state == ProviderObservationStateV1::Open as i32
                        && w.active.contains(&self.sequence)
                        && w.subject.matches_original_static_bearer(
                            authorization,
                            host,
                            port,
                            target,
                        )
                });
            let snapshot = s.snapshot.clone();
            drop(s);
            let Some(receipt) = self.lease.receipt(&snapshot) else {
                return false;
            };
            let Ok(mut e) = self.event.lock() else {
                o.invalidate();
                return false;
            };
            e.mediation_stream_receipt_sha256 = receipt;
            e.policy_generation = generation;
            e.resolver_generation = revision;
            e.route_class = match target.split('?').next().unwrap_or("") {
                "/v1/messages" | "/messages" => "messages",
                "/v1/messages/count_tokens" | "/messages/count_tokens" => "count_tokens",
                _ => "other_unknown",
            }
            .into();
            matches
        }
        pub fn rewrite(&self, value: ProviderObservationRewriteV1) {
            if let Ok(mut e) = self.event.lock() {
                e.rewrite = value as i32;
            }
        }
        pub fn upstream_write(&self, n: usize) {
            if let Ok(mut e) = self.event.lock() {
                if let Some(v) = e.upstream_application_request_bytes.checked_add(n as u64) {
                    e.upstream_application_request_bytes = v;
                } else if let Some(o) = &self.observer {
                    o.invalidate();
                }
            }
        }
        pub fn upstream_read(&self, n: usize) {
            if n != 0
                && let Ok(mut e) = self.event.lock()
            {
                e.response_origin = "upstream".into();
                if let Some(v) = e.upstream_response_bytes.checked_add(n as u64) {
                    e.upstream_response_bytes = v;
                } else if let Some(o) = &self.observer {
                    o.invalidate();
                }
            }
        }
        pub fn relay_failed(&self) {
            if let Ok(mut e) = self.event.lock()
                && e.rewrite != ProviderObservationRewriteV1::ExpectedUnavailable as i32
            {
                e.http_framing = "partial_or_unknown".into();
                e.client_socket_write = "unobserved".into();
            }
        }
        pub fn close_after_response(&self) {
            self.lease
                .life
                .close_requested
                .store(true, Ordering::Release);
        }
        pub fn framing_complete(&self) {
            if let Ok(mut e) = self.event.lock() {
                e.http_framing = "complete".into();
                e.client_socket_write = "accepted".into();
            }
        }
        pub async fn finish(&self) {
            if self.done.swap(true, Ordering::AcqRel) {
                return;
            }
            self.lease.life.requests.fetch_sub(1, Ordering::AcqRel);
            let Some(o) = &self.observer else {
                if self.lease.life.close_requested.load(Ordering::Acquire) {
                    self.lease.life.complete.store(true, Ordering::Release);
                }
                return;
            };
            if !self.lease.live() || o.boundary.path().await.as_ref() != Some(&o.path) {
                o.invalidate();
                return;
            }
            let Some(now) = system_now() else {
                o.invalidate();
                return;
            };
            let Ok(mut e) = self.event.lock() else {
                o.invalidate();
                return;
            };
            e.closed_time = Some(timestamp(now));
            if e.rewrite == ProviderObservationRewriteV1::ExpectedUnavailable as i32
                && e.upstream_application_request_bytes == 0
            {
                e.response_origin = "native_refusal".into();
                e.http_framing = "not_applicable".into();
            }
            let completion = (e.rewrite
                == ProviderObservationRewriteV1::ExpectedUnavailable as i32
                && e.upstream_application_request_bytes == 0)
                || (e.http_framing == "complete"
                    && self.lease.life.close_requested.load(Ordering::Acquire));
            if !o.finish(e.clone(), now) {
                o.invalidate();
            } else if completion && self.lease.life.requests.load(Ordering::Acquire) == 0 {
                self.lease.life.complete.store(true, Ordering::Release);
            }
        }
    }
    impl Drop for RequestObservation {
        fn drop(&mut self) {
            if !self.done.load(Ordering::Acquire) {
                self.lease.life.requests.fetch_sub(1, Ordering::AcqRel);
                if let Some(o) = &self.observer {
                    o.invalidate();
                }
                if let Some(r) = self.lease.registry.upgrade() {
                    r.invalidate();
                }
            }
        }
    }

    struct Window {
        result: ProviderObservationResultV1,
        subject: Arc<ProviderRevocationSubject>,
        active: HashSet<u64>,
        fault: bool,
    }
    struct State {
        snapshot: ProviderObservationSnapshotV1,
        windows: HashMap<String, Window>,
        issued_reads: HashSet<Vec<u8>>,
        last_time: i64,
        poisoned: bool,
        install_sequence: u64,
    }
    /// Per original execution, shared by ingress, terminal, and current reads.
    /// Its ordering mutex is never held across a transport wait.
    pub struct Observer {
        inner: Mutex<State>,
        live: AtomicBool,
        pub boundary: Arc<dyn Boundary>,
        path: OwnedPath,
    }
    impl fmt::Debug for Observer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Observer(<original-source>)")
        }
    }
    impl Observer {
        pub async fn from_boundary(
            snapshot: ProviderObservationSnapshotV1,
            boundary: Arc<dyn Boundary>,
        ) -> Option<Arc<Self>> {
            let path = boundary.path().await?;
            if snapshot.boundary_incarnation != path.boundary_incarnation
                || snapshot.mediation_path_id != path.mediation_path_id
                || snapshot.resource.as_ref()?.execution_id != path.execution_id
                || !valid_profile(&snapshot.profile_id, &snapshot.profile_sha256)
                || !id(&snapshot.source_incarnation)
                || !id(&snapshot.supervisor_session)
                || !valid_snapshot(&snapshot)
            {
                return None;
            }
            let observer = Arc::new(Self {
                inner: Mutex::new(State {
                    snapshot,
                    windows: HashMap::new(),
                    issued_reads: HashSet::new(),
                    last_time: 0,
                    poisoned: false,
                    install_sequence: 0,
                }),
                live: AtomicBool::new(true),
                boundary,
                path,
            });
            observer
                .boundary
                .streams()
                .attach(&observer)
                .then_some(observer)
        }
        fn lock(&self, now: i64) -> Option<MutexGuard<'_, State>> {
            let mut s = self.inner.lock().ok()?;
            if !self.live.load(Ordering::Acquire) || now < s.last_time || s.poisoned {
                s.poisoned = true;
                return None;
            }
            s.last_time = now;
            Some(s)
        }
        pub fn invalidate(&self) {
            self.live.store(false, Ordering::Release);
        }
        pub fn fault_open_windows(&self) {
            if let Ok(mut s) = self.inner.lock() {
                for w in s.windows.values_mut() {
                    if w.result.state == ProviderObservationStateV1::Open as i32 {
                        w.fault = true;
                    }
                }
            } else {
                self.invalidate();
            }
        }
        pub fn update_snapshot(&self, snapshot: ProviderObservationSnapshotV1, now: i64) -> bool {
            if !valid_snapshot(&snapshot) {
                return false;
            }
            let Some(mut s) = self.lock(now) else {
                return false;
            };
            if s.snapshot.profile_id != snapshot.profile_id
                || s.snapshot.profile_sha256 != snapshot.profile_sha256
                || s.snapshot.source_incarnation != snapshot.source_incarnation
                || s.snapshot.boundary_incarnation != snapshot.boundary_incarnation
                || s.snapshot.mediation_path_id != snapshot.mediation_path_id
                || s.snapshot.gateway_boot_id != snapshot.gateway_boot_id
                || s.snapshot.supervisor_instance != snapshot.supervisor_instance
                || s.snapshot.supervisor_session != snapshot.supervisor_session
                || (!s.windows.is_empty()
                    && (s.snapshot.mediation_path_receipt_sha256
                        != snapshot.mediation_path_receipt_sha256
                        || s.snapshot.resource != snapshot.resource))
            {
                return false;
            }
            // Discovery is a metadata projection, not a provider reservation.
            // Before ANY original install, a different authorized resource may
            // be projected without renewing source/path/session identities.
            if s.snapshot.configuration_sha256 != snapshot.configuration_sha256
                || s.snapshot.policy_generation != snapshot.policy_generation
                || s.snapshot.resolver_generation != snapshot.resolver_generation
            {
                for w in s.windows.values_mut() {
                    if w.result.state == ProviderObservationStateV1::Open as i32 {
                        w.fault = true;
                    }
                }
            }
            let counter = s.snapshot.current_ingress_sequence;
            s.snapshot = snapshot;
            s.snapshot.current_ingress_sequence = counter;
            true
        }
        pub async fn current(&self, now: i64) -> Option<ProviderObservationSnapshotV1> {
            if self.boundary.path().await? != self.path {
                self.invalidate();
                return None;
            }
            Some(self.lock(now)?.snapshot.clone())
        }
        pub fn install(
            &self,
            q: ProviderObservationRequestV1,
            subject: Arc<ProviderRevocationSubject>,
            now: i64,
        ) -> Option<ProviderObservationResultV1> {
            if !shape(&q) {
                return None;
            }
            let registry = self.boundary.streams();
            registry.view(|pending, registry_fault| {
                if pending != 0 || registry_fault {
                    return None;
                }
                let mut s = self.lock(now)?;
                let deadline = time_ms(q.deadline.as_ref()?)?;
                let end = deadline.checked_sub(5000)?;
                if end <= now
                    || end - now > 60_000
                    || s.windows.len() >= MAX_WINDOWS
                    || s.snapshot.profile_id != q.profile_id
                    || s.snapshot.profile_sha256 != q.profile_sha256
                    || s.snapshot.resource != q.resource
                    || s.snapshot.source_incarnation != q.source_incarnation
                    || s.snapshot.boundary_incarnation != q.boundary_incarnation
                    || q.resource.as_ref()?.provider_id != subject.provider_id
                    || (q.phase == ProviderObservationPhaseV1::Detached as i32
                        && q.baseline_mediation_path_receipt_sha256
                            != s.snapshot.mediation_path_receipt_sha256)
                    || s.windows.values().any(|w| {
                        w.result
                            .window
                            .as_ref()
                            .and_then(|w| w.request.as_ref())
                            .is_some_and(|r| r.request_sha256 == q.request_sha256)
                            || w.result.state == ProviderObservationStateV1::Open as i32
                    })
                {
                    return None;
                }
                let install_sequence = s.install_sequence.checked_add(1)?;
                let mut window = ProviderObservationWindowV1 {
                    request: Some(q),
                    installed_snapshot: Some(s.snapshot.clone()),
                    window_id: uuid::Uuid::new_v4().to_string(),
                    install_sequence,
                    installed_time: Some(timestamp(now)),
                    ingress_watermark: s.snapshot.current_ingress_sequence,
                    window_sha256: String::new(),
                    capture_end: Some(timestamp(end)),
                };
                window.window_sha256 = window_digest(&window);
                let result = ProviderObservationResultV1 {
                    window: Some(window),
                    state: ProviderObservationStateV1::Open as i32,
                    ..Default::default()
                };
                // Reserve every public event and the entire live read/reply BEFORE install.
                install_budget(result.window.as_ref()?.request.as_ref()?, &s.snapshot)?;
                let key = result
                    .window
                    .as_ref()?
                    .request
                    .as_ref()?
                    .request_sha256
                    .clone();
                s.install_sequence = install_sequence;
                s.windows.insert(
                    key,
                    Window {
                        result: result.clone(),
                        subject,
                        active: HashSet::new(),
                        fault: false,
                    },
                );
                Some(result)
            })
        }
        /// Allocate before request interpretation, including unsupported transport.
        /// Every relevant ingress increments the SAME counter, even after terminal.
        pub fn ingress(&self, now: i64) -> Option<u64> {
            let mut s = self.lock(now)?;
            s.snapshot.current_ingress_sequence =
                s.snapshot.current_ingress_sequence.checked_add(1)?;
            let seq = s.snapshot.current_ingress_sequence;
            for w in s.windows.values_mut() {
                if w.result.state == ProviderObservationStateV1::Open as i32 {
                    if w.active.len() >= MAX_EVENTS
                        || w.result.events.len() + w.active.len() >= MAX_EVENTS
                    {
                        w.fault = true;
                    } else {
                        w.active.insert(seq);
                    }
                }
            }
            Some(seq)
        }
        fn note_transport(&self) -> Option<u64> {
            let mut s = self.inner.lock().ok()?;
            s.snapshot.current_ingress_sequence =
                s.snapshot.current_ingress_sequence.checked_add(1)?;
            let seq = s.snapshot.current_ingress_sequence;
            for w in s.windows.values_mut() {
                if w.result.state == ProviderObservationStateV1::Open as i32 {
                    if w.active.len() + w.result.events.len() >= MAX_EVENTS {
                        w.fault = true;
                    } else {
                        w.active.insert(seq);
                    }
                }
            }
            Some(seq)
        }
        fn finish_transport(&self, lease: &PathLease, generation: u64) -> bool {
            let Some(now) = system_now() else {
                return false;
            };
            let snapshot = {
                let Some(s) = self.lock(now) else {
                    return false;
                };
                s.snapshot.clone()
            };
            let Some(receipt) = lease.receipt(&snapshot) else {
                return false;
            };
            let event = ProviderObservationEventV1 {
                ingress_sequence: lease.life.ingress_sequence,
                native_request_id: uuid::Uuid::new_v4().to_string(),
                native_connection_id: lease.connection_id().into(),
                captured_time: Some(timestamp(lease.life.captured_time)),
                mediation_stream_receipt_sha256: receipt,
                route_class: "unobserved".into(),
                request_stream_class: "unobserved".into(),
                rewrite: ProviderObservationRewriteV1::Unobserved as i32,
                native_response_id: uuid::Uuid::new_v4().to_string(),
                response_origin: "not_applicable".into(),
                response_sequence: lease.life.ingress_sequence,
                http_framing: "not_applicable".into(),
                client_socket_write: "not_applicable".into(),
                closed_time: Some(timestamp(now)),
                policy_generation: generation,
                resolver_generation: snapshot.resolver_generation,
                attempt_kind: "transport".into(),
                ..Default::default()
            };
            // No open window is not an accounting failure. The pending stream
            // remained visible before this actual authorization completed.
            let open = self.inner.lock().ok().is_some_and(|s| {
                s.windows
                    .values()
                    .any(|w| w.result.state == ProviderObservationStateV1::Open as i32)
            });
            !open || self.finish(event, now)
        }
        pub fn subject_matches(
            &self,
            key: &str,
            value: &str,
            host: &str,
            port: u16,
            path: &str,
            now: i64,
        ) -> bool {
            self.lock(now)
                .and_then(|s| {
                    s.windows.get(key).map(|w| {
                        w.subject
                            .matches_original_static_bearer(value, host, port, path)
                    })
                })
                .unwrap_or(false)
        }
        pub fn finish(&self, event: ProviderObservationEventV1, now: i64) -> bool {
            let Some(mut s) = self.lock(now) else {
                return false;
            };
            let mut recorded = false;
            for w in s.windows.values_mut() {
                if w.result.state != ProviderObservationStateV1::Open as i32 {
                    continue;
                }
                if !w.active.remove(&event.ingress_sequence)
                    || event.encoded_len() > MAX_EVENT
                    || w.result.events.len() >= MAX_EVENTS
                    || time_ms(
                        w.result
                            .window
                            .as_ref()
                            .unwrap()
                            .capture_end
                            .as_ref()
                            .unwrap(),
                    )
                    .is_none_or(|end| now > end)
                {
                    w.fault = true;
                    continue;
                }
                let installed = w
                    .result
                    .window
                    .as_ref()
                    .and_then(|v| v.installed_snapshot.as_ref());
                if installed.is_none_or(|v| {
                    v.policy_generation != event.policy_generation
                        || v.resolver_generation != event.resolver_generation
                }) || event.mediation_stream_receipt_sha256.len() != 64
                    || (event.attempt_kind != "transport"
                        && (!matches!(
                            ProviderObservationRewriteV1::try_from(event.rewrite),
                            Ok(ProviderObservationRewriteV1::ExpectedMaterialized
                                | ProviderObservationRewriteV1::ExpectedUnavailable)
                        ) || (event.rewrite
                            == ProviderObservationRewriteV1::ExpectedMaterialized as i32
                            && event.http_framing != "complete")
                            || (event.rewrite
                                == ProviderObservationRewriteV1::ExpectedUnavailable as i32
                                && event.upstream_application_request_bytes != 0)))
                {
                    w.fault = true;
                }
                w.result.events.push(event.clone());
                w.result.events.sort_unstable_by_key(|e| e.ingress_sequence);
                recorded = true;
            }
            recorded
        }
        pub fn close(&self, key: &str, now: i64) -> Option<ProviderObservationResultV1> {
            let registry = self.boundary.streams();
            registry.view(|pending, registry_fault| {
                let mut s = self.lock(now)?;
                let w = s.windows.get_mut(key)?;
                if w.result.state == ProviderObservationStateV1::Open as i32 {
                    let end = time_ms(w.result.window.as_ref()?.capture_end.as_ref()?)?;
                    if now < end {
                        return Some(w.result.clone());
                    }
                    w.result.state = if registry_fault
                        || pending != 0
                        || w.fault
                        || !w.active.is_empty()
                        || w.result.events.is_empty()
                    {
                        ProviderObservationStateV1::Unknown as i32
                    } else {
                        ProviderObservationStateV1::Terminal as i32
                    };
                    w.result.closed_time = Some(timestamp(end));
                    w.result.terminal_sha256 = terminal_digest(&w.result);
                }
                Some(w.result.clone())
            })
        }
        /// Read request receipt precedes this actual serialized ingress sample.
        pub async fn read(
            &self,
            q: ProviderObservationCurrentReadV1,
            _received_at: i64,
        ) -> Option<ProviderObservationCurrentReplyV1> {
            if self.boundary.path().await? != self.path {
                self.invalidate();
                return None;
            }
            let now = crate::time::timestamp_from_system_time(std::time::SystemTime::now())
                .ok()
                .and_then(|t| time_ms(&t))?;
            self.sample_read(q, now)
        }
        fn sample_read(
            &self,
            q: ProviderObservationCurrentReadV1,
            now: i64,
        ) -> Option<ProviderObservationCurrentReplyV1> {
            if !read_fits(&q)
                || q.read_correlation.len() != 16
                || time_ms(q.read_deadline.as_ref()?)? <= now
                || time_ms(q.read_deadline.as_ref()?)? - now > 2000
            {
                return None;
            }
            let registry = self.boundary.streams();
            registry.view(|pending, registry_fault| {
                let mut s = self.lock(now)?;
                let expected = q.expected_identity.as_ref()?;
                let selector = q.selector.as_ref()?;
                let discovery = selector.original_request.is_none() && selector.resource.is_some();
                let mut expected_identity = expected.clone();
                let mut actual_identity = s.snapshot.clone();
                if discovery {
                    expected_identity.configuration_sha256.clear();
                    actual_identity.configuration_sha256.clear();
                    expected_identity.policy_generation = 0;
                    actual_identity.policy_generation = 0;
                    expected_identity.resolver_generation = 0;
                    actual_identity.resolver_generation = 0;
                }
                if !same_identity(&expected_identity, &actual_identity)
                    || expected.current_ingress_sequence > s.snapshot.current_ingress_sequence
                    || s.issued_reads.len() >= 4096
                    || !s.issued_reads.insert(q.read_correlation.clone())
                {
                    return None;
                }
                let (active, fault) = match (&selector.original_request, &selector.resource) {
                    (None, Some(r))
                        if Some(r) == s.snapshot.resource.as_ref()
                            && q.window_sha256.is_empty()
                            && q.terminal_sha256.is_empty() =>
                    {
                        (0, false)
                    }
                    (Some(original), None) if shape(original) => {
                        let w = s.windows.get(&original.request_sha256)?;
                        if w.result.window.as_ref()?.request.as_ref() != Some(original)
                            || w.result.window.as_ref()?.window_sha256 != q.window_sha256
                            || w.result.terminal_sha256 != q.terminal_sha256
                            || time_ms(original.deadline.as_ref()?)? <= now
                        {
                            return None;
                        }
                        (u32::try_from(w.active.len()).ok()?, w.fault)
                    }
                    _ => return None,
                };
                let reply = ProviderObservationCurrentReplyV1 {
                    original_read: Some(q),
                    sampled_snapshot: Some(s.snapshot.clone()),
                    active_attempts: active.checked_add(pending)?,
                    accounting_fault: fault || registry_fault,
                    sampled_time: Some(timestamp(now)),
                };
                reply_fits(&reply).then_some(reply)
            })
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::proto::ProviderDetachResourceV1;
        #[derive(Debug)]
        struct FakeBoundary {
            path: Mutex<Option<OwnedPath>>,
            streams: Arc<StreamRegistry>,
        }
        #[async_trait::async_trait]
        impl Boundary for FakeBoundary {
            async fn path(&self) -> Option<OwnedPath> {
                self.path.lock().ok()?.clone()
            }
            fn streams(&self) -> Arc<StreamRegistry> {
                self.streams.clone()
            }
        }
        fn uuid() -> String {
            uuid::Uuid::new_v4().to_string()
        }
        async fn fixture() -> (
            Arc<Observer>,
            ProviderObservationRequestV1,
            Arc<ProviderRevocationSubject>,
            Arc<FakeBoundary>,
        ) {
            let resource = ProviderDetachResourceV1 {
                authority: "gateway".into(),
                workspace: "default".into(),
                sandbox: "agent".into(),
                sandbox_id: uuid(),
                execution_id: format!("exec-v1:{}", "a".repeat(64)),
                provider: "provider".into(),
                provider_id: uuid(),
            };
            let path = OwnedPath {
                boundary_incarnation: uuid(),
                execution_id: resource.execution_id.clone(),
                mediation_path_id: uuid(),
            };
            let boundary = Arc::new(FakeBoundary {
                path: Mutex::new(Some(path.clone())),
                streams: StreamRegistry::new(),
            });
            let mut snapshot = ProviderObservationSnapshotV1 {
                resource: Some(resource.clone()),
                profile_id: PROFILE.into(),
                profile_sha256: profile_digest(),
                source_incarnation: uuid(),
                boundary_incarnation: path.boundary_incarnation,
                gateway_boot_id: uuid(),
                supervisor_instance: uuid(),
                supervisor_session: uuid(),
                configuration_sha256: "c".repeat(64),
                policy_generation: 1,
                resolver_generation: 7,
                mediation_path_receipt_sha256: String::new(),
                current_ingress_sequence: 0,
                evidence_scope: EVIDENCE_SCOPE.into(),
                process_writer_attribution: WRITER_UNPROVEN,
                mediation_path_id: path.mediation_path_id,
            };
            snapshot.mediation_path_receipt_sha256 = path_digest(&snapshot);
            let mut request = ProviderObservationRequestV1 {
                resource: Some(resource.clone()),
                run_id: uuid(),
                step_id: uuid(),
                profile_id: PROFILE.into(),
                profile_sha256: profile_digest(),
                source_incarnation: snapshot.source_incarnation.clone(),
                boundary_incarnation: snapshot.boundary_incarnation.clone(),
                deadline: Some(timestamp(6010)),
                phase: ProviderObservationPhaseV1::Baseline as i32,
                evidence_scope: EVIDENCE_SCOPE.into(),
                ..Default::default()
            };
            request.request_sha256 = request_digest(&request);
            let subject = Arc::new(ProviderRevocationSubject {
                provider_id: resource.provider_id,
                installation_id: uuid(),
                revision: 7,
                keys: Vec::new(),
                references: Vec::new(),
                metadata_bytes: 0,
            });
            let observer = Observer::from_boundary(snapshot, boundary.clone())
                .await
                .unwrap();
            (observer, request, subject, boundary)
        }
        fn event(sequence: u64, stream: &str) -> ProviderObservationEventV1 {
            ProviderObservationEventV1 {
                ingress_sequence: sequence,
                native_request_id: format!("q{sequence}"),
                native_connection_id: "connection".into(),
                captured_time: Some(timestamp(1001)),
                mediation_stream_receipt_sha256: "d".repeat(64),
                route_class: "messages".into(),
                request_stream_class: stream.into(),
                rewrite: ProviderObservationRewriteV1::ExpectedMaterialized as i32,
                native_response_id: format!("r{sequence}"),
                response_origin: "upstream".into(),
                response_sequence: sequence,
                http_framing: "complete".into(),
                client_socket_write: "accepted".into(),
                closed_time: Some(timestamp(1002)),
                policy_generation: 1,
                resolver_generation: 7,
                attempt_kind: "request".into(),
                ..Default::default()
            }
        }
        fn read(
            result: &ProviderObservationResultV1,
            correlation: u8,
        ) -> ProviderObservationCurrentReadV1 {
            let window = result.window.as_ref().unwrap();
            ProviderObservationCurrentReadV1 {
                selector: Some(GetProviderDetachObservationRequest {
                    original_request: window.request.clone(),
                    resource: None,
                    workspace_scope: None,
                }),
                expected_identity: window.installed_snapshot.clone(),
                read_correlation: vec![correlation; 16],
                read_deadline: Some(timestamp(1500)),
                window_sha256: window.window_sha256.clone(),
                terminal_sha256: result.terminal_sha256.clone(),
            }
        }
        #[tokio::test]
        async fn ordinary_pending_later_ingress_cannot_hide_behind_terminal_report() {
            let (observer, q, subject, _) = fixture().await;
            observer.install(q.clone(), subject, 1000).unwrap();
            let seq = observer.ingress(1001).unwrap();
            assert!(observer.finish(event(seq, "true"), 1002));
            let result = observer.close(&q.request_sha256, 1010).unwrap();
            assert_eq!(result.state, ProviderObservationStateV1::Terminal as i32);
            let current = observer.sample_read(read(&result, 1), 1011).unwrap();
            assert_eq!(
                current.sampled_snapshot.unwrap().current_ingress_sequence,
                seq
            );
            let later = observer.ingress(1012).unwrap(); // report intentionally not delivered
            let current = observer.sample_read(read(&result, 2), 1013).unwrap();
            assert_eq!(
                current.sampled_snapshot.unwrap().current_ingress_sequence,
                later
            );
            assert_ne!(later, result.events.last().unwrap().ingress_sequence);
            assert_eq!(observer.close(&q.request_sha256, 1014).unwrap(), result);
        }
        #[tokio::test]
        async fn ordinary_accounts_stream_and_nonstream_without_early_close() {
            let (observer, q, subject, _) = fixture().await;
            observer.install(q.clone(), subject, 1000).unwrap();
            let a = observer.ingress(1001).unwrap();
            let mut first = event(a, "true");
            first.http_framing = "incomplete".into();
            observer.finish(first, 1002);
            assert_eq!(
                observer.close(&q.request_sha256, 1003).unwrap().state,
                ProviderObservationStateV1::Open as i32
            );
            let b = observer.ingress(1004).unwrap();
            observer.finish(event(b, "false"), 1005);
            let r = observer.close(&q.request_sha256, 1010).unwrap();
            assert_eq!(
                r.events
                    .iter()
                    .map(|e| e.request_stream_class.as_str())
                    .collect::<Vec<_>>(),
                vec!["true", "false"]
            );
        }
        #[tokio::test]
        async fn ordinary_drop_overflow_and_active_at_end_are_unknown() {
            for count in [1, 9] {
                let (observer, q, subject, _) = fixture().await;
                observer.install(q.clone(), subject, 1000).unwrap();
                for _ in 0..count {
                    observer.ingress(1001).unwrap();
                }
                assert_eq!(
                    observer.close(&q.request_sha256, 1010).unwrap().state,
                    ProviderObservationStateV1::Unknown as i32
                );
            }
        }
        #[tokio::test]
        async fn ordinary_read_replay_wrong_session_expiry_and_identity_refuse() {
            let (observer, q, subject, boundary) = fixture().await;
            observer.install(q.clone(), subject, 1000).unwrap();
            let n = observer.ingress(1001).unwrap();
            observer.finish(event(n, "unobserved"), 1002);
            let r = observer.close(&q.request_sha256, 1010).unwrap();
            let valid = read(&r, 1);
            assert!(observer.sample_read(valid.clone(), 1011).is_some());
            assert!(observer.sample_read(valid.clone(), 1012).is_none());
            let mut wrong = read(&r, 2);
            wrong.expected_identity.as_mut().unwrap().supervisor_session = uuid();
            assert!(observer.sample_read(wrong, 1013).is_none());
            assert!(observer.sample_read(read(&r, 3), 1500).is_none());
            *boundary.path.lock().unwrap() = None;
            assert!(observer.current(1501).await.is_none());
        }
        struct TestStream {
            guard: Option<StreamOwner>,
            payload: u64,
        }
        impl Drop for TestStream {
            fn drop(&mut self) {
                if let Some(g) = &self.guard {
                    g.revoke();
                }
            }
        }
        fn registered(r: &Arc<StreamRegistry>, cookie: u64) -> Box<TestStream> {
            let mut owner = Box::new(TestStream {
                guard: None,
                payload: 7,
            });
            owner.guard = Some(r.register(&owner, cookie, uuid()).unwrap());
            owner
        }
        #[test]
        fn ordinary_stream_drop_revokes_before_same_allocation_reuse() {
            let r = StreamRegistry::new();
            let mut stream = registered(&r, 11);
            let lease = r.take(&stream, 11).unwrap();
            assert!(lease.authorized(Some(3)));
            let old_key = (std::ptr::from_ref(&*stream).cast::<()>() as usize, 11);
            let old_life = lease.life.clone();
            lease.life.inspected.store(true, Ordering::Release);
            stream.guard.as_ref().unwrap().complete();
            // Reuse actual owned storage without any unsafe duplicate Box or
            // pointer dereference. Assignment must DROP the old stream first.
            *stream = TestStream {
                guard: None,
                payload: 9,
            };
            assert!(!lease.live());
            assert!(r.inner.lock().unwrap().entries.is_empty());
            stream.guard = Some(r.register(&stream, 11, uuid()).unwrap());
            let fresh = r.take(&stream, 11).unwrap();
            assert!(fresh.authorized(Some(3)));
            fresh.life.inspected.store(true, Ordering::Release);
            r.revoke(old_key, &old_life); // delayed old cleanup must not evict new
            assert!(fresh.live());
            assert!(
                r.view(|pending, fault| Some((pending, fault)))
                    .is_some_and(|v| v == (0, false))
            );
            stream.guard.as_ref().unwrap().complete();
            drop(stream);
            assert!(!fresh.live());
        }
        #[test]
        fn ordinary_stream_take_is_live_owned_once_not_cookie_or_rebox() {
            let r = StreamRegistry::new();
            let stream = registered(&r, 12);
            let lease = r.take(&stream, 12).unwrap();
            assert!(lease.live());
            assert!(r.take(&stream, 12).is_none());
            assert!(r.view(|_, fault| Some(fault)).unwrap());
            drop(stream);
            assert!(!lease.live());
            let r = StreamRegistry::new();
            let stream = registered(&r, 13);
            let wrapper = Box::new(stream);
            assert!(r.take(&wrapper, 13).is_none()); // wrapper BEFORE take
            let other = StreamRegistry::new();
            assert!(other.take(&*wrapper, 13).is_none());
        }
        #[test]
        fn ordinary_stream_abandon_pending_capacity_and_poison_refuse() {
            let r = StreamRegistry::new();
            let stream = registered(&r, 14);
            assert_eq!(r.view(|p, f| Some((p, f))), Some((1, false)));
            drop(stream);
            assert_eq!(r.view(|p, f| Some((p, f))), Some((0, true)));
            let r = StreamRegistry::new();
            let mut streams = Vec::new();
            for cookie in 1..=96 {
                streams.push(registered(&r, cookie));
            }
            let extra = Box::new(TestStream {
                guard: None,
                payload: 8,
            });
            assert!(r.register(&extra, 97, uuid()).is_none());
            assert!(r.view(|_, f| Some(f)).unwrap());
            drop(streams);
            let r = StreamRegistry::new();
            let stream = registered(&r, 15);
            let lease = r.take(&stream, 15).unwrap();
            let r2 = r.clone();
            assert!(
                std::thread::spawn(move || {
                    let _lock = r2.inner.lock().unwrap();
                    panic!("synthetic registry poison");
                })
                .join()
                .is_err()
            );
            drop(stream);
            assert!(!lease.live());
            assert!(r.view(|p, _| Some(p)).is_none());
        }
        #[test]
        fn ordinary_stream_zero_size_duplicate_and_drop_reentry_refuse_safely() {
            let r = StreamRegistry::new();
            assert!(r.register(&Box::new(()), 91, uuid()).is_none());
            let r = StreamRegistry::new();
            let stream = registered(&r, 92);
            assert!(r.register(&stream, 93, uuid()).is_none()); // changing a cookie cannot duplicate an allocation
            drop(stream);
            struct Reentrant {
                guard: Option<StreamOwner>,
                registry: Arc<StreamRegistry>,
                closed: Arc<AtomicBool>,
            }
            impl Drop for Reentrant {
                fn drop(&mut self) {
                    drop(self.guard.take());
                    assert_eq!(
                        self.registry.view(|pending, fault| Some((pending, fault))),
                        Some((0, false))
                    );
                    self.closed.store(true, Ordering::Release);
                }
            }
            let r = StreamRegistry::new();
            let closed = Arc::new(AtomicBool::new(false));
            let mut stream = Box::new(Reentrant {
                guard: None,
                registry: r.clone(),
                closed: closed.clone(),
            });
            stream.guard = Some(r.register(&stream, 94, uuid()).unwrap());
            stream.guard.as_ref().unwrap().complete();
            let lease = r.take(&stream, 94).unwrap();
            assert!(lease.authorized(Some(1)));
            lease.life.inspected.store(true, Ordering::Release);
            drop(stream);
            assert!(closed.load(Ordering::Acquire));
            assert!(!lease.live());
        }
        #[test]
        fn ordinary_authorized_raw_close_does_not_erase_uninspected_fault() {
            let registry = StreamRegistry::new();
            let stream = registered(&registry, 96);
            let lease = registry.take(&stream, 96).unwrap();
            assert!(lease.authorized(Some(1)));
            stream.guard.as_ref().unwrap().complete();
            drop(stream);
            assert_eq!(registry.view(|p, f| Some((p, f))), Some((0, true)));
            assert!(!lease.live());
        }
        #[tokio::test]
        async fn ordinary_clean_uninspected_close_keeps_window_unknown() {
            let (observer, q, subject, boundary) = fixture().await;
            observer.install(q.clone(), subject, 1000).unwrap();
            let stream = registered(&boundary.streams, 95);
            let lease = boundary.streams.take(&stream, 95).unwrap();
            stream.guard.as_ref().unwrap().complete();
            drop(stream);
            assert_eq!(boundary.streams.view(|p, f| Some((p, f))), Some((0, true)));
            assert_eq!(
                observer.close(&q.request_sha256, 1010).unwrap().state,
                ProviderObservationStateV1::Unknown as i32
            );
            assert!(!lease.live());
        }
        #[test]
        fn ordinary_stream_requires_captured_policy_and_original_pin() {
            let r = StreamRegistry::new();
            let stream = registered(&r, 16);
            let lease = r.take(&stream, 16).unwrap();
            assert!(!lease.authorized(None)); // boundary placeholder is NOT policy
            let r = StreamRegistry::new();
            let stream = registered(&r, 17);
            let lease = r.take(&stream, 17).unwrap();
            assert!(lease.authorized(Some(4)));
            r.invalidate();
            assert!(!lease.live());
            assert!(!lease.authorized(Some(4)));
        }
        #[tokio::test]
        async fn ordinary_pending_stream_cannot_hide_behind_cached_terminal_n() {
            let (observer, q, subject, boundary) = fixture().await;
            observer.install(q.clone(), subject, 1000).unwrap();
            let n = observer.ingress(1001).unwrap();
            observer.finish(event(n, "true"), 1002);
            let terminal = observer.close(&q.request_sha256, 1010).unwrap();
            let pending = registered(&boundary.streams, 18);
            let reply = observer.sample_read(read(&terminal, 8), 1011).unwrap();
            assert_eq!(reply.active_attempts, 1);
            assert!(reply.sampled_snapshot.unwrap().current_ingress_sequence > n);
            drop(pending);
            let reply = observer.sample_read(read(&terminal, 9), 1012).unwrap();
            assert!(reply.accounting_fault);
        }
        #[tokio::test]
        async fn ordinary_discovery_projection_is_not_a_provider_reservation() {
            let (observer, q, subject, _) = fixture().await;
            let original = observer.inner.lock().unwrap().snapshot.clone();
            let mut other = original.clone();
            other.resource.as_mut().unwrap().provider_id = uuid();
            other.resource.as_mut().unwrap().provider = "other".into();
            other.mediation_path_receipt_sha256 = path_digest(&other);
            assert!(observer.update_snapshot(other.clone(), 1000));
            {
                let s = observer.inner.lock().unwrap();
                assert!(s.windows.is_empty());
                assert_eq!(s.snapshot.current_ingress_sequence, 0);
                assert_eq!(s.snapshot.mediation_path_id, original.mediation_path_id);
                assert_eq!(s.snapshot.source_incarnation, original.source_incarnation);
            }
            assert!(observer.update_snapshot(original, 1001));
            observer.install(q, subject, 1002).unwrap();
            assert!(!observer.update_snapshot(other, 1003));
        }
        #[tokio::test]
        async fn ordinary_explicit_unproven_and_complete_read_budget_before_effects() {
            let (observer, mut q, _, _) = fixture().await;
            let mut snapshot = observer.inner.lock().unwrap().snapshot.clone();
            for attribution in [0, 2, -1] {
                let mut bad = snapshot.clone();
                bad.process_writer_attribution = attribution;
                bad.mediation_path_receipt_sha256 = path_digest(&bad);
                assert!(!valid_snapshot(&bad));
            }
            for scope in ["", "actor-proof/v1", "caller-ready"] {
                let mut bad = q.clone();
                bad.evidence_scope = scope.into();
                bad.request_sha256 = request_digest(&bad);
                assert!(!shape(&bad));
            }
            assert!(install_budget(&q, &snapshot).is_some());
            let resource = q.resource.as_mut().unwrap();
            resource.authority = "a".repeat(253);
            resource.workspace = "w".repeat(253);
            resource.sandbox = "s".repeat(253);
            resource.provider = "p".repeat(253);
            snapshot.resource = q.resource.clone();
            snapshot.mediation_path_receipt_sha256 = path_digest(&snapshot);
            q.request_sha256 = request_digest(&q);
            assert!(shape(&q));
            assert!(install_budget(&q, &snapshot).is_none());
            assert!(observer.inner.lock().unwrap().windows.is_empty());
        }
        #[tokio::test]
        async fn ordinary_response_completion_order_keeps_original_ingress_sequence() {
            let (observer, q, subject, _) = fixture().await;
            observer.install(q.clone(), subject, 1000).unwrap();
            let first = observer.ingress(1001).unwrap();
            let second = observer.ingress(1001).unwrap();
            assert!(observer.finish(event(second, "false"), 1002));
            assert!(observer.finish(event(first, "true"), 1003));
            let result = observer.close(&q.request_sha256, 1010).unwrap();
            assert_eq!(
                result
                    .events
                    .iter()
                    .map(|e| e.ingress_sequence)
                    .collect::<Vec<_>>(),
                vec![first, second]
            );
            assert_eq!(result.state, ProviderObservationStateV1::Terminal as i32);
        }
        #[tokio::test]
        async fn ordinary_open_read_is_install_ack_not_a_terminal_or_model_result() {
            let (observer, q, subject, _) = fixture().await;
            let open = observer.install(q.clone(), subject, 1000).unwrap();
            let reply = observer.sample_read(read(&open, 34), 1001).unwrap();
            assert_eq!(reply.active_attempts, 0);
            assert!(!reply.accounting_fault);
            assert!(open.terminal_sha256.is_empty());
            assert!(open.detached_ack.is_none());
            assert!(open.events.is_empty());
            assert_eq!(open.state, ProviderObservationStateV1::Open as i32);
        }
        #[tokio::test]
        async fn ordinary_install_once_budget_known_digest_and_no_runtime_enable() {
            let (observer, q, subject, _) = fixture().await;
            let r = observer.install(q.clone(), subject.clone(), 1000).unwrap();
            assert!(
                install_budget(
                    &q,
                    r.window
                        .as_ref()
                        .unwrap()
                        .installed_snapshot
                        .as_ref()
                        .unwrap()
                )
                .unwrap()
                    <= MAX_RESULT
            );
            assert!(observer.install(q.clone(), subject, 1000).is_none());
            let mut other = q.clone();
            other.profile_id = "caller-ready".into();
            other.request_sha256 = request_digest(&other);
            assert!(!shape(&other));
            let mut terminal = r.clone();
            terminal.current_snapshot =
                terminal.window.as_ref().unwrap().installed_snapshot.clone();
            terminal.current_read = Some(ProviderObservationCurrentReplyV1::default());
            assert_eq!(terminal_digest(&r), terminal_digest(&terminal));
            let state = ProviderCredentialState::from_child_env_snapshot(1, HashMap::new());
            assert!(state.ordinary_observer().is_none());
            assert!(state.observation_boundary().is_none());
        }
        // Boundary fixtures deliberately isolate byte accounting from semantic
        // authorization. shape/install/client tests retain all semantic checks.
        fn byte_request() -> ProviderObservationRequestV1 {
            ProviderObservationRequestV1 {
                profile_id: PROFILE.into(),
                profile_sha256: profile_digest(),
                resource: Some(Default::default()),
                ..Default::default()
            }
        }
        fn byte_arm(size: usize) -> crate::proto::ProviderDetachArmSealV1 {
            for n in 0..=size {
                let arm = crate::proto::ProviderDetachArmSealV1 {
                    request: Some(crate::proto::ProviderDetachArmRequestV1 {
                        attempt_id: "a".repeat(n),
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                if arm.encoded_len() == size {
                    return arm;
                }
            }
            panic!("unreachable synthetic seal size");
        }
        fn pad_request(q: &mut ProviderObservationRequestV1, size: usize) {
            for n in 0..=size {
                q.resource.as_mut().unwrap().authority = "a".repeat(n);
                if q.encoded_len() == size {
                    return;
                }
            }
            panic!("unreachable synthetic request size");
        }
        #[test]
        fn ordinary_v2_profiles_and_request_exact_limits_preserve_v1() {
            assert_eq!(
                profile_digest_for(LEGACY_PROFILE).unwrap(),
                "d0d289d4154d013b241b7db743d73c57281e4217d75676187892ba9af75cc3fb"
            );
            assert_eq!(
                profile_digest(),
                "3a3eb5c329052de53d7df9379e90ee6aa2a8caeaeeae2b7608af2035b6cbc01b"
            );
            assert!(!valid_profile(
                PROFILE,
                &profile_digest_for(LEGACY_PROFILE).unwrap()
            ));
            let mut q = byte_request();
            pad_request(&mut q, MAX_READ);
            q.installed_arm = Some(byte_arm(MAX_ARM));
            let before = q.encode_to_vec();
            assert_eq!(q.encoded_len(), MAX_REQUEST_V2);
            assert!(request_fits(&q));
            assert_eq!(
                q.encode_to_vec(),
                before,
                "size projection mutated original"
            );
            let mut excess = q.clone();
            excess.resource.as_mut().unwrap().authority.push('x');
            assert_eq!(excess.encoded_len(), MAX_REQUEST_V2 + 1);
            assert!(!request_fits(&excess));
            let mut excess = q.clone();
            excess.installed_arm = Some(byte_arm(MAX_ARM + 1));
            assert!(!request_fits(&excess));
            q.profile_id = LEGACY_PROFILE.into();
            q.profile_sha256 = profile_digest_for(LEGACY_PROFILE).unwrap();
            assert!(!request_fits(&q));
            q.installed_arm = None;
            assert!(request_fits(&q));
            q.resource.as_mut().unwrap().authority.push('x');
            assert!(!request_fits(&q));
        }
        #[tokio::test]
        async fn ordinary_v2_detached_size_does_not_drop_arm_or_reset_original() {
            let (observer, mut q, subject, _) = fixture().await;
            q.phase = ProviderObservationPhaseV1::Detached as i32;
            q.baseline_mediation_path_receipt_sha256 = observer
                .inner
                .lock()
                .unwrap()
                .snapshot
                .mediation_path_receipt_sha256
                .clone();
            let mut arm = byte_arm(3809);
            arm.install_sequence = 1;
            arm.installed_time = Some(timestamp(1000));
            let r = arm.request.as_mut().unwrap();
            r.attempt_id = uuid();
            r.request_sha256 = "a".repeat(64);
            r.attempt = Some(crate::proto::ProviderDetachAttemptV1 {
                schema_version: 1,
                ..Default::default()
            });
            // A synthetic complete seal sufficiently large to reproduce the old
            // nested request/read rejection; real Arm checks occur before this seam.
            r.original_action = Some(crate::proto::ProviderDetachActionV1 {
                event_id: "x".repeat(3500),
                ..Default::default()
            });
            q.installed_arm = Some(arm);
            q.request_sha256 = request_digest(&q);
            assert!(q.encoded_len() > 4096);
            assert!(shape(&q));
            let snap = observer.inner.lock().unwrap().snapshot.clone();
            assert!(install_budget(&q, &snap).is_some());
            let installed = observer.install(q.clone(), subject.clone(), 1000).unwrap();
            assert_eq!(
                installed.window.as_ref().unwrap().request.as_ref(),
                Some(&q)
            );
            assert!(observer.install(q.clone(), subject, 1000).is_none());
            let mut legacy = q.clone();
            legacy.profile_id = LEGACY_PROFILE.into();
            legacy.profile_sha256 = profile_digest_for(LEGACY_PROFILE).unwrap();
            legacy.request_sha256 = request_digest(&legacy);
            assert!(!shape(&legacy));
            let mut swapped = snap.clone();
            swapped.profile_id = LEGACY_PROFILE.into();
            swapped.profile_sha256 = profile_digest_for(LEGACY_PROFILE).unwrap();
            swapped.mediation_path_receipt_sha256 = path_digest(&swapped);
            assert!(!observer.update_snapshot(swapped, 1001));
        }
        #[tokio::test]
        async fn ordinary_v2_read_reply_result_and_control_account_complete_arms() {
            let (observer, mut q, _, _) = fixture().await;
            let snapshot = observer.inner.lock().unwrap().snapshot.clone();
            q.installed_arm = Some(byte_arm(3809));
            let read = ProviderObservationCurrentReadV1 {
                selector: Some(GetProviderDetachObservationRequest {
                    original_request: Some(q.clone()),
                    ..Default::default()
                }),
                expected_identity: Some(snapshot.clone()),
                read_correlation: vec![1; 16],
                ..Default::default()
            };
            let reply = ProviderObservationCurrentReplyV1 {
                original_read: Some(read.clone()),
                sampled_snapshot: Some(snapshot.clone()),
                ..Default::default()
            };
            assert!(read.encoded_len() > MAX_READ);
            assert!(read_fits(&read));
            assert!(reply_fits(&reply));
            let result = ProviderObservationResultV1 {
                window: Some(ProviderObservationWindowV1 {
                    request: Some(q),
                    installed_snapshot: Some(snapshot),
                    ..Default::default()
                }),
                current_read: Some(reply.clone()),
                ..Default::default()
            };
            let wire = result.encode_to_vec();
            assert!(result_fits(&result));
            assert_eq!(wire, result.encode_to_vec());
            for payload in [
                crate::proto::provider_observation_control_v1::Payload::CurrentRead(read.clone()),
                crate::proto::provider_observation_control_v1::Payload::CurrentReply(reply),
                crate::proto::provider_observation_control_v1::Payload::Report(result.clone()),
            ] {
                assert!(control_fits(&crate::proto::ProviderObservationControlV1 {
                    payload: Some(payload)
                }));
            }
            let mut mixed = read.clone();
            mixed.expected_identity.as_mut().unwrap().profile_sha256 =
                profile_digest_for(LEGACY_PROFILE).unwrap();
            assert!(!read_fits(&mixed));
            let mut oversized = read;
            oversized.read_correlation = vec![0; MAX_READ_V2 + 1];
            assert!(!read_fits(&oversized));
            let mut oversized = result;
            oversized.ack_window_sha256 = "x".repeat(MAX_RESULT_V2 + 1);
            assert!(!result_fits(&oversized));
            for size in [127, 128, 16_383, 16_384] {
                // Preserve actual prost varint framing, rather than summing raw fields.
                let mut nested = byte_request();
                nested.installed_arm = Some(byte_arm(size));
                assert_eq!(request_fits(&nested), size <= MAX_ARM);
            }
        }
        #[test]
        fn ordinary_v2_nested_exact_edges_keep_independent_stripped_bounds() {
            let mut q = byte_request();
            q.installed_arm = Some(byte_arm(MAX_ARM));
            let snapshot = ProviderObservationSnapshotV1 {
                profile_id: PROFILE.into(),
                profile_sha256: profile_digest(),
                ..Default::default()
            };
            let small = ProviderObservationCurrentReadV1 {
                selector: Some(GetProviderDetachObservationRequest {
                    original_request: Some(q.clone()),
                    ..Default::default()
                }),
                expected_identity: Some(snapshot.clone()),
                ..Default::default()
            };
            let mut read = small.clone();
            let mut found = false;
            for n in 0..MAX_READ {
                read.read_correlation = vec![1; n];
                if read.encoded_len() == MAX_READ_V2 {
                    found = true;
                    break;
                }
            }
            assert!(found);
            assert!(read_fits(&read));
            read.read_correlation.push(1);
            assert_eq!(read.encoded_len(), MAX_READ_V2 + 1);
            assert!(!read_fits(&read));
            let mut reply = ProviderObservationCurrentReplyV1 {
                original_read: Some(small.clone()),
                sampled_snapshot: Some(snapshot),
                ..Default::default()
            };
            let mut found = false;
            for n in 0..MAX_READ {
                reply.sampled_snapshot.as_mut().unwrap().supervisor_instance = "s".repeat(n);
                if reply.encoded_len() == MAX_REPLY_V2 - 1 {
                    found = true;
                    break;
                }
            }
            assert!(found);
            assert!(reply_fits(&reply));
            reply
                .sampled_snapshot
                .as_mut()
                .unwrap()
                .supervisor_instance
                .push('s');
            assert_eq!(reply.encoded_len(), MAX_REPLY_V2);
            assert!(
                !reply_fits(&reply),
                "conservative full ceiling cannot waive stripped4096"
            );
            reply
                .sampled_snapshot
                .as_mut()
                .unwrap()
                .supervisor_instance
                .push('s');
            assert_eq!(reply.encoded_len(), MAX_REPLY_V2 + 1);
            assert!(!reply_fits(&reply));
            let mut result = ProviderObservationResultV1 {
                window: Some(ProviderObservationWindowV1 {
                    request: Some(q),
                    ..Default::default()
                }),
                current_read: Some(ProviderObservationCurrentReplyV1 {
                    original_read: Some(small.clone()),
                    sampled_snapshot: small.expected_identity.clone(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let mut found = false;
            for n in 0..MAX_RESULT {
                result.ack_window_sha256 = "a".repeat(n);
                if result.encoded_len() == MAX_RESULT_V2 - 2 {
                    found = true;
                    break;
                }
            }
            assert!(found);
            assert!(result_fits(&result));
            for target in [MAX_RESULT_V2 - 1, MAX_RESULT_V2, MAX_RESULT_V2 + 1] {
                result.ack_window_sha256.push('a');
                assert_eq!(result.encoded_len(), target);
                assert!(
                    !result_fits(&result),
                    "all size projections must fit independently"
                );
            }
            let encoded = small.encode_to_vec();
            assert!(read_fits(&small));
            assert_eq!(small.encode_to_vec(), encoded);
        }
    }
}
