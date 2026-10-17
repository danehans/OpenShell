// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Installation evidence reported under the accepted supervisor session.
//!
//! Desired-state cursors never establish success. Credentials, policy, and
//! the authenticated workload boundary must acknowledge the same authority.

use std::sync::Arc;
use std::time::Duration;

use openshell_core::proto::{
    ProviderReadinessObservation, ProviderReadinessReason as Reason,
    ReportProviderReadinessResponse,
};
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation_interface::contract::{BoundaryExec, ProviderEnvironmentInstallation};
use openshell_supervisor_network::opa::PolicyGenerationGuard;
use tokio::sync::watch;

/// Authority captured before consuming a provider response's credential fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvironmentIdentity {
    pub(crate) attachment_epoch: String,
    pub(crate) revision: u64,
    pub(crate) policy_hash: String,
}

impl EnvironmentIdentity {
    /// Preserve the authority delivered with a credential snapshot before consuming it.
    pub(crate) fn from_environment(
        result: &openshell_core::grpc_client::ProviderEnvironmentResult,
    ) -> Self {
        Self {
            attachment_epoch: result.provider_attachment_epoch.clone(),
            revision: result.provider_env_revision,
            policy_hash: result.policy_hash.clone(),
        }
    }

    /// Capture the requested authority without claiming that it is installed.
    pub(crate) fn from_settings(result: &openshell_core::grpc_client::SettingsPollResult) -> Self {
        Self {
            attachment_epoch: result.provider_attachment_epoch.clone(),
            revision: result.provider_env_revision,
            policy_hash: result.policy_hash.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct InstalledPolicy {
    epoch: String,
    hash: String,
    config_revision: u64,
    generation: PolicyGenerationGuard,
}

#[derive(Clone, Debug)]
struct FailedPolicy {
    identity: EnvironmentIdentity,
    config_revision: u64,
}

#[derive(Clone, Debug)]
struct State {
    identity: EnvironmentIdentity,
    installation_id: String,
    credential_reason: Reason,
    expires_at_ms: Option<i64>,
    policy: Option<InstalledPolicy>,
    policy_failure: Option<FailedPolicy>,
    process: Option<ProviderEnvironmentInstallation>,
    process_reason: Reason,
}

/// Shared installation tracker; each transition wakes the independent reporter.
#[derive(Clone, Debug)]
pub struct Tracker {
    state: watch::Sender<State>,
}

impl Tracker {
    /// Start without credential, policy, or process installation evidence.
    pub(crate) fn new() -> Self {
        let (state, _) = watch::channel(State {
            identity: EnvironmentIdentity::default(),
            installation_id: String::new(),
            credential_reason: Reason::WaitingForCredentials,
            expires_at_ms: None,
            policy: None,
            policy_failure: None,
            process: None,
            process_reason: Reason::WaitingForProcess,
        });
        Self { state }
    }

    /// Invalidate old success before a replacement or fail-closed clear begins.
    pub(crate) fn credentials_failed(&self, identity: EnvironmentIdentity, reason: Reason) {
        self.state.send_modify(|state| {
            state.identity = identity;
            state.installation_id.clear();
            state.credential_reason = reason;
            state.expires_at_ms = None;
            state.process = None;
            state.process_reason = Reason::WaitingForProcess;
        });
    }

    /// Record a completed credential installation and require a fresh process acknowledgment.
    pub(crate) fn credentials_installed(
        &self,
        identity: EnvironmentIdentity,
        credentials: &ProviderCredentialState,
        expires_at_ms: Option<i64>,
    ) {
        let snapshot = credentials.snapshot();
        self.state.send_modify(|state| {
            state.credential_reason =
                if !identity.policy_hash.is_empty() && snapshot.revision == identity.revision {
                    Reason::Unspecified
                } else {
                    Reason::SnapshotMismatch
                };
            state.identity = identity;
            state.installation_id.clone_from(&snapshot.installation_id);
            state.expires_at_ms = expires_at_ms;
            state.process = None;
            state.process_reason = Reason::WaitingForProcess;
        });
    }

    /// Retry failed installations even when the requested fingerprint is unchanged.
    pub(crate) fn needs_environment(&self, identity: &EnvironmentIdentity) -> bool {
        let state = self.state.borrow();
        state.credential_reason != Reason::Unspecified || state.identity != *identity
    }

    /// Bind policy evidence to the exact generation returned by runtime installation.
    pub(crate) fn policy_activated(
        &self,
        identity: &EnvironmentIdentity,
        config_revision: u64,
        generation: PolicyGenerationGuard,
    ) {
        self.state.send_modify(|state| {
            state.policy = Some(InstalledPolicy {
                epoch: identity.attachment_epoch.clone(),
                hash: identity.policy_hash.clone(),
                config_revision,
                generation,
            });
            state.policy_failure = None;
        });
    }

    /// Report the rejected desired configuration without acknowledging its policy.
    pub(crate) fn policy_install_failed(
        &self,
        identity: EnvironmentIdentity,
        config_revision: u64,
    ) {
        self.state.send_modify(|state| {
            // Failed desired identity must not masquerade as evidence for the
            // last installed policy, even when the failure retains that policy.
            state.policy_failure = Some(FailedPolicy {
                identity,
                config_revision,
            });
        });
    }

    fn process_installed(
        &self,
        installed: ProviderEnvironmentInstallation,
        credentials: &ProviderCredentialState,
    ) {
        let current = credentials.snapshot();
        self.state.send_if_modified(|state| {
            if installed.installation_id != current.installation_id
                || installed.installation_id != state.installation_id
                || installed.revision != state.identity.revision
            {
                return false;
            }
            let changed = state.process.as_ref() != Some(&installed)
                || state.process_reason != Reason::Unspecified;
            state.process = Some(installed);
            state.process_reason = Reason::Unspecified;
            changed
        });
    }

    fn process_failed(&self) {
        self.state.send_if_modified(|state| {
            let changed =
                state.process.is_some() || state.process_reason != Reason::ProcessInstallFailed;
            state.process = None;
            state.process_reason = Reason::ProcessInstallFailed;
            changed
        });
    }

    /// Observe the installed static-provider resolver independently of any
    /// traffic decision. This does not invent action/attempt association: the
    /// authenticated caller must separately bind the captured subject and fresh
    /// sequence to its original native action. Missing association stays absent.
    #[cfg(test)]
    pub(crate) fn provider_revocation_observation(
        &self,
        credentials: &ProviderCredentialState,
        subject: &openshell_core::provider_credentials::ProviderRevocationSubject,
        expected_epoch: &str,
        expected_revision: u64,
    ) -> Option<(
        ProviderReadinessObservation,
        openshell_core::provider_credentials::ProviderRevocationEvidence,
    )> {
        if expected_epoch.is_empty() || expected_revision == 0 {
            return None;
        }
        let before = self.observation(credentials);
        if before.attachment_epoch != expected_epoch
            || before.provider_env_revision != expected_revision
            || !before.credentials_installed
            || !before.policy_active
            || !before.launch_environment_installed
        {
            return None;
        }
        let installation = self.state.borrow().installation_id.clone();
        let proof = credentials.observe_static_provider_revocation(
            subject,
            expected_revision,
            &installation,
        )?;
        let after = self.observation(credentials);
        if before != after {
            return None;
        }
        Some((after, proof))
    }

    /// Read current evidence, rechecking credential expiry and policy generation.
    pub(crate) fn observation(
        &self,
        credentials: &ProviderCredentialState,
    ) -> ProviderReadinessObservation {
        let state = self.state.borrow();
        let current = credentials.snapshot();
        let identity = state
            .policy_failure
            .as_ref()
            .map_or(&state.identity, |failure| &failure.identity);
        let expired = state
            .expires_at_ms
            .is_some_and(|expiry| expiry <= openshell_core::time::now_ms());
        let credentials_installed = state.credential_reason == Reason::Unspecified
            && !expired
            && state.identity == *identity
            && current.installation_id == state.installation_id;
        let policy_active = state.policy_failure.is_none()
            && state.policy.as_ref().is_some_and(|policy| {
                !policy.hash.is_empty()
                    && policy.hash == identity.policy_hash
                    && policy.epoch == identity.attachment_epoch
                    && !policy.generation.is_stale()
            });
        let launch_environment_installed = credentials_installed
            && state.process.as_ref().is_some_and(|process| {
                process.installation_id == state.installation_id
                    && process.revision == identity.revision
            });
        let reason = if state.policy_failure.is_some() {
            Reason::PolicyActivationFailed
        } else if expired {
            Reason::CredentialExpired
        } else if state.credential_reason != Reason::Unspecified {
            state.credential_reason
        } else if !credentials_installed {
            Reason::WaitingForCredentials
        } else if !policy_active {
            Reason::WaitingForPolicy
        } else if !launch_environment_installed {
            if state.process_reason == Reason::Unspecified {
                Reason::WaitingForProcess
            } else {
                state.process_reason
            }
        } else {
            Reason::Unspecified
        };
        ProviderReadinessObservation {
            attachment_epoch: identity.attachment_epoch.clone(),
            provider_env_revision: identity.revision,
            config_revision: state.policy_failure.as_ref().map_or_else(
                || {
                    state
                        .policy
                        .as_ref()
                        .map_or(0, |policy| policy.config_revision)
                },
                |failure| failure.config_revision,
            ),
            policy_hash: identity.policy_hash.clone(),
            credentials_installed,
            policy_active,
            launch_environment_installed,
            process_instance_id: state
                .process
                .as_ref()
                .map_or_else(String::new, |process| process.session_id.to_string()),
            reason: reason.into(),
            ..Default::default()
        }
    }

    /// Report while the owner holds this handle; reconnects use the accepted session.
    pub(crate) fn start_reporter(
        &self,
        endpoint: String,
        sandbox_id: String,
        credentials: ProviderCredentialState,
        sessions: watch::Receiver<Option<String>>,
        boundary: Arc<dyn BoundaryExec>,
    ) -> Reporter {
        let tracker = self.clone();
        Reporter(tokio::spawn(async move {
            tracker
                .run_reporter(
                    credentials,
                    sessions,
                    boundary,
                    GatewayReporter {
                        endpoint,
                        sandbox_id,
                    },
                )
                .await;
        }))
    }

    async fn run_reporter<C: ReportClient>(
        &self,
        credentials: ProviderCredentialState,
        mut sessions: watch::Receiver<Option<String>>,
        boundary: Arc<dyn BoundaryExec>,
        client: C,
    ) {
        let tracker = self;
        let mut updates = tracker.state.subscribe();
        let mut active_session = None;
        let mut sequence = 0_u64;
        let mut pending_report: Option<ProviderReadinessObservation> = None;
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let guard = tracker
                .state
                .borrow()
                .policy
                .as_ref()
                .map(|policy| policy.generation.clone())
                .filter(|guard| !guard.is_stale());
            tokio::select! {
                changed = sessions.changed() => { if changed.is_err() { return; } }
                changed = updates.changed() => { if changed.is_err() { return; } }
                _ = interval.tick() => {}
                () = async {
                    if let Some(guard) = guard { guard.wait_until_stale().await; }
                    else { std::future::pending::<()>().await; }
                } => {}
            }
            let session = sessions.borrow_and_update().clone();
            if session != active_session {
                sequence = 0;
                pending_report = None;
                active_session = session.clone();
            }
            let Some(session) = session else {
                continue;
            };
            // Synchronization is also a boundary liveness check. A stopped
            // boundary cannot keep renewing successful launch evidence.
            let synchronization = tokio::time::timeout(
                Duration::from_secs(10),
                boundary.synchronize_provider_environment(),
            );
            let installed = tokio::select! {
                changed = sessions.changed() => { if changed.is_err() { return; } interval.reset_immediately(); continue; }
                installed = synchronization => installed,
            };
            match installed {
                Ok(Ok(installed)) => tracker.process_installed(installed, &credentials),
                _ => tracker.process_failed(),
            }
            let Ok(now) =
                openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now())
            else {
                continue;
            };
            // Lost proof-report replies retry the exact original report; a new
            // heartbeat cannot silently reassign the event's originating seq.
            if pending_report.as_ref().is_some_and(|old| {
                old.provider_detach
                    .as_ref()
                    .is_some_and(|m| !m.attempt_id.is_empty())
            }) {
                let fresh = tracker.observation(&credentials);
                let old = pending_report.as_ref().unwrap();
                let current_meta = credentials.provider_detach_report(&session, old.sequence, &now);
                let original_id = old.provider_detach.as_ref().map(|m| m.attempt_id.as_str());
                let same_attempt =
                    current_meta.as_ref().map(|m| m.attempt_id.as_str()) == original_id;
                if !same_attempt
                    || old.attachment_epoch != fresh.attachment_epoch
                    || old.config_revision != fresh.config_revision
                    || old.provider_env_revision != fresh.provider_env_revision
                    || old.policy_hash != fresh.policy_hash
                    || !fresh.credentials_installed
                    || !fresh.policy_active
                    || !fresh.launch_environment_installed
                {
                    pending_report = None;
                }
            }
            let observation = if let Some(old) = pending_report.as_ref() {
                old.clone()
            } else {
                let Some(next_sequence) = sequence.checked_add(1) else {
                    return;
                };
                sequence = next_sequence;
                let mut next = tracker.observation(&credentials);
                next.session_id.clone_from(&session);
                next.sequence = sequence;
                next.provider_detach = credentials.provider_detach_report(&session, sequence, &now);
                pending_report = Some(next.clone());
                next
            };
            let sent = observation.clone();
            let report = tokio::time::timeout(Duration::from_secs(5), client.report(observation));
            let response = tokio::select! {
                changed=sessions.changed()=>{if changed.is_err(){return;}interval.reset_immediately();continue;}
                response=report=>response,
            };
            if let Ok(Ok(response)) = response {
                if !report_acknowledged(&response, sent.sequence) {
                    if sent
                        .provider_detach
                        .as_ref()
                        .is_none_or(|m| m.attempt_id.is_empty())
                    {
                        pending_report = None;
                    }
                    tracing::warn!("Provider readiness report was not acknowledged");
                    continue;
                }
                pending_report = None;
                credentials.bind_provider_detach_session(
                    &response.provider_detach_gateway_boot_id,
                    &session,
                );
                if let Some(installed) = response.provider_detach_installed.as_ref() {
                    credentials.acknowledge_provider_detach_arm(installed);
                }
                if let Some(meta) = sent.provider_detach.as_ref() {
                    credentials.acknowledge_provider_detach_report(meta);
                }
                if let Some(seal) = response.provider_detach_pending.as_ref() {
                    let state = tracker.state.borrow().clone();
                    if let Some(policy) = state.policy.as_ref() {
                        let guard = policy.generation.clone();
                        let checker: Arc<dyn Fn() -> bool + Send + Sync> =
                            Arc::new(move || !guard.is_stale());
                        let next = sent.sequence.checked_add(1).unwrap_or(0);
                        let Ok(installed_now) = openshell_core::time::timestamp_from_system_time(
                            std::time::SystemTime::now(),
                        ) else {
                            continue;
                        };
                        if credentials.install_provider_detach_arm(
                            seal,
                            &sent,
                            &state.installation_id,
                            next,
                            installed_now,
                            checker,
                        ) {
                            interval.reset_immediately();
                        }
                    }
                }
            } else if sent
                .provider_detach
                .as_ref()
                .is_none_or(|m| m.attempt_id.is_empty())
            {
                pending_report = None;
            }
        }
    }
}

/// An acknowledgment must bind this report and a valid positive evidence lease.
fn report_acknowledged(response: &ReportProviderReadinessResponse, sequence: u64) -> bool {
    response.accepted_sequence == sequence
        && response
            .observation_ttl
            .as_ref()
            .and_then(|ttl| openshell_core::time::duration_to_std(ttl).ok())
            .is_some_and(|ttl| !ttl.is_zero())
}

#[tonic::async_trait]
trait ReportClient: Send + Sync {
    async fn report(
        &self,
        observation: ProviderReadinessObservation,
    ) -> miette::Result<ReportProviderReadinessResponse>;
}

struct GatewayReporter {
    endpoint: String,
    sandbox_id: String,
}

#[tonic::async_trait]
impl ReportClient for GatewayReporter {
    async fn report(
        &self,
        observation: ProviderReadinessObservation,
    ) -> miette::Result<ReportProviderReadinessResponse> {
        openshell_core::grpc_client::report_provider_readiness(
            &self.endpoint,
            &self.sandbox_id,
            observation,
        )
        .await
    }
}

/// Cancels reporting before supervisor teardown can renew stale evidence.
pub struct Reporter(tokio::task::JoinHandle<()>);

impl Drop for Reporter {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Optional single-profile control. This is not an execution framework: it can
/// only forward a gateway-authenticated, durably claimed original to the bound
/// Native transport. No profile artifact or Native support means disabled.
struct FixedWitnessControl {
    credentials: ProviderCredentialState,
    engine: Arc<openshell_supervisor_network::opa::OpaEngine>,
    boundary: Arc<dyn openshell_core::provider_credentials::ProviderWitnessBoundary>,
    capability: openshell_core::provider_credentials::WitnessBoundaryCapability,
    closed: std::sync::atomic::AtomicBool,
    accepted_session: std::sync::Mutex<Option<String>>,
    originals: std::sync::Mutex<
        std::collections::HashMap<String, openshell_core::proto::ProviderDetachWitnessControlV1>,
    >,
    observations: tokio::sync::mpsc::Sender<openshell_core::proto::ProviderDetachWitnessControlV1>,
    receiver: std::sync::Mutex<
        Option<tokio::sync::mpsc::Receiver<openshell_core::proto::ProviderDetachWitnessControlV1>>,
    >,
}

pub async fn fixed_witness_control(
    credentials: ProviderCredentialState,
    engine: Arc<openshell_supervisor_network::opa::OpaEngine>,
) -> Option<Arc<dyn openshell_supervisor_process::supervisor_session::ProviderWitnessControl>> {
    let expected_profile = openshell_core::provider_credentials::fixed_provider_witness_profile()?;
    if !credentials.provider_detach_attempts_enabled() {
        return None;
    }
    let boundary = credentials.witness_boundary()?;
    let capability = boundary.capability().await?;
    let uuid =
        |v: &str| uuid::Uuid::parse_str(v).is_ok_and(|id| !id.is_nil() && id.to_string() == v);
    if capability.profile_sha256 != expected_profile
        || !uuid(&capability.boundary_incarnation)
        || !openshell_core::traffic_identity::valid_execution_id(&capability.execution_id)
        || capability.profile_sha256.len() != 64
        || !capability
            .profile_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let control = Arc::new(FixedWitnessControl {
        credentials,
        engine,
        boundary,
        capability,
        closed: std::sync::atomic::AtomicBool::new(false),
        accepted_session: std::sync::Mutex::new(None),
        originals: std::sync::Mutex::default(),
        observations: tx,
        receiver: std::sync::Mutex::new(Some(rx)),
    });
    let weak = Arc::downgrade(&control);
    let mut fences = control.credentials.witness_launch_gate().subscribe();
    tokio::spawn(async move {
        while fences.changed().await.is_ok() {
            let fence = fences.borrow_and_update().clone();
            let Some(control) = weak.upgrade() else { break };
            let mut messages = {
                let Ok(mut originals) = control.originals.lock() else {
                    control
                        .closed
                        .store(true, std::sync::atomic::Ordering::Release);
                    break;
                };
                originals
                    .values_mut()
                    .map(|original| {
                        if original.state == "unknown" {
                            original.state = "source-invalidated".into();
                        }
                        original.clone()
                    })
                    .collect::<Vec<_>>()
            };
            if messages.is_empty() {
                continue;
            }
            for message in &messages {
                let _ = control.observations.try_send(message.clone());
            }
            let quiesced = control.boundary.fence(fence).await;
            for message in &mut messages {
                message.state = if quiesced || message.state == "boundary-quiesced" {
                    "boundary-quiesced"
                } else {
                    "cancel-pending"
                }
                .into();
                if let Ok(mut originals) = control.originals.lock()
                    && let Some(original) = originals.get_mut(&message.original_key)
                {
                    *original = message.clone();
                }
                let _ = control.observations.try_send(message.clone());
            }
        }
    });
    Some(control)
}

#[tonic::async_trait]
impl openshell_supervisor_process::supervisor_session::ProviderWitnessControl
    for FixedWitnessControl
{
    fn capability(
        &self,
        session: &str,
    ) -> Option<openshell_core::proto::ProviderDetachWitnessControlV1> {
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        let Ok(mut accepted) = self.accepted_session.lock() else {
            return None;
        };
        if accepted
            .as_ref()
            .is_some_and(|original| original != session)
        {
            return None;
        }
        if !uuid::Uuid::parse_str(session).is_ok_and(|id| !id.is_nil() && id.to_string() == session)
        {
            return None;
        }
        if accepted.is_none() {
            *accepted = Some(session.into());
        }
        let source = self.credentials.witness_launch_gate().snapshot();
        if source.disabled {
            return None;
        }
        Some(openshell_core::proto::ProviderDetachWitnessControlV1 {
            original_key: String::new(),
            request_sha256: String::new(),
            source_incarnation: source.source_incarnation,
            boundary_incarnation: self.capability.boundary_incarnation.clone(),
            profile_sha256: self.capability.profile_sha256.clone(),
            state: "capability".into(),
            execution_id: self.capability.execution_id.clone(),
        })
    }
    fn observations(
        &self,
    ) -> Option<tokio::sync::mpsc::Receiver<openshell_core::proto::ProviderDetachWitnessControlV1>>
    {
        self.receiver.lock().ok()?.take()
    }
    fn disconnect(&self) {
        // A failed dial before the first authenticated acceptance has no old
        // session to retire. Actual accepted-session loss never rebinds.
        if self
            .accepted_session
            .lock()
            .is_ok_and(|session| session.is_none())
        {
            return;
        }
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.credentials.witness_launch_gate().lock().disable();
    }
    async fn invoke(
        &self,
        session: &str,
        q: openshell_core::proto::ProviderDetachWitnessRequestV1,
    ) -> openshell_core::proto::ProviderDetachWitnessControlV1 {
        use openshell_core::provider_credentials::{
            WitnessOperation, witness_original_key, witness_request_digest, witness_sha256,
        };
        use prost::Message;
        let mut result = openshell_core::proto::ProviderDetachWitnessControlV1 {
            original_key: String::new(),
            request_sha256: q.request_sha256.clone(),
            source_incarnation: q.source_incarnation.clone(),
            boundary_incarnation: q.boundary_incarnation.clone(),
            profile_sha256: q.profile_sha256.clone(),
            state: "unknown".into(),
            execution_id: self.capability.execution_id.clone(),
        };
        let Some(seal) = q.installed_arm.as_ref() else {
            return result;
        };
        let Some(arm) = seal.request.as_ref() else {
            return result;
        };
        let Some(action) = arm.original_action.as_ref() else {
            return result;
        };
        let Some(target) = action.target.as_ref() else {
            return result;
        };
        let Some(attempt) = arm.attempt.as_ref() else {
            return result;
        };
        result.original_key = witness_original_key(&target.authority, &q.run_id, &action.action_id);
        let now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|v| i64::try_from(v.as_millis()).ok())
        };
        let source = self.credentials.witness_launch_gate().snapshot();
        if self.closed.load(std::sync::atomic::Ordering::Acquire)
            || !self
                .accepted_session
                .lock()
                .is_ok_and(|original| original.as_deref() == Some(session))
            || source.disabled
            || q.encoded_len() > 12 * 1024
            || q.request_sha256 != witness_request_digest(&q)
            || q.profile_id != "provider-detach-benign-witness-v1"
            || q.source_incarnation != source.source_incarnation
            || q.boundary_incarnation != self.capability.boundary_incarnation
            || q.profile_sha256 != self.capability.profile_sha256
            || target.execution_id != self.capability.execution_id
            || attempt.supervisor_session != session
        {
            return result;
        }
        {
            let Ok(mut originals) = self.originals.lock() else {
                return result;
            };
            if originals.len() >= 16 || originals.contains_key(&result.original_key) {
                return result;
            }
            // Original reservation precedes every prepare/send; transport loss
            // never removes it or creates another source attempt.
            originals.insert(result.original_key.clone(), result.clone());
        }
        let Some(deadline) = attempt.deadline.as_ref() else {
            return result;
        };
        let Some(deadline_ms) = deadline
            .seconds
            .checked_mul(1000)
            .and_then(|v| v.checked_add(i64::from(deadline.nanos / 1_000_000)))
        else {
            return result;
        };
        let operation = WitnessOperation {
            prepared_source_incarnation: source.source_incarnation,
            prepared_source_epoch: source.epoch,
            original_key: result.original_key.clone(),
            request_sha256: q.request_sha256,
            profile_sha256: q.profile_sha256,
            installed_arm_sha256: witness_sha256(&seal.encode_to_vec()),
            boundary_incarnation: q.boundary_incarnation,
            prepared_ticket: String::new(),
            supervisor_session: session.into(),
            execution_id: target.execution_id.clone(),
            deadline_unix_ms: deadline_ms,
            arm_request: arm.encode_to_vec(),
        };
        let Some(prepared) = self.boundary.prepare(operation.clone()).await else {
            return result;
        };
        let mut expected = operation;
        expected.prepared_ticket = prepared.prepared_ticket.clone();
        if expected != prepared || uuid::Uuid::parse_str(&prepared.prepared_ticket).is_err() {
            return result;
        }
        let Some(now) = now() else { return result };
        let Ok(permit) = self
            .engine
            .commit_provider_witness(&self.credentials, &prepared, now)
        else {
            return result;
        };
        // Source L has completed. No gate is held over this sole remote send.
        let _ = self.boundary.permit(permit).await;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn acknowledgment_requires_matching_sequence_and_valid_positive_ttl() {
        let mut response = ReportProviderReadinessResponse {
            accepted_sequence: 7,
            ..Default::default()
        };
        assert!(!report_acknowledged(&response, 7));
        for (seconds, nanos, valid) in [
            (15, 0, true),
            (0, 1, true),
            (0, 0, false),
            (-1, 0, false),
            (0, -1, false),
            (1, -1, false),
            (0, 1_000_000_000, false),
            (315_576_000_001, 0, false),
        ] {
            response.observation_ttl = Some(prost_types::Duration { seconds, nanos });
            assert_eq!(
                report_acknowledged(&response, 7),
                valid,
                "seconds={seconds}, nanos={nanos}"
            );
        }
        response.observation_ttl = Some(prost_types::Duration {
            seconds: 15,
            nanos: 0,
        });
        assert!(!report_acknowledged(&response, 8));
    }

    struct CapturingReporter(tokio::sync::mpsc::UnboundedSender<ProviderReadinessObservation>);

    #[tonic::async_trait]
    impl ReportClient for CapturingReporter {
        async fn report(
            &self,
            observation: ProviderReadinessObservation,
        ) -> miette::Result<ReportProviderReadinessResponse> {
            let sequence = observation.sequence;
            self.0.send(observation).unwrap();
            Ok(ReportProviderReadinessResponse {
                accepted_sequence: sequence,
                report_interval: Some(
                    openshell_core::time::duration_from_std(Duration::from_secs(5)).unwrap(),
                ),
                observation_ttl: Some(
                    openshell_core::time::duration_from_std(Duration::from_secs(15)).unwrap(),
                ),
                ..Default::default()
            })
        }
    }

    struct DelayedReporter(
        tokio::sync::mpsc::UnboundedSender<(
            ProviderReadinessObservation,
            tokio::sync::oneshot::Sender<ReportProviderReadinessResponse>,
        )>,
    );

    #[tonic::async_trait]
    impl ReportClient for DelayedReporter {
        async fn report(
            &self,
            observation: ProviderReadinessObservation,
        ) -> miette::Result<ReportProviderReadinessResponse> {
            let (response, received) = tokio::sync::oneshot::channel();
            self.0.send((observation, response)).unwrap();
            received
                .await
                .map_err(|_| miette::miette!("report response channel closed"))
        }
    }

    struct DelayedBoundary(
        tokio::sync::mpsc::UnboundedSender<
            tokio::sync::oneshot::Sender<ProviderEnvironmentInstallation>,
        >,
    );

    #[tonic::async_trait]
    impl BoundaryExec for DelayedBoundary {
        async fn exec(
            &self,
            _spec: openshell_isolation_interface::contract::ExecSpec,
        ) -> Result<
            openshell_isolation_interface::contract::ExecSession,
            openshell_isolation_interface::contract::BackendError,
        > {
            unreachable!("reporting must never launch a workload process")
        }

        async fn synchronize_provider_environment(
            &self,
        ) -> Result<
            ProviderEnvironmentInstallation,
            openshell_isolation_interface::contract::BackendError,
        > {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            self.0.send(sender).unwrap();
            receiver.await.map_err(|_| {
                openshell_isolation_interface::contract::BackendError::Unavailable(
                    "boundary disconnected".into(),
                )
            })
        }
    }

    async fn next_installation_report(
        installations: &mut tokio::sync::mpsc::UnboundedReceiver<
            tokio::sync::oneshot::Sender<ProviderEnvironmentInstallation>,
        >,
        reports: &mut tokio::sync::mpsc::UnboundedReceiver<(
            ProviderReadinessObservation,
            tokio::sync::oneshot::Sender<ReportProviderReadinessResponse>,
        )>,
        installed: &ProviderEnvironmentInstallation,
        wait: Duration,
    ) -> (
        ProviderReadinessObservation,
        tokio::sync::oneshot::Sender<ReportProviderReadinessResponse>,
    ) {
        tokio::time::timeout(wait, async {
            installations
                .recv()
                .await
                .unwrap()
                .send(installed.clone())
                .unwrap();
            reports.recv().await.unwrap()
        })
        .await
        .expect("reporter did not synchronize and report before the deadline")
    }

    #[tokio::test]
    async fn invalid_report_acknowledgments_retry_without_installation_feedback() {
        let tracker = Tracker::new();
        let credentials = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
        tracker.credentials_installed(identity(), &credentials, None);
        let policy = openshell_policy::restrictive_default_policy();
        let engine = openshell_supervisor_network::opa::OpaEngine::from_proto(&policy).unwrap();
        tracker.policy_activated(&identity(), 12, engine.generation_guard(0).unwrap());
        let mut installed = installation(&credentials);
        let (sessions, receiver) = watch::channel(Some("current-session".to_string()));
        let (boundary_tx, mut boundary_rx) = tokio::sync::mpsc::unbounded_channel();
        let (report_tx, mut report_rx) = tokio::sync::mpsc::unbounded_channel();
        let reporting_tracker = tracker.clone();
        let reporting_credentials = credentials.clone();
        let task = tokio::spawn(async move {
            reporting_tracker
                .run_reporter(
                    reporting_credentials,
                    receiver,
                    Arc::new(DelayedBoundary(boundary_tx)),
                    DelayedReporter(report_tx),
                )
                .await;
        });
        // The first installation changes local evidence once. Its watch update
        // may cause one additional report, but an invalid gateway reply must
        // not keep toggling that evidence and scheduling more installations.
        for sequence in 1..=2 {
            let (report, response) = next_installation_report(
                &mut boundary_rx,
                &mut report_rx,
                &installed,
                Duration::from_secs(1),
            )
            .await;
            assert_eq!(report.sequence, sequence);
            assert!(report.launch_environment_installed);
            response
                .send(ReportProviderReadinessResponse::default())
                .unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), boundary_rx.recv())
                .await
                .is_err(),
            "invalid report replies must not repeatedly reinstall an unchanged environment"
        );

        // A real credential installation still wakes the reporter immediately.
        credentials.install_child_env_snapshot(6, HashMap::new());
        tracker.credentials_installed(identity(), &credentials, None);
        installed.installation_id = credentials.snapshot().installation_id.clone();
        let (report, response) = next_installation_report(
            &mut boundary_rx,
            &mut report_rx,
            &installed,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(report.sequence, 3);
        assert!(report.launch_environment_installed);
        // A policy update received while the report is pending must survive
        // processing its reply and cause a report of the new configuration.
        tracker.policy_activated(&identity(), 13, engine.generation_guard(0).unwrap());
        response
            .send(ReportProviderReadinessResponse::default())
            .unwrap();
        let (report, response) = next_installation_report(
            &mut boundary_rx,
            &mut report_rx,
            &installed,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(report.sequence, 4);
        assert_eq!(report.config_revision, 13);
        response
            .send(ReportProviderReadinessResponse::default())
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), boundary_rx.recv())
                .await
                .is_err()
        );

        sessions.send_replace(Some("replacement-session".to_string()));
        let (report, response) = next_installation_report(
            &mut boundary_rx,
            &mut report_rx,
            &installed,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(report.session_id, "replacement-session");
        assert_eq!(report.sequence, 1);
        response
            .send(ReportProviderReadinessResponse::default())
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), boundary_rx.recv())
                .await
                .is_err()
        );

        // Without further state changes, the periodic liveness check retries.
        let (report, response) = next_installation_report(
            &mut boundary_rx,
            &mut report_rx,
            &installed,
            Duration::from_secs(6),
        )
        .await;
        assert_eq!(report.session_id, "replacement-session");
        assert_eq!(report.sequence, 2);
        assert!(report.launch_environment_installed);
        response
            .send(ReportProviderReadinessResponse::default())
            .unwrap();
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn reconnect_cancels_delayed_boundary_ack_and_starts_a_new_report_sequence() {
        let tracker = Tracker::new();
        let credentials = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
        tracker.credentials_installed(identity(), &credentials, None);
        let installed = installation(&credentials);
        let (sessions, receiver) = watch::channel(Some("old-session".to_string()));
        let (boundary_tx, mut boundary_rx) = tokio::sync::mpsc::unbounded_channel();
        let (report_tx, mut report_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            tracker
                .run_reporter(
                    credentials,
                    receiver,
                    Arc::new(DelayedBoundary(boundary_tx)),
                    CapturingReporter(report_tx),
                )
                .await;
        });
        let old_ack = tokio::time::timeout(Duration::from_secs(1), boundary_rx.recv())
            .await
            .unwrap()
            .unwrap();
        sessions.send_replace(Some("current-session".to_string()));
        let current_ack = tokio::time::timeout(Duration::from_secs(1), boundary_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            old_ack.send(installed.clone()).is_err(),
            "replaced session must cancel its pending installation"
        );
        current_ack.send(installed.clone()).unwrap();
        let report = tokio::time::timeout(Duration::from_secs(1), report_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.session_id, "current-session");
        assert_eq!(report.sequence, 1);
        assert!(report.launch_environment_installed);
        // The installation transition wakes a second report, whose sequence
        // must advance even though its desired authority is unchanged.
        let next_ack = tokio::time::timeout(Duration::from_secs(1), boundary_rx.recv())
            .await
            .unwrap()
            .unwrap();
        next_ack.send(installed).unwrap();
        let report = tokio::time::timeout(Duration::from_secs(1), report_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.sequence, 2);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), boundary_rx.recv())
                .await
                .is_err(),
            "an unchanged installation acknowledgment must not trigger another report"
        );
        sessions.send_replace(None);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), report_rx.recv())
                .await
                .is_err()
        );
        task.abort();
        let _ = task.await;
    }

    fn identity() -> EnvironmentIdentity {
        EnvironmentIdentity {
            attachment_epoch: "epoch".into(),
            revision: 6,
            policy_hash: "policy".into(),
        }
    }

    fn installation(credentials: &ProviderCredentialState) -> ProviderEnvironmentInstallation {
        ProviderEnvironmentInstallation {
            installation_id: credentials.snapshot().installation_id.clone(),
            revision: 6,
            session_id: uuid::Uuid::new_v4().to_string().parse().unwrap(),
        }
    }

    #[test]
    fn same_revision_repair_rejects_the_previous_boundary_acknowledgment() {
        let tracker = Tracker::new();
        let credentials = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
        tracker.credentials_installed(identity(), &credentials, None);
        let old = installation(&credentials);
        credentials
            .install_child_env_snapshot(6, HashMap::from([("TOKEN".into(), "restored".into())]));
        tracker.credentials_installed(identity(), &credentials, None);
        tracker.process_installed(old, &credentials);
        assert!(
            !tracker
                .observation(&credentials)
                .launch_environment_installed
        );
        tracker.process_installed(installation(&credentials), &credentials);
        assert!(
            tracker
                .observation(&credentials)
                .launch_environment_installed
        );
    }

    #[test]
    fn policy_failure_and_generation_change_invalidate_installed_evidence() {
        let tracker = Tracker::new();
        let credentials = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
        let policy = openshell_policy::restrictive_default_policy();
        let engine = openshell_supervisor_network::opa::OpaEngine::from_proto(&policy).unwrap();
        tracker.credentials_installed(identity(), &credentials, None);
        tracker.policy_activated(&identity(), 12, engine.generation_guard(0).unwrap());
        tracker.process_installed(installation(&credentials), &credentials);
        assert!(tracker.observation(&credentials).policy_active);
        engine.enter_fail_closed("test quarantine").unwrap();
        assert!(!tracker.observation(&credentials).policy_active);
        let mut rejected = identity();
        rejected.policy_hash = "rejected".into();
        tracker.policy_install_failed(rejected, 13);
        let observed = tracker.observation(&credentials);
        assert_eq!(observed.config_revision, 13);
        assert_eq!(observed.policy_hash, "rejected");
        assert!(!observed.credentials_installed);
        assert!(!observed.launch_environment_installed);
    }

    #[test]
    fn expired_credentials_and_disconnected_boundary_never_complete() {
        let tracker = Tracker::new();
        let credentials = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
        tracker.credentials_installed(identity(), &credentials, Some(1));
        tracker.process_installed(installation(&credentials), &credentials);
        assert_eq!(
            tracker.observation(&credentials).reason,
            i32::from(Reason::CredentialExpired)
        );
        tracker.credentials_installed(identity(), &credentials, None);
        tracker.process_installed(installation(&credentials), &credentials);
        tracker.process_failed();
        assert!(
            !tracker
                .observation(&credentials)
                .launch_environment_installed
        );
    }
    #[test]
    fn detached_provider_observation_requires_installed_policy_and_live_boundary() {
        use openshell_core::proto::{StaticCredentialBinding, StaticCredentialEndpointBinding};
        let provider = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let credentials = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".into(), "synthetic-only".into())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".into(),
                StaticCredentialBinding {
                    credential_identity: format!("{provider}:API_KEY"),
                    workload_credential_handle: String::new(),
                    endpoints: vec![StaticCredentialEndpointBinding {
                        host: "api.example.test".into(),
                        port: 443,
                        path: "/**".into(),
                    }],
                },
            )]),
            Vec::new(),
        )
        .unwrap();
        let subject = credentials
            .capture_static_provider_revocation(provider)
            .unwrap();
        credentials
            .install_bound_environment(
                6,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
            )
            .unwrap();
        let tracker = Tracker::new();
        assert!(
            tracker
                .provider_revocation_observation(&credentials, &subject, "epoch", 6)
                .is_none()
        );
        tracker.credentials_installed(identity(), &credentials, None);
        assert!(
            tracker
                .provider_revocation_observation(&credentials, &subject, "epoch", 6)
                .is_none()
        );
        let policy = openshell_policy::restrictive_default_policy();
        let engine = openshell_supervisor_network::opa::OpaEngine::from_proto(&policy).unwrap();
        tracker.policy_activated(&identity(), 12, engine.generation_guard(0).unwrap());
        assert!(
            tracker
                .provider_revocation_observation(&credentials, &subject, "epoch", 6)
                .is_none()
        );
        tracker.process_installed(installation(&credentials), &credentials);
        let (observation, evidence) = tracker
            .provider_revocation_observation(&credentials, &subject, "epoch", 6)
            .unwrap();
        assert!(evidence.unavailable);
        assert_eq!(evidence.provider_id, provider);
        assert!(
            observation.credentials_installed
                && observation.policy_active
                && observation.launch_environment_installed
        );
        // No fresh request/action/session association is manufactured by this helper.
        assert!(observation.session_id.is_empty());
        assert_eq!(observation.sequence, 0);
        assert!(
            tracker
                .provider_revocation_observation(&credentials, &subject, "other-epoch", 6)
                .is_none()
        );
        assert!(
            tracker
                .provider_revocation_observation(&credentials, &subject, "epoch", 5)
                .is_none()
        );
        engine
            .enter_fail_closed("synthetic policy invalidation")
            .unwrap();
        assert!(
            tracker
                .provider_revocation_observation(&credentials, &subject, "epoch", 6)
                .is_none()
        );
    }
    #[tokio::test]
    async fn provider_detach_reporter_lost_metadata_replies_keep_exact_install_and_proof_sequences()
    {
        use openshell_core::proto::*;
        let provider = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let credentials = ProviderCredentialState::from_bound_environment(
            5,
            HashMap::from([("API_TOKEN".into(), "synthetic-only".into())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_TOKEN".into(),
                StaticCredentialBinding {
                    endpoints: vec![StaticCredentialEndpointBinding {
                        host: "api.example.test".into(),
                        port: 8080,
                        path: "/v1/**".into(),
                    }],
                    credential_identity: format!("{provider}:API_TOKEN"),
                    workload_credential_handle: String::new(),
                },
            )]),
            vec![],
        )
        .unwrap();
        credentials.enable_provider_detach_attempts();
        credentials
            .install_bound_environment(
                6,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                vec![],
            )
            .unwrap();
        let identity = EnvironmentIdentity {
            attachment_epoch: "33333333-3333-4333-8333-333333333333".into(),
            revision: 6,
            policy_hash: "e".repeat(64),
        };
        let tracker = Tracker::new();
        tracker.credentials_installed(identity.clone(), &credentials, None);
        let policy = openshell_policy::restrictive_default_policy();
        let engine = openshell_supervisor_network::opa::OpaEngine::from_proto(&policy).unwrap();
        tracker.policy_activated(&identity, 9, engine.generation_guard(0).unwrap());
        let installed = installation(&credentials);
        let session = "55555555-5555-4555-8555-555555555555";
        let boot = "88888888-8888-4888-8888-888888888888";
        let (sessions, receiver) = watch::channel(Some(session.into()));
        let (boundary_tx, mut boundary_rx) = tokio::sync::mpsc::unbounded_channel();
        let (report_tx, mut report_rx) = tokio::sync::mpsc::unbounded_channel();
        let worker = tracker.clone();
        let worker_credentials = credentials.clone();
        let task = tokio::spawn(async move {
            worker
                .run_reporter(
                    worker_credentials,
                    receiver,
                    Arc::new(DelayedBoundary(boundary_tx)),
                    DelayedReporter(report_tx),
                )
                .await;
        });
        let (first, response) = next_installation_report(
            &mut boundary_rx,
            &mut report_rx,
            &installed,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(first.sequence, 1);
        let now =
            openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now()).unwrap();
        let attempt_id = "5891bfb6-f198-5af2-ad78-cccd52e62f10";
        let challenge = "a".repeat(64);
        let a = ProviderDetachAttemptV1 {
            schema_version: 1,
            action_id: "original-action".into(),
            target_sha256: "b".repeat(64),
            gateway_boot_id: boot.into(),
            supervisor_session: session.into(),
            supervisor_instance: "44444444-4444-4444-8444-444444444444".into(),
            provider_id: provider.into(),
            attachment_epoch: identity.attachment_epoch.clone(),
            configuration_instance: "config-after".into(),
            provider_env_revision: 6,
            config_revision: 9,
            native_policy_hash: identity.policy_hash.clone(),
            native_policy_version: 4,
            arm_capture_sequence: 1,
            challenge: challenge.clone(),
            not_before: Some(prost_types::Timestamp {
                seconds: now.seconds - 1,
                nanos: now.nanos,
            }),
            deadline: Some(prost_types::Timestamp {
                seconds: now.seconds + 20,
                nanos: now.nanos,
            }),
            ..Default::default()
        };
        let q = ProviderDetachArmRequestV1 {
            original_action: Some(ProviderDetachActionV1 {
                target: Some(ProviderDetachTargetV1 {
                    provider_env_revision: 5,
                    provider_id: provider.into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            attempt: Some(a),
            attempt_id: attempt_id.into(),
            request_sha256: "b".repeat(64),
            ..Default::default()
        };
        let seal = ProviderDetachArmSealV1 {
            request: Some(q),
            hold_generation: 1,
            row_resource_version: 1,
            install_sequence: 0,
            installed_time: None,
        };
        let ack = |seq| ReportProviderReadinessResponse {
            accepted_sequence: seq,
            observation_ttl: Some(prost_types::Duration {
                seconds: 15,
                nanos: 0,
            }),
            provider_detach_gateway_boot_id: boot.into(),
            ..Default::default()
        };
        let mut delivered = ack(1);
        delivered.provider_detach_pending = Some(seal.clone());
        response.send(delivered).unwrap();
        let (install, lost) = next_installation_report(
            &mut boundary_rx,
            &mut report_rx,
            &installed,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(install.sequence, 2);
        assert_eq!(
            install.provider_detach.as_ref().unwrap().install_sequence,
            2
        );
        drop(lost);
        tracker.state.send_modify(|_| {});
        let (install_retry, response) = next_installation_report(
            &mut boundary_rx,
            &mut report_rx,
            &installed,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(install_retry, install);
        let mut installed_seal = seal;
        installed_seal.install_sequence = 2;
        installed_seal.installed_time = Some(
            openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now()).unwrap(),
        );
        let mut accepted = ack(2);
        accepted.provider_detach_installed = Some(installed_seal);
        response.send(accepted).unwrap();
        // The next actual boundary synchronization happens after processing
        // the previous native ACK; no scheduler timing assumption is needed.
        tracker.state.send_modify(|_| {});
        let waiting = tokio::time::timeout(Duration::from_secs(1), boundary_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let now =
            openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now()).unwrap();
        assert_eq!(
            credentials.witness_provider_detach_header(
                attempt_id,
                &challenge,
                "Bearer openshell:resolve:env:v5_API_TOKEN",
                "api.example.test",
                8080,
                "/v1/messages?beta=true",
                None,
                6,
                now
            ),
            openshell_core::provider_credentials::ProviderDetachWitness::Unavailable
        );
        waiting.send(installed.clone()).unwrap();
        let (proof, lost) = tokio::time::timeout(Duration::from_secs(1), report_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(proof.sequence, 3);
        assert_eq!(
            proof
                .provider_detach
                .as_ref()
                .unwrap()
                .refusal
                .as_ref()
                .unwrap()
                .sequence,
            3
        );
        drop(lost);
        tracker.state.send_modify(|_| {});
        let (proof_retry, response) = next_installation_report(
            &mut boundary_rx,
            &mut report_rx,
            &installed,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(proof_retry, proof);
        response.send(ack(3)).unwrap();
        sessions.send_replace(Some("77777777-7777-4777-8777-777777777777".into()));
        let (reconnected, response) = next_installation_report(
            &mut boundary_rx,
            &mut report_rx,
            &installed,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(reconnected.sequence, 1);
        assert!(
            reconnected
                .provider_detach
                .as_ref()
                .unwrap()
                .attempt_id
                .is_empty()
        );
        assert!(
            reconnected
                .provider_detach
                .as_ref()
                .unwrap()
                .refusal
                .is_none()
        );
        response.send(ack(1)).unwrap();
        task.abort();
        let _ = task.await;
    }
    #[derive(Debug, Default)]
    struct WitnessBoundaryProbe {
        calls: std::sync::atomic::AtomicUsize,
    }
    #[tonic::async_trait]
    impl openshell_core::provider_credentials::ProviderWitnessBoundary for WitnessBoundaryProbe {
        async fn capability(
            &self,
        ) -> Option<openshell_core::provider_credentials::WitnessBoundaryCapability> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            None
        }
        async fn prepare(
            &self,
            _operation: openshell_core::provider_credentials::WitnessOperation,
        ) -> Option<openshell_core::provider_credentials::WitnessOperation> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            None
        }
        async fn permit(
            &self,
            _permit: openshell_core::provider_credentials::WitnessCommittedPermit,
        ) -> bool {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            false
        }
        async fn fence(
            &self,
            _fence: openshell_core::provider_credentials::WitnessSourceFence,
        ) -> bool {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            false
        }
    }
    fn witness_control_fixture() -> (FixedWitnessControl, Arc<WitnessBoundaryProbe>) {
        let credentials = ProviderCredentialState::from_child_env_snapshot(1, HashMap::new());
        let mut engine = openshell_supervisor_network::opa::OpaEngine::from_proto(
            &openshell_policy::restrictive_default_policy(),
        )
        .unwrap();
        engine.bind_witness_launch_gate(&credentials);
        let boundary = Arc::new(WitnessBoundaryProbe::default());
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        (
            FixedWitnessControl {
                credentials,
                engine: Arc::new(engine),
                boundary: boundary.clone(),
                capability: openshell_core::provider_credentials::WitnessBoundaryCapability {
                    boundary_incarnation: uuid::Uuid::new_v4().to_string(),
                    execution_id: format!("exec-v1:{}", "a".repeat(64)),
                    profile_sha256: "b".repeat(64),
                },
                closed: std::sync::atomic::AtomicBool::new(false),
                accepted_session: std::sync::Mutex::new(None),
                originals: std::sync::Mutex::default(),
                observations: tx,
                receiver: std::sync::Mutex::new(Some(rx)),
            },
            boundary,
        )
    }
    #[tokio::test]
    async fn witness_control_unknown_prepare_is_original_and_never_replayed() {
        use openshell_core::proto::{
            ProviderDetachActionV1, ProviderDetachArmRequestV1, ProviderDetachArmSealV1,
            ProviderDetachAttemptV1, ProviderDetachTargetV1, ProviderDetachWitnessRequestV1,
        };
        use openshell_supervisor_process::supervisor_session::ProviderWitnessControl as _;
        let (control, boundary) = witness_control_fixture();
        let session = uuid::Uuid::new_v4().to_string();
        let cap = control.capability(&session).unwrap();
        let mut q = ProviderDetachWitnessRequestV1 {
            run_id: uuid::Uuid::new_v4().to_string(),
            profile_id: "provider-detach-benign-witness-v1".into(),
            profile_sha256: cap.profile_sha256,
            source_incarnation: cap.source_incarnation,
            boundary_incarnation: cap.boundary_incarnation,
            installed_arm: Some(ProviderDetachArmSealV1 {
                request: Some(ProviderDetachArmRequestV1 {
                    original_action: Some(ProviderDetachActionV1 {
                        action_id: uuid::Uuid::new_v4().to_string(),
                        target: Some(ProviderDetachTargetV1 {
                            authority: "gateway".into(),
                            execution_id: cap.execution_id,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    attempt: Some(ProviderDetachAttemptV1 {
                        supervisor_session: session.clone(),
                        deadline: Some(prost_types::Timestamp {
                            seconds: i64::MAX / 1000,
                            nanos: 0,
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        q.request_sha256 = openshell_core::provider_credentials::witness_request_digest(&q);
        // A rejected replacement session cannot borrow the old capability,
        // even if its typed request and digest name that replacement session.
        let other_session = uuid::Uuid::new_v4().to_string();
        let mut substituted = q.clone();
        substituted
            .installed_arm
            .as_mut()
            .unwrap()
            .request
            .as_mut()
            .unwrap()
            .attempt
            .as_mut()
            .unwrap()
            .supervisor_session = other_session.clone();
        substituted.request_sha256 =
            openshell_core::provider_credentials::witness_request_digest(&substituted);
        let _refused = control.invoke(&other_session, substituted).await;
        assert_eq!(boundary.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(control.originals.lock().unwrap().is_empty());
        let response = control.invoke(&session, q.clone()).await;
        assert_eq!(response.state, "unknown");
        assert!(!response.original_key.is_empty());
        assert_eq!(boundary.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(control.invoke(&session, q.clone()).await, response);
        assert_eq!(boundary.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        control.disconnect();
        assert!(control.capability(&session).is_none());
        let other = uuid::Uuid::new_v4().to_string();
        assert!(control.capability(&other).is_none());
        let _ = control.invoke(&session, q).await;
        assert_eq!(boundary.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    #[test]
    fn witness_control_failed_initial_dial_is_distinct_from_accepted_session_loss() {
        use openshell_supervisor_process::supervisor_session::ProviderWitnessControl as _;
        let (control, boundary) = witness_control_fixture();
        control.disconnect();
        assert!(control.capability(&uuid::Uuid::nil().to_string()).is_none());
        assert!(control.capability("INVALID").is_none());
        let original = uuid::Uuid::new_v4().to_string();
        let cap = control.capability(&original).unwrap();
        assert_eq!(control.capability(&original), Some(cap));
        assert!(
            control
                .capability(&uuid::Uuid::new_v4().to_string())
                .is_none()
        );
        control.disconnect();
        assert!(control.capability(&original).is_none());
        assert_eq!(boundary.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn witness_control_without_compiled_artifact_never_probes_boundary() {
        if openshell_core::provider_credentials::fixed_provider_witness_profile().is_some() {
            return;
        }
        let (control, boundary) = witness_control_fixture();
        control.credentials.enable_provider_detach_attempts();
        assert!(
            control
                .credentials
                .install_witness_boundary(boundary.clone())
        );
        assert!(
            fixed_witness_control(control.credentials, control.engine)
                .await
                .is_none()
        );
        assert_eq!(boundary.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
