// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0

//! Original ordinary observation metadata only. No task input or model effect.
#![allow(clippy::result_large_err)]
use crate::auth::workspace_authz::{
    MinWorkspaceRole, authorize_workspace, selected_workspace_name,
};
use crate::{ServerState, auth::principal::Principal};
use openshell_core::proto::{
    BeginProviderDetachObservationRequest, BeginProviderDetachObservationResponse,
    GetProviderDetachObservationRequest, GetProviderDetachObservationResponse, ProviderDetachAckv1,
    ProviderDetachResourceV1, ProviderObservationPhaseV1, ProviderObservationRequestV1,
    ProviderObservationResultV1, ProviderObservationSnapshotV1, ProviderObservationStateV1,
    Sandbox, SandboxPhase, WorkspaceSelector,
};
use openshell_core::provider_credentials::ordinary_observation as obs;
use openshell_core::{ObjectName, ObjectWorkspace};
use prost::Message;
use std::sync::Arc;
use tonic::{Request, Response, Status};

fn invalid() -> Status {
    Status::failed_precondition("ordinary original/current binding unavailable")
}
fn resource(q: &GetProviderDetachObservationRequest) -> Result<&ProviderDetachResourceV1, Status> {
    if q.encoded_len() > 8192 {
        return Err(Status::resource_exhausted("ordinary query capacity"));
    }
    match (&q.original_request, &q.resource) {
        (None, Some(r)) => Ok(r),
        (Some(original), None) if obs::shape(original) => {
            original.resource.as_ref().ok_or_else(invalid)
        }
        _ => Err(Status::invalid_argument("ordinary query mode invalid")),
    }
}
async fn authorize<T: Sync>(
    state: &Arc<ServerState>,
    rpc: &Request<T>,
    r: &ProviderDetachResourceV1,
    scope: Option<&WorkspaceSelector>,
    write: bool,
    current: bool,
) -> Result<(), Status> {
    if [
        &r.authority,
        &r.workspace,
        &r.sandbox,
        &r.sandbox_id,
        &r.execution_id,
        &r.provider,
        &r.provider_id,
    ]
    .iter()
    .any(|s| s.is_empty() || s.len() > 253 || s.chars().any(char::is_whitespace))
        || r.authority != state.config.name
        || selected_workspace_name(scope)? != r.workspace
    {
        return Err(Status::invalid_argument("ordinary resource invalid"));
    }
    let Some(Principal::User(user)) = rpc.extensions().get::<Principal>() else {
        return Err(Status::permission_denied("ordinary verified user required"));
    };
    let oidc = state
        .config
        .oidc
        .as_ref()
        .ok_or_else(|| Status::permission_denied("ordinary issuer unavailable"))?;
    crate::auth::authz::check_ordinary_observation_grant(
        &user.identity,
        &crate::auth::authz::AuthzPolicy {
            admin_role: oidc.admin_role.clone(),
            user_role: oidc.user_role.clone(),
            scopes_enabled: !oidc.scopes_claim.is_empty(),
        },
        &super::provider_detach::resource_digest(r)?,
        write,
    )?;
    authorize_workspace(
        state.store.as_ref(),
        &oidc.admin_role,
        &Principal::User(user.clone()),
        &r.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    if !state.store.is_single_replica() {
        return Err(Status::unimplemented("ordinary store unsupported"));
    }
    if !current {
        return Ok(());
    }
    let sandbox = state
        .store
        .get_message::<Sandbox>(&r.sandbox_id)
        .await
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    if sandbox.object_name() != r.sandbox
        || sandbox.object_workspace() != r.workspace
        || sandbox.phase() != SandboxPhase::Ready as i32
        || crate::auth::sandbox_session::sandbox_execution_id(&sandbox)? != r.execution_id
    {
        return Err(invalid());
    }
    Ok(())
}
async fn configuration_current(
    state: &Arc<ServerState>,
    r: &ProviderDetachResourceV1,
    sample: &ProviderObservationSnapshotV1,
) -> Result<u64, Status> {
    if !obs::valid_snapshot(sample) || sample.resource.as_ref() != Some(r) {
        return Err(invalid());
    }
    let sandbox = state
        .store
        .get_message::<Sandbox>(&r.sandbox_id)
        .await
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    if sandbox.object_name() != r.sandbox
        || sandbox.object_workspace() != r.workspace
        || sandbox.phase() != SandboxPhase::Ready as i32
        || crate::auth::sandbox_session::sandbox_execution_id(&sandbox)? != r.execution_id
    {
        return Err(invalid());
    }
    let provider = state
        .store
        .get_by_name("provider", &r.workspace, &r.provider)
        .await
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    if provider.id != r.provider_id {
        return Err(invalid());
    }
    let config = super::policy::load_sandbox_config(state, &sandbox).await?;
    if !config.configuration_admitted
        || config.configuration_instance_id.is_empty()
        || config.config_revision == 0
        || config.provider_env_revision == 0
    {
        return Err(invalid());
    }
    let instance = sandbox
        .status
        .as_ref()
        .map(|s| s.main_process_instance_id.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(invalid)?;
    state.supervisor_sessions.with_provider_detach_attempts(
        &r.sandbox_id,
        &sample.supervisor_session,
        instance,
        |evidence, attempts| {
            let (network, ready, _) = evidence.provider_detach_snapshot().ok_or_else(invalid)?;
            if network != instance
                || sample.supervisor_instance != instance
                || sample.gateway_boot_id != attempts.boot_id
                || ready.session_id != sample.supervisor_session
                || ready.attachment_epoch != config.provider_attachment_epoch
                || ready.config_revision != config.config_revision
                || ready.provider_env_revision != config.provider_env_revision
                || ready.policy_hash != config.policy_hash
                || !ready.credentials_installed
                || !ready.policy_active
                || !ready.launch_environment_installed
                || ready.process_instance_id.is_empty()
                || sample.resolver_generation != ready.provider_env_revision
                || sample.configuration_sha256 != obs::configuration_digest(&ready)
            {
                return Err(invalid());
            }
            Ok(ready.sequence)
        },
    )
}
async fn detached_current(
    state: &Arc<ServerState>,
    q: &ProviderObservationRequestV1,
) -> Result<Option<ProviderDetachAckv1>, Status> {
    if q.phase != ProviderObservationPhaseV1::Detached as i32 {
        return Ok(None);
    }
    let seal = q.installed_arm.as_ref().ok_or_else(invalid)?;
    let arm = seal
        .request
        .as_ref()
        .filter(|r| r.attempt.is_some() && !r.attempt_id.is_empty() && !r.request_sha256.is_empty())
        .ok_or_else(invalid)?;
    // Reuse the actual non-bootstrap original hold/config/ACK validator.
    // This helper is called only AFTER the exact ordinary OIDC/workspace grant.
    let read = super::provider_detach::read_attempt(state, arm, false).await?;
    if read.seal.as_ref() != Some(seal) {
        return Err(invalid());
    }
    let current = read.current.ok_or_else(invalid)?;
    if current.hold_generation != seal.hold_generation
        || current.row_resource_version != seal.row_resource_version
    {
        return Err(invalid());
    }
    Ok(Some(current.ack.ok_or_else(invalid)?))
}
pub async fn begin(
    state: &Arc<ServerState>,
    rpc: Request<BeginProviderDetachObservationRequest>,
) -> Result<Response<BeginProviderDetachObservationResponse>, Status> {
    let q = rpc
        .get_ref()
        .request
        .as_ref()
        .filter(|q| obs::shape(q))
        .ok_or_else(invalid)?;
    let r = q.resource.as_ref().ok_or_else(invalid)?;
    authorize(
        state,
        &rpc,
        r,
        rpc.get_ref().workspace_scope.as_ref(),
        true,
        true,
    )
    .await?;
    detached_current(state, q).await?;
    let fence = state
        .store
        .provider_detach_fence()
        .await
        .map_err(|_| invalid())?;
    let selector = GetProviderDetachObservationRequest {
        workspace_scope: rpc.get_ref().workspace_scope.clone(),
        original_request: None,
        resource: Some(r.clone()),
    };
    let cap = state.supervisor_sessions.ordinary_snapshot(r)?;
    let fresh = state
        .supervisor_sessions
        .ordinary_read(selector, cap, None)
        .await?;
    let expected = fresh.sampled_snapshot.as_ref().ok_or_else(invalid)?;
    if fresh.active_attempts != 0 || fresh.accounting_fault {
        return Err(invalid());
    }
    configuration_current(state, r, expected).await?;
    obs::install_budget(q, expected)
        .ok_or_else(|| Status::resource_exhausted("ordinary complete result/read budget"))?;
    if q.source_incarnation != expected.source_incarnation
        || q.boundary_incarnation != expected.boundary_incarnation
        || q.profile_sha256 != expected.profile_sha256
        || expected.resource.as_ref() != Some(r)
    {
        return Err(invalid());
    }
    if q.phase == ProviderObservationPhaseV1::Detached as i32
        && q.baseline_mediation_path_receipt_sha256 != expected.mediation_path_receipt_sha256
    {
        return Err(invalid());
    }
    let created = state
        .store
        .claim_ordinary_observation(q, &fence, expected)
        .await
        .map_err(|_| invalid())?;
    if !created {
        return Err(Status::already_exists("ordinary original is query only"));
    }
    // A committed original is consumed even if any subsequent check/send fails.
    if state
        .store
        .provider_detach_fence()
        .await
        .map_err(|_| invalid())?
        != fence
    {
        return Err(invalid());
    }
    detached_current(state, q).await?;
    configuration_current(state, r, expected).await?;
    if !state.supervisor_sessions.ordinary_closing(r, expected) {
        return Err(invalid());
    }
    state
        .supervisor_sessions
        .ordinary_send_once(r, expected, q.clone())?;
    Ok(Response::new(BeginProviderDetachObservationResponse {
        result: Some(ProviderObservationResultV1 {
            state: ProviderObservationStateV1::PendingInstall as i32,
            ..Default::default()
        }),
    }))
}
pub async fn get(
    state: &Arc<ServerState>,
    rpc: Request<GetProviderDetachObservationRequest>,
) -> Result<Response<GetProviderDetachObservationResponse>, Status> {
    let selector = rpc.get_ref();
    let r = resource(selector)?;
    authorize(
        state,
        &rpc,
        r,
        selector.workspace_scope.as_ref(),
        false,
        selector.original_request.is_none(),
    )
    .await?;
    let fence = state
        .store
        .provider_detach_fence()
        .await
        .map_err(|_| invalid())?;
    if let Some(q) = &selector.original_request {
        let result = state.supervisor_sessions.ordinary_result(r, q).or(state
            .store
            .ordinary_history(q)
            .await
            .map_err(|_| invalid())?);
        let Some(mut result) = result else {
            return Err(Status::not_found(
                "ordinary original outcome unknown; no retry",
            ));
        };
        if !result.terminal_sha256.is_empty() {
            state
                .store
                .retain_ordinary_result(q, &result)
                .await
                .map_err(|_| invalid())?;
        }
        // History remains immutable and may exist without a live session. A
        // failed fresh read never silently returns current proof from cache.
        let expected = result
            .window
            .as_ref()
            .and_then(|w| w.installed_snapshot.clone())
            .ok_or_else(invalid)?;
        let read = state
            .supervisor_sessions
            .ordinary_read(selector.clone(), expected.clone(), Some(&result))
            .await;
        if let Ok(read) = read {
            let sample = read.sampled_snapshot.as_ref().ok_or_else(invalid)?;
            let last = result.events.last().map_or_else(
                || result.window.as_ref().map_or(0, |w| w.ingress_watermark),
                |e| e.ingress_sequence,
            );
            let now = crate::persistence::current_time_ms();
            let terminal = result.state == ProviderObservationStateV1::Terminal as i32
                && !result.events.is_empty();
            let installed_open = result.state == ProviderObservationStateV1::Open as i32
                && result.terminal_sha256.is_empty()
                && result
                    .window
                    .as_ref()
                    .and_then(|w| w.capture_end.as_ref())
                    .and_then(obs::time_ms)
                    .is_some_and(|end| now < end);
            // Open/current is only the original install/read ACK for a manual
            // consumed input. It is never terminal traffic qualification.
            if (terminal || installed_open)
                && read.active_attempts == 0
                && !read.accounting_fault
                && sample.current_ingress_sequence == last
                && obs::same_identity(&expected, sample)
                && q.deadline
                    .as_ref()
                    .and_then(obs::time_ms)
                    .is_some_and(|end| now < end)
                && state
                    .store
                    .provider_detach_fence()
                    .await
                    .map_err(|_| invalid())?
                    == fence
            {
                result.current_report_sequence = configuration_current(state, r, sample).await?;
                result.detached_ack = detached_current(state, q).await?;
                if !state.supervisor_sessions.ordinary_closing(r, sample) {
                    return Err(invalid());
                }
                result.current_snapshot = Some(sample.clone());
                result.ack_window_sha256 = result
                    .window
                    .as_ref()
                    .ok_or_else(invalid)?
                    .window_sha256
                    .clone();
                result.ack_terminal_sha256 = result.terminal_sha256.clone();
                result.current_read = Some(read);
            }
        }
        if result.encoded_len() > obs::MAX_RESULT {
            return Err(Status::resource_exhausted(
                "ordinary public result capacity",
            ));
        }
        Ok(Response::new(GetProviderDetachObservationResponse {
            result: Some(result),
            snapshot: None,
            current_read: None,
        }))
    } else {
        let cap = state.supervisor_sessions.ordinary_snapshot(r)?;
        let reply = state
            .supervisor_sessions
            .ordinary_read(selector.clone(), cap, None)
            .await?;
        configuration_current(
            state,
            r,
            reply.sampled_snapshot.as_ref().ok_or_else(invalid)?,
        )
        .await?;
        if state
            .store
            .provider_detach_fence()
            .await
            .map_err(|_| invalid())?
            != fence
            || !state
                .supervisor_sessions
                .ordinary_closing(r, reply.sampled_snapshot.as_ref().ok_or_else(invalid)?)
        {
            return Err(invalid());
        }
        Ok(Response::new(GetProviderDetachObservationResponse {
            result: None,
            snapshot: reply.sampled_snapshot.clone(),
            current_read: Some(reply),
        }))
    }
}
#[cfg(test)]
#[path = "provider_detach_observation_tests.rs"]
mod tests;
