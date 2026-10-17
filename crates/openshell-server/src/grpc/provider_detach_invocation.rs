// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! One original fixed-profile witness. No generic execution or replay fallback.
#![allow(clippy::result_large_err)]

use crate::ServerState;
use crate::auth::principal::Principal;
use crate::auth::workspace_authz::{
    MinWorkspaceRole, authorize_workspace, selected_workspace_name,
};
use crate::persistence::{
    ProviderDetachWitnessAdmission, ProviderDetachWitnessBinding, ProviderDetachWitnessPlan,
};
use crate::policy_store::PolicyStoreExt;
use openshell_core::proto::{
    GetProviderDetachWitnessInvocationRequest, GetProviderDetachWitnessInvocationResponse,
    InvokeProviderDetachWitnessRequest, InvokeProviderDetachWitnessResponse, Provider,
    ProviderDetachArmStateV1, ProviderDetachResourceV1, ProviderDetachTargetV1,
    ProviderDetachWitnessInvocationV1, ProviderDetachWitnessRequestV1,
    ReserveProviderDetachWitnessRequest, ReserveProviderDetachWitnessResponse, Sandbox,
    SandboxPhase, WorkspaceSelector,
};
use openshell_core::{ObjectName, ObjectWorkspace};
use prost::Message;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub const PROFILE_ID: &str = "provider-detach-benign-witness-v1";

pub fn request_digest(q: &ProviderDetachWitnessRequestV1) -> String {
    let mut canonical = q.clone();
    canonical.request_sha256.clear();
    let mut hash = Sha256::new();
    hash.update(b"openshell.provider-detach.witness-request/v1\n");
    hash.update(canonical.encode_to_vec());
    format!("{:x}", hash.finalize())
}

pub fn original_key(q: &ProviderDetachWitnessRequestV1) -> Result<String, Status> {
    Ok(shape(q)?.original_key())
}

fn resource_digest(t: &ProviderDetachTargetV1) -> Result<String, Status> {
    // Same immutable existing resource projection; no mutable config/RV grant.
    #[derive(Serialize)]
    struct Resource<'a> {
        authority: &'a str,
        workspace: &'a str,
        sandbox: &'a str,
        sandbox_id: &'a str,
        execution_id: &'a str,
        provider: &'a str,
        provider_id: &'a str,
    }
    let body = serde_json::to_string(&Resource {
        authority: &t.authority,
        workspace: &t.workspace,
        sandbox: &t.sandbox,
        sandbox_id: &t.sandbox_id,
        execution_id: &t.execution_id,
        provider: &t.provider,
        provider_id: &t.provider_id,
    })
    .map_err(|_| Status::invalid_argument("witness resource unavailable"))?;
    // Match the predecessor's Go encoding/json-compatible escaping.
    let body = body
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    let mut hash = Sha256::new();
    hash.update(b"openshell.provider-detach.resource/v1\n");
    hash.update(body.as_bytes());
    Ok(format!("{:x}", hash.finalize()))
}

fn shape(q: &ProviderDetachWitnessRequestV1) -> Result<ProviderDetachWitnessBinding, Status> {
    let bad = || Status::invalid_argument("provider witness original binding invalid");
    if q.encoded_len() > 12 * 1024
        || q.profile_id != PROFILE_ID
        || q.request_sha256 != request_digest(q)
        || [&q.run_id, &q.source_incarnation, &q.boundary_incarnation]
            .into_iter()
            .any(|v| uuid::Uuid::parse_str(v).is_err())
    {
        return Err(bad());
    }
    let seal = q.installed_arm.as_ref().ok_or_else(bad)?;
    let arm = seal.request.as_ref().ok_or_else(bad)?;
    let action = arm.original_action.as_ref().ok_or_else(bad)?;
    let receipt = arm.original_receipt.as_ref().ok_or_else(bad)?;
    let attempt = arm.attempt.as_ref().ok_or_else(bad)?;
    let target = action.target.as_ref().ok_or_else(bad)?;
    super::validate_provider_detach_original_action(action)?;
    if seal.install_sequence == 0
        || seal.installed_time.is_none()
        || receipt.action_id != action.action_id
        || receipt.target != action.target
        || attempt.action_id != action.action_id
        || attempt.hold_id != receipt.hold_id
        || attempt.native_receipt_id != receipt.native_receipt_id
        || attempt.execution_id != target.execution_id
        || attempt.provider_id != target.provider_id
    {
        return Err(bad());
    }
    let deadline = attempt.deadline.as_ref().ok_or_else(bad)?;
    if !(0..1_000_000_000).contains(&deadline.nanos) {
        return Err(bad());
    }
    let deadline_ms = deadline
        .seconds
        .checked_mul(1000)
        .and_then(|v| v.checked_add(i64::from(deadline.nanos / 1_000_000)))
        .ok_or_else(bad)?;
    Ok(ProviderDetachWitnessBinding {
        authority: target.authority.clone(),
        run_id: q.run_id.clone(),
        action_id: action.action_id.clone(),
        request_sha256: q.request_sha256.clone(),
        profile_sha256: q.profile_sha256.clone(),
        original_action: action.encode_to_vec(),
        original_receipt: receipt.encode_to_vec(),
        installed_arm: seal.encode_to_vec(),
        hold_generation: seal.hold_generation,
        hold_resource_version: seal.row_resource_version,
        // Actual related-row versions are captured by plan(), never from these
        // shape-only placeholders and never used to authorize query effects.
        sandbox_resource_version: 0,
        provider_resource_version: 0,
        deadline_ms,
    })
}

async fn authorize<T: Sync>(
    state: &Arc<ServerState>,
    rpc: &Request<T>,
    q: &ProviderDetachWitnessRequestV1,
    workspace: Option<&WorkspaceSelector>,
    write: bool,
) -> Result<ProviderDetachWitnessBinding, Status> {
    let binding = shape(q)?;
    let target = q
        .installed_arm
        .as_ref()
        .unwrap()
        .request
        .as_ref()
        .unwrap()
        .original_action
        .as_ref()
        .unwrap()
        .target
        .as_ref()
        .unwrap();
    let Some(Principal::User(user)) = rpc.extensions().get::<Principal>() else {
        return Err(Status::permission_denied("witness user approval required"));
    };
    if target.authority != state.config.name
        || selected_workspace_name(workspace)? != target.workspace
    {
        return Err(Status::permission_denied(
            "witness authority/workspace mismatch",
        ));
    }
    let oidc = state
        .config
        .oidc
        .as_ref()
        .ok_or_else(|| Status::permission_denied("witness issuer unavailable"))?;
    let policy = crate::auth::authz::AuthzPolicy {
        admin_role: oidc.admin_role.clone(),
        user_role: oidc.user_role.clone(),
        scopes_enabled: !oidc.scopes_claim.is_empty(),
    };
    let approval = crate::auth::authz::check_provider_witness_grant(
        &user.identity,
        &policy,
        write,
        &resource_digest(target)?,
        &q.request_sha256,
        crate::persistence::current_time_ms(),
    )?;
    let seal = q.installed_arm.as_ref().unwrap();
    let arm = seal.request.as_ref().unwrap();
    let receipt = arm.original_receipt.as_ref().unwrap();
    if approval.run_id != q.run_id
        || approval.action_id != binding.action_id
        || approval.native_receipt_id != receipt.native_receipt_id
        || approval.hold_id != receipt.hold_id
        || approval.attempt_id != arm.attempt_id
        || approval.profile_sha256 != q.profile_sha256
        || approval.installed_arm_sha256 != format!("{:x}", Sha256::digest(seal.encode_to_vec()))
        || approval.deadline_unix_ms != binding.deadline_ms
    {
        return Err(Status::permission_denied(
            "witness original approval mismatch",
        ));
    }
    authorize_workspace(
        state.store.as_ref(),
        &state.admin_role,
        &Principal::User(user.clone()),
        &target.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    super::workspace::resolve_workspace(state.store.as_ref(), &target.workspace)
        .await?
        .ensure_active()?;
    if !state.store.is_single_replica() {
        return Err(Status::unimplemented("witness backend unsupported"));
    }
    Ok(binding)
}

async fn plan(
    state: &Arc<ServerState>,
    q: &ProviderDetachWitnessRequestV1,
    mut binding: ProviderDetachWitnessBinding,
) -> Result<ProviderDetachWitnessPlan, Status> {
    let compiled = openshell_core::provider_credentials::fixed_provider_witness_profile()
        .ok_or_else(|| Status::unimplemented("witness compiled profile unsupported"))?;
    if q.profile_sha256 != compiled {
        return Err(Status::failed_precondition(
            "witness compiled profile mismatch",
        ));
    }
    let bad = || Status::failed_precondition("witness current original prerequisites unavailable");
    let seal = q.installed_arm.as_ref().ok_or_else(bad)?;
    let arm = seal.request.as_ref().ok_or_else(bad)?;
    let attempt = arm.attempt.as_ref().ok_or_else(bad)?;
    let receipt = arm.original_receipt.as_ref().ok_or_else(bad)?;
    let target = arm
        .original_action
        .as_ref()
        .and_then(|a| a.target.as_ref())
        .ok_or_else(bad)?;
    // No external catalog, policy backfill, or implicit config activation.
    if state
        .provider_profile_sources
        .source_ids()
        .iter()
        .any(|id| *id != "user")
    {
        return Err(bad());
    }
    state
        .supervisor_sessions
        .check_provider_witness_capability(&target.sandbox_id, attempt, q)?;
    let native = state.supervisor_sessions.with_provider_detach_attempts(
        &target.sandbox_id,
        &attempt.supervisor_session,
        &attempt.supervisor_instance,
        |_, attempts| {
            attempts.query(
                arm,
                &openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now())
                    .map_err(|_| bad())?,
            )
        },
    )?;
    if native.state != ProviderDetachArmStateV1::Armed as i32
        || native.seal.as_ref() != Some(seal)
        || native.result != 0
    {
        return Err(bad());
    }
    let fence = state
        .store
        .provider_detach_fence()
        .await
        .map_err(|_| bad())?;
    let sandbox_row = state
        .store
        .get("sandbox", &target.sandbox_id)
        .await
        .map_err(|_| bad())?
        .ok_or_else(bad)?;
    let sandbox = Sandbox::decode(sandbox_row.payload.as_slice()).map_err(|_| bad())?;
    let provider_row = state
        .store
        .get_by_name("provider", &target.workspace, &target.provider)
        .await
        .map_err(|_| bad())?
        .ok_or_else(bad)?;
    if sandbox.object_name() != target.sandbox
        || sandbox.object_workspace() != target.workspace
        || provider_row.id != target.provider_id
        || state
            .store
            .get_latest_policy(&target.sandbox_id)
            .await
            .map_err(|_| bad())?
            .is_none()
    {
        return Err(bad());
    }
    let config = super::policy::load_sandbox_config(state, &sandbox).await?;
    let expected_snapshot = (
        receipt.configuration_instance.as_str(),
        receipt.config_revision,
        receipt.provider_env_revision,
        receipt.native_policy_hash.as_str(),
        receipt.native_policy_version,
        receipt.after_attachment_epoch.as_str(),
    );
    let actual_snapshot = (
        config.configuration_instance_id.as_str(),
        config.config_revision,
        config.provider_env_revision,
        config.policy_hash.as_str(),
        config.version,
        config.provider_attachment_epoch.as_str(),
    );
    if !config.configuration_admitted
        || actual_snapshot != expected_snapshot
        || state
            .store
            .provider_detach_fence()
            .await
            .map_err(|_| bad())?
            != fence
    {
        return Err(bad());
    }
    binding.sandbox_resource_version = sandbox_row.resource_version;
    binding.provider_resource_version = provider_row.resource_version;
    Ok(ProviderDetachWitnessPlan { binding, fence })
}

fn readback(admission: &ProviderDetachWitnessAdmission) -> ProviderDetachWitnessInvocationV1 {
    ProviderDetachWitnessInvocationV1 {
        original_key: admission.binding.original_key(),
        request_sha256: admission.binding.request_sha256.clone(),
        state: if admission.dispatch_claimed {
            "unknown"
        } else {
            "reserved"
        }
        .into(),
        ..Default::default()
    }
}

pub async fn reserve(
    state: &Arc<ServerState>,
    rpc: Request<ReserveProviderDetachWitnessRequest>,
) -> Result<Response<ReserveProviderDetachWitnessResponse>, Status> {
    let q = rpc
        .get_ref()
        .request
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("witness request absent"))?;
    let binding = authorize(state, &rpc, q, rpc.get_ref().workspace_scope.as_ref(), true).await?;
    let plan = plan(state, q, binding).await?;
    let original = state
        .store
        .reserve_provider_detach_witness(&plan, false)
        .await
        .map_err(|_| Status::failed_precondition("witness reservation refused or unknown"))?;
    Ok(Response::new(ReserveProviderDetachWitnessResponse {
        invocation: Some(readback(&original)),
    }))
}

pub async fn invoke(
    state: &Arc<ServerState>,
    rpc: Request<InvokeProviderDetachWitnessRequest>,
) -> Result<Response<InvokeProviderDetachWitnessResponse>, Status> {
    let q = rpc
        .get_ref()
        .request
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("witness request absent"))?;
    let binding = authorize(state, &rpc, q, rpc.get_ref().workspace_scope.as_ref(), true).await?;
    let plan = plan(state, q, binding).await?;
    let original = state
        .store
        .reserve_provider_detach_witness(&plan, true)
        .await
        .map_err(|_| {
            Status::failed_precondition("witness dispatch refused or unknown; read original only")
        })?;
    // Exactly one nonrecovering send after durable first claim. Full/closed/lost
    // transport remains unknown; no retry, reconnect adoption or generic Exec.
    let target = q
        .installed_arm
        .as_ref()
        .unwrap()
        .request
        .as_ref()
        .unwrap()
        .original_action
        .as_ref()
        .unwrap()
        .target
        .as_ref()
        .unwrap();
    let _ = state
        .supervisor_sessions
        .send_provider_witness_once(&target.sandbox_id, q);
    Ok(Response::new(InvokeProviderDetachWitnessResponse {
        invocation: Some(readback(&original)),
    }))
}

fn metadata_resource_shape(resource: &ProviderDetachResourceV1) -> Result<(), Status> {
    let token = |v: &str| {
        !v.is_empty()
            && v.len() <= 253
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
    };
    if [
        &resource.authority,
        &resource.workspace,
        &resource.sandbox,
        &resource.sandbox_id,
        &resource.provider,
        &resource.provider_id,
    ]
    .iter()
    .any(|v| !token(v))
        || resource
            .execution_id
            .strip_prefix("exec-v1:")
            .is_none_or(|v| {
                v.len() != 64
                    || !v
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
    {
        return Err(Status::invalid_argument("witness resource invalid"));
    }
    Ok(())
}
fn metadata_resource_digest(resource: &ProviderDetachResourceV1) -> Result<String, Status> {
    resource_digest(&ProviderDetachTargetV1 {
        authority: resource.authority.clone(),
        workspace: resource.workspace.clone(),
        sandbox: resource.sandbox.clone(),
        sandbox_id: resource.sandbox_id.clone(),
        execution_id: resource.execution_id.clone(),
        provider: resource.provider.clone(),
        provider_id: resource.provider_id.clone(),
        ..Default::default()
    })
}
fn query_metadata_mode(q: &GetProviderDetachWitnessInvocationRequest) -> Result<bool, Status> {
    if q.encoded_len() > 12 * 1024 {
        return Err(Status::invalid_argument("witness query too large"));
    }
    match (q.request.is_some(), q.capability_resources.len()) {
        (true, 0) => Ok(false),
        (false, 1) => {
            metadata_resource_shape(&q.capability_resources[0])?;
            Ok(true)
        }
        _ => Err(Status::invalid_argument("witness query mode invalid")),
    }
}
async fn authorize_metadata(
    state: &Arc<ServerState>,
    rpc: &Request<GetProviderDetachWitnessInvocationRequest>,
    resource: &ProviderDetachResourceV1,
) -> Result<(), Status> {
    metadata_resource_shape(resource)?;
    let Some(Principal::User(user)) = rpc.extensions().get::<Principal>() else {
        return Err(Status::permission_denied("witness metadata user required"));
    };
    if resource.authority != state.config.name
        || selected_workspace_name(rpc.get_ref().workspace_scope.as_ref())? != resource.workspace
    {
        return Err(Status::permission_denied(
            "witness authority/workspace mismatch",
        ));
    }
    let oidc = state
        .config
        .oidc
        .as_ref()
        .ok_or_else(|| Status::permission_denied("witness issuer unavailable"))?;
    crate::auth::authz::check_provider_witness_metadata_grant(
        &user.identity,
        &crate::auth::authz::AuthzPolicy {
            admin_role: oidc.admin_role.clone(),
            user_role: oidc.user_role.clone(),
            scopes_enabled: !oidc.scopes_claim.is_empty(),
        },
        &metadata_resource_digest(resource)?,
    )?;
    authorize_workspace(
        state.store.as_ref(),
        &oidc.admin_role,
        &Principal::User(user.clone()),
        &resource.workspace,
        MinWorkspaceRole::User,
    )
    .await
    .map_err(|_| Status::permission_denied("witness workspace unavailable"))?;
    super::workspace::resolve_workspace(state.store.as_ref(), &resource.workspace)
        .await
        .map_err(|_| Status::failed_precondition("witness workspace unavailable"))?
        .ensure_active()
        .map_err(|_| Status::failed_precondition("witness workspace unavailable"))?;
    if !state.store.is_single_replica() {
        return Err(Status::unimplemented("witness backend unsupported"));
    }
    Ok(())
}
// Exact original row contents and RVs, not only names or an execution label.
// This deliberately never invokes policy/config resolution or backfill.
async fn metadata_rows(
    state: &Arc<ServerState>,
    resource: &ProviderDetachResourceV1,
) -> Result<(u64, u64, Vec<u8>, Vec<u8>), Status> {
    let bad = || Status::failed_precondition("witness current resource changed");
    if state
        .provider_profile_sources
        .source_ids()
        .iter()
        .any(|id| *id != "user")
    {
        return Err(bad());
    }
    let sandbox_row = state
        .store
        .get("sandbox", &resource.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("witness catalog unavailable"))?
        .ok_or_else(|| Status::not_found("witness resource absent"))?;
    let provider_row = state
        .store
        .get_by_name("provider", &resource.workspace, &resource.provider)
        .await
        .map_err(|_| Status::unavailable("witness catalog unavailable"))?
        .ok_or_else(|| Status::not_found("witness resource absent"))?;
    let sandbox = Sandbox::decode(sandbox_row.payload.as_slice()).map_err(|_| bad())?;
    let provider = Provider::decode(provider_row.payload.as_slice()).map_err(|_| bad())?;
    if sandbox_row.id != resource.sandbox_id
        || sandbox
            .metadata
            .as_ref()
            .is_none_or(|m| m.id != resource.sandbox_id)
        || sandbox.object_name() != resource.sandbox
        || sandbox.object_workspace() != resource.workspace
        || sandbox
            .status
            .as_ref()
            .is_none_or(|s| s.phase != SandboxPhase::Ready as i32)
        || !crate::auth::sandbox_session::sandbox_execution_id(&sandbox)
            .is_ok_and(|id| id == resource.execution_id)
        || provider_row.id != resource.provider_id
        || provider
            .metadata
            .as_ref()
            .is_none_or(|m| m.id != resource.provider_id)
        || provider.object_name() != resource.provider
        || provider.object_workspace() != resource.workspace
        || sandbox.spec.as_ref().is_none_or(|spec| {
            spec.providers
                .iter()
                .filter(|p| *p == &resource.provider)
                .count()
                > 1
        })
    {
        return Err(bad());
    }
    Ok((
        sandbox_row.resource_version,
        provider_row.resource_version,
        sandbox_row.payload,
        provider_row.payload,
    ))
}
async fn discovery(
    state: &Arc<ServerState>,
    rpc: &Request<GetProviderDetachWitnessInvocationRequest>,
    resource: &ProviderDetachResourceV1,
    expected_profile: &str,
    #[cfg(test)] hook: Option<&(dyn Fn(u8) + Sync)>,
) -> Result<GetProviderDetachWitnessInvocationResponse, Status> {
    authorize_metadata(state, rpc, resource).await?;
    #[cfg(test)]
    if let Some(h) = hook {
        h(0)
    }
    let rows = metadata_rows(state, resource).await?;
    #[cfg(test)]
    if let Some(h) = hook {
        h(1)
    }
    let snapshot = state.supervisor_sessions.provider_witness_metadata(
        &resource.sandbox_id,
        &resource.execution_id,
        expected_profile,
    )?;
    #[cfg(test)]
    if let Some(h) = hook {
        h(2)
    }
    // No registry lock crosses these DB awaits. Read twice, then perform the
    // closing exact session/nonce/compiled-profile association check.
    if metadata_rows(state, resource).await? != rows {
        return Err(Status::failed_precondition("witness resource changed"));
    }
    #[cfg(test)]
    if let Some(h) = hook {
        h(3)
    }
    let closing = state.supervisor_sessions.provider_witness_metadata(
        &resource.sandbox_id,
        &resource.execution_id,
        expected_profile,
    )?;
    if closing != snapshot {
        return Err(Status::failed_precondition("witness session changed"));
    }
    Ok(GetProviderDetachWitnessInvocationResponse {
        invocation: None,
        capability: Some(snapshot.1),
        capability_resource: Some(resource.clone()),
        capability_supervisor_session: snapshot.0,
    })
}

pub async fn query(
    state: &Arc<ServerState>,
    rpc: Request<GetProviderDetachWitnessInvocationRequest>,
) -> Result<Response<GetProviderDetachWitnessInvocationResponse>, Status> {
    if query_metadata_mode(rpc.get_ref())? {
        let profile = openshell_core::provider_credentials::fixed_provider_witness_profile()
            .ok_or_else(|| Status::unimplemented("witness compiled profile unsupported"))?;
        return discovery(
            state,
            &rpc,
            &rpc.get_ref().capability_resources[0],
            &profile,
            #[cfg(test)]
            None,
        )
        .await
        .map(Response::new);
    }
    let q = rpc
        .get_ref()
        .request
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("witness request absent"))?;
    let binding = authorize(
        state,
        &rpc,
        q,
        rpc.get_ref().workspace_scope.as_ref(),
        false,
    )
    .await?;
    let original = state
        .store
        .read_provider_witness_original(&binding.original_key(), &q.request_sha256)
        .await
        .map_err(|_| Status::failed_precondition("witness original read unavailable"))?;
    let mut result = original.as_ref().map_or_else(
        || ProviderDetachWitnessInvocationV1 {
            original_key: binding.original_key(),
            request_sha256: q.request_sha256.clone(),
            state: "unknown".into(),
            ..Default::default()
        },
        readback,
    );
    // Current transport observations are distinct from original durable history.
    state
        .supervisor_sessions
        .observe_provider_witness(q, &mut result);
    if let Some(arm) = q
        .installed_arm
        .as_ref()
        .and_then(|seal| seal.request.as_ref())
        && let Some(attempt) = arm.attempt.as_ref()
        && let Ok(now) =
            openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now())
        && let Ok(observation) = state.supervisor_sessions.with_provider_detach_attempts(
            &attempt.sandbox_id,
            &attempt.supervisor_session,
            &attempt.supervisor_instance,
            |_, attempts| attempts.query(arm, &now),
        )
    {
        // Existing Native transcript checks remain independent of launch,
        // process exit and boundary cancellation observations.
        result.native_observation = Some(observation);
    }

    Ok(Response::new(GetProviderDetachWitnessInvocationResponse {
        invocation: Some(result),
        ..Default::default()
    }))
}

#[cfg(test)]
#[path = "provider_detach_invocation_tests.rs"]
mod tests;
