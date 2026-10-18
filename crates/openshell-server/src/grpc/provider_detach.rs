// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Optional exact-provider-detachment boundary. Legacy detach is never a fallback.
use std::sync::Arc;

use openshell_core::proto::{
    ConditionalDetachSandboxProviderRequest, ConditionalDetachSandboxProviderResponse,
    GetConditionalProviderDetachStateRequest, GetConditionalProviderDetachStateResponse,
    ProviderDetachActionV1, ProviderDetachOriginalIntentV1, ProviderDetachResourceV1,
    ProviderDetachTargetV1,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};

use crate::ServerState;
use crate::policy_store::PolicyStoreExt;

/// Separate immutable resource grant from the mutable action target digest.
/// This is native transport authorization, not the controller's response key.
pub(super) fn resource_digest(resource: &ProviderDetachResourceV1) -> Result<String, Status> {
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
    projection(
        "openshell.provider-detach.resource/v1",
        &Resource {
            authority: &resource.authority,
            workspace: &resource.workspace,
            sandbox: &resource.sandbox,
            sandbox_id: &resource.sandbox_id,
            execution_id: &resource.execution_id,
            provider: &resource.provider,
            provider_id: &resource.provider_id,
        },
    )
}

#[derive(Serialize)]
struct CanonicalTarget<'a> {
    authority: &'a str,
    workspace: &'a str,
    sandbox: &'a str,
    sandbox_id: &'a str,
    execution_id: &'a str,
    sandbox_resource_version: String,
    provider: &'a str,
    provider_id: &'a str,
    provider_resource_version: String,
    attachment_epoch: &'a str,
    configuration_fingerprint: &'a str,
    configuration_instance: &'a str,
    config_revision: String,
    provider_env_revision: String,
    native_policy_hash: &'a str,
    native_policy_version: u32,
}

fn canonical_target(target: &ProviderDetachTargetV1) -> CanonicalTarget<'_> {
    CanonicalTarget {
        authority: &target.authority,
        workspace: &target.workspace,
        sandbox: &target.sandbox,
        sandbox_id: &target.sandbox_id,
        execution_id: &target.execution_id,
        sandbox_resource_version: target.sandbox_resource_version.to_string(),
        provider: &target.provider,
        provider_id: &target.provider_id,
        provider_resource_version: target.provider_resource_version.to_string(),
        attachment_epoch: &target.attachment_epoch,
        configuration_fingerprint: &target.configuration_fingerprint,
        configuration_instance: &target.configuration_instance,
        config_revision: target.config_revision.to_string(),
        provider_env_revision: target.provider_env_revision.to_string(),
        native_policy_hash: &target.native_policy_hash,
        native_policy_version: target.native_policy_version,
    }
}

/// Matches the controller-owned v1 domain/ordered JSON, including uint64 strings
/// and encoding/json HTML/U+2028/U+2029 escaping. Never route through f64.
pub fn target_digest(target: &ProviderDetachTargetV1) -> Result<String, Status> {
    #[derive(Serialize)]
    struct Projection<T> {
        schema_version: u32,
        target: T,
    }
    projection(
        "openshield.provider-detach.target/v1",
        &Projection {
            schema_version: 1,
            target: canonical_target(target),
        },
    )
}

/// Reconstruct the exact Controller-owned v1 intent preimage. This validates
/// metadata binding, not `OpenShield` rule-policy authority or execution grants.
pub fn original_intent_digest(intent: &ProviderDetachOriginalIntentV1) -> Result<String, Status> {
    #[derive(Serialize)]
    struct Source<'a> {
        #[serde(rename = "gatewayID")]
        gateway_id: &'a str,
        workspace: &'a str,
        sandbox: &'a str,
        #[serde(rename = "sandboxID")]
        sandbox_id: &'a str,
        #[serde(rename = "executionID")]
        execution_id: &'a str,
        #[serde(rename = "runtimeHandle", skip_serializing_if = "str::is_empty")]
        runtime_handle: &'a str,
    }
    #[derive(Serialize)]
    struct Detach<'a> {
        schema_version: u32,
        profile_id: &'a str,
        violation_sha256: &'a str,
        target: CanonicalTarget<'a>,
        target_sha256: &'a str,
    }
    #[derive(Serialize)]
    struct Intent<'a> {
        schema_version: u32,
        target: Source<'a>,
        event_id: &'a str,
        policy_revision: &'a str,
        policy_hash: &'a str,
        rule_id: &'a str,
        detach: Detach<'a>,
    }
    let source = intent
        .target
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("original source absent"))?;
    let detach = intent
        .detach
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("original detach absent"))?;
    let target = detach
        .target
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("original target absent"))?;
    projection(
        "openshield.provider-detach.intent/v1",
        &Intent {
            schema_version: intent.schema_version,
            target: Source {
                gateway_id: &source.gateway_id,
                workspace: &source.workspace,
                sandbox: &source.sandbox,
                sandbox_id: &source.sandbox_id,
                execution_id: &source.execution_id,
                runtime_handle: &source.runtime_handle,
            },
            event_id: &intent.event_id,
            policy_revision: &intent.policy_revision,
            policy_hash: &intent.policy_hash,
            rule_id: &intent.rule_id,
            detach: Detach {
                schema_version: detach.schema_version,
                profile_id: &detach.profile_id,
                violation_sha256: &detach.violation_sha256,
                target: canonical_target(target),
                target_sha256: &detach.target_sha256,
            },
        },
    )
}

fn sha256_value(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn action_id_for_digest(digest: &str) -> Result<String, Status> {
    if !sha256_value(digest) {
        return Err(Status::invalid_argument("invalid intent digest"));
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[i * 2..i * 2 + 2], 16)
            .map_err(|_| Status::invalid_argument("invalid intent digest"))?;
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(uuid::Uuid::from_bytes(bytes).to_string())
}

/// Check the complete closed original intent and redundant request identities.
/// Gateway alias and native authority are intentionally never equated.
pub fn validate_original_action(action: &ProviderDetachActionV1) -> Result<(), Status> {
    let invalid = || Status::invalid_argument("provider original intent mismatch");
    let intent = action.original_intent.as_ref().ok_or_else(invalid)?;
    let source = intent.target.as_ref().ok_or_else(invalid)?;
    let detach = intent.detach.as_ref().ok_or_else(invalid)?;
    let target = action.target.as_ref().ok_or_else(invalid)?;
    let token = |v: &str| {
        !v.is_empty()
            && v.len() <= 253
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
    };
    let bounded = |v: &str| !v.is_empty() && v.len() <= 253;
    if action.schema_version != 1
        || intent.schema_version != 1
        || detach.schema_version != 1
        || !bounded(&source.gateway_id)
        || !source.runtime_handle.is_empty()
        || !bounded(&intent.event_id)
        || !bounded(&intent.policy_revision)
        || !bounded(&intent.rule_id)
        || !sha256_value(&intent.policy_hash)
        || !sha256_value(&detach.violation_sha256)
        || !token(&detach.profile_id)
        || [
            &target.authority,
            &target.workspace,
            &target.sandbox,
            &target.sandbox_id,
            &target.provider,
            &target.provider_id,
            &target.attachment_epoch,
            &target.configuration_instance,
        ]
        .iter()
        .any(|v| !token(v))
        || target
            .execution_id
            .strip_prefix("exec-v1:")
            .is_none_or(|v| !sha256_value(v))
        || target.sandbox_resource_version == 0
        || target.provider_resource_version == 0
        || target.config_revision == 0
        || target.provider_env_revision == 0
        || target.native_policy_version == 0
        || !sha256_value(&target.native_policy_hash)
        || target.configuration_fingerprint.is_empty()
        || target.configuration_fingerprint.len() > 1024
        || source.workspace != target.workspace
        || source.sandbox != target.sandbox
        || source.sandbox_id != target.sandbox_id
        || source.execution_id != target.execution_id
        || detach.target.as_ref() != Some(target)
        || detach.profile_id != action.profile_id
        || intent.event_id != action.event_id
        || detach.target_sha256 != action.target_sha256
        || target_digest(target)? != action.target_sha256
        || original_intent_digest(intent)? != action.intent_sha256
        || action_id_for_digest(&action.intent_sha256)? != action.action_id
    {
        return Err(invalid());
    }
    Ok(())
}

fn projection(domain: &str, value: &impl Serialize) -> Result<String, Status> {
    let json = serde_json::to_string(value)
        .map_err(|_| Status::internal("provider projection failed"))?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update(b"\n");
    hash.update(json.as_bytes());
    Ok(format!("{:x}", hash.finalize()))
}

fn resource_for(target: &ProviderDetachTargetV1) -> ProviderDetachResourceV1 {
    ProviderDetachResourceV1 {
        authority: target.authority.clone(),
        workspace: target.workspace.clone(),
        sandbox: target.sandbox.clone(),
        sandbox_id: target.sandbox_id.clone(),
        execution_id: target.execution_id.clone(),
        provider: target.provider.clone(),
        provider_id: target.provider_id.clone(),
    }
}

async fn authorize<T: Sync>(
    state: &Arc<ServerState>,
    request: &Request<T>,
    resource: &ProviderDetachResourceV1,
    workspace: Option<&openshell_core::proto::datamodel::v1::WorkspaceSelector>,
    write: bool,
) -> Result<(), Status> {
    use crate::auth::{
        identity::IdentityProvider,
        principal::Principal,
        workspace_authz::{MinWorkspaceRole, authorize_workspace, selected_workspace_name},
    };
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
            .is_none_or(|v| !sha256_value(v))
    {
        return Err(Status::invalid_argument("provider detach resource invalid"));
    }
    let principal = super::extract_principal(request)?;
    let Principal::User(user) = &principal else {
        return Err(Status::permission_denied(
            "provider detach user grant required",
        ));
    };
    let enabled = state
        .config
        .oidc
        .as_ref()
        .is_some_and(|c| !c.scopes_claim.is_empty());
    if user.identity.provider != IdentityProvider::Oidc || resource.authority != state.config.name {
        return Err(Status::permission_denied(
            "provider detach authority unavailable",
        ));
    }
    crate::auth::authz::check_provider_detach_grant(
        &user.identity,
        enabled,
        write,
        &resource_digest(resource)?,
    )?;
    if selected_workspace_name(workspace)? != resource.workspace {
        return Err(Status::invalid_argument(
            "provider detach workspace mismatch",
        ));
    }
    authorize_workspace(
        state.store.as_ref(),
        &state.admin_role,
        &principal,
        &resource.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    super::workspace::resolve_workspace(state.store.as_ref(), &resource.workspace)
        .await?
        .ensure_active()?;
    if !state.store.is_single_replica() {
        return Err(Status::unimplemented(
            "provider detach persistence backend unsupported",
        ));
    }
    Ok(())
}

fn configuration_fingerprint(
    config: &openshell_core::proto::GetSandboxConfigResponse,
) -> Result<String, Status> {
    #[derive(Serialize)]
    struct SnapshotProjection<'a> {
        config_revision: String,
        provider_env_revision: String,
        policy_hash: &'a str,
        policy_version: u32,
        attachment_epoch: &'a str,
        configuration_instance: &'a str,
    }
    projection(
        "openshell.provider-detach.configuration/v1",
        &SnapshotProjection {
            config_revision: config.config_revision.to_string(),
            provider_env_revision: config.provider_env_revision.to_string(),
            policy_hash: &config.policy_hash,
            policy_version: config.version,
            attachment_epoch: &config.provider_attachment_epoch,
            configuration_instance: &config.configuration_instance_id,
        },
    )
}

async fn current_snapshot(
    state: &Arc<ServerState>,
    resource: &ProviderDetachResourceV1,
) -> Result<(openshell_core::proto::Sandbox, ProviderDetachTargetV1), Status> {
    use openshell_core::{GetResourceVersion, ObjectId, ObjectName, ObjectWorkspace};
    if state
        .provider_profile_sources
        .source_ids()
        .iter()
        .any(|id| *id != "user")
    {
        return Err(Status::unimplemented(
            "provider detach catalog source unsupported",
        ));
    }
    let sandbox = state
        .store
        .get_message::<openshell_core::proto::Sandbox>(&resource.sandbox_id)
        .await
        .map_err(|_| Status::internal("provider detach snapshot unavailable"))?
        .ok_or_else(|| Status::not_found("provider detach sandbox absent"))?;
    if sandbox.object_name() != resource.sandbox
        || sandbox.object_workspace() != resource.workspace
        || sandbox.phase() != openshell_core::proto::SandboxPhase::Ready as i32
        || crate::auth::sandbox_session::sandbox_execution_id(&sandbox)? != resource.execution_id
        || !sandbox.spec.as_ref().is_some_and(|spec| {
            spec.providers
                .iter()
                .filter(|p| *p == &resource.provider)
                .count()
                == 1
        })
    {
        return Err(Status::failed_precondition(
            "provider detach resource changed",
        ));
    }
    // The legacy loader can backfill absent history. This read-only surface must
    // refuse that case rather than mutate it as an incidental Resolve operation.
    if state
        .store
        .get_latest_policy(sandbox.object_id())
        .await
        .map_err(|_| Status::internal("provider detach policy unavailable"))?
        .is_none()
    {
        return Err(Status::failed_precondition(
            "provider detach policy history required",
        ));
    }
    let provider = state
        .store
        .get_by_name("provider", &resource.workspace, &resource.provider)
        .await
        .map_err(|_| Status::internal("provider detach provider unavailable"))?
        .ok_or_else(|| Status::not_found("provider detach provider absent"))?;
    if provider.id != resource.provider_id {
        return Err(Status::failed_precondition(
            "provider detach provider changed",
        ));
    }
    let config = super::policy::load_sandbox_config(state, &sandbox).await?;
    if !config.configuration_admitted
        || config.configuration_instance_id.is_empty()
        || config.version == 0
        || !sha256_value(&config.policy_hash)
        || config.config_revision == 0
        || config.provider_env_revision == 0
        || config.provider_attachment_epoch.is_empty()
    {
        return Err(Status::failed_precondition(
            "provider detach effective configuration unavailable",
        ));
    }
    let target = ProviderDetachTargetV1 {
        authority: state.config.name.clone(),
        workspace: resource.workspace.clone(),
        sandbox: resource.sandbox.clone(),
        sandbox_id: resource.sandbox_id.clone(),
        execution_id: resource.execution_id.clone(),
        sandbox_resource_version: sandbox.get_resource_version(),
        provider: resource.provider.clone(),
        provider_id: provider.id,
        provider_resource_version: provider.resource_version,
        attachment_epoch: config.provider_attachment_epoch.clone(),
        configuration_fingerprint: configuration_fingerprint(&config)?,
        configuration_instance: config.configuration_instance_id,
        config_revision: config.config_revision,
        provider_env_revision: config.provider_env_revision,
        native_policy_hash: config.policy_hash,
        native_policy_version: config.version,
    };
    Ok((sandbox, target))
}

pub(super) async fn conditional_detach(
    state: &Arc<ServerState>,
    request: Request<ConditionalDetachSandboxProviderRequest>,
) -> Result<Response<ConditionalDetachSandboxProviderResponse>, Status> {
    use openshell_core::proto::ProviderDetachReceiptV1;
    let action = request
        .get_ref()
        .action
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("provider detach action required"))?;
    validate_original_action(action)?;
    let target = action
        .target
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("provider detach target required"))?;
    let resource = resource_for(target);
    authorize(
        state,
        &request,
        &resource,
        request.get_ref().workspace_scope.as_ref(),
        true,
    )
    .await?;
    let storage_error = |_| Status::internal("provider detach original outcome unavailable");
    if let Some(outcome) = state
        .store
        .recover_provider_detach(action)
        .await
        .map_err(storage_error)?
    {
        return Ok(Response::new(ConditionalDetachSandboxProviderResponse {
            outcome: Some(outcome),
        }));
    }
    let (_lifecycle, _sync) = state
        .compute
        .sandbox_create_guards(&target.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("provider detach lifecycle ownership unavailable"))?;
    if let Some(outcome) = state
        .store
        .recover_provider_detach(action)
        .await
        .map_err(storage_error)?
    {
        return Ok(Response::new(ConditionalDetachSandboxProviderResponse {
            outcome: Some(outcome),
        }));
    }
    let fence = state
        .store
        .provider_detach_fence()
        .await
        .map_err(|_| Status::unavailable("provider detach configuration fence unavailable"))?;
    let snapshot = current_snapshot(state, &resource).await;
    let (mut sandbox, actual) = match snapshot {
        Ok(v) => v,
        Err(e)
            if matches!(
                e.code(),
                tonic::Code::NotFound | tonic::Code::FailedPrecondition
            ) =>
        {
            let outcome = state
                .store
                .reject_provider_detach(action)
                .await
                .map_err(storage_error)?;
            return Ok(Response::new(ConditionalDetachSandboxProviderResponse {
                outcome: Some(outcome),
            }));
        }
        Err(e) => return Err(e),
    };
    if actual != *target {
        let outcome = state
            .store
            .reject_provider_detach(action)
            .await
            .map_err(storage_error)?;
        return Ok(Response::new(ConditionalDetachSandboxProviderResponse {
            outcome: Some(outcome),
        }));
    }
    let epoch = uuid::Uuid::new_v4().to_string();
    let spec = sandbox
        .spec
        .as_mut()
        .ok_or_else(|| Status::failed_precondition("provider detach spec absent"))?;
    spec.providers.retain(|p| p != &target.provider);
    spec.provider_attachment_epoch.clone_from(&epoch);
    let providers = spec.providers.clone();
    super::policy::validate_candidate_provider_attachments(
        state,
        &target.workspace,
        &sandbox,
        &providers,
    )
    .await?;
    let after = super::policy::load_sandbox_config(state, &sandbox).await?;
    let current_fence = state
        .store
        .provider_detach_fence()
        .await
        .map_err(|_| Status::unavailable("provider detach configuration fence unavailable"))?;
    if current_fence != fence
        || !after.configuration_admitted
        || after.configuration_instance_id.is_empty()
        || after.version == 0
        || !sha256_value(&after.policy_hash)
        || after.config_revision == 0
        || after.provider_env_revision == 0
    {
        let outcome = state
            .store
            .reject_provider_detach(action)
            .await
            .map_err(storage_error)?;
        return Ok(Response::new(ConditionalDetachSandboxProviderResponse {
            outcome: Some(outcome),
        }));
    }
    let receipt = ProviderDetachReceiptV1 {
        action_id: action.action_id.clone(),
        intent_sha256: action.intent_sha256.clone(),
        target_sha256: action.target_sha256.clone(),
        target: Some(target.clone()),
        before_attachment_epoch: target.attachment_epoch.clone(),
        after_attachment_epoch: epoch,
        native_receipt_id: uuid::Uuid::new_v4().to_string(),
        hold_id: uuid::Uuid::new_v4().to_string(),
        config_revision: after.config_revision,
        provider_env_revision: after.provider_env_revision,
        configuration_instance: after.configuration_instance_id,
        native_policy_hash: after.policy_hash,
        native_policy_version: after.version,
        recorded_time: Some(
            openshell_core::time::timestamp_from_millis(crate::persistence::current_time_ms())
                .map_err(|_| Status::internal("provider detach clock unavailable"))?,
        ),
    };
    let outcome = state
        .store
        .commit_provider_detach(&crate::persistence::ProviderDetachCommit {
            action: action.clone(),
            fence,
            receipt,
        })
        .await
        .map_err(storage_error)?;
    if outcome.state == "applied" {
        state.sandbox_watch_bus.notify(&target.sandbox_id);
        if let Ok(Some(current)) = state
            .store
            .get_message::<openshell_core::proto::Sandbox>(&target.sandbox_id)
            .await
        {
            state.sandbox_index.update_from_sandbox(&current);
        }
    }
    Ok(Response::new(ConditionalDetachSandboxProviderResponse {
        outcome: Some(outcome),
    }))
}

pub(super) async fn read_state(
    state: &Arc<ServerState>,
    request: Request<GetConditionalProviderDetachStateRequest>,
) -> Result<Response<GetConditionalProviderDetachStateResponse>, Status> {
    use openshell_core::proto::{
        ProviderDetachOutcomeV1, get_conditional_provider_detach_state_request::Query,
        get_conditional_provider_detach_state_response::Result as QueryResult,
    };
    let query = request
        .get_ref()
        .query
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("provider detach query required"))?;
    let resource =
        match query {
            Query::Resolve(q) => q
                .resource
                .clone()
                .ok_or_else(|| Status::invalid_argument("provider detach resource required"))?,
            Query::Recover(q) => {
                let action = q
                    .action
                    .as_ref()
                    .ok_or_else(|| Status::invalid_argument("provider detach action required"))?;
                validate_original_action(action)?;
                resource_for(
                    action.target.as_ref().ok_or_else(|| {
                        Status::invalid_argument("provider detach target required")
                    })?,
                )
            }
            Query::QueryAttempt(q) => {
                let action = q
                    .original_action
                    .as_ref()
                    .ok_or_else(|| Status::invalid_argument("original arm action required"))?;
                validate_original_action(action)?;
                resource_for(
                    action
                        .target
                        .as_ref()
                        .ok_or_else(|| Status::invalid_argument("original arm target required"))?,
                )
            }
            Query::Observe(q) => {
                let action = q
                    .action
                    .as_ref()
                    .ok_or_else(|| Status::invalid_argument("provider detach action required"))?;
                validate_original_action(action)?;
                resource_for(
                    action.target.as_ref().ok_or_else(|| {
                        Status::invalid_argument("provider detach target required")
                    })?,
                )
            }
        };
    authorize(
        state,
        &request,
        &resource,
        request.get_ref().workspace_scope.as_ref(),
        false,
    )
    .await?;
    let result =
        match query {
            Query::Resolve(_) => {
                let (_lifecycle, _sync) = state
                    .compute
                    .sandbox_create_guards(&resource.sandbox_id)
                    .await
                    .map_err(|_| {
                        Status::unavailable("provider detach lifecycle ownership unavailable")
                    })?;
                let fence = state.store.provider_detach_fence().await.map_err(|_| {
                    Status::unavailable("provider detach configuration fence unavailable")
                })?;
                let (_, target) = current_snapshot(state, &resource).await?;
                if state.store.provider_detach_fence().await.map_err(|_| {
                    Status::unavailable("provider detach configuration fence unavailable")
                })? != fence
                {
                    return Err(Status::aborted("provider detach snapshot changed"));
                }
                QueryResult::Target(target)
            }
            Query::Recover(q) => QueryResult::Outcome(
                state
                    .store
                    .recover_provider_detach(q.action.as_ref().ok_or_else(|| {
                        Status::invalid_argument("provider detach action required")
                    })?)
                    .await
                    .map_err(|_| Status::internal("provider detach original outcome unavailable"))?
                    .unwrap_or_else(|| ProviderDetachOutcomeV1 {
                        state: "unknown".into(),
                        receipt: None,
                    }),
            ),
            Query::QueryAttempt(q) => QueryResult::Attempt(read_attempt(state, q, false).await?),
            Query::Observe(_) => {
                return Err(Status::unimplemented(
                    "provider detach fresh observation transport unsupported",
                ));
            }
        };
    Ok(Response::new(GetConditionalProviderDetachStateResponse {
        result: Some(result),
    }))
}

#[cfg(test)]
#[path = "provider_detach_tests.rs"]
mod tests;

pub(super) async fn arm_attempt(
    state: &Arc<ServerState>,
    request: Request<openshell_core::proto::ArmProviderDetachAttemptRequest>,
) -> Result<Response<openshell_core::proto::ArmProviderDetachAttemptResponse>, Status> {
    let q = request
        .get_ref()
        .request
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("arm request absent"))?;
    validate_arm_metadata(q)?;
    let action = q
        .original_action
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("original action absent"))?;
    let target = action
        .target
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("original target absent"))?;
    authorize(
        state,
        &request,
        &resource_for(target),
        request.get_ref().workspace_scope.as_ref(),
        true,
    )
    .await?;
    let readback = read_attempt(state, q, true).await?;
    Ok(Response::new(
        openshell_core::proto::ArmProviderDetachAttemptResponse {
            readback: Some(readback),
        },
    ))
}

#[derive(Serialize)]
struct CanonicalAttemptTime {
    seconds: String,
    nanos: i32,
}
fn timestamp_ns(value: &prost_types::Timestamp) -> Result<i128, Status> {
    if !(-62_135_596_800..=253_402_300_799).contains(&value.seconds)
        || !(0..1_000_000_000).contains(&value.nanos)
    {
        return Err(Status::invalid_argument("invalid attempt timestamp"));
    }
    Ok(i128::from(value.seconds) * 1_000_000_000 + i128::from(value.nanos))
}
fn canonical_attempt_time(
    value: Option<&prost_types::Timestamp>,
) -> Result<CanonicalAttemptTime, Status> {
    let v = value.ok_or_else(|| Status::invalid_argument("attempt time absent"))?;
    timestamp_ns(v)?;
    Ok(CanonicalAttemptTime {
        seconds: v.seconds.to_string(),
        nanos: v.nanos,
    })
}
pub fn attempt_digest(
    a: &openshell_core::proto::ProviderDetachAttemptV1,
) -> Result<String, Status> {
    #[derive(Serialize)]
    struct Attempt<'a> {
        schema_version: u32,
        dispatcher_decision_id: &'a str,
        action_id: &'a str,
        intent_sha256: &'a str,
        target_sha256: &'a str,
        native_receipt_id: &'a str,
        hold_id: &'a str,
        authority: &'a str,
        gateway_boot_id: &'a str,
        workspace: &'a str,
        sandbox_id: &'a str,
        execution_id: &'a str,
        provider_id: &'a str,
        attachment_epoch: &'a str,
        configuration_instance: &'a str,
        config_revision: String,
        provider_env_revision: String,
        native_policy_hash: &'a str,
        native_policy_version: u32,
        supervisor_instance: &'a str,
        supervisor_session: &'a str,
        arm_capture_sequence: String,
        challenge: &'a str,
        not_before: CanonicalAttemptTime,
        deadline: CanonicalAttemptTime,
    }
    projection(
        "openshell.provider-detach.attempt/v1",
        &Attempt {
            schema_version: a.schema_version,
            dispatcher_decision_id: &a.dispatcher_decision_id,
            action_id: &a.action_id,
            intent_sha256: &a.intent_sha256,
            target_sha256: &a.target_sha256,
            native_receipt_id: &a.native_receipt_id,
            hold_id: &a.hold_id,
            authority: &a.authority,
            gateway_boot_id: &a.gateway_boot_id,
            workspace: &a.workspace,
            sandbox_id: &a.sandbox_id,
            execution_id: &a.execution_id,
            provider_id: &a.provider_id,
            attachment_epoch: &a.attachment_epoch,
            configuration_instance: &a.configuration_instance,
            config_revision: a.config_revision.to_string(),
            provider_env_revision: a.provider_env_revision.to_string(),
            native_policy_hash: &a.native_policy_hash,
            native_policy_version: a.native_policy_version,
            supervisor_instance: &a.supervisor_instance,
            supervisor_session: &a.supervisor_session,
            arm_capture_sequence: a.arm_capture_sequence.to_string(),
            challenge: &a.challenge,
            not_before: canonical_attempt_time(a.not_before.as_ref())?,
            deadline: canonical_attempt_time(a.deadline.as_ref())?,
        },
    )
}
fn validate_arm_metadata(
    q: &openshell_core::proto::ProviderDetachArmRequestV1,
) -> Result<(), Status> {
    use prost::Message;
    let invalid = || Status::invalid_argument("provider detach arm binding invalid");
    let original = q.original_action.as_ref().ok_or_else(invalid)?;
    validate_original_action(original)?;
    let r = q.original_receipt.as_ref().ok_or_else(invalid)?;
    let t = original.target.as_ref().ok_or_else(invalid)?;
    let a = q.attempt.as_ref().ok_or_else(invalid)?;
    let before = timestamp_ns(a.not_before.as_ref().ok_or_else(invalid)?)?;
    let deadline = timestamp_ns(a.deadline.as_ref().ok_or_else(invalid)?)?;
    let recorded = timestamp_ns(r.recorded_time.as_ref().ok_or_else(invalid)?)?;
    let receipt_after_epoch = r.after_attachment_epoch.as_str();
    if q.encoded_len() > 8192
        || a.schema_version != 1
        || before >= deadline
        || deadline - before > 30_000_000_000
        || recorded > before
        || q.request_sha256 != attempt_digest(a)?
        || q.attempt_id != action_id_for_digest(&q.request_sha256)?
        || a.action_id != original.action_id
        || a.intent_sha256 != original.intent_sha256
        || a.target_sha256 != original.target_sha256
        || r.action_id != a.action_id
        || r.intent_sha256 != a.intent_sha256
        || r.target_sha256 != a.target_sha256
        || r.target.as_ref() != Some(t)
        || r.before_attachment_epoch != t.attachment_epoch
        || r.after_attachment_epoch.is_empty()
        || r.after_attachment_epoch == r.before_attachment_epoch
        || a.native_receipt_id != r.native_receipt_id
        || a.hold_id != r.hold_id
        || a.authority != t.authority
        || a.workspace != t.workspace
        || a.sandbox_id != t.sandbox_id
        || a.execution_id != t.execution_id
        || a.provider_id != t.provider_id
        || a.attachment_epoch != receipt_after_epoch
        || a.configuration_instance != r.configuration_instance
        || a.configuration_instance.is_empty()
        || a.configuration_instance.len() > 253
        || a.config_revision != r.config_revision
        || a.config_revision == 0
        || a.provider_env_revision != r.provider_env_revision
        || a.provider_env_revision == 0
        || a.native_policy_hash != r.native_policy_hash
        || !sha256_value(&a.native_policy_hash)
        || a.native_policy_version != r.native_policy_version
        || a.native_policy_version == 0
        || a.arm_capture_sequence == 0
        || !sha256_value(&a.challenge)
    {
        return Err(invalid());
    }
    for id in [
        &a.dispatcher_decision_id,
        &a.gateway_boot_id,
        &a.supervisor_instance,
        &a.supervisor_session,
        &a.native_receipt_id,
        &a.hold_id,
    ] {
        let parsed = uuid::Uuid::parse_str(id).map_err(|_| invalid())?;
        if parsed.is_nil() || parsed.to_string() != *id {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Ephemeral registry-owned metadata, never an execution or observation journal.
/// Callers serialize this object under the authenticated session registry lock.
pub struct ProviderDetachAttempts {
    pub boot_id: String,
    entries: std::collections::HashMap<String, DetachAttemptEntry>,
}
#[derive(Clone)]
struct DetachAttemptEntry {
    readback: openshell_core::proto::ProviderDetachAttemptReadbackV1,
    delivered_sequence: Option<u64>,
    delivered_time: Option<prost_types::Timestamp>,
    reported_install_time: Option<prost_types::Timestamp>,
    reserved_bytes: usize,
}
impl Default for ProviderDetachAttempts {
    fn default() -> Self {
        Self {
            boot_id: uuid::Uuid::new_v4().to_string(),
            entries: std::collections::HashMap::new(),
        }
    }
}
impl ProviderDetachAttempts {
    pub fn admit(
        &mut self,
        request: &openshell_core::proto::ProviderDetachArmRequestV1,
        generation: u64,
        row_version: u64,
        now: &prost_types::Timestamp,
    ) -> Result<openshell_core::proto::ProviderDetachAttemptReadbackV1, Status> {
        use prost::Message;
        validate_arm_metadata(request)?;
        let a = request
            .attempt
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("attempt absent"))?;
        let time = timestamp_ns(now)?;
        if a.gateway_boot_id != self.boot_id
            || generation == 0
            || row_version == 0
            || time < timestamp_ns(a.not_before.as_ref().unwrap())?
            || time >= timestamp_ns(a.deadline.as_ref().unwrap())?
        {
            return Err(Status::failed_precondition(
                "attempt boot, hold or time changed",
            ));
        }
        if let Some(old) = self.entries.get(&request.attempt_id) {
            if old.readback.seal.as_ref().and_then(|s| s.request.as_ref()) != Some(request) {
                return Err(Status::already_exists("attempt request conflict"));
            }
            return Ok(old.readback.clone());
        }
        if self.entries.values().any(|entry| {
            entry
                .readback
                .seal
                .as_ref()
                .and_then(|s| s.request.as_ref())
                .and_then(|q| q.attempt.as_ref())
                .is_some_and(|old| {
                    old.dispatcher_decision_id == a.dispatcher_decision_id
                        && old
                            .deadline
                            .as_ref()
                            .and_then(|t| timestamp_ns(t).ok())
                            .is_some_and(|end| time < end)
                })
        }) {
            return Err(Status::already_exists(
                "original dispatcher decision already bound",
            ));
        }
        self.entries.retain(|_, entry| {
            entry
                .readback
                .seal
                .as_ref()
                .and_then(|s| s.request.as_ref())
                .and_then(|q| q.attempt.as_ref())
                .and_then(|a| a.deadline.as_ref())
                .and_then(|t| timestamp_ns(t).ok())
                .is_some_and(|expiry| time < expiry)
        });
        if self.entries.values().any(|entry| {
            let Some(old) = entry
                .readback
                .seal
                .as_ref()
                .and_then(|s| s.request.as_ref())
                .and_then(|q| q.attempt.as_ref())
            else {
                return true;
            };
            entry.readback.state <= 3
                && old.hold_id == a.hold_id
                && old.supervisor_session == a.supervisor_session
        }) {
            return Err(Status::resource_exhausted(
                "original hold already has an unresolved attempt",
            ));
        }
        let seal = openshell_core::proto::ProviderDetachArmSealV1 {
            request: Some(request.clone()),
            hold_generation: generation,
            row_resource_version: row_version,
            install_sequence: 0,
            installed_time: None,
        };
        // Reserve space for the immutable future installation sequence/time.
        if seal.encoded_len().saturating_add(64) > 8192 {
            return Err(Status::resource_exhausted(
                "attempt seal exceeds closed bounds",
            ));
        }
        let reserved = seal
            .encoded_len()
            .checked_add(64 + 4096)
            .ok_or_else(|| Status::resource_exhausted("attempt size unavailable"))?;
        if self.entries.len() >= 16
            || self
                .entries
                .values()
                .map(|e| e.reserved_bytes)
                .sum::<usize>()
                .saturating_add(reserved)
                > 128 * 1024
        {
            return Err(Status::resource_exhausted("attempt capacity exhausted"));
        }
        let readback = openshell_core::proto::ProviderDetachAttemptReadbackV1 {
            state: 1,
            seal: Some(seal),
            result: 0,
            proof: None,
            current: None,
        };
        self.entries.insert(
            request.attempt_id.clone(),
            DetachAttemptEntry {
                readback: readback.clone(),
                delivered_sequence: None,
                delivered_time: None,
                reported_install_time: None,
                reserved_bytes: reserved,
            },
        );
        Ok(readback)
    }
    pub fn query(
        &self,
        request: &openshell_core::proto::ProviderDetachArmRequestV1,
        now: &prost_types::Timestamp,
    ) -> Result<openshell_core::proto::ProviderDetachAttemptReadbackV1, Status> {
        validate_arm_metadata(request)?;
        let a = request.attempt.as_ref().unwrap();
        let empty = |state| openshell_core::proto::ProviderDetachAttemptReadbackV1 {
            state,
            seal: None,
            result: 0,
            proof: None,
            current: None,
        };
        if timestamp_ns(now)? >= timestamp_ns(a.deadline.as_ref().unwrap())? {
            return Ok(empty(5));
        }
        if a.gateway_boot_id != self.boot_id
            || timestamp_ns(now)? < timestamp_ns(a.not_before.as_ref().unwrap())?
        {
            return Ok(empty(6));
        }
        let Some(entry) = self.entries.get(&request.attempt_id) else {
            return Ok(empty(6));
        };
        if entry
            .readback
            .seal
            .as_ref()
            .and_then(|s| s.request.as_ref())
            != Some(request)
        {
            return Err(Status::already_exists("attempt request conflict"));
        }
        Ok(entry.readback.clone())
    }
}

fn unknown_attempt() -> openshell_core::proto::ProviderDetachAttemptReadbackV1 {
    openshell_core::proto::ProviderDetachAttemptReadbackV1 {
        state: 6,
        seal: None,
        result: 0,
        proof: None,
        current: None,
    }
}
fn ack_for_original(
    q: &openshell_core::proto::ProviderDetachArmRequestV1,
    evidence: &super::provider_readiness::ProviderReadinessEvidence,
    boot: &str,
    now: &prost_types::Timestamp,
) -> Result<openshell_core::proto::ProviderDetachAckv1, Status> {
    let invalid = || Status::failed_precondition("attempt current installed state unavailable");
    let action = q.original_action.as_ref().ok_or_else(invalid)?;
    let target = action.target.as_ref().ok_or_else(invalid)?;
    let receipt = q.original_receipt.as_ref().ok_or_else(invalid)?;
    let (instance, obs, observed) = evidence.provider_detach_snapshot().ok_or_else(invalid)?;
    let meta = obs
        .provider_detach
        .as_ref()
        .filter(|m| m.supported)
        .ok_or_else(invalid)?;
    let receipt_after_epoch = receipt.after_attachment_epoch.as_str();
    if (!meta.gateway_boot_id.is_empty() && meta.gateway_boot_id != boot)
        || !obs.credentials_installed
        || !obs.policy_active
        || !obs.launch_environment_installed
        || obs.process_instance_id.is_empty()
        || obs.attachment_epoch != receipt_after_epoch
        || obs.config_revision != receipt.config_revision
        || obs.provider_env_revision != receipt.provider_env_revision
        || obs.policy_hash != receipt.native_policy_hash
        || obs.sequence == 0
        || timestamp_ns(&observed)? > timestamp_ns(now)?
        || timestamp_ns(now)? - timestamp_ns(&observed)? >= 30_000_000_000
        || timestamp_ns(&observed)?
            < timestamp_ns(receipt.recorded_time.as_ref().ok_or_else(invalid)?)?
    {
        return Err(invalid());
    }
    if let Some(a) = q.attempt.as_ref()
        && *a != openshell_core::proto::ProviderDetachAttemptV1::default()
        && (a.supervisor_instance != instance
            || a.supervisor_session != obs.session_id
            || obs.sequence < a.arm_capture_sequence)
    {
        return Err(invalid());
    }
    Ok(openshell_core::proto::ProviderDetachAckv1 {
        action_id: action.action_id.clone(),
        target_sha256: action.target_sha256.clone(),
        native_receipt_id: receipt.native_receipt_id.clone(),
        hold_id: receipt.hold_id.clone(),
        sandbox_id: target.sandbox_id.clone(),
        execution_id: target.execution_id.clone(),
        provider_id: target.provider_id.clone(),
        attachment_epoch: obs.attachment_epoch,
        configuration_instance: receipt.configuration_instance.clone(),
        config_revision: obs.config_revision,
        provider_env_revision: obs.provider_env_revision,
        native_policy_hash: obs.policy_hash,
        native_policy_version: receipt.native_policy_version,
        supervisor_instance: instance,
        supervisor_session: obs.session_id,
        sequence: obs.sequence,
        state: "REVOKED".into(),
        credentials_installed: true,
        policy_active: true,
        launch_environment_acknowledged: true,
        evaluated_time: Some(*now),
        observed_time: Some(observed),
    })
}
impl ProviderDetachAttempts {
    fn current_binding_matches(
        &self,
        q: &openshell_core::proto::ProviderDetachArmRequestV1,
        evidence: &super::provider_readiness::ProviderReadinessEvidence,
    ) -> bool {
        let Some(entry) = self.entries.get(&q.attempt_id) else {
            return false;
        };
        let Some(seal) = entry.readback.seal.as_ref() else {
            return false;
        };
        let Some((_, obs, _)) = evidence.provider_detach_snapshot() else {
            return false;
        };
        let Some(meta) = obs.provider_detach.as_ref() else {
            return false;
        };
        // Core reports an original binding only while retained installation,
        // subject and policy provenance still match its actual current state.
        let original_install_time = entry.reported_install_time.as_ref();
        meta.supported
            && meta.gateway_boot_id == self.boot_id
            && meta.attempt_id == q.attempt_id
            && meta.request_sha256 == q.request_sha256
            && meta.install_sequence == seal.install_sequence
            && meta.installed_time.as_ref() == original_install_time
    }

    pub fn installed_for(
        &self,
        sandbox_id: &str,
        session_id: &str,
        attempt_id: &str,
        now: &prost_types::Timestamp,
    ) -> Option<openshell_core::proto::ProviderDetachArmSealV1> {
        let e = self.entries.get(attempt_id)?;
        if e.readback.state < 2 {
            return None;
        }
        let seal = e.readback.seal.as_ref()?;
        let a = seal.request.as_ref()?.attempt.as_ref()?;
        if a.sandbox_id != sandbox_id
            || a.supervisor_session != session_id
            || a.gateway_boot_id != self.boot_id
            || timestamp_ns(now).ok()? >= timestamp_ns(a.deadline.as_ref()?).ok()?
        {
            return None;
        }
        Some(seal.clone())
    }

    /// Called only after authenticated ordered report validation, under both
    /// registry locks. Build a candidate and commit it once validation succeeds.
    pub fn accept_report(
        &mut self,
        sandbox_id: &str,
        evidence: &super::provider_readiness::ProviderReadinessEvidence,
        now: &prost_types::Timestamp,
    ) -> Result<Option<openshell_core::proto::ProviderDetachArmSealV1>, Status> {
        use openshell_core::proto::{ProviderDetachObservationV1, ProviderDetachRefusalV1};
        let Some((_, obs, _)) = evidence.provider_detach_snapshot() else {
            return Ok(None);
        };
        let Some(meta) = obs.provider_detach.as_ref().filter(|m| m.supported) else {
            return Ok(None);
        };
        if !meta.attempt_id.is_empty() {
            let mut entry = self
                .entries
                .get(&meta.attempt_id)
                .cloned()
                .ok_or_else(|| Status::failed_precondition("original attempt absent"))?;
            let seal = entry
                .readback
                .seal
                .as_mut()
                .ok_or_else(|| Status::failed_precondition("attempt seal absent"))?;
            let request = seal
                .request
                .as_ref()
                .ok_or_else(|| Status::failed_precondition("attempt request absent"))?;
            let a = request
                .attempt
                .as_ref()
                .ok_or_else(|| Status::failed_precondition("attempt metadata absent"))?;
            let bad = || Status::failed_precondition("attempt installation/report binding changed");
            if a.sandbox_id != sandbox_id
                || a.supervisor_session != obs.session_id
                || a.gateway_boot_id != self.boot_id
                || meta.gateway_boot_id != self.boot_id
                || meta.request_sha256 != request.request_sha256
                || timestamp_ns(now)? < timestamp_ns(a.not_before.as_ref().ok_or_else(bad)?)?
                || timestamp_ns(now)? >= timestamp_ns(a.deadline.as_ref().ok_or_else(bad)?)?
            {
                return Err(bad());
            }
            let ack = ack_for_original(request, evidence, &self.boot_id, now)?;
            if entry.readback.state == 1 {
                let delivered = entry.delivered_sequence.ok_or_else(bad)?;
                let delivered_time = entry.delivered_time.as_ref().ok_or_else(bad)?;
                let installed = meta.installed_time.as_ref().ok_or_else(bad)?;
                if meta.install_sequence != obs.sequence
                    || meta.install_sequence <= delivered
                    || meta.install_sequence <= a.arm_capture_sequence
                    || timestamp_ns(installed)? < timestamp_ns(delivered_time)?
                    || timestamp_ns(installed)? > timestamp_ns(now)?
                    || meta.result != 0
                    || meta.refusal.is_some()
                {
                    return Err(bad());
                }
                seal.install_sequence = meta.install_sequence;
                entry.reported_install_time = Some(*installed);
                seal.installed_time = Some(*now);
                entry.readback.state = 2;
            } else {
                let sequence_matches = meta.install_sequence == seal.install_sequence;
                let timestamp_matches = meta.installed_time == entry.reported_install_time;
                if !sequence_matches || !timestamp_matches {
                    return Err(bad());
                }
            }
            if meta.result != 0 {
                if !(1..=4).contains(&meta.result) || seal.install_sequence == 0 {
                    return Err(bad());
                }
                if entry.readback.state == 4 {
                    if entry.readback.result != meta.result
                        || entry
                            .readback
                            .proof
                            .as_ref()
                            .and_then(|p| p.refusal.as_ref())
                            != meta.refusal.as_ref()
                    {
                        return Err(bad());
                    }
                } else {
                    if entry.readback.state != 2 || obs.sequence <= seal.install_sequence {
                        return Err(bad());
                    }
                    let proof = if meta.result == 1 {
                        let f: &ProviderDetachRefusalV1 = meta.refusal.as_ref().ok_or_else(bad)?;
                        if !f.unavailable
                            || f.action_id != a.action_id
                            || f.target_sha256 != a.target_sha256
                            || f.attempt_id != request.attempt_id
                            || f.challenge != a.challenge
                            || f.supervisor_instance != a.supervisor_instance
                            || f.supervisor_session != a.supervisor_session
                            || f.sequence != obs.sequence
                            || f.attachment_epoch != a.attachment_epoch
                            || f.configuration_instance != a.configuration_instance
                            || f.config_revision != a.config_revision
                            || f.provider_env_revision != a.provider_env_revision
                        {
                            return Err(bad());
                        }
                        let attempted = timestamp_ns(f.attempted_time.as_ref().ok_or_else(bad)?)?;
                        let observed = timestamp_ns(f.observed_time.as_ref().ok_or_else(bad)?)?;
                        if attempted < timestamp_ns(seal.installed_time.as_ref().ok_or_else(bad)?)?
                            || observed < attempted
                            || observed > timestamp_ns(ack.observed_time.as_ref().ok_or_else(bad)?)?
                        {
                            return Err(bad());
                        }
                        Some(ProviderDetachObservationV1 {
                            ack: Some(ack),
                            refusal: Some(f.clone()),
                        })
                    } else {
                        if meta.refusal.is_some() {
                            return Err(bad());
                        }
                        None
                    };
                    if proof
                        .as_ref()
                        .is_some_and(|p| prost::Message::encoded_len(p) > 4096)
                    {
                        return Err(Status::resource_exhausted(
                            "attempt proof exceeds closed bounds",
                        ));
                    }
                    entry.readback.state = 4;
                    entry.readback.result = meta.result;
                    entry.readback.proof = proof;
                }
            }
            self.entries.insert(meta.attempt_id.clone(), entry);
        } else if !meta.request_sha256.is_empty()
            || meta.install_sequence != 0
            || meta.installed_time.is_some()
            || meta.result != 0
            || meta.refusal.is_some()
        {
            return Err(Status::invalid_argument("partial attempt report"));
        }
        for entry in self.entries.values_mut() {
            if entry.readback.state != 1 {
                continue;
            }
            let Some(seal) = entry.readback.seal.as_ref() else {
                continue;
            };
            let Some(a) = seal.request.as_ref().and_then(|q| q.attempt.as_ref()) else {
                continue;
            };
            if a.sandbox_id == sandbox_id
                && a.supervisor_session == obs.session_id
                && a.gateway_boot_id == self.boot_id
                && timestamp_ns(now)?
                    < timestamp_ns(
                        a.deadline.as_ref().ok_or_else(|| {
                            Status::failed_precondition("attempt deadline absent")
                        })?,
                    )?
            {
                if entry.delivered_sequence.is_none() {
                    entry.delivered_sequence = Some(obs.sequence);
                    entry.delivered_time = Some(*now);
                }
                return Ok(Some(seal.clone()));
            }
        }
        Ok(None)
    }
}

async fn current_detached_hold(
    state: &Arc<ServerState>,
    q: &openshell_core::proto::ProviderDetachArmRequestV1,
) -> Result<(u64, u64, String), Status> {
    use openshell_core::{ObjectName, ObjectWorkspace};
    use prost::Message;
    let bad = || Status::failed_precondition("original detached hold/current state unavailable");
    let action = q.original_action.as_ref().ok_or_else(bad)?;
    validate_original_action(action)?;
    let r = q.original_receipt.as_ref().ok_or_else(bad)?;
    let t = action.target.as_ref().ok_or_else(bad)?;
    let row = state
        .store
        .get(
            crate::persistence::PROVIDER_DETACH_HOLD_OBJECT_TYPE,
            &r.hold_id,
        )
        .await
        .map_err(|_| bad())?
        .ok_or_else(bad)?;
    let hold = crate::storage_proto::StoredProviderDetachHoldV1::decode(row.payload.as_slice())
        .map_err(|_| bad())?;
    if hold.schema_version != 1
        || hold.generation == 0
        || row.resource_version == 0
        || row.id != r.hold_id
        || row.workspace != t.workspace
        || hold.hold_id != r.hold_id
        || hold.original_action.as_ref() != Some(action)
        || hold.original_receipt.as_ref() != Some(r)
        || hold.native_receipt_id != r.native_receipt_id
    {
        return Err(bad());
    }
    let sandbox = state
        .store
        .get_message::<openshell_core::proto::Sandbox>(&t.sandbox_id)
        .await
        .map_err(|_| bad())?
        .ok_or_else(bad)?;
    if sandbox.object_name() != t.sandbox
        || sandbox.object_workspace() != t.workspace
        || sandbox.phase() != openshell_core::proto::SandboxPhase::Ready as i32
        || crate::auth::sandbox_session::sandbox_execution_id(&sandbox)? != t.execution_id
        || !sandbox.spec.as_ref().is_some_and(|s| {
            s.provider_attachment_epoch == r.after_attachment_epoch
                && !s.providers.contains(&t.provider)
        })
        || state
            .store
            .get_latest_policy(&t.sandbox_id)
            .await
            .map_err(|_| bad())?
            .is_none()
    {
        return Err(bad());
    }
    let config = super::policy::load_sandbox_config(state, &sandbox).await?;
    let receipt_policy_hash = r.native_policy_hash.as_str();
    if !config.configuration_admitted
        || config.configuration_instance_id != r.configuration_instance
        || config.config_revision != r.config_revision
        || config.provider_env_revision != r.provider_env_revision
        || config.policy_hash != receipt_policy_hash
        || config.version != r.native_policy_version
        || config.provider_attachment_epoch != r.after_attachment_epoch
    {
        return Err(bad());
    }
    let instance = sandbox
        .status
        .as_ref()
        .map(|s| s.main_process_instance_id.clone())
        .filter(|id| !id.is_empty())
        .ok_or_else(bad)?;
    Ok((hold.generation, row.resource_version, instance))
}
pub(super) async fn read_attempt(
    state: &Arc<ServerState>,
    q: &openshell_core::proto::ProviderDetachArmRequestV1,
    write: bool,
) -> Result<openshell_core::proto::ProviderDetachAttemptReadbackV1, Status> {
    use prost::Message;
    let bootstrap = q
        .attempt
        .as_ref()
        .is_none_or(|a| *a == openshell_core::proto::ProviderDetachAttemptV1::default())
        && q.attempt_id.is_empty()
        && q.request_sha256.is_empty();
    if write || !bootstrap {
        validate_arm_metadata(q)?;
    }
    if q.encoded_len() > 8192 {
        return Err(Status::invalid_argument("attempt request too large"));
    }
    let action = q
        .original_action
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("original action absent"))?;
    validate_original_action(action)?;
    let target = action
        .target
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("original target absent"))?;
    let (_lifecycle, _sync) = state
        .compute
        .sandbox_create_guards(&target.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("attempt lifecycle unavailable"))?;
    let fence = state
        .store
        .provider_detach_fence()
        .await
        .map_err(|_| Status::unavailable("attempt configuration fence unavailable"))?;
    let (generation, row_version, instance) = current_detached_hold(state, q).await?;
    let session = if bootstrap {
        state
            .supervisor_sessions
            .provider_readiness(&target.sandbox_id)?
            .and_then(|e| e.provider_detach_snapshot())
            .map(|(_, o, _)| o.session_id)
    } else {
        q.attempt.as_ref().map(|a| a.supervisor_session.clone())
    }
    .ok_or_else(|| Status::failed_precondition("attempt supervisor session absent"))?;
    let now = openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now())
        .map_err(|_| Status::internal("attempt clock unavailable"))?;
    let result = state.supervisor_sessions.with_provider_detach_attempts(
        &target.sandbox_id,
        &session,
        &instance,
        |evidence, attempts| {
            let current_ack = match ack_for_original(q, evidence, &attempts.boot_id, &now) {
                Ok(ack) => ack,
                Err(_e) if !write => return Ok(unknown_attempt()),
                Err(e) => return Err(e),
            };
            let current = openshell_core::proto::ProviderDetachAttemptCurrentV1 {
                gateway_boot_id: attempts.boot_id.clone(),
                hold_generation: generation,
                row_resource_version: row_version,
                ack: Some(current_ack.clone()),
            };
            if bootstrap {
                let mut r = unknown_attempt();
                r.current = Some(current);
                return Ok(r);
            }
            let mut r = if write {
                attempts.admit(q, generation, row_version, &now)?
            } else {
                attempts.query(q, &now)?
            };
            if let Some(seal) = r.seal.as_ref() {
                if seal.hold_generation != generation || seal.row_resource_version != row_version {
                    return Ok(unknown_attempt());
                }
                if r.state == 2 || r.state == 3 || r.state == 4 {
                    if !attempts.current_binding_matches(q, evidence) {
                        return Ok(unknown_attempt());
                    }
                    let a = q.attempt.as_ref().unwrap();
                    if seal.install_sequence <= a.arm_capture_sequence
                        || current_ack.sequence < seal.install_sequence
                        || seal.installed_time.as_ref().is_none_or(|installed| {
                            timestamp_ns(installed).is_err()
                                || timestamp_ns(installed).ok() > timestamp_ns(&now).ok()
                        })
                    {
                        return Ok(unknown_attempt());
                    }
                }
            }
            if let Some(proof) = r.proof.as_ref() {
                let old = proof
                    .ack
                    .as_ref()
                    .ok_or_else(|| Status::failed_precondition("original proof ACK absent"))?;
                let refusal = proof
                    .refusal
                    .as_ref()
                    .ok_or_else(|| Status::failed_precondition("original refusal absent"))?;
                let bad = || Status::failed_precondition("original proof/current closing changed");
                let old_observed = timestamp_ns(old.observed_time.as_ref().ok_or_else(bad)?)?;
                let old_evaluated = timestamp_ns(old.evaluated_time.as_ref().ok_or_else(bad)?)?;
                let refusal_observed =
                    timestamp_ns(refusal.observed_time.as_ref().ok_or_else(bad)?)?;
                if old.sequence != refusal.sequence
                    || current_ack.sequence < old.sequence
                    || old_evaluated < old_observed
                    || old_evaluated > timestamp_ns(&now)?
                    || timestamp_ns(&now)? - old_observed >= 30_000_000_000
                    || timestamp_ns(current_ack.observed_time.as_ref().ok_or_else(bad)?)?
                        < old_observed
                    || timestamp_ns(current_ack.evaluated_time.as_ref().ok_or_else(bad)?)?
                        < refusal_observed
                    || old_observed < refusal_observed
                {
                    return Ok(unknown_attempt());
                }
            }
            if r.state != 5 {
                r.current = Some(current);
            }
            Ok(r)
        },
    )?;
    if state
        .store
        .provider_detach_fence()
        .await
        .map_err(|_| Status::unavailable("attempt closing fence unavailable"))?
        != fence
    {
        return Err(Status::aborted("attempt current state changed"));
    }
    Ok(result)
}

#[cfg(test)]
pub fn registry_arm_fixture(
    boot: &str,
    now: prost_types::Timestamp,
) -> openshell_core::proto::ProviderDetachArmRequestV1 {
    use openshell_core::proto::*;
    let mut original = tests::original_action();
    let mut target = original.target.clone().unwrap();
    target.sandbox_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into();
    original.target_sha256 = target_digest(&target).unwrap();
    original.target = Some(target.clone());
    let intent = original.original_intent.as_mut().unwrap();
    intent.target.as_mut().unwrap().sandbox_id = target.sandbox_id.clone();
    let detach = intent.detach.as_mut().unwrap();
    detach.target = Some(target.clone());
    detach.target_sha256 = original.target_sha256.clone();
    original.intent_sha256 = original_intent_digest(intent).unwrap();
    original.action_id = action_id_for_digest(&original.intent_sha256).unwrap();
    let recorded = prost_types::Timestamp {
        seconds: now.seconds - 2,
        nanos: now.nanos,
    };
    let receipt = ProviderDetachReceiptV1 {
        action_id: original.action_id.clone(),
        intent_sha256: original.intent_sha256.clone(),
        target_sha256: original.target_sha256.clone(),
        target: Some(target.clone()),
        before_attachment_epoch: target.attachment_epoch.clone(),
        after_attachment_epoch: "33333333-3333-4333-8333-333333333333".into(),
        native_receipt_id: "11111111-1111-4111-8111-111111111111".into(),
        hold_id: "22222222-2222-4222-8222-222222222222".into(),
        config_revision: 9,
        provider_env_revision: 3,
        configuration_instance: "config-after".into(),
        native_policy_hash: "e".repeat(64),
        native_policy_version: 4,
        recorded_time: Some(recorded),
    };
    let a = ProviderDetachAttemptV1 {
        schema_version: 1,
        dispatcher_decision_id: uuid::Uuid::new_v4().to_string(),
        action_id: original.action_id.clone(),
        intent_sha256: original.intent_sha256.clone(),
        target_sha256: original.target_sha256.clone(),
        native_receipt_id: receipt.native_receipt_id.clone(),
        hold_id: receipt.hold_id.clone(),
        authority: target.authority.clone(),
        gateway_boot_id: boot.into(),
        workspace: target.workspace.clone(),
        sandbox_id: target.sandbox_id.clone(),
        execution_id: target.execution_id.clone(),
        provider_id: target.provider_id.clone(),
        attachment_epoch: receipt.after_attachment_epoch.clone(),
        configuration_instance: receipt.configuration_instance.clone(),
        config_revision: receipt.config_revision,
        provider_env_revision: receipt.provider_env_revision,
        native_policy_hash: receipt.native_policy_hash.clone(),
        native_policy_version: receipt.native_policy_version,
        supervisor_instance: "44444444-4444-4444-8444-444444444444".into(),
        supervisor_session: "55555555-5555-4555-8555-555555555555".into(),
        arm_capture_sequence: 10,
        challenge: "a".repeat(64),
        not_before: Some(prost_types::Timestamp {
            seconds: now.seconds - 1,
            nanos: now.nanos,
        }),
        deadline: Some(prost_types::Timestamp {
            seconds: now.seconds + 20,
            nanos: now.nanos,
        }),
    };
    let digest = attempt_digest(&a).unwrap();
    let id = action_id_for_digest(&digest).unwrap();
    ProviderDetachArmRequestV1 {
        original_action: Some(original),
        original_receipt: Some(receipt),
        attempt: Some(a),
        attempt_id: id,
        request_sha256: digest,
    }
}
