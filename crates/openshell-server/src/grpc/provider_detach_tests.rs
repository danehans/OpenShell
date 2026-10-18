// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;

fn target() -> ProviderDetachTargetV1 {
    ProviderDetachTargetV1 {
        authority: "gateway-a".into(),
        workspace: "default".into(),
        sandbox: "agent".into(),
        sandbox_id: "sandbox-uuid".into(),
        execution_id: format!("exec-v1:{}", "a".repeat(64)),
        sandbox_resource_version: 9_007_199_254_740_993,
        provider: "model".into(),
        provider_id: "provider-uuid".into(),
        provider_resource_version: 17,
        attachment_epoch: "epoch-1".into(),
        configuration_fingerprint: "opaque/<cfg>&雪".into(),
        configuration_instance: "config-1".into(),
        config_revision: 8,
        provider_env_revision: 2,
        native_policy_hash: "b".repeat(64),
        native_policy_version: 3,
    }
}

#[test]
fn controller_v3_target_vector_is_exact_without_float_conversion() {
    let mut target = target();
    assert_eq!(
        target_digest(&target).unwrap(),
        "6389f95c089e24f49bf59f7966fbc3ee09d045ec19816d54c31244a1a56854d2"
    );
    let original = target_digest(&target).unwrap();
    target.sandbox_resource_version -= 1;
    assert_ne!(target_digest(&target).unwrap(), original);
    target = self::target();
    target.configuration_fingerprint.push(' ');
    assert_ne!(target_digest(&target).unwrap(), original);
}

#[test]
fn resource_grant_does_not_rebind_when_snapshot_revision_changes() {
    let target = target();
    let mut resource = ProviderDetachResourceV1 {
        authority: target.authority,
        workspace: target.workspace,
        sandbox: target.sandbox,
        sandbox_id: target.sandbox_id,
        execution_id: target.execution_id,
        provider: target.provider,
        provider_id: target.provider_id,
    };
    let digest = resource_digest(&resource).unwrap();
    assert_eq!(
        digest,
        "55d6d2b621787571674ca35afa5faceb8473917656a8c79009b5f241c9f105f8"
    );
    resource.provider_id = "another-provider".into();
    assert_ne!(resource_digest(&resource).unwrap(), digest);
    resource.provider_id = "provider-uuid".into();
    resource.execution_id.push('b');
    assert_ne!(resource_digest(&resource).unwrap(), digest);
}

pub(super) fn original_action() -> ProviderDetachActionV1 {
    use openshell_core::proto::{
        ProviderDetachIntentV1, ProviderDetachOriginalIntentV1, ProviderDetachSourceTargetV1,
    };
    let target = target();
    let target_sha256 = target_digest(&target).unwrap();
    ProviderDetachActionV1 {
        schema_version: 1,
        action_id: "78b7f3e7-7413-5338-a795-f35973214544".into(),
        profile_id: "profile-1".into(),
        event_id: "event-1".into(),
        intent_sha256: "78b7f3e774131338e795f3597321454491bafb249cbdc83c0aaa15f112182c3b".into(),
        target: Some(target.clone()),
        target_sha256: target_sha256.clone(),
        original_intent: Some(ProviderDetachOriginalIntentV1 {
            schema_version: 1,
            target: Some(ProviderDetachSourceTargetV1 {
                gateway_id: "gateway-a".into(),
                workspace: "default".into(),
                sandbox: "agent".into(),
                sandbox_id: "sandbox-uuid".into(),
                execution_id: target.execution_id.clone(),
                runtime_handle: String::new(),
            }),
            event_id: "event-1".into(),
            policy_revision: "rules-1".into(),
            policy_hash: "c".repeat(64),
            rule_id: "secret".into(),
            detach: Some(ProviderDetachIntentV1 {
                schema_version: 1,
                profile_id: "profile-1".into(),
                violation_sha256: "d".repeat(64),
                target: Some(target),
                target_sha256,
            }),
        }),
    }
}

#[test]
fn controller_original_intent_vector_and_action_uuid_match_exactly() {
    let action = original_action();
    assert_eq!(
        original_intent_digest(action.original_intent.as_ref().unwrap()).unwrap(),
        action.intent_sha256
    );
    assert_eq!(
        action_id_for_digest(&action.intent_sha256).unwrap(),
        action.action_id
    );
    validate_original_action(&action).unwrap();
    // A controller alias is an independent original identity, not native authority.
    let mut alias = action.clone();
    alias
        .original_intent
        .as_mut()
        .unwrap()
        .target
        .as_mut()
        .unwrap()
        .gateway_id = "controller-alias".into();
    alias.intent_sha256 = original_intent_digest(alias.original_intent.as_ref().unwrap()).unwrap();
    alias.action_id = action_id_for_digest(&alias.intent_sha256).unwrap();
    validate_original_action(&alias).unwrap();
    assert_ne!(alias.intent_sha256, action.intent_sha256);
}

#[test]
fn original_intent_substitution_and_redundant_request_mismatch_refuse() {
    for case in 0..17 {
        let mut action = original_action();
        let intent = action.original_intent.as_mut().unwrap();
        match case {
            0 => intent.policy_revision.push('x'),
            1 => intent.policy_hash = "a".repeat(64),
            2 => intent.rule_id.push('x'),
            3 => intent.detach.as_mut().unwrap().violation_sha256 = "a".repeat(64),
            4 => intent.target.as_mut().unwrap().gateway_id = "other-alias".into(),
            5 => intent.target.as_mut().unwrap().runtime_handle = "forbidden".into(),
            6 => intent.target.as_mut().unwrap().sandbox_id.push('x'),
            7 => intent.schema_version = 2,
            8 => intent.detach.as_mut().unwrap().schema_version = 2,
            9 => action.profile_id.push('x'),
            10 => action.event_id.push('x'),
            11 => action.action_id = "00000000-0000-4000-8000-000000000000".into(),
            12 => action.target.as_mut().unwrap().sandbox_resource_version -= 1,
            13 => action.original_intent = None,
            14 => action.original_intent.as_mut().unwrap().detach = None,
            15 => action.original_intent.as_mut().unwrap().target = None,
            16 => action.target_sha256 = "a".repeat(64),
            _ => unreachable!(),
        }
        assert!(validate_original_action(&action).is_err(), "case {case}");
    }
}

fn scoped_request<T>(value: T, resource: &ProviderDetachResourceV1) -> Request<T> {
    use crate::auth::principal::Principal;
    let mut request = crate::grpc::test_support::authed_request(value);
    let Principal::User(user) = request.extensions_mut().get_mut::<Principal>().unwrap() else {
        unreachable!()
    };
    user.identity.scopes = vec![
        "sandbox:provider-detach".into(),
        "sandbox:provider-detach:read".into(),
        format!(
            "sandbox:provider-detach:target:{}",
            resource_digest(resource).unwrap()
        ),
    ];
    request
}

async fn rpc_fixture() -> (Arc<ServerState>, ProviderDetachResourceV1) {
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{
        Provider, Sandbox, SandboxConfigurationAdmission, SandboxSpec, SandboxStatus,
    };
    use prost::Message;
    let mut state = crate::grpc::test_support::test_server_state().await;
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.config.name = "gateway-a".into();
    mutable.config.oidc=Some(serde_json::from_value(serde_json::json!({"issuer":"https://issuer.example.test","audience":"fixture","scopes_claim":"scope"})).unwrap());
    let policy = openshell_policy::restrictive_default_policy();
    let mut sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: "sandbox-uuid".into(),
            name: "agent".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            policy: Some(policy.clone()),
            providers: vec!["model".into()],
            provider_attachment_epoch: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        }),
        status: Some(SandboxStatus {
            phase: openshell_core::proto::SandboxPhase::Ready as i32,
            configuration_admission: Some(SandboxConfigurationAdmission {
                instance_id: "config-1".into(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    crate::auth::sandbox_session::PersistedSandboxIdentity::new()
        .unwrap()
        .write(&mut sandbox.metadata.as_mut().unwrap().annotations);
    let execution = crate::auth::sandbox_session::sandbox_execution_id(&sandbox).unwrap();
    state.store.put_message(&sandbox).await.unwrap();
    let provider = Provider {
        metadata: Some(ObjectMeta {
            id: "provider-uuid".into(),
            name: "model".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&provider).await.unwrap();
    state
        .store
        .put_policy_revision(
            "policy-1",
            "sandbox-uuid",
            "default",
            1,
            &policy.encode_to_vec(),
            &openshell_core::policy_identity::deterministic_policy_hash(&policy),
        )
        .await
        .unwrap();
    (
        state,
        ProviderDetachResourceV1 {
            authority: "gateway-a".into(),
            workspace: "default".into(),
            sandbox: "agent".into(),
            sandbox_id: "sandbox-uuid".into(),
            execution_id: execution,
            provider: "model".into(),
            provider_id: "provider-uuid".into(),
        },
    )
}

async fn resolve_rpc(
    state: &Arc<ServerState>,
    resource: &ProviderDetachResourceV1,
) -> ProviderDetachTargetV1 {
    use openshell_core::proto::{
        ResolveProviderDetachV1, get_conditional_provider_detach_state_request::Query,
        get_conditional_provider_detach_state_response::Result,
    };
    let result = read_state(
        state,
        scoped_request(
            GetConditionalProviderDetachStateRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                query: Some(Query::Resolve(ResolveProviderDetachV1 {
                    resource: Some(resource.clone()),
                })),
            },
            resource,
        ),
    )
    .await
    .unwrap()
    .into_inner()
    .result
    .unwrap();
    let Result::Target(target) = result else {
        panic!("wrong resolve variant")
    };
    target
}

fn action_for_rpc(target: ProviderDetachTargetV1) -> ProviderDetachActionV1 {
    let mut action = original_action();
    action.target = Some(target.clone());
    action.target_sha256 = target_digest(&target).unwrap();
    let original = action.original_intent.as_mut().unwrap();
    let source = original.target.as_mut().unwrap();
    source.gateway_id = "controller-alias".into();
    source.workspace = target.workspace.clone();
    source.sandbox = target.sandbox.clone();
    source.sandbox_id = target.sandbox_id.clone();
    source.execution_id = target.execution_id.clone();
    original.detach.as_mut().unwrap().target = Some(target);
    original.detach.as_mut().unwrap().target_sha256 = action.target_sha256.clone();
    action.intent_sha256 = original_intent_digest(original).unwrap();
    action.action_id = action_id_for_digest(&action.intent_sha256).unwrap();
    validate_original_action(&action).unwrap();
    action
}

#[tokio::test]
async fn actual_rpc_detaches_and_recovers_original_without_mutating_replacement() {
    use openshell_core::proto::{
        RecoverProviderDetachV1, Sandbox, get_conditional_provider_detach_state_request::Query,
        get_conditional_provider_detach_state_response::Result,
    };
    let (state, resource) = rpc_fixture().await;
    let target = resolve_rpc(&state, &resource).await;
    let action = action_for_rpc(target);
    let response = conditional_detach(
        &state,
        scoped_request(
            ConditionalDetachSandboxProviderRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                action: Some(action.clone()),
            },
            &resource,
        ),
    )
    .await
    .unwrap()
    .into_inner()
    .outcome
    .unwrap();
    assert_eq!(response.state, "applied");
    assert!(response.receipt.is_some());
    let sandbox = state
        .store
        .get_message::<Sandbox>("sandbox-uuid")
        .await
        .unwrap()
        .unwrap();
    assert!(sandbox.spec.as_ref().unwrap().providers.is_empty());
    assert_eq!(
        sandbox.phase(),
        openshell_core::proto::SandboxPhase::Ready as i32
    );
    state.store.delete("sandbox", "sandbox-uuid").await.unwrap();
    state
        .store
        .delete("provider", "provider-uuid")
        .await
        .unwrap();
    let mut replacement = sandbox.clone();
    replacement.metadata.as_mut().unwrap().id = "replacement-sandbox".into();
    replacement.spec.as_mut().unwrap().providers = vec!["model".into()];
    crate::auth::sandbox_session::PersistedSandboxIdentity::new()
        .unwrap()
        .write(&mut replacement.metadata.as_mut().unwrap().annotations);
    state.store.put_message(&replacement).await.unwrap();
    let replacement_before = state
        .store
        .get("sandbox", "replacement-sandbox")
        .await
        .unwrap()
        .unwrap();
    let recovered = read_state(
        &state,
        scoped_request(
            GetConditionalProviderDetachStateRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                query: Some(Query::Recover(RecoverProviderDetachV1 {
                    action: Some(action.clone()),
                })),
            },
            &resource,
        ),
    )
    .await
    .unwrap()
    .into_inner()
    .result
    .unwrap();
    assert_eq!(recovered, Result::Outcome(response.clone()));
    let repeated = conditional_detach(
        &state,
        scoped_request(
            ConditionalDetachSandboxProviderRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                action: Some(action),
            },
            &resource,
        ),
    )
    .await
    .unwrap()
    .into_inner()
    .outcome
    .unwrap();
    assert_eq!(repeated, response);
    let replacement_after = state
        .store
        .get("sandbox", "replacement-sandbox")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replacement_after.payload, replacement_before.payload);
    assert_eq!(
        replacement_after.resource_version,
        replacement_before.resource_version
    );
    assert!(
        state
            .store
            .get("sandbox", "sandbox-uuid")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn actual_rpc_stale_snapshot_is_durably_rejected_and_broad_grant_refused() {
    let (state, resource) = rpc_fixture().await;
    let mut target = resolve_rpc(&state, &resource).await;
    target.sandbox_resource_version += 1;
    let action = action_for_rpc(target);
    let body = ConditionalDetachSandboxProviderRequest {
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        action: Some(action.clone()),
    };
    let mut broad = crate::grpc::test_support::authed_request(body.clone());
    let crate::auth::principal::Principal::User(user) = broad
        .extensions_mut()
        .get_mut::<crate::auth::principal::Principal>()
        .unwrap()
    else {
        unreachable!()
    };
    user.identity.scopes = vec!["openshell:all".into()];
    assert_eq!(
        conditional_detach(&state, broad).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert!(
        state
            .store
            .recover_provider_detach(&action)
            .await
            .unwrap()
            .is_none()
    );
    let result = conditional_detach(&state, scoped_request(body, &resource))
        .await
        .unwrap()
        .into_inner()
        .outcome
        .unwrap();
    assert_eq!(result.state, "rejected_no_effect");
    assert!(result.receipt.is_none());
    assert_eq!(
        state.store.recover_provider_detach(&action).await.unwrap(),
        Some(result)
    );
}

#[tokio::test]
async fn actual_rpc_unknown_recovery_is_read_only_and_read_grant_cannot_dispatch() {
    use crate::auth::principal::Principal;
    use openshell_core::proto::{
        RecoverProviderDetachV1, get_conditional_provider_detach_state_request::Query,
        get_conditional_provider_detach_state_response::Result,
    };
    let (state, resource) = rpc_fixture().await;
    let action = action_for_rpc(resolve_rpc(&state, &resource).await);
    let result = read_state(
        &state,
        scoped_request(
            GetConditionalProviderDetachStateRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                query: Some(Query::Recover(RecoverProviderDetachV1 {
                    action: Some(action.clone()),
                })),
            },
            &resource,
        ),
    )
    .await
    .unwrap()
    .into_inner()
    .result
    .unwrap();
    assert!(matches!(result,Result::Outcome(ref o) if o.state=="unknown"&&o.receipt.is_none()));
    assert!(
        state
            .store
            .list(
                crate::persistence::PROVIDER_DETACH_ACTION_OBJECT_TYPE,
                "default",
                10,
                0
            )
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        state
            .store
            .list(
                crate::persistence::PROVIDER_DETACH_HOLD_OBJECT_TYPE,
                "default",
                10,
                0
            )
            .await
            .unwrap()
            .is_empty()
    );
    let mut request = scoped_request(
        ConditionalDetachSandboxProviderRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            action: Some(action.clone()),
        },
        &resource,
    );
    let Principal::User(user) = request.extensions_mut().get_mut::<Principal>().unwrap() else {
        unreachable!()
    };
    user.identity
        .scopes
        .retain(|s| s != "sandbox:provider-detach");
    assert_eq!(
        conditional_detach(&state, request)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert!(
        state
            .store
            .recover_provider_detach(&action)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn actual_rpc_resolve_refuses_missing_history_and_wrong_bindings_without_writes() {
    use openshell_core::proto::{
        ResolveProviderDetachV1, get_conditional_provider_detach_state_request::Query,
    };
    let (state, resource) = rpc_fixture().await;
    assert!(
        state
            .store
            .delete(crate::persistence::POLICY_OBJECT_TYPE, "policy-1")
            .await
            .unwrap()
    );
    let before = state.store.provider_detach_fence().await.unwrap();
    let body = |resource: ProviderDetachResourceV1, workspace: &str| {
        GetConditionalProviderDetachStateRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector(workspace)),
            query: Some(Query::Resolve(ResolveProviderDetachV1 {
                resource: Some(resource),
            })),
        }
    };
    let missing = read_state(
        &state,
        scoped_request(body(resource.clone(), "default"), &resource),
    )
    .await
    .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::FailedPrecondition);
    assert!(
        state
            .store
            .get_latest_policy("sandbox-uuid")
            .await
            .unwrap()
            .is_none()
    );
    let mut wrong_authority = resource.clone();
    wrong_authority.authority = "other-gateway".into();
    let wrong = read_state(
        &state,
        scoped_request(body(wrong_authority.clone(), "default"), &wrong_authority),
    )
    .await
    .unwrap_err();
    assert_eq!(wrong.code(), tonic::Code::PermissionDenied);
    let wrong = read_state(
        &state,
        scoped_request(body(resource.clone(), "other-workspace"), &resource),
    )
    .await
    .unwrap_err();
    assert_eq!(wrong.code(), tonic::Code::InvalidArgument);
    assert!(state.store.provider_detach_fence().await.unwrap() == before);
}

#[tokio::test]
async fn actual_rpc_arm_bootstrap_install_and_historical_proof_require_current_joins() {
    use openshell_core::proto::*;
    use prost::Message;
    let (state, mut resource) = rpc_fixture().await;
    let old = state
        .store
        .get_message::<Sandbox>(&resource.sandbox_id)
        .await
        .unwrap()
        .unwrap();
    state
        .store
        .delete("sandbox", &resource.sandbox_id)
        .await
        .unwrap();
    let mut sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            name: resource.sandbox.clone(),
            workspace: resource.workspace.clone(),
            ..Default::default()
        }),
        spec: old.spec,
        status: old.status,
        ..Default::default()
    };
    let instance = "44444444-4444-4444-8444-444444444444";
    let session = "55555555-5555-4555-8555-555555555555";
    sandbox.status.as_mut().unwrap().main_process_instance_id = instance.into();
    crate::auth::sandbox_session::PersistedSandboxIdentity::new()
        .unwrap()
        .write(&mut sandbox.metadata.as_mut().unwrap().annotations);
    resource.sandbox_id = sandbox.metadata.as_ref().unwrap().id.clone();
    resource.execution_id = crate::auth::sandbox_session::sandbox_execution_id(&sandbox).unwrap();
    state.store.put_message(&sandbox).await.unwrap();
    let policy = sandbox.spec.as_ref().unwrap().policy.as_ref().unwrap();
    state
        .store
        .put_policy_revision(
            "policy-arm",
            &resource.sandbox_id,
            "default",
            1,
            &policy.encode_to_vec(),
            &openshell_core::policy_identity::deterministic_policy_hash(policy),
        )
        .await
        .unwrap();
    let action = action_for_rpc(resolve_rpc(&state, &resource).await);
    let r = conditional_detach(
        &state,
        scoped_request(
            ConditionalDetachSandboxProviderRequest {
                workspace_scope: Some(workspace_selector("default")),
                action: Some(action.clone()),
            },
            &resource,
        ),
    )
    .await
    .unwrap()
    .into_inner()
    .outcome
    .unwrap()
    .receipt
    .unwrap();
    let unchanged = state
        .store
        .get("sandbox", &resource.sandbox_id)
        .await
        .unwrap()
        .unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    state.supervisor_sessions.register(
        resource.sandbox_id.clone(),
        session.into(),
        tx,
        tokio::sync::oneshot::channel().0,
    );
    assert!(
        state
            .supervisor_sessions
            .initialize_endpoint_status_authority(&resource.sandbox_id, session)
    );
    let hello = SupervisorHello {
        sandbox_id: resource.sandbox_id.clone(),
        instance_id: instance.into(),
        supports_provider_readiness: true,
        ..Default::default()
    };
    state
        .supervisor_sessions
        .initialize_provider_readiness(
            &resource.sandbox_id,
            session,
            crate::grpc::provider_readiness::ProviderReadinessEvidence::from_hello(&hello).unwrap(),
        )
        .unwrap();
    let mut obs = ProviderReadinessObservation {
        session_id: session.into(),
        sequence: 10,
        attachment_epoch: r.after_attachment_epoch.clone(),
        config_revision: r.config_revision,
        provider_env_revision: r.provider_env_revision,
        policy_hash: r.native_policy_hash.clone(),
        credentials_installed: true,
        policy_active: true,
        launch_environment_installed: true,
        process_instance_id: "99999999-9999-4999-8999-999999999999".into(),
        provider_detach: Some(ProviderDetachSupervisorReportV1 {
            supported: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    state
        .supervisor_sessions
        .accept_provider_readiness(&resource.sandbox_id, instance, obs.clone())
        .unwrap();
    let bootstrap = ProviderDetachArmRequestV1 {
        original_action: Some(action.clone()),
        original_receipt: Some(r.clone()),
        ..Default::default()
    };
    let query = |request: ProviderDetachArmRequestV1| {
        scoped_request(
            GetConditionalProviderDetachStateRequest {
                workspace_scope: Some(workspace_selector("default")),
                query: Some(
                    get_conditional_provider_detach_state_request::Query::QueryAttempt(request),
                ),
            },
            &resource,
        )
    };
    let current = read_state(&state, query(bootstrap.clone()))
        .await
        .unwrap()
        .into_inner()
        .result
        .and_then(|r| match r {
            get_conditional_provider_detach_state_response::Result::Attempt(a) => Some(a),
            _ => None,
        })
        .unwrap();
    assert_eq!(current.state, 6);
    assert!(current.seal.is_none() && current.proof.is_none());
    let current = current.current.unwrap();
    let now =
        openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now()).unwrap();
    let mut q = registry_arm_fixture(&current.gateway_boot_id, now);
    q.original_action = Some(action.clone());
    q.original_receipt = Some(r.clone());
    let a = q.attempt.as_mut().unwrap();
    let target = action.target.as_ref().unwrap();
    a.action_id = action.action_id.clone();
    a.intent_sha256 = action.intent_sha256.clone();
    a.target_sha256 = action.target_sha256.clone();
    a.native_receipt_id = r.native_receipt_id.clone();
    a.hold_id = r.hold_id.clone();
    a.authority = target.authority.clone();
    a.workspace = target.workspace.clone();
    a.sandbox_id = target.sandbox_id.clone();
    a.execution_id = target.execution_id.clone();
    a.provider_id = target.provider_id.clone();
    a.attachment_epoch = r.after_attachment_epoch.clone();
    a.configuration_instance = r.configuration_instance.clone();
    a.config_revision = r.config_revision;
    a.provider_env_revision = r.provider_env_revision;
    a.native_policy_hash = r.native_policy_hash.clone();
    a.native_policy_version = r.native_policy_version;
    a.not_before = Some(now);
    a.arm_capture_sequence = current.ack.as_ref().unwrap().sequence;
    q.request_sha256 = attempt_digest(a).unwrap();
    q.attempt_id = action_id_for_digest(&q.request_sha256).unwrap();
    let pending = arm_attempt(
        &state,
        scoped_request(
            ArmProviderDetachAttemptRequest {
                workspace_scope: Some(workspace_selector("default")),
                request: Some(q.clone()),
            },
            &resource,
        ),
    )
    .await
    .unwrap()
    .into_inner()
    .readback
    .unwrap();
    assert_eq!(pending.state, 1);
    assert_eq!(pending.seal.as_ref().unwrap().install_sequence, 0);
    let (_, delivered, _) = state
        .supervisor_sessions
        .provider_detach_report_reply(&resource.sandbox_id, session, instance)
        .unwrap();
    assert_eq!(delivered.unwrap().request.as_ref(), Some(&q));
    obs.sequence = 11;
    obs.provider_detach = Some(ProviderDetachSupervisorReportV1 {
        supported: true,
        gateway_boot_id: current.gateway_boot_id.clone(),
        attempt_id: q.attempt_id.clone(),
        request_sha256: q.request_sha256.clone(),
        install_sequence: 11,
        installed_time: Some(
            openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now()).unwrap(),
        ),
        ..Default::default()
    });
    state
        .supervisor_sessions
        .accept_provider_readiness(&resource.sandbox_id, instance, obs.clone())
        .unwrap();
    let armed = read_state(&state, query(q.clone()))
        .await
        .unwrap()
        .into_inner()
        .result
        .and_then(|r| match r {
            get_conditional_provider_detach_state_response::Result::Attempt(a) => Some(a),
            _ => None,
        })
        .unwrap();
    assert_eq!(armed.state, 2);
    assert_eq!(armed.seal.as_ref().unwrap().install_sequence, 11);
    let a = q.attempt.as_ref().unwrap();
    let event =
        openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now()).unwrap();
    obs.sequence = 12;
    let meta = obs.provider_detach.as_mut().unwrap();
    meta.result = 1;
    meta.refusal = Some(ProviderDetachRefusalV1 {
        action_id: a.action_id.clone(),
        target_sha256: a.target_sha256.clone(),
        attempt_id: q.attempt_id.clone(),
        challenge: a.challenge.clone(),
        supervisor_instance: instance.into(),
        supervisor_session: session.into(),
        sequence: 12,
        attachment_epoch: a.attachment_epoch.clone(),
        configuration_instance: a.configuration_instance.clone(),
        config_revision: a.config_revision,
        provider_env_revision: a.provider_env_revision,
        unavailable: true,
        attempted_time: Some(event),
        observed_time: Some(event),
    });
    state
        .supervisor_sessions
        .accept_provider_readiness(&resource.sandbox_id, instance, obs.clone())
        .unwrap();
    let first = read_state(&state, query(q.clone()))
        .await
        .unwrap()
        .into_inner()
        .result
        .and_then(|r| match r {
            get_conditional_provider_detach_state_response::Result::Attempt(a) => Some(a),
            _ => None,
        })
        .unwrap();
    assert_eq!(first.state, 4);
    assert_eq!(first.result, 1);
    assert_eq!(
        first.proof.as_ref().unwrap().ack.as_ref().unwrap().sequence,
        12
    );
    obs.sequence = 13;
    state
        .supervisor_sessions
        .accept_provider_readiness(&resource.sandbox_id, instance, obs)
        .unwrap();
    let later = read_state(&state, query(q.clone()))
        .await
        .unwrap()
        .into_inner()
        .result
        .and_then(|r| match r {
            get_conditional_provider_detach_state_response::Result::Attempt(a) => Some(a),
            _ => None,
        })
        .unwrap();
    assert_eq!(first.proof, later.proof);
    assert_eq!(later.current.unwrap().ack.unwrap().sequence, 13);
    let after = state
        .store
        .get("sandbox", &resource.sandbox_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.payload, after.payload);
    assert_eq!(unchanged.resource_version, after.resource_version);
    // Loss of the retained local arm/provenance under the same revisions
    // cannot be repaired from a capability-only heartbeat or cached old proof.
    let lost_context = ProviderReadinessObservation {
        session_id: session.into(),
        sequence: 14,
        attachment_epoch: r.after_attachment_epoch.clone(),
        config_revision: r.config_revision,
        provider_env_revision: r.provider_env_revision,
        policy_hash: r.native_policy_hash.clone(),
        credentials_installed: true,
        policy_active: true,
        launch_environment_installed: true,
        process_instance_id: "99999999-9999-4999-8999-999999999999".into(),
        provider_detach: Some(ProviderDetachSupervisorReportV1 {
            supported: true,
            gateway_boot_id: current.gateway_boot_id.clone(),
            ..Default::default()
        }),
        ..Default::default()
    };
    state
        .supervisor_sessions
        .accept_provider_readiness(&resource.sandbox_id, instance, lost_context)
        .unwrap();
    let withheld = read_state(&state, query(q.clone()))
        .await
        .unwrap()
        .into_inner()
        .result
        .and_then(|r| match r {
            get_conditional_provider_detach_state_response::Result::Attempt(a) => Some(a),
            _ => None,
        })
        .unwrap();
    assert_eq!(withheld.state, 6);
    assert!(withheld.seal.is_none() && withheld.proof.is_none());
    let mut partial = bootstrap;
    partial.attempt = Some(ProviderDetachAttemptV1 {
        gateway_boot_id: current.gateway_boot_id,
        ..Default::default()
    });
    assert!(read_state(&state, query(partial)).await.is_err());
}

#[test]
fn arm_attempt_v3_matches_controller_sdk_hash_and_timestamp_framing() {
    let a = openshell_core::proto::ProviderDetachAttemptV1 {
        schema_version: 1,
        dispatcher_decision_id: "66666666-6666-4666-8666-666666666666".into(),
        action_id: "78b7f3e7-7413-5338-a795-f35973214544".into(),
        intent_sha256: "78b7f3e774131338e795f3597321454491bafb249cbdc83c0aaa15f112182c3b".into(),
        target_sha256: "6389f95c089e24f49bf59f7966fbc3ee09d045ec19816d54c31244a1a56854d2".into(),
        native_receipt_id: "11111111-1111-4111-8111-111111111111".into(),
        hold_id: "22222222-2222-4222-8222-222222222222".into(),
        authority: "gateway-a".into(),
        gateway_boot_id: "88888888-8888-4888-8888-888888888888".into(),
        workspace: "default".into(),
        sandbox_id: "sandbox-uuid".into(),
        execution_id: "exec-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .into(),
        provider_id: "provider-uuid".into(),
        attachment_epoch: "33333333-3333-4333-8333-333333333333".into(),
        configuration_instance: "config-after".into(),
        config_revision: 9,
        provider_env_revision: 3,
        native_policy_hash: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            .into(),
        native_policy_version: 4,
        supervisor_instance: "44444444-4444-4444-8444-444444444444".into(),
        supervisor_session: "55555555-5555-4555-8555-555555555555".into(),
        arm_capture_sequence: 10,
        challenge: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        not_before: Some(prost_types::Timestamp {
            seconds: 1792180000,
            nanos: 0,
        }),
        deadline: Some(prost_types::Timestamp {
            seconds: 1792180020,
            nanos: 0,
        }),
    };
    let digest = attempt_digest(&a).unwrap();
    assert_eq!(
        digest,
        "5891bfb6f1986af26d78cccd52e62f1078b7132fc676975e6ca39e457a79da15"
    );
    assert_eq!(
        action_id_for_digest(&digest).unwrap(),
        "5891bfb6-f198-5af2-ad78-cccd52e62f10"
    );
    let mut bad = a;
    bad.not_before.as_mut().unwrap().nanos = -1;
    assert!(attempt_digest(&bad).is_err());
}
