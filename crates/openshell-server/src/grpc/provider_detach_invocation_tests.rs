// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::auth::{
    authz::{AuthzPolicy, check_provider_witness_grant},
    identity::{Identity, IdentityProvider, ProviderDetachWitnessApproval},
};
use openshell_core::proto::{
    GatewayMessage, ProviderDetachActionV1, ProviderDetachArmRequestV1, ProviderDetachArmSealV1,
    ProviderDetachAttemptV1, ProviderDetachReceiptV1, ProviderDetachWitnessControlV1, SandboxSpec,
    SandboxStatus, Workspace, WorkspaceMember, WorkspaceRole, workspace_selector,
};
fn identity() -> Identity {
    let id = uuid::Uuid::new_v4().to_string();
    Identity {
        subject: "approved-user".into(),
        display_name: None,
        roles: vec!["user".into()],
        scopes: vec![
            "sandbox:provider-detach:witness".into(),
            "sandbox:provider-detach:witness:read".into(),
            format!("sandbox:provider-detach:target:{}", "a".repeat(64)),
        ],
        provider: IdentityProvider::Oidc,
        provider_detach_witness_approval: Some(Box::new(ProviderDetachWitnessApproval {
            schema: "openshell.provider-detach.witness-approval/v1".into(),
            subject: "approved-user".into(),
            run_id: id.clone(),
            action_id: id.clone(),
            native_receipt_id: id.clone(),
            hold_id: id.clone(),
            attempt_id: id,
            installed_arm_sha256: "a".repeat(64),
            profile_sha256: "a".repeat(64),
            request_sha256: "b".repeat(64),
            resource_sha256: "a".repeat(64),
            deadline_unix_ms: 2000,
            count: 1,
        })),
    }
}
fn grant(i: &Identity, write: bool, now: i64) -> bool {
    check_provider_witness_grant(
        i,
        &AuthzPolicy {
            admin_role: "admin".into(),
            user_role: "user".into(),
            scopes_enabled: true,
        },
        write,
        &"a".repeat(64),
        &"b".repeat(64),
        now,
    )
    .is_ok()
}
#[test]
fn witness_approval_exact_scope_and_deadline() {
    let original = identity();
    assert!(grant(&original, true, 1999));
    assert!(!grant(&original, true, 2000));
    assert!(grant(&original, false, 2001));
    for scope in [
        "*",
        "sandbox:*",
        "sandbox:provider-detach",
        "sandbox:exec",
        "openid",
    ] {
        let mut i = original.clone();
        i.scopes.push(scope.into());
        assert!(!grant(&i, true, 1000));
    }
    let mut i = original.clone();
    i.roles.push("admin".into());
    assert!(!grant(&i, true, 1000));
    let mut i = original.clone();
    i.provider = IdentityProvider::Mtls;
    assert!(!grant(&i, true, 1000));
    let mut i = original.clone();
    i.provider_detach_witness_approval = None;
    assert!(!grant(&i, true, 1000));
}
#[test]
fn witness_approval_closed_shape_and_original_identity() {
    let original = identity();
    for mutate in 0..5 {
        let mut i = original.clone();
        let a = i.provider_detach_witness_approval.as_mut().unwrap();
        match mutate {
            0 => a.count = 2,
            1 => a.subject = "other".into(),
            2 => a.run_id = uuid::Uuid::nil().to_string(),
            3 => a.request_sha256 = "c".repeat(64),
            _ => a.resource_sha256 = "c".repeat(64),
        }
        assert!(!grant(&i, true, 1000));
    }
    let raw =
        r#"{"schema":"openshell.provider-detach.witness-approval/v1","subject":"x","subject":"y"}"#;
    assert!(serde_json::from_str::<ProviderDetachWitnessApproval>(raw).is_err());
    let raw = r#"{"schema":"openshell.provider-detach.witness-approval/v1","unrecognized_authority":true}"#;
    assert!(serde_json::from_str::<ProviderDetachWitnessApproval>(raw).is_err());
}
#[test]
fn witness_digest_binds_incarnation_profile_and_arm() {
    let mut q = ProviderDetachWitnessRequestV1 {
        run_id: uuid::Uuid::new_v4().to_string(),
        profile_id: PROFILE_ID.into(),
        ..Default::default()
    };
    let before = request_digest(&q);
    q.request_sha256 = before.clone();
    assert_eq!(request_digest(&q), before);
    q.source_incarnation = uuid::Uuid::new_v4().to_string();
    assert_ne!(request_digest(&q), before);
    assert!(shape(&q).is_err());
}

fn metadata_identity(resource: &ProviderDetachResourceV1) -> Identity {
    let mut i = identity();
    i.provider_detach_witness_approval = None;
    i.scopes = vec![
        "sandbox:provider-detach:witness:read".into(),
        format!(
            "sandbox:provider-detach:target:{}",
            metadata_resource_digest(resource).unwrap()
        ),
    ];
    i
}
fn metadata_request(
    resource: &ProviderDetachResourceV1,
) -> Request<GetProviderDetachWitnessInvocationRequest> {
    let mut rpc = Request::new(GetProviderDetachWitnessInvocationRequest {
        workspace_scope: Some(workspace_selector(&resource.workspace)),
        capability_resources: vec![resource.clone()],
        ..Default::default()
    });
    rpc.extensions_mut()
        .insert(Principal::User(crate::auth::principal::UserPrincipal {
            identity: metadata_identity(resource),
        }));
    rpc
}
fn metadata_cap(resource: &ProviderDetachResourceV1) -> ProviderDetachWitnessControlV1 {
    ProviderDetachWitnessControlV1 {
        source_incarnation: uuid::Uuid::new_v4().to_string(),
        boundary_incarnation: uuid::Uuid::new_v4().to_string(),
        profile_sha256: "a".repeat(64),
        state: "capability".into(),
        execution_id: resource.execution_id.clone(),
        ..Default::default()
    }
}
async fn metadata_fixture() -> (
    Arc<ServerState>,
    ProviderDetachResourceV1,
    String,
    ProviderDetachWitnessControlV1,
    tokio::sync::mpsc::Receiver<GatewayMessage>,
) {
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    let mut state = crate::grpc::test_support::test_server_state_without_provider_profiles().await;
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.config.name = "gateway-a".into();
    mutable.config.oidc=Some(serde_json::from_value(serde_json::json!({"issuer":"https://issuer.example.test","audience":"fixture","scopes_claim":"scope","admin_role":"admin","user_role":"user"})).unwrap());
    let sandbox_id = uuid::Uuid::new_v4().to_string();
    let provider_id = uuid::Uuid::new_v4().to_string();
    let mut sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: sandbox_id.clone(),
            name: "agent".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            providers: vec![],
            ..Default::default()
        }),
        status: Some(SandboxStatus {
            phase: SandboxPhase::Ready as i32,
            ..Default::default()
        }),
        ..Default::default()
    };
    crate::auth::sandbox_session::PersistedSandboxIdentity::new()
        .unwrap()
        .write(&mut sandbox.metadata.as_mut().unwrap().annotations);
    let execution_id = crate::auth::sandbox_session::sandbox_execution_id(&sandbox).unwrap();
    state.store.put_message(&sandbox).await.unwrap();
    state
        .store
        .put_message(&Provider {
            metadata: Some(ObjectMeta {
                id: provider_id.clone(),
                name: "model".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    state
        .store
        .put_message(&WorkspaceMember {
            metadata: Some(ObjectMeta {
                id: uuid::Uuid::new_v4().to_string(),
                name: "approved-user".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            principal_subject: "approved-user".into(),
            role: WorkspaceRole::User as i32,
        })
        .await
        .unwrap();
    let resource = ProviderDetachResourceV1 {
        authority: "gateway-a".into(),
        workspace: "default".into(),
        sandbox: "agent".into(),
        sandbox_id,
        execution_id,
        provider: "model".into(),
        provider_id,
    };
    let session = uuid::Uuid::new_v4().to_string();
    let cap = metadata_cap(&resource);
    let rx = state.supervisor_sessions.witness_metadata_fixture(
        &resource.sandbox_id,
        &session,
        Some(cap.clone()),
        true,
    );
    (state, resource, session, cap, rx)
}
#[test]
fn witness_metadata_modes_and_decoded_wire_bind_complete_object() {
    let resource = ProviderDetachResourceV1 {
        authority: "a".into(),
        workspace: "default".into(),
        sandbox: "s".into(),
        sandbox_id: "i".into(),
        execution_id: format!("exec-v1:{}", "a".repeat(64)),
        provider: "p".into(),
        provider_id: "j".into(),
    };
    let valid = metadata_request(&resource).into_inner();
    assert!(query_metadata_mode(&valid).unwrap());
    for case in 0..7 {
        let mut q = valid.clone();
        match case {
            0 => q.capability_resources.clear(),
            1 => q.request = Some(Default::default()),
            2 => q.capability_resources.push(resource.clone()),
            3 => {
                let mut r = resource.clone();
                r.provider_id = "other".into();
                q.capability_resources.push(r)
            }
            4 => q.capability_resources[0] = Default::default(),
            5 => q.capability_resources[0].provider = "x".repeat(13000),
            _ => q.capability_resources[0].execution_id = "label".into(),
        };
        assert!(query_metadata_mode(&q).is_err(), "mode case {case}");
    }
    let original = GetProviderDetachWitnessInvocationRequest {
        request: Some(Default::default()),
        ..Default::default()
    };
    assert!(!query_metadata_mode(&original).unwrap());
    // Scalar last-wins and embedded-message merge are real prost decode behavior.
    let one = GetProviderDetachWitnessInvocationRequest {
        request: Some(ProviderDetachWitnessRequestV1 {
            run_id: "earlier".into(),
            source_incarnation: "retained".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let two = GetProviderDetachWitnessInvocationRequest {
        request: Some(ProviderDetachWitnessRequestV1 {
            run_id: "later".into(),
            boundary_incarnation: "merged".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let wire = [one.encode_to_vec(), two.encode_to_vec()].concat();
    let q = GetProviderDetachWitnessInvocationRequest::decode(wire.as_slice()).unwrap();
    let final_object = q.request.unwrap();
    assert_eq!(final_object.run_id, "later");
    assert_eq!(final_object.source_incarnation, "retained");
    assert_eq!(final_object.boundary_incarnation, "merged");
    assert_ne!(
        request_digest(&final_object),
        request_digest(one.request.as_ref().unwrap())
    );
    assert!(shape(&final_object).is_err());
    let mixed = [one.encode_to_vec(), valid.encode_to_vec()].concat();
    assert!(
        query_metadata_mode(
            &GetProviderDetachWitnessInvocationRequest::decode(mixed.as_slice()).unwrap()
        )
        .is_err()
    );
}
#[test]
fn witness_metadata_authority_is_separate_read_and_not_approval() {
    let r = ProviderDetachResourceV1 {
        authority: "a".into(),
        workspace: "default".into(),
        sandbox: "s".into(),
        sandbox_id: "i".into(),
        execution_id: format!("exec-v1:{}", "a".repeat(64)),
        provider: "p".into(),
        provider_id: "j".into(),
    };
    let good = metadata_identity(&r);
    let policy = AuthzPolicy {
        admin_role: "admin".into(),
        user_role: "user".into(),
        scopes_enabled: true,
    };
    let digest = metadata_resource_digest(&r).unwrap();
    assert!(good.provider_detach_witness_approval.is_none());
    assert!(
        crate::auth::authz::check_provider_witness_metadata_grant(&good, &policy, &digest).is_ok()
    );
    assert!(!grant(&good, false, 1));
    let disabled = AuthzPolicy {
        scopes_enabled: false,
        ..policy.clone()
    };
    assert!(
        crate::auth::authz::check_provider_witness_metadata_grant(&good, &disabled, &digest)
            .is_err()
    );
    for policy in [
        AuthzPolicy {
            admin_role: String::new(),
            ..policy.clone()
        },
        AuthzPolicy {
            user_role: String::new(),
            ..policy.clone()
        },
    ] {
        assert!(
            crate::auth::authz::check_provider_witness_metadata_grant(&good, &policy, &digest)
                .is_err()
        );
    }
    for case in 0..13 {
        let mut i = good.clone();
        match case {
            0 => i.provider = IdentityProvider::Mtls,
            1 => i.roles.push("admin".into()),
            2 => i.roles.clear(),
            3 => i.scopes.clear(),
            4 => i.scopes[1] = format!("sandbox:provider-detach:target:{}", "b".repeat(64)),
            5 => i.scopes.push("sandbox:provider-detach:witness".into()),
            6 => i.scopes[0] = "sandbox:provider-detach:witness".into(),
            7 => i.scopes.push("*".into()),
            8 => i.scopes.push("sandbox:*".into()),
            9 => i.scopes.push("sandbox:exec".into()),
            10 => {
                i.roles.push("admin".into());
                i.scopes.push("*".into())
            }
            11 => i.provider = IdentityProvider::LocalDev,
            _ => i.scopes.push("openid".into()),
        };
        assert!(
            crate::auth::authz::check_provider_witness_metadata_grant(&i, &policy, &digest)
                .is_err(),
            "auth case{case}"
        )
    }
}
#[tokio::test]
async fn witness_metadata_actual_rows_zero_attachment_and_zero_effects() {
    let (state, r, session, cap, mut rx) = metadata_fixture().await;
    let before = metadata_rows(&state, &r).await.unwrap();
    let fence = state.store.provider_detach_fence().await.unwrap();
    for _ in 0..2 {
        let response = discovery(&state, &metadata_request(&r), &r, &cap.profile_sha256, None)
            .await
            .unwrap();
        assert!(response.invocation.is_none());
        assert_eq!(response.capability, Some(cap.clone()));
        assert_eq!(response.capability_resource, Some(r.clone()));
        assert_eq!(response.capability_supervisor_session, session)
    }
    assert_eq!(metadata_rows(&state, &r).await.unwrap(), before);
    assert!(state.store.provider_detach_fence().await.unwrap() == fence);
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(
        state
            .store
            .read_provider_witness_original("not-created", &"a".repeat(64))
            .await
            .unwrap()
            .is_none()
    );
    let mut sandbox = Sandbox::decode(before.2.as_slice()).unwrap();
    sandbox.spec.as_mut().unwrap().providers = vec![r.provider.clone()];
    state.store.put_message(&sandbox).await.unwrap();
    assert!(
        discovery(&state, &metadata_request(&r), &r, &cap.profile_sha256, None)
            .await
            .is_ok()
    );
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .providers
        .push(r.provider.clone());
    state.store.put_message(&sandbox).await.unwrap();
    assert!(
        discovery(&state, &metadata_request(&r), &r, &cap.profile_sha256, None)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn witness_metadata_resource_and_workspace_substitutions_refuse() {
    let (state, r, _, cap, _) = metadata_fixture().await;
    for case in 0..8 {
        let mut wrong = r.clone();
        match case {
            0 => wrong.authority = "other".into(),
            1 => wrong.workspace = "foreign".into(),
            2 => wrong.sandbox = "renamed".into(),
            3 => wrong.sandbox_id = uuid::Uuid::new_v4().to_string(),
            4 => wrong.provider = "renamed".into(),
            5 => wrong.provider_id = uuid::Uuid::new_v4().to_string(),
            6 => wrong.execution_id = format!("exec-v1:{}", "b".repeat(64)),
            _ => wrong.provider_id.clear(),
        };
        assert!(
            discovery(
                &state,
                &metadata_request(&wrong),
                &wrong,
                &cap.profile_sha256,
                None
            )
            .await
            .is_err(),
            "resource case{case}"
        )
    }
    let mut rpc = metadata_request(&r);
    rpc.extensions_mut().remove::<Principal>();
    assert!(
        discovery(&state, &rpc, &r, &cap.profile_sha256, None)
            .await
            .is_err()
    );
    let mut rpc = metadata_request(&r);
    rpc.get_mut().workspace_scope = Some(workspace_selector("foreign"));
    assert!(
        discovery(&state, &rpc, &r, &cap.profile_sha256, None)
            .await
            .is_err()
    );
    let mut rpc = metadata_request(&r);
    let Some(Principal::User(user)) = rpc.extensions_mut().get_mut::<Principal>() else {
        panic!()
    };
    user.identity.subject = "nonmember".into();
    assert!(
        discovery(&state, &rpc, &r, &cap.profile_sha256, None)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn witness_metadata_session_states_and_closing_replacements_refuse() {
    let (state, r, session, cap, _) = metadata_fixture().await;
    for case in 0..9 {
        let mut changed = cap.clone();
        let initialized = case != 0;
        let replacement = if case == 1 {
            None
        } else {
            match case {
                2 => changed.execution_id = format!("exec-v1:{}", "b".repeat(64)),
                3 => changed.profile_sha256 = "b".repeat(64),
                4 => changed.source_incarnation = uuid::Uuid::nil().to_string(),
                5 => changed.boundary_incarnation = "invalid".into(),
                6 => changed.state = "unknown".into(),
                7 => changed.original_key = "not-metadata".into(),
                8 => changed.request_sha256 = "a".repeat(64),
                _ => {}
            };
            Some(changed)
        };
        let _rx = state.supervisor_sessions.witness_metadata_fixture(
            &r.sandbox_id,
            &session,
            replacement,
            initialized,
        );
        assert!(
            discovery(&state, &metadata_request(&r), &r, &cap.profile_sha256, None)
                .await
                .is_err(),
            "session case{case}"
        )
    }
    for phase in 1..=3 {
        let _rx = state.supervisor_sessions.witness_metadata_fixture(
            &r.sandbox_id,
            &session,
            Some(cap.clone()),
            true,
        );
        let next = uuid::Uuid::new_v4().to_string();
        let changed = metadata_cap(&r);
        let hook = |point| {
            if point == phase {
                let _rx = state.supervisor_sessions.witness_metadata_fixture(
                    &r.sandbox_id,
                    &next,
                    Some(changed.clone()),
                    true,
                );
            }
        };
        // Replacement before the first registry read is a valid fresh snapshot;
        // replacements after it must fail the closing association.
        let result = discovery(
            &state,
            &metadata_request(&r),
            &r,
            &cap.profile_sha256,
            Some(&hook),
        )
        .await;
        if phase == 1 {
            assert_eq!(result.unwrap().capability_supervisor_session, next)
        } else {
            assert!(result.is_err())
        }
    }
    state.supervisor_sessions.disconnect(&r.sandbox_id);
    assert!(
        discovery(&state, &metadata_request(&r), &r, &cap.profile_sha256, None)
            .await
            .is_err()
    );
    state.supervisor_sessions.poison_witness_metadata_fixture();
    assert_eq!(
        discovery(&state, &metadata_request(&r), &r, &cap.profile_sha256, None)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn witness_metadata_row_replacement_at_closing_check_refuses() {
    let (state, r, _, cap, _) = metadata_fixture().await;
    let rows = metadata_rows(&state, &r).await.unwrap();
    let mut changed = Sandbox::decode(rows.2.as_slice()).unwrap();
    changed.status.as_mut().unwrap().phase = SandboxPhase::Stopped as i32;
    let hook = |phase| {
        if phase == 2 {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(state.store.put_message(&changed))
            })
            .unwrap();
        }
    };
    assert!(
        discovery(
            &state,
            &metadata_request(&r),
            &r,
            &cap.profile_sha256,
            Some(&hook)
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn witness_metadata_reconnect_never_rebinds_original_nonce() {
    let (state, r, session, cap, _) = metadata_fixture().await;
    let initial = discovery(&state, &metadata_request(&r), &r, &cap.profile_sha256, None)
        .await
        .unwrap();
    let attempt = ProviderDetachAttemptV1 {
        sandbox_id: r.sandbox_id.clone(),
        execution_id: r.execution_id.clone(),
        supervisor_session: session.clone(),
        supervisor_instance: session,
        ..Default::default()
    };
    let old = ProviderDetachWitnessRequestV1 {
        source_incarnation: cap.source_incarnation.clone(),
        boundary_incarnation: cap.boundary_incarnation.clone(),
        profile_sha256: cap.profile_sha256.clone(),
        installed_arm: Some(ProviderDetachArmSealV1 {
            request: Some(ProviderDetachArmRequestV1 {
                attempt: Some(attempt.clone()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(
        state
            .supervisor_sessions
            .check_provider_witness_capability(&r.sandbox_id, &attempt, &old)
            .is_ok()
    );
    for variant in 0..4 {
        let mut substituted = cap.clone();
        match variant {
            0 => substituted.source_incarnation = uuid::Uuid::new_v4().to_string(),
            1 => substituted.boundary_incarnation = uuid::Uuid::new_v4().to_string(),
            2 => substituted.profile_sha256 = "b".repeat(64),
            _ => substituted.execution_id = format!("exec-v1:{}", "b".repeat(64)),
        };
        let _rx = state.supervisor_sessions.witness_metadata_fixture(
            &r.sandbox_id,
            &attempt.supervisor_session,
            Some(substituted),
            true,
        );
        assert!(
            state
                .supervisor_sessions
                .check_provider_witness_capability(&r.sandbox_id, &attempt, &old)
                .is_err()
        );
    }
    let new = metadata_cap(&r);
    let _rx = state.supervisor_sessions.witness_metadata_fixture(
        &r.sandbox_id,
        &uuid::Uuid::new_v4().to_string(),
        Some(new.clone()),
        true,
    );
    let now = discovery(&state, &metadata_request(&r), &r, &cap.profile_sha256, None)
        .await
        .unwrap();
    assert_ne!(now.capability, initial.capability);
    assert_eq!(old.source_incarnation, cap.source_incarnation);
    assert!(
        state
            .supervisor_sessions
            .check_provider_witness_capability(&r.sandbox_id, &attempt, &old)
            .is_err()
    );
    assert!(
        state
            .supervisor_sessions
            .send_provider_witness_once(&r.sandbox_id, &old)
            .is_err()
    );
}

fn history_target() -> ProviderDetachTargetV1 {
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

fn history_action() -> ProviderDetachActionV1 {
    use openshell_core::proto::{
        ProviderDetachIntentV1, ProviderDetachOriginalIntentV1, ProviderDetachSourceTargetV1,
    };
    let target = history_target();
    let target_sha256 =
        "6389f95c089e24f49bf59f7966fbc3ee09d045ec19816d54c31244a1a56854d2".to_string();
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
#[tokio::test]
async fn witness_historical_read_keeps_exact_approval_without_current_session() {
    let (state, r, _, cap, mut rx) = metadata_fixture().await;
    let action = history_action();
    let target = action.target.as_ref().unwrap();
    let hold = uuid::Uuid::new_v4().to_string();
    let receipt_id = uuid::Uuid::new_v4().to_string();
    let attempt_id = uuid::Uuid::new_v4().to_string();
    let receipt = ProviderDetachReceiptV1 {
        action_id: action.action_id.clone(),
        target: action.target.clone(),
        hold_id: hold.clone(),
        native_receipt_id: receipt_id.clone(),
        ..Default::default()
    };
    let attempt = ProviderDetachAttemptV1 {
        action_id: action.action_id.clone(),
        hold_id: hold.clone(),
        native_receipt_id: receipt_id.clone(),
        execution_id: target.execution_id.clone(),
        provider_id: target.provider_id.clone(),
        deadline: Some(prost_types::Timestamp {
            seconds: 2,
            nanos: 0,
        }),
        sandbox_id: target.sandbox_id.clone(),
        supervisor_session: uuid::Uuid::new_v4().to_string(),
        supervisor_instance: uuid::Uuid::new_v4().to_string(),
        ..Default::default()
    };
    let seal = ProviderDetachArmSealV1 {
        request: Some(ProviderDetachArmRequestV1 {
            original_action: Some(action.clone()),
            original_receipt: Some(receipt),
            attempt: Some(attempt),
            attempt_id: attempt_id.clone(),
            ..Default::default()
        }),
        install_sequence: 1,
        hold_generation: 1,
        row_resource_version: 1,
        installed_time: Some(prost_types::Timestamp {
            seconds: 1,
            nanos: 0,
        }),
    };
    let mut q = ProviderDetachWitnessRequestV1 {
        run_id: uuid::Uuid::new_v4().to_string(),
        profile_id: PROFILE_ID.into(),
        profile_sha256: cap.profile_sha256.clone(),
        source_incarnation: cap.source_incarnation.clone(),
        boundary_incarnation: cap.boundary_incarnation.clone(),
        installed_arm: Some(seal.clone()),
        ..Default::default()
    };
    q.request_sha256 = request_digest(&q);
    shape(&q).unwrap();
    let mut i = identity();
    let approval = i.provider_detach_witness_approval.as_mut().unwrap();
    approval.action_id = action.action_id;
    approval.run_id = q.run_id.clone();
    approval.hold_id = hold;
    approval.native_receipt_id = receipt_id;
    approval.attempt_id = attempt_id;
    approval.profile_sha256 = q.profile_sha256.clone();
    approval.request_sha256 = q.request_sha256.clone();
    approval.resource_sha256 = resource_digest(target).unwrap();
    approval.installed_arm_sha256 = format!("{:x}", Sha256::digest(seal.encode_to_vec()));
    i.scopes = vec![
        "sandbox:provider-detach:witness:read".into(),
        format!(
            "sandbox:provider-detach:target:{}",
            approval.resource_sha256
        ),
    ];
    let request = |i: Identity| {
        let mut rpc = Request::new(GetProviderDetachWitnessInvocationRequest {
            workspace_scope: Some(workspace_selector("default")),
            request: Some(q.clone()),
            ..Default::default()
        });
        rpc.extensions_mut()
            .insert(Principal::User(crate::auth::principal::UserPrincipal {
                identity: i,
            }));
        rpc
    };
    let before = query(&state, request(i.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(before.capability.is_none());
    assert_eq!(before.invocation.as_ref().unwrap().state, "unknown");
    // Start from a fully authorized original and merge a second embedded
    // request occurrence. Retaining its old hash cannot authorize the changed
    // final decoded source incarnation; do not authorize the first occurrence.
    let original_wire = request(i.clone()).get_ref().encode_to_vec();
    let fragment = GetProviderDetachWitnessInvocationRequest {
        request: Some(ProviderDetachWitnessRequestV1 {
            source_incarnation: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        }),
        ..Default::default()
    }
    .encode_to_vec();
    let merged = GetProviderDetachWitnessInvocationRequest::decode(
        [original_wire, fragment].concat().as_slice(),
    )
    .unwrap();
    assert_ne!(
        request_digest(merged.request.as_ref().unwrap()),
        q.request_sha256
    );
    let mut altered = Request::new(merged);
    altered
        .extensions_mut()
        .insert(Principal::User(crate::auth::principal::UserPrincipal {
            identity: i.clone(),
        }));
    assert_eq!(
        query(&state, altered).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    state.supervisor_sessions.disconnect(&r.sandbox_id);
    let after = query(&state, request(i.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(before, after);
    i.provider_detach_witness_approval = None;
    assert!(query(&state, request(i)).await.is_err());
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));
}
#[tokio::test]
async fn witness_metadata_without_compiled_profile_remains_unsupported() {
    if openshell_core::provider_credentials::fixed_provider_witness_profile().is_none() {
        let (state, r, _, _, _) = metadata_fixture().await;
        assert_eq!(
            query(&state, metadata_request(&r))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unimplemented
        );
    }
}
#[tokio::test]
async fn witness_metadata_nonuser_and_disabled_scope_enforcement_refuse() {
    use crate::auth::principal::{PeerPrincipal, SandboxIdentitySource, SandboxPrincipal};
    let (mut state, r, _, cap, mut rx) = metadata_fixture().await;
    for principal in [
        Principal::Anonymous,
        Principal::Peer(PeerPrincipal {
            replica_id: "peer".into(),
            pod_uid: uuid::Uuid::new_v4().to_string(),
        }),
        Principal::Sandbox(SandboxPrincipal {
            sandbox_id: r.sandbox_id.clone(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "gateway".into(),
            },
            trust_domain: None,
        }),
    ] {
        let mut rpc = metadata_request(&r);
        rpc.extensions_mut().insert(principal);
        assert_eq!(
            discovery(&state, &rpc, &r, &cap.profile_sha256, None)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        )
    }
    Arc::get_mut(&mut state)
        .unwrap()
        .config
        .oidc
        .as_mut()
        .unwrap()
        .scopes_claim
        .clear();
    assert_eq!(
        discovery(&state, &metadata_request(&r), &r, &cap.profile_sha256, None)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}
#[tokio::test]
async fn witness_metadata_terminating_workspace_refuses_without_effect() {
    let (state, r, _, cap, mut rx) = metadata_fixture().await;
    let mut workspace = state
        .store
        .get_message_by_name::<Workspace>("", "default")
        .await
        .unwrap()
        .unwrap();
    workspace.metadata.as_mut().unwrap().deletion_time = Some(prost_types::Timestamp {
        seconds: 1,
        nanos: 0,
    });
    state.store.put_message(&workspace).await.unwrap();
    let before = metadata_rows(&state, &r).await.unwrap();
    let fence = state.store.provider_detach_fence().await.unwrap();
    let result = discovery(&state, &metadata_request(&r), &r, &cap.profile_sha256, None)
        .await
        .unwrap_err();
    assert_eq!(result.code(), tonic::Code::FailedPrecondition);
    assert_eq!(result.message(), "witness workspace unavailable");
    assert_eq!(metadata_rows(&state, &r).await.unwrap(), before);
    assert!(state.store.provider_detach_fence().await.unwrap() == fence);
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}
