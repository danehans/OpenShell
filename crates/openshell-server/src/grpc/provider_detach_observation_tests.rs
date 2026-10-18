// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::auth::{
    authz::{AuthzPolicy, check_ordinary_observation_grant},
    identity::{Identity, IdentityProvider},
};
use crate::persistence::{PROVIDER_OBSERVATION_OBJECT_TYPE, ordinary_key};
use openshell_core::proto::{Provider, ProviderObservationWindowV1, SandboxSpec, SandboxStatus};
fn identity() -> Identity {
    Identity {
        subject: "approved-user".into(),
        display_name: None,
        roles: vec!["user".into()],
        scopes: vec![
            "sandbox:provider-detach:observe".into(),
            "sandbox:provider-detach:observe:read".into(),
            format!("sandbox:provider-detach:target:{}", "a".repeat(64)),
        ],
        provider: IdentityProvider::Oidc,
        provider_detach_witness_approval: None,
    }
}
fn policy() -> AuthzPolicy {
    AuthzPolicy {
        admin_role: "admin".into(),
        user_role: "user".into(),
        scopes_enabled: true,
    }
}
#[test]
fn ordinary_observation_auth_is_narrow_without_fixed_approval() {
    let original = identity();
    assert!(check_ordinary_observation_grant(&original, &policy(), &"a".repeat(64), true).is_ok());
    assert!(check_ordinary_observation_grant(&original, &policy(), &"a".repeat(64), false).is_ok());
    for case in 0..9 {
        let mut i = original.clone();
        let mut p = policy();
        match case {
            0 => p.scopes_enabled = false,
            1 => i.roles.push("admin".into()),
            2 => i.roles.clear(),
            3 => i.subject.clear(),
            4 => i.scopes.push("openshell:all".into()),
            5 => i.scopes.push("sandbox:exec".into()),
            6 => i
                .scopes
                .retain(|s| !s.starts_with("sandbox:provider-detach:target:")),
            7 => i.scopes.retain(|s| s != "sandbox:provider-detach:observe"),
            _ => p.user_role.clear(),
        }
        assert!(
            check_ordinary_observation_grant(&i, &p, &"a".repeat(64), true).is_err(),
            "case{case}"
        );
    }
}
#[test]
fn ordinary_observation_final_decoded_modes_refuse_mixed() {
    let r = ProviderDetachResourceV1 {
        authority: "gateway".into(),
        ..Default::default()
    };
    let first = GetProviderDetachObservationRequest {
        resource: Some(r),
        ..Default::default()
    };
    assert!(resource(&first).is_ok());
    let second = GetProviderDetachObservationRequest {
        original_request: Some(Default::default()),
        ..Default::default()
    };
    let wire = [first.encode_to_vec(), second.encode_to_vec()].concat();
    let decoded = GetProviderDetachObservationRequest::decode(wire.as_slice()).unwrap();
    assert!(resource(&decoded).is_err());
    assert!(resource(&Default::default()).is_err());
}
async fn store_fixture() -> (Arc<ServerState>, ProviderObservationRequestV1) {
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    let state = crate::grpc::test_support::test_server_state_without_provider_profiles().await;
    let mut sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: "agent".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            providers: vec!["model".into()],
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
    let provider = Provider {
        metadata: Some(ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: "model".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&sandbox).await.unwrap();
    state.store.put_message(&provider).await.unwrap();
    let r = ProviderDetachResourceV1 {
        authority: "gateway".into(),
        workspace: "default".into(),
        sandbox: "agent".into(),
        sandbox_id: sandbox.metadata.as_ref().unwrap().id.clone(),
        execution_id: crate::auth::sandbox_session::sandbox_execution_id(&sandbox).unwrap(),
        provider: "model".into(),
        provider_id: provider.metadata.as_ref().unwrap().id.clone(),
    };
    let mut q = ProviderObservationRequestV1 {
        resource: Some(r),
        run_id: uuid::Uuid::new_v4().to_string(),
        step_id: uuid::Uuid::new_v4().to_string(),
        profile_id: obs::PROFILE.into(),
        profile_sha256: obs::profile_digest(),
        source_incarnation: uuid::Uuid::new_v4().to_string(),
        boundary_incarnation: uuid::Uuid::new_v4().to_string(),
        deadline: Some(obs::timestamp(
            crate::persistence::current_time_ms() + 60000,
        )),
        phase: ProviderObservationPhaseV1::Baseline as i32,
        evidence_scope: obs::EVIDENCE_SCOPE.into(),
        ..Default::default()
    };
    q.request_sha256 = obs::request_digest(&q);
    (state, q)
}
fn expected_snapshot(q: &ProviderObservationRequestV1) -> ProviderObservationSnapshotV1 {
    let mut snapshot = ProviderObservationSnapshotV1 {
        resource: q.resource.clone(),
        source_incarnation: q.source_incarnation.clone(),
        boundary_incarnation: q.boundary_incarnation.clone(),
        profile_id: obs::PROFILE.into(),
        profile_sha256: obs::profile_digest(),
        evidence_scope: obs::EVIDENCE_SCOPE.into(),
        process_writer_attribution: obs::WRITER_UNPROVEN,
        mediation_path_id: uuid::Uuid::new_v4().to_string(),
        gateway_boot_id: uuid::Uuid::new_v4().to_string(),
        supervisor_instance: uuid::Uuid::new_v4().to_string(),
        supervisor_session: uuid::Uuid::new_v4().to_string(),
        configuration_sha256: "a".repeat(64),
        policy_generation: 1,
        resolver_generation: 1,
        ..Default::default()
    };
    snapshot.mediation_path_receipt_sha256 = obs::path_digest(&snapshot);
    snapshot
}
#[tokio::test]
async fn ordinary_observation_actual_sqlite_original_race_and_no_crud_reopen() {
    let (state, q) = store_fixture().await;
    let fence = state.store.provider_detach_fence().await.unwrap();
    let expected = expected_snapshot(&q);
    let (a, b) = tokio::join!(
        state
            .store
            .claim_ordinary_observation(&q, &fence, &expected),
        state
            .store
            .claim_ordinary_observation(&q, &fence, &expected)
    );
    assert_ne!(a.unwrap(), b.unwrap());
    let key = ordinary_key(&q);
    assert!(
        state
            .store
            .delete(PROVIDER_OBSERVATION_OBJECT_TYPE, &key)
            .await
            .is_err()
    );
    assert!(
        state
            .store
            .delete_many(PROVIDER_OBSERVATION_OBJECT_TYPE, &[key.clone()])
            .await
            .is_err()
    );
    assert!(
        state
            .store
            .delete_all_in_workspace(PROVIDER_OBSERVATION_OBJECT_TYPE, "default")
            .await
            .is_err()
    );
    assert!(
        !state
            .store
            .claim_ordinary_observation(&q, &fence, &expected)
            .await
            .unwrap()
    );
    let mut conflict = q.clone();
    conflict.source_incarnation = uuid::Uuid::new_v4().to_string();
    conflict.request_sha256 = obs::request_digest(&conflict);
    assert!(
        state
            .store
            .claim_ordinary_observation(&conflict, &fence, &expected)
            .await
            .is_err()
    );
    assert!(state.store.ordinary_history(&q).await.unwrap().is_none()); // pending is unknown, not a new sender
}
#[tokio::test]
async fn ordinary_observation_sqlite_actual_changed_rows_and_deadline_refuse() {
    let (state, mut q) = store_fixture().await;
    let fence = state.store.provider_detach_fence().await.unwrap();
    let expected = expected_snapshot(&q);
    q.deadline = Some(obs::timestamp(crate::persistence::current_time_ms()));
    q.request_sha256 = obs::request_digest(&q);
    assert!(
        state
            .store
            .claim_ordinary_observation(&q, &fence, &expected)
            .await
            .is_err()
    );
    q.deadline = Some(obs::timestamp(
        crate::persistence::current_time_ms() + 60000,
    ));
    q.request_sha256 = obs::request_digest(&q);
    state
        .store
        .delete("provider", &q.resource.as_ref().unwrap().provider_id)
        .await
        .unwrap();
    assert!(
        state
            .store
            .claim_ordinary_observation(&q, &fence, &expected)
            .await
            .is_err()
    );
}
#[test]
fn ordinary_observation_descriptor_auth_is_explicit_and_distinct() {
    for (method, scope) in [
        (
            "BeginProviderDetachObservation",
            "sandbox:provider-detach:observe",
        ),
        (
            "GetProviderDetachObservation",
            "sandbox:provider-detach:observe:read",
        ),
    ] {
        let entry = crate::auth::method_authz::lookup(&format!("/openshell.v1.OpenShell/{method}"))
            .expect("declared method");
        assert!(matches!(
            entry.auth_mode,
            crate::auth::method_authz::AuthMode::Bearer
        ));
        // Descriptor authority is checked by the real middleware tables, not a caller flag.
        let mut i = identity();
        i.scopes = vec![scope.into()];
        assert!(
            policy()
                .check(&i, &format!("/openshell.v1.OpenShell/{method}"))
                .is_ok()
        );
    }
}

#[tokio::test]
async fn ordinary_observation_retained_original_snapshot_rejects_config_adoption() {
    let (state, q) = store_fixture().await;
    let expected = expected_snapshot(&q);
    let fence = state.store.provider_detach_fence().await.unwrap();
    assert!(
        state
            .store
            .claim_ordinary_observation(&q, &fence, &expected)
            .await
            .unwrap()
    );
    let mut result = ProviderObservationResultV1 {
        state: ProviderObservationStateV1::Unknown as i32,
        window: Some(ProviderObservationWindowV1 {
            request: Some(q.clone()),
            installed_snapshot: Some(expected.clone()),
            ingress_watermark: expected.current_ingress_sequence,
            ..Default::default()
        }),
        ..Default::default()
    };
    // A report cannot adopt a new configuration between the original fresh read and installation.
    result
        .window
        .as_mut()
        .unwrap()
        .installed_snapshot
        .as_mut()
        .unwrap()
        .configuration_sha256 = "b".repeat(64);
    result.terminal_sha256 = obs::terminal_digest(&result);
    assert!(
        state
            .store
            .retain_ordinary_result(&q, &result)
            .await
            .is_err()
    );
    assert!(state.store.ordinary_history(&q).await.unwrap().is_none());
    result.window.as_mut().unwrap().installed_snapshot = Some(expected);
    result.terminal_sha256 = obs::terminal_digest(&result);
    state
        .store
        .retain_ordinary_result(&q, &result)
        .await
        .unwrap();
    assert_eq!(
        state.store.ordinary_history(&q).await.unwrap(),
        Some(result)
    );
}
