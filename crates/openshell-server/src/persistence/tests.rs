// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{ObjectListQuery, ObjectType, PersistenceError, Store, generate_name, test_store};
use crate::policy_store::{AtomicPolicyRevisionWrite, PolicyStoreExt};
use openshell_core::proto::datamodel::v1::ObjectMeta as ProtoObjectMeta;
use openshell_core::proto::{ObjectForTest, Sandbox, SandboxPolicy, SandboxSpec};
use prost::Message;
use std::collections::HashMap as StdHashMap;

// Storage-only fixtures: these do not authenticate an approval or authorize a
// runtime send. The RPC/source/boundary gates remain independent prerequisites.
async fn provider_witness_storage_fixture() -> (Store, super::ProviderDetachWitnessPlan) {
    use openshell_core::proto::{
        ProviderDetachArmRequestV1, ProviderDetachArmSealV1, ProviderDetachAttemptV1,
    };
    let (store, detach) = provider_detach_commit_fixture().await;
    let result = store.commit_provider_detach(&detach).await.unwrap();
    assert_eq!(result.state, "applied");
    let now = super::current_time_ms();
    let deadline = now + 60_000;
    let arm = ProviderDetachArmSealV1 {
        request: Some(ProviderDetachArmRequestV1 {
            original_action: Some(detach.action.clone()),
            original_receipt: Some(detach.receipt.clone()),
            attempt: Some(ProviderDetachAttemptV1 {
                deadline: openshell_core::time::timestamp_from_millis(deadline).ok(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        hold_generation: 1,
        row_resource_version: 1,
        install_sequence: 42,
        installed_time: openshell_core::time::timestamp_from_millis(now).ok(),
        ..Default::default()
    };
    let target = detach.action.target.as_ref().unwrap();
    let sandbox = store
        .get("sandbox", &target.sandbox_id)
        .await
        .unwrap()
        .unwrap();
    let binding = super::ProviderDetachWitnessBinding {
        authority: target.authority.clone(),
        run_id: uuid::Uuid::new_v4().to_string(),
        action_id: detach.action.action_id.clone(),
        request_sha256: "a".repeat(64),
        profile_sha256: "b".repeat(64),
        original_action: detach.action.encode_to_vec(),
        original_receipt: detach.receipt.encode_to_vec(),
        installed_arm: arm.encode_to_vec(),
        hold_generation: 1,
        hold_resource_version: 1,
        sandbox_resource_version: sandbox.resource_version,
        provider_resource_version: 1,
        deadline_ms: deadline,
    };
    let fence = store.provider_detach_fence().await.unwrap();
    (store, super::ProviderDetachWitnessPlan { binding, fence })
}

#[tokio::test]
async fn provider_witness_first_claim_is_permanent_and_duplicates_never_select_sender() {
    let (store, plan) = provider_witness_storage_fixture().await;
    assert!(
        store
            .reserve_provider_detach_witness(&plan, true)
            .await
            .is_err()
    );
    assert!(
        !store
            .reserve_provider_detach_witness(&plan, false)
            .await
            .unwrap()
            .dispatch_claimed
    );
    let (one, two) = tokio::join!(
        store.reserve_provider_detach_witness(&plan, true),
        store.reserve_provider_detach_witness(&plan, true),
    );
    assert_ne!(one.is_ok(), two.is_ok());
    // Losing a commit reply supplies only readback of the original, not send
    // authority. Reading twice or reserving again cannot reset this tombstone.
    for _ in 0..2 {
        assert!(
            store
                .read_provider_detach_witness(&plan.binding)
                .await
                .unwrap()
                .unwrap()
                .dispatch_claimed
        );
        assert!(
            store
                .reserve_provider_detach_witness(&plan, false)
                .await
                .unwrap()
                .dispatch_claimed
        );
        assert!(
            store
                .reserve_provider_detach_witness(&plan, true)
                .await
                .is_err()
        );
    }
    let mut changed = plan.binding.clone();
    changed.request_sha256 = "c".repeat(64);
    assert_eq!(changed.original_key(), plan.binding.original_key());
    assert!(store.read_provider_detach_witness(&changed).await.is_err());
    let id = plan.binding.original_key();
    assert!(
        store
            .delete(super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE, &id)
            .await
            .is_err()
    );
    assert!(
        store
            .put(
                super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE,
                &id,
                &id,
                "default",
                b"{}",
                None
            )
            .await
            .is_err()
    );
    assert!(
        store
            .delete_all_in_workspace(super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE, "default")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn provider_witness_dependency_drift_between_external_read_and_transaction_refuses_both_phases()
 {
    for claim in [false, true] {
        let (store, plan) = provider_witness_storage_fixture().await;
        if claim {
            store
                .reserve_provider_detach_witness(&plan, false)
                .await
                .unwrap();
        }
        // A real DB dependency changes after the external fence was captured,
        // before the reserve/claim transaction begins.
        store
            .put(
                "gateway_settings",
                "changed",
                "changed",
                "",
                b"changed",
                None,
            )
            .await
            .unwrap();
        assert!(
            store
                .reserve_provider_detach_witness(&plan, claim)
                .await
                .is_err()
        );
        let original = store
            .read_provider_detach_witness(&plan.binding)
            .await
            .unwrap();
        assert_eq!(
            original.map(|v| v.dispatch_claimed),
            if claim { Some(false) } else { None }
        );
    }
}

#[tokio::test]
async fn provider_witness_actual_provider_replacement_refuses_even_with_refreshed_external_fence() {
    let (store, mut plan) = provider_witness_storage_fixture().await;
    store
        .reserve_provider_detach_witness(&plan, false)
        .await
        .unwrap();
    let action = openshell_core::proto::ProviderDetachActionV1::decode(
        plan.binding.original_action.as_slice(),
    )
    .unwrap();
    let target = action.target.unwrap();
    store.delete("provider", &target.provider_id).await.unwrap();
    let replacement = openshell_core::proto::Provider {
        metadata: Some(ProtoObjectMeta {
            id: "replacement".into(),
            name: target.provider.clone(),
            workspace: target.workspace.clone(),
            ..Default::default()
        }),
        ..Default::default()
    };
    store
        .put(
            "provider",
            "replacement",
            &target.provider,
            &target.workspace,
            &replacement.encode_to_vec(),
            None,
        )
        .await
        .unwrap();
    plan.fence = store.provider_detach_fence().await.unwrap();
    assert!(
        store
            .reserve_provider_detach_witness(&plan, true)
            .await
            .is_err()
    );
    assert!(
        !store
            .read_provider_detach_witness(&plan.binding)
            .await
            .unwrap()
            .unwrap()
            .dispatch_claimed
    );
}

/// A failed store call must be visible as a failure in the trace, not as a
/// span that merely happened to return nothing.
#[tokio::test]
async fn failed_store_calls_are_marked_on_the_span() {
    use crate::otel_tracing::test_exporter;

    let store = test_store().await;
    let traced = test_exporter::install_traced();
    store.close_for_test().await;
    store
        .get("sandbox", "failed-store-call")
        .await
        .expect_err("a closed pool fails the query");

    let span = traced.span_with("store.get", "object.id", "failed-store-call");

    assert!(
        matches!(span.status, opentelemetry::trace::Status::Error { .. }),
        "the span carries error status so trace UIs flag it, got {:?}",
        span.status
    );
}

/// Losing a `MustCreate` race is how callers learn a record already exists, so
/// the span must stay clean — otherwise every lease a replica does not win, and
/// every gateway restart, exports as a failure.
#[tokio::test]
#[ignore = "flaky under concurrent test execution"]
async fn expected_conflicts_leave_the_span_unmarked() {
    use crate::otel_tracing::test_exporter;

    let store = test_store().await;
    store
        .put(
            "workspace",
            "expected-conflict-first",
            "expected-conflict",
            "",
            b"payload",
            None,
        )
        .await
        .expect("seed conflicting record");

    let traced = test_exporter::install_traced();
    store
        .put_if(
            "workspace",
            "expected-conflict-second",
            "expected-conflict",
            "",
            b"payload",
            None,
            super::WriteCondition::MustCreate,
        )
        .await
        .expect_err("the name is already taken");

    let span = traced.span_with("store.put_if", "object.id", "expected-conflict-second");

    assert_eq!(
        span.status,
        opentelemetry::trace::Status::Unset,
        "a unique violation is a return value the caller acts on, got {:?}",
        span.status
    );
}

/// Span names stay low-cardinality so they group across object types; what
/// each call touched is carried as attributes.
#[tokio::test]
#[ignore = "flaky under concurrent test execution"]
async fn store_spans_record_what_they_touched_as_attributes() {
    use crate::otel_tracing::test_exporter;

    let store = test_store().await;
    store
        .put("sandbox", "abc", "my-sandbox", "default", b"payload", None)
        .await
        .unwrap();

    let traced = test_exporter::install_traced();
    store.get("sandbox", "abc").await.unwrap();
    store
        .get_by_name("sandbox", "default", "my-sandbox")
        .await
        .unwrap();
    store.list("sandbox", "default", 10, 0).await.unwrap();

    let by_name = traced.span_with("store.get_by_name", "object.name", "my-sandbox");
    assert_eq!(
        test_exporter::attribute(&by_name, "object_type").as_deref(),
        Some("sandbox"),
        "the span records which type it queried"
    );

    traced.span_with("store.get", "object.id", "abc");
    traced.span_with("store.list", "object_type", "sandbox");
}

#[tokio::test]
async fn sqlite_put_get_round_trip() {
    let store = test_store().await;

    store
        .put("sandbox", "abc", "my-sandbox", "default", b"payload", None)
        .await
        .unwrap();

    let record = store.get("sandbox", "abc").await.unwrap().unwrap();
    assert_eq!(record.object_type, "sandbox");
    assert_eq!(record.id, "abc");
    assert_eq!(record.name, "my-sandbox");
    assert_eq!(record.payload, b"payload");
}

#[tokio::test]
async fn collect_records_exhausts_multiple_keyset_pages_exactly_once() {
    let store = test_store().await;
    let expected = 1005_usize;
    for index in 0..expected {
        let id = format!("collect-{index:04}");
        let name = format!("sandbox-{index:04}");
        store
            .put("sandbox", &id, &name, "collect-test", b"payload", None)
            .await
            .unwrap();
    }

    let records = store
        .collect_records("sandbox", ObjectListQuery::Workspace("collect-test"))
        .await
        .unwrap();
    let ids = records
        .iter()
        .map(|record| record.id.as_str())
        .collect::<std::collections::HashSet<_>>();

    assert_eq!(records.len(), expected);
    assert_eq!(ids.len(), expected, "every record is visited exactly once");
}

#[tokio::test]
async fn sqlite_connect_runs_embedded_migrations() {
    let store = test_store().await;

    let records = store.list("sandbox", "default", 10, 0).await.unwrap();
    assert!(records.is_empty());
}

#[tokio::test]
async fn sqlite_inference_route_removal_migration_deletes_only_managed_routes() {
    use sqlx::{Connection, SqliteConnection};

    let migration = super::sqlite::embedded_migration_sql(7)
        .expect("SQLite migrator must embed removal migration 007");
    let mut connection = SqliteConnection::connect("sqlite::memory:")
        .await
        .expect("connect to migration test database");
    sqlx::raw_sql(
        "CREATE TABLE objects (object_type TEXT NOT NULL, id TEXT NOT NULL);\
         INSERT INTO objects VALUES ('inference_route', 'managed-route');\
         INSERT INTO objects VALUES ('sandbox', 'preserved-sandbox');",
    )
    .execute(&mut connection)
    .await
    .expect("seed pre-migration objects");

    sqlx::raw_sql(migration)
        .execute(&mut connection)
        .await
        .expect("run SQLite removal migration");

    let remaining: Vec<(String, String)> =
        sqlx::query_as("SELECT object_type, id FROM objects ORDER BY object_type, id")
            .fetch_all(&mut connection)
            .await
            .expect("read migrated objects");
    assert_eq!(
        remaining,
        vec![("sandbox".to_string(), "preserved-sandbox".to_string())],
        "removal migration must purge managed routes without touching other objects"
    );
}

#[test]
fn embedded_migrators_include_inference_route_removal() {
    for (backend, migration) in [
        ("sqlite", super::sqlite::embedded_migration_sql(7)),
        ("postgres", super::postgres::embedded_migration_sql(7)),
    ] {
        let sql =
            migration.unwrap_or_else(|| panic!("{backend} migrator is missing migration 007"));
        assert!(
            sql.contains("DELETE FROM objects WHERE object_type = 'inference_route'"),
            "{backend} migration 007 must purge managed inference route objects"
        );
    }
}

#[test]
fn embedded_migrators_include_pagination_indexes() {
    for (backend, migration) in [
        ("sqlite", super::sqlite::embedded_migration_sql(8)),
        ("postgres", super::postgres::embedded_migration_sql(8)),
    ] {
        let sql =
            migration.unwrap_or_else(|| panic!("{backend} migrator is missing migration 008"));
        assert!(
            sql.contains("objects_workspace_page_idx")
                && sql.contains("objects_all_workspaces_page_idx"),
            "{backend} migration 008 must add both keyset pagination indexes"
        );
    }
}

#[tokio::test]
async fn sqlite_in_memory_store_survives_pool_connection_replacement() {
    for url in ["sqlite::memory:", "sqlite://?mode=memory"] {
        let store = super::sqlite::SqliteStore::connect(url)
            .await
            .expect("connect to in-memory SQLite");
        store.migrate().await.expect("migrate in-memory SQLite");
        store
            .put(
                "sandbox",
                "before-replacement",
                "before-replacement",
                "default",
                b"before",
                None,
            )
            .await
            .expect("write before connection replacement");

        super::sqlite::replace_pool_connection(&store)
            .await
            .expect("replace operational pool connection");

        let preserved = store
            .get("sandbox", "before-replacement")
            .await
            .expect("schema survives connection replacement")
            .expect("existing object survives connection replacement");
        assert_eq!(preserved.payload, b"before", "database URL: {url}");

        store
            .put(
                "sandbox",
                "after-replacement",
                "after-replacement",
                "default",
                b"after",
                None,
            )
            .await
            .expect("write after connection replacement");
        assert!(
            store
                .get("sandbox", "after-replacement")
                .await
                .expect("read after connection replacement")
                .is_some(),
            "database URL: {url}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn sqlite_connect_restricts_db_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("openshell.db");
    let url = format!("sqlite:{}?mode=rwc", db_path.display());

    let _store = Store::connect(&url).await.expect("connect to sqlite");

    let mode = std::fs::metadata(&db_path)
        .expect("db file exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "expected 0600, got {mode:04o}");
}

#[cfg(unix)]
#[tokio::test]
async fn sqlite_connect_tightens_existing_db_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("openshell.db");
    let url = format!("sqlite:{}?mode=rwc", db_path.display());

    // First connect creates the file; close the pool by dropping the store.
    {
        let _store = Store::connect(&url).await.expect("initial connect");
    }

    // Simulate a pre-existing database left with permissive permissions
    // (e.g., from an older gateway version that lacked this hardening).
    std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o644))
        .expect("loosen permissions");

    let _store = Store::connect(&url).await.expect("reconnect to sqlite");

    let mode = std::fs::metadata(&db_path)
        .expect("db file exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "expected 0600, got {mode:04o}");
}

fn on_disk_store_url(db_path: &std::path::Path) -> String {
    format!("sqlite:{}?mode=rwc", db_path.display())
}

async fn connect_on_disk_sqlite(url: &str) -> super::SqliteStore {
    match Store::connect(url).await.expect("connect to sqlite") {
        Store::Sqlite(store) => store,
        Store::Postgres(_) => unreachable!("sqlite URL must select the SQLite store"),
    }
}

async fn file_journal_mode(db_path: &std::path::Path) -> String {
    use sqlx::{Connection, SqliteConnection};

    let mut connection = SqliteConnection::connect(&format!("sqlite:{}", db_path.display()))
        .await
        .expect("open database file directly");
    let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&mut connection)
        .await
        .expect("read journal_mode");
    connection.close().await.expect("close direct connection");
    journal_mode
}

#[tokio::test]
async fn sqlite_connect_enables_wal_and_full_synchronous_on_disk() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("openshell.db");
    let url = on_disk_store_url(&db_path);

    let store = connect_on_disk_sqlite(&url).await;

    let (journal_mode, synchronous) = super::sqlite::journal_settings(&store)
        .await
        .expect("read journal settings through the pool");
    assert_eq!(journal_mode, "wal", "on-disk stores must run in WAL mode");
    // FULL (2), not NORMAL (1): acknowledged commits such as SSH session
    // revocations must survive a power loss.
    assert_eq!(
        synchronous, 2,
        "on-disk stores must run with synchronous=FULL (2), got {synchronous}"
    );
    let (relaxed_journal_mode, relaxed_synchronous) =
        super::sqlite::relaxed_journal_settings(&store)
            .await
            .expect("read journal settings through the relaxed pool");
    assert_eq!(relaxed_journal_mode, "wal");
    assert_eq!(
        relaxed_synchronous, 1,
        "the relaxed pool must run with synchronous=NORMAL (1), got {relaxed_synchronous}"
    );

    // Force a write so the WAL sidecars exist on disk, then confirm they are
    // owner-only like the main file.
    store
        .put(
            "sandbox",
            "wal-probe",
            "wal-probe",
            "default",
            b"payload",
            None,
        )
        .await
        .expect("write through the store");
    let [wal_path, shm_path] = super::sqlite::sqlite_sidecar_paths(&db_path);
    assert!(wal_path.exists(), "WAL sidecar should exist after a write");
    assert!(shm_path.exists(), "SHM sidecar should exist after a write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&db_path, &wal_path, &shm_path] {
            let mode = std::fs::metadata(path)
                .expect("sidecar metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode,
                0o600,
                "{}: expected 0600, got {mode:04o}",
                path.display()
            );
        }
    }

    store.close().await;
    assert_eq!(
        file_journal_mode(&db_path).await,
        "wal",
        "WAL must persist in the database file after the store closes"
    );
}

#[tokio::test]
async fn sqlite_create_relaxed_is_must_create_visible_to_durable_writes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("openshell.db");
    let store = Store::connect(&on_disk_store_url(&db_path))
        .await
        .expect("connect to sqlite");

    let created = store
        .create_relaxed("ssh_session", "tok", "tok", "default", b"issued", None)
        .await
        .expect("relaxed create");
    assert_eq!(created.resource_version, 1);

    let duplicate = store
        .create_relaxed("ssh_session", "tok", "tok", "default", b"again", None)
        .await
        .expect_err("relaxed create must reject an existing object");
    assert!(
        matches!(duplicate, PersistenceError::UniqueViolation { .. }),
        "expected UniqueViolation, got {duplicate:?}"
    );

    // The durable pool sees the relaxed insert and can revoke it with CAS.
    store
        .put_if(
            "ssh_session",
            "tok",
            "tok",
            "default",
            b"revoked",
            None,
            super::WriteCondition::MatchResourceVersion(1),
        )
        .await
        .expect("durable revoke of a relaxed insert");
    let record = store
        .get("ssh_session", "tok")
        .await
        .expect("get")
        .expect("record present");
    assert_eq!(record.payload, b"revoked");
    assert_eq!(record.resource_version, 2);
}

#[tokio::test]
async fn sqlite_connect_switches_existing_rollback_journal_database_to_wal() {
    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::{Connection, SqliteConnection};
    use std::str::FromStr;

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("openshell.db");
    let url = on_disk_store_url(&db_path);

    // A database created by an older gateway, or by any sqlx 0.8 default
    // connection, is in rollback-journal (`delete`) mode.
    {
        let options = SqliteConnectOptions::from_str(&url)
            .expect("parse url")
            .create_if_missing(true);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("create legacy database");
        sqlx::query("CREATE TABLE legacy_probe (x INTEGER)")
            .execute(&mut connection)
            .await
            .expect("write legacy database");
        connection.close().await.expect("close legacy connection");
    }
    assert_eq!(file_journal_mode(&db_path).await, "delete");

    let store = connect_on_disk_sqlite(&url).await;
    let (journal_mode, _) = super::sqlite::journal_settings(&store)
        .await
        .expect("read journal settings");
    assert_eq!(
        journal_mode, "wal",
        "connect must switch existing files to WAL"
    );
    store.close().await;
    assert_eq!(file_journal_mode(&db_path).await, "wal");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_file_backed_reads_and_writes_proceed_concurrently() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("openshell.db");
    let url = on_disk_store_url(&db_path);
    let store = std::sync::Arc::new(Store::connect(&url).await.expect("connect to sqlite"));

    store
        .put("sandbox", "seed", "seed", "default", b"seed", None)
        .await
        .expect("seed object");

    // Mirror the forward-service pattern: many independent autocommit writes
    // (a relaxed insert and a durable update per "connection", so the two
    // pools contend for the writer lock) while readers keep fetching. Every operation must complete; no caller may observe a
    // "database is locked" error even though the writes contend for the
    // single SQLite writer.
    let writers = (0..8).map(|writer| {
        let store = store.clone();
        tokio::spawn(async move {
            for index in 0..25 {
                let id = format!("session-{writer}-{index}");
                store
                    .create_relaxed("ssh_session", &id, &id, "default", b"issued", None)
                    .await
                    .expect("insert session");
                store
                    .put_if(
                        "ssh_session",
                        &id,
                        &id,
                        "default",
                        b"revoked",
                        None,
                        super::WriteCondition::MatchResourceVersion(1),
                    )
                    .await
                    .expect("revoke session");
            }
        })
    });
    let readers = (0..4).map(|_| {
        let store = store.clone();
        tokio::spawn(async move {
            for _ in 0..100 {
                let record = store
                    .get("sandbox", "seed")
                    .await
                    .expect("read while writers are active")
                    .expect("seed object present");
                assert_eq!(record.payload, b"seed");
            }
        })
    });

    for handle in writers.chain(readers) {
        handle.await.expect("task completed");
    }

    let sessions = store
        .list("ssh_session", "default", 1000, 0)
        .await
        .expect("list sessions");
    assert_eq!(sessions.len(), 200, "every session write must be durable");
    assert!(
        sessions.iter().all(|record| record.payload == b"revoked"),
        "every session must have been revoked by its follow-up write"
    );
}

// The next three tests cover `restrict_db_file_permissions` against the
// WAL/SHM sidecars at increasing levels of fidelity:
//
// 1. `_tightens_main_and_wal_and_shm_files`: synthetic empty files, proves
//    the chmod loop walks all three paths.
// 2. `_skips_missing_sidecars`: proves the `exists()` guard for databases
//    that have not been written yet or were created before the adapter
//    enabled WAL (sqlx 0.8 doesn't default to WAL and doesn't accept
//    `journal_mode` as a URL parameter; `SqliteStore::connect` opts in
//    through the builder API).
// 3. `_handles_real_sqlite_wal_files`: opens a real sqlx pool with
//    `SqliteJournalMode::Wal` via the builder API so SQLite materializes
//    real `-wal` and `-shm` files, then checks the helper tightens them.

#[cfg(unix)]
#[test]
fn restrict_db_file_permissions_tightens_main_and_wal_and_shm_files() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("openshell.db");
    let [wal_path, shm_path] = super::sqlite::sqlite_sidecar_paths(&db_path);

    // Simulate a SQLite database in WAL mode whose three files were left
    // world-readable (older gateway version, or non-zero umask at creation).
    for path in [&db_path, &wal_path, &shm_path] {
        std::fs::write(path, b"").expect("create file");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).expect("set 0o644");
    }

    super::sqlite::restrict_db_file_permissions(&db_path).expect("restrict permissions");

    for path in [&db_path, &wal_path, &shm_path] {
        let mode = std::fs::metadata(path)
            .expect("file exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode,
            0o600,
            "expected 0600 on {}, got {mode:04o}",
            path.display()
        );
    }
}

#[cfg(unix)]
#[test]
fn restrict_db_file_permissions_skips_missing_sidecars() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("openshell.db");
    let [wal_path, shm_path] = super::sqlite::sqlite_sidecar_paths(&db_path);

    // Only the main DB file exists (non-WAL journal mode, or pre-write WAL).
    std::fs::write(&db_path, b"").expect("create file");
    std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o644)).expect("set 0o644");

    super::sqlite::restrict_db_file_permissions(&db_path).expect("restrict permissions");

    assert!(!wal_path.exists(), "WAL sidecar should not be created");
    assert!(!shm_path.exists(), "SHM sidecar should not be created");

    let mode = std::fs::metadata(&db_path)
        .expect("db file exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "expected 0600, got {mode:04o}");
}

#[cfg(unix)]
#[tokio::test]
async fn restrict_db_file_permissions_handles_real_sqlite_wal_files() {
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
    use std::os::unix::fs::PermissionsExt;
    use std::str::FromStr;

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("openshell.db");
    let url = format!("sqlite:{}", db_path.display());

    // sqlx does not parse `journal_mode` from the connection URL — callers
    // must opt into WAL via the builder API.
    let options = SqliteConnectOptions::from_str(&url)
        .expect("parse url")
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("connect with WAL");

    // Force a write so SQLite definitely materializes a non-empty WAL on disk.
    sqlx::query("CREATE TABLE _hardening_probe (x INTEGER)")
        .execute(&pool)
        .await
        .expect("write");

    let [wal_path, shm_path] = super::sqlite::sqlite_sidecar_paths(&db_path);
    assert!(wal_path.exists(), "WAL should exist after write");
    assert!(shm_path.exists(), "SHM should exist after WAL write");

    // Loosen permissions on every file to simulate what an older gateway
    // version (or a non-zero default umask) would have left behind.
    for path in [&db_path, &wal_path, &shm_path] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen permissions");
    }

    super::sqlite::restrict_db_file_permissions(&db_path).expect("restrict permissions");

    for path in [&db_path, &wal_path, &shm_path] {
        let mode = std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode,
            0o600,
            "expected 0600 on {}, got {mode:04o}",
            path.display()
        );
    }
}

#[tokio::test]
async fn sqlite_updates_timestamp() {
    let store = test_store().await;

    store
        .put("sandbox", "abc", "my-sandbox", "default", b"payload", None)
        .await
        .unwrap();

    let first = store.get("sandbox", "abc").await.unwrap().unwrap();

    store
        .put("sandbox", "abc", "my-sandbox", "default", b"payload2", None)
        .await
        .unwrap();

    let second = store.get("sandbox", "abc").await.unwrap().unwrap();
    assert!(second.updated_at_ms >= first.updated_at_ms);
    assert_eq!(second.payload, b"payload2");
}

#[tokio::test]
async fn sqlite_list_paging() {
    let store = test_store().await;

    for idx in 0..5 {
        let id = format!("id-{idx}");
        let name = format!("name-{idx}");
        let payload = format!("payload-{idx}");
        store
            .put("sandbox", &id, &name, "default", payload.as_bytes(), None)
            .await
            .unwrap();
    }

    let records = store.list("sandbox", "default", 2, 1).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].name, "name-1");
    assert_eq!(records[1].name, "name-2");
}

#[tokio::test]
async fn sqlite_delete_behavior() {
    let store = test_store().await;

    store
        .put("sandbox", "abc", "my-sandbox", "default", b"payload", None)
        .await
        .unwrap();

    let deleted = store.delete("sandbox", "abc").await.unwrap();
    assert!(deleted);

    let deleted_again = store.delete("sandbox", "missing").await.unwrap();
    assert!(!deleted_again);
}

#[tokio::test]
async fn delete_many_is_bounded_idempotent_and_type_scoped() {
    let store = test_store().await;
    let mut ids = Vec::new();
    for idx in 0..(super::DELETE_MANY_BATCH_SIZE + 12) {
        let id = format!("sandbox-{idx}");
        store
            .put(
                "sandbox",
                &id,
                &format!("name-{idx}"),
                "default",
                b"payload",
                None,
            )
            .await
            .unwrap();
        ids.push(id);
    }
    store
        .put(
            "provider",
            "other-type",
            "other-type",
            "default",
            b"payload",
            None,
        )
        .await
        .unwrap();

    ids.extend([
        "missing".to_string(),
        "other-type".to_string(),
        "sandbox-0".to_string(),
    ]);
    let expected = u64::try_from(super::DELETE_MANY_BATCH_SIZE + 12).unwrap();
    assert_eq!(store.delete_many("sandbox", &ids).await.unwrap(), expected);
    assert_eq!(store.delete_many("sandbox", &ids).await.unwrap(), 0);
    assert_eq!(store.delete_many("sandbox", &[]).await.unwrap(), 0);
    assert!(store.get("provider", "other-type").await.unwrap().is_some());
}

#[tokio::test]
async fn file_backed_sqlite_bulk_delete_allows_concurrent_control_reads() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let tmp = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}?mode=rwc", tmp.path().join("bulk.db").display());
    let store = Store::connect(&url)
        .await
        .expect("connect file-backed store");
    store
        .put(
            "provider",
            "control-row",
            "control-row",
            "default",
            b"control",
            None,
        )
        .await
        .unwrap();

    let mut ids = Vec::new();
    for idx in 0..500 {
        let id = format!("session-{idx}");
        store
            .put("ssh_session", &id, &id, "default", b"payload", None)
            .await
            .unwrap();
        ids.push(id);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let read_store = store.clone();
    let read_stop = stop.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let reader = tokio::spawn(async move {
        let mut reads = 0_usize;
        let mut started_tx = Some(started_tx);
        while !read_stop.load(Ordering::Relaxed) {
            read_store
                .get("provider", "control-row")
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "control row disappeared".to_string())?;
            reads += 1;
            if let Some(started_tx) = started_tx.take() {
                let _ = started_tx.send(());
            }
            tokio::task::yield_now().await;
        }
        Ok::<usize, String>(reads)
    });
    started_rx.await.expect("reader started");

    assert_eq!(store.delete_many("ssh_session", &ids).await.unwrap(), 500);
    stop.store(true, Ordering::Relaxed);
    assert!(reader.await.unwrap().unwrap() > 0);
    assert!(
        store
            .get("provider", "control-row")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn sqlite_protobuf_round_trip() {
    let store = test_store().await;

    let object = ObjectForTest {
        id: "abc".to_string(),
        name: "test-object".to_string(),
        count: 42,
    };

    store.put_message(&object).await.unwrap();

    let loaded = store
        .get_message::<ObjectForTest>(&object.id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(loaded.id, object.id);
    assert_eq!(loaded.name, object.name);
    assert_eq!(loaded.count, object.count);
}

#[tokio::test]
async fn sqlite_get_by_name() {
    let store = test_store().await;

    store
        .put("sandbox", "id-1", "my-sandbox", "default", b"payload", None)
        .await
        .unwrap();

    let record = store
        .get_by_name("sandbox", "default", "my-sandbox")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.id, "id-1");
    assert_eq!(record.name, "my-sandbox");
    assert_eq!(record.payload, b"payload");

    let missing = store
        .get_by_name("sandbox", "default", "no-such-name")
        .await
        .unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn sqlite_get_message_by_name() {
    let store = test_store().await;

    let object = ObjectForTest {
        id: "uid-1".to_string(),
        name: "my-test".to_string(),
        count: 7,
    };

    store.put_message(&object).await.unwrap();

    let loaded = store
        .get_message_by_name::<ObjectForTest>("", "my-test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.id, "uid-1");
    assert_eq!(loaded.name, "my-test");
    assert_eq!(loaded.count, 7);

    let missing = store
        .get_message_by_name::<ObjectForTest>("", "no-such-name")
        .await
        .unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn sqlite_delete_by_name() {
    let store = test_store().await;

    store
        .put("sandbox", "id-1", "my-sandbox", "default", b"payload", None)
        .await
        .unwrap();

    let deleted = store
        .delete_by_name("sandbox", "default", "my-sandbox")
        .await
        .unwrap();
    assert!(deleted);

    let deleted_again = store
        .delete_by_name("sandbox", "default", "my-sandbox")
        .await
        .unwrap();
    assert!(!deleted_again);

    let gone = store.get("sandbox", "id-1").await.unwrap();
    assert!(gone.is_none());
}

#[tokio::test]
async fn sqlite_name_unique_per_object_type() {
    let store = test_store().await;

    store
        .put(
            "sandbox",
            "id-1",
            "shared-name",
            "default",
            b"payload1",
            None,
        )
        .await
        .unwrap();

    // Same name, same object_type, different id -> upsert on name.
    store
        .put(
            "sandbox",
            "id-2",
            "shared-name",
            "default",
            b"payload2",
            None,
        )
        .await
        .unwrap();

    let record = store
        .get_by_name("sandbox", "default", "shared-name")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.id, "id-1");
    assert_eq!(record.payload, b"payload2");

    // Same name, different object_type -> should succeed.
    store
        .put(
            "secret",
            "id-3",
            "shared-name",
            "default",
            b"payload3",
            None,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlite_name_unique_scoped_by_workspace() {
    let store = test_store().await;

    store
        .put("sandbox", "id-1", "shared-name", "alpha", b"payload1", None)
        .await
        .unwrap();

    // Same name, same type, different workspace -> separate records.
    store
        .put("sandbox", "id-2", "shared-name", "beta", b"payload2", None)
        .await
        .unwrap();

    let alpha = store
        .get_by_name("sandbox", "alpha", "shared-name")
        .await
        .unwrap()
        .unwrap();
    let beta = store
        .get_by_name("sandbox", "beta", "shared-name")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alpha.id, "id-1");
    assert_eq!(beta.id, "id-2");
    assert_eq!(alpha.payload, b"payload1");
    assert_eq!(beta.payload, b"payload2");

    // Same name, same type, same workspace -> upsert (existing behavior).
    store
        .put("sandbox", "id-3", "shared-name", "alpha", b"payload3", None)
        .await
        .unwrap();
    let alpha = store
        .get_by_name("sandbox", "alpha", "shared-name")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alpha.id, "id-1", "upsert should keep original id");
    assert_eq!(alpha.payload, b"payload3", "upsert should update payload");
}

#[tokio::test]
async fn sqlite_id_globally_unique() {
    let store = test_store().await;

    store
        .put("sandbox", "same-id", "name-a", "default", b"payload1", None)
        .await
        .unwrap();

    // Same id, different object_type -> should fail because ids remain global
    // primary keys even when writes upsert on name.
    let result = store
        .put("secret", "same-id", "name-b", "default", b"payload2", None)
        .await;
    assert!(result.is_err());

    // Original row is untouched.
    let record = store.get("sandbox", "same-id").await.unwrap().unwrap();
    assert_eq!(record.object_type, "sandbox");
    assert_eq!(record.payload, b"payload1");

    // The secret was not inserted.
    let missing = store.get("secret", "same-id").await.unwrap();
    assert!(missing.is_none());
}

#[test]
fn generate_name_format() {
    for _ in 0..100 {
        let name = generate_name();
        assert_eq!(name.len(), 6);
        assert!(name.chars().all(|c| c.is_ascii_lowercase()));
    }
}

impl ObjectType for ObjectForTest {
    fn object_type() -> &'static str {
        "object_for_test"
    }
}

// ObjectId, ObjectName, ObjectLabels implementations
// for ObjectForTest are in openshell-core::metadata

// ---------------------------------------------------------------------------
// ObjectMeta tests (labels)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn labels_round_trip() {
    let store = test_store().await;

    let labels = r#"{"env":"production","team":"platform"}"#;
    store
        .put(
            "sandbox",
            "id-1",
            "labeled-sandbox",
            "default",
            b"payload",
            Some(labels),
        )
        .await
        .unwrap();

    let record = store.get("sandbox", "id-1").await.unwrap().unwrap();
    assert_eq!(record.labels.as_deref(), Some(labels));
}

#[tokio::test]
async fn label_selector_single_match() {
    let store = test_store().await;

    store
        .put(
            "sandbox",
            "id-1",
            "s1",
            "default",
            b"p1",
            Some(r#"{"env":"prod"}"#),
        )
        .await
        .unwrap();
    store
        .put(
            "sandbox",
            "id-2",
            "s2",
            "default",
            b"p2",
            Some(r#"{"env":"dev"}"#),
        )
        .await
        .unwrap();
    store
        .put(
            "sandbox",
            "id-3",
            "s3",
            "default",
            b"p3",
            Some(r#"{"env":"prod","team":"platform"}"#),
        )
        .await
        .unwrap();

    let results = store
        .list_with_selector("sandbox", "default", "env=prod", 10, 0)
        .await
        .unwrap();

    assert_eq!(results.len(), 2);
    let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"id-1"));
    assert!(ids.contains(&"id-3"));
}

#[tokio::test]
async fn label_selector_multiple_labels() {
    let store = test_store().await;

    store
        .put(
            "sandbox",
            "id-1",
            "s1",
            "default",
            b"p1",
            Some(r#"{"env":"prod","team":"platform"}"#),
        )
        .await
        .unwrap();
    store
        .put(
            "sandbox",
            "id-2",
            "s2",
            "default",
            b"p2",
            Some(r#"{"env":"prod","team":"data"}"#),
        )
        .await
        .unwrap();
    store
        .put(
            "sandbox",
            "id-3",
            "s3",
            "default",
            b"p3",
            Some(r#"{"env":"dev","team":"platform"}"#),
        )
        .await
        .unwrap();

    let results = store
        .list_with_selector("sandbox", "default", "env=prod,team=platform", 10, 0)
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "id-1");
}

#[tokio::test]
async fn label_selector_no_match() {
    let store = test_store().await;

    store
        .put(
            "sandbox",
            "id-1",
            "s1",
            "default",
            b"p1",
            Some(r#"{"env":"prod"}"#),
        )
        .await
        .unwrap();

    let results = store
        .list_with_selector("sandbox", "default", "env=staging", 10, 0)
        .await
        .unwrap();

    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn label_selector_respects_paging() {
    let store = test_store().await;

    for idx in 0..5 {
        let id = format!("id-{idx}");
        let name = format!("name-{idx}");
        store
            .put(
                "sandbox",
                &id,
                &name,
                "default",
                b"payload",
                Some(r#"{"env":"prod"}"#),
            )
            .await
            .unwrap();
    }

    let page1 = store
        .list_with_selector("sandbox", "default", "env=prod", 2, 0)
        .await
        .unwrap();
    assert_eq!(page1.len(), 2);

    let page2 = store
        .list_with_selector("sandbox", "default", "env=prod", 2, 2)
        .await
        .unwrap();
    assert_eq!(page2.len(), 2);

    let page3 = store
        .list_with_selector("sandbox", "default", "env=prod", 2, 4)
        .await
        .unwrap();
    assert_eq!(page3.len(), 1);
}

#[tokio::test]
async fn empty_labels_not_matched_by_selector() {
    let store = test_store().await;

    store
        .put("sandbox", "id-1", "s1", "default", b"p1", None)
        .await
        .unwrap();
    store
        .put(
            "sandbox",
            "id-2",
            "s2",
            "default",
            b"p2",
            Some(r#"{"env":"prod"}"#),
        )
        .await
        .unwrap();

    let results = store
        .list_with_selector("sandbox", "default", "env=prod", 10, 0)
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "id-2");
}

// ---------------------------------------------------------------------------
// Policy revision tests
// ---------------------------------------------------------------------------

fn policy_test_sandbox(id: &str, name: &str) -> Sandbox {
    Sandbox {
        metadata: Some(ProtoObjectMeta {
            id: id.to_string(),
            name: name.to_string(),
            created_time: openshell_core::time::timestamp_from_millis(1).ok(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec::default()),
        ..Default::default()
    }
}

#[tokio::test]
async fn policy_atomic_write_commits_revision_provenance_and_sandbox_projection() {
    let store = test_store().await;
    store
        .put_message(&policy_test_sandbox("sandbox-atomic", "atomic"))
        .await
        .unwrap();
    let current = store
        .get_message::<Sandbox>("sandbox-atomic")
        .await
        .unwrap()
        .unwrap();
    let current_version = current.metadata.as_ref().unwrap().resource_version;
    let policy = SandboxPolicy {
        version: 1,
        ..Default::default()
    };
    let provenance = StdHashMap::from([("signature".to_string(), "signed".to_string())]);

    let updated = store
        .put_policy_revision_atomic(&AtomicPolicyRevisionWrite {
            id: "policy-atomic-1".to_string(),
            sandbox_id: "sandbox-atomic".to_string(),
            workspace: "default".to_string(),
            version: 1,
            policy_payload: policy.encode_to_vec(),
            policy_hash: "hash-atomic-1".to_string(),
            provenance: provenance.clone(),
            expected_resource_version: current_version,
            annotations: provenance.clone(),
            backfill_policy: Some(policy.clone()),
        })
        .await
        .unwrap();

    assert_eq!(
        updated.metadata.as_ref().unwrap().resource_version,
        current_version + 1
    );
    assert_eq!(updated.metadata.as_ref().unwrap().annotations, provenance);
    assert_eq!(
        updated.spec.as_ref().unwrap().policy.as_ref(),
        Some(&policy)
    );
    let revision = store
        .get_latest_policy("sandbox-atomic")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revision.provenance, provenance);
    store
        .update_policy_status("sandbox-atomic", 1, "loaded", None, Some(100))
        .await
        .unwrap();
    let loaded = store
        .get_latest_policy("sandbox-atomic")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.provenance, provenance);
}

#[tokio::test]
async fn policy_atomic_write_advances_version_without_projection_changes() {
    for conditional in [false, true] {
        for unchanged_annotations in [false, true] {
            let store = test_store().await;
            let policy = SandboxPolicy::default();
            let annotations = StdHashMap::from([("signature".to_string(), "old".to_string())]);
            let mut sandbox = policy_test_sandbox("sandbox-cas", "cas");
            sandbox.spec.as_mut().unwrap().policy = Some(policy.clone());
            sandbox.metadata.as_mut().unwrap().annotations = annotations.clone();
            store.put_message(&sandbox).await.unwrap();
            let before = store
                .get_message::<Sandbox>("sandbox-cas")
                .await
                .unwrap()
                .unwrap();
            let original_version = before.metadata.as_ref().unwrap().resource_version;
            let write = AtomicPolicyRevisionWrite {
                id: "policy-cas-1".to_string(),
                sandbox_id: "sandbox-cas".to_string(),
                workspace: "default".to_string(),
                version: 1,
                policy_payload: policy.encode_to_vec(),
                policy_hash: "hash-cas-1".to_string(),
                provenance: StdHashMap::new(),
                expected_resource_version: if conditional { original_version } else { 0 },
                annotations: if unchanged_annotations {
                    annotations
                } else {
                    StdHashMap::new()
                },
                backfill_policy: None,
            };

            let first = store.put_policy_revision_atomic(&write).await.unwrap();
            let mut expected = before;
            expected.metadata.as_mut().unwrap().resource_version = original_version + 1;
            assert_eq!(first, expected);
            assert_eq!(
                store.get_message::<Sandbox>("sandbox-cas").await.unwrap(),
                Some(expected.clone())
            );

            // Both writers read the original sandbox version. The first policy
            // changed no projected fields, but the second writer is still stale.
            let mut second_write = AtomicPolicyRevisionWrite {
                id: "policy-cas-2".to_string(),
                version: 2,
                policy_payload: SandboxPolicy {
                    version: 2,
                    ..Default::default()
                }
                .encode_to_vec(),
                policy_hash: "hash-cas-2".to_string(),
                expected_resource_version: original_version,
                annotations: StdHashMap::from([("signature".to_string(), "new".to_string())]),
                ..write
            };
            let error = store
                .put_policy_revision_atomic(&second_write)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                PersistenceError::Conflict {
                    current_resource_version: Some(version),
                } if version == original_version + 1
            ));
            assert_eq!(
                store.get_message::<Sandbox>("sandbox-cas").await.unwrap(),
                Some(expected)
            );
            assert!(
                store
                    .get_policy_by_version("sandbox-cas", 2)
                    .await
                    .unwrap()
                    .is_none()
            );
            let latest = store
                .get_latest_policy("sandbox-cas")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(latest.version, 1);
            assert_eq!(latest.status, "pending");

            second_write.expected_resource_version = original_version + 1;
            let second = store
                .put_policy_revision_atomic(&second_write)
                .await
                .unwrap();
            assert_eq!(
                second.metadata.as_ref().unwrap().resource_version,
                original_version + 2
            );
            assert_eq!(
                second.metadata.as_ref().unwrap().annotations,
                second_write.annotations
            );
            assert_eq!(second.spec.as_ref().unwrap().policy, Some(policy));
            assert_eq!(
                store.get_message::<Sandbox>("sandbox-cas").await.unwrap(),
                Some(second)
            );

            // Identical policy content still creates a new revision and advances
            // the version used by the next conditional writer.
            let third = store
                .put_policy_revision_atomic(&AtomicPolicyRevisionWrite {
                    id: "policy-cas-3".to_string(),
                    version: 3,
                    expected_resource_version: original_version + 2,
                    ..second_write
                })
                .await
                .unwrap();
            assert_eq!(
                third.metadata.as_ref().unwrap().resource_version,
                original_version + 3
            );
        }
    }
}

#[tokio::test]
async fn policy_atomic_write_rolls_back_sandbox_when_revision_insert_conflicts() {
    let store = test_store().await;
    store
        .put_message(&policy_test_sandbox("sandbox-rollback", "rollback"))
        .await
        .unwrap();
    let policy = SandboxPolicy::default();
    store
        .put_policy_revision(
            "existing-policy",
            "sandbox-rollback",
            "default",
            1,
            &policy.encode_to_vec(),
            "existing-hash",
        )
        .await
        .unwrap();
    let before = store
        .get_message::<Sandbox>("sandbox-rollback")
        .await
        .unwrap()
        .unwrap();
    let before_version = before.metadata.as_ref().unwrap().resource_version;

    let error = store
        .put_policy_revision_atomic(&AtomicPolicyRevisionWrite {
            id: "conflicting-policy".to_string(),
            sandbox_id: "sandbox-rollback".to_string(),
            workspace: "default".to_string(),
            version: 1,
            policy_payload: policy.encode_to_vec(),
            policy_hash: "conflicting-hash".to_string(),
            provenance: StdHashMap::from([("signature".to_string(), "new".to_string())]),
            expected_resource_version: before_version,
            annotations: StdHashMap::from([("signature".to_string(), "new".to_string())]),
            backfill_policy: Some(policy),
        })
        .await
        .unwrap_err();
    assert!(error.is_unique_violation_on("objects_version_uq"));

    let after = store
        .get_message::<Sandbox>("sandbox-rollback")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after.metadata.as_ref().unwrap().resource_version,
        before_version
    );
    assert!(after.metadata.as_ref().unwrap().annotations.is_empty());
    assert!(after.spec.as_ref().unwrap().policy.is_none());
    assert_eq!(after, before);
    let revision = store
        .get_latest_policy("sandbox-rollback")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revision.id, "existing-policy");
    assert_eq!(revision.policy_hash, "existing-hash");
    assert_eq!(revision.status, "pending");
}

#[tokio::test]
async fn policy_atomic_write_persists_workspace() {
    let store = test_store().await;
    store
        .put_message(&policy_test_sandbox("sandbox-ws", "ws-test"))
        .await
        .unwrap();
    let current = store
        .get_message::<Sandbox>("sandbox-ws")
        .await
        .unwrap()
        .unwrap();
    let current_version = current.metadata.as_ref().unwrap().resource_version;
    let policy = SandboxPolicy::default();

    store
        .put_policy_revision_atomic(&AtomicPolicyRevisionWrite {
            id: "policy-ws-1".to_string(),
            sandbox_id: "sandbox-ws".to_string(),
            workspace: "my-workspace".to_string(),
            version: 1,
            policy_payload: policy.encode_to_vec(),
            policy_hash: "hash-ws-1".to_string(),
            provenance: StdHashMap::new(),
            expected_resource_version: current_version,
            annotations: StdHashMap::new(),
            backfill_policy: Some(policy),
        })
        .await
        .unwrap();

    let record = store
        .get("sandbox_policy", "policy-ws-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.workspace, "my-workspace");
}

#[tokio::test]
async fn policy_put_and_get_latest() {
    let store = test_store().await;

    let policy_v1 = SandboxPolicy::default().encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", "default", 1, &policy_v1, "hash1")
        .await
        .unwrap();

    let latest = store.get_latest_policy("sandbox-1").await.unwrap().unwrap();
    assert_eq!(latest.version, 1);
    assert_eq!(latest.policy_hash, "hash1");
    assert_eq!(latest.status, "pending");
    assert_eq!(latest.policy_payload, policy_v1);

    // Add version 2
    let policy_v2 = SandboxPolicy {
        version: 2,
        ..SandboxPolicy::default()
    }
    .encode_to_vec();
    store
        .put_policy_revision("p2", "sandbox-1", "default", 2, &policy_v2, "hash2")
        .await
        .unwrap();

    let latest = store.get_latest_policy("sandbox-1").await.unwrap().unwrap();
    assert_eq!(latest.version, 2);
    assert_eq!(latest.policy_hash, "hash2");
}

#[tokio::test]
async fn policy_get_by_version() {
    let store = test_store().await;

    let policy_v1 = SandboxPolicy::default().encode_to_vec();
    let policy_v2 = SandboxPolicy {
        version: 2,
        ..SandboxPolicy::default()
    }
    .encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", "default", 1, &policy_v1, "h1")
        .await
        .unwrap();
    store
        .put_policy_revision("p2", "sandbox-1", "default", 2, &policy_v2, "h2")
        .await
        .unwrap();

    let v1 = store
        .get_policy_by_version("sandbox-1", 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v1.version, 1);
    assert_eq!(v1.policy_hash, "h1");

    let v2 = store
        .get_policy_by_version("sandbox-1", 2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v2.version, 2);
    assert_eq!(v2.policy_hash, "h2");

    let none = store.get_policy_by_version("sandbox-1", 99).await.unwrap();
    assert!(none.is_none());
}

#[tokio::test]
async fn policy_update_status_and_get_loaded() {
    let store = test_store().await;

    let payload = SandboxPolicy::default().encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", "default", 1, &payload, "h1")
        .await
        .unwrap();

    // No loaded policy yet.
    let loaded = store.get_latest_loaded_policy("sandbox-1").await.unwrap();
    assert!(loaded.is_none());

    // Mark as loaded.
    let updated = store
        .update_policy_status("sandbox-1", 1, "loaded", None, Some(1000))
        .await
        .unwrap();
    assert!(updated);

    let loaded = store
        .get_latest_loaded_policy("sandbox-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.version, 1);
    assert_eq!(loaded.status, "loaded");
    assert_eq!(loaded.loaded_at_ms, Some(1000));
}

#[tokio::test]
async fn policy_status_failed_with_error() {
    let store = test_store().await;

    let payload = SandboxPolicy::default().encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", "default", 1, &payload, "h1")
        .await
        .unwrap();

    store
        .update_policy_status("sandbox-1", 1, "failed", Some("L7 validation error"), None)
        .await
        .unwrap();

    let record = store
        .get_policy_by_version("sandbox-1", 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.status, "failed");
    assert_eq!(record.load_error.as_deref(), Some("L7 validation error"));
}

#[tokio::test]
async fn policy_supersede_older() {
    let store = test_store().await;

    let payload = SandboxPolicy::default().encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", "default", 1, &payload, "h1")
        .await
        .unwrap();
    store
        .put_policy_revision("p2", "sandbox-1", "default", 2, &payload, "h2")
        .await
        .unwrap();
    store
        .put_policy_revision("p3", "sandbox-1", "default", 3, &payload, "h3")
        .await
        .unwrap();

    // Mark v1 as loaded.
    store
        .update_policy_status("sandbox-1", 1, "loaded", None, Some(1000))
        .await
        .unwrap();

    // Supersede all older revisions (pending + loaded) before v3.
    let count = store
        .supersede_older_policies("sandbox-1", 3)
        .await
        .unwrap();
    assert_eq!(count, 2); // v1 (loaded) + v2 (pending) both < v3

    let v1 = store
        .get_policy_by_version("sandbox-1", 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v1.status, "superseded");

    let v2 = store
        .get_policy_by_version("sandbox-1", 2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v2.status, "superseded");

    let v3 = store
        .get_policy_by_version("sandbox-1", 3)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v3.status, "pending"); // still pending (not < 3)
}

#[tokio::test]
async fn policy_list_ordered_by_version_desc() {
    let store = test_store().await;

    let payload = SandboxPolicy::default().encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", "default", 1, &payload, "h1")
        .await
        .unwrap();
    store
        .put_policy_revision("p2", "sandbox-1", "default", 2, &payload, "h2")
        .await
        .unwrap();
    store
        .put_policy_revision("p3", "sandbox-1", "default", 3, &payload, "h3")
        .await
        .unwrap();

    let records = store.list_policies("sandbox-1", 10, 0).await.unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].version, 3);
    assert_eq!(records[1].version, 2);
    assert_eq!(records[2].version, 1);

    // Test with limit.
    let records = store.list_policies("sandbox-1", 2, 0).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].version, 3);
    assert_eq!(records[1].version, 2);
}

#[tokio::test]
async fn policy_isolation_between_sandboxes() {
    let store = test_store().await;

    let policy_s1 = SandboxPolicy::default().encode_to_vec();
    let policy_s2 = SandboxPolicy {
        version: 7,
        ..SandboxPolicy::default()
    }
    .encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", "default", 1, &policy_s1, "h1")
        .await
        .unwrap();
    store
        .put_policy_revision("p2", "sandbox-2", "default", 1, &policy_s2, "h2")
        .await
        .unwrap();

    let s1 = store.get_latest_policy("sandbox-1").await.unwrap().unwrap();
    let s2 = store.get_latest_policy("sandbox-2").await.unwrap().unwrap();

    assert_eq!(s1.policy_payload, policy_s1);
    assert_eq!(s2.policy_payload, policy_s2);
}

// ---- Label selector parsing tests ----

#[test]
fn parse_label_selector_empty_string() {
    let result = super::parse_label_selector("").unwrap();
    assert!(result.is_empty());
}

#[test]
fn parse_label_selector_single_pair() {
    let result = super::parse_label_selector("env=prod").unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result.get("env"), Some(&"prod".to_string()));
}

#[test]
fn parse_label_selector_multiple_pairs() {
    let result = super::parse_label_selector("env=prod,tier=frontend,version=v1").unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result.get("env"), Some(&"prod".to_string()));
    assert_eq!(result.get("tier"), Some(&"frontend".to_string()));
    assert_eq!(result.get("version"), Some(&"v1".to_string()));
}

#[test]
fn parse_label_selector_accepts_empty_value() {
    // Kubernetes allows empty label values, so selectors should accept "key=" format
    let result = super::parse_label_selector("env=").unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result.get("env"), Some(&String::new()));
}

#[test]
fn parse_label_selector_multiple_with_empty_value() {
    let result = super::parse_label_selector("env=,tier=frontend").unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result.get("env"), Some(&String::new()));
    assert_eq!(result.get("tier"), Some(&"frontend".to_string()));
}

#[test]
fn parse_label_selector_rejects_empty_key() {
    let result = super::parse_label_selector("=value");
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("key cannot be empty")
    );
}

#[test]
fn parse_label_selector_rejects_missing_equals() {
    let result = super::parse_label_selector("env");
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("expected 'key=value'")
    );
}

#[test]
fn parse_label_selector_handles_whitespace() {
    let result = super::parse_label_selector("env = prod , tier = frontend").unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result.get("env"), Some(&"prod".to_string()));
    assert_eq!(result.get("tier"), Some(&"frontend".to_string()));
}

#[tokio::test]
async fn create_scoped_is_insert_only_and_preserves_scope() {
    use super::PersistenceError;

    let store = test_store().await;
    let created = store
        .create_scoped(
            "refresh",
            "winner-id",
            "provider-token",
            "default",
            "winner-provider",
            b"winner",
            None,
        )
        .await
        .unwrap();
    assert_eq!(created.resource_version, 1);

    let duplicate = store
        .create_scoped(
            "refresh",
            "loser-id",
            "provider-token",
            "default",
            "loser-provider",
            b"loser",
            None,
        )
        .await;
    assert!(matches!(
        duplicate,
        Err(PersistenceError::UniqueViolation { .. })
    ));

    let winner = store
        .get_by_name("refresh", "default", "provider-token")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(winner.id, "winner-id");
    assert_eq!(winner.payload, b"winner");
    assert_eq!(
        store
            .list_by_scope("refresh", "winner-provider", 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        store
            .list_by_scope("refresh", "loser-provider", 10, 0)
            .await
            .unwrap()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// CAS (compare-and-swap) tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cas_put_if_must_create_succeeds() {
    use super::WriteCondition;

    let store = test_store().await;

    let result = store
        .put_if(
            "sandbox",
            "id-1",
            "new-sandbox",
            "default",
            b"payload",
            None,
            WriteCondition::MustCreate,
        )
        .await
        .unwrap();

    assert_eq!(result.resource_version, 1);

    let record = store.get("sandbox", "id-1").await.unwrap().unwrap();
    assert_eq!(record.resource_version, 1);
    assert_eq!(record.payload, b"payload");
}

#[tokio::test]
async fn cas_put_if_must_create_fails_on_duplicate() {
    use super::{PersistenceError, WriteCondition};

    let store = test_store().await;

    // First insert succeeds
    store
        .put_if(
            "sandbox",
            "id-1",
            "sandbox-1",
            "default",
            b"payload1",
            None,
            WriteCondition::MustCreate,
        )
        .await
        .unwrap();

    // Second insert with same ID fails
    let result = store
        .put_if(
            "sandbox",
            "id-1",
            "sandbox-2",
            "default",
            b"payload2",
            None,
            WriteCondition::MustCreate,
        )
        .await;

    assert!(matches!(
        result,
        Err(PersistenceError::UniqueViolation { .. })
    ));
}

#[tokio::test]
async fn cas_put_if_match_version_succeeds() {
    use super::WriteCondition;

    let store = test_store().await;

    // Create initial object
    store
        .put_if(
            "sandbox",
            "id-1",
            "sandbox-1",
            "default",
            b"v1",
            None,
            WriteCondition::MustCreate,
        )
        .await
        .unwrap();

    // Update with correct version
    let result = store
        .put_if(
            "sandbox",
            "id-1",
            "sandbox-1",
            "default",
            b"v2",
            None,
            WriteCondition::MatchResourceVersion(1),
        )
        .await
        .unwrap();

    assert_eq!(result.resource_version, 2);

    let record = store.get("sandbox", "id-1").await.unwrap().unwrap();
    assert_eq!(record.resource_version, 2);
    assert_eq!(record.payload, b"v2");
}

#[tokio::test]
async fn cas_put_if_match_version_fails_on_mismatch() {
    use super::{PersistenceError, WriteCondition};

    let store = test_store().await;

    // Create initial object
    store
        .put_if(
            "sandbox",
            "id-1",
            "sandbox-1",
            "default",
            b"v1",
            None,
            WriteCondition::MustCreate,
        )
        .await
        .unwrap();

    // Update with wrong version
    let result = store
        .put_if(
            "sandbox",
            "id-1",
            "sandbox-1",
            "default",
            b"v2",
            None,
            WriteCondition::MatchResourceVersion(99),
        )
        .await;

    assert!(matches!(
        result,
        Err(PersistenceError::Conflict {
            current_resource_version: Some(1)
        })
    ));

    // Original payload unchanged
    let record = store.get("sandbox", "id-1").await.unwrap().unwrap();
    assert_eq!(record.resource_version, 1);
    assert_eq!(record.payload, b"v1");
}

#[tokio::test]
async fn cas_delete_if_succeeds_with_correct_version() {
    use super::WriteCondition;

    let store = test_store().await;

    store
        .put_if(
            "sandbox",
            "id-1",
            "sandbox-1",
            "default",
            b"payload",
            None,
            WriteCondition::MustCreate,
        )
        .await
        .unwrap();

    let deleted = store.delete_if("sandbox", "id-1", 1).await.unwrap();
    assert!(deleted);

    let record = store.get("sandbox", "id-1").await.unwrap();
    assert!(record.is_none());
}

#[tokio::test]
async fn cas_delete_if_fails_with_wrong_version() {
    use super::{PersistenceError, WriteCondition};

    let store = test_store().await;

    store
        .put_if(
            "sandbox",
            "id-1",
            "sandbox-1",
            "default",
            b"payload",
            None,
            WriteCondition::MustCreate,
        )
        .await
        .unwrap();

    let result = store.delete_if("sandbox", "id-1", 99).await;
    assert!(matches!(
        result,
        Err(PersistenceError::Conflict {
            current_resource_version: Some(1)
        })
    ));

    // Object still exists
    let record = store.get("sandbox", "id-1").await.unwrap().unwrap();
    assert_eq!(record.resource_version, 1);
}

#[tokio::test]
async fn cas_resource_version_increments() {
    use super::WriteCondition;

    let store = test_store().await;

    // Create
    let r1 = store
        .put_if(
            "sandbox",
            "id-1",
            "sandbox-1",
            "default",
            b"v1",
            None,
            WriteCondition::MustCreate,
        )
        .await
        .unwrap();
    assert_eq!(r1.resource_version, 1);

    // Update 1
    let r2 = store
        .put_if(
            "sandbox",
            "id-1",
            "sandbox-1",
            "default",
            b"v2",
            None,
            WriteCondition::MatchResourceVersion(1),
        )
        .await
        .unwrap();
    assert_eq!(r2.resource_version, 2);

    // Update 2
    let r3 = store
        .put_if(
            "sandbox",
            "id-1",
            "sandbox-1",
            "default",
            b"v3",
            None,
            WriteCondition::MatchResourceVersion(2),
        )
        .await
        .unwrap();
    assert_eq!(r3.resource_version, 3);

    let record = store.get("sandbox", "id-1").await.unwrap().unwrap();
    assert_eq!(record.resource_version, 3);
}

#[tokio::test]
async fn cas_concurrent_updates_one_succeeds() {
    use super::WriteCondition;
    use std::sync::Arc;

    let store = Arc::new(test_store().await);

    // Create initial object
    store
        .put_if(
            "sandbox",
            "id-1",
            "sandbox-1",
            "default",
            b"initial",
            None,
            WriteCondition::MustCreate,
        )
        .await
        .unwrap();

    // Spawn 10 concurrent updates trying to update from version 1
    let mut handles = vec![];
    for i in 0..10 {
        let store = Arc::clone(&store);
        let handle = tokio::spawn(async move {
            store
                .put_if(
                    "sandbox",
                    "id-1",
                    "sandbox-1",
                    "default",
                    format!("update-{i}").as_bytes(),
                    None,
                    WriteCondition::MatchResourceVersion(1),
                )
                .await
        });
        handles.push(handle);
    }

    let results: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    // Exactly one should succeed, rest should conflict
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let conflicts = results.iter().filter(|r| r.is_err()).count();

    assert_eq!(successes, 1);
    assert_eq!(conflicts, 9);

    // Final version should be 2
    let record = store.get("sandbox", "id-1").await.unwrap().unwrap();
    assert_eq!(record.resource_version, 2);
}

#[tokio::test]
async fn cas_update_message_cas_succeeds() {
    use openshell_core::proto::Sandbox;

    let store = test_store().await;

    // Create a sandbox
    let sandbox = Sandbox {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: "test-id".to_string(),
            name: "test-sandbox".to_string(),
            created_time: openshell_core::time::timestamp_from_millis(1000).ok(),
            labels: std::collections::HashMap::new(),
            resource_version: 0,
            annotations: std::collections::HashMap::new(),
            workspace: "default".to_string(),
            deletion_time: None,
        }),
        spec: None,
        status: None,
        ..Sandbox::default()
    };

    store.put_message(&sandbox).await.unwrap();

    // Update using CAS with expected_version = 0 (use current version)
    let updated = store
        .update_message_cas::<Sandbox, _>("test-id", 0, |s| {
            s.set_phase(2); // Set to Ready
            s.set_current_policy_version(42);
        })
        .await
        .unwrap();

    assert_eq!(updated.phase(), 2);
    assert_eq!(updated.current_policy_version(), 42);
    assert_eq!(
        updated.metadata.as_ref().map_or(0, |m| m.resource_version),
        2
    );
}

#[tokio::test]
async fn cas_update_message_cas_internal_updates_survive_concurrent_writers() {
    use openshell_core::proto::Sandbox;
    use std::sync::Arc;

    let store = Arc::new(test_store().await);
    let sandbox = Sandbox {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: "test-id".to_string(),
            name: "test-sandbox".to_string(),
            created_time: openshell_core::time::timestamp_from_millis(1000).ok(),
            labels: std::collections::HashMap::new(),
            resource_version: 0,
            annotations: std::collections::HashMap::new(),
            workspace: "default".to_string(),
            deletion_time: None,
        }),
        ..Sandbox::default()
    };
    store.put_message(&sandbox).await.unwrap();

    let handles: Vec<_> = (0..5)
        .map(|i| {
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                store
                    .update_message_cas::<Sandbox, _>("test-id", 0, move |s| {
                        s.metadata
                            .as_mut()
                            .unwrap()
                            .annotations
                            .insert(format!("writer-{i}"), "done".to_string());
                    })
                    .await
            })
        })
        .collect();
    for result in futures::future::join_all(handles).await {
        result
            .unwrap()
            .expect("internal update must not surface a conflict");
    }

    let stored = store
        .get_message::<Sandbox>("test-id")
        .await
        .unwrap()
        .unwrap();
    let metadata = stored.metadata.unwrap();
    assert_eq!(metadata.resource_version, 6);
    for i in 0..5 {
        assert_eq!(metadata.annotations[&format!("writer-{i}")], "done");
    }
}

#[tokio::test]
async fn cas_update_message_cas_conflicts_on_concurrent_updates() {
    use openshell_core::proto::Sandbox;
    use std::sync::Arc;

    let store = Arc::new(test_store().await);

    // Create a sandbox
    let sandbox = Sandbox {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: "test-id".to_string(),
            name: "test-sandbox".to_string(),
            created_time: openshell_core::time::timestamp_from_millis(1000).ok(),
            labels: std::collections::HashMap::new(),
            resource_version: 0,
            annotations: std::collections::HashMap::new(),
            workspace: "default".to_string(),
            deletion_time: None,
        }),
        spec: None,
        status: None,
        ..Sandbox::default()
    };

    store.put_message(&sandbox).await.unwrap();

    // Spawn 5 concurrent CAS updates using the same observed version. Passing an
    // explicit version makes this deterministic: later tasks cannot re-read the
    // latest committed version and legitimately succeed.
    let mut handles = vec![];
    for i in 0..5 {
        let store = Arc::clone(&store);
        let handle = tokio::spawn(async move {
            store
                .update_message_cas::<Sandbox, _>("test-id", 1, |s| {
                    s.set_current_policy_version(i);
                })
                .await
        });
        handles.push(handle);
    }

    let results: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    // Only one should succeed; others fail with Conflict due to single-attempt CAS.
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let conflicts = results
        .iter()
        .filter(|r| matches!(r, Err(PersistenceError::Conflict { .. })))
        .count();
    assert_eq!(successes, 1, "exactly one concurrent update should succeed");
    assert_eq!(conflicts, 4, "four updates should fail with Conflict");

    // Final version should be 2 (initial 1 + 1 successful update)
    let final_sandbox = store
        .get_message::<Sandbox>("test-id")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        final_sandbox
            .metadata
            .as_ref()
            .map_or(0, |m| m.resource_version),
        2,
        "resource_version should be 2 (initial 1 + 1 successful update)"
    );
}

#[tokio::test]
async fn cas_update_message_cas_rejects_workspace_change() {
    use openshell_core::proto::Sandbox;

    let store = test_store().await;

    let sandbox = Sandbox {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: "ws-immutable".to_string(),
            name: "test-sandbox".to_string(),
            created_time: openshell_core::time::timestamp_from_millis(1000).ok(),
            labels: std::collections::HashMap::new(),
            annotations: std::collections::HashMap::new(),
            resource_version: 0,
            workspace: "alpha".to_string(),
            deletion_time: None,
        }),
        spec: None,
        status: None,
        ..Sandbox::default()
    };

    store.put_message(&sandbox).await.unwrap();

    let err = store
        .update_message_cas::<Sandbox, _>("ws-immutable", 0, |s| {
            if let Some(meta) = s.metadata.as_mut() {
                meta.workspace = "beta".to_string();
            }
        })
        .await
        .unwrap_err();

    assert!(
        matches!(err, PersistenceError::Encode(_)),
        "expected Encode error, got: {err:?}"
    );
    assert!(
        err.to_string().contains("cannot be changed"),
        "error should mention immutability: {err}"
    );
}

#[tokio::test]
async fn cas_update_message_cas_rejects_name_change() {
    use openshell_core::proto::Sandbox;

    let store = test_store().await;

    let sandbox = Sandbox {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: "name-immutable".to_string(),
            name: "original".to_string(),
            created_time: openshell_core::time::timestamp_from_millis(1000).ok(),
            labels: std::collections::HashMap::new(),
            annotations: std::collections::HashMap::new(),
            resource_version: 0,
            workspace: "default".to_string(),
            deletion_time: None,
        }),
        spec: None,
        status: None,
        ..Sandbox::default()
    };

    store.put_message(&sandbox).await.unwrap();

    let err = store
        .update_message_cas::<Sandbox, _>("name-immutable", 0, |s| {
            if let Some(meta) = s.metadata.as_mut() {
                meta.name = "renamed".to_string();
            }
        })
        .await
        .unwrap_err();

    assert!(
        matches!(err, PersistenceError::Encode(_)),
        "expected Encode error, got: {err:?}"
    );
    assert!(
        err.to_string().contains("name cannot be changed"),
        "error should mention name immutability: {err}"
    );
}

#[tokio::test]
async fn list_by_scope_returns_resource_version() {
    let store = test_store().await;

    // Create a scoped record via put_scoped (resource_version = 1).
    store
        .put_scoped(
            "ssh_session",
            "sess-1",
            "sess-1",
            "default",
            "sandbox-owner-id",
            b"payload-v1",
            None,
        )
        .await
        .unwrap();

    // Update via put_scoped (ON CONFLICT increments resource_version to 2).
    store
        .put_scoped(
            "ssh_session",
            "sess-1",
            "sess-1",
            "default",
            "sandbox-owner-id",
            b"payload-v2",
            None,
        )
        .await
        .unwrap();

    let records = store
        .list_by_scope("ssh_session", "sandbox-owner-id", 100, 0)
        .await
        .unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].resource_version, 2,
        "list_by_scope must return the actual resource_version, not a default"
    );
}
#[tokio::test]
async fn membership_and_label_selector_filters_both() {
    let store = test_store().await;

    // Workspace objects (object_type="workspace", workspace="")
    store
        .put(
            "workspace",
            "ws-a-id",
            "ws-a",
            "",
            b"p1",
            Some(r#"{"env":"prod"}"#),
        )
        .await
        .unwrap();
    store
        .put(
            "workspace",
            "ws-b-id",
            "ws-b",
            "",
            b"p2",
            Some(r#"{"env":"dev"}"#),
        )
        .await
        .unwrap();
    store
        .put(
            "workspace",
            "ws-c-id",
            "ws-c",
            "",
            b"p3",
            Some(r#"{"env":"prod","team":"platform"}"#),
        )
        .await
        .unwrap();
    store
        .put(
            "workspace",
            "ws-d-id",
            "ws-d",
            "",
            b"p4",
            Some(r#"{"env":"prod"}"#),
        )
        .await
        .unwrap();

    // Member objects: alice is a member of ws-a, ws-b, ws-c but NOT ws-d
    store
        .put("workspace_member", "m1-id", "alice", "ws-a", b"m1", None)
        .await
        .unwrap();
    store
        .put("workspace_member", "m2-id", "alice", "ws-b", b"m2", None)
        .await
        .unwrap();
    store
        .put("workspace_member", "m3-id", "alice", "ws-c", b"m3", None)
        .await
        .unwrap();

    // env=prod AND alice is a member → ws-a, ws-c (not ws-b: wrong label, not ws-d: no membership)
    let results = store
        .list_with_membership_and_selector(
            "workspace",
            "workspace_member",
            "alice",
            "env=prod",
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 2, "should match ws-a and ws-c");
    let names: Vec<&str> = results.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"ws-a"));
    assert!(names.contains(&"ws-c"));

    // env=prod,team=platform AND alice is a member → ws-c only
    let results = store
        .list_with_membership_and_selector(
            "workspace",
            "workspace_member",
            "alice",
            "env=prod,team=platform",
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 1, "should match ws-c only");
    assert_eq!(results[0].name, "ws-c");

    // env=staging AND alice is a member → empty
    let results = store
        .list_with_membership_and_selector(
            "workspace",
            "workspace_member",
            "alice",
            "env=staging",
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 0, "no workspace has env=staging");

    // bob has no memberships → empty even though label matches exist
    let results = store
        .list_with_membership_and_selector(
            "workspace",
            "workspace_member",
            "bob",
            "env=prod",
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 0, "bob has no memberships");

    // Paging: limit=1 on the env=prod query
    let page1 = store
        .list_with_membership_and_selector(
            "workspace",
            "workspace_member",
            "alice",
            "env=prod",
            1,
            0,
        )
        .await
        .unwrap();
    assert_eq!(page1.len(), 1, "page 1 should have 1 result");

    let page2 = store
        .list_with_membership_and_selector(
            "workspace",
            "workspace_member",
            "alice",
            "env=prod",
            1,
            1,
        )
        .await
        .unwrap();
    assert_eq!(page2.len(), 1, "page 2 should have 1 result");

    let page3 = store
        .list_with_membership_and_selector(
            "workspace",
            "workspace_member",
            "alice",
            "env=prod",
            1,
            2,
        )
        .await
        .unwrap();
    assert_eq!(page3.len(), 0, "page 3 should be empty");
}

#[tokio::test]
async fn membership_and_label_selector_handles_dotted_keys() {
    let store = test_store().await;

    store
        .put(
            "workspace",
            "ws-dot-id",
            "ws-dot",
            "",
            b"p1",
            Some(r#"{"example.com/env":"prod","simple":"yes"}"#),
        )
        .await
        .unwrap();
    store
        .put(
            "workspace",
            "ws-plain-id",
            "ws-plain",
            "",
            b"p2",
            Some(r#"{"env":"prod"}"#),
        )
        .await
        .unwrap();

    store
        .put("workspace_member", "m1", "alice", "ws-dot", b"", None)
        .await
        .unwrap();
    store
        .put("workspace_member", "m2", "alice", "ws-plain", b"", None)
        .await
        .unwrap();

    // Dotted key selector matches only ws-dot
    let results = store
        .list_with_membership_and_selector(
            "workspace",
            "workspace_member",
            "alice",
            "example.com/env=prod",
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 1, "dotted key should match ws-dot");
    assert_eq!(results[0].name, "ws-dot");

    // Combining dotted and simple keys
    let results = store
        .list_with_membership_and_selector(
            "workspace",
            "workspace_member",
            "alice",
            "example.com/env=prod,simple=yes",
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "ws-dot");

    // Dotted key with wrong value returns nothing
    let results = store
        .list_with_membership_and_selector(
            "workspace",
            "workspace_member",
            "alice",
            "example.com/env=staging",
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 0, "wrong value for dotted key");
}

/// Single quotes in label keys must not break the SQL query (CWE-89
/// defense-in-depth). The gRPC validation layer rejects such keys, but the
/// persistence layer must handle them safely regardless.
#[tokio::test]
async fn membership_selector_escapes_adversarial_label_key() {
    let store = test_store().await;

    store
        .put(
            "workspace",
            "ws-sq-id",
            "ws-sq",
            "",
            b"p1",
            Some(r#"{"it's":"here"}"#),
        )
        .await
        .unwrap();
    store
        .put("workspace_member", "m1", "alice", "ws-sq", b"", None)
        .await
        .unwrap();

    // A key containing a single quote must not cause a SQL error.
    let results = store
        .list_with_membership_and_selector(
            "workspace",
            "workspace_member",
            "alice",
            "it's=here",
            10,
            0,
        )
        .await;
    assert!(
        results.is_ok(),
        "single-quote key must not cause SQL error: {:?}",
        results.unwrap_err()
    );

    // A key designed to break out of the SQL string literal must not match
    // unrelated rows or cause an error.
    let results = store
        .list_with_membership_and_selector(
            "workspace",
            "workspace_member",
            "alice",
            "x' OR '1'='1=pwned",
            10,
            0,
        )
        .await;
    assert!(
        results.is_ok(),
        "SQL injection attempt must not cause SQL error: {:?}",
        results.unwrap_err()
    );
    assert_eq!(
        results.unwrap().len(),
        0,
        "SQL injection must not match rows"
    );
}

/// Store operations open a child span under whatever request span is active,
/// so a trace decomposes an RPC into the storage work it did rather than
/// bottoming out at the request boundary.
#[tokio::test]
#[ignore = "flaky under concurrent test execution"]
async fn store_operations_export_spans_with_parents() {
    use tracing::Instrument as _;

    use crate::otel_tracing::test_exporter;

    let store = test_store().await;

    let traced = test_exporter::install_traced();
    let request_span = tracing::info_span!("request");
    async {
        store
            .list("sandbox", "default", 10, 0)
            .await
            .expect("list succeeds");
    }
    .instrument(request_span.clone())
    .await;
    drop(request_span);

    let root = traced.span_named("request");
    let spans = traced.finished_spans();
    let child = spans
        .iter()
        .find(|span| {
            span.name == "store.list"
                && span.span_context.trace_id() == root.span_context.trace_id()
        })
        .unwrap_or_else(|| {
            panic!(
                "a store span is recorded, got {:?}",
                spans.iter().map(|s| &s.name).collect::<Vec<_>>()
            )
        });

    test_exporter::assert_has_parent(child);
    assert_eq!(
        test_exporter::attribute(child, "object_type").as_deref(),
        Some("sandbox"),
        "the store span records what it queried"
    );
}

// The native hold is independent of every client-side attach entry point.
fn provider_held_fixture(attached: bool) -> Sandbox {
    Sandbox {
        metadata: Some(ProtoObjectMeta {
            id: "sandbox-id".into(),
            name: "agent".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            providers: if attached {
                vec!["model".into(), "other".into()]
            } else {
                vec!["other".into()]
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn provider_hold_record() -> crate::storage_proto::StoredProviderDetachHoldV1 {
    let target = openshell_core::proto::ProviderDetachTargetV1 {
        authority: "gateway-fixture".into(),
        workspace: "default".into(),
        sandbox: "agent".into(),
        sandbox_id: "sandbox-id".into(),
        execution_id: format!("exec-v1:{}", "a".repeat(64)),
        sandbox_resource_version: 1,
        provider: "model".into(),
        provider_id: "provider-original".into(),
        provider_resource_version: 17,
        attachment_epoch: "epoch-original".into(),
        configuration_fingerprint: "config-fingerprint".into(),
        configuration_instance: "config-original".into(),
        config_revision: 8,
        provider_env_revision: 2,
        native_policy_hash: "b".repeat(64),
        native_policy_version: 3,
    };
    let target_sha256 = crate::grpc::provider_detach_target_digest(&target).unwrap();
    let original_intent = openshell_core::proto::ProviderDetachOriginalIntentV1 {
        schema_version: 1,
        target: Some(openshell_core::proto::ProviderDetachSourceTargetV1 {
            gateway_id: "controller-alias".into(),
            workspace: target.workspace.clone(),
            sandbox: target.sandbox.clone(),
            sandbox_id: target.sandbox_id.clone(),
            execution_id: target.execution_id.clone(),
            runtime_handle: String::new(),
        }),
        event_id: "event-original".into(),
        policy_revision: "rules-original".into(),
        policy_hash: "c".repeat(64),
        rule_id: "rule-original".into(),
        detach: Some(openshell_core::proto::ProviderDetachIntentV1 {
            schema_version: 1,
            profile_id: "profile-original".into(),
            violation_sha256: "e".repeat(64),
            target: Some(target.clone()),
            target_sha256: target_sha256.clone(),
        }),
    };
    let intent_sha256 =
        crate::grpc::provider_detach_original_intent_digest(&original_intent).unwrap();
    let action_id = crate::grpc::provider_detach_action_id_for_digest(&intent_sha256).unwrap();
    let action = openshell_core::proto::ProviderDetachActionV1 {
        schema_version: 1,
        action_id: action_id.clone(),
        profile_id: "profile-original".into(),
        event_id: "event-original".into(),
        intent_sha256,
        original_intent: Some(original_intent),
        target: Some(target),
        target_sha256: target_sha256.clone(),
    };
    let receipt = openshell_core::proto::ProviderDetachReceiptV1 {
        action_id: action.action_id.clone(),
        intent_sha256: action.intent_sha256.clone(),
        target_sha256: action.target_sha256.clone(),
        target: action.target.clone(),
        before_attachment_epoch: "epoch-original".into(),
        after_attachment_epoch: "epoch-detached".into(),
        native_receipt_id: "receipt-original".into(),
        hold_id: "hold-id".into(),
        config_revision: 9,
        provider_env_revision: 3,
        configuration_instance: "config-detached".into(),
        native_policy_hash: "d".repeat(64),
        native_policy_version: 4,
        recorded_time: Some(prost_types::Timestamp {
            seconds: 1000,
            nanos: 0,
        }),
    };
    crate::storage_proto::StoredProviderDetachHoldV1 {
        schema_version: 1,
        sandbox_id: "sandbox-id".into(),
        workspace: "default".into(),
        provider: "model".into(),
        provider_id: "provider-original".into(),
        action_id,
        target_sha256,
        hold_id: "hold-id".into(),
        generation: 1,
        original_action: Some(action),
        original_receipt: Some(receipt),
        native_receipt_id: "receipt-original".into(),
        created_time: Some(prost_types::Timestamp {
            seconds: 1000,
            nanos: 0,
        }),
    }
}

async fn seed_provider_hold(store: &Store) {
    let held = provider_hold_record();
    store
        .put(
            super::PROVIDER_DETACH_HOLD_OBJECT_TYPE,
            "hold-id",
            "sandbox-id:model",
            "default",
            &held.encode_to_vec(),
            None,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn provider_detach_hold_fences_all_sandbox_write_entries() {
    use super::WriteCondition;
    let store = test_store().await;
    store
        .put(
            "sandbox",
            "sandbox-id",
            "agent",
            "default",
            &provider_held_fixture(false).encode_to_vec(),
            None,
        )
        .await
        .unwrap();
    seed_provider_hold(&store).await;
    let raw = provider_held_fixture(true).encode_to_vec();
    let mut errors = Vec::new();
    errors.push(
        store
            .put("sandbox", "sandbox-id", "agent", "default", &raw, None)
            .await
            .unwrap_err(),
    );
    errors.push(
        store
            .put_if(
                "sandbox",
                "sandbox-id",
                "agent",
                "default",
                &raw,
                None,
                WriteCondition::Unconditional,
            )
            .await
            .unwrap_err(),
    );
    errors.push(
        store
            .put_if(
                "sandbox",
                "sandbox-id",
                "agent",
                "default",
                &raw,
                None,
                WriteCondition::MatchResourceVersion(1),
            )
            .await
            .unwrap_err(),
    );
    errors.push(
        store
            .put_if(
                "sandbox",
                "sandbox-id",
                "agent",
                "default",
                &raw,
                None,
                WriteCondition::MustCreate,
            )
            .await
            .unwrap_err(),
    );
    errors.push(
        store
            .put_scoped(
                "sandbox",
                "sandbox-id",
                "agent",
                "default",
                "scope",
                &raw,
                None,
            )
            .await
            .unwrap_err(),
    );
    errors.push(
        store
            .create_scoped(
                "sandbox",
                "sandbox-id",
                "agent",
                "default",
                "scope",
                &raw,
                None,
            )
            .await
            .unwrap_err(),
    );
    errors.push(
        store
            .create_relaxed("sandbox", "sandbox-id", "agent", "default", &raw, None)
            .await
            .unwrap_err(),
    );
    errors.push(
        store
            .create_if_workspace_count_below(
                "sandbox",
                "sandbox-id",
                "agent",
                "default",
                &raw,
                None,
                100,
            )
            .await
            .unwrap_err(),
    );
    for error in errors {
        assert!(
            error.to_string().contains("provider attachment held"),
            "{error}"
        );
    }
    let current = store
        .get_message::<Sandbox>("sandbox-id")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.spec.unwrap().providers, ["other"]);
    assert_eq!(current.metadata.unwrap().resource_version, 1);
}

#[tokio::test]
async fn provider_detach_hold_survives_outcome_retention_and_sandbox_rewrite() {
    use super::WriteCondition;
    let store = test_store().await;
    store
        .put(
            "sandbox",
            "sandbox-id",
            "agent",
            "default",
            &provider_held_fixture(false).encode_to_vec(),
            None,
        )
        .await
        .unwrap();
    seed_provider_hold(&store).await;
    // A status/policy write preserving detached membership is still allowed.
    let raw = provider_held_fixture(false).encode_to_vec();
    assert_eq!(
        store
            .put_if(
                "sandbox",
                "sandbox-id",
                "agent",
                "default",
                &raw,
                None,
                WriteCondition::MatchResourceVersion(1)
            )
            .await
            .unwrap()
            .resource_version,
        2
    );
    store
        .put(
            "provider_detach_action_v1",
            "action",
            "action",
            "default",
            b"metadata-only",
            None,
        )
        .await
        .unwrap();
    store
        .delete("provider_detach_action_v1", "action")
        .await
        .unwrap();
    let retained = store
        .get(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE, "hold-id")
        .await
        .unwrap()
        .unwrap();
    let retained =
        crate::storage_proto::StoredProviderDetachHoldV1::decode(retained.payload.as_slice())
            .unwrap();
    assert_eq!(retained, provider_hold_record());
    assert_eq!(
        retained
            .original_action
            .unwrap()
            .target
            .unwrap()
            .execution_id,
        format!("exec-v1:{}", "a".repeat(64))
    );
    let error = store
        .put(
            "sandbox",
            "sandbox-id",
            "agent",
            "default",
            &provider_held_fixture(true).encode_to_vec(),
            None,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("provider attachment held"));
    // Even reusing the immutable ID after deletion cannot restore that attachment.
    store.delete("sandbox", "sandbox-id").await.unwrap();
    let error = store
        .put_if(
            "sandbox",
            "sandbox-id",
            "agent",
            "default",
            &provider_held_fixture(true).encode_to_vec(),
            None,
            WriteCondition::MustCreate,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("provider attachment held"));
}

#[tokio::test]
async fn provider_detach_hold_rejects_name_upsert_identity_substitution() {
    let store = test_store().await;
    store
        .put(
            "sandbox",
            "sandbox-id",
            "agent",
            "default",
            &provider_held_fixture(false).encode_to_vec(),
            None,
        )
        .await
        .unwrap();
    seed_provider_hold(&store).await;
    let mut replacement = provider_held_fixture(true);
    replacement.metadata.as_mut().unwrap().id = "replacement-id".into();
    assert!(
        store
            .put(
                "sandbox",
                "replacement-id",
                "agent",
                "default",
                &replacement.encode_to_vec(),
                None
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("identity changed")
    );
    // Other sandbox IDs/names are outside this hold.
    replacement.metadata.as_mut().unwrap().name = "other-agent".into();
    store
        .put(
            "sandbox",
            "replacement-id",
            "other-agent",
            "default",
            &replacement.encode_to_vec(),
            None,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn provider_detach_hold_invalid_payload_fails_closed() {
    let store = test_store().await;
    store
        .put(
            "sandbox",
            "sandbox-id",
            "agent",
            "default",
            &provider_held_fixture(false).encode_to_vec(),
            None,
        )
        .await
        .unwrap();
    store
        .put(
            super::PROVIDER_DETACH_HOLD_OBJECT_TYPE,
            "hold-id",
            "sandbox-id:model",
            "default",
            b"invalid",
            None,
        )
        .await
        .unwrap();
    assert!(
        store
            .put(
                "sandbox",
                "sandbox-id",
                "agent",
                "default",
                &provider_held_fixture(true).encode_to_vec(),
                None
            )
            .await
            .is_err()
    );
}

// Historical/partial records and altered generations never become exemptions.
#[tokio::test]
async fn provider_detach_hold_missing_or_rebound_provenance_fails_closed() {
    for case in 0..10 {
        let store = test_store().await;
        let mut hold = provider_hold_record();
        match case {
            0 => hold.original_action = None,
            1 => hold.generation = 0,
            2 => hold.hold_id = "another-hold".into(),
            3 => hold.original_action.as_mut().unwrap().action_id = "other-action".into(),
            4 => {
                hold.original_action
                    .as_mut()
                    .unwrap()
                    .target
                    .as_mut()
                    .unwrap()
                    .execution_id = "other-exec".into()
            }
            5 => hold.original_action.as_mut().unwrap().intent_sha256.clear(),
            6 => hold.native_receipt_id.clear(),
            7 => hold.schema_version = 2,
            8 => hold.original_receipt = None,
            9 => hold.original_receipt.as_mut().unwrap().hold_id = "other-hold".into(),
            _ => unreachable!(),
        }
        store
            .put(
                super::PROVIDER_DETACH_HOLD_OBJECT_TYPE,
                "hold-id",
                "sandbox-id:model",
                "default",
                &hold.encode_to_vec(),
                None,
            )
            .await
            .unwrap();
        assert!(
            store
                .put(
                    "sandbox",
                    "sandbox-id",
                    "agent",
                    "default",
                    &provider_held_fixture(false).encode_to_vec(),
                    None
                )
                .await
                .is_err(),
            "case {case}"
        );
    }
}

#[tokio::test]
async fn provider_detach_hold_generation_cannot_be_replaced_or_cleared() {
    let store = test_store().await;
    seed_provider_hold(&store).await;
    let before = store
        .get(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE, "hold-id")
        .await
        .unwrap()
        .unwrap();
    seed_provider_hold(&store).await; // Exact replay preserves original version.
    let mut changed = provider_hold_record();
    changed.original_action.as_mut().unwrap().intent_sha256 = "d".repeat(64);
    assert!(
        store
            .put(
                super::PROVIDER_DETACH_HOLD_OBJECT_TYPE,
                "hold-id",
                "sandbox-id:model",
                "default",
                &changed.encode_to_vec(),
                None
            )
            .await
            .is_err()
    );
    assert!(
        store
            .put(
                super::PROVIDER_DETACH_HOLD_OBJECT_TYPE,
                "new-hold-id",
                "sandbox-id:model",
                "default",
                &provider_hold_record().encode_to_vec(),
                None
            )
            .await
            .is_err()
    );
    assert!(
        store
            .delete(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE, "hold-id")
            .await
            .is_err()
    );
    assert!(
        store
            .delete_many(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE, &["hold-id".into()])
            .await
            .is_err()
    );
    assert!(
        store
            .put_if(
                super::PROVIDER_DETACH_HOLD_OBJECT_TYPE,
                "hold-id",
                "sandbox-id:model",
                "default",
                &changed.encode_to_vec(),
                None,
                super::WriteCondition::MatchResourceVersion(1)
            )
            .await
            .is_err()
    );
    assert!(
        store
            .delete_if(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE, "hold-id", 1)
            .await
            .is_err()
    );
    assert!(
        store
            .delete_all_in_workspace(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE, "default")
            .await
            .is_err()
    );
    assert!(
        store
            .delete_by_scope(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE, "sandbox-id")
            .await
            .is_err()
    );
    assert!(
        store
            .delete_by_name(
                super::PROVIDER_DETACH_HOLD_OBJECT_TYPE,
                "default",
                "sandbox-id:model"
            )
            .await
            .is_err()
    );
    let after = store
        .get(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE, "hold-id")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.payload, after.payload);
    assert_eq!(before.resource_version, after.resource_version);
}

// Storage qualification only: effective policy/grant/lifecycle ownership remain
// RPC prerequisites. No fake configuration is accepted as a native live proof.
async fn provider_detach_commit_fixture() -> (Store, super::ProviderDetachCommit) {
    let store = test_store().await;
    let mut sandbox = provider_held_fixture(true);
    sandbox.set_phase(openshell_core::proto::SandboxPhase::Ready as i32);
    sandbox.spec.as_mut().unwrap().provider_attachment_epoch = "epoch-original".into();
    let identity = crate::auth::sandbox_session::PersistedSandboxIdentity::new().unwrap();
    identity.write(&mut sandbox.metadata.as_mut().unwrap().annotations);
    let execution = crate::auth::sandbox_session::sandbox_execution_id(&sandbox).unwrap();
    store
        .put(
            "sandbox",
            "sandbox-id",
            "agent",
            "default",
            &sandbox.encode_to_vec(),
            None,
        )
        .await
        .unwrap();
    let provider = openshell_core::proto::Provider {
        metadata: Some(ProtoObjectMeta {
            id: "provider-original".into(),
            name: "model".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    store
        .put(
            "provider",
            "provider-original",
            "model",
            "default",
            &provider.encode_to_vec(),
            None,
        )
        .await
        .unwrap();
    let held = provider_hold_record();
    let mut action = held.original_action.unwrap();
    action.target.as_mut().unwrap().execution_id = execution.clone();
    action.target.as_mut().unwrap().provider_resource_version = 1;
    let original = action.original_intent.as_mut().unwrap();
    original.target.as_mut().unwrap().execution_id = execution;
    original.detach.as_mut().unwrap().target = action.target.clone();
    action.target_sha256 =
        crate::grpc::provider_detach_target_digest(action.target.as_ref().unwrap()).unwrap();
    original.detach.as_mut().unwrap().target_sha256 = action.target_sha256.clone();
    action.intent_sha256 = crate::grpc::provider_detach_original_intent_digest(original).unwrap();
    action.action_id =
        crate::grpc::provider_detach_action_id_for_digest(&action.intent_sha256).unwrap();
    let mut receipt = held.original_receipt.unwrap();
    receipt.action_id = action.action_id.clone();
    receipt.intent_sha256 = action.intent_sha256.clone();
    receipt.target_sha256 = action.target_sha256.clone();
    receipt.target = action.target.clone();
    receipt.after_attachment_epoch = uuid::Uuid::new_v4().to_string();
    receipt.hold_id = uuid::Uuid::new_v4().to_string();
    receipt.native_receipt_id = uuid::Uuid::new_v4().to_string();
    let fence = store.provider_detach_fence().await.unwrap();
    (
        store,
        super::ProviderDetachCommit {
            action,
            fence,
            receipt,
        },
    )
}

#[tokio::test]
async fn provider_detach_atomic_commit_lost_ack_recovers_without_current_lookup_or_reapply() {
    let (store, plan) = provider_detach_commit_fixture().await;
    assert!(
        store
            .recover_provider_detach(&plan.action)
            .await
            .unwrap()
            .is_none()
    );
    // The caller loses the response AFTER the actual durable transaction.
    let original = store.commit_provider_detach(&plan).await.unwrap();
    assert_eq!(original.state, "applied");
    let sandbox = store
        .get_message::<Sandbox>("sandbox-id")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sandbox.metadata.as_ref().unwrap().resource_version, 2);
    assert_eq!(
        sandbox.phase(),
        openshell_core::proto::SandboxPhase::Ready as i32
    );
    assert_eq!(sandbox.spec.as_ref().unwrap().providers, vec!["other"]);
    assert_eq!(
        sandbox.spec.as_ref().unwrap().provider_attachment_epoch,
        plan.receipt.after_attachment_epoch
    );
    let hold = store
        .get(
            super::PROVIDER_DETACH_HOLD_OBJECT_TYPE,
            &plan.receipt.hold_id,
        )
        .await
        .unwrap()
        .unwrap();
    let hold =
        crate::storage_proto::StoredProviderDetachHoldV1::decode(hold.payload.as_slice()).unwrap();
    assert_eq!(hold.original_action.as_ref(), Some(&plan.action));
    assert_eq!(hold.original_receipt.as_ref(), Some(&plan.receipt));
    // Outcome pruning cannot erase the hold-pinned original effect lineage.
    store
        .delete(
            super::PROVIDER_DETACH_ACTION_OBJECT_TYPE,
            &plan.action.action_id,
        )
        .await
        .unwrap();
    store.delete("sandbox", "sandbox-id").await.unwrap();
    store.delete("provider", "provider-original").await.unwrap();
    assert_eq!(
        store.recover_provider_detach(&plan.action).await.unwrap(),
        Some(original.clone())
    );
    assert_eq!(store.commit_provider_detach(&plan).await.unwrap(), original);
    assert!(store.get("sandbox", "sandbox-id").await.unwrap().is_none());
}

#[tokio::test]
async fn provider_detach_atomic_dependency_drift_records_stable_no_effect() {
    let (store, mut plan) = provider_detach_commit_fixture().await;
    let before = store.get("sandbox", "sandbox-id").await.unwrap().unwrap();
    // Raw put preserves RV but changes actual config dependency bytes.
    store
        .put(
            "gateway_settings",
            "global-setting",
            "global",
            "",
            b"changed-dependency",
            None,
        )
        .await
        .unwrap();
    let outcome = store.commit_provider_detach(&plan).await.unwrap();
    assert_eq!(outcome.state, "rejected_no_effect");
    assert!(outcome.receipt.is_none());
    assert_eq!(
        store
            .get("sandbox", "sandbox-id")
            .await
            .unwrap()
            .unwrap()
            .payload,
        before.payload
    );
    assert!(
        store
            .list(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE, "default", 10, 0)
            .await
            .unwrap()
            .is_empty()
    );
    store
        .delete("gateway_settings", "global-setting")
        .await
        .unwrap();
    plan.fence = store.provider_detach_fence().await.unwrap();
    assert_eq!(store.commit_provider_detach(&plan).await.unwrap(), outcome);
    assert_eq!(
        store.recover_provider_detach(&plan.action).await.unwrap(),
        Some(outcome)
    );
}

#[tokio::test]
async fn provider_detach_atomic_hold_insert_failure_rolls_back_sandbox_and_outcome() {
    let (store, plan) = provider_detach_commit_fixture().await;
    let before = store.get("sandbox", "sandbox-id").await.unwrap().unwrap();
    // ID collision occurs AFTER the transaction attempts its Sandbox update.
    store
        .put(
            "unrelated",
            &plan.receipt.hold_id,
            "collision",
            "default",
            b"preserve",
            None,
        )
        .await
        .unwrap();
    assert!(store.commit_provider_detach(&plan).await.is_err());
    let after = store.get("sandbox", "sandbox-id").await.unwrap().unwrap();
    assert_eq!(after.payload, before.payload);
    assert_eq!(after.resource_version, before.resource_version);
    assert!(
        store
            .recover_provider_detach(&plan.action)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .list(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE, "default", 10, 0)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .get("unrelated", &plan.receipt.hold_id)
            .await
            .unwrap()
            .unwrap()
            .payload,
        b"preserve"
    );
}

#[tokio::test]
async fn provider_detach_atomic_competing_actions_preserve_one_original_hold() {
    let (store, plan) = provider_detach_commit_fixture().await;
    let mut other_action = plan.action.clone();
    other_action.original_intent.as_mut().unwrap().rule_id = "another-rule".into();
    other_action.intent_sha256 = crate::grpc::provider_detach_original_intent_digest(
        other_action.original_intent.as_ref().unwrap(),
    )
    .unwrap();
    other_action.action_id =
        crate::grpc::provider_detach_action_id_for_digest(&other_action.intent_sha256).unwrap();
    let mut other_receipt = plan.receipt.clone();
    other_receipt.action_id = other_action.action_id.clone();
    other_receipt.intent_sha256 = other_action.intent_sha256.clone();
    other_receipt.hold_id = uuid::Uuid::new_v4().to_string();
    other_receipt.native_receipt_id = uuid::Uuid::new_v4().to_string();
    other_receipt.after_attachment_epoch = uuid::Uuid::new_v4().to_string();
    let other = super::ProviderDetachCommit {
        action: other_action,
        fence: plan.fence.clone(),
        receipt: other_receipt,
    };
    let (one, two) = tokio::join!(
        store.commit_provider_detach(&plan),
        store.commit_provider_detach(&other)
    );
    let results = [one.unwrap(), two.unwrap()];
    assert_eq!(results.iter().filter(|r| r.state == "applied").count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| r.state == "rejected_no_effect")
            .count(),
        1
    );
    assert_eq!(
        store
            .list(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE, "default", 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .get("sandbox", "sandbox-id")
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        2
    );
}

#[tokio::test]
async fn provider_detach_hold_rechecks_triggered_payload_before_committing_cas_conflict() {
    let temporary = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}",
        temporary.path().join("held-cas.db").display()
    );
    let store = Store::connect(&url).await.unwrap();
    let raw = provider_held_fixture(false).encode_to_vec();
    store
        .put("sandbox", "sandbox-id", "agent", "default", &raw, None)
        .await
        .unwrap();
    seed_provider_hold(&store).await;
    let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
    sqlx::query("CREATE TABLE conflict_marker (id TEXT PRIMARY KEY)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE conflict_restore (payload BLOB NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO conflict_restore(payload) VALUES(?)")
        .bind(provider_held_fixture(true).encode_to_vec())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER restore_during_cas BEFORE UPDATE OF payload ON objects WHEN OLD.object_type='sandbox' BEGIN INSERT INTO conflict_marker(id) VALUES(OLD.id); UPDATE objects SET payload=(SELECT payload FROM conflict_restore LIMIT 1),resource_version=resource_version+1 WHERE id=OLD.id; SELECT RAISE(IGNORE); END")
        .execute(&pool).await.unwrap();
    assert!(
        store
            .put_if(
                "sandbox",
                "sandbox-id",
                "agent",
                "default",
                &raw,
                None,
                super::WriteCondition::MatchResourceVersion(1)
            )
            .await
            .is_err()
    );
    let after = store.get("sandbox", "sandbox-id").await.unwrap().unwrap();
    assert_eq!(after.payload, raw);
    assert_eq!(after.resource_version, 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM conflict_marker")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "unsafe trigger side effects must roll back");
    pool.close().await;
}

#[tokio::test]
async fn provider_detach_atomic_capacity_refuses_before_creating_unreadable_hold_set() {
    let (store, plan) = provider_detach_commit_fixture().await;
    let before = store.get("sandbox", "sandbox-id").await.unwrap().unwrap();
    for index in 0..32 {
        let mut hold = provider_hold_record();
        let name = format!("previous-provider-{index}");
        let id = format!("previous-hold-{index}");
        hold.provider = name.clone();
        hold.hold_id = id.clone();
        let action = hold.original_action.as_mut().unwrap();
        action.target.as_mut().unwrap().provider = name.clone();
        let target_hash =
            crate::grpc::provider_detach_target_digest(action.target.as_ref().unwrap()).unwrap();
        action.target_sha256 = target_hash.clone();
        hold.target_sha256 = target_hash.clone();
        let intent = action.original_intent.as_mut().unwrap();
        intent.detach.as_mut().unwrap().target = action.target.clone();
        intent.detach.as_mut().unwrap().target_sha256 = target_hash.clone();
        action.intent_sha256 = crate::grpc::provider_detach_original_intent_digest(intent).unwrap();
        action.action_id =
            crate::grpc::provider_detach_action_id_for_digest(&action.intent_sha256).unwrap();
        hold.action_id = action.action_id.clone();
        let receipt = hold.original_receipt.as_mut().unwrap();
        receipt.action_id = action.action_id.clone();
        receipt.intent_sha256 = action.intent_sha256.clone();
        receipt.target_sha256 = target_hash;
        receipt.target = action.target.clone();
        receipt.hold_id = id.clone();
        store
            .put(
                super::PROVIDER_DETACH_HOLD_OBJECT_TYPE,
                &id,
                &format!("sandbox-id:{name}"),
                "default",
                &hold.encode_to_vec(),
                None,
            )
            .await
            .unwrap();
    }
    let outcome = store.commit_provider_detach(&plan).await.unwrap();
    assert_eq!(outcome.state, "rejected_no_effect");
    assert!(outcome.receipt.is_none());
    let after = store.get("sandbox", "sandbox-id").await.unwrap().unwrap();
    assert_eq!(after.payload, before.payload);
    assert_eq!(after.resource_version, before.resource_version);
    assert_eq!(
        store
            .list(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE, "default", 100, 0)
            .await
            .unwrap()
            .len(),
        32
    );
}

#[tokio::test]
async fn provider_detach_hold_cas_binds_actual_row_identity() {
    for mismatch in 0..8 {
        let store = test_store().await;
        store
            .put(
                "sandbox",
                "sandbox-id",
                "agent",
                "default",
                &provider_held_fixture(false).encode_to_vec(),
                None,
            )
            .await
            .unwrap();
        seed_provider_hold(&store).await;
        let before = store.get("sandbox", "sandbox-id").await.unwrap().unwrap();
        let mut restored = provider_held_fixture(true);
        if mismatch >= 2 {
            let meta = restored.metadata.as_mut().unwrap();
            match mismatch {
                2 => meta.workspace = "other-workspace".into(),
                3 | 7 => meta.name = "other-name".into(),
                6 => meta.workspace = "other-workspace".into(),
                _ => meta.id = "other-id".into(),
            }
        }
        let result = if mismatch >= 5 {
            store
                .update_message_cas::<Sandbox, _>("sandbox-id", before.resource_version, |value| {
                    *value = restored.clone();
                })
                .await
                .map(|_| ())
        } else {
            store
                .put_if(
                    "sandbox",
                    "sandbox-id",
                    if mismatch == 1 { "other-name" } else { "agent" },
                    if mismatch == 0 {
                        "other-workspace"
                    } else {
                        "default"
                    },
                    &restored.encode_to_vec(),
                    None,
                    super::WriteCondition::MatchResourceVersion(before.resource_version),
                )
                .await
                .map(|_| ())
        };
        assert!(
            result.is_err(),
            "mismatched identity case {mismatch} bypassed hold"
        );
        let after = store.get("sandbox", "sandbox-id").await.unwrap().unwrap();
        assert_eq!(before.payload, after.payload);
        assert_eq!(before.resource_version, after.resource_version);
        assert_eq!(before.workspace, after.workspace);
        assert_eq!(before.name, after.name);
    }
}

#[tokio::test]
async fn provider_detach_hold_cannot_rebind_deleted_id_to_another_workspace() {
    let store = test_store().await;
    store
        .put(
            "sandbox",
            "sandbox-id",
            "agent",
            "default",
            &provider_held_fixture(false).encode_to_vec(),
            None,
        )
        .await
        .unwrap();
    seed_provider_hold(&store).await;
    assert!(store.delete("sandbox", "sandbox-id").await.unwrap());
    let mut value = provider_held_fixture(true);
    value.metadata.as_mut().unwrap().workspace = "other-workspace".into();
    assert!(store.put_message(&value).await.is_err());
    assert!(store.get("sandbox", "sandbox-id").await.unwrap().is_none());
    assert!(
        store
            .get(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE, "hold-id")
            .await
            .unwrap()
            .is_some()
    );
}
