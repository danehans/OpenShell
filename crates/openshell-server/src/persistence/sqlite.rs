// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{
    DraftChunkRecord, ObjectCursor, ObjectListQuery, ObjectRecord, PersistenceError,
    PersistenceResult, PolicyRecord, WriteCondition, WriteResult, current_time_ms, map_db_error,
    map_migrate_error,
};
use crate::policy_store::{
    AtomicPolicyRevisionWrite, apply_draft_chunk_evaluation, draft_chunk_evaluation_inputs_match,
    draft_chunk_payload_from_record, draft_chunk_record_from_parts, policy_payload_from_record,
    policy_record_for_atomic_write, policy_record_from_parts, project_policy_revision_onto_sandbox,
};
use openshell_core::SetResourceVersion;
use openshell_core::paths::set_file_owner_only;
use openshell_core::proto::Sandbox;
use prost::Message;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::{Connection, QueryBuilder, Row, Sqlite, SqlitePool};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

#[cfg(test)]
pub(super) fn embedded_migration_sql(version: i64) -> Option<&'static str> {
    SQLITE_MIGRATOR
        .iter()
        .find(|migration| migration.version == version)
        .map(|migration| migration.sql.as_ref())
}
static IN_MEMORY_DB_SEQUENCE: AtomicU64 = AtomicU64::new(0);

use super::{DELETE_MANY_BATCH_SIZE, DRAFT_CHUNK_OBJECT_TYPE, POLICY_OBJECT_TYPE};

#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
    /// Pool for writes whose loss after a crash is harmless; see
    /// [`SqliteStore::create_relaxed`]. On-disk stores open it with
    /// `synchronous=NORMAL`; in-memory stores share `pool`.
    relaxed_pool: SqlitePool,
    #[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
    in_memory_keepalive: Option<Arc<Mutex<Option<SqliteConnection>>>>,
}

fn push_label_selector(
    sql: &mut QueryBuilder<Sqlite>,
    label_selector: &str,
) -> PersistenceResult<()> {
    let mut labels: Vec<_> = super::parse_label_selector(label_selector)?
        .into_iter()
        .collect();
    labels.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    for (key, value) in labels {
        let escaped_key = key
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\'', "''");
        sql.push(format!(
            " AND json_extract(o.labels, '$.\"{escaped_key}\"') = "
        ))
        .push_bind(value);
    }
    Ok(())
}

#[cfg(test)]
pub(super) async fn replace_pool_connection(store: &SqliteStore) -> PersistenceResult<()> {
    let connection = store.pool.acquire().await.map_err(|e| map_db_error(&e))?;
    connection.close().await.map_err(|e| map_db_error(&e))
}

/// Apply the on-disk journal settings and switch the database file to WAL
/// once, before the pool opens its connections.
///
/// The gateway's hot paths (SSH-session tokens minted and revoked around every
/// forwarded connection, sandbox status updates) are many small autocommit
/// writes. `SQLite`'s default rollback journal makes each of those commits pay
/// several `fsync` calls and blocks readers while a writer holds the lock, so
/// under a burst of forwarded connections the whole store serializes on disk
/// latency. WAL mode removes the reader/writer exclusion and cuts each commit
/// to a single `fsync` of the WAL file.
///
/// The main pool keeps `synchronous=FULL` rather than the usual WAL pairing
/// of `NORMAL`. Under `NORMAL` a power loss or kernel crash can roll back
/// transactions that were already acknowledged, and several of those writes
/// tighten authorization: an SSH session revoked just before the crash would
/// come back valid for the rest of its lifetime. `FULL` keeps every
/// acknowledged commit durable. Writes whose loss only ever denies access,
/// such as minting a new SSH session token, go through a separate
/// `synchronous=NORMAL` pool instead ([`SqliteStore::create_relaxed`]). Both
/// pools append to the same WAL file, so the next `FULL` commit's `fsync` also
/// makes every earlier relaxed commit durable, and a crash can never roll back
/// a `FULL` commit.
///
/// `journal_mode=WAL` is persistent in the database file, but switching into
/// it needs exclusive access: if another connection holds the file open, the
/// switch waits out `busy_timeout` and then fails. Doing it up front on one
/// connection means the pool connections only ever re-apply the pragma to a
/// file that is already in WAL mode, which never blocks, and a failure
/// surfaces as a single clear connect error instead of a pool error later.
/// The first start after upgrading a rollback-journal database therefore needs
/// the file to be otherwise unopened. `synchronous` is a per-connection
/// setting and is applied through the options on every connection.
///
/// In-memory databases are left on their defaults: WAL is meaningless there
/// and the shared-cache keepalive connection already provides their lifetime
/// guarantees.
async fn configure_on_disk_durability(
    options: SqliteConnectOptions,
) -> PersistenceResult<SqliteConnectOptions> {
    let options = options
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full);
    let wal_error = |e: &sqlx::Error| {
        PersistenceError::Database(format!(
            "failed to switch SQLite database {} to WAL journal mode (the switch needs \
             exclusive access; close other connections to the file and retry): {}",
            options.get_filename().display(),
            map_db_error(e)
        ))
    };
    let connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|e| wal_error(&e))?;
    connection.close().await.map_err(|e| wal_error(&e))?;
    Ok(options)
}

/// Insert a new object at resource version 1, failing if it already exists.
async fn insert_new_object(
    pool: &SqlitePool,
    object_type: &str,
    id: &str,
    name: &str,
    workspace: &str,
    payload: &[u8],
    labels: Option<&str>,
) -> PersistenceResult<WriteResult> {
    let now_ms = current_time_ms();
    sqlx::query(
        r#"
INSERT INTO "objects" ("object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version")
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, 1)
"#,
    )
    .bind(object_type)
    .bind(id)
    .bind(name)
    .bind(workspace)
    .bind(payload)
    .bind(now_ms)
    .bind(labels.unwrap_or("{}"))
    .execute(pool)
    .await
    .map_err(|e| map_db_error(&e))?;

    Ok(WriteResult {
        resource_version: 1,
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
    })
}

#[cfg(test)]
pub(super) async fn journal_settings(store: &SqliteStore) -> PersistenceResult<(String, i64)> {
    pool_journal_settings(&store.pool).await
}

#[cfg(test)]
pub(super) async fn relaxed_journal_settings(
    store: &SqliteStore,
) -> PersistenceResult<(String, i64)> {
    pool_journal_settings(&store.relaxed_pool).await
}

#[cfg(test)]
async fn pool_journal_settings(pool: &SqlitePool) -> PersistenceResult<(String, i64)> {
    let mut connection = pool.acquire().await.map_err(|e| map_db_error(&e))?;
    let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&mut *connection)
        .await
        .map_err(|e| map_db_error(&e))?;
    let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
        .fetch_one(&mut *connection)
        .await
        .map_err(|e| map_db_error(&e))?;
    Ok((journal_mode, synchronous))
}

/// Check every sandbox write under the same write transaction as the mutation.
/// A stale full-object writer must not restore a held provider attachment.
/// Callers box this bounded check so its transaction-local state does not enlarge
/// every existing lifecycle writer's future.
async fn check_provider_detach_holds(
    connection: &mut SqliteConnection,
    id: &str,
    name: &str,
    workspace: &str,
    payload: &[u8],
) -> PersistenceResult<()> {
    use crate::storage_proto::StoredProviderDetachHoldV1;
    use prost::Message;
    // CAS writes address the existing row by ID, not the caller's workspace.
    // Bind that authoritative identity inside this same write transaction before
    // any caller-scoped hold lookup can report an empty set.
    let actual: Option<(String, String)> =
        sqlx::query_as("SELECT name,workspace FROM objects WHERE object_type='sandbox' AND id=?")
            .bind(id)
            .fetch_optional(&mut *connection)
            .await
            .map_err(|e| map_db_error(&e))?;
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM objects WHERE object_type='sandbox' AND workspace=? AND name=?",
    )
    .bind(workspace)
    .bind(name)
    .fetch_optional(&mut *connection)
    .await
    .map_err(|e| map_db_error(&e))?;
    let mut ids = vec![id.to_string()];
    if let Some((existing_id,)) = existing
        && existing_id != id
    {
        ids.push(existing_id);
    }
    let mut holds = Vec::new();
    for sandbox_id in ids {
        let prefix = format!("{sandbox_id}:");
        let rows: Vec<(String, String, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT id,name,payload,resource_version FROM objects WHERE object_type=? AND substr(name,1,?)=? LIMIT 33")
            .bind(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE)
            .bind(i64::try_from(prefix.len()).unwrap_or(i64::MAX)).bind(prefix)
            .fetch_all(&mut *connection).await.map_err(|e| map_db_error(&e))?;
        if rows.len() > 32 {
            return Err(PersistenceError::Config("provider hold capacity".into()));
        }
        for (hold_id, hold_name, bytes, resource_version) in rows {
            let hold = StoredProviderDetachHoldV1::decode(bytes.as_slice())
                .map_err(|_| PersistenceError::Decode("invalid provider hold".into()))?;
            let action = hold.original_action.as_ref().ok_or_else(|| {
                PersistenceError::Config("provider hold original action absent".into())
            })?;
            let target = action.target.as_ref().ok_or_else(|| {
                PersistenceError::Config("provider hold original target absent".into())
            })?;
            let receipt = hold.original_receipt.as_ref().ok_or_else(|| {
                PersistenceError::Config("provider hold original receipt absent".into())
            })?;
            crate::grpc::validate_provider_detach_original_action(action).map_err(|_| {
                PersistenceError::Config("provider hold original intent invalid".into())
            })?;
            if hold.schema_version != 1
                || receipt.hold_id != hold.hold_id
                || receipt.native_receipt_id != hold.native_receipt_id
                || receipt.action_id != action.action_id
                || receipt.intent_sha256 != action.intent_sha256
                || receipt.target_sha256 != action.target_sha256
                || receipt.target != action.target
                || receipt.before_attachment_epoch != target.attachment_epoch
                || receipt.after_attachment_epoch.is_empty()
                || receipt.after_attachment_epoch == receipt.before_attachment_epoch
                || hold.hold_id.is_empty()
                || hold.hold_id != hold_id
                || hold.generation == 0
                || resource_version <= 0
                || hold.native_receipt_id.is_empty()
                || action.schema_version != 1
                || action.action_id != hold.action_id
                || action.target_sha256 != hold.target_sha256
                || action.profile_id.is_empty()
                || action.event_id.is_empty()
                || action.intent_sha256.len() != 64
                || !action
                    .intent_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || target.sandbox_id != hold.sandbox_id
                || target.workspace != hold.workspace
                || target.provider != hold.provider
                || target.provider_id != hold.provider_id
                || target.sandbox != name
                || crate::grpc::provider_detach_target_digest(target)
                    .ok()
                    .as_deref()
                    != Some(hold.target_sha256.as_str())
                || hold.sandbox_id != sandbox_id
                || hold.workspace != workspace
                || hold.provider.is_empty()
                || hold.provider_id.is_empty()
                || hold.action_id.is_empty()
                || hold.target_sha256.len() != 64
                || !hold
                    .target_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || hold_name != format!("{}:{}", hold.sandbox_id, hold.provider)
            {
                return Err(PersistenceError::Config(
                    "invalid provider hold binding".into(),
                ));
            }
            holds.push(hold);
        }
    }
    if holds.is_empty() {
        return Ok(());
    }
    if let Some((actual_name, actual_workspace)) = actual
        && (actual_name != name || actual_workspace != workspace)
    {
        return Err(PersistenceError::Config(
            "sandbox row identity mismatch".into(),
        ));
    }
    let sandbox = Sandbox::decode(payload)
        .map_err(|_| PersistenceError::Decode("held sandbox payload invalid".into()))?;
    let meta = sandbox
        .metadata
        .as_ref()
        .ok_or_else(|| PersistenceError::Config("held sandbox metadata absent".into()))?;
    for hold in holds {
        if meta.id != hold.sandbox_id
            || meta.name != name
            || meta.workspace != workspace
            || id != hold.sandbox_id
        {
            return Err(PersistenceError::Config(
                "held sandbox identity changed".into(),
            ));
        }
        if sandbox
            .spec
            .as_ref()
            .is_none_or(|spec| spec.providers.iter().any(|p| p == &hold.provider))
        {
            return Err(PersistenceError::Config("provider attachment held".into()));
        }
    }
    Ok(())
}

// Includes raw payload identity because legacy put does not increment RV. The
// bounded, conservative fence spans every DB-backed config dependency; external
// catalog sources are unsupported at the RPC boundary. Hashes never leave the
// native plan and raw payloads are neither retained nor logged.
async fn provider_detach_fence_on(
    connection: &mut SqliteConnection,
) -> PersistenceResult<super::ProviderDetachFence> {
    use futures::TryStreamExt;
    use sha2::{Digest, Sha256};
    let mut rows = sqlx::query("SELECT object_type,id,name,scope,version,status,CASE WHEN length(payload)<=16777216 THEN payload ELSE NULL END AS payload,workspace,labels,resource_version,created_at_ms,updated_at_ms FROM objects WHERE object_type IN ('sandbox','provider','sandbox_policy','gateway_settings','sandbox_settings','provider_profile') ORDER BY object_type,id LIMIT 4097")
        .fetch(&mut *connection);
    let mut count = 0usize;
    let mut hash = Sha256::new();
    hash.update(b"openshell.provider-detach.internal-db-fence/v1\n");
    let mut total = 0usize;
    while let Some(row) = rows.try_next().await.map_err(|e| map_db_error(&e))? {
        count += 1;
        if count > 4096 {
            return Err(PersistenceError::Config(
                "provider detach dependency capacity".into(),
            ));
        }
        for field in [
            "object_type",
            "id",
            "name",
            "scope",
            "status",
            "workspace",
            "labels",
        ] {
            let value: Option<String> = row.try_get(field).map_err(|e| map_db_error(&e))?;
            hash.update([u8::from(value.is_some())]);
            let bytes = value.as_deref().unwrap_or("").as_bytes();
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        for field in [
            "version",
            "resource_version",
            "created_at_ms",
            "updated_at_ms",
        ] {
            let value: Option<i64> = row.try_get(field).map_err(|e| map_db_error(&e))?;
            hash.update([u8::from(value.is_some())]);
            hash.update(value.unwrap_or(0).to_be_bytes());
        }
        let bytes: Option<Vec<u8>> = row.try_get("payload").map_err(|e| map_db_error(&e))?;
        let bytes = bytes.ok_or_else(|| {
            PersistenceError::Config("provider detach dependency capacity".into())
        })?;
        total = total.checked_add(bytes.len()).ok_or_else(|| {
            PersistenceError::Config("provider detach dependency capacity".into())
        })?;
        if total > 16 * 1024 * 1024 {
            return Err(PersistenceError::Config(
                "provider detach dependency capacity".into(),
            ));
        }
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(&bytes);
    }
    Ok(super::ProviderDetachFence(hash.finalize().into()))
}

async fn recover_provider_detach_on(
    connection: &mut SqliteConnection,
    action: &openshell_core::proto::ProviderDetachActionV1,
) -> PersistenceResult<Option<openshell_core::proto::ProviderDetachOutcomeV1>> {
    use crate::storage_proto::StoredProviderDetachActionV1;
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT payload FROM objects WHERE object_type=? AND id=?")
            .bind(super::PROVIDER_DETACH_ACTION_OBJECT_TYPE)
            .bind(&action.action_id)
            .fetch_optional(&mut *connection)
            .await
            .map_err(|e| map_db_error(&e))?;
    let Some((bytes,)) = row else {
        // Active holds pin original effect metadata beyond outcome retention.
        // This is historical readback of the EXACT original action, never a
        // lookup of a replacement Sandbox/provider or authorization to retry.
        let target = action
            .target
            .as_ref()
            .ok_or_else(|| PersistenceError::Config("provider detach target absent".into()))?;
        let hold:Option<(String,Vec<u8>,i64)>=sqlx::query_as("SELECT id,payload,resource_version FROM objects WHERE object_type=? AND workspace=? AND name=?")
            .bind(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE).bind(&target.workspace).bind(format!("{}:{}",target.sandbox_id,target.provider))
            .fetch_optional(&mut *connection).await.map_err(|e| map_db_error(&e))?;
        let Some((id, payload, rv)) = hold else {
            return Ok(None);
        };
        let hold = crate::storage_proto::StoredProviderDetachHoldV1::decode(payload.as_slice())
            .map_err(|_| {
                PersistenceError::Decode("provider detach retained hold invalid".into())
            })?;
        if hold.original_action.as_ref() != Some(action) {
            return Ok(None);
        }
        let receipt = hold.original_receipt.ok_or_else(|| {
            PersistenceError::Decode("provider detach retained receipt absent".into())
        })?;
        let canonical_uuid =
            |v: &str| uuid::Uuid::parse_str(v).is_ok_and(|u| !u.is_nil() && u.to_string() == v);
        let original_epoch = target.attachment_epoch.as_str();
        if hold.schema_version != 1
            || hold.generation == 0
            || rv <= 0
            || hold.hold_id != id
            || !canonical_uuid(&id)
            || hold.action_id != action.action_id
            || hold.target_sha256 != action.target_sha256
            || hold.sandbox_id != target.sandbox_id
            || hold.workspace != target.workspace
            || hold.provider != target.provider
            || hold.provider_id != target.provider_id
            || receipt.hold_id != id
            || receipt.native_receipt_id != hold.native_receipt_id
            || !canonical_uuid(&receipt.native_receipt_id)
            || receipt.action_id != action.action_id
            || receipt.intent_sha256 != action.intent_sha256
            || receipt.target_sha256 != action.target_sha256
            || receipt.target != action.target
            || receipt.before_attachment_epoch != original_epoch
            || receipt.after_attachment_epoch == target.attachment_epoch
            || !canonical_uuid(&receipt.after_attachment_epoch)
        {
            return Err(PersistenceError::Decode(
                "provider detach retained hold binding invalid".into(),
            ));
        }
        return Ok(Some(openshell_core::proto::ProviderDetachOutcomeV1 {
            state: "applied".into(),
            receipt: Some(receipt),
        }));
    };

    let stored = StoredProviderDetachActionV1::decode(bytes.as_slice())
        .map_err(|_| PersistenceError::Decode("provider detach outcome invalid".into()))?;
    if stored.schema_version != 1 || stored.original_action.as_ref() != Some(action) {
        return Err(PersistenceError::Config(
            "provider detach original action conflict".into(),
        ));
    }
    let outcome = stored
        .outcome
        .ok_or_else(|| PersistenceError::Decode("provider detach outcome absent".into()))?;
    if (outcome.state == "applied"
        && outcome.receipt.as_ref().is_some_and(|r| {
            r.action_id == action.action_id
                && r.intent_sha256 == action.intent_sha256
                && r.target_sha256 == action.target_sha256
                && r.target == action.target
                && !r.hold_id.is_empty()
                && !r.native_receipt_id.is_empty()
        }))
        || (outcome.state == "rejected_no_effect" && outcome.receipt.is_none())
    {
        Ok(Some(outcome))
    } else {
        Err(PersistenceError::Decode(
            "provider detach outcome binding invalid".into(),
        ))
    }
}

impl SqliteStore {
    pub(crate) async fn claim_ordinary_observation(
        &self,
        q: &openshell_core::proto::ProviderObservationRequestV1,
        fence: &super::ProviderDetachFence,
        expected: &openshell_core::proto::ProviderObservationSnapshotV1,
    ) -> PersistenceResult<bool> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use openshell_core::proto::{ProviderObservationPhaseV1, SandboxPhase};
        use openshell_core::provider_credentials::ordinary_observation as obs;
        let bad = || PersistenceError::Config("ordinary original/current predicate refused".into());
        if !obs::shape(q)
            || !obs::valid_snapshot(expected)
            || expected.resource != q.resource
            || expected.source_incarnation != q.source_incarnation
            || expected.boundary_incarnation != q.boundary_incarnation
            || expected.profile_sha256 != q.profile_sha256
            || obs::install_budget(q, expected).is_none()
        {
            return Err(bad());
        }
        let resource = q.resource.as_ref().ok_or_else(bad)?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| map_db_error(&e))?;
        if provider_detach_fence_on(&mut tx).await? != *fence {
            return Err(bad());
        }
        let now = current_time_ms();
        let end = q.deadline.as_ref().and_then(obs::time_ms).ok_or_else(bad)?;
        if end <= now + 5000 || end - now > 65000 {
            return Err(bad());
        }
        let current: Option<(Vec<u8>,)> = sqlx::query_as("SELECT payload FROM objects WHERE object_type='sandbox' AND id=? AND workspace=? AND name=? AND length(payload)<=16777216")
            .bind(&resource.sandbox_id).bind(&resource.workspace).bind(&resource.sandbox).fetch_optional(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        let sandbox = Sandbox::decode(current.ok_or_else(bad)?.0.as_slice()).map_err(|_| bad())?;
        let provider: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM objects WHERE object_type='provider' AND workspace=? AND name=?",
        )
        .bind(&resource.workspace)
        .bind(&resource.provider)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;
        if sandbox.phase() != SandboxPhase::Ready as i32
            || crate::auth::sandbox_session::sandbox_execution_id(&sandbox)
                .ok()
                .as_deref()
                != Some(resource.execution_id.as_str())
            || provider.is_none_or(|(id,)| id != resource.provider_id)
        {
            return Err(bad());
        }
        let secondary = if q.phase == ProviderObservationPhaseV1::Detached as i32 {
            let seal = q.installed_arm.as_ref().ok_or_else(bad)?;
            let arm = seal.request.as_ref().ok_or_else(bad)?;
            let action = arm.original_action.as_ref().ok_or_else(bad)?;
            let receipt = arm.original_receipt.as_ref().ok_or_else(bad)?;
            let target = action.target.as_ref().ok_or_else(bad)?;
            let attempt = arm.attempt.as_ref().ok_or_else(bad)?;
            crate::grpc::validate_provider_detach_original_action(action).map_err(|_| bad())?;
            if target.authority != resource.authority
                || target.workspace != resource.workspace
                || target.sandbox_id != resource.sandbox_id
                || target.execution_id != resource.execution_id
                || target.provider_id != resource.provider_id
                || receipt.action_id != action.action_id
                || receipt.target.as_ref() != Some(target)
                || attempt
                    .deadline
                    .as_ref()
                    .and_then(obs::time_ms)
                    .is_none_or(|d| end > d)
                || sandbox
                    .spec
                    .as_ref()
                    .is_none_or(|s| s.providers.contains(&resource.provider))
            {
                return Err(bad());
            }
            let bytes: Option<(Vec<u8>, i64)> = sqlx::query_as("SELECT payload,resource_version FROM objects WHERE object_type=? AND id=? AND workspace=? AND name=? AND length(payload)<=16384")
                .bind(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE).bind(&receipt.hold_id).bind(&resource.workspace).bind(format!("{}:{}",resource.sandbox_id,resource.provider)).fetch_optional(&mut *tx).await.map_err(|e| map_db_error(&e))?;
            let (bytes, version) = bytes.ok_or_else(bad)?;
            let hold = crate::storage_proto::StoredProviderDetachHoldV1::decode(bytes.as_slice())
                .map_err(|_| bad())?;
            let original: Option<(Vec<u8>,)> = sqlx::query_as("SELECT payload FROM objects WHERE object_type=? AND id=? AND workspace=? AND length(payload)<=16384")
                .bind(super::PROVIDER_DETACH_ACTION_OBJECT_TYPE).bind(&action.action_id).bind(&resource.workspace).fetch_optional(&mut *tx).await.map_err(|e|map_db_error(&e))?;
            let original = crate::storage_proto::StoredProviderDetachActionV1::decode(
                original.ok_or_else(bad)?.0.as_slice(),
            )
            .map_err(|_| bad())?;
            if original.schema_version != 1
                || original.original_action.as_ref() != Some(action)
                || original
                    .outcome
                    .as_ref()
                    .is_none_or(|o| o.state != "applied" || o.receipt.as_ref() != Some(receipt))
            {
                return Err(bad());
            }
            if hold.schema_version != 1
                || hold.hold_id != receipt.hold_id
                || hold.workspace != resource.workspace
                || hold.sandbox_id != resource.sandbox_id
                || hold.provider_id != resource.provider_id
                || hold.provider != resource.provider
                || hold.native_receipt_id != receipt.native_receipt_id
                || hold.original_action.as_ref() != Some(action)
                || hold.original_receipt.as_ref() != Some(receipt)
                || hold.generation != seal.hold_generation
                || u64::try_from(version).ok() != Some(seal.row_resource_version)
            {
                return Err(bad());
            }
            let fixed: i64 = sqlx::query_scalar("SELECT count(*) FROM objects WHERE object_type=? AND json_extract(CAST(payload AS TEXT),'$.binding.action_id')=?")
                .bind(super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE).bind(&action.action_id).fetch_one(&mut *tx).await.map_err(|e| map_db_error(&e))?;
            if fixed != 0 {
                return Err(bad());
            }
            format!("action:{}", action.action_id)
        } else {
            if sandbox
                .spec
                .as_ref()
                .is_none_or(|s| !s.providers.contains(&resource.provider))
            {
                return Err(bad());
            }
            format!("baseline:{}:{}", q.run_id, q.step_id)
        };
        let key = super::ordinary_key(q);
        // Domain changes cannot reset an original operation or action claim.
        // Old actor-mode records are never decoded/upgraded as path evidence.
        let legacy: i64 = sqlx::query_scalar("SELECT count(*) FROM objects WHERE object_type=? AND (id=? OR (workspace=? AND name=?))")
            .bind(super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE).bind(&key).bind(&resource.workspace).bind(&secondary).fetch_one(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        if legacy != 0 {
            return Err(bad());
        }
        let old: Option<(Vec<u8>,)> = sqlx::query_as("SELECT payload FROM objects WHERE object_type=? AND (id=? OR (workspace=? AND name=?)) AND length(payload)<=32768")
            .bind(super::PROVIDER_OBSERVATION_OBJECT_TYPE).bind(&key).bind(&resource.workspace).bind(&secondary).fetch_optional(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        let request_protobuf = STANDARD.encode(q.encode_to_vec());
        if let Some((old,)) = old {
            let old: super::OrdinaryAdmission = serde_json::from_slice(&old).map_err(|_| bad())?;
            if old.request_protobuf != request_protobuf {
                return Err(bad());
            }
            return Ok(false); // identical original is query-only, NEVER install again
        }
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM objects WHERE object_type IN (?,?,?)")
                .bind(super::PROVIDER_OBSERVATION_OBJECT_TYPE)
                .bind(super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE)
                .bind(super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| map_db_error(&e))?;
        if count >= 4096 {
            return Err(bad());
        }
        let mut admission = super::OrdinaryAdmission {
            schema_version: 1,
            expected_snapshot_protobuf: STANDARD.encode(expected.encode_to_vec()),
            request_protobuf,
            result_protobuf: String::new(),
        };
        // Reserve the complete eventual private row BEFORE committing a claim.
        // The bound includes duplicated original/snapshot and base64/JSON framing,
        // not just the public protobuf result's 16 KiB ceiling.
        let result_bound = obs::install_budget(q, expected).ok_or_else(bad)?;
        let encoded_bound = result_bound
            .checked_add(2)
            .and_then(|n| n.checked_div(3))
            .and_then(|n| n.checked_mul(4))
            .ok_or_else(bad)?;
        admission.result_protobuf = "A".repeat(encoded_bound);
        if serde_json::to_vec(&admission).map_err(|_| bad())?.len() > 32768 {
            return Err(bad());
        }
        admission.result_protobuf.clear();
        let payload = serde_json::to_vec(&admission).map_err(|_| bad())?;
        sqlx::query("INSERT INTO objects(object_type,id,name,workspace,payload,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?)")
            .bind(super::PROVIDER_OBSERVATION_OBJECT_TYPE).bind(&key).bind(&secondary).bind(&resource.workspace).bind(payload).bind(now).bind(now).execute(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        tx.commit().await.map_err(|e| map_db_error(&e))?;
        Ok(true)
    }
    pub(crate) async fn retain_ordinary_result(
        &self,
        q: &openshell_core::proto::ProviderObservationRequestV1,
        result: &openshell_core::proto::ProviderObservationResultV1,
    ) -> PersistenceResult<()> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use openshell_core::provider_credentials::ordinary_observation as obs;
        let bad = || PersistenceError::Config("ordinary terminal binding refused".into());
        if !obs::result_fits(result)
            || result.window.as_ref().and_then(|w| w.request.as_ref()) != Some(q)
            || result.terminal_sha256.is_empty()
            || result.terminal_sha256 != obs::terminal_digest(result)
        {
            return Err(bad());
        }
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| map_db_error(&e))?;
        let key = super::ordinary_key(q);
        let row: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT payload FROM objects WHERE object_type=? AND id=? AND length(payload)<=32768",
        )
        .bind(super::PROVIDER_OBSERVATION_OBJECT_TYPE)
        .bind(&key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;
        let mut row: super::OrdinaryAdmission =
            serde_json::from_slice(&row.ok_or_else(bad)?.0).map_err(|_| bad())?;
        super::ordinary_admission_window(&row, q, result)?;
        let mut immutable = result.clone();
        immutable.current_snapshot = None;
        immutable.current_read = None;
        immutable.detached_ack = None;
        immutable.current_report_sequence = 0;
        immutable.ack_window_sha256.clear();
        immutable.ack_terminal_sha256.clear();
        let encoded = STANDARD.encode(immutable.encode_to_vec());
        if row.request_protobuf != STANDARD.encode(q.encode_to_vec())
            || (!row.result_protobuf.is_empty() && row.result_protobuf != encoded)
        {
            return Err(bad());
        }
        row.result_protobuf = encoded;
        let payload = serde_json::to_vec(&row).map_err(|_| bad())?;
        if payload.len() > 32768 {
            return Err(bad());
        }
        sqlx::query("UPDATE objects SET payload=?,resource_version=resource_version+1,updated_at_ms=? WHERE object_type=? AND id=?").bind(payload).bind(current_time_ms()).bind(super::PROVIDER_OBSERVATION_OBJECT_TYPE).bind(&key).execute(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        tx.commit().await.map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    /// D1: all related predicates and the original admission transition share
    /// one write transaction. No launch, transport, session wait or detach occurs.
    pub(crate) async fn reserve_provider_detach_witness(
        &self,
        plan: &super::ProviderDetachWitnessPlan,
        claim_dispatch: bool,
    ) -> PersistenceResult<super::ProviderDetachWitnessAdmission> {
        use crate::storage_proto::{StoredProviderDetachActionV1, StoredProviderDetachHoldV1};
        use openshell_core::proto::{
            ProviderDetachActionV1, ProviderDetachArmSealV1, ProviderDetachReceiptV1, Sandbox,
            SandboxPhase,
        };
        use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
        let bad = || {
            PersistenceError::Config("provider witness original/current predicate refused".into())
        };
        let binding = &plan.binding;
        let is_digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if binding.authority.is_empty()
            || binding.authority.len() > 253
            || uuid::Uuid::parse_str(&binding.run_id).is_err()
            || !is_digest(&binding.request_sha256)
            || !is_digest(&binding.profile_sha256)
            || binding.original_action.len() > 8192
            || binding.original_receipt.len() > 8192
            || binding.installed_arm.len() > 8192
            || binding.installed_arm.is_empty()
            || binding.hold_generation == 0
            || binding.hold_resource_version == 0
            || binding.sandbox_resource_version == 0
            || binding.provider_resource_version == 0
        {
            return Err(bad());
        }
        let action = ProviderDetachActionV1::decode(binding.original_action.as_slice())
            .map_err(|_| bad())?;
        let receipt = ProviderDetachReceiptV1::decode(binding.original_receipt.as_slice())
            .map_err(|_| bad())?;
        let arm =
            ProviderDetachArmSealV1::decode(binding.installed_arm.as_slice()).map_err(|_| bad())?;
        crate::grpc::validate_provider_detach_original_action(&action).map_err(|_| bad())?;
        let target = action.target.as_ref().ok_or_else(bad)?;
        let request = arm.request.as_ref().ok_or_else(bad)?;
        let attempt = request.attempt.as_ref().ok_or_else(bad)?;
        if action.action_id != binding.action_id
            || target.authority != binding.authority
            || receipt.action_id != action.action_id
            || receipt.target != action.target
            || request.original_action.as_ref() != Some(&action)
            || request.original_receipt.as_ref() != Some(&receipt)
            || arm.hold_generation != binding.hold_generation
            || arm.row_resource_version != binding.hold_resource_version
            || arm.install_sequence == 0
            || arm.installed_time.is_none()
            || attempt.deadline.as_ref().and_then(|t| {
                if !(0..1_000_000_000).contains(&t.nanos) {
                    return None;
                }
                t.seconds
                    .checked_mul(1000)?
                    .checked_add(i64::from(t.nanos / 1_000_000))
            }) != Some(binding.deadline_ms)
        {
            return Err(bad());
        }
        let payload = serde_json::to_vec(&super::ProviderDetachWitnessAdmission {
            binding: binding.clone(),
            dispatch_claimed: claim_dispatch,
        })
        .map_err(|_| bad())?;
        if payload.len() > 32 * 1024 {
            return Err(bad());
        }
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| map_db_error(&e))?;
        // This reads the actual dependency rows *after* BEGIN IMMEDIATE.
        if provider_detach_fence_on(&mut tx).await? != plan.fence {
            return Err(bad());
        }
        let hold: Option<(String, String, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT name,workspace,payload,resource_version FROM objects WHERE object_type=? AND id=? AND length(payload)<=16384")
            .bind(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE).bind(&receipt.hold_id)
            .fetch_optional(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        let (hold_name, hold_workspace, hold_bytes, hold_rv) = hold.ok_or_else(bad)?;
        let hold = StoredProviderDetachHoldV1::decode(hold_bytes.as_slice()).map_err(|_| bad())?;
        let original: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT payload FROM objects WHERE object_type=? AND id=? AND workspace=? AND length(payload)<=16384")
            .bind(super::PROVIDER_DETACH_ACTION_OBJECT_TYPE).bind(&action.action_id).bind(&target.workspace)
            .fetch_optional(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        let original = StoredProviderDetachActionV1::decode(original.ok_or_else(bad)?.0.as_slice())
            .map_err(|_| bad())?;
        let sandbox: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload,resource_version FROM objects WHERE object_type='sandbox' AND id=? AND workspace=? AND name=? AND length(payload)<=16777216")
            .bind(&target.sandbox_id).bind(&target.workspace).bind(&target.sandbox)
            .fetch_optional(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        let (sandbox_bytes, sandbox_rv) = sandbox.ok_or_else(bad)?;
        let sandbox = Sandbox::decode(sandbox_bytes.as_slice()).map_err(|_| bad())?;
        let provider: Option<(String, i64)> = sqlx::query_as(
            "SELECT id,resource_version FROM objects WHERE object_type='provider' AND workspace=? AND name=?")
            .bind(&target.workspace).bind(&target.provider).fetch_optional(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        if hold.schema_version != 1
            || hold.hold_id != receipt.hold_id
            || hold_name != format!("{}:{}", target.sandbox_id, target.provider)
            || hold_workspace != target.workspace
            || hold.workspace != target.workspace
            || hold.sandbox_id != target.sandbox_id
            || hold.provider_id != target.provider_id
            || hold.provider != target.provider
            || hold.generation != binding.hold_generation
            || u64::try_from(hold_rv).ok() != Some(binding.hold_resource_version)
            || hold.original_action.as_ref() != Some(&action)
            || hold.original_receipt.as_ref() != Some(&receipt)
            || hold.native_receipt_id != receipt.native_receipt_id
            || original.schema_version != 1
            || original.original_action.as_ref() != Some(&action)
            || !original
                .outcome
                .as_ref()
                .is_some_and(|o| o.state == "applied" && o.receipt.as_ref() == Some(&receipt))
            || sandbox.object_id() != target.sandbox_id
            || sandbox.object_name() != target.sandbox
            || sandbox.object_workspace() != target.workspace
            || sandbox.phase() != SandboxPhase::Ready as i32
            || u64::try_from(sandbox_rv).ok() != Some(binding.sandbox_resource_version)
            || crate::auth::sandbox_session::sandbox_execution_id(&sandbox)
                .ok()
                .as_deref()
                != Some(target.execution_id.as_str())
            || !sandbox.spec.as_ref().is_some_and(|s| {
                s.provider_attachment_epoch == receipt.after_attachment_epoch
                    && !s.providers.contains(&target.provider)
            })
            || provider.as_ref().is_none_or(|(id, rv)| {
                id != &target.provider_id
                    || u64::try_from(*rv).ok() != Some(binding.provider_resource_version)
            })
        {
            return Err(bad());
        }
        let now = current_time_ms();
        if now >= binding.deadline_ms {
            return Err(bad());
        }
        // Ordinary observation and fixed invocation may not both own an action.
        let ordinary: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM objects WHERE object_type IN (?,?) AND workspace=? AND name=?",
        )
        .bind(super::PROVIDER_OBSERVATION_OBJECT_TYPE)
        .bind(super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE)
        .bind(&target.workspace)
        .bind(format!("action:{}", action.action_id))
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;
        if ordinary != 0 {
            return Err(bad());
        }
        let id = binding.original_key();
        let existing: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT payload,resource_version FROM objects WHERE object_type=? AND id=? AND length(payload)<=32768")
            .bind(super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE).bind(&id)
            .fetch_optional(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        if let Some((bytes, rv)) = existing {
            let original: super::ProviderDetachWitnessAdmission =
                serde_json::from_slice(&bytes).map_err(|_| bad())?;
            if original.binding != *binding || (claim_dispatch && original.dispatch_claimed) {
                return Err(bad());
            }
            if !claim_dispatch {
                return Ok(original);
            }
            let updated = sqlx::query("UPDATE objects SET payload=?,resource_version=resource_version+1,updated_at_ms=? WHERE object_type=? AND id=? AND resource_version=?")
                    .bind(&payload).bind(now).bind(super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE).bind(&id).bind(rv)
                    .execute(&mut *tx).await.map_err(|e| map_db_error(&e))?;
            if updated.rows_affected() != 1 {
                return Err(bad());
            }
        } else {
            // An invoke cannot create its own reservation or recover an
            // absent reservation into another original dispatch.
            if claim_dispatch {
                return Err(bad());
            }
            let count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM objects WHERE object_type IN (?,?,?)")
                    .bind(super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE)
                    .bind(super::PROVIDER_OBSERVATION_OBJECT_TYPE)
                    .bind(super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|e| map_db_error(&e))?;
            if count >= 4096 {
                return Err(bad());
            }
            sqlx::query("INSERT INTO objects(object_type,id,name,workspace,payload,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?)")
                    .bind(super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE).bind(&id).bind(&id).bind(&target.workspace)
                    .bind(&payload).bind(now).bind(now).execute(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        }
        // No sender is selected if commit's response is lost or ambiguous.
        tx.commit().await.map_err(|e| map_db_error(&e))?;
        Ok(super::ProviderDetachWitnessAdmission {
            binding: binding.clone(),
            dispatch_claimed: claim_dispatch,
        })
    }

    pub(crate) async fn reject_provider_detach(
        &self,
        action: &openshell_core::proto::ProviderDetachActionV1,
    ) -> PersistenceResult<openshell_core::proto::ProviderDetachOutcomeV1> {
        use tracing::instrument::WithSubscriber;
        async {
            crate::grpc::validate_provider_detach_original_action(action).map_err(|_| PersistenceError::Config("provider detach action invalid".into()))?;
            let mut tx=self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(|e|map_db_error(&e))?;
            if let Some(original)=recover_provider_detach_on(&mut tx,action).await? {return Ok(original)}
            let outcome=openshell_core::proto::ProviderDetachOutcomeV1{state:"rejected_no_effect".into(),receipt:None};
            let now=current_time_ms();
            let stored=crate::storage_proto::StoredProviderDetachActionV1{schema_version:1,original_action:Some(action.clone()),outcome:Some(outcome.clone()),recorded_time:openshell_core::time::timestamp_from_millis(now).ok()};
            sqlx::query("INSERT INTO objects(object_type,id,name,workspace,payload,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?)")
                .bind(super::PROVIDER_DETACH_ACTION_OBJECT_TYPE).bind(&action.action_id).bind(&action.action_id)
                .bind(&action.target.as_ref().ok_or_else(||PersistenceError::Config("provider detach target absent".into()))?.workspace)
                .bind(stored.encode_to_vec()).bind(now).bind(now).execute(&mut *tx).await.map_err(|e|map_db_error(&e))?;
            tx.commit().await.map_err(|e|map_db_error(&e))?;
            Ok(outcome)
        }.with_subscriber(tracing::subscriber::NoSubscriber::default()).await
    }

    pub(crate) async fn provider_detach_fence(
        &self,
    ) -> PersistenceResult<super::ProviderDetachFence> {
        let mut connection = self.pool.acquire().await.map_err(|e| map_db_error(&e))?;
        provider_detach_fence_on(&mut connection).await
    }

    pub(crate) async fn recover_provider_detach(
        &self,
        action: &openshell_core::proto::ProviderDetachActionV1,
    ) -> PersistenceResult<Option<openshell_core::proto::ProviderDetachOutcomeV1>> {
        crate::grpc::validate_provider_detach_original_action(action)
            .map_err(|_| PersistenceError::Config("provider detach action invalid".into()))?;
        let mut connection = self.pool.acquire().await.map_err(|e| map_db_error(&e))?;
        recover_provider_detach_on(&mut connection, action).await
    }

    /// One commit contains membership removal, persistent hold and original
    /// historical outcome. A lost commit ACK is read back, never replayed by RPC.
    /// This is not a standalone authorization boundary: no RPC calls it until
    /// lifecycle ownership, grant and complete effective-config checks are wired.
    pub(crate) async fn commit_provider_detach(
        &self,
        plan: &super::ProviderDetachCommit,
    ) -> PersistenceResult<openshell_core::proto::ProviderDetachOutcomeV1> {
        // Keep outer Store/RPC spans intact. SQLx transaction worker spans
        // otherwise retain registry IDs across dispatchers, reproduced by the
        // existing compute parent-span regression; isolate internal SQL spans.
        use tracing::instrument::WithSubscriber;
        async {
        use crate::storage_proto::{StoredProviderDetachActionV1, StoredProviderDetachHoldV1};
        use openshell_core::proto::{ProviderDetachOutcomeV1, SandboxPhase};
        use openshell_core::{GetResourceVersion, ObjectId, ObjectName, ObjectWorkspace};
        let action = &plan.action;
        crate::grpc::validate_provider_detach_original_action(action)
            .map_err(|_| PersistenceError::Config("provider detach action invalid".into()))?;
        let target = action
            .target
            .as_ref()
            .ok_or_else(|| PersistenceError::Config("provider detach target absent".into()))?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| map_db_error(&e))?;
        if let Some(original) = recover_provider_detach_on(&mut tx, action).await? {
            return Ok(original);
        }
        let receipt = &plan.receipt;
        let uuid_valid =
            |v: &str| uuid::Uuid::parse_str(v).is_ok_and(|id| !id.is_nil() && id.to_string() == v);
        let original_epoch = target.attachment_epoch.as_str();
    if receipt.action_id != action.action_id
            || receipt.intent_sha256 != action.intent_sha256
            || receipt.target_sha256 != action.target_sha256
            || receipt.target != action.target
            || receipt.before_attachment_epoch != original_epoch
            || receipt.after_attachment_epoch == target.attachment_epoch
            || !uuid_valid(&receipt.after_attachment_epoch)
            || !uuid_valid(&receipt.hold_id)
            || !uuid_valid(&receipt.native_receipt_id)
            || receipt.config_revision == 0
            || receipt.provider_env_revision == 0
            || receipt.configuration_instance.is_empty()
            || receipt.native_policy_version == 0
            || receipt.native_policy_hash.len() != 64
            || !receipt
                .native_policy_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || receipt
                .recorded_time
                .as_ref()
                .is_none_or(|t| t.seconds <= 0 || !(0..1_000_000_000).contains(&t.nanos))
        {
            return Err(PersistenceError::Config(
                "provider detach receipt invalid".into(),
            ));
        }
        let current: Option<(Vec<u8>, i64)> = sqlx::query_as("SELECT payload,resource_version FROM objects WHERE object_type='sandbox' AND id=? AND workspace=? AND name=?")
            .bind(&target.sandbox_id).bind(&target.workspace).bind(&target.sandbox)
            .fetch_optional(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        let provider: Option<(String,i64)> = sqlx::query_as("SELECT id,resource_version FROM objects WHERE object_type='provider' AND workspace=? AND name=?")
            .bind(&target.workspace).bind(&target.provider).fetch_optional(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        let existing_provider_hold_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM objects WHERE object_type=? AND workspace=? AND name=?",
        )
        .bind(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE)
        .bind(&target.workspace)
        .bind(format!("{}:{}", target.sandbox_id, target.provider))
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;
        let hold_prefix = format!("{}:",target.sandbox_id);
        let prefix_len = i64::try_from(hold_prefix.len()).map_err(|_| PersistenceError::Config("provider hold prefix unsupported".into()))?;
        let hold_count:i64=sqlx::query_scalar("SELECT count(*) FROM objects WHERE object_type=? AND workspace=? AND substr(name,1,?)=?")
            .bind(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE).bind(&target.workspace).bind(prefix_len).bind(&hold_prefix)
            .fetch_one(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        let mut candidate = current.as_ref().and_then(|(b, rv)| {
            Sandbox::decode(b.as_slice()).ok().and_then(|mut sandbox| {
                sandbox.set_resource_version(u64::try_from(*rv).ok()?);
                Some(sandbox)
            })
        });
        let matches = provider_detach_fence_on(&mut tx).await? == plan.fence
            && existing_provider_hold_count == 0
            && hold_count < 32
            && provider.as_ref().is_some_and(|(id, rv)| {
                id == &target.provider_id
                    && u64::try_from(*rv).ok() == Some(target.provider_resource_version)
            })
            && candidate.as_ref().is_some_and(|s| {
                s.object_id() == target.sandbox_id
                    && s.object_name() == target.sandbox
                    && s.object_workspace() == target.workspace
                    && s.get_resource_version() == target.sandbox_resource_version
                    && s.phase() == SandboxPhase::Ready as i32
                    && crate::auth::sandbox_session::sandbox_execution_id(s)
                        .ok()
                        .as_deref()
                        == Some(target.execution_id.as_str())
                    && s.spec.as_ref().is_some_and(|spec| {
                        spec.provider_attachment_epoch == target.attachment_epoch
                            && spec
                                .providers
                                .iter()
                                .filter(|p| *p == &target.provider)
                                .count()
                                == 1
                    })
            });
        let outcome = if matches {
            let sandbox = candidate
                .as_mut()
                .ok_or_else(|| PersistenceError::Config("provider detach sandbox absent".into()))?;
            let spec = sandbox
                .spec
                .as_mut()
                .ok_or_else(|| PersistenceError::Config("provider detach spec absent".into()))?;
            spec.providers.retain(|name| name != &target.provider);
            spec.provider_attachment_epoch
                .clone_from(&receipt.after_attachment_epoch);
            crate::compute::provisioning_deadline::attachments_changed(sandbox, current_time_ms());
            let payload = sandbox.encode_to_vec();
            Box::pin(check_provider_detach_holds(
                &mut tx,
                &target.sandbox_id,
                &target.sandbox,
                &target.workspace,
                &payload,
            ))
            .await?;
            let changed = sqlx::query("UPDATE objects SET payload=?,resource_version=resource_version+1,updated_at_ms=? WHERE object_type='sandbox' AND id=? AND resource_version=?")
                .bind(payload).bind(current_time_ms()).bind(&target.sandbox_id).bind(i64::try_from(target.sandbox_resource_version).map_err(|_| PersistenceError::Config("sandbox RV unsupported".into()))?)
                .execute(&mut *tx).await.map_err(|e| map_db_error(&e))?;
            if changed.rows_affected() != 1 {
                return Err(PersistenceError::Conflict {
                    current_resource_version: None,
                });
            }
            let hold = StoredProviderDetachHoldV1 {
                schema_version: 1,
                sandbox_id: target.sandbox_id.clone(),
                workspace: target.workspace.clone(),
                provider: target.provider.clone(),
                provider_id: target.provider_id.clone(),
                action_id: action.action_id.clone(),
                target_sha256: action.target_sha256.clone(),
                created_time: receipt.recorded_time,
                hold_id: receipt.hold_id.clone(),
                generation: 1,
                original_action: Some(action.clone()),
                native_receipt_id: receipt.native_receipt_id.clone(),
                original_receipt: Some(receipt.clone()),
            };
            let now = current_time_ms();
            sqlx::query("INSERT INTO objects (object_type,id,name,workspace,payload,created_at_ms,updated_at_ms) VALUES (?,?,?,?,?,?,?)")
                .bind(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE).bind(&hold.hold_id).bind(format!("{}:{}",target.sandbox_id,target.provider)).bind(&target.workspace).bind(hold.encode_to_vec()).bind(now).bind(now)
                .execute(&mut *tx).await.map_err(|e| map_db_error(&e))?;
            ProviderDetachOutcomeV1 {
                state: "applied".into(),
                receipt: Some(receipt.clone()),
            }
        } else {
            ProviderDetachOutcomeV1 {
                state: "rejected_no_effect".into(),
                receipt: None,
            }
        };
        let stored = StoredProviderDetachActionV1 {
            schema_version: 1,
            original_action: Some(action.clone()),
            outcome: Some(outcome.clone()),
            recorded_time: receipt.recorded_time,
        };
        let now = current_time_ms();
        sqlx::query("INSERT INTO objects (object_type,id,name,workspace,payload,created_at_ms,updated_at_ms) VALUES (?,?,?,?,?,?,?)")
            .bind(super::PROVIDER_DETACH_ACTION_OBJECT_TYPE).bind(&action.action_id).bind(&action.action_id).bind(&target.workspace).bind(stored.encode_to_vec()).bind(now).bind(now)
            .execute(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        tx.commit().await.map_err(|e| map_db_error(&e))?;
        Ok(outcome)
        }.with_subscriber(tracing::subscriber::NoSubscriber::default()).await
    }

    // Internal v1 creation preserves one immutable current hold. Exact replay
    // keeps its original row/version; a conflicting name OR ID never overwrites
    // provenance. Future authorized transitions need a separate reviewed CAS API.
    async fn put_provider_detach_hold(
        &self,
        id: &str,
        name: &str,
        workspace: &str,
        payload: &[u8],
    ) -> PersistenceResult<()> {
        // Keep outer Store/RPC spans intact. SQLx transaction worker spans
        // otherwise retain registry IDs across dispatchers, reproduced by the
        // existing compute parent-span regression; isolate internal SQL spans.
        use tracing::instrument::WithSubscriber;
        async {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| map_db_error(&e))?;
        let rows: Vec<(String, String, String, Vec<u8>)> = sqlx::query_as(
            "SELECT id,name,workspace,payload FROM objects WHERE object_type=? AND (id=? OR (workspace=? AND name=?))")
            .bind(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE).bind(id).bind(workspace).bind(name)
            .fetch_all(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        if rows.is_empty() {
            let now = current_time_ms();
            sqlx::query("INSERT INTO objects (object_type,id,name,workspace,payload,created_at_ms,updated_at_ms) VALUES (?,?,?,?,?,?,?)")
                .bind(super::PROVIDER_DETACH_HOLD_OBJECT_TYPE).bind(id).bind(name).bind(workspace)
                .bind(payload).bind(now).bind(now).execute(&mut *tx).await.map_err(|e| map_db_error(&e))?;
        } else if rows.len() != 1
            || rows[0]
                != (
                    id.to_string(),
                    name.to_string(),
                    workspace.to_string(),
                    payload.to_vec(),
                )
        {
            return Err(PersistenceError::Config(
                "provider hold immutable generation conflict".into(),
            ));
        }
        tx.commit().await.map_err(|e| map_db_error(&e))?;
        Ok(())
        }.with_subscriber(tracing::subscriber::NoSubscriber::default()).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn put_held_sandbox(
        &self,
        id: &str,
        name: &str,
        workspace: &str,
        scope: Option<&str>,
        payload: &[u8],
        labels: Option<&str>,
        condition: WriteCondition,
        increment: bool,
    ) -> PersistenceResult<WriteResult> {
        // Keep outer Store/RPC spans intact. SQLx transaction worker spans
        // otherwise retain registry IDs across dispatchers, reproduced by the
        // existing compute parent-span regression; isolate internal SQL spans.
        use tracing::instrument::WithSubscriber;
        async {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| map_db_error(&e))?;
        Box::pin(check_provider_detach_holds(&mut tx, id, name, workspace, payload)).await?;
        let now_ms = current_time_ms();
        let lookup_by_id = matches!(condition, WriteCondition::MatchResourceVersion(_));
        match condition {
            WriteCondition::MatchResourceVersion(expected) => {
                let expected = i64::try_from(expected).map_err(|_| PersistenceError::Conflict {
                    current_resource_version: None,
                })?;
                let changed = sqlx::query("UPDATE objects SET payload=?,labels=?,updated_at_ms=?,resource_version=resource_version+1 WHERE object_type='sandbox' AND id=? AND resource_version=?")
                    .bind(payload).bind(labels.unwrap_or("{}")).bind(now_ms).bind(id).bind(expected)
                    .execute(&mut *tx).await.map_err(|e| map_db_error(&e))?;
                if changed.rows_affected() != 1 {
                    let current: Option<(i64, Vec<u8>, String, String)> = sqlx::query_as(
                        "SELECT resource_version,payload,name,workspace FROM objects WHERE object_type='sandbox' AND id=?",
                    )
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| map_db_error(&e))?;
                    // Preserve the pre-existing CAS contract: a concurrent write
                    // simulated by an UPDATE trigger must survive this conflict,
                    // otherwise its marker/RV rolls back and retries never make
                    // progress. Recheck the actual resulting payload before
                    // committing; a trigger cannot restore an active hold.
                    if let Some((_, bytes, current_name, current_workspace)) = &current {
                        Box::pin(check_provider_detach_holds(
                            &mut tx,
                            id,
                            current_name,
                            current_workspace,
                            bytes,
                        ))
                        .await?;
                    }
                    let version = current.and_then(|(v, _, _, _)| u64::try_from(v).ok());
                    tx.commit().await.map_err(|e| map_db_error(&e))?;
                    return Err(PersistenceError::Conflict {
                        current_resource_version: version,
                    });
                }
            }
            WriteCondition::MustCreate => {
                sqlx::query("INSERT INTO objects(object_type,id,name,workspace,scope,payload,created_at_ms,updated_at_ms,labels,resource_version) VALUES('sandbox',?,?,?,?,?,?,?,?,1)")
                    .bind(id).bind(name).bind(workspace).bind(scope).bind(payload).bind(now_ms).bind(now_ms).bind(labels.unwrap_or("{}"))
                    .execute(&mut *tx).await.map_err(|e| map_db_error(&e))?;
            }
            WriteCondition::Unconditional => {
                sqlx::query("INSERT INTO objects(object_type,id,name,workspace,scope,payload,created_at_ms,updated_at_ms,labels,resource_version) VALUES('sandbox',?,?,?,?,?,?,?,?,1) ON CONFLICT(object_type,workspace,name) WHERE name IS NOT NULL DO UPDATE SET scope=COALESCE(excluded.scope,objects.scope),payload=excluded.payload,updated_at_ms=excluded.updated_at_ms,labels=excluded.labels,resource_version=objects.resource_version+?")
                    .bind(id).bind(name).bind(workspace).bind(scope).bind(payload).bind(now_ms).bind(now_ms).bind(labels.unwrap_or("{}")).bind(i64::from(increment))
                    .execute(&mut *tx).await.map_err(|e| map_db_error(&e))?;
            }
        }
        let result: (i64, i64, i64) = if lookup_by_id {
            sqlx::query_as("SELECT resource_version,created_at_ms,updated_at_ms FROM objects WHERE object_type='sandbox' AND id=?")
                .bind(id).fetch_one(&mut *tx).await.map_err(|e| map_db_error(&e))?
        } else {
            sqlx::query_as("SELECT resource_version,created_at_ms,updated_at_ms FROM objects WHERE object_type='sandbox' AND workspace=? AND name=?")
                .bind(workspace).bind(name).fetch_one(&mut *tx).await.map_err(|e| map_db_error(&e))?
        };
        tx.commit().await.map_err(|e| map_db_error(&e))?;
        Ok(WriteResult {
            resource_version: u64::try_from(result.0)
                .map_err(|_| PersistenceError::Decode("invalid sandbox version".into()))?,
            created_at_ms: result.1,
            updated_at_ms: result.2,
        })
        }.with_subscriber(tracing::subscriber::NoSubscriber::default()).await
    }

    /// Closes the connection pool.
    #[cfg(test)]
    pub(crate) async fn close_for_test(&self) {
        self.close().await;
    }

    pub async fn connect(url: &str) -> PersistenceResult<Self> {
        let is_in_memory = url.contains(":memory:") || url.contains("mode=memory");
        let max_connections = if is_in_memory { 1 } else { 5 };

        let mut options = SqliteConnectOptions::from_str(url)
            .map_err(|e| map_db_error(&e))?
            .create_if_missing(true);

        if is_in_memory {
            if options.get_filename().as_os_str().is_empty()
                || options.get_filename() == Path::new(":memory:")
            {
                let sequence = IN_MEMORY_DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                options = options.filename(format!("file:openshell-in-memory-{sequence}"));
            }
            options = options.shared_cache(true);
        }

        let mut pool_options = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .min_connections(max_connections);

        if is_in_memory {
            pool_options = pool_options.idle_timeout(None).max_lifetime(None);
        }

        // Capture the on-disk path before `connect_with` consumes the options
        // so we can restrict the permissions after the database is connected.
        let db_path = (!is_in_memory).then(|| options.get_filename().to_path_buf());

        if !is_in_memory {
            options = configure_on_disk_durability(options).await?;
        }

        let in_memory_keepalive = if is_in_memory {
            let connection = SqliteConnection::connect_with(&options)
                .await
                .map_err(|e| map_db_error(&e))?;
            Some(Arc::new(Mutex::new(Some(connection))))
        } else {
            None
        };

        let relaxed_options =
            (!is_in_memory).then(|| options.clone().synchronous(SqliteSynchronous::Normal));

        let pool = pool_options
            .connect_with(options)
            .await
            .map_err(|e| map_db_error(&e))?;

        // SQLite serializes writers, so one connection is enough for the
        // relaxed pool.
        let relaxed_pool = match relaxed_options {
            Some(relaxed_options) => SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(relaxed_options)
                .await
                .map_err(|e| map_db_error(&e))?,
            None => pool.clone(),
        };

        // Tighten the permissions of the database file to owner-only access (0o600).
        if let Some(path) = db_path {
            restrict_db_file_permissions(&path)?;
        }

        Ok(Self {
            pool,
            relaxed_pool,
            in_memory_keepalive,
        })
    }

    pub async fn migrate(&self) -> PersistenceResult<()> {
        SQLITE_MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|e| map_migrate_error(&e))?;
        self.migrate_legacy_time_payloads().await
    }

    async fn migrate_legacy_time_payloads(&self) -> PersistenceResult<()> {
        let mut transaction = self.pool.begin().await.map_err(|e| map_db_error(&e))?;
        let rows = sqlx::query("SELECT id, object_type, payload FROM objects ORDER BY id")
            .fetch_all(&mut *transaction)
            .await
            .map_err(|e| map_db_error(&e))?;

        for row in rows {
            let id: String = row.try_get("id").map_err(|e| map_db_error(&e))?;
            let object_type: String = row.try_get("object_type").map_err(|e| map_db_error(&e))?;
            let payload: Vec<u8> = row.try_get("payload").map_err(|e| map_db_error(&e))?;
            let migrated =
                super::legacy_time_wire::migrate(&object_type, &payload).map_err(|error| {
                    PersistenceError::Migration(format!(
                        "failed to migrate {object_type} record {id}: {error}"
                    ))
                })?;
            if migrated != payload {
                sqlx::query("UPDATE objects SET payload = ?1 WHERE id = ?2")
                    .bind(migrated)
                    .bind(id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|e| map_db_error(&e))?;
            }
        }

        transaction.commit().await.map_err(|e| map_db_error(&e))
    }

    /// Verify the database is reachable by acquiring a pooled connection
    /// and issuing a ping.
    pub async fn ping(&self) -> PersistenceResult<()> {
        let mut conn = self.pool.acquire().await.map_err(|e| map_db_error(&e))?;
        conn.ping().await.map_err(|e| map_db_error(&e))
    }

    /// Test support only: close the underlying connection pool.
    ///
    /// Do not call from runtime code; this tears down the active pool.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn close(&self) {
        self.relaxed_pool.close().await;
        self.pool.close().await;
        if let Some(keepalive) = &self.in_memory_keepalive {
            let connection = keepalive.lock().await.take();
            if let Some(connection) = connection {
                let _ = connection.close().await;
            }
        }
    }

    pub async fn put(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<()> {
        if object_type == super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE
            || object_type == super::PROVIDER_OBSERVATION_OBJECT_TYPE
            || object_type == super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE
        {
            return Err(PersistenceError::Config(
                "provider witness requires original native transaction".into(),
            ));
        }
        if object_type == super::PROVIDER_DETACH_HOLD_OBJECT_TYPE {
            return Box::pin(self.put_provider_detach_hold(id, name, workspace, payload)).await;
        }
        if object_type == "sandbox" {
            Box::pin(self.put_held_sandbox(
                id,
                name,
                workspace,
                None,
                payload,
                labels,
                WriteCondition::Unconditional,
                false,
            ))
            .await?;
            return Ok(());
        }
        let now_ms = current_time_ms();

        sqlx::query(
            r#"
INSERT INTO "objects" ("object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels")
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)
ON CONFLICT ("object_type", "workspace", "name") WHERE "name" IS NOT NULL DO UPDATE SET
    "payload" = excluded."payload",
    "updated_at_ms" = excluded."updated_at_ms",
    "labels" = excluded."labels"
"#,
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(workspace)
        .bind(payload)
        .bind(now_ms)
        .bind(labels.unwrap_or("{}"))
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    /// Create an object with `synchronous=NORMAL` durability.
    ///
    /// Same semantics as [`Self::put_if`] with [`WriteCondition::MustCreate`],
    /// except that a power loss or kernel crash shortly after the call returns
    /// may roll the insert back. Use it only for objects whose absence denies
    /// access, never for writes that revoke or tighten anything.
    pub async fn create_relaxed(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<WriteResult> {
        if object_type == super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE
            || object_type == super::PROVIDER_OBSERVATION_OBJECT_TYPE
            || object_type == super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE
        {
            return Err(PersistenceError::Config(
                "provider witness requires original native transaction".into(),
            ));
        }
        if object_type == super::PROVIDER_DETACH_HOLD_OBJECT_TYPE {
            return Err(PersistenceError::Config(
                "provider hold requires immutable native creation".into(),
            ));
        }
        if object_type == "sandbox" {
            return Box::pin(self.put_held_sandbox(
                id,
                name,
                workspace,
                None,
                payload,
                labels,
                WriteCondition::MustCreate,
                true,
            ))
            .await;
        }
        insert_new_object(
            &self.relaxed_pool,
            object_type,
            id,
            name,
            workspace,
            payload,
            labels,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_if(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        payload: &[u8],
        labels: Option<&str>,
        condition: WriteCondition,
    ) -> PersistenceResult<WriteResult> {
        if object_type == super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE
            || object_type == super::PROVIDER_OBSERVATION_OBJECT_TYPE
            || object_type == super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE
        {
            return Err(PersistenceError::Config(
                "provider witness requires original native transaction".into(),
            ));
        }
        if object_type == super::PROVIDER_DETACH_HOLD_OBJECT_TYPE {
            return Err(PersistenceError::Config(
                "provider hold requires immutable native creation".into(),
            ));
        }
        if object_type == "sandbox" {
            return Box::pin(
                self.put_held_sandbox(id, name, workspace, None, payload, labels, condition, true),
            )
            .await;
        }
        let now_ms = current_time_ms();

        match condition {
            WriteCondition::MustCreate => {
                insert_new_object(
                    &self.pool,
                    object_type,
                    id,
                    name,
                    workspace,
                    payload,
                    labels,
                )
                .await
            }
            WriteCondition::MatchResourceVersion(expected_version) => {
                // Update with version check
                let result = sqlx::query(
                    r#"
UPDATE "objects"
SET "payload" = ?4, "labels" = ?5, "updated_at_ms" = ?6, "resource_version" = "resource_version" + 1
WHERE "object_type" = ?1 AND "id" = ?2 AND "resource_version" = ?3
"#,
                )
                .bind(object_type)
                .bind(id)
                .bind(i64::try_from(expected_version).unwrap_or(i64::MAX))
                .bind(payload)
                .bind(labels.unwrap_or("{}"))
                .bind(now_ms)
                .execute(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?;

                if result.rows_affected() == 0 {
                    // The version-matched UPDATE matched no row. Distinguish a
                    // version mismatch (row present, different version) from an
                    // absent row (deleted / never existed). Both are CAS
                    // precondition failures, so report them as typed `Conflict`
                    // rather than a backend-dependent error string: absent rows
                    // carry `current_resource_version: None`.
                    let existing = self.get(object_type, id).await?;
                    return Err(PersistenceError::Conflict {
                        current_resource_version: existing.map(|record| record.resource_version),
                    });
                }

                // Fetch the updated record to get the new resource_version
                let updated = self.get(object_type, id).await?.ok_or_else(|| {
                    PersistenceError::Database("object disappeared after update".to_string())
                })?;

                Ok(WriteResult {
                    resource_version: updated.resource_version,
                    created_at_ms: updated.created_at_ms,
                    updated_at_ms: updated.updated_at_ms,
                })
            }
            WriteCondition::Unconditional => {
                // Unconditional upsert by name
                sqlx::query(
                    r#"
INSERT INTO "objects" ("object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version")
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, 1)
ON CONFLICT ("object_type", "workspace", "name") WHERE "name" IS NOT NULL DO UPDATE SET
    "payload" = excluded."payload",
    "updated_at_ms" = excluded."updated_at_ms",
    "labels" = excluded."labels",
    "resource_version" = "objects"."resource_version" + 1
"#,
                )
                .bind(object_type)
                .bind(id)
                .bind(name)
                .bind(workspace)
                .bind(payload)
                .bind(now_ms)
                .bind(labels.unwrap_or("{}"))
                .execute(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?;

                // Fetch the result to get the resource_version
                let record = self
                    .get_by_name(object_type, workspace, name)
                    .await?
                    .ok_or_else(|| {
                        PersistenceError::Database("object disappeared after upsert".to_string())
                    })?;

                Ok(WriteResult {
                    resource_version: record.resource_version,
                    created_at_ms: record.created_at_ms,
                    updated_at_ms: record.updated_at_ms,
                })
            }
        }
    }

    pub async fn delete_if(
        &self,
        object_type: &str,
        id: &str,
        expected_resource_version: u64,
    ) -> PersistenceResult<bool> {
        if object_type == super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE
            || object_type == super::PROVIDER_OBSERVATION_OBJECT_TYPE
            || object_type == super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE
        {
            return Err(PersistenceError::Config(
                "provider witness requires original native transaction".into(),
            ));
        }
        if object_type == super::PROVIDER_DETACH_HOLD_OBJECT_TYPE {
            return Err(PersistenceError::Config(
                "provider hold requires immutable native creation".into(),
            ));
        }
        let result = sqlx::query(
            r#"
DELETE FROM "objects"
WHERE "object_type" = ?1 AND "id" = ?2 AND "resource_version" = ?3
"#,
        )
        .bind(object_type)
        .bind(id)
        .bind(i64::try_from(expected_resource_version).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        if result.rows_affected() > 0 {
            Ok(true)
        } else {
            // Check if object exists to distinguish NotFound from Conflict
            let existing = self.get(object_type, id).await?;
            if let Some(record) = existing {
                return Err(PersistenceError::Conflict {
                    current_resource_version: Some(record.resource_version),
                });
            }
            Ok(false)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_scoped(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        scope: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<()> {
        if object_type == super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE
            || object_type == super::PROVIDER_OBSERVATION_OBJECT_TYPE
            || object_type == super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE
        {
            return Err(PersistenceError::Config(
                "provider witness requires original native transaction".into(),
            ));
        }
        if object_type == super::PROVIDER_DETACH_HOLD_OBJECT_TYPE {
            return Err(PersistenceError::Config(
                "provider hold requires immutable native creation".into(),
            ));
        }
        if object_type == "sandbox" {
            Box::pin(self.put_held_sandbox(
                id,
                name,
                workspace,
                Some(scope),
                payload,
                labels,
                WriteCondition::Unconditional,
                true,
            ))
            .await?;
            return Ok(());
        }
        let now_ms = current_time_ms();

        sqlx::query(
            r#"
INSERT INTO "objects" ("object_type", "id", "name", "workspace", "scope", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version")
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, 1)
ON CONFLICT ("object_type", "workspace", "name") WHERE "name" IS NOT NULL DO UPDATE SET
    "scope" = excluded."scope",
    "payload" = excluded."payload",
    "updated_at_ms" = excluded."updated_at_ms",
    "labels" = excluded."labels",
    "resource_version" = "objects"."resource_version" + 1
"#,
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(workspace)
        .bind(scope)
        .bind(payload)
        .bind(now_ms)
        .bind(labels.unwrap_or("{}"))
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_scoped(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        scope: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<WriteResult> {
        if object_type == super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE
            || object_type == super::PROVIDER_OBSERVATION_OBJECT_TYPE
            || object_type == super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE
        {
            return Err(PersistenceError::Config(
                "provider witness requires original native transaction".into(),
            ));
        }
        if object_type == super::PROVIDER_DETACH_HOLD_OBJECT_TYPE {
            return Err(PersistenceError::Config(
                "provider hold requires immutable native creation".into(),
            ));
        }
        if object_type == "sandbox" {
            return Box::pin(self.put_held_sandbox(
                id,
                name,
                workspace,
                Some(scope),
                payload,
                labels,
                WriteCondition::MustCreate,
                true,
            ))
            .await;
        }
        let now_ms = current_time_ms();

        sqlx::query(
            r#"
INSERT INTO "objects" ("object_type", "id", "name", "workspace", "scope", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version")
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, 1)
"#,
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(workspace)
        .bind(scope)
        .bind(payload)
        .bind(now_ms)
        .bind(labels.unwrap_or("{}"))
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(WriteResult {
            resource_version: 1,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_if_workspace_count_below(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        payload: &[u8],
        labels: Option<&str>,
        max_count: u64,
    ) -> PersistenceResult<Option<WriteResult>> {
        if object_type == super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE
            || object_type == super::PROVIDER_OBSERVATION_OBJECT_TYPE
            || object_type == super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE
        {
            return Err(PersistenceError::Config(
                "provider witness requires original native transaction".into(),
            ));
        }
        if object_type == super::PROVIDER_DETACH_HOLD_OBJECT_TYPE {
            return Err(PersistenceError::Config(
                "provider hold requires immutable native creation".into(),
            ));
        }
        let now_ms = current_time_ms();
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| map_db_error(&e))?;

        if object_type == "sandbox" {
            Box::pin(check_provider_detach_holds(
                &mut tx, id, name, workspace, payload,
            ))
            .await?;
        }

        let row: (i64,) = sqlx::query_as(
            r#"
SELECT COUNT(*) FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2
"#,
        )
        .bind(object_type)
        .bind(workspace)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;
        let count = u64::try_from(row.0).unwrap_or(0);
        if count >= max_count {
            tx.commit().await.map_err(|e| map_db_error(&e))?;
            return Ok(None);
        }

        sqlx::query(
            r#"
INSERT INTO "objects" ("object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version")
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, 1)
"#,
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(workspace)
        .bind(payload)
        .bind(now_ms)
        .bind(labels.unwrap_or("{}"))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;

        tx.commit().await.map_err(|e| map_db_error(&e))?;

        Ok(Some(WriteResult {
            resource_version: 1,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        }))
    }

    pub async fn get(
        &self,
        object_type: &str,
        id: &str,
    ) -> PersistenceResult<Option<ObjectRecord>> {
        let row = sqlx::query(
            r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "id" = ?2
"#,
        )
        .bind(object_type)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(row_to_object_record))
    }

    pub async fn get_by_name(
        &self,
        object_type: &str,
        workspace: &str,
        name: &str,
    ) -> PersistenceResult<Option<ObjectRecord>> {
        let row = sqlx::query(
            r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2 AND "name" = ?3
"#,
        )
        .bind(object_type)
        .bind(workspace)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(row_to_object_record))
    }

    pub async fn delete(&self, object_type: &str, id: &str) -> PersistenceResult<bool> {
        if object_type == super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE
            || object_type == super::PROVIDER_OBSERVATION_OBJECT_TYPE
            || object_type == super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE
        {
            return Err(PersistenceError::Config(
                "provider witness requires original native transaction".into(),
            ));
        }
        if object_type == super::PROVIDER_DETACH_HOLD_OBJECT_TYPE {
            return Err(PersistenceError::Config(
                "provider hold requires immutable native creation".into(),
            ));
        }
        let result = sqlx::query(
            r#"
DELETE FROM "objects"
WHERE "object_type" = ?1 AND "id" = ?2
"#,
        )
        .bind(object_type)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_many(&self, object_type: &str, ids: &[String]) -> PersistenceResult<u64> {
        if object_type == super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE
            || object_type == super::PROVIDER_OBSERVATION_OBJECT_TYPE
            || object_type == super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE
        {
            return Err(PersistenceError::Config(
                "provider witness requires original native transaction".into(),
            ));
        }
        if object_type == super::PROVIDER_DETACH_HOLD_OBJECT_TYPE {
            return Err(PersistenceError::Config(
                "provider hold requires immutable native creation".into(),
            ));
        }
        let mut deleted = 0_u64;
        for ids in ids.chunks(DELETE_MANY_BATCH_SIZE) {
            let mut query = QueryBuilder::<Sqlite>::new("DELETE FROM objects WHERE object_type = ");
            query.push_bind(object_type).push(" AND id IN (");
            let mut separated = query.separated(", ");
            for id in ids {
                separated.push_bind(id);
            }
            separated.push_unseparated(")");

            deleted += query
                .build()
                .execute(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?
                .rows_affected();
        }
        Ok(deleted)
    }

    pub async fn count_in_workspace(
        &self,
        object_type: &str,
        workspace: &str,
    ) -> PersistenceResult<u64> {
        let row: (i64,) = sqlx::query_as(
            r#"
SELECT COUNT(*) FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2
"#,
        )
        .bind(object_type)
        .bind(workspace)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(u64::try_from(row.0).unwrap_or(0))
    }

    pub async fn delete_all_in_workspace(
        &self,
        object_type: &str,
        workspace: &str,
    ) -> PersistenceResult<u64> {
        if object_type == super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE
            || object_type == super::PROVIDER_OBSERVATION_OBJECT_TYPE
            || object_type == super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE
        {
            return Err(PersistenceError::Config(
                "provider witness requires original native transaction".into(),
            ));
        }
        if object_type == super::PROVIDER_DETACH_HOLD_OBJECT_TYPE {
            return Err(PersistenceError::Config(
                "provider hold requires immutable native creation".into(),
            ));
        }
        let result = sqlx::query(
            r#"
DELETE FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2
"#,
        )
        .bind(object_type)
        .bind(workspace)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }

    pub async fn delete_by_scope(&self, object_type: &str, scope: &str) -> PersistenceResult<u64> {
        if object_type == super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE
            || object_type == super::PROVIDER_OBSERVATION_OBJECT_TYPE
            || object_type == super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE
        {
            return Err(PersistenceError::Config(
                "provider witness requires original native transaction".into(),
            ));
        }
        if object_type == super::PROVIDER_DETACH_HOLD_OBJECT_TYPE {
            return Err(PersistenceError::Config(
                "provider hold requires immutable native creation".into(),
            ));
        }
        let result = sqlx::query(
            r#"
DELETE FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2
"#,
        )
        .bind(object_type)
        .bind(scope)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }

    pub async fn delete_by_name(
        &self,
        object_type: &str,
        workspace: &str,
        name: &str,
    ) -> PersistenceResult<bool> {
        if object_type == super::PROVIDER_DETACH_WITNESS_OBJECT_TYPE
            || object_type == super::PROVIDER_OBSERVATION_OBJECT_TYPE
            || object_type == super::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE
        {
            return Err(PersistenceError::Config(
                "provider witness requires original native transaction".into(),
            ));
        }
        if object_type == super::PROVIDER_DETACH_HOLD_OBJECT_TYPE {
            return Err(PersistenceError::Config(
                "provider hold requires immutable native creation".into(),
            ));
        }
        let result = sqlx::query(
            r#"
DELETE FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2 AND "name" = ?3
"#,
        )
        .bind(object_type)
        .bind(workspace)
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list(
        &self,
        object_type: &str,
        workspace: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2
ORDER BY "created_at_ms" ASC, "name" ASC
LIMIT ?3 OFFSET ?4
"#,
        )
        .bind(object_type)
        .bind(workspace)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_by_type(
        &self,
        object_type: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1
ORDER BY "created_at_ms" ASC, "name" ASC, "workspace" ASC, "id" ASC
LIMIT ?2 OFFSET ?3
"#,
        )
        .bind(object_type)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }
    pub async fn list_after(
        &self,
        object_type: &str,
        workspace: &str,
        after: Option<&ObjectCursor>,
        limit: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = if let Some(cursor) = after {
            sqlx::query(
                r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2
  AND ("created_at_ms", "name", "id") > (?3, ?4, ?5)
ORDER BY "created_at_ms" ASC, "name" ASC, "id" ASC
LIMIT ?6
"#,
            )
            .bind(object_type)
            .bind(workspace)
            .bind(cursor.created_at_ms)
            .bind(&cursor.name)
            .bind(&cursor.id)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2
ORDER BY "created_at_ms" ASC, "name" ASC, "id" ASC
LIMIT ?3
"#,
            )
            .bind(object_type)
            .bind(workspace)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|e| map_db_error(&e))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }
    pub async fn list_by_type_after(
        &self,
        object_type: &str,
        after: Option<&ObjectCursor>,
        limit: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = if let Some(cursor) = after {
            sqlx::query(r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1
  AND ("created_at_ms", "name", "workspace", "id") > (?2, ?3, ?4, ?5)
ORDER BY "created_at_ms" ASC, "name" ASC, "workspace" ASC, "id" ASC
LIMIT ?6
"#).bind(object_type).bind(cursor.created_at_ms).bind(&cursor.name).bind(&cursor.workspace).bind(&cursor.id).bind(i64::from(limit)).fetch_all(&self.pool).await
        } else {
            sqlx::query(r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1
ORDER BY "created_at_ms" ASC, "name" ASC, "workspace" ASC, "id" ASC
LIMIT ?2
"#).bind(object_type).bind(i64::from(limit)).fetch_all(&self.pool).await
        }.map_err(|e| map_db_error(&e))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_object_page(
        &self,
        object_type: &str,
        query: ObjectListQuery<'_>,
        after: Option<&ObjectCursor>,
        limit: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let mut sql = QueryBuilder::<Sqlite>::new(
            "SELECT o.object_type, o.id, o.name, o.workspace, o.payload, \
             o.created_at_ms, o.updated_at_ms, o.labels, o.resource_version \
             FROM objects o WHERE o.object_type = ",
        );
        sql.push_bind(object_type);

        match query {
            ObjectListQuery::Workspace(workspace) => {
                sql.push(" AND o.workspace = ").push_bind(workspace);
            }
            ObjectListQuery::AllWorkspaces => {}
            ObjectListQuery::Scope(scope) => {
                sql.push(" AND o.scope = ").push_bind(scope);
            }
            ObjectListQuery::WorkspaceSelector {
                workspace,
                label_selector,
            } => {
                sql.push(" AND o.workspace = ").push_bind(workspace);
                push_label_selector(&mut sql, label_selector)?;
            }
            ObjectListQuery::AllWorkspacesSelector(label_selector) => {
                push_label_selector(&mut sql, label_selector)?;
            }
            ObjectListQuery::Membership {
                member_type,
                member_name,
            } => {
                sql.push(
                    " AND o.workspace = '' AND EXISTS (SELECT 1 FROM objects m \
                          WHERE m.object_type = ",
                )
                .push_bind(member_type)
                .push(" AND m.workspace = o.name AND m.name = ")
                .push_bind(member_name)
                .push(")");
            }
            ObjectListQuery::MembershipSelector {
                member_type,
                member_name,
                label_selector,
            } => {
                sql.push(
                    " AND o.workspace = '' AND EXISTS (SELECT 1 FROM objects m \
                          WHERE m.object_type = ",
                )
                .push_bind(member_type)
                .push(" AND m.workspace = o.name AND m.name = ")
                .push_bind(member_name)
                .push(")");
                push_label_selector(&mut sql, label_selector)?;
            }
        }

        if let Some(cursor) = after {
            sql.push(" AND (o.created_at_ms, COALESCE(o.name, ''), o.workspace, o.id) > (")
                .push_bind(cursor.created_at_ms)
                .push(", ")
                .push_bind(&cursor.name)
                .push(", ")
                .push_bind(&cursor.workspace)
                .push(", ")
                .push_bind(&cursor.id)
                .push(")");
        }
        sql.push(
            " ORDER BY o.created_at_ms ASC, COALESCE(o.name, '') ASC, \
             o.workspace ASC, o.id ASC LIMIT ",
        )
        .push_bind(i64::from(limit));

        let rows = sql
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_with_membership(
        &self,
        object_type: &str,
        member_type: &str,
        member_name: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r#"
SELECT w."object_type", w."id", w."name", w."workspace", w."payload",
       w."created_at_ms", w."updated_at_ms", w."labels", w."resource_version"
FROM "objects" w
WHERE w."object_type" = ?1 AND w."workspace" = ''
AND EXISTS (
    SELECT 1 FROM "objects" m
    WHERE m."object_type" = ?2
    AND m."workspace" = w."name"
    AND m."name" = ?3
)
ORDER BY w."created_at_ms" ASC, w."name" ASC
LIMIT ?4 OFFSET ?5
"#,
        )
        .bind(object_type)
        .bind(member_type)
        .bind(member_name)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_with_membership_and_selector(
        &self,
        object_type: &str,
        member_type: &str,
        member_name: &str,
        label_selector: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        use std::fmt::Write;

        use super::parse_label_selector;

        let required_labels = parse_label_selector(label_selector)?;

        let mut sql = String::from(
            r#"
SELECT w."object_type", w."id", w."name", w."workspace", w."payload",
       w."created_at_ms", w."updated_at_ms", w."labels", w."resource_version"
FROM "objects" w
WHERE w."object_type" = ?1 AND w."workspace" = ''
AND EXISTS (
    SELECT 1 FROM "objects" m
    WHERE m."object_type" = ?2
    AND m."workspace" = w."name"
    AND m."name" = ?3
)"#,
        );

        let label_pairs: Vec<(&String, &String)> = required_labels.iter().collect();
        for (i, (key, _)) in label_pairs.iter().enumerate() {
            let param_idx = 4 + i;
            write!(
                sql,
                "\nAND json_extract(w.\"labels\", '$.\"{}\"') = ?{}",
                key.replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\'', "''"),
                param_idx
            )
            .unwrap();
        }

        let limit_idx = 4 + label_pairs.len();
        let offset_idx = limit_idx + 1;
        write!(
            sql,
            "\nORDER BY w.\"created_at_ms\" ASC, w.\"name\" ASC\nLIMIT ?{limit_idx} OFFSET ?{offset_idx}\n"
        )
        .unwrap();

        // Label paths above escape SQL quotes; all values remain bound parameters.
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
            .bind(object_type)
            .bind(member_type)
            .bind(member_name);

        for (_, value) in &label_pairs {
            query = query.bind(*value);
        }

        query = query.bind(i64::from(limit)).bind(i64::from(offset));

        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_by_scope(
        &self,
        object_type: &str,
        scope: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2
ORDER BY "created_at_ms" ASC, "name" ASC
LIMIT ?3 OFFSET ?4
"#,
        )
        .bind(object_type)
        .bind(scope)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }
    pub async fn list_with_selector(
        &self,
        object_type: &str,
        workspace: &str,
        label_selector: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let mut sql = QueryBuilder::<Sqlite>::new(
            r#"SELECT o."object_type", o."id", o."name", o."workspace", o."payload", o."created_at_ms", o."updated_at_ms", o."labels", o."resource_version"
FROM "objects" o
WHERE o."object_type" = "#,
        );
        sql.push_bind(object_type).push(" AND o.\"workspace\" = ");
        sql.push_bind(workspace);
        push_label_selector(&mut sql, label_selector)?;
        sql.push(" ORDER BY o.\"created_at_ms\" ASC, o.\"name\" ASC LIMIT ")
            .push_bind(i64::from(limit))
            .push(" OFFSET ")
            .push_bind(i64::from(offset));
        let rows = sql
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_all_with_selector(
        &self,
        object_type: &str,
        label_selector: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let mut sql = QueryBuilder::<Sqlite>::new(
            r#"SELECT o."object_type", o."id", o."name", o."workspace", o."payload", o."created_at_ms", o."updated_at_ms", o."labels", o."resource_version"
FROM "objects" o
WHERE o."object_type" = "#,
        );
        sql.push_bind(object_type);
        push_label_selector(&mut sql, label_selector)?;
        sql.push(" ORDER BY o.\"created_at_ms\" ASC, o.\"name\" ASC LIMIT ")
            .push_bind(i64::from(limit))
            .push(" OFFSET ")
            .push_bind(i64::from(offset));
        let rows = sql
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }
    pub async fn put_policy_revision(
        &self,
        id: &str,
        sandbox_id: &str,
        workspace: &str,
        version: i64,
        payload: &[u8],
        hash: &str,
    ) -> PersistenceResult<()> {
        let now_ms = current_time_ms();
        let record = PolicyRecord {
            id: id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            version,
            policy_payload: payload.to_vec(),
            policy_hash: hash.to_string(),
            status: "pending".to_string(),
            load_error: None,
            created_at_ms: now_ms,
            loaded_at_ms: None,
            provenance: std::collections::HashMap::default(),
        };
        let wrapped_payload = policy_payload_from_record(&record)?;

        sqlx::query(
            r#"
INSERT INTO "objects" (
    "object_type", "id", "scope", "version", "status", "payload", "created_at_ms", "updated_at_ms", "workspace"
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8)
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(id)
        .bind(sandbox_id)
        .bind(version)
        .bind("pending")
        .bind(wrapped_payload)
        .bind(now_ms)
        .bind(workspace)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    pub async fn put_policy_revision_atomic(
        &self,
        write: &AtomicPolicyRevisionWrite,
    ) -> PersistenceResult<Sandbox> {
        let now_ms = current_time_ms();
        let record = policy_record_for_atomic_write(write, now_ms);
        let wrapped_payload = policy_payload_from_record(&record)?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| map_db_error(&e))?;

        let row = sqlx::query(
            r#"
SELECT "payload", "resource_version"
FROM "objects"
WHERE "object_type" = 'sandbox' AND "id" = ?1
"#,
        )
        .bind(&write.sandbox_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?
        .ok_or_else(|| {
            PersistenceError::Database(format!("sandbox object {} not found", write.sandbox_id))
        })?;

        let sandbox_payload: Vec<u8> = row.get("payload");
        let current_version: i64 = row.try_get("resource_version").unwrap_or(1);
        let current_version = current_version.max(1).cast_unsigned();
        let mut sandbox =
            project_policy_revision_onto_sandbox(write, &sandbox_payload, current_version)?;
        let meta = sandbox
            .metadata
            .as_ref()
            .ok_or_else(|| PersistenceError::Config("sandbox metadata absent".into()))?;
        Box::pin(check_provider_detach_holds(
            &mut tx,
            &write.sandbox_id,
            &meta.name,
            &write.workspace,
            &sandbox.encode_to_vec(),
        ))
        .await?;

        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "payload" = ?2, "updated_at_ms" = ?3, "resource_version" = "resource_version" + 1
WHERE "object_type" = 'sandbox' AND "id" = ?1 AND "resource_version" = ?4
"#,
        )
        .bind(&write.sandbox_id)
        .bind(sandbox.encode_to_vec())
        .bind(now_ms)
        .bind(i64::try_from(current_version).unwrap_or(i64::MAX))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;
        if result.rows_affected() != 1 {
            return Err(PersistenceError::Conflict {
                current_resource_version: Some(current_version),
            });
        }
        let resulting_version = current_version.saturating_add(1);

        sqlx::query(
            r#"
INSERT INTO "objects" (
    "object_type", "id", "scope", "version", "status", "payload", "created_at_ms", "updated_at_ms", "workspace"
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8)
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(&write.id)
        .bind(&write.sandbox_id)
        .bind(write.version)
        .bind("pending")
        .bind(wrapped_payload)
        .bind(now_ms)
        .bind(&write.workspace)
        .execute(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;

        sqlx::query(
            r#"
UPDATE "objects"
SET "status" = 'superseded', "updated_at_ms" = ?4
WHERE "object_type" = ?1
  AND "scope" = ?2
  AND "version" < ?3
  AND "status" IN ('pending', 'loaded')
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(&write.sandbox_id)
        .bind(write.version)
        .bind(now_ms)
        .execute(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;

        tx.commit().await.map_err(|e| map_db_error(&e))?;
        sandbox.set_resource_version(resulting_version);
        Ok(sandbox)
    }

    pub async fn get_latest_policy(
        &self,
        sandbox_id: &str,
    ) -> PersistenceResult<Option<PolicyRecord>> {
        let row = sqlx::query(
            r#"
SELECT "id", "scope", "version", "status", "payload", "created_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2
ORDER BY "version" DESC, "created_at_ms" DESC
LIMIT 1
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        row.map(row_to_policy_record).transpose()
    }

    pub async fn get_latest_loaded_policy(
        &self,
        sandbox_id: &str,
    ) -> PersistenceResult<Option<PolicyRecord>> {
        let row = sqlx::query(
            r#"
SELECT "id", "scope", "version", "status", "payload", "created_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2 AND "status" = 'loaded'
ORDER BY "version" DESC, "created_at_ms" DESC
LIMIT 1
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        row.map(row_to_policy_record).transpose()
    }

    pub async fn get_policy_by_version(
        &self,
        sandbox_id: &str,
        version: i64,
    ) -> PersistenceResult<Option<PolicyRecord>> {
        let row = sqlx::query(
            r#"
SELECT "id", "scope", "version", "status", "payload", "created_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2 AND "version" = ?3
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        row.map(row_to_policy_record).transpose()
    }

    pub async fn list_policies(
        &self,
        sandbox_id: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<PolicyRecord>> {
        let rows = sqlx::query(
            r#"
SELECT "id", "scope", "version", "status", "payload", "created_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2
ORDER BY "version" DESC, "created_at_ms" DESC
LIMIT ?3 OFFSET ?4
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        rows.into_iter().map(row_to_policy_record).collect()
    }

    pub async fn list_policies_before(
        &self,
        sandbox_id: &str,
        limit: u32,
        before_version: Option<i64>,
    ) -> PersistenceResult<Vec<PolicyRecord>> {
        let rows = sqlx::query(
            r#"
SELECT "id", "scope", "version", "status", "payload", "created_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2 AND (?3 IS NULL OR "version" < ?3)
ORDER BY "version" DESC
LIMIT ?4
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(before_version)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        rows.into_iter().map(row_to_policy_record).collect()
    }

    pub async fn update_policy_status(
        &self,
        sandbox_id: &str,
        version: i64,
        status: &str,
        load_error: Option<&str>,
        loaded_at_ms: Option<i64>,
    ) -> PersistenceResult<bool> {
        let Some(mut record) = self.get_policy_by_version(sandbox_id, version).await? else {
            return Ok(false);
        };

        record.status = status.to_string();
        record.load_error = load_error.map(ToOwned::to_owned);
        record.loaded_at_ms = loaded_at_ms;
        let payload = policy_payload_from_record(&record)?;
        let now_ms = current_time_ms();

        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "status" = ?4, "payload" = ?5, "updated_at_ms" = ?6
WHERE "object_type" = ?1 AND "scope" = ?2 AND "version" = ?3
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(version)
        .bind(status)
        .bind(payload)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn supersede_older_policies(
        &self,
        sandbox_id: &str,
        before_version: i64,
    ) -> PersistenceResult<u64> {
        let now_ms = current_time_ms();
        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "status" = 'superseded', "updated_at_ms" = ?4
WHERE "object_type" = ?1
  AND "scope" = ?2
  AND "version" < ?3
  AND "status" IN ('pending', 'loaded')
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(before_version)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }

    pub async fn put_draft_chunk(
        &self,
        chunk: &DraftChunkRecord,
        dedup_key: Option<&str>,
        workspace: &str,
    ) -> PersistenceResult<String> {
        let payload = draft_chunk_payload_from_record(chunk)?;
        // RETURNING "id" gives us the row's effective id regardless of
        // whether INSERT inserted a fresh row or ON CONFLICT updated an
        // existing one. Callers report this id to clients so the response
        // can never advertise a chunk_id that isn't actually persisted.
        let row = sqlx::query(
            r#"
INSERT INTO "objects" (
    "object_type", "id", "scope", "status", "dedup_key", "hit_count", "payload", "created_at_ms", "updated_at_ms", "workspace"
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
ON CONFLICT ("object_type", "scope", "dedup_key") WHERE "dedup_key" IS NOT NULL DO UPDATE SET
    "hit_count" = "objects"."hit_count" + excluded."hit_count",
    "updated_at_ms" = excluded."updated_at_ms"
RETURNING "id"
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(&chunk.id)
        .bind(&chunk.sandbox_id)
        .bind(&chunk.status)
        .bind(dedup_key)
        .bind(i64::from(chunk.hit_count))
        .bind(payload)
        .bind(chunk.first_seen_ms)
        .bind(chunk.last_seen_ms)
        .bind(workspace)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(row.get::<String, _>("id"))
    }

    pub async fn get_draft_chunk(&self, id: &str) -> PersistenceResult<Option<DraftChunkRecord>> {
        let row = sqlx::query(
            r#"
SELECT "id", "scope", "status", "hit_count", "payload", "created_at_ms", "updated_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "id" = ?2
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        row.map(row_to_draft_chunk_record).transpose()
    }

    pub async fn list_draft_chunks(
        &self,
        sandbox_id: &str,
        status_filter: Option<&str>,
    ) -> PersistenceResult<Vec<DraftChunkRecord>> {
        let rows = if let Some(status) = status_filter {
            sqlx::query(
                r#"
SELECT "id", "scope", "status", "hit_count", "payload", "created_at_ms", "updated_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2 AND "status" = ?3
ORDER BY "created_at_ms" DESC
"#,
            )
            .bind(DRAFT_CHUNK_OBJECT_TYPE)
            .bind(sandbox_id)
            .bind(status)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                r#"
SELECT "id", "scope", "status", "hit_count", "payload", "created_at_ms", "updated_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2
ORDER BY "created_at_ms" DESC
"#,
            )
            .bind(DRAFT_CHUNK_OBJECT_TYPE)
            .bind(sandbox_id)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|e| map_db_error(&e))?;

        rows.into_iter().map(row_to_draft_chunk_record).collect()
    }

    pub async fn update_draft_chunk_status(
        &self,
        id: &str,
        status: &str,
        decided_at_ms: Option<i64>,
        rejection_reason: Option<&str>,
    ) -> PersistenceResult<bool> {
        let Some(mut record) = self.get_draft_chunk(id).await? else {
            return Ok(false);
        };

        record.status = status.to_string();
        record.decided_at_ms = decided_at_ms;
        record.last_seen_ms = current_time_ms();
        if let Some(reason) = rejection_reason {
            record.rejection_reason = reason.to_string();
        }
        let payload = draft_chunk_payload_from_record(&record)?;

        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "status" = ?3, "payload" = ?4, "updated_at_ms" = ?5
WHERE "object_type" = ?1 AND "id" = ?2
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(id)
        .bind(status)
        .bind(payload)
        .bind(record.last_seen_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn conditionally_reject_draft_chunk(
        &self,
        id: &str,
        decided_at_ms: i64,
        rejection_reason: &str,
    ) -> PersistenceResult<bool> {
        let Some(mut record) = self.get_draft_chunk(id).await? else {
            return Ok(false);
        };

        if record.status != "pending" {
            return Ok(false);
        }

        record.status = "rejected".to_string();
        record.decided_at_ms = Some(decided_at_ms);
        record.rejection_reason = rejection_reason.to_string();
        record.last_seen_ms = current_time_ms();
        let payload = draft_chunk_payload_from_record(&record)?;

        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "status" = ?3, "payload" = ?4, "updated_at_ms" = ?5
WHERE "object_type" = ?1 AND "id" = ?2 AND "status" = 'pending'
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(id)
        .bind("rejected")
        .bind(payload)
        .bind(record.last_seen_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_draft_chunk_rule(
        &self,
        id: &str,
        proposed_rule: &[u8],
    ) -> PersistenceResult<bool> {
        let Some(mut record) = self.get_draft_chunk(id).await? else {
            return Ok(false);
        };

        if record.status != "pending" {
            return Ok(false);
        }

        record.proposed_rule = proposed_rule.to_vec();
        record.last_seen_ms = current_time_ms();
        let payload = draft_chunk_payload_from_record(&record)?;

        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "payload" = ?3, "updated_at_ms" = ?4
WHERE "object_type" = ?1 AND "id" = ?2 AND "status" = 'pending'
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(id)
        .bind(payload)
        .bind(record.last_seen_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_draft_chunk_evaluation(
        &self,
        chunk: &DraftChunkRecord,
    ) -> PersistenceResult<bool> {
        let payload = draft_chunk_payload_from_record(chunk)?;
        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "payload" = ?3, "updated_at_ms" = ?4
WHERE "object_type" = ?1 AND "id" = ?2 AND "status" IN ('pending', 'rejected')
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(&chunk.id)
        .bind(payload)
        .bind(chunk.last_seen_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_draft_chunk_evaluation_if_unchanged(
        &self,
        expected: &DraftChunkRecord,
        evaluated: &DraftChunkRecord,
    ) -> PersistenceResult<bool> {
        let Some(row) = sqlx::query(
            r#"
SELECT "id", "scope", "status", "hit_count", "payload", "created_at_ms", "updated_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "id" = ?2 AND "status" IN ('pending', 'rejected')
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(&expected.id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?
        else {
            return Ok(false);
        };
        let stored_payload: Vec<u8> = row.get("payload");
        let mut current = row_to_draft_chunk_record(row)?;
        if !draft_chunk_evaluation_inputs_match(&current, expected) {
            return Ok(false);
        }
        apply_draft_chunk_evaluation(&mut current, evaluated);
        let payload = draft_chunk_payload_from_record(&current)?;
        // Compare-and-swap on the payload read above: a concurrent edit or
        // evaluation between the read and this write leaves nothing updated.
        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "payload" = ?3, "updated_at_ms" = ?4
WHERE "object_type" = ?1 AND "id" = ?2 AND "status" IN ('pending', 'rejected')
  AND "payload" = ?5
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(&expected.id)
        .bind(payload)
        .bind(current.last_seen_ms)
        .bind(stored_payload)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_draft_chunks(
        &self,
        sandbox_id: &str,
        status: &str,
    ) -> PersistenceResult<u64> {
        let result = sqlx::query(
            r#"
DELETE FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2 AND "status" = ?3
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(status)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }

    pub async fn get_draft_version(&self, sandbox_id: &str) -> PersistenceResult<i64> {
        let rows = sqlx::query(
            r#"
SELECT "payload"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(sandbox_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        let mut max_version = 0_i64;
        for row in rows {
            let payload: Vec<u8> = row.get("payload");
            let wrapper = draft_chunk_record_from_parts(
                String::new(),
                sandbox_id.to_string(),
                String::new(),
                0,
                &payload,
                0,
                0,
            )?;
            max_version = max_version.max(wrapper.draft_version);
        }
        Ok(max_version)
    }
}

/// Restrict the on-disk `SQLite` database file (and its WAL/SHM sidecars,
/// when present) to owner-only read/write (`0o600`).
///
/// In WAL mode, `SQLite` keeps two sidecars next to
/// the main database file: `<db>-wal` (uncommitted page log)
/// and `<db>-shm` (shared memory index). They mirror the same sensitive data
/// as the main file, so they get the same `0o600` treatment whenever they exist on disk.
///
/// Delegates to `set_file_owner_only`, which is a no-op on non-Unix platforms.
pub(super) fn restrict_db_file_permissions(path: &Path) -> PersistenceResult<()> {
    set_file_owner_only(path).map_err(|err| PersistenceError::Database(err.to_string()))?;

    for sidecar in sqlite_sidecar_paths(path) {
        if sidecar.exists() {
            set_file_owner_only(&sidecar)
                .map_err(|err| PersistenceError::Database(err.to_string()))?;
        }
    }
    Ok(())
}

/// Compute the WAL/SHM sidecar paths `SQLite` derives from a main database file
/// (e.g. `foo.db` -> [`foo.db-wal`, `foo.db-shm`]).
pub(super) fn sqlite_sidecar_paths(path: &Path) -> [PathBuf; 2] {
    let with_suffix = |suffix: &str| -> PathBuf {
        let mut buf = path.as_os_str().to_os_string();
        buf.push(suffix);
        PathBuf::from(buf)
    };
    [with_suffix("-wal"), with_suffix("-shm")]
}

fn row_to_object_record(row: sqlx::sqlite::SqliteRow) -> ObjectRecord {
    let resource_version_i64: i64 = row.try_get("resource_version").unwrap_or(1);
    ObjectRecord {
        object_type: row.get("object_type"),
        id: row.get("id"),
        name: row.get("name"),
        workspace: row.try_get("workspace").unwrap_or_default(),
        payload: row.get("payload"),
        created_at_ms: row.get("created_at_ms"),
        updated_at_ms: row.get("updated_at_ms"),
        labels: row.get("labels"),
        resource_version: resource_version_i64.max(1).cast_unsigned(),
    }
}

fn row_to_policy_record(row: sqlx::sqlite::SqliteRow) -> PersistenceResult<PolicyRecord> {
    let id: String = row.get("id");
    let sandbox_id: String = row.get("scope");
    let version: i64 = row.get("version");
    let status: String = row.get("status");
    let payload: Vec<u8> = row.get("payload");
    let created_at_ms: i64 = row.get("created_at_ms");
    policy_record_from_parts(id, sandbox_id, version, status, &payload, created_at_ms)
}

fn row_to_draft_chunk_record(row: sqlx::sqlite::SqliteRow) -> PersistenceResult<DraftChunkRecord> {
    let id: String = row.get("id");
    let sandbox_id: String = row.get("scope");
    let status: String = row.get("status");
    let hit_count: i64 = row.get("hit_count");
    let payload: Vec<u8> = row.get("payload");
    let created_at_ms: i64 = row.get("created_at_ms");
    let updated_at_ms: i64 = row.get("updated_at_ms");
    draft_chunk_record_from_parts(
        id,
        sandbox_id,
        status,
        hit_count,
        &payload,
        created_at_ms,
        updated_at_ms,
    )
}

#[cfg(test)]
mod ordinary_original_budget_tests {
    use super::*;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::*;
    use openshell_core::provider_credentials::ordinary_observation as obs;

    #[tokio::test]
    async fn ordinary_old_new_fixed_domains_share_original_exclusion_and_capacity() {
        let state = crate::grpc::test_support::test_server_state_without_provider_profiles().await;
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: uuid::Uuid::new_v4().to_string(),
                name: "ordinary-budget".into(),
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
        let resource = ProviderDetachResourceV1 {
            authority: "gateway".into(),
            workspace: "default".into(),
            sandbox: "ordinary-budget".into(),
            sandbox_id: sandbox.metadata.as_ref().unwrap().id.clone(),
            execution_id: crate::auth::sandbox_session::sandbox_execution_id(&sandbox).unwrap(),
            provider: "model".into(),
            provider_id: provider.metadata.as_ref().unwrap().id.clone(),
        };
        let mut q = ProviderObservationRequestV1 {
            resource: Some(resource.clone()),
            run_id: uuid::Uuid::new_v4().to_string(),
            step_id: uuid::Uuid::new_v4().to_string(),
            profile_id: obs::PROFILE.into(),
            profile_sha256: obs::profile_digest(),
            source_incarnation: uuid::Uuid::new_v4().to_string(),
            boundary_incarnation: uuid::Uuid::new_v4().to_string(),
            deadline: Some(obs::timestamp(current_time_ms() + 60000)),
            phase: ProviderObservationPhaseV1::Baseline as i32,
            evidence_scope: obs::EVIDENCE_SCOPE.into(),
            ..Default::default()
        };
        q.request_sha256 = obs::request_digest(&q);
        let mut expected = ProviderObservationSnapshotV1 {
            resource: Some(resource),
            profile_id: obs::PROFILE.into(),
            profile_sha256: obs::profile_digest(),
            source_incarnation: q.source_incarnation.clone(),
            boundary_incarnation: q.boundary_incarnation.clone(),
            evidence_scope: obs::EVIDENCE_SCOPE.into(),
            process_writer_attribution: obs::WRITER_UNPROVEN,
            mediation_path_id: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        };
        expected.mediation_path_receipt_sha256 = obs::path_digest(&expected);
        let crate::persistence::Store::Sqlite(store) = &*state.store else {
            panic!("SQLite fixture")
        };
        let fence = state.store.provider_detach_fence().await.unwrap();
        // Inject historical opaque rows only through the private test pool. The
        // production CRUD surface cannot create, mutate or delete these kinds.
        sqlx::query("INSERT INTO objects(object_type,id,name,workspace,payload,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,0,0)")
            .bind(crate::persistence::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE).bind(crate::persistence::ordinary_key(&q)).bind(format!("baseline:{}:{}",q.run_id,q.step_id)).bind("default").bind(b"opaque-old-kind".as_slice()).execute(&store.pool).await.unwrap();
        assert!(
            store
                .claim_ordinary_observation(&q, &fence, &expected)
                .await
                .is_err()
        );
        assert!(
            state
                .store
                .delete(
                    crate::persistence::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE,
                    &crate::persistence::ordinary_key(&q)
                )
                .await
                .is_err()
        );
        sqlx::query("DELETE FROM objects WHERE object_type=?")
            .bind(crate::persistence::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE)
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<4095) INSERT INTO objects(object_type,id,name,workspace,payload,created_at_ms,updated_at_ms) SELECT CASE i%3 WHEN 0 THEN ? WHEN 1 THEN ? ELSE ? END, 'budget-'||i,'budget-'||i,'default',X'00',0,0 FROM n")
            .bind(crate::persistence::PROVIDER_OBSERVATION_OBJECT_TYPE).bind(crate::persistence::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE).bind(crate::persistence::PROVIDER_DETACH_WITNESS_OBJECT_TYPE).execute(&store.pool).await.unwrap();
        assert!(
            store
                .claim_ordinary_observation(&q, &fence, &expected)
                .await
                .is_err()
        );
        let claimed: i64 = sqlx::query_scalar("SELECT count(*) FROM objects WHERE id=?")
            .bind(crate::persistence::ordinary_key(&q))
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(claimed, 0);
        for kind in [
            crate::persistence::PROVIDER_OBSERVATION_OBJECT_TYPE,
            crate::persistence::LEGACY_PROVIDER_OBSERVATION_OBJECT_TYPE,
            crate::persistence::PROVIDER_DETACH_WITNESS_OBJECT_TYPE,
        ] {
            assert!(
                state
                    .store
                    .delete_all_in_workspace(kind, "default")
                    .await
                    .is_err()
            );
        }
    }
}
