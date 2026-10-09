// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable workload admission shares the sandbox row's lifecycle CAS boundary.

use std::collections::{BTreeSet, HashSet};

use openshell_core::proto::{
    Sandbox, SandboxAdmissionOperation, SandboxAdmissionReason, SandboxAdmissionReceipt,
    SandboxPhase, SandboxRuntimeAdmission,
};
use openshell_core::{GetResourceVersion, ObjectId};
use tonic::Status;

use super::{ComputeRuntime, provisioning_deadline};
use crate::persistence::PersistenceError;

const MAX_RECEIPTS: usize = 1024;
const MAX_ACTIVE_HOLDS: usize = 128;
const CAS_ATTEMPTS: usize = 16;

#[derive(Clone, Debug)]
pub struct Mutation {
    pub sandbox_id: String,
    pub action_id: String,
    pub hold_action_id: String,
    pub operation: SandboxAdmissionOperation,
    pub reason: SandboxAdmissionReason,
    pub expected_epoch: u64,
}

pub fn validate_id(value: &str) -> Result<(), Status> {
    let id = uuid::Uuid::parse_str(value)
        .map_err(|_| Status::invalid_argument("admission identity must be a canonical UUID"))?;
    if id.is_nil() || id.to_string() != value {
        return Err(Status::invalid_argument(
            "admission identity must be a canonical nonzero UUID",
        ));
    }
    Ok(())
}

impl Mutation {
    fn validate(&self) -> Result<(), Status> {
        validate_id(&self.sandbox_id)?;
        validate_id(&self.action_id)?;
        validate_id(&self.hold_action_id)?;
        if !matches!(
            (self.operation, self.reason),
            (
                SandboxAdmissionOperation::Hold,
                SandboxAdmissionReason::Incident
                    | SandboxAdmissionReason::Policy
                    | SandboxAdmissionReason::Operator
            ) | (
                SandboxAdmissionOperation::Release,
                SandboxAdmissionReason::Operator
            )
        ) || (self.operation == SandboxAdmissionOperation::Hold
            && self.action_id != self.hold_action_id)
            || (self.operation == SandboxAdmissionOperation::Release
                && self.action_id == self.hold_action_id)
        {
            return Err(Status::invalid_argument("invalid admission mutation"));
        }
        Ok(())
    }

    fn matches(&self, receipt: &SandboxAdmissionReceipt) -> bool {
        receipt.sandbox_id == self.sandbox_id
            && receipt.action_id == self.action_id
            && receipt.hold_action_id == self.hold_action_id
            && receipt.operation == self.operation as i32
            && receipt.reason == self.reason as i32
            && receipt.previous_epoch == self.expected_epoch
    }
}

fn state(sandbox: &Sandbox) -> SandboxRuntimeAdmission {
    sandbox
        .status
        .as_ref()
        .and_then(|status| status.runtime_admission.clone())
        .unwrap_or_default()
}

/// Validate the complete retained history. Unknown or contradictory records
/// cannot silently turn into an empty/allowed state.
pub fn active_holds(sandbox: &Sandbox) -> Result<BTreeSet<String>, Status> {
    let admission = state(sandbox);
    let corrupt = || Status::failed_precondition("sandbox admission history is invalid");
    if admission.receipts.len() > MAX_RECEIPTS
        || admission.epoch != u64::try_from(admission.receipts.len()).map_err(|_| corrupt())?
    {
        return Err(corrupt());
    }
    let mut actions = HashSet::new();
    let mut holds = BTreeSet::new();
    for (index, receipt) in admission.receipts.iter().enumerate() {
        let mutation = Mutation {
            sandbox_id: receipt.sandbox_id.clone(),
            action_id: receipt.action_id.clone(),
            hold_action_id: receipt.hold_action_id.clone(),
            operation: SandboxAdmissionOperation::try_from(receipt.operation)
                .map_err(|_| corrupt())?,
            reason: SandboxAdmissionReason::try_from(receipt.reason).map_err(|_| corrupt())?,
            expected_epoch: receipt.previous_epoch,
        };
        mutation.validate().map_err(|_| corrupt())?;
        if receipt.sandbox_id != sandbox.object_id()
            || !actions.insert(&receipt.action_id)
            || receipt.previous_epoch != u64::try_from(index).map_err(|_| corrupt())?
            || receipt.epoch != receipt.previous_epoch.checked_add(1).ok_or_else(corrupt)?
            || receipt.recorded_time.as_ref().is_none_or(|time| {
                time.seconds <= 0
                    || time.seconds > 253_402_300_799
                    || !(0..1_000_000_000).contains(&time.nanos)
            })
        {
            return Err(corrupt());
        }
        match mutation.operation {
            SandboxAdmissionOperation::Hold => {
                if !holds.insert(receipt.hold_action_id.clone()) {
                    return Err(corrupt());
                }
            }
            SandboxAdmissionOperation::Release => {
                if !holds.remove(&receipt.hold_action_id) {
                    return Err(corrupt());
                }
            }
            SandboxAdmissionOperation::Unspecified => return Err(corrupt()),
        }
    }
    if holds.len() > MAX_ACTIVE_HOLDS || admission.receipts.len() + holds.len() > MAX_RECEIPTS {
        return Err(corrupt());
    }
    Ok(holds)
}

pub fn ensure_allowed(sandbox: &Sandbox) -> Result<(), Status> {
    if !active_holds(sandbox)?.is_empty() {
        return Err(Status::failed_precondition(
            "sandbox runtime admission is held",
        ));
    }
    Ok(())
}

pub fn epoch(sandbox: &Sandbox) -> u64 {
    state(sandbox).epoch
}

pub fn receipt(sandbox: &Sandbox, action_id: &str) -> Result<SandboxAdmissionReceipt, Status> {
    validate_id(action_id)?;
    active_holds(sandbox)?;
    state(sandbox)
        .receipts
        .into_iter()
        .find(|r| r.action_id == action_id)
        .ok_or_else(|| Status::not_found("sandbox admission receipt not found"))
}

fn prepare(
    sandbox: &Sandbox,
    mutation: &Mutation,
) -> Result<(SandboxRuntimeAdmission, bool), Status> {
    mutation.validate()?;
    if sandbox.object_id() != mutation.sandbox_id {
        return Err(Status::failed_precondition(
            "sandbox immutable identity changed",
        ));
    }
    let holds = active_holds(sandbox)?;
    let mut admission = state(sandbox);
    if let Some(original) = admission
        .receipts
        .iter()
        .find(|r| r.action_id == mutation.action_id)
    {
        if !mutation.matches(original) {
            return Err(Status::failed_precondition(
                "admission action arguments changed",
            ));
        }
        return Ok((admission, false));
    }
    if admission.epoch != mutation.expected_epoch {
        return Err(Status::failed_precondition(
            "sandbox admission epoch changed",
        ));
    }
    if admission.receipts.len() == MAX_RECEIPTS {
        return Err(Status::resource_exhausted(
            "sandbox admission receipt capacity reached",
        ));
    }
    match mutation.operation {
        SandboxAdmissionOperation::Hold => {
            // Reserve a release receipt for every outstanding hold.
            if holds.len() == MAX_ACTIVE_HOLDS
                || admission.receipts.len() + holds.len() + 2 > MAX_RECEIPTS
            {
                return Err(Status::resource_exhausted(
                    "sandbox admission hold capacity reached",
                ));
            }
            let phase = SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown);
            if provisioning_deadline::driver_operation_pending(sandbox)
                || (phase == SandboxPhase::Ready
                    && super::sandbox_provisioning_attempt_id(sandbox).is_none())
                || !matches!(
                    phase,
                    SandboxPhase::Ready
                        | SandboxPhase::Stopped
                        | SandboxPhase::Completed
                        | SandboxPhase::Error
                )
            {
                return Err(Status::failed_precondition(
                    "sandbox launch must settle before an admission hold can be confirmed",
                ));
            }
        }
        SandboxAdmissionOperation::Release => {
            if !holds.contains(&mutation.hold_action_id) {
                return Err(Status::failed_precondition(
                    "sandbox admission hold is not active",
                ));
            }
        }
        SandboxAdmissionOperation::Unspecified => unreachable!("validated mutation"),
    }
    let next = admission
        .epoch
        .checked_add(1)
        .ok_or_else(|| Status::resource_exhausted("sandbox admission epoch exhausted"))?;
    admission.receipts.push(SandboxAdmissionReceipt {
        sandbox_id: mutation.sandbox_id.clone(),
        action_id: mutation.action_id.clone(),
        hold_action_id: mutation.hold_action_id.clone(),
        operation: mutation.operation as i32,
        reason: mutation.reason as i32,
        previous_epoch: admission.epoch,
        epoch: next,
        recorded_time: Some(
            openshell_core::time::timestamp_from_millis(openshell_core::time::now_ms())
                .map_err(|_| Status::internal("admission timestamp is unavailable"))?,
        ),
    });
    admission.epoch = next;
    Ok((admission, true))
}

impl ComputeRuntime {
    pub(crate) async fn mutate_admission(
        &self,
        mutation: &Mutation,
    ) -> Result<SandboxAdmissionReceipt, Status> {
        for _ in 0..CAS_ATTEMPTS {
            let current = self
                .store
                .get_message::<Sandbox>(&mutation.sandbox_id)
                .await
                .map_err(|_| Status::internal("read sandbox admission failed"))?
                .ok_or_else(|| Status::not_found("sandbox not found"))?;
            let (admission, changed) = prepare(&current, mutation)?;
            if !changed {
                return receipt(&current, &mutation.action_id);
            }
            // Driver settlement precedes publication of its authenticated
            // binding. A Ready observation of the old runtime must not let a
            // hold confirm inside that gap on another gateway replica.
            if mutation.operation == SandboxAdmissionOperation::Hold
                && current.phase() == SandboxPhase::Ready as i32
                && self.supports_sandbox_authentication()
            {
                let execution = crate::auth::sandbox_session::sandbox_execution_id(&current)?;
                if current.metadata.as_ref().and_then(|metadata| {
                    metadata
                        .annotations
                        .get(super::COMPUTE_BOOTSTRAP_EXECUTION_ANNOTATION)
                }) != Some(&execution)
                {
                    return Err(Status::failed_precondition(
                        "sandbox runtime binding must publish before an admission hold can be confirmed",
                    ));
                }
            }
            match self
                .store
                .update_message_cas::<Sandbox, _>(
                    &mutation.sandbox_id,
                    current.get_resource_version(),
                    |sandbox| {
                        sandbox
                            .status
                            .get_or_insert_with(Default::default)
                            .runtime_admission = Some(admission.clone());
                    },
                )
                .await
            {
                Ok(updated) => {
                    self.sandbox_index.update_from_sandbox(&updated);
                    self.sandbox_watch_bus.notify(&mutation.sandbox_id);
                    return receipt(&updated, &mutation.action_id);
                }
                Err(PersistenceError::Conflict { .. }) => {}
                Err(_) => {
                    return Err(Status::internal(
                        "persist sandbox admission failed; outcome must be queried",
                    ));
                }
            }
        }
        Err(Status::aborted(
            "sandbox kept changing during admission mutation",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use prost::Message;

    fn sandbox() -> Sandbox {
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: uuid::Uuid::new_v4().to_string(),
                name: "agent".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Stopped as i32);
        sandbox
    }
    fn hold(sandbox: &Sandbox) -> Mutation {
        let id = uuid::Uuid::new_v4().to_string();
        Mutation {
            sandbox_id: sandbox.object_id().into(),
            action_id: id.clone(),
            hold_action_id: id,
            operation: SandboxAdmissionOperation::Hold,
            reason: SandboxAdmissionReason::Incident,
            expected_epoch: epoch(sandbox),
        }
    }
    fn apply(sandbox: &mut Sandbox, mutation: &Mutation) -> SandboxAdmissionReceipt {
        let (state, changed) = prepare(sandbox, mutation).unwrap();
        assert!(changed);
        sandbox.status.as_mut().unwrap().runtime_admission = Some(state);
        receipt(sandbox, &mutation.action_id).unwrap()
    }
    fn release(sandbox: &Sandbox, hold_id: &str) -> Mutation {
        Mutation {
            sandbox_id: sandbox.object_id().into(),
            action_id: uuid::Uuid::new_v4().to_string(),
            hold_action_id: hold_id.into(),
            operation: SandboxAdmissionOperation::Release,
            reason: SandboxAdmissionReason::Operator,
            expected_epoch: epoch(sandbox),
        }
    }

    #[test]
    fn independent_holds_survive_partial_release_and_wire_reopen() {
        let mut sandbox = sandbox();
        let first = hold(&sandbox);
        apply(&mut sandbox, &first);
        let second = hold(&sandbox);
        apply(&mut sandbox, &second);
        let release_first = release(&sandbox, &first.action_id);
        apply(&mut sandbox, &release_first);
        let mut reopened = Sandbox::decode(sandbox.encode_to_vec().as_slice()).unwrap();
        assert_eq!(
            active_holds(&reopened).unwrap(),
            BTreeSet::from([second.action_id.clone()])
        );
        assert!(ensure_allowed(&reopened).is_err());
        let release_second = release(&reopened, &second.action_id);
        apply(&mut reopened, &release_second);
        assert!(ensure_allowed(&reopened).is_ok());
        assert_eq!(epoch(&reopened), 4);
    }

    #[test]
    fn historical_retries_preserve_original_receipts_after_release() {
        let mut sandbox = sandbox();
        let first = hold(&sandbox);
        let original = apply(&mut sandbox, &first);
        let released = release(&sandbox, &first.action_id);
        let original_release = apply(&mut sandbox, &released);
        assert!(!prepare(&sandbox, &first).unwrap().1);
        assert!(!prepare(&sandbox, &released).unwrap().1);
        assert_eq!(receipt(&sandbox, &first.action_id).unwrap(), original);
        assert_eq!(
            receipt(&sandbox, &released.action_id).unwrap(),
            original_release
        );
        assert!(ensure_allowed(&sandbox).is_ok());
        let mut conflict = first.clone();
        conflict.reason = SandboxAdmissionReason::Policy;
        assert_eq!(
            prepare(&sandbox, &conflict).unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
    }

    #[test]
    fn stale_foreign_unknown_and_repeated_releases_fail() {
        let mut sandbox = sandbox();
        let first = hold(&sandbox);
        apply(&mut sandbox, &first);
        let mut stale = hold(&sandbox);
        stale.expected_epoch = 0;
        assert!(prepare(&sandbox, &stale).is_err());
        let mut foreign = hold(&sandbox);
        foreign.sandbox_id = uuid::Uuid::new_v4().to_string();
        assert!(prepare(&sandbox, &foreign).is_err());
        let unknown = release(&sandbox, &uuid::Uuid::new_v4().to_string());
        assert!(prepare(&sandbox, &unknown).is_err());
        let released = release(&sandbox, &first.action_id);
        apply(&mut sandbox, &released);
        let repeated = release(&sandbox, &first.action_id);
        assert!(prepare(&sandbox, &repeated).is_err());
    }

    #[test]
    fn unsettled_launch_and_legacy_ready_cannot_confirm_holds() {
        let mut sandbox = sandbox();
        for phase in [
            SandboxPhase::Starting,
            SandboxPhase::Provisioning,
            SandboxPhase::Ready,
            SandboxPhase::Deleting,
        ] {
            sandbox.set_phase(phase as i32);
            assert_eq!(
                prepare(&sandbox, &hold(&sandbox)).unwrap_err().code(),
                tonic::Code::FailedPrecondition
            );
        }
        sandbox.set_phase(SandboxPhase::Stopped as i32);
        sandbox.status.as_mut().unwrap().provisioning = Some(provisioning_deadline::new_record(0));
        sandbox
            .status
            .as_mut()
            .unwrap()
            .provisioning
            .as_mut()
            .unwrap()
            .driver_operation_pending = true;
        assert!(prepare(&sandbox, &hold(&sandbox)).is_err());
    }

    #[test]
    fn corrupt_history_fails_closed_even_when_no_holds_would_remain() {
        let mut sandbox = sandbox();
        let first = hold(&sandbox);
        apply(&mut sandbox, &first);
        let released = release(&sandbox, &first.action_id);
        apply(&mut sandbox, &released);
        let healthy = sandbox.clone();
        for mode in 0..7 {
            let mut corrupt = healthy.clone();
            let state = corrupt
                .status
                .as_mut()
                .unwrap()
                .runtime_admission
                .as_mut()
                .unwrap();
            match mode {
                0 => state.epoch = 0,
                1 => state.receipts[0].operation = 99,
                2 => state.receipts[1].previous_epoch = 0,
                3 => state.receipts[0].sandbox_id = uuid::Uuid::new_v4().to_string(),
                4 => state.receipts[1].hold_action_id = uuid::Uuid::new_v4().to_string(),
                5 => state.receipts[0].recorded_time = None,
                _ => state.receipts[0].reason = 99,
            }
            assert!(ensure_allowed(&corrupt).is_err(), "mode {mode}");
            assert!(prepare(&corrupt, &first).is_err());
        }
    }

    #[test]
    fn capacity_refuses_mutations_without_evicting_retry_history() {
        let mut sandbox = sandbox();
        let first = hold(&sandbox);
        let original = apply(&mut sandbox, &first);
        let released = release(&sandbox, &first.action_id);
        apply(&mut sandbox, &released);
        for _ in 1..MAX_RECEIPTS / 2 {
            let next = hold(&sandbox);
            apply(&mut sandbox, &next);
            let released = release(&sandbox, &next.action_id);
            apply(&mut sandbox, &released);
        }
        assert_eq!(
            prepare(&sandbox, &hold(&sandbox)).unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        assert!(!prepare(&sandbox, &first).unwrap().1);
        assert_eq!(receipt(&sandbox, &first.action_id).unwrap(), original);
    }

    #[test]
    fn hold_capacity_reserves_each_independent_release() {
        let mut sandbox = sandbox();
        for _ in 0..MAX_ACTIVE_HOLDS {
            let next = hold(&sandbox);
            apply(&mut sandbox, &next);
        }
        assert_eq!(
            prepare(&sandbox, &hold(&sandbox)).unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        for id in active_holds(&sandbox).unwrap() {
            let released = release(&sandbox, &id);
            apply(&mut sandbox, &released);
        }
        assert!(ensure_allowed(&sandbox).is_ok());
    }

    #[test]
    fn legacy_absence_allows_but_unknown_identity_and_reason_are_rejected() {
        let sandbox = sandbox();
        assert!(ensure_allowed(&sandbox).is_ok());
        let mut mutation = hold(&sandbox);
        mutation.action_id = uuid::Uuid::nil().to_string();
        assert!(prepare(&sandbox, &mutation).is_err());
        let mut mutation = hold(&sandbox);
        mutation.reason = SandboxAdmissionReason::Unspecified;
        assert!(prepare(&sandbox, &mutation).is_err());
    }
}
