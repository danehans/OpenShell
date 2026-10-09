// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workspace-administrator admission operations; never sandbox authority.

use std::sync::Arc;

use openshell_core::ObjectId;
use openshell_core::proto::{
    GetSandboxAdmissionReceiptRequest, GetSandboxAdmissionReceiptResponse,
    GetSandboxAdmissionRequest, GetSandboxAdmissionResponse, HoldSandboxAdmissionRequest,
    HoldSandboxAdmissionResponse, ReleaseSandboxAdmissionRequest, ReleaseSandboxAdmissionResponse,
    Sandbox, SandboxAdmissionOperation, SandboxAdmissionReason,
};
use tonic::{Request, Response, Status};

use crate::{
    ServerState,
    auth::{principal::Principal, workspace_authz::MinWorkspaceRole},
    compute::admission,
};

async fn resolve<T: Sync>(
    state: &Arc<ServerState>,
    request: &Request<T>,
    workspace: &str,
    name: &str,
    expected_id: &str,
) -> Result<Sandbox, Status> {
    let principal = super::extract_principal(request)?;
    if matches!(principal, Principal::Sandbox(_)) {
        return Err(Status::permission_denied(
            "runtime admission requires operator authority",
        ));
    }
    admission::validate_id(expected_id)?;
    let sandbox = super::sandbox::resolve_and_authorize_sandbox_name(
        state,
        &principal,
        name,
        workspace,
        MinWorkspaceRole::Admin,
    )
    .await?;
    if sandbox.object_id() != expected_id {
        return Err(Status::failed_precondition(
            "sandbox immutable identity changed",
        ));
    }
    Ok(sandbox)
}

pub(super) async fn hold(
    state: &Arc<ServerState>,
    request: Request<HoldSandboxAdmissionRequest>,
) -> Result<Response<HoldSandboxAdmissionResponse>, Status> {
    let req = request.get_ref();
    let workspace =
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?;
    resolve(
        state,
        &request,
        workspace,
        &req.name,
        &req.expected_sandbox_id,
    )
    .await?;
    let receipt = state
        .compute
        .mutate_admission(&admission::Mutation {
            sandbox_id: req.expected_sandbox_id.clone(),
            action_id: req.action_id.clone(),
            hold_action_id: req.action_id.clone(),
            operation: SandboxAdmissionOperation::Hold,
            reason: SandboxAdmissionReason::try_from(req.reason)
                .map_err(|_| Status::invalid_argument("unknown admission reason"))?,
            expected_epoch: req.expected_epoch,
        })
        .await?;
    Ok(Response::new(HoldSandboxAdmissionResponse {
        receipt: Some(receipt),
    }))
}

pub(super) async fn release(
    state: &Arc<ServerState>,
    request: Request<ReleaseSandboxAdmissionRequest>,
) -> Result<Response<ReleaseSandboxAdmissionResponse>, Status> {
    let req = request.get_ref();
    let workspace =
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?;
    resolve(
        state,
        &request,
        workspace,
        &req.name,
        &req.expected_sandbox_id,
    )
    .await?;
    let receipt = state
        .compute
        .mutate_admission(&admission::Mutation {
            sandbox_id: req.expected_sandbox_id.clone(),
            action_id: req.action_id.clone(),
            hold_action_id: req.hold_action_id.clone(),
            operation: SandboxAdmissionOperation::Release,
            reason: SandboxAdmissionReason::Operator,
            expected_epoch: req.expected_epoch,
        })
        .await?;
    Ok(Response::new(ReleaseSandboxAdmissionResponse {
        receipt: Some(receipt),
    }))
}

pub(super) async fn get(
    state: &Arc<ServerState>,
    request: Request<GetSandboxAdmissionRequest>,
) -> Result<Response<GetSandboxAdmissionResponse>, Status> {
    let req = request.get_ref();
    let workspace =
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?;
    let sandbox = resolve(
        state,
        &request,
        workspace,
        &req.name,
        &req.expected_sandbox_id,
    )
    .await?;
    let holds = admission::active_holds(&sandbox)?;
    Ok(Response::new(GetSandboxAdmissionResponse {
        sandbox_id: sandbox.object_id().to_string(),
        epoch: admission::epoch(&sandbox),
        active_hold_action_ids: holds.into_iter().collect(),
    }))
}

pub(super) async fn get_receipt(
    state: &Arc<ServerState>,
    request: Request<GetSandboxAdmissionReceiptRequest>,
) -> Result<Response<GetSandboxAdmissionReceiptResponse>, Status> {
    let req = request.get_ref();
    let workspace =
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?;
    let sandbox = resolve(
        state,
        &request,
        workspace,
        &req.name,
        &req.expected_sandbox_id,
    )
    .await?;
    Ok(Response::new(GetSandboxAdmissionReceiptResponse {
        receipt: Some(admission::receipt(&sandbox, &req.action_id)?),
    }))
}
