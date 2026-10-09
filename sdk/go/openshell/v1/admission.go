// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// AdmissionInterface is optional. Older clients need not implement this surface;
// older gateways return Unimplemented without a policy or stop fallback.
type AdmissionInterface interface {
	Get(context.Context, string, string, string) (*AdmissionState, error)
	Hold(context.Context, string, string, string, string, uint64, AdmissionReason) (*AdmissionReceipt, error)
	Release(context.Context, string, string, string, string, string, uint64) (*AdmissionReceipt, error)
	Receipt(context.Context, string, string, string, string) (*AdmissionReceipt, error)
}

// AdmissionReason is a fixed administrative reason, never retained traffic text.
type AdmissionReason string

// Admission reasons distinguish incident, policy and explicit operator holds.
const (
	AdmissionIncident AdmissionReason = "incident"
	AdmissionPolicy   AdmissionReason = "policy"
	AdmissionOperator AdmissionReason = "operator"
)

// AdmissionState describes current holds; historical receipts do not.
type AdmissionState struct {
	SandboxID           string
	Epoch               uint64
	ActiveHoldActionIDs []string
}

// AdmissionReceipt records one immutable mutation, independently of current state.
type AdmissionReceipt struct {
	SandboxID, ActionID, HoldActionID string
	Operation                         string
	Reason                            AdmissionReason
	PreviousEpoch, Epoch              uint64
	RecordedAt                        time.Time
}

type admissionClient struct{ client pb.OpenShellClient }

// Admission exposes runtime-owned workload holds without changing ClientInterface.
// Calls require workspace administrator authority and an immutable sandbox ID.
func (c *Client) Admission() AdmissionInterface {
	return &admissionClient{client: pb.NewOpenShellClient(c.conn)}
}

func admissionTarget(workspace, name, id string) error {
	if workspace == "" || name == "" || id == "" {
		return &StatusError{Code: ErrorInvalidArgument, Message: "admission workspace, name and immutable sandbox ID are required"}
	}
	return nil
}

func admissionReceipt(p *pb.SandboxAdmissionReceipt, sandboxID, actionID string) (*AdmissionReceipt, error) {
	if p == nil || p.GetSandboxId() != sandboxID || p.GetActionId() != actionID || p.GetHoldActionId() == "" ||
		p.GetPreviousEpoch() == ^uint64(0) || p.GetEpoch() != p.GetPreviousEpoch()+1 || p.GetRecordedTime() == nil ||
		p.GetRecordedTime().CheckValid() != nil || p.GetRecordedTime().GetSeconds() <= 0 {
		return nil, &StatusError{Code: ErrorInternal, Message: "invalid sandbox admission receipt"}
	}
	result := &AdmissionReceipt{SandboxID: sandboxID, ActionID: actionID, HoldActionID: p.GetHoldActionId(),
		PreviousEpoch: p.GetPreviousEpoch(), Epoch: p.GetEpoch(), RecordedAt: p.GetRecordedTime().AsTime()}
	switch p.GetOperation() {
	case pb.SandboxAdmissionOperation_SANDBOX_ADMISSION_OPERATION_HOLD:
		result.Operation = "hold"
		if p.GetHoldActionId() != actionID {
			return nil, &StatusError{Code: ErrorInternal, Message: "invalid sandbox admission hold"}
		}
	case pb.SandboxAdmissionOperation_SANDBOX_ADMISSION_OPERATION_RELEASE:
		result.Operation = "release"
		if p.GetHoldActionId() == actionID {
			return nil, &StatusError{Code: ErrorInternal, Message: "invalid sandbox admission release"}
		}
	default:
		return nil, &StatusError{Code: ErrorInternal, Message: "unknown sandbox admission operation"}
	}
	switch p.GetReason() {
	case pb.SandboxAdmissionReason_SANDBOX_ADMISSION_REASON_INCIDENT:
		result.Reason = AdmissionIncident
	case pb.SandboxAdmissionReason_SANDBOX_ADMISSION_REASON_POLICY:
		result.Reason = AdmissionPolicy
	case pb.SandboxAdmissionReason_SANDBOX_ADMISSION_REASON_OPERATOR:
		result.Reason = AdmissionOperator
	default:
		return nil, &StatusError{Code: ErrorInternal, Message: "unknown sandbox admission reason"}
	}
	if result.Operation == "release" && result.Reason != AdmissionOperator {
		return nil, &StatusError{Code: ErrorInternal, Message: "invalid sandbox admission release reason"}
	}
	return result, nil
}

func (c *admissionClient) Get(ctx context.Context, workspace, name, id string) (*AdmissionState, error) {
	if err := admissionTarget(workspace, name, id); err != nil {
		return nil, err
	}
	resp, err := c.client.GetSandboxAdmission(ctx, &pb.GetSandboxAdmissionRequest{
		WorkspaceScope: namedWorkspaceScope(workspace), Name: name, ExpectedSandboxId: id,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	if resp.GetSandboxId() != id || len(resp.GetActiveHoldActionIds()) > 128 {
		return nil, &StatusError{Code: ErrorInternal, Message: "invalid sandbox admission state"}
	}
	seen := map[string]bool{}
	for _, hold := range resp.GetActiveHoldActionIds() {
		if hold == "" || seen[hold] {
			return nil, &StatusError{Code: ErrorInternal, Message: "invalid active admission holds"}
		}
		seen[hold] = true
	}
	return &AdmissionState{SandboxID: id, Epoch: resp.GetEpoch(), ActiveHoldActionIDs: append([]string(nil), resp.GetActiveHoldActionIds()...)}, nil
}

func (c *admissionClient) Hold(ctx context.Context, workspace, name, id, actionID string, epoch uint64, reason AdmissionReason) (*AdmissionReceipt, error) {
	if err := admissionTarget(workspace, name, id); err != nil {
		return nil, err
	}
	reasons := map[AdmissionReason]pb.SandboxAdmissionReason{AdmissionIncident: pb.SandboxAdmissionReason_SANDBOX_ADMISSION_REASON_INCIDENT,
		AdmissionPolicy: pb.SandboxAdmissionReason_SANDBOX_ADMISSION_REASON_POLICY, AdmissionOperator: pb.SandboxAdmissionReason_SANDBOX_ADMISSION_REASON_OPERATOR}
	nativeReason, ok := reasons[reason]
	if !ok || actionID == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "admission action ID and fixed reason are required"}
	}
	resp, err := c.client.HoldSandboxAdmission(ctx, &pb.HoldSandboxAdmissionRequest{
		WorkspaceScope: namedWorkspaceScope(workspace), Name: name, ExpectedSandboxId: id,
		ActionId: actionID, ExpectedEpoch: epoch, Reason: nativeReason,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	result, err := admissionReceipt(resp.GetReceipt(), id, actionID)
	if err != nil {
		return nil, err
	}
	if result.Operation != "hold" || result.Reason != reason || result.PreviousEpoch != epoch {
		return nil, &StatusError{Code: ErrorInternal, Message: "sandbox admission hold receipt differs from request"}
	}
	return result, nil
}

func (c *admissionClient) Release(ctx context.Context, workspace, name, id, actionID, holdID string, epoch uint64) (*AdmissionReceipt, error) {
	if err := admissionTarget(workspace, name, id); err != nil {
		return nil, err
	}
	if actionID == "" || holdID == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "admission action and hold IDs are required"}
	}
	resp, err := c.client.ReleaseSandboxAdmission(ctx, &pb.ReleaseSandboxAdmissionRequest{
		WorkspaceScope: namedWorkspaceScope(workspace), Name: name, ExpectedSandboxId: id,
		ActionId: actionID, HoldActionId: holdID, ExpectedEpoch: epoch,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	result, err := admissionReceipt(resp.GetReceipt(), id, actionID)
	if err != nil {
		return nil, err
	}
	if result.Operation != "release" || result.HoldActionID != holdID || result.PreviousEpoch != epoch {
		return nil, &StatusError{Code: ErrorInternal, Message: "sandbox admission release receipt differs from request"}
	}
	return result, nil
}

func (c *admissionClient) Receipt(ctx context.Context, workspace, name, id, actionID string) (*AdmissionReceipt, error) {
	if err := admissionTarget(workspace, name, id); err != nil {
		return nil, err
	}
	if actionID == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "admission action ID is required"}
	}
	resp, err := c.client.GetSandboxAdmissionReceipt(ctx, &pb.GetSandboxAdmissionReceiptRequest{
		WorkspaceScope: namedWorkspaceScope(workspace), Name: name, ExpectedSandboxId: id, ActionId: actionID,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return admissionReceipt(resp.GetReceipt(), id, actionID)
}
