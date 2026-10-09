// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"testing"
	"time"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type admissionRPC struct {
	pb.OpenShellClient // Unexpected fallback methods panic rather than succeed.
	hold               *pb.HoldSandboxAdmissionRequest
	release            *pb.ReleaseSandboxAdmissionRequest
	state              *pb.GetSandboxAdmissionResponse
	result             *pb.SandboxAdmissionReceipt
	err                error
	calls              int
}

func (s *admissionRPC) HoldSandboxAdmission(_ context.Context, req *pb.HoldSandboxAdmissionRequest, _ ...grpc.CallOption) (*pb.HoldSandboxAdmissionResponse, error) {
	s.calls++
	s.hold = req
	return &pb.HoldSandboxAdmissionResponse{Receipt: s.result}, s.err
}
func (s *admissionRPC) ReleaseSandboxAdmission(_ context.Context, req *pb.ReleaseSandboxAdmissionRequest, _ ...grpc.CallOption) (*pb.ReleaseSandboxAdmissionResponse, error) {
	s.calls++
	s.release = req
	return &pb.ReleaseSandboxAdmissionResponse{Receipt: s.result}, s.err
}
func (s *admissionRPC) GetSandboxAdmission(_ context.Context, _ *pb.GetSandboxAdmissionRequest, _ ...grpc.CallOption) (*pb.GetSandboxAdmissionResponse, error) {
	s.calls++
	return s.state, s.err
}
func (s *admissionRPC) GetSandboxAdmissionReceipt(_ context.Context, _ *pb.GetSandboxAdmissionReceiptRequest, _ ...grpc.CallOption) (*pb.GetSandboxAdmissionReceiptResponse, error) {
	s.calls++
	return &pb.GetSandboxAdmissionReceiptResponse{Receipt: s.result}, s.err
}

func admissionTestReceipt() *pb.SandboxAdmissionReceipt {
	return &pb.SandboxAdmissionReceipt{SandboxId: "resource", ActionId: "hold", HoldActionId: "hold",
		Operation: pb.SandboxAdmissionOperation_SANDBOX_ADMISSION_OPERATION_HOLD,
		Reason:    pb.SandboxAdmissionReason_SANDBOX_ADMISSION_REASON_INCIDENT,
		Epoch:     1, RecordedTime: timestamppb.New(time.Unix(1, 0))}
}

func TestAdmissionForwardsImmutableTargetAndStableActions(t *testing.T) {
	rpc := &admissionRPC{result: admissionTestReceipt()}
	client := &admissionClient{client: rpc}
	first, err := client.Hold(context.Background(), "default", "agent", "resource", "hold", 0, AdmissionIncident)
	require.NoError(t, err)
	require.Equal(t, "resource", rpc.hold.GetExpectedSandboxId())
	require.Equal(t, "default", rpc.hold.GetWorkspaceScope().GetWorkspace())
	require.Equal(t, "agent", rpc.hold.GetName())
	repeated, err := client.Hold(context.Background(), "default", "agent", "resource", "hold", 0, AdmissionIncident)
	require.NoError(t, err)
	require.Equal(t, first, repeated)
	rpc.result = &pb.SandboxAdmissionReceipt{SandboxId: "resource", ActionId: "release", HoldActionId: "hold",
		Operation:     pb.SandboxAdmissionOperation_SANDBOX_ADMISSION_OPERATION_RELEASE,
		Reason:        pb.SandboxAdmissionReason_SANDBOX_ADMISSION_REASON_OPERATOR,
		PreviousEpoch: 1, Epoch: 2, RecordedTime: timestamppb.New(time.Unix(2, 0))}
	released, err := client.Release(context.Background(), "default", "agent", "resource", "release", "hold", 1)
	require.NoError(t, err)
	require.Equal(t, "release", released.Operation)
	require.Equal(t, "hold", rpc.release.GetHoldActionId())
	require.Equal(t, uint64(1), rpc.release.GetExpectedEpoch())
	require.Equal(t, 3, rpc.calls)
}

func TestAdmissionUnsupportedAndStaleCallsHaveNoFallback(t *testing.T) {
	for _, code := range []codes.Code{codes.Unimplemented, codes.FailedPrecondition, codes.PermissionDenied, codes.Unavailable} {
		rpc := &admissionRPC{err: status.Error(code, "denied")}
		client := &admissionClient{client: rpc}
		_, err := client.Hold(context.Background(), "default", "agent", "resource", "hold", 0, AdmissionIncident)
		require.Error(t, err)
		require.Equal(t, 1, rpc.calls)
		if code == codes.Unimplemented {
			require.True(t, IsUnimplemented(err))
		}
	}
}

func TestAdmissionRejectsIncompleteTargetsBeforeRPC(t *testing.T) {
	rpc := &admissionRPC{}
	client := &admissionClient{client: rpc}
	for _, target := range [][3]string{{"", "agent", "resource"}, {"default", "", "resource"}, {"default", "agent", ""}} {
		_, err := client.Get(context.Background(), target[0], target[1], target[2])
		require.True(t, IsInvalidArgument(err))
	}
	_, err := client.Hold(context.Background(), "default", "agent", "resource", "hold", 0, "unknown")
	require.True(t, IsInvalidArgument(err))
	require.Zero(t, rpc.calls)
}

func TestAdmissionRejectsForeignAndMalformedReceipts(t *testing.T) {
	for _, change := range []func(*pb.SandboxAdmissionReceipt){
		func(r *pb.SandboxAdmissionReceipt) { r.SandboxId = "foreign" },
		func(r *pb.SandboxAdmissionReceipt) { r.ActionId = "other" },
		func(r *pb.SandboxAdmissionReceipt) { r.Operation = 99 },
		func(r *pb.SandboxAdmissionReceipt) { r.Reason = 99 },
		func(r *pb.SandboxAdmissionReceipt) { r.Epoch = 0 },
		func(r *pb.SandboxAdmissionReceipt) { r.RecordedTime = nil },
	} {
		receipt := admissionTestReceipt()
		change(receipt)
		rpc := &admissionRPC{result: receipt}
		client := &admissionClient{client: rpc}
		_, err := client.Hold(context.Background(), "default", "agent", "resource", "hold", 0, AdmissionIncident)
		require.Error(t, err)
	}
}

func TestAdmissionCurrentStateIsSeparateFromHistoricalReceipt(t *testing.T) {
	rpc := &admissionRPC{result: admissionTestReceipt(), state: &pb.GetSandboxAdmissionResponse{SandboxId: "resource", Epoch: 2}}
	client := &admissionClient{client: rpc}
	historical, err := client.Receipt(context.Background(), "default", "agent", "resource", "hold")
	require.NoError(t, err)
	require.Equal(t, uint64(1), historical.Epoch)
	current, err := client.Get(context.Background(), "default", "agent", "resource")
	require.NoError(t, err)
	require.Empty(t, current.ActiveHoldActionIDs)
	require.Equal(t, uint64(2), current.Epoch)
	rpc.state.ActiveHoldActionIds = []string{"hold", "hold"}
	_, err = client.Get(context.Background(), "default", "agent", "resource")
	require.Error(t, err)
}
