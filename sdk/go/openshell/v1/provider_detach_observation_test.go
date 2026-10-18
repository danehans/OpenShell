// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
package v1

import (
	"context"
	"errors"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
	proto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"testing"
	"time"
)

func ordinaryFixture(t *testing.T) (OrdinaryObservationRequest, *pb.ProviderObservationResultV1, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	q := OrdinaryObservationRequest{Resource: detachFixture(t).Target.Resource(), RunID: "11111111-1111-4111-8111-111111111111", StepID: "22222222-2222-4222-8222-222222222222", ProfileID: OrdinaryObservationProfile, ProfileSHA256: OrdinaryObservationProfileSHA256(), SourceIncarnation: "33333333-3333-4333-8333-333333333333", BoundaryIncarnation: "44444444-4444-4444-8444-444444444444", Deadline: now.Add(4 * time.Second), Phase: "baseline", EvidenceScope: OrdinaryObservationEvidenceScope}
	q.RequestSHA256 = q.SHA256()
	snapshot := &pb.ProviderObservationSnapshotV1{Resource: detachResourceToProto(q.Resource), ProfileId: q.ProfileID, ProfileSha256: q.ProfileSHA256, SourceIncarnation: q.SourceIncarnation, BoundaryIncarnation: q.BoundaryIncarnation, GatewayBootId: "55555555-5555-4555-8555-555555555555", SupervisorInstance: "instance", SupervisorSession: "66666666-6666-4666-8666-666666666666", ConfigurationSha256: detachFixture(t).Target.NativePolicyHash, MediationPathReceiptSha256: "", EvidenceScope: OrdinaryObservationEvidenceScope, ProcessWriterAttribution: pb.ProviderObservationProcessWriterAttributionV1_PROVIDER_OBSERVATION_PROCESS_WRITER_ATTRIBUTION_V1_PROCESS_WRITER_UNPROVEN, MediationPathId: "88888888-8888-4888-8888-888888888888"}
	snapshot.MediationPathReceiptSha256 = ordinaryPathSHA256(snapshot)
	w := &pb.ProviderObservationWindowV1{Request: q.native(), InstalledSnapshot: snapshot, WindowId: "77777777-7777-4777-8777-777777777777", InstallSequence: 1, InstalledTime: timestamppb.New(now.Add(-2 * time.Second)), CaptureEnd: timestamppb.New(now.Add(-time.Second))}
	w.WindowSha256 = ordinaryDigest("openshell.provider-detach.sandbox-mediation-window/v1", w)
	e := &pb.ProviderObservationEventV1{NativeRequestId: "request1", NativeConnectionId: "connection1", IngressSequence: 1, CapturedTime: timestamppb.New(now.Add(-1900 * time.Millisecond)), MediationStreamReceiptSha256: snapshot.MediationPathReceiptSha256, RouteClass: "messages", RequestStreamClass: "true", Rewrite: pb.ProviderObservationRewriteV1_PROVIDER_OBSERVATION_REWRITE_V1_EXPECTED_MATERIALIZED, NativeResponseId: "response1", ResponseOrigin: "upstream", ResponseSequence: 1, HttpFraming: "complete", ClientSocketWrite: "accepted", ClosedTime: timestamppb.New(now.Add(-1100 * time.Millisecond)), AttemptKind: "request"}
	r := &pb.ProviderObservationResultV1{Window: w, State: pb.ProviderObservationStateV1_PROVIDER_OBSERVATION_STATE_V1_TERMINAL, Events: []*pb.ProviderObservationEventV1{e}, ClosedTime: w.CaptureEnd}
	r.TerminalSha256 = ordinaryDigest("openshell.provider-detach.sandbox-mediation-terminal/v1", r)
	sampled := proto.Clone(snapshot).(*pb.ProviderObservationSnapshotV1)
	sampled.CurrentIngressSequence = 1
	read := &pb.ProviderObservationCurrentReadV1{Selector: &pb.GetProviderDetachObservationRequest{WorkspaceScope: namedWorkspaceScope(q.Resource.Workspace), OriginalRequest: q.native()}, ExpectedIdentity: snapshot, ReadCorrelation: make([]byte, 16), ReadDeadline: timestamppb.New(now.Add(time.Second)), WindowSha256: w.WindowSha256, TerminalSha256: r.TerminalSha256}
	r.CurrentReportSequence = 1
	r.CurrentSnapshot = sampled
	r.CurrentRead = &pb.ProviderObservationCurrentReplyV1{OriginalRead: read, SampledSnapshot: sampled, SampledTime: timestamppb.New(now.Add(-time.Millisecond))}
	r.AckWindowSha256 = w.WindowSha256
	r.AckTerminalSha256 = r.TerminalSha256
	return q, r, now
}
func TestOrdinaryObservationCurrentCounterAndBindingNegatives(t *testing.T) {
	q, r, now := ordinaryFixture(t)
	v, err := ordinaryResult(r, q, now)
	if q.Validate() != nil || err != nil || !v.Current || v.CredentialRefusal {
		t.Fatalf("valid baseline refused: %v", err)
	}
	mutations := []func(*pb.ProviderObservationResultV1){func(r *pb.ProviderObservationResultV1) { r.CurrentRead.SampledSnapshot.CurrentIngressSequence = 2 }, func(r *pb.ProviderObservationResultV1) { r.CurrentRead.OriginalRead.ReadCorrelation = nil }, func(r *pb.ProviderObservationResultV1) { r.CurrentRead.OriginalRead.TerminalSha256 = "wrong" }, func(r *pb.ProviderObservationResultV1) {
		r.CurrentRead.SampledSnapshot.SupervisorSession = "replacement"
	}, func(r *pb.ProviderObservationResultV1) { r.CurrentRead.AccountingFault = true }, func(r *pb.ProviderObservationResultV1) { r.CurrentRead.ActiveAttempts = 1 }, func(r *pb.ProviderObservationResultV1) {
		r.CurrentRead.OriginalRead.Selector.Resource = detachResourceToProto(q.Resource)
	}, func(r *pb.ProviderObservationResultV1) {
		r.CurrentRead.OriginalRead.ReadDeadline = timestamppb.New(time.Unix(0, 0))
	}, func(r *pb.ProviderObservationResultV1) { r.DetachedAck = &pb.ProviderDetachACKV1{} }}
	for i, mutate := range mutations {
		q, r, now := ordinaryFixture(t)
		mutate(r)
		if _, e := ordinaryResult(r, q, now); e == nil {
			t.Fatalf("mutation%d accepted", i)
		}
	}
}
func TestOrdinaryObservationRecursiveKnownProjectionAndHistory(t *testing.T) {
	q, r, now := ordinaryFixture(t)
	n := q.native()
	before := ordinaryDigest("test", n)
	u := protowire.AppendTag(nil, 2345, protowire.VarintType)
	u = protowire.AppendVarint(u, 99)
	n.ProtoReflect().SetUnknown(u)
	n.Deadline.ProtoReflect().SetUnknown(u)
	n.Resource.ProtoReflect().SetUnknown(u)
	if ordinaryDigest("test", n) != before || len(n.Deadline.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("projection retained unknown or mutated borrowed object")
	}
	r.CurrentRead = nil
	r.CurrentReportSequence = 0
	r.CurrentSnapshot = nil
	r.AckWindowSha256 = ""
	r.AckTerminalSha256 = ""
	v, e := ordinaryResult(r, q, now)
	if e != nil || !v.HistoricalOnly || v.Current || v.CredentialRefusal {
		t.Fatalf("history qualified %v", e)
	}
}
func TestOrdinaryObservationClosedPhase(t *testing.T) {
	q, _, _ := ordinaryFixture(t)
	for _, phase := range []string{"", "ready", "fixed", "unknown"} {
		n := q
		n.Phase = phase
		n.RequestSHA256 = n.SHA256()
		if n.Validate() == nil {
			t.Fatal("unsupported phase")
		}
	}
	q.InstalledArm = &ProviderDetachArmSeal{}
	q.RequestSHA256 = q.SHA256()
	if q.Validate() == nil {
		t.Fatal("baseline invented Arm")
	}
}

type ordinaryTransport struct {
	pb.OpenShellClient
	begin, get int
	query      *pb.GetProviderDetachObservationRequest
	fail       error
}

func (f *ordinaryTransport) BeginProviderDetachObservation(_ context.Context, _ *pb.BeginProviderDetachObservationRequest, _ ...grpc.CallOption) (*pb.BeginProviderDetachObservationResponse, error) {
	f.begin++
	return nil, f.fail
}
func (f *ordinaryTransport) GetProviderDetachObservation(_ context.Context, q *pb.GetProviderDetachObservationRequest, _ ...grpc.CallOption) (*pb.GetProviderDetachObservationResponse, error) {
	f.get++
	f.query = q
	return nil, f.fail
}
func TestOrdinaryObservationActualClientOneSendAndExactRecovery(t *testing.T) {
	q, _, _ := ordinaryFixture(t)
	f := &ordinaryTransport{fail: errors.New("lost original response")}
	c := &ProviderDetachmentClient{rpc: f, resource: q.Resource, timeout: time.Second}
	if _, e := c.BeginOrdinaryObservation(context.Background(), q); e == nil {
		t.Fatal("unknown success")
	}
	if f.begin != 1 || f.get != 0 {
		t.Fatal("retry or discovery")
	}
	if _, e := c.QueryOrdinaryObservation(context.Background(), q); e == nil {
		t.Fatal("unknown success")
	}
	if f.get != 1 || f.query.OriginalRequest == nil || f.query.Resource != nil {
		t.Fatal("recovery changed mode")
	}
}
