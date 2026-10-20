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
	"strings"
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

// Byte-envelope fixtures are not authorization fixtures. Existing client and
// Arm tests plus the retained private regression cover complete semantic checks.
func byteOrdinaryArm(t *testing.T, size int) *pb.ProviderDetachArmSealV1 {
	t.Helper()
	for n := 0; n <= size; n++ {
		a := &pb.ProviderDetachArmSealV1{Request: &pb.ProviderDetachArmRequestV1{AttemptId: strings.Repeat("a", n)}}
		if proto.Size(a) == size {
			return a
		}
	}
	t.Fatal("unreachable seal size")
	return nil
}
func byteOrdinaryRequest() *pb.ProviderObservationRequestV1 {
	return &pb.ProviderObservationRequestV1{ProfileId: OrdinaryObservationProfile, ProfileSha256: OrdinaryObservationProfileSHA256(), Resource: &pb.ProviderDetachResourceV1{}}
}
func padOrdinaryRequest(t *testing.T, q *pb.ProviderObservationRequestV1, size int) {
	t.Helper()
	for n := 0; n <= size; n++ {
		q.Resource.Authority = strings.Repeat("a", n)
		if proto.Size(q) == size {
			return
		}
	}
	t.Fatal("unreachable size")
}
func TestOrdinaryV2RequestExactBoundaryAndLegacySeparation(t *testing.T) {
	if ordinaryProfileSHA256(LegacyOrdinaryObservationProfile) != "d0d289d4154d013b241b7db743d73c57281e4217d75676187892ba9af75cc3fb" || OrdinaryObservationProfileSHA256() != "3a3eb5c329052de53d7df9379e90ee6aa2a8caeaeeae2b7608af2035b6cbc01b" {
		t.Fatal("profile vector")
	}
	q := byteOrdinaryRequest()
	padOrdinaryRequest(t, q, 4096)
	q.InstalledArm = byteOrdinaryArm(t, 8192)
	before := proto.Clone(q)
	if proto.Size(q) != 12291 || !ordinaryRequestFits(q) || !proto.Equal(q, before) {
		t.Fatal("exact request bound/mutation")
	}
	q.Resource.Authority += "x"
	if proto.Size(q) != 12292 || ordinaryRequestFits(q) {
		t.Fatal("oversize request")
	}
	q = proto.Clone(before).(*pb.ProviderObservationRequestV1)
	q.InstalledArm = byteOrdinaryArm(t, 8193)
	if ordinaryRequestFits(q) {
		t.Fatal("oversize seal")
	}
	q = proto.Clone(before).(*pb.ProviderObservationRequestV1)
	q.ProfileId = LegacyOrdinaryObservationProfile
	q.ProfileSha256 = ordinaryProfileSHA256(q.ProfileId)
	if ordinaryRequestFits(q) {
		t.Fatal("legacy silently widened")
	}
	q.InstalledArm = nil
	if !ordinaryRequestFits(q) {
		t.Fatal("legacy exact4096")
	}
	q.Resource.Authority += "x"
	if ordinaryRequestFits(q) {
		t.Fatal("legacy4097")
	}
}
func TestOrdinaryV2ReadReplyResultFullAndStrippedBudgets(t *testing.T) {
	q, r, _ := ordinaryFixture(t)
	arm := byteOrdinaryArm(t, 3809)
	r.Window.Request.InstalledArm = arm
	r.CurrentRead.OriginalRead.Selector.OriginalRequest.InstalledArm = proto.Clone(arm).(*pb.ProviderDetachArmSealV1)
	before := proto.Clone(r)
	if proto.Size(r.CurrentRead) <= 4096 || !ordinaryReadFits(r.CurrentRead.OriginalRead) || !ordinaryReplyFits(r.CurrentRead) || !ordinaryResultFits(r) || !proto.Equal(r, before) {
		t.Fatal("complete arm accounting/mutation")
	}
	for _, which := range []string{"read", "reply", "result", "mixed"} {
		t.Run(which, func(t *testing.T) {
			n := proto.Clone(r).(*pb.ProviderObservationResultV1)
			switch which {
			case "read":
				n.CurrentRead.OriginalRead.ReadCorrelation = make([]byte, 12294)
			case "reply":
				n.CurrentRead.SampledSnapshot.SupervisorInstance = strings.Repeat("x", 12295)
			case "result":
				n.AckWindowSha256 = strings.Repeat("x", 32781)
			case "mixed":
				n.CurrentRead.SampledSnapshot.ProfileSha256 = ordinaryProfileSHA256(LegacyOrdinaryObservationProfile)
			}
			if ordinaryResultFits(n) {
				t.Fatal("oversize or version mix accepted")
			}
		})
	}
	// Full ceilings are conservative maxima, not a promise every shape at the
	// ceiling is admissible. The old stripped ceiling also applies independently.
	for _, limit := range []int{12293, 12294, 32780} {
		n := proto.Clone(r).(*pb.ProviderObservationResultV1)
		n.AckWindowSha256 = strings.Repeat("x", limit)
		if ordinaryResultFits(n) {
			t.Fatal("ignored stripped16384")
		}
	}
	_ = q
}
func TestOrdinaryV1HistoricalAndCurrentVectorsRemainReadable(t *testing.T) {
	q, r, now := ordinaryFixture(t)
	q.ProfileID = LegacyOrdinaryObservationProfile
	q.ProfileSHA256 = ordinaryProfileSHA256(q.ProfileID)
	q.RequestSHA256 = q.SHA256()
	r.Window.Request = q.native()
	for _, s := range []*pb.ProviderObservationSnapshotV1{r.Window.InstalledSnapshot, r.CurrentSnapshot, r.CurrentRead.OriginalRead.ExpectedIdentity, r.CurrentRead.SampledSnapshot} {
		s.ProfileId = q.ProfileID
		s.ProfileSha256 = q.ProfileSHA256
		s.MediationPathReceiptSha256 = ordinaryPathSHA256(s)
	}
	r.Events[0].MediationStreamReceiptSha256 = r.Window.InstalledSnapshot.MediationPathReceiptSha256
	r.Window.WindowSha256 = ""
	r.Window.WindowSha256 = ordinaryDigest("openshell.provider-detach.sandbox-mediation-window/v1", r.Window)
	r.CurrentRead = nil
	r.CurrentSnapshot = nil
	r.CurrentReportSequence = 0
	r.AckWindowSha256 = ""
	r.AckTerminalSha256 = ""
	r.TerminalSha256 = ""
	r.TerminalSha256 = ordinaryDigest("openshell.provider-detach.sandbox-mediation-terminal/v1", r)
	if q.Validate() != nil {
		t.Fatal("legacy request refused")
	}
	v, e := ordinaryResult(r, q, now)
	if e != nil || !v.HistoricalOnly || v.Current {
		t.Fatal("legacy history reinterpreted", e)
	}
}

func TestOrdinaryV2NestedExactReadReplyResultEdges(t *testing.T) {
	q := byteOrdinaryRequest()
	q.InstalledArm = byteOrdinaryArm(t, 8192)
	snapshot := &pb.ProviderObservationSnapshotV1{ProfileId: OrdinaryObservationProfile, ProfileSha256: OrdinaryObservationProfileSHA256()}
	small := &pb.ProviderObservationCurrentReadV1{Selector: &pb.GetProviderDetachObservationRequest{OriginalRequest: q}, ExpectedIdentity: snapshot}
	read := proto.Clone(small).(*pb.ProviderObservationCurrentReadV1)
	found := false
	for n := 0; n < 4096; n++ {
		read.ReadCorrelation = make([]byte, n)
		if proto.Size(read) == 12293 {
			found = true
			break
		}
	}
	if !found || !ordinaryReadFits(read) {
		t.Fatal("exact read edge")
	}
	read.ReadCorrelation = append(read.ReadCorrelation, 1)
	if proto.Size(read) != 12294 || ordinaryReadFits(read) {
		t.Fatal("read edge+1")
	}
	reply := &pb.ProviderObservationCurrentReplyV1{OriginalRead: proto.Clone(small).(*pb.ProviderObservationCurrentReadV1), SampledSnapshot: proto.Clone(snapshot).(*pb.ProviderObservationSnapshotV1)}
	found = false
	for n := 0; n < 4096; n++ {
		reply.SampledSnapshot.SupervisorInstance = strings.Repeat("s", n)
		if proto.Size(reply) == 12293 {
			found = true
			break
		}
	}
	if !found || !ordinaryReplyFits(reply) {
		t.Fatal("reachable reply edge")
	}
	reply.SampledSnapshot.SupervisorInstance += "s"
	if proto.Size(reply) != 12294 || ordinaryReplyFits(reply) {
		t.Fatal("full reply ceiling must not waive stripped4096")
	}
	reply.SampledSnapshot.SupervisorInstance += "s"
	if proto.Size(reply) != 12295 || ordinaryReplyFits(reply) {
		t.Fatal("reply+1")
	}
	result := &pb.ProviderObservationResultV1{Window: &pb.ProviderObservationWindowV1{Request: q}, CurrentRead: &pb.ProviderObservationCurrentReplyV1{OriginalRead: small, SampledSnapshot: snapshot}}
	found = false
	for n := 0; n < 16384; n++ {
		result.AckWindowSha256 = strings.Repeat("a", n)
		if proto.Size(result) == 32778 {
			found = true
			break
		}
	}
	if !found || !ordinaryResultFits(result) {
		t.Fatal("reachable result edge")
	}
	for _, target := range []int{32779, 32780, 32781} {
		result.AckWindowSha256 += "a"
		if proto.Size(result) != target || ordinaryResultFits(result) {
			t.Fatal("full result ceiling waived stripped16384", target)
		}
	}
}
