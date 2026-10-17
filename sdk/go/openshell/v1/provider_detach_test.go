// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package v1

import (
	"context"
	"errors"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	gproto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"strings"
	"time"

	"encoding/json"
	"testing"
)

// Literal owner-produced v4 fixture preserves all v3 hash domains/preimages.
const providerDetachOriginalRequest = `{"schema_version":1,"action_id":"78b7f3e7-7413-5338-a795-f35973214544","profile_id":"profile-1","event_id":"event-1","intent_sha256":"78b7f3e774131338e795f3597321454491bafb249cbdc83c0aaa15f112182c3b","target":{"authority":"gateway-a","workspace":"default","sandbox":"agent","sandbox_id":"sandbox-uuid","execution_id":"exec-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sandbox_resource_version":"9007199254740993","provider":"model","provider_id":"provider-uuid","provider_resource_version":"17","attachment_epoch":"epoch-1","configuration_fingerprint":"opaque/\u003ccfg\u003e\u0026雪","configuration_instance":"config-1","config_revision":"8","provider_env_revision":"2","native_policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","native_policy_version":3},"target_sha256":"6389f95c089e24f49bf59f7966fbc3ee09d045ec19816d54c31244a1a56854d2","original_intent":{"schema_version":1,"target":{"gatewayID":"gateway-a","workspace":"default","sandbox":"agent","sandboxID":"sandbox-uuid","executionID":"exec-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"event_id":"event-1","policy_revision":"rules-1","policy_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","rule_id":"secret","detach":{"schema_version":1,"profile_id":"profile-1","violation_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","target":{"authority":"gateway-a","workspace":"default","sandbox":"agent","sandbox_id":"sandbox-uuid","execution_id":"exec-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sandbox_resource_version":"9007199254740993","provider":"model","provider_id":"provider-uuid","provider_resource_version":"17","attachment_epoch":"epoch-1","configuration_fingerprint":"opaque/\u003ccfg\u003e\u0026雪","configuration_instance":"config-1","config_revision":"8","provider_env_revision":"2","native_policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","native_policy_version":3},"target_sha256":"6389f95c089e24f49bf59f7966fbc3ee09d045ec19816d54c31244a1a56854d2"}}}`

func detachFixture(t *testing.T) ProviderDetachRequest {
	t.Helper()
	var q ProviderDetachRequest
	if err := json.Unmarshal([]byte(providerDetachOriginalRequest), &q); err != nil {
		t.Fatal(err)
	}
	return q
}

func TestProviderDetachOriginalIntentMatchesControllerAndRustVectors(t *testing.T) {
	q := detachFixture(t)
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
	if q.Target.SandboxResourceVersion != 9007199254740993 {
		t.Fatal("uint64 precision lost")
	}
	if q.Target.SHA256() != "6389f95c089e24f49bf59f7966fbc3ee09d045ec19816d54c31244a1a56854d2" ||
		q.OriginalIntent.SHA256() != "78b7f3e774131338e795f3597321454491bafb249cbdc83c0aaa15f112182c3b" ||
		q.ActionID != "78b7f3e7-7413-5338-a795-f35973214544" {
		t.Fatal("cross-language vector mismatch")
	}
	bytes, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if string(bytes) != providerDetachOriginalRequest {
		t.Fatal("closed request field order/HTML/string integer projection changed")
	}
}

func TestProviderDetachOriginalIntentSubstitutionsRefuse(t *testing.T) {
	mutations := []func(*ProviderDetachRequest){
		func(q *ProviderDetachRequest) { q.OriginalIntent.PolicyRevision += "x" },
		func(q *ProviderDetachRequest) { q.OriginalIntent.PolicyHash = q.Target.NativePolicyHash },
		func(q *ProviderDetachRequest) { q.OriginalIntent.RuleID += "x" },
		func(q *ProviderDetachRequest) { q.OriginalIntent.Detach.ViolationSHA256 = q.Target.NativePolicyHash },
		func(q *ProviderDetachRequest) { q.OriginalIntent.Target.GatewayID = "other" },
		func(q *ProviderDetachRequest) { q.OriginalIntent.Target.RuntimeHandle = "forbidden" },
		func(q *ProviderDetachRequest) { q.OriginalIntent.Target.SandboxID += "x" },
		func(q *ProviderDetachRequest) { q.OriginalIntent.SchemaVersion = 2 },
		func(q *ProviderDetachRequest) { q.OriginalIntent.Detach.SchemaVersion = 2 },
		func(q *ProviderDetachRequest) { q.ProfileID += "x" },
		func(q *ProviderDetachRequest) { q.EventID += "x" },
		func(q *ProviderDetachRequest) { q.ActionID = "00000000-0000-4000-8000-000000000000" },
		func(q *ProviderDetachRequest) { q.Target.SandboxResourceVersion-- },
		func(q *ProviderDetachRequest) { q.OriginalIntent.Detach = nil },
		func(q *ProviderDetachRequest) { q.TargetSHA256 = q.Target.NativePolicyHash },
		func(q *ProviderDetachRequest) { q.Target.ConfigurationFingerprint = string([]byte{255}) },
	}
	for i, mutate := range mutations {
		q := detachFixture(t)
		mutate(&q)
		if q.Validate() == nil {
			t.Fatalf("substitution %d accepted", i)
		}
	}
}

func TestProviderDetachControllerAliasIsIndependentFromNativeAuthority(t *testing.T) {
	q := detachFixture(t)
	q.OriginalIntent.Target.GatewayID = "controller-alias"
	q.IntentSHA256 = q.OriginalIntent.SHA256()
	q.ActionID = detachActionID(q.IntentSHA256)
	if q.OriginalIntent.Target.GatewayID == q.Target.Authority {
		t.Fatal("fixture aliases unexpectedly equal")
	}
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestProviderDetachResourceScopeDoesNotNeedFreshSnapshot(t *testing.T) {
	q := detachFixture(t)
	original := q.Target.Resource().SHA256()
	if original != "55d6d2b621787571674ca35afa5faceb8473917656a8c79009b5f241c9f105f8" {
		t.Fatal("native resource-scope vector mismatch")
	}
	q.Target.SandboxResourceVersion++
	q.Target.ConfigRevision++
	q.Target.ProviderEnvRevision++
	q.Target.ConfigurationFingerprint = "another opaque snapshot"
	if q.Target.Resource().SHA256() != original {
		t.Fatal("mutable snapshot changed immutable grant scope")
	}
	q.Target.ExecutionID = "exec-v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if q.Target.Resource().SHA256() == original {
		t.Fatal("execution grant rebound")
	}
	q = detachFixture(t)
	q.Target.ProviderID = "another-provider"
	if q.Target.Resource().SHA256() == original {
		t.Fatal("provider grant rebound")
	}
}

type detachTransportFake struct {
	armCalls    int
	armErr      error
	armReadback *pb.ProviderDetachAttemptReadbackV1
	lastArm     *pb.ArmProviderDetachAttemptRequest
	pb.OpenShellClient
	writes, reads int
	writeErr      error
	outcome       *pb.ProviderDetachOutcomeV1
	target        *pb.ProviderDetachTargetV1
	lastAction    *pb.ProviderDetachActionV1
	lastRead      *pb.GetConditionalProviderDetachStateRequest
}

func (f *detachTransportFake) ConditionalDetachSandboxProvider(_ context.Context, q *pb.ConditionalDetachSandboxProviderRequest, _ ...grpc.CallOption) (*pb.ConditionalDetachSandboxProviderResponse, error) {
	f.writes++
	f.lastAction = q.Action
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	return &pb.ConditionalDetachSandboxProviderResponse{Outcome: f.outcome}, nil
}
func (f *detachTransportFake) GetConditionalProviderDetachState(_ context.Context, q *pb.GetConditionalProviderDetachStateRequest, _ ...grpc.CallOption) (*pb.GetConditionalProviderDetachStateResponse, error) {
	f.reads++
	f.lastRead = q
	switch q.Query.(type) {
	case *pb.GetConditionalProviderDetachStateRequest_Resolve:
		return &pb.GetConditionalProviderDetachStateResponse{Result: &pb.GetConditionalProviderDetachStateResponse_Target{Target: f.target}}, nil
	case *pb.GetConditionalProviderDetachStateRequest_QueryAttempt:
		return &pb.GetConditionalProviderDetachStateResponse{Result: &pb.GetConditionalProviderDetachStateResponse_Attempt{Attempt: f.armReadback}}, nil
	case *pb.GetConditionalProviderDetachStateRequest_Recover:
		return &pb.GetConditionalProviderDetachStateResponse{Result: &pb.GetConditionalProviderDetachStateResponse_Outcome{Outcome: f.outcome}}, nil
	default:
		panic("unexpected or mutating recovery path")
	}
}
func nativeDetachOutcome(q ProviderDetachRequest) *pb.ProviderDetachOutcomeV1 {
	return &pb.ProviderDetachOutcomeV1{State: "applied", Receipt: &pb.ProviderDetachReceiptV1{
		ActionId: q.ActionID, IntentSha256: q.IntentSHA256, TargetSha256: q.TargetSHA256, Target: detachTargetToProto(q.Target), BeforeAttachmentEpoch: q.Target.AttachmentEpoch,
		AfterAttachmentEpoch: "11111111-1111-4111-8111-111111111111", NativeReceiptId: "22222222-2222-4222-8222-222222222222", HoldId: "33333333-3333-4333-8333-333333333333", ConfigRevision: 9, ProviderEnvRevision: 3, ConfigurationInstance: "after-config", NativePolicyHash: q.Target.NativePolicyHash, NativePolicyVersion: 4, RecordedTime: timestamppb.New(time.Now())}}
}
func TestProviderDetachTransportUnknownUsesOnlyOriginalReadback(t *testing.T) {
	q := detachFixture(t)
	fake := &detachTransportFake{writeErr: status.Error(codes.Unavailable, "synthetic lost ACK"), target: detachTargetToProto(q.Target)}
	client := &ProviderDetachmentClient{rpc: fake, resource: q.Target.Resource(), timeout: time.Second}
	target, err := client.Resolve(context.Background())
	if err != nil || target != q.Target {
		t.Fatal("resolve mapping", err)
	}
	unknown, err := client.Dispatch(context.Background(), q)
	if err == nil || unknown.State != "unknown" || unknown.Receipt != nil || fake.writes != 1 {
		t.Fatal("uncertain write was retried or qualified", err)
	}
	if fake.lastAction.OriginalIntent.PolicyHash != q.OriginalIntent.PolicyHash || fake.lastAction.OriginalIntent.Detach.ViolationSha256 != q.OriginalIntent.Detach.ViolationSHA256 || fake.lastAction.OriginalIntent.Target.GatewayId != q.OriginalIntent.Target.GatewayID {
		t.Fatal("original intent lost in transport")
	}
	fake.outcome = nativeDetachOutcome(q)
	recovered, err := client.Recover(context.Background(), q)
	if err != nil || recovered.State != "applied" || recovered.Receipt == nil || fake.writes != 1 || fake.reads != 2 {
		t.Fatal("recovery did not remain read-only", err)
	}
	if fake.lastRead.GetRecover().Action.ActionId != q.ActionID {
		t.Fatal("recovery rebound original action")
	}
	fake.outcome.Receipt.ActionId = "another-action"
	invalid, err := client.Recover(context.Background(), q)
	if err == nil || invalid.State != "unknown" || invalid.Receipt != nil || fake.writes != 1 {
		t.Fatal("mismatched native receipt accepted")
	}
}
func TestProviderDetachTransportRejectsUnimplementedWithoutFallbackAndOutsideResource(t *testing.T) {
	q := detachFixture(t)
	fake := &detachTransportFake{writeErr: status.Error(codes.Unimplemented, "old gateway")}
	client := &ProviderDetachmentClient{rpc: fake, resource: q.Target.Resource(), timeout: time.Second}
	result, err := client.Dispatch(context.Background(), q)
	var typed *StatusError
	if result.State != "unknown" || !errors.As(err, &typed) || typed.Code != ErrorUnimplemented || fake.writes != 1 {
		t.Fatal("unsupported gateway fallback", err)
	}
	client.resource.ProviderID = "another-provider"
	if _, err = client.Dispatch(context.Background(), q); err == nil || fake.writes != 1 {
		t.Fatal("out-of-resource dispatch reached transport")
	}
	client.resource = q.Target.Resource()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = client.Recover(ctx, q); !errors.Is(err, context.Canceled) || fake.reads != 0 {
		t.Fatal("cancelled recovery reached transport", err)
	}
}
func TestProviderDetachConstructorRejectsImplicitOrInsecureAuthority(t *testing.T) {
	q := detachFixture(t)
	cases := []ProviderDetachmentConfig{
		{Address: "localhost:8443", Resource: q.Target.Resource()},
		{Address: "http://localhost:8443", Resource: q.Target.Resource(), TLS: &TLSConfig{CAFile: "/not-read"}, Auth: StaticToken("synthetic")},
		{Address: "localhost:8443", Resource: q.Target.Resource(), TLS: &TLSConfig{Insecure: true, CAFile: "/not-read"}, Auth: StaticToken("synthetic")},
		{Address: "localhost:8443", Resource: q.Target.Resource(), TLS: &TLSConfig{CAFile: "/not-read"}, Auth: NoAuth()},
	}
	for i, cfg := range cases {
		if _, err := NewProviderDetachmentClient(cfg); err == nil {
			t.Fatalf("unsafe constructor %d accepted", i)
		}
	}
	var nilAuth *staticToken
	if _, err := NewProviderDetachmentClient(ProviderDetachmentConfig{Address: "localhost:8443", Resource: q.Target.Resource(), TLS: &TLSConfig{CAFile: "/not-read"}, Auth: nilAuth}); err == nil {
		t.Fatal("typed nil auth accepted")
	}
}

// Literal agreed Native/controller v3 attempt vector; synthetic metadata only.
const providerDetachAttemptVector = `{"schema_version":1,"dispatcher_decision_id":"66666666-6666-4666-8666-666666666666","action_id":"78b7f3e7-7413-5338-a795-f35973214544","intent_sha256":"78b7f3e774131338e795f3597321454491bafb249cbdc83c0aaa15f112182c3b","target_sha256":"6389f95c089e24f49bf59f7966fbc3ee09d045ec19816d54c31244a1a56854d2","native_receipt_id":"11111111-1111-4111-8111-111111111111","hold_id":"22222222-2222-4222-8222-222222222222","authority":"gateway-a","gateway_boot_id":"88888888-8888-4888-8888-888888888888","workspace":"default","sandbox_id":"sandbox-uuid","execution_id":"exec-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provider_id":"provider-uuid","attachment_epoch":"33333333-3333-4333-8333-333333333333","configuration_instance":"config-after","config_revision":"9","provider_env_revision":"3","native_policy_hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","native_policy_version":4,"supervisor_instance":"44444444-4444-4444-8444-444444444444","supervisor_session":"55555555-5555-4555-8555-555555555555","arm_capture_sequence":"10","challenge":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","not_before":{"seconds":"1792180000","nanos":0},"deadline":{"seconds":"1792180020","nanos":0}}`

func TestProviderDetachAttemptMatchesClosedNativeControllerVector(t *testing.T) {
	var a ProviderDetachAttempt
	if err := json.Unmarshal([]byte(providerDetachAttemptVector), &a); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(a)
	if err != nil || string(b) != providerDetachAttemptVector {
		t.Fatal("attempt framing drift")
	}
	if ProviderDetachAttemptSHA256(a) != "5891bfb6f1986af26d78cccd52e62f1078b7132fc676975e6ca39e457a79da15" || ProviderDetachAttemptID(a) != "5891bfb6-f198-5af2-ad78-cccd52e62f10" {
		t.Fatal("attempt hash or UUID mismatch")
	}
	if a.NotBefore.Validate() != nil || a.Deadline.Validate() != nil {
		t.Fatal("valid vector time refused")
	}
}

func TestProviderDetachAttemptTimestampRejectsNormalization(t *testing.T) {
	for _, a := range []ProviderDetachAttemptTime{{0, -1}, {0, 1000000000}, {-62135596801, 0}, {253402300800, 0}} {
		if a.Validate() == nil {
			t.Fatal("invalid native timestamp normalized")
		}
	}
	for _, a := range []ProviderDetachAttemptTime{{-62135596800, 0}, {253402300799, 999999999}, {0, 0}} {
		if a.Validate() != nil {
			t.Fatal("valid protobuf timestamp refused")
		}
	}
}

func armFixture(t *testing.T) ProviderDetachArmRequest {
	t.Helper()
	var a ProviderDetachAttempt
	if err := json.Unmarshal([]byte(providerDetachAttemptVector), &a); err != nil {
		t.Fatal(err)
	}
	q := detachFixture(t)
	r := ProviderDetachReceipt{ActionID: q.ActionID, IntentSHA256: q.IntentSHA256, TargetSHA256: q.TargetSHA256, Target: q.Target,
		BeforeAttachmentEpoch: q.Target.AttachmentEpoch, AfterAttachmentEpoch: a.AttachmentEpoch, NativeReceiptID: a.NativeReceiptID, HoldID: a.HoldID,
		ConfigRevision: a.ConfigRevision, ProviderEnvRevision: a.ProviderEnvRevision, ConfigurationInstance: a.ConfigurationInstance,
		NativePolicyHash: a.NativePolicyHash, NativePolicyVersion: a.NativePolicyVersion, RecordedAt: a.NotBefore.Time().Add(-time.Second)}
	return ProviderDetachArmRequest{OriginalAction: q, OriginalReceipt: r, Attempt: a, AttemptID: ProviderDetachAttemptID(a), RequestSHA256: ProviderDetachAttemptSHA256(a)}
}

func TestProviderDetachArmBindingRejectsRehashedSubstitutionAndInvalidTime(t *testing.T) {
	q := armFixture(t)
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []func(*ProviderDetachArmRequest){
		func(q *ProviderDetachArmRequest) { q.Attempt.ProviderID = "different-provider" },
		func(q *ProviderDetachArmRequest) { q.Attempt.ConfigRevision++ },
		func(q *ProviderDetachArmRequest) { q.OriginalReceipt.HoldID = "99999999-9999-4999-8999-999999999999" },
		func(q *ProviderDetachArmRequest) { q.OriginalReceipt.Target.ProviderID = "different-provider" },
		func(q *ProviderDetachArmRequest) { q.Attempt.GatewayBootID = "" },
		func(q *ProviderDetachArmRequest) { q.Attempt.ArmCaptureSequence = 0 },
		func(q *ProviderDetachArmRequest) { q.Attempt.NotBefore.Nanos = -1 },
		func(q *ProviderDetachArmRequest) { q.Attempt.Deadline = q.Attempt.NotBefore },
		func(q *ProviderDetachArmRequest) { q.Attempt.Deadline.Seconds = q.Attempt.NotBefore.Seconds + 31 },
		func(q *ProviderDetachArmRequest) {
			q.OriginalReceipt.RecordedAt = q.Attempt.NotBefore.Time().Add(time.Nanosecond)
		},
	}
	for i, mutate := range cases {
		q := armFixture(t)
		mutate(&q)
		// A freshly derived hash supplies no authority to change original joins.
		q.RequestSHA256 = ProviderDetachAttemptSHA256(q.Attempt)
		q.AttemptID = ProviderDetachAttemptID(q.Attempt)
		if q.Validate() == nil {
			t.Fatalf("substitution %d admitted", i)
		}
	}
}

func (f *detachTransportFake) ArmProviderDetachAttempt(_ context.Context, q *pb.ArmProviderDetachAttemptRequest, _ ...grpc.CallOption) (*pb.ArmProviderDetachAttemptResponse, error) {
	f.armCalls++
	f.lastArm = q
	if f.armErr != nil {
		return nil, f.armErr
	}
	return &pb.ArmProviderDetachAttemptResponse{Readback: f.armReadback}, nil
}
func freshArmFixture(t *testing.T, now time.Time) ProviderDetachArmRequest {
	q := armFixture(t)
	start, end := now.Add(-2*time.Second), now.Add(20*time.Second)
	q.Attempt.NotBefore = ProviderDetachAttemptTime{Seconds: start.Unix(), Nanos: int32(start.Nanosecond())}
	q.Attempt.Deadline = ProviderDetachAttemptTime{Seconds: end.Unix(), Nanos: int32(end.Nanosecond())}
	q.OriginalReceipt.RecordedAt = now.Add(-3 * time.Second)
	q.RequestSHA256 = ProviderDetachAttemptSHA256(q.Attempt)
	q.AttemptID = ProviderDetachAttemptID(q.Attempt)
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
	return q
}
func nativeArmReadback(q ProviderDetachArmRequest, now time.Time, terminal bool) *pb.ProviderDetachAttemptReadbackV1 {
	a, r, t := q.Attempt, q.OriginalReceipt, q.OriginalAction.Target
	ack := &pb.ProviderDetachACKV1{ActionId: q.OriginalAction.ActionID, TargetSha256: q.OriginalAction.TargetSHA256, NativeReceiptId: r.NativeReceiptID, HoldId: r.HoldID, SandboxId: t.SandboxID, ExecutionId: t.ExecutionID, ProviderId: t.ProviderID, AttachmentEpoch: r.AfterAttachmentEpoch, ConfigurationInstance: r.ConfigurationInstance, ConfigRevision: r.ConfigRevision, ProviderEnvRevision: r.ProviderEnvRevision, NativePolicyHash: r.NativePolicyHash, NativePolicyVersion: r.NativePolicyVersion, SupervisorInstance: a.SupervisorInstance, SupervisorSession: a.SupervisorSession, Sequence: 13, State: "REVOKED", CredentialsInstalled: true, PolicyActive: true, LaunchEnvironmentAcknowledged: true, ObservedTime: timestamppb.New(now.Add(-800 * time.Millisecond)), EvaluatedTime: timestamppb.New(now.Add(-700 * time.Millisecond))}
	p := &pb.ProviderDetachAttemptReadbackV1{State: pb.ProviderDetachArmStateV1(2), Seal: &pb.ProviderDetachArmSealV1{Request: detachArmToProto(q), HoldGeneration: 1, RowResourceVersion: 9, InstallSequence: 11, InstalledTime: timestamppb.New(now.Add(-1500 * time.Millisecond))}, Current: &pb.ProviderDetachAttemptCurrentV1{GatewayBootId: a.GatewayBootID, HoldGeneration: 1, RowResourceVersion: 9, Ack: ack}}
	if terminal {
		p.State = pb.ProviderDetachArmStateV1(4)
		p.Result = pb.ProviderDetachAttemptResultV1(1)
		old := gproto.Clone(ack).(*pb.ProviderDetachACKV1)
		old.Sequence = 12
		old.ObservedTime = timestamppb.New(now.Add(-time.Second))
		old.EvaluatedTime = timestamppb.New(now.Add(-900 * time.Millisecond))
		p.Proof = &pb.ProviderDetachObservationV1{Ack: old, Refusal: &pb.ProviderDetachRefusalV1{ActionId: a.ActionID, TargetSha256: a.TargetSHA256, AttemptId: q.AttemptID, Challenge: a.Challenge, SupervisorInstance: a.SupervisorInstance, SupervisorSession: a.SupervisorSession, Sequence: 12, AttachmentEpoch: a.AttachmentEpoch, ConfigurationInstance: a.ConfigurationInstance, ConfigRevision: a.ConfigRevision, ProviderEnvRevision: a.ProviderEnvRevision, Unavailable: true, AttemptedTime: timestamppb.New(now.Add(-1200 * time.Millisecond)), ObservedTime: timestamppb.New(now.Add(-1100 * time.Millisecond))}}
	}
	return p
}
func TestProviderDetachArmTransportLostReplyQueriesOriginalOnly(t *testing.T) {
	now := time.Now().UTC()
	q := freshArmFixture(t, now)
	f := &detachTransportFake{armErr: status.Error(codes.Unavailable, "synthetic lost reply"), armReadback: nativeArmReadback(q, now, false)}
	c := &ProviderDetachmentClient{rpc: f, resource: q.OriginalAction.Target.Resource(), timeout: time.Second}
	out, err := c.ArmDetachAttempt(context.Background(), q)
	if err == nil || out.State != ProviderDetachUnknown || f.armCalls != 1 || f.writes != 0 {
		t.Fatal("unknown arm was not preserved")
	}
	out, err = c.QueryDetachAttempt(context.Background(), q)
	if err != nil || out.State != ProviderDetachArmed || out.Seal.InstallSequence != 11 || f.reads != 1 || f.armCalls != 1 || f.writes != 0 {
		t.Fatal("original RO arm recovery failed", err)
	}
	if !gproto.Equal(f.lastArm.Request, f.lastRead.GetQueryAttempt()) {
		t.Fatal("query retargeted original arm")
	}
	f.armErr = status.Error(codes.Unimplemented, "old peer")
	if out, err = c.ArmDetachAttempt(context.Background(), q); err == nil || out.State != ProviderDetachUnknown || f.writes != 0 {
		t.Fatal("unsupported peer fell back")
	}
}
func TestProviderDetachArmReadbackClosesOriginalProofAndCurrentSeparately(t *testing.T) {
	now := time.Now().UTC()
	q := freshArmFixture(t, now)
	good := nativeArmReadback(q, now, true)
	out, err := detachReadbackFromProto(good, q, now)
	if err != nil || out.Proof.Refusal.Sequence != 12 || out.Current.ACK.Sequence != 13 {
		t.Fatal("valid historical/current transcript refused", err)
	}
	cases := []func(*pb.ProviderDetachAttemptReadbackV1){
		func(p *pb.ProviderDetachAttemptReadbackV1) { p.State = 0 },
		func(p *pb.ProviderDetachAttemptReadbackV1) { p.Current.Ack.Sequence = 11 },
		func(p *pb.ProviderDetachAttemptReadbackV1) { p.Seal.InstallSequence = 10 },
		func(p *pb.ProviderDetachAttemptReadbackV1) { p.Current.RowResourceVersion++ },
		func(p *pb.ProviderDetachAttemptReadbackV1) { p.Proof.Ack.Sequence = 13 },
		func(p *pb.ProviderDetachAttemptReadbackV1) { p.Proof.Refusal.Sequence = 11 },
		func(p *pb.ProviderDetachAttemptReadbackV1) { p.Proof.Refusal.Challenge = "b" },
		func(p *pb.ProviderDetachAttemptReadbackV1) {
			p.Proof.Refusal.AttemptedTime = timestamppb.New(now.Add(-1600 * time.Millisecond))
		},
		func(p *pb.ProviderDetachAttemptReadbackV1) {
			p.Current.Ack.ObservedTime = timestamppb.New(now.Add(-2 * time.Second))
		},
		func(p *pb.ProviderDetachAttemptReadbackV1) {
			p.Proof.Ack.ObservedTime = timestamppb.New(now.Add(-31 * time.Second))
		},
		func(p *pb.ProviderDetachAttemptReadbackV1) {
			p.Current.Ack.EvaluatedTime = timestamppb.New(now.Add(time.Second))
		},
		func(p *pb.ProviderDetachAttemptReadbackV1) { p.Seal.Request.OriginalReceipt.HoldId = "different" },
	}
	for i, mutate := range cases {
		p := gproto.Clone(good).(*pb.ProviderDetachAttemptReadbackV1)
		mutate(p)
		if out, err := detachReadbackFromProto(p, q, now); err == nil || out.State != ProviderDetachUnknown {
			t.Fatalf("invalid transcript %d admitted", i)
		}
	}
	if out, err := detachReadbackFromProto(good, q, q.Attempt.Deadline.Time()); err == nil || out.State != ProviderDetachUnknown {
		t.Fatal("proof survived exact deadline")
	}
}
func TestProviderDetachArmBootstrapIsStrictZeroReadOnlyMetadata(t *testing.T) {
	now := time.Now().UTC()
	original := freshArmFixture(t, now)
	bootstrap := original
	bootstrap.Attempt = ProviderDetachAttempt{}
	bootstrap.AttemptID = ""
	bootstrap.RequestSHA256 = ""
	native := nativeArmReadback(original, now, false)
	f := &detachTransportFake{armReadback: &pb.ProviderDetachAttemptReadbackV1{State: pb.ProviderDetachArmStateV1(6), Current: native.Current}}
	c := &ProviderDetachmentClient{rpc: f, resource: original.OriginalAction.Target.Resource(), timeout: time.Second}
	out, err := c.QueryDetachAttempt(context.Background(), bootstrap)
	if err != nil || out.State != ProviderDetachUnknown || out.Current == nil || out.Seal != nil || out.Proof != nil || out.Result != "" || f.armCalls != 0 || f.writes != 0 {
		t.Fatal("bootstrap conferred authority", err)
	}
	if f.lastRead.GetQueryAttempt().Attempt != nil {
		t.Fatal("zero bootstrap serialized a partial attempt")
	}
	partial := bootstrap
	partial.Attempt.GatewayBootID = original.Attempt.GatewayBootID
	before := f.reads
	if _, err := c.QueryDetachAttempt(context.Background(), partial); err == nil || f.reads != before {
		t.Fatal("partial bootstrap reached transport")
	}
	f.armReadback = native
	if out, err = c.QueryDetachAttempt(context.Background(), bootstrap); err == nil || out.State != ProviderDetachUnknown {
		t.Fatal("bootstrap accepted a positive seal")
	}
}

type witnessTransportFake struct {
	metadata  *pb.GetProviderDetachWitnessInvocationResponse
	lastQuery *pb.GetProviderDetachWitnessInvocationRequest
	pb.OpenShellClient
	invokes, reserves, queries int
	request                    *pb.ProviderDetachWitnessRequestV1
	reply                      *pb.ProviderDetachWitnessInvocationV1
	err                        error
}

func (f *witnessTransportFake) ReserveProviderDetachWitness(_ context.Context, q *pb.ReserveProviderDetachWitnessRequest, _ ...grpc.CallOption) (*pb.ReserveProviderDetachWitnessResponse, error) {
	f.reserves++
	f.request = q.Request
	return &pb.ReserveProviderDetachWitnessResponse{Invocation: f.reply}, f.err
}
func (f *witnessTransportFake) InvokeProviderDetachWitness(_ context.Context, q *pb.InvokeProviderDetachWitnessRequest, _ ...grpc.CallOption) (*pb.InvokeProviderDetachWitnessResponse, error) {
	f.invokes++
	f.request = q.Request
	return &pb.InvokeProviderDetachWitnessResponse{Invocation: f.reply}, f.err
}
func (f *witnessTransportFake) GetProviderDetachWitnessInvocation(_ context.Context, q *pb.GetProviderDetachWitnessInvocationRequest, _ ...grpc.CallOption) (*pb.GetProviderDetachWitnessInvocationResponse, error) {
	f.queries++
	f.lastQuery = q
	f.request = q.Request
	if f.metadata != nil {
		return f.metadata, f.err
	}
	return &pb.GetProviderDetachWitnessInvocationResponse{Invocation: f.reply}, f.err
}
func witnessFixture(t *testing.T) ProviderDetachWitnessRequest {
	t.Helper()
	now := time.Now().UTC()
	q := ProviderDetachWitnessRequest{RunID: "11111111-1111-4111-8111-111111111111", ProfileID: ProviderDetachWitnessProfile, ProfileSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		InstalledArm: ProviderDetachArmSeal{Request: freshArmFixture(t, now), HoldGeneration: 1, RowResourceVersion: 2, InstallSequence: 3, InstalledAt: now}, SourceIncarnation: "22222222-2222-4222-8222-222222222222", BoundaryIncarnation: "33333333-3333-4333-8333-333333333333"}
	q.RequestSHA256 = q.SHA256()
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
	return q
}
func TestProviderDetachWitnessOneUnknownInvokeNeverRetriesOrFallsBack(t *testing.T) {
	q := witnessFixture(t)
	f := &witnessTransportFake{err: status.Error(codes.Unavailable, "synthetic lost original response")}
	c := &ProviderDetachmentClient{rpc: f, resource: q.InstalledArm.Request.OriginalAction.Target.Resource(), timeout: time.Second}
	result, err := c.InvokeDetachWitness(context.Background(), q)
	if err == nil || result.State != "unknown" || f.invokes != 1 || f.reserves != 0 || f.queries != 0 {
		t.Fatal("unknown call was retried or transformed", result, err)
	}
	if !gproto.Equal(f.request, q.native()) {
		t.Fatal("original source/incarnation/arm binding changed")
	}
	f.err = nil
	f.reply = &pb.ProviderDetachWitnessInvocationV1{OriginalKey: q.originalKey(), RequestSha256: q.RequestSHA256, State: "unknown", SourceInvalidated: true, BoundaryCancelPending: true}
	result, err = c.QueryDetachWitness(context.Background(), q)
	if err != nil || !result.BoundaryCancelPending || result.NativeObservation != nil || f.invokes != 1 || f.queries != 1 {
		t.Fatal("readback manufactured native proof or invoked", result, err)
	}
}
func TestProviderDetachWitnessSubstitutionsRefuseBeforeTransport(t *testing.T) {
	original := witnessFixture(t)
	f := &witnessTransportFake{}
	c := &ProviderDetachmentClient{rpc: f, resource: original.InstalledArm.Request.OriginalAction.Target.Resource(), timeout: time.Second}
	for _, mutate := range []func(*ProviderDetachWitnessRequest){func(q *ProviderDetachWitnessRequest) { q.ProfileID = "shell" }, func(q *ProviderDetachWitnessRequest) { q.SourceIncarnation = "" }, func(q *ProviderDetachWitnessRequest) { q.BoundaryIncarnation = "different" }, func(q *ProviderDetachWitnessRequest) { q.InstalledArm.InstallSequence++ }, func(q *ProviderDetachWitnessRequest) { q.RequestSHA256 = "0" }} {
		q := original
		mutate(&q)
		if _, err := c.InvokeDetachWitness(context.Background(), q); err == nil || f.invokes != 0 {
			t.Fatal("substitution reached transport")
		}
	}
	f.reply = &pb.ProviderDetachWitnessInvocationV1{OriginalKey: original.originalKey(), RequestSha256: original.RequestSHA256, State: "unknown", BoundaryQuiesced: true}
	if _, err := c.QueryDetachWitness(context.Background(), original); err == nil {
		t.Fatal("unbound quiescence accepted")
	}
}

func TestProviderDetachWitnessMetadataClosedResponseAndNoEffects(t *testing.T) {
	q := witnessFixture(t)
	r := q.InstalledArm.Request.OriginalAction.Target.Resource()
	valid := &pb.GetProviderDetachWitnessInvocationResponse{Capability: &pb.ProviderDetachWitnessControlV1{State: "capability", SourceIncarnation: q.SourceIncarnation, BoundaryIncarnation: q.BoundaryIncarnation, ProfileSha256: q.ProfileSHA256, ExecutionId: r.ExecutionID}, CapabilityResource: detachResourceToProto(r), CapabilitySupervisorSession: q.InstalledArm.Request.Attempt.SupervisorSession}
	f := &witnessTransportFake{metadata: valid}
	c := &ProviderDetachmentClient{rpc: f, resource: r, timeout: time.Second}
	out, err := c.DiscoverDetachWitnessMetadata(context.Background())
	if err != nil || out.Resource != r || out.SourceIncarnation != q.SourceIncarnation || f.invokes != 0 || f.reserves != 0 || f.queries != 1 || f.lastQuery.Request != nil || len(f.lastQuery.CapabilityResources) != 1 {
		t.Fatal("not one pure metadata read", out, err)
	}
	for caseID := 0; caseID < 14; caseID++ {
		p := gproto.Clone(valid).(*pb.GetProviderDetachWitnessInvocationResponse)
		switch caseID {
		case 0:
			p.Invocation = &pb.ProviderDetachWitnessInvocationV1{State: "unknown"}
		case 1:
			p.Capability = nil
		case 2:
			p.CapabilityResource = nil
		case 3:
			p.CapabilitySupervisorSession = ""
		case 4:
			p.CapabilityResource.ProviderId = "foreign"
		case 5:
			p.Capability.SourceIncarnation = ""
		case 6:
			p.Capability.BoundaryIncarnation = "00000000-0000-0000-0000-000000000000"
		case 7:
			p.Capability.State = "unknown"
		case 8:
			p.Capability.ExecutionId = "exec-v1:" + strings.Repeat("b", 64)
		case 9:
			p.Capability.OriginalKey = strings.Repeat("a", 64)
		case 10:
			p.Capability.RequestSha256 = strings.Repeat("a", 64)
		case 11:
			p.Capability.ProfileSha256 = "invalid"
		case 12:
			p.CapabilitySupervisorSession = "invalid"
		case 13:
			p = &pb.GetProviderDetachWitnessInvocationResponse{Invocation: &pb.ProviderDetachWitnessInvocationV1{}}
		}
		f.metadata = p
		if _, err = c.DiscoverDetachWitnessMetadata(context.Background()); err == nil {
			t.Fatalf("response case%d accepted", caseID)
		}
	}
	f.metadata = valid
	if _, err = c.QueryDetachWitness(context.Background(), q); err == nil {
		t.Fatal("historical read accepted discovery-mode response")
	}
	if f.invokes != 0 || f.reserves != 0 {
		t.Fatal("read caused a write")
	}
	// A fresh snapshot never mutates an already-issued original request/digest.
	before := q.SHA256()
	f.metadata = gproto.Clone(valid).(*pb.GetProviderDetachWitnessInvocationResponse)
	f.metadata.Capability.SourceIncarnation = "44444444-4444-4444-8444-444444444444"
	if _, err = c.DiscoverDetachWitnessMetadata(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q.SHA256() != before {
		t.Fatal("discovery rebound original")
	}
	f.metadata = nil
	f.reply = &pb.ProviderDetachWitnessInvocationV1{OriginalKey: q.originalKey(), RequestSha256: q.RequestSHA256, State: "unknown"}
	if _, err = c.QueryDetachWitness(context.Background(), q); err != nil {
		t.Fatal("original history changed", err)
	}
	if !gproto.Equal(f.request, q.native()) {
		t.Fatal("history query substituted new nonce")
	}
}
