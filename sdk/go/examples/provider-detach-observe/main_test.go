//go:build linux || darwin

// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fakeObservation struct {
	begins, queries atomic.Int32
	fail            bool
	value           v1.OrdinaryObservationEvidence
}

func (f *fakeObservation) Close() error { return nil }
func (f *fakeObservation) DiscoverOrdinaryObservation(context.Context) (v1.OrdinaryObservationMetadata, error) {
	return v1.OrdinaryObservationMetadata{}, nil
}
func (f *fakeObservation) BeginOrdinaryObservation(context.Context, v1.OrdinaryObservationRequest) (v1.OrdinaryObservationEvidence, error) {
	f.begins.Add(1)
	if f.fail {
		return f.value, errors.New("synthetic lost response with private canary")
	}
	return f.value, nil
}
func (f *fakeObservation) QueryOrdinaryObservation(context.Context, v1.OrdinaryObservationRequest) (v1.OrdinaryObservationEvidence, error) {
	f.queries.Add(1)
	return f.value, nil
}
func fixture(t *testing.T) (string, string, string, ledger) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	resource := v1.ProviderDetachResource{Authority: "gateway", Workspace: "default", Sandbox: "agent", SandboxID: "11111111-1111-4111-8111-111111111111", ExecutionID: "exec-v1:" + strings.Repeat("a", 64), Provider: "model", ProviderID: "22222222-2222-4222-8222-222222222222"}
	q := v1.OrdinaryObservationRequest{Resource: resource, RunID: "33333333-3333-4333-8333-333333333333", StepID: "44444444-4444-4444-8444-444444444444", ProfileID: v1.OrdinaryObservationProfile, ProfileSHA256: v1.OrdinaryObservationProfileSHA256(), EvidenceScope: v1.OrdinaryObservationEvidenceScope, SourceIncarnation: "55555555-5555-4555-8555-555555555555", BoundaryIncarnation: "66666666-6666-4666-8666-666666666666", Phase: "baseline", Deadline: time.Now().Add(time.Minute)}
	q.RequestSHA256 = q.SHA256()
	if q.Validate() != nil {
		t.Fatal("fixture invalid")
	}
	request := filepath.Join(dir, "request.json")
	raw, _ := json.Marshal(q)
	os.WriteFile(request, raw, 0600)
	token := filepath.Join(dir, "grant")
	os.WriteFile(token, []byte("synthetic-private-canary"), 0600)
	return dir, request, token, ledger{"openshell.manual-observation-original/v1", "single-operator-0001", strings.Repeat("b", 64), q}
}
func TestOriginalBeginConsumedBeforeLostResponseAndRace(t *testing.T) {
	dir, request, token, l := fixture(t)
	client := &fakeObservation{fail: true}
	factory := func(v1.ProviderDetachmentConfig) (observationClient, error) { return client, nil }
	args := []string{"begin", "-request-file", request, "-grant-file", token, "-ledger-dir", dir, "-operator-session", l.OperatorSession, "-run-profile-sha256", l.RunProfileSHA256}
	var results [2]error
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i] = run(args, &bytes.Buffer{}, factory) }(i)
	}
	wg.Wait()
	if client.begins.Load() != 1 || results[0] == nil || results[1] == nil {
		t.Fatal("original race delivered twice or lost response promoted")
	}
	original := filepath.Join(dir, ledgerName(l.Request))
	var retained ledger
	if privateRead(original, &retained) != nil || retained.Request.RequestSHA256 != l.Request.RequestSHA256 {
		t.Fatal("original not durable")
	}
	if run([]string{"query", "-original-ledger", original, "-grant-file", token}, &bytes.Buffer{}, factory) != nil || client.queries.Load() != 1 || client.begins.Load() != 1 {
		t.Fatal("query did not retain original-only semantics")
	}
	data, _ := os.ReadFile(original)
	if bytes.Contains(data, []byte("synthetic-private-canary")) {
		t.Fatal("credential leaked into ledger")
	}
	l.Request.SourceIncarnation = "77777777-7777-4777-8777-777777777777"
	l.Request.RequestSHA256 = l.Request.SHA256()
	raw, _ := json.Marshal(l.Request)
	os.WriteFile(request, raw, 0600)
	if run(args, &bytes.Buffer{}, factory) == nil || client.begins.Load() != 1 {
		t.Fatal("changed request reopened original")
	}
}
func TestInputIsConsumedOnlyAfterOriginalLiveInstallRead(t *testing.T) {
	dir, _, token, l := fixture(t)
	if exclusive(dir, ledgerName(l.Request), l) != nil {
		t.Fatal("ledger")
	}
	original := filepath.Join(dir, ledgerName(l.Request))
	client := &fakeObservation{value: v1.OrdinaryObservationEvidence{State: "open", Current: true, HistoricalOnly: false, CaptureEnd: time.Now().Add(20 * time.Second), WindowSHA256: strings.Repeat("c", 64), EvidenceScope: v1.OrdinaryObservationEvidenceScope}}
	factory := func(v1.ProviderDetachmentConfig) (observationClient, error) { return client, nil }
	args := []string{"consume-input", "-original-ledger", original, "-grant-file", token}
	for _, mutation := range []func(*v1.OrdinaryObservationEvidence){func(v *v1.OrdinaryObservationEvidence) { v.HistoricalOnly = true }, func(v *v1.OrdinaryObservationEvidence) { v.Current = false }, func(v *v1.OrdinaryObservationEvidence) { v.State = "terminal" }, func(v *v1.OrdinaryObservationEvidence) { v.ProcessWriterIdentityProven = true }} {
		before := client.value
		mutation(&client.value)
		if run(args, &bytes.Buffer{}, factory) == nil {
			t.Fatal("invalid readiness consumed input")
		}
		client.value = before
	}
	var output bytes.Buffer
	if run(args, &output, factory) != nil {
		t.Fatal("valid manual original input refused")
	}
	if run(args, &bytes.Buffer{}, factory) == nil {
		t.Fatal("manual input replayed")
	}
	if !bytes.Contains(output.Bytes(), []byte(`"process_writer_identity_proven":false`)) {
		t.Fatal("unproven writer disclosure absent")
	}
	var out bytes.Buffer
	if run([]string{"outcome", "-original-ledger", original, "-outcome", "unknown", "-task-id", "operator-task-0001"}, &out, factory) != nil || !bytes.Contains(out.Bytes(), []byte(`"native_model_completion_proof":false`)) {
		t.Fatal("manual outcome not distinct")
	}
}
func TestPrivateBoundedFilesAndPartialOriginalNeverReopened(t *testing.T) {
	dir, _, _, l := fixture(t)
	name := ledgerName(l.Request)
	path := filepath.Join(dir, name)
	os.WriteFile(path, []byte("{"), 0600)
	if exclusive(dir, name, l) == nil {
		t.Fatal("partial original overwritten")
	}
	var v ledger
	if privateRead(path, &v) == nil {
		t.Fatal("partial original accepted")
	}
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte(`{}`), 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	if privateRead(link, &v) == nil {
		t.Fatal("symlink accepted")
	}
	os.Chmod(target, 0644)
	if privateRead(target, &v) == nil {
		t.Fatal("public file accepted")
	}
	os.Chmod(target, 0600)
	os.WriteFile(target, bytes.Repeat([]byte("x"), maxFile+1), 0600)
	if privateRead(target, &v) == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestPrivateFIFOInputsRefuseBeforeClientEffects(t *testing.T) {
	for _, kind := range []string{"metadata", "grant"} {
		t.Run(kind, func(t *testing.T) {
			dir, request, token, l := fixture(t)
			fifo := filepath.Join(dir, "private-fifo")
			if err := unix.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "metadata" {
				request = fifo
			} else {
				token = fifo
			}
			var clients atomic.Int32
			client := &fakeObservation{}
			factory := func(v1.ProviderDetachmentConfig) (observationClient, error) {
				clients.Add(1)
				return client, nil
			}
			var out bytes.Buffer
			done := make(chan error, 1)
			go func() {
				done <- run([]string{"begin", "-request-file", request, "-grant-file", token, "-ledger-dir", dir, "-operator-session", l.OperatorSession, "-run-profile-sha256", l.RunProfileSHA256}, &out, factory)
			}()
			var err error
			select {
			case err = <-done:
			case <-time.After(500 * time.Millisecond):
				// Settle the old blocking implementation without leaving a reader
				// behind. No writer is opened on the successful refusal path.
				fd, openErr := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
				if openErr != nil {
					t.Fatal(openErr)
				}
				unix.Close(fd)
				select {
				case err = <-done:
				case <-time.After(time.Second):
					t.Fatal("FIFO reader did not settle")
				}
				t.Error("private FIFO blocked before regular-file validation")
			}
			if err != refused || clients.Load() != 0 || client.begins.Load() != 0 || client.queries.Load() != 0 || out.Len() != 0 {
				t.Fatal("nonregular input reached a client or produced output")
			}
			if _, err := os.Lstat(filepath.Join(dir, ledgerName(l.Request))); !os.IsNotExist(err) {
				t.Fatal("FIFO refusal created or repaired an original ledger")
			}
		})
	}
}

func TestPrivateRegularInputsRemainAccepted(t *testing.T) {
	_, request, grant, l := fixture(t)
	var decoded v1.OrdinaryObservationRequest
	if err := privateRead(request, &decoded); err != nil || decoded.RequestSHA256 != l.Request.RequestSHA256 {
		t.Fatal("private regular metadata refused")
	}
	if token, err := tokenRead(grant); err != nil || token != "synthetic-private-canary" {
		t.Fatal("private regular grant refused")
	}
}

// Existing cross-language original-action vector; no private action-ID implementation.
const manualCanonicalOriginal = `{"schema_version":1,"action_id":"78b7f3e7-7413-5338-a795-f35973214544","profile_id":"profile-1","event_id":"event-1","intent_sha256":"78b7f3e774131338e795f3597321454491bafb249cbdc83c0aaa15f112182c3b","target":{"authority":"gateway-a","workspace":"default","sandbox":"agent","sandbox_id":"sandbox-uuid","execution_id":"exec-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sandbox_resource_version":"9007199254740993","provider":"model","provider_id":"provider-uuid","provider_resource_version":"17","attachment_epoch":"epoch-1","configuration_fingerprint":"opaque/\u003ccfg\u003e\u0026雪","configuration_instance":"config-1","config_revision":"8","provider_env_revision":"2","native_policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","native_policy_version":3},"target_sha256":"6389f95c089e24f49bf59f7966fbc3ee09d045ec19816d54c31244a1a56854d2","original_intent":{"schema_version":1,"target":{"gatewayID":"gateway-a","workspace":"default","sandbox":"agent","sandboxID":"sandbox-uuid","executionID":"exec-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"event_id":"event-1","policy_revision":"rules-1","policy_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","rule_id":"secret","detach":{"schema_version":1,"profile_id":"profile-1","violation_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","target":{"authority":"gateway-a","workspace":"default","sandbox":"agent","sandbox_id":"sandbox-uuid","execution_id":"exec-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sandbox_resource_version":"9007199254740993","provider":"model","provider_id":"provider-uuid","provider_resource_version":"17","attachment_epoch":"epoch-1","configuration_fingerprint":"opaque/\u003ccfg\u003e\u0026雪","configuration_instance":"config-1","config_revision":"8","provider_env_revision":"2","native_policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","native_policy_version":3},"target_sha256":"6389f95c089e24f49bf59f7966fbc3ee09d045ec19816d54c31244a1a56854d2"}}}`

type assemblyFake struct {
	fakeObservation
	resolves, dispatches, recovers, arms, armQueries atomic.Int32
	metadata                                         v1.OrdinaryObservationMetadata
	action                                           v1.ProviderDetachRequest
	current                                          v1.ProviderDetachAttemptReadback
	lose                                             bool
}

func (f *assemblyFake) DiscoverOrdinaryObservation(context.Context) (v1.OrdinaryObservationMetadata, error) {
	return f.metadata, nil
}
func (f *assemblyFake) Resolve(context.Context) (v1.ProviderDetachTarget, error) {
	f.resolves.Add(1)
	return f.action.Target, nil
}
func (f *assemblyFake) Dispatch(context.Context, v1.ProviderDetachRequest) (v1.ProviderDetachOutcome, error) {
	f.dispatches.Add(1)
	if f.lose {
		return v1.ProviderDetachOutcome{}, errors.New("private-provider-sentinel")
	}
	return v1.ProviderDetachOutcome{State: "unknown"}, nil
}
func (f *assemblyFake) Recover(context.Context, v1.ProviderDetachRequest) (v1.ProviderDetachOutcome, error) {
	f.recovers.Add(1)
	return v1.ProviderDetachOutcome{State: "unknown"}, nil
}
func (f *assemblyFake) ArmDetachAttempt(context.Context, v1.ProviderDetachArmRequest) (v1.ProviderDetachAttemptReadback, error) {
	f.arms.Add(1)
	if f.lose {
		return v1.ProviderDetachAttemptReadback{}, errors.New("private-provider-sentinel")
	}
	return f.current, nil
}
func (f *assemblyFake) QueryDetachAttempt(context.Context, v1.ProviderDetachArmRequest) (v1.ProviderDetachAttemptReadback, error) {
	f.armQueries.Add(1)
	return f.current, nil
}
func savePrivate(t *testing.T, dir, name string, value any) string {
	t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, name)
	if e = os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func assemblyFixture(t *testing.T) (string, originalAction, *assemblyFake, []string, clientFactory) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	var q v1.ProviderDetachRequest
	if json.Unmarshal([]byte(manualCanonicalOriginal), &q) != nil || q.Validate() != nil {
		t.Fatal("canonical vector")
	}
	a := originalAction{"openshell.manual-detach-original/v1", "controller-securityresponse", "operator-session-001", journalIdentity{"pd-original", "security", "11111111-1111-4111-8111-111111111111", "123"}, q}
	action := savePrivate(t, dir, "action.json", a)
	resource := savePrivate(t, dir, "resource.json", q.Target.Resource())
	token := filepath.Join(dir, "detach-grant")
	os.WriteFile(token, []byte("private-detach-sentinel"), 0600)
	now := time.Now().UTC()
	receipt := v1.ProviderDetachReceipt{ActionID: q.ActionID, IntentSHA256: q.IntentSHA256, TargetSHA256: q.TargetSHA256, Target: q.Target, BeforeAttachmentEpoch: q.Target.AttachmentEpoch, AfterAttachmentEpoch: "epoch-2", NativeReceiptID: "22222222-2222-4222-8222-222222222222", HoldID: "33333333-3333-4333-8333-333333333333", ConfigRevision: 9, ProviderEnvRevision: 3, ConfigurationInstance: "config-2", NativePolicyHash: strings.Repeat("e", 64), NativePolicyVersion: 4, RecordedAt: now.Add(-time.Second)}
	receiptFile := savePrivate(t, dir, "receipt.json", receipt)
	ack := v1.ProviderDetachACK{ActionID: q.ActionID, TargetSHA256: q.TargetSHA256, NativeReceiptID: receipt.NativeReceiptID, HoldID: receipt.HoldID, SandboxID: q.Target.SandboxID, ExecutionID: q.Target.ExecutionID, ProviderID: q.Target.ProviderID, AttachmentEpoch: receipt.AfterAttachmentEpoch, ConfigurationInstance: receipt.ConfigurationInstance, ConfigRevision: receipt.ConfigRevision, ProviderEnvRevision: receipt.ProviderEnvRevision, NativePolicyHash: receipt.NativePolicyHash, NativePolicyVersion: receipt.NativePolicyVersion, SupervisorInstance: "44444444-4444-4444-8444-444444444444", SupervisorSession: "55555555-5555-4555-8555-555555555555", Sequence: 7, State: "REVOKED", CredentialsInstalled: true, PolicyActive: true, LaunchEnvironmentAcknowledged: true, ObservedAt: now, EvaluatedAt: now}
	f := &assemblyFake{action: q, current: v1.ProviderDetachAttemptReadback{State: v1.ProviderDetachUnknown, Current: &v1.ProviderDetachAttemptCurrent{GatewayBootID: "66666666-6666-4666-8666-666666666666", HoldGeneration: 1, RowResourceVersion: 5, ACK: ack}}, metadata: v1.OrdinaryObservationMetadata{Resource: q.Target.Resource(), SourceIncarnation: "77777777-7777-4777-8777-777777777777", BoundaryIncarnation: "88888888-8888-4888-8888-888888888888", ProfileSHA256: v1.OrdinaryObservationProfileSHA256(), EvidenceScope: v1.OrdinaryObservationEvidenceScope}}
	args := []string{"-resource-file", resource, "-action-file", action, "-receipt-file", receiptFile, "-detach-grant-file", token, "-ledger-dir", dir, "-address", "gateway.example:8080", "-ca", "explicit-fixture-ca"}
	factory := func(c v1.ProviderDetachmentConfig) (observationClient, error) {
		if c.Resource != q.Target.Resource() || c.TLS == nil || c.TLS.CAFile != "explicit-fixture-ca" {
			t.Fatal("transport/resource substituted")
		}
		return f, nil
	}
	return dir, a, f, args, factory
}
func TestAssemblyCanonicalJournalProjectionAndControllerCustody(t *testing.T) {
	dir, a, f, args, factory := assemblyFixture(t)
	s := securityResponse{APIVersion: "security.openshield.io/v1alpha1", Kind: "SecurityResponse", Metadata: json.RawMessage(`{"name":"pd-original","namespace":"security","uid":"11111111-1111-4111-8111-111111111111","resourceVersion":"123","managedFields":[]}`), Status: json.RawMessage(`{"attempts":0,"verified":false}`)}
	s.Spec.Target = a.Request.OriginalIntent.Target
	s.Spec.Action = "detach_provider"
	s.Spec.EventID = a.Request.EventID
	s.Spec.PolicyRevision = a.Request.OriginalIntent.PolicyRevision
	s.Spec.PolicyHash = a.Request.OriginalIntent.PolicyHash
	s.Spec.RuleID = a.Request.OriginalIntent.RuleID
	s.Spec.RequestID = a.Request.ActionID
	s.Spec.ProviderDetach = a.Request.OriginalIntent.Detach
	p := savePrivate(t, dir, "response.json", s)
	var out bytes.Buffer
	argv := append([]string{"prepare-response"}, args...)
	argv = append(argv, "-response-file", p, "-operator-session", a.OperatorSession)
	if e := run(argv, &out, factory); e != nil {
		t.Fatal(e)
	}
	var projected originalAction
	if json.Unmarshal(out.Bytes(), &projected) != nil || !reflect.DeepEqual(projected.Request, a.Request) || projected.Origin != "controller-securityresponse" {
		t.Fatal("projection drift")
	}
	if projected.Request.IntentSHA256 != "78b7f3e774131338e795f3597321454491bafb249cbdc83c0aaa15f112182c3b" {
		t.Fatal("canonical vector changed")
	}
	// Even zero Attempts is never a controller ownership transfer.
	if run(append([]string{"dispatch"}, args...), &bytes.Buffer{}, factory) == nil || f.dispatches.Load() != 0 {
		t.Fatal("controller dispatch adopted")
	}
	if run(append([]string{"recover"}, args...), &bytes.Buffer{}, factory) != nil || f.recovers.Load() != 1 {
		t.Fatal("exact recovery unavailable")
	}
	s.Spec.RequestID = "99999999-9999-4999-8999-999999999999"
	if _, e := projectResponse(s, a.Request.Target.Resource(), a.OperatorSession); e == nil {
		t.Fatal("invented action ID accepted")
	}
	s.Spec.RequestID = a.Request.ActionID
	s.Spec.PolicyHash = strings.Repeat("f", 64)
	if _, e := projectResponse(s, a.Request.Target.Resource(), a.OperatorSession); e == nil {
		t.Fatal("original policy substitution accepted")
	}
}
func TestAssemblyManualDispatchConsumedAcrossSessionFileTokenChanges(t *testing.T) {
	dir, a, f, args, factory := assemblyFixture(t)
	a.Origin = "admitted-manual-original"
	a.Journal = journalIdentity{}
	action := savePrivate(t, dir, "manual.json", a)
	custody := manualCustody{"openshell.manual-detach-custody/v1", a.Origin, a.OperatorSession, a.Request.ActionID, a.Request.IntentSHA256, a.Request.Target.Resource().SHA256()}
	cp := savePrivate(t, dir, "custody.json", custody)
	argv := append([]string{"dispatch"}, args...)
	argv = append(argv, "-action-file", action, "-dispatch-custody-file", cp)
	f.lose = true
	var out bytes.Buffer
	if run(argv, &out, factory) == nil || f.dispatches.Load() != 1 || strings.Contains(out.String(), "sentinel") {
		t.Fatal("lost dispatch promoted or leaked")
	}
	a.OperatorSession = "another-session-001"
	action2 := savePrivate(t, dir, "manual2.json", a)
	custody.OperatorSession = a.OperatorSession
	cp2 := savePrivate(t, dir, "custody2.json", custody)
	token2 := filepath.Join(dir, "other-grant")
	os.WriteFile(token2, []byte("different-private-sentinel"), 0600)
	if run(append(argv, "-action-file", action2, "-dispatch-custody-file", cp2, "-detach-grant-file", token2), &bytes.Buffer{}, factory) == nil || f.dispatches.Load() != 1 {
		t.Fatal("changed file/session/token restored send")
	}
	if run(append(append([]string{"recover"}, args...), "-action-file", action2), &bytes.Buffer{}, factory) != nil || f.recovers.Load() != 1 {
		t.Fatal("recovery changed into write")
	}
}
func prepareArmArgs(a originalAction, args []string) []string {
	return append(append([]string{"prepare-arm"}, args...), "-operator-session", a.OperatorSession, "-decision-id", "99999999-9999-4999-8999-999999999999", "-challenge", strings.Repeat("a", 64), "-deadline", time.Now().Add(20*time.Second).UTC().Format(time.RFC3339Nano))
}
func TestAssemblyArmCanonicalCurrentAndUnknownOnce(t *testing.T) {
	dir, a, f, args, factory := assemblyFixture(t)
	var out bytes.Buffer
	if e := run(prepareArmArgs(a, args), &out, factory); e != nil {
		t.Fatal(e)
	}
	var prepared armOriginal
	if json.Unmarshal(out.Bytes(), &prepared) != nil || prepared.Request.Validate() != nil || prepared.Request.AttemptID != v1.ProviderDetachAttemptID(prepared.Request.Attempt) || prepared.Request.RequestSHA256 != v1.ProviderDetachAttemptSHA256(prepared.Request.Attempt) {
		t.Fatal("noncanonical arm")
	}
	if f.armQueries.Load() != 1 {
		t.Fatal("bootstrap replayed")
	}
	if run(prepareArmArgs(a, args), &bytes.Buffer{}, factory) == nil || f.armQueries.Load() != 1 {
		t.Fatal("preparation refreshed original")
	}
	armPath := filepath.Join(dir, "arm-"+a.Request.ActionID+".json")
	argv := append(append([]string{"arm"}, args...), "-arm-file", armPath)
	f.lose = true
	if run(argv, &bytes.Buffer{}, factory) == nil || f.arms.Load() != 1 {
		t.Fatal("lost Arm not held")
	}
	if run(argv, &bytes.Buffer{}, factory) == nil || f.arms.Load() != 1 {
		t.Fatal("Arm replayed")
	}
	if run(append(append([]string{"query-arm"}, args...), "-arm-file", armPath), &bytes.Buffer{}, factory) != nil || f.armQueries.Load() != 2 || f.arms.Load() != 1 {
		t.Fatal("exact query unavailable")
	}
}
func TestAssemblyCurrentSubstitutionAndDurabilityFailureZeroEffects(t *testing.T) {
	for _, mutate := range []func(*assemblyFake){func(f *assemblyFake) { f.current.Current.ACK.ExecutionID = "exec-v1:" + strings.Repeat("f", 64) }, func(f *assemblyFake) { f.current.Current.ACK.PolicyActive = false }, func(f *assemblyFake) { f.current.Current.ACK.State = "installed" }, func(f *assemblyFake) { f.current.Current.ACK.ObservedAt = time.Now().Add(-time.Minute) }} {
		t.Run("current", func(t *testing.T) {
			_, a, f, args, factory := assemblyFixture(t)
			mutate(f)
			if run(prepareArmArgs(a, args), &bytes.Buffer{}, factory) == nil || f.arms.Load() != 0 {
				t.Fatal("invalid current prepared or armed")
			}
		})
	}
	dir, a, f, args, factory := assemblyFixture(t)
	if exclusive(dir, "prepare-arm-"+a.Request.ActionID+".consumed.json", map[string]string{"state": "partial"}) != nil {
		t.Fatal("fixture")
	}
	if run(prepareArmArgs(a, args), &bytes.Buffer{}, factory) == nil || f.armQueries.Load() != 0 || f.arms.Load() != 0 {
		t.Fatal("partial preparation reopened")
	}
}
func TestAssemblyObservationPreparationNoInventedContextAndTLSSeparation(t *testing.T) {
	dir, a, f, args, factory := assemblyFixture(t)
	observer := filepath.Join(dir, "observer-grant")
	os.WriteFile(observer, []byte("private-observer-sentinel"), 0600)
	argv := append(append([]string{"prepare-observation"}, args...), "-grant-file", observer, "-operator-session", a.OperatorSession, "-run-id", "99999999-9999-4999-8999-999999999999", "-step-id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "-phase", "baseline", "-deadline", time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	called := 0
	wrapped := func(c v1.ProviderDetachmentConfig) (observationClient, error) {
		called++
		if c.TLS.CertFile != "fixture-client-cert" || c.TLS.KeyFile != "fixture-client-key" {
			t.Fatal("mTLS not propagated")
		}
		return factory(c)
	}
	var out bytes.Buffer
	if e := run(append(argv, "-client-cert", "fixture-client-cert", "-client-key", "fixture-client-key"), &out, wrapped); e != nil {
		t.Fatal(e)
	}
	var q v1.OrdinaryObservationRequest
	if json.Unmarshal(out.Bytes(), &q) != nil || q.Validate() != nil || q.SourceIncarnation != f.metadata.SourceIncarnation || q.BoundaryIncarnation != f.metadata.BoundaryIncarnation || q.InstalledArm != nil || q.BaselineMediationPathReceiptSHA256 != "" {
		t.Fatal("discovery context invented/mixed")
	}
	if run(argv, &bytes.Buffer{}, factory) == nil {
		t.Fatal("same preparation rediscovered")
	}
	bad := append([]string(nil), argv...)
	bad = append(bad, "-client-cert", "unpaired")
	before := called
	if run(bad, &bytes.Buffer{}, wrapped) == nil || called != before {
		t.Fatal("unpaired mTLS reached client")
	}
	if strings.Contains(out.String(), "private-observer-sentinel") || strings.Contains(out.String(), "private-detach-sentinel") {
		t.Fatal("grant leaked")
	}
}

func TestAssemblyDetachedObservationRetainsOriginalSealAndSeparateGrants(t *testing.T) {
	for _, defect := range []string{"none", "same-grant", "missing-seal", "different-original", "old-current", "different-boot"} {
		t.Run(defect, func(t *testing.T) {
			dir, a, f, args, factory := assemblyFixture(t)
			var prepared bytes.Buffer
			if err := run(prepareArmArgs(a, args), &prepared, factory); err != nil {
				t.Fatal(err)
			}
			var arm armOriginal
			if json.Unmarshal(prepared.Bytes(), &arm) != nil {
				t.Fatal("arm fixture")
			}
			f.current.Seal = &v1.ProviderDetachArmSeal{Request: arm.Request, HoldGeneration: 1, RowResourceVersion: 5, InstallSequence: 7, InstalledAt: time.Now().UTC()}
			observer := filepath.Join(dir, "observe-grant")
			os.WriteFile(observer, []byte("distinct-observer-grant"), 0600)
			switch defect {
			case "same-grant":
				os.WriteFile(observer, []byte("private-detach-sentinel"), 0600)
			case "missing-seal":
				f.current.Seal = nil
			case "different-original":
				f.current.Seal.Request.Attempt.Challenge = strings.Repeat("b", 64)
			case "old-current":
				f.current.Current.ACK.Sequence = 6
			case "different-boot":
				f.current.Current.GatewayBootID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			}
			argv := append(append([]string{"prepare-observation"}, args...), "-grant-file", observer, "-operator-session", a.OperatorSession, "-run-id", "99999999-9999-4999-8999-999999999999", "-step-id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "-phase", "detached", "-baseline-receipt-sha256", strings.Repeat("b", 64), "-arm-file", filepath.Join(dir, "arm-"+a.Request.ActionID+".json"), "-deadline", time.Now().Add(10*time.Second).UTC().Format(time.RFC3339Nano))
			var out bytes.Buffer
			err := run(argv, &out, factory)
			if defect == "none" {
				var q v1.OrdinaryObservationRequest
				if err != nil || json.Unmarshal(out.Bytes(), &q) != nil || q.Validate() != nil || q.InstalledArm == nil || !reflect.DeepEqual(q.InstalledArm.Request, arm.Request) {
					t.Fatalf("original detached preparation: %v", err)
				}
			} else if err == nil || out.Len() != 0 {
				t.Fatal("invalid original/current/grant accepted")
			}
			if f.arms.Load() != 0 || f.dispatches.Load() != 0 || f.begins.Load() != 0 {
				t.Fatal("preparation performed an effect")
			}
			before := f.armQueries.Load()
			if run(argv, &bytes.Buffer{}, factory) == nil || f.armQueries.Load() != before {
				t.Fatal("preparation replayed after success or refusal")
			}
		})
	}
}

func TestAssemblyConcurrentArmAndPartialDispatchRemainConsumed(t *testing.T) {
	dir, a, f, args, factory := assemblyFixture(t)
	if run(prepareArmArgs(a, args), &bytes.Buffer{}, factory) != nil {
		t.Fatal("prepare")
	}
	argv := append(append([]string{"arm"}, args...), "-arm-file", filepath.Join(dir, "arm-"+a.Request.ActionID+".json"))
	f.lose = true
	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() { _ = run(argv, &bytes.Buffer{}, factory); done <- struct{}{} }()
	}
	<-done
	<-done
	if f.arms.Load() != 1 {
		t.Fatal("concurrent Arm had more than one send")
	}
	a.Origin = "admitted-manual-original"
	a.Journal = journalIdentity{}
	path := savePrivate(t, dir, "manual-partial.json", a)
	custody := savePrivate(t, dir, "manual-custody.json", manualCustody{"openshell.manual-detach-custody/v1", a.Origin, a.OperatorSession, a.Request.ActionID, a.Request.IntentSHA256, a.Request.Target.Resource().SHA256()})
	if exclusive(dir, "dispatch-"+a.Request.ActionID+".consumed.json", map[string]string{"state": "partial"}) != nil {
		t.Fatal("partial fixture")
	}
	if run(append(append([]string{"dispatch"}, args...), "-action-file", path, "-dispatch-custody-file", custody), &bytes.Buffer{}, factory) == nil || f.dispatches.Load() != 0 {
		t.Fatal("partial durable record restored dispatch")
	}
}
