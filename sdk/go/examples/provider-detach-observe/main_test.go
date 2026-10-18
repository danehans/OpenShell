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
