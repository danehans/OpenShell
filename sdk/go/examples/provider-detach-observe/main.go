//go:build linux || darwin

// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0

// A deliberately manual metadata client. It never launches an agent, supplies
// task input, mints a grant, changes networking, or performs a model request.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"golang.org/x/sys/unix"
)

const maxFile = 32768

var refused = errors.New("manual observation refused or original outcome unknown; query the exact original, never repeat input")

type ledger struct {
	Schema           string                        `json:"schema"`
	OperatorSession  string                        `json:"operator_session"`
	RunProfileSHA256 string                        `json:"run_profile_sha256"`
	Request          v1.OrdinaryObservationRequest `json:"original_request"`
}
type manualInput struct {
	Schema                      string    `json:"schema"`
	OriginalRequestSHA256       string    `json:"original_request_sha256"`
	WindowSHA256                string    `json:"window_sha256"`
	RunProfileSHA256            string    `json:"run_profile_sha256"`
	OperatorSession             string    `json:"operator_session"`
	EvidenceScope               string    `json:"evidence_scope"`
	ProcessWriterIdentityProven bool      `json:"process_writer_identity_proven"`
	ConsumedAt                  time.Time `json:"consumed_at"`
}
type manualOutcome struct {
	Schema                     string      `json:"schema"`
	Input                      manualInput `json:"original_input"`
	TaskID                     string      `json:"operator_task_id"`
	Outcome                    string      `json:"operator_observed_outcome"`
	ObservedAt                 time.Time   `json:"observed_at"`
	NativeModelCompletionProof bool        `json:"native_model_completion_proof"`
}
type observationClient interface {
	DiscoverOrdinaryObservation(context.Context) (v1.OrdinaryObservationMetadata, error)
	BeginOrdinaryObservation(context.Context, v1.OrdinaryObservationRequest) (v1.OrdinaryObservationEvidence, error)
	QueryOrdinaryObservation(context.Context, v1.OrdinaryObservationRequest) (v1.OrdinaryObservationEvidence, error)
	Close() error
}
type clientFactory func(v1.ProviderDetachmentConfig) (observationClient, error)

func actualClient(c v1.ProviderDetachmentConfig) (observationClient, error) {
	return v1.NewProviderDetachmentClient(c)
}
func hash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}
func identifier(s string) bool {
	// The SDK/server validate canonical run/step/resource UUIDs. This private
	// operator correlation label is not an issuer or grant.
	return len(s) >= 16 && len(s) <= 64 && !strings.ContainsAny(s, "/\\ \t\r\n")
}
func privateRead(name string, target any) error {
	fd, e := unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return refused
	}
	f := os.NewFile(uintptr(fd), "private-metadata")
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() > maxFile {
		return refused
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) {
		return refused
	}
	b, e := io.ReadAll(io.LimitReader(f, maxFile+1))
	if e != nil || len(b) > maxFile {
		return refused
	}
	after, e := f.Stat()
	if e != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return refused
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return refused
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return refused
	}
	return nil
}
func tokenRead(name string) (string, error) {
	fd, e := unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", refused
	}
	f := os.NewFile(uintptr(fd), "private-grant")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()) {
		return "", refused
	}
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(b) == 0 || len(b) > 16384 {
		return "", refused
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return "", refused
	}
	return s, nil
}
func exclusive(dir, name string, value any) error {
	b, e := json.Marshal(value)
	if e != nil || len(b)+1 > maxFile || filepath.Base(name) != name {
		return refused
	}
	b = append(b, '\n')
	d, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return refused
	}
	defer unix.Close(d)
	var st unix.Stat_t
	if unix.Fstat(d, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return refused
	}
	fd, e := unix.Openat(d, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return refused
	}
	f := os.NewFile(uintptr(fd), "original-consumed")
	defer f.Close()
	// A partial write/fsync remains consumed/unknown, never deleted or replayed.
	n, e := f.Write(b)
	if e != nil || n != len(b) || f.Chmod(0400) != nil || f.Sync() != nil || unix.Fsync(d) != nil {
		return refused
	}
	return nil
}
func ledgerName(q v1.OrdinaryObservationRequest) string {
	h := sha256.New()
	for _, s := range []string{q.Resource.Authority, q.RunID, q.StepID} {
		fmt.Fprintf(h, "%d:%s", len(s), s)
	}
	return fmt.Sprintf("%x.original.json", h.Sum(nil))
}
func output(w io.Writer, v any) error {
	b, e := json.Marshal(v)
	if e != nil || len(b)+1 > maxFile {
		return refused
	}
	_, e = w.Write(append(b, '\n'))
	return e
}
func run(args []string, w io.Writer, factory clientFactory) error {
	f := flag.NewFlagSet("provider-detach-observe", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	address := f.String("address", "", "explicit HTTPS gateway host:port")
	ca := f.String("ca", "", "explicit trusted gateway CA file")
	grant := f.String("grant-file", "", "private narrow OIDC grant file; no environment fallback")
	resourceFile := f.String("resource-file", "", "private immutable resource metadata")
	requestFile := f.String("request-file", "", "private complete original request")
	directory := f.String("ledger-dir", "", "existing private operator ledger directory")
	originalFile := f.String("original-ledger", "", "exact retained original ledger, never reconstructed")
	session := f.String("operator-session", "", "one protected operator/session correlation")
	profile := f.String("run-profile-sha256", "", "separately approved actual run profile hash; hash alone is not approval")
	outcome := f.String("outcome", "", "manual success/error/partial/unknown")
	task := f.String("task-id", "", "operator-owned task correlation; no raw input/output")
	if len(args) == 0 {
		return refused
	}
	command := args[0]
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return refused
	}
	var l ledger
	var r v1.ProviderDetachResource
	if command == "discover" {
		if privateRead(*resourceFile, &r) != nil {
			return refused
		}
	} else if command == "begin" {
		if privateRead(*requestFile, &l.Request) != nil || l.Request.Validate() != nil || !identifier(*session) || !hash(*profile) {
			return refused
		}
		l.Schema = "openshell.manual-observation-original/v1"
		l.OperatorSession = *session
		l.RunProfileSHA256 = *profile
		r = l.Request.Resource
	} else if command == "query" || command == "consume-input" || command == "outcome" {
		if privateRead(*originalFile, &l) != nil || l.Schema != "openshell.manual-observation-original/v1" || l.Request.Validate() != nil || !identifier(l.OperatorSession) || !hash(l.RunProfileSHA256) {
			return refused
		}
		r = l.Request.Resource
	} else {
		return refused
	}
	if command == "outcome" {
		if *outcome != "success" && *outcome != "error" && *outcome != "partial" && *outcome != "unknown" {
			return refused
		}
		if !identifier(*task) {
			return refused
		}
		var consumed manualInput
		if privateRead(*originalFile+".input", &consumed) != nil || consumed.Schema != "openshell.manual-observation-input/v1" || consumed.OriginalRequestSHA256 != l.Request.RequestSHA256 || consumed.OperatorSession != l.OperatorSession || consumed.RunProfileSHA256 != l.RunProfileSHA256 || consumed.EvidenceScope != v1.OrdinaryObservationEvidenceScope || consumed.ProcessWriterIdentityProven || !hash(consumed.WindowSHA256) {
			return refused
		}
		v := manualOutcome{"openshell.manual-observation-outcome/v1", consumed, *task, *outcome, time.Now().UTC(), false}
		if exclusive(filepath.Dir(*originalFile), filepath.Base(*originalFile)+".outcome", v) != nil {
			return refused
		}
		return output(w, v)
	}
	token, e := tokenRead(*grant)
	if e != nil {
		return refused
	}
	client, e := factory(v1.ProviderDetachmentConfig{Address: *address, TLS: &v1.TLSConfig{CAFile: *ca}, Auth: v1.StaticToken(token), Resource: r, Timeout: 5 * time.Second})
	if e != nil {
		return refused
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if command == "discover" {
		v, e := client.DiscoverOrdinaryObservation(ctx)
		if e != nil {
			return refused
		}
		return output(w, v)
	}
	if command == "begin" {
		if exclusive(*directory, ledgerName(l.Request), l) != nil {
			return refused
		}
		v, e := client.BeginOrdinaryObservation(ctx, l.Request)
		if e != nil {
			return refused
		}
		return output(w, v)
	}
	v, e := client.QueryOrdinaryObservation(ctx, l.Request)
	if e != nil {
		return refused
	}
	if command == "query" {
		return output(w, v)
	}
	// This consumes the operator's manual input allowance BEFORE any input. It
	// does not supply that input, prove a model outcome or confer operation rights.
	if !v.Current || v.HistoricalOnly || v.State != "open" || !time.Now().Before(v.CaptureEnd) || len(v.Events) != 0 || !hash(v.WindowSHA256) || v.ProcessWriterIdentityProven || v.EvidenceScope != v1.OrdinaryObservationEvidenceScope {
		return refused
	}
	consumed := manualInput{"openshell.manual-observation-input/v1", l.Request.RequestSHA256, v.WindowSHA256, l.RunProfileSHA256, l.OperatorSession, v1.OrdinaryObservationEvidenceScope, false, time.Now().UTC()}
	if exclusive(filepath.Dir(*originalFile), filepath.Base(*originalFile)+".input", consumed) != nil {
		return refused
	}
	return output(w, consumed)
}
func main() {
	if run(os.Args[1:], os.Stdout, actualClient) != nil {
		fmt.Fprintln(os.Stderr, refused.Error())
		os.Exit(1)
	}
}
