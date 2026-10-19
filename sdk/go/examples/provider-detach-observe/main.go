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
	"reflect"
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
	fd, e := unix.Open(name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
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
	fd, e := unix.Open(name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
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
	if len(args) > 0 && assemblyCommand(args[0]) {
		return runAssembly(args, w, factory)
	}
	f := flag.NewFlagSet("provider-detach-observe", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	address := f.String("address", "", "explicit HTTPS gateway host:port")
	ca := f.String("ca", "", "explicit trusted gateway CA file")
	grant := f.String("grant-file", "", "private narrow OIDC grant file; no environment fallback")
	cert := f.String("client-cert", "", "optional paired mTLS certificate")
	key := f.String("client-key", "", "optional paired mTLS key")
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
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || (*cert == "") != (*key == "") {
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
	client, e := factory(v1.ProviderDetachmentConfig{Address: *address, TLS: &v1.TLSConfig{CAFile: *ca, CertFile: *cert, KeyFile: *key}, Auth: v1.StaticToken(token), Resource: r, Timeout: 5 * time.Second})
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

// These operations extend the same manual tool; they never execute agent input.
type detachmentClient interface {
	Resolve(context.Context) (v1.ProviderDetachTarget, error)
	Dispatch(context.Context, v1.ProviderDetachRequest) (v1.ProviderDetachOutcome, error)
	Recover(context.Context, v1.ProviderDetachRequest) (v1.ProviderDetachOutcome, error)
	ArmDetachAttempt(context.Context, v1.ProviderDetachArmRequest) (v1.ProviderDetachAttemptReadback, error)
	QueryDetachAttempt(context.Context, v1.ProviderDetachArmRequest) (v1.ProviderDetachAttemptReadback, error)
}
type journalIdentity struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
}
type originalAction struct {
	Schema          string                   `json:"schema"`
	Origin          string                   `json:"origin"`
	OperatorSession string                   `json:"operator_session"`
	Journal         journalIdentity          `json:"journal"`
	Request         v1.ProviderDetachRequest `json:"original_request"`
}
type securityResponse struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   json.RawMessage `json:"metadata"`
	Spec       struct {
		Target         v1.ProviderDetachSourceTarget `json:"target"`
		Action         string                        `json:"action"`
		EventID        string                        `json:"eventID"`
		PolicyRevision string                        `json:"policyRevision"`
		PolicyHash     string                        `json:"policyHash"`
		RuleID         string                        `json:"ruleID"`
		EvidenceRefs   []string                      `json:"evidenceRefs,omitempty"`
		RequestID      string                        `json:"requestID"`
		ProviderDetach *v1.ProviderDetachIntent      `json:"providerDetach,omitempty"`
	} `json:"spec"`
	// The full bounded original object is retained by the operator. Status is not
	// an ownership transfer or authority, and cannot permit helper Dispatch.
	Status json.RawMessage `json:"status,omitempty"`
}
type manualCustody struct {
	Schema          string `json:"schema"`
	Origin          string `json:"origin"`
	OperatorSession string `json:"operator_session"`
	ActionID        string `json:"action_id"`
	IntentSHA256    string `json:"intent_sha256"`
	ResourceSHA256  string `json:"resource_sha256"`
}
type armOriginal struct {
	Schema          string                      `json:"schema"`
	OperatorSession string                      `json:"operator_session"`
	Action          originalAction              `json:"original_action"`
	Request         v1.ProviderDetachArmRequest `json:"original_request"`
}

func assemblyCommand(s string) bool {
	switch s {
	case "resolve", "prepare-response", "dispatch", "recover", "prepare-arm", "arm", "query-arm", "prepare-observation":
		return true
	}
	return false
}
func originalActionValid(a originalAction, resource v1.ProviderDetachResource) bool {
	if a.Schema != "openshell.manual-detach-original/v1" || !identifier(a.OperatorSession) || a.Request.Validate() != nil || a.Request.Target.Resource() != resource {
		return false
	}
	switch a.Origin {
	case "controller-securityresponse":
		return a.Journal.Name != "" && a.Journal.Namespace != "" && identifier(a.Journal.UID) && a.Journal.ResourceVersion != ""
	case "admitted-manual-original":
		return a.Journal == (journalIdentity{})
	}
	return false
}
func projectResponse(s securityResponse, resource v1.ProviderDetachResource, session string) (originalAction, error) {
	var empty originalAction
	if s.APIVersion != "security.openshield.io/v1alpha1" || s.Kind != "SecurityResponse" || s.Spec.Action != "detach_provider" || s.Spec.ProviderDetach == nil || !identifier(session) {
		return empty, refused
	}
	// Kubernetes metadata has unrelated standard fields; only these four exact
	// identity fields participate. Unknown spec fields remain rejected by privateRead.
	var fields map[string]json.RawMessage
	if json.Unmarshal(s.Metadata, &fields) != nil {
		return empty, refused
	}
	var j journalIdentity
	for key, target := range map[string]*string{"name": &j.Name, "namespace": &j.Namespace, "uid": &j.UID, "resourceVersion": &j.ResourceVersion} {
		if json.Unmarshal(fields[key], target) != nil || *target == "" {
			return empty, refused
		}
	}
	i := v1.ProviderDetachOriginalIntent{SchemaVersion: 1, Target: s.Spec.Target, EventID: s.Spec.EventID, PolicyRevision: s.Spec.PolicyRevision, PolicyHash: s.Spec.PolicyHash, RuleID: s.Spec.RuleID, Detach: s.Spec.ProviderDetach}
	q := v1.ProviderDetachRequest{SchemaVersion: 1, ActionID: s.Spec.RequestID, ProfileID: s.Spec.ProviderDetach.ProfileID, EventID: s.Spec.EventID, IntentSHA256: i.SHA256(), Target: s.Spec.ProviderDetach.Target, TargetSHA256: s.Spec.ProviderDetach.TargetSHA256, OriginalIntent: i}
	a := originalAction{"openshell.manual-detach-original/v1", "controller-securityresponse", session, j, q}
	if !originalActionValid(a, resource) {
		return empty, refused
	}
	return a, nil
}
func canonicalUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	raw := strings.ReplaceAll(s, "-", "")
	b, e := hex.DecodeString(raw)
	return e == nil && len(b) == 16 && raw == strings.ToLower(raw) && raw != strings.Repeat("0", 32)
}
func receiptMatches(q v1.ProviderDetachRequest, r v1.ProviderDetachReceipt) bool {
	return r.ActionID == q.ActionID && r.IntentSHA256 == q.IntentSHA256 && r.TargetSHA256 == q.TargetSHA256 && r.Target == q.Target && r.BeforeAttachmentEpoch == q.Target.AttachmentEpoch && r.AfterAttachmentEpoch != "" && r.AfterAttachmentEpoch != r.BeforeAttachmentEpoch && r.NativeReceiptID != "" && r.HoldID != "" && r.ConfigurationInstance != "" && r.ConfigRevision > 0 && r.ProviderEnvRevision > 0 && hash(r.NativePolicyHash) && r.NativePolicyVersion > 0 && !r.RecordedAt.IsZero()
}
func actionFileName(q v1.ProviderDetachRequest) string { return "action-" + q.ActionID + ".json" }
func readArm(name string, resource v1.ProviderDetachResource) (armOriginal, error) {
	var a armOriginal
	if privateRead(name, &a) != nil || a.Schema != "openshell.manual-arm-original/v1" || !identifier(a.OperatorSession) || a.OperatorSession != a.Action.OperatorSession || !originalActionValid(a.Action, resource) || !reflect.DeepEqual(a.Request.OriginalAction, a.Action.Request) || a.Request.Validate() != nil {
		return armOriginal{}, refused
	}
	return a, nil
}
func runAssembly(args []string, w io.Writer, factory clientFactory) error {
	f := flag.NewFlagSet("provider-detach-observe", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	address := f.String("address", "", "explicit TLS gateway host:port")
	ca := f.String("ca", "", "trusted CA")
	cert := f.String("client-cert", "", "optional paired mTLS certificate")
	key := f.String("client-key", "", "optional paired mTLS key")
	grant := f.String("grant-file", "", "private observer grant only")
	detachGrant := f.String("detach-grant-file", "", "private detach grant only")
	resourceFile := f.String("resource-file", "", "exact immutable resource")
	responseFile := f.String("response-file", "", "retained original SecurityResponse")
	actionFile := f.String("action-file", "", "protected original action")
	receiptFile := f.String("receipt-file", "", "actual original Native receipt")
	armFile := f.String("arm-file", "", "protected complete original Arm")
	custodyFile := f.String("dispatch-custody-file", "", "separately admitted manual-original custody only; not authority")
	directory := f.String("ledger-dir", "", "existing protected ledger directory")
	session := f.String("operator-session", "", "one protected operator session")
	decision := f.String("decision-id", "", "original admitted Arm decision UUID")
	challenge := f.String("challenge", "", "original admitted challenge")
	deadlineText := f.String("deadline", "", "original admitted RFC3339Nano deadline")
	runID := f.String("run-id", "", "original admitted run UUID")
	stepID := f.String("step-id", "", "original admitted step UUID")
	phase := f.String("phase", "", "baseline or detached")
	baseline := f.String("baseline-receipt-sha256", "", "actual same-original baseline mediation receipt")
	if len(args) == 0 || f.Parse(args[1:]) != nil || f.NArg() != 0 || (*cert == "") != (*key == "") {
		return refused
	}
	command := args[0]
	var resource v1.ProviderDetachResource
	if privateRead(*resourceFile, &resource) != nil || resource.Validate() != nil {
		return refused
	}
	if command == "prepare-response" {
		var response securityResponse
		if privateRead(*responseFile, &response) != nil {
			return refused
		}
		a, e := projectResponse(response, resource, *session)
		if e != nil || exclusive(*directory, actionFileName(a.Request), a) != nil {
			return refused
		}
		return output(w, a)
	}
	var action originalAction
	var arm armOriginal
	if command == "arm" || command == "query-arm" {
		var e error
		arm, e = readArm(*armFile, resource)
		if e != nil {
			return refused
		}
		action = arm.Action
	} else if command != "resolve" && command != "prepare-observation" {
		if privateRead(*actionFile, &action) != nil || !originalActionValid(action, resource) {
			return refused
		}
	}
	var receipt v1.ProviderDetachReceipt
	if command == "prepare-arm" {
		if privateRead(*receiptFile, &receipt) != nil || !receiptMatches(action.Request, receipt) {
			return refused
		}
	}
	if command == "dispatch" {
		// A journal action never becomes manual merely because status/Attempts is zero.
		if action.Origin != "admitted-manual-original" {
			return refused
		}
		var c manualCustody
		if privateRead(*custodyFile, &c) != nil || c.Schema != "openshell.manual-detach-custody/v1" || c.Origin != action.Origin || c.OperatorSession != action.OperatorSession || c.ActionID != action.Request.ActionID || c.IntentSHA256 != action.Request.IntentSHA256 || c.ResourceSHA256 != resource.SHA256() {
			return refused
		}
		// Keyed by original action, not session, token, file path or timestamp.
		if exclusive(*directory, "dispatch-"+action.Request.ActionID+".consumed.json", action) != nil {
			return refused
		}
	}
	if command == "arm" {
		now := time.Now()
		if now.Before(arm.Request.Attempt.NotBefore.Time()) || !now.Before(arm.Request.Attempt.Deadline.Time()) {
			return refused
		}
		if exclusive(*directory, "arm-"+action.Request.ActionID+".consumed.json", arm) != nil {
			return refused
		}
	}
	// Preparation also has an original consumed intent before any discovery read.
	// Unknown reads do not authorize a new challenge, deadline or preparation.
	if command == "prepare-arm" || command == "prepare-observation" {
		if !identifier(*session) {
			return refused
		}
		var deadline time.Time
		var e error
		deadline, e = time.Parse(time.RFC3339Nano, *deadlineText)
		if e != nil || !time.Now().Before(deadline) {
			return refused
		}
		name := "prepare-arm-" + action.Request.ActionID + ".consumed.json"
		value := any(struct {
			Schema, Session, Decision, Challenge string
			Deadline                             time.Time
			Action                               originalAction
		}{"openshell.manual-arm-preparation/v1", *session, *decision, *challenge, deadline, action})
		if command == "prepare-arm" {
			if *session != action.OperatorSession || !canonicalUUID(*decision) || !hash(*challenge) || time.Until(deadline) > 30*time.Second {
				return refused
			}
		} else {
			if *phase != "baseline" && *phase != "detached" {
				return refused
			}
			if !canonicalUUID(*runID) || !canonicalUUID(*stepID) {
				return refused
			}
			if *phase == "baseline" && (*armFile != "" || *baseline != "") {
				return refused
			}
			if *phase == "detached" && (!hash(*baseline) || *armFile == "") {
				return refused
			}
			name = "prepare-observation-" + *runID + "-" + *stepID + ".consumed.json"
			value = struct {
				Schema, Session, RunID, StepID, Phase, Baseline string
				Deadline                                        time.Time
				Resource                                        v1.ProviderDetachResource
			}{"openshell.manual-observation-preparation/v1", *session, *runID, *stepID, *phase, *baseline, deadline, resource}
		}
		if exclusive(*directory, name, value) != nil {
			return refused
		}
	}
	var observerToken string
	tlsConfig := &v1.TLSConfig{CAFile: *ca, CertFile: *cert, KeyFile: *key}
	makeClient := func(file string) (observationClient, error) {
		if *address == "" || *ca == "" {
			return nil, refused
		}
		t, e := tokenRead(file)
		if e != nil {
			return nil, refused
		}
		if command == "prepare-observation" && *phase == "detached" {
			if observerToken == "" {
				observerToken = t
			} else if observerToken == t {
				return nil, refused
			}
		}
		return factory(v1.ProviderDetachmentConfig{Address: *address, TLS: tlsConfig, Auth: v1.StaticToken(t), Resource: resource, Timeout: 5 * time.Second})
	}
	if command == "prepare-observation" {
		client, e := makeClient(*grant)
		if e != nil {
			return refused
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		metadata, e := client.DiscoverOrdinaryObservation(ctx)
		if e != nil || metadata.Resource != resource || metadata.ProcessWriterIdentityProven || metadata.EvidenceScope != v1.OrdinaryObservationEvidenceScope || metadata.ProfileSHA256 != v1.OrdinaryObservationProfileSHA256() {
			return refused
		}
		deadline, _ := time.Parse(time.RFC3339Nano, *deadlineText)
		q := v1.OrdinaryObservationRequest{Resource: resource, RunID: *runID, StepID: *stepID, ProfileID: v1.OrdinaryObservationProfile, ProfileSHA256: metadata.ProfileSHA256, SourceIncarnation: metadata.SourceIncarnation, BoundaryIncarnation: metadata.BoundaryIncarnation, Phase: *phase, Deadline: deadline, EvidenceScope: v1.OrdinaryObservationEvidenceScope}
		if *phase == "detached" {
			original, e := readArm(*armFile, resource)
			if e != nil || original.OperatorSession != *session {
				return refused
			}
			dc, e := makeClient(*detachGrant)
			if e != nil {
				return refused
			}
			defer dc.Close()
			detacher, ok := dc.(detachmentClient)
			if !ok {
				return refused
			}
			current, e := detacher.QueryDetachAttempt(ctx, original.Request)
			if e != nil || current.Current == nil || current.Seal == nil || !reflect.DeepEqual(current.Seal.Request, original.Request) || current.Seal.InstallSequence == 0 || current.Seal.InstalledAt.IsZero() || current.Current.ACK.Sequence < current.Seal.InstallSequence || current.Current.GatewayBootID != original.Request.Attempt.GatewayBootID || !time.Now().Before(original.Request.Attempt.Deadline.Time()) {
				return refused
			}
			q.InstalledArm = current.Seal
			q.BaselineMediationPathReceiptSHA256 = *baseline
		}
		q.RequestSHA256 = q.SHA256()
		if q.Validate() != nil || !time.Now().Before(q.Deadline) {
			return refused
		}
		// The request is not a grant or a Begin. The subsequent Begin records its own ledger.
		if exclusive(*directory, "observation-"+*runID+"-"+*stepID+".json", q) != nil {
			return refused
		}
		return output(w, q)
	}
	client, e := makeClient(*detachGrant)
	if e != nil {
		return refused
	}
	defer client.Close()
	dc, ok := client.(detachmentClient)
	if !ok {
		return refused
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	switch command {
	case "resolve":
		t, e := dc.Resolve(ctx)
		if e != nil || t.Validate() != nil || t.Resource() != resource {
			return refused
		}
		return output(w, t)
	case "dispatch":
		v, e := dc.Dispatch(ctx, action.Request)
		if e != nil {
			return refused
		}
		return output(w, v)
	case "recover":
		v, e := dc.Recover(ctx, action.Request)
		if e != nil {
			return refused
		}
		return output(w, v)
	case "prepare-arm":
		bootstrap := v1.ProviderDetachArmRequest{OriginalAction: action.Request, OriginalReceipt: receipt}
		current, e := dc.QueryDetachAttempt(ctx, bootstrap)
		if e != nil || current.Current == nil || current.Current.HoldGeneration == 0 || current.Current.RowResourceVersion == 0 {
			return refused
		}
		ack := current.Current.ACK
		now := time.Now().UTC()
		deadline, _ := time.Parse(time.RFC3339Nano, *deadlineText)
		if ack.ActionID != action.Request.ActionID || ack.TargetSHA256 != action.Request.TargetSHA256 || ack.NativeReceiptID != receipt.NativeReceiptID || ack.HoldID != receipt.HoldID || ack.SandboxID != resource.SandboxID || ack.ExecutionID != resource.ExecutionID || ack.ProviderID != resource.ProviderID || ack.AttachmentEpoch != receipt.AfterAttachmentEpoch || ack.ConfigurationInstance != receipt.ConfigurationInstance || ack.ConfigRevision != receipt.ConfigRevision || ack.ProviderEnvRevision != receipt.ProviderEnvRevision || ack.NativePolicyHash != receipt.NativePolicyHash || ack.NativePolicyVersion != receipt.NativePolicyVersion || ack.State != "REVOKED" || !ack.CredentialsInstalled || !ack.PolicyActive || !ack.LaunchEnvironmentAcknowledged || ack.Sequence == 0 || ack.ObservedAt.After(now) || now.Sub(ack.ObservedAt) > 5*time.Second || !now.Before(deadline) {
			return refused
		}
		toTime := func(t time.Time) v1.ProviderDetachAttemptTime {
			return v1.ProviderDetachAttemptTime{Seconds: t.Unix(), Nanos: int32(t.Nanosecond())}
		}
		a := v1.ProviderDetachAttempt{SchemaVersion: 1, DispatcherDecisionID: *decision, ActionID: action.Request.ActionID, IntentSHA256: action.Request.IntentSHA256, TargetSHA256: action.Request.TargetSHA256, NativeReceiptID: receipt.NativeReceiptID, HoldID: receipt.HoldID, Authority: resource.Authority, GatewayBootID: current.Current.GatewayBootID, Workspace: resource.Workspace, SandboxID: resource.SandboxID, ExecutionID: resource.ExecutionID, ProviderID: resource.ProviderID, AttachmentEpoch: receipt.AfterAttachmentEpoch, ConfigurationInstance: receipt.ConfigurationInstance, ConfigRevision: receipt.ConfigRevision, ProviderEnvRevision: receipt.ProviderEnvRevision, NativePolicyHash: receipt.NativePolicyHash, NativePolicyVersion: receipt.NativePolicyVersion, SupervisorInstance: ack.SupervisorInstance, SupervisorSession: ack.SupervisorSession, ArmCaptureSequence: ack.Sequence, Challenge: *challenge, NotBefore: toTime(now), Deadline: toTime(deadline)}
		q := v1.ProviderDetachArmRequest{OriginalAction: action.Request, OriginalReceipt: receipt, Attempt: a, AttemptID: v1.ProviderDetachAttemptID(a), RequestSHA256: v1.ProviderDetachAttemptSHA256(a)}
		if q.Validate() != nil {
			return refused
		}
		v := armOriginal{"openshell.manual-arm-original/v1", action.OperatorSession, action, q}
		if exclusive(*directory, "arm-"+action.Request.ActionID+".json", v) != nil {
			return refused
		}
		return output(w, v)
	case "arm":
		v, e := dc.ArmDetachAttempt(ctx, arm.Request)
		if e != nil {
			return refused
		}
		return output(w, v)
	case "query-arm":
		v, e := dc.QueryDetachAttempt(ctx, arm.Request)
		if e != nil {
			return refused
		}
		return output(w, v)
	}
	return refused
}
