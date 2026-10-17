// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	gproto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ProviderDetachVersion is the closed optional exact-provider metadata contract.
// These are SDK domain values; native protobufs remain inside transport adapters.
const ProviderDetachVersion = 1

// ProviderDetachResource binds a narrow grant before reading mutable RV/config.
// Its native transport digest is separate from the Controller intent domains.
type ProviderDetachResource struct {
	Authority   string `json:"authority"`
	Workspace   string `json:"workspace"`
	Sandbox     string `json:"sandbox"`
	SandboxID   string `json:"sandbox_id"`
	ExecutionID string `json:"execution_id"`
	Provider    string `json:"provider"`
	ProviderID  string `json:"provider_id"`
}

func (t ProviderDetachTarget) Resource() ProviderDetachResource {
	return ProviderDetachResource{t.Authority, t.Workspace, t.Sandbox, t.SandboxID, t.ExecutionID, t.Provider, t.ProviderID}
}

// SHA256 is the issuer-bound immutable resource scope, not execution authority.
func (r ProviderDetachResource) SHA256() string {
	return detachProjection("openshell.provider-detach.resource/v1", r)
}

type ProviderDetachSourceTarget struct {
	GatewayID     string `json:"gatewayID"`
	Workspace     string `json:"workspace"`
	Sandbox       string `json:"sandbox"`
	SandboxID     string `json:"sandboxID"`
	ExecutionID   string `json:"executionID"`
	RuntimeHandle string `json:"runtimeHandle,omitempty"`
}

type ProviderDetachTarget struct {
	Authority                string `json:"authority" toml:"authority"`
	Workspace                string `json:"workspace" toml:"workspace"`
	Sandbox                  string `json:"sandbox" toml:"sandbox"`
	SandboxID                string `json:"sandbox_id" toml:"sandbox_id"`
	ExecutionID              string `json:"execution_id" toml:"execution_id"`
	SandboxResourceVersion   uint64 `json:"sandbox_resource_version,string" toml:"sandbox_resource_version"`
	Provider                 string `json:"provider" toml:"provider"`
	ProviderID               string `json:"provider_id" toml:"provider_id"`
	ProviderResourceVersion  uint64 `json:"provider_resource_version,string" toml:"provider_resource_version"`
	AttachmentEpoch          string `json:"attachment_epoch" toml:"attachment_epoch"`
	ConfigurationFingerprint string `json:"configuration_fingerprint" toml:"configuration_fingerprint"`
	ConfigurationInstance    string `json:"configuration_instance" toml:"configuration_instance"`
	ConfigRevision           uint64 `json:"config_revision,string" toml:"config_revision"`
	ProviderEnvRevision      uint64 `json:"provider_env_revision,string" toml:"provider_env_revision"`
	NativePolicyHash         string `json:"native_policy_hash" toml:"native_policy_hash"`
	NativePolicyVersion      uint32 `json:"native_policy_version" toml:"native_policy_version"`
}

type ProviderDetachIntent struct {
	SchemaVersion   int                  `json:"schema_version"`
	ProfileID       string               `json:"profile_id"`
	ViolationSHA256 string               `json:"violation_sha256"`
	Target          ProviderDetachTarget `json:"target"`
	TargetSHA256    string               `json:"target_sha256"`
}

type ProviderDetachOriginalIntent struct {
	SchemaVersion  int                        `json:"schema_version"`
	Target         ProviderDetachSourceTarget `json:"target"`
	EventID        string                     `json:"event_id"`
	PolicyRevision string                     `json:"policy_revision"`
	PolicyHash     string                     `json:"policy_hash"`
	RuleID         string                     `json:"rule_id"`
	Detach         *ProviderDetachIntent      `json:"detach"`
}

type ProviderDetachRequest struct {
	SchemaVersion  int                          `json:"schema_version"`
	ActionID       string                       `json:"action_id"`
	ProfileID      string                       `json:"profile_id"`
	EventID        string                       `json:"event_id"`
	IntentSHA256   string                       `json:"intent_sha256"`
	Target         ProviderDetachTarget         `json:"target"`
	TargetSHA256   string                       `json:"target_sha256"`
	OriginalIntent ProviderDetachOriginalIntent `json:"original_intent"`
}

var detachTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_.:/-]+$`)
var detachHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var detachExecutionPattern = regexp.MustCompile(`^exec-v1:[0-9a-f]{64}$`)

func detachProjection(domain string, value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(append([]byte(domain+"\n"), data...))
	return hex.EncodeToString(sum[:])
}

func (t ProviderDetachTarget) SHA256() string {
	return detachProjection("openshield.provider-detach.target/v1", struct {
		SchemaVersion int                  `json:"schema_version"`
		Target        ProviderDetachTarget `json:"target"`
	}{ProviderDetachVersion, t})
}

func (i ProviderDetachOriginalIntent) SHA256() string {
	return detachProjection("openshield.provider-detach.intent/v1", i)
}

func detachActionID(digest string) string {
	bytes, err := hex.DecodeString(digest)
	if err != nil || len(bytes) != 32 {
		return ""
	}
	id := append([]byte(nil), bytes[:16]...)
	id[6] = (id[6] & 0x0f) | 0x50
	id[8] = (id[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:16])
}

// Validate binds the complete original intent, never granting policy or execution
// authority. GatewayID is an independent original alias, not native Authority.
func (q ProviderDetachRequest) Validate() error {
	bad := func() error {
		return &StatusError{Code: ErrorInvalidArgument, Message: "provider detach original intent invalid"}
	}
	i := q.OriginalIntent
	if q.SchemaVersion != 1 || i.SchemaVersion != 1 || i.Detach == nil || i.Detach.SchemaVersion != 1 {
		return bad()
	}
	d := i.Detach
	t := q.Target
	token := func(s string) bool { return len(s) > 0 && len(s) <= 253 && detachTokenPattern.MatchString(s) }
	bounded := func(s string) bool { return len(s) > 0 && len(s) <= 253 }
	for _, s := range []string{t.Authority, t.Workspace, t.Sandbox, t.SandboxID, t.Provider, t.ProviderID, t.AttachmentEpoch, t.ConfigurationInstance, d.ProfileID} {
		if !token(s) {
			return bad()
		}
	}
	if !bounded(i.Target.GatewayID) || !bounded(i.EventID) || !bounded(i.PolicyRevision) || !bounded(i.RuleID) || i.Target.RuntimeHandle != "" ||
		!detachHashPattern.MatchString(i.PolicyHash) || !detachHashPattern.MatchString(d.ViolationSHA256) ||
		!detachExecutionPattern.MatchString(t.ExecutionID) || !detachHashPattern.MatchString(t.NativePolicyHash) ||
		t.SandboxResourceVersion == 0 || t.ProviderResourceVersion == 0 || t.ConfigRevision == 0 || t.ProviderEnvRevision == 0 || t.NativePolicyVersion == 0 || len(t.ConfigurationFingerprint) == 0 || len(t.ConfigurationFingerprint) > 1024 || !utf8.ValidString(t.ConfigurationFingerprint) ||
		i.Target.Workspace != t.Workspace || i.Target.Sandbox != t.Sandbox || i.Target.SandboxID != t.SandboxID || i.Target.ExecutionID != t.ExecutionID ||
		q.ProfileID != d.ProfileID || q.EventID != i.EventID || t != d.Target || q.TargetSHA256 != d.TargetSHA256 || q.TargetSHA256 != t.SHA256() || q.IntentSHA256 != i.SHA256() || q.ActionID != detachActionID(q.IntentSHA256) {
		return bad()
	}
	return nil
}

type ProviderDetachReceipt struct {
	ActionID              string               `json:"action_id"`
	IntentSHA256          string               `json:"intent_sha256"`
	TargetSHA256          string               `json:"target_sha256"`
	Target                ProviderDetachTarget `json:"target"`
	BeforeAttachmentEpoch string               `json:"before_attachment_epoch"`
	AfterAttachmentEpoch  string               `json:"after_attachment_epoch"`
	NativeReceiptID       string               `json:"native_receipt_id"`
	HoldID                string               `json:"hold_id"`
	ConfigRevision        uint64               `json:"config_revision,string"`
	ProviderEnvRevision   uint64               `json:"provider_env_revision,string"`
	ConfigurationInstance string               `json:"configuration_instance"`
	NativePolicyHash      string               `json:"native_policy_hash"`
	NativePolicyVersion   uint32               `json:"native_policy_version"`
	RecordedAt            time.Time            `json:"recorded_at"`
}

type ProviderDetachOutcome struct {
	// Only applied, rejected_no_effect, and unknown are valid. Missing is unknown,
	// not authority to dispatch again. A rejection must come from the native ledger.
	State   string                 `json:"state"`
	Receipt *ProviderDetachReceipt `json:"receipt,omitempty"`
}

// ProviderDetachmentConfig constructs a dedicated scoped client. Auth must be an
// explicitly supplied narrow grant; no ordinary Client credentials are inherited.
// The gateway independently verifies issuer, expiry, method and exact resource.
type ProviderDetachmentConfig struct {
	Address  string
	TLS      *TLSConfig
	Auth     AuthProvider
	Resource ProviderDetachResource
	Timeout  time.Duration
}

type ProviderDetachmentClient struct {
	rpc       pb.OpenShellClient
	conn      *grpc.ClientConn
	resource  ProviderDetachResource
	timeout   time.Duration
	closeOnce sync.Once
	closeErr  error
}

func (t ProviderDetachTarget) Validate() error {
	bad := func() error {
		return &StatusError{Code: ErrorInvalidArgument, Message: "provider detach target invalid"}
	}
	if t.Resource().Validate() != nil {
		return bad()
	}
	for _, v := range []string{t.AttachmentEpoch, t.ConfigurationInstance} {
		if len(v) == 0 || len(v) > 253 || !detachTokenPattern.MatchString(v) {
			return bad()
		}
	}
	if t.SandboxResourceVersion == 0 || t.ProviderResourceVersion == 0 || t.ConfigRevision == 0 || t.ProviderEnvRevision == 0 || t.NativePolicyVersion == 0 || !detachHashPattern.MatchString(t.NativePolicyHash) || len(t.ConfigurationFingerprint) == 0 || len(t.ConfigurationFingerprint) > 1024 || !utf8.ValidString(t.ConfigurationFingerprint) {
		return bad()
	}
	return nil
}

func (r ProviderDetachResource) Validate() error {
	for _, v := range []string{r.Authority, r.Workspace, r.Sandbox, r.SandboxID, r.Provider, r.ProviderID} {
		if len(v) == 0 || len(v) > 253 || !detachTokenPattern.MatchString(v) {
			return &StatusError{Code: ErrorInvalidArgument, Message: "provider detach resource invalid"}
		}
	}
	if !detachExecutionPattern.MatchString(r.ExecutionID) {
		return &StatusError{Code: ErrorInvalidArgument, Message: "provider detach execution invalid"}
	}
	return nil
}

func NewProviderDetachmentClient(cfg ProviderDetachmentConfig) (*ProviderDetachmentClient, error) {
	invalid := func() error {
		return &StatusError{Code: ErrorInvalidArgument, Message: "explicit secure scoped provider transport required"}
	}
	if cfg.Resource.Validate() != nil || cfg.Auth == nil || (reflect.ValueOf(cfg.Auth).Kind() == reflect.Ptr && reflect.ValueOf(cfg.Auth).IsNil()) || !cfg.Auth.RequireTransportSecurity() || cfg.TLS == nil || cfg.TLS.Insecure || cfg.TLS.CAFile == "" || strings.HasPrefix(cfg.Address, "http://") {
		return nil, invalid()
	}
	address := strings.TrimPrefix(cfg.Address, "https://")
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" || strings.ContainsAny(address, "/ ?#@\r\n") {
		return nil, invalid()
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Timeout < 0 || cfg.Timeout > 30*time.Second {
		return nil, invalid()
	}
	ca, err := os.ReadFile(cfg.TLS.CAFile)
	if err != nil {
		return nil, invalid()
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, invalid()
	}
	transport := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: host}
	if cfg.TLS.CertFile != "" || cfg.TLS.KeyFile != "" {
		if cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
			return nil, invalid()
		}
		certificate, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, invalid()
		}
		transport.Certificates = []tls.Certificate{certificate}
	}
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(transport)), grpc.WithPerRPCCredentials(cfg.Auth), grpc.WithDisableRetry(), grpc.WithDisableServiceConfig())
	if err != nil {
		return nil, invalid()
	}
	return &ProviderDetachmentClient{rpc: pb.NewOpenShellClient(conn), conn: conn, resource: cfg.Resource, timeout: cfg.Timeout}, nil
}

func (c *ProviderDetachmentClient) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		if c.conn != nil {
			c.closeErr = c.conn.Close()
		}
	})
	return c.closeErr
}

func (c *ProviderDetachmentClient) bound(ctx context.Context, q *ProviderDetachRequest) (context.Context, context.CancelFunc, error) {
	if c == nil || c.rpc == nil || ctx == nil || c.resource.Validate() != nil {
		return nil, nil, &StatusError{Code: ErrorInvalidArgument, Message: "provider detach client unavailable"}
	}
	if q != nil && (q.Validate() != nil || q.Target.Resource() != c.resource) {
		return nil, nil, &StatusError{Code: ErrorPermissionDenied, Message: "provider detach request outside client resource"}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, c.timeout)
	return bounded, cancel, nil
}

func detachTargetToProto(q ProviderDetachTarget) *pb.ProviderDetachTargetV1 {
	return &pb.ProviderDetachTargetV1{Authority: q.Authority, Workspace: q.Workspace, Sandbox: q.Sandbox, SandboxId: q.SandboxID, ExecutionId: q.ExecutionID, SandboxResourceVersion: q.SandboxResourceVersion, Provider: q.Provider, ProviderId: q.ProviderID, ProviderResourceVersion: q.ProviderResourceVersion, AttachmentEpoch: q.AttachmentEpoch, ConfigurationFingerprint: q.ConfigurationFingerprint, ConfigurationInstance: q.ConfigurationInstance, ConfigRevision: q.ConfigRevision, ProviderEnvRevision: q.ProviderEnvRevision, NativePolicyHash: q.NativePolicyHash, NativePolicyVersion: q.NativePolicyVersion}
}
func detachSourceToProto(q ProviderDetachSourceTarget) *pb.ProviderDetachSourceTargetV1 {
	return &pb.ProviderDetachSourceTargetV1{GatewayId: q.GatewayID, Workspace: q.Workspace, Sandbox: q.Sandbox, SandboxId: q.SandboxID, ExecutionId: q.ExecutionID, RuntimeHandle: q.RuntimeHandle}
}
func detachIntentToProto(q ProviderDetachIntent) *pb.ProviderDetachIntentV1 {
	return &pb.ProviderDetachIntentV1{SchemaVersion: uint32(q.SchemaVersion), ProfileId: q.ProfileID, ViolationSha256: q.ViolationSHA256, TargetSha256: q.TargetSHA256, Target: detachTargetToProto(q.Target)}
}
func detachOriginalToProto(q ProviderDetachOriginalIntent) *pb.ProviderDetachOriginalIntentV1 {
	return &pb.ProviderDetachOriginalIntentV1{SchemaVersion: uint32(q.SchemaVersion), EventId: q.EventID, PolicyRevision: q.PolicyRevision, PolicyHash: q.PolicyHash, RuleId: q.RuleID, Target: detachSourceToProto(q.Target), Detach: detachIntentToProto(*q.Detach)}
}
func detachActionToProto(q ProviderDetachRequest) *pb.ProviderDetachActionV1 {
	return &pb.ProviderDetachActionV1{SchemaVersion: uint32(q.SchemaVersion), ActionId: q.ActionID, ProfileId: q.ProfileID, EventId: q.EventID, IntentSha256: q.IntentSHA256, TargetSha256: q.TargetSHA256, Target: detachTargetToProto(q.Target), OriginalIntent: detachOriginalToProto(q.OriginalIntent)}
}
func detachResourceToProto(q ProviderDetachResource) *pb.ProviderDetachResourceV1 {
	return &pb.ProviderDetachResourceV1{Authority: q.Authority, Workspace: q.Workspace, Sandbox: q.Sandbox, SandboxId: q.SandboxID, ExecutionId: q.ExecutionID, Provider: q.Provider, ProviderId: q.ProviderID}
}
func detachTargetFromProto(q *pb.ProviderDetachTargetV1) ProviderDetachTarget {
	if q == nil {
		return ProviderDetachTarget{}
	}
	return ProviderDetachTarget{Authority: q.Authority, Workspace: q.Workspace, Sandbox: q.Sandbox, SandboxID: q.SandboxId, ExecutionID: q.ExecutionId, SandboxResourceVersion: q.SandboxResourceVersion, Provider: q.Provider, ProviderID: q.ProviderId, ProviderResourceVersion: q.ProviderResourceVersion, AttachmentEpoch: q.AttachmentEpoch, ConfigurationFingerprint: q.ConfigurationFingerprint, ConfigurationInstance: q.ConfigurationInstance, ConfigRevision: q.ConfigRevision, ProviderEnvRevision: q.ProviderEnvRevision, NativePolicyHash: q.NativePolicyHash, NativePolicyVersion: q.NativePolicyVersion}
}

func detachNativeError() error {
	return &StatusError{Code: ErrorInternal, Message: "provider detach native response invalid"}
}

func detachOutcomeFromProto(q *pb.ProviderDetachOutcomeV1, original ProviderDetachRequest) (ProviderDetachOutcome, error) {
	unknown := ProviderDetachOutcome{State: "unknown"}
	if q == nil {
		return unknown, detachNativeError()
	}
	if q.State == "unknown" || q.State == "rejected_no_effect" {
		if q.Receipt != nil {
			return unknown, detachNativeError()
		}
		return ProviderDetachOutcome{State: q.State}, nil
	}
	r := q.Receipt
	if q.State != "applied" || r == nil || r.RecordedTime == nil || r.RecordedTime.CheckValid() != nil {
		return unknown, detachNativeError()
	}
	receipt := ProviderDetachReceipt{ActionID: r.ActionId, IntentSHA256: r.IntentSha256, TargetSHA256: r.TargetSha256, BeforeAttachmentEpoch: r.BeforeAttachmentEpoch, AfterAttachmentEpoch: r.AfterAttachmentEpoch, NativeReceiptID: r.NativeReceiptId, HoldID: r.HoldId, ConfigRevision: r.ConfigRevision, ProviderEnvRevision: r.ProviderEnvRevision, ConfigurationInstance: r.ConfigurationInstance, NativePolicyHash: r.NativePolicyHash, NativePolicyVersion: r.NativePolicyVersion, Target: detachTargetFromProto(r.Target), RecordedAt: r.RecordedTime.AsTime()}
	if receipt.ActionID != original.ActionID || receipt.IntentSHA256 != original.IntentSHA256 || receipt.TargetSHA256 != original.TargetSHA256 || receipt.Target != original.Target || receipt.BeforeAttachmentEpoch != original.Target.AttachmentEpoch || receipt.AfterAttachmentEpoch == "" || receipt.AfterAttachmentEpoch == receipt.BeforeAttachmentEpoch || receipt.NativeReceiptID == "" || receipt.HoldID == "" || receipt.ConfigRevision == 0 || receipt.ProviderEnvRevision == 0 || receipt.ConfigurationInstance == "" || receipt.NativePolicyVersion == 0 || !detachHashPattern.MatchString(receipt.NativePolicyHash) || receipt.RecordedAt.IsZero() {
		return unknown, detachNativeError()
	}
	return ProviderDetachOutcome{State: "applied", Receipt: &receipt}, nil
}

func (c *ProviderDetachmentClient) Resolve(ctx context.Context) (ProviderDetachTarget, error) {
	bounded, cancel, err := c.bound(ctx, nil)
	if err != nil {
		return ProviderDetachTarget{}, err
	}
	defer cancel()
	reply, err := c.rpc.GetConditionalProviderDetachState(bounded, &pb.GetConditionalProviderDetachStateRequest{WorkspaceScope: namedWorkspaceScope(c.resource.Workspace), Query: &pb.GetConditionalProviderDetachStateRequest_Resolve{Resolve: &pb.ResolveProviderDetachV1{Resource: detachResourceToProto(c.resource)}}})
	if err != nil {
		return ProviderDetachTarget{}, converter.FromGRPCError(err)
	}
	if reply == nil || reply.GetTarget() == nil {
		return ProviderDetachTarget{}, detachNativeError()
	}
	target := detachTargetFromProto(reply.GetTarget())
	if target.Validate() != nil || target.Resource() != c.resource || target.SandboxResourceVersion == 0 || target.ProviderResourceVersion == 0 || target.ConfigRevision == 0 || target.ProviderEnvRevision == 0 || target.NativePolicyVersion == 0 || !detachHashPattern.MatchString(target.NativePolicyHash) || target.AttachmentEpoch == "" || target.ConfigurationFingerprint == "" || target.ConfigurationInstance == "" {
		return ProviderDetachTarget{}, detachNativeError()
	}
	return target, nil
}

// Dispatch makes one unary mutation call with transport retries disabled. Any
// transport failure is UNKNOWN; callers must use Recover, never reissue Dispatch.
func (c *ProviderDetachmentClient) Dispatch(ctx context.Context, q ProviderDetachRequest) (ProviderDetachOutcome, error) {
	bounded, cancel, err := c.bound(ctx, &q)
	if err != nil {
		return ProviderDetachOutcome{State: "unknown"}, err
	}
	defer cancel()
	reply, err := c.rpc.ConditionalDetachSandboxProvider(bounded, &pb.ConditionalDetachSandboxProviderRequest{WorkspaceScope: namedWorkspaceScope(c.resource.Workspace), Action: detachActionToProto(q)})
	if err != nil {
		return ProviderDetachOutcome{State: "unknown"}, converter.FromGRPCError(err)
	}
	if reply == nil {
		return ProviderDetachOutcome{State: "unknown"}, detachNativeError()
	}
	return detachOutcomeFromProto(reply.Outcome, q)
}

// Recover exclusively queries the original action; it performs no mutation or
// receipt-less provider status call, and never falls back to a name-only detach.
func (c *ProviderDetachmentClient) Recover(ctx context.Context, q ProviderDetachRequest) (ProviderDetachOutcome, error) {
	bounded, cancel, err := c.bound(ctx, &q)
	if err != nil {
		return ProviderDetachOutcome{State: "unknown"}, err
	}
	defer cancel()
	reply, err := c.rpc.GetConditionalProviderDetachState(bounded, &pb.GetConditionalProviderDetachStateRequest{WorkspaceScope: namedWorkspaceScope(c.resource.Workspace), Query: &pb.GetConditionalProviderDetachStateRequest_Recover{Recover: &pb.RecoverProviderDetachV1{Action: detachActionToProto(q)}}})
	if err != nil {
		return ProviderDetachOutcome{State: "unknown"}, converter.FromGRPCError(err)
	}
	if reply == nil {
		return ProviderDetachOutcome{State: "unknown"}, detachNativeError()
	}
	return detachOutcomeFromProto(reply.GetOutcome(), q)
}

// Optional attempt domain contract; transport wiring is implemented separately.
type ProviderDetachACK struct {
	ActionID                      string    `json:"action_id"`
	TargetSHA256                  string    `json:"target_sha256"`
	NativeReceiptID               string    `json:"native_receipt_id"`
	HoldID                        string    `json:"hold_id"`
	SandboxID                     string    `json:"sandbox_id"`
	ExecutionID                   string    `json:"execution_id"`
	ProviderID                    string    `json:"provider_id"`
	AttachmentEpoch               string    `json:"attachment_epoch"`
	ConfigurationInstance         string    `json:"configuration_instance"`
	ConfigRevision                uint64    `json:"config_revision,string"`
	ProviderEnvRevision           uint64    `json:"provider_env_revision,string"`
	NativePolicyHash              string    `json:"native_policy_hash"`
	NativePolicyVersion           uint32    `json:"native_policy_version"`
	SupervisorInstance            string    `json:"supervisor_instance"`
	SupervisorSession             string    `json:"supervisor_session"`
	Sequence                      uint64    `json:"sequence,string"`
	State                         string    `json:"state"`
	CredentialsInstalled          bool      `json:"credentials_installed"`
	PolicyActive                  bool      `json:"policy_active"`
	LaunchEnvironmentAcknowledged bool      `json:"launch_environment_acknowledged"`
	EvaluatedAt                   time.Time `json:"evaluated_at"`
	ObservedAt                    time.Time `json:"observed_at"`
}

// Refusal is separate from an ACK or traffic-denied call. Unsupported association
// stays nil. It must originate at the current installed resolver, not endpoint history.
type ProviderDetachRefusal struct {
	ActionID              string    `json:"action_id"`
	TargetSHA256          string    `json:"target_sha256"`
	AttemptID             string    `json:"attempt_id"`
	Challenge             string    `json:"challenge"`
	SupervisorInstance    string    `json:"supervisor_instance"`
	SupervisorSession     string    `json:"supervisor_session"`
	Sequence              uint64    `json:"sequence,string"`
	AttachmentEpoch       string    `json:"attachment_epoch"`
	ConfigurationInstance string    `json:"configuration_instance"`
	ConfigRevision        uint64    `json:"config_revision,string"`
	ProviderEnvRevision   uint64    `json:"provider_env_revision,string"`
	Unavailable           bool      `json:"unavailable"`
	AttemptedAt           time.Time `json:"attempted_at"`
	ObservedAt            time.Time `json:"observed_at"`
}

type ProviderDetachObservation struct {
	ACK     *ProviderDetachACK     `json:"ack,omitempty"`
	Refusal *ProviderDetachRefusal `json:"refusal,omitempty"`
}

type ProviderDetachAttemptTime struct {
	Seconds int64 `json:"seconds,string"`
	Nanos   int32 `json:"nanos"`
}

func (t ProviderDetachAttemptTime) Time() time.Time {
	return time.Unix(t.Seconds, int64(t.Nanos)).UTC()
}

type ProviderDetachAttempt struct {
	SchemaVersion         int                       `json:"schema_version"`
	DispatcherDecisionID  string                    `json:"dispatcher_decision_id"`
	ActionID              string                    `json:"action_id"`
	IntentSHA256          string                    `json:"intent_sha256"`
	TargetSHA256          string                    `json:"target_sha256"`
	NativeReceiptID       string                    `json:"native_receipt_id"`
	HoldID                string                    `json:"hold_id"`
	Authority             string                    `json:"authority"`
	GatewayBootID         string                    `json:"gateway_boot_id"`
	Workspace             string                    `json:"workspace"`
	SandboxID             string                    `json:"sandbox_id"`
	ExecutionID           string                    `json:"execution_id"`
	ProviderID            string                    `json:"provider_id"`
	AttachmentEpoch       string                    `json:"attachment_epoch"`
	ConfigurationInstance string                    `json:"configuration_instance"`
	ConfigRevision        uint64                    `json:"config_revision,string"`
	ProviderEnvRevision   uint64                    `json:"provider_env_revision,string"`
	NativePolicyHash      string                    `json:"native_policy_hash"`
	NativePolicyVersion   uint32                    `json:"native_policy_version"`
	SupervisorInstance    string                    `json:"supervisor_instance"`
	SupervisorSession     string                    `json:"supervisor_session"`
	ArmCaptureSequence    uint64                    `json:"arm_capture_sequence,string"`
	Challenge             string                    `json:"challenge"`
	NotBefore             ProviderDetachAttemptTime `json:"not_before"`
	Deadline              ProviderDetachAttemptTime `json:"deadline"`
}

func ProviderDetachAttemptSHA256(a ProviderDetachAttempt) string {
	return detachProjection("openshell.provider-detach.attempt/v1", a)
}
func ProviderDetachAttemptID(a ProviderDetachAttempt) string {
	raw, _ := hex.DecodeString(ProviderDetachAttemptSHA256(a))
	id := append([]byte(nil), raw[:16]...)
	id[6], id[8] = (id[6]&0x0f)|0x50, (id[8]&0x3f)|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}

type ProviderDetachArmRequest struct {
	OriginalAction  ProviderDetachRequest `json:"original_action"`
	OriginalReceipt ProviderDetachReceipt `json:"original_receipt"`
	Attempt         ProviderDetachAttempt `json:"attempt"`
	AttemptID       string                `json:"attempt_id"`
	RequestSHA256   string                `json:"request_sha256"`
}

type ProviderDetachArmState string

const (
	ProviderDetachPendingDelivery ProviderDetachArmState = "pending_delivery"
	ProviderDetachArmed           ProviderDetachArmState = "armed"
	ProviderDetachConsuming       ProviderDetachArmState = "consuming"
	ProviderDetachTerminal        ProviderDetachArmState = "terminal"
	ProviderDetachExpired         ProviderDetachArmState = "expired"
	ProviderDetachUnknown         ProviderDetachArmState = "unknown_or_unsupported"
)

type ProviderDetachAttemptResult string

const (
	ProviderDetachRefused          ProviderDetachAttemptResult = "refused"
	ProviderDetachNotRefused       ProviderDetachAttemptResult = "not_refused"
	ProviderDetachProofUnsupported ProviderDetachAttemptResult = "unsupported"
	ProviderDetachInvalidated      ProviderDetachAttemptResult = "invalidated"
)

// Seal is server-owned provenance, not configuration resourceVersion. Only an
// authenticated supervisor installation ACK can populate InstallSequence/At.
type ProviderDetachArmSeal struct {
	Request            ProviderDetachArmRequest `json:"request"`
	HoldGeneration     uint64                   `json:"hold_generation,string"`
	RowResourceVersion uint64                   `json:"row_resource_version,string"`
	InstallSequence    uint64                   `json:"install_sequence,string"`
	InstalledAt        time.Time                `json:"installed_at"`
}
type ProviderDetachAttemptCurrent struct {
	GatewayBootID      string            `json:"gateway_boot_id"`
	HoldGeneration     uint64            `json:"hold_generation,string"`
	RowResourceVersion uint64            `json:"row_resource_version,string"`
	ACK                ProviderDetachACK `json:"ack"`
}
type ProviderDetachAttemptReadback struct {
	State   ProviderDetachArmState        `json:"state"`
	Seal    *ProviderDetachArmSeal        `json:"seal,omitempty"`
	Result  ProviderDetachAttemptResult   `json:"result,omitempty"`
	Proof   *ProviderDetachObservation    `json:"proof,omitempty"`
	Current *ProviderDetachAttemptCurrent `json:"current,omitempty"`
}

// Validate prevents time.Unix normalization from admitting a malformed native
// timestamp. Call before Time when checking any attempt deadline or boundary.
func (t ProviderDetachAttemptTime) Validate() error {
	if t.Seconds < -62135596800 || t.Seconds > 253402300799 || t.Nanos < 0 || t.Nanos >= 1000000000 {
		return &StatusError{Code: ErrorInvalidArgument, Message: "provider detach attempt timestamp invalid"}
	}
	return nil
}

var detachUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func detachValidUUID(s string) bool {
	return detachUUIDPattern.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}

// Validate binds attempt metadata to the complete original action and native
// historical receipt. It grants no authority; current time, boot/session, hold
// and protected dispatcher checks remain native admission requirements.
func (q ProviderDetachArmRequest) Validate() error {
	invalid := func() error {
		return &StatusError{Code: ErrorInvalidArgument, Message: "provider detach arm binding invalid"}
	}
	if q.OriginalAction.Validate() != nil {
		return invalid()
	}
	a, r, t := q.Attempt, q.OriginalReceipt, q.OriginalAction.Target
	if a.SchemaVersion != 1 || a.NotBefore.Validate() != nil || a.Deadline.Validate() != nil ||
		!a.Deadline.Time().After(a.NotBefore.Time()) || a.Deadline.Time().Sub(a.NotBefore.Time()) > 30*time.Second ||
		r.RecordedAt.IsZero() || r.RecordedAt.After(a.NotBefore.Time()) {
		return invalid()
	}
	for _, id := range []string{a.DispatcherDecisionID, a.GatewayBootID, a.SupervisorInstance, a.SupervisorSession, a.NativeReceiptID, a.HoldID} {
		if !detachValidUUID(id) {
			return invalid()
		}
	}
	if !detachHashPattern.MatchString(a.Challenge) || a.ArmCaptureSequence == 0 ||
		q.RequestSHA256 != ProviderDetachAttemptSHA256(a) || q.AttemptID != ProviderDetachAttemptID(a) ||
		a.ActionID != q.OriginalAction.ActionID || a.IntentSHA256 != q.OriginalAction.IntentSHA256 || a.TargetSHA256 != q.OriginalAction.TargetSHA256 ||
		r.ActionID != a.ActionID || r.IntentSHA256 != a.IntentSHA256 || r.TargetSHA256 != a.TargetSHA256 || r.Target != t ||
		r.BeforeAttachmentEpoch != t.AttachmentEpoch || r.AfterAttachmentEpoch == "" || r.AfterAttachmentEpoch == r.BeforeAttachmentEpoch ||
		a.NativeReceiptID != r.NativeReceiptID || a.HoldID != r.HoldID ||
		a.Authority != t.Authority || a.Workspace != t.Workspace || a.SandboxID != t.SandboxID || a.ExecutionID != t.ExecutionID || a.ProviderID != t.ProviderID ||
		a.AttachmentEpoch != r.AfterAttachmentEpoch || a.ConfigurationInstance != r.ConfigurationInstance || a.ConfigurationInstance == "" ||
		a.ConfigRevision != r.ConfigRevision || a.ConfigRevision == 0 || a.ProviderEnvRevision != r.ProviderEnvRevision || a.ProviderEnvRevision == 0 ||
		a.NativePolicyHash != r.NativePolicyHash || !detachHashPattern.MatchString(a.NativePolicyHash) || a.NativePolicyVersion != r.NativePolicyVersion || a.NativePolicyVersion == 0 {
		return invalid()
	}
	for _, value := range []string{a.AttachmentEpoch, a.ConfigurationInstance} {
		if len(value) > 253 || !detachTokenPattern.MatchString(value) {
			return invalid()
		}
	}
	data, err := json.Marshal(q)
	if err != nil || len(data) > 8192 {
		return invalid()
	}
	return nil
}

func detachReceiptToProto(r ProviderDetachReceipt) *pb.ProviderDetachReceiptV1 {
	return &pb.ProviderDetachReceiptV1{ActionId: r.ActionID, IntentSha256: r.IntentSHA256, TargetSha256: r.TargetSHA256, Target: detachTargetToProto(r.Target), BeforeAttachmentEpoch: r.BeforeAttachmentEpoch, AfterAttachmentEpoch: r.AfterAttachmentEpoch, NativeReceiptId: r.NativeReceiptID, HoldId: r.HoldID, ConfigRevision: r.ConfigRevision, ProviderEnvRevision: r.ProviderEnvRevision, ConfigurationInstance: r.ConfigurationInstance, NativePolicyHash: r.NativePolicyHash, NativePolicyVersion: r.NativePolicyVersion, RecordedTime: timestamppb.New(r.RecordedAt)}
}
func detachAttemptToProto(a ProviderDetachAttempt) *pb.ProviderDetachAttemptV1 {
	if a == (ProviderDetachAttempt{}) {
		return nil
	}
	return &pb.ProviderDetachAttemptV1{SchemaVersion: uint32(a.SchemaVersion), DispatcherDecisionId: a.DispatcherDecisionID, ActionId: a.ActionID, IntentSha256: a.IntentSHA256, TargetSha256: a.TargetSHA256, NativeReceiptId: a.NativeReceiptID, HoldId: a.HoldID, Authority: a.Authority, GatewayBootId: a.GatewayBootID, Workspace: a.Workspace, SandboxId: a.SandboxID, ExecutionId: a.ExecutionID, ProviderId: a.ProviderID, AttachmentEpoch: a.AttachmentEpoch, ConfigurationInstance: a.ConfigurationInstance, ConfigRevision: a.ConfigRevision, ProviderEnvRevision: a.ProviderEnvRevision, NativePolicyHash: a.NativePolicyHash, NativePolicyVersion: a.NativePolicyVersion, SupervisorInstance: a.SupervisorInstance, SupervisorSession: a.SupervisorSession, ArmCaptureSequence: a.ArmCaptureSequence, Challenge: a.Challenge, NotBefore: &timestamppb.Timestamp{Seconds: a.NotBefore.Seconds, Nanos: a.NotBefore.Nanos}, Deadline: &timestamppb.Timestamp{Seconds: a.Deadline.Seconds, Nanos: a.Deadline.Nanos}}
}
func detachArmToProto(q ProviderDetachArmRequest) *pb.ProviderDetachArmRequestV1 {
	return &pb.ProviderDetachArmRequestV1{OriginalAction: detachActionToProto(q.OriginalAction), OriginalReceipt: detachReceiptToProto(q.OriginalReceipt), Attempt: detachAttemptToProto(q.Attempt), AttemptId: q.AttemptID, RequestSha256: q.RequestSHA256}
}
func detachBootstrap(q ProviderDetachArmRequest) bool {
	return q.Attempt == (ProviderDetachAttempt{}) && q.AttemptID == "" && q.RequestSHA256 == ""
}
func (q ProviderDetachArmRequest) validateQuery() error {
	if !detachBootstrap(q) {
		return q.Validate()
	}
	if q.OriginalAction.Validate() != nil {
		return detachNativeError()
	}
	_, err := detachOutcomeFromProto(&pb.ProviderDetachOutcomeV1{State: "applied", Receipt: detachReceiptToProto(q.OriginalReceipt)}, q.OriginalAction)
	if err != nil || !detachValidUUID(q.OriginalReceipt.HoldID) || !detachValidUUID(q.OriginalReceipt.NativeReceiptID) {
		return detachNativeError()
	}
	return nil
}
func detachNativeTime(t *timestamppb.Timestamp) (time.Time, error) {
	if t == nil || t.CheckValid() != nil {
		return time.Time{}, detachNativeError()
	}
	return t.AsTime(), nil
}
func detachACKFromProto(p *pb.ProviderDetachACKV1, q ProviderDetachArmRequest, now time.Time) (*ProviderDetachACK, error) {
	if p == nil {
		return nil, detachNativeError()
	}
	observed, e1 := detachNativeTime(p.ObservedTime)
	evaluated, e2 := detachNativeTime(p.EvaluatedTime)
	r, t := q.OriginalReceipt, q.OriginalAction.Target
	if e1 != nil || e2 != nil || observed.Before(r.RecordedAt) || evaluated.Before(observed) || evaluated.After(now) || now.Sub(observed) >= 30*time.Second ||
		p.ActionId != q.OriginalAction.ActionID || p.TargetSha256 != q.OriginalAction.TargetSHA256 || p.NativeReceiptId != r.NativeReceiptID || p.HoldId != r.HoldID ||
		p.SandboxId != t.SandboxID || p.ExecutionId != t.ExecutionID || p.ProviderId != t.ProviderID || p.AttachmentEpoch != r.AfterAttachmentEpoch || p.ConfigurationInstance != r.ConfigurationInstance ||
		p.ConfigRevision != r.ConfigRevision || p.ProviderEnvRevision != r.ProviderEnvRevision || p.NativePolicyHash != r.NativePolicyHash || p.NativePolicyVersion != r.NativePolicyVersion ||
		p.State != "REVOKED" || !p.CredentialsInstalled || !p.PolicyActive || !p.LaunchEnvironmentAcknowledged || p.Sequence == 0 ||
		!detachValidUUID(p.SupervisorInstance) || !detachValidUUID(p.SupervisorSession) {
		return nil, detachNativeError()
	}
	if !detachBootstrap(q) && (p.SupervisorInstance != q.Attempt.SupervisorInstance || p.SupervisorSession != q.Attempt.SupervisorSession || p.Sequence < q.Attempt.ArmCaptureSequence) {
		return nil, detachNativeError()
	}
	return &ProviderDetachACK{ActionID: p.ActionId, TargetSHA256: p.TargetSha256, NativeReceiptID: p.NativeReceiptId, HoldID: p.HoldId, SandboxID: p.SandboxId, ExecutionID: p.ExecutionId, ProviderID: p.ProviderId, AttachmentEpoch: p.AttachmentEpoch, ConfigurationInstance: p.ConfigurationInstance, ConfigRevision: p.ConfigRevision, ProviderEnvRevision: p.ProviderEnvRevision, NativePolicyHash: p.NativePolicyHash, NativePolicyVersion: p.NativePolicyVersion, SupervisorInstance: p.SupervisorInstance, SupervisorSession: p.SupervisorSession, Sequence: p.Sequence, State: p.State, CredentialsInstalled: p.CredentialsInstalled, PolicyActive: p.PolicyActive, LaunchEnvironmentAcknowledged: p.LaunchEnvironmentAcknowledged, ObservedAt: observed, EvaluatedAt: evaluated}, nil
}
func detachReadbackFromProto(p *pb.ProviderDetachAttemptReadbackV1, q ProviderDetachArmRequest, now time.Time) (ProviderDetachAttemptReadback, error) {
	unknown := ProviderDetachAttemptReadback{State: ProviderDetachUnknown}
	bad := func() (ProviderDetachAttemptReadback, error) { return unknown, detachNativeError() }
	if p == nil || gproto.Size(p) > 16384 || (p.Seal != nil && gproto.Size(p.Seal) > 8192) || (p.Proof != nil && gproto.Size(p.Proof) > 4096) {
		return bad()
	}
	states := map[int32]ProviderDetachArmState{1: ProviderDetachPendingDelivery, 2: ProviderDetachArmed, 3: ProviderDetachConsuming, 4: ProviderDetachTerminal, 5: ProviderDetachExpired, 6: ProviderDetachUnknown}
	state, ok := states[int32(p.State)]
	if !ok {
		return bad()
	}
	out := ProviderDetachAttemptReadback{State: state}
	if p.Current != nil {
		c := p.Current
		ack, err := detachACKFromProto(c.Ack, q, now)
		if err != nil || !detachValidUUID(c.GatewayBootId) || c.HoldGeneration == 0 || c.RowResourceVersion == 0 {
			return bad()
		}
		if !detachBootstrap(q) && c.GatewayBootId != q.Attempt.GatewayBootID {
			return bad()
		}
		out.Current = &ProviderDetachAttemptCurrent{GatewayBootID: c.GatewayBootId, HoldGeneration: c.HoldGeneration, RowResourceVersion: c.RowResourceVersion, ACK: *ack}
	}
	if state == ProviderDetachUnknown || state == ProviderDetachExpired {
		if p.Seal != nil || p.Proof != nil || p.Result != 0 || (state == ProviderDetachExpired && p.Current != nil) {
			return bad()
		}
		return out, nil
	}
	if detachBootstrap(q) || !now.Before(q.Attempt.Deadline.Time()) || now.Before(q.Attempt.NotBefore.Time()) || p.Seal == nil || out.Current == nil {
		return bad()
	}
	seal := p.Seal
	if !gproto.Equal(seal.Request, detachArmToProto(q)) || seal.HoldGeneration == 0 || seal.RowResourceVersion == 0 || seal.HoldGeneration != out.Current.HoldGeneration || seal.RowResourceVersion != out.Current.RowResourceVersion {
		return bad()
	}
	out.Seal = &ProviderDetachArmSeal{Request: q, HoldGeneration: seal.HoldGeneration, RowResourceVersion: seal.RowResourceVersion, InstallSequence: seal.InstallSequence}
	if state == ProviderDetachPendingDelivery {
		if seal.InstallSequence != 0 || seal.InstalledTime != nil || p.Proof != nil || p.Result != 0 {
			return bad()
		}
		return out, nil
	}
	installed, err := detachNativeTime(seal.InstalledTime)
	if err != nil || seal.InstallSequence <= q.Attempt.ArmCaptureSequence || out.Current.ACK.Sequence < seal.InstallSequence || installed.Before(q.Attempt.NotBefore.Time()) || installed.After(now) || !installed.Before(q.Attempt.Deadline.Time()) {
		return bad()
	}
	out.Seal.InstalledAt = installed
	if state != ProviderDetachTerminal {
		if p.Proof != nil || p.Result != 0 {
			return bad()
		}
		return out, nil
	}
	results := map[int32]ProviderDetachAttemptResult{1: ProviderDetachRefused, 2: ProviderDetachNotRefused, 3: ProviderDetachProofUnsupported, 4: ProviderDetachInvalidated}
	result, ok := results[int32(p.Result)]
	if !ok {
		return bad()
	}
	out.Result = result
	if result != ProviderDetachRefused {
		if p.Proof != nil {
			return bad()
		}
		return out, nil
	}
	if p.Proof == nil || p.Proof.Refusal == nil {
		return bad()
	}
	ack, err := detachACKFromProto(p.Proof.Ack, q, now)
	if err != nil {
		return bad()
	}
	f := p.Proof.Refusal
	attempted, e1 := detachNativeTime(f.AttemptedTime)
	observed, e2 := detachNativeTime(f.ObservedTime)
	a := q.Attempt
	if e1 != nil || e2 != nil || !f.Unavailable || f.ActionId != a.ActionID || f.TargetSha256 != a.TargetSHA256 || f.AttemptId != q.AttemptID || f.Challenge != a.Challenge ||
		f.SupervisorInstance != a.SupervisorInstance || f.SupervisorSession != a.SupervisorSession || f.Sequence <= seal.InstallSequence || f.Sequence != ack.Sequence ||
		f.AttachmentEpoch != a.AttachmentEpoch || f.ConfigurationInstance != a.ConfigurationInstance || f.ConfigRevision != a.ConfigRevision || f.ProviderEnvRevision != a.ProviderEnvRevision ||
		attempted.Before(installed) || observed.Before(attempted) || ack.ObservedAt.Before(observed) || out.Current.ACK.Sequence < ack.Sequence || out.Current.ACK.ObservedAt.Before(ack.ObservedAt) || out.Current.ACK.EvaluatedAt.Before(observed) {
		return bad()
	}
	out.Proof = &ProviderDetachObservation{ACK: ack, Refusal: &ProviderDetachRefusal{ActionID: f.ActionId, TargetSHA256: f.TargetSha256, AttemptID: f.AttemptId, Challenge: f.Challenge, SupervisorInstance: f.SupervisorInstance, SupervisorSession: f.SupervisorSession, Sequence: f.Sequence, AttachmentEpoch: f.AttachmentEpoch, ConfigurationInstance: f.ConfigurationInstance, ConfigRevision: f.ConfigRevision, ProviderEnvRevision: f.ProviderEnvRevision, Unavailable: true, AttemptedAt: attempted, ObservedAt: observed}}
	return out, nil
}

// ArmDetachAttempt sends one explicit metadata write. It never invokes an agent,
// retries an unknown operation, falls back to detach, or changes a native hold.
func (c *ProviderDetachmentClient) ArmDetachAttempt(ctx context.Context, q ProviderDetachArmRequest) (ProviderDetachAttemptReadback, error) {
	unknown := ProviderDetachAttemptReadback{State: ProviderDetachUnknown}
	if err := q.Validate(); err != nil {
		return unknown, err
	}
	bounded, cancel, err := c.bound(ctx, &q.OriginalAction)
	if err != nil {
		return unknown, err
	}
	defer cancel()
	reply, err := c.rpc.ArmProviderDetachAttempt(bounded, &pb.ArmProviderDetachAttemptRequest{WorkspaceScope: namedWorkspaceScope(c.resource.Workspace), Request: detachArmToProto(q)})
	if err != nil {
		return unknown, converter.FromGRPCError(err)
	}
	if reply == nil {
		return unknown, detachNativeError()
	}
	return detachReadbackFromProto(reply.Readback, q, time.Now())
}

// QueryDetachAttempt is read-only. Strictly zero attempt metadata bootstraps
// authenticated current fields only; it never supplies a seal, proof or authority.
func (c *ProviderDetachmentClient) QueryDetachAttempt(ctx context.Context, q ProviderDetachArmRequest) (ProviderDetachAttemptReadback, error) {
	unknown := ProviderDetachAttemptReadback{State: ProviderDetachUnknown}
	if err := q.validateQuery(); err != nil {
		return unknown, err
	}
	bounded, cancel, err := c.bound(ctx, &q.OriginalAction)
	if err != nil {
		return unknown, err
	}
	defer cancel()
	reply, err := c.rpc.GetConditionalProviderDetachState(bounded, &pb.GetConditionalProviderDetachStateRequest{WorkspaceScope: namedWorkspaceScope(c.resource.Workspace), Query: &pb.GetConditionalProviderDetachStateRequest_QueryAttempt{QueryAttempt: detachArmToProto(q)}})
	if err != nil {
		return unknown, converter.FromGRPCError(err)
	}
	if reply == nil {
		return unknown, detachNativeError()
	}
	return detachReadbackFromProto(reply.GetAttempt(), q, time.Now())
}
