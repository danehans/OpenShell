// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
package v1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	proto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

const LegacyOrdinaryObservationProfile = "ordinary-sandbox-mediation-static-bearer-v1"
const OrdinaryObservationProfile = "ordinary-sandbox-mediation-static-bearer-v2"
const ordinaryMaxResult = 16384
const ordinaryMaxResultV2 = 32780
const OrdinaryObservationEvidenceScope = "original-sandbox-mediation-path/v1"

func ordinaryProfileSHA256(profile string) string {
	var descriptor string
	switch profile {
	case LegacyOrdinaryObservationProfile:
		descriptor = "openshell.provider-detach.sandbox-mediation-profile/v1\nordinary-sandbox-mediation-static-bearer-v1\nevidence_scope:original-sandbox-mediation-path/v1\nprocess_writer_identity:unproven\nhttp1:static-authorization-bearer\nstream:true,false,unobserved\nwindow:60s\nevents:8\nevent:512\nresult:16384\ncurrent:original-channel-read-v1\nassociation:retained-original-stream-allocation-v1\n"
	case OrdinaryObservationProfile:
		descriptor = "openshell.provider-detach.sandbox-mediation-profile/v2\nordinary-sandbox-mediation-static-bearer-v2\nevidence_scope:original-sandbox-mediation-path/v1\nprocess_writer_identity:unproven\nhttp1:static-authorization-bearer\nstream:true,false,unobserved\nwindow:60s\nevents:8\nevent:512\nrequest:12291\nread:12293\nreply:12294\nresult:32780\narm:8192\nstripped:request4096,read4096,reply4096,result16384\ncurrent:original-channel-read-v1\nassociation:retained-original-stream-allocation-v1\n"
	default:
		return ""
	}
	h := sha256.Sum256([]byte(descriptor))
	return hex.EncodeToString(h[:])
}
func OrdinaryObservationProfileSHA256() string {
	return ordinaryProfileSHA256(OrdinaryObservationProfile)
}
func ordinaryProfileOK(profile, hash string) bool {
	h := ordinaryProfileSHA256(profile)
	return h != "" && h == hash
}

// Size projections never alter a borrowed message, wire bytes or canonical hash.
func ordinaryStripRead(q *pb.ProviderObservationCurrentReadV1) {
	if q != nil && q.Selector != nil && q.Selector.OriginalRequest != nil {
		q.Selector.OriginalRequest.InstalledArm = nil
	}
}
func ordinaryRequestFits(q *pb.ProviderObservationRequestV1) bool {
	if q == nil || !ordinaryProfileOK(q.ProfileId, q.ProfileSha256) {
		return false
	}
	if q.ProfileId == LegacyOrdinaryObservationProfile {
		return proto.Size(q) <= 4096
	}
	if proto.Size(q) > 12291 || (q.InstalledArm != nil && proto.Size(q.InstalledArm) > 8192) {
		return false
	}
	c := proto.Clone(q).(*pb.ProviderObservationRequestV1)
	c.InstalledArm = nil
	return proto.Size(c) <= 4096
}
func ordinaryQueryFits(q *pb.GetProviderDetachObservationRequest) bool {
	if q == nil {
		return false
	}
	if q.OriginalRequest == nil {
		return proto.Size(q) <= 8192
	}
	if !ordinaryRequestFits(q.OriginalRequest) {
		return false
	}
	if q.OriginalRequest.ProfileId == LegacyOrdinaryObservationProfile {
		return proto.Size(q) <= 8192
	}
	if proto.Size(q) > 12293 {
		return false
	}
	c := proto.Clone(q).(*pb.GetProviderDetachObservationRequest)
	c.OriginalRequest.InstalledArm = nil
	return proto.Size(c) <= 8192
}
func ordinaryReadFits(q *pb.ProviderObservationCurrentReadV1) bool {
	if q == nil || proto.Size(q) > 12293 || q.ExpectedIdentity == nil || !ordinaryQueryFits(q.Selector) {
		return false
	}
	s := q.ExpectedIdentity
	if !ordinaryProfileOK(s.ProfileId, s.ProfileSha256) {
		return false
	}
	if q.Selector != nil && q.Selector.OriginalRequest != nil {
		r := q.Selector.OriginalRequest
		if r.ProfileId != s.ProfileId || r.ProfileSha256 != s.ProfileSha256 || !ordinaryRequestFits(r) {
			return false
		}
	}
	if s.ProfileId == LegacyOrdinaryObservationProfile {
		return proto.Size(q) <= 4096
	}
	if proto.Size(q) > 12293 {
		return false
	}
	c := proto.Clone(q).(*pb.ProviderObservationCurrentReadV1)
	ordinaryStripRead(c)
	return proto.Size(c) <= 4096
}
func ordinaryReplyFits(q *pb.ProviderObservationCurrentReplyV1) bool {
	if q == nil || proto.Size(q) > 12294 || !ordinaryReadFits(q.OriginalRead) || q.SampledSnapshot == nil {
		return false
	}
	s := q.OriginalRead.ExpectedIdentity
	if q.SampledSnapshot.ProfileId != s.ProfileId || q.SampledSnapshot.ProfileSha256 != s.ProfileSha256 {
		return false
	}
	if s.ProfileId == LegacyOrdinaryObservationProfile {
		return proto.Size(q) <= 4096
	}
	if proto.Size(q) > 12294 {
		return false
	}
	c := proto.Clone(q).(*pb.ProviderObservationCurrentReplyV1)
	ordinaryStripRead(c.OriginalRead)
	return proto.Size(c) <= 4096
}
func ordinaryResultFits(q *pb.ProviderObservationResultV1) bool {
	if q == nil || proto.Size(q) > ordinaryMaxResultV2 {
		return false
	}
	if q.Window == nil || q.Window.Request == nil {
		return proto.Size(q) <= ordinaryMaxResult
	}
	r := q.Window.Request
	if !ordinaryRequestFits(r) || (q.CurrentRead != nil && !ordinaryReplyFits(q.CurrentRead)) {
		return false
	}
	if r.ProfileId == LegacyOrdinaryObservationProfile {
		return proto.Size(q) <= ordinaryMaxResult
	}
	if proto.Size(q) > ordinaryMaxResultV2 {
		return false
	}
	c := proto.Clone(q).(*pb.ProviderObservationResultV1)
	c.Window.Request.InstalledArm = nil
	if c.CurrentRead != nil {
		ordinaryStripRead(c.CurrentRead.OriginalRead)
	}
	return proto.Size(c) <= ordinaryMaxResult
}

// OrdinaryObservationRequest authorizes metadata observation only, never input.
type OrdinaryObservationRequest struct {
	Resource                           ProviderDetachResource `json:"resource"`
	RunID                              string                 `json:"run_id"`
	StepID                             string                 `json:"step_id"`
	ProfileID                          string                 `json:"profile_id"`
	ProfileSHA256                      string                 `json:"profile_sha256"`
	SourceIncarnation                  string                 `json:"source_incarnation"`
	BoundaryIncarnation                string                 `json:"boundary_incarnation"`
	Deadline                           time.Time              `json:"deadline"`
	Phase                              string                 `json:"phase"`
	InstalledArm                       *ProviderDetachArmSeal `json:"installed_arm,omitempty"`
	BaselineMediationPathReceiptSHA256 string                 `json:"baseline_mediation_path_receipt_sha256,omitempty"`
	RequestSHA256                      string                 `json:"request_sha256"`
	EvidenceScope                      string                 `json:"evidence_scope"`
}

func (q OrdinaryObservationRequest) native() *pb.ProviderObservationRequestV1 {
	phase := pb.ProviderObservationPhaseV1_PROVIDER_OBSERVATION_PHASE_V1_UNSPECIFIED
	if q.Phase == "baseline" {
		phase = pb.ProviderObservationPhaseV1_PROVIDER_OBSERVATION_PHASE_V1_BASELINE
	}
	if q.Phase == "detached" {
		phase = pb.ProviderObservationPhaseV1_PROVIDER_OBSERVATION_PHASE_V1_DETACHED
	}
	n := &pb.ProviderObservationRequestV1{Resource: detachResourceToProto(q.Resource), RunId: q.RunID, StepId: q.StepID, ProfileId: q.ProfileID, ProfileSha256: q.ProfileSHA256, SourceIncarnation: q.SourceIncarnation, BoundaryIncarnation: q.BoundaryIncarnation, Deadline: timestamppb.New(q.Deadline), Phase: phase, BaselineMediationPathReceiptSha256: q.BaselineMediationPathReceiptSHA256, RequestSha256: q.RequestSHA256, EvidenceScope: q.EvidenceScope}
	if s := q.InstalledArm; s != nil && s.Request.validateQuery() == nil {
		n.InstalledArm = &pb.ProviderDetachArmSealV1{Request: detachArmToProto(s.Request), HoldGeneration: s.HoldGeneration, RowResourceVersion: s.RowResourceVersion, InstallSequence: s.InstallSequence, InstalledTime: timestamppb.New(s.InstalledAt)}
	}
	return n
}

// Canonical projections contain only recursively known fields. Go's default
// deterministic marshal retains unknown fields; prost discards them on decode.
func ordinaryKnown(m protoreflect.Message) {
	m.SetUnknown(nil)
	m.Range(func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if f.IsMap() {
			if f.MapValue().Message() != nil {
				v.Map().Range(func(_ protoreflect.MapKey, v protoreflect.Value) bool { ordinaryKnown(v.Message()); return true })
			}
		}
		if f.IsList() {
			if f.Message() != nil {
				for i := 0; i < v.List().Len(); i++ {
					ordinaryKnown(v.List().Get(i).Message())
				}
			}
		} else if !f.IsMap() && f.Message() != nil {
			ordinaryKnown(v.Message())
		}
		return true
	})
}
func ordinaryDigest(domain string, m proto.Message) string {
	c := proto.Clone(m)
	ordinaryKnown(c.ProtoReflect())
	b, err := (proto.MarshalOptions{Deterministic: true}).Marshal(c)
	if err != nil {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(domain + "\n"))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
func (q OrdinaryObservationRequest) SHA256() string {
	n := q.native()
	n.RequestSha256 = ""
	return ordinaryDigest("openshell.provider-detach.sandbox-mediation-request/v1", n)
}
func (q OrdinaryObservationRequest) Validate() error {
	if q.Resource.Validate() != nil || !detachValidUUID(q.RunID) || !detachValidUUID(q.StepID) || !detachValidUUID(q.SourceIncarnation) || !detachValidUUID(q.BoundaryIncarnation) || q.EvidenceScope != OrdinaryObservationEvidenceScope || !ordinaryProfileOK(q.ProfileID, q.ProfileSHA256) || q.RequestSHA256 != q.SHA256() || q.Deadline.IsZero() || q.native().Deadline.CheckValid() != nil || !ordinaryRequestFits(q.native()) {
		return detachNativeError()
	}
	if q.Phase == "baseline" {
		if q.InstalledArm != nil || q.BaselineMediationPathReceiptSHA256 != "" {
			return detachNativeError()
		}
	} else if q.Phase == "detached" {
		if q.InstalledArm == nil || q.InstalledArm.Request.Validate() != nil || q.InstalledArm.InstallSequence == 0 || !detachHashPattern.MatchString(q.BaselineMediationPathReceiptSHA256) {
			return detachNativeError()
		}
	} else {
		return detachNativeError()
	}
	return nil
}

type OrdinaryObservationMetadata struct {
	Resource                    ProviderDetachResource `json:"resource"`
	SourceIncarnation           string                 `json:"source_incarnation"`
	BoundaryIncarnation         string                 `json:"boundary_incarnation"`
	GatewayBootID               string                 `json:"gateway_boot_id"`
	SupervisorInstance          string                 `json:"supervisor_instance"`
	SupervisorSession           string                 `json:"supervisor_session"`
	ProfileSHA256               string                 `json:"profile_sha256"`
	ConfigurationSHA256         string                 `json:"configuration_sha256"`
	MediationPathReceiptSHA256  string                 `json:"mediation_path_receipt_sha256"`
	IngressSequence             uint64                 `json:"ingress_sequence,string"`
	EvidenceScope               string                 `json:"evidence_scope"`
	MediationPathID             string                 `json:"mediation_path_id"`
	ProcessWriterIdentityProven bool                   `json:"process_writer_identity_proven"`
}

func ordinaryPathSHA256(n *pb.ProviderObservationSnapshotV1) string {
	c := proto.Clone(n).(*pb.ProviderObservationSnapshotV1)
	c.MediationPathReceiptSha256 = ""
	c.ConfigurationSha256 = ""
	c.PolicyGeneration = 0
	c.ResolverGeneration = 0
	c.CurrentIngressSequence = 0
	return ordinaryDigest("openshell.provider-detach.sandbox-mediation-path/v1", c)
}

func ordinaryMetadata(n *pb.ProviderObservationSnapshotV1, r ProviderDetachResource) (OrdinaryObservationMetadata, error) {
	empty := OrdinaryObservationMetadata{}
	if n == nil || n.EvidenceScope != OrdinaryObservationEvidenceScope || n.ProcessWriterAttribution != pb.ProviderObservationProcessWriterAttributionV1_PROVIDER_OBSERVATION_PROCESS_WRITER_ATTRIBUTION_V1_PROCESS_WRITER_UNPROVEN || !detachValidUUID(n.MediationPathId) || n.MediationPathReceiptSha256 != ordinaryPathSHA256(n) || !proto.Equal(n.Resource, detachResourceToProto(r)) || !ordinaryProfileOK(n.ProfileId, n.ProfileSha256) || !detachValidUUID(n.SourceIncarnation) || !detachValidUUID(n.BoundaryIncarnation) || !detachValidUUID(n.GatewayBootId) || !detachValidUUID(n.SupervisorSession) || n.SupervisorInstance == "" || !detachHashPattern.MatchString(n.MediationPathReceiptSha256) || !detachHashPattern.MatchString(n.ConfigurationSha256) {
		return empty, detachNativeError()
	}
	return OrdinaryObservationMetadata{r, n.SourceIncarnation, n.BoundaryIncarnation, n.GatewayBootId, n.SupervisorInstance, n.SupervisorSession, n.ProfileSha256, n.ConfigurationSha256, n.MediationPathReceiptSha256, n.CurrentIngressSequence, n.EvidenceScope, n.MediationPathId, false}, nil
}

type OrdinaryObservationEvent struct {
	Sequence                 uint64 `json:"sequence,string"`
	RequestID                string `json:"request_id,omitempty"`
	ResponseID               string `json:"response_id,omitempty"`
	ConnectionID             string `json:"connection_id"`
	AttemptKind              string `json:"attempt_kind"`
	StreamClass              string `json:"stream_class"`
	ResponseOrigin           string `json:"response_origin"`
	HTTPFraming              string `json:"http_framing"`
	ClientSocketWrite        string `json:"client_socket_write"`
	Rewrite                  string `json:"rewrite"`
	UpstreamApplicationBytes uint64 `json:"upstream_application_bytes,string"`
}
type OrdinaryObservationEvidence struct {
	CaptureEnd                  time.Time                  `json:"capture_end,omitempty"`
	IngressWatermark            uint64                     `json:"ingress_watermark,string"`
	EvidenceScope               string                     `json:"evidence_scope"`
	ProcessWriterIdentityProven bool                       `json:"process_writer_identity_proven"`
	State                       string                     `json:"state"`
	HistoricalOnly              bool                       `json:"historical_only"`
	Current                     bool                       `json:"current"`
	CredentialRefusal           bool                       `json:"credential_refusal"`
	WindowSHA256                string                     `json:"window_sha256,omitempty"`
	TerminalSHA256              string                     `json:"terminal_sha256,omitempty"`
	MediationPathReceiptSHA256  string                     `json:"mediation_path_receipt_sha256,omitempty"`
	Events                      []OrdinaryObservationEvent `json:"events,omitempty"`
	// This type intentionally has NO agent/model completion assertion.
}

func ordinarySame(a, b *pb.ProviderObservationSnapshotV1) bool {
	if a == nil || b == nil {
		return false
	}
	x := proto.Clone(a).(*pb.ProviderObservationSnapshotV1)
	y := proto.Clone(b).(*pb.ProviderObservationSnapshotV1)
	x.CurrentIngressSequence = 0
	y.CurrentIngressSequence = 0
	ordinaryKnown(x.ProtoReflect())
	ordinaryKnown(y.ProtoReflect())
	return proto.Equal(x, y)
}
func ordinaryRead(n *pb.ProviderObservationCurrentReplyV1, selector *pb.GetProviderDetachObservationRequest, expected *pb.ProviderObservationSnapshotV1, window, terminal string, now time.Time) error {
	if !ordinaryReplyFits(n) || n.OriginalRead == nil || n.SampledSnapshot == nil || n.SampledTime == nil || n.SampledTime.CheckValid() != nil {
		return detachNativeError()
	}
	q := n.OriginalRead
	if q.Selector == nil || !proto.Equal(q.Selector, selector) || q.ExpectedIdentity == nil || q.ReadDeadline == nil || q.ReadDeadline.CheckValid() != nil || !now.Before(q.ReadDeadline.AsTime()) || q.ReadDeadline.AsTime().Sub(now) > 2*time.Second || len(q.ReadCorrelation) != 16 || q.WindowSha256 != window || q.TerminalSha256 != terminal || n.SampledTime.AsTime().After(now) || n.SampledTime.AsTime().After(q.ReadDeadline.AsTime()) || n.AccountingFault || n.ActiveAttempts != 0 {
		return detachNativeError()
	}
	a := proto.Clone(q.ExpectedIdentity).(*pb.ProviderObservationSnapshotV1)
	b := proto.Clone(n.SampledSnapshot).(*pb.ProviderObservationSnapshotV1)
	if selector.OriginalRequest == nil && selector.Resource != nil {
		a.ConfigurationSha256 = ""
		b.ConfigurationSha256 = ""
		a.PolicyGeneration = 0
		b.PolicyGeneration = 0
		a.ResolverGeneration = 0
		b.ResolverGeneration = 0
	}
	if !ordinarySame(a, b) || n.SampledSnapshot.CurrentIngressSequence < q.ExpectedIdentity.CurrentIngressSequence {
		return detachNativeError()
	}
	if expected != nil && (!ordinarySame(q.ExpectedIdentity, expected) || !ordinarySame(n.SampledSnapshot, expected)) {
		return detachNativeError()
	}
	return nil
}
func ordinaryResult(n *pb.ProviderObservationResultV1, q OrdinaryObservationRequest, now time.Time) (OrdinaryObservationEvidence, error) {
	out := OrdinaryObservationEvidence{HistoricalOnly: true, EvidenceScope: OrdinaryObservationEvidenceScope, ProcessWriterIdentityProven: false}
	if !ordinaryResultFits(n) {
		return out, detachNativeError()
	}
	switch n.State {
	case pb.ProviderObservationStateV1_PROVIDER_OBSERVATION_STATE_V1_PENDING_INSTALL:
		out.State = "pending_install"
	case pb.ProviderObservationStateV1_PROVIDER_OBSERVATION_STATE_V1_OPEN:
		out.State = "open"
	case pb.ProviderObservationStateV1_PROVIDER_OBSERVATION_STATE_V1_TERMINAL:
		out.State = "terminal"
	case pb.ProviderObservationStateV1_PROVIDER_OBSERVATION_STATE_V1_UNKNOWN:
		out.State = "unknown"
	case pb.ProviderObservationStateV1_PROVIDER_OBSERVATION_STATE_V1_EXPIRED:
		out.State = "expired"
	default:
		return out, detachNativeError()
	}
	if n.Window == nil {
		if out.State == "pending_install" && n.CurrentRead == nil && n.TerminalSha256 == "" {
			return out, nil
		}
		return out, detachNativeError()
	}
	w := n.Window
	if w != nil && w.CaptureEnd != nil {
		out.CaptureEnd = w.CaptureEnd.AsTime()
		out.IngressWatermark = w.IngressWatermark
	}
	if w.Request == nil || !proto.Equal(w.Request, q.native()) || w.InstalledSnapshot == nil || w.InstalledSnapshot.ProfileId != q.ProfileID || w.InstalledSnapshot.ProfileSha256 != q.ProfileSHA256 || w.InstalledTime == nil || w.CaptureEnd == nil || w.CaptureEnd.CheckValid() != nil || w.InstalledTime.CheckValid() != nil || w.InstallSequence == 0 || !detachValidUUID(w.WindowId) || w.CaptureEnd.AsTime().After(q.Deadline.Add(-5*time.Second)) || !w.CaptureEnd.AsTime().After(w.InstalledTime.AsTime()) || w.CaptureEnd.AsTime().Sub(w.InstalledTime.AsTime()) > 60*time.Second {
		return out, detachNativeError()
	}
	copyWindow := proto.Clone(w).(*pb.ProviderObservationWindowV1)
	copyWindow.WindowSha256 = ""
	if w.WindowSha256 != ordinaryDigest("openshell.provider-detach.sandbox-mediation-window/v1", copyWindow) {
		return out, detachNativeError()
	}
	meta, err := ordinaryMetadata(w.InstalledSnapshot, q.Resource)
	if err != nil || meta.SourceIncarnation != q.SourceIncarnation || meta.BoundaryIncarnation != q.BoundaryIncarnation {
		return out, detachNativeError()
	}
	out.MediationPathReceiptSHA256 = meta.MediationPathReceiptSHA256
	out.WindowSHA256 = w.WindowSha256
	out.TerminalSHA256 = n.TerminalSha256
	if len(n.Events) > 8 {
		return out, detachNativeError()
	}
	last := w.IngressWatermark
	allRefused := true
	requests := 0
	for _, e := range n.Events {
		if e == nil || proto.Size(e) > 512 || e.IngressSequence <= last || e.NativeConnectionId == "" || e.MediationStreamReceiptSha256 == "" || e.CapturedTime == nil || e.ClosedTime == nil || e.CapturedTime.CheckValid() != nil || e.ClosedTime.CheckValid() != nil || e.ClosedTime.AsTime().Before(e.CapturedTime.AsTime()) || e.ClosedTime.AsTime().After(w.CaptureEnd.AsTime()) {
			return out, detachNativeError()
		}
		last = e.IngressSequence
		if e.AttemptKind != "transport" && e.AttemptKind != "request" {
			return out, detachNativeError()
		}
		if e.AttemptKind == "request" && e.NativeRequestId == "" {
			return out, detachNativeError()
		}
		if e.RequestStreamClass != "true" && e.RequestStreamClass != "false" && e.RequestStreamClass != "absent" && e.RequestStreamClass != "other" && e.RequestStreamClass != "unobserved" {
			return out, detachNativeError()
		}
		name, ok := pb.ProviderObservationRewriteV1_name[int32(e.Rewrite)]
		if !ok {
			return out, detachNativeError()
		}
		if e.AttemptKind == "transport" {
			if e.Rewrite != pb.ProviderObservationRewriteV1_PROVIDER_OBSERVATION_REWRITE_V1_UNOBSERVED || e.UpstreamApplicationRequestBytes != 0 || e.ResponseOrigin != "not_applicable" {
				return out, detachNativeError()
			}
		} else {
			requests++
			allRefused = allRefused && e.Rewrite == pb.ProviderObservationRewriteV1_PROVIDER_OBSERVATION_REWRITE_V1_EXPECTED_UNAVAILABLE && e.UpstreamApplicationRequestBytes == 0 && e.ResponseOrigin == "native_refusal"
		}
		out.Events = append(out.Events, OrdinaryObservationEvent{e.IngressSequence, e.NativeRequestId, e.NativeResponseId, e.NativeConnectionId, e.AttemptKind, e.RequestStreamClass, e.ResponseOrigin, e.HttpFraming, e.ClientSocketWrite, name, e.UpstreamApplicationRequestBytes})
	}
	if n.TerminalSha256 != "" {
		c := proto.Clone(n).(*pb.ProviderObservationResultV1)
		c.TerminalSha256 = ""
		c.CurrentSnapshot = nil
		c.DetachedAck = nil
		c.CurrentReportSequence = 0
		c.AckWindowSha256 = ""
		c.AckTerminalSha256 = ""
		c.CurrentRead = nil
		if n.TerminalSha256 != ordinaryDigest("openshell.provider-detach.sandbox-mediation-terminal/v1", c) {
			return out, detachNativeError()
		}
	}
	if n.CurrentRead == nil {
		if n.CurrentSnapshot != nil || n.DetachedAck != nil || n.AckWindowSha256 != "" || n.AckTerminalSha256 != "" || n.CurrentReportSequence != 0 {
			return out, detachNativeError()
		}
		return out, nil
	}
	selector := &pb.GetProviderDetachObservationRequest{WorkspaceScope: namedWorkspaceScope(q.Resource.Workspace), OriginalRequest: q.native()}
	terminal := out.State == "terminal" && len(n.Events) > 0 && n.ClosedTime != nil && n.ClosedTime.CheckValid() == nil && n.ClosedTime.AsTime().Equal(w.CaptureEnd.AsTime()) && n.TerminalSha256 != ""
	installedOpen := out.State == "open" && n.TerminalSha256 == "" && n.ClosedTime == nil && now.Before(w.CaptureEnd.AsTime())
	if (!terminal && !installedOpen) || n.CurrentReportSequence == 0 || !now.Before(q.Deadline) || n.AckWindowSha256 != w.WindowSha256 || n.AckTerminalSha256 != n.TerminalSha256 || !proto.Equal(n.CurrentSnapshot, n.CurrentRead.SampledSnapshot) || ordinaryRead(n.CurrentRead, selector, w.InstalledSnapshot, w.WindowSha256, n.TerminalSha256, now) != nil || n.CurrentSnapshot.CurrentIngressSequence != last {
		return out, detachNativeError()
	}
	if q.Phase == "detached" {
		if n.DetachedAck == nil || q.InstalledArm == nil {
			return out, detachNativeError()
		}
		if _, err := detachACKFromProto(n.DetachedAck, q.InstalledArm.Request, now); err != nil {
			return out, err
		}
	} else if n.DetachedAck != nil {
		return out, detachNativeError()
	}
	out.HistoricalOnly = false
	out.Current = true
	out.CredentialRefusal = terminal && q.Phase == "detached" && requests > 0 && allRefused
	return out, nil
}

// DiscoverOrdinaryObservation performs ONE metadata read. No fixed ELF lookup.
func (c *ProviderDetachmentClient) DiscoverOrdinaryObservation(ctx context.Context) (OrdinaryObservationMetadata, error) {
	empty := OrdinaryObservationMetadata{}
	bounded, cancel, err := c.bound(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer cancel()
	q := &pb.GetProviderDetachObservationRequest{WorkspaceScope: namedWorkspaceScope(c.resource.Workspace), Resource: detachResourceToProto(c.resource)}
	n, err := c.rpc.GetProviderDetachObservation(bounded, q)
	if err != nil {
		return empty, converter.FromGRPCError(err)
	}
	if n == nil || n.Result != nil || ordinaryRead(n.CurrentRead, q, nil, "", "", time.Now()) != nil || !proto.Equal(n.Snapshot, n.CurrentRead.SampledSnapshot) {
		return empty, detachNativeError()
	}
	return ordinaryMetadata(n.Snapshot, c.resource)
}
func (c *ProviderDetachmentClient) BeginOrdinaryObservation(ctx context.Context, q OrdinaryObservationRequest) (OrdinaryObservationEvidence, error) {
	empty := OrdinaryObservationEvidence{}
	if q.Validate() != nil || q.Resource != c.resource || !time.Now().Before(q.Deadline) {
		return empty, detachNativeError()
	}
	bounded, cancel, err := c.bound(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer cancel()
	n, err := c.rpc.BeginProviderDetachObservation(bounded, &pb.BeginProviderDetachObservationRequest{WorkspaceScope: namedWorkspaceScope(c.resource.Workspace), Request: q.native()})
	if err != nil {
		return empty, converter.FromGRPCError(err)
	}
	if n == nil {
		return empty, detachNativeError()
	}
	return ordinaryResult(n.Result, q, time.Now())
}
func (c *ProviderDetachmentClient) QueryOrdinaryObservation(ctx context.Context, q OrdinaryObservationRequest) (OrdinaryObservationEvidence, error) {
	empty := OrdinaryObservationEvidence{}
	if q.Validate() != nil || q.Resource != c.resource {
		return empty, detachNativeError()
	}
	bounded, cancel, err := c.bound(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer cancel()
	selector := &pb.GetProviderDetachObservationRequest{WorkspaceScope: namedWorkspaceScope(c.resource.Workspace), OriginalRequest: q.native()}
	if !ordinaryQueryFits(selector) {
		return empty, detachNativeError()
	}
	n, err := c.rpc.GetProviderDetachObservation(bounded, selector)
	if err != nil {
		return empty, converter.FromGRPCError(err)
	}
	if n == nil || n.Snapshot != nil || n.CurrentRead != nil {
		return empty, detachNativeError()
	}
	return ordinaryResult(n.Result, q, time.Now())
}
