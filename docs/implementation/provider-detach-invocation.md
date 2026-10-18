# Single-profile provider-detach invocation

This source change implements the reviewed, default-off witness protocol. It does
not supply an issuer, grant, profile artifact, matching runtime image, deployment,
or live qualification. The only intended workload is the immutable admitted
`provider-detach-benign-witness-v1` profile; arbitrary commands are unsupported.

## Original ownership and database transaction

The gateway reserves one original authority/run/action key in the existing
SQLite objects table. Reservation and the first dispatch claim each use
`BEGIN IMMEDIATE`, load the actual original action and hold/receipt, validate the
current sandbox/provider identities and versions, and recompute the database
configuration-dependency fence within that transaction. Neither an external
cached fence nor admission-only CAS substitutes for these related-row checks.
The first dispatch claim commits before any transport send. A lost commit reply
allows only original readback, never a send or a second claim. The admission is a
permanent tombstone: generic retention and CRUD cannot reopen it. Unsupported
database backends refuse this capability.

## Source authorization and boundary ordering

One per-execution outer gate is shared by live Core credential state and OPA.
Lock order is outer gate, OPA engine, middleware/fail-closed state, Core state.
Preparation and policy compilation happen outside the gate. Publication and
bounded metadata validation happen inside it; network awaits, fsync, compilation
and process creation do not. OPA's credential-publication callback borrows the
same typed guard rather than recursively acquiring it.

The boundary first prepares an ephemeral ticket with its fresh unpredictable
incarnation, exact authenticated session, original request/profile and unchanged
deadline. Preparation starts no workload. The gateway independently validates
the issuer's closed approval before its durable dispatch claim. Source
authorization **L** binds that authenticated gateway request to the server-accepted
installed Arm, current credential installation and OPA generation, execution and
prepared ticket; it commits one nonreusable source permit under the gate. Revocation **R**
takes the same gate before publishing any effective change, invalidates the
source epoch, then sends cancellation after releasing locks.

R before L denies authorization. L before R describes one legitimately
authorized in-flight operation: its physical child can start later if the permit
beats a delayed remote fence. A received boundary fence prevents a later local
spawn. A spawn that wins locally registers its owned child before cancellation
can act. Source invalidation, pending cancellation, observed boundary quiescence,
process exit and Native credential refusal are separate facts. Signal delivery
is not termination evidence. This protocol does not promise zero instructions
after source revocation or instantaneous remote quiescence across a partition.

## Restart and replay

Every boundary start or state loss creates a new incarnation. The memory-only
boundary witness fence never expires consumed entries within that incarnation;
capacity exhaustion refuses rather than evicts. Source restart likewise creates
a fresh source incarnation. The durable gateway claim never rebinds to a new
hello, session, nonce or boot. Lost ephemeral state or an ambiguous send remains
unknown, with no relaunch. No second journal or fabricated local fsync is used.

The Native adapter pins the original cached connection generation, transport
identity and credential fingerprint. It uses that original channel directly;
it does not enter ordinary credential renewal, reconnect, attach or confirm
recovery. Missing, changed or aborted ownership returns unknown without another
send. The adapter keeps weak ownership references and validates the original
association again after a response. A changed connection is not a fresh grant.

## Verification boundaries

Causal tests must cover transaction-local dependency drift, competing claims,
lost responses, all effective source writers, borrowed-guard lock order, both
L/R orderings, boundary fence/spawn order, restart and capacity refusal. Offline
tests and compilation are source evidence only. Actual issuer issuance, the
immutable launcher artifact and authenticated runtime/Native refusal observations
remain separate operational prerequisites.

## Read-only incarnation discovery

An issuer-bound caller must discover the fresh source and boundary incarnations
before constructing a request digest and obtaining its exact closed approval.
No existing OIDC discovery/JWKS, gateway-info or current-user endpoint supplies
these Native session values. The existing witness Get RPC has two disjoint typed
modes: the original request alone, or exactly one immutable resource selector.
Both, neither, multiple selectors (even identical ones), and mixed or incomplete
response modes refuse. The SDK exposes discovery as a separate method; an
unknown invocation never triggers discovery, reapproval or a retry.

Metadata mode requires a verified OIDC User, enabled scope enforcement, a
permitted non-admin role, workspace membership, exactly `sandbox:provider-detach:witness:read` and its
exact immutable-resource target scope. It does not require the request-specific
approval that discovery is needed to construct. That exception applies only to
metadata mode; original-history reads retain their exact closed approval.
Actual current catalog rows, immutable execution identity, authenticated
initialized supervisor session, source/boundary incarnations and the compiled
profile must agree. Zero current attachment is valid after detach; duplicate
attachments refuse. No policy/configuration resolution or backfill occurs.

Returned resource/session/execution identities, UUIDs and profile hash are
sensitive correlation metadata, not bearer authority or Native refusal proof.
They do not reserve, Arm, consume, send, launch, adopt a session, renew a nonce or
extend a deadline. Row contents and versions are checked around the registry
snapshot, then the current session/capability is checked again. No registry lock
crosses a database await. This is not a joint distributed transaction: the
snapshot can become stale immediately. Reserve, Invoke and source L independently
reject a stale exact request; they never replace its nonce pair. Historical
original reads remain separate when the current session disappears.

Authorization and digest checks bind the entire final decoded protobuf object.
Singular scalars generally use last-wins semantics; repeated occurrences of a
singular embedded message may merge. Repeated resource selectors preserve
multiplicity and are rejected when more than one is supplied. This contract does
not claim rejection of every raw duplicate or unknown wire field and adds no raw
request decoder. Lossless descriptor guards separately validate the exact five
added field declarations and custom authorization options, replay the initial
witness schema, and retain all older public/durable/private compatibility guards.

## Optional manual sandbox mediation-path observation

The separate ordinary observer records traffic metadata on one original,
inspected sandbox execution path. It does not run a task or model. Its profile
is `ordinary-sandbox-mediation-static-bearer-v1`, with evidence scope
`original-sandbox-mediation-path/v1`. Every snapshot explicitly declares process
writer attribution **unproven**. This is distinct from the fixed witness above;
an unsupported writer query is never converted into a successful path proof.

The trusted backend retains each original accepted stream and its authenticated
connection generation. A private stream-owned lease is taken once before proxy
wrapping. Stream drop revokes membership before allocation reuse and cancels the
bridge, including after `RelayReady`. A cookie, TID, header, sandbox name or hash
cannot supply that membership. Recovery, replacement, dropped setup, missing
association and accounting overflow leave the original observation unqualified.
The existing binary, route and policy checks still apply. The boundary's
`NetworkConnected.policy_generation` placeholder is not policy evidence: actual
supervisor authorization supplies the generation checked again at rewriting.

Ordinary `Get` has two distinct modes: exact resource discovery, independent of
any fixed ELF, and recovery of one complete original observation request. After
an unknown `Begin`, use only the latter; do not rediscover, renew the request or
repeat `Begin`. Narrow verified OIDC method, immutable resource and workspace
authority are required. The baseline uses its own original install/read seal.
Detached observations additionally require the actual original conditional
action, hold, installed Arm and current ACK. They never fabricate a detach ACK
for baseline or treat a revoked status, cancellation, policy denial or HTTP 503
as expected-reference credential refusal.

A fresh correlated read travels on the original supervisor channel. Core
samples its ingress counter after receiving that read and includes pending
stream setup and incomplete requests. Gateway checks the original session,
configuration/readiness, resource, deadlines and known later reports at closing.
A cached terminal N cannot qualify while N+1 is pending. This is a point-in-time
read, not proof of quiescence through client receipt.

Every bounded eligible transport and request is accounted for, including
keepalive, streaming and nonstreaming followups. Capture ends at the fixed
window deadline, not the first result, error or truncated stream. Native records
actual expected-reference header rewriting, upstream application bytes, HTTP
framing and accepted socket writes; it does not infer model completion. Stream
mode may be `unobserved`; that never filters out the request or establishes an
SDK retry mechanism. Loss, ambiguity, incomplete work or an exhausted event cap
makes the whole window unqualified. The protocol's eight-event cap is not a
retry, token or spending allowance.

The Go SDK validates the distinct profile, digest domains, explicit unproven
writer status, original request and current closing. The manual example in
`sdk/go/examples/provider-detach-observe` offers `discover`, `begin`, `query`,
`consume-input` and `outcome`. Supply explicit TLS CA, private narrow-grant and
metadata files; there is no credential/environment fallback or automatic retry.
It records an exclusive, fsynced original ledger before the only `Begin` send.
A partial or lost write remains consumed and unknown. `consume-input` requires
the original live open-window ACK, then durably consumes the operator's input
allowance before the operator supplies input separately. It never supplies that
input itself. `outcome` records a closed manual outcome without raw prompt,
response, credential, body hash or a Native model-completion assertion.

The operator must use a separately approved actual run profile and bounded
operation authority. A profile hash or operator-session label is not approval.
One trusted operator/session and private local files provide manual custody;
this is not distributed exclusion or a hostile-host guarantee. Real model access
before detachment and loss after it remain separate manual observations.
Subsequent CNI containment, unaffected control and original cleanup require
independent evidence.

Mediation-path records do **not** prove which process wrote each request, exclude
cross-sandbox FD delegation, or cover imported host/other-sandbox sockets and
alternate credentialed routes. Broader sandbox causality requires actual
configuration evidence for the dedicated sandbox and control: trusted host,
original runtime/session, no shared control credentials or FD-capable IPC/mounts,
no imported model sockets and no alternate real credentials or proxies. Quiet
logs and labels are insufficient. Agent exit cannot bypass original execution
or phase checks, permit relaunch, or adopt a replacement session. Matching
runtime/images, actual TLS/reference injection, narrow grants, model/spending
allocation and live enforcement remain separate qualification gates. The
synthetic TLS/SSE client trials establish none of those live properties.
