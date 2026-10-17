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
