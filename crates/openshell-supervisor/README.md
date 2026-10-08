# OpenShell supervisor

The supervisor loads and reconciles policy, maintains provider credentials, applies network and MCP inspection, and drives the admitted isolation backend through attachment, confirmation, and workload start.

## Backend startup

The public `run_sandbox` entry point selects the OpenShell Sandbox Protocol backend and collects its startup inputs into a private `SandboxRunConfig`. Shared startup receives that config and the trusted backend setup separately. The `backend_setup` module owns that backend's launch-data decoder, workload policy discovery, and client construction. Descriptor contents cannot select an implementation.

Shared startup checks the admitted backend name before passing the opaque payload to its decoder. It then compares the decoded sandbox, session, and runtime generation with the trusted launch inputs before installing credentials or discovering workload policy. A mismatch stops startup.

The built-in decoder also carries the VM driver's fixed workload identity into shared policy validation. Startup and later policy updates must reject selectors that conflict with that identity. Other launch descriptors do not enable this VM-specific check.

The supervisor admits policy and prepares credentials before constructing and attaching the selected client. It uses the isolation contract's `BoundBoundary` and `ConfirmedBoundary` directly: confirm the attached boundary, prepare network mediation, then start the workload. Backend implementations remain responsible for validating their native enforcement evidence through the isolation contract.

The client receives the supervisor's live provider state, bearer-token slot, and CA-path slot. Provider refresh, token rotation, and later CA publication must remain visible through those shared handles. Startup does not create independent copies of their current values.

The setup interface stays private to the supervisor. It adds no runtime backend registration, endpoint configuration, or public factory API. The public `run_sandbox` signature and standard backend selection remain unchanged.

## Runtime-origin traffic credentials

An experimental operator grant can require supervisor-owned identity on an exact
HTTPS traffic gateway. Startup derives the execution from authenticated launch
inputs and uses the current gateway session for separate traffic-token issuance.
The token client connects lazily on first issuance; the disabled default adds no
startup connection. Local policy overrides cannot activate these grants.

The poll loop reserves discovered destinations behind rejection, prepares their
TLS roots and descriptor bounds, and activates the snapshot only after native
runtime reconciliation and a successful configuration acknowledgement within five
seconds. The admission instance must exactly match this supervisor's trusted
startup instance. Failed polling, preparation or acknowledgement revokes traffic
bindings. Recovery must
acknowledge the exact snapshot again, including unchanged policy revisions.

The network supervisor admits only authenticated isolation-boundary traffic with
native enforce-mode REST, GraphQL, JSON-RPC or MCP inspection. Raw, audit,
plaintext, upgrade and signed requests cannot acquire traffic identity. Explicit
TLS roots replace platform roots and hostname verification is mandatory. The
supervisor strips workload-supplied identity headers before middleware, then adds
its own `x-openshield-traffic-token` after native admission and provider/header
transformations. Provider Authorization is independent.

A target cache uses single-flight issuance, one five-second deadline including
queue time and a 15-second renewal margin. Returned execution, descriptor, configuration and expiry
must match the frozen snapshot. Policy changes, snapshot replacement, revocation
and expiry cancel client and upstream I/O, including idle reads and blocked
writes. Internal identity
response fields and trailers are rejected before delivery.

These host-level checks do not qualify a complete gateway deployment. The
selected traffic gateway must verify the dedicated JWT type, audience and claims,
strip the carrier before the backend, avoid recording or reflecting it, and
provide trusted bounded identity metadata to the traffic processor. Shared-origin
HTTP/MCP qualification and forced routing remain separate integration gates.
