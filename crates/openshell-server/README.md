<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# OpenShell gateway server

This crate owns gateway authentication, policy discovery and sandbox lifecycle.
The following experimental contract adds supervisor-owned traffic origin credentials.

Status: discovery/issuance checkpoint; injection and live qualification pending.

A workload Pod is capability free. Its separate supervisor authenticates the
Sandbox Protocol boundary and holds its gateway session. Do not project another
service-account token into the workload, copy supervisor credentials to it, or
borrow rotating extension credentials for gateway traffic.

The gateway owns a disabled-by-default traffic target registry. Operator grants
bind exact HTTPS DNS authority, dedicated `urn:openshell:traffic:` audience,
workspace and immutable sandbox UUIDs, HTTP/MCP transports and optional public
TLS roots. Discovery exposes only the sandbox's grants; changes affect target
fingerprints and effective configuration revision. Aggregate discovery metadata
is limited to 512 KiB of protobuf bytes. Public certificate contents
are canonicalized, sorted and fingerprinted; key material is refused.

`IssueTrafficToken` accepts only the current supervisor gateway session. It
requires the frozen execution/target/configuration identities and an admitted,
ready sandbox; it rechecks session currency and sandbox resource version after
policy resolution. It issues an independent 60-second `openshell-traffic+jwt`
with signed `purpose=traffic`, sandbox UUID, execution, target and configuration
SHA-256 identities. It does not rotate or write refresh lineage. Issuance has a
separate bounded per-sandbox rate window. Traffic credentials have no
`caller_kind` and cannot authenticate extension or gateway session RPCs.

The token is an attestation at issuance, not continuing execution authorization.
Native policy can change immediately afterward, as can runtime generation and
revocation. The supervisor must authorize each request under its current native
policy before injecting `x-openshield-traffic-token`, pin the exact target TLS
identity, replace workload-supplied carriers, refuse redirects/downgrades and
never return the token to the workload. This forwarding work is not implemented
by this checkpoint. Provider Authorization is a separate credential channel.

The downstream gateway must validate type, purpose, signature, issuer, exact
audience, lifetime and all origin/configuration relationships, strip the carrier
before any backend, and convey only bounded authenticated identity to processors.
OpenShield must independently recheck execution currency, adopted configuration
and durable fences at every request and response stage. Canary authority remains
independent of origin authentication; a probe alone cannot impersonate an actor.

Required follow-up includes supervisor authenticated-boundary/TLS/injection tests,
neutral runtime identity descriptors, shared-gateway HTTP/MCP multiplexing with
independent actor snapshots and canaries, two-actor revocation/replacement/outage
qualification, Calico bypass/quarantine and real-agent/cloud gates. No deployed
or production-security claim follows from host issuance tests.
