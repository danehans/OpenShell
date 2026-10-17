// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider-agnostic identity representation.
//!
//! Any authentication backend (OIDC, mTLS, static RBAC, OS users) produces
//! an `Identity` that the authorization layer can evaluate without knowing
//! which provider authenticated the caller.

/// Authenticated caller identity.
///
/// Produced by an authentication provider and consumed by the authorization
/// layer. The gateway's auth middleware converts provider-specific claims
/// (OIDC JWT, mTLS cert CN, etc.) into this common representation.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Unique subject identifier (OIDC `sub`, cert CN, username, etc.).
    pub subject: String,

    /// Human-readable display name (OIDC `preferred_username`, cert CN, etc.).
    pub display_name: Option<String>,

    /// Roles granted to this identity (OIDC `realm_access.roles`, cert OU, etc.).
    pub roles: Vec<String>,

    /// `OAuth2` scopes granted to this identity. Empty when scope enforcement is disabled.
    pub scopes: Vec<String>,

    /// Which authentication provider produced this identity.
    pub provider: IdentityProvider,

    /// Closed issuer-attested capability, retained only after JWT verification.
    /// Ordinary scopes, roles and mTLS identities never manufacture this value.
    pub provider_detach_witness_approval: Option<Box<ProviderDetachWitnessApproval>>,
}

/// Exactly one original witness operation, distinct from a broad worker token.
#[derive(Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDetachWitnessApproval {
    pub schema: String,
    pub subject: String,
    pub run_id: String,
    pub action_id: String,
    pub native_receipt_id: String,
    pub hold_id: String,
    pub attempt_id: String,
    pub installed_arm_sha256: String,
    pub profile_sha256: String,
    pub request_sha256: String,
    pub resource_sha256: String,
    pub deadline_unix_ms: i64,
    pub count: u32,
}

impl std::fmt::Debug for ProviderDetachWitnessApproval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderDetachWitnessApproval(<issuer-attested metadata>)")
    }
}

impl ProviderDetachWitnessApproval {
    pub fn valid_shape(&self, authenticated_subject: &str) -> bool {
        let uuid =
            |s: &str| uuid::Uuid::parse_str(s).is_ok_and(|id| !id.is_nil() && id.to_string() == s);
        let digest = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        self.schema == "openshell.provider-detach.witness-approval/v1"
            && !self.subject.is_empty()
            && self.subject.len() <= 253
            && self.subject == authenticated_subject
            && self.count == 1
            && self.deadline_unix_ms > 0
            && [
                &self.run_id,
                &self.action_id,
                &self.native_receipt_id,
                &self.hold_id,
                &self.attempt_id,
            ]
            .into_iter()
            .all(|v| uuid(v))
            && [
                &self.installed_arm_sha256,
                &self.profile_sha256,
                &self.request_sha256,
                &self.resource_sha256,
            ]
            .into_iter()
            .all(|v| digest(v))
    }
}

/// Authentication provider that produced an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProvider {
    /// OIDC/OAuth2 JWT bearer token.
    Oidc,
    /// mTLS client certificate.
    Mtls,
    /// Cloudflare Access JWT.
    CloudflareAccess,
    /// Explicit unauthenticated local-development user principal.
    LocalDev,
}
