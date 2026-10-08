// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime-origin credentials for policy-authorized traffic gateways.
//!
//! These credentials are distinct from extension and supervisor session tokens.
//! Only an authenticated supervisor may hold them; workload processes never do.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

pub const TRAFFIC_JWT_TYP: &str = "openshell-traffic+jwt";
pub const TRAFFIC_TOKEN_TTL: Duration = Duration::from_mins(1);
pub const TRAFFIC_TOKEN_HEADER: &str = "x-openshield-traffic-token";

/// Operator-owned grant. A sandbox name, label, or worker identity is not a grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficTargetConfig {
    pub name: String,
    pub https_endpoint: String,
    pub audience: String,
    pub workspace: String,
    pub sandbox_ids: Vec<String>,
    pub transports: Vec<TrafficTransport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca_cert_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficTransport {
    Http,
    Mcp,
}

impl TrafficTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Mcp => "mcp",
        }
    }
}

/// Signed traffic-origin claims, never accepted as extension caller credentials.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficJwtClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub purpose: TrafficTokenPurpose,
    pub sandbox_id: String,
    pub execution_id: String,
    pub target_sha256: String,
    pub configuration_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficTokenPurpose {
    Traffic,
}

// Avoid accidentally serializing origin claims into diagnostic logs.
impl std::fmt::Debug for TrafficJwtClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficJwtClaims").finish_non_exhaustive()
    }
}

/// Stable launch identity shared by the gateway and trusted supervisor.
pub fn execution_id(sandbox_id: &str, generation: &str, epoch: u64) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"openshell-execution-v1\0");
    for value in [sandbox_id, generation] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.update(epoch.to_be_bytes());
    format!("exec-v1:{:x}", digest.finalize())
}

pub fn valid_execution_id(value: &str) -> bool {
    value.strip_prefix("exec-v1:").is_some_and(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Frozen issuance identity; framing stays compatible with the first traffic RPC.
pub fn configuration_sha256_parts(
    config_revision: u64,
    provider_revision: u64,
    policy_hash: &str,
    attachment: &str,
    instance: &str,
    target_sha256: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut part = |value: &[u8]| {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    };
    part(b"openshell-traffic-origin-configuration-v1");
    part(&config_revision.to_be_bytes());
    part(&provider_revision.to_be_bytes());
    for value in [policy_hash, attachment, instance, target_sha256] {
        part(value.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// Bound the aggregate encoded discovery contract without importing wire traits downstream.
pub fn target_encoded_len(target: &crate::proto::TrafficIdentityTarget) -> usize {
    use prost::Message;
    target.encoded_len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_framing_preserves_legacy_vector() {
        assert_eq!(
            execution_id("sandbox-one", "generation-one", 1),
            "exec-v1:bd467847de5288a9688e11174c21d6f3ef5dce054321d6746970ebcef6061b53"
        );
        assert_ne!(execution_id("ab", "c", 1), execution_id("a", "bc", 1));
        assert_ne!(
            execution_id("sandbox-one", "generation-one", 1),
            execution_id("sandbox-one", "generation-one", 2)
        );
        assert!(valid_execution_id(&execution_id(
            "sandbox-one",
            "generation-one",
            1
        )));
        assert!(!valid_execution_id(
            &execution_id("sandbox-one", "generation-one", 1).to_uppercase()
        ));
    }

    #[test]
    fn configuration_framing_preserves_issuance_vector() {
        assert_eq!(
            configuration_sha256_parts(
                7,
                3,
                &"a".repeat(64),
                "attachment-one",
                "instance-one",
                &"b".repeat(64)
            ),
            "6b7cda8715ab087a683b929a73a7eb25288cad09e42c652ff2a8db6b47a8474b"
        );
        assert_ne!(
            configuration_sha256_parts(7, 3, "ab", "c", "instance", "target"),
            configuration_sha256_parts(7, 3, "a", "bc", "instance", "target")
        );
    }
}
