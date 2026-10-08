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
