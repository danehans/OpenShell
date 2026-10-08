// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Immutable operator grants for exact runtime-origin traffic destinations.

use base64::Engine as _;
use openshell_core::proto::TrafficIdentityTarget;
use openshell_core::traffic_identity::{TrafficTargetConfig, TrafficTransport};
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use tonic::Status;

const MAX_TARGETS: usize = 32;
const MAX_SANDBOXES: usize = 256;
const MAX_DESCRIPTOR_BYTES: usize = 512 * 1024;

#[derive(Debug, Default)]
pub struct TrafficIdentityRegistry {
    targets: BTreeMap<String, RegisteredTarget>,
}

#[derive(Debug)]
struct RegisteredTarget {
    descriptor: TrafficIdentityTarget,
    workspace: String,
    sandbox_ids: BTreeSet<String>,
}

impl TrafficIdentityRegistry {
    pub fn from_configs(configs: &[TrafficTargetConfig]) -> Result<Self, String> {
        if configs.len() > MAX_TARGETS {
            return Err("too many traffic identity targets".into());
        }
        let mut targets = BTreeMap::new();
        let mut authorities = BTreeSet::new();
        let mut descriptor_bytes = 0;
        for config in configs {
            if !valid_name(&config.name)
                || crate::grpc::workspace::validate_workspace_name(&config.workspace).is_err()
            {
                return Err("invalid traffic target or workspace name".into());
            }
            // Dedicated namespace prevents accidental extension/session audiences.
            if !config.audience.starts_with("urn:openshell:traffic:")
                || config.audience.len() > 256
                || config.audience.len() <= "urn:openshell:traffic:".len()
                || !config
                    .audience
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || b":._/-".contains(&v))
            {
                return Err("invalid traffic target audience".into());
            }
            if config.https_endpoint.len() > 2048 {
                return Err("traffic HTTPS endpoint exceeds maximum length".into());
            }
            let url = url::Url::parse(&config.https_endpoint)
                .map_err(|_| "invalid traffic target HTTPS endpoint")?;
            if url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
                || !matches!(url.host(), Some(url::Host::Domain(_)))
                || url.host_str().is_some_and(|host| host.ends_with('.'))
                || url.port_or_known_default() == Some(0)
            {
                return Err("traffic target requires an exact HTTPS DNS authority".into());
            }
            if !authorities.insert(url.as_str().to_string()) {
                return Err("duplicate traffic target authority".into());
            }
            if config.sandbox_ids.is_empty() || config.sandbox_ids.len() > MAX_SANDBOXES {
                return Err("traffic target requires a bounded sandbox UUID grant".into());
            }
            let mut sandbox_ids = BTreeSet::new();
            for id in &config.sandbox_ids {
                let parsed =
                    uuid::Uuid::parse_str(id).map_err(|_| "invalid traffic target sandbox UUID")?;
                if parsed.is_nil() || parsed.to_string() != *id || !sandbox_ids.insert(id.clone()) {
                    return Err("invalid or duplicate traffic target sandbox UUID".into());
                }
            }
            let transports: BTreeSet<_> = config.transports.iter().copied().collect();
            if transports.is_empty() || transports.len() != config.transports.len() {
                return Err("traffic target requires unique HTTP/MCP transports".into());
            }
            let tls_ca_cert_pem = if let Some(path) = &config.tls_ca_cert_path {
                let path = path.to_str().ok_or("invalid traffic TLS CA path")?;
                let pem = openshell_core::driver_utils::read_upstream_proxy_ca_bundle_file(
                    path,
                    "traffic TLS CA",
                )
                .map_err(|_| "invalid traffic TLS CA certificate bundle")?;
                if pem.lines().any(|line| {
                    let line = line.trim();
                    line.starts_with("-----BEGIN ") && line != "-----BEGIN CERTIFICATE-----"
                }) {
                    return Err("traffic TLS CA bundle must contain only certificates".into());
                }
                // The bounded existing reader validates usable rustls anchors;
                // additionally reject any embedded key or other PEM item.
                for item in rustls_pemfile::read_all(&mut Cursor::new(pem.as_bytes())) {
                    if !matches!(item, Ok(rustls_pemfile::Item::X509Certificate(_))) {
                        return Err("traffic TLS CA bundle must contain only certificates".into());
                    }
                }
                let mut certificates = BTreeSet::new();
                for certificate in rustls_pemfile::certs(&mut pem.as_bytes()) {
                    let certificate =
                        certificate.map_err(|_| "invalid traffic TLS CA certificate")?;
                    rustls::RootCertStore::empty()
                        .add(certificate.clone())
                        .map_err(|_| "invalid traffic TLS CA certificate")?;
                    certificates.insert(certificate.as_ref().to_vec());
                }
                let mut canonical = String::new();
                for certificate in certificates {
                    canonical.push_str("-----BEGIN CERTIFICATE-----\n");
                    let encoded = base64::engine::general_purpose::STANDARD.encode(certificate);
                    for line in encoded.as_bytes().chunks(64) {
                        canonical.push_str(std::str::from_utf8(line).expect("base64 ASCII"));
                        canonical.push('\n');
                    }
                    canonical.push_str("-----END CERTIFICATE-----\n");
                }
                canonical.into_bytes()
            } else {
                Vec::new()
            };
            let mut hasher = Sha256::new();
            hash_part(&mut hasher, b"openshell-traffic-target-v1");
            for part in [
                &config.name,
                url.as_str(),
                &config.audience,
                &config.workspace,
            ] {
                hash_part(&mut hasher, part.as_bytes());
            }
            hash_part(&mut hasher, &tls_ca_cert_pem);
            hash_part(&mut hasher, &(sandbox_ids.len() as u64).to_be_bytes());
            for id in &sandbox_ids {
                hash_part(&mut hasher, id.as_bytes());
            }
            hash_part(&mut hasher, &(transports.len() as u64).to_be_bytes());
            for transport in &transports {
                hash_part(&mut hasher, transport.as_str().as_bytes());
            }
            let descriptor = TrafficIdentityTarget {
                name: config.name.clone(),
                https_endpoint: url.to_string(),
                audience: config.audience.clone(),
                tls_ca_cert_pem,
                transports: transports
                    .into_iter()
                    .map(TrafficTransport::as_str)
                    .map(str::to_string)
                    .collect(),
                target_sha256: format!("{:x}", hasher.finalize()),
            };
            reserve_descriptor_bytes(&mut descriptor_bytes, &descriptor)?;
            if targets
                .insert(
                    config.name.clone(),
                    RegisteredTarget {
                        descriptor,
                        workspace: config.workspace.clone(),
                        sandbox_ids,
                    },
                )
                .is_some()
            {
                return Err("duplicate traffic target registration name".into());
            }
        }
        Ok(Self { targets })
    }

    pub fn authorized_targets(
        &self,
        sandbox_id: &str,
        workspace: &str,
    ) -> Vec<TrafficIdentityTarget> {
        self.targets
            .values()
            .filter(|target| {
                target.workspace == workspace && target.sandbox_ids.contains(sandbox_id)
            })
            .map(|target| target.descriptor.clone())
            .collect()
    }

    #[allow(clippy::result_large_err)]
    pub fn authorize(
        &self,
        name: &str,
        sandbox_id: &str,
        workspace: &str,
    ) -> Result<TrafficIdentityTarget, Status> {
        self.targets
            .get(name)
            .filter(|target| {
                target.workspace == workspace && target.sandbox_ids.contains(sandbox_id)
            })
            .map(|target| target.descriptor.clone())
            .ok_or_else(|| {
                Status::permission_denied("traffic target is not authorized for this sandbox")
            })
    }
}

fn reserve_descriptor_bytes(
    bytes: &mut usize,
    target: &TrafficIdentityTarget,
) -> Result<(), String> {
    *bytes = bytes
        .checked_add(target.encoded_len())
        .filter(|value| *value <= MAX_DESCRIPTOR_BYTES)
        .ok_or("traffic identity descriptors exceed the 512 KiB limit")?;
    Ok(())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || v == b'-')
        && !name.ends_with('-')
}

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// Preserve legacy configuration revisions when no traffic grant is present.
pub fn configuration_revision(base: u64, targets: &[TrafficIdentityTarget]) -> u64 {
    if targets.is_empty() {
        return base;
    }
    let mut target_fingerprints: Vec<_> = targets
        .iter()
        .map(|target| target.target_sha256.as_str())
        .collect();
    target_fingerprints.sort_unstable();
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, b"openshell-traffic-configuration-v1");
    hash_part(&mut hasher, &base.to_be_bytes());
    for hash in target_fingerprints {
        hash_part(&mut hasher, hash.as_bytes());
    }
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[..8].try_into().expect("eight digest bytes"))
}

pub fn configuration_sha256(
    config: &openshell_core::proto::GetSandboxConfigResponse,
    target: &TrafficIdentityTarget,
) -> String {
    openshell_core::traffic_identity::configuration_sha256_parts(
        config.config_revision,
        config.provider_env_revision,
        &config.policy_hash,
        &config.provider_attachment_epoch,
        &config.configuration_instance_id,
        &target.target_sha256,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "c1bf54a4-7789-4091-b682-e183f71a3fca";
    pub(super) fn config() -> TrafficTargetConfig {
        TrafficTargetConfig {
            name: "shared-gateway".into(),
            https_endpoint: "https://gateway.example.test:8443".into(),
            audience: "urn:openshell:traffic:shared-gateway".into(),
            workspace: "default".into(),
            sandbox_ids: vec![ID.into()],
            transports: vec![TrafficTransport::Http, TrafficTransport::Mcp],
            tls_ca_cert_path: None,
        }
    }
    #[test]
    fn discovery_and_grants_require_immutable_id_and_workspace() {
        let registry = TrafficIdentityRegistry::from_configs(&[config()]).unwrap();
        assert_eq!(registry.authorized_targets(ID, "default").len(), 1);
        for (id, workspace) in [("sandbox-name", "default"), (ID, "other"), ("", "default")] {
            assert!(registry.authorized_targets(id, workspace).is_empty());
            assert_eq!(
                registry
                    .authorize("shared-gateway", id, workspace)
                    .unwrap_err()
                    .code(),
                tonic::Code::PermissionDenied
            );
        }
        assert!(
            TrafficIdentityRegistry::default()
                .authorized_targets(ID, "default")
                .is_empty()
        );
    }
    #[test]
    fn unsafe_or_ambiguous_targets_fail_closed() {
        for endpoint in [
            "http://gateway.example.test",
            "https://user:secret@gateway.example.test",
            "https://gateway.example.test/path",
            "https://gateway.example.test/?q=1",
            "https://gateway.example.test/#x",
            "https://127.0.0.1",
            "https://gateway.example.test.",
            "https://gateway.example.test:0",
        ] {
            let mut cfg = config();
            cfg.https_endpoint = endpoint.into();
            assert!(TrafficIdentityRegistry::from_configs(&[cfg]).is_err());
        }
        for audience in [
            "openshell-gateway:test",
            "urn:openshell:extension:middleware:x",
            "urn:openshell:traffic:",
            "urn:openshell:traffic:secret\n",
        ] {
            let mut cfg = config();
            cfg.audience = audience.into();
            assert!(TrafficIdentityRegistry::from_configs(&[cfg]).is_err());
        }
        let cfg = config();
        assert!(TrafficIdentityRegistry::from_configs(&[cfg.clone(), cfg]).is_err());
        let mut cfg = config();
        cfg.sandbox_ids = vec!["sandbox-name".into()];
        assert!(TrafficIdentityRegistry::from_configs(&[cfg]).is_err());
        let mut cfg = config();
        cfg.transports.push(TrafficTransport::Http);
        assert!(TrafficIdentityRegistry::from_configs(&[cfg]).is_err());
    }
    #[test]
    fn invalid_ca_and_registry_bounds_are_rejected_without_content_disclosure() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let marker = "secret-marker-never-in-diagnostics";
        std::fs::write(file.path(), marker).unwrap();
        let mut cfg = config();
        cfg.tls_ca_cert_path = Some(file.path().into());
        let error = TrafficIdentityRegistry::from_configs(&[cfg]).unwrap_err();
        assert!(!error.contains(marker));
        assert!(TrafficIdentityRegistry::from_configs(&vec![config(); 33]).is_err());
        let mut cfg = config();
        cfg.sandbox_ids.clear();
        assert!(TrafficIdentityRegistry::from_configs(&[cfg]).is_err());
        let mut cfg = config();
        cfg.transports.clear();
        assert!(TrafficIdentityRegistry::from_configs(&[cfg]).is_err());
        let mut cfg = config();
        cfg.sandbox_ids = vec![ID.into(); 257];
        assert!(TrafficIdentityRegistry::from_configs(&[cfg]).is_err());
    }

    #[test]
    fn private_ca_contents_are_canonicalized_without_copying_keys_or_comments() {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["gateway.example.test".into()]).unwrap();
        let a = tempfile::NamedTempFile::new().unwrap();
        let b = tempfile::NamedTempFile::new().unwrap();
        let marker = "secret-marker-never-in-discovery";
        std::fs::write(a.path(), format!("{}\n{marker}\n", certificate.cert.pem())).unwrap();
        std::fs::write(b.path(), certificate.cert.pem()).unwrap();
        let mut cfg = config();
        cfg.tls_ca_cert_path = Some(a.path().into());
        let first = TrafficIdentityRegistry::from_configs(&[cfg.clone()])
            .unwrap()
            .authorized_targets(ID, "default")
            .remove(0);
        assert!(
            !String::from_utf8(first.tls_ca_cert_pem.clone())
                .unwrap()
                .contains(marker)
        );
        cfg.tls_ca_cert_path = Some(b.path().into());
        let second = TrafficIdentityRegistry::from_configs(&[cfg.clone()])
            .unwrap()
            .authorized_targets(ID, "default")
            .remove(0);
        assert_eq!(
            first, second,
            "paths and harmless PEM formatting cannot change effective roots"
        );
        std::fs::write(
            b.path(),
            format!(
                "{}{}",
                certificate.cert.pem(),
                certificate.key_pair.serialize_pem()
            ),
        )
        .unwrap();
        assert!(TrafficIdentityRegistry::from_configs(&[cfg.clone()]).is_err());
        std::fs::write(
            b.path(),
            format!(
                "{}-----BEGIN OPENSSH PRIVATE KEY-----\nYWJj\n-----END OPENSSH PRIVATE KEY-----\n",
                certificate.cert.pem()
            ),
        )
        .unwrap();
        assert!(TrafficIdentityRegistry::from_configs(&[cfg]).is_err());
    }

    #[test]
    fn discovery_budget_bounds_aggregate_protobuf_bytes() {
        let first = TrafficIdentityTarget {
            tls_ca_cert_pem: vec![0; MAX_DESCRIPTOR_BYTES - 16],
            ..Default::default()
        };
        let second = TrafficIdentityTarget {
            tls_ca_cert_pem: vec![0; 16],
            ..Default::default()
        };
        let mut bytes = 0;
        reserve_descriptor_bytes(&mut bytes, &first).unwrap();
        assert!(reserve_descriptor_bytes(&mut bytes, &second).is_err());
        let mut bytes = usize::MAX;
        assert!(reserve_descriptor_bytes(&mut bytes, &second).is_err());
    }

    #[test]
    fn fingerprints_are_stable_and_cover_effective_authorization() {
        let cfg = config();
        let descriptor = |cfg| {
            TrafficIdentityRegistry::from_configs(&[cfg])
                .unwrap()
                .authorized_targets(ID, "default")
                .remove(0)
        };
        let original = descriptor(cfg.clone());
        let mut reordered = cfg.clone();
        reordered.transports.reverse();
        assert_eq!(original, descriptor(reordered));
        let mut changed = cfg.clone();
        changed.audience.push_str("-new");
        assert_ne!(original.target_sha256, descriptor(changed).target_sha256);
        let mut changed = cfg.clone();
        changed
            .sandbox_ids
            .push("04eb0371-9e4d-49cd-acb2-8c3abfb1b7bc".into());
        assert_ne!(original.target_sha256, descriptor(changed).target_sha256);
        let mut changed = cfg;
        changed.https_endpoint = "https://different.example.test".into();
        assert_ne!(original.target_sha256, descriptor(changed).target_sha256);
        assert_eq!(configuration_revision(42, &[]), 42);
        assert_ne!(
            configuration_revision(42, std::slice::from_ref(&original)),
            42
        );
        let config = openshell_core::proto::GetSandboxConfigResponse::default();
        let mut changed = config.clone();
        changed.provider_attachment_epoch = "new".into();
        assert_ne!(
            configuration_sha256(&config, &original),
            configuration_sha256(&changed, &original)
        );
    }
}
