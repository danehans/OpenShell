// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-owned, snapshot-bound credentials for authenticated HTTPS traffic.

use crate::opa::PolicyGenerationGuard;
use async_trait::async_trait;
use openshell_core::grpc_client::{CachedOpenShellClient, SettingsPollResult};
use openshell_core::jwt::SecretJwt;
use openshell_core::proto::{
    IssueTrafficTokenRequest, IssueTrafficTokenResponse, TrafficIdentityTarget,
};
use openshell_core::traffic_identity::{TRAFFIC_TOKEN_HEADER, TrafficTransport};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const EXPIRY_MARGIN: i64 = 15;
const ISSUANCE_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficIdentityError {
    InvalidConfiguration,
    Unavailable,
    StaleBinding,
    Unsupported,
    InvalidCredential,
}
impl std::fmt::Display for TrafficIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid traffic identity configuration",
            Self::Unavailable => "traffic identity unavailable",
            Self::StaleBinding => "traffic identity binding is stale",
            Self::Unsupported => {
                "traffic identity requires authenticated enforced HTTPS inspection"
            }
            Self::InvalidCredential => "invalid traffic identity credential",
        })
    }
}
impl std::error::Error for TrafficIdentityError {}
impl miette::Diagnostic for TrafficIdentityError {}

type Result<T> = std::result::Result<T, TrafficIdentityError>;

#[async_trait]
pub trait TrafficTokenSource: Send + Sync {
    fn execution_id(&self) -> &str;
    async fn issue(&self, request: IssueTrafficTokenRequest) -> Result<IssueTrafficTokenResponse>;
}

pub struct GatewayTrafficTokenSource {
    client: tokio::sync::OnceCell<CachedOpenShellClient>,
    endpoint: String,
    execution_id: String,
}
impl GatewayTrafficTokenSource {
    pub fn new(endpoint: &str, execution_id: String) -> Result<Self> {
        let url = reqwest::Url::parse(endpoint)
            .map_err(|_| TrafficIdentityError::InvalidConfiguration)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.port_or_known_default() == Some(0)
            || !openshell_core::traffic_identity::valid_execution_id(&execution_id)
        {
            return Err(TrafficIdentityError::InvalidConfiguration);
        }
        Ok(Self {
            client: tokio::sync::OnceCell::new(),
            endpoint: endpoint.to_owned(),
            execution_id,
        })
    }
}
#[async_trait]
impl TrafficTokenSource for GatewayTrafficTokenSource {
    fn execution_id(&self) -> &str {
        &self.execution_id
    }
    async fn issue(&self, request: IssueTrafficTokenRequest) -> Result<IssueTrafficTokenResponse> {
        let client = self
            .client
            .get_or_try_init(|| async {
                CachedOpenShellClient::connect(&self.endpoint)
                    .await
                    .map_err(|_| TrafficIdentityError::Unavailable)
            })
            .await?;
        let response = client
            .raw_client()
            .issue_traffic_token(request)
            .await
            .map_err(|_| TrafficIdentityError::Unavailable)?;
        Ok(response.into_inner())
    }
}

#[derive(Clone, Default)]
pub struct TrafficIdentityState(Arc<RwLock<Registry>>, Arc<tokio::sync::Notify>);
#[derive(Default)]
struct Registry {
    source: Option<Arc<dyn TrafficTokenSource>>,
    active: Option<Arc<Installed>>,
    // Keep destinations after revocation so a failed state cannot become passthrough.
    destinations: BTreeSet<(String, u16)>,
    committed_destinations: BTreeSet<(String, u16)>,
}
struct Installed {
    config_revision: u64,
    provider_env_revision: u64,
    policy_hash: String,
    provider_attachment_epoch: String,
    configuration_instance_id: String,
    generation: u64,
    source: Arc<dyn TrafficTokenSource>,
    targets: BTreeMap<(String, u16), Arc<Target>>,
}
struct Target {
    descriptor: TrafficIdentityTarget,
    tls: Arc<rustls::ClientConfig>,
    cache: tokio::sync::Mutex<Option<CachedCredential>>,
}
#[derive(Clone)]
struct CachedCredential {
    token: SecretJwt,
    expires: i64,
}

pub struct PreparedTrafficIdentity(Option<Arc<Installed>>);
#[derive(Clone)]
pub struct TrafficTargetBinding {
    state: TrafficIdentityState,
    installed: Arc<Installed>,
    target: Arc<Target>,
}
impl std::fmt::Debug for TrafficTargetBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficTargetBinding")
            .finish_non_exhaustive()
    }
}

impl TrafficIdentityState {
    pub fn configure_source(&self, source: Arc<dyn TrafficTokenSource>) -> Result<()> {
        if !openshell_core::traffic_identity::valid_execution_id(source.execution_id()) {
            return Err(TrafficIdentityError::InvalidConfiguration);
        }
        let mut registry = self
            .0
            .write()
            .map_err(|_| TrafficIdentityError::Unavailable)?;
        if registry.source.is_some() {
            return Err(TrafficIdentityError::InvalidConfiguration);
        }
        registry.source = Some(source);
        Ok(())
    }

    pub fn prepare(
        &self,
        snapshot: &SettingsPollResult,
        generation: u64,
    ) -> Result<PreparedTrafficIdentity> {
        if snapshot.traffic_identity_targets.is_empty() {
            return Ok(PreparedTrafficIdentity(None));
        }
        if !snapshot.configuration_admitted || snapshot.traffic_identity_targets.len() > 32 {
            return Err(TrafficIdentityError::InvalidConfiguration);
        }
        let registry = self
            .0
            .read()
            .map_err(|_| TrafficIdentityError::Unavailable)?;
        if let Some(active) = registry.active.as_ref()
            && active.config_revision == snapshot.config_revision
            && active.provider_env_revision == snapshot.provider_env_revision
            && active.policy_hash == snapshot.policy_hash
            && active.provider_attachment_epoch == snapshot.provider_attachment_epoch
            && active.configuration_instance_id == snapshot.configuration_instance_id
            && active.generation == generation
            && active.targets.len() == snapshot.traffic_identity_targets.len()
            && active.targets.values().all(|target| {
                snapshot
                    .traffic_identity_targets
                    .iter()
                    .any(|descriptor| target.descriptor == *descriptor)
            })
        {
            return Ok(PreparedTrafficIdentity(Some(active.clone())));
        }
        let source = registry
            .source
            .clone()
            .ok_or(TrafficIdentityError::Unavailable)?;
        drop(registry);
        let mut targets = BTreeMap::new();
        let mut names = BTreeSet::new();
        let mut bytes = 0usize;
        for descriptor in &snapshot.traffic_identity_targets {
            bytes = bytes
                .checked_add(openshell_core::traffic_identity::target_encoded_len(
                    descriptor,
                ))
                .filter(|v| *v <= 512 * 1024)
                .ok_or(TrafficIdentityError::InvalidConfiguration)?;
            let url = reqwest::Url::parse(&descriptor.https_endpoint)
                .map_err(|_| TrafficIdentityError::InvalidConfiguration)?;
            if url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
                || url
                    .host_str()
                    .is_none_or(|h| h.parse::<std::net::IpAddr>().is_ok())
                || url.host_str().is_some_and(|h| h.ends_with('.'))
                || url.port_or_known_default() == Some(0)
                || descriptor.https_endpoint.len() > 2048
                || !valid_name(&descriptor.name)
                || !names.insert(descriptor.name.clone())
                || !descriptor.audience.starts_with("urn:openshell:traffic:")
                || descriptor.audience.len() > 256
                || descriptor.audience.len() <= "urn:openshell:traffic:".len()
                || !descriptor
                    .audience
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b":._/-".contains(&b))
                || descriptor.transports.is_empty()
                || descriptor.transports.len() > 2
                || descriptor
                    .transports
                    .iter()
                    .any(|t| t != "http" && t != "mcp")
                || (descriptor.transports.len() == 2
                    && descriptor.transports[0] == descriptor.transports[1])
                || !valid_hash(&descriptor.target_sha256)
            {
                return Err(TrafficIdentityError::InvalidConfiguration);
            }
            let tls = if descriptor.tls_ca_cert_pem.is_empty() {
                crate::l7::tls::build_upstream_client_config("")
                    .map_err(|_| TrafficIdentityError::InvalidConfiguration)?
            } else {
                if descriptor.tls_ca_cert_pem.len() > 1024 * 1024
                    || std::str::from_utf8(&descriptor.tls_ca_cert_pem)
                        .map_err(|_| TrafficIdentityError::InvalidConfiguration)?
                        .lines()
                        .any(|line| {
                            let line = line.trim();
                            line.starts_with("-----BEGIN ") && line != "-----BEGIN CERTIFICATE-----"
                        })
                {
                    return Err(TrafficIdentityError::InvalidConfiguration);
                }
                let mut roots = rustls::RootCertStore::empty();
                for item in rustls_pemfile::read_all(&mut descriptor.tls_ca_cert_pem.as_slice()) {
                    let Ok(rustls_pemfile::Item::X509Certificate(cert)) = item else {
                        return Err(TrafficIdentityError::InvalidConfiguration);
                    };
                    roots
                        .add(cert)
                        .map_err(|_| TrafficIdentityError::InvalidConfiguration)?;
                }
                if roots.is_empty() {
                    return Err(TrafficIdentityError::InvalidConfiguration);
                }
                let mut config = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
                Arc::new(config)
            };
            let authority = (
                url.host_str()
                    .ok_or(TrafficIdentityError::InvalidConfiguration)?
                    .to_string(),
                url.port_or_known_default()
                    .ok_or(TrafficIdentityError::InvalidConfiguration)?,
            );
            if targets
                .insert(
                    authority,
                    Arc::new(Target {
                        descriptor: descriptor.clone(),
                        tls,
                        cache: tokio::sync::Mutex::new(None),
                    }),
                )
                .is_some()
            {
                return Err(TrafficIdentityError::InvalidConfiguration);
            }
        }
        Ok(PreparedTrafficIdentity(Some(Arc::new(Installed {
            config_revision: snapshot.config_revision,
            provider_env_revision: snapshot.provider_env_revision,
            policy_hash: snapshot.policy_hash.clone(),
            provider_attachment_epoch: snapshot.provider_attachment_epoch.clone(),
            configuration_instance_id: snapshot.configuration_instance_id.clone(),
            generation,
            source,
            targets,
        }))))
    }

    /// Reserve discovered destinations before preparation/ACK; failure must deny.
    pub fn observe_snapshot(&self, snapshot: &SettingsPollResult) -> Result<()> {
        if snapshot.traffic_identity_targets.len() > 32 {
            return Err(TrafficIdentityError::InvalidConfiguration);
        }
        let mut authorities = Vec::new();
        for descriptor in &snapshot.traffic_identity_targets {
            let url = reqwest::Url::parse(&descriptor.https_endpoint)
                .map_err(|_| TrafficIdentityError::InvalidConfiguration)?;
            if descriptor.https_endpoint.len() > 2048
                || url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
                || url
                    .host_str()
                    .is_none_or(|h| h.parse::<std::net::IpAddr>().is_ok() || h.ends_with('.'))
                || url.port_or_known_default() == Some(0)
            {
                return Err(TrafficIdentityError::InvalidConfiguration);
            }
            authorities.push((
                url.host_str()
                    .ok_or(TrafficIdentityError::InvalidConfiguration)?
                    .to_owned(),
                url.port_or_known_default()
                    .ok_or(TrafficIdentityError::InvalidConfiguration)?,
            ));
        }
        let mut registry = self
            .0
            .write()
            .map_err(|_| TrafficIdentityError::Unavailable)?;
        let Registry {
            destinations,
            committed_destinations,
            ..
        } = &mut *registry;
        destinations.clone_from(committed_destinations);
        for authority in authorities {
            destinations.insert(authority);
        }
        Ok(())
    }

    pub fn matches_snapshot(&self, snapshot: &SettingsPollResult, generation: u64) -> bool {
        let Ok(registry) = self.0.read() else {
            return false;
        };
        if snapshot.traffic_identity_targets.is_empty() {
            return registry.active.is_none() && registry.destinations.is_empty();
        }
        registry.active.as_ref().is_some_and(|active| {
            snapshot.configuration_admitted
                && active.config_revision == snapshot.config_revision
                && active.provider_env_revision == snapshot.provider_env_revision
                && active.policy_hash == snapshot.policy_hash
                && active.provider_attachment_epoch == snapshot.provider_attachment_epoch
                && active.configuration_instance_id == snapshot.configuration_instance_id
                && active.generation == generation
                && active.targets.len() == snapshot.traffic_identity_targets.len()
                && active.targets.values().all(|target| {
                    snapshot
                        .traffic_identity_targets
                        .iter()
                        .any(|descriptor| target.descriptor == *descriptor)
                })
        })
    }

    pub fn activate(&self, prepared: PreparedTrafficIdentity) -> Result<()> {
        let mut registry = self
            .0
            .write()
            .map_err(|_| TrafficIdentityError::Unavailable)?;
        registry.destinations = prepared
            .0
            .as_ref()
            .map(|a| a.targets.keys().cloned().collect())
            .unwrap_or_default();
        let Registry {
            destinations,
            committed_destinations,
            ..
        } = &mut *registry;
        committed_destinations.clone_from(destinations);
        registry.active = prepared.0;
        drop(registry);
        self.1.notify_waiters();
        Ok(())
    }
    pub fn revoke(&self) {
        if let Ok(mut registry) = self.0.write() {
            registry.active = None;
        }
        self.1.notify_waiters();
    }
    pub fn requires_identity(&self, host: &str, port: u16) -> Result<bool> {
        Ok(self
            .0
            .read()
            .map_err(|_| TrafficIdentityError::Unavailable)?
            .destinations
            .contains(&(host.to_ascii_lowercase(), port)))
    }
    pub fn bind(
        &self,
        host: &str,
        port: u16,
        generation: u64,
        authenticated_boundary: bool,
    ) -> Result<Option<TrafficTargetBinding>> {
        let registry = self
            .0
            .read()
            .map_err(|_| TrafficIdentityError::Unavailable)?;
        let authority = (host.to_ascii_lowercase(), port);
        if !registry.destinations.contains(&authority) {
            return Ok(None);
        }
        if !authenticated_boundary {
            return Err(TrafficIdentityError::Unsupported);
        }
        let installed = registry
            .active
            .clone()
            .ok_or(TrafficIdentityError::Unavailable)?;
        if installed.generation != generation {
            return Err(TrafficIdentityError::StaleBinding);
        }
        let target = installed
            .targets
            .get(&authority)
            .cloned()
            .ok_or(TrafficIdentityError::Unavailable)?;
        Ok(Some(TrafficTargetBinding {
            state: self.clone(),
            installed,
            target,
        }))
    }
}

impl TrafficTargetBinding {
    pub fn tls_config(&self) -> &Arc<rustls::ClientConfig> {
        &self.target.tls
    }
    fn current(&self) -> Result<()> {
        let registry = self
            .state
            .0
            .read()
            .map_err(|_| TrafficIdentityError::Unavailable)?;
        if registry
            .active
            .as_ref()
            .is_none_or(|a| !Arc::ptr_eq(a, &self.installed))
        {
            return Err(TrafficIdentityError::StaleBinding);
        }
        Ok(())
    }
    fn configuration_sha256(&self) -> String {
        openshell_core::traffic_identity::configuration_sha256_parts(
            self.installed.config_revision,
            self.installed.provider_env_revision,
            &self.installed.policy_hash,
            &self.installed.provider_attachment_epoch,
            &self.installed.configuration_instance_id,
            &self.target.descriptor.target_sha256,
        )
    }
    pub(crate) async fn credential(
        &self,
        transport: TrafficTransport,
        generation: &PolicyGenerationGuard,
    ) -> Result<TrafficCredential> {
        self.current()?;
        if generation.is_stale()
            || generation.captured_generation() != self.installed.generation
            || !self
                .target
                .descriptor
                .transports
                .iter()
                .any(|t| t == transport.as_str())
        {
            return Err(TrafficIdentityError::Unsupported);
        }
        let deadline = tokio::time::Instant::now() + ISSUANCE_DEADLINE;
        let mut cache = tokio::time::timeout_at(deadline, self.target.cache.lock())
            .await
            .map_err(|_| TrafficIdentityError::Unavailable)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(TrafficIdentityError::Unavailable);
        }
        self.current()?;
        let now = now_seconds()?;
        if cache
            .as_ref()
            .is_none_or(|c| c.expires <= now + EXPIRY_MARGIN)
        {
            // Retire expired/uncertain material before an asynchronous replacement.
            *cache = None;
            let response = tokio::time::timeout_at(
                deadline,
                self.installed.source.issue(IssueTrafficTokenRequest {
                    target_name: self.target.descriptor.name.clone(),
                    expected_execution_id: self.installed.source.execution_id().into(),
                    expected_target_sha256: self.target.descriptor.target_sha256.clone(),
                    expected_config_revision: self.installed.config_revision,
                }),
            )
            .await
            .map_err(|_| TrafficIdentityError::Unavailable)??;
            self.current()?;
            if generation.is_stale() {
                return Err(TrafficIdentityError::StaleBinding);
            }
            let expiry = response
                .expiration_time
                .as_ref()
                .ok_or(TrafficIdentityError::InvalidCredential)?;
            openshell_core::time::validate_timestamp(expiry)
                .map_err(|_| TrafficIdentityError::InvalidCredential)?;
            let now = now_seconds()?;
            if response.execution_id != self.installed.source.execution_id()
                || response.target.as_ref() != Some(&self.target.descriptor)
                || response.configuration_sha256 != self.configuration_sha256()
                || expiry.seconds <= now + EXPIRY_MARGIN
                || expiry.seconds > now + 65
                || response.token.len() > 8192
                || response.token.is_empty()
                || !response.token.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err(TrafficIdentityError::InvalidCredential);
            }
            let token = SecretJwt::parse(response.token)
                .map_err(|_| TrafficIdentityError::InvalidCredential)?;
            *cache = Some(CachedCredential {
                token,
                expires: expiry.seconds,
            });
        }
        let cached = cache
            .as_ref()
            .ok_or(TrafficIdentityError::Unavailable)?
            .clone();
        let credential = TrafficCredential {
            binding: self.clone(),
            generation: generation.clone(),
            token: cached.token,
            expires: cached.expires,
        };
        credential.ensure_current()?;
        Ok(credential)
    }
}

pub(crate) struct TrafficCredential {
    binding: TrafficTargetBinding,
    generation: PolicyGenerationGuard,
    token: SecretJwt,
    expires: i64,
}
impl TrafficCredential {
    pub(crate) fn ensure_current(&self) -> Result<()> {
        self.binding.current()?;
        if self.generation.is_stale() || self.expires <= now_seconds()? {
            return Err(TrafficIdentityError::StaleBinding);
        }
        Ok(())
    }
    pub(crate) fn header(&self, headers: &[u8]) -> miette::Result<Vec<u8>> {
        self.ensure_current().map_err(miette::Report::new)?;
        let mut clean = strip_carrier(headers)?;
        clean.truncate(clean.len() - 2);
        clean.extend_from_slice(TRAFFIC_TOKEN_HEADER.as_bytes());
        clean.extend_from_slice(b": ");
        clean.extend_from_slice(self.token.expose_secret().as_bytes());
        clean.extend_from_slice(b"\r\n\r\n");
        if clean.len() > crate::l7::rest::MAX_HEADER_BYTES {
            return Err(miette::Report::new(TrafficIdentityError::InvalidCredential));
        }
        Ok(clean)
    }
}

pub(crate) fn strip_carrier(raw: &[u8]) -> miette::Result<Vec<u8>> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| miette::Report::new(TrafficIdentityError::Unsupported))?
        + 4;
    let mut clean = crate::l7::rest::strip_header(&raw[..end], TRAFFIC_TOKEN_HEADER)?;
    clean.extend_from_slice(&raw[end..]);
    Ok(clean)
}
pub(crate) fn is_carrier_field(line: &[u8]) -> bool {
    std::str::from_utf8(line).ok().is_some_and(|line| {
        line.split_once(':')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case(TRAFFIC_TOKEN_HEADER))
    })
}
pub(crate) fn response_has_carrier(headers: &[u8]) -> bool {
    String::from_utf8_lossy(headers)
        .split("\r\n")
        .skip(1)
        .any(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case(TRAFFIC_TOKEN_HEADER))
        })
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.ends_with('-')
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now_seconds() -> Result<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TrafficIdentityError::Unavailable)?
            .as_secs(),
    )
    .map_err(|_| TrafficIdentityError::Unavailable)
}

/// Recheck authority even while client or upstream I/O is idle.
pub(crate) struct TrafficBoundStream<'a, S> {
    stream: &'a mut S,
    credential: Option<&'a TrafficCredential>,
    invalid: Option<Pin<Box<dyn Future<Output = ()> + Send + 'a>>>,
    invalidated: bool,
}
impl<'a, S> TrafficBoundStream<'a, S> {
    pub(crate) fn new(stream: &'a mut S, credential: Option<&'a TrafficCredential>) -> Self {
        Self {
            stream,
            credential,
            invalidated: false,
            invalid: credential.map(|c| {
                let future: Pin<Box<dyn Future<Output = ()> + Send + 'a>> =
                    Box::pin(c.wait_until_invalid());
                future
            }),
        }
    }
    fn poll_current(&mut self, cx: &mut Context<'_>) -> std::io::Result<()> {
        if self.invalidated
            || self.credential.is_some_and(|c| c.ensure_current().is_err())
            || self
                .invalid
                .as_mut()
                .is_some_and(|f| f.as_mut().poll(cx).is_ready())
        {
            self.invalidated = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "traffic identity revoked or expired",
            ));
        }
        Ok(())
    }
}
impl TrafficCredential {
    async fn wait_until_invalid(&self) {
        let remaining = u64::try_from(self.expires)
            .ok()
            .and_then(|seconds| UNIX_EPOCH.checked_add(Duration::from_secs(seconds)))
            .and_then(|deadline| deadline.duration_since(SystemTime::now()).ok())
            .unwrap_or_default();
        let expiry = tokio::time::sleep(remaining);
        tokio::pin!(expiry);
        loop {
            let changed = self.binding.state.1.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.ensure_current().is_err() {
                return;
            }
            tokio::select! {
                () = changed.as_mut() => {},
                () = self.generation.wait_until_stale() => return,
                () = expiry.as_mut() => return,
            }
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for TrafficBoundStream<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Err(e) = self.poll_current(cx) {
            return Poll::Ready(Err(e));
        }
        let result = Pin::new(&mut *self.stream).poll_read(cx, buf);
        if result.is_ready()
            && let Err(error) = self.poll_current(cx)
        {
            return Poll::Ready(Err(error));
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for TrafficBoundStream<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Err(e) = self.poll_current(cx) {
            return Poll::Ready(Err(e));
        }
        let result = Pin::new(&mut *self.stream).poll_write(cx, buf);
        if result.is_ready()
            && let Err(error) = self.poll_current(cx)
        {
            return Poll::Ready(Err(error));
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Err(e) = self.poll_current(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut *self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opa::OpaEngine;
    use openshell_core::proto::PolicySource;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Source {
        execution: String,
        calls: AtomicUsize,
        response: Mutex<IssueTrafficTokenResponse>,
        requests: Mutex<Vec<IssueTrafficTokenRequest>>,
        pending: AtomicBool,
    }
    #[async_trait]
    impl TrafficTokenSource for Source {
        fn execution_id(&self) -> &str {
            &self.execution
        }
        async fn issue(
            &self,
            request: IssueTrafficTokenRequest,
        ) -> Result<IssueTrafficTokenResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.requests.lock().unwrap().push(request);
            if self.pending.load(Ordering::SeqCst) {
                return std::future::pending().await;
            }
            tokio::task::yield_now().await;
            Ok(self.response.lock().unwrap().clone())
        }
    }
    fn snapshot() -> SettingsPollResult {
        SettingsPollResult {
            configuration_instance_id: "instance-one".into(),
            configuration_admitted: true,
            configuration_error: String::new(),
            policy: None,
            version: 1,
            policy_hash: "a".repeat(64),
            config_revision: 7,
            policy_source: PolicySource::Sandbox,
            settings: std::collections::HashMap::default(),
            global_policy_version: 0,
            provider_env_revision: 3,
            provider_attachment_epoch: "attachment-one".into(),
            supervisor_middleware_services: vec![],
            traffic_identity_targets: vec![TrafficIdentityTarget {
                name: "shared-gateway".into(),
                https_endpoint: "https://gateway.example.test/".into(),
                audience: "urn:openshell:traffic:shared-gateway".into(),
                tls_ca_cert_pem: vec![],
                transports: vec!["http".into(), "mcp".into()],
                target_sha256: "b".repeat(64),
            }],
            workspace: "default".into(),
            policy_validation_failure_mode: openshell_core::PolicyValidationFailureMode::default(),
            extension_authentication_enabled: true,
        }
    }
    fn response(snapshot: &SettingsPollResult, execution: &str) -> IssueTrafficTokenResponse {
        IssueTrafficTokenResponse {
            token: "synthetic.traffic.credential".into(),
            expiration_time: Some(prost_types::Timestamp {
                seconds: now_seconds().unwrap() + 60,
                nanos: 0,
            }),
            execution_id: execution.into(),
            target: Some(snapshot.traffic_identity_targets[0].clone()),
            configuration_sha256: openshell_core::traffic_identity::configuration_sha256_parts(
                snapshot.config_revision,
                snapshot.provider_env_revision,
                &snapshot.policy_hash,
                &snapshot.provider_attachment_epoch,
                &snapshot.configuration_instance_id,
                &snapshot.traffic_identity_targets[0].target_sha256,
            ),
        }
    }
    fn source(snapshot: &SettingsPollResult) -> Arc<Source> {
        let execution =
            openshell_core::traffic_identity::execution_id("sandbox-one", "generation-one", 1);
        Arc::new(Source {
            response: Mutex::new(response(snapshot, &execution)),
            execution,
            calls: AtomicUsize::new(0),
            requests: Mutex::new(vec![]),
            pending: AtomicBool::new(false),
        })
    }
    fn engine() -> OpaEngine {
        OpaEngine::from_strings("package sandbox\ndefault allow := false", "{}").unwrap()
    }
    fn installed(
        snapshot: &SettingsPollResult,
        engine: &OpaEngine,
    ) -> (TrafficIdentityState, Arc<Source>, TrafficTargetBinding) {
        let state = TrafficIdentityState::default();
        let source = source(snapshot);
        state.configure_source(source.clone()).unwrap();
        state
            .activate(
                state
                    .prepare(snapshot, engine.current_generation())
                    .unwrap(),
            )
            .unwrap();
        let binding = state
            .bind(
                "gateway.example.test",
                443,
                engine.current_generation(),
                true,
            )
            .unwrap()
            .unwrap();
        (state, source, binding)
    }

    #[test]
    fn gateway_source_factory_is_lazy_and_refuses_unsafe_endpoints() {
        let execution =
            openshell_core::traffic_identity::execution_id("sandbox-one", "generation-one", 1);
        let source =
            GatewayTrafficTokenSource::new("https://gateway.example.test/", execution.clone())
                .unwrap();
        assert!(source.client.get().is_none());
        for endpoint in [
            "http://gateway.example.test/",
            "https://secret@gateway.example.test/",
            "https://gateway.example.test/?secret=x",
            "https://gateway.example.test/#secret",
            "https://gateway.example.test/path",
            "https://gateway.example.test:0/",
        ] {
            assert!(GatewayTrafficTokenSource::new(endpoint, execution.clone()).is_err());
        }
        assert!(
            GatewayTrafficTokenSource::new(
                "https://gateway.example.test/",
                "invalid-execution".into()
            )
            .is_err()
        );
    }

    #[test]
    fn observed_destination_rejects_before_activation_even_when_tls_preparation_fails() {
        let engine = engine();
        let mut snap = snapshot();
        let state = TrafficIdentityState::default();
        state.configure_source(source(&snap)).unwrap();
        snap.traffic_identity_targets[0].tls_ca_cert_pem = b"invalid certificate".to_vec();
        state.observe_snapshot(&snap).unwrap();
        assert!(state.prepare(&snap, engine.current_generation()).is_err());
        state.revoke();
        assert!(
            state
                .requires_identity("gateway.example.test", 443)
                .unwrap()
        );
        assert!(
            state
                .bind(
                    "gateway.example.test",
                    443,
                    engine.current_generation(),
                    true
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn duplicated_descriptors_cannot_reuse_an_active_snapshot() {
        let engine = engine();
        let mut snap = snapshot();
        let mut other = snap.traffic_identity_targets[0].clone();
        other.name = "other-gateway".into();
        other.https_endpoint = "https://other.example.test/".into();
        snap.traffic_identity_targets.push(other);
        let (state, _, _) = installed(&snap, &engine);
        snap.traffic_identity_targets[1] = snap.traffic_identity_targets[0].clone();
        assert!(!state.matches_snapshot(&snap, engine.current_generation()));
        assert!(state.prepare(&snap, engine.current_generation()).is_err());
    }

    #[tokio::test]
    async fn issuance_is_single_flight_and_binds_exact_snapshot() {
        let engine = engine();
        let snap = snapshot();
        let (_, source, binding) = installed(&snap, &engine);
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let (a, b) = tokio::join!(
            binding.credential(TrafficTransport::Http, &guard),
            binding.credential(TrafficTransport::Mcp, &guard)
        );
        a.unwrap().ensure_current().unwrap();
        b.unwrap().ensure_current().unwrap();
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
        let requests = source.requests.lock().unwrap();
        assert_eq!(
            requests[0].target_name,
            snap.traffic_identity_targets[0].name
        );
        assert_eq!(requests[0].expected_execution_id, source.execution);
        assert_eq!(requests[0].expected_config_revision, snap.config_revision);
        assert_eq!(
            requests[0].expected_target_sha256,
            snap.traffic_identity_targets[0].target_sha256
        );
        assert!(!format!("{binding:?}").contains("synthetic"));
    }

    #[tokio::test]
    async fn replacement_without_policy_change_invalidates_credentials() {
        let engine = engine();
        let mut snap = snapshot();
        let (state, source, old) = installed(&snap, &engine);
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let credential = old
            .credential(TrafficTransport::Http, &guard)
            .await
            .unwrap();
        assert!(state.matches_snapshot(&snap, engine.current_generation()));
        snap.configuration_instance_id = "instance-two".into();
        assert!(!state.matches_snapshot(&snap, engine.current_generation()));
        state
            .activate(state.prepare(&snap, engine.current_generation()).unwrap())
            .unwrap();
        assert!(credential.ensure_current().is_err());
        assert!(
            old.credential(TrafficTransport::Http, &guard)
                .await
                .is_err()
        );
        *source.response.lock().unwrap() = response(&snap, &source.execution);
        let new = state
            .bind(
                "gateway.example.test",
                443,
                engine.current_generation(),
                true,
            )
            .unwrap()
            .unwrap();
        new.credential(TrafficTransport::Http, &guard)
            .await
            .unwrap();
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn revocation_preserves_deny_destination_and_recovery_reissues() {
        let engine = engine();
        let snap = snapshot();
        let (state, source, binding) = installed(&snap, &engine);
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let old = binding
            .credential(TrafficTransport::Http, &guard)
            .await
            .unwrap();
        state.revoke();
        assert!(
            state
                .requires_identity("gateway.example.test", 443)
                .unwrap()
        );
        assert!(
            state
                .bind(
                    "gateway.example.test",
                    443,
                    engine.current_generation(),
                    true
                )
                .is_err()
        );
        assert!(!state.matches_snapshot(&snap, engine.current_generation()));
        state
            .activate(state.prepare(&snap, engine.current_generation()).unwrap())
            .unwrap();
        assert!(old.ensure_current().is_err());
        let new = state
            .bind(
                "gateway.example.test",
                443,
                engine.current_generation(),
                true,
            )
            .unwrap()
            .unwrap();
        new.credential(TrafficTransport::Http, &guard)
            .await
            .unwrap();
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn unchanged_snapshot_preserves_cache_independent_of_descriptor_order() {
        let engine = engine();
        let mut snap = snapshot();
        let mut second = snap.traffic_identity_targets[0].clone();
        second.name = "another-gateway".into();
        second.https_endpoint = "https://another.example.test/".into();
        snap.traffic_identity_targets.push(second);
        let (state, source, binding) = installed(&snap, &engine);
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let credential = binding
            .credential(TrafficTransport::Http, &guard)
            .await
            .unwrap();
        snap.traffic_identity_targets.reverse();
        state
            .activate(state.prepare(&snap, engine.current_generation()).unwrap())
            .unwrap();
        credential.ensure_current().unwrap();
        binding
            .credential(TrafficTransport::Http, &guard)
            .await
            .unwrap();
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn requires_authenticated_boundary_and_current_policy_generation() {
        let engine = engine();
        let (state, source, _) = installed(&snapshot(), &engine);
        assert!(
            state
                .bind(
                    "gateway.example.test",
                    443,
                    engine.current_generation(),
                    false
                )
                .is_err()
        );
        assert!(
            state
                .bind(
                    "gateway.example.test",
                    443,
                    engine.current_generation() + 1,
                    true
                )
                .is_err()
        );
        assert!(
            state
                .bind(
                    "unregistered.example.test",
                    443,
                    engine.current_generation(),
                    false
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn refuses_invalid_descriptors_and_duplicate_names() {
        for field in 0..14 {
            let engine = engine();
            let mut snap = snapshot();
            let source = source(&snap);
            let state = TrafficIdentityState::default();
            state.configure_source(source).unwrap();
            let target = &mut snap.traffic_identity_targets[0];
            match field {
                0=>target.https_endpoint="http://gateway.example.test/".into(),
                1=>target.https_endpoint="https://secret@gateway.example.test/".into(),
                2=>target.https_endpoint="https://127.0.0.1/".into(),
                3=>target.https_endpoint="https://gateway.example.test./".into(),
                4=>target.https_endpoint="https://gateway.example.test/path".into(),
                5=>target.https_endpoint="https://gateway.example.test/?secret=x".into(),
                6=>target.name="BAD NAME".into(), 7=>target.audience="urn:openshell:traffic:".into(),
                8=>target.audience="urn:openshell:traffic:secret\r\n".into(),
                9=>target.transports=vec!["http".into(),"http".into()],
                10=>target.target_sha256="B".repeat(64),
                11=>target.tls_ca_cert_pem=b"-----BEGIN OPENSSH PRIVATE KEY-----\nYWJj\n-----END OPENSSH PRIVATE KEY-----\n".to_vec(),
                12=>snap.configuration_admitted=false,
                _=>{ let mut other=target.clone(); other.https_endpoint="https://other.example.test/".into(); snap.traffic_identity_targets.push(other); }
            }
            assert!(
                state.prepare(&snap, engine.current_generation()).is_err(),
                "case {field}"
            );
        }
    }

    #[tokio::test]
    async fn refuses_substituted_expired_and_malformed_issuance() {
        for field in 0..9 {
            let engine = engine();
            let (_, source, binding) = installed(&snapshot(), &engine);
            {
                let mut reply = source.response.lock().unwrap();
                match field {
                    0 => reply.execution_id.push('x'),
                    1 => reply.configuration_sha256 = "c".repeat(64),
                    2 => reply.target.as_mut().unwrap().audience.push('x'),
                    3 => reply.expiration_time = None,
                    4 => {
                        reply.expiration_time.as_mut().unwrap().seconds =
                            now_seconds().unwrap() + 14;
                    }
                    5 => {
                        reply.expiration_time.as_mut().unwrap().seconds =
                            now_seconds().unwrap() + 66;
                    }
                    6 => reply.token = "synthetic\r\nsecret".into(),
                    7 => reply.token = "x".repeat(8193),
                    _ => reply.expiration_time.as_mut().unwrap().nanos = -1,
                }
            }
            let guard = engine
                .generation_guard(engine.current_generation())
                .unwrap();
            let error = binding
                .credential(TrafficTransport::Http, &guard)
                .await
                .err()
                .unwrap();
            assert!(!format!("{error}").contains("synthetic"));
            assert!(binding.target.cache.lock().await.is_none());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_issuance_queue_shares_one_absolute_deadline() {
        let engine = engine();
        let (_, source, binding) = installed(&snapshot(), &engine);
        source.pending.store(true, Ordering::SeqCst);
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let started = tokio::time::Instant::now();
        let (a, b) = tokio::join!(
            binding.credential(TrafficTransport::Http, &guard),
            binding.credential(TrafficTransport::Mcp, &guard)
        );
        assert!(a.is_err() && b.is_err());
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
        assert!(started.elapsed() <= ISSUANCE_DEADLINE);
    }

    #[tokio::test(start_paused = true)]
    async fn issuance_timeout_never_uses_old_cache() {
        let engine = engine();
        let (_, source, binding) = installed(&snapshot(), &engine);
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        binding
            .credential(TrafficTransport::Http, &guard)
            .await
            .unwrap();
        binding.target.cache.lock().await.as_mut().unwrap().expires = now_seconds().unwrap() + 14;
        source.pending.store(true, Ordering::SeqCst);
        assert!(
            binding
                .credential(TrafficTransport::Http, &guard)
                .await
                .is_err()
        );
        assert!(binding.target.cache.lock().await.is_none());
    }

    #[tokio::test]
    async fn idle_read_and_write_wake_on_revocation() {
        for (policy_revoke, blocked_write) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let engine = engine();
            let (state, _, binding) = installed(&snapshot(), &engine);
            let guard = engine
                .generation_guard(engine.current_generation())
                .unwrap();
            let credential = binding
                .credential(TrafficTransport::Http, &guard)
                .await
                .unwrap();
            let (mut upstream, _peer) = tokio::io::duplex(1);
            let mut bound = TrafficBoundStream::new(&mut upstream, Some(&credential));
            bound.write_all(b"a").await.unwrap();
            let invalidation = async {
                tokio::task::yield_now().await;
                if policy_revoke {
                    engine.enter_fail_closed("synthetic test").unwrap();
                } else {
                    state.revoke();
                }
            };
            let read = async {
                if blocked_write {
                    bound.write_all(b"b").await.map(|()| 0)
                } else {
                    let mut byte = [0];
                    bound.read(&mut byte).await
                }
            };
            let ((), result) = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(invalidation, read)
            })
            .await
            .unwrap();
            assert_eq!(
                result.unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                bound.write_all(b"b").await.unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_read_wakes_on_credential_expiry() {
        let engine = engine();
        let (_, _, binding) = installed(&snapshot(), &engine);
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let mut credential = binding
            .credential(TrafficTransport::Http, &guard)
            .await
            .unwrap();
        credential.expires = now_seconds().unwrap() + 1;
        let (mut upstream, _peer) = tokio::io::duplex(1);
        let mut bound = TrafficBoundStream::new(&mut upstream, Some(&credential));
        let mut byte = [0];
        assert_eq!(
            bound.read(&mut byte).await.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            bound.read(&mut byte).await.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn strips_workload_carrier_without_changing_binary_body_or_provider_auth() {
        let mut raw=b"POST /mcp HTTP/1.1\r\nAuthorization: Bearer provider\r\nX-OpenShield-Traffic-Token: forged\r\nx-openshield-traffic-token: second\r\nContent-Length: 3\r\n\r\n".to_vec();
        raw.extend_from_slice(&[0, 255, 1]);
        let stripped = strip_carrier(&raw).unwrap();
        assert!(stripped.ends_with(&[0, 255, 1]));
        assert!(
            stripped
                .windows(b"Authorization: Bearer provider".len())
                .any(|w| w == b"Authorization: Bearer provider")
        );
        assert!(!response_has_carrier(&stripped[..stripped.len() - 3]));
        let parsed =
            crate::l7::rest::request_from_buffered_http("POST", "/mcp", "/mcp", raw).unwrap();
        assert_eq!(parsed.raw_header, stripped);
    }

    #[tokio::test]
    async fn final_relay_injects_after_connection_cleanup_and_preserves_provider_auth() {
        let engine = engine();
        let (_, _, binding) = installed(&snapshot(), &engine);
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let credential = binding
            .credential(TrafficTransport::Mcp, &guard)
            .await
            .unwrap();
        let raw=b"POST /mcp HTTP/1.1\r\nHost: gateway.example.test\r\nAuthorization: Bearer provider\r\nConnection: x-openshield-traffic-token\r\nx-openshield-traffic-token: forged\r\nContent-Length: 2\r\n\r\n{}".to_vec();
        let request =
            crate::l7::rest::request_from_buffered_http("POST", "/mcp", "/mcp", raw).unwrap();
        let (mut upstream, mut server) = tokio::io::duplex(4096);
        let backend = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut byte = [0];
            while !received.ends_with(b"\r\n\r\n{}") {
                server.read_exact(&mut byte).await.unwrap();
                received.push(byte[0]);
            }
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            received
        });
        let (mut client, mut caller) = tokio::io::duplex(4096);
        crate::l7::rest::relay_http_request_with_options_guarded(
            &request,
            &mut client,
            &mut upstream,
            crate::l7::rest::RelayRequestOptions {
                generation_guard: Some(&guard),
                traffic_credential: Some(&credential),
                host: "gateway.example.test",
                port: 443,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let received = String::from_utf8(backend.await.unwrap()).unwrap();
        assert_eq!(received.matches("x-openshield-traffic-token:").count(), 1);
        assert!(received.contains("x-openshield-traffic-token: synthetic.traffic.credential\r\n"));
        assert!(received.contains("Authorization: Bearer provider\r\n"));
        assert!(!received.contains("forged"));
        drop(client);
        let mut delivered = Vec::new();
        caller.read_to_end(&mut delivered).await.unwrap();
        assert!(
            !delivered
                .windows(b"synthetic".len())
                .any(|w| w == b"synthetic")
        );
    }

    #[tokio::test]
    async fn explicit_tls_roots_require_matching_certificate_and_hostname() {
        let cert = rcgen::generate_simple_self_signed(vec!["gateway.example.test".into()]).unwrap();
        let other =
            rcgen::generate_simple_self_signed(vec!["foreign.example.test".into()]).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
            )
            .unwrap();
        for (correct_root, correct_name) in [(true, true), (false, true), (true, false)] {
            let engine = engine();
            let mut snap = snapshot();
            snap.traffic_identity_targets[0].tls_ca_cert_pem = if correct_root {
                cert.cert.pem()
            } else {
                other.cert.pem()
            }
            .into_bytes();
            let (_, source, binding) = installed(&snap, &engine);
            let (client, server) = tokio::io::duplex(8192);
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config.clone()));
            let connector = tokio_rustls::TlsConnector::from(binding.tls_config().clone());
            let name = rustls::pki_types::ServerName::try_from(if correct_name {
                "gateway.example.test"
            } else {
                "spoof.example.test"
            })
            .unwrap();
            let (connected, _accepted) =
                tokio::join!(connector.connect(name, client), acceptor.accept(server));
            assert_eq!(connected.is_ok(), correct_root && correct_name);
            assert_eq!(source.calls.load(Ordering::SeqCst), 0);
        }
    }
}
