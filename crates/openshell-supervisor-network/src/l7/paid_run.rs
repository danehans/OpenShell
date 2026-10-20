// SPDX-License-Identifier: Apache-2.0
//! Opt-in, finite manual M1 admission. Not an account-wide dollar budget.
//!
//! Both supervisors must bind the SAME private ledger inode, inaccessible to
//! workloads, and deny alternate credentialed routes in policy. No creation,
//! refund, replenishment or recovery occurs here. A torn append refuses closed.
use super::provider::{BodyLength, L7Request};
use miette::{Result, miette};
use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
use tokio::io::{AsyncRead, AsyncReadExt};

const MAX_BODY: usize = 262_144;
const MODEL: &str = "gpt-5.4-mini-2026-03-17";
const REFUSAL: &str = "manual paid-run admission refused";

// serde_json::Value normally accepts duplicate keys with last-wins semantics.
// This closed request contract rejects them at EVERY object depth instead.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bounded unique-key JSON")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut m = serde_json::Map::new();
                while let Some((k, v)) = a.next_entry::<String, Unique>()? {
                    if m.insert(k, v.0).is_some() {
                        return Err(de::Error::custom("duplicate field"));
                    }
                }
                Ok(Unique(Value::Object(m)))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut v = Vec::new();
                while let Some(x) = a.next_element::<Unique>()? {
                    v.push(x.0);
                }
                Ok(Unique(Value::Array(v)))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
        }
        d.deserialize_any(V)
    }
}

fn normalize(body: &[u8]) -> Result<Vec<u8>> {
    let mut d = serde_json::Deserializer::from_slice(body);
    let Unique(v) = Unique::deserialize(&mut d).map_err(|_| miette!(REFUSAL))?;
    d.end().map_err(|_| miette!(REFUSAL))?;
    let mut m = v.as_object().cloned().ok_or_else(|| miette!(REFUSAL))?;
    // Deliberately finite Responses input surface. Unknown billable features
    // never pass through. No prompt/body values are logged or persisted.
    const ALLOWED: &[&str] = &[
        "model",
        "input",
        "instructions",
        "stream",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "reasoning",
        "text",
        "store",
        "include",
        "prompt_cache_key",
        "max_output_tokens",
        "service_tier",
        "background",
        "truncation",
    ];
    if m.keys().any(|k| !ALLOWED.contains(&k.as_str()))
        || m.get("model").and_then(Value::as_str) != Some(MODEL)
        || !m.get("input").is_some_and(Value::is_array)
        || !matches!(m.get("stream"), Some(Value::Bool(_)))
    {
        return Err(miette!(REFUSAL));
    }
    if m.get("background")
        .is_some_and(|v| v != &Value::Bool(false))
        || m.get("service_tier")
            .is_some_and(|v| v.as_str() != Some("default"))
        || m.get("max_output_tokens")
            .is_some_and(|v| v.as_u64().is_none_or(|n| n < 16 || n > 128))
    {
        return Err(miette!(REFUSAL));
    }
    // Text and bounded prior reasoning context from the pinned Codex protocol
    // are input billing, including encrypted context. No media, file, remote
    // reference, tool result or hosted operation can enter this closed profile.
    for item in m["input"].as_array().ok_or_else(|| miette!(REFUSAL))? {
        let o = item.as_object().ok_or_else(|| miette!(REFUSAL))?;
        if o.get("id").is_some_and(|v| !v.is_string() && !v.is_null()) {
            return Err(miette!(REFUSAL));
        }
        if let Some(meta) = o.get("internal_chat_message_metadata_passthrough") {
            if !meta.is_null() {
                let meta = meta.as_object().ok_or_else(|| miette!(REFUSAL))?;
                if meta.keys().any(|k| k != "turn_id")
                    || meta
                        .get("turn_id")
                        .is_some_and(|v| !v.is_string() && !v.is_null())
                {
                    return Err(miette!(REFUSAL));
                }
            }
        }
        if o.get("type").and_then(Value::as_str) == Some("reasoning") {
            if o.keys().any(|k| {
                ![
                    "type",
                    "id",
                    "summary",
                    "content",
                    "encrypted_content",
                    "internal_chat_message_metadata_passthrough",
                ]
                .contains(&k.as_str())
            }) || o
                .get("encrypted_content")
                .is_some_and(|v| !v.is_string() && !v.is_null())
            {
                return Err(miette!(REFUSAL));
            }
            for (key, kind) in [("summary", "summary_text"), ("content", "reasoning_text")] {
                if let Some(v) = o.get(key).filter(|v| !v.is_null()) {
                    for p in v.as_array().ok_or_else(|| miette!(REFUSAL))? {
                        let p = p.as_object().ok_or_else(|| miette!(REFUSAL))?;
                        if p.len() != 2
                            || p.get("type").and_then(Value::as_str) != Some(kind)
                            || !p.get("text").is_some_and(Value::is_string)
                        {
                            return Err(miette!(REFUSAL));
                        }
                    }
                } else if key == "summary" {
                    return Err(miette!(REFUSAL));
                }
            }
            continue;
        }
        if o.keys().any(|k| {
            ![
                "type",
                "role",
                "content",
                "id",
                "phase",
                "internal_chat_message_metadata_passthrough",
            ]
            .contains(&k.as_str())
        }) || o.get("type").is_some_and(|v| v.as_str() != Some("message"))
            || !matches!(
                o.get("role").and_then(Value::as_str),
                Some("user" | "assistant" | "developer" | "system")
            )
            || o.get("phase").is_some_and(|v| {
                !v.is_null() && !matches!(v.as_str(), Some("commentary" | "final_answer"))
            })
        {
            return Err(miette!(REFUSAL));
        }
        for part in o
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| miette!(REFUSAL))?
        {
            let p = part.as_object().ok_or_else(|| miette!(REFUSAL))?;
            if p.len() != 2
                || !p.get("text").is_some_and(Value::is_string)
                || !matches!(
                    p.get("type").and_then(Value::as_str),
                    Some("input_text" | "output_text")
                )
            {
                return Err(miette!(REFUSAL));
            }
        }
    }
    if m.get("instructions").is_some_and(|v| !v.is_string()) {
        return Err(miette!(REFUSAL));
    }
    // The manual benign profile deliberately disables all function definitions
    // supplied by the agent; it is NOT general tool-use qualification.
    if m.get("tools").is_some_and(|v| {
        v.as_array().is_none_or(|a| {
            a.iter()
                .any(|t| t.get("type").and_then(Value::as_str) != Some("function"))
        })
    }) {
        return Err(miette!(REFUSAL));
    }
    // Force the billing-relevant final values rather than trusting a client
    // default. max_output_tokens includes reasoning and visible output tokens.
    m.insert("tools".into(), serde_json::json!([]));
    m.insert("tool_choice".into(), "none".into());
    m.insert("parallel_tool_calls".into(), false.into());
    m.insert(
        "max_output_tokens".into(),
        m.get("max_output_tokens").cloned().unwrap_or(128.into()),
    );
    m.insert("service_tier".into(), "default".into());
    m.insert("background".into(), false.into());
    m.insert("store".into(), false.into());
    // Only text output. Explicit schema/format overrides cannot reintroduce
    // another modality or billed tool. Other tuning is intentionally dropped.
    m.insert("text".into(), serde_json::json!({"format":{"type":"text"}}));
    m.remove("include");
    m.remove("prompt_cache_key");
    let out = serde_json::to_vec(&m).map_err(|_| miette!(REFUSAL))?;
    if out.len() > MAX_BODY {
        return Err(miette!(REFUSAL));
    }
    Ok(out)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u8,
    run: String,
    boot: String,
    deadline_ms: u64,
    requests: u8,
}

#[cfg(unix)]
fn consume_at(path: &Path, run: &str, boot: &str, now_ms: u64) -> Result<u64> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut f = OpenOptions::new()
        .read(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| miette!(REFUSAL))?;
    let md = f.metadata().map_err(|_| miette!(REFUSAL))?;
    if !md.is_file()
        || md.mode() & 0o7777 != 0o600
        || md.nlink() != 1
        || md.uid() != unsafe { libc::geteuid() }
    {
        return Err(miette!(REFUSAL));
    }
    // Nonblocking contention refuses, never waits behind an unbounded holder.
    f.try_lock().map_err(|_| miette!(REFUSAL))?;
    let mut raw = Vec::new();
    (&mut f)
        .take(4097)
        .read_to_end(&mut raw)
        .map_err(|_| miette!(REFUSAL))?;
    if raw.len() > 4096 || !raw.ends_with(b"\n") {
        return Err(miette!(REFUSAL));
    }
    let mut lines = raw.split_inclusive(|b| *b == b'\n');
    let header = lines.next().ok_or_else(|| miette!(REFUSAL))?;
    let l: Ledger = serde_json::from_slice(header).map_err(|_| miette!(REFUSAL))?;
    let used = lines
        .try_fold(0u8, |n, line| {
            if line == b"1\n" {
                n.checked_add(1)
            } else {
                None
            }
        })
        .ok_or_else(|| miette!(REFUSAL))?;
    if l.version != 1
        || l.run != run
        || run.len() != 32
        || !run.bytes().all(|c| c.is_ascii_hexdigit())
        || l.boot != boot
        || l.requests == 0
        || l.requests > 8
        || used >= l.requests
        || l.deadline_ms <= now_ms
        || l.deadline_ms - now_ms > 300_000
    {
        return Err(miette!(REFUSAL));
    }
    let named = std::fs::symlink_metadata(path).map_err(|_| miette!(REFUSAL))?;
    if named.dev() != md.dev() || named.ino() != md.ino() {
        return Err(miette!(REFUSAL));
    }
    f.seek(SeekFrom::End(0)).map_err(|_| miette!(REFUSAL))?;
    // Permission is returned ONLY after append durability. Failure, cancellation
    // or uncertain response never refunds this record; malformed tails refuse.
    f.write_all(b"1\n")
        .and_then(|()| f.sync_all())
        .map_err(|_| miette!(REFUSAL))?;
    Ok(l.deadline_ms)
}

#[cfg(target_os = "linux")]
fn boot_now() -> Result<(String, u64)> {
    let boot =
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| miette!(REFUSAL))?;
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0 || ts.tv_sec < 0 {
        return Err(miette!(REFUSAL));
    }
    Ok((
        boot.trim().to_owned(),
        (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000,
    ))
}
#[cfg(target_os = "linux")]
fn consume(path: &Path, run: &str) -> Result<Permit> {
    let (boot, now) = boot_now()?;
    let deadline = consume_at(path, run, &boot, now)?;
    let (_, closing) = boot_now()?;
    if closing >= deadline {
        return Err(miette!(REFUSAL));
    }
    Ok(Permit {
        window: std::sync::Arc::new(LinuxBootWindow::new(deadline)?),
    })
}
#[cfg(not(target_os = "linux"))]
fn consume(_path: &Path, _run: &str) -> Result<Permit> {
    Err(miette!(REFUSAL))
}

// Authority stays in the original clock domain. The timer must wake pending
// work after suspend; a monotonic-duration translation is NOT an expiry timer.
trait BootWindow: Send + Sync {
    fn check(&self) -> std::io::Result<()>;
    fn poll_expired(&self, cx: &mut std::task::Context<'_>)
    -> std::task::Poll<std::io::Result<()>>;
}
fn expired() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "manual paid-run expired or unmeasurable",
    )
}
#[cfg(target_os = "linux")]
struct LinuxBootWindow {
    deadline_ms: u64,
    timer: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
}
#[cfg(target_os = "linux")]
impl LinuxBootWindow {
    fn new(deadline_ms: u64) -> Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        // SAFETY: no pointer arguments; the successful descriptor is immediately
        // owned and closed on every later error/drop, never inherited by exec.
        let raw = unsafe {
            libc::timerfd_create(libc::CLOCK_BOOTTIME, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC)
        };
        if raw < 0 {
            return Err(miette!(REFUSAL));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let spec = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: (deadline_ms / 1000)
                    .try_into()
                    .map_err(|_| miette!(REFUSAL))?,
                tv_nsec: ((deadline_ms % 1000) * 1_000_000) as _,
            },
        };
        // SAFETY: valid initialized input, no old-value output requested. This
        // absolute BOOTTIME deadline is set once, never renewed on a wakeup.
        if unsafe {
            libc::timerfd_settime(
                fd.as_raw_fd(),
                libc::TFD_TIMER_ABSTIME,
                &spec,
                std::ptr::null_mut(),
            )
        } != 0
        {
            return Err(miette!(REFUSAL));
        }
        let timer = tokio::io::unix::AsyncFd::new(fd).map_err(|_| miette!(REFUSAL))?;
        Ok(Self { deadline_ms, timer })
    }
}
#[cfg(target_os = "linux")]
impl BootWindow for LinuxBootWindow {
    fn check(&self) -> std::io::Result<()> {
        if boot_now().is_ok_and(|(_, now)| now < self.deadline_ms) {
            Ok(())
        } else {
            Err(expired())
        }
    }
    fn poll_expired(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        if let Err(e) = self.check() {
            return Poll::Ready(Err(e));
        }
        // No readiness clearing/read: this one-shot timer is terminal. Retaining
        // its ready state prevents another poll from treating expiry as fresh.
        match self.timer.poll_read_ready(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}
pub(super) struct Permit {
    window: std::sync::Arc<dyn BootWindow>,
}
impl Permit {
    fn check(&self) -> std::io::Result<()> {
        self.window.check()
    }
}
/// Poll expiry before the relay and register its original-clock wakeup even
/// when all I/O is idle. Drop/cancel the original future on expiry or clock
/// failure; no replacement timer, admission or ledger refund is created.
pub(super) async fn within<T, F: Future<Output = Result<T>>>(
    permit: Option<&Permit>,
    relay: F,
) -> Result<T> {
    let Some(p) = permit else {
        return relay.await;
    };
    let mut relay = std::pin::pin!(relay);
    std::future::poll_fn(|cx| {
        if p.window.poll_expired(cx).is_ready() {
            return std::task::Poll::Ready(Err(miette!(REFUSAL)));
        }
        if p.check().is_err() {
            return std::task::Poll::Ready(Err(miette!(REFUSAL)));
        }
        match relay.as_mut().poll(cx) {
            std::task::Poll::Ready(r) => {
                if p.check().is_err() {
                    std::task::Poll::Ready(Err(miette!(REFUSAL)))
                } else {
                    std::task::Poll::Ready(r)
                }
            }
            std::task::Poll::Pending => {
                if p.check().is_err() {
                    std::task::Poll::Ready(Err(miette!(REFUSAL)))
                } else {
                    std::task::Poll::Pending
                }
            }
        }
    })
    .await
}

/// Covers BOTH directions, including already buffered responses written to the
/// client and flush/shutdown of buffered transports. Default-off delegates.
pub(super) struct WindowIo<'a, T> {
    inner: T,
    permit: Option<&'a Permit>,
}
impl<'a, T> WindowIo<'a, T> {
    pub(super) fn new(inner: T, permit: Option<&'a Permit>) -> Self {
        Self { inner, permit }
    }
    fn check(&self) -> std::io::Result<()> {
        self.permit.map_or(Ok(()), Permit::check)
    }
}
impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for WindowIo<'_, T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Err(e) = this.check() {
            return std::task::Poll::Ready(Err(e));
        }
        let before = buf.filled().len();
        let r = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Err(e) = this.check() {
            buf.set_filled(before);
            return std::task::Poll::Ready(Err(e));
        }
        r
    }
}
impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for WindowIo<'_, T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if let Err(e) = this.check() {
            return std::task::Poll::Ready(Err(e));
        }
        let r = std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Err(e) = this.check() {
            return std::task::Poll::Ready(Err(e));
        }
        r
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Err(e) = this.check() {
            return std::task::Poll::Ready(Err(e));
        }
        let r = std::pin::Pin::new(&mut this.inner).poll_flush(cx);
        if let Err(e) = this.check() {
            return std::task::Poll::Ready(Err(e));
        }
        r
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Err(e) = this.check() {
            return std::task::Poll::Ready(Err(e));
        }
        let r = std::pin::Pin::new(&mut this.inner).poll_shutdown(cx);
        if let Err(e) = this.check() {
            return std::task::Poll::Ready(Err(e));
        }
        r
    }
}

pub(super) struct Prepared {
    pub request: L7Request,
    pub permit: Permit,
}

/// Applies only when explicitly activated by the trusted supervisor launcher.
/// Gate errors escape before header rewriting and EVERY upstream write here.
pub(super) async fn prepare<C: AsyncRead + Unpin>(
    req: &L7Request,
    client: &mut C,
    host: &str,
    port: u16,
) -> Result<Option<Prepared>> {
    let Some(path) = std::env::var_os("OPENSHELL_M1_PAID_LEDGER") else {
        if std::env::var_os("OPENSHELL_M1_PAID_RUN").is_some() {
            return Err(miette!(REFUSAL));
        }
        return Ok(None);
    };
    let run = std::env::var("OPENSHELL_M1_PAID_RUN").map_err(|_| miette!(REFUSAL))?;
    prepare_active(req, client, host, port, Path::new(&path), &run, consume).await
}

async fn prepare_active<C: AsyncRead + Unpin, F: FnOnce(&Path, &str) -> Result<Permit>>(
    req: &L7Request,
    client: &mut C,
    host: &str,
    port: u16,
    path: &Path,
    run: &str,
    admit: F,
) -> Result<Option<Prepared>> {
    let header_end = req
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| miette!(REFUSAL))?
        + 4;
    if host != "api.openai.com"
        || port != 443
        || req.action != "POST"
        || req.target != "/v1/responses"
        || !req.query_params.is_empty()
    {
        return Err(miette!(REFUSAL));
    }
    let header =
        std::str::from_utf8(&req.raw_header[..header_end]).map_err(|_| miette!(REFUSAL))?;
    let mut fields = BTreeMap::new();
    for line in header.split("\r\n").skip(1).filter(|s| !s.is_empty()) {
        let (k, v) = line.split_once(':').ok_or_else(|| miette!(REFUSAL))?;
        if fields.insert(k.to_ascii_lowercase(), v.trim()).is_some() {
            return Err(miette!(REFUSAL));
        }
    }
    if fields.contains_key("transfer-encoding")
        || fields.contains_key("content-encoding")
        || fields.contains_key("upgrade")
        || ["openai-project", "openai-organization", "openai-beta"]
            .iter()
            .any(|k| fields.contains_key(*k))
        || !matches!(
            fields.get("host").copied(),
            Some("api.openai.com" | "api.openai.com:443")
        )
        || fields
            .get("content-type")
            .is_none_or(|s| *s != "application/json")
    {
        return Err(miette!(REFUSAL));
    }
    let BodyLength::ContentLength(n) = req.body_length else {
        return Err(miette!(REFUSAL));
    };
    if n == 0
        || n > MAX_BODY as u64
        || fields
            .get("content-length")
            .and_then(|s| s.parse::<u64>().ok())
            != Some(n)
    {
        return Err(miette!(REFUSAL));
    }
    let mut body = req.raw_header[header_end..].to_vec();
    if body.len() > n as usize {
        return Err(miette!(REFUSAL));
    }
    let have = body.len();
    body.resize(n as usize, 0);
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_exact(&mut body[have..]),
    )
    .await
    .map_err(|_| miette!(REFUSAL))?
    .map_err(|_| miette!(REFUSAL))?;
    let body = normalize(&body)?;
    let permit = admit(path, run)?;
    let mut raw = Vec::new();
    raw.extend_from_slice(
        header
            .lines()
            .next()
            .ok_or_else(|| miette!(REFUSAL))?
            .trim_end_matches('\r')
            .as_bytes(),
    );
    raw.extend_from_slice(b"\r\n");
    for line in header.split("\r\n").skip(1).filter(|s| !s.is_empty()) {
        if !line
            .split_once(':')
            .is_some_and(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        {
            raw.extend_from_slice(line.as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
    }
    raw.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    raw.extend_from_slice(&body);
    Ok(Some(Prepared {
        permit,
        request: L7Request {
            action: req.action.clone(),
            target: req.target.clone(),
            query_params: req.query_params.clone(),
            raw_header: raw,
            body_length: BodyLength::ContentLength(body.len() as u64),
        },
    }))
}

#[cfg(all(test, unix))]
struct TestBootWindow {
    now: std::sync::atomic::AtomicU64,
    measurable: std::sync::atomic::AtomicBool,
    deadline: u64,
    waker: futures::task::AtomicWaker,
}
#[cfg(all(test, unix))]
impl TestBootWindow {
    fn advance(&self, now: u64) {
        self.now.store(now, std::sync::atomic::Ordering::SeqCst);
        self.waker.wake();
    }
    fn unavailable(&self) {
        self.measurable
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.waker.wake();
    }
}
#[cfg(all(test, unix))]
impl BootWindow for TestBootWindow {
    fn check(&self) -> std::io::Result<()> {
        if self.measurable.load(std::sync::atomic::Ordering::SeqCst)
            && self.now.load(std::sync::atomic::Ordering::SeqCst) < self.deadline
        {
            Ok(())
        } else {
            Err(expired())
        }
    }
    fn poll_expired(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.waker.register(cx.waker());
        match self.check() {
            Ok(()) => std::task::Poll::Pending,
            Err(e) => std::task::Poll::Ready(Err(e)),
        }
    }
}
#[cfg(all(test, unix))]
fn test_window(deadline: u64) -> (Permit, std::sync::Arc<TestBootWindow>) {
    let w = std::sync::Arc::new(TestBootWindow {
        now: std::sync::atomic::AtomicU64::new(1),
        measurable: std::sync::atomic::AtomicBool::new(true),
        deadline,
        waker: futures::task::AtomicWaker::new(),
    });
    (Permit { window: w.clone() }, w)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    const RUN: &str = "0123456789abcdef0123456789abcdef";
    fn body() -> Value {
        serde_json::json!({"model":MODEL,"stream":true,"input":[{"role":"user","content":[{"type":"input_text","text":"benign"}]}],"tools":[{"type":"function","name":"shell"}]})
    }
    fn ledger() -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        writeln!(f,"{}",serde_json::json!({"version":1,"run":RUN,"boot":"boot","deadline_ms":300001,"requests":8})).unwrap();
        f.as_file().sync_all().unwrap();
        f
    }
    #[test]
    fn paid_normalizes_final_billing_fields_and_counts_reasoning_limit() {
        let v: Value =
            serde_json::from_slice(&normalize(&serde_json::to_vec(&body()).unwrap()).unwrap())
                .unwrap();
        assert_eq!(v["max_output_tokens"], 128);
        assert_eq!(v["tools"], serde_json::json!([]));
        assert_eq!(v["tool_choice"], "none");
        assert_eq!(v["service_tier"], "default");
        assert_eq!(v["background"], false);
        assert_eq!(v["store"], false);
        assert_eq!(v["model"], MODEL);
    }
    #[test]
    fn paid_prior_reasoning_and_assistant_text_are_preserved_input_not_extra_output() {
        let mut b = body();
        b["input"] = serde_json::json!([
            {"type":"reasoning","id":"r-original","summary":[],"encrypted_content":"public-synthetic-context"},
            {"type":"message","id":"m-original","phase":"final_answer","role":"assistant","content":[{"type":"output_text","text":"benign"}]}
        ]);
        let v: Value =
            serde_json::from_slice(&normalize(&serde_json::to_vec(&b).unwrap()).unwrap()).unwrap();
        assert_eq!(v["input"], b["input"]);
        assert_eq!(v["max_output_tokens"], 128);
    }
    #[test]
    fn paid_refuses_billing_extensions_and_bad_shapes() {
        for (k, v) in [
            ("model", serde_json::json!("other")),
            ("max_output_tokens", serde_json::json!(129)),
            ("max_output_tokens", serde_json::json!(0)),
            ("service_tier", serde_json::json!("priority")),
            ("background", serde_json::json!(true)),
            ("tools", serde_json::json!([{"type":"web_search"}])),
            ("audio", serde_json::json!({})),
            (
                "input",
                serde_json::json!([{"role":"user","content":[{"type":"input_image","image_url":"https://private.invalid"}]}]),
            ),
        ] {
            let mut b = body();
            b[k] = v;
            assert!(normalize(&serde_json::to_vec(&b).unwrap()).is_err(), "{k}");
        }
        for b in [
            br#"{"model":"one","model":"two"}"#.as_slice(),
            br#"{"input":[{"x":1,"x":2}]}"#,
            br#"{} {}"#,
        ] {
            assert!(normalize(b).is_err());
        }
    }
    #[test]
    fn paid_followups_unknowns_restart_never_refund_or_replenish() {
        let f = ledger();
        for _ in 0..8 {
            assert_eq!(consume_at(f.path(), RUN, "boot", 1).unwrap(), 300001);
        }
        // Reopening the ledger models reconnect, changed process and unknown
        // previous response alike; none can invent a fresh allowance.
        assert!(consume_at(f.path(), RUN, "boot", 1).is_err());
        assert_eq!(
            std::fs::read_to_string(f.path()).unwrap().lines().count(),
            9
        );
    }
    #[test]
    fn paid_concurrent_supervisors_share_at_most_eight_durable_permits() {
        let f = ledger();
        let p = f.path().to_owned();
        let handles: Vec<_> = (0..32)
            .map(|_| {
                let p = p.clone();
                std::thread::spawn(move || consume_at(&p, RUN, "boot", 1).is_ok())
            })
            .collect();
        let n = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert!(n > 0 && n <= 8);
        let used = std::fs::read_to_string(&p).unwrap().lines().count() - 1;
        assert_eq!(n, used);
        for _ in n..8 {
            assert!(consume_at(&p, RUN, "boot", 1).is_ok());
        }
        assert!(consume_at(&p, RUN, "boot", 1).is_err());
    }
    #[test]
    fn paid_deadline_boot_run_torn_tail_modes_symlink_fifo_refuse() {
        let f = ledger();
        for (run, boot, now) in [
            (RUN, "boot", 300001),
            (RUN, "other", 1),
            ("wrong", "boot", 1),
            (RUN, "boot", 0),
        ] {
            assert!(consume_at(f.path(), run, boot, now).is_err());
        }
        OpenOptions::new()
            .append(true)
            .open(f.path())
            .unwrap()
            .write_all(b"1")
            .unwrap();
        assert!(consume_at(f.path(), RUN, "boot", 1).is_err());
        let f = ledger();
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(consume_at(f.path(), RUN, "boot", 1).is_err());
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(f.path(), &link).unwrap();
        assert!(consume_at(&link, RUN, "boot", 1).is_err());
        use std::ffi::CString;
        let fifo = dir.path().join("fifo");
        let c = CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(consume_at(&fifo, RUN, "boot", 1).is_err());
    }
}

#[cfg(all(test, unix))]
mod forwarding_tests {
    use super::*;
    use std::{collections::HashMap, io::Write};
    const RUN: &str = "0123456789abcdef0123456789abcdef";
    fn input(extra: &str, body: &[u8]) -> L7Request {
        let mut raw=format!("POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}\r\n",body.len(),extra).into_bytes();
        raw.extend_from_slice(body);
        L7Request {
            action: "POST".into(),
            target: "/v1/responses".into(),
            query_params: HashMap::new(),
            raw_header: raw,
            body_length: BodyLength::ContentLength(body.len() as u64),
        }
    }
    fn body() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"model":MODEL,"stream":true,"input":[]})).unwrap()
    }
    #[tokio::test]
    async fn paid_pipeline_shared_finite_admission_and_final_body() {
        use std::os::unix::fs::PermissionsExt;
        let mut ledger = tempfile::NamedTempFile::new().unwrap();
        std::fs::set_permissions(ledger.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        writeln!(
            ledger,
            "{}",
            serde_json::json!({"version":1,"run":RUN,"boot":"boot","deadline_ms":1001,"requests":8})
        )
        .unwrap();
        let mut forwarded = Vec::new();
        for n in 0..10 {
            let r = input("", &body());
            let mut client = tokio::io::empty();
            let p = prepare_active(
                &r,
                &mut client,
                "api.openai.com",
                443,
                ledger.path(),
                RUN,
                |path, run| {
                    consume_at(path, run, "boot", 1)?;
                    Ok(test_window(1001).0)
                },
            )
            .await;
            if n < 8 {
                let prepared = p.unwrap().unwrap();
                let h = prepared
                    .request
                    .raw_header
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let v: Value = serde_json::from_slice(&prepared.request.raw_header[h..]).unwrap();
                assert_eq!(v["max_output_tokens"], 128);
                assert_eq!(v["service_tier"], "default");
                forwarded.extend(prepared.request.raw_header);
            } else {
                assert!(p.is_err());
            }
        }
        assert!(!forwarded.is_empty());
        assert_eq!(
            std::fs::read_to_string(ledger.path())
                .unwrap()
                .lines()
                .count(),
            9
        );
    }
    #[tokio::test(start_paused = true)]
    async fn paid_incomplete_body_times_out_before_admission() {
        let mut r = input("", &body());
        let e = r
            .raw_header
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap()
            + 4;
        r.raw_header.truncate(e);
        let (mut client, _writer) = tokio::io::duplex(1024);
        let p = prepare_active(
            &r,
            &mut client,
            "api.openai.com",
            443,
            Path::new("unused"),
            RUN,
            |_, _| panic!("no permit for incomplete body"),
        )
        .await;
        assert!(p.is_err());
    }
    #[tokio::test]
    async fn paid_bad_route_headers_encoding_smuggling_no_permit() {
        for header in [
            "Transfer-Encoding: chunked\r\n",
            "Content-Encoding: gzip\r\n",
            "Upgrade: websocket\r\n",
            "Content-Length: 42\r\n",
            "OpenAI-Project: another\r\n",
            "OpenAI-Beta: extras\r\n",
        ] {
            let r = input(header, &body());
            let mut client = tokio::io::empty();
            assert!(
                prepare_active(
                    &r,
                    &mut client,
                    "api.openai.com",
                    443,
                    Path::new("unused"),
                    RUN,
                    |_, _| panic!("no permit")
                )
                .await
                .is_err()
            );
        }
        for (host, port, target) in [
            ("other", 443, "/v1/responses"),
            ("api.openai.com", 80, "/v1/responses"),
            ("api.openai.com", 443, "/v1/batches"),
        ] {
            let mut r = input("", &body());
            r.target = target.into();
            let mut client = tokio::io::empty();
            assert!(
                prepare_active(
                    &r,
                    &mut client,
                    host,
                    port,
                    Path::new("unused"),
                    RUN,
                    |_, _| panic!("no permit")
                )
                .await
                .is_err()
            );
        }
    }
}

#[cfg(all(test, unix))]
mod boot_clock_regression {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    #[derive(Default)]
    struct Counts {
        reads: AtomicUsize,
        writes: AtomicUsize,
        flushes: AtomicUsize,
        shutdowns: AtomicUsize,
    }
    struct Probe {
        counts: Arc<Counts>,
        advance_on_read: Option<Arc<TestBootWindow>>,
    }
    impl AsyncRead for Probe {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.counts.reads.fetch_add(1, Ordering::SeqCst);
            buf.put_slice(b"R");
            if let Some(w) = &self.advance_on_read {
                w.advance(401_000);
            }
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for Probe {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.counts.writes.fetch_add(buf.len(), Ordering::SeqCst);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.counts.flushes.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.counts.shutdowns.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }
    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    #[tokio::test(start_paused = true)]
    async fn paid_boot_jump_blocks_response_read_buffered_client_write_and_upstream_write() {
        let (permit, boot) = test_window(301_000);
        boot.advance(1000);
        let start = tokio::time::Instant::now();
        tokio::time::advance(std::time::Duration::from_millis(10_000)).await;
        let counts = Arc::new(Counts::default());
        let mut io = WindowIo::new(
            Probe {
                counts: counts.clone(),
                advance_on_read: None,
            },
            Some(&permit),
        );
        let mut already_buffered = [0; 1];
        io.read_exact(&mut already_buffered).await.unwrap();
        boot.advance(401_000);
        assert!(tokio::time::Instant::now() < start + std::time::Duration::from_millis(300_000));
        assert!(io.write_all(&already_buffered).await.is_err()); // response to client
        assert!(io.write_all(b"new upstream request bytes").await.is_err());
        assert!(io.read_exact(&mut [0; 1]).await.is_err());
        assert!(io.flush().await.is_err());
        assert!(io.shutdown().await.is_err());
        assert_eq!(counts.reads.load(Ordering::SeqCst), 1);
        assert_eq!(counts.writes.load(Ordering::SeqCst), 0);
        assert_eq!(counts.flushes.load(Ordering::SeqCst), 0);
        assert_eq!(counts.shutdowns.load(Ordering::SeqCst), 0);
    }
    #[tokio::test(start_paused = true)]
    async fn paid_boot_expiry_wakes_and_cancels_idle_relay_without_monotonic_timeout() {
        let (permit, boot) = test_window(301_000);
        boot.advance(1000);
        let start = tokio::time::Instant::now();
        tokio::time::advance(std::time::Duration::from_millis(10_000)).await;
        let dropped = Arc::new(AtomicBool::new(false));
        let seen = dropped.clone();
        let polled = Arc::new(AtomicBool::new(false));
        let flag = polled.clone();
        let task = tokio::spawn(async move {
            within(Some(&permit), async move {
                let _drop = Dropped(seen);
                flag.store(true, Ordering::SeqCst);
                std::future::pending::<Result<()>>().await
            })
            .await
        });
        tokio::task::yield_now().await;
        assert!(polled.load(Ordering::SeqCst));
        boot.advance(401_000);
        assert!(task.await.unwrap().is_err());
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(
            tokio::time::Instant::now() - start,
            std::time::Duration::from_millis(10_000)
        );
    }
    #[tokio::test]
    async fn paid_clock_failure_cancels_idle_and_prevents_any_forwarding() {
        let (permit, boot) = test_window(301_000);
        let task = tokio::spawn(async move {
            within(Some(&permit), std::future::pending::<Result<()>>()).await
        });
        tokio::task::yield_now().await;
        boot.unavailable();
        assert!(task.await.unwrap().is_err());
        let (permit, boot) = test_window(301_000);
        boot.unavailable();
        let counts = Arc::new(Counts::default());
        let mut io = WindowIo::new(
            Probe {
                counts: counts.clone(),
                advance_on_read: None,
            },
            Some(&permit),
        );
        assert!(io.write_all(b"buffered response").await.is_err());
        assert_eq!(counts.writes.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn paid_read_crossing_original_deadline_discards_new_buffer_and_default_off_delegates() {
        let (permit, boot) = test_window(301_000);
        let counts = Arc::new(Counts::default());
        let mut io = WindowIo::new(
            Probe {
                counts: counts.clone(),
                advance_on_read: Some(boot),
            },
            Some(&permit),
        );
        let mut bytes = [0; 1];
        let mut buf = ReadBuf::new(&mut bytes);
        let result = std::future::poll_fn(|cx| Pin::new(&mut io).poll_read(cx, &mut buf)).await;
        assert!(result.is_err());
        assert!(buf.filled().is_empty());
        let mut default = WindowIo::new(
            Probe {
                counts: counts.clone(),
                advance_on_read: None,
            },
            None,
        );
        default.write_all(b"old mode").await.unwrap();
        assert_eq!(counts.writes.load(Ordering::SeqCst), 8);
        assert_eq!(within(None, async { Ok(7) }).await.unwrap(), 7);
    }
}
