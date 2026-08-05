use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};
use url::Url;

use crate::auto_forge::ForgedContent;
use crate::budget::BudgetTracker;
use crate::domain::{Artifact, Attempt, Failure, FailureCode, redact_url};
use crate::egress::{EgressProxy, EgressStats};
use crate::process::{is_executable_file, resolve_executable};
use crate::request::PreparedRequest;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Default)]
pub struct RuntimeConfig {
    pub browser: Option<PathBuf>,
    pub node: Option<PathBuf>,
    pub puppeteer_root: Option<PathBuf>,
}

impl RuntimeConfig {
    #[must_use]
    pub fn from_environment() -> Self {
        Self {
            browser: env_path("AXIOM_COLLECT_BROWSER"),
            node: env_path("AXIOM_COLLECT_NODE"),
            puppeteer_root: env_path("AXIOM_COLLECT_PUPPETEER_ROOT"),
        }
    }
}

pub(crate) fn resolve_browser(explicit: Option<&Path>) -> Result<PathBuf, Failure> {
    if explicit.is_some() {
        return resolve_executable(explicit, &[]);
    }
    if let Ok(path) = resolve_executable(
        None,
        &[
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "brave-browser",
            "microsoft-edge",
        ],
    ) {
        return Ok(path);
    }

    let mut candidates = vec![
        PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        PathBuf::from("/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary"),
        PathBuf::from("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
        PathBuf::from("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
    ];
    if let Some(home) = env::var_os("HOME") {
        let applications = PathBuf::from(home).join("Applications");
        candidates.extend([
            applications.join("Google Chrome.app/Contents/MacOS/Google Chrome"),
            applications.join("Chromium.app/Contents/MacOS/Chromium"),
            applications.join("Brave Browser.app/Contents/MacOS/Brave Browser"),
            applications.join("Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
        ]);
    }
    for variable in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        if let Some(base) = env::var_os(variable) {
            let base = PathBuf::from(base);
            candidates.extend([
                base.join("Google/Chrome/Application/chrome.exe"),
                base.join("Chromium/Application/chrome.exe"),
                base.join("BraveSoftware/Brave-Browser/Application/brave.exe"),
                base.join("Microsoft/Edge/Application/msedge.exe"),
            ]);
        }
    }
    candidates
        .into_iter()
        .find(|path| is_executable_file(path))
        .ok_or_else(|| {
            Failure::new(
                FailureCode::ToolUnavailable,
                "no installed Chromium-family browser was found; configure --browser-path or AXIOM_COLLECT_BROWSER",
            )
        })
}

pub(crate) fn validate_browser_version(version: &str) -> Result<(), Failure> {
    let value = version.trim().to_ascii_lowercase();
    if !["chrome", "chromium", "brave", "edge"]
        .iter()
        .any(|name| value.contains(name))
    {
        return Err(Failure::new(
            FailureCode::ToolUnavailable,
            format!("configured executable is not a Chromium-family browser: {version}"),
        ));
    }
    Ok(())
}

/// Adapter-neutral result of one rendered retrieval attempt.
#[derive(Debug, Clone)]
pub(crate) struct RenderedOutput {
    pub version: Option<String>,
    pub final_url: Url,
    pub final_url_observed: bool,
    pub http_status: Option<u16>,
    pub body: Vec<u8>,
    pub forged: Option<ForgedContent>,
    pub attempt: Attempt,
    pub artifacts: Vec<Artifact>,
}

/// Adapter-neutral failure of one rendered retrieval attempt.
#[derive(Debug, Clone)]
pub(crate) struct RenderedFailure {
    pub failure: Failure,
    pub attempt: Attempt,
    pub version: Option<String>,
    pub final_url: Option<Url>,
    pub final_url_observed: bool,
    pub http_status: Option<u16>,
    pub artifacts: Vec<Artifact>,
}

pub(crate) fn hardened_browser_args(proxy_endpoint: &str) -> Vec<String> {
    [
        format!("--proxy-server={proxy_endpoint}"),
        "--proxy-bypass-list=<-loopback>".to_owned(),
        "--disable-background-networking".to_owned(),
        "--disable-component-update".to_owned(),
        "--disable-default-apps".to_owned(),
        "--disable-extensions".to_owned(),
        "--disable-features=AutofillServerCommunication,MediaRouter,OptimizationHints,Translate"
            .to_owned(),
        "--disable-quic".to_owned(),
        "--disable-sync".to_owned(),
        "--force-color-profile=srgb".to_owned(),
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_owned(),
        "--hide-scrollbars".to_owned(),
        "--metrics-recording-only".to_owned(),
        "--mute-audio".to_owned(),
        "--no-default-browser-check".to_owned(),
        "--no-first-run".to_owned(),
        "--password-store=basic".to_owned(),
        "--use-mock-keychain".to_owned(),
    ]
    .into_iter()
    .collect()
}

pub(crate) async fn create_private_directory(path: &Path) -> Result<(), Failure> {
    tokio::fs::create_dir(path).await.map_err(|error| {
        Failure::new(
            FailureCode::ProviderFailed,
            format!("failed to create isolated browser profile: {error}"),
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|error| {
                Failure::new(
                    FailureCode::ProviderFailed,
                    format!("failed to secure isolated browser profile: {error}"),
                )
            })?;
    }
    Ok(())
}

pub(crate) fn create_sandbox() -> Result<TempDir, Failure> {
    tempdir().map_err(|error| {
        Failure::new(
            FailureCode::ProviderFailed,
            format!("failed to create browser sandbox: {error}"),
        )
    })
}

pub(crate) async fn screenshot_path(
    request: &PreparedRequest,
    session: &str,
) -> Result<PathBuf, Failure> {
    let directory = request.execution.artifact_dir.as_ref().ok_or_else(|| {
        Failure::new(
            FailureCode::InvalidRequest,
            "screenshot capability requires artifact_dir",
        )
    })?;
    let mut directory = directory.clone();
    if directory.is_relative() {
        directory = std::env::current_dir()
            .map_err(|error| {
                Failure::new(
                    FailureCode::ProviderFailed,
                    format!("failed to resolve artifact directory: {error}"),
                )
            })?
            .join(directory);
    }
    tokio::fs::create_dir_all(&directory)
        .await
        .map_err(|error| {
            Failure::new(
                FailureCode::ProviderFailed,
                format!("failed to create artifact directory: {error}"),
            )
        })?;
    Ok(directory.join(format!("axiom-collect-{session}.png")))
}

pub(crate) async fn write_artifact(
    kind: &str,
    path: &Path,
    media_type: &str,
    bytes: &[u8],
) -> Result<Artifact, Failure> {
    if bytes.is_empty() {
        return Err(Failure::new(
            FailureCode::ProviderFailed,
            "browser produced an empty screenshot",
        ));
    }
    let guard = ArtifactFileGuard::new(path.to_path_buf());
    tokio::fs::write(path, bytes).await.map_err(|error| {
        Failure::new(
            FailureCode::ProviderFailed,
            format!("failed to write screenshot artifact: {error}"),
        )
    })?;
    let digest = Sha256::digest(bytes);
    let artifact = Artifact {
        kind: kind.to_owned(),
        path: path.to_string_lossy().into_owned(),
        media_type: media_type.to_owned(),
        bytes: bytes.len(),
        sha256: hex_lower(&digest),
    };
    guard.disarm();
    Ok(artifact)
}

pub(crate) async fn shutdown_egress(
    proxy: &mut Option<EgressProxy>,
    budget: &mut BudgetTracker,
) -> Result<EgressStats, Failure> {
    let Some(proxy) = proxy.take() else {
        return Ok(EgressStats::default());
    };
    let stats = proxy.shutdown().await;
    budget.reserve_network(stats.connection_operations)?;
    budget.reserve_external_network_bytes(stats.transferred_bytes)?;
    if let Some(fatal) = &stats.fatal_error {
        return Err(Failure::new(fatal.code, fatal.message.clone()));
    }
    Ok(stats)
}

pub(crate) fn sanitize_text(value: &str, request: &PreparedRequest, target: &Url) -> String {
    value
        .replace(&request.intent.url, &redact_url(&request.intent.url))
        .replace(target.as_str(), &redact_url(target.as_str()))
}

pub(crate) fn session_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u128, |duration| duration.as_nanos());
    let counter = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("axiom-{}-{nanos}-{counter}", std::process::id())
}

pub(crate) fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

pub(crate) async fn cleanup_artifacts(artifacts: &[Artifact]) {
    for artifact in artifacts {
        let _ = tokio::fs::remove_file(&artifact.path).await;
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

struct ArtifactFileGuard {
    path: PathBuf,
    armed: bool,
}

impl ArtifactFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for ArtifactFileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}
