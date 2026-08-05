use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use eoka::cdp::transport::CdpMessage;
use eoka::{Browser, Page, StealthConfig};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use url::Url;

use crate::auto_forge::{self, ForgedContent, NetworkResponse};
use crate::budget::BudgetTracker;
use crate::domain::{
    Artifact, Attempt, BrowserCapability, BudgetConfig, Failure, FailureCode, redact_url,
};
use crate::egress::{EgressProxy, EgressStats};
use crate::policy::{parse_url, validate_and_resolve};
use crate::process::{
    ManagedProcess, ManagedProcessSpec, first_line, isolated_environment, probe_version,
};
use crate::rendered::{
    RenderedFailure, RenderedOutput, RuntimeConfig, create_private_directory, create_sandbox,
    elapsed_ms, hardened_browser_args, resolve_browser, sanitize_text, screenshot_path, session_id,
    shutdown_egress, validate_browser_version, write_artifact,
};
use crate::request::PreparedRequest;

const STDERR_LIMIT: usize = 64 * 1024;
const DOM_QUIET_WINDOW: Duration = Duration::from_millis(500);
const DOM_POLL_INTERVAL: Duration = Duration::from_millis(100);
const NAVIGATION_COMMIT_DELAY: Duration = Duration::from_millis(100);
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const CHROME_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
/// Hard ceiling on full-page screenshot area. The effective limit is also reduced
/// from the remaining total-byte budget before CDP capture, because CDP returns a
/// base64 string and the decoded artifact coexist briefly during conversion.
const MAX_SCREENSHOT_PIXELS: f64 = 25_000_000.0;
const SCREENSHOT_PEAK_BYTES_PER_PIXEL: usize = 6;
const MAX_FORGE_RESPONSE_CAPTURES: usize = 32;

#[derive(Debug)]
pub(crate) struct BrowserProbe {
    pub path: PathBuf,
    pub version: String,
}

/// Budget for the capability probe. It navigates nothing but `about:blank`, so its
/// bounds are stated once here and every timeout and proxy limit is derived from
/// them rather than restated at each call.
fn probe_budget() -> Result<BudgetTracker, Failure> {
    BudgetTracker::new(BudgetConfig {
        max_wall_ms: 10_000,
        max_network_operations: 8,
        max_response_bytes: 1024 * 1024,
        max_extracted_bytes: 1024 * 1024,
        max_total_bytes: 1024 * 1024,
        connect_timeout_ms: 5_000,
        read_timeout_ms: 5_000,
        ..BudgetConfig::default()
    })
}

pub(crate) async fn probe_runtime(config: &RuntimeConfig) -> Result<BrowserProbe, Failure> {
    let mut budget = probe_budget()?;
    let session = BrowserSession::start(config, &mut budget).await?;

    let handshake = async {
        session.browser.version().await.map_err(cdp_failure)?;
        let page = session
            .browser
            .new_page("about:blank")
            .await
            .map_err(cdp_failure)?;
        page.execute(
            "document.body.innerHTML = '<main id=\"axiom-collect-cdp-probe\">cdp-ready</main>'",
        )
        .await
        .map_err(cdp_failure)?;
        let content = page.content().await.map_err(cdp_failure)?;
        if !content.contains("axiom-collect-cdp-probe") || !content.contains("cdp-ready") {
            return Err(Failure::new(
                FailureCode::ProviderFailed,
                "browser CDP probe did not observe the JavaScript DOM mutation",
            ));
        }
        Ok(())
    }
    .await;

    let probe = BrowserProbe {
        path: session.path.clone(),
        version: session.version.clone(),
    };
    let closed = session.close(&mut budget).await;
    handshake?;
    let _ = closed.close?;
    closed.egress?;
    Ok(probe)
}

/// One isolated browser session: a temporary sandbox, a hardened process tree, a
/// loopback CDP connection, and the egress proxy that bounds all of its traffic.
///
/// The capability probe and a rendered retrieval need exactly this set, brought up
/// in exactly this order and torn down together. Owning them in one value makes that
/// ordering a property of the type instead of a sequence repeated at two call sites,
/// and makes partial startup failure tear down whatever already exists.
struct BrowserSession {
    browser: Browser,
    process: ManagedProcess,
    proxy: Option<EgressProxy>,
    path: PathBuf,
    version: String,
    /// Kept alive so the profile directory outlives the process using it.
    _sandbox: TempDir,
}

/// Teardown outcomes, reported separately because a caller combines them with its
/// own result: a cleanup failure must never be hidden behind a usable capture, and a
/// capture failure must not lose the cleanup detail either.
struct SessionClose {
    close: Result<Option<String>, Failure>,
    egress: Result<EgressStats, Failure>,
}

impl BrowserSession {
    async fn start(config: &RuntimeConfig, budget: &mut BudgetTracker) -> Result<Self, Failure> {
        let path = resolve_browser(config.browser.as_deref())?;
        let sandbox = create_sandbox()?;
        let environment = isolated_environment(sandbox.path());
        let version = probe_version(
            &path,
            sandbox.path(),
            &environment,
            budget.remaining_wall().min(VERSION_PROBE_TIMEOUT),
        )
        .await?;
        validate_browser_version(&version)?;
        let profile = sandbox.path().join("browser-profile");
        create_private_directory(&profile).await?;

        let mut proxy = Some(
            EgressProxy::start(
                budget.remaining_network_operations(),
                budget.remaining_total_bytes(),
            )
            .await?,
        );
        let endpoint = proxy
            .as_ref()
            .map(EgressProxy::endpoint)
            .unwrap_or_default();
        let mut process = ManagedProcess::spawn(ManagedProcessSpec {
            executable: path.clone(),
            args: browser_args(&profile, endpoint),
            environment,
            current_dir: sandbox.path().to_path_buf(),
            stderr_limit: STDERR_LIMIT,
        })?;

        // A process tree exists from here on, so every exit below tears it down and
        // folds any cleanup failure into the failure that caused the abort.
        let websocket = match wait_for_devtools(&profile, &mut process, budget).await {
            Ok(value) => value,
            Err(failure) => return Err(abort(&mut process, &mut proxy, budget, failure).await),
        };
        let cdp_timeout = budget
            .remaining_wall()
            .min(Duration::from_millis(budget.config().read_timeout_ms));
        let browser =
            match Browser::connect_with_config(&websocket, cdp_config(cdp_timeout, &version)).await
            {
                Ok(value) => value,
                Err(error) => {
                    let failure = Failure::new(
                        FailureCode::ProviderFailed,
                        format!("failed to connect to browser DevTools: {error}"),
                    );
                    return Err(abort(&mut process, &mut proxy, budget, failure).await);
                }
            };

        Ok(Self {
            browser,
            process,
            proxy,
            path,
            version,
            _sandbox: sandbox,
        })
    }

    async fn close(self, budget: &mut BudgetTracker) -> SessionClose {
        let Self {
            browser,
            mut process,
            mut proxy,
            _sandbox,
            ..
        } = self;
        let close = close_browser(browser, &mut process).await;
        let egress = shutdown_egress(&mut proxy, budget).await;
        // `_sandbox` is dropped here, after the process that owned its profile is gone.
        SessionClose { close, egress }
    }
}

/// Tears down a partially started session and folds any cleanup failure into the
/// failure that caused the abort, so neither is lost.
async fn abort(
    process: &mut ManagedProcess,
    proxy: &mut Option<EgressProxy>,
    budget: &mut BudgetTracker,
    failure: Failure,
) -> Failure {
    let cleanup = terminate_process(process, Duration::ZERO).await;
    let egress_cleanup = shutdown_egress(proxy, budget).await.err();
    let failure = append_cleanup(failure, cleanup.err(), "browser cleanup");
    append_cleanup(failure, egress_cleanup, "egress cleanup")
}

#[derive(Debug)]
struct BrowserCapture {
    final_url: Url,
    http_status: u16,
    html: Vec<u8>,
    screenshot: Option<Vec<u8>>,
    forged: Option<ForgedContent>,
    version: String,
}

#[derive(Debug)]
struct BrowserCaptureFailure {
    failure: Failure,
    http_status: Option<u16>,
    final_url: Option<Url>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PageNavigate {
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    referrer: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PageNavigateResult {
    #[serde(default)]
    error_text: Option<String>,
    #[serde(default)]
    frame_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkDocumentResponse {
    #[serde(rename = "requestId")]
    request_id: Option<String>,
    #[serde(rename = "type")]
    resource_type: Option<String>,
    #[serde(default)]
    frame_id: Option<String>,
    response: NetworkResponseSummary,
}

#[derive(Debug, Deserialize)]
struct NetworkResponseSummary {
    url: String,
    status: f64,
    #[serde(rename = "mimeType")]
    mime_type: Option<String>,
}

impl From<Failure> for BrowserCaptureFailure {
    fn from(failure: Failure) -> Self {
        Self {
            failure,
            http_status: None,
            final_url: None,
        }
    }
}

/// Accumulates the provenance that every rendered failure has to carry.
///
/// Every fallible step reports the same request, target, elapsed time, transition
/// reason, and browser version. Threading them through one value keeps each step's
/// error handling to a single call and prevents one site from omitting a field the
/// others record.
struct BrowserContext<'a> {
    request: &'a PreparedRequest,
    target: &'a Url,
    started: std::time::Instant,
    transition_reason: Option<String>,
    version: Option<String>,
}

impl BrowserContext<'_> {
    fn fail(&self, failure: Failure) -> RenderedFailure {
        browser_failure(
            self.request,
            self.target,
            self.started,
            failure,
            self.transition_reason.clone(),
            self.version.clone(),
            Vec::new(),
        )
    }
}

pub(crate) async fn run_rendered(
    request: &PreparedRequest,
    target: &Url,
    budget: &mut BudgetTracker,
    config: &RuntimeConfig,
    transition_reason: Option<String>,
) -> Result<RenderedOutput, RenderedFailure> {
    let mut context = BrowserContext {
        request,
        target,
        started: std::time::Instant::now(),
        transition_reason,
        version: None,
    };

    budget
        .reserve_browser_launch()
        .map_err(|failure| context.fail(failure))?;
    let session = BrowserSession::start(config, budget)
        .await
        .map_err(|failure| context.fail(failure))?;
    let version = session.version.clone();
    context.version = Some(version.clone());

    let workflow = capture_page(request, target, budget, &session.browser, version).await;
    let closed = session.close(budget).await;

    match (workflow, closed.close, closed.egress) {
        (Ok(capture), Ok(close_diagnostic), Ok(stats)) => {
            let mut artifacts = Vec::new();
            if let Some(screenshot) = capture.screenshot {
                let path = screenshot_path(request, &session_id())
                    .await
                    .map_err(|failure| context.fail(failure))?;
                let artifact = write_artifact("screenshot", &path, "image/png", &screenshot)
                    .await
                    .map_err(|failure| context.fail(failure))?;
                artifacts.push(artifact);
            }
            Ok(RenderedOutput {
                version: Some(capture.version),
                final_url: capture.final_url,
                final_url_observed: true,
                body: capture.html.clone(),
                forged: capture.forged.clone(),
                http_status: Some(capture.http_status),
                attempt: browser_attempt(
                    request,
                    target,
                    BrowserAttemptData {
                        duration_ms: elapsed_ms(context.started),
                        bytes: capture.html.len(),
                        http_status: Some(capture.http_status),
                        network_operations: stats.connection_operations,
                        outcome: "provider_accepted",
                        transition_reason: context.transition_reason,
                        // A non-fatal browser exit note stays visible in the trace
                        // instead of turning a validated capture into a failure.
                        error: close_diagnostic,
                    },
                ),
                artifacts,
            })
        }
        (Ok(capture), close, egress) => {
            // The page was captured but teardown failed, which is a real defect and is
            // never hidden behind the otherwise usable document.
            let (egress_failure, network_operations) = match egress {
                Ok(stats) => (None, stats.connection_operations),
                Err(failure) => (Some(failure), 0),
            };
            let failure = close.err().or(egress_failure).unwrap_or_else(|| {
                Failure::new(FailureCode::InternalError, "browser cleanup failed")
            });
            let mut failure = browser_failure_at_status(
                &context,
                &capture.final_url,
                failure,
                Some(capture.http_status),
            );
            failure.attempt.network_operations = network_operations;
            Err(failure)
        }
        (Err(mut capture_failure), close, egress) => {
            if let Err(cleanup) = close {
                capture_failure.failure =
                    append_cleanup(capture_failure.failure, Some(cleanup), "browser cleanup");
            }
            let network_operations = match egress {
                Ok(stats) => stats.connection_operations,
                Err(cleanup) => {
                    capture_failure.failure =
                        append_cleanup(capture_failure.failure, Some(cleanup), "egress cleanup");
                    0
                }
            };
            let observed_final_url = capture_failure.final_url;
            let failure_target = observed_final_url.as_ref().unwrap_or(target);
            let mut failure = browser_failure_at_status(
                &context,
                failure_target,
                capture_failure.failure,
                capture_failure.http_status,
            );
            failure.attempt.network_operations = network_operations;
            failure.final_url_observed = observed_final_url.is_some();
            Err(failure)
        }
    }
}

async fn capture_page(
    request: &PreparedRequest,
    target: &Url,
    budget: &mut BudgetTracker,
    browser: &Browser,
    version: String,
) -> Result<BrowserCapture, BrowserCaptureFailure> {
    let page = browser.new_blank_page().await.map_err(cdp_failure)?;
    let network_events = page.session().transport().subscribe();
    page.enable_request_capture().await.map_err(cdp_failure)?;
    let navigation = page
        .session()
        .send::<_, PageNavigateResult>(
            "Page.navigate",
            &PageNavigate {
                url: target.as_str().to_owned(),
                referrer: None,
            },
        )
        .await
        .map_err(cdp_failure)?;
    if let Some(error) = navigation.error_text
        && error != "net::ERR_HTTP_RESPONSE_CODE_FAILURE"
    {
        return Err(Failure::new(
            FailureCode::ProviderFailed,
            format!("browser navigation failed: {error}"),
        )
        .into());
    }
    let mut document = MainDocumentStatus::new(
        network_events,
        page.session().session_id().to_owned(),
        navigation.frame_id,
    );
    // Give the navigation a moment to commit so the first settle probe runs against
    // the target document rather than the blank page it replaces.
    tokio::time::sleep(NAVIGATION_COMMIT_DELAY).await;
    wait_until_settled(&page, request, budget, &mut document).await?;
    document.drain();
    let final_url_text = page.url().await.map_err(cdp_failure)?;
    if final_url_text.is_empty() {
        return Err(Failure::new(
            FailureCode::ProviderFailed,
            "browser did not report a final URL",
        )
        .into());
    }
    let final_url = parse_url(&final_url_text).map_err(|failure| {
        Failure::new(
            FailureCode::PolicyRejected,
            format!("browser reported an invalid final URL: {}", failure.message),
        )
    })?;
    let dns_timeout = budget.remaining_wall().min(Duration::from_millis(
        request.execution.budget.connect_timeout_ms,
    ));
    validate_and_resolve(final_url.clone(), request.execution.network, dns_timeout)
        .await
        .map_err(|failure| {
            Failure::new(
                FailureCode::PolicyRejected,
                format!("browser final URL rejected: {}", failure.message),
            )
        })?;
    let http_status = document
        .resolve(&final_url)
        .ok_or_else(|| Failure::new(FailureCode::ProviderFailed, document.diagnostic()))?;
    if !(200..=299).contains(&http_status) {
        return Err(BrowserCaptureFailure {
            failure: Failure::new(
                FailureCode::HttpRejected,
                format!("browser main-document HTTP status {http_status} is not usable content"),
            ),
            http_status: Some(http_status),
            final_url: Some(final_url),
        });
    }
    let html = page.content().await.map_err(cdp_failure)?.into_bytes();
    if html.iter().all(u8::is_ascii_whitespace) {
        return Err(Failure::new(
            FailureCode::ContentEmpty,
            "browser returned an empty document",
        )
        .into());
    }
    budget.reserve_response_bytes(0, html.len())?;

    let forged = if request.execution.adaptive.enable_auto_forge {
        let responses = capture_network_responses(&page, &document, budget).await;
        auto_forge::select(&final_url, &html, responses)
    } else {
        None
    };

    let screenshot = if request.intent.browser_capability == BrowserCapability::Screenshot {
        let screenshot =
            capture_full_page_screenshot(&page, budget.remaining_total_bytes()).await?;
        budget.reserve_artifact_bytes(screenshot.len())?;
        Some(screenshot)
    } else {
        None
    };
    Ok(BrowserCapture {
        final_url,
        http_status,
        html,
        screenshot,
        forged,
        version,
    })
}

/// Tracks the main-document HTTP status observed on the navigated frame.
///
/// The CDP event stream is a bounded broadcast channel, so it must be drained
/// while the page settles rather than once at the end; otherwise subresource
/// events evict the main-document response and the status is lost. Events are
/// scoped to the navigated frame because `Network.responseReceived` also reports
/// `Document` resources for nested iframes, whose status must never be mistaken
/// for the main document's.
struct MainDocumentStatus {
    events: tokio::sync::broadcast::Receiver<CdpMessage>,
    session_id: String,
    frame_id: Option<String>,
    observed: Vec<(String, u16)>,
    resources: Vec<CapturedResource>,
    lagged: bool,
}

#[derive(Debug, Clone)]
struct CapturedResource {
    request_id: String,
    url: Url,
    status: u16,
    content_type: String,
}

const MAX_DOCUMENT_OBSERVATIONS: usize = 64;

impl MainDocumentStatus {
    fn new(
        events: tokio::sync::broadcast::Receiver<CdpMessage>,
        session_id: String,
        frame_id: Option<String>,
    ) -> Self {
        Self {
            events,
            session_id,
            frame_id,
            observed: Vec::new(),
            resources: Vec::new(),
            lagged: false,
        }
    }

    fn drain(&mut self) {
        loop {
            let message = match self.events.try_recv() {
                Ok(message) => message,
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                    self.lagged = true;
                    continue;
                }
                Err(
                    tokio::sync::broadcast::error::TryRecvError::Empty
                    | tokio::sync::broadcast::error::TryRecvError::Closed,
                ) => break,
            };
            let CdpMessage::Event {
                method,
                params,
                session_id,
            } = message
            else {
                continue;
            };
            if method != "Network.responseReceived"
                || session_id.as_deref() != Some(self.session_id.as_str())
            {
                continue;
            }
            let Ok(event) = serde_json::from_value::<NetworkDocumentResponse>(params) else {
                continue;
            };
            let status = event.response.status;
            if let (Some(request_id), Ok(status), Ok(url)) = (
                event.request_id,
                finite_http_status(status),
                parse_url(&event.response.url),
            ) {
                let duplicate = self
                    .resources
                    .iter()
                    .any(|resource| resource.request_id == request_id);
                if !duplicate && self.resources.len() < MAX_DOCUMENT_OBSERVATIONS * 2 {
                    self.resources.push(CapturedResource {
                        request_id,
                        url,
                        status,
                        content_type: event.response.mime_type.unwrap_or_default(),
                    });
                }
            }
            if event.resource_type.as_deref() != Some("Document") {
                continue;
            }
            // A Document event without the navigated frame id cannot be safely
            // attributed to the main document. Accepting it would let a malformed
            // or nested-frame event supply the status, so the match is exact and
            // fail-closed when either side is absent.
            if self.frame_id.as_ref() != event.frame_id.as_ref() {
                continue;
            }
            let Ok(status) = finite_http_status(event.response.status) else {
                continue;
            };
            if self.observed.len() == MAX_DOCUMENT_OBSERVATIONS {
                self.observed.remove(0);
            }
            self.observed.push((event.response.url, status));
        }
    }

    /// Prefers the response whose URL is the observed final URL and falls back to
    /// the most recent main-frame document response, which is the last redirect hop.
    fn resolve(&self, final_url: &Url) -> Option<u16> {
        self.observed
            .iter()
            .rev()
            .find(|(url, _)| {
                parse_url(url)
                    .ok()
                    .as_ref()
                    .is_some_and(|parsed| parsed == final_url)
            })
            .or_else(|| self.observed.last())
            .map(|(_, status)| *status)
    }

    fn diagnostic(&self) -> &'static str {
        if self.lagged {
            "browser navigation did not report the main-document HTTP status; the DevTools event buffer overflowed"
        } else {
            "browser navigation did not report the main-document HTTP status"
        }
    }
}

fn finite_http_status(status: f64) -> Result<u16, ()> {
    if !status.is_finite() || status.fract() != 0.0 || !(100.0..=599.0).contains(&status) {
        return Err(());
    }
    Ok(status as u16)
}

async fn capture_network_responses(
    page: &Page,
    document: &MainDocumentStatus,
    budget: &mut BudgetTracker,
) -> Vec<NetworkResponse> {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ResponseBody {
        body: String,
        #[serde(default)]
        base64_encoded: bool,
    }

    let mut responses = Vec::new();
    // CDP body reads are local inspection calls, not external network
    // operations. Their count is independently bounded; response and total-byte
    // budgets still charge every body that is retained.
    for resource in document.resources.iter().take(MAX_FORGE_RESPONSE_CAPTURES) {
        let url = resource.url.as_str().to_ascii_lowercase();
        let content_type = resource.content_type.to_ascii_lowercase();
        if !(content_type.contains("json")
            || content_type.contains("graphql")
            || [
                "/api/", "/graphql", ".json", "/ajax/", "/query", "/feed", "/data/",
            ]
            .iter()
            .any(|marker| url.contains(marker)))
        {
            continue;
        }
        let body = page
            .session()
            .transport()
            .send_to_session::<_, ResponseBody>(
                page.session().session_id(),
                "Network.getResponseBody",
                &serde_json::json!({ "requestId": resource.request_id }),
            )
            .await;
        let Ok(body) = body else {
            continue;
        };
        let bytes = if body.base64_encoded {
            let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(body.body) else {
                continue;
            };
            bytes
        } else {
            body.body.into_bytes()
        };
        if bytes.is_empty() || bytes.len() > 2 * 1024 * 1024 {
            continue;
        }
        if budget.reserve_response_bytes(0, bytes.len()).is_err() {
            break;
        }
        responses.push(NetworkResponse {
            url: resource.url.clone(),
            status: resource.status,
            content_type: resource.content_type.clone(),
            body: bytes,
        });
    }
    responses
}

#[derive(Debug, Deserialize)]
struct SettleStatus {
    ready: String,
    quiet_ms: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LayoutMetrics {
    content_size: PageRect,
}

#[derive(Debug, Deserialize)]
struct PageRect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

#[derive(Debug, Deserialize)]
struct ScreenshotData {
    data: String,
}

fn screenshot_pixel_limit(remaining_total_bytes: usize) -> f64 {
    MAX_SCREENSHOT_PIXELS.min((remaining_total_bytes / SCREENSHOT_PEAK_BYTES_PER_PIXEL) as f64)
}

fn decode_screenshot(data: String, max_bytes: usize) -> Result<Vec<u8>, Failure> {
    let estimated_bytes = base64::decoded_len_estimate(data.len());
    if estimated_bytes > max_bytes {
        return Err(Failure::new(
            FailureCode::BudgetExhausted,
            "browser screenshot exceeds the remaining total-byte budget",
        ));
    }
    let mut screenshot = Vec::with_capacity(estimated_bytes);
    base64::engine::general_purpose::STANDARD
        .decode_vec(data.as_bytes(), &mut screenshot)
        .map_err(|error| {
            Failure::new(
                FailureCode::ProviderFailed,
                format!("browser screenshot decoding failed: {error}"),
            )
        })?;
    Ok(screenshot)
}

async fn capture_full_page_screenshot(
    page: &Page,
    remaining_total_bytes: usize,
) -> Result<Vec<u8>, Failure> {
    let session = page.session();
    let transport = session.transport();
    let metrics: LayoutMetrics = transport
        .send_to_session(
            session.session_id(),
            "Page.getLayoutMetrics",
            &serde_json::json!({}),
        )
        .await
        .map_err(cdp_failure)?;
    let rect = metrics.content_size;
    let max_pixels = screenshot_pixel_limit(remaining_total_bytes);
    let valid = [rect.x, rect.y, rect.width, rect.height]
        .into_iter()
        .all(f64::is_finite)
        && rect.width > 0.0
        && rect.height > 0.0
        && max_pixels >= 1.0
        && rect.width * rect.height <= max_pixels;
    if !valid {
        return Err(Failure::new(
            FailureCode::BudgetExhausted,
            "full-page screenshot dimensions are invalid or exceed the pixel or byte limit",
        ));
    }
    let result: ScreenshotData = transport
        .send_to_session(
            session.session_id(),
            "Page.captureScreenshot",
            &serde_json::json!({
                "format": "png",
                "fromSurface": true,
                "captureBeyondViewport": true,
                "clip": {
                    "x": rect.x,
                    "y": rect.y,
                    "width": rect.width,
                    "height": rect.height,
                    "scale": 1.0
                }
            }),
        )
        .await
        .map_err(cdp_failure)?;
    decode_screenshot(result.data, remaining_total_bytes)
}

async fn wait_until_settled(
    page: &Page,
    request: &PreparedRequest,
    budget: &BudgetTracker,
    document: &mut MainDocumentStatus,
) -> Result<(), Failure> {
    let settle_limit = budget.remaining_wall().min(Duration::from_millis(
        request.execution.budget.read_timeout_ms,
    ));
    let deadline = tokio::time::Instant::now() + settle_limit;
    let mut last_error = None;
    loop {
        document.drain();
        if tokio::time::Instant::now() >= deadline {
            return Err(Failure::new(
                FailureCode::BudgetExhausted,
                match last_error {
                    // A page that never evaluates is a different defect from a page
                    // that keeps mutating, so the last probe error is not discarded.
                    Some(error) => format!(
                        "browser page did not reach a stable loaded state; last settle probe failed: {error}"
                    ),
                    None => "browser page did not reach a stable loaded state".to_owned(),
                },
            ));
        }
        let expression = r#"(() => {
            const now = performance.now();
            if (!globalThis.__axiomCollectObserver) {
                globalThis.__axiomCollectLastMutation = now;
                const observer = new MutationObserver(() => {
                    globalThis.__axiomCollectLastMutation = performance.now();
                });
                observer.observe(document, {
                    subtree: true,
                    childList: true,
                    attributes: true,
                    characterData: true
                });
                globalThis.__axiomCollectObserver = observer;
            }
            return {
                ready: document.readyState,
                quiet_ms: now - globalThis.__axiomCollectLastMutation
            };
        })()"#;
        match page.evaluate::<SettleStatus>(expression).await {
            Ok(status) => {
                if status.ready == "complete"
                    && status.quiet_ms >= DOM_QUIET_WINDOW.as_millis() as f64
                {
                    document.drain();
                    return Ok(());
                }
                last_error = None;
            }
            Err(error) => last_error = Some(error.to_string()),
        }
        tokio::time::sleep(DOM_POLL_INTERVAL).await;
    }
}

async fn wait_for_devtools(
    profile: &Path,
    process: &mut ManagedProcess,
    budget: &BudgetTracker,
) -> Result<String, Failure> {
    let path = profile.join("DevToolsActivePort");
    let deadline =
        tokio::time::Instant::now() + budget.remaining_wall().min(Duration::from_secs(10));
    loop {
        if process.has_exited()? {
            return Err(Failure::new(
                FailureCode::ProviderFailed,
                "browser exited before exposing DevTools",
            ));
        }
        if let Ok(value) = tokio::fs::read_to_string(&path).await {
            let mut lines = value.lines();
            let port = lines
                .next()
                .and_then(|line| line.parse::<u16>().ok())
                .filter(|port| *port != 0);
            let socket_path = lines.next().filter(|line| line.starts_with('/'));
            if let (Some(port), Some(socket_path)) = (port, socket_path) {
                return Ok(format!("ws://127.0.0.1:{port}{socket_path}"));
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Failure::new(
                FailureCode::BudgetExhausted,
                "browser DevTools launch timed out",
            ));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Closes the CDP session, terminates the browser tree, and reports any non-fatal
/// exit diagnostic the browser produced.
async fn close_browser(
    browser: Browser,
    process: &mut ManagedProcess,
) -> Result<Option<String>, Failure> {
    let close = tokio::time::timeout(CHROME_SHUTDOWN_GRACE, browser.close()).await;
    let close_result = match close {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(Failure::new(
            FailureCode::ProviderFailed,
            format!("browser close command failed: {error}"),
        )),
        Err(_) => Err(Failure::new(
            FailureCode::ProviderFailed,
            "browser close command timed out",
        )),
    };
    let process_result = terminate_process(process, CHROME_SHUTDOWN_GRACE).await;
    match close_result {
        Ok(()) => process_result,
        Err(failure) => match process_result {
            Ok(_) => Err(failure),
            Err(process_failure) => Err(append_cleanup(
                failure,
                Some(process_failure),
                "browser process cleanup",
            )),
        },
    }
}

/// Terminates the browser process tree and returns a non-fatal exit diagnostic.
///
/// A chatty stderr stream or a non-zero exit code after an explicit close is a
/// property of the installed browser, not evidence that retrieval failed, so
/// neither discards a document that was already captured and validated. Only a
/// failure to terminate or reap the process tree is an error, which keeps a real
/// cleanup failure visible without inventing one.
async fn terminate_process(
    process: &mut ManagedProcess,
    grace: Duration,
) -> Result<Option<String>, Failure> {
    let result = process.shutdown(grace).await?;
    let mut notes = Vec::new();
    if result.stderr_truncated {
        notes.push("browser diagnostic output exceeded its limit and was truncated".to_owned());
    }
    if !result.success && !result.forced {
        let diagnostic = first_line(&result.stderr);
        notes.push(if diagnostic.is_empty() {
            format!("browser exited with status {:?}", result.status_code)
        } else {
            format!(
                "browser exited with status {:?}: {diagnostic}",
                result.status_code
            )
        });
    }
    Ok((!notes.is_empty()).then(|| notes.join("; ")))
}

fn browser_args(profile: &Path, proxy_endpoint: &str) -> Vec<OsString> {
    let mut arguments = vec![
        "--headless=new".to_owned(),
        "--remote-debugging-address=127.0.0.1".to_owned(),
        "--remote-debugging-port=0".to_owned(),
        format!("--user-data-dir={}", profile.display()),
    ];
    arguments.extend(hardened_browser_args(proxy_endpoint));
    arguments.push("about:blank".to_owned());
    arguments.into_iter().map(OsString::from).collect()
}

struct BrowserAttemptData<'a> {
    duration_ms: u64,
    bytes: usize,
    http_status: Option<u16>,
    network_operations: u32,
    outcome: &'a str,
    transition_reason: Option<String>,
    error: Option<String>,
}

fn browser_attempt(
    request: &PreparedRequest,
    target: &Url,
    data: BrowserAttemptData<'_>,
) -> Attempt {
    Attempt {
        provider: "browser".to_owned(),
        phase: "render".to_owned(),
        url: redact_url(target.as_str()),
        duration_ms: data.duration_ms,
        http_status: data.http_status,
        bytes: data.bytes,
        network_operations: data.network_operations,
        redirect_chain: Vec::new(),
        outcome: data.outcome.to_owned(),
        transition_reason: data.transition_reason,
        error: data
            .error
            .map(|value| sanitize_text(&value, request, target)),
    }
}

fn browser_failure(
    request: &PreparedRequest,
    target: &Url,
    started: std::time::Instant,
    failure: Failure,
    transition_reason: Option<String>,
    version: Option<String>,
    artifacts: Vec<Artifact>,
) -> RenderedFailure {
    let message = sanitize_text(&failure.message, request, target);
    RenderedFailure {
        failure: Failure::new(failure.code, message.clone()),
        attempt: browser_attempt(
            request,
            target,
            BrowserAttemptData {
                duration_ms: elapsed_ms(started),
                bytes: 0,
                http_status: None,
                network_operations: 0,
                outcome: "provider_failed",
                transition_reason,
                error: Some(message),
            },
        ),
        version,
        final_url: Some(target.clone()),
        final_url_observed: false,
        http_status: None,
        artifacts,
    }
}

/// Same as [`BrowserContext::fail`] but for a target and status observed during
/// capture rather than the originally requested one.
fn browser_failure_at_status(
    context: &BrowserContext<'_>,
    target: &Url,
    failure: Failure,
    http_status: Option<u16>,
) -> RenderedFailure {
    let mut failure = browser_failure(
        context.request,
        target,
        context.started,
        failure,
        context.transition_reason.clone(),
        context.version.clone(),
        Vec::new(),
    );
    failure.http_status = http_status;
    failure.attempt.http_status = http_status;
    failure
}

fn append_cleanup(mut failure: Failure, cleanup: Option<Failure>, label: &str) -> Failure {
    if let Some(cleanup) = cleanup {
        failure.message = format!("{}; {label} failed: {}", failure.message, cleanup.message);
    }
    failure
}

fn cdp_failure(error: eoka::Error) -> Failure {
    Failure::new(
        FailureCode::ProviderFailed,
        format!("browser DevTools operation failed: {error}"),
    )
}

fn cdp_config(timeout: Duration, version: &str) -> StealthConfig {
    let timeout_ms = timeout.as_millis();
    let timeout_secs = timeout_ms.div_ceil(1_000);
    StealthConfig {
        chrome_path: None,
        patch_binary: false,
        headless: true,
        user_agent: browser_user_agent(version),
        timezone: iana_time_zone::get_timezone().ok(),
        cdp_timeout: u64::try_from(timeout_secs).unwrap_or(u64::MAX).max(1),
        live_session: false,
        filter_cdp: true,
        aggressive_cdp_evasion: false,
        ..StealthConfig::default()
    }
}

fn browser_user_agent(version: &str) -> Option<String> {
    let full_version = version.split_whitespace().find(|part| {
        let mut components = part.split('.');
        let valid = components.by_ref().take(4).all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        });
        valid && components.next().is_none() && part.matches('.').count() == 3
    })?;
    eoka::Fingerprint::native_chrome_user_agent(full_version)
}

#[cfg(test)]
mod tests {
    use eoka::cdp::transport::CdpMessage;
    use serde_json::json;
    use tokio::sync::broadcast;
    use url::Url;

    use super::{
        MainDocumentStatus, browser_args, browser_user_agent, decode_screenshot,
        screenshot_pixel_limit,
    };
    use crate::domain::FailureCode;
    use crate::rendered::validate_browser_version;
    use base64::Engine as _;
    use std::path::Path;

    #[test]
    fn installed_chromium_family_browsers_are_accepted() {
        assert!(validate_browser_version("Google Chrome 150.0.0.0").is_ok());
        assert!(validate_browser_version("Chromium 150.0.0.0").is_ok());
        assert!(validate_browser_version("Microsoft Edge 150.0.0.0").is_ok());
        assert!(validate_browser_version("Firefox 150.0").is_err());
    }

    #[test]
    fn user_agent_uses_the_installed_browser_version() {
        let user_agent = browser_user_agent("Google Chrome 150.0.7871.187");
        assert!(user_agent.is_some_and(|value| value.contains("Chrome/150.0.7871.187")));
    }

    #[test]
    fn browser_launch_never_disables_the_sandbox_or_downloads_a_browser() {
        let args = browser_args(Path::new("/tmp/profile"), "http://127.0.0.1:1234")
            .into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(!args.iter().any(|value| value == "--no-sandbox"));
        assert!(args.iter().any(|value| value == "--headless=new"));
        assert!(
            args.iter()
                .any(|value| value == "--proxy-bypass-list=<-loopback>")
        );
        assert!(args.iter().any(|value| value == "--use-mock-keychain"));
    }

    #[test]
    fn screenshot_pixel_limit_is_tied_to_remaining_bytes() {
        assert_eq!(screenshot_pixel_limit(24 * 1024 * 1024), 4_194_304.0);
        assert_eq!(screenshot_pixel_limit(512), 85.0);
        assert_eq!(screenshot_pixel_limit(0), 0.0);
    }

    #[test]
    fn screenshot_decode_rejects_before_allocating_over_budget() {
        let data = base64::engine::general_purpose::STANDARD.encode([0_u8; 1024]);
        let result = decode_screenshot(data, 512);
        assert_eq!(
            result.as_ref().err().map(|failure| failure.code),
            Some(FailureCode::BudgetExhausted)
        );
    }

    #[test]
    fn screenshot_decode_preserves_valid_png_bytes() {
        let expected = b"png";
        let data = base64::engine::general_purpose::STANDARD.encode(expected);
        let result = decode_screenshot(data, expected.len());
        assert_eq!(result.as_deref(), Ok(expected.as_slice()));
    }

    #[tokio::test]
    async fn main_document_status_requires_exact_frame_id() {
        let (sender, receiver) = broadcast::channel(8);
        let mut status = MainDocumentStatus::new(
            receiver,
            "session".to_owned(),
            Some("main-frame".to_owned()),
        );

        let send_document = |frame_id: Option<&str>, response_status: u16| {
            assert!(
                sender
                    .send(CdpMessage::Event {
                        method: "Network.responseReceived".to_owned(),
                        params: json!({
                            "type": "Document",
                            "frameId": frame_id,
                            "response": {
                                "url": "https://example.com/",
                                "status": response_status,
                            },
                        }),
                        session_id: Some("session".to_owned()),
                    })
                    .is_ok()
            );
        };

        send_document(Some("main-frame"), 200);
        send_document(Some("iframe"), 404);
        send_document(None, 500);
        status.drain();

        let final_url = Url::parse("https://example.com/");
        assert!(final_url.is_ok());
        let Some(final_url) = final_url.ok() else {
            return;
        };
        assert_eq!(status.resolve(&final_url), Some(200));
    }

    #[tokio::test]
    async fn main_document_status_reports_broadcast_lag() {
        let (sender, receiver) = broadcast::channel(1);
        let mut status = MainDocumentStatus::new(receiver, "session".to_owned(), None);
        for response_status in [404, 500] {
            assert!(
                sender
                    .send(CdpMessage::Event {
                        method: "Network.loadingFinished".to_owned(),
                        params: json!({ "status": response_status }),
                        session_id: Some("session".to_owned()),
                    })
                    .is_ok()
            );
        }

        status.drain();

        assert!(
            status
                .diagnostic()
                .contains("DevTools event buffer overflowed")
        );
    }
}
