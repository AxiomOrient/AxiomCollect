use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::budget::BudgetTracker;
use crate::domain::{Artifact, Attempt, BrowserCapability, Failure, FailureCode, redact_url};
use crate::egress::EgressProxy;
use crate::policy::{parse_url, validate_and_resolve};
use crate::process::{
    CommandSpec, first_line, isolated_environment, probe_version, resolve_executable, run_command,
};
use crate::rendered::{
    RenderedFailure, RenderedOutput, RuntimeConfig, create_private_directory, create_sandbox,
    elapsed_ms, hardened_browser_args, resolve_browser, sanitize_text, screenshot_path, session_id,
    shutdown_egress, validate_browser_version, write_artifact,
};
use crate::request::PreparedRequest;

const HELPER_SOURCE: &str = include_str!("../puppeteer-rescue/puppeteer-helper.mjs");
#[cfg(test)]
const PACKAGE_SOURCE: &str = include_str!("../puppeteer-rescue/package.json");
const REQUIRED_PUPPETEER_VERSION: &str = "25.4.0";
const STDERR_LIMIT: usize = 64 * 1024;
/// Kept identical to the primary browser backend's ceiling so both rendered paths
/// bound a full-page capture the same way.
const MAX_SCREENSHOT_PIXELS: usize = 25_000_000;

#[derive(Debug)]
struct RescueRuntime {
    node: PathBuf,
    module_root: PathBuf,
}

#[derive(Debug)]
pub(crate) struct PuppeteerProbe {
    pub node: PathBuf,
    pub node_version: String,
    pub module_root: PathBuf,
    pub puppeteer_version: String,
    pub browser_version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HelperInput {
    browser_executable: String,
    module_root: String,
    output_directory: String,
    target_url: String,
    browser_args: Vec<String>,
    timeout_ms: u64,
    quiet_window_ms: u64,
    poll_interval_ms: u64,
    max_response_bytes: usize,
    max_screenshot_bytes: usize,
    max_screenshot_pixels: usize,
    screenshot: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HelperStatus {
    ok: bool,
    puppeteer_version: String,
    http_status: Option<u16>,
}

/// Typed failure contract the helper writes to stdout before exiting non-zero.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HelperFailure {
    code: String,
    message: String,
}

impl HelperFailure {
    fn into_failure(self) -> Failure {
        let code = match self.code.as_str() {
            "budget_exhausted" => FailureCode::BudgetExhausted,
            "content_empty" => FailureCode::ContentEmpty,
            "invalid_request" => FailureCode::InvalidRequest,
            "provider_unsupported" => FailureCode::ProviderUnsupported,
            _ => FailureCode::ProviderFailed,
        };
        Failure::new(code, format!("Puppeteer rescue failed: {}", self.message))
    }
}

#[must_use]
pub(crate) fn is_configured(config: &RuntimeConfig) -> bool {
    config.puppeteer_root.is_some()
}

pub(crate) async fn probe_runtime(config: &RuntimeConfig) -> Result<PuppeteerProbe, Failure> {
    let runtime = resolve_runtime(config)?;
    let browser_path = resolve_browser(config.browser.as_deref())?;
    let sandbox = create_sandbox()?;
    let environment = isolated_environment(sandbox.path());
    let browser_version = probe_version(
        &browser_path,
        sandbox.path(),
        &environment,
        Duration::from_secs(5),
    )
    .await
    .and_then(|version| {
        validate_browser_version(&version)?;
        Ok(version)
    })?;
    let node_version = probe_version(
        &runtime.node,
        sandbox.path(),
        &environment,
        Duration::from_secs(5),
    )
    .await
    .and_then(validate_node_version)?;
    create_private_directory(&sandbox.path().join("browser-profile")).await?;
    let helper_path = sandbox.path().join("puppeteer-helper.mjs");
    tokio::fs::write(&helper_path, HELPER_SOURCE)
        .await
        .map_err(|error| {
            Failure::new(
                FailureCode::ProviderFailed,
                format!("failed to prepare Puppeteer capability probe: {error}"),
            )
        })?;
    let proxy = EgressProxy::start(8, 1024 * 1024).await?;
    let input = HelperInput {
        browser_executable: browser_path.to_string_lossy().into_owned(),
        module_root: runtime.module_root.to_string_lossy().into_owned(),
        output_directory: sandbox.path().to_string_lossy().into_owned(),
        target_url: "about:blank".to_owned(),
        browser_args: hardened_browser_args(proxy.endpoint()),
        timeout_ms: 10_000,
        quiet_window_ms: 500,
        poll_interval_ms: 100,
        max_response_bytes: 1024 * 1024,
        max_screenshot_bytes: 1024 * 1024,
        max_screenshot_pixels: MAX_SCREENSHOT_PIXELS,
        screenshot: false,
    };
    let input = serde_json::to_vec(&input).map_err(|error| {
        Failure::new(
            FailureCode::InternalError,
            format!("failed to serialize Puppeteer capability probe: {error}"),
        )
    })?;
    let command = run_command(CommandSpec {
        executable: runtime.node.clone(),
        args: vec![OsString::from(&helper_path)],
        environment,
        current_dir: sandbox.path().to_path_buf(),
        stdin: Some(input),
        timeout: Duration::from_secs(15),
        stdout_limit: 8 * 1024,
        stderr_limit: STDERR_LIMIT,
    })
    .await;
    let egress = proxy.shutdown().await;
    if let Some(fatal) = egress.fatal_error {
        return Err(Failure::new(
            fatal.code,
            format!(
                "Puppeteer capability probe egress failed: {}",
                fatal.message
            ),
        ));
    }
    let command = command?;
    if command.timed_out {
        return Err(Failure::new(
            FailureCode::ToolUnavailable,
            "Puppeteer capability probe timed out",
        ));
    }
    if !command.success {
        return Err(Failure::new(
            FailureCode::ToolUnavailable,
            format!(
                "Puppeteer capability probe failed with status {:?}: {}",
                command.status_code,
                first_line(&command.stderr)
            ),
        ));
    }
    let status = serde_json::from_slice::<HelperStatus>(&command.stdout).map_err(|error| {
        Failure::new(
            FailureCode::ToolUnavailable,
            format!("Puppeteer capability probe returned invalid JSON: {error}"),
        )
    })?;
    if !status.ok || status.puppeteer_version != REQUIRED_PUPPETEER_VERSION {
        return Err(Failure::new(
            FailureCode::ProviderUnsupported,
            format!(
                "Puppeteer rescue version mismatch: expected {REQUIRED_PUPPETEER_VERSION}, got {}",
                status.puppeteer_version
            ),
        ));
    }
    let html = read_bounded(&sandbox.path().join("page.html"), 1024 * 1024).await?;
    if html.is_empty() {
        return Err(Failure::new(
            FailureCode::ToolUnavailable,
            "Puppeteer capability probe captured no DOM",
        ));
    }
    Ok(PuppeteerProbe {
        node: runtime.node,
        node_version,
        module_root: runtime.module_root,
        puppeteer_version: status.puppeteer_version,
        browser_version,
    })
}

/// Accumulates the provenance that every rendered-rescue failure has to carry.
///
/// Each fallible step reports the same request, target, elapsed time, transition
/// reason, browser version, and egress operation count. Threading them through one
/// value keeps each step's error handling to a single call and makes it impossible
/// for one site to forget a field the others record.
struct RescueContext<'a> {
    request: &'a PreparedRequest,
    target: &'a Url,
    started: std::time::Instant,
    transition_reason: Option<String>,
    version: Option<String>,
    network_operations: u32,
}

impl RescueContext<'_> {
    fn fail(&self, failure: Failure) -> RenderedFailure {
        rescue_failure(
            self.request,
            self.target,
            self.started,
            failure,
            self.transition_reason.clone(),
            self.version.clone(),
            self.network_operations,
        )
    }

    fn fail_with(&self, code: FailureCode, message: impl Into<String>) -> RenderedFailure {
        self.fail(Failure::new(code, message))
    }

    fn fail_at_status(&self, failure: Failure, http_status: u16) -> RenderedFailure {
        let mut failure = self.fail(failure);
        failure.http_status = Some(http_status);
        failure.attempt.http_status = Some(http_status);
        failure
    }
}

pub(crate) async fn run_rendered(
    request: &PreparedRequest,
    target: &Url,
    budget: &mut BudgetTracker,
    config: &RuntimeConfig,
    transition_reason: Option<String>,
) -> Result<RenderedOutput, RenderedFailure> {
    let mut context = RescueContext {
        request,
        target,
        started: std::time::Instant::now(),
        transition_reason,
        version: None,
        network_operations: 0,
    };

    let runtime = resolve_runtime(config).map_err(|failure| context.fail(failure))?;
    let browser_path =
        resolve_browser(config.browser.as_deref()).map_err(|failure| context.fail(failure))?;
    budget
        .reserve_browser_launch()
        .map_err(|failure| context.fail(failure))?;
    let sandbox = create_sandbox().map_err(|failure| context.fail(failure))?;
    let environment = isolated_environment(sandbox.path());

    let browser_version = probe_version(
        &browser_path,
        sandbox.path(),
        &environment,
        budget.remaining_wall().min(Duration::from_secs(5)),
    )
    .await
    .and_then(|version| {
        validate_browser_version(&version)?;
        Ok(version)
    })
    .map_err(|failure| context.fail(failure))?;
    context.version = Some(browser_version.clone());

    let node_version = probe_version(
        &runtime.node,
        sandbox.path(),
        &environment,
        budget.remaining_wall().min(Duration::from_secs(5)),
    )
    .await
    .and_then(validate_node_version)
    .map_err(|failure| context.fail(failure))?;

    let profile = sandbox.path().join("browser-profile");
    create_private_directory(&profile)
        .await
        .map_err(|failure| context.fail(failure))?;
    let helper_path = sandbox.path().join("puppeteer-helper.mjs");
    tokio::fs::write(&helper_path, HELPER_SOURCE)
        .await
        .map_err(|error| {
            context.fail_with(
                FailureCode::ProviderFailed,
                format!("failed to prepare Puppeteer helper: {error}"),
            )
        })?;

    let mut proxy = Some(
        EgressProxy::start(
            budget.remaining_network_operations(),
            budget.remaining_total_bytes(),
        )
        .await
        .map_err(|failure| context.fail(failure))?,
    );
    let proxy_endpoint = proxy
        .as_ref()
        .map(EgressProxy::endpoint)
        .unwrap_or_default();
    let helper_input = HelperInput {
        browser_executable: browser_path.to_string_lossy().into_owned(),
        module_root: runtime.module_root.to_string_lossy().into_owned(),
        output_directory: sandbox.path().to_string_lossy().into_owned(),
        target_url: target.as_str().to_owned(),
        browser_args: hardened_browser_args(proxy_endpoint),
        timeout_ms: request
            .execution
            .budget
            .read_timeout_ms
            .min(duration_ms(budget.remaining_wall()))
            .max(1),
        quiet_window_ms: 500,
        poll_interval_ms: 100,
        max_response_bytes: request
            .execution
            .budget
            .max_response_bytes
            .min(budget.remaining_total_bytes()),
        max_screenshot_bytes: budget.remaining_total_bytes(),
        max_screenshot_pixels: MAX_SCREENSHOT_PIXELS,
        screenshot: request.intent.browser_capability == BrowserCapability::Screenshot,
    };
    let input = serde_json::to_vec(&helper_input).map_err(|error| {
        context.fail_with(
            FailureCode::InternalError,
            format!("failed to serialize Puppeteer helper input: {error}"),
        )
    })?;
    let command = run_command(CommandSpec {
        executable: runtime.node,
        args: vec![OsString::from(&helper_path)],
        environment,
        current_dir: sandbox.path().to_path_buf(),
        stdin: Some(input),
        timeout: budget.remaining_wall(),
        stdout_limit: 8 * 1024,
        stderr_limit: STDERR_LIMIT,
    })
    .await;

    let stats = shutdown_egress(&mut proxy, budget)
        .await
        .map_err(|failure| context.fail(failure))?;
    context.network_operations = stats.connection_operations;

    let command = command.map_err(|failure| context.fail(failure))?;
    if command.timed_out {
        return Err(context.fail_with(
            FailureCode::BudgetExhausted,
            "Puppeteer rescue exceeded the remaining wall-clock budget",
        ));
    }
    if !command.success {
        // The helper reports its own typed reason on stdout; stderr is only a
        // fallback for a process that died before it could write one.
        let failure = serde_json::from_slice::<HelperFailure>(&command.stdout)
            .map(HelperFailure::into_failure)
            .unwrap_or_else(|_| {
                let diagnostic = first_line(&command.stderr);
                Failure::new(
                    FailureCode::ProviderFailed,
                    if diagnostic.is_empty() {
                        format!(
                            "Puppeteer rescue exited with status {:?} without diagnostics",
                            command.status_code
                        )
                    } else {
                        format!("Puppeteer rescue failed: {diagnostic}")
                    },
                )
            });
        return Err(context.fail(failure));
    }
    let status = serde_json::from_slice::<HelperStatus>(&command.stdout).map_err(|error| {
        context.fail_with(
            FailureCode::ProviderFailed,
            format!("Puppeteer rescue returned invalid status JSON: {error}"),
        )
    })?;
    if !status.ok || status.puppeteer_version != REQUIRED_PUPPETEER_VERSION {
        return Err(context.fail_with(
            FailureCode::ProviderUnsupported,
            format!(
                "Puppeteer rescue version mismatch: expected {REQUIRED_PUPPETEER_VERSION}, got {}",
                status.puppeteer_version
            ),
        ));
    }
    let http_status = status.http_status.ok_or_else(|| {
        context.fail_with(
            FailureCode::ProviderFailed,
            "Puppeteer rescue did not report the main-document HTTP status",
        )
    })?;

    let final_url_text = read_bounded(&sandbox.path().join("final-url.txt"), 16 * 1024)
        .await
        .map_err(|failure| context.fail(failure))?;
    let final_url = parse_url(
        std::str::from_utf8(&final_url_text)
            .unwrap_or_default()
            .trim(),
    )
    .map_err(|failure| {
        context.fail_with(
            FailureCode::PolicyRejected,
            format!(
                "Puppeteer rescue reported an invalid final URL: {}",
                failure.message
            ),
        )
    })?;
    let dns_timeout = budget.remaining_wall().min(Duration::from_millis(
        request.execution.budget.connect_timeout_ms,
    ));
    validate_and_resolve(final_url.clone(), request.execution.network, dns_timeout)
        .await
        .map_err(|failure| {
            context.fail_with(
                FailureCode::PolicyRejected,
                format!("Puppeteer rescue final URL rejected: {}", failure.message),
            )
        })?;
    if !(200..=299).contains(&http_status) {
        let mut failure = context.fail_at_status(
            Failure::new(
                FailureCode::HttpRejected,
                format!(
                    "Puppeteer rescue main-document HTTP status {http_status} is not usable content"
                ),
            ),
            http_status,
        );
        failure.final_url = Some(final_url);
        failure.final_url_observed = true;
        return Err(failure);
    }

    let html = read_bounded(
        &sandbox.path().join("page.html"),
        request.execution.budget.max_response_bytes,
    )
    .await
    .map_err(|failure| context.fail(failure))?;
    if html.iter().all(u8::is_ascii_whitespace) {
        return Err(context.fail_with(
            FailureCode::ContentEmpty,
            "Puppeteer rescue returned an empty document",
        ));
    }
    budget
        .reserve_response_bytes(0, html.len())
        .map_err(|failure| context.fail(failure))?;

    let mut artifacts = Vec::new();
    if request.intent.browser_capability == BrowserCapability::Screenshot {
        let screenshot = read_bounded(
            &sandbox.path().join("screenshot.png"),
            budget.remaining_total_bytes(),
        )
        .await
        .map_err(|failure| context.fail(failure))?;
        budget
            .reserve_artifact_bytes(screenshot.len())
            .map_err(|failure| context.fail(failure))?;
        let path = screenshot_path(request, &session_id())
            .await
            .map_err(|failure| context.fail(failure))?;
        let artifact = write_artifact("screenshot", &path, "image/png", &screenshot)
            .await
            .map_err(|failure| context.fail(failure))?;
        artifacts.push(artifact);
    }

    let version = format!(
        "puppeteer-core/{}; {}; {}",
        status.puppeteer_version, node_version, browser_version
    );
    Ok(RenderedOutput {
        version: Some(version),
        final_url,
        final_url_observed: true,
        http_status: Some(http_status),
        body: html.clone(),
        forged: None,
        attempt: rescue_attempt(
            request,
            target,
            elapsed_ms(context.started),
            html.len(),
            Some(http_status),
            context.network_operations,
            "provider_accepted",
            context.transition_reason,
            None,
        ),
        artifacts,
    })
}

fn resolve_runtime(config: &RuntimeConfig) -> Result<RescueRuntime, Failure> {
    let module_root = config.puppeteer_root.clone().ok_or_else(|| {
        Failure::new(
            FailureCode::ToolUnavailable,
            "Puppeteer rescue is not configured; use --puppeteer-root or AXIOM_COLLECT_PUPPETEER_ROOT",
        )
    })?;
    for required in [
        module_root.join("package.json"),
        module_root.join("node_modules/puppeteer-core/package.json"),
    ] {
        if !required.is_file() {
            return Err(Failure::new(
                FailureCode::ToolUnavailable,
                format!(
                    "Puppeteer rescue dependency is missing: {}; prepare the external runtime from puppeteer-rescue/package.json and package-lock.json with npm ci --ignore-scripts",
                    required.display()
                ),
            ));
        }
    }
    let node = resolve_executable(config.node.as_deref(), &["node"])?;
    Ok(RescueRuntime { node, module_root })
}

fn validate_node_version(version: String) -> Result<String, Failure> {
    let numeric = version.trim().strip_prefix('v').unwrap_or_default();
    let major = numeric
        .split('.')
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_default();
    if major < 20 {
        return Err(Failure::new(
            FailureCode::ProviderUnsupported,
            format!("Puppeteer rescue requires Node.js 20 or newer, got {version}"),
        ));
    }
    Ok(format!("node/{numeric}"))
}

async fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Failure> {
    let metadata = tokio::fs::metadata(path).await.map_err(|error| {
        Failure::new(
            FailureCode::ProviderFailed,
            format!("Puppeteer rescue output is missing: {error}"),
        )
    })?;
    let length = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if length == 0 {
        return Err(Failure::new(
            FailureCode::ContentEmpty,
            "Puppeteer rescue output is empty",
        ));
    }
    if length > limit {
        return Err(Failure::new(
            FailureCode::BudgetExhausted,
            "Puppeteer rescue output exceeds its byte budget",
        ));
    }
    tokio::fs::read(path).await.map_err(|error| {
        Failure::new(
            FailureCode::ProviderFailed,
            format!("failed to read Puppeteer rescue output: {error}"),
        )
    })
}

fn rescue_failure(
    request: &PreparedRequest,
    target: &Url,
    started: std::time::Instant,
    failure: Failure,
    transition_reason: Option<String>,
    version: Option<String>,
    network_operations: u32,
) -> RenderedFailure {
    let message = sanitize_text(&failure.message, request, target);
    RenderedFailure {
        failure: Failure::new(failure.code, message.clone()),
        attempt: rescue_attempt(
            request,
            target,
            elapsed_ms(started),
            0,
            None,
            network_operations,
            "provider_failed",
            transition_reason,
            Some(message),
        ),
        version,
        final_url: Some(target.clone()),
        final_url_observed: false,
        http_status: None,
        artifacts: Vec::<Artifact>::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn rescue_attempt(
    request: &PreparedRequest,
    target: &Url,
    duration_ms: u64,
    bytes: usize,
    http_status: Option<u16>,
    network_operations: u32,
    outcome: &str,
    transition_reason: Option<String>,
    error: Option<String>,
) -> Attempt {
    Attempt {
        provider: "browser_puppeteer".to_owned(),
        phase: "render_rescue".to_owned(),
        url: redact_url(target.as_str()),
        duration_ms,
        http_status,
        bytes,
        network_operations,
        redirect_chain: Vec::new(),
        outcome: outcome.to_owned(),
        transition_reason,
        error: error.map(|value| sanitize_text(&value, request, target)),
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{PACKAGE_SOURCE, REQUIRED_PUPPETEER_VERSION, is_configured, validate_node_version};
    use crate::rendered::RuntimeConfig;

    #[test]
    fn rescue_is_opt_in_through_an_explicit_module_root() {
        assert!(!is_configured(&RuntimeConfig::default()));
        assert!(is_configured(&RuntimeConfig {
            puppeteer_root: Some(PathBuf::from("/tmp/puppeteer")),
            ..RuntimeConfig::default()
        }));
    }

    #[test]
    fn node_20_or_newer_is_required() {
        assert!(validate_node_version("v20.0.0".to_owned()).is_ok());
        assert!(validate_node_version("v19.9.0".to_owned()).is_err());
        assert!(validate_node_version("not-node".to_owned()).is_err());
    }

    #[test]
    fn configured_package_and_runtime_version_gate_are_identical() {
        let package = serde_json::from_str::<serde_json::Value>(PACKAGE_SOURCE);
        assert!(package.is_ok());
        let Some(package) = package.ok() else {
            return;
        };
        assert_eq!(
            package
                .pointer("/dependencies/puppeteer-core")
                .and_then(serde_json::Value::as_str),
            Some(REQUIRED_PUPPETEER_VERSION)
        );
    }
}
