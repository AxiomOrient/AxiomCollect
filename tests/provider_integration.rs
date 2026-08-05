#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use axiom_collect::{
    BrowserCapability, Engine, EvidenceSpec, EvidenceStatus, ExecutionPolicy, FailureCode,
    FetchRequest, RetrievalMode, RuntimeConfig,
};
use tempfile::tempdir;

fn executable(directory: &Path, name: &str, source: &str) -> std::io::Result<std::path::PathBuf> {
    let path = directory.join(name);
    fs::write(&path, source)?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

#[tokio::test]
async fn non_chromium_browser_is_rejected_before_launch() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let browser = executable(
        directory.path(),
        "not-a-chromium-browser",
        "#!/bin/sh\nprintf '%s\\n' 'Firefox 150.0'\n",
    )?;
    let runtime = RuntimeConfig {
        browser: Some(browser),
        ..RuntimeConfig::default()
    };
    let mut request = FetchRequest::new("https://example.com/");
    request.mode = RetrievalMode::Rendered;
    let result = Engine::public(runtime).fetch(request).await;
    assert!(!result.ok);
    assert_eq!(result.failure_provider.as_deref(), Some("browser"));
    assert!(
        result
            .failure
            .as_ref()
            .is_some_and(|failure| failure.message.contains("not a Chromium-family browser"))
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires an installed Chromium-family browser and public network; run this test explicitly"]
async fn installed_browser_captures_dom_and_screenshot() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let artifacts = directory.path().join("artifacts");
    let execution = ExecutionPolicy {
        artifact_dir: Some(artifacts),
        ..ExecutionPolicy::default()
    };
    let mut request = FetchRequest::new("https://example.com/");
    request.mode = RetrievalMode::Rendered;
    request.browser_capability = BrowserCapability::Screenshot;
    request.evidence = EvidenceSpec {
        selectors: vec!["h1".to_owned()],
        required_text: vec!["Example Domain".to_owned()],
        minimum_text_bytes: Some(20),
    };
    let result = Engine::new(RuntimeConfig::default(), execution)
        .fetch(request)
        .await;
    assert!(result.ok, "{:?}", result.failure);
    assert_eq!(result.provider_used.as_deref(), Some("browser"));
    assert!(result.final_url_observed);
    assert!(result.content.contains("Example Domain"));
    assert_eq!(result.artifacts.len(), 1);
    let artifact = result.artifacts.first();
    assert!(artifact.is_some_and(|value| value.bytes > 0 && value.sha256.len() == 64));
    assert!(artifact.is_some_and(|value| Path::new(&value.path).is_file()));
    assert!(result.validate_invariants().is_ok());
    Ok(())
}

#[tokio::test]
#[ignore = "requires an installed Chromium-family browser and public network; run this test explicitly"]
async fn installed_browser_renders_javascript_content() -> Result<(), Box<dyn std::error::Error>> {
    let mut request = FetchRequest::new("https://quotes.toscrape.com/js/");
    request.mode = RetrievalMode::Rendered;
    request.evidence = EvidenceSpec {
        selectors: vec![".quote .text".to_owned()],
        required_text: vec![
            "The world as we have created it is a process of our thinking".to_owned(),
        ],
        minimum_text_bytes: Some(500),
    };

    let result = Engine::public(RuntimeConfig::default())
        .fetch(request)
        .await;

    assert!(result.ok, "{:?}", result.failure);
    assert_eq!(result.provider_used.as_deref(), Some("browser"));
    assert!(result.final_url_observed);
    assert_eq!(result.evidence_status, EvidenceStatus::Satisfied);
    assert!(result.content.contains("Albert Einstein"));
    assert!(
        result
            .trace
            .iter()
            .any(|attempt| attempt.provider == "browser" && attempt.network_operations > 1)
    );
    assert!(result.validate_invariants().is_ok());
    Ok(())
}

#[tokio::test]
#[ignore = "requires an installed Chromium-family browser and public network; run this test explicitly"]
async fn rendered_main_document_error_status_is_not_content_success()
-> Result<(), Box<dyn std::error::Error>> {
    let mut request = FetchRequest::new("https://example.com/axiom-collect-missing-page");
    request.mode = RetrievalMode::Rendered;

    let result = Engine::public(RuntimeConfig::default())
        .fetch(request)
        .await;

    assert!(!result.ok);
    assert_eq!(
        result.failure.as_ref().map(|failure| failure.code),
        Some(FailureCode::HttpRejected)
    );
    assert_eq!(result.http_status, Some(404));
    assert!(result.final_url_observed);
    assert_eq!(result.failure_provider.as_deref(), Some("browser"));
    assert!(
        result
            .trace
            .iter()
            .any(|attempt| attempt.http_status == Some(404))
    );
    assert!(result.validate_invariants().is_ok());
    Ok(())
}

#[tokio::test]
#[ignore = "requires AXIOM_COLLECT_TEST_BROWSER and AXIOM_COLLECT_TEST_PUPPETEER_ROOT"]
async fn puppeteer_rescue_recovers_after_primary_browser_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let browser = std::env::var("AXIOM_COLLECT_TEST_BROWSER")?;
    let puppeteer_root = std::env::var("AXIOM_COLLECT_TEST_PUPPETEER_ROOT")?;
    let directory = tempdir()?;
    let state = directory.path().join("browser-launch-count");
    let launched_pid = directory.path().join("rescue-browser.pid");
    let wrapper_source = format!(
        r#"#!/bin/sh
BROWSER={}
STATE={}
PID_FILE={}
if [ "${{1:-}}" = "--version" ]; then
  exec "$BROWSER" --version
fi
COUNT=0
if [ -f "$STATE" ]; then
  IFS= read -r COUNT < "$STATE"
fi
COUNT=$((COUNT + 1))
printf '%s\n' "$COUNT" > "$STATE"
if [ $((COUNT % 2)) -eq 1 ]; then
  exit 42
fi
printf '%s\n' "$$" > "$PID_FILE"
exec "$BROWSER" "$@"
"#,
        shell_quote(&browser),
        shell_quote(&state.to_string_lossy()),
        shell_quote(&launched_pid.to_string_lossy()),
    );
    let wrapper = executable(directory.path(), "browser-wrapper", &wrapper_source)?;
    let runtime = RuntimeConfig {
        browser: Some(wrapper),
        puppeteer_root: Some(puppeteer_root.into()),
        ..RuntimeConfig::default()
    };
    let mut request = FetchRequest::new("https://quotes.toscrape.com/js/");
    request.mode = RetrievalMode::Rendered;
    request.browser_capability = BrowserCapability::Screenshot;
    request.evidence = EvidenceSpec {
        selectors: vec![".quote .text".to_owned()],
        required_text: vec!["Albert Einstein".to_owned()],
        minimum_text_bytes: Some(500),
    };

    let execution = ExecutionPolicy {
        artifact_dir: Some(directory.path().join("artifacts")),
        ..ExecutionPolicy::default()
    };
    let engine = Engine::new(runtime, execution);
    let result = engine.fetch(request).await;

    assert!(result.ok, "{:?}", result.failure);
    assert_eq!(result.provider_used.as_deref(), Some("browser_puppeteer"));
    assert_eq!(
        result
            .trace
            .iter()
            .map(|attempt| attempt.provider.as_str())
            .collect::<Vec<_>>(),
        vec!["browser", "browser_puppeteer"]
    );
    assert_eq!(result.budget.browser_launches, 2);
    assert_eq!(result.evidence_status, EvidenceStatus::Satisfied);
    assert!(result.content.contains("Albert Einstein"));
    assert_eq!(result.artifacts.len(), 1);
    assert!(
        result
            .artifacts
            .first()
            .is_some_and(|artifact| artifact.bytes > 0 && Path::new(&artifact.path).is_file())
    );
    assert!(result.validate_invariants().is_ok());

    let mut error_request = FetchRequest::new("https://example.com/axiom-collect-missing-page");
    error_request.mode = RetrievalMode::Rendered;
    let error_result = engine.fetch(error_request).await;
    assert!(!error_result.ok);
    assert_eq!(
        error_result.failure.as_ref().map(|failure| failure.code),
        Some(FailureCode::HttpRejected)
    );
    assert_eq!(error_result.http_status, Some(404));
    assert!(error_result.final_url_observed);
    assert_eq!(
        error_result.failure_provider.as_deref(),
        Some("browser_puppeteer")
    );
    assert_eq!(
        error_result
            .trace
            .iter()
            .map(|attempt| attempt.provider.as_str())
            .collect::<Vec<_>>(),
        vec!["browser", "browser_puppeteer"]
    );
    assert!(error_result.validate_invariants().is_ok());

    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let pid = fs::read_to_string(launched_pid)?.trim().to_owned();
    let still_running = std::process::Command::new("/bin/kill")
        .args(["-0", &pid])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    assert!(
        !still_running,
        "Puppeteer rescue left Chrome process {pid} running"
    );
    Ok(())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
