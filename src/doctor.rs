use schemars::JsonSchema;
use serde::Serialize;
use std::path::Path;

use crate::browser::probe_runtime;
use crate::domain::{BudgetConfig, PRODUCT_VERSION, SCHEMA_VERSION};
use crate::puppeteer;
use crate::rendered::RuntimeConfig;
use crate::transport::probe_static_stack;

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ToolStatus {
    pub name: String,
    pub ready: bool,
    pub configured_path: Option<String>,
    pub resolved_path: Option<String>,
    pub version: Option<String>,
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DoctorReport {
    pub product: String,
    pub product_version: String,
    pub schema_version: u32,
    pub core_ok: bool,
    pub static_ready: bool,
    pub static_diagnostic: Option<String>,
    pub browser: ToolStatus,
    pub puppeteer_rescue: ToolStatus,
    pub rendered_ready: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CapabilitiesReport {
    pub product: String,
    pub product_version: String,
    pub schema_version: u32,
    pub canonical_interface: String,
    pub optional_interface: String,
    pub backends: Vec<BackendCapability>,
    pub success_contract: Vec<String>,
    pub security_contract: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct BackendCapability {
    pub name: String,
    pub built_in: bool,
    pub requires_external_program: bool,
    pub capabilities: Vec<String>,
    pub limitations: Vec<String>,
}

pub async fn run(config: RuntimeConfig) -> DoctorReport {
    let (browser, puppeteer_rescue) =
        tokio::join!(inspect_browser(&config), inspect_puppeteer(&config));
    let rendered_ready = browser.ready || puppeteer_rescue.ready;
    // Static readiness is measured, not asserted: the built-in HTTP stack has to be
    // constructible on this host for `static` mode and the HTTP leg of `auto` to work.
    let static_diagnostic = probe_static_stack(&BudgetConfig::default())
        .err()
        .map(|failure| failure.message);
    let static_ready = static_diagnostic.is_none();
    let mut notes = vec![
        "static HTTP retrieval is built into the Rust binary".to_owned(),
        "rendered mode uses eoka CDP first and an explicitly configured Puppeteer Core rescue second"
            .to_owned(),
        "browser discovery may use an existing Chrome, Chromium, Brave, or Edge installation"
            .to_owned(),
        "Chromium-family browser downloads, installers, and bundled runtimes are forbidden"
            .to_owned(),
        "Puppeteer rescue setup installs only the exact puppeteer-core library with lifecycle scripts disabled"
            .to_owned(),
        "each rendered request uses an isolated temporary profile and never reuses the user profile"
            .to_owned(),
    ];
    if !rendered_ready {
        notes.push(
            "rendered DOM and screenshot capabilities require an installed Chromium-family browser"
                .to_owned(),
        );
    }
    DoctorReport {
        product: "axiom-collect".to_owned(),
        product_version: PRODUCT_VERSION.to_owned(),
        schema_version: SCHEMA_VERSION,
        // The product cannot retrieve anything at all without the static stack, so
        // core readiness is exactly static readiness rather than a constant.
        core_ok: static_ready,
        static_ready,
        static_diagnostic,
        browser,
        puppeteer_rescue,
        rendered_ready,
        notes,
    }
}

#[must_use]
pub fn capabilities() -> CapabilitiesReport {
    CapabilitiesReport {
        product: "axiom-collect".to_owned(),
        product_version: PRODUCT_VERSION.to_owned(),
        schema_version: SCHEMA_VERSION,
        canonical_interface: "CLI JSON".to_owned(),
        optional_interface: "stdio MCP".to_owned(),
        backends: vec![
            BackendCapability {
                name: "http".to_owned(),
                built_in: true,
                requires_external_program: false,
                capabilities: vec![
                    "public HTTP(S) retrieval".to_owned(),
                    "manual redirect validation".to_owned(),
                    "HTML, JSON, XML, text, and PDF extraction".to_owned(),
                ],
                limitations: vec!["does not execute JavaScript".to_owned()],
            },
            BackendCapability {
                name: "public_routes".to_owned(),
                built_in: true,
                requires_external_program: false,
                capabilities: vec![
                    "bounded public API and RSS fallback".to_owned(),
                    "platform metadata endpoints and safe URL variants".to_owned(),
                    "Wayback CDX lookup followed by a verified public snapshot replay".to_owned(),
                    "optional Jina Reader public-route fallback".to_owned(),
                    "per-route URL and transition provenance".to_owned(),
                ],
                limitations: vec![
                    "uses no-auth public endpoints only".to_owned(),
                    "detects and refuses CAPTCHA, authentication, and paywall gates".to_owned(),
                    "external reader routes are skipped for sensitive query keys".to_owned(),
                ],
            },
            BackendCapability {
                name: "media_oembed".to_owned(),
                built_in: true,
                requires_external_program: false,
                capabilities: vec![
                    "public oEmbed metadata for YouTube, Vimeo, and SoundCloud".to_owned(),
                    "uses the built-in Rust HTTP transport and its public-network controls"
                        .to_owned(),
                    "allowlists scalar metadata without media, embed, thumbnail, or signed URLs"
                        .to_owned(),
                ],
                limitations: vec![
                    "supports only the built-in YouTube, Vimeo, and SoundCloud catalog"
                        .to_owned(),
                    "does not use credentials, cookies, netrc, Python, or external executables"
                        .to_owned(),
                    "does not download media, captions, thumbnails, or embed HTML".to_owned(),
                ],
            },
            BackendCapability {
                name: "browser".to_owned(),
                built_in: false,
                requires_external_program: true,
                capabilities: vec![
                    "JavaScript execution and full rendering".to_owned(),
                    "post-render DOM extraction".to_owned(),
                    "full-page screenshot artifact".to_owned(),
                ],
                limitations: vec![
                    "requires an existing Chromium-family browser installation".to_owned(),
                    "private-network retrieval is intentionally unavailable".to_owned(),
                    "browser installation and download are intentionally unavailable".to_owned(),
                ],
            },
            BackendCapability {
                name: "browser_puppeteer".to_owned(),
                built_in: false,
                requires_external_program: true,
                capabilities: vec![
                    "isolated rendered recovery after the primary eoka backend fails".to_owned(),
                    "JavaScript DOM and full-page screenshot capture".to_owned(),
                ],
                limitations: vec![
                    "requires Node.js 20+, an explicitly prepared puppeteer-core runtime, and an existing Chromium-family browser".to_owned(),
                    "never installs or downloads Chrome or Chromium".to_owned(),
                ],
            },
        ],
        success_contract: vec![
            "transport or browser capture completed".to_owned(),
            "content extraction produced usable content".to_owned(),
            "all requested evidence checks passed".to_owned(),
        ],
        security_contract: vec![
            "public network only by default".to_owned(),
            "credentials and credential-like query parameters in URLs are rejected".to_owned(),
            "redirect and rendered final URLs are revalidated".to_owned(),
            "browser egress is enforced by a local public-only proxy".to_owned(),
            "public route fallback never authenticates or forwards sensitive query keys to an external reader"
                .to_owned(),
            "query values are redacted from output traces".to_owned(),
            "the browser uses an isolated temporary profile and process tree".to_owned(),
            "explicit modes never silently change HTTP versus rendered intent".to_owned(),
        ],
    }
}

async fn inspect_browser(config: &RuntimeConfig) -> ToolStatus {
    let configured_path = config.browser.as_deref().map(display_path);
    match probe_runtime(config).await {
        Ok(probe) => ToolStatus {
            name: "chromium_family_browser".to_owned(),
            ready: true,
            configured_path,
            resolved_path: Some(display_path(&probe.path)),
            version: Some(probe.version),
            diagnostic: None,
        },
        Err(failure) => ToolStatus {
            name: "chromium_family_browser".to_owned(),
            ready: false,
            configured_path,
            resolved_path: None,
            version: None,
            diagnostic: Some(failure.message),
        },
    }
}

async fn inspect_puppeteer(config: &RuntimeConfig) -> ToolStatus {
    let configured_path = config.puppeteer_root.as_deref().map(display_path);
    if !puppeteer::is_configured(config) {
        return ToolStatus {
            name: "puppeteer_core_rescue".to_owned(),
            ready: false,
            configured_path,
            resolved_path: None,
            version: None,
            diagnostic: Some(
                "not configured; prepare an external runtime from puppeteer-rescue/package.json and package-lock.json, then use --puppeteer-root"
                    .to_owned(),
            ),
        };
    }
    match puppeteer::probe_runtime(config).await {
        Ok(probe) => ToolStatus {
            name: "puppeteer_core_rescue".to_owned(),
            ready: true,
            configured_path: Some(display_path(&probe.module_root)),
            resolved_path: Some(display_path(&probe.node)),
            version: Some(format!(
                "puppeteer-core/{}; {}; {}",
                probe.puppeteer_version, probe.node_version, probe.browser_version
            )),
            diagnostic: None,
        },
        Err(failure) => ToolStatus {
            name: "puppeteer_core_rescue".to_owned(),
            ready: false,
            configured_path,
            resolved_path: config.node.as_deref().map(display_path),
            version: None,
            diagnostic: Some(failure.message),
        },
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
