use std::collections::BTreeMap;

use clap::ValueEnum;
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const SCHEMA_VERSION: u32 = 7;
pub const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalMode {
    #[default]
    Auto,
    Static,
    Rendered,
}

impl RetrievalMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Static => "static",
            Self::Rendered => "rendered",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    #[default]
    PublicOnly,
    AllowPrivate,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BrowserCapability {
    #[default]
    Content,
    Screenshot,
}

/// Preferred client family for the adaptive public-route grid.
///
/// This is a routing hint, not a TLS-fingerprint impersonation. The transport
/// still uses the product's pinned, public-only HTTP stack.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    #[default]
    Auto,
    Desktop,
    Mobile,
}

impl DeviceClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Desktop => "desktop",
            Self::Mobile => "mobile",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct EvidenceSpec {
    #[serde(default)]
    pub selectors: Vec<String>,
    #[serde(default)]
    pub required_text: Vec<String>,
    #[schemars(range(min = 1))]
    pub minimum_text_bytes: Option<usize>,
}

impl EvidenceSpec {
    #[must_use]
    pub fn is_requested(&self) -> bool {
        !self.selectors.is_empty()
            || !self.required_text.is_empty()
            || self.minimum_text_bytes.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetConfig {
    pub max_wall_ms: u64,
    /// HTTP/media count outbound request attempts; browser/egress count public
    /// upstream connections because HTTPS request boundaries are opaque there.
    pub max_network_operations: u32,
    pub max_response_bytes: usize,
    pub max_extracted_bytes: usize,
    pub max_total_bytes: usize,
    pub max_redirects: u16,
    pub max_retries: u16,
    pub max_browser_launches: u16,
    pub max_retry_delay_ms: u64,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
}

/// Default budget values.
///
/// These are the single source of truth: `BudgetConfig::default()` and the CLI
/// option defaults both read them, so the two can never drift apart unnoticed.
pub const DEFAULT_MAX_WALL_MS: u64 = 45_000;
pub const DEFAULT_MAX_NETWORK_OPERATIONS: u32 = 64;
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_EXTRACTED_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 24 * 1024 * 1024;
pub const DEFAULT_MAX_REDIRECTS: u16 = 5;
pub const DEFAULT_MAX_RETRIES: u16 = 2;
pub const DEFAULT_MAX_BROWSER_LAUNCHES: u16 = 2;
pub const DEFAULT_MAX_RETRY_DELAY_MS: u64 = 2_000;
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 8_000;
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 15_000;

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            max_wall_ms: DEFAULT_MAX_WALL_MS,
            max_network_operations: DEFAULT_MAX_NETWORK_OPERATIONS,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_extracted_bytes: DEFAULT_MAX_EXTRACTED_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            max_retries: DEFAULT_MAX_RETRIES,
            max_browser_launches: DEFAULT_MAX_BROWSER_LAUNCHES,
            max_retry_delay_ms: DEFAULT_MAX_RETRY_DELAY_MS,
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            read_timeout_ms: DEFAULT_READ_TIMEOUT_MS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchRequest {
    pub schema_version: u32,
    pub url: String,
    #[serde(default)]
    pub mode: RetrievalMode,
    #[serde(default)]
    pub browser_capability: BrowserCapability,
    #[serde(default)]
    pub evidence: EvidenceSpec,
}

impl FetchRequest {
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            url: url.into(),
            mode: RetrievalMode::Auto,
            browser_capability: BrowserCapability::Content,
            evidence: EvidenceSpec::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OverallStatus {
    EvidenceSatisfied,
    ContentOnly,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransportStatus {
    NotStarted,
    Accepted,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContentStatus {
    NotAttempted,
    Parsed,
    Empty,
    Unsupported,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    NotRequested,
    Satisfied,
    NotSatisfied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    InvalidRequest,
    PolicyRejected,
    DnsRejected,
    NetworkFailed,
    HttpRejected,
    AccessRestricted,
    ContentEmpty,
    ContentUnsupported,
    ExtractionFailed,
    EvidenceNotSatisfied,
    BudgetExhausted,
    ToolUnavailable,
    ProviderUnsupported,
    ProviderFailed,
    InternalError,
}

impl FailureCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::PolicyRejected => "policy_rejected",
            Self::DnsRejected => "dns_rejected",
            Self::NetworkFailed => "network_failed",
            Self::HttpRejected => "http_rejected",
            Self::AccessRestricted => "access_restricted",
            Self::ContentEmpty => "content_empty",
            Self::ContentUnsupported => "content_unsupported",
            Self::ExtractionFailed => "extraction_failed",
            Self::EvidenceNotSatisfied => "evidence_not_satisfied",
            Self::BudgetExhausted => "budget_exhausted",
            Self::ToolUnavailable => "tool_unavailable",
            Self::ProviderUnsupported => "provider_unsupported",
            Self::ProviderFailed => "provider_failed",
            Self::InternalError => "internal_error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Failure {
    pub code: FailureCode,
    pub message: String,
}

impl Failure {
    #[must_use]
    pub fn new(code: FailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceCheck {
    pub kind: String,
    pub requirement: String,
    pub satisfied: bool,
    pub observed: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedContent {
    pub content: String,
    pub source: String,
    pub quality: f32,
    pub title: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub links: Vec<String>,
    #[serde(default)]
    pub json_ld: Vec<Value>,
    #[serde(default)]
    pub selector_hits: BTreeMap<String, usize>,
    pub dynamic_shell: bool,
}

impl ExtractedContent {
    #[must_use]
    pub fn content_bytes(&self) -> usize {
        self.content.len()
    }

    #[must_use]
    pub fn is_usable(&self) -> bool {
        !self.content.trim().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ContentSafetyReport {
    pub content_trust: String,
    pub prompt_injection_risk: String,
    #[serde(default)]
    pub prompt_injection_signals: Vec<String>,
}

impl Default for ContentSafetyReport {
    fn default() -> Self {
        Self {
            content_trust: "untrusted_external".to_owned(),
            prompt_injection_risk: "none".to_owned(),
            prompt_injection_signals: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Attempt {
    pub provider: String,
    pub phase: String,
    pub url: String,
    pub duration_ms: u64,
    pub http_status: Option<u16>,
    pub bytes: usize,
    /// HTTP/media request attempts or browser/egress upstream connections,
    /// according to the provider represented by this attempt.
    pub network_operations: u32,
    #[serde(default)]
    pub redirect_chain: Vec<String>,
    pub outcome: String,
    pub transition_reason: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Artifact {
    pub kind: String,
    pub path: String,
    pub media_type: String,
    pub bytes: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct BudgetUsage {
    pub elapsed_ms: u64,
    /// Same provider-specific unit as `BudgetConfig::max_network_operations`.
    pub network_operations: u32,
    pub browser_launches: u16,
    pub total_bytes: usize,
    pub redirects: u16,
    pub retries: u16,
    pub retry_delay_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FetchResult {
    pub schema_version: u32,
    pub product_version: String,
    pub ok: bool,
    pub status: OverallStatus,
    pub transport_status: TransportStatus,
    pub content_status: ContentStatus,
    pub evidence_status: EvidenceStatus,
    pub requested_url: String,
    pub final_url: Option<String>,
    pub final_url_observed: bool,
    pub mode_requested: RetrievalMode,
    pub provider_used: Option<String>,
    pub failure_provider: Option<String>,
    pub failure_provider_version: Option<String>,
    pub provider_version: Option<String>,
    pub http_status: Option<u16>,
    pub content_length: usize,
    pub content: String,
    pub content_omitted: bool,
    pub extraction_source: Option<String>,
    pub extraction_quality: Option<f32>,
    pub title: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub links: Vec<String>,
    #[serde(default)]
    pub json_ld: Vec<Value>,
    #[serde(default)]
    pub evidence_checks: Vec<EvidenceCheck>,
    #[serde(default)]
    pub trace: Vec<Attempt>,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
    pub budget: BudgetUsage,
    pub failure: Option<Failure>,
    pub content_safety: ContentSafetyReport,
}

impl FetchResult {
    #[must_use]
    pub fn failed(request: &FetchRequest, failure: Failure) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            product_version: PRODUCT_VERSION.to_owned(),
            ok: false,
            status: OverallStatus::Failed,
            transport_status: TransportStatus::NotStarted,
            content_status: ContentStatus::NotAttempted,
            evidence_status: if request.evidence.is_requested() {
                EvidenceStatus::NotSatisfied
            } else {
                EvidenceStatus::NotRequested
            },
            requested_url: redact_url(&request.url),
            final_url: None,
            final_url_observed: false,
            mode_requested: request.mode,
            provider_used: None,
            failure_provider: None,
            failure_provider_version: None,
            provider_version: None,
            http_status: None,
            content_length: 0,
            content: String::new(),
            content_omitted: false,
            extraction_source: None,
            extraction_quality: None,
            title: None,
            description: None,
            links: Vec::new(),
            json_ld: Vec::new(),
            evidence_checks: Vec::new(),
            trace: Vec::new(),
            artifacts: Vec::new(),
            budget: BudgetUsage::default(),
            failure: Some(failure),
            content_safety: ContentSafetyReport::default(),
        }
    }

    #[must_use]
    pub fn for_output(mut self, include_content: bool) -> Self {
        self.content_length = self.content.len();
        if !include_content && !self.content.is_empty() {
            self.content.clear();
            self.content_omitted = true;
        }
        self
    }

    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.ok {
            return 0;
        }
        match self.failure.as_ref().map(|value| value.code) {
            Some(FailureCode::InvalidRequest) => 2,
            Some(FailureCode::PolicyRejected | FailureCode::DnsRejected) => 3,
            Some(FailureCode::BudgetExhausted) => 4,
            Some(FailureCode::ToolUnavailable) => 5,
            Some(FailureCode::ProviderUnsupported) => 6,
            _ => 1,
        }
    }

    pub fn validate_invariants(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err("result schema_version is invalid".to_owned());
        }
        if self.requested_url.is_empty() {
            return Err("requested URL provenance is missing".to_owned());
        }
        if self.final_url_observed && self.final_url.is_none() {
            return Err("observed final URL is missing".to_owned());
        }
        if self
            .extraction_quality
            .is_some_and(|quality| !quality.is_finite() || !(0.0..=1.0).contains(&quality))
        {
            return Err("extraction quality must be finite and between zero and one".to_owned());
        }
        if self.content_omitted {
            if !self.content.is_empty() {
                return Err("omitted content must be empty".to_owned());
            }
        } else if self.content_length != self.content.len() {
            return Err("content_length does not match content bytes".to_owned());
        }
        if self.ok {
            if self.failure.is_some()
                || self.status == OverallStatus::Failed
                || self.transport_status != TransportStatus::Accepted
                || self.content_status != ContentStatus::Parsed
                || self.content_length == 0
                || self.provider_used.is_none()
                || self.failure_provider.is_some()
                || self.failure_provider_version.is_some()
                || self.final_url.is_none()
                || self.extraction_source.is_none()
                || self.extraction_quality.is_none()
                || self.trace.is_empty()
            {
                return Err("successful result violates success-state contract".to_owned());
            }
            match self.status {
                OverallStatus::EvidenceSatisfied
                    if self.evidence_status != EvidenceStatus::Satisfied =>
                {
                    return Err("evidence_satisfied result lacks satisfied evidence".to_owned());
                }
                OverallStatus::ContentOnly
                    if self.evidence_status != EvidenceStatus::NotRequested =>
                {
                    return Err("content_only result has inconsistent evidence state".to_owned());
                }
                OverallStatus::Failed => {
                    return Err("successful result cannot have failed status".to_owned());
                }
                _ => {}
            }
        } else {
            if self.failure.is_none() || self.status != OverallStatus::Failed {
                return Err("failed result must carry a failure and failed status".to_owned());
            }
            if self.content_length > 0
                && (self.provider_used.is_none()
                    || self.extraction_source.is_none()
                    || self.extraction_quality.is_none())
            {
                return Err("failed result content lacks candidate provenance".to_owned());
            }
            if self.content_length == 0
                && (!self.content.is_empty()
                    || self.extraction_source.is_some()
                    || self.extraction_quality.is_some())
            {
                return Err("content-free failure carries extraction data".to_owned());
            }
            if self.failure_provider.is_some() && self.trace.is_empty() {
                return Err("provider failure lacks an attempt trace".to_owned());
            }
            if self.failure_provider_version.is_some() && self.failure_provider.is_none() {
                return Err("failure provider version lacks provider provenance".to_owned());
            }
        }
        Ok(())
    }
}

#[must_use]
pub fn redact_url(input: &str) -> String {
    let Ok(mut url) = Url::parse(input) else {
        return "<invalid-url>".to_owned();
    };
    let query_keys = url
        .query_pairs()
        .map(|(key, _)| key.into_owned())
        .collect::<Vec<_>>();
    if !query_keys.is_empty() {
        url.set_query(None);
        let mut pairs = url.query_pairs_mut();
        for key in query_keys {
            pairs.append_pair(&key, "redacted");
        }
    }
    url.set_fragment(None);
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        ContentStatus, EvidenceStatus, Failure, FailureCode, FetchRequest, OverallStatus,
        TransportStatus, redact_url,
    };

    #[test]
    fn url_query_values_are_redacted() {
        let redacted = redact_url("https://example.com/a?token=secret&q=term#part");
        assert!(redacted.contains("token=redacted"));
        assert!(redacted.contains("q=redacted"));
        assert!(!redacted.contains("secret"));
        assert!(!redacted.contains("#part"));
    }

    #[test]
    fn exit_codes_are_stable() {
        let request = FetchRequest::new("https://example.com");
        let result = super::FetchResult::failed(
            &request,
            Failure::new(FailureCode::ToolUnavailable, "missing"),
        );
        assert_eq!(result.exit_code(), 5);
        assert!(result.validate_invariants().is_ok());
    }

    #[test]
    fn invalid_success_is_detected() {
        let request = FetchRequest::new("https://example.com");
        let mut result = super::FetchResult::failed(
            &request,
            Failure::new(FailureCode::NetworkFailed, "failed"),
        );
        result.ok = true;
        result.failure = None;
        result.status = OverallStatus::ContentOnly;
        result.transport_status = TransportStatus::Accepted;
        result.content_status = ContentStatus::Parsed;
        result.evidence_status = EvidenceStatus::NotRequested;
        result.content = "content".to_owned();
        result.content_length = result.content.len();
        assert!(result.validate_invariants().is_err());
    }
}
