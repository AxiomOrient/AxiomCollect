use std::path::PathBuf;
use std::sync::Arc;

use url::Url;

use crate::budget::validate_config;
use crate::domain::{
    BrowserCapability, BudgetConfig, DeviceClass, Failure, FailureCode, FetchRequest,
    NetworkPolicy, RetrievalMode, SCHEMA_VERSION,
};
use crate::evidence::{CompiledEvidence, compile};
use crate::policy::parse_url;

const MAX_URL_BYTES: usize = 8 * 1024;
const MAX_WALL_MS: u64 = 5 * 60 * 1_000;
const MAX_NETWORK_OPERATIONS: u32 = 512;
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
const MAX_REDIRECTS: u16 = 20;
const MAX_RETRIES: u16 = 10;
const MAX_BROWSER_LAUNCHES: u16 = 3;
const MAX_RETRY_DELAY_MS: u64 = 30_000;

/// Controls the external project's adaptive retrieval features without making
/// them a second network or result contract.
#[derive(Debug, Clone)]
pub struct AdaptivePolicy {
    pub device: DeviceClass,
    pub max_attempts: Option<u16>,
    pub enable_phase0: bool,
    pub enable_extraction: bool,
    pub enable_markdown: bool,
    pub enable_maincontent: bool,
    pub enable_browser: bool,
    pub enable_recipes: bool,
    pub enable_jina_reader: bool,
    pub enable_learning: bool,
    pub enable_auto_forge: bool,
    pub profiles_path: Option<PathBuf>,
    pub recipes_dir: Option<PathBuf>,
    pub learning_path: Option<PathBuf>,
    pub observations_dir: Option<PathBuf>,
}

impl Default for AdaptivePolicy {
    fn default() -> Self {
        Self {
            device: DeviceClass::Auto,
            max_attempts: None,
            enable_phase0: true,
            enable_extraction: true,
            enable_markdown: true,
            enable_maincontent: false,
            enable_browser: true,
            enable_recipes: true,
            enable_jina_reader: true,
            // Persistence is explicit because MCP advertises the engine as
            // read-only and should not silently write to the operator's home.
            enable_learning: false,
            enable_auto_forge: false,
            profiles_path: None,
            recipes_dir: None,
            learning_path: None,
            observations_dir: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionPolicy {
    pub budget: BudgetConfig,
    pub network: NetworkPolicy,
    pub artifact_dir: Option<PathBuf>,
    pub adaptive: AdaptivePolicy,
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            budget: BudgetConfig::default(),
            network: NetworkPolicy::PublicOnly,
            artifact_dir: None,
            adaptive: AdaptivePolicy::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedRequest {
    pub intent: FetchRequest,
    pub initial_url: Url,
    pub evidence: Arc<CompiledEvidence>,
    pub execution: ExecutionPolicy,
}

impl PreparedRequest {
    #[must_use]
    pub fn evidence_requested(&self) -> bool {
        self.evidence.spec().is_requested()
    }
}

pub(crate) fn compile_request(
    intent: FetchRequest,
    execution: ExecutionPolicy,
) -> Result<PreparedRequest, Failure> {
    if intent.schema_version != SCHEMA_VERSION {
        return Err(invalid(format!(
            "unsupported schema_version {}; expected {SCHEMA_VERSION}",
            intent.schema_version
        )));
    }
    if intent.url.len() > MAX_URL_BYTES {
        return Err(invalid(format!("URL exceeds {MAX_URL_BYTES} bytes")));
    }
    validate_execution_policy(&execution)?;
    let initial_url = parse_url(&intent.url)?;
    let evidence = Arc::new(compile(intent.evidence.clone())?);
    if evidence
        .spec()
        .minimum_text_bytes
        .is_some_and(|minimum| minimum > execution.budget.max_extracted_bytes)
    {
        return Err(invalid(
            "minimum_text_bytes cannot exceed max_extracted_bytes",
        ));
    }
    if intent.browser_capability == BrowserCapability::Screenshot {
        if execution.artifact_dir.is_none() {
            return Err(invalid(
                "screenshot capability requires an operator-configured artifact directory",
            ));
        }
        if intent.mode == RetrievalMode::Static {
            return Err(Failure::new(
                FailureCode::ProviderUnsupported,
                "screenshot capability requires auto or rendered mode",
            ));
        }
    }
    if execution.network == NetworkPolicy::AllowPrivate && intent.mode != RetrievalMode::Static {
        return Err(Failure::new(
            FailureCode::ProviderUnsupported,
            "private-network retrieval is restricted to explicit static mode",
        ));
    }

    Ok(PreparedRequest {
        intent,
        initial_url,
        evidence,
        execution,
    })
}

fn validate_execution_policy(execution: &ExecutionPolicy) -> Result<(), Failure> {
    let budget = &execution.budget;
    validate_config(budget)?;
    let within_hard_limits = budget.max_wall_ms <= MAX_WALL_MS
        && budget.max_network_operations <= MAX_NETWORK_OPERATIONS
        && budget.max_response_bytes <= MAX_RESPONSE_BYTES
        && budget.max_extracted_bytes <= MAX_EXTRACTED_BYTES
        && budget.max_total_bytes <= MAX_TOTAL_BYTES
        && budget.max_redirects <= MAX_REDIRECTS
        && budget.max_retries <= MAX_RETRIES
        && budget.max_browser_launches <= MAX_BROWSER_LAUNCHES
        && budget.max_retry_delay_ms <= MAX_RETRY_DELAY_MS;
    if !within_hard_limits {
        return Err(invalid("execution policy exceeds the product hard limits"));
    }
    if execution
        .adaptive
        .max_attempts
        .is_some_and(|attempts| attempts == 0 || u32::from(attempts) > MAX_NETWORK_OPERATIONS)
    {
        return Err(invalid(
            "adaptive max_attempts must be between 1 and the network-operation hard limit",
        ));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> Failure {
    Failure::new(FailureCode::InvalidRequest, message)
}

#[cfg(test)]
mod tests {
    use super::{ExecutionPolicy, compile_request};
    use crate::domain::{
        BrowserCapability, FailureCode, FetchRequest, NetworkPolicy, RetrievalMode,
    };

    #[test]
    fn private_network_authority_is_separate_from_intent() {
        let mut request = FetchRequest::new("http://127.0.0.1");
        request.mode = RetrievalMode::Static;
        let execution = ExecutionPolicy {
            network: NetworkPolicy::AllowPrivate,
            ..ExecutionPolicy::default()
        };
        assert!(compile_request(request, execution).is_ok());
    }

    #[test]
    fn screenshot_requires_operator_artifact_directory() {
        let mut request = FetchRequest::new("https://example.com");
        request.mode = RetrievalMode::Rendered;
        request.browser_capability = BrowserCapability::Screenshot;
        assert!(compile_request(request, ExecutionPolicy::default()).is_err());
    }

    #[test]
    fn mcp_style_public_policy_cannot_request_private_access() {
        let mut request = FetchRequest::new("http://127.0.0.1");
        request.mode = RetrievalMode::Auto;
        assert!(compile_request(request, ExecutionPolicy::default()).is_ok());
    }

    #[test]
    fn credential_like_query_parameters_are_rejected_before_routing() {
        for key in ["api_key", "access_token", "client_secret", "signature"] {
            let request = FetchRequest::new(format!("https://example.com/?{key}=redacted"));
            let failure = compile_request(request, ExecutionPolicy::default()).err();
            assert_eq!(
                failure.map(|value| value.code),
                Some(crate::domain::FailureCode::PolicyRejected)
            );
        }
    }

    #[test]
    fn adaptive_attempt_budget_is_bounded_and_nonzero() {
        let request = FetchRequest::new("https://example.com");
        let mut execution = ExecutionPolicy::default();
        execution.adaptive.max_attempts = Some(0);
        assert_eq!(
            compile_request(request.clone(), execution)
                .err()
                .map(|failure| failure.code),
            Some(FailureCode::InvalidRequest)
        );

        let mut execution = ExecutionPolicy::default();
        execution.adaptive.max_attempts = Some(513);
        assert_eq!(
            compile_request(request, execution)
                .err()
                .map(|failure| failure.code),
            Some(FailureCode::InvalidRequest)
        );
    }
}
