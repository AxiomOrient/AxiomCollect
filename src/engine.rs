use std::time::Duration;

use serde_json::Value;
use url::Url;

use crate::access_gate;
use crate::adaptive;
use crate::archive;
use crate::browser::run_rendered;
use crate::budget::BudgetTracker;
use crate::content_safety;
use crate::domain::{
    Artifact, Attempt, BrowserCapability, ContentSafetyReport, ContentStatus, EvidenceCheck,
    EvidenceStatus, ExtractedContent, Failure, FailureCode, FetchRequest, FetchResult,
    OverallStatus, PRODUCT_VERSION, RetrievalMode, SCHEMA_VERSION, TransportStatus, redact_url,
};
use crate::evidence::{EvidenceEvaluation, evaluate};
use crate::extract;
use crate::media;
use crate::public_routes;
use crate::puppeteer;
use crate::recipe;
use crate::rendered::{RenderedFailure, RenderedOutput, RuntimeConfig, cleanup_artifacts};
use crate::request::{ExecutionPolicy, PreparedRequest, compile_request};
use crate::transport::{
    HttpResponseData, HttpRouteProfile, TransportFailure, fetch_http, fetch_http_at,
    fetch_http_at_with_profile,
};

#[derive(Debug, Clone)]
pub struct Engine {
    runtime: RuntimeConfig,
    execution: ExecutionPolicy,
}

impl Engine {
    #[must_use]
    pub fn new(runtime: RuntimeConfig, execution: ExecutionPolicy) -> Self {
        Self { runtime, execution }
    }

    #[must_use]
    pub fn public(runtime: RuntimeConfig) -> Self {
        Self::new(runtime, ExecutionPolicy::default())
    }

    #[must_use]
    pub fn runtime_config(&self) -> RuntimeConfig {
        self.runtime.clone()
    }

    pub async fn fetch(&self, intent: FetchRequest) -> FetchResult {
        let request = match compile_request(intent.clone(), self.execution.clone()) {
            Ok(value) => value,
            Err(failure) => return FetchResult::failed(&intent, failure),
        };
        let mut budget = match BudgetTracker::new(request.execution.budget.clone()) {
            Ok(value) => value,
            Err(failure) => return FetchResult::failed(&intent, failure),
        };
        let wall = Duration::from_millis(request.execution.budget.max_wall_ms);
        match tokio::time::timeout(wall, self.run(&request, &mut budget)).await {
            Ok(result) => enforce_invariants(&intent, &budget, result),
            Err(_) => {
                let mut result = FetchResult::failed(
                    &intent,
                    Failure::new(
                        FailureCode::BudgetExhausted,
                        "retrieval exceeded the whole-operation wall-clock budget",
                    ),
                );
                result.budget = budget.usage();
                result
            }
        }
    }

    async fn run(&self, request: &PreparedRequest, budget: &mut BudgetTracker) -> FetchResult {
        let route = provider_route(request, puppeteer::is_configured(&self.runtime));
        run_route(self, route, request, budget).await
    }
}

/// Executes one route step. The only effect boundary the route state machine has.
///
/// Naming it separates the two halves that are already distinct in the
/// architecture: `attempt` performs DNS, sockets, subprocesses, and browsers,
/// while [`run_route`] decides escalation, candidate preservation, terminal
/// classification, and provenance from the outcomes alone. That second half is
/// where the branching lives and is the half no end-to-end test can otherwise
/// reach — `auto` needs public DNS, and private-network authority is confined to
/// explicit `static` mode, so a loopback server can never drive the ladder. A test
/// implements this trait to script provider outcomes directly instead of the
/// network policy being loosened to make the ladder observable.
trait RouteExecutor {
    fn attempt(
        &self,
        provider: ProviderKind,
        request: &PreparedRequest,
        budget: &mut BudgetTracker,
        target: &Url,
        transition_reason: Option<String>,
    ) -> impl Future<Output = Result<CandidateInput, AttemptFailure>> + Send;
}

impl RouteExecutor for Engine {
    fn attempt(
        &self,
        provider: ProviderKind,
        request: &PreparedRequest,
        budget: &mut BudgetTracker,
        target: &Url,
        transition_reason: Option<String>,
    ) -> impl Future<Output = Result<CandidateInput, AttemptFailure>> + Send {
        self.attempt_provider(provider, request, budget, target, transition_reason)
    }
}

async fn run_route<E: RouteExecutor>(
    executor: &E,
    route: Vec<ProviderStep>,
    request: &PreparedRequest,
    budget: &mut BudgetTracker,
) -> FetchResult {
    let route_len = route.len();
    let mut trace = Vec::new();
    let mut best_candidate: Option<EvaluatedCandidate> = None;
    let mut transition_reason = None;
    let adaptive_probe_available = route
        .iter()
        .any(|step| step.provider == ProviderKind::AdaptiveHttp);

    for (index, step) in route.into_iter().enumerate() {
        let provider = step.provider;
        if access_restriction_is_terminal(
            best_candidate
                .as_ref()
                .and_then(|candidate| candidate.assessment.failure.as_ref()),
        ) && let Some(candidate) = best_candidate.take()
        {
            // A detected gate is a terminal safety boundary. Public routes may
            // recover a blocked transport response, but must not become a way
            // around an observed CAPTCHA, authentication, or paywall page.
            return finish_candidate(request, budget, trace, candidate);
        }
        if let Err(failure) = budget.check_wall() {
            return finish_failure(
                request,
                budget,
                trace,
                best_candidate,
                AttemptFailure::without_attempt(provider, failure),
            );
        }
        let target = if matches!(
            provider,
            ProviderKind::Browser | ProviderKind::BrowserPuppeteer
        ) {
            best_candidate
                .as_ref()
                .filter(|candidate| {
                    matches!(
                        candidate.meta.provider,
                        ProviderKind::Http | ProviderKind::AdaptiveHttp
                    )
                })
                .map_or(&step.target, |candidate| &candidate.meta.final_url)
        } else {
            &step.target
        };
        let attempt_transition_reason =
            combine_transition_reason(transition_reason.clone(), step.route_reason);
        let event = executor
            .attempt(provider, request, budget, target, attempt_transition_reason)
            .await;
        let is_last = index + 1 == route_len;

        match event {
            Ok(mut candidate) => {
                trace.append(&mut candidate.attempts);
                let assessment = assess_content(
                    request,
                    budget,
                    candidate.meta.final_url.clone(),
                    candidate.body,
                    candidate.content_type,
                )
                .await;
                let mut evaluated = EvaluatedCandidate {
                    meta: candidate.meta,
                    assessment,
                };
                if evaluated.assessment.failure.is_none() {
                    cleanup_best_candidate(&mut best_candidate).await;
                    return finish_candidate(request, budget, trace, evaluated);
                }
                if is_last || !evaluated.assessment.can_escalate() {
                    cleanup_best_candidate(&mut best_candidate).await;
                    return finish_candidate(request, budget, trace, evaluated);
                }
                transition_reason = Some(evaluated.assessment.transition_reason(provider.as_str()));
                if candidate_supersedes(&evaluated, best_candidate.as_ref()) {
                    cleanup_best_candidate(&mut best_candidate).await;
                    best_candidate = Some(evaluated);
                } else {
                    evaluated.meta.artifacts.cleanup().await;
                }
            }
            Err(mut failure) => {
                trace.append(&mut failure.attempts);
                let access_status =
                    access_status_is_terminal(provider, failure.failure.code, failure.http_status);
                let allow_adaptive_403_probe = adaptive_probe_available
                    && provider == ProviderKind::Http
                    && failure.failure.code == FailureCode::HttpRejected
                    && failure.http_status == Some(403);
                if is_last
                    || (access_status && !allow_adaptive_403_probe)
                    || failure_is_terminal(failure.failure.code)
                {
                    if best_candidate.is_some() {
                        cleanup_artifacts(&failure.artifacts).await;
                        failure.artifacts.clear();
                    }
                    return finish_failure(request, budget, trace, best_candidate, failure);
                }
                cleanup_artifacts(&failure.artifacts).await;
                failure.artifacts.clear();
                transition_reason = Some(format!(
                    "{}_failed:{}",
                    provider.as_str(),
                    failure.failure.code.as_str()
                ));
            }
        }
    }

    build_failure(
        request,
        budget,
        trace,
        None,
        None,
        Failure::new(
            FailureCode::InternalError,
            "provider route completed without a terminal result",
        ),
        None,
    )
}

impl Engine {
    async fn attempt_provider(
        &self,
        provider: ProviderKind,
        request: &PreparedRequest,
        budget: &mut BudgetTracker,
        target: &Url,
        transition_reason: Option<String>,
    ) -> Result<CandidateInput, AttemptFailure> {
        match provider {
            ProviderKind::Http => fetch_http(request, budget)
                .await
                .map(|response| CandidateInput::from_http(provider, response))
                .map_err(|failure| AttemptFailure::from_http(provider, failure)),
            ProviderKind::AdaptiveHttp => {
                adaptive::fetch_grid(request, budget, target, transition_reason.as_deref())
                    .await
                    .map(|response| CandidateInput::from_http(provider, response))
                    .map_err(|failure| AttemptFailure::from_http(provider, failure))
            }
            ProviderKind::Phase0Threads => adaptive::fetch_threads_metadata(
                request,
                budget,
                target,
                transition_reason.as_deref(),
            )
            .await
            .map(|response| CandidateInput::from_http(provider, response))
            .map_err(|failure| AttemptFailure::from_http(provider, failure)),
            ProviderKind::Recipe => {
                let profile = recipe::profile_for(
                    &request.initial_url,
                    target,
                    request.execution.adaptive.recipes_dir.as_deref(),
                )
                .unwrap_or_else(|| HttpRouteProfile {
                    accept_http_errors: false,
                    ..HttpRouteProfile::default()
                });
                fetch_http_at_with_profile(
                    request,
                    budget,
                    target.clone(),
                    "recipe",
                    transition_reason.as_deref(),
                    Some(&profile),
                )
                .await
                .map(|response| CandidateInput::from_http(provider, response))
                .map_err(|failure| AttemptFailure::from_http(provider, failure))
            }
            ProviderKind::PublicRoute => fetch_http_at(
                request,
                budget,
                target.clone(),
                "http_public",
                transition_reason.as_deref(),
            )
            .await
            .map(|response| CandidateInput::from_http(provider, response))
            .map_err(|failure| AttemptFailure::from_http(provider, failure)),
            ProviderKind::PublicArchive => archive::fetch(
                request,
                budget,
                &request.initial_url,
                target,
                transition_reason,
            )
            .await
            .map(|response| CandidateInput::from_http(provider, response))
            .map_err(|failure| AttemptFailure::from_http(provider, failure)),
            ProviderKind::MediaOembed => media::fetch(request, budget, target, transition_reason)
                .await
                .map(|output| CandidateInput::from_media(provider, output))
                .map_err(|failure| AttemptFailure::from_media(provider, target, failure)),
            ProviderKind::Browser => {
                run_rendered(request, target, budget, &self.runtime, transition_reason)
                    .await
                    .map(|output| CandidateInput::from_browser(provider, output))
                    .map_err(|failure| AttemptFailure::from_browser(provider, failure))
            }
            ProviderKind::BrowserPuppeteer => {
                puppeteer::run_rendered(request, target, budget, &self.runtime, transition_reason)
                    .await
                    .map(|output| CandidateInput::from_browser(provider, output))
                    .map_err(|failure| AttemptFailure::from_browser(provider, failure))
            }
        }
    }
}

async fn cleanup_best_candidate(candidate: &mut Option<EvaluatedCandidate>) {
    if let Some(mut candidate) = candidate.take() {
        candidate.meta.artifacts.cleanup().await;
    }
}

/// How much a candidate is worth keeping while the route continues.
///
/// Ordered the way a caller reads a failed result: how much of the evidence they
/// asked for was actually observed, then the amount of content adjusted by the
/// extraction quality, then the quality and raw byte count as tie-breakers.
///
/// `quality` is a confidence in the representation, not a universal source
/// authority. Multiplying it by content size prevents a tiny exact JSON metadata
/// response from displacing a substantially larger article merely because JSON
/// has a higher format score.
fn candidate_rank(candidate: &EvaluatedCandidate) -> (usize, f64, f32, usize) {
    let satisfied = candidate
        .assessment
        .evidence
        .checks
        .iter()
        .filter(|check| check.satisfied)
        .count();
    let (quality, bytes) = candidate
        .assessment
        .extracted
        .as_ref()
        .map_or((0.0, 0), |content| {
            (content.quality, content.content_bytes())
        });
    let quality = if quality.is_finite() {
        quality.clamp(0.0, 1.0)
    } else {
        0.0
    };
    (satisfied, f64::from(quality) * bytes as f64, quality, bytes)
}

/// Whether a newly assessed candidate should replace the one being preserved.
///
/// The preserved candidate is what a failed result reports as the best thing the
/// route actually retrieved, so taking whichever arrived last can downgrade the
/// answer: a full article that missed a single evidence check would be dropped for a
/// thin reader-route rendering of the same page, and the caller would never see the
/// better one. A candidate with no extracted content is never worth preserving, and
/// a tie keeps the earlier candidate because it came from the more direct route.
fn candidate_supersedes(
    candidate: &EvaluatedCandidate,
    preserved: Option<&EvaluatedCandidate>,
) -> bool {
    if candidate.assessment.extracted.is_none() {
        return false;
    }
    preserved.is_none_or(|preserved| candidate_rank(candidate) > candidate_rank(preserved))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderKind {
    Http,
    AdaptiveHttp,
    Phase0Threads,
    Recipe,
    PublicRoute,
    PublicArchive,
    MediaOembed,
    Browser,
    BrowserPuppeteer,
}

impl ProviderKind {
    /// Whether this provider retrieves the requested resource itself rather than a
    /// derived public alternative. Only these speak for the origin's own access
    /// decision.
    const fn speaks_for_origin(self) -> bool {
        matches!(
            self,
            Self::Http | Self::Browser | Self::BrowserPuppeteer | Self::AdaptiveHttp
        )
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::AdaptiveHttp => "adaptive_http",
            Self::Phase0Threads => "phase0_threads",
            Self::Recipe => "recipe",
            Self::PublicRoute => "http_public",
            Self::PublicArchive => "http_public",
            Self::MediaOembed => "media_oembed",
            Self::Browser => "browser",
            Self::BrowserPuppeteer => "browser_puppeteer",
        }
    }
}

#[derive(Debug, Clone)]
struct ProviderStep {
    provider: ProviderKind,
    target: Url,
    route_reason: Option<String>,
}

impl ProviderStep {
    fn new(provider: ProviderKind, target: Url, route_reason: Option<String>) -> Self {
        Self {
            provider,
            target,
            route_reason,
        }
    }
}

fn provider_route(request: &PreparedRequest, puppeteer_configured: bool) -> Vec<ProviderStep> {
    let mut route = match request.intent.mode {
        RetrievalMode::Static => {
            vec![ProviderStep::new(
                ProviderKind::Http,
                request.initial_url.clone(),
                None,
            )]
        }
        RetrievalMode::Rendered => {
            vec![ProviderStep::new(
                ProviderKind::Browser,
                request.initial_url.clone(),
                None,
            )]
        }
        RetrievalMode::Auto
            if request.intent.browser_capability == BrowserCapability::Screenshot =>
        {
            vec![ProviderStep::new(
                ProviderKind::Browser,
                request.initial_url.clone(),
                None,
            )]
        }
        RetrievalMode::Auto => {
            let mut route = Vec::new();
            let mut phase0 = Vec::new();
            let mut fallback = Vec::new();
            if request.execution.adaptive.enable_phase0 {
                if adaptive::supports_threads(&request.initial_url) {
                    route.push(ProviderStep::new(
                        ProviderKind::Phase0Threads,
                        request.initial_url.clone(),
                        Some("phase0=threads_inline_metadata".to_owned()),
                    ));
                }
                for candidate in public_routes::candidates(
                    &request.initial_url,
                    request.execution.adaptive.enable_jina_reader,
                ) {
                    let provider = if candidate.kind == "wayback_cdx" {
                        ProviderKind::PublicArchive
                    } else {
                        ProviderKind::PublicRoute
                    };
                    let step = ProviderStep::new(
                        provider,
                        candidate.url,
                        Some(format!("public_route={}", candidate.kind)),
                    );
                    if public_routes::is_phase0_kind(candidate.kind) {
                        phase0.push(step);
                    } else {
                        fallback.push(step);
                    }
                }
            }
            route.extend(phase0);
            if media::supports(&request.initial_url) {
                route.push(ProviderStep::new(
                    ProviderKind::MediaOembed,
                    request.initial_url.clone(),
                    Some("public_route=media_oembed".to_owned()),
                ));
            }
            if request.execution.adaptive.enable_recipes {
                route.extend(
                    recipe::candidates(
                        &request.initial_url,
                        request.execution.adaptive.recipes_dir.as_deref(),
                    )
                    .into_iter()
                    .map(|candidate| {
                        ProviderStep::new(
                            ProviderKind::Recipe,
                            candidate.url,
                            Some(format!("recipe={}", candidate.name)),
                        )
                    }),
                );
            }
            route.push(ProviderStep::new(
                ProviderKind::Http,
                request.initial_url.clone(),
                None,
            ));
            route.push(ProviderStep::new(
                ProviderKind::AdaptiveHttp,
                request.initial_url.clone(),
                Some("adaptive=profile_grid".to_owned()),
            ));
            route.extend(fallback);
            if request.execution.adaptive.enable_browser {
                route.push(ProviderStep::new(
                    ProviderKind::Browser,
                    request.initial_url.clone(),
                    None,
                ));
            }
            route
        }
    };
    if puppeteer_configured
        && route
            .last()
            .is_some_and(|step| step.provider == ProviderKind::Browser)
    {
        route.push(ProviderStep::new(
            ProviderKind::BrowserPuppeteer,
            request.initial_url.clone(),
            None,
        ));
    }
    route
}

fn combine_transition_reason(
    previous: Option<String>,
    route_reason: Option<String>,
) -> Option<String> {
    match (previous, route_reason) {
        (Some(previous), Some(route_reason)) => Some(format!("{previous}; {route_reason}")),
        (Some(previous), None) => Some(previous),
        (None, Some(route_reason)) => Some(route_reason),
        (None, None) => None,
    }
}

fn access_restriction_is_terminal(failure: Option<&Failure>) -> bool {
    failure.is_some_and(|failure| failure.code == FailureCode::AccessRestricted)
}

/// Whether a rejected HTTP status is the origin itself demanding authentication or
/// payment, which normally ends the route the same way a detected gate page does.
///
/// Only the providers that speak for the requested resource can report this. A
/// public API, feed, or archive candidate answering 401/403 is that route being
/// unavailable, not the target refusing anonymous access, and must stay escalatable.
/// Auto mode makes one explicit exception for an origin 403 so the adaptive
/// provider can classify a public WAF challenge body before deciding whether the
/// safety boundary applies.
fn access_status_is_terminal(
    provider: ProviderKind,
    code: FailureCode,
    http_status: Option<u16>,
) -> bool {
    provider.speaks_for_origin()
        && code == FailureCode::HttpRejected
        && matches!(http_status, Some(401..=403))
}

#[derive(Debug)]
struct CandidateInput {
    meta: CandidateMeta,
    body: Vec<u8>,
    content_type: String,
    attempts: Vec<Attempt>,
}

impl CandidateInput {
    fn from_http(provider: ProviderKind, response: HttpResponseData) -> Self {
        Self {
            meta: CandidateMeta {
                provider,
                provider_version: None,
                final_url: response.final_url,
                final_url_observed: true,
                http_status: Some(response.status),
                artifacts: OwnedArtifacts::default(),
            },
            body: response.body,
            content_type: response.content_type,
            attempts: response.attempts,
        }
    }

    fn from_browser(provider: ProviderKind, output: RenderedOutput) -> Self {
        let forged = output.forged;
        let final_url = forged
            .as_ref()
            .map(|value| value.url.clone())
            .unwrap_or_else(|| output.final_url.clone());
        let http_status = forged
            .as_ref()
            .map(|value| value.status)
            .or(output.http_status);
        let body = forged
            .as_ref()
            .map(|value| value.body.clone())
            .unwrap_or_else(|| output.body.clone());
        let content_type = forged.as_ref().map_or_else(
            || "text/html; charset=utf-8".to_owned(),
            |value| value.content_type.clone(),
        );
        Self {
            meta: CandidateMeta {
                provider,
                provider_version: output.version,
                final_url,
                final_url_observed: output.final_url_observed,
                http_status,
                artifacts: OwnedArtifacts::new(output.artifacts),
            },
            body,
            content_type,
            attempts: vec![output.attempt],
        }
    }

    fn from_media(provider: ProviderKind, output: media::MediaOutput) -> Self {
        Self {
            meta: CandidateMeta {
                provider,
                provider_version: None,
                final_url: output.final_url,
                final_url_observed: true,
                http_status: Some(output.http_status),
                artifacts: OwnedArtifacts::default(),
            },
            body: output.body,
            content_type: "application/json".to_owned(),
            attempts: output.attempts,
        }
    }
}

#[derive(Debug)]
struct AttemptFailure {
    provider: ProviderKind,
    provider_was_attempted: bool,
    provider_version: Option<String>,
    failure: Failure,
    final_url: Option<Url>,
    final_url_observed: bool,
    http_status: Option<u16>,
    artifacts: Vec<Artifact>,
    attempts: Vec<Attempt>,
}

impl AttemptFailure {
    fn from_http(provider: ProviderKind, failure: TransportFailure) -> Self {
        let final_url_observed = !failure.attempts.is_empty();
        Self {
            provider,
            provider_was_attempted: final_url_observed,
            provider_version: None,
            failure: failure.failure,
            final_url: failure.final_url,
            final_url_observed,
            http_status: failure.http_status,
            artifacts: Vec::new(),
            attempts: failure.attempts,
        }
    }

    fn from_browser(provider: ProviderKind, failure: RenderedFailure) -> Self {
        Self {
            provider,
            provider_was_attempted: true,
            provider_version: failure.version,
            failure: failure.failure,
            final_url: failure.final_url,
            final_url_observed: failure.final_url_observed,
            http_status: failure.http_status,
            artifacts: failure.artifacts,
            attempts: vec![failure.attempt],
        }
    }

    fn from_media(provider: ProviderKind, _target: &Url, failure: media::MediaFailure) -> Self {
        let provider_was_attempted = !failure.attempts.is_empty();
        Self {
            provider,
            provider_was_attempted,
            provider_version: None,
            failure: failure.failure,
            final_url: failure.final_url,
            final_url_observed: provider_was_attempted,
            http_status: failure.http_status,
            artifacts: Vec::new(),
            attempts: failure.attempts,
        }
    }

    fn without_attempt(provider: ProviderKind, failure: Failure) -> Self {
        Self {
            provider,
            provider_was_attempted: false,
            provider_version: None,
            failure,
            final_url: None,
            final_url_observed: false,
            http_status: None,
            artifacts: Vec::new(),
            attempts: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct CandidateMeta {
    provider: ProviderKind,
    provider_version: Option<String>,
    final_url: Url,
    final_url_observed: bool,
    http_status: Option<u16>,
    artifacts: OwnedArtifacts,
}

#[derive(Debug, Default)]
struct OwnedArtifacts {
    values: Vec<Artifact>,
}

impl OwnedArtifacts {
    fn new(values: Vec<Artifact>) -> Self {
        Self { values }
    }

    fn publish(mut self) -> Vec<Artifact> {
        std::mem::take(&mut self.values)
    }

    async fn cleanup(&mut self) {
        cleanup_artifacts(&self.values).await;
        self.values.clear();
    }
}

impl Drop for OwnedArtifacts {
    fn drop(&mut self) {
        for artifact in &self.values {
            let _ = std::fs::remove_file(&artifact.path);
        }
    }
}

#[derive(Debug)]
struct EvaluatedCandidate {
    meta: CandidateMeta,
    assessment: ContentAssessment,
}

#[derive(Debug)]
struct ContentAssessment {
    extracted: Option<ExtractedContent>,
    content_status: ContentStatus,
    evidence: EvidenceEvaluation,
    failure: Option<Failure>,
}

impl ContentAssessment {
    fn can_escalate(&self) -> bool {
        if self
            .extracted
            .as_ref()
            .is_some_and(|content| content.dynamic_shell)
        {
            return true;
        }
        self.failure.as_ref().is_some_and(|failure| {
            matches!(
                failure.code,
                FailureCode::ContentEmpty
                    | FailureCode::ContentUnsupported
                    | FailureCode::ExtractionFailed
                    | FailureCode::EvidenceNotSatisfied
                    | FailureCode::HttpRejected
                    | FailureCode::NetworkFailed
                    | FailureCode::ToolUnavailable
                    | FailureCode::ProviderUnsupported
                    | FailureCode::ProviderFailed
                    | FailureCode::AccessRestricted
            )
        })
    }

    fn transition_reason(&self, provider: &str) -> String {
        if self
            .extracted
            .as_ref()
            .is_some_and(|content| content.dynamic_shell)
        {
            return format!("{provider}_insufficient:dynamic_shell");
        }
        let code = self
            .failure
            .as_ref()
            .map_or("unknown", |failure| failure.code.as_str());
        format!("{provider}_insufficient:{code}")
    }
}

async fn assess_content(
    request: &PreparedRequest,
    budget: &mut BudgetTracker,
    final_url: Url,
    bytes: Vec<u8>,
    content_type: String,
) -> ContentAssessment {
    let evidence = request.evidence.clone();
    let max_extracted_bytes = request.execution.budget.max_extracted_bytes;
    let remaining = budget.remaining_wall();
    if remaining.is_zero() {
        return failed_assessment(
            request,
            Failure::new(
                FailureCode::BudgetExhausted,
                "no wall-clock budget remains for content extraction",
            ),
        );
    }
    let extraction_options = extract::ExtractionOptions {
        enable_extraction: request.execution.adaptive.enable_extraction,
        enable_markdown: request.execution.adaptive.enable_markdown,
        enable_maincontent: request.execution.adaptive.enable_maincontent,
    };
    let task = tokio::task::spawn_blocking(move || {
        extract::extract_with_options(
            &bytes,
            &content_type,
            &final_url,
            evidence.as_ref(),
            max_extracted_bytes,
            extraction_options,
        )
    });
    let extracted = match tokio::time::timeout(remaining, task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(Failure::new(
            FailureCode::InternalError,
            format!("content extraction worker failed: {error}"),
        )),
        Err(_) => Err(Failure::new(
            FailureCode::BudgetExhausted,
            "content extraction exceeded the remaining wall-clock budget",
        )),
    };

    match extracted {
        Ok(extracted) => {
            if let Err(failure) = budget.reserve_extracted_bytes(extracted.content_bytes()) {
                return ContentAssessment {
                    extracted: Some(extracted),
                    content_status: ContentStatus::Failed,
                    evidence: EvidenceEvaluation {
                        status: requested_evidence_status(request),
                        checks: Vec::new(),
                    },
                    failure: Some(failure),
                };
            }
            let evidence = evaluate(request.evidence.as_ref(), &extracted);
            let failure = if let Some(gate) = access_gate::detect(&extracted) {
                Some(Failure::new(
                    FailureCode::AccessRestricted,
                    format!(
                        "public access is restricted by {}; CAPTCHA, authentication, and paywall bypass are not supported",
                        gate.as_str()
                    ),
                ))
            } else if evidence.status == EvidenceStatus::NotSatisfied {
                Some(Failure::new(
                    FailureCode::EvidenceNotSatisfied,
                    "one or more requested evidence conditions were not satisfied",
                ))
            } else if extracted.dynamic_shell && !request.evidence_requested() {
                Some(Failure::new(
                    FailureCode::ContentEmpty,
                    "document appears to be an unrendered JavaScript shell",
                ))
            } else {
                None
            };
            ContentAssessment {
                extracted: Some(extracted),
                content_status: ContentStatus::Parsed,
                evidence,
                failure,
            }
        }
        Err(failure) => failed_assessment(request, failure),
    }
}

fn failed_assessment(request: &PreparedRequest, failure: Failure) -> ContentAssessment {
    let content_status = match failure.code {
        FailureCode::ContentEmpty => ContentStatus::Empty,
        FailureCode::ContentUnsupported => ContentStatus::Unsupported,
        _ => ContentStatus::Failed,
    };
    ContentAssessment {
        extracted: None,
        content_status,
        evidence: EvidenceEvaluation {
            status: requested_evidence_status(request),
            checks: Vec::new(),
        },
        failure: Some(failure),
    }
}

fn finish_candidate(
    request: &PreparedRequest,
    budget: &BudgetTracker,
    trace: Vec<Attempt>,
    mut candidate: EvaluatedCandidate,
) -> FetchResult {
    let provider = candidate.meta.provider;
    match candidate.assessment.failure.take() {
        Some(failure) => build_failure(
            request,
            budget,
            trace,
            Some(candidate),
            Some(provider),
            failure,
            None,
        ),
        None => build_success(request, budget, trace, candidate),
    }
}

fn finish_failure(
    request: &PreparedRequest,
    budget: &BudgetTracker,
    trace: Vec<Attempt>,
    candidate: Option<EvaluatedCandidate>,
    attempt: AttemptFailure,
) -> FetchResult {
    let failure_provider = attempt.provider_was_attempted.then_some(attempt.provider);
    let cause = attempt.failure.clone();
    build_failure(
        request,
        budget,
        trace,
        candidate,
        failure_provider,
        cause,
        Some(attempt),
    )
}

fn build_success(
    request: &PreparedRequest,
    budget: &BudgetTracker,
    trace: Vec<Attempt>,
    mut candidate: EvaluatedCandidate,
) -> FetchResult {
    let Some(extracted) = candidate.assessment.extracted.take() else {
        return build_failure(
            request,
            budget,
            trace,
            Some(candidate),
            None,
            Failure::new(
                FailureCode::InternalError,
                "successful assessment did not contain extracted content",
            ),
            None,
        );
    };
    let status = if candidate.assessment.evidence.status == EvidenceStatus::Satisfied {
        OverallStatus::EvidenceSatisfied
    } else {
        OverallStatus::ContentOnly
    };
    let safety = content_safety::analyze(&extracted.content);
    FetchResult {
        schema_version: SCHEMA_VERSION,
        product_version: PRODUCT_VERSION.to_owned(),
        ok: true,
        status,
        transport_status: TransportStatus::Accepted,
        content_status: ContentStatus::Parsed,
        evidence_status: candidate.assessment.evidence.status,
        requested_url: redact_url(&request.intent.url),
        final_url: Some(redact_url(candidate.meta.final_url.as_str())),
        final_url_observed: candidate.meta.final_url_observed,
        mode_requested: request.intent.mode,
        provider_used: Some(candidate.meta.provider.as_str().to_owned()),
        failure_provider: None,
        failure_provider_version: None,
        provider_version: candidate.meta.provider_version,
        http_status: candidate.meta.http_status,
        content_length: extracted.content.len(),
        content: extracted.content,
        content_omitted: false,
        extraction_source: Some(extracted.source),
        extraction_quality: Some(extracted.quality),
        title: extracted.title,
        description: extracted.description,
        links: extracted.links,
        json_ld: extracted.json_ld,
        evidence_checks: candidate.assessment.evidence.checks,
        trace,
        artifacts: candidate.meta.artifacts.publish(),
        budget: budget.usage(),
        failure: None,
        content_safety: safety,
    }
}

/// Everything a failed result carries that depends on whether a content candidate
/// survived. Named fields replace a wide positional tuple whose same-typed members
/// could be transposed without the compiler or the result invariants noticing.
#[derive(Debug)]
struct FailureParts {
    provider_used: Option<String>,
    provider_version: Option<String>,
    failure_provider_version: Option<String>,
    final_url: Option<String>,
    final_url_observed: bool,
    http_status: Option<u16>,
    content_status: ContentStatus,
    evidence_status: EvidenceStatus,
    evidence_checks: Vec<EvidenceCheck>,
    content: String,
    extraction_source: Option<String>,
    extraction_quality: Option<f32>,
    title: Option<String>,
    description: Option<String>,
    links: Vec<String>,
    json_ld: Vec<Value>,
    artifacts: Vec<Artifact>,
    content_safety: ContentSafetyReport,
    transport_status: TransportStatus,
}

impl FailureParts {
    /// A candidate was retrieved and assessed, so its provenance and any extracted
    /// content are preserved alongside the failure.
    fn from_candidate(
        candidate: EvaluatedCandidate,
        fallback_provider_version: Option<String>,
    ) -> Self {
        let meta = candidate.meta;
        let assessment = candidate.assessment;
        let candidate_version = meta.provider_version;
        let failure_provider_version =
            fallback_provider_version.or_else(|| candidate_version.clone());
        let extracted = assessment.extracted;
        let has_content = extracted
            .as_ref()
            .is_some_and(|value| !value.content.is_empty());
        let safety = extracted
            .as_ref()
            .map_or_else(ContentSafetyReport::default, |value| {
                content_safety::analyze(&value.content)
            });
        Self {
            provider_used: has_content.then(|| meta.provider.as_str().to_owned()),
            provider_version: has_content.then_some(candidate_version).flatten(),
            failure_provider_version,
            final_url: Some(redact_url(meta.final_url.as_str())),
            final_url_observed: meta.final_url_observed,
            http_status: meta.http_status,
            content_status: assessment.content_status,
            evidence_status: assessment.evidence.status,
            evidence_checks: assessment.evidence.checks,
            content: extracted
                .as_ref()
                .map_or_else(String::new, |value| value.content.clone()),
            extraction_source: extracted.as_ref().map(|value| value.source.clone()),
            extraction_quality: extracted.as_ref().map(|value| value.quality),
            title: extracted.as_ref().and_then(|value| value.title.clone()),
            description: extracted
                .as_ref()
                .and_then(|value| value.description.clone()),
            links: extracted
                .as_ref()
                .map_or_else(Vec::new, |value| value.links.clone()),
            json_ld: extracted.map_or_else(Vec::new, |value| value.json_ld),
            artifacts: meta.artifacts.publish(),
            content_safety: safety,
            transport_status: TransportStatus::Accepted,
        }
    }

    /// No candidate survived, so only the last attempt's own provenance is available.
    fn from_attempt(
        request: &PreparedRequest,
        attempt: Option<AttemptFailure>,
        failure: &Failure,
        trace: &[Attempt],
    ) -> Self {
        let (failure_provider_version, final_url, final_url_observed, http_status, artifacts) =
            attempt.map_or_else(
                || (None, None, false, None, Vec::new()),
                |attempt| {
                    (
                        attempt.provider_version,
                        attempt.final_url,
                        attempt.final_url_observed,
                        attempt.http_status,
                        attempt.artifacts,
                    )
                },
            );
        let transport_status = match failure.code {
            FailureCode::InvalidRequest
            | FailureCode::PolicyRejected
            | FailureCode::DnsRejected
                if trace.is_empty() =>
            {
                TransportStatus::NotStarted
            }
            FailureCode::HttpRejected => TransportStatus::Rejected,
            _ => TransportStatus::Failed,
        };
        Self {
            provider_used: None,
            provider_version: None,
            failure_provider_version,
            final_url: final_url.as_ref().map(|url| redact_url(url.as_str())),
            final_url_observed,
            http_status,
            content_status: ContentStatus::NotAttempted,
            evidence_status: requested_evidence_status(request),
            evidence_checks: Vec::new(),
            content: String::new(),
            extraction_source: None,
            extraction_quality: None,
            title: None,
            description: None,
            links: Vec::new(),
            json_ld: Vec::new(),
            artifacts,
            content_safety: ContentSafetyReport::default(),
            transport_status,
        }
    }
}

fn build_failure(
    request: &PreparedRequest,
    budget: &BudgetTracker,
    trace: Vec<Attempt>,
    candidate: Option<EvaluatedCandidate>,
    failure_provider: Option<ProviderKind>,
    failure: Failure,
    attempt: Option<AttemptFailure>,
) -> FetchResult {
    let parts = match candidate {
        Some(candidate) => FailureParts::from_candidate(
            candidate,
            attempt.and_then(|value| value.provider_version),
        ),
        None => FailureParts::from_attempt(request, attempt, &failure, &trace),
    };
    let content_length = parts.content.len();
    FetchResult {
        schema_version: SCHEMA_VERSION,
        product_version: PRODUCT_VERSION.to_owned(),
        ok: false,
        status: OverallStatus::Failed,
        transport_status: parts.transport_status,
        content_status: parts.content_status,
        evidence_status: parts.evidence_status,
        requested_url: redact_url(&request.intent.url),
        final_url: parts.final_url,
        final_url_observed: parts.final_url_observed,
        mode_requested: request.intent.mode,
        provider_used: parts.provider_used,
        failure_provider: failure_provider.map(|provider| provider.as_str().to_owned()),
        failure_provider_version: parts.failure_provider_version,
        provider_version: parts.provider_version,
        http_status: parts.http_status,
        content_length,
        content: parts.content,
        content_omitted: false,
        extraction_source: parts.extraction_source,
        extraction_quality: parts.extraction_quality,
        title: parts.title,
        description: parts.description,
        links: parts.links,
        json_ld: parts.json_ld,
        evidence_checks: parts.evidence_checks,
        trace,
        artifacts: parts.artifacts,
        budget: budget.usage(),
        failure: Some(failure),
        content_safety: parts.content_safety,
    }
}

fn requested_evidence_status(request: &PreparedRequest) -> EvidenceStatus {
    if request.evidence_requested() {
        EvidenceStatus::NotSatisfied
    } else {
        EvidenceStatus::NotRequested
    }
}

fn failure_is_terminal(code: FailureCode) -> bool {
    matches!(
        code,
        FailureCode::InvalidRequest
            | FailureCode::PolicyRejected
            | FailureCode::DnsRejected
            | FailureCode::BudgetExhausted
            | FailureCode::AccessRestricted
            | FailureCode::InternalError
    )
}

fn enforce_invariants(
    request: &FetchRequest,
    budget: &BudgetTracker,
    result: FetchResult,
) -> FetchResult {
    if let Err(message) = result.validate_invariants() {
        let mut fallback = FetchResult::failed(
            request,
            Failure::new(
                FailureCode::InternalError,
                format!("result invariant violation: {message}"),
            ),
        );
        fallback.budget = budget.usage();
        return fallback;
    }
    result
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use url::Url;

    use super::{
        AttemptFailure, CandidateInput, CandidateMeta, ContentAssessment, EvaluatedCandidate,
        OwnedArtifacts, ProviderKind, ProviderStep, RouteExecutor, access_restriction_is_terminal,
        build_failure, provider_route, run_route,
    };
    use crate::budget::BudgetTracker;
    use crate::domain::{Attempt, FetchResult};
    use crate::domain::{
        BrowserCapability, ContentStatus, EvidenceStatus, ExtractedContent, Failure, FailureCode,
        FetchRequest, RetrievalMode,
    };
    use crate::evidence::EvidenceEvaluation;
    use crate::rendered::RuntimeConfig;
    use crate::request::PreparedRequest;
    use crate::request::{ExecutionPolicy, compile_request};
    use crate::transport::{HttpResponseData, TransportFailure};

    fn prepared(mut request: FetchRequest) -> Option<crate::request::PreparedRequest> {
        request.schema_version = crate::domain::SCHEMA_VERSION;
        compile_request(request, ExecutionPolicy::default()).ok()
    }

    #[test]
    fn explicit_rendered_mode_has_no_hidden_http_prefetch() {
        let mut request = FetchRequest::new("https://example.com");
        request.mode = RetrievalMode::Rendered;
        let prepared = prepared(request);
        assert!(prepared.is_some());
        let Some(prepared) = prepared else {
            return;
        };
        assert_eq!(
            provider_route(&prepared, false)
                .into_iter()
                .map(|step| step.provider)
                .collect::<Vec<_>>(),
            vec![ProviderKind::Browser]
        );
    }

    #[test]
    fn screenshot_auto_routes_directly_to_browser() {
        let mut request = FetchRequest::new("https://example.com");
        request.mode = RetrievalMode::Auto;
        request.browser_capability = BrowserCapability::Screenshot;
        let execution = ExecutionPolicy {
            artifact_dir: Some(std::path::PathBuf::from("artifacts")),
            ..ExecutionPolicy::default()
        };
        let request = compile_request(request, execution);
        assert!(request.is_ok());
        let Some(request) = request.ok() else {
            return;
        };
        assert_eq!(
            provider_route(&request, false)
                .into_iter()
                .map(|step| step.provider)
                .collect::<Vec<_>>(),
            vec![ProviderKind::Browser]
        );
    }

    #[test]
    fn content_auto_uses_the_documented_ladder() {
        let request = prepared(FetchRequest::new("https://example.com"));
        assert!(request.is_some());
        let Some(request) = request else {
            return;
        };
        let route = provider_route(&request, false);
        assert_eq!(
            route.first().map(|step| step.provider),
            Some(ProviderKind::Http)
        );
        assert_eq!(
            route.last().map(|step| step.provider),
            Some(ProviderKind::Browser)
        );
        assert!(
            route
                .iter()
                .any(|step| step.provider == ProviderKind::PublicRoute)
        );
        assert!(
            route
                .iter()
                .any(|step| step.provider == ProviderKind::PublicArchive)
        );
        assert!(
            route
                .iter()
                .any(|step| step.provider == ProviderKind::AdaptiveHttp)
        );
    }

    #[test]
    fn external_phase0_and_recipe_routes_precede_generic_http() {
        let Some(threads) = prepared(FetchRequest::new(
            "https://www.threads.net/@user/post/ABC_123",
        )) else {
            return;
        };
        assert_eq!(
            provider_route(&threads, false)
                .first()
                .map(|step| step.provider),
            Some(ProviderKind::Phase0Threads)
        );

        let Some(naver) = prepared(FetchRequest::new("https://section.blog.naver.com/")) else {
            return;
        };
        let route = provider_route(&naver, false);
        let recipe_index = route
            .iter()
            .position(|step| step.provider == ProviderKind::Recipe);
        let http_index = route
            .iter()
            .position(|step| step.provider == ProviderKind::Http);
        assert!(recipe_index.is_some_and(|index| { http_index.is_some_and(|http| index < http) }));
    }

    #[test]
    fn youtube_auto_routes_to_the_single_oembed_provider_before_fallbacks() {
        let request = prepared(FetchRequest::new("https://www.youtube.com/watch?v=example"));
        assert!(request.is_some());
        let Some(request) = request else {
            return;
        };
        let route = provider_route(&request, false);
        assert_eq!(
            route.first().map(|step| step.provider),
            Some(ProviderKind::MediaOembed)
        );
        let media_index = route
            .iter()
            .position(|step| step.provider == ProviderKind::MediaOembed);
        let first_public_route = route
            .iter()
            .position(|step| step.provider == ProviderKind::PublicRoute);
        assert!(
            media_index
                .is_some_and(|media| { first_public_route.is_none_or(|public| media < public) })
        );
    }

    #[test]
    fn access_restriction_is_terminal_before_any_fallback() {
        let failure = Failure::new(FailureCode::AccessRestricted, "authentication is required");
        assert!(access_restriction_is_terminal(Some(&failure)));
        assert!(!access_restriction_is_terminal(None));
    }

    #[test]
    fn origin_authentication_status_ends_the_route_for_every_origin_provider() {
        // An origin answering 401/403 is the target refusing anonymous access. Routing
        // that around through an archive or an external reader is exactly the bypass
        // the product refuses, so it is terminal for every provider that fetches the
        // requested resource itself.
        for provider in [
            ProviderKind::Http,
            ProviderKind::Browser,
            ProviderKind::BrowserPuppeteer,
        ] {
            for status in [401, 402, 403] {
                assert!(
                    super::access_status_is_terminal(
                        provider,
                        FailureCode::HttpRejected,
                        Some(status)
                    ),
                    "{provider:?} {status} should be terminal"
                );
            }
        }
    }

    #[test]
    fn a_public_route_rejection_stays_escalatable() {
        // A derived candidate answering 401/403 means that route is unavailable, not
        // that the target refused anonymous access.
        for provider in [ProviderKind::PublicRoute, ProviderKind::PublicArchive] {
            assert!(!super::access_status_is_terminal(
                provider,
                FailureCode::HttpRejected,
                Some(403)
            ));
        }
        assert!(!super::access_status_is_terminal(
            ProviderKind::Http,
            FailureCode::HttpRejected,
            Some(404)
        ));
        assert!(!super::access_status_is_terminal(
            ProviderKind::Http,
            FailureCode::NetworkFailed,
            Some(403)
        ));
    }

    #[test]
    fn configured_rescue_is_only_appended_after_the_primary_browser() {
        let mut rendered = FetchRequest::new("https://example.com");
        rendered.mode = RetrievalMode::Rendered;
        let rendered = prepared(rendered);
        assert!(rendered.is_some());
        let Some(rendered) = rendered else {
            return;
        };
        assert_eq!(
            provider_route(&rendered, true)
                .into_iter()
                .map(|step| step.provider)
                .collect::<Vec<_>>(),
            vec![ProviderKind::Browser, ProviderKind::BrowserPuppeteer]
        );

        let static_request = {
            let mut request = FetchRequest::new("https://example.com");
            request.mode = RetrievalMode::Static;
            prepared(request)
        };
        assert!(static_request.is_some());
        let Some(static_request) = static_request else {
            return;
        };
        assert_eq!(
            provider_route(&static_request, true)
                .into_iter()
                .map(|step| step.provider)
                .collect::<Vec<_>>(),
            vec![ProviderKind::Http]
        );
    }

    #[tokio::test]
    async fn explicit_rendered_failure_keeps_exact_provenance() {
        let mut request = FetchRequest::new("https://example.com");
        request.mode = RetrievalMode::Rendered;
        let runtime = RuntimeConfig {
            browser: Some(std::path::PathBuf::from(
                "/definitely-not-an-axiom-collect-browser",
            )),
            ..RuntimeConfig::default()
        };
        let result = super::Engine::public(runtime).fetch(request).await;
        assert!(!result.ok);
        assert_eq!(result.failure_provider.as_deref(), Some("browser"));
        assert_eq!(result.trace.len(), 1);
        assert_eq!(
            result
                .trace
                .first()
                .map(|attempt| attempt.provider.as_str()),
            Some("browser")
        );
    }

    #[test]
    fn preserved_candidate_does_not_replace_final_failure_version() {
        let request = prepared(FetchRequest::new("https://example.com"));
        assert!(request.is_some());
        let Some(request) = request else {
            return;
        };
        let budget = BudgetTracker::new(request.execution.budget.clone());
        assert!(budget.is_ok());
        let Some(budget) = budget.ok() else {
            return;
        };
        let final_url = url::Url::parse("https://example.com");
        assert!(final_url.is_ok());
        let Some(final_url) = final_url.ok() else {
            return;
        };
        let candidate = EvaluatedCandidate {
            meta: CandidateMeta {
                provider: ProviderKind::Browser,
                provider_version: Some("primary-version".to_owned()),
                final_url,
                final_url_observed: true,
                http_status: None,
                artifacts: OwnedArtifacts::default(),
            },
            assessment: ContentAssessment {
                extracted: Some(ExtractedContent {
                    content: "usable primary content".to_owned(),
                    source: "plain_text".to_owned(),
                    quality: 0.8,
                    title: None,
                    description: None,
                    links: Vec::new(),
                    json_ld: Vec::new(),
                    selector_hits: std::collections::BTreeMap::new(),
                    dynamic_shell: false,
                }),
                content_status: ContentStatus::Parsed,
                evidence: EvidenceEvaluation {
                    status: EvidenceStatus::NotRequested,
                    checks: Vec::new(),
                },
                failure: Some(Failure::new(
                    FailureCode::EvidenceNotSatisfied,
                    "primary candidate was insufficient",
                )),
            },
        };
        let result = build_failure(
            &request,
            &budget,
            Vec::new(),
            Some(candidate),
            Some(ProviderKind::BrowserPuppeteer),
            Failure::new(FailureCode::ProviderFailed, "rescue failed"),
            Some(AttemptFailure {
                provider: ProviderKind::BrowserPuppeteer,
                provider_was_attempted: true,
                provider_version: Some("rescue-version".to_owned()),
                failure: Failure::new(FailureCode::ProviderFailed, "rescue failed"),
                final_url: None,
                final_url_observed: false,
                http_status: None,
                artifacts: Vec::new(),
                attempts: Vec::new(),
            }),
        );
        assert_eq!(result.provider_version.as_deref(), Some("primary-version"));
        assert_eq!(
            result.failure_provider_version.as_deref(),
            Some("rescue-version")
        );
        assert_eq!(
            result.failure_provider.as_deref(),
            Some("browser_puppeteer")
        );
    }

    #[test]
    fn unpublished_candidate_artifacts_are_removed_on_cancellation_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("candidate.png");
        std::fs::write(&path, b"png")?;
        let artifacts = OwnedArtifacts::new(vec![crate::domain::Artifact {
            kind: "screenshot".to_owned(),
            path: path.to_string_lossy().into_owned(),
            media_type: "image/png".to_owned(),
            bytes: 3,
            sha256: "0".repeat(64),
        }]);
        drop(artifacts);
        assert!(!path.exists());
        Ok(())
    }

    /// One scripted provider outcome, standing in for a real retrieval.
    #[derive(Debug, Clone)]
    enum ScriptedOutcome {
        Content {
            content_type: &'static str,
            body: &'static str,
        },
        Rejected {
            code: FailureCode,
            http_status: Option<u16>,
        },
    }

    impl ScriptedOutcome {
        fn html(body: &'static str) -> Self {
            Self::Content {
                content_type: "text/html; charset=utf-8",
                body,
            }
        }

        fn text(body: &'static str) -> Self {
            Self::Content {
                content_type: "text/plain; charset=utf-8",
                body,
            }
        }

        fn rejected(code: FailureCode, http_status: Option<u16>) -> Self {
            Self::Rejected { code, http_status }
        }

        /// Returns the outcome already wrapped in a future, mirroring the shape the
        /// real executor has, so the scripted path is not a different signature.
        fn into_event(
            self,
            provider: ProviderKind,
            target: &Url,
        ) -> std::future::Ready<Result<CandidateInput, AttemptFailure>> {
            std::future::ready(match self {
                Self::Content { content_type, body } => Ok(CandidateInput::from_http(
                    provider,
                    HttpResponseData {
                        final_url: target.clone(),
                        status: 200,
                        content_type: content_type.to_owned(),
                        body: body.as_bytes().to_vec(),
                        headers: std::collections::BTreeMap::new(),
                        cookies: std::collections::BTreeMap::new(),
                        attempts: vec![scripted_attempt(provider)],
                    },
                )),
                Self::Rejected { code, http_status } => Err(AttemptFailure::from_http(
                    provider,
                    TransportFailure {
                        failure: Failure::new(code, "scripted provider outcome"),
                        attempts: vec![scripted_attempt(provider)],
                        final_url: Some(target.clone()),
                        http_status,
                    },
                )),
            })
        }
    }

    fn scripted_attempt(provider: ProviderKind) -> Attempt {
        Attempt {
            provider: provider.as_str().to_owned(),
            phase: "scripted".to_owned(),
            url: "https://example.com/".to_owned(),
            duration_ms: 0,
            http_status: None,
            bytes: 0,
            network_operations: 1,
            redirect_chain: Vec::new(),
            outcome: "scripted".to_owned(),
            transition_reason: None,
            error: None,
        }
    }

    /// Replays scripted outcomes and records which steps the route actually reached.
    ///
    /// What each assertion is really about is the step that was *not* taken, so the
    /// executor records every call rather than only the outcomes it produced.
    #[derive(Debug, Default)]
    struct ScriptedRoute {
        outcomes: Mutex<VecDeque<ScriptedOutcome>>,
        reached: Mutex<Vec<(ProviderKind, Option<String>)>>,
    }

    impl ScriptedRoute {
        fn new(outcomes: Vec<ScriptedOutcome>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into()),
                reached: Mutex::new(Vec::new()),
            }
        }

        fn reached(&self) -> Vec<(ProviderKind, Option<String>)> {
            self.reached
                .lock()
                .map(|value| value.clone())
                .unwrap_or_default()
        }

        fn providers(&self) -> Vec<ProviderKind> {
            self.reached()
                .into_iter()
                .map(|(provider, _)| provider)
                .collect()
        }
    }

    impl RouteExecutor for ScriptedRoute {
        fn attempt(
            &self,
            provider: ProviderKind,
            _request: &PreparedRequest,
            _budget: &mut BudgetTracker,
            target: &Url,
            transition_reason: Option<String>,
        ) -> impl Future<Output = Result<CandidateInput, AttemptFailure>> + Send {
            if let Ok(mut reached) = self.reached.lock() {
                reached.push((provider, transition_reason));
            }
            let outcome = self
                .outcomes
                .lock()
                .ok()
                .and_then(|mut outcomes| outcomes.pop_front())
                .unwrap_or_else(|| {
                    // A route that reached further than the script is itself the defect
                    // under test, so it must not look like a plausible provider result.
                    ScriptedOutcome::rejected(FailureCode::InternalError, None)
                });
            outcome.into_event(provider, target)
        }
    }

    fn steps(request: &PreparedRequest, providers: &[ProviderKind]) -> Vec<ProviderStep> {
        providers
            .iter()
            .map(|provider| {
                let reason = match provider {
                    ProviderKind::PublicRoute => Some("public_route=example_api".to_owned()),
                    ProviderKind::PublicArchive => Some("public_route=wayback_cdx".to_owned()),
                    _ => None,
                };
                ProviderStep::new(*provider, request.initial_url.clone(), reason)
            })
            .collect()
    }

    async fn drive(
        request: &PreparedRequest,
        providers: &[ProviderKind],
        outcomes: Vec<ScriptedOutcome>,
    ) -> Option<(FetchResult, ScriptedRoute)> {
        let mut budget = BudgetTracker::new(request.execution.budget.clone()).ok()?;
        let executor = ScriptedRoute::new(outcomes);
        let route = steps(request, providers);
        let result = run_route(&executor, route, request, &mut budget).await;
        Some((result, executor))
    }

    const LADDER: &[ProviderKind] = &[
        ProviderKind::Http,
        ProviderKind::PublicRoute,
        ProviderKind::PublicArchive,
        ProviderKind::Browser,
    ];

    /// A shell with visible text under the byte floor and more than one script, which
    /// is what makes `auto` escalate rather than accept the document.
    const SHELL_HTML: &str = "<html><body><main>Loading</main><script>a()</script><script src=\"b.js\"></script></body></html>";
    const ARTICLE_HTML: &str = "<html><head><title>Example</title></head><body><main>A real article body that is long enough to be usable content.</main></body></html>";

    #[tokio::test]
    async fn origin_authentication_status_stops_the_ladder_before_any_public_route() {
        let Some(request) = prepared(FetchRequest::new("https://example.com")) else {
            return;
        };
        let Some((result, executor)) = drive(
            &request,
            LADDER,
            vec![ScriptedOutcome::rejected(
                FailureCode::HttpRejected,
                Some(401),
            )],
        )
        .await
        else {
            return;
        };

        // The archive and the external reader must never see a URL whose origin just
        // demanded authentication.
        assert_eq!(executor.providers(), vec![ProviderKind::Http]);
        assert!(!result.ok);
        assert_eq!(
            result.failure.as_ref().map(|failure| failure.code),
            Some(FailureCode::HttpRejected)
        );
        assert_eq!(result.failure_provider.as_deref(), Some("http"));
        assert!(result.validate_invariants().is_ok());
    }

    #[tokio::test]
    async fn a_detected_gate_page_stops_the_ladder_and_keeps_its_candidate() {
        let Some(request) = prepared(FetchRequest::new("https://example.com")) else {
            return;
        };
        let gate = "<html><head><title>Just a moment...</title></head><body><main>Checking your browser before accessing the site.</main></body></html>";
        let Some((result, executor)) =
            drive(&request, LADDER, vec![ScriptedOutcome::html(gate)]).await
        else {
            return;
        };

        assert_eq!(executor.providers(), vec![ProviderKind::Http]);
        assert!(!result.ok);
        assert_eq!(
            result.failure.as_ref().map(|failure| failure.code),
            Some(FailureCode::AccessRestricted)
        );
        // The blocked page itself is still reported, so a caller can see what was hit.
        assert_eq!(result.provider_used.as_deref(), Some("http"));
        assert!(result.content.contains("Checking your browser"));
        assert!(result.validate_invariants().is_ok());
    }

    #[tokio::test]
    async fn a_dynamic_shell_escalates_through_public_routes_to_the_browser() {
        let Some(request) = prepared(FetchRequest::new("https://example.com")) else {
            return;
        };
        let Some((result, executor)) = drive(
            &request,
            &[
                ProviderKind::Http,
                ProviderKind::PublicRoute,
                ProviderKind::Browser,
            ],
            vec![
                ScriptedOutcome::html(SHELL_HTML),
                ScriptedOutcome::rejected(FailureCode::HttpRejected, Some(404)),
                ScriptedOutcome::html(ARTICLE_HTML),
            ],
        )
        .await
        else {
            return;
        };

        assert_eq!(
            executor.providers(),
            vec![
                ProviderKind::Http,
                ProviderKind::PublicRoute,
                ProviderKind::Browser
            ]
        );
        assert!(result.ok);
        assert_eq!(result.provider_used.as_deref(), Some("browser"));
        assert!(result.content.contains("A real article body"));

        // Each hop carries why the previous one was insufficient, plus the route that
        // produced this candidate.
        let reached = executor.reached();
        let public_route_reason = reached.get(1).and_then(|(_, reason)| reason.clone());
        assert_eq!(
            public_route_reason.as_deref(),
            Some("http_insufficient:dynamic_shell; public_route=example_api")
        );
        let browser_reason = reached.get(2).and_then(|(_, reason)| reason.clone());
        assert_eq!(
            browser_reason.as_deref(),
            Some("http_public_failed:http_rejected")
        );
        assert!(result.validate_invariants().is_ok());
    }

    #[tokio::test]
    async fn a_preserved_candidate_survives_every_later_provider_failure() {
        let mut intent = FetchRequest::new("https://example.com");
        intent.evidence.required_text = vec!["a phrase this page never contains".to_owned()];
        let Some(request) = prepared(intent) else {
            return;
        };
        let Some((result, executor)) = drive(
            &request,
            &[
                ProviderKind::Http,
                ProviderKind::PublicRoute,
                ProviderKind::Browser,
            ],
            vec![
                ScriptedOutcome::html(ARTICLE_HTML),
                ScriptedOutcome::rejected(FailureCode::NetworkFailed, None),
                ScriptedOutcome::rejected(FailureCode::ProviderFailed, None),
            ],
        )
        .await
        else {
            return;
        };

        assert_eq!(executor.providers().len(), 3);
        assert!(!result.ok);
        // The last provider owns the failure; the surviving candidate owns the content.
        assert_eq!(
            result.failure.as_ref().map(|failure| failure.code),
            Some(FailureCode::ProviderFailed)
        );
        assert_eq!(result.failure_provider.as_deref(), Some("browser"));
        assert_eq!(result.provider_used.as_deref(), Some("http"));
        assert!(result.content.contains("A real article body"));
        assert_eq!(result.content_status, ContentStatus::Parsed);
        assert_eq!(result.evidence_status, EvidenceStatus::NotSatisfied);
        assert!(result.validate_invariants().is_ok());
    }

    /// Requests evidence no scripted page satisfies, so every candidate is preserved
    /// rather than accepted and the ranking is what decides which one survives.
    fn unsatisfiable_evidence_request() -> Option<PreparedRequest> {
        let mut intent = FetchRequest::new("https://example.com");
        intent.evidence.required_text = vec!["a phrase this page never contains".to_owned()];
        prepared(intent)
    }

    #[tokio::test]
    async fn a_thinner_later_candidate_does_not_displace_a_better_one() {
        let Some(request) = unsatisfiable_evidence_request() else {
            return;
        };
        let Some((result, _)) = drive(
            &request,
            &[
                ProviderKind::Http,
                ProviderKind::PublicRoute,
                ProviderKind::Browser,
            ],
            vec![
                ScriptedOutcome::html(ARTICLE_HTML),
                ScriptedOutcome::text("short"),
                ScriptedOutcome::rejected(FailureCode::ProviderFailed, None),
            ],
        )
        .await
        else {
            return;
        };

        // The article was extracted more exactly and says more; a five-byte reader
        // rendering arriving later must not be what the caller is shown.
        assert!(!result.ok);
        assert_eq!(result.provider_used.as_deref(), Some("http"));
        assert_eq!(
            result.extraction_source.as_deref(),
            Some("html_selector:main+markdown")
        );
        assert!(result.content.contains("A real article body"));
        assert!(result.validate_invariants().is_ok());
    }

    #[tokio::test]
    async fn a_stronger_later_candidate_does_replace_a_weaker_one() {
        let Some(request) = unsatisfiable_evidence_request() else {
            return;
        };
        let Some((result, _)) = drive(
            &request,
            &[
                ProviderKind::Http,
                ProviderKind::PublicRoute,
                ProviderKind::Browser,
            ],
            vec![
                ScriptedOutcome::html(SHELL_HTML),
                ScriptedOutcome::html(ARTICLE_HTML),
                ScriptedOutcome::rejected(FailureCode::ProviderFailed, None),
            ],
        )
        .await
        else {
            return;
        };

        // Preservation is a ranking, not a preference for whichever came first.
        assert!(!result.ok);
        assert_eq!(result.provider_used.as_deref(), Some("http_public"));
        assert!(result.content.contains("A real article body"));
        assert!(result.validate_invariants().is_ok());
    }

    #[tokio::test]
    async fn long_article_beats_short_structured_response_when_evidence_ties() {
        let Some(request) = unsatisfiable_evidence_request() else {
            return;
        };
        let Some((result, _)) = drive(
            &request,
            &[
                ProviderKind::Http,
                ProviderKind::PublicRoute,
                ProviderKind::Browser,
            ],
            vec![
                ScriptedOutcome::Content {
                    content_type: "application/json",
                    body: r#"{"title":"short"}"#,
                },
                ScriptedOutcome::html(ARTICLE_HTML),
                ScriptedOutcome::rejected(FailureCode::ProviderFailed, None),
            ],
        )
        .await
        else {
            return;
        };

        // JSON parsing is more exact, but a short metadata payload is not a
        // better preserved failure than a substantially longer article body.
        assert!(!result.ok);
        assert_eq!(result.provider_used.as_deref(), Some("http_public"));
        assert!(result.content.contains("A real article body"));
        assert!(result.validate_invariants().is_ok());
    }

    #[tokio::test]
    async fn a_sufficient_first_candidate_ends_the_ladder() {
        let Some(request) = prepared(FetchRequest::new("https://example.com")) else {
            return;
        };
        let Some((result, executor)) =
            drive(&request, LADDER, vec![ScriptedOutcome::html(ARTICLE_HTML)]).await
        else {
            return;
        };

        assert_eq!(executor.providers(), vec![ProviderKind::Http]);
        assert!(result.ok);
        assert_eq!(result.provider_used.as_deref(), Some("http"));
        assert!(result.validate_invariants().is_ok());
    }
}
