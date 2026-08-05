use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::Deserialize;
use url::Url;

use crate::budget::BudgetTracker;
use crate::domain::{DeviceClass, Failure, FailureCode};
use crate::learning;
use crate::observations;
use crate::policy::has_sensitive_query_key;
use crate::request::PreparedRequest;
use crate::transport::{
    HttpResponseData, HttpRouteProfile, TransportFailure, fetch_http_at_with_profile,
};

const EMBEDDED_PROFILES: &str = include_str!("../skills/axiom-collect/waf_profiles.yaml");
const MIN_ADAPTIVE_BODY_BYTES: usize = 128;

#[derive(Debug, Clone, Deserialize, Default)]
struct DetectorSet {
    #[serde(default)]
    cookie: Vec<String>,
    #[serde(default)]
    header: Vec<String>,
    #[serde(default)]
    server_contains: Vec<String>,
    #[serde(default)]
    body: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ConfidenceRules {
    #[serde(default = "default_strong_signal_count")]
    strong: usize,
    #[serde(default = "default_weak_signal_count")]
    weak: usize,
}

impl Default for ConfidenceRules {
    fn default() -> Self {
        Self {
            strong: default_strong_signal_count(),
            weak: default_weak_signal_count(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
struct WafProfile {
    #[serde(default)]
    detectors: DetectorSet,
    #[serde(default)]
    confidence_rules: ConfidenceRules,
    #[serde(default)]
    tls_impersonate_candidates: Vec<Vec<String>>,
    #[serde(default)]
    tls_impersonate_avoid: Vec<String>,
    #[serde(default)]
    referer_strategies: Vec<String>,
    #[serde(default)]
    url_transform_order: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetectionHit {
    profile_id: String,
    confidence: u8,
    signals: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AdaptiveVerdict {
    Success,
    Challenge,
    Terminal(FailureCode),
    Retryable(FailureCode),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedRoute {
    profile_id: String,
    transform: String,
    identity: String,
    referer: String,
    url: Url,
}

fn default_strong_signal_count() -> usize {
    2
}

fn default_weak_signal_count() -> usize {
    1
}

/// Run the external project's profile-driven HTTP grid through the existing
/// public-only transport. The first request is a probe; later requests are
/// ordered by the detected profile, URL transforms, client family, and referer.
pub(crate) async fn fetch_grid(
    request: &PreparedRequest,
    budget: &mut BudgetTracker,
    target: &Url,
    route_reason: Option<&str>,
) -> Result<HttpResponseData, TransportFailure> {
    let profiles = match load_profiles(request.execution.adaptive.profiles_path.as_deref()) {
        Ok(value) => value,
        Err(failure) => {
            return Err(TransportFailure {
                failure,
                attempts: Vec::new(),
                final_url: Some(target.clone()),
                http_status: None,
            });
        }
    };
    let mut attempts = Vec::new();
    let mut last_failure = None;
    let mut attempted = HashSet::new();
    let probe_identity = match request.execution.adaptive.device {
        DeviceClass::Mobile => "chrome_android",
        DeviceClass::Auto | DeviceClass::Desktop => "chrome",
    };
    let probe = PlannedRoute {
        profile_id: "probe".to_owned(),
        transform: "original".to_owned(),
        identity: probe_identity.to_owned(),
        referer: "none".to_owned(),
        url: target.clone(),
    };

    let probe_response = run_candidate(
        request,
        budget,
        &probe,
        route_reason,
        &mut attempts,
        &mut last_failure,
    )
    .await?;
    let probe_for_detection = probe_response.clone();
    if let Some(mut response) = probe_response
        && matches!(validate_response(&response), AdaptiveVerdict::Success)
    {
        record_learning_success(request, &probe, attempts.len());
        response.attempts = attempts.clone();
        return Ok(response);
    }
    attempted.insert(route_key(&probe));

    // The probe is deliberately retained only for in-memory detection. Raw
    // headers never enter the public attempt trace.
    let hits = probe_for_detection
        .as_ref()
        .map(|response| detect_profiles(&profiles, response))
        .unwrap_or_default();
    let matched = hits
        .iter()
        .filter_map(|hit| profiles.get(&hit.profile_id).map(|profile| (hit, profile)))
        .collect::<Vec<_>>();
    let profile_order = if matched.is_empty() {
        vec![(
            "unknown_challenge".to_owned(),
            profiles.get("unknown_challenge"),
        )]
    } else {
        matched
            .into_iter()
            .map(|(hit, profile)| (hit.profile_id.clone(), Some(profile)))
            .collect()
    };

    let mut plan = Vec::new();
    for (profile_id, profile) in profile_order {
        let Some(profile) = profile else {
            continue;
        };
        let transforms = preferred_transforms(profile, request.execution.adaptive.device);
        let identities = preferred_identities(profile, request.execution.adaptive.device);
        let referers = preferred_referers(profile);
        for transform in transforms {
            for identity in &identities {
                for referer in &referers {
                    let Some(url) = transform_url(target, &transform) else {
                        continue;
                    };
                    let candidate = PlannedRoute {
                        profile_id: profile_id.clone(),
                        transform: transform.clone(),
                        identity: identity.clone(),
                        referer: referer.clone(),
                        url,
                    };
                    if attempted.contains(&route_key(&candidate))
                        || plan
                            .iter()
                            .any(|other: &PlannedRoute| route_key(other) == route_key(&candidate))
                    {
                        continue;
                    }
                    plan.push(candidate);
                }
            }
        }
    }

    if let Some(max_attempts) = request.execution.adaptive.max_attempts {
        plan.truncate(usize::from(max_attempts.saturating_sub(1)));
    }
    if request.execution.adaptive.enable_learning
        && let Some(preferred) = learning::preferred_route(
            target.host_str().unwrap_or_default(),
            request.execution.adaptive.device.as_str(),
            request.execution.adaptive.learning_path.as_deref(),
        )
    {
        plan.sort_by_key(|candidate| {
            usize::from(!matches!(
                (
                    candidate.transform.as_str(),
                    candidate.identity.as_str(),
                    candidate.referer.as_str()
                ),
                (transform, identity, referer)
                    if transform == preferred.0
                        && identity == preferred.1
                        && referer == preferred.2
            ))
        });
    }
    for candidate in plan {
        if let Some(mut response) = run_candidate(
            request,
            budget,
            &candidate,
            route_reason,
            &mut attempts,
            &mut last_failure,
        )
        .await?
        {
            match validate_response(&response) {
                AdaptiveVerdict::Success => {
                    record_learning_success(request, &candidate, attempts.len());
                    response.attempts = attempts.clone();
                    return Ok(response);
                }
                AdaptiveVerdict::Terminal(code) => {
                    record_learning_failure(request);
                    last_failure = Some(TransportFailure {
                        failure: Failure::new(code, adaptive_failure_message(code)),
                        attempts: Vec::new(),
                        final_url: Some(response.final_url),
                        http_status: Some(response.status),
                    });
                }
                AdaptiveVerdict::Challenge | AdaptiveVerdict::Retryable(_) => {
                    record_learning_failure(request);
                }
            }
        } else {
            record_learning_failure(request);
        }
    }

    record_learning_failure(request);
    let failure = last_failure.unwrap_or_else(|| TransportFailure {
        failure: Failure::new(
            FailureCode::HttpRejected,
            "adaptive public-route grid found no usable response",
        ),
        attempts: Vec::new(),
        final_url: Some(target.clone()),
        http_status: None,
    });
    Err(TransportFailure {
        failure: failure.failure,
        attempts,
        final_url: failure.final_url,
        http_status: failure.http_status,
    })
}

fn record_learning_success(request: &PreparedRequest, route: &PlannedRoute, attempts: usize) {
    if !request.execution.adaptive.enable_learning {
        return;
    }
    let Some(host) = request.initial_url.host_str() else {
        return;
    };
    let device = request.execution.adaptive.device.as_str();
    learning::record_success(
        host,
        device,
        &route.profile_id,
        &route.transform,
        &route.identity,
        &route.referer,
        request.execution.adaptive.learning_path.as_deref(),
    );
    observations::append(observations::ObservationInput {
        host,
        device,
        profile_id: &route.profile_id,
        transform: &route.transform,
        identity: &route.identity,
        referer: &route.referer,
        attempts,
        configured_dir: request.execution.adaptive.observations_dir.as_deref(),
    });
}

fn record_learning_failure(request: &PreparedRequest) {
    if !request.execution.adaptive.enable_learning {
        return;
    }
    let Some(host) = request.initial_url.host_str() else {
        return;
    };
    learning::record_failure(
        host,
        request.execution.adaptive.device.as_str(),
        request.execution.adaptive.learning_path.as_deref(),
    );
}

/// Safe Phase 0 metadata rescue for Threads. The external project exposes
/// signed CDN URLs; this integration intentionally returns only post identity
/// and media counts so its public result never becomes a signed-media broker.
pub(crate) async fn fetch_threads_metadata(
    request: &PreparedRequest,
    budget: &mut BudgetTracker,
    target: &Url,
    route_reason: Option<&str>,
) -> Result<HttpResponseData, TransportFailure> {
    if !supports_threads(target) {
        return Err(TransportFailure {
            failure: Failure::new(
                FailureCode::ProviderUnsupported,
                "Threads Phase 0 route does not support this host",
            ),
            attempts: Vec::new(),
            final_url: Some(target.clone()),
            http_status: None,
        });
    }
    let response = crate::transport::fetch_http_at(
        request,
        budget,
        target.clone(),
        "phase0_threads",
        route_reason,
    )
    .await?;
    let Some(metadata) = threads_metadata(&response.body, target) else {
        return Err(TransportFailure {
            failure: Failure::new(
                FailureCode::ContentEmpty,
                "Threads page did not expose safe inline media metadata",
            ),
            attempts: response.attempts,
            final_url: Some(response.final_url),
            http_status: Some(response.status),
        });
    };
    Ok(HttpResponseData {
        final_url: response.final_url,
        status: response.status,
        content_type: "application/json".to_owned(),
        body: metadata.into_bytes(),
        headers: response.headers,
        cookies: response.cookies,
        attempts: response.attempts,
    })
}

pub(crate) fn supports_threads(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host == "threads.com"
            || host == "threads.net"
            || host.ends_with(".threads.com")
            || host.ends_with(".threads.net")
    }) && url.path().split('/').any(|segment| segment == "post")
}

fn threads_metadata(body: &[u8], url: &Url) -> Option<String> {
    let code = url
        .path_segments()?
        .collect::<Vec<_>>()
        .windows(2)
        .find(|segments| segments[0] == "post")
        .map(|segments| segments[1])
        .filter(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })?;
    let text = String::from_utf8_lossy(body);
    let marker = "video_versions";
    let mut cursor = 0;
    let mut video_count = 0_usize;
    while let Some(offset) = text[cursor..].find(marker) {
        let start = cursor + offset;
        let end = text[start..]
            .find(']')
            .map_or(text.len(), |end| start + end);
        video_count = video_count.saturating_add(text[start..end].matches("\"url\"").count());
        cursor = end.saturating_add(1);
        if cursor >= text.len() {
            break;
        }
    }
    (video_count > 0).then(|| {
        serde_json::json!({
            "post_code": code,
            "media_type": "video",
            "video_count": video_count,
            "signed_urls_omitted": true,
        })
        .to_string()
    })
}

async fn run_candidate(
    request: &PreparedRequest,
    budget: &mut BudgetTracker,
    candidate: &PlannedRoute,
    route_reason: Option<&str>,
    attempts: &mut Vec<crate::domain::Attempt>,
    last_failure: &mut Option<TransportFailure>,
) -> Result<Option<HttpResponseData>, TransportFailure> {
    let reason = format!(
        "{};adaptive_profile={};url_transform={};identity={};referer={}",
        route_reason.unwrap_or("adaptive_grid"),
        candidate.profile_id,
        candidate.transform,
        candidate.identity,
        candidate.referer
    );
    let profile = HttpRouteProfile {
        user_agent: Some(identity_user_agent(
            &candidate.identity,
            request.execution.adaptive.device,
        )),
        referer: referer_value(&candidate.url, &candidate.referer),
        extra_headers: BTreeMap::new(),
        accept_http_errors: true,
    };
    match fetch_http_at_with_profile(
        request,
        budget,
        candidate.url.clone(),
        "adaptive_http",
        Some(&reason),
        Some(&profile),
    )
    .await
    {
        Ok(response) => {
            attempts.extend(response.attempts.iter().cloned());
            Ok(Some(response))
        }
        Err(failure) => {
            attempts.extend(failure.attempts.iter().cloned());
            if failure.failure.code == FailureCode::BudgetExhausted {
                return Err(failure);
            }
            *last_failure = Some(failure);
            Ok(None)
        }
    }
}

fn validate_response(response: &HttpResponseData) -> AdaptiveVerdict {
    let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    if matches!(response.status, 401 | 407) {
        return if challenge_markers()
            .iter()
            .any(|marker| body.contains(marker))
        {
            AdaptiveVerdict::Challenge
        } else {
            AdaptiveVerdict::Terminal(FailureCode::AccessRestricted)
        };
    }
    if matches!(response.status, 404 | 410) {
        return AdaptiveVerdict::Terminal(FailureCode::HttpRejected);
    }
    if challenge_markers()
        .iter()
        .any(|marker| body.contains(marker))
    {
        return AdaptiveVerdict::Challenge;
    }
    if response.status == 429 {
        return AdaptiveVerdict::Retryable(FailureCode::HttpRejected);
    }
    if response.status == 403 {
        return AdaptiveVerdict::Terminal(FailureCode::AccessRestricted);
    }
    if !(200..300).contains(&response.status) {
        return AdaptiveVerdict::Retryable(FailureCode::HttpRejected);
    }
    if response.body.len() < MIN_ADAPTIVE_BODY_BYTES && response.body.is_empty() {
        return AdaptiveVerdict::Retryable(FailureCode::ContentEmpty);
    }
    AdaptiveVerdict::Success
}

fn adaptive_failure_message(code: FailureCode) -> &'static str {
    match code {
        FailureCode::AccessRestricted => {
            "adaptive grid reached an authentication-protected response; bypass is not supported"
        }
        FailureCode::HttpRejected => "adaptive grid reached a terminal HTTP response",
        _ => "adaptive grid did not produce usable content",
    }
}

fn challenge_markers() -> &'static [&'static str] {
    &[
        "just a moment...",
        "checking your browser",
        "verify you are human",
        "attention required! | cloudflare",
        "cf-chl-bypass",
        "sec-if-cpt-container",
        "px-captcha",
        "press & hold to confirm you are a human",
        "incapsula incident id",
        "the requested url was rejected",
        "support id is:",
        "access denied",
        "enable javascript and cookies to continue",
    ]
}

fn load_profiles(path: Option<&Path>) -> Result<BTreeMap<String, WafProfile>, Failure> {
    let source = if let Some(path) = path {
        std::fs::read_to_string(path).map_err(|error| {
            Failure::new(
                FailureCode::ProviderFailed,
                format!(
                    "failed to read WAF profile file {}: {error}",
                    path.display()
                ),
            )
        })?
    } else {
        EMBEDDED_PROFILES.to_owned()
    };
    let root = serde_yaml::from_str::<serde_yaml::Mapping>(&source).map_err(|error| {
        Failure::new(
            FailureCode::ProviderFailed,
            format!("failed to parse WAF profile YAML: {error}"),
        )
    })?;
    let mut profiles = BTreeMap::new();
    for (key, value) in root {
        let Some(key) = key.as_str() else {
            continue;
        };
        if key == "_meta" {
            continue;
        }
        let profile = serde_yaml::from_value::<WafProfile>(value).map_err(|error| {
            Failure::new(
                FailureCode::ProviderFailed,
                format!("failed to parse WAF profile {key}: {error}"),
            )
        })?;
        profiles.insert(key.to_owned(), profile);
    }
    if profiles.is_empty() {
        return Err(Failure::new(
            FailureCode::ProviderFailed,
            "WAF profile file contains no profiles",
        ));
    }
    Ok(profiles)
}

fn detect_profiles(
    profiles: &BTreeMap<String, WafProfile>,
    response: &HttpResponseData,
) -> Vec<DetectionHit> {
    let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    let mut hits = profiles
        .iter()
        .filter_map(|(profile_id, profile)| {
            let signals = detector_signal_count(profile, response, &body);
            let confidence = if signals >= profile.confidence_rules.strong
                && profile.confidence_rules.strong > 0
            {
                90
            } else if signals >= profile.confidence_rules.weak && profile.confidence_rules.weak > 0
            {
                60
            } else {
                0
            };
            (confidence > 0).then_some(DetectionHit {
                profile_id: profile_id.clone(),
                confidence,
                signals,
            })
        })
        .collect::<Vec<_>>();
    hits.sort_by(|left, right| {
        right
            .confidence
            .cmp(&left.confidence)
            .then_with(|| right.signals.cmp(&left.signals))
            .then_with(|| left.profile_id.cmp(&right.profile_id))
    });
    hits
}

fn detector_signal_count(profile: &WafProfile, response: &HttpResponseData, body: &str) -> usize {
    let cookies = response
        .cookies
        .keys()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let header_names = response.headers.keys().cloned().collect::<Vec<_>>();
    let server = response
        .headers
        .get("server")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    usize::from(
        profile
            .detectors
            .cookie
            .iter()
            .any(|pattern| cookies.iter().any(|value| wildcard_match(pattern, value))),
    ) + usize::from(profile.detectors.header.iter().any(|pattern| {
        header_names
            .iter()
            .any(|value| wildcard_match(pattern, value))
    })) + usize::from(
        profile
            .detectors
            .server_contains
            .iter()
            .any(|marker| server.contains(&marker.to_ascii_lowercase())),
    ) + usize::from(
        profile
            .detectors
            .body
            .iter()
            .any(|marker| body.contains(&marker.to_ascii_lowercase())),
    )
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    let mut pattern_index = 0;
    let mut value_index = 0;
    let mut star = None;
    let mut star_value = 0;
    let pattern_bytes = pattern.as_bytes();
    let value_bytes = value.as_bytes();
    while value_index < value_bytes.len() {
        if pattern_index < pattern_bytes.len()
            && (pattern_bytes[pattern_index] == value_bytes[value_index]
                || pattern_bytes[pattern_index] == b'?')
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern_bytes.len() && pattern_bytes[pattern_index] == b'*' {
            star = Some(pattern_index);
            pattern_index += 1;
            star_value = value_index;
        } else if let Some(star_index) = star {
            pattern_index = star_index + 1;
            star_value += 1;
            value_index = star_value;
        } else {
            return false;
        }
    }
    while pattern_index < pattern_bytes.len() && pattern_bytes[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern_bytes.len()
}

fn preferred_transforms(profile: &WafProfile, device: DeviceClass) -> Vec<String> {
    let mut values = if profile.url_transform_order.is_empty() {
        vec![
            "original".to_owned(),
            "mobile_subdomain".to_owned(),
            "drop_www".to_owned(),
        ]
    } else {
        profile.url_transform_order.clone()
    };
    if device == DeviceClass::Mobile && !values.iter().any(|value| value == "mobile_subdomain") {
        values.insert(0, "mobile_subdomain".to_owned());
    }
    values
}

fn preferred_identities(profile: &WafProfile, device: DeviceClass) -> Vec<String> {
    let mut values = profile
        .tls_impersonate_candidates
        .iter()
        .flatten()
        .filter(|identity| {
            !profile
                .tls_impersonate_avoid
                .iter()
                .any(|avoid| avoid.eq_ignore_ascii_case(identity))
        })
        .cloned()
        .collect::<Vec<_>>();
    if values.is_empty() {
        values = vec!["chrome".to_owned(), "safari".to_owned()];
    }
    if device == DeviceClass::Mobile {
        values
            .sort_by_key(|value| usize::from(!value.contains("mobile") && !value.contains("ios")));
    }
    values.dedup();
    values
}

fn preferred_referers(profile: &WafProfile) -> Vec<String> {
    if profile.referer_strategies.is_empty() {
        vec!["self_root".to_owned(), "none".to_owned()]
    } else {
        profile.referer_strategies.clone()
    }
}

fn transform_url(original: &Url, transform: &str) -> Option<Url> {
    if has_sensitive_query_key(original) {
        return None;
    }
    let mut candidate = original.clone();
    candidate.set_fragment(None);
    match transform {
        "original" => Some(candidate),
        "mobile_subdomain" => {
            let host = candidate.host_str()?;
            let apex = host.strip_prefix("www.")?;
            candidate.set_host(Some(&format!("m.{apex}"))).ok()?;
            Some(candidate)
        }
        "am_prefix" => {
            let host = candidate.host_str()?;
            if host.starts_with("m.") {
                return Some(candidate);
            }
            candidate.set_host(Some(&format!("m.{host}"))).ok()?;
            Some(candidate)
        }
        "drop_www" => {
            let apex = candidate.host_str()?.strip_prefix("www.")?.to_owned();
            candidate.set_host(Some(&apex)).ok()?;
            Some(candidate)
        }
        _ => None,
    }
}

fn identity_user_agent(identity: &str, device: DeviceClass) -> String {
    let mobile = device == DeviceClass::Mobile
        || identity.contains("android")
        || identity.contains("ios")
        || identity.contains("mobile");
    if mobile {
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36".to_owned()
    } else if identity.contains("safari") {
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15".to_owned()
    } else if identity.contains("firefox") {
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0"
            .to_owned()
    } else if identity.contains("edge") {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/131.0.0.0 Safari/537.36".to_owned()
    } else {
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_owned()
    }
}

fn referer_value(url: &Url, strategy: &str) -> Option<String> {
    match strategy {
        "self_root" => Some(format!("{}://{}/", url.scheme(), url.host_str()?)),
        "google_search" => Some("https://www.google.com/".to_owned()),
        _ => None,
    }
}

fn route_key(route: &PlannedRoute) -> String {
    format!("{}|{}|{}", route.url, route.identity, route.referer)
}

#[cfg(test)]
mod tests {
    use super::{
        AdaptiveVerdict, DetectorSet, WafProfile, detect_profiles, identity_user_agent,
        transform_url, validate_response, wildcard_match,
    };
    use crate::transport::HttpResponseData;
    use std::collections::BTreeMap;

    fn response(
        body: &str,
        headers: &[(&str, &str)],
        cookies: &[(&str, &str)],
    ) -> Option<HttpResponseData> {
        let final_url = url::Url::parse("https://example.com").ok()?;
        Some(HttpResponseData {
            final_url,
            status: 403,
            content_type: "text/html".to_owned(),
            body: body.as_bytes().to_vec(),
            headers: headers
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
            cookies: cookies
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
            attempts: Vec::new(),
        })
    }

    #[test]
    fn wildcard_detector_matches_product_headers_and_cookies() {
        assert!(wildcard_match("x-akamai-*", "x-akamai-test"));
        assert!(wildcard_match("_px*", "_px3"));
        assert!(!wildcard_match("cf-*", "x-cf-test"));
    }

    #[test]
    fn profile_detection_requires_configured_signals() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "example".to_owned(),
            WafProfile {
                detectors: DetectorSet {
                    cookie: vec!["challenge".to_owned()],
                    ..DetectorSet::default()
                },
                ..WafProfile::default()
            },
        );
        let Some(response) = response("blocked", &[], &[("challenge", "1")]) else {
            return;
        };
        let hits = detect_profiles(&profiles, &response);
        assert_eq!(
            hits.first().map(|hit| hit.profile_id.as_str()),
            Some("example")
        );
    }

    #[test]
    fn forbidden_challenge_is_grid_eligible_but_auth_response_is_terminal() {
        let challenge = response("Just a moment... Checking your browser", &[], &[]);
        let Some(challenge) = challenge else {
            return;
        };
        assert_eq!(validate_response(&challenge), AdaptiveVerdict::Challenge);

        let auth = response("Please sign in to continue", &[], &[]);
        let Some(auth) = auth else {
            return;
        };
        assert_eq!(
            validate_response(&auth),
            AdaptiveVerdict::Terminal(crate::domain::FailureCode::AccessRestricted)
        );
    }

    #[test]
    fn transforms_remove_fragments_and_preserve_public_query() {
        let Some(url) = url::Url::parse("https://www.example.com/post?id=1#part").ok() else {
            return;
        };
        let Some(mobile) = transform_url(&url, "mobile_subdomain") else {
            return;
        };
        assert_eq!(mobile.host_str(), Some("m.example.com"));
        assert_eq!(mobile.fragment(), None);
        assert_eq!(mobile.query(), Some("id=1"));
    }

    #[test]
    fn identity_hints_change_only_the_http_user_agent_family() {
        let mobile = identity_user_agent("chrome_android", crate::domain::DeviceClass::Auto);
        let desktop = identity_user_agent("chrome", crate::domain::DeviceClass::Desktop);
        assert!(mobile.contains("Mobile"));
        assert!(!desktop.contains("Mobile"));
    }

    #[test]
    fn threads_phase0_returns_metadata_without_signed_urls() {
        let Some(url) = url::Url::parse("https://www.threads.net/@user/post/ABC_123").ok() else {
            return;
        };
        let body = br#"<script>\"code\":\"ABC_123\",\"video_versions\":[{\"url\":\"https://cdn.example/video?sig=secret\"}]</script>"#;
        let Some(metadata) = super::threads_metadata(body, &url) else {
            return;
        };
        assert!(metadata.contains("ABC_123"));
        assert!(!metadata.contains("sig=secret"));
    }
}
