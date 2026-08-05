use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use reqwest::header::{
    ACCEPT, CONTENT_LENGTH, LOCATION, REFERER, RETRY_AFTER, SET_COOKIE,
    USER_AGENT as USER_AGENT_HEADER,
};
use reqwest::{Client, StatusCode};
use url::Url;

use crate::budget::BudgetTracker;
use crate::domain::{Attempt, BudgetConfig, Failure, FailureCode, redact_url};
use crate::policy::{ValidatedTarget, redirect_target, validate_and_resolve};
use crate::request::PreparedRequest;

const USER_AGENT: &str = concat!(
    "axiom-collect/",
    env!("CARGO_PKG_VERSION"),
    " (+public-url-retrieval)"
);
const ACCEPT_VALUE: &str =
    "text/html,application/xhtml+xml,application/json,application/pdf,text/plain;q=0.9,*/*;q=0.1";

#[derive(Debug, Clone)]
pub struct HttpResponseData {
    pub final_url: Url,
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    pub headers: BTreeMap<String, String>,
    pub cookies: BTreeMap<String, String>,
    pub attempts: Vec<Attempt>,
}

/// Per-route request hints used by the adaptive grid.
///
/// The names mirror the external project's identity/referer dimensions, but
/// values are still ordinary HTTP headers. This deliberately does not pretend
/// to provide curl_cffi-style TLS impersonation.
#[derive(Debug, Clone, Default)]
pub(crate) struct HttpRouteProfile {
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub extra_headers: BTreeMap<String, String>,
    pub accept_http_errors: bool,
}

#[derive(Debug, Clone)]
pub struct TransportFailure {
    pub failure: Failure,
    pub attempts: Vec<Attempt>,
    pub final_url: Option<Url>,
    pub http_status: Option<u16>,
}

#[derive(Debug)]
struct BodyFailure {
    failure: Failure,
    bytes_read: usize,
}

pub(crate) async fn fetch_http(
    request: &PreparedRequest,
    budget: &mut BudgetTracker,
) -> Result<HttpResponseData, TransportFailure> {
    fetch_http_at(request, budget, request.initial_url.clone(), "http", None).await
}

pub(crate) async fn fetch_http_at(
    request: &PreparedRequest,
    budget: &mut BudgetTracker,
    initial_url: Url,
    provider_label: &str,
    route_reason: Option<&str>,
) -> Result<HttpResponseData, TransportFailure> {
    fetch_http_at_with_profile(
        request,
        budget,
        initial_url,
        provider_label,
        route_reason,
        None,
    )
    .await
}

pub(crate) async fn fetch_http_at_with_profile(
    request: &PreparedRequest,
    budget: &mut BudgetTracker,
    initial_url: Url,
    provider_label: &str,
    route_reason: Option<&str>,
    route_profile: Option<&HttpRouteProfile>,
) -> Result<HttpResponseData, TransportFailure> {
    let mut current = initial_url;
    let mut attempts = Vec::new();
    let mut redirect_chain = Vec::new();
    let mut retry_index = 0_u16;
    let mut clients = ClientCache::default();

    loop {
        budget.check_wall().map_err(|failure| TransportFailure {
            failure,
            attempts: attempts.clone(),
            final_url: Some(current.clone()),
            http_status: None,
        })?;
        let dns_timeout = budget.remaining_wall().min(Duration::from_millis(
            request.execution.budget.connect_timeout_ms,
        ));
        let target = validate_and_resolve(current.clone(), request.execution.network, dns_timeout)
            .await
            .map_err(|failure| TransportFailure {
                failure,
                attempts: attempts.clone(),
                final_url: Some(current.clone()),
                http_status: None,
            })?;
        budget
            .reserve_network(1)
            .map_err(|failure| TransportFailure {
                failure,
                attempts: attempts.clone(),
                final_url: Some(current.clone()),
                http_status: None,
            })?;

        let started = Instant::now();
        let remaining = budget.remaining_wall();
        let client = clients
            .get(&target, request, remaining)
            .map_err(|failure| TransportFailure {
                failure,
                attempts: attempts.clone(),
                final_url: Some(current.clone()),
                http_status: None,
            })?;
        let mut request_builder = client.get(target.url.clone()).header(ACCEPT, ACCEPT_VALUE);
        if let Some(user_agent) = route_profile.and_then(|profile| profile.user_agent.as_deref()) {
            request_builder = request_builder.header(USER_AGENT_HEADER, user_agent);
        }
        if let Some(referer) = route_profile.and_then(|profile| profile.referer.as_deref()) {
            request_builder = request_builder.header(REFERER, referer);
        }
        if let Some(profile) = route_profile {
            for (name, value) in &profile.extra_headers {
                if let (Ok(name), Ok(value)) = (
                    reqwest::header::HeaderName::from_bytes(name.as_bytes()),
                    reqwest::header::HeaderValue::from_str(value),
                ) {
                    request_builder = request_builder.header(name, value);
                }
            }
        }
        // Applied per request rather than per client so a reused client still
        // gets the wall budget that actually remains right now.
        let response = request_builder.timeout(remaining).send().await;

        let response = match response {
            Ok(value) => value,
            Err(error) => {
                let retryable = error.is_timeout() || error.is_connect();
                let message = error.without_url().to_string();
                attempts.push(Attempt {
                    provider: provider_label.to_owned(),
                    phase: "request".to_owned(),
                    url: redact_url(current.as_str()),
                    duration_ms: elapsed_ms(started),
                    http_status: None,
                    bytes: 0,
                    network_operations: 1,
                    redirect_chain: redirect_chain.clone(),
                    outcome: "network_error".to_owned(),
                    transition_reason: route_reason.map(str::to_owned),
                    error: Some(message.clone()),
                });
                if retryable && retry_index < request.execution.budget.max_retries {
                    reserve_retry_and_sleep(
                        request,
                        budget,
                        retry_index,
                        &attempts,
                        &current,
                        None,
                    )
                    .await?;
                    retry_index = retry_index.saturating_add(1);
                    continue;
                }
                return Err(TransportFailure {
                    failure: Failure::new(
                        FailureCode::NetworkFailed,
                        format!("HTTP request failed: {message}"),
                    ),
                    attempts,
                    final_url: Some(current),
                    http_status: None,
                });
            }
        };

        let status = response.status();
        let status_code = status.as_u16();

        if is_redirect(status) {
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            attempts.push(Attempt {
                provider: provider_label.to_owned(),
                phase: "redirect".to_owned(),
                url: redact_url(current.as_str()),
                duration_ms: elapsed_ms(started),
                http_status: Some(status_code),
                bytes: 0,
                network_operations: 1,
                redirect_chain: redirect_chain.clone(),
                outcome: "redirect".to_owned(),
                transition_reason: route_reason.map_or_else(
                    || location.as_ref().map(|_| "location_header".to_owned()),
                    |route| Some(format!("{route}; location_header")),
                ),
                error: None,
            });
            let location = location.ok_or_else(|| TransportFailure {
                failure: Failure::new(
                    FailureCode::HttpRejected,
                    format!("redirect status {status_code} has no Location header"),
                ),
                attempts: attempts.clone(),
                final_url: Some(current.clone()),
                http_status: Some(status_code),
            })?;
            budget
                .reserve_redirect()
                .map_err(|failure| TransportFailure {
                    failure,
                    attempts: attempts.clone(),
                    final_url: Some(current.clone()),
                    http_status: Some(status_code),
                })?;
            let next =
                redirect_target(&current, &location).map_err(|failure| TransportFailure {
                    failure,
                    attempts: attempts.clone(),
                    final_url: Some(current.clone()),
                    http_status: Some(status_code),
                })?;
            redirect_chain.push(redact_url(next.as_str()));
            current = next;
            retry_index = 0;
            continue;
        }

        if is_retryable_status(status) && retry_index < request.execution.budget.max_retries {
            let delay = retry_after_delay(
                response.headers(),
                retry_index,
                budget.remaining_retry_delay_ms(),
            );
            let retry_reason = format!("retry_after_ms={}", delay.as_millis());
            attempts.push(Attempt {
                provider: provider_label.to_owned(),
                phase: "retry".to_owned(),
                url: redact_url(current.as_str()),
                duration_ms: elapsed_ms(started),
                http_status: Some(status_code),
                bytes: 0,
                network_operations: 1,
                redirect_chain: redirect_chain.clone(),
                outcome: "retryable_http_status".to_owned(),
                transition_reason: Some(route_reason.map_or_else(
                    || retry_reason.clone(),
                    |route| format!("{route}; {retry_reason}"),
                )),
                error: None,
            });
            budget.reserve_retry().map_err(|failure| TransportFailure {
                failure,
                attempts: attempts.clone(),
                final_url: Some(current.clone()),
                http_status: Some(status_code),
            })?;
            sleep_with_budget(delay, budget)
                .await
                .map_err(|failure| TransportFailure {
                    failure,
                    attempts: attempts.clone(),
                    final_url: Some(current.clone()),
                    http_status: Some(status_code),
                })?;
            retry_index = retry_index.saturating_add(1);
            continue;
        }

        if !is_accepted_status(status)
            && route_profile.is_some_and(|profile| profile.accept_http_errors)
            && (400..=599).contains(&status_code)
        {
            let headers = response_headers(response.headers());
            let cookies = response_cookies(response.headers());
            let body = match read_body(response, budget).await {
                Ok(value) => value,
                Err(body_failure) => {
                    attempts.push(Attempt {
                        provider: provider_label.to_owned(),
                        phase: "response_body".to_owned(),
                        url: redact_url(current.as_str()),
                        duration_ms: elapsed_ms(started),
                        http_status: Some(status_code),
                        bytes: body_failure.bytes_read,
                        network_operations: 1,
                        redirect_chain: redirect_chain.clone(),
                        outcome: "body_read_failed".to_owned(),
                        transition_reason: route_reason.map(str::to_owned),
                        error: Some(body_failure.failure.message.clone()),
                    });
                    return Err(TransportFailure {
                        failure: body_failure.failure,
                        attempts,
                        final_url: Some(current),
                        http_status: Some(status_code),
                    });
                }
            };
            attempts.push(Attempt {
                provider: provider_label.to_owned(),
                phase: "response".to_owned(),
                url: redact_url(current.as_str()),
                duration_ms: elapsed_ms(started),
                http_status: Some(status_code),
                bytes: body.len(),
                network_operations: 1,
                redirect_chain,
                outcome: "http_candidate".to_owned(),
                transition_reason: route_reason.map(str::to_owned),
                error: None,
            });
            return Ok(HttpResponseData {
                final_url: current,
                status: status_code,
                content_type: response_content_type(&headers),
                body,
                headers,
                cookies,
                attempts,
            });
        }

        if !is_accepted_status(status) {
            attempts.push(Attempt {
                provider: provider_label.to_owned(),
                phase: "response".to_owned(),
                url: redact_url(current.as_str()),
                duration_ms: elapsed_ms(started),
                http_status: Some(status_code),
                bytes: 0,
                network_operations: 1,
                redirect_chain: redirect_chain.clone(),
                outcome: "http_rejected".to_owned(),
                transition_reason: route_reason.map(str::to_owned),
                error: None,
            });
            return Err(TransportFailure {
                failure: Failure::new(
                    FailureCode::HttpRejected,
                    format!("HTTP status {status_code} is not usable content"),
                ),
                attempts,
                final_url: Some(current),
                http_status: Some(status_code),
            });
        }

        let headers = response_headers(response.headers());
        let cookies = response_cookies(response.headers());
        let content_type = response_content_type(&headers);
        let body = match read_body(response, budget).await {
            Ok(value) => value,
            Err(body_failure) => {
                attempts.push(Attempt {
                    provider: provider_label.to_owned(),
                    phase: "response_body".to_owned(),
                    url: redact_url(current.as_str()),
                    duration_ms: elapsed_ms(started),
                    http_status: Some(status_code),
                    bytes: body_failure.bytes_read,
                    network_operations: 1,
                    redirect_chain: redirect_chain.clone(),
                    outcome: "body_read_failed".to_owned(),
                    transition_reason: route_reason.map(str::to_owned),
                    error: Some(body_failure.failure.message.clone()),
                });
                return Err(TransportFailure {
                    failure: body_failure.failure,
                    attempts,
                    final_url: Some(current),
                    http_status: Some(status_code),
                });
            }
        };
        attempts.push(Attempt {
            provider: provider_label.to_owned(),
            phase: "response".to_owned(),
            url: redact_url(current.as_str()),
            duration_ms: elapsed_ms(started),
            http_status: Some(status_code),
            bytes: body.len(),
            network_operations: 1,
            redirect_chain,
            outcome: "http_accepted".to_owned(),
            transition_reason: route_reason.map(str::to_owned),
            error: None,
        });
        return Ok(HttpResponseData {
            final_url: current,
            status: status_code,
            content_type,
            body,
            headers,
            cookies,
            attempts,
        });
    }
}

async fn reserve_retry_and_sleep(
    request: &PreparedRequest,
    budget: &mut BudgetTracker,
    retry_index: u16,
    attempts: &[Attempt],
    current: &Url,
    status: Option<u16>,
) -> Result<(), TransportFailure> {
    budget.reserve_retry().map_err(|failure| TransportFailure {
        failure,
        attempts: attempts.to_vec(),
        final_url: Some(current.clone()),
        http_status: status,
    })?;
    let delay = backoff_delay(retry_index, budget.remaining_retry_delay_ms());
    if delay.is_zero() && request.execution.budget.max_retry_delay_ms == 0 {
        return Ok(());
    }
    sleep_with_budget(delay, budget)
        .await
        .map_err(|failure| TransportFailure {
            failure,
            attempts: attempts.to_vec(),
            final_url: Some(current.clone()),
            http_status: status,
        })
}

/// Builds the client shape every HTTP request shares: no environment proxy, no
/// automatic redirects or retries, no referer, and explicit timeouts.
fn base_client_builder(budget: &BudgetConfig, remaining: Duration) -> reqwest::ClientBuilder {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .no_proxy()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_millis(budget.connect_timeout_ms).min(remaining))
        .read_timeout(Duration::from_millis(budget.read_timeout_ms).min(remaining))
        .timeout(remaining)
}

/// Reuses one client across retries and same-host redirect hops.
///
/// The address pin is a client-level setting, so a new client is still built the
/// moment the host or its validated address set changes. That keeps every request
/// bound to addresses this run resolved and approved, while a retry against an
/// unchanged target no longer rebuilds a TLS configuration and connection pool.
#[derive(Default)]
struct ClientCache {
    current: Option<(String, Vec<SocketAddr>, Client)>,
}

impl ClientCache {
    fn get(
        &mut self,
        target: &ValidatedTarget,
        request: &PreparedRequest,
        remaining: Duration,
    ) -> Result<&Client, Failure> {
        if remaining.is_zero() {
            return Err(Failure::new(
                FailureCode::BudgetExhausted,
                "no wall budget remains before HTTP request",
            ));
        }
        let reusable = self.current.as_ref().is_some_and(|(host, addresses, _)| {
            host == &target.host && addresses == &target.addresses
        });
        if !reusable {
            let client = base_client_builder(&request.execution.budget, remaining)
                // `target.host` is the normalized host the request itself carries,
                // so the validated address set is what the connection actually uses.
                .resolve_to_addrs(&target.host, &target.addresses)
                .build()
                .map_err(|error| {
                    Failure::new(
                        FailureCode::InternalError,
                        format!("HTTP client construction failed: {error}"),
                    )
                })?;
            self.current = Some((target.host.clone(), target.addresses.clone(), client));
        }
        self.current
            .as_ref()
            .map(|(_, _, client)| client)
            .ok_or_else(|| {
                Failure::new(
                    FailureCode::InternalError,
                    "HTTP client cache was left empty",
                )
            })
    }
}

/// Verifies that the built-in HTTP stack can actually be constructed on this host,
/// which is what `doctor` reports as static readiness.
pub(crate) fn probe_static_stack(budget: &BudgetConfig) -> Result<(), Failure> {
    base_client_builder(budget, Duration::from_millis(budget.max_wall_ms))
        .build()
        .map(|_| ())
        .map_err(|error| {
            Failure::new(
                FailureCode::InternalError,
                format!("HTTP client construction failed: {error}"),
            )
        })
}

async fn read_body(
    response: reqwest::Response,
    budget: &mut BudgetTracker,
) -> Result<Vec<u8>, BodyFailure> {
    if let Some(content_length) = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        && content_length > budget.config().max_response_bytes
    {
        return Err(BodyFailure {
            failure: Failure::new(
                FailureCode::BudgetExhausted,
                format!(
                    "declared response size {content_length} exceeds per-response limit {}",
                    budget.config().max_response_bytes
                ),
            ),
            bytes_read: 0,
        });
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        if let Err(failure) = budget.check_wall() {
            return Err(BodyFailure {
                failure,
                bytes_read: body.len(),
            });
        }
        let chunk = match chunk {
            Ok(value) => value,
            Err(error) => {
                return Err(BodyFailure {
                    failure: Failure::new(
                        FailureCode::NetworkFailed,
                        format!("response body read failed: {}", error.without_url()),
                    ),
                    bytes_read: body.len(),
                });
            }
        };
        let next = body.len().saturating_add(chunk.len());
        if next > budget.config().max_response_bytes {
            return Err(BodyFailure {
                failure: Failure::new(
                    FailureCode::BudgetExhausted,
                    format!(
                        "response body exceeds per-response limit {}",
                        budget.config().max_response_bytes
                    ),
                ),
                bytes_read: body.len(),
            });
        }
        if let Err(failure) = budget.reserve_response_bytes(body.len(), chunk.len()) {
            return Err(BodyFailure {
                failure,
                bytes_read: body.len(),
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn response_headers(headers: &reqwest::header::HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_owned()))
        })
        .collect()
}

fn response_cookies(headers: &reqwest::header::HeaderMap) -> BTreeMap<String, String> {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

fn response_content_type(headers: &BTreeMap<String, String>) -> String {
    headers.get("content-type").cloned().unwrap_or_default()
}

#[must_use]
pub fn is_accepted_status(status: StatusCode) -> bool {
    status.is_success() && !matches!(status.as_u16(), 204 | 205)
}

#[must_use]
pub fn is_redirect(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

#[must_use]
pub fn is_retryable_status(status: StatusCode) -> bool {
    matches!(status.as_u16(), 429 | 502 | 503 | 504)
}

fn retry_after_delay(
    headers: &reqwest::header::HeaderMap,
    retry_index: u16,
    remaining_delay_ms: u64,
) -> Duration {
    let header_ms = headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1_000));
    let backoff_ms = u64::try_from(backoff_delay(retry_index, remaining_delay_ms).as_millis())
        .unwrap_or(u64::MAX);
    Duration::from_millis(header_ms.unwrap_or(backoff_ms).min(remaining_delay_ms))
}

fn backoff_delay(retry_index: u16, maximum_ms: u64) -> Duration {
    let shift = u32::from(retry_index.min(16));
    let multiplier = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
    Duration::from_millis(200_u64.saturating_mul(multiplier).min(maximum_ms))
}

async fn sleep_with_budget(delay: Duration, budget: &mut BudgetTracker) -> Result<(), Failure> {
    budget.reserve_retry_delay(delay)?;
    tokio::time::sleep(delay).await;
    budget.check_wall()
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;

    use super::{is_accepted_status, is_redirect, is_retryable_status};

    #[test]
    fn only_usable_2xx_is_accepted() {
        assert!(is_accepted_status(StatusCode::OK));
        assert!(!is_accepted_status(StatusCode::NO_CONTENT));
        assert!(!is_accepted_status(StatusCode::RESET_CONTENT));
        assert!(!is_accepted_status(StatusCode::BAD_REQUEST));
        assert!(!is_accepted_status(StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn redirects_and_retries_are_explicit() {
        assert!(is_redirect(StatusCode::FOUND));
        assert!(!is_redirect(StatusCode::MULTIPLE_CHOICES));
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(!is_retryable_status(StatusCode::NOT_FOUND));
    }
}
