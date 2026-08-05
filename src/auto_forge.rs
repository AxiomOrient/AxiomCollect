use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use url::Url;

const MAX_FORGED_BODY_BYTES: usize = 2 * 1024 * 1024;

static AD_TELEMETRY: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?i)(gfp|sodar|doubleclick|googlesyndication|google-analytics|googletag|/gtm|/gtag|/collect|/beacon|/log(?:ging|s)?\b|/metric|/telemetry|/track|/pixel|criteo|taboola|outbrain|adsystem|/ads?/|revenuesourcemap|login-status|/config\b|/csp|/sentry|amplitude|mixpanel|segment|/consent|/geo\b|/ping\b|onetrust|cookielaw|scripttemplates|/otSDKStub|hotjar|clarity\.ms|/rum\b|newrelic|datadog|fastlane|prebid|pubmatic|rubicon|openx|indexexchange|adnxs|adservice|/gampad|/hb\b)").ok()
});

#[derive(Debug, Clone)]
pub(crate) struct NetworkResponse {
    pub url: Url,
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct ForgedContent {
    pub url: Url,
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// Pick a same-origin JSON/API response from a browser network capture.
///
/// This is the safe portion of insane-search's auto-forge idea: ranking and
/// reusing an already observed response. It never invents an endpoint, injects
/// cookies, or makes a second request with browser credentials.
pub(crate) fn select(
    page_url: &Url,
    page_html: &[u8],
    responses: Vec<NetworkResponse>,
) -> Option<ForgedContent> {
    let page_text = String::from_utf8_lossy(page_html).to_ascii_lowercase();
    if [
        "just a moment",
        "checking your browser",
        "verify you are human",
        "captcha",
        "sign in to continue",
        "subscribe to continue",
    ]
    .iter()
    .any(|marker| page_text.contains(marker))
    {
        return None;
    }
    let page_tokens = tokens(page_html);
    responses
        .into_iter()
        .filter(|response| {
            (200..300).contains(&response.status)
                && response.body.len() <= MAX_FORGED_BODY_BYTES
                && !response.body.is_empty()
                && !contains_signed_url_marker(&response.body)
                && response.url.host_str() == page_url.host_str()
                && matches!(response.url.scheme(), "http" | "https")
                && is_api_like(response)
                && !is_telemetry(&response.url)
        })
        .max_by_key(|response| score(response, &page_tokens))
        .map(|response| ForgedContent {
            url: response.url,
            status: response.status,
            content_type: response.content_type,
            body: response.body,
        })
}

fn contains_signed_url_marker(body: &[u8]) -> bool {
    let body = String::from_utf8_lossy(body).to_ascii_lowercase();
    [
        "?sig=",
        "&sig=",
        "?signature=",
        "&signature=",
        "?token=",
        "&token=",
        "?expires=",
        "&expires=",
    ]
    .iter()
    .any(|marker| body.contains(marker))
}

fn is_telemetry(url: &Url) -> bool {
    let text = url.as_str();
    AD_TELEMETRY.as_ref().is_some_and(|re| re.is_match(text))
}

fn is_api_like(response: &NetworkResponse) -> bool {
    let content_type = response.content_type.to_ascii_lowercase();
    let url = response.url.as_str().to_ascii_lowercase();
    content_type.contains("json")
        || content_type.contains("graphql")
        || [
            "/api/", "/graphql", ".json", "/ajax/", "/query", "/feed", "/data/",
        ]
        .iter()
        .any(|marker| url.contains(marker))
}

fn score(response: &NetworkResponse, page_tokens: &HashSet<String>) -> usize {
    let url = response.url.as_str().to_ascii_lowercase();
    let endpoint_score = [
        "/api/", "/graphql", ".json", "/ajax/", "/query", "/feed", "/data/",
    ]
    .iter()
    .filter(|marker| url.contains(**marker))
    .count()
    .saturating_mul(100);
    let body_tokens = tokens(&response.body);
    let overlap = body_tokens.intersection(page_tokens).count().min(100);
    endpoint_score
        .saturating_add(overlap.saturating_mul(10))
        .saturating_add(response.body.len().min(1_000_000) / 1_000)
}

fn tokens(bytes: &[u8]) -> HashSet<String> {
    String::from_utf8_lossy(bytes)
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| token.chars().count() >= 4)
        .map(str::to_ascii_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{NetworkResponse, select};

    #[test]
    fn same_origin_json_endpoint_is_ranked_over_an_asset() {
        let Some(page_url) = url::Url::parse("https://example.com/article").ok() else {
            return;
        };
        let Some(api_url) = url::Url::parse("https://example.com/api/article.json").ok() else {
            return;
        };
        let Some(asset_url) = url::Url::parse("https://example.com/app.js").ok() else {
            return;
        };
        let selected = select(
            &page_url,
            b"A public article about adaptive retrieval",
            vec![
                NetworkResponse {
                    url: asset_url,
                    status: 200,
                    content_type: "application/javascript".to_owned(),
                    body: b"const article = 'asset'".to_vec(),
                },
                NetworkResponse {
                    url: api_url.clone(),
                    status: 200,
                    content_type: "application/json".to_owned(),
                    body: b"{\"title\":\"adaptive retrieval article\"}".to_vec(),
                },
            ],
        );
        assert_eq!(selected.map(|value| value.url), Some(api_url));
    }

    #[test]
    fn cross_origin_and_error_responses_are_not_forged() {
        let Some(page_url) = url::Url::parse("https://example.com/article").ok() else {
            return;
        };
        let Some(url) = url::Url::parse("https://api.example.net/data.json").ok() else {
            return;
        };
        assert!(
            select(
                &page_url,
                b"article",
                vec![NetworkResponse {
                    url,
                    status: 403,
                    content_type: "application/json".to_owned(),
                    body: b"blocked".to_vec(),
                }]
            )
            .is_none()
        );
    }

    #[test]
    fn challenge_pages_cannot_turn_observed_api_data_into_a_bypass() {
        let Some(page_url) = url::Url::parse("https://example.com/article").ok() else {
            return;
        };
        let Some(url) = url::Url::parse("https://example.com/api/data.json").ok() else {
            return;
        };
        assert!(
            select(
                &page_url,
                b"Just a moment... Checking your browser",
                vec![NetworkResponse {
                    url,
                    status: 200,
                    content_type: "application/json".to_owned(),
                    body: b"{\"article\":\"content\"}".to_vec(),
                }]
            )
            .is_none()
        );
    }

    #[test]
    fn telemetry_endpoints_are_excluded_from_auto_forge() {
        let Some(page_url) = url::Url::parse("https://example.com/article").ok() else {
            return;
        };
        let Some(telemetry_url) = url::Url::parse("https://example.com/gtm/collect?v=2").ok()
        else {
            return;
        };
        assert!(
            select(
                &page_url,
                b"Article content",
                vec![NetworkResponse {
                    url: telemetry_url,
                    status: 200,
                    content_type: "application/json".to_owned(),
                    body: b"{\"tracking\":\"event\"}".to_vec(),
                }]
            )
            .is_none()
        );
    }
}
