use serde_json::Value;
use url::Url;

use crate::budget::BudgetTracker;
use crate::domain::{Attempt, Failure, FailureCode};
use crate::request::PreparedRequest;
use crate::transport::{HttpResponseData, TransportFailure, fetch_http_at};

const PROVIDER_LABEL: &str = "media_oembed";

#[derive(Debug, Clone, Copy)]
struct OembedProvider {
    hosts: &'static [&'static str],
    endpoint: &'static str,
    accepts_format_query: bool,
}

const OEMBED_PROVIDERS: &[OembedProvider] = &[
    OembedProvider {
        hosts: &["youtube.com", "youtu.be"],
        endpoint: "https://www.youtube.com/oembed",
        accepts_format_query: true,
    },
    OembedProvider {
        hosts: &["vimeo.com"],
        endpoint: "https://vimeo.com/api/oembed.json",
        accepts_format_query: false,
    },
    OembedProvider {
        hosts: &["soundcloud.com"],
        endpoint: "https://soundcloud.com/oembed",
        accepts_format_query: true,
    },
];

#[cfg(test)]
const SAFE_METADATA_FIELDS: &[&str] = &[
    "title",
    "uploader",
    "extractor",
    "media_type",
    "oembed_version",
    "width",
    "height",
    "thumbnail_width",
    "thumbnail_height",
];

#[derive(Debug)]
pub(crate) struct MediaOutput {
    pub final_url: Url,
    pub body: Vec<u8>,
    pub http_status: u16,
    pub attempts: Vec<Attempt>,
}

#[derive(Debug)]
pub(crate) struct MediaFailure {
    pub failure: Failure,
    pub attempts: Vec<Attempt>,
    pub final_url: Option<Url>,
    pub http_status: Option<u16>,
}

/// Returns whether an URL belongs to the small, explicit catalog of public
/// oEmbed providers. Direct media files and unlisted hosts stay on ordinary
/// retrieval routes; this adapter never guesses an endpoint or downloads bytes.
#[must_use]
pub(crate) fn supports(url: &Url) -> bool {
    provider_for(url).is_some()
}

pub(crate) async fn fetch(
    request: &PreparedRequest,
    budget: &mut BudgetTracker,
    target: &Url,
    transition_reason: Option<String>,
) -> Result<MediaOutput, MediaFailure> {
    let endpoint = endpoint_for(target).map_err(MediaFailure::unattempted)?;
    let response = fetch_http_at(
        request,
        budget,
        endpoint,
        PROVIDER_LABEL,
        transition_reason.as_deref(),
    )
    .await
    .map_err(MediaFailure::from_transport)?;
    let HttpResponseData {
        final_url,
        status,
        body: response_body,
        attempts,
        ..
    } = response;
    let body = match parse_metadata(&response_body) {
        Ok(body) => body,
        Err(failure) => {
            let mut attempts = attempts;
            if let Some(attempt) = attempts.last_mut() {
                attempt.outcome = "metadata_rejected".to_owned();
                attempt.error = Some(failure.message.clone());
            }
            return Err(MediaFailure {
                failure,
                attempts,
                final_url: Some(final_url),
                http_status: Some(status),
            });
        }
    };
    Ok(MediaOutput {
        final_url,
        body,
        http_status: status,
        attempts,
    })
}

impl MediaFailure {
    fn unattempted(failure: Failure) -> Self {
        Self {
            failure,
            attempts: Vec::new(),
            final_url: None,
            http_status: None,
        }
    }

    fn from_transport(failure: TransportFailure) -> Self {
        Self {
            failure: failure.failure,
            attempts: failure.attempts,
            final_url: failure.final_url,
            http_status: failure.http_status,
        }
    }
}

fn provider_for(url: &Url) -> Option<&'static OembedProvider> {
    let host = url.host_str()?;
    OEMBED_PROVIDERS.iter().find(|provider| {
        provider
            .hosts
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    })
}

fn endpoint_for(target: &Url) -> Result<Url, Failure> {
    let provider = provider_for(target).ok_or_else(|| {
        Failure::new(
            FailureCode::ProviderFailed,
            "no built-in public oEmbed provider is registered for this host",
        )
    })?;
    let mut endpoint = Url::parse(provider.endpoint).map_err(|error| {
        Failure::new(
            FailureCode::ProviderFailed,
            format!("built-in oEmbed endpoint is invalid: {error}"),
        )
    })?;
    let mut query = endpoint.query_pairs_mut();
    query.append_pair("url", target.as_str());
    if provider.accepts_format_query {
        query.append_pair("format", "json");
    }
    drop(query);
    Ok(endpoint)
}

fn parse_metadata(bytes: &[u8]) -> Result<Vec<u8>, Failure> {
    let value = serde_json::from_slice::<Value>(bytes).map_err(|error| {
        Failure::new(
            FailureCode::ProviderFailed,
            format!("oEmbed returned invalid metadata JSON: {error}"),
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        Failure::new(
            FailureCode::ContentEmpty,
            "oEmbed returned metadata without an object",
        )
    })?;
    let media_type = object.get("type").and_then(Value::as_str).ok_or_else(|| {
        Failure::new(
            FailureCode::ContentEmpty,
            "oEmbed returned metadata without a media type",
        )
    })?;
    if !matches!(media_type, "video" | "rich") {
        return Err(Failure::new(
            FailureCode::ContentEmpty,
            "oEmbed returned a non-media response type",
        ));
    }
    let title = object
        .get("title")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty());
    if title.is_none() {
        return Err(Failure::new(
            FailureCode::ContentEmpty,
            "oEmbed returned no usable media title",
        ));
    }

    let mut safe = serde_json::Map::new();
    insert_safe_string(&mut safe, "title", title);
    insert_safe_string(
        &mut safe,
        "uploader",
        object.get("author_name").and_then(Value::as_str),
    );
    insert_safe_string(
        &mut safe,
        "extractor",
        object.get("provider_name").and_then(Value::as_str),
    );
    insert_safe_string(&mut safe, "media_type", Some(media_type));
    insert_safe_scalar(&mut safe, "oembed_version", object.get("version"));
    for field in ["width", "height", "thumbnail_width", "thumbnail_height"] {
        insert_safe_scalar(&mut safe, field, object.get(field));
    }
    if safe.is_empty() {
        return Err(Failure::new(
            FailureCode::ContentEmpty,
            "oEmbed returned no safe public media metadata",
        ));
    }
    serde_json::to_vec_pretty(&Value::Object(safe)).map_err(|error| {
        Failure::new(
            FailureCode::ProviderFailed,
            format!("oEmbed metadata serialization failed: {error}"),
        )
    })
}

fn insert_safe_string(
    output: &mut serde_json::Map<String, Value>,
    field: &str,
    value: Option<&str>,
) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        output.insert(field.to_owned(), Value::String(value.to_owned()));
    }
}

fn insert_safe_scalar(
    output: &mut serde_json::Map<String, Value>,
    field: &str,
    value: Option<&Value>,
) {
    if let Some(value @ (Value::String(_) | Value::Number(_) | Value::Bool(_))) = value {
        output.insert(field.to_owned(), value.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::{SAFE_METADATA_FIELDS, endpoint_for, parse_metadata, supports};
    use url::Url;

    #[test]
    fn catalogues_only_documented_oembed_hosts() {
        for input in [
            "https://www.youtube.com/watch?v=abc",
            "https://youtu.be/abc",
            "https://vimeo.com/123456",
            "https://soundcloud.com/artist/track",
        ] {
            let url = Url::parse(input);
            assert!(url.is_ok_and(|url| supports(&url)), "{input}");
        }
        for input in [
            "https://cdn.example.com/video.mp4",
            "https://www.tiktok.com/@artist/video/1",
            "https://example.com/video",
        ] {
            let url = Url::parse(input);
            assert!(url.is_ok_and(|url| !supports(&url)), "{input}");
        }
    }

    #[test]
    fn endpoints_encode_the_original_url_with_provider_specific_queries() {
        let youtube = Url::parse("https://www.youtube.com/watch?v=a&list=b");
        assert!(youtube.is_ok());
        let Some(youtube) = youtube.ok() else {
            return;
        };
        let endpoint = endpoint_for(&youtube);
        assert!(endpoint.is_ok());
        let Some(endpoint) = endpoint.ok() else {
            return;
        };
        assert_eq!(
            endpoint.as_str().split('?').next(),
            Some("https://www.youtube.com/oembed")
        );
        let query = endpoint.query_pairs().collect::<Vec<_>>();
        assert!(
            query
                .iter()
                .any(|(key, value)| key == "url" && value == youtube.as_str())
        );
        assert!(
            query
                .iter()
                .any(|(key, value)| key == "format" && value == "json")
        );

        let vimeo = Url::parse("https://vimeo.com/123456");
        assert!(vimeo.is_ok());
        let Some(vimeo) = vimeo.ok() else {
            return;
        };
        let vimeo_endpoint = endpoint_for(&vimeo);
        assert!(vimeo_endpoint.is_ok());
        let Some(vimeo_endpoint) = vimeo_endpoint.ok() else {
            return;
        };
        assert_eq!(
            vimeo_endpoint.as_str().split('?').next(),
            Some("https://vimeo.com/api/oembed.json")
        );
        let vimeo_query = vimeo_endpoint.query_pairs().collect::<Vec<_>>();
        assert!(
            vimeo_query
                .iter()
                .any(|(key, value)| key == "url" && value == vimeo.as_str())
        );
        assert!(vimeo_query.iter().all(|(key, _)| key != "format"));

        let unsupported = Url::parse("https://example.com/video");
        assert!(unsupported.is_ok_and(|url| endpoint_for(&url).is_err()));
    }

    #[test]
    fn metadata_requires_media_and_keeps_only_allowlisted_scalars() {
        let parsed = parse_metadata(
            br#"{"version":"1.0","type":"video","title":"A video","author_name":"Public author","provider_name":"YouTube","width":1280,"height":720,"thumbnail_width":480,"thumbnail_height":360,"html":"<iframe src=\"https://embed.example/?token=secret\"></iframe>","thumbnail_url":"https://cdn.example/thumb.jpg?sig=secret","author_url":"https://example.com/author","extra":{"url":"https://example.com/private"}}"#,
        );
        assert!(parsed.is_ok());
        let Some(parsed) = parsed.ok() else {
            return;
        };
        let value = serde_json::from_slice::<serde_json::Value>(&parsed);
        assert!(value.is_ok());
        let Some(value) = value.ok() else {
            return;
        };
        let object = value.as_object();
        assert!(object.is_some(), "sanitized metadata must be an object");
        let Some(object) = object else {
            return;
        };
        assert!(object.contains_key("title"));
        assert!(object.contains_key("uploader"));
        assert!(object.contains_key("extractor"));
        assert!(object.contains_key("media_type"));
        assert!(
            object
                .keys()
                .all(|key| SAFE_METADATA_FIELDS.contains(&key.as_str()))
        );
        let rendered = String::from_utf8(parsed);
        assert!(rendered.is_ok_and(|rendered| {
            !rendered.contains("iframe")
                && !rendered.contains("thumbnail_url")
                && !rendered.contains("token=secret")
                && !rendered.contains("sig=secret")
                && !rendered.contains("author_url")
        }));
    }

    #[test]
    fn metadata_rejects_non_media_or_unusable_responses() {
        assert!(parse_metadata(br#"[]"#).is_err());
        assert!(parse_metadata(br#"{"type":"link","title":"Not media"}"#).is_err());
        assert!(parse_metadata(br#"{"type":"video","title":""}"#).is_err());
    }
}
