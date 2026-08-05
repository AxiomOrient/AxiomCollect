use serde_json::Value;
use url::Url;

use crate::budget::BudgetTracker;
use crate::domain::{Failure, FailureCode};
use crate::request::PreparedRequest;
use crate::transport::{HttpResponseData, TransportFailure, fetch_http_at};

pub(crate) async fn fetch(
    request: &PreparedRequest,
    budget: &mut BudgetTracker,
    original: &Url,
    cdx_url: &Url,
    transition_reason: Option<String>,
) -> Result<HttpResponseData, TransportFailure> {
    let cdx = fetch_http_at(
        request,
        budget,
        cdx_url.clone(),
        "http_public",
        transition_reason.as_deref(),
    )
    .await?;
    let timestamp = match capture_timestamp(&cdx.body) {
        Ok(timestamp) => timestamp,
        Err(message) => {
            return Err(TransportFailure {
                failure: Failure::new(FailureCode::ContentEmpty, message),
                attempts: cdx.attempts,
                final_url: Some(cdx.final_url),
                http_status: Some(cdx.status),
            });
        }
    };
    let replay_url = replay_url(original, &timestamp).ok_or_else(|| TransportFailure {
        failure: Failure::new(
            FailureCode::ProviderFailed,
            "Wayback capture timestamp could not form a replay URL",
        ),
        attempts: cdx.attempts.clone(),
        final_url: Some(cdx.final_url.clone()),
        http_status: Some(cdx.status),
    })?;
    let replay_reason = transition_reason.map_or_else(
        || Some("archive_replay".to_owned()),
        |reason| Some(format!("{reason}; archive_replay")),
    );
    match fetch_http_at(
        request,
        budget,
        replay_url,
        "http_public",
        replay_reason.as_deref(),
    )
    .await
    {
        Ok(mut replay) => {
            let mut attempts = cdx.attempts;
            attempts.append(&mut replay.attempts);
            replay.attempts = attempts;
            Ok(replay)
        }
        Err(mut failure) => {
            let mut attempts = cdx.attempts;
            attempts.append(&mut failure.attempts);
            failure.attempts = attempts;
            Err(failure)
        }
    }
}

fn capture_timestamp(body: &[u8]) -> Result<String, String> {
    let value = serde_json::from_slice::<Value>(body)
        .map_err(|error| format!("Wayback CDX response was not valid JSON: {error}"))?;
    let rows = value
        .as_array()
        .ok_or_else(|| "Wayback CDX response was not a JSON array".to_owned())?;
    let header = rows
        .first()
        .and_then(Value::as_array)
        .ok_or_else(|| "Wayback CDX response did not contain a header row".to_owned())?;
    let timestamp_index = header
        .iter()
        .position(|value| value.as_str() == Some("timestamp"))
        .ok_or_else(|| "Wayback CDX response has no timestamp field".to_owned())?;
    let status_index = header
        .iter()
        .position(|value| value.as_str() == Some("statuscode"));
    for row in rows.iter().skip(1).filter_map(Value::as_array) {
        let timestamp = row.get(timestamp_index).and_then(Value::as_str);
        let status_ok =
            status_index.is_none_or(|index| row.get(index).and_then(Value::as_str) == Some("200"));
        if let Some(timestamp) = timestamp
            && status_ok
            && timestamp.len() == 14
            && timestamp.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Ok(timestamp.to_owned());
        }
    }
    Err("Wayback CDX has no usable public 200 capture".to_owned())
}

fn replay_url(original: &Url, timestamp: &str) -> Option<Url> {
    if timestamp.len() != 14 || !timestamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut target = original.clone();
    target.set_fragment(None);
    Url::parse(&format!(
        "https://web.archive.org/web/{timestamp}id_/{}",
        target.as_str()
    ))
    .ok()
}

#[cfg(test)]
mod tests {
    use super::{capture_timestamp, replay_url};
    use url::Url;

    #[test]
    fn selects_only_a_valid_200_capture() {
        let body = br#"[
            ["timestamp","statuscode","mimetype"],
            ["20240101000000","404","text/html"],
            ["20240202000000","200","text/html"]
        ]"#;
        assert_eq!(
            capture_timestamp(body).ok().as_deref(),
            Some("20240202000000")
        );
    }

    #[test]
    fn rejects_empty_or_invalid_capture_rows() {
        let body = br#"[["timestamp","statuscode"],["bad","200"]]"#;
        assert!(capture_timestamp(body).is_err());
    }

    #[test]
    fn replay_removes_fragment_and_preserves_public_target() {
        let original = Url::parse("https://example.com/article?view=full#section");
        assert!(original.is_ok());
        let Some(original) = original.ok() else {
            return;
        };
        let replay = replay_url(&original, "20240202000000");
        assert_eq!(
            replay.map(|url| url.to_string()),
            Some("https://web.archive.org/web/20240202000000id_/https://example.com/article?view=full".to_owned())
        );
    }
}
