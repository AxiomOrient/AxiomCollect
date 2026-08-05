use std::time::Duration;

use axiom_collect::{
    BudgetConfig, Engine, EvidenceSpec, ExecutionPolicy, FailureCode, FetchRequest, NetworkPolicy,
    RetrievalMode, RuntimeConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Serves one scripted response per connection, in order, so a redirect chain or a
/// retry sequence can be exercised against the real transport loop.
async fn serve_sequence(responses: Vec<String>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await;
    assert!(listener.is_ok());
    let Some(listener) = listener.ok() else {
        return ("http://127.0.0.1:1/".to_owned(), tokio::spawn(async {}));
    };
    let address = listener.local_addr();
    assert!(address.is_ok());
    let Some(address) = address.ok() else {
        return ("http://127.0.0.1:1/".to_owned(), tokio::spawn(async {}));
    };
    let base = format!("http://{address}");
    let handle = tokio::spawn(async move {
        for response in responses {
            let accepted = listener.accept().await;
            let Ok((mut stream, _)) = accepted else {
                return;
            };
            let mut buffer = [0_u8; 4096];
            let _ = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer)).await;
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    (base, handle)
}

fn html_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

async fn serve_response(response: String) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await;
    assert!(listener.is_ok());
    let Some(listener) = listener.ok() else {
        return ("http://127.0.0.1:1/".to_owned(), tokio::spawn(async {}));
    };
    let address = listener.local_addr();
    assert!(address.is_ok());
    let Some(address) = address.ok() else {
        return ("http://127.0.0.1:1/".to_owned(), tokio::spawn(async {}));
    };
    let handle = tokio::spawn(async move {
        let accepted = listener.accept().await;
        let Ok((mut stream, _)) = accepted else {
            return;
        };
        let mut buffer = [0_u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer)).await;
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });
    (format!("http://{address}/"), handle)
}

fn request(url: String) -> FetchRequest {
    let mut request = FetchRequest::new(url);
    request.mode = RetrievalMode::Static;
    request
}

fn execution() -> ExecutionPolicy {
    let budget = BudgetConfig {
        max_wall_ms: 5_000,
        connect_timeout_ms: 2_000,
        read_timeout_ms: 2_000,
        ..BudgetConfig::default()
    };
    ExecutionPolicy {
        budget,
        network: NetworkPolicy::AllowPrivate,
        ..ExecutionPolicy::default()
    }
}

#[tokio::test]
async fn html_success_requires_real_content() {
    let body =
        "<html><head><title>Example</title></head><body><main>Hello world</main></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (url, server) = serve_response(response).await;
    let result = Engine::new(RuntimeConfig::default(), execution())
        .fetch(request(url))
        .await;
    assert!(result.ok);
    assert_eq!(result.provider_used.as_deref(), Some("http"));
    assert_eq!(result.title.as_deref(), Some("Example"));
    assert!(result.content.contains("Hello world"));
    assert!(result.validate_invariants().is_ok());
    let _ = server.await;
}

#[tokio::test]
async fn access_gate_is_typed_and_never_success() {
    let body = "<html><head><title>Just a moment...</title><script>challenge()</script><script>wait()</script></head><body><main>Checking your browser before accessing the site. Verify you are human.</main></body></html>";
    let (url, server) = serve_response(html_response(body)).await;
    let mut request = FetchRequest::new(url);
    request.mode = RetrievalMode::Static;
    let result = Engine::new(RuntimeConfig::default(), execution())
        .fetch(request)
        .await;
    assert!(!result.ok);
    assert_eq!(
        result.failure.as_ref().map(|failure| failure.code),
        Some(FailureCode::AccessRestricted)
    );
    assert_eq!(result.failure_provider.as_deref(), Some("http"));
    assert_eq!(result.trace.len(), 1);
    assert_eq!(result.trace[0].provider, "http");
    assert!(result.content.contains("Verify you are human"));
    assert!(result.validate_invariants().is_ok());
    let _ = server.await;
}

#[tokio::test]
async fn error_json_is_not_false_success() {
    let body = "{\"error\":\"forbidden\"}";
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (url, server) = serve_response(response).await;
    let result = Engine::new(RuntimeConfig::default(), execution())
        .fetch(request(url))
        .await;
    assert!(!result.ok);
    assert_eq!(
        result.failure.as_ref().map(|failure| failure.code),
        Some(FailureCode::HttpRejected)
    );
    assert!(result.content.is_empty());
    assert!(result.validate_invariants().is_ok());
    let _ = server.await;
}

#[tokio::test]
async fn requested_evidence_is_enforced() {
    let body = "<html><body><main>available text</main></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (url, server) = serve_response(response).await;
    let mut request = request(url);
    request.evidence = EvidenceSpec {
        selectors: vec!["main".to_owned()],
        required_text: vec!["missing phrase".to_owned()],
        minimum_text_bytes: Some(4),
    };
    let result = Engine::new(RuntimeConfig::default(), execution())
        .fetch(request)
        .await;
    assert!(!result.ok);
    assert_eq!(
        result.failure.as_ref().map(|failure| failure.code),
        Some(FailureCode::EvidenceNotSatisfied)
    );
    assert!(result.content.contains("available text"));
    assert!(result.evidence_checks.iter().any(|check| !check.satisfied));
    let _ = server.await;
}

#[tokio::test]
async fn malformed_pdf_is_extraction_failure() {
    let body = b"%PDF-not-a-real-pdf";
    let response_head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut response = response_head.into_bytes();
    response.extend_from_slice(body);
    let response = String::from_utf8_lossy(&response).into_owned();
    let (url, server) = serve_response(response).await;
    let result = Engine::new(RuntimeConfig::default(), execution())
        .fetch(request(url))
        .await;
    assert!(!result.ok);
    assert!(matches!(
        result.failure.as_ref().map(|failure| failure.code),
        Some(FailureCode::ExtractionFailed | FailureCode::ContentEmpty)
    ));
    let _ = server.await;
}

#[tokio::test]
async fn redirects_are_followed_manually_and_recorded() {
    let body = "<html><body><main>after redirect</main></body></html>";
    let (base, server) = serve_sequence(vec![
        "HTTP/1.1 302 Found\r\nLocation: /second\r\nConnection: close\r\n\r\n".to_owned(),
        "HTTP/1.1 301 Moved Permanently\r\nLocation: /third\r\nConnection: close\r\n\r\n"
            .to_owned(),
        html_response(body),
    ])
    .await;
    let result = Engine::new(RuntimeConfig::default(), execution())
        .fetch(request(format!("{base}/first")))
        .await;
    assert!(result.ok, "{:?}", result.failure);
    assert!(result.content.contains("after redirect"));
    assert_eq!(result.budget.redirects, 2);
    assert!(
        result
            .final_url
            .as_deref()
            .is_some_and(|url| url.ends_with("/third"))
    );
    let hops = result
        .trace
        .iter()
        .filter(|attempt| attempt.phase == "redirect")
        .count();
    assert_eq!(hops, 2);
    let _ = server.await;
}

#[tokio::test]
async fn redirect_budget_is_hard() {
    let (base, server) = serve_sequence(vec![
        "HTTP/1.1 302 Found\r\nLocation: /b\r\nConnection: close\r\n\r\n".to_owned(),
        "HTTP/1.1 302 Found\r\nLocation: /c\r\nConnection: close\r\n\r\n".to_owned(),
        "HTTP/1.1 302 Found\r\nLocation: /d\r\nConnection: close\r\n\r\n".to_owned(),
    ])
    .await;
    let mut execution = execution();
    execution.budget.max_redirects = 2;
    let result = Engine::new(RuntimeConfig::default(), execution)
        .fetch(request(format!("{base}/a")))
        .await;
    assert!(!result.ok);
    assert_eq!(
        result.failure.as_ref().map(|failure| failure.code),
        Some(FailureCode::BudgetExhausted)
    );
    assert!(result.validate_invariants().is_ok());
    let _ = server.await;
}

#[tokio::test]
async fn retryable_status_is_retried_within_budget() {
    let body = "<html><body><main>recovered after retry</main></body></html>";
    let (base, server) = serve_sequence(vec![
        "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_owned(),
        html_response(body),
    ])
    .await;
    let result = Engine::new(RuntimeConfig::default(), execution())
        .fetch(request(format!("{base}/flaky")))
        .await;
    assert!(result.ok, "{:?}", result.failure);
    assert!(result.content.contains("recovered after retry"));
    assert_eq!(result.budget.retries, 1);
    assert!(
        result
            .trace
            .iter()
            .any(|attempt| attempt.outcome == "retryable_http_status")
    );
    let _ = server.await;
}

#[tokio::test]
async fn exhausted_retries_do_not_become_success() {
    let unavailable =
        "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_owned();
    let (base, server) = serve_sequence(vec![
        unavailable.clone(),
        unavailable.clone(),
        unavailable.clone(),
    ])
    .await;
    let mut execution = execution();
    execution.budget.max_retries = 2;
    let result = Engine::new(RuntimeConfig::default(), execution)
        .fetch(request(format!("{base}/down")))
        .await;
    assert!(!result.ok);
    assert_eq!(
        result.failure.as_ref().map(|failure| failure.code),
        Some(FailureCode::HttpRejected)
    );
    assert_eq!(result.http_status, Some(503));
    assert!(result.content.is_empty());
    assert!(result.validate_invariants().is_ok());
    let _ = server.await;
}

#[tokio::test]
async fn declared_response_size_over_budget_is_refused_before_reading() {
    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n"
        .to_owned();
    let (url, server) = serve_response(response).await;
    let mut execution = execution();
    execution.budget.max_response_bytes = 1024;
    let result = Engine::new(RuntimeConfig::default(), execution)
        .fetch(request(url))
        .await;
    assert!(!result.ok);
    assert_eq!(
        result.failure.as_ref().map(|failure| failure.code),
        Some(FailureCode::BudgetExhausted)
    );
    assert!(result.validate_invariants().is_ok());
    let _ = server.await;
}
