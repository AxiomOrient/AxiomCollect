use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

const PROTOCOL_VERSION: &str = "2026-07-28";

fn metadata() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {
            "name": "axiom-collect-integration",
            "version": "1.0.0"
        },
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

fn request(id: u64, method: &str, parameters: Value) -> Value {
    let mut parameters = parameters;
    parameters["_meta"] = metadata();
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": parameters
    })
}

async fn send_request(
    input: &mut tokio::process::ChildStdin,
    output: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    value: Value,
) -> Result<Value, String> {
    let line = serde_json::to_string(&value)
        .map_err(|error| format!("MCP request serialization failed: {error}"))?;
    input
        .write_all(line.as_bytes())
        .await
        .map_err(|error| format!("MCP request write failed: {error}"))?;
    input
        .write_all(b"\n")
        .await
        .map_err(|error| format!("MCP request framing failed: {error}"))?;
    input
        .flush()
        .await
        .map_err(|error| format!("MCP request flush failed: {error}"))?;
    let line = tokio::time::timeout(Duration::from_secs(5), output.next_line())
        .await
        .map_err(|_| "MCP response did not arrive within five seconds".to_owned())?
        .map_err(|error| format!("MCP stdout read failed: {error}"))?
        .ok_or_else(|| "MCP server closed stdout before responding".to_owned())?;
    serde_json::from_str(&line).map_err(|error| format!("MCP response was not JSON: {error}"))
}

#[tokio::test]
async fn fresh_stdio_server_supports_current_mcp_lifecycle() -> Result<(), String> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_axiom-collect"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("MCP server start failed: {error}"))?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| "MCP stdin was not piped".to_owned())?;
    let output = child
        .stdout
        .take()
        .ok_or_else(|| "MCP stdout was not piped".to_owned())?;
    let mut output = BufReader::new(output).lines();

    let discover = send_request(
        &mut input,
        &mut output,
        request(1, "server/discover", json!({})),
    )
    .await?;
    assert_eq!(discover["id"], 1);
    assert_eq!(
        discover["result"]["supportedVersions"],
        json!([PROTOCOL_VERSION])
    );

    let tools = send_request(&mut input, &mut output, request(2, "tools/list", json!({}))).await?;
    assert_eq!(tools["id"], 2);
    let names = tools["result"]["tools"]
        .as_array()
        .ok_or_else(|| "tools/list did not return a tools array".to_owned())?
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, ["doctor", "retrieve_public_url"]);

    let doctor = send_request(
        &mut input,
        &mut output,
        request(3, "tools/call", json!({"name": "doctor", "arguments": {}})),
    )
    .await?;
    assert_eq!(doctor["id"], 3);
    assert!(doctor["result"]["structuredContent"]["core_ok"].is_boolean());

    // The MCP surface carries user intent only. A caller cannot reach a private
    // address, and the failure comes back as typed structured content rather than
    // as an unstructured error string.
    let private = send_request(
        &mut input,
        &mut output,
        request(
            4,
            "tools/call",
            json!({
                "name": "retrieve_public_url",
                "arguments": {"url": "http://127.0.0.1/", "mode": "static"}
            }),
        ),
    )
    .await?;
    assert_eq!(private["id"], 4);
    let structured = &private["result"]["structuredContent"];
    assert_eq!(structured["ok"], json!(false));
    assert_eq!(structured["failure"]["code"], json!("policy_rejected"));
    assert_eq!(private["result"]["isError"], json!(true));

    // Screenshot output needs an operator-configured artifact root, which this
    // server was started without.
    let screenshot = send_request(
        &mut input,
        &mut output,
        request(
            5,
            "tools/call",
            json!({
                "name": "retrieve_public_url",
                "arguments": {
                    "url": "https://example.com/",
                    "browser_capability": "screenshot"
                }
            }),
        ),
    )
    .await?;
    assert_eq!(
        screenshot["result"]["structuredContent"]["failure"]["code"],
        json!("invalid_request")
    );

    drop(input);
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .map_err(|_| "MCP server did not stop after stdin closed".to_owned())?
        .map_err(|error| format!("MCP server wait failed: {error}"))?;
    if !status.success() {
        return Err(format!("MCP server exited with {status}"));
    }
    Ok(())
}
