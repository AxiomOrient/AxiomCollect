use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::doctor;
use crate::domain::{
    BrowserCapability, BudgetConfig, DEFAULT_CONNECT_TIMEOUT_MS, DEFAULT_MAX_BROWSER_LAUNCHES,
    DEFAULT_MAX_EXTRACTED_BYTES, DEFAULT_MAX_NETWORK_OPERATIONS, DEFAULT_MAX_REDIRECTS,
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_MAX_RETRIES, DEFAULT_MAX_RETRY_DELAY_MS,
    DEFAULT_MAX_TOTAL_BYTES, DEFAULT_MAX_WALL_MS, DEFAULT_READ_TIMEOUT_MS, DeviceClass,
    EvidenceSpec, Failure, FailureCode, FetchRequest, FetchResult, NetworkPolicy, RetrievalMode,
    SCHEMA_VERSION,
};
use crate::engine::Engine;
use crate::rendered::RuntimeConfig;
use crate::request::{AdaptivePolicy, ExecutionPolicy};

#[derive(Debug, Parser)]
#[command(
    name = "axiom-collect",
    version,
    about = "Fail-closed public URL retrieval with bounded HTTP and isolated installed-browser recovery"
)]
pub struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    browser_path: Option<PathBuf>,
    #[arg(long, global = true, value_name = "PATH")]
    node_path: Option<PathBuf>,
    #[arg(long, global = true, value_name = "DIR")]
    puppeteer_root: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Retrieve(Box<RetrieveArgs>),
    Doctor(DoctorArgs),
    Capabilities(OutputArgs),
    Mcp(McpArgs),
}

#[derive(Debug, Args)]
struct RetrieveArgs {
    url: String,
    #[arg(long, value_enum, default_value_t = RetrievalMode::Auto)]
    mode: RetrievalMode,
    #[arg(long, value_enum, default_value_t = BrowserCapability::Content)]
    browser_capability: BrowserCapability,
    #[arg(long = "selector")]
    selectors: Vec<String>,
    #[arg(long = "require-text")]
    required_text: Vec<String>,
    #[arg(long)]
    minimum_text_bytes: Option<usize>,
    #[arg(long, value_name = "DIR")]
    artifact_dir: Option<PathBuf>,
    #[arg(long)]
    allow_private: bool,
    #[arg(long)]
    omit_content: bool,
    #[arg(long)]
    pretty: bool,
    #[arg(long, value_enum, default_value_t = DeviceClass::Auto)]
    device: DeviceClass,
    #[arg(long)]
    max_attempts: Option<u16>,
    #[arg(long)]
    no_retry: bool,
    #[arg(long)]
    no_extract: bool,
    #[arg(long)]
    no_markdown: bool,
    #[arg(long)]
    maincontent: bool,
    #[arg(long)]
    no_playwright: bool,
    #[arg(long)]
    no_phase0: bool,
    #[arg(long)]
    no_jina_reader: bool,
    #[arg(long)]
    enable_learning: bool,
    #[arg(long)]
    auto_forge: bool,
    #[arg(long, value_name = "PATH")]
    profiles_path: Option<PathBuf>,
    #[arg(long, value_name = "DIR")]
    recipes_dir: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    learning_path: Option<PathBuf>,
    #[arg(long, value_name = "DIR")]
    observations_dir: Option<PathBuf>,
    /// External-project-compatible wall timeout in seconds.
    #[arg(long)]
    timeout: Option<u64>,
    #[arg(long, default_value_t = DEFAULT_MAX_WALL_MS)]
    max_wall_ms: u64,
    #[arg(long, default_value_t = DEFAULT_MAX_NETWORK_OPERATIONS)]
    max_network_operations: u32,
    #[arg(long, default_value_t = DEFAULT_MAX_RESPONSE_BYTES)]
    max_response_bytes: usize,
    #[arg(long, default_value_t = DEFAULT_MAX_EXTRACTED_BYTES)]
    max_extracted_bytes: usize,
    #[arg(long, default_value_t = DEFAULT_MAX_TOTAL_BYTES)]
    max_total_bytes: usize,
    #[arg(long, default_value_t = DEFAULT_MAX_REDIRECTS)]
    max_redirects: u16,
    #[arg(long, default_value_t = DEFAULT_MAX_RETRIES)]
    max_retries: u16,
    #[arg(long, default_value_t = DEFAULT_MAX_BROWSER_LAUNCHES)]
    max_browser_launches: u16,
    #[arg(long, default_value_t = DEFAULT_MAX_RETRY_DELAY_MS)]
    max_retry_delay_ms: u64,
    #[arg(long, default_value_t = DEFAULT_CONNECT_TIMEOUT_MS)]
    connect_timeout_ms: u64,
    #[arg(long, default_value_t = DEFAULT_READ_TIMEOUT_MS)]
    read_timeout_ms: u64,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[arg(long)]
    require_rendered: bool,
    #[arg(long)]
    pretty: bool,
}

#[derive(Debug, Args)]
struct OutputArgs {
    #[arg(long)]
    pretty: bool,
}

#[derive(Debug, Args)]
struct McpArgs {
    #[arg(long, default_value_t = 1024 * 1024)]
    max_frame_bytes: usize,
    #[arg(long, value_name = "DIR")]
    artifact_dir: Option<PathBuf>,
}

impl Cli {
    #[must_use]
    fn runtime_config(&self) -> RuntimeConfig {
        let mut config = RuntimeConfig::from_environment();
        if let Some(path) = &self.browser_path {
            config.browser = Some(path.clone());
        }
        if let Some(path) = &self.node_path {
            config.node = Some(path.clone());
        }
        if let Some(path) = &self.puppeteer_root {
            config.puppeteer_root = Some(path.clone());
        }
        config
    }
}

impl RetrieveArgs {
    #[must_use]
    fn into_parts(self) -> (FetchRequest, ExecutionPolicy) {
        let max_wall_ms = self
            .timeout
            .map_or(self.max_wall_ms, |seconds| seconds.saturating_mul(1_000));
        let intent = FetchRequest {
            schema_version: SCHEMA_VERSION,
            url: self.url,
            mode: self.mode,
            browser_capability: self.browser_capability,
            evidence: EvidenceSpec {
                selectors: self.selectors,
                required_text: self.required_text,
                minimum_text_bytes: self.minimum_text_bytes,
            },
        };
        let execution = ExecutionPolicy {
            budget: BudgetConfig {
                max_wall_ms,
                max_network_operations: self.max_network_operations,
                max_response_bytes: self.max_response_bytes,
                max_extracted_bytes: self.max_extracted_bytes,
                max_total_bytes: self.max_total_bytes,
                max_redirects: self.max_redirects,
                max_retries: if self.no_retry { 0 } else { self.max_retries },
                max_browser_launches: self.max_browser_launches,
                max_retry_delay_ms: self.max_retry_delay_ms,
                connect_timeout_ms: self.connect_timeout_ms,
                read_timeout_ms: self.read_timeout_ms,
            },
            network: if self.allow_private {
                NetworkPolicy::AllowPrivate
            } else {
                NetworkPolicy::PublicOnly
            },
            artifact_dir: self.artifact_dir,
            adaptive: AdaptivePolicy {
                device: self.device,
                max_attempts: self.max_attempts,
                enable_phase0: !self.no_phase0,
                enable_extraction: !self.no_extract,
                enable_markdown: !self.no_markdown,
                enable_maincontent: self.maincontent,
                enable_browser: !self.no_playwright,
                enable_recipes: true,
                enable_jina_reader: !self.no_jina_reader,
                enable_learning: self.enable_learning,
                enable_auto_forge: self.auto_forge,
                profiles_path: self.profiles_path,
                recipes_dir: self.recipes_dir,
                learning_path: self.learning_path,
                observations_dir: self.observations_dir,
            },
        };
        (intent, execution)
    }
}

pub async fn run(cli: Cli) -> u8 {
    let runtime = cli.runtime_config();
    match cli.command {
        Command::Retrieve(args) => {
            let args = *args;
            let include_content = !args.omit_content;
            let pretty = args.pretty;
            let (request, execution) = args.into_parts();
            let engine = Engine::new(runtime, execution);
            let mut fetch = Box::pin(engine.fetch(request.clone()));
            let result = tokio::select! {
                result = fetch.as_mut() => result,
                signal = operator_interrupt() => {
                    match signal {
                        Ok(()) => FetchResult::failed(
                            &request,
                            Failure::new(
                                FailureCode::ProviderFailed,
                                "retrieval interrupted by the operator",
                            ),
                        ),
                        Err(_) => fetch.as_mut().await,
                    }
                }
            };
            drop(fetch);
            let exit_code = result.exit_code();
            match write_json(&result.for_output(include_content), pretty) {
                Ok(()) => exit_code,
                Err(error) => {
                    eprintln!("JSON serialization failed: {error}");
                    1
                }
            }
        }
        Command::Doctor(args) => {
            let report = doctor::run(runtime).await;
            let success = report.core_ok && (!args.require_rendered || report.rendered_ready);
            match write_json(&report, args.pretty) {
                Ok(()) if success => 0,
                Ok(()) => 1,
                Err(error) => {
                    eprintln!("JSON serialization failed: {error}");
                    1
                }
            }
        }
        Command::Capabilities(args) => match write_json(&doctor::capabilities(), args.pretty) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("JSON serialization failed: {error}");
                1
            }
        },
        Command::Mcp(args) => {
            if args.max_frame_bytes < 1024 {
                eprintln!("MCP max_frame_bytes must be at least 1024");
                return 2;
            }
            let execution = ExecutionPolicy {
                artifact_dir: args.artifact_dir,
                ..ExecutionPolicy::default()
            };
            match crate::mcp::serve(Engine::new(runtime, execution), args.max_frame_bytes).await {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("MCP server failed: {error}");
                    1
                }
            }
        }
    }
}

#[cfg(unix)]
async fn operator_interrupt() -> Result<(), std::io::Error> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn operator_interrupt() -> Result<(), std::io::Error> {
    tokio::signal::ctrl_c().await
}

fn write_json<T: serde::Serialize>(value: &T, pretty: bool) -> Result<(), serde_json::Error> {
    let serialized = if pretty {
        serde_json::to_string_pretty(value)?
    } else {
        serde_json::to_string(value)?
    };
    println!("{serialized}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command};
    use crate::domain::BudgetConfig;

    #[test]
    fn cli_defaults_are_the_product_defaults() {
        // An operator who passes no budget option must get exactly the documented
        // default policy, so the two definitions are pinned to each other here.
        let cli = Cli::try_parse_from(["axiom-collect", "retrieve", "https://example.com"]);
        assert!(cli.is_ok());
        let Some(Command::Retrieve(args)) = cli.ok().map(|value| value.command) else {
            return;
        };
        let (_, execution) = (*args).into_parts();
        assert_eq!(execution.budget, BudgetConfig::default());
    }

    #[test]
    fn external_adaptive_flags_compile_into_operator_policy() {
        let cli = Cli::try_parse_from([
            "axiom-collect",
            "retrieve",
            "https://example.com",
            "--device",
            "mobile",
            "--max-attempts",
            "7",
            "--no-retry",
            "--no-extract",
            "--no-markdown",
            "--maincontent",
            "--no-playwright",
            "--no-phase0",
            "--no-jina-reader",
            "--enable-learning",
            "--auto-forge",
            "--timeout",
            "30",
        ]);
        assert!(cli.is_ok());
        let Some(Command::Retrieve(args)) = cli.ok().map(|value| value.command) else {
            return;
        };
        let (request, execution) = (*args).into_parts();
        assert_eq!(request.url, "https://example.com");
        assert_eq!(
            execution.adaptive.device,
            crate::domain::DeviceClass::Mobile
        );
        assert_eq!(execution.adaptive.max_attempts, Some(7));
        assert!(!execution.adaptive.enable_phase0);
        assert!(!execution.adaptive.enable_jina_reader);
        assert!(!execution.adaptive.enable_browser);
        assert!(!execution.adaptive.enable_extraction);
        assert!(!execution.adaptive.enable_markdown);
        assert!(execution.adaptive.enable_maincontent);
        assert!(execution.adaptive.enable_learning);
        assert!(execution.adaptive.enable_auto_forge);
        assert_eq!(execution.budget.max_retries, 0);
        assert_eq!(execution.budget.max_wall_ms, 30_000);
    }
}
