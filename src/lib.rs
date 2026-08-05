mod access_gate;
mod adaptive;
mod archive;
mod auto_forge;
mod browser;
mod budget;
mod cli;
mod content_safety;
mod doctor;
mod domain;
mod egress;
mod engine;
mod evidence;
mod extract;
mod learning;
mod mcp;
mod media;
mod observations;
mod policy;
mod process;
mod public_routes;
mod puppeteer;
mod recipe;
mod rendered;
mod request;
mod transport;

pub use cli::{Cli, run as run_cli};
pub use content_safety::{
    BEGIN_UNTRUSTED_WEB_CONTENT, Boundary, END_UNTRUSTED_WEB_CONTENT, boundary_for,
    wrap_untrusted_content,
};
pub use domain::{
    Artifact, Attempt, BrowserCapability, BudgetConfig, BudgetUsage, ContentSafetyReport,
    ContentStatus, DeviceClass, EvidenceCheck, EvidenceSpec, EvidenceStatus, Failure, FailureCode,
    FetchRequest, FetchResult, NetworkPolicy, OverallStatus, PRODUCT_VERSION, RetrievalMode,
    SCHEMA_VERSION, TransportStatus,
};
pub use engine::Engine;
pub use rendered::RuntimeConfig;
pub use request::{AdaptivePolicy, ExecutionPolicy};
