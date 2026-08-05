use axiom_collect::Cli;
use clap::Parser;

#[tokio::main]
async fn main() {
    let code = axiom_collect::run_cli(Cli::parse()).await;
    std::process::exit(i32::from(code));
}
