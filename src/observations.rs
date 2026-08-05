use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

#[derive(Debug)]
pub(crate) struct ObservationInput<'a> {
    pub(crate) host: &'a str,
    pub(crate) device: &'a str,
    pub(crate) profile_id: &'a str,
    pub(crate) transform: &'a str,
    pub(crate) identity: &'a str,
    pub(crate) referer: &'a str,
    pub(crate) attempts: usize,
    pub(crate) configured_dir: Option<&'a Path>,
}

#[derive(Debug, Serialize)]
struct Observation<'a> {
    host: &'a str,
    device: &'a str,
    profile_id: &'a str,
    transform: &'a str,
    identity: &'a str,
    referer: &'a str,
    attempts: usize,
    recorded_at: u64,
}

pub(crate) fn append(input: ObservationInput<'_>) {
    let Some(directory) = resolve_dir(input.configured_dir) else {
        return;
    };
    if std::fs::create_dir_all(&directory).is_err() {
        return;
    }
    let day = now_seconds() / (24 * 60 * 60);
    let path = directory.join(format!("{day}.jsonl"));
    let observation = Observation {
        host: input.host,
        device: input.device,
        profile_id: input.profile_id,
        transform: input.transform,
        identity: input.identity,
        referer: input.referer,
        attempts: input.attempts,
        recorded_at: now_seconds(),
    };
    let Ok(mut line) = serde_json::to_string(&observation) else {
        return;
    };
    line.push('\n');
    use std::io::Write;
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let _ = file.write_all(line.as_bytes());
}

fn resolve_dir(configured_dir: Option<&Path>) -> Option<PathBuf> {
    configured_dir
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("AXIOM_COLLECT_OBSERVATIONS_DIR").map(PathBuf::from))
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
