use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
const MAX_ENTRIES: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LearnedRoute {
    profile_id: String,
    transform: String,
    identity: String,
    referer: String,
    wins: u32,
    consecutive_failures: u32,
    updated_at: u64,
}

pub(crate) fn preferred_route(
    host: &str,
    device: &str,
    configured_path: Option<&Path>,
) -> Option<(String, String, String)> {
    let path = resolve_path(configured_path)?;
    let entries = read_entries(&path)?;
    let key = route_key(host, device);
    let now = now_seconds();
    entries.get(&key).and_then(|entry| {
        (now.saturating_sub(entry.updated_at) <= TTL_SECONDS && entry.consecutive_failures < 2)
            .then(|| {
                (
                    entry.transform.clone(),
                    entry.identity.clone(),
                    entry.referer.clone(),
                )
            })
    })
}

pub(crate) fn record_success(
    host: &str,
    device: &str,
    profile_id: &str,
    transform: &str,
    identity: &str,
    referer: &str,
    configured_path: Option<&Path>,
) {
    let Some(path) = resolve_path(configured_path) else {
        return;
    };
    let mut entries = read_entries(&path).unwrap_or_default();
    let key = route_key(host, device);
    let entry = entries.entry(key).or_insert_with(|| LearnedRoute {
        profile_id: profile_id.to_owned(),
        transform: transform.to_owned(),
        identity: identity.to_owned(),
        referer: referer.to_owned(),
        wins: 0,
        consecutive_failures: 0,
        updated_at: 0,
    });
    entry.profile_id = profile_id.to_owned();
    entry.transform = transform.to_owned();
    entry.identity = identity.to_owned();
    entry.referer = referer.to_owned();
    entry.wins = entry.wins.saturating_add(1);
    entry.consecutive_failures = 0;
    entry.updated_at = now_seconds();
    trim_entries(&mut entries);
    let _ = write_entries(&path, &entries);
}

pub(crate) fn record_failure(host: &str, device: &str, configured_path: Option<&Path>) {
    let Some(path) = resolve_path(configured_path) else {
        return;
    };
    let mut entries = read_entries(&path).unwrap_or_default();
    let key = route_key(host, device);
    let should_remove = entries.get_mut(&key).is_some_and(|entry| {
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.consecutive_failures >= 2
    });
    if should_remove {
        entries.remove(&key);
    }
    let _ = write_entries(&path, &entries);
}

fn resolve_path(configured_path: Option<&Path>) -> Option<PathBuf> {
    configured_path
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("AXIOM_COLLECT_LEARNING_PATH").map(PathBuf::from))
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".axiom_collect/learned.json"))
        })
}

fn read_entries(path: &Path) -> Option<BTreeMap<String, LearnedRoute>> {
    let source = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&source).ok()
}

fn write_entries(path: &Path, entries: &BTreeMap<String, LearnedRoute>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(entries).map_err(std::io::Error::other)?;
    std::fs::write(path, bytes)
}

fn trim_entries(entries: &mut BTreeMap<String, LearnedRoute>) {
    while entries.len() > MAX_ENTRIES {
        let Some(oldest) = entries
            .iter()
            .min_by_key(|(_, entry)| entry.updated_at)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        entries.remove(&oldest);
    }
}

fn route_key(host: &str, device: &str) -> String {
    format!("{}::{}", host.to_ascii_lowercase(), device)
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::{preferred_route, record_failure, record_success};
    use tempfile::tempdir;

    #[test]
    fn learning_promotes_wins_and_evicts_after_two_failures() {
        let Some(dir) = tempdir().ok() else {
            return;
        };
        let path = dir.path().join("learned.json");
        record_success(
            "example.com",
            "desktop",
            "cloudflare",
            "drop_www",
            "chrome",
            "self_root",
            Some(&path),
        );
        assert_eq!(
            preferred_route("example.com", "desktop", Some(&path)),
            Some((
                "drop_www".to_owned(),
                "chrome".to_owned(),
                "self_root".to_owned()
            ))
        );
        record_failure("example.com", "desktop", Some(&path));
        record_failure("example.com", "desktop", Some(&path));
        assert_eq!(preferred_route("example.com", "desktop", Some(&path)), None);
    }
}
