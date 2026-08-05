use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Deserialize;
use url::Url;

use crate::policy::{has_sensitive_query_key, parse_url};
use crate::transport::HttpRouteProfile;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecipeCandidate {
    pub url: Url,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RecipeFile {
    domain: String,
    #[serde(default)]
    url_rewrites: Vec<UrlRewrite>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct UrlRewrite {
    name: String,
    pattern: String,
    replacement: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

pub(crate) fn candidates(original: &Url, configured_dir: Option<&Path>) -> Vec<RecipeCandidate> {
    let Some(recipe) = load_recipe(original, configured_dir) else {
        return Vec::new();
    };
    if !recipe
        .domain
        .eq_ignore_ascii_case(original.host_str().unwrap_or_default())
    {
        return Vec::new();
    }
    let mut seen = std::collections::HashSet::new();
    recipe
        .url_rewrites
        .into_iter()
        .filter_map(|rewrite| {
            let regex = Regex::new(&rewrite.pattern).ok()?;
            if !regex.is_match(original.as_str()) {
                return None;
            }
            let replacement = rust_replacement(&rewrite.replacement);
            let rewritten = regex
                .replace(original.as_str(), replacement.as_str())
                .into_owned();
            let url = original
                .join(&rewritten)
                .ok()
                .and_then(|url| parse_url(url.as_str()).ok())?;
            if url.host_str() != original.host_str() || has_sensitive_query_key(&url) {
                return None;
            }
            seen.insert(url.to_string()).then_some(RecipeCandidate {
                url,
                name: rewrite.name,
            })
        })
        .collect()
}

pub(crate) fn profile_for(
    original: &Url,
    target: &Url,
    configured_dir: Option<&Path>,
) -> Option<HttpRouteProfile> {
    let recipe = load_recipe(original, configured_dir)?;
    for rewrite in recipe.url_rewrites {
        let regex = Regex::new(&rewrite.pattern).ok()?;
        if !regex.is_match(original.as_str()) {
            continue;
        }
        let replacement = rust_replacement(&rewrite.replacement);
        let rewritten = regex
            .replace(original.as_str(), replacement.as_str())
            .into_owned();
        let candidate = original.join(&rewritten).ok()?.to_string();
        if candidate == target.to_string() {
            return Some(HttpRouteProfile {
                user_agent: None,
                referer: rewrite
                    .headers
                    .get("Referer")
                    .or_else(|| rewrite.headers.get("referer"))
                    .cloned(),
                extra_headers: safe_headers(&rewrite.headers),
                accept_http_errors: false,
            });
        }
    }
    None
}

fn load_recipe(original: &Url, configured_dir: Option<&Path>) -> Option<RecipeFile> {
    let host = original.host_str()?;
    let root = configured_dir
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("AXIOM_COLLECT_RECIPES_DIR").map(PathBuf::from))
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("skills")
                .join("axiom-collect")
                .join("recipes")
        });
    let path = if root
        .extension()
        .is_some_and(|extension| extension == "yaml")
    {
        root
    } else {
        root.join(host).join("recipe.yaml")
    };
    let source = std::fs::read_to_string(path).ok()?;
    serde_yaml::from_str(&source).ok()
}

fn rust_replacement(replacement: &str) -> String {
    let mut value = replacement.to_owned();
    for index in (1..10).rev() {
        value = value.replace(&format!(r"\{index}"), &format!("${index}"));
    }
    value
}

fn safe_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter(|(name, value)| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "accept" | "referer" | "x-requested-with" | "content-type" | "user-agent"
            ) && !value.contains('\r')
                && !value.contains('\n')
        })
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{candidates, profile_for};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn recipe_rewrites_are_validated_and_headers_are_allowlisted() {
        let Some(dir) = tempdir().ok() else {
            return;
        };
        let host_dir = dir.path().join("example.com");
        if fs::create_dir_all(&host_dir).is_err() {
            return;
        }
        let source = r#"
domain: example.com
url_rewrites:
  - name: feed
    pattern: '^https://example\.com/article/(\d+)$'
    replacement: '/api/post/\1'
    headers:
      Accept: application/json
      X-Requested-With: XMLHttpRequest
      Cookie: must-not-pass
"#;
        if fs::write(host_dir.join("recipe.yaml"), source).is_err() {
            return;
        }
        let Some(url) = url::Url::parse("https://example.com/article/42").ok() else {
            return;
        };
        let routes = candidates(&url, Some(dir.path()));
        assert_eq!(
            routes.first().map(|route| route.url.as_str()),
            Some("https://example.com/api/post/42")
        );
        let Some(first) = routes.first() else {
            return;
        };
        let Some(profile) = profile_for(&url, &first.url, Some(dir.path())) else {
            return;
        };
        assert!(profile.extra_headers.contains_key("Accept"));
        assert!(!profile.extra_headers.contains_key("Cookie"));
    }
}
