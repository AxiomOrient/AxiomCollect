use std::collections::HashSet;

use url::Url;

use crate::policy::has_sensitive_query_key;

/// A public, no-auth alternative to the URL the caller supplied.
///
/// Routes are deliberately descriptive rather than opaque. The route kind is
/// copied into the attempt provenance so a caller can tell whether content came
/// from the origin, a platform API/feed, or an external public reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteCandidate {
    pub url: Url,
    pub kind: &'static str,
}

pub(crate) fn candidates(original: &Url, enable_jina_reader: bool) -> Vec<RouteCandidate> {
    let mut routes = Vec::new();
    let mut seen = HashSet::new();

    if let Some(url) = reddit_rss(original) {
        push(&mut routes, &mut seen, original, url, "reddit_rss");
    }
    if let Some(url) = hacker_news_api(original) {
        push(&mut routes, &mut seen, original, url, "hacker_news_api");
    }
    if let Some(url) = github_api(original) {
        push(&mut routes, &mut seen, original, url, "github_api");
    }
    if let Some(url) = arxiv_api(original) {
        push(&mut routes, &mut seen, original, url, "arxiv_api");
    }
    if let Some(url) = stack_exchange_api(original) {
        push(&mut routes, &mut seen, original, url, "stack_exchange_api");
    }
    if let Some(url) = twitter_syndication(original) {
        push(&mut routes, &mut seen, original, url, "twitter_syndication");
    }
    if let Some(url) = twitter_timeline(original) {
        push(&mut routes, &mut seen, original, url, "twitter_timeline");
    }
    if let Some(url) = twitter_oembed(original) {
        push(&mut routes, &mut seen, original, url, "twitter_oembed");
    }
    if let Some(url) = hacker_news_search(original) {
        push(&mut routes, &mut seen, original, url, "hacker_news_search");
    }
    if let Some(url) = bluesky_api(original) {
        push(&mut routes, &mut seen, original, url, "bluesky_api");
    }
    if let Some(url) = mastodon_api(original) {
        push(&mut routes, &mut seen, original, url, "mastodon_api");
    }
    if let Some(url) = dev_to_api(original) {
        push(&mut routes, &mut seen, original, url, "dev_to_api");
    }
    if let Some(url) = lobsters_api(original) {
        push(&mut routes, &mut seen, original, url, "lobsters_api");
    }
    if let Some(url) = v2ex_api(original) {
        push(&mut routes, &mut seen, original, url, "v2ex_api");
    }
    if let Some(url) = crossref_api(original) {
        push(&mut routes, &mut seen, original, url, "crossref_api");
    }
    if let Some(url) = wikipedia_api(original) {
        push(&mut routes, &mut seen, original, url, "wikipedia_api");
    }
    if let Some(url) = openlibrary_api(original) {
        push(&mut routes, &mut seen, original, url, "openlibrary_api");
    }
    if let Some(url) = npm_api(original) {
        push(&mut routes, &mut seen, original, url, "npm_api");
    }
    if let Some(url) = pypi_api(original) {
        push(&mut routes, &mut seen, original, url, "pypi_api");
    }
    if let Some(url) = naver_blog_mobile(original) {
        push(&mut routes, &mut seen, original, url, "naver_blog_mobile");
    }
    if let Some(url) = naver_news_mobile(original) {
        push(&mut routes, &mut seen, original, url, "naver_news_mobile");
    }
    if let Some(url) = naver_finance_api(original) {
        push(&mut routes, &mut seen, original, url, "naver_finance_api");
    }
    if let Some(url) = mobile_variant(original) {
        push(&mut routes, &mut seen, original, url, "mobile_variant");
    }
    if let Some(url) = drop_www(original) {
        push(&mut routes, &mut seen, original, url, "drop_www");
    }
    if let Some(url) = wayback_cdx(original) {
        push(&mut routes, &mut seen, original, url, "wayback_cdx");
    }
    if enable_jina_reader
        && !has_sensitive_query_key(original)
        && let Some(url) = jina_reader(original)
    {
        push(&mut routes, &mut seen, original, url, "jina_reader");
    }

    routes
}

/// Routes backed by an official, public platform endpoint. The adaptive
/// external baseline tries these Phase 0 routes before generic origin HTTP;
/// archive, reader, and domain-agnostic variants remain later fallbacks.
pub(crate) fn is_phase0_kind(kind: &str) -> bool {
    !matches!(
        kind,
        "mobile_variant" | "drop_www" | "wayback_cdx" | "jina_reader"
    )
}

fn push(
    routes: &mut Vec<RouteCandidate>,
    seen: &mut HashSet<String>,
    original: &Url,
    url: Url,
    kind: &'static str,
) {
    if url == *original || !matches!(url.scheme(), "http" | "https") {
        return;
    }
    if seen.insert(url.as_str().to_owned()) {
        routes.push(RouteCandidate { url, kind });
    }
}

fn reddit_rss(url: &Url) -> Option<Url> {
    if !host_is(url, &["reddit.com"]) || url.path() == "/" {
        return None;
    }
    let mut candidate = url.clone();
    let path = candidate.path();
    let next = if let Some(prefix) = path.strip_suffix(".json") {
        format!("{prefix}.rss")
    } else if path.ends_with(".rss") {
        return None;
    } else {
        format!("{}.rss", path.trim_end_matches('/'))
    };
    candidate.set_path(&next);
    candidate.set_fragment(None);
    Some(candidate)
}

fn hacker_news_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["news.ycombinator.com"]) {
        return None;
    }
    let path = url.path().trim_end_matches('/');
    let query_id = url
        .query_pairs()
        .find(|(key, _)| key == "id")
        .map(|(_, value)| value.into_owned());
    if path == "/item" {
        let id = query_id.filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))?;
        return Url::parse(&format!(
            "https://hacker-news.firebaseio.com/v0/item/{id}.json"
        ))
        .ok();
    }
    None
}

fn hacker_news_search(url: &Url) -> Option<Url> {
    if !host_is(url, &["news.ycombinator.com"]) {
        return None;
    }
    let path = url.path().trim_end_matches('/');
    if path != "/search" {
        return None;
    }
    let query = url
        .query_pairs()
        .find(|(key, _)| key == "q")
        .map(|(_, value)| value.into_owned())?;
    if query.is_empty() {
        return None;
    }
    let mut api = Url::parse("https://hn.algolia.com/api/v1/search").ok()?;
    api.query_pairs_mut().append_pair("query", &query);
    Some(api)
}

fn github_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["github.com"]) {
        return None;
    }
    let segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.len() < 2 || !segments[..2].iter().all(|segment| safe_segment(segment)) {
        return None;
    }
    let owner = segments[0];
    let repository = segments[1].trim_end_matches(".git");
    if !safe_segment(repository) || matches!(owner, "features" | "topics" | "marketplace") {
        return None;
    }

    let mut path = format!("/repos/{owner}/{repository}");
    if segments.len() >= 4
        && matches!(segments[2], "issues" | "pull" | "discussions")
        && segments[3].bytes().all(|byte| byte.is_ascii_digit())
    {
        path.push_str(&format!("/{}/{}", segments[2], segments[3]));
    } else if segments.len() > 2 {
        return None;
    }
    let mut api = Url::parse("https://api.github.com").ok()?;
    api.set_path(&path);
    Some(api)
}

fn arxiv_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["arxiv.org"]) {
        return None;
    }
    let mut segments = url.path_segments()?;
    let kind = segments.next()?;
    let identifier = segments.next()?;
    if !matches!(kind, "abs" | "pdf") || segments.next().is_some() || !safe_segment(identifier) {
        return None;
    }
    let mut api = Url::parse("https://export.arxiv.org/api/query").ok()?;
    api.query_pairs_mut().append_pair("id_list", identifier);
    Some(api)
}

fn stack_exchange_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["stackoverflow.com"]) {
        return None;
    }
    let mut segments = url.path_segments()?;
    if segments.next()? != "questions" {
        return None;
    }
    let question_id = segments.next()?;
    if !safe_numeric(question_id) {
        return None;
    }
    let mut api = Url::parse(&format!(
        "https://api.stackexchange.com/2.3/questions/{question_id}"
    ))
    .ok()?;
    api.query_pairs_mut()
        .append_pair("site", "stackoverflow")
        .append_pair("filter", "withbody");
    Some(api)
}

fn twitter_oembed(url: &Url) -> Option<Url> {
    if !host_is(url, &["x.com", "twitter.com"]) {
        return None;
    }
    let mut endpoint = Url::parse("https://publish.twitter.com/oembed").ok()?;
    endpoint
        .query_pairs_mut()
        .append_pair("url", url.as_str())
        .append_pair("omit_script", "1");
    Some(endpoint)
}

fn twitter_syndication(url: &Url) -> Option<Url> {
    if !host_is(url, &["x.com", "twitter.com"]) {
        return None;
    }
    let segments = url.path_segments()?.collect::<Vec<_>>();
    let status_index = segments.iter().position(|segment| *segment == "status")?;
    let status_id = segments.get(status_index + 1)?;
    if !safe_numeric(status_id) {
        return None;
    }
    let mut endpoint = Url::parse("https://cdn.syndication.twimg.com/tweet-result").ok()?;
    endpoint
        .query_pairs_mut()
        .append_pair("id", status_id)
        .append_pair("lang", "en");
    Some(endpoint)
}

fn twitter_timeline(url: &Url) -> Option<Url> {
    if !host_is(url, &["x.com", "twitter.com"]) {
        return None;
    }
    let segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.len() != 1 || !safe_segment(segments[0]) {
        return None;
    }
    let handle = segments[0];
    let reserved = [
        "i",
        "search",
        "home",
        "explore",
        "messages",
        "notifications",
        "settings",
        "hashtag",
        "tos",
        "privacy",
    ];
    if reserved.iter().any(|r| r.eq_ignore_ascii_case(handle)) {
        return None;
    }
    Url::parse(&format!(
        "https://syndication.twitter.com/srv/timeline-profile/screen-name/{handle}"
    ))
    .ok()
}

fn bluesky_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["bsky.app"]) {
        return None;
    }
    let segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.len() != 4
        || segments[0] != "profile"
        || segments[2] != "post"
        || !safe_segment(segments[1])
        || !safe_segment(segments[3])
    {
        return None;
    }
    let uri = format!("at://{}/app.bsky.feed.post/{}", segments[1], segments[3]);
    let mut api = Url::parse("https://public.api.bsky.app/xrpc/app.bsky.feed.getPosts").ok()?;
    api.query_pairs_mut().append_pair("uris", &uri);
    Some(api)
}

fn mastodon_api(url: &Url) -> Option<Url> {
    let mut segments = url.path_segments()?;
    let actor = segments.next()?;
    let status_id = segments.next()?;
    if !actor.starts_with('@')
        || !safe_segment(actor.trim_start_matches('@'))
        || !safe_numeric(status_id)
        || segments.next().is_some()
    {
        return None;
    }
    let mut api = url.clone();
    api.set_path(&format!("/api/v1/statuses/{status_id}"));
    api.set_query(None);
    api.set_fragment(None);
    Some(api)
}

fn dev_to_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["dev.to"]) {
        return None;
    }
    let segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.len() != 2 || !segments.iter().all(|segment| safe_segment(segment)) {
        return None;
    }
    let mut api = Url::parse("https://dev.to/api/articles").ok()?;
    api.path_segments_mut().ok()?.push(segments[0]);
    api.path_segments_mut().ok()?.push(segments[1]);
    Some(api)
}

fn lobsters_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["lobste.rs"]) {
        return None;
    }
    let segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.len() < 2 || segments[0] != "s" || !safe_segment(segments[1]) {
        return None;
    }
    let mut api = Url::parse("https://lobste.rs").ok()?;
    api.set_path(&format!("/s/{}.json", segments[1]));
    Some(api)
}

fn v2ex_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["v2ex.com"]) {
        return None;
    }
    let mut segments = url.path_segments()?;
    if segments.next()? != "t" {
        return None;
    }
    let topic_id = segments.next()?;
    if !safe_numeric(topic_id) || segments.next().is_some() {
        return None;
    }
    let mut api = Url::parse("https://www.v2ex.com/api/topics/show.json").ok()?;
    api.query_pairs_mut().append_pair("id", topic_id);
    Some(api)
}

fn crossref_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["doi.org", "dx.doi.org"]) {
        return None;
    }
    let doi = url.path().trim_matches('/');
    if !doi.starts_with("10.") || !safe_doi(doi) {
        return None;
    }
    let mut api = Url::parse("https://api.crossref.org").ok()?;
    api.set_path(&format!("/works/{doi}"));
    Some(api)
}

fn wikipedia_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["wikipedia.org"]) {
        return None;
    }
    let title = url.path().strip_prefix("/wiki/")?;
    if title.is_empty() || title.starts_with("Special:") || !safe_wiki_title(title) {
        return None;
    }
    let host = url.host_str()?;
    let mut api = Url::parse(&format!("https://{host}/api/rest_v1/page/summary")).ok()?;
    api.set_path(&format!("/api/rest_v1/page/summary/{title}"));
    Some(api)
}

fn openlibrary_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["openlibrary.org"]) {
        return None;
    }
    let segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.len() != 2
        || !matches!(segments[0], "books" | "works" | "authors")
        || !safe_segment(segments[1])
    {
        return None;
    }
    let mut api = url.clone();
    api.set_path(&format!("/{}/{}.json", segments[0], segments[1]));
    api.set_query(None);
    api.set_fragment(None);
    Some(api)
}

fn npm_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["npmjs.com"]) {
        return None;
    }
    let segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.len() != 2 || segments[0] != "package" || !safe_package(segments[1]) {
        return None;
    }
    let mut api = Url::parse("https://registry.npmjs.org").ok()?;
    api.set_path(&format!("/{}", segments[1]));
    Some(api)
}

fn pypi_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["pypi.org"]) {
        return None;
    }
    let segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.len() != 2 || segments[0] != "project" || !safe_segment(segments[1]) {
        return None;
    }
    let mut api = Url::parse("https://pypi.org").ok()?;
    api.set_path(&format!("/pypi/{}/json", segments[1]));
    Some(api)
}

fn naver_blog_mobile(url: &Url) -> Option<Url> {
    if !host_is(url, &["blog.naver.com"]) || url.host_str()? == "m.blog.naver.com" {
        return None;
    }
    let path = url.path().trim_end_matches('/');
    let mut mobile = url.clone();
    mobile.set_host(Some("m.blog.naver.com")).ok()?;
    mobile.set_fragment(None);
    if path.eq_ignore_ascii_case("/PostView.naver") {
        let blog_id = url
            .query_pairs()
            .find(|(key, _)| key == "blogId")
            .map(|(_, value)| value.into_owned())?;
        let log_no = url
            .query_pairs()
            .find(|(key, _)| key == "logNo")
            .map(|(_, value)| value.into_owned())?;
        if !safe_segment(&blog_id) || !safe_numeric(&log_no) {
            return None;
        }
        mobile.set_path("/PostView.naver");
        mobile.set_query(None);
        mobile
            .query_pairs_mut()
            .append_pair("blogId", &blog_id)
            .append_pair("logNo", &log_no);
        return Some(mobile);
    }
    let segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.len() != 2 || !safe_segment(segments[0]) || !safe_numeric(segments[1]) {
        return None;
    }
    mobile.set_path(path);
    mobile.set_query(None);
    Some(mobile)
}

fn naver_news_mobile(url: &Url) -> Option<Url> {
    let host = url.host_str()?;
    let mut article = None;
    if host == "news.naver.com" && url.path().eq_ignore_ascii_case("/main/read.naver") {
        let oid = url
            .query_pairs()
            .find(|(key, _)| key == "oid")
            .map(|(_, value)| value.into_owned())?;
        let aid = url
            .query_pairs()
            .find(|(key, _)| key == "aid")
            .map(|(_, value)| value.into_owned())?;
        if safe_numeric(&oid) && safe_numeric(&aid) {
            article = Some((oid, aid));
        }
    } else if host == "n.news.naver.com" {
        let segments = url.path_segments()?.collect::<Vec<_>>();
        if segments.len() == 3
            && segments[0] == "article"
            && safe_numeric(segments[1])
            && safe_numeric(segments[2])
        {
            article = Some((segments[1].to_owned(), segments[2].to_owned()));
        }
    }
    let (oid, aid) = article?;
    Url::parse(&format!(
        "https://n.news.naver.com/mnews/article/{oid}/{aid}"
    ))
    .ok()
}

fn naver_finance_api(url: &Url) -> Option<Url> {
    if !host_is(url, &["finance.naver.com"]) {
        return None;
    }
    let code = url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())?;
    if !safe_numeric(&code) {
        return None;
    }
    let mut api = Url::parse("https://api.finance.naver.com/siseJson.naver").ok()?;
    api.query_pairs_mut()
        .append_pair("symbol", &code)
        .append_pair("requestType", "1");
    Some(api)
}

fn wayback_cdx(url: &Url) -> Option<Url> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || host_is(url, &["web.archive.org"])
    {
        return None;
    }
    let mut target = url.clone();
    target.set_fragment(None);
    let mut cdx = Url::parse("https://web.archive.org/cdx/search/cdx").ok()?;
    cdx.query_pairs_mut()
        .append_pair("url", target.as_str())
        .append_pair("output", "json")
        .append_pair("fl", "timestamp,statuscode,mimetype")
        .append_pair("filter", "statuscode:200")
        .append_pair("limit", "5")
        .append_pair("collapse", "digest");
    Some(cdx)
}

fn mobile_variant(url: &Url) -> Option<Url> {
    let host = url.host_str()?;
    let suffix = host.strip_prefix("www.")?;
    if suffix.is_empty() || suffix.starts_with("m.") {
        return None;
    }
    let mut candidate = url.clone();
    candidate.set_host(Some(&format!("m.{suffix}"))).ok()?;
    candidate.set_fragment(None);
    Some(candidate)
}

/// A domain-agnostic fallback used by sites that serve different public
/// content on the apex host and on `www`. It is intentionally just another
/// bounded public route; the normal policy and transport validate it again.
fn drop_www(url: &Url) -> Option<Url> {
    let host = url.host_str()?;
    let apex = host.strip_prefix("www.")?;
    if apex.is_empty() {
        return None;
    }
    let mut candidate = url.clone();
    candidate.set_host(Some(apex)).ok()?;
    candidate.set_fragment(None);
    Some(candidate)
}

fn jina_reader(url: &Url) -> Option<Url> {
    let mut target = url.clone();
    target.set_fragment(None);
    Url::parse(&format!("https://r.jina.ai/{}", target.as_str())).ok()
}

fn host_is(url: &Url, suffixes: &[&str]) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    suffixes
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn safe_numeric(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn safe_doi(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_' | b'(' | b')')
    })
}

fn safe_wiki_title(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'/' | b'.' | b'-' | b'_' | b':' | b'(' | b')' | b'%')
    })
}

fn safe_package(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'@'))
}

#[cfg(test)]
mod tests {
    use super::candidates;
    use url::Url;

    fn urls(input: &str) -> Vec<String> {
        let Ok(url) = Url::parse(input) else {
            return Vec::new();
        };
        candidates(&url, true)
            .into_iter()
            .map(|candidate| format!("{}={}", candidate.kind, candidate.url))
            .collect()
    }

    #[test]
    fn reddit_prefers_public_feed_before_reader() {
        let routes = urls("https://www.reddit.com/r/rust.json");
        assert!(
            routes
                .iter()
                .any(|route| route == "reddit_rss=https://www.reddit.com/r/rust.rss")
        );
        assert!(
            routes
                .iter()
                .any(|route| route.starts_with("jina_reader=https://r.jina.ai/"))
        );
    }

    #[test]
    fn platform_routes_are_specific_and_public() {
        let hn = urls("https://news.ycombinator.com/item?id=123");
        assert!(
            hn.iter().any(|route| route
                == "hacker_news_api=https://hacker-news.firebaseio.com/v0/item/123.json")
        );

        let github = urls("https://github.com/openai/codex/issues/42");
        assert!(
            github
                .iter()
                .any(|route| route
                    == "github_api=https://api.github.com/repos/openai/codex/issues/42")
        );
    }

    #[test]
    fn external_reader_is_not_used_for_sensitive_query_values() {
        let routes = urls("https://example.com/article?access_token=redacted");
        assert!(!routes.iter().any(|route| route.starts_with("jina_reader=")));
    }

    #[test]
    fn external_reader_can_be_disabled_without_disabling_other_public_routes() {
        let Ok(url) = Url::parse("https://www.reddit.com/r/rust.json") else {
            return;
        };
        let routes = candidates(&url, false);
        assert!(routes.iter().any(|route| route.kind == "reddit_rss"));
        assert!(!routes.iter().any(|route| route.kind == "jina_reader"));
    }

    #[test]
    fn social_metadata_routes_encode_the_source_url() {
        let x = urls("https://x.com/example/status/1");
        let syndication = x.iter().position(|route| {
            route.starts_with("twitter_syndication=https://cdn.syndication.twimg.com/tweet-result?")
        });
        let oembed = x
            .iter()
            .position(|route| route.starts_with("twitter_oembed="));
        assert!(syndication.is_some_and(|index| oembed.is_some_and(|other| index < other)));
        assert!(x.iter().any(|route| {
            route.starts_with("twitter_oembed=https://publish.twitter.com/oembed?url=")
        }));
    }

    #[test]
    fn public_platform_routes_are_exact_and_no_auth() {
        let bluesky = urls("https://bsky.app/profile/alice.example/post/3kxyz");
        assert!(bluesky.iter().any(|route| {
            route.starts_with(
                "bluesky_api=https://public.api.bsky.app/xrpc/app.bsky.feed.getPosts?uris=",
            )
        }));

        let mastodon = urls("https://mastodon.social/@alice/123456");
        assert!(mastodon.iter().any(|route| {
            route == "mastodon_api=https://mastodon.social/api/v1/statuses/123456"
        }));

        let dev_to = urls("https://dev.to/alice/an-article");
        assert!(
            dev_to
                .iter()
                .any(|route| route == "dev_to_api=https://dev.to/api/articles/alice/an-article")
        );

        let v2ex = urls("https://www.v2ex.com/t/123");
        assert!(
            v2ex.iter()
                .any(|route| route == "v2ex_api=https://www.v2ex.com/api/topics/show.json?id=123")
        );
    }

    #[test]
    fn registry_and_metadata_routes_are_deterministic() {
        let crossref = urls("https://doi.org/10.1000/xyz123");
        assert!(
            crossref
                .iter()
                .any(|route| route == "crossref_api=https://api.crossref.org/works/10.1000/xyz123")
        );

        let wikipedia = urls("https://en.wikipedia.org/wiki/Rust_(programming_language)");
        assert!(wikipedia.iter().any(|route| {
            route == "wikipedia_api=https://en.wikipedia.org/api/rest_v1/page/summary/Rust_(programming_language)"
        }));

        let openlibrary = urls("https://openlibrary.org/books/OL1M");
        assert!(
            openlibrary
                .iter()
                .any(|route| route == "openlibrary_api=https://openlibrary.org/books/OL1M.json")
        );

        let npm = urls("https://www.npmjs.com/package/serde");
        assert!(
            npm.iter()
                .any(|route| route == "npm_api=https://registry.npmjs.org/serde")
        );

        let pypi = urls("https://pypi.org/project/requests");
        assert!(
            pypi.iter()
                .any(|route| route == "pypi_api=https://pypi.org/pypi/requests/json")
        );

        let archive = urls("https://example.com/article");
        assert!(archive.iter().any(|route| {
            route.starts_with("wayback_cdx=https://web.archive.org/cdx/search/cdx?url=")
        }));
    }

    #[test]
    fn naver_routes_preserve_the_exact_public_article_identity() {
        let blog = urls("https://blog.naver.com/example/123456");
        assert!(
            blog.iter().any(|route| {
                route == "naver_blog_mobile=https://m.blog.naver.com/example/123456"
            })
        );

        let post_view = urls("https://blog.naver.com/PostView.naver?blogId=example&logNo=123456");
        assert!(post_view.iter().any(|route| {
            route == "naver_blog_mobile=https://m.blog.naver.com/PostView.naver?blogId=example&logNo=123456"
        }));

        let news = urls("https://news.naver.com/main/read.naver?oid=001&aid=1234567");
        assert!(news.iter().any(|route| {
            route == "naver_news_mobile=https://n.news.naver.com/mnews/article/001/1234567"
        }));
    }

    #[test]
    fn drop_www_is_a_bounded_domain_agnostic_route() {
        let routes = urls("https://www.example.com/article#section");
        assert!(
            routes
                .iter()
                .any(|route| { route == "drop_www=https://example.com/article" })
        );
    }

    #[test]
    fn integrated_public_routes_produce_expected_urls() {
        let twitter = urls("https://x.com/rustlang");
        assert!(twitter.iter().any(|route| {
            route == "twitter_timeline=https://syndication.twitter.com/srv/timeline-profile/screen-name/rustlang"
        }));

        let hn = urls("https://news.ycombinator.com/search?q=rust");
        assert!(hn.iter().any(|route| {
            route == "hacker_news_search=https://hn.algolia.com/api/v1/search?query=rust"
        }));

        let finance = urls("https://finance.naver.com/item/main.naver?code=005930");
        assert!(finance.iter().any(|route| {
            route == "naver_finance_api=https://api.finance.naver.com/siseJson.naver?symbol=005930&requestType=1"
        }));
    }
}
