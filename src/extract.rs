use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::LazyLock;

use ego_tree::iter::Edge;
use encoding_rs::{Encoding, UTF_8};
use scraper::{ElementRef, Html, Node, Selector};
use serde_json::Value;
use url::Url;

use crate::domain::{ExtractedContent, Failure, FailureCode};
use crate::evidence::CompiledEvidence;

const MAX_LINKS: usize = 1_000;
const MAX_JSON_LD: usize = 100;
const JSON_LD_RESCUE_MIN_CHARS: usize = 100;
const JSON_LD_RESCUE_MAX_CHARS: usize = 1_000_000;
/// A document under this many bytes of visible text that also ships several scripts
/// is treated as an unrendered JavaScript shell. This is the switch that makes
/// `auto` escalate from HTTP to the rendered chain, so both bounds are named: the
/// byte floor is below any real article's opening paragraph, and requiring more
/// than one script keeps a single analytics tag on a short page from tripping it.
const DYNAMIC_SHELL_MAX_TEXT_BYTES: usize = 160;
const DYNAMIC_SHELL_MIN_SCRIPTS: usize = 2;

/// The fixed selectors the HTML path applies to every document.
///
/// These are literals, so parsing them per document was pure repeated work. They
/// are compiled once here; the compile stays fallible rather than assumed, so a
/// broken built-in selector surfaces as a real error instead of silently matching
/// nothing.
struct HtmlSelectors {
    title: Selector,
    description: Selector,
    og_description: Selector,
    /// Content roots in priority order with the extraction quality each implies.
    roots: [(&'static str, f32, Selector); 4],
    json_ld: Selector,
    script: Selector,
    links: Selector,
    main_content: Vec<Selector>,
}

static HTML_SELECTORS: LazyLock<Result<HtmlSelectors, String>> = LazyLock::new(|| {
    let compile =
        |input: &str| Selector::parse(input).map_err(|error| format!("`{input}`: {error}"));
    Ok(HtmlSelectors {
        // Scoped to the head so an inline SVG `<title>` in the body cannot
        // masquerade as the document title.
        title: compile("head > title")?,
        description: compile("meta[name=description]")?,
        og_description: compile("meta[property=\"og:description\"]")?,
        roots: [
            ("article", 0.9, compile("article")?),
            ("main", 0.9, compile("main")?),
            ("[role=\"main\"]", 0.9, compile("[role=\"main\"]")?),
            ("body", 0.65, compile("body")?),
        ],
        json_ld: compile("script[type=\"application/ld+json\"]")?,
        script: compile("script")?,
        links: compile("a[href]")?,
        main_content: [
            "article",
            "main",
            "[role=\"main\"]",
            "[itemprop=\"articleBody\"]",
            ".article-body",
            ".post-content",
            ".entry-content",
            "#content",
        ]
        .into_iter()
        .map(compile)
        .collect::<Result<Vec<_>, _>>()?,
    })
});

fn html_selectors() -> Result<&'static HtmlSelectors, Failure> {
    HTML_SELECTORS.as_ref().map_err(|error| {
        Failure::new(
            FailureCode::InternalError,
            format!("built-in CSS selector is invalid: {error}"),
        )
    })
}

#[derive(Debug, Clone, Copy)]
pub struct ExtractionOptions {
    pub enable_extraction: bool,
    pub enable_markdown: bool,
    pub enable_maincontent: bool,
}

impl Default for ExtractionOptions {
    fn default() -> Self {
        Self {
            enable_extraction: true,
            enable_markdown: false,
            enable_maincontent: false,
        }
    }
}

#[cfg(test)]
fn extract(
    bytes: &[u8],
    content_type: &str,
    final_url: &Url,
    evidence: &CompiledEvidence,
    max_extracted_bytes: usize,
) -> Result<ExtractedContent, Failure> {
    extract_with_options(
        bytes,
        content_type,
        final_url,
        evidence,
        max_extracted_bytes,
        ExtractionOptions::default(),
    )
}

pub fn extract_with_options(
    bytes: &[u8],
    content_type: &str,
    final_url: &Url,
    evidence: &CompiledEvidence,
    max_extracted_bytes: usize,
    options: ExtractionOptions,
) -> Result<ExtractedContent, Failure> {
    if bytes.is_empty() {
        return Err(Failure::new(
            FailureCode::ContentEmpty,
            "response body is empty",
        ));
    }
    if !options.enable_extraction {
        return enforce_extracted_limit(extract_raw(bytes, content_type), max_extracted_bytes);
    }
    let media_type = normalized_media_type(content_type);
    let result = if media_type == "application/pdf" {
        extract_pdf(bytes, max_extracted_bytes)
    } else if is_json_type(&media_type) {
        extract_json(bytes, content_type)
    } else if is_html_type(&media_type) {
        extract_html(bytes, content_type, final_url, evidence, options)
    } else if is_xml_type(&media_type) {
        extract_xml(bytes, content_type)
    } else if media_type.starts_with("text/") {
        extract_plain_text(bytes, content_type)
    } else if media_type.is_empty() || media_type == "application/octet-stream" {
        extract_ambiguous(
            bytes,
            content_type,
            final_url,
            evidence,
            max_extracted_bytes,
            options,
        )
    } else {
        Err(Failure::new(
            FailureCode::ContentUnsupported,
            format!("unsupported content type: {media_type}"),
        ))
    };

    enforce_extracted_limit(result, max_extracted_bytes)
}

fn enforce_extracted_limit(
    result: Result<ExtractedContent, Failure>,
    max_extracted_bytes: usize,
) -> Result<ExtractedContent, Failure> {
    let result = result?;
    if !result.is_usable() {
        return Err(Failure::new(
            FailureCode::ContentEmpty,
            "content extraction produced no usable text",
        ));
    }
    if result.content_bytes() > max_extracted_bytes {
        return Err(Failure::new(
            FailureCode::BudgetExhausted,
            format!(
                "extracted content is {} bytes, exceeding limit {max_extracted_bytes}",
                result.content_bytes()
            ),
        ));
    }
    Ok(result)
}

fn extract_raw(bytes: &[u8], content_type: &str) -> Result<ExtractedContent, Failure> {
    Ok(ExtractedContent {
        content: decode_bytes(bytes, content_type).into_owned(),
        source: "raw".to_owned(),
        quality: 0.25,
        title: None,
        description: None,
        links: Vec::new(),
        json_ld: Vec::new(),
        selector_hits: BTreeMap::new(),
        dynamic_shell: false,
    })
}

fn extract_ambiguous(
    bytes: &[u8],
    content_type: &str,
    final_url: &Url,
    evidence: &CompiledEvidence,
    max_extracted_bytes: usize,
    options: ExtractionOptions,
) -> Result<ExtractedContent, Failure> {
    if bytes.starts_with(b"%PDF-") {
        return extract_pdf(bytes, max_extracted_bytes);
    }
    if looks_like_html(bytes) {
        return extract_html(bytes, content_type, final_url, evidence, options);
    }
    if looks_like_xml(bytes) {
        return extract_xml(bytes, content_type);
    }
    if looks_like_json(bytes) {
        return extract_json(bytes, content_type)
            .or_else(|_| extract_plain_text(bytes, content_type));
    }
    extract_plain_text(bytes, content_type)
}

fn extract_html(
    bytes: &[u8],
    content_type: &str,
    final_url: &Url,
    evidence: &CompiledEvidence,
    options: ExtractionOptions,
) -> Result<ExtractedContent, Failure> {
    let selectors = html_selectors()?;
    let decoded = decode_bytes(bytes, content_type);
    let document = Html::parse_document(&decoded);

    let title = first_text(&document, &selectors.title);
    let description = first_attribute(&document, &selectors.description, "content")
        .or_else(|| first_attribute(&document, &selectors.og_description, "content"));

    let root = selectors
        .roots
        .iter()
        .find_map(|(name, quality, selector)| {
            document
                .select(selector)
                .next()
                .map(|element| (*name, *quality, element))
        });
    let (mut source, mut quality, mut content) = match root {
        Some((name, quality, element)) => (
            format!("html_selector:{name}"),
            quality,
            visible_text(element),
        ),
        None => (
            "html_document".to_owned(),
            0.55,
            visible_text(document.root_element()),
        ),
    };

    if options.enable_maincontent
        && let Some(main_content) = best_main_content(&document, &selectors.main_content)
        && main_content.chars().count() >= 120
        && (source == "html_document" || main_content.chars().count() > content.chars().count())
    {
        content = main_content;
        source = "html_maincontent".to_owned();
        quality = quality.max(0.82);
    }

    let mut json_ld = Vec::new();
    for element in document.select(&selectors.json_ld).take(MAX_JSON_LD) {
        let raw = element.text().collect::<Vec<_>>().join("");
        if let Ok(value) = serde_json::from_str::<Value>(&raw) {
            json_ld.push(value);
        }
    }
    if let Some(rescued) = json_ld_rescue(&json_ld)
        && rescued.chars().count() > JSON_LD_RESCUE_MIN_CHARS
        && rescued.chars().count() > content.chars().count()
    {
        content = rescued;
        source = "html_json_ld".to_owned();
        quality = 0.7;
    } else if content.is_empty() && !json_ld.is_empty() {
        content = serde_json::to_string_pretty(&json_ld).map_err(|error| {
            Failure::new(
                FailureCode::ExtractionFailed,
                format!("JSON-LD serialization failed: {error}"),
            )
        })?;
        source = "html_json_ld".to_owned();
        quality = 0.7;
    }

    if options.enable_markdown
        && matches!(
            source.as_str(),
            "html_selector:article"
                | "html_selector:main"
                | "html_selector:[role=\"main\"]"
                | "html_selector:body"
                | "html_document"
                | "html_maincontent"
        )
    {
        let markdown = html_to_markdown(&decoded);
        if markdown.chars().count() > content.chars().count() / 2 {
            content = markdown;
            source.push_str("+markdown");
            quality = quality.max(0.7);
        }
    }

    let links = extract_links(&document, &selectors.links, final_url);
    let mut selector_hits = BTreeMap::new();
    for (selector_text, selector) in evidence.selectors() {
        selector_hits.insert(selector_text.clone(), document.select(selector).count());
    }

    let script_count = document.select(&selectors.script).count();
    let dynamic_shell =
        content.len() < DYNAMIC_SHELL_MAX_TEXT_BYTES && script_count >= DYNAMIC_SHELL_MIN_SCRIPTS;
    if dynamic_shell {
        quality = quality.min(0.25);
    }

    Ok(ExtractedContent {
        content,
        source,
        quality,
        title,
        description,
        links,
        json_ld,
        selector_hits,
        dynamic_shell,
    })
}

fn best_main_content(document: &Html, selectors: &[Selector]) -> Option<String> {
    selectors
        .iter()
        .flat_map(|selector| document.select(selector))
        .map(visible_text)
        .filter(|value| !value.is_empty())
        .max_by_key(|value| value.chars().count())
}

fn html_to_markdown(html: &str) -> String {
    let markdown = quick_html2md::html_to_markdown(html);
    let mut output = String::new();
    let mut blank_lines = 0_usize;
    for line in markdown.lines().map(str::trim_end) {
        if line.trim().is_empty() {
            blank_lines = blank_lines.saturating_add(1);
            if blank_lines <= 2 {
                output.push('\n');
            }
        } else {
            blank_lines = 0;
            output.push_str(line);
            output.push('\n');
        }
    }
    output.trim().to_owned()
}

fn extract_json(bytes: &[u8], content_type: &str) -> Result<ExtractedContent, Failure> {
    let decoded = decode_bytes(bytes, content_type);
    let value = serde_json::from_str::<Value>(&decoded).map_err(|error| {
        Failure::new(
            FailureCode::ExtractionFailed,
            format!("JSON parsing failed: {error}"),
        )
    })?;
    let content = serde_json::to_string_pretty(&value).map_err(|error| {
        Failure::new(
            FailureCode::ExtractionFailed,
            format!("JSON serialization failed: {error}"),
        )
    })?;
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let description = value
        .get("description")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(ExtractedContent {
        content,
        source: "json".to_owned(),
        quality: 1.0,
        title,
        description,
        links: Vec::new(),
        json_ld: vec![value],
        selector_hits: BTreeMap::new(),
        dynamic_shell: false,
    })
}

fn extract_plain_text(bytes: &[u8], content_type: &str) -> Result<ExtractedContent, Failure> {
    let content = normalize_text(&decode_bytes(bytes, content_type));
    Ok(ExtractedContent {
        content,
        source: "plain_text".to_owned(),
        quality: 0.8,
        title: None,
        description: None,
        links: Vec::new(),
        json_ld: Vec::new(),
        selector_hits: BTreeMap::new(),
        dynamic_shell: false,
    })
}

fn extract_xml(bytes: &[u8], content_type: &str) -> Result<ExtractedContent, Failure> {
    let decoded = decode_bytes(bytes, content_type);
    let fragment = Html::parse_fragment(&decoded);
    let content = visible_text(fragment.root_element());
    Ok(ExtractedContent {
        content,
        source: "xml_text".to_owned(),
        quality: 0.65,
        title: None,
        description: None,
        links: Vec::new(),
        json_ld: Vec::new(),
        selector_hits: BTreeMap::new(),
        dynamic_shell: false,
    })
}

fn extract_pdf(bytes: &[u8], max_extracted_bytes: usize) -> Result<ExtractedContent, Failure> {
    let extracted = catch_unwind(AssertUnwindSafe(|| {
        let document = lopdf::Document::load_mem_with_options(
            bytes,
            lopdf::LoadOptions::with_max_decompressed_size(max_extracted_bytes),
        )?;
        let page_numbers = document.get_pages().into_keys().collect::<Vec<_>>();
        if page_numbers.is_empty() {
            return Ok(String::new());
        }
        let per_page_decompression_limit = max_extracted_bytes / page_numbers.len();
        if per_page_decompression_limit == 0 {
            return Err(lopdf::Error::Decompress(
                lopdf::DecompressError::MemoryLimitExceeded {
                    limit: max_extracted_bytes,
                },
            ));
        }
        document.extract_text_with_limit(&page_numbers, per_page_decompression_limit)
    }))
    .map_err(|_| {
        Failure::new(
            FailureCode::ExtractionFailed,
            "PDF parser panicked while processing input",
        )
    })?
    .map_err(|error| {
        Failure::new(
            FailureCode::ExtractionFailed,
            format!("PDF text extraction failed: {error}"),
        )
    })?;
    let content = normalize_text(&extracted);
    if content.is_empty() {
        return Err(Failure::new(
            FailureCode::ContentEmpty,
            "PDF contains no extractable text layer",
        ));
    }
    Ok(ExtractedContent {
        content,
        source: "pdf_text".to_owned(),
        quality: 0.75,
        title: None,
        description: None,
        links: Vec::new(),
        json_ld: Vec::new(),
        selector_hits: BTreeMap::new(),
        dynamic_shell: false,
    })
}

fn extract_links(document: &Html, selector: &Selector, base: &Url) -> Vec<String> {
    let mut links = BTreeSet::new();
    for element in document.select(selector) {
        let Some(href) = element.value().attr("href") else {
            continue;
        };
        let Ok(mut url) = base.join(href) else {
            continue;
        };
        if !matches!(url.scheme(), "http" | "https") {
            continue;
        }
        url.set_fragment(None);
        links.insert(url.to_string());
        if links.len() >= MAX_LINKS {
            break;
        }
    }
    links.into_iter().collect()
}

fn first_text(document: &Html, selector: &Selector) -> Option<String> {
    document.select(selector).next().and_then(|element| {
        let text = visible_text(element);
        (!text.is_empty()).then_some(text)
    })
}

fn first_attribute(document: &Html, selector: &Selector, attribute: &str) -> Option<String> {
    document
        .select(selector)
        .next()
        .and_then(|element| element.value().attr(attribute))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Extracts article text from structured data when the visible DOM is only a
/// JavaScript shell. The value is still untrusted page content; this only
/// chooses a better representation for the existing extraction contract.
fn json_ld_rescue(values: &[Value]) -> Option<String> {
    let mut parts = Vec::new();
    let mut total_chars = 0;
    for value in values {
        collect_json_ld_rescue(value, &mut parts, &mut total_chars);
        if total_chars >= JSON_LD_RESCUE_MAX_CHARS {
            break;
        }
    }
    (!parts.is_empty()).then(|| parts.join("\n\n"))
}

fn collect_json_ld_rescue(value: &Value, parts: &mut Vec<String>, total_chars: &mut usize) {
    if *total_chars >= JSON_LD_RESCUE_MAX_CHARS {
        return;
    }
    match value {
        Value::Array(values) => {
            for value in values {
                collect_json_ld_rescue(value, parts, total_chars);
                if *total_chars >= JSON_LD_RESCUE_MAX_CHARS {
                    break;
                }
            }
        }
        Value::Object(object) => {
            let article_type = object.get("@type").is_some_and(is_article_type);
            let body = object
                .get("articleBody")
                .and_then(Value::as_str)
                .filter(|body| !body.trim().is_empty())
                .or_else(|| {
                    article_type
                        .then(|| object.get("description"))
                        .flatten()
                        .and_then(Value::as_str)
                        .filter(|body| !body.trim().is_empty())
                });
            if let Some(body) = body {
                let remaining = JSON_LD_RESCUE_MAX_CHARS.saturating_sub(*total_chars);
                let body = body.chars().take(remaining).collect::<String>();
                if !body.is_empty() {
                    *total_chars += body.chars().count();
                    parts.push(normalize_text(&body));
                }
            }
            if let Some(graph) = object.get("@graph") {
                collect_json_ld_rescue(graph, parts, total_chars);
            }
        }
        _ => {}
    }
}

fn is_article_type(value: &Value) -> bool {
    match value {
        Value::String(value) => matches!(
            value.as_str(),
            "Article" | "NewsArticle" | "BlogPosting" | "TechArticle"
        ),
        Value::Array(values) => values.iter().any(is_article_type),
        _ => false,
    }
}

/// Collapses whitespace as text is appended.
///
/// Separators are only emitted immediately before a non-whitespace character and
/// never when the output is still empty, so the result carries no leading or
/// trailing whitespace by construction and needs no trimming pass afterwards.
#[derive(Default)]
struct Normalizer {
    output: String,
    pending_space: bool,
    pending_newline: bool,
}

impl Normalizer {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            output: String::with_capacity(capacity),
            ..Self::default()
        }
    }

    fn push_str(&mut self, input: &str) {
        for character in input.chars() {
            if character == '\r' || character == '\n' {
                self.pending_newline = true;
                self.pending_space = false;
                continue;
            }
            if character.is_whitespace() {
                self.pending_space = true;
                continue;
            }
            if self.pending_newline && !self.output.is_empty() {
                if !self.output.ends_with('\n') {
                    self.output.push('\n');
                }
            } else if self.pending_space
                && !self.output.is_empty()
                && !self.output.ends_with(' ')
                && !self.output.ends_with('\n')
            {
                self.output.push(' ');
            }
            self.output.push(character);
            self.pending_space = false;
            self.pending_newline = false;
        }
    }

    /// Marks a boundary between adjacent text nodes so words never run together.
    fn push_break(&mut self) {
        self.pending_space = true;
    }

    fn finish(self) -> String {
        self.output
    }
}

/// Visible text of an element, normalized in the same traversal that collects it.
fn visible_text(element: ElementRef<'_>) -> String {
    let mut output = Normalizer::default();
    let mut hidden_depth = 0_usize;
    for edge in element.traverse() {
        match edge {
            Edge::Open(node) => match node.value() {
                Node::Element(value) if is_non_content_element(value.name()) => {
                    hidden_depth = hidden_depth.saturating_add(1);
                }
                Node::Text(value) if hidden_depth == 0 => {
                    output.push_str(value);
                    output.push_break();
                }
                _ => {}
            },
            Edge::Close(node) => {
                if node
                    .value()
                    .as_element()
                    .is_some_and(|value| is_non_content_element(value.name()))
                {
                    hidden_depth = hidden_depth.saturating_sub(1);
                }
            }
        }
    }
    output.finish()
}

fn is_non_content_element(name: &str) -> bool {
    matches!(name, "script" | "style" | "noscript" | "template")
}

/// Decodes a response body, preferring the declared charset and falling back to
/// what the document itself declares.
///
/// A page whose only charset declaration is a BOM or an in-document `<meta>` is
/// common enough that assuming UTF-8 turns it into replacement characters, and the
/// damaged text would then be handed to evidence matching as if it were the page.
fn decode_bytes<'a>(bytes: &'a [u8], content_type: &str) -> Cow<'a, str> {
    let encoding = charset_label(content_type)
        .and_then(|label| Encoding::for_label(label.as_bytes()))
        .or_else(|| Encoding::for_bom(bytes).map(|(encoding, _)| encoding))
        .or_else(|| {
            meta_charset_label(bytes).and_then(|label| Encoding::for_label(label.as_bytes()))
        })
        .unwrap_or(UTF_8);
    // `decode` also strips a BOM that matches the chosen encoding.
    let (decoded, _, _) = encoding.decode(bytes);
    decoded
}

const MAX_META_CHARSET_PREFIX: usize = 1024;

/// Reads a `<meta charset>` or `<meta http-equiv content="...; charset=...">`
/// declaration out of the document prefix.
///
/// Attributes are parsed rather than the prefix being searched for the first
/// `charset` substring. A page whose description or keywords happen to mention
/// `charset=` would otherwise decide how the whole document is decoded, and a
/// wrongly chosen legacy encoding does not fail loudly: it silently hands damaged
/// text to evidence matching and content safety as if it were the page. A
/// plain-text body that mentions `charset=` is likewise never reinterpreted,
/// because it carries no `<meta` tag at all.
fn meta_charset_label(bytes: &[u8]) -> Option<String> {
    let prefix = lowercase_prefix(bytes, MAX_META_CHARSET_PREFIX);
    let mut rest = prefix.as_str();
    while let Some(start) = rest.find("<meta") {
        // A tag cut off by the prefix limit is still worth reading; the cut is
        // arbitrary and the attributes before it are intact.
        let body = rest.get(start + "<meta".len()..).unwrap_or_default();
        // `<metadata>` and `<meta-property>` are custom elements, not the HTML
        // metadata element. Without this boundary check they could supply a
        // charset attribute and silently corrupt the document decode.
        if body
            .chars()
            .next()
            .is_some_and(|character| !character.is_whitespace() && !matches!(character, '/' | '>'))
        {
            rest = body;
            continue;
        }
        let (tag, remainder) = body.split_once('>').unwrap_or((body, ""));
        let attributes = tag_attributes(tag);
        let attribute = |wanted: &str| {
            attributes
                .iter()
                .find(|(name, _)| *name == wanted)
                .map(|(_, value)| value.trim())
        };
        if let Some(label) = attribute("charset").filter(|value| !value.is_empty()) {
            return Some(label.to_owned());
        }
        if attribute("http-equiv") == Some("content-type")
            && let Some(label) = attribute("content").and_then(charset_label)
        {
            return Some(label);
        }
        rest = remainder;
    }
    None
}

/// Attribute name/value pairs of a tag body, with quotes removed.
fn tag_attributes(tag: &str) -> Vec<(&str, &str)> {
    let mut attributes = Vec::new();
    let mut rest = tag;
    loop {
        rest = rest.trim_start_matches(|character: char| character.is_whitespace());
        rest = rest.trim_start_matches('/');
        let name_end = rest
            .find(|character: char| character.is_whitespace() || matches!(character, '=' | '/'))
            .unwrap_or(rest.len());
        let (name, after) = rest.split_at(name_end);
        if name.is_empty() {
            return attributes;
        }
        let after = after.trim_start();
        let Some(after) = after.strip_prefix('=') else {
            // A valueless attribute is still recorded so the next one is not read as
            // this one's value.
            attributes.push((name, ""));
            rest = after;
            continue;
        };
        let after = after.trim_start();
        let (value, remainder) = match after.chars().next() {
            Some(quote @ ('"' | '\'')) => {
                let body = after.get(quote.len_utf8()..).unwrap_or_default();
                body.split_once(quote).unwrap_or((body, ""))
            }
            _ => {
                let end = after.find(char::is_whitespace).unwrap_or(after.len());
                after.split_at(end)
            }
        };
        attributes.push((name, value));
        rest = remainder;
    }
}

fn charset_label(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        name.eq_ignore_ascii_case("charset").then(|| {
            value
                .trim()
                .trim_matches(|character| character == '\'' || character == '"')
                .to_owned()
        })
    })
}

fn normalized_media_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn is_json_type(media_type: &str) -> bool {
    media_type == "application/json" || media_type.ends_with("+json")
}

fn is_html_type(media_type: &str) -> bool {
    matches!(media_type, "text/html" | "application/xhtml+xml")
}

fn is_xml_type(media_type: &str) -> bool {
    media_type == "application/xml"
        || media_type == "text/xml"
        || media_type.ends_with("+xml")
        || matches!(media_type, "application/rss+xml" | "application/atom+xml")
}

fn looks_like_json(bytes: &[u8]) -> bool {
    matches!(first_non_whitespace(bytes), Some(b'{') | Some(b'['))
}

fn looks_like_html(bytes: &[u8]) -> bool {
    let prefix = lowercase_prefix(bytes, 256);
    prefix.contains("<!doctype html")
        || prefix.contains("<html")
        || prefix.contains("<head")
        || prefix.contains("<body")
}

fn looks_like_xml(bytes: &[u8]) -> bool {
    lowercase_prefix(bytes, 128).contains("<?xml")
}

fn first_non_whitespace(bytes: &[u8]) -> Option<u8> {
    bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
}

fn lowercase_prefix(bytes: &[u8], limit: usize) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]).to_ascii_lowercase()
}

fn normalize_text(input: &str) -> String {
    let mut output = Normalizer::with_capacity(input.len());
    output.push_str(input);
    output.finish()
}

#[cfg(test)]
mod tests {
    use lopdf::content::{Content, Operation};
    use lopdf::{Document, Object, Stream, dictionary};
    use url::Url;

    use super::{ExtractionOptions, extract, extract_with_options};
    use crate::domain::EvidenceSpec;
    use crate::evidence::{CompiledEvidence, compile};

    fn compile_evidence(spec: EvidenceSpec) -> Option<CompiledEvidence> {
        compile(spec).ok()
    }

    #[test]
    fn extracts_html_metadata_links_and_selector_hits() {
        let html = br#"<!doctype html><html><head><title>Example</title>
            <meta name="description" content="Description"></head>
            <body><main><h1>Hello</h1><p>World</p><a href="/more">More</a></main></body></html>"#;
        let url = Url::parse("https://example.com/path");
        assert!(url.is_ok());
        let Some(url) = url.ok() else {
            return;
        };
        let evidence = EvidenceSpec {
            selectors: vec!["main".to_owned()],
            required_text: Vec::new(),
            minimum_text_bytes: None,
        };
        let evidence = compile_evidence(evidence);
        assert!(evidence.is_some());
        let Some(evidence) = evidence else {
            return;
        };
        let result = extract(html, "text/html; charset=utf-8", &url, &evidence, 1024);
        assert!(result.is_ok());
        let Some(extracted) = result.ok() else {
            return;
        };
        assert_eq!(extracted.title.as_deref(), Some("Example"));
        assert!(extracted.content.contains("Hello"));
        assert_eq!(extracted.selector_hits.get("main"), Some(&1));
        assert!(
            extracted
                .links
                .iter()
                .any(|link| link == "https://example.com/more")
        );
    }

    #[test]
    fn external_extraction_options_enable_markdown_and_raw_mode() {
        let Some(url) = Url::parse("https://example.com/article").ok() else {
            return;
        };
        let Some(evidence) = compile_evidence(EvidenceSpec::default()) else {
            return;
        };
        let html = br#"<html><body><nav>boilerplate</nav><main><h1>Article title</h1><p>A sufficiently useful article body.</p></main></body></html>"#;
        let markdown = extract_with_options(
            html,
            "text/html",
            &url,
            &evidence,
            4096,
            ExtractionOptions {
                enable_extraction: true,
                enable_markdown: true,
                enable_maincontent: true,
            },
        );
        assert!(markdown.is_ok());
        assert!(
            markdown
                .ok()
                .is_some_and(|value| value.source.contains("markdown"))
        );

        let raw = extract_with_options(
            html,
            "text/html",
            &url,
            &evidence,
            4096,
            ExtractionOptions {
                enable_extraction: false,
                enable_markdown: false,
                enable_maincontent: false,
            },
        );
        assert!(raw.is_ok());
        assert!(
            raw.ok()
                .is_some_and(|value| value.source == "raw" && value.content.contains("<main>"))
        );
    }

    #[test]
    fn script_source_is_not_treated_as_visible_content() {
        let html = br#"<html><body><div id="app"></div><script>let secret = 'many words that are not page content';</script><script src="app.js"></script></body></html>"#;
        let url = Url::parse("https://example.com");
        assert!(url.is_ok());
        let Some(url) = url.ok() else {
            return;
        };
        let evidence = compile_evidence(EvidenceSpec::default());
        assert!(evidence.is_some());
        let Some(evidence) = evidence else {
            return;
        };
        let result = extract(html, "text/html", &url, &evidence, 1024);
        assert!(result.is_err());
    }

    #[test]
    fn rescues_article_body_from_a_thin_json_ld_shell() {
        let body = "A real article body recovered from JSON-LD. ".repeat(8);
        let serialized = serde_json::to_string(&body);
        assert!(serialized.is_ok());
        let Some(serialized) = serialized.ok() else {
            return;
        };
        let html = format!(
            r#"<html><head><script type="application/ld+json">{{"@type":"NewsArticle","articleBody":{serialized}}}</script></head><body><div id="root"></div><script>load()</script><script>hydrate()</script></body></html>"#
        );
        let url = Url::parse("https://example.com/shell");
        assert!(url.is_ok());
        let Some(url) = url.ok() else {
            return;
        };
        let evidence = compile_evidence(EvidenceSpec::default());
        assert!(evidence.is_some());
        let Some(evidence) = evidence else {
            return;
        };
        let result = extract(html.as_bytes(), "text/html", &url, &evidence, 4096);
        assert!(result.is_ok());
        let Some(extracted) = result.ok() else {
            return;
        };
        assert_eq!(extracted.source, "html_json_ld");
        assert_eq!(extracted.content, body.trim());
        assert!(!extracted.dynamic_shell);
    }

    #[test]
    fn rejects_error_json_that_is_not_valid_json() {
        let url = Url::parse("https://example.com");
        assert!(url.is_ok());
        let Some(url) = url.ok() else {
            return;
        };
        let evidence = compile_evidence(EvidenceSpec::default());
        assert!(evidence.is_some());
        let Some(evidence) = evidence else {
            return;
        };
        let result = extract(b"{broken", "application/json", &url, &evidence, 1024);
        assert!(result.is_err());
    }

    #[test]
    fn declared_plain_text_is_not_reclassified_from_its_first_byte() {
        let url = Url::parse("https://example.com/Cargo.toml");
        assert!(url.is_ok());
        let Some(url) = url.ok() else {
            return;
        };
        let evidence = compile_evidence(EvidenceSpec::default());
        assert!(evidence.is_some());
        let Some(evidence) = evidence else {
            return;
        };
        let toml = b"[package]\nname = \"axiom-collect\"\n";
        let result = extract(toml, "text/plain; charset=utf-8", &url, &evidence, 1024);
        assert!(result.is_ok());
        let Some(extracted) = result.ok() else {
            return;
        };
        assert_eq!(extracted.source, "plain_text");
        assert!(extracted.content.starts_with("[package]"));
    }

    #[test]
    fn malformed_json_sniffed_without_a_declared_type_falls_back_to_text() {
        let url = Url::parse("https://example.com/unknown");
        assert!(url.is_ok());
        let Some(url) = url.ok() else {
            return;
        };
        let evidence = compile_evidence(EvidenceSpec::default());
        assert!(evidence.is_some());
        let Some(evidence) = evidence else {
            return;
        };
        let result = extract(b"[not json", "", &url, &evidence, 1024);
        assert!(result.is_ok());
        assert_eq!(
            result.ok().map(|content| content.source),
            Some("plain_text".to_owned())
        );
    }

    #[test]
    fn in_document_charset_declarations_are_honoured() -> Result<(), String> {
        let url = Url::parse("https://example.com/legacy").map_err(|error| error.to_string())?;
        let evidence = compile_evidence(EvidenceSpec::default())
            .ok_or_else(|| "evidence compilation failed".to_owned())?;
        let extract = |bytes: &[u8], content_type: &str| {
            extract(bytes, content_type, &url, &evidence, 4096).map_err(|failure| failure.message)
        };

        // Declared only in markup, with no charset on the Content-Type header.
        let (euc_kr, _, _) = encoding_rs::EUC_KR.encode(
            "<html><head><meta charset=\"euc-kr\"><title>제목</title></head><body><main>한글 본문</main></body></html>",
        );
        let extracted = extract(&euc_kr, "text/html")?;
        assert_eq!(extracted.title.as_deref(), Some("제목"));
        assert!(extracted.content.contains("한글 본문"));
        assert!(!extracted.content.contains('\u{fffd}'));

        // Declared only by a BOM.
        let mut utf16 = vec![0xff, 0xfe];
        for unit in "hello bom".encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        let extracted = extract(&utf16, "text/plain")?;
        assert_eq!(extracted.content, "hello bom");

        // A plain-text body that merely mentions charset= must not be reinterpreted.
        let extracted = extract(b"charset=euc-kr is a header", "text/plain")?;
        assert_eq!(extracted.content, "charset=euc-kr is a header");
        Ok(())
    }

    #[test]
    fn charset_comes_from_meta_attributes_not_from_arbitrary_markup_text() -> Result<(), String> {
        let url = Url::parse("https://example.com/legacy").map_err(|error| error.to_string())?;
        let evidence = compile_evidence(EvidenceSpec::default())
            .ok_or_else(|| "evidence compilation failed".to_owned())?;
        let extract = |bytes: &[u8], content_type: &str| {
            extract(bytes, content_type, &url, &evidence, 4096).map_err(|failure| failure.message)
        };

        // An earlier tag whose *value* mentions another encoding must not decide how
        // the document is decoded. Searching the prefix for the first `charset`
        // substring used to pick `euc-kr` here and corrupt the entire page.
        let utf8 = "<html><head><meta name=\"description\" content=\"charset=euc-kr 안내 문서\"><meta charset=\"utf-8\"><title>제목</title></head><body><main>한글 본문</main></body></html>";
        let extracted = extract(utf8.as_bytes(), "text/html")?;
        assert_eq!(extracted.title.as_deref(), Some("제목"));
        assert!(extracted.content.contains("한글 본문"));
        assert!(!extracted.content.contains('\u{fffd}'));

        // The `http-equiv` form is still honoured, now by name rather than by luck.
        let (euc_kr, _, _) = encoding_rs::EUC_KR.encode(
            "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=euc-kr\"><title>제목</title></head><body><main>한글 본문</main></body></html>",
        );
        let extracted = extract(&euc_kr, "text/html")?;
        assert_eq!(extracted.title.as_deref(), Some("제목"));
        assert!(extracted.content.contains("한글 본문"));

        // A similarly named custom element is not a `<meta>` declaration. The
        // tag scanner must enforce the element-name boundary before parsing its
        // attributes.
        let custom_element = "<metadata charset=euc-kr><main>한글 본문</main>";
        let extracted = extract(custom_element.as_bytes(), "text/html")?;
        assert!(extracted.content.contains("한글 본문"));
        assert!(!extracted.content.contains('\u{fffd}'));

        // A valueless attribute must not swallow the one that follows it.
        let (euc_kr, _, _) = encoding_rs::EUC_KR
            .encode("<html><head><meta async charset=euc-kr><title>제목</title></head><body><main>한글 본문</main></body></html>");
        let extracted = extract(&euc_kr, "text/html")?;
        assert_eq!(extracted.title.as_deref(), Some("제목"));
        Ok(())
    }

    #[test]
    fn rejects_textless_pdf() {
        let url = Url::parse("https://example.com/a.pdf");
        assert!(url.is_ok());
        let Some(url) = url.ok() else {
            return;
        };
        let evidence = compile_evidence(EvidenceSpec::default());
        assert!(evidence.is_some());
        let Some(evidence) = evidence else {
            return;
        };
        let result = extract(
            b"%PDF-not-a-real-pdf",
            "application/pdf",
            &url,
            &evidence,
            1024,
        );
        assert!(result.is_err());
    }

    #[test]
    fn extracts_pdf_text_within_decompression_budget() -> Result<(), Box<dyn std::error::Error>> {
        let mut document = Document::with_version("1.5");
        let pages_id = document.new_object_id();
        let font_id = document.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Courier",
        });
        let resources_id = document.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let content = Content {
            operations: vec![
                Operation::new("BT", Vec::new()),
                Operation::new("Tf", vec![Object::Name(b"F1".to_vec()), 24.into()]),
                Operation::new("Td", vec![100.into(), 700.into()]),
                Operation::new("Tj", vec![Object::string_literal("Bounded PDF extraction")]),
                Operation::new("ET", Vec::new()),
            ],
        }
        .encode()?;
        let content_id = document.add_object(Stream::new(dictionary! {}, content));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        });
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page_id.into()],
                "Count" => 1,
            }),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        document.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;

        let url = Url::parse("https://example.com/a.pdf")?;
        let evidence = compile_evidence(EvidenceSpec::default());
        assert!(evidence.is_some());
        let Some(evidence) = evidence else {
            return Ok(());
        };
        let extracted = extract(&bytes, "application/pdf", &url, &evidence, 4096);
        assert!(extracted.is_ok());
        let Some(extracted) = extracted.ok() else {
            return Ok(());
        };

        assert!(extracted.content.contains("Bounded PDF extraction"));
        assert_eq!(extracted.source, "pdf_text");
        Ok(())
    }
}
