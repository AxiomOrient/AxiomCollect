use std::collections::BTreeSet;

use aho_corasick::AhoCorasick;
use scraper::Selector;

use crate::domain::{
    EvidenceCheck, EvidenceSpec, EvidenceStatus, ExtractedContent, Failure, FailureCode,
};

pub const MAX_SELECTORS: usize = 32;
pub const MAX_SELECTOR_BYTES: usize = 512;
pub const MAX_REQUIRED_TEXTS: usize = 64;
pub const MAX_REQUIRED_TEXT_BYTES: usize = 4 * 1024;
pub const MAX_REQUIRED_TEXT_TOTAL_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct CompiledEvidence {
    spec: EvidenceSpec,
    selectors: Vec<(String, Selector)>,
    required_text_matcher: Option<AhoCorasick>,
}

impl CompiledEvidence {
    #[must_use]
    pub fn spec(&self) -> &EvidenceSpec {
        &self.spec
    }

    #[must_use]
    pub fn selectors(&self) -> &[(String, Selector)] {
        &self.selectors
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceEvaluation {
    pub status: EvidenceStatus,
    pub checks: Vec<EvidenceCheck>,
}

pub fn compile(spec: EvidenceSpec) -> Result<CompiledEvidence, Failure> {
    if spec.selectors.len() > MAX_SELECTORS {
        return Err(invalid(format!(
            "at most {MAX_SELECTORS} CSS selectors may be requested"
        )));
    }
    if spec.required_text.len() > MAX_REQUIRED_TEXTS {
        return Err(invalid(format!(
            "at most {MAX_REQUIRED_TEXTS} required text values may be requested"
        )));
    }

    let mut selector_names = BTreeSet::new();
    let mut selectors = Vec::with_capacity(spec.selectors.len());
    for selector in &spec.selectors {
        let trimmed = selector.trim();
        if trimmed.is_empty() {
            return Err(invalid("CSS selector evidence cannot be empty"));
        }
        if trimmed.len() > MAX_SELECTOR_BYTES {
            return Err(invalid(format!(
                "CSS selector exceeds {MAX_SELECTOR_BYTES} bytes"
            )));
        }
        if !selector_names.insert(trimmed.to_owned()) {
            return Err(invalid(format!("duplicate CSS selector: {trimmed}")));
        }
        let compiled = Selector::parse(trimmed)
            .map_err(|error| invalid(format!("invalid CSS selector `{trimmed}`: {error}")))?;
        selectors.push((trimmed.to_owned(), compiled));
    }

    let mut required_names = BTreeSet::new();
    let mut required_patterns = Vec::with_capacity(spec.required_text.len());
    let mut required_total = 0_usize;
    for text in &spec.required_text {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(invalid("required text evidence cannot be empty"));
        }
        if trimmed.len() > MAX_REQUIRED_TEXT_BYTES {
            return Err(invalid(format!(
                "required text exceeds {MAX_REQUIRED_TEXT_BYTES} bytes"
            )));
        }
        required_total = required_total
            .checked_add(trimmed.len())
            .ok_or_else(|| invalid("required text size overflow"))?;
        if required_total > MAX_REQUIRED_TEXT_TOTAL_BYTES {
            return Err(invalid(format!(
                "required text values exceed {MAX_REQUIRED_TEXT_TOTAL_BYTES} total bytes"
            )));
        }
        let normalized = trimmed.to_lowercase();
        if !required_names.insert(normalized.clone()) {
            return Err(invalid(format!(
                "duplicate required text after case normalization: {trimmed}"
            )));
        }
        required_patterns.push(normalized);
    }
    if spec.minimum_text_bytes == Some(0) {
        return Err(invalid("minimum_text_bytes must be greater than zero"));
    }

    let required_text_matcher = if required_patterns.is_empty() {
        None
    } else {
        Some(AhoCorasick::new(required_patterns).map_err(|error| {
            invalid(format!(
                "required text matcher construction failed: {error}"
            ))
        })?)
    };

    Ok(CompiledEvidence {
        spec,
        selectors,
        required_text_matcher,
    })
}

#[must_use]
pub fn evaluate(compiled: &CompiledEvidence, content: &ExtractedContent) -> EvidenceEvaluation {
    let spec = compiled.spec();
    if !spec.is_requested() {
        return EvidenceEvaluation {
            status: EvidenceStatus::NotRequested,
            checks: Vec::new(),
        };
    }

    let mut checks = Vec::with_capacity(
        spec.selectors.len()
            + spec.required_text.len()
            + usize::from(spec.minimum_text_bytes.is_some()),
    );
    for selector in &spec.selectors {
        let hits = content.selector_hits.get(selector).copied().unwrap_or(0);
        checks.push(EvidenceCheck {
            kind: "selector".to_owned(),
            requirement: selector.clone(),
            satisfied: hits > 0,
            observed: format!("{hits} match(es)"),
        });
    }

    let mut text_matches = vec![false; spec.required_text.len()];
    if let Some(matcher) = &compiled.required_text_matcher {
        let lowercase_content = content.content.to_lowercase();
        let mut remaining = text_matches.len();
        for found in matcher.find_overlapping_iter(lowercase_content.as_bytes()) {
            let index = found.pattern().as_usize();
            if !text_matches[index] {
                text_matches[index] = true;
                remaining = remaining.saturating_sub(1);
                if remaining == 0 {
                    break;
                }
            }
        }
    }
    for (required, satisfied) in spec.required_text.iter().zip(text_matches) {
        checks.push(EvidenceCheck {
            kind: "required_text".to_owned(),
            requirement: required.clone(),
            satisfied,
            observed: if satisfied {
                "present".to_owned()
            } else {
                "absent".to_owned()
            },
        });
    }

    if let Some(minimum) = spec.minimum_text_bytes {
        let observed = content.content_bytes();
        checks.push(EvidenceCheck {
            kind: "minimum_text_bytes".to_owned(),
            requirement: minimum.to_string(),
            satisfied: observed >= minimum,
            observed: observed.to_string(),
        });
    }

    let status = if checks.iter().all(|check| check.satisfied) {
        EvidenceStatus::Satisfied
    } else {
        EvidenceStatus::NotSatisfied
    };
    EvidenceEvaluation { status, checks }
}

fn invalid(message: impl Into<String>) -> Failure {
    Failure::new(FailureCode::InvalidRequest, message)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{compile, evaluate};
    use crate::domain::{EvidenceSpec, EvidenceStatus, ExtractedContent};

    fn content() -> ExtractedContent {
        let mut selector_hits = BTreeMap::new();
        selector_hits.insert("main".to_owned(), 1);
        ExtractedContent {
            content: "Hello world".to_owned(),
            source: "test".to_owned(),
            quality: 1.0,
            title: None,
            description: None,
            links: Vec::new(),
            json_ld: Vec::new(),
            selector_hits,
            dynamic_shell: false,
        }
    }

    #[test]
    fn all_requested_evidence_must_pass() {
        let compiled = compile(EvidenceSpec {
            selectors: vec!["main".to_owned()],
            required_text: vec!["world".to_owned()],
            minimum_text_bytes: Some(5),
        });
        assert!(compiled.is_ok());
        assert_eq!(
            compiled
                .as_ref()
                .map(|value| evaluate(value, &content()).status),
            Ok(EvidenceStatus::Satisfied)
        );
    }

    #[test]
    fn overlapping_required_text_is_detected_in_one_scan() {
        let compiled = compile(EvidenceSpec {
            selectors: Vec::new(),
            required_text: vec!["hello".to_owned(), "hello world".to_owned()],
            minimum_text_bytes: None,
        });
        assert!(compiled.is_ok());
        let checks = compiled
            .as_ref()
            .map(|value| evaluate(value, &content()).checks.clone())
            .unwrap_or_default();
        assert_eq!(checks.len(), 2);
        assert!(checks.iter().all(|check| check.satisfied));
    }

    #[test]
    fn duplicate_and_unbounded_requirements_are_rejected() {
        assert!(
            compile(EvidenceSpec {
                selectors: Vec::new(),
                required_text: vec!["same".to_owned(), "SAME".to_owned()],
                minimum_text_bytes: None,
            })
            .is_err()
        );
        assert!(
            compile(EvidenceSpec {
                selectors: vec!["a".repeat(super::MAX_SELECTOR_BYTES + 1)],
                required_text: Vec::new(),
                minimum_text_bytes: None,
            })
            .is_err()
        );
    }
}
