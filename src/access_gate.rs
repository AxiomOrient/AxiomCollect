use std::sync::LazyLock;

use aho_corasick::{AhoCorasick, MatchKind};

use crate::domain::ExtractedContent;

/// A public page can be successfully fetched while still withholding the
/// requested content. These are terminal access conditions, not retrieval
/// failures to solve with credentials, CAPTCHA services, or paywall tricks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccessGate {
    Captcha,
    Authentication,
    Paywall,
}

impl AccessGate {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Captcha => "captcha_or_anti_bot",
            Self::Authentication => "authentication_required",
            Self::Paywall => "paywall_or_subscription",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Signal {
    needle: &'static str,
    gate: AccessGate,
    high_confidence: bool,
}

const MAX_GATE_PAGE_TEXT_BYTES: usize = 4 * 1024;

const SIGNALS: &[Signal] = &[
    Signal {
        needle: "verify you are human",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "verify you're human",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "checking your browser",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "just a moment",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "challenge-platform",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "cf-chl-",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "unusual traffic",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "enable javascript and cookies",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "security verification",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "attention required",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "access denied",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "bot detection",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "datadome",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "perimeterx",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "akamai bot manager",
        gate: AccessGate::Captcha,
        high_confidence: true,
    },
    Signal {
        needle: "captcha",
        gate: AccessGate::Captcha,
        high_confidence: false,
    },
    Signal {
        needle: "sign in to continue",
        gate: AccessGate::Authentication,
        high_confidence: true,
    },
    Signal {
        needle: "log in to continue",
        gate: AccessGate::Authentication,
        high_confidence: true,
    },
    Signal {
        needle: "login required",
        gate: AccessGate::Authentication,
        high_confidence: true,
    },
    Signal {
        needle: "authentication required",
        gate: AccessGate::Authentication,
        high_confidence: true,
    },
    Signal {
        needle: "you must be logged in",
        gate: AccessGate::Authentication,
        high_confidence: true,
    },
    Signal {
        needle: "please sign in",
        gate: AccessGate::Authentication,
        high_confidence: true,
    },
    Signal {
        needle: "please log in",
        gate: AccessGate::Authentication,
        high_confidence: true,
    },
    Signal {
        needle: "members only",
        gate: AccessGate::Authentication,
        high_confidence: true,
    },
    Signal {
        needle: "sign in",
        gate: AccessGate::Authentication,
        high_confidence: false,
    },
    Signal {
        needle: "log in",
        gate: AccessGate::Authentication,
        high_confidence: false,
    },
    Signal {
        needle: "login",
        gate: AccessGate::Authentication,
        high_confidence: false,
    },
    Signal {
        needle: "subscribe to continue",
        gate: AccessGate::Paywall,
        high_confidence: true,
    },
    Signal {
        needle: "subscription required",
        gate: AccessGate::Paywall,
        high_confidence: true,
    },
    Signal {
        needle: "premium content",
        gate: AccessGate::Paywall,
        high_confidence: true,
    },
    Signal {
        needle: "unlock this article",
        gate: AccessGate::Paywall,
        high_confidence: true,
    },
    Signal {
        needle: "continue reading with a subscription",
        gate: AccessGate::Paywall,
        high_confidence: true,
    },
    Signal {
        needle: "become a member to continue",
        gate: AccessGate::Paywall,
        high_confidence: true,
    },
    Signal {
        needle: "paywall",
        gate: AccessGate::Paywall,
        high_confidence: false,
    },
    Signal {
        needle: "subscribe",
        gate: AccessGate::Paywall,
        high_confidence: false,
    },
];

/// Leftmost-longest, not the default standard semantics.
///
/// Several high-confidence needles have a low-confidence one as their prefix
/// (`sign in to continue` over `sign in`, `login required` over `login`). Standard
/// semantics report the match that ends first and `find_iter` then resumes past it,
/// so under the default every one of those longer needles is unreachable and a page
/// that says exactly `Sign in to continue` is only ever seen as the weak `sign in`
/// signal. Preferring the longest match at each position is what makes the
/// confidence tier of a needle mean what it says.
static MATCHER: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostLongest)
        .build(SIGNALS.iter().map(|signal| signal.needle))
        .ok()
});

#[must_use]
pub(crate) fn detect(content: &ExtractedContent) -> Option<AccessGate> {
    if let Some(title) = content.title.as_deref()
        && let Some(gate) = find(title, true, false)
    {
        return Some(gate);
    }
    if let Some(description) = content.description.as_deref()
        && let Some(gate) = find(description, false, content.dynamic_shell)
    {
        return Some(gate);
    }
    find(&content.content, false, content.dynamic_shell)
}

fn find(text: &str, title_context: bool, dynamic_shell: bool) -> Option<AccessGate> {
    let matcher_result = MATCHER.as_ref();
    let matcher = matcher_result.as_ref()?;
    matcher.find_iter(text).find_map(|found| {
        let signal = SIGNALS[found.pattern().as_usize()];
        let is_title_gate = title_context && title_matches_gate(text, signal);
        let is_short_gate_page = text.len() <= MAX_GATE_PAGE_TEXT_BYTES;
        // A dynamic shell lifts the length ceiling but not the confidence bar. An
        // unrendered shell that merely carries a `Sign in` navigation link is the
        // exact input `auto` exists to escalate to the browser, so only a
        // high-confidence gate phrase may end the route here.
        let allowed = if title_context {
            is_title_gate
        } else {
            (is_short_gate_page || dynamic_shell) && signal.high_confidence
        };
        allowed.then_some(signal.gate)
    })
}

fn title_matches_gate(title: &str, signal: Signal) -> bool {
    let normalized = title.trim().to_ascii_lowercase();
    if signal.high_confidence {
        normalized.starts_with(signal.needle)
    } else {
        matches!(
            normalized.as_str(),
            "captcha" | "sign in" | "log in" | "login" | "paywall" | "subscribe"
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{AccessGate, detect};
    use crate::domain::ExtractedContent;

    fn content(title: Option<&str>, body: &str, dynamic_shell: bool) -> ExtractedContent {
        ExtractedContent {
            content: body.to_owned(),
            source: "html_document".to_owned(),
            quality: 0.5,
            title: title.map(str::to_owned),
            description: None,
            links: Vec::new(),
            json_ld: Vec::new(),
            selector_hits: BTreeMap::new(),
            dynamic_shell,
        }
    }

    #[test]
    fn detects_anti_bot_challenge() {
        let value = content(
            Some("Just a moment..."),
            "Checking your browser before accessing the site. Verify you are human.",
            true,
        );
        assert_eq!(detect(&value), Some(AccessGate::Captcha));
    }

    #[test]
    fn detects_authentication_gate() {
        let value = content(
            Some("Sign in to continue"),
            "Please sign in to continue.",
            false,
        );
        assert_eq!(detect(&value), Some(AccessGate::Authentication));
    }

    #[test]
    fn detects_paywall_gate() {
        let value = content(
            Some("Subscribe to continue"),
            "This premium content requires a subscription.",
            false,
        );
        assert_eq!(detect(&value), Some(AccessGate::Paywall));
    }

    /// Every high-confidence needle must be reachable on its own.
    ///
    /// Under standard multi-pattern semantics the needles whose prefix is also a
    /// low-confidence needle were shadowed and could never be reported, which made
    /// a plain `Sign in to continue` page look ungated.
    #[test]
    fn every_high_confidence_signal_is_reachable_on_its_own() {
        for signal in super::SIGNALS
            .iter()
            .filter(|signal| signal.high_confidence)
        {
            let value = content(Some("Untitled"), signal.needle, false);
            assert_eq!(
                detect(&value),
                Some(signal.gate),
                "high-confidence signal `{}` was not detected",
                signal.needle
            );
        }
    }

    #[test]
    fn high_confidence_gate_wording_is_detected_in_body_text() {
        for (body, gate) in [
            ("Sign in to continue.", AccessGate::Authentication),
            ("Log in to continue.", AccessGate::Authentication),
            ("Login required.", AccessGate::Authentication),
            ("Subscribe to continue.", AccessGate::Paywall),
        ] {
            let value = content(Some("Untitled"), body, false);
            assert_eq!(detect(&value), Some(gate), "body `{body}` was not detected");
        }
    }

    #[test]
    fn dynamic_shell_navigation_wording_is_not_a_gate() {
        // An unrendered shell whose only signal is a weak navigation label must stay
        // escalatable to the browser instead of ending the route as access-restricted.
        let value = content(Some("Example app"), "Sign in Subscribe Login", true);
        assert_eq!(detect(&value), None);
    }

    #[test]
    fn dynamic_shell_still_reports_a_high_confidence_gate() {
        let value = content(Some("Example app"), "Please sign in to read this.", true);
        assert_eq!(detect(&value), Some(AccessGate::Authentication));
    }

    #[test]
    fn does_not_flag_an_article_discussing_access_controls() {
        let value = content(
            Some("Web security research"),
            "This article explains CAPTCHA, login, and paywall systems without restricting the article.",
            false,
        );
        assert_eq!(detect(&value), None);
    }

    #[test]
    fn does_not_flag_a_long_article_that_mentions_a_gate_phrase() {
        let body = format!(
            "{} Verify you are human is a phrase discussed in this article.",
            "research text ".repeat(400)
        );
        let value = content(Some("Web security research"), &body, false);
        assert_eq!(detect(&value), None);
    }
}
