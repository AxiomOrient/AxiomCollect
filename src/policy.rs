use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::lookup_host;
use url::Url;

use crate::domain::{Failure, FailureCode, NetworkPolicy};

#[derive(Debug, Clone)]
pub struct ValidatedTarget {
    pub url: Url,
    pub host: String,
    pub addresses: Vec<SocketAddr>,
}

pub fn parse_url(input: &str) -> Result<Url, Failure> {
    let mut url = Url::parse(input).map_err(|error| {
        Failure::new(FailureCode::InvalidRequest, format!("invalid URL: {error}"))
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Failure::new(
            FailureCode::PolicyRejected,
            "only http and https URLs are allowed",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Failure::new(
            FailureCode::PolicyRejected,
            "URL credentials are not allowed",
        ));
    }
    if has_sensitive_query_key(&url) {
        return Err(Failure::new(
            FailureCode::PolicyRejected,
            "credential-like query parameters are not allowed",
        ));
    }
    if url.host_str().is_none() {
        return Err(Failure::new(
            FailureCode::InvalidRequest,
            "URL host is required",
        ));
    }
    normalize_host(&mut url)?;
    Ok(url)
}

#[must_use]
pub(crate) fn has_sensitive_query_key(url: &Url) -> bool {
    url.query_pairs().any(|(key, _)| {
        let key = key.to_ascii_lowercase();
        matches!(
            key.as_str(),
            "api_key"
                | "apikey"
                | "auth"
                | "authorization"
                | "cookie"
                | "key"
                | "password"
                | "secret"
                | "session"
                | "signature"
                | "sig"
                | "token"
        ) || key.ends_with("_token")
            || key.ends_with("_secret")
            || key.ends_with("_signature")
    })
}

/// Rewrites a domain host into the exact form every later stage compares against.
///
/// DNS validation, the reqwest address pin, and the egress proxy all key on the
/// host string. A trailing root label or uppercase letters would make the pinned
/// address set miss the outgoing request and silently fall back to an unvalidated
/// connection-time resolution, so the URL itself is normalized once here.
fn normalize_host(url: &mut Url) -> Result<(), Failure> {
    let normalized = match url.host() {
        Some(url::Host::Domain(domain)) => {
            let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
            if normalized == domain {
                return Ok(());
            }
            normalized
        }
        _ => return Ok(()),
    };
    if normalized.is_empty() {
        return Err(Failure::new(
            FailureCode::InvalidRequest,
            "URL host is required",
        ));
    }
    url.set_host(Some(&normalized)).map_err(|error| {
        Failure::new(
            FailureCode::InvalidRequest,
            format!("URL host could not be normalized: {error}"),
        )
    })
}

pub async fn validate_and_resolve(
    url: Url,
    network_policy: NetworkPolicy,
    timeout: Duration,
) -> Result<ValidatedTarget, Failure> {
    // `parse_url` already normalized the host, so this is the exact string the
    // outgoing request carries and the address pin can key on.
    let host = url
        .host_str()
        .ok_or_else(|| Failure::new(FailureCode::InvalidRequest, "URL host is required"))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Failure::new(FailureCode::InvalidRequest, "URL port is required"))?;

    let addresses = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        let resolved = tokio::time::timeout(timeout, lookup_host((host.as_str(), port)))
            .await
            .map_err(|_| Failure::new(FailureCode::DnsRejected, "DNS resolution timed out"))?
            .map_err(|error| {
                Failure::new(
                    FailureCode::DnsRejected,
                    format!("DNS resolution failed: {error}"),
                )
            })?;
        let unique = resolved.collect::<BTreeSet<_>>();
        unique.into_iter().collect::<Vec<_>>()
    };

    if addresses.is_empty() {
        return Err(Failure::new(
            FailureCode::DnsRejected,
            "DNS resolution returned no addresses",
        ));
    }
    if network_policy == NetworkPolicy::PublicOnly {
        let denied = addresses
            .iter()
            .filter(|address| !is_public_ip(address.ip()))
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if !denied.is_empty() {
            return Err(Failure::new(
                FailureCode::PolicyRejected,
                format!(
                    "target resolves to denied address(es): {}",
                    denied.join(", ")
                ),
            ));
        }
    }

    Ok(ValidatedTarget {
        url,
        host,
        addresses,
    })
}

pub fn redirect_target(base: &Url, location: &str) -> Result<Url, Failure> {
    let joined = base.join(location).map_err(|error| {
        Failure::new(
            FailureCode::HttpRejected,
            format!("invalid redirect target: {error}"),
        )
    })?;
    parse_url(joined.as_str()).map_err(|failure| {
        Failure::new(
            FailureCode::PolicyRejected,
            format!("redirect rejected: {}", failure.message),
        )
    })
}

#[must_use]
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => is_public_ipv4(value),
        IpAddr::V6(value) => is_public_ipv6(value),
    }
}

fn is_public_ipv4(value: Ipv4Addr) -> bool {
    let [a, b, c, _] = value.octets();
    if a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 192 && b == 52 && c == 193)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
    {
        return false;
    }
    true
}

fn is_public_ipv6(value: Ipv6Addr) -> bool {
    if let Some(mapped) = value.to_ipv4() {
        return is_public_ipv4(mapped);
    }
    let segments = value.segments();
    if value.is_unspecified()
        || value.is_loopback()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        || (segments[0] & 0xff00) == 0xff00
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1)
        || (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0)
        || (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 1)
        || (segments[0] == 0x2001 && segments[1] <= 0x01ff)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[0] == 0x2002
        || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
        || segments[0] == 0x5f00
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{is_public_ip, parse_url};

    #[test]
    fn rejects_url_credentials_and_non_http_schemes() {
        assert!(parse_url("file:///etc/passwd").is_err());
        assert!(parse_url("https://user:pass@example.com").is_err());
    }

    #[test]
    fn host_is_normalized_so_the_address_pin_cannot_be_bypassed() {
        // A trailing root label or uppercase host used to survive into the request
        // while validation keyed on the trimmed form, which detached the pinned
        // address set from the connection.
        let url = parse_url("https://EXAMPLE.com./a");
        assert_eq!(
            url.as_ref().ok().and_then(|value| value.host_str()),
            Some("example.com")
        );
        assert!(parse_url("https://.").is_err());
        let literal = parse_url("http://[::1]/");
        assert_eq!(
            literal.as_ref().ok().and_then(|value| value.host_str()),
            Some("[::1]")
        );
    }

    #[test]
    fn rejects_private_and_documentation_addresses() {
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }
}
