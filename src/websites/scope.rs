use patchriot_protocol::websites::WebsiteScope;
use std::net::IpAddr;
use url::{Host, Url};

pub const MAX_URL_BYTES: usize = 2048;

/// Normalize before saving the approval. A later collection validates it again;
/// URLs found in a page cannot add origins to this allowlist.
pub fn normalize_scope(scope: &WebsiteScope) -> Result<WebsiteScope, &'static str> {
    if scope.script_origins.len() > 3 {
        return Err("too_many_script_origins");
    }
    let homepage = origin(&scope.homepage)?;
    let mut script_origins = Vec::new();
    for raw in &scope.script_origins {
        let approved = origin(raw)?.origin().ascii_serialization();
        if approved != homepage.origin().ascii_serialization() {
            script_origins.push(approved);
        }
    }
    script_origins.sort();
    script_origins.dedup();
    Ok(WebsiteScope {
        homepage: homepage.to_string(),
        script_origins,
    })
}

fn origin(raw: &str) -> Result<Url, &'static str> {
    let url = public_url(raw)?;
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err("origin_required");
    }
    Ok(url)
}

pub(super) fn public_url(raw: &str) -> Result<Url, &'static str> {
    if raw.is_empty()
        || raw.len() > MAX_URL_BYTES
        || raw.chars().any(|c| c.is_control() || c.is_whitespace())
        || raw.contains('\\')
    {
        return Err("invalid_url");
    }
    let url = Url::parse(raw).map_err(|_| "invalid_url")?;
    if url.as_str().len() > MAX_URL_BYTES {
        return Err("url_too_long");
    }
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
    {
        return Err("https_origin_required");
    }
    let Some(Host::Domain(host)) = url.host() else {
        return Err("hostname_required");
    };
    if !host.contains('.')
        || host.len() > 253
        || host.ends_with('.')
        || host.ends_with(".localhost")
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err("invalid_hostname");
    }
    Ok(url)
}

pub(super) fn approved_url(raw: &str, scope: &WebsiteScope) -> Result<Url, &'static str> {
    let mut url = public_url(raw)?;
    let origin = url.origin().ascii_serialization();
    let homepage = Url::parse(&scope.homepage).map_err(|_| "invalid_scope")?;
    if origin != homepage.origin().ascii_serialization() && !scope.script_origins.contains(&origin)
    {
        return Err("origin_not_approved");
    }
    // Fragments are never sent over HTTP; do not fetch duplicates for each hash.
    url.set_fragment(None);
    Ok(url)
}

/// Deliberately conservative public-unicast policy. DNS must pass this for every
/// returned address, then the HTTP connection is pinned to that exact set. Special
/// and transition ranges are excluded even when some addresses are globally routed.
pub(super) fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 192 && b == 0 && matches!(c, 0 | 2))
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && matches!(b, 18 | 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            (a & 0xe000) == 0x2000
                && !(a == 0x2001 && (b < 0x0200 || b == 0x0db8))
                && a != 0x2002
                && !(a == 0x3fff && b < 0x1000)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_is_exact_and_canonical() {
        let scope = normalize_scope(&WebsiteScope {
            homepage: "https://EXAMPLE.com:443".into(),
            script_origins: vec![
                "https://cdn.example.com/".into(),
                "https://example.com".into(),
            ],
        })
        .unwrap();
        assert_eq!(scope.homepage, "https://example.com/");
        assert_eq!(scope.script_origins, ["https://cdn.example.com"]);
        assert!(approved_url("https://cdn.example.com/a.js?v=1#x", &scope).is_ok());
        for raw in [
            "https://evil.example.com/a.js",
            "https://example.com.evil.test/a.js",
            "https://example.com@evil.test/a.js",
            "https://example.com:444/a.js",
            "http://example.com/a.js",
        ] {
            assert!(approved_url(raw, &scope).is_err(), "{raw}");
        }
    }

    #[test]
    fn scope_rejects_private_literals_credentials_and_non_origins() {
        for raw in [
            "https://127.1",
            "https://2130706433",
            "https://0x7f000001",
            "https://[::1]",
            "https://localhost",
            "https://site.localhost",
            "https://example.com.",
            "https://name:secret@example.com",
            "https://example.com/path",
            "https://example.com/?key=x",
            "https://example.com/#x",
            "file:///etc/passwd",
            "https://example.com\\@evil.test",
            " https://example.com",
            "https://example\n.com",
            "https://bad_host.example",
        ] {
            assert!(
                normalize_scope(&WebsiteScope {
                    homepage: raw.into(),
                    script_origins: vec![]
                })
                .is_err(),
                "{raw}"
            );
        }
    }

    #[test]
    fn blocks_special_ranges_including_ipv6_transition_and_documentation() {
        for raw in [
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "100::1",
            "2001::1",
            "2001:1::1",
            "2001:db8::1",
            "2002:0808:0808::1",
            "3fff::1",
            "3fff:fff::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(!public_ip(raw.parse().unwrap()), "{raw}");
        }
        for raw in [
            "1.1.1.1",
            "8.8.8.8",
            "100.128.0.1",
            "172.32.0.1",
            "192.0.3.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(public_ip(raw.parse().unwrap()), "{raw}");
        }
    }
}
