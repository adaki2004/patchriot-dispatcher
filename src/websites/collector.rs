use super::scope::{MAX_URL_BYTES, approved_url, normalize_scope, public_ip};
use patchriot_protocol::websites::{
    ResourceKind, ScriptReference, ScriptStatus, WebsiteResource, WebsiteScope, WebsiteSnapshot,
};
use reqwest::{Client, Response, header};
use scraper::{Html, Selector};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, net::SocketAddr, time::Duration};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout, timeout_at};
use url::Url;

const MAX_HOMEPAGE_BYTES: usize = 256 * 1024;
const MAX_HTML_MARKERS: usize = 8 * 1024;
const MAX_SCRIPT_BYTES: usize = 512 * 1024;
const MAX_CAPTURED_BYTES: usize = 2 * 1024 * 1024;
const MAX_SCRIPTS: usize = 40;
const MAX_REQUESTS: u16 = 5; // Homepage plus four referenced scripts; no retries.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const COLLECTION_TIMEOUT: Duration = Duration::from_secs(30);
static HTML_PARSER_SLOT: Semaphore = Semaphore::const_new(1);

/// Stable, non-sensitive reason code. Do not expose reqwest errors: they can
/// contain customer URLs, query strings or details of the server's network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollectionError(pub &'static str);

impl std::fmt::Display for CollectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for CollectionError {}

/// Capture an already approved, immutable scope. This is a limited HTTP snapshot,
/// not a browser run or a verdict. It makes no requests beyond the homepage and
/// four directly referenced scripts, and never executes their content.
pub async fn collect(scope: &WebsiteScope) -> Result<WebsiteSnapshot, CollectionError> {
    let scope = normalize_scope(scope).map_err(CollectionError)?;
    let deadline = Instant::now() + COLLECTION_TIMEOUT;
    let mut fetcher = Fetcher {
        deadline,
        requests: 0,
        captured_bytes: 0,
    };
    snapshot(scope, &mut fetcher, deadline).await
}

async fn snapshot(
    scope: WebsiteScope,
    fetcher: &mut impl Source,
    deadline: Instant,
) -> Result<WebsiteSnapshot, CollectionError> {
    let started_at = crate::now();
    let homepage_url = approved_url(&scope.homepage, &scope).map_err(CollectionError)?;
    let homepage = fetcher.fetch(&homepage_url, ResourceKind::Homepage).await?;
    let html = homepage.text.clone();
    let parse_url = homepage_url.clone();
    let (base, candidates, script_limit_reached) =
        run_parser(deadline, move || parse_scripts(&html, &parse_url)).await?;
    let mut resources = Vec::new();
    let mut scripts = Vec::new();
    let mut fetched = BTreeMap::<String, Result<String, CollectionError>>::new();
    for (index, candidate) in candidates.into_iter().enumerate() {
        let mut reference = candidate.reference(index as u16);
        if candidate.invalid_attributes {
            reference.reason = Some("invalid_script_attributes".into());
        } else if !candidate.executable {
            reference.status = ScriptStatus::DataOnly;
            reference.reason = Some("non_executable_script_type".into());
        } else if let Some(src) = candidate.src {
            let resolved = base
                .as_ref()
                .ok_or(CollectionError("invalid_base_url"))
                .and_then(|base| {
                    base.join(&src)
                        .map_err(|_| CollectionError("invalid_script_url"))
                })
                .and_then(|url| approved_url(url.as_str(), &scope).map_err(CollectionError));
            let result = match resolved {
                Err(error) => Err(error),
                Ok(url) => {
                    reference.src = Some(url.to_string());
                    if let Some(result) = fetched.get(url.as_str()) {
                        result.clone()
                    } else {
                        let result = fetcher.fetch(&url, ResourceKind::ExternalScript).await.map(
                            |resource| {
                                let hash = resource.sha256.clone();
                                resources.push(resource);
                                hash
                            },
                        );
                        fetched.insert(url.to_string(), result.clone());
                        result
                    }
                }
            };
            match result {
                Ok(hash) => {
                    reference.status = ScriptStatus::Collected;
                    reference.artifact_sha256 = Some(hash);
                }
                Err(error) => reference.reason = Some(error.0.into()),
            }
        } else {
            // html5ever's script text is parsed text, not the raw HTTP bytes. The
            // original homepage hash preserves the exact source for comparison.
            let text = candidate.inline;
            if !valid_text(&text) {
                reference.reason = Some("unsupported_text".into());
            } else {
                let resource = WebsiteResource {
                    kind: ResourceKind::InlineScript,
                    url: format!("{}#patchriot-script-{index}", homepage_url),
                    sha256: digest(text.as_bytes()),
                    bytes: text.len() as u64,
                    content_type: "text/javascript".into(),
                    headers: BTreeMap::new(),
                    text,
                    collected_at: homepage.collected_at,
                    connected_ip: None,
                };
                reference.status = ScriptStatus::Collected;
                reference.artifact_sha256 = Some(resource.sha256.clone());
                resources.push(resource);
            }
        }
        scripts.push(reference);
    }
    Ok(WebsiteSnapshot {
        schema_version: 1,
        scope,
        homepage,
        resources,
        scripts,
        script_limit_reached,
        requests_made: fetcher.totals().0,
        captured_response_bytes: fetcher.totals().1 as u64,
        started_at,
        finished_at: crate::now(),
    })
}

struct Fetcher {
    deadline: Instant,
    requests: u16,
    captured_bytes: usize,
}

// A private test seam: production only constructs Fetcher, whose DNS and pinned
// transport checks cannot be disabled by a request or configuration switch.
trait Source {
    fn fetch(
        &mut self,
        url: &Url,
        kind: ResourceKind,
    ) -> impl std::future::Future<Output = Result<WebsiteResource, CollectionError>> + Send;
    fn totals(&self) -> (u16, usize);
}

impl Source for Fetcher {
    async fn fetch(
        &mut self,
        url: &Url,
        kind: ResourceKind,
    ) -> Result<WebsiteResource, CollectionError> {
        if Instant::now() >= self.deadline {
            return Err(CollectionError("collection_deadline"));
        }
        if self.requests >= MAX_REQUESTS {
            return Err(CollectionError("request_limit"));
        }
        let remaining = MAX_CAPTURED_BYTES.saturating_sub(self.captured_bytes);
        if remaining == 0 {
            return Err(CollectionError("saved_body_limit"));
        }
        let maximum = match kind {
            ResourceKind::Homepage => MAX_HOMEPAGE_BYTES,
            _ => MAX_SCRIPT_BYTES,
        }
        .min(remaining);
        let host = url.host_str().ok_or(CollectionError("invalid_hostname"))?;
        let addresses = timeout_at(self.deadline, resolve(host))
            .await
            .map_err(|_| CollectionError("collection_deadline"))??;
        let client = client_builder()
            .https_only(true)
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|_| CollectionError("http_client_failed"))?;
        self.requests += 1;
        let resource = timeout_at(self.deadline, async {
            let response = client
                .get(url.clone())
                .header(header::ACCEPT_ENCODING, "identity")
                .header(
                    header::ACCEPT,
                    if kind == ResourceKind::Homepage {
                        "text/html"
                    } else {
                        "text/javascript, application/javascript"
                    },
                )
                .send()
                .await
                .map_err(http_error)?;
            if !response
                .remote_addr()
                .is_some_and(|peer| addresses.contains(&peer))
            {
                return Err(CollectionError("unexpected_remote_address"));
            }
            read_response(response, url, kind, maximum).await
        })
        .await
        .map_err(|_| CollectionError("collection_deadline"))??;
        self.captured_bytes += resource.bytes as usize;
        Ok(resource)
    }

    fn totals(&self) -> (u16, usize) {
        (self.requests, self.captured_bytes)
    }
}

fn client_builder() -> reqwest::ClientBuilder {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .http1_only()
        .http1_max_headers(64)
        .pool_max_idle_per_host(0)
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(Duration::from_secs(3))
        .user_agent("Patchriot/0.0.1 (approved website snapshot)")
}

async fn resolve(host: &str) -> Result<Vec<SocketAddr>, CollectionError> {
    let addresses = timeout(Duration::from_secs(2), tokio::net::lookup_host((host, 443)))
        .await
        .map_err(|_| CollectionError("dns_timeout"))?
        .map_err(|_| CollectionError("dns_unavailable"))?;
    checked_addresses(addresses)
}

fn checked_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, CollectionError> {
    let mut checked = Vec::new();
    for address in addresses {
        if address.port() != 443 || !public_ip(address.ip()) {
            return Err(CollectionError("non_public_address"));
        }
        if !checked.contains(&address) {
            checked.push(address);
        }
        if checked.len() > 8 {
            return Err(CollectionError("too_many_dns_addresses"));
        }
    }
    if checked.is_empty() {
        return Err(CollectionError("dns_unavailable"));
    }
    Ok(checked)
}

async fn read_response(
    mut response: Response,
    url: &Url,
    kind: ResourceKind,
    maximum: usize,
) -> Result<WebsiteResource, CollectionError> {
    if response.status().is_redirection() {
        return Err(CollectionError("redirect_not_followed"));
    }
    if response.status() != reqwest::StatusCode::OK {
        return Err(CollectionError("unexpected_http_status"));
    }
    if response
        .headers()
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .any(|value| value.as_bytes() != b"identity")
    {
        return Err(CollectionError("encoded_body_not_supported"));
    }
    if response
        .headers()
        .get_all(header::CONTENT_TYPE)
        .iter()
        .count()
        != 1
    {
        return Err(CollectionError("unsupported_content_type"));
    }
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .filter(|value| content_type_allowed(value, kind))
        .ok_or(CollectionError("unsupported_content_type"))?
        .to_owned();
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(CollectionError("body_too_large"));
    }
    let headers = selected_headers(response.headers())?;
    let connected_ip = response
        .remote_addr()
        .map(|address| address.ip().to_string());
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(http_error)? {
        if chunk.len() > maximum.saturating_sub(body.len()) {
            return Err(CollectionError("body_too_large"));
        }
        body.extend_from_slice(&chunk);
    }
    let sha256 = digest(&body);
    let bytes = body.len() as u64;
    let text = String::from_utf8(body).map_err(|_| CollectionError("unsupported_text"))?;
    if !valid_text(&text) {
        return Err(CollectionError("unsupported_text"));
    }
    Ok(WebsiteResource {
        kind,
        url: url.to_string(),
        sha256,
        bytes,
        content_type,
        headers,
        text,
        collected_at: crate::now(),
        connected_ip,
    })
}

fn content_type_allowed(value: &str, kind: ResourceKind) -> bool {
    let mut parts = value.split(';');
    let mime = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    let accepted = match kind {
        ResourceKind::Homepage => mime == "text/html",
        _ => javascript_type(&mime),
    };
    accepted
        && parts.all(|parameter| {
            let Some((name, value)) = parameter.trim().split_once('=') else {
                return false;
            };
            !name.trim().eq_ignore_ascii_case("charset")
                || matches!(
                    value.trim().trim_matches('"').to_ascii_lowercase().as_str(),
                    "utf-8" | "utf8" | "us-ascii"
                )
        })
}

fn javascript_type(mime: &str) -> bool {
    matches!(
        mime,
        "text/javascript"
            | "application/javascript"
            | "application/x-javascript"
            | "text/ecmascript"
            | "application/ecmascript"
    )
}

fn selected_headers(
    headers: &header::HeaderMap,
) -> Result<BTreeMap<String, String>, CollectionError> {
    let mut result = BTreeMap::new();
    let mut total = 0;
    for name in [
        "content-type",
        "content-security-policy",
        "content-security-policy-report-only",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "cross-origin-embedder-policy",
    ] {
        let mut values = Vec::new();
        for value in headers.get_all(name) {
            let text = value
                .to_str()
                .map_err(|_| CollectionError("unsupported_response_headers"))?;
            total += text.len();
            if text.len() > 4096 || total > 16 * 1024 || text.chars().any(char::is_control) {
                return Err(CollectionError("unsupported_response_headers"));
            }
            values.push(text);
        }
        if !values.is_empty() {
            result.insert(name.to_owned(), values.join("\n"));
        }
    }
    Ok(result)
}

fn valid_text(text: &str) -> bool {
    !text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn http_error(error: reqwest::Error) -> CollectionError {
    CollectionError(if error.is_timeout() {
        "http_timeout"
    } else {
        "http_request_failed"
    })
}

struct Candidate {
    src: Option<String>,
    integrity: Option<String>,
    type_hint: Option<String>,
    inline: String,
    executable: bool,
    invalid_attributes: bool,
}

impl Candidate {
    fn reference(&self, index: u16) -> ScriptReference {
        ScriptReference {
            index,
            src: self.src.clone(),
            integrity: self.integrity.clone(),
            type_hint: self.type_hint.clone(),
            status: ScriptStatus::Skipped,
            artifact_sha256: None,
            reason: None,
        }
    }
}

type ParsedScripts = (Option<Url>, Vec<Candidate>, bool);

// Parsing must not stop API requests or the collection worker's lease checks.
// A timeout/cancellation stops waiting, but cannot interrupt a running blocking
// task. Keep its slot inside the task until it really finishes, so cancelled
// captures cannot accumulate CPU work. Only owned strings leave that thread.
async fn run_parser(
    deadline: Instant,
    parse: impl FnOnce() -> Result<ParsedScripts, CollectionError> + Send + 'static,
) -> Result<ParsedScripts, CollectionError> {
    if Instant::now() >= deadline {
        return Err(CollectionError("collection_deadline"));
    }
    let permit = timeout_at(deadline, HTML_PARSER_SLOT.acquire())
        .await
        .map_err(|_| CollectionError("collection_deadline"))?
        .map_err(|_| CollectionError("html_parser_unavailable"))?;
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if Instant::now() >= deadline {
            return Err(CollectionError("collection_deadline"));
        }
        parse()
    });
    timeout_at(deadline, task)
        .await
        .map_err(|_| CollectionError("collection_deadline"))?
        .map_err(|_| CollectionError("html_parse_failed"))?
}

fn parse_scripts(html: &str, homepage: &Url) -> Result<ParsedScripts, CollectionError> {
    // A small body can still contain thousands of unclosed, uniquely attributed
    // tags that make HTML tree building expensive. Count raw '<' bytes before
    // parsing; this deliberately includes comments and script text. Reject the
    // whole capture rather than returning a partially parsed security snapshot.
    if html
        .bytes()
        .filter(|byte| *byte == b'<')
        .take(MAX_HTML_MARKERS + 1)
        .count()
        > MAX_HTML_MARKERS
    {
        return Err(CollectionError("html_too_complex"));
    }
    let document = Html::parse_document(html);
    let base = document
        .select(&Selector::parse("base[href]").expect("static selector"))
        .next()
        .and_then(|element| element.attr("href"));
    let base = match base {
        None => Some(homepage.clone()),
        Some(base) if safe_attribute(base, MAX_URL_BYTES) => homepage.join(base).ok(),
        _ => None,
    };
    let selector = Selector::parse("script").expect("static selector");
    let mut elements = document.select(&selector);
    let candidates = elements
        .by_ref()
        .take(MAX_SCRIPTS)
        .map(|element| {
            let src = element.attr("src");
            let integrity = element.attr("integrity");
            let type_hint = element.attr("type");
            let mime = type_hint.unwrap_or("").trim().to_ascii_lowercase();
            let invalid_attributes = src
                .is_some_and(|src| src.is_empty() || !safe_attribute(src, MAX_URL_BYTES))
                || integrity.is_some_and(|value| !safe_attribute(value, 1024))
                || type_hint.is_some_and(|value| !safe_attribute(value, 128));
            Candidate {
                src: src.map(|text| bounded_attribute(text, MAX_URL_BYTES)),
                integrity: integrity.map(|text| bounded_attribute(text, 1024)),
                type_hint: type_hint.map(|text| bounded_attribute(text, 128)),
                inline: if src.is_none() {
                    element.text().collect()
                } else {
                    String::new()
                },
                executable: mime.is_empty()
                    || mime == "module"
                    || javascript_type(mime.split(';').next().unwrap_or("").trim()),
                invalid_attributes,
            }
        })
        .collect();
    Ok((base, candidates, elements.next().is_some()))
}

fn safe_attribute(text: &str, limit: usize) -> bool {
    text.len() <= limit && !text.chars().any(char::is_control) && !text.contains('\\')
}

fn bounded_attribute(text: &str, limit: usize) -> String {
    let end = text.floor_char_boundary(limit.min(text.len()));
    text[..end].chars().filter(|c| !c.is_control()).collect()
}

#[cfg(test)]
mod tests;
