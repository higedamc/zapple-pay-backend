//! NIP-98 HTTP authentication for the mutation endpoints.
//!
//! Every request that creates, updates or deletes user state must carry an
//! `Authorization: Nostr <base64(event)>` header holding a kind 27235 event
//! signed by the key that owns the state being touched. On top of the NIP-98
//! checks this fork also enforces a static allowlist of pubkeys (the instance
//! is private), so a valid signature from an unknown key is still rejected.
//!
//! The verifier is a pure function (`verify_nip98`) so it can be tested
//! without an HTTP stack; `nip98_auth` is the axum middleware wrapper that
//! buffers the body, runs the verifier and stores the authenticated pubkey as
//! a request extension (`AuthedPubkey`) for the handler.

use crate::State;
use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use bitcoin::hashes::{sha256, Hash};
use http_body_util::BodyExt;
use log::warn;
use nostr::nips::nip19::FromBech32;
use nostr::{
    Alphabet, Event, EventId, JsonUtil, Kind, PublicKey, SingleLetterTag, TagKind, Timestamp,
};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;

/// Maximum clock skew (in either direction) accepted on `created_at`.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;
/// Largest request body the auth layer will buffer for payload hashing.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Static configuration for NIP-98 verification. Built once at startup and
/// shared through [`State`].
pub struct Nip98Config {
    /// Externally visible base URL of this API (scheme + host [+ port]),
    /// e.g. `https://185-18-221-23.sslip.io`. The `u` tag must match
    /// `public_url + path[?query]` exactly.
    public_url: String,
    /// Keys allowed to mutate state. Empty allowlist = every mutation is
    /// rejected (fail closed).
    allowlist: HashSet<PublicKey>,
    /// Event ids seen inside the clock-skew window, for replay protection.
    seen: Mutex<HashMap<EventId, Timestamp>>,
}

impl fmt::Debug for Nip98Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nip98Config")
            .field("public_url", &self.public_url)
            .field("allowlist_len", &self.allowlist.len())
            .finish()
    }
}

impl Nip98Config {
    /// Parse config from CLI values. `allowed` entries may be `npub1…` or hex.
    pub fn new(public_url: &str, allowed: &[String]) -> anyhow::Result<Self> {
        let public_url = normalize_public_url(public_url)?;
        let mut allowlist = HashSet::new();
        for raw in allowed {
            let raw = raw.trim();
            let pk = PublicKey::from_bech32(raw)
                .or_else(|_| PublicKey::from_str(raw))
                .map_err(|_| anyhow::anyhow!("invalid --allowed-npub value: {raw}"))?;
            allowlist.insert(pk);
        }
        if allowlist.is_empty() {
            warn!("NIP-98 allowlist is empty: every mutation request will be rejected");
        }
        Ok(Self {
            public_url,
            allowlist,
            seen: Mutex::new(HashMap::new()),
        })
    }

    pub fn public_url(&self) -> &str {
        &self.public_url
    }

    pub fn is_allowed(&self, pk: &PublicKey) -> bool {
        self.allowlist.contains(pk)
    }

    /// Record `id` as used. Returns `false` if it was already seen inside the
    /// skew window (replay). Prunes expired entries on every call so the map
    /// stays bounded by the request rate within the window.
    fn remember(&self, id: EventId, created_at: Timestamp, now: Timestamp) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = now.as_secs().saturating_sub(MAX_CLOCK_SKEW_SECS);
        seen.retain(|_, ts| ts.as_secs() >= cutoff);
        seen.insert(id, created_at).is_none()
    }
}

/// Strip a trailing slash so `public_url + path` never double-slashes.
fn normalize_public_url(url: &str) -> anyhow::Result<String> {
    let parsed =
        nostr::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid --public-url {url:?}: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        anyhow::bail!("--public-url must be an absolute http(s) URL, got {url:?}");
    }
    Ok(url.trim_end_matches('/').to_string())
}

/// Why a request failed authentication. The `Display` text is what the client
/// sees; it never includes header contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    MissingHeader,
    MalformedHeader,
    InvalidEvent,
    WrongKind,
    BadSignature,
    Expired,
    UrlMismatch,
    MethodMismatch,
    PayloadMismatch,
    Replay,
    NotAllowed,
    BodyTooLarge,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::MissingHeader => "missing Authorization header",
            Self::MalformedHeader => "malformed Authorization header",
            Self::InvalidEvent => "invalid nostr event",
            Self::WrongKind => "event kind must be 27235",
            Self::BadSignature => "invalid event signature",
            Self::Expired => "event created_at outside allowed window",
            Self::UrlMismatch => "u tag does not match request URL",
            Self::MethodMismatch => "method tag does not match request method",
            Self::PayloadMismatch => "payload tag does not match request body",
            Self::Replay => "event already used",
            Self::NotAllowed => "pubkey not allowed on this instance",
            Self::BodyTooLarge => "request body too large",
        };
        f.write_str(s)
    }
}

impl AuthError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::NotAllowed => StatusCode::FORBIDDEN,
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            _ => StatusCode::UNAUTHORIZED,
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({"status": "ERROR", "reason": self.to_string()});
        (self.status(), axum::Json(body)).into_response()
    }
}

/// The pubkey that signed the NIP-98 event for this request. Inserted by
/// [`nip98_auth`]; handlers extract it with `Extension<AuthedPubkey>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthedPubkey(pub PublicKey);

/// Verify a NIP-98 `Authorization` header value against the request it
/// arrived with. On success returns the signer's pubkey.
///
/// `url` is the absolute URL the server believes it was reached at
/// (`public_url + path[?query]`), `method` the uppercase HTTP method and
/// `body` the raw request body (empty for body-less requests).
pub fn verify_nip98(
    config: &Nip98Config,
    header: Option<&str>,
    method: &str,
    url: &str,
    body: &[u8],
    now: Timestamp,
) -> Result<PublicKey, AuthError> {
    let header = header.ok_or(AuthError::MissingHeader)?;
    let (scheme, token) = header.split_once(' ').ok_or(AuthError::MalformedHeader)?;
    if !scheme.eq_ignore_ascii_case("nostr") {
        return Err(AuthError::MalformedHeader);
    }
    let json = base64_decode(token.trim()).ok_or(AuthError::MalformedHeader)?;
    let event = Event::from_json(json).map_err(|_| AuthError::InvalidEvent)?;

    if event.kind != Kind::HttpAuth {
        return Err(AuthError::WrongKind);
    }
    event.verify().map_err(|_| AuthError::BadSignature)?;

    let created = event.created_at.as_secs();
    let now_s = now.as_secs();
    if created.abs_diff(now_s) > MAX_CLOCK_SKEW_SECS {
        return Err(AuthError::Expired);
    }

    let mut tag_url: Option<String> = None;
    let mut tag_method: Option<String> = None;
    let mut tag_payload: Option<String> = None;
    // Raw tag values, compared as strings: the `u` tag must match the URL the
    // server was reached at byte for byte (no URL normalisation on either
    // side), exactly as before the nostr crate bump.
    for tag in event.tags.iter() {
        match tag.kind() {
            TagKind::SingleLetter(SingleLetterTag {
                character: Alphabet::U,
                uppercase: false,
            }) => tag_url = tag.content().map(str::to_string),
            TagKind::Method => tag_method = tag.content().map(str::to_string),
            TagKind::Payload => tag_payload = tag.content().map(str::to_string),
            _ => {}
        }
    }

    if tag_url.as_deref() != Some(url) {
        return Err(AuthError::UrlMismatch);
    }
    if tag_method.as_deref() != Some(method) {
        return Err(AuthError::MethodMismatch);
    }

    if body.is_empty() {
        // NIP-98: payload tag is optional without a body. If the client sent
        // one anyway it must still be the hash of what we received.
        if let Some(p) = tag_payload {
            if p != sha256_hex(body) {
                return Err(AuthError::PayloadMismatch);
            }
        }
    } else {
        match tag_payload {
            Some(p) if p == sha256_hex(body) => {}
            _ => return Err(AuthError::PayloadMismatch),
        }
    }

    // Allowlist before the replay cache so unknown keys never occupy it.
    let pubkey = event.pubkey;
    if !config.is_allowed(&pubkey) {
        return Err(AuthError::NotAllowed);
    }

    if !config.remember(event.id, event.created_at, now) {
        return Err(AuthError::Replay);
    }

    Ok(pubkey)
}

fn sha256_hex(bytes: &[u8]) -> String {
    sha256::Hash::hash(bytes).to_string()
}

/// Standard base64 (with or without padding). Done by hand to avoid pulling
/// a second `base64` major version into the tree.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u8;
    for &c in s {
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Return `Ok` only if the authenticated key is the owner of the resource
/// addressed by `npub`. Used by every handler behind the auth layer so a
/// valid key can never touch another user's config.
pub fn require_owner(auth: &AuthedPubkey, npub: &PublicKey) -> Result<(), (StatusCode, String)> {
    if &auth.0 == npub {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Authenticated key does not own this resource\"}"),
        ))
    }
}

/// axum middleware: buffer the body (bounded), verify NIP-98 + allowlist,
/// then forward the request with the body restored and `AuthedPubkey` set.
pub async fn nip98_auth(Extension(state): Extension<State>, req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();

    let body_bytes = match read_body(body).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };

    let header = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", state.auth.public_url(), path_and_query);

    let pubkey = match verify_nip98(
        &state.auth,
        header,
        parts.method.as_str(),
        &url,
        &body_bytes,
        Timestamp::now(),
    ) {
        Ok(pk) => pk,
        Err(e) => {
            warn!("NIP-98 rejected {} {}: {e}", parts.method, parts.uri.path());
            return e.into_response();
        }
    };

    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.extensions_mut().insert(AuthedPubkey(pubkey));
    next.run(req).await
}

async fn read_body(mut body: Body) -> Result<Bytes, AuthError> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| AuthError::MalformedHeader)?;
        if let Ok(chunk) = frame.into_data() {
            if buf.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(AuthError::BodyTooLarge);
            }
            buf.extend_from_slice(&chunk);
        }
    }
    Ok(Bytes::from(buf))
}

/// Test-only helpers shared with the router tests in `routes.rs`.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use nostr::nips::nip98::{HttpData, HttpMethod};
    use nostr::{EventBuilder, Keys, Url};

    pub(crate) fn b64(bytes: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    /// Build a signed NIP-98 header for `method url` with optional body hash.
    pub(crate) fn header(
        keys: &Keys,
        method: HttpMethod,
        url: &str,
        body: Option<&[u8]>,
        at: Timestamp,
    ) -> String {
        let mut data = HttpData::new(Url::parse(url).unwrap(), method);
        if let Some(b) = body {
            data = data.payload(sha256::Hash::hash(b));
        }
        let event = EventBuilder::http_auth(data)
            .custom_created_at(at)
            .sign_with_keys(keys)
            .unwrap();
        format!("Nostr {}", b64(event.as_json().as_bytes()))
    }
}

#[cfg(test)]
mod test {
    use super::test_support::{b64, header};
    use super::*;
    use nostr::nips::nip98::{HttpData, HttpMethod};
    use nostr::{EventBuilder, Keys, Tag, Url};

    const PUBLIC_URL: &str = "https://185-18-221-23.sslip.io";

    fn config_for(keys: &[&Keys]) -> Nip98Config {
        let allowed: Vec<String> = keys.iter().map(|k| k.public_key().to_string()).collect();
        Nip98Config::new(PUBLIC_URL, &allowed).unwrap()
    }

    #[test]
    fn base64_roundtrip() {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar", "{\"a\":1}"] {
            assert_eq!(
                base64_decode(&b64(s.as_bytes())).unwrap(),
                s.as_bytes(),
                "{s}"
            );
        }
        assert!(base64_decode("not base64!").is_none());
    }

    #[test]
    fn accepts_valid_post_with_body() {
        let keys = Keys::generate();
        let cfg = config_for(&[&keys]);
        let now = Timestamp::now();
        let url = format!("{PUBLIC_URL}/set-user");
        let body = br#"{"npub":"x","amount_sats":21}"#;
        let h = header(&keys, HttpMethod::POST, &url, Some(body), now);
        let pk = verify_nip98(&cfg, Some(&h), "POST", &url, body, now).unwrap();
        assert_eq!(pk, keys.public_key());
    }

    #[test]
    fn accepts_valid_post_without_body() {
        let keys = Keys::generate();
        let cfg = config_for(&[&keys]);
        let now = Timestamp::now();
        let url = format!("{PUBLIC_URL}/delete-user/{}", keys.public_key());
        let h = header(&keys, HttpMethod::POST, &url, None, now);
        assert!(verify_nip98(&cfg, Some(&h), "POST", &url, b"", now).is_ok());
    }

    #[test]
    fn rejects_missing_and_malformed_header() {
        let keys = Keys::generate();
        let cfg = config_for(&[&keys]);
        let now = Timestamp::now();
        let url = format!("{PUBLIC_URL}/set-user");
        assert_eq!(
            verify_nip98(&cfg, None, "POST", &url, b"", now),
            Err(AuthError::MissingHeader)
        );
        assert_eq!(
            verify_nip98(&cfg, Some("Bearer abc"), "POST", &url, b"", now),
            Err(AuthError::MalformedHeader)
        );
        assert_eq!(
            verify_nip98(&cfg, Some("Nostr !!!"), "POST", &url, b"", now),
            Err(AuthError::MalformedHeader)
        );
        assert_eq!(
            verify_nip98(
                &cfg,
                Some(&format!("Nostr {}", b64(b"{}"))),
                "POST",
                &url,
                b"",
                now
            ),
            Err(AuthError::InvalidEvent)
        );
    }

    #[test]
    fn rejects_wrong_kind() {
        let keys = Keys::generate();
        let cfg = config_for(&[&keys]);
        let now = Timestamp::now();
        let url = format!("{PUBLIC_URL}/set-user");
        let data = HttpData::new(Url::parse(&url).unwrap(), HttpMethod::POST);
        let tags: Vec<Tag> = data.into();
        let event = EventBuilder::new(Kind::TextNote, "")
            .tags(tags)
            .custom_created_at(now)
            .sign_with_keys(&keys)
            .unwrap();
        let h = format!("Nostr {}", b64(event.as_json().as_bytes()));
        assert_eq!(
            verify_nip98(&cfg, Some(&h), "POST", &url, b"", now),
            Err(AuthError::WrongKind)
        );
    }

    #[test]
    fn rejects_tampered_signature() {
        let keys = Keys::generate();
        let cfg = config_for(&[&keys]);
        let now = Timestamp::now();
        let url = format!("{PUBLIC_URL}/set-user");
        let data = HttpData::new(Url::parse(&url).unwrap(), HttpMethod::POST);
        let event = EventBuilder::http_auth(data)
            .custom_created_at(now)
            .sign_with_keys(&keys)
            .unwrap();
        // Flip the content after signing: id/sig no longer match.
        let mut v: serde_json::Value = serde_json::from_str(&event.as_json()).unwrap();
        v["content"] = serde_json::Value::String("tampered".into());
        let h = format!("Nostr {}", b64(v.to_string().as_bytes()));
        assert_eq!(
            verify_nip98(&cfg, Some(&h), "POST", &url, b"", now),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn rejects_stale_and_future_events() {
        let keys = Keys::generate();
        let cfg = config_for(&[&keys]);
        let now = Timestamp::now();
        let url = format!("{PUBLIC_URL}/set-user");
        let old = Timestamp::from_secs(now.as_secs() - MAX_CLOCK_SKEW_SECS - 1);
        let h = header(&keys, HttpMethod::POST, &url, None, old);
        assert_eq!(
            verify_nip98(&cfg, Some(&h), "POST", &url, b"", now),
            Err(AuthError::Expired)
        );
        let future = Timestamp::from_secs(now.as_secs() + MAX_CLOCK_SKEW_SECS + 1);
        let h = header(&keys, HttpMethod::POST, &url, None, future);
        assert_eq!(
            verify_nip98(&cfg, Some(&h), "POST", &url, b"", now),
            Err(AuthError::Expired)
        );
        // Edge: exactly at the boundary is still accepted.
        let edge = Timestamp::from_secs(now.as_secs() - MAX_CLOCK_SKEW_SECS);
        let h = header(&keys, HttpMethod::POST, &url, None, edge);
        assert!(verify_nip98(&cfg, Some(&h), "POST", &url, b"", now).is_ok());
    }

    #[test]
    fn rejects_url_and_method_mismatch() {
        let keys = Keys::generate();
        let cfg = config_for(&[&keys]);
        let now = Timestamp::now();
        let url = format!("{PUBLIC_URL}/delete-user/{}", keys.public_key());
        // Signed for a different path (another user's delete).
        let other = format!("{PUBLIC_URL}/delete-user/{}", Keys::generate().public_key());
        let h = header(&keys, HttpMethod::POST, &other, None, now);
        assert_eq!(
            verify_nip98(&cfg, Some(&h), "POST", &url, b"", now),
            Err(AuthError::UrlMismatch)
        );
        // Signed for the same path on a different host.
        let h = header(
            &keys,
            HttpMethod::POST,
            &url.replace("https://185-18-221-23.sslip.io", "https://evil.example"),
            None,
            now,
        );
        assert_eq!(
            verify_nip98(&cfg, Some(&h), "POST", &url, b"", now),
            Err(AuthError::UrlMismatch)
        );
        // Right URL, signed for GET, sent as POST.
        let h = header(&keys, HttpMethod::GET, &url, None, now);
        assert_eq!(
            verify_nip98(&cfg, Some(&h), "POST", &url, b"", now),
            Err(AuthError::MethodMismatch)
        );
    }

    #[test]
    fn rejects_payload_mismatch() {
        let keys = Keys::generate();
        let cfg = config_for(&[&keys]);
        let now = Timestamp::now();
        let url = format!("{PUBLIC_URL}/set-user");
        // Body present but no payload tag.
        let h = header(&keys, HttpMethod::POST, &url, None, now);
        assert_eq!(
            verify_nip98(&cfg, Some(&h), "POST", &url, b"{\"a\":1}", now),
            Err(AuthError::PayloadMismatch)
        );
        // Payload tag for a different body (body swapped in transit).
        let h = header(
            &keys,
            HttpMethod::POST,
            &url,
            Some(b"{\"amount_sats\":1}"),
            now,
        );
        assert_eq!(
            verify_nip98(
                &cfg,
                Some(&h),
                "POST",
                &url,
                b"{\"amount_sats\":1000000}",
                now
            ),
            Err(AuthError::PayloadMismatch)
        );
    }

    #[test]
    fn rejects_key_outside_allowlist() {
        let allowed = Keys::generate();
        let stranger = Keys::generate();
        let cfg = config_for(&[&allowed]);
        let now = Timestamp::now();
        let url = format!("{PUBLIC_URL}/set-user");
        let h = header(&stranger, HttpMethod::POST, &url, None, now);
        assert_eq!(
            verify_nip98(&cfg, Some(&h), "POST", &url, b"", now),
            Err(AuthError::NotAllowed)
        );
    }

    #[test]
    fn empty_allowlist_rejects_everyone() {
        let keys = Keys::generate();
        let cfg = Nip98Config::new(PUBLIC_URL, &[]).unwrap();
        let now = Timestamp::now();
        let url = format!("{PUBLIC_URL}/set-user");
        let h = header(&keys, HttpMethod::POST, &url, None, now);
        assert_eq!(
            verify_nip98(&cfg, Some(&h), "POST", &url, b"", now),
            Err(AuthError::NotAllowed)
        );
    }

    #[test]
    fn rejects_replay_within_window() {
        let keys = Keys::generate();
        let cfg = config_for(&[&keys]);
        let now = Timestamp::now();
        let url = format!("{PUBLIC_URL}/set-user");
        let h = header(&keys, HttpMethod::POST, &url, None, now);
        assert!(verify_nip98(&cfg, Some(&h), "POST", &url, b"", now).is_ok());
        assert_eq!(
            verify_nip98(&cfg, Some(&h), "POST", &url, b"", now),
            Err(AuthError::Replay)
        );
        // After the window has passed the id is pruned and the event is
        // rejected as expired, not replayed; either way it cannot be reused.
        let later = Timestamp::from_secs(now.as_secs() + MAX_CLOCK_SKEW_SECS + 1);
        assert_eq!(
            verify_nip98(&cfg, Some(&h), "POST", &url, b"", later),
            Err(AuthError::Expired)
        );
    }

    #[test]
    fn allowlist_accepts_npub_and_hex() {
        let keys = Keys::generate();
        let npub = nostr::ToBech32::to_bech32(&keys.public_key()).unwrap();
        let cfg = Nip98Config::new(PUBLIC_URL, &[npub]).unwrap();
        assert!(cfg.is_allowed(&keys.public_key()));
        let cfg = Nip98Config::new(PUBLIC_URL, &[keys.public_key().to_string()]).unwrap();
        assert!(cfg.is_allowed(&keys.public_key()));
        assert!(Nip98Config::new(PUBLIC_URL, &["nonsense".to_string()]).is_err());
    }

    #[test]
    fn public_url_validation() {
        assert_eq!(
            Nip98Config::new("https://x.example/", &[])
                .unwrap()
                .public_url(),
            "https://x.example"
        );
        assert!(Nip98Config::new("x.example", &[]).is_err());
        assert!(Nip98Config::new("ftp://x.example", &[]).is_err());
    }

    #[test]
    fn require_owner_matches_only_same_key() {
        let a = Keys::generate().public_key();
        let b = Keys::generate().public_key();
        assert!(require_owner(&AuthedPubkey(a), &a).is_ok());
        let err = require_owner(&AuthedPubkey(a), &b).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn errors_never_echo_header_contents() {
        for e in [
            AuthError::MissingHeader,
            AuthError::MalformedHeader,
            AuthError::InvalidEvent,
            AuthError::WrongKind,
            AuthError::BadSignature,
            AuthError::Expired,
            AuthError::UrlMismatch,
            AuthError::MethodMismatch,
            AuthError::PayloadMismatch,
            AuthError::Replay,
            AuthError::NotAllowed,
            AuthError::BodyTooLarge,
        ] {
            let s = e.to_string();
            assert!(!s.is_empty());
            assert!(s.is_ascii());
        }
    }
}
