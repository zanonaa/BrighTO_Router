//! OAuth flows: authorize, device code, token exchange, refresh.
//!
//! All three providers are driven from `OAuthProviderSpec`, so this module contains the flow
//! machinery exactly once. A provider differs only in its table row.
//!
//! Only the admin Portal and the background refresh loop call into this module. The proxy
//! never does: by the time a request is forwarded, `DbConfigLoader` has already turned a
//! credential reference into a plain access token held in `ConfigSnapshot`.

use std::time::Duration;

use dashmap::DashMap;
use serde::Deserialize;

use super::{BodyEncoding, OAuthFlow, OAuthProviderSpec, OAuthToken};

/// How long an unfinished authorize/device flow stays valid.
const FLOW_TTL_SECS: i64 = 15 * 60;

/// In-flight authorize or device-code flow, keyed by the `state` we generated.
///
/// Lives in a process-global map rather than the database: a flow that is abandoned mid-way
/// must not outlive a restart, and holding `state` is what binds a pasted callback to the
/// PKCE verifier we issued.
#[derive(Debug, Clone)]
pub struct PendingFlow {
    pub provider: String,
    pub code_verifier: String,
    pub created_at: i64,
    /// RFC 8628 device code, for flows that started as a device grant.
    pub device_code: Option<String>,
    pub poll_interval_secs: u64,
    pub verification_uri: Option<String>,
}

static FLOWS: std::sync::OnceLock<DashMap<String, PendingFlow>> = std::sync::OnceLock::new();

fn flows() -> &'static DashMap<String, PendingFlow> {
    FLOWS.get_or_init(DashMap::new)
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// Begin an OAuth flow. Returns the `state` the operator hands back with the callback.
///
/// `requested_state` adopts an id the Portal generated client-side, which the device-code flow
/// needs: the Portal polls `/complete` with that id and has to find the device code recorded
/// here. It is used for correlation only — the PKCE verifier generated below is what actually
/// protects the exchange — so a caller cannot borrow an existing flow's protection by guessing
/// its state, since adopting an id discards whatever was stored under it.
///
/// A malformed or oversized id is replaced by a fresh random one rather than rejected, so a
/// client bug cannot wedge the flow.
pub fn begin_flow(
    spec: &'static OAuthProviderSpec,
    requested_state: Option<&str>,
) -> (String, PendingFlow) {
    let state = requested_state
        .map(str::trim)
        .filter(|s| is_wellformed_flow_id(s))
        .map(str::to_string)
        .unwrap_or_else(|| random_urlsafe(32));
    let flow = PendingFlow {
        provider: spec.key.to_string(),
        code_verifier: random_urlsafe(64),
        created_at: now_secs(),
        device_code: None,
        poll_interval_secs: 5,
        verification_uri: None,
    };
    flows().insert(state.clone(), flow.clone());
    (state, flow)
}

/// A flow id is our own opaque handle: no separators, no whitespace, bounded length.
///
/// Constrained because the id becomes a `DashMap` key and is echoed in admin responses. A
/// 4 KiB "id" would be memory an unauthenticated-but-CIDR-allowed caller could allocate on every
/// request; an id with `:` or `/` in it would collide with the credential-reference grammar.
fn is_wellformed_flow_id(candidate: &str) -> bool {
    candidate.len() >= 16
        && candidate.len() <= 128
        && candidate
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Consume a flow. Single-use by design: a `state` must not be replayable, or a captured
/// callback could be replayed against a verifier the router has already retired.
pub fn take_flow(state: &str) -> Option<PendingFlow> {
    prune_expired();
    flows().remove(state).map(|(_, flow)| flow)
}

pub fn peek_flow(state: &str) -> Option<PendingFlow> {
    prune_expired();
    flows().get(state).map(|f| f.clone())
}

pub fn update_flow(state: &str, patch: impl FnOnce(&mut PendingFlow)) -> bool {
    prune_expired();
    if let Some(mut f) = flows().get_mut(state) {
        patch(f.value_mut());
        return true;
    }
    false
}

/// Drop flows that can no longer be completed. Called on every flow entry so an abandoned
/// authorize URL does not sit in memory forever.
fn prune_expired() {
    let cutoff = now_secs() - FLOW_TTL_SECS;
    flows().retain(|_, f| f.created_at > cutoff);
}

pub fn pending_flow_count() -> usize {
    flows().len()
}

// ===== Authorize URL =====

/// Build the URL the operator opens in a browser.
pub fn authorize_url(spec: &'static OAuthProviderSpec, state: &str) -> String {
    let mut url = format!(
        "{}?code_challenge={}&code_challenge_method=S256&client_id={}&response_type=code&state={}",
        spec.authorize_url,
        percent_encode(&pkce_challenge(&flow_verifier(state))),
        percent_encode(spec.client_id),
        percent_encode(state),
    );
    if !spec.scope.is_empty() {
        url.push_str(&format!("&scope={}", percent_encode(spec.scope)));
    }
    if !spec.redirect_uri.is_empty() {
        url.push_str(&format!(
            "&redirect_uri={}",
            percent_encode(spec.redirect_uri)
        ));
    }
    for (k, v) in spec.extra_authorize_params {
        url.push_str(&format!("&{k}={}", percent_encode(v)));
    }
    url
}

fn flow_verifier(state: &str) -> String {
    flows()
        .get(state)
        .map(|f| f.code_verifier.clone())
        .unwrap_or_default()
}

// ===== Token endpoint =====

/// Token endpoint response. Field names vary slightly by provider, so both spellings are
/// accepted rather than failing an otherwise valid login.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default, alias = "accessToken", alias = "access_token")]
    access: String,
    #[serde(default, alias = "refreshToken", alias = "refresh_token")]
    refresh: Option<String>,
    #[serde(default, alias = "idToken", alias = "id_token")]
    id_token: Option<String>,
    #[serde(default, alias = "expiresIn", alias = "expires_in")]
    expires_in: Option<i64>,
    #[serde(default, alias = "scope", alias = "scopes")]
    scope: Option<String>,
    #[serde(default, alias = "email")]
    email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    #[serde(default, alias = "device_code")]
    device_code: String,
    #[serde(default, alias = "user_code")]
    user_code: String,
    #[serde(default, alias = "verification_uri")]
    verification_uri: Option<String>,
    #[serde(default, alias = "verification_uri_complete")]
    verification_uri_complete: Option<String>,
    /// RFC 8628 poll interval, in seconds. Optional and independent of `expires_in`, so it needs
    /// its own field: sharing one would let a provider's device-code lifetime be read as its poll
    /// interval (or the reverse), and the two differ by an order of magnitude.
    #[serde(default, alias = "interval")]
    poll_interval_secs: Option<u64>,
    /// How long the device code stays usable. Not currently used for a deadline — a flow older
    /// than `FLOW_TTL_SECS` is already pruned — but parsed so a malformed response is still
    /// rejected rather than half-accepted.
    #[serde(default, alias = "expires_in")]
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

/// Errors the device flow reports while the operator is still approving.
const DEVICE_PENDING: &[&str] = &["authorization_pending", "slow_down", "pending"];

#[derive(Debug, PartialEq, Eq)]
pub enum FlowError {
    /// Operator has not approved yet; caller should poll again.
    AuthorizationPending,
    /// Retryable provider or transport failure.
    Transient(String),
    /// Credential can never be recovered; the operator must reconnect.
    NeedsReconnect(String),
    /// Malformed request from the Portal.
    BadRequest(String),
}

impl FlowError {
    pub fn message(&self) -> String {
        match self {
            Self::AuthorizationPending => "authorization_pending".into(),
            Self::Transient(m) | Self::NeedsReconnect(m) | Self::BadRequest(m) => m.clone(),
        }
    }

    /// Whether the caller may usefully try the exact same request again. Device-code polling
    /// says yes for "not approved yet"; everything else says no until the operator intervenes.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::AuthorizationPending | Self::Transient(_))
    }

    pub fn status_code(&self) -> u16 {
        match self {
            Self::AuthorizationPending => 202,
            Self::BadRequest(_) => 400,
            Self::NeedsReconnect(_) => 409,
            Self::Transient(_) => 502,
        }
    }
}

/// Exchange an authorization code for a token.
pub async fn exchange_code(
    client: &reqwest::Client,
    spec: &'static OAuthProviderSpec,
    state: &str,
    code: &str,
) -> Result<OAuthToken, FlowError> {
    let flow = take_flow(state).ok_or_else(|| {
        FlowError::BadRequest("unknown or expired OAuth state; start the flow again".into())
    })?;
    if flow.provider != spec.key {
        return Err(FlowError::BadRequest(
            "OAuth state does not belong to this provider".into(),
        ));
    }
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code.trim()),
        ("redirect_uri", spec.redirect_uri),
        ("client_id", spec.client_id),
        ("code_verifier", &flow.code_verifier),
    ];
    form.push(("scope", spec.scope));
    let body = post_token(client, spec, &form).await?;
    Ok(build_token(spec, body, None))
}

/// Start a device-code grant and record the device code against `state`.
pub async fn request_device_code(
    client: &reqwest::Client,
    spec: &'static OAuthProviderSpec,
    state: &str,
) -> Result<DeviceAuthorization, FlowError> {
    let Some(url) = spec.device_code_url else {
        return Err(FlowError::BadRequest(format!(
            "{} does not support the device-code flow",
            spec.key
        )));
    };
    let form: Vec<(&str, &str)> = vec![("client_id", spec.client_id), ("scope", spec.scope)];
    let resp = client
        .post(url)
        .timeout(Duration::from_secs(20))
        .header(reqwest::header::ACCEPT, "application/json")
        .body(encode_form(&form))
        .send()
        .await
        .map_err(|e| FlowError::Transient(format!("device code request failed: {e}")))?;
    let status = resp.status().as_u16();
    let text = resp
        .text()
        .await
        .map_err(|e| FlowError::Transient(format!("device code read failed: {e}")))?;
    if !(200..300).contains(&status) {
        return Err(classify(&text, status));
    }
    let parsed: DeviceCodeResponse = serde_json::from_str(&text)
        .map_err(|e| FlowError::Transient(format!("device code response malformed: {e}")))?;
    if parsed.device_code.is_empty() {
        return Err(FlowError::Transient(
            "device code response had no device_code".into(),
        ));
    }
    let interval = parsed.poll_interval_secs.unwrap_or(5).clamp(1, 30);
    update_flow(state, |f| {
        f.device_code = Some(parsed.device_code.clone());
        f.poll_interval_secs = interval;
        f.verification_uri = parsed.verification_uri.clone();
    });
    Ok(DeviceAuthorization {
        user_code: parsed.user_code,
        // Prefer the pre-filled URI: it encodes the user code, so the operator types nothing.
        verification_uri: parsed
            .verification_uri_complete
            .clone()
            .or(parsed.verification_uri)
            .unwrap_or_default(),
        verification_uri_complete: parsed.verification_uri_complete,
        interval_secs: interval,
    })
}

pub struct DeviceAuthorization {
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub interval_secs: u64,
}

/// Poll the device-code grant. `AuthorizationPending` is not an error the operator sees.
pub async fn poll_device_code(
    client: &reqwest::Client,
    spec: &'static OAuthProviderSpec,
    state: &str,
) -> Result<OAuthToken, FlowError> {
    let Some(flow) = peek_flow(state) else {
        return Err(FlowError::BadRequest(
            "unknown or expired device flow; start again".into(),
        ));
    };
    let Some(device_code) = flow.device_code.clone() else {
        return Err(FlowError::BadRequest(
            "device flow was never started".into(),
        ));
    };
    let form: Vec<(&str, &str)> = vec![
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", &device_code),
        ("client_id", spec.client_id),
    ];
    let body = post_token(client, spec, &form).await?;
    flows().remove(state);
    Ok(build_token(spec, body, None))
}

/// Refresh one credential and return the replaced token.
///
/// The caller is responsible for calling this at most once per credential at a time: Codex
/// rotates its refresh token, so two concurrent refreshes would present a spent token and log
/// the credential out. `RefreshCoordinator` enforces that.
pub async fn refresh_token(
    client: &reqwest::Client,
    spec: &'static OAuthProviderSpec,
    token: &OAuthToken,
) -> Result<OAuthToken, FlowError> {
    let Some(refresh) = token.refresh_token.as_deref().filter(|r| !r.is_empty()) else {
        return Err(FlowError::NeedsReconnect(
            "credential has no refresh token; reconnect the account".into(),
        ));
    };
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh),
        ("client_id", spec.client_id),
    ];
    if !spec.redirect_uri.is_empty() {
        form.push(("redirect_uri", spec.redirect_uri));
    }
    if !spec.scope.is_empty() {
        form.push(("scope", spec.scope));
    }
    let body = post_token(client, spec, &form).await?;
    // A refresh response usually omits the refresh token, meaning "keep using the old one".
    let rotated = body
        .refresh
        .clone()
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| refresh.to_string());
    let mut next = build_token(spec, body, Some(token));
    next.refresh_token = Some(rotated);
    Ok(next)
}

async fn post_token(
    client: &reqwest::Client,
    spec: &'static OAuthProviderSpec,
    form: &[(&str, &str)],
) -> Result<TokenResponse, FlowError> {
    let request = client
        .post(spec.token_url)
        .timeout(Duration::from_secs(20))
        .header(reqwest::header::ACCEPT, "application/json");
    // Encoding is not cosmetic: Claude's token endpoint expects a JSON body, Codex's expects
    // form encoding, and sending the wrong one fails the exchange.
    let request = match spec.body_encoding {
        BodyEncoding::Form => request
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(encode_form(form)),
        BodyEncoding::Json => {
            let mut payload = serde_json::Map::with_capacity(form.len());
            for (k, v) in form {
                payload.insert(
                    (*k).to_string(),
                    serde_json::Value::String((*v).to_string()),
                );
            }
            request.json(&payload)
        }
    };
    let resp = request
        .send()
        .await
        .map_err(|e| FlowError::Transient(format!("token request failed: {e}")))?;
    let status = resp.status().as_u16();
    let text = resp
        .text()
        .await
        .map_err(|e| FlowError::Transient(format!("token response read failed: {e}")))?;
    if !(200..300).contains(&status) {
        return Err(classify(&text, status));
    }
    serde_json::from_str::<TokenResponse>(&text)
        .map_err(|e| FlowError::Transient(format!("token response malformed: {e}")))
}

/// Turn a token-endpoint failure into a retry decision.
fn classify(body: &str, status: u16) -> FlowError {
    let raw = format!("HTTP {status}: {}", body.trim());
    let lowered = body.to_ascii_lowercase();
    if DEVICE_PENDING.iter().any(|m| lowered.contains(m)) {
        return FlowError::AuthorizationPending;
    }
    if super::is_terminal_refresh_error(body) {
        return FlowError::NeedsReconnect(raw);
    }
    if status == 400 && lowered.contains("expired_token") {
        return FlowError::NeedsReconnect(raw);
    }
    if status == 429 || status >= 500 {
        return FlowError::Transient(raw);
    }
    FlowError::Transient(raw)
}

fn build_token(
    spec: &'static OAuthProviderSpec,
    body: TokenResponse,
    previous: Option<&OAuthToken>,
) -> OAuthToken {
    if body.access.is_empty() {
        // Keep whatever we had so a sparse refresh response cannot blank a working credential.
        if let Some(prev) = previous {
            return prev.clone();
        }
    }
    let account_id = extract_account_id(body.id_token.as_deref(), &body.access)
        .or_else(|| previous.and_then(|p| p.account_id.clone()));
    let email = body
        .email
        .clone()
        .or_else(|| extract_email(body.id_token.as_deref()))
        .or_else(|| previous.and_then(|p| p.account_name.clone()));
    let label = super::account_label(email.as_deref(), account_id.as_deref());
    let ttl = body.expires_in.unwrap_or(3600).clamp(60, 30 * 24 * 3600);
    OAuthToken {
        provider: spec.key.to_string(),
        label,
        account_id,
        account_name: email,
        access_token: body.access,
        refresh_token: body.refresh.filter(|r| !r.is_empty()),
        expires_at: now_secs() + ttl,
        scopes: body
            .scope
            .or_else(|| previous.and_then(|p| p.scopes.clone())),
        refreshed_at: now_secs(),
    }
}

/// Read the ChatGPT account id that `chatgpt.com/backend-api` requires on every request.
///
/// Prefers the `chatgpt_account_id` claim in the `id_token`, then falls back to
/// `organizations[0].id` inside the access token, because OpenAI has shipped both.
fn extract_account_id(id_token: Option<&str>, access: &str) -> Option<String> {
    if let Some(claims) = id_token.and_then(jwt_claims)
        && let Some(v) = claims.get("chatgpt_account_id").and_then(|v| v.as_str())
    {
        return Some(v.to_string());
    }
    for raw in [id_token, Some(access)].into_iter().flatten() {
        let Some(claims) = jwt_claims(raw) else {
            continue;
        };
        if let Some(id) = claims.get("chatgpt_account_id").and_then(|v| v.as_str()) {
            return Some(id.to_string());
        }
        if let Some(id) = claims
            .get("organizations")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|o| o.get("id"))
            .and_then(|v| v.as_str())
        {
            return Some(id.to_string());
        }
    }
    None
}

fn extract_email(id_token: Option<&str>) -> Option<String> {
    id_token.and_then(jwt_claims).and_then(|claims| {
        claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    })
}

/// Decode a JWT payload without verifying the signature.
///
/// Safe here by construction: the token was just received over TLS directly from the
/// provider's token endpoint, so it is not attacker-controlled input. Nothing in this file
/// makes an authorization decision from these claims.
fn jwt_claims(token: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let payload = token.split('.').nth(1)?;
    let raw = base64url_decode(payload)?;
    serde_json::from_slice::<serde_json::Value>(&raw)
        .ok()
        .and_then(|v| v.as_object().cloned())
}

// ===== Encoding helpers =====

/// PKCE S256 challenge: base64url(SHA-256(verifier)) without padding.
pub fn pkce_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    base64url_encode(&Sha256::digest(verifier.as_bytes()))
}

/// Cryptographically random, URL-safe, unpadded base64 — used for the PKCE verifier and the
/// `state` that binds a pasted callback to the flow we issued.
fn random_urlsafe(bytes: usize) -> String {
    use rand::RngExt as _;
    let mut buf = vec![0u8; bytes];
    rand::rng().fill(&mut buf);
    base64url_encode(&buf)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[n as usize & 63] as char);
        }
    }
    out
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = B64.iter().position(|b| *b == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// `application/x-www-form-urlencoded` for the token endpoint.
///
/// Written out rather than pulled from a feature flag: the two providers that need it post
/// form-encoded bodies, and `Cargo.toml` pins reqwest's features deliberately.
fn encode_form(form: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (k, v) in form {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&percent_encode(k));
        out.push('=');
        out.push_str(&percent_encode(v));
    }
    out
}

/// Percent-encode everything outside the unreserved set, including `+` and space.
///
/// `application/x-www-form-urlencoded` treats `+` as a space, so it must be escaped or a scope
/// such as `user:profile user:inference` silently arrives with spaces where spaces belong and
/// colons stripped.
fn percent_encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// True when a provider uses the device-code flow. Exposed for the Portal hint.
pub fn is_device_flow(spec: &OAuthProviderSpec) -> bool {
    spec.flow == OAuthFlow::DeviceCode
}

#[cfg(test)]
mod tests {
    use super::super::spec;
    use super::*;

    fn claude() -> &'static OAuthProviderSpec {
        spec("claude-code").unwrap()
    }
    fn codex() -> &'static OAuthProviderSpec {
        spec("codex").unwrap()
    }

    #[test]
    fn a_device_flow_adopts_the_id_the_portal_will_poll_with() {
        // The device flow has no redirect URL to read a state out of, so the Portal generates the
        // id first and polls `/complete` with it. If `begin_flow` minted its own key instead, the
        // poll would find nothing and the login could never complete.
        let wanted = "portal_generated_flow_id_0001";
        let (id, flow) = begin_flow(codex(), Some(wanted));
        assert_eq!(id, wanted);
        assert!(
            peek_flow(wanted).is_some(),
            "the device code must be reachable under the requested id"
        );
        assert!(
            flow.code_verifier.len() >= 43,
            "verifier must be high-entropy"
        );
        let _ = take_flow(wanted);
    }

    #[test]
    fn a_malformed_requested_id_is_replaced_not_adopted() {
        // Adopting arbitrary caller input would let a request allocate a map entry under any key
        // it liked, including ones that collide with the credential-reference grammar.
        for bad in [
            "short",
            "has spaces in the middle of the id",
            "has:colons:in:it",
            "has/slashes/in/it",
            &"x".repeat(129),
        ] {
            let (id, _) = begin_flow(codex(), Some(bad));
            assert_ne!(id, bad, "must not adopt a malformed id: {bad:?}");
            assert!(is_wellformed_flow_id(&id));
            let _ = take_flow(&id);
        }
    }

    #[test]
    fn adopting_an_id_replaces_whatever_was_under_it() {
        let id = "shared_flow_id_abcdefgh";
        let (_, first) = begin_flow(codex(), Some(id));
        let (_, second) = begin_flow(codex(), Some(id));
        assert_ne!(
            first.code_verifier, second.code_verifier,
            "re-adopting an id must issue a new verifier, not hand out the live one"
        );
        let _ = take_flow(id);
    }

    #[test]
    fn a_flow_is_single_use_so_a_captured_callback_cannot_be_replayed() {
        let id = "single_use_flow_id_1234";
        let (_, _) = begin_flow(claude(), Some(id));
        assert!(take_flow(id).is_some());
        assert!(
            take_flow(id).is_none(),
            "the verifier must not survive a completed exchange"
        );
    }

    #[test]
    fn base64url_round_trips() {
        for case in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            b"\x00\xff\xfe\x01",
        ] {
            let encoded = base64url_encode(case);
            assert!(!encoded.contains('='));
            assert!(!encoded.contains('+'));
            assert!(!encoded.contains('/'));
            assert_eq!(base64url_decode(&encoded).as_deref(), Some(case));
        }
    }

    #[test]
    fn base64url_matches_rfc7636_challenge_example() {
        // RFC 7636 appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn percent_encoding_covers_scope_and_base64_specials() {
        assert_eq!(
            percent_encode("user:profile user:inference"),
            "user%3Aprofile%20user%3Ainference"
        );
        assert_eq!(percent_encode("a+b"), "a%2Bb");
        assert_eq!(percent_encode("azAZ09-_.~"), "azAZ09-_.~");
    }

    #[test]
    fn form_encoding_joins_pairs() {
        let form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("scope", "openid email profile"),
        ];
        assert_eq!(
            encode_form(&form),
            "grant_type=authorization_code&scope=openid%20email%20profile"
        );
    }

    #[test]
    fn device_pending_is_not_reported_as_an_error() {
        let e = classify(r#"{"error":"authorization_pending"}"#, 400);
        assert_eq!(e, FlowError::AuthorizationPending);
        let e = classify(r#"{"error":"slow_down"}"#, 400);
        assert_eq!(e, FlowError::AuthorizationPending);
    }

    #[test]
    fn provider_errors_map_to_the_right_retry_decision() {
        // Codex rotates refresh tokens; replaying a spent one must stop, not retry.
        assert!(matches!(
            classify(r#"{"error":"refresh_token_reused"}"#, 400),
            FlowError::NeedsReconnect(_)
        ));
        assert!(matches!(
            classify(r#"{"error":"invalid_grant"}"#, 400),
            FlowError::NeedsReconnect(_)
        ));
        assert!(matches!(
            classify(r#"{"error":"expired_token"}"#, 400),
            FlowError::NeedsReconnect(_)
        ));
        // Server-side and throttling problems are worth another attempt.
        assert!(matches!(
            classify("overloaded", 529),
            FlowError::Transient(_)
        ));
        assert!(matches!(
            classify("slow down", 429),
            FlowError::Transient(_)
        ));
        assert!(matches!(
            classify("connection reset", 503),
            FlowError::Transient(_)
        ));
    }

    #[test]
    fn flow_errors_carry_portal_friendly_statuses() {
        assert_eq!(FlowError::AuthorizationPending.status_code(), 202);
        assert_eq!(FlowError::BadRequest("x".into()).status_code(), 400);
        assert_eq!(FlowError::NeedsReconnect("x".into()).status_code(), 409);
        assert_eq!(FlowError::Transient("x".into()).status_code(), 502);
    }

    #[test]
    fn begin_flow_stores_a_verifier_and_take_consumes_it_once() {
        let (state, flow) = begin_flow(claude(), None);
        assert!(!flow.code_verifier.is_empty());
        assert!(flow.created_at > 0);
        assert_eq!(flow.provider, "claude-code");
        assert!(peek_flow(&state).is_some());
        // Verifier is reachable by state so the authorize URL can hash it.
        assert_eq!(flow_verifier(&state), flow.code_verifier);
        assert!(take_flow(&state).is_some());
        // A state is single-use: replaying a callback must not be possible.
        assert!(take_flow(&state).is_none());
        assert!(flow_verifier(&state).is_empty());
    }

    #[test]
    fn authorize_url_carries_pkce_and_provider_params() {
        let (state, flow) = begin_flow(codex(), None);
        let url = authorize_url(codex(), &state);
        assert!(url.starts_with("https://auth.openai.com/oauth/authorize?"));
        assert!(url.contains("code_challenge_method=S256"));
        // The challenge must be the S256 hash of the verifier we issued.
        assert!(url.contains(&percent_encode(&pkce_challenge(&flow.code_verifier))));
        assert!(!url.contains("code_challenge=") || !url.contains(&flow.code_verifier));
        assert!(url.contains("scope=openid%20email%20profile%20offline_access"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback"));
        assert!(url.contains("id_token_add_organizations=true"));
        assert!(url.contains("prompt=login"));
        assert!(url.contains("codex_cli_simplified_flow=true"));
        assert!(url.contains(&format!("state={state}")));
    }

    #[test]
    fn claude_authorize_url_has_no_codex_only_params() {
        let (state, _) = begin_flow(claude(), None);
        let url = authorize_url(claude(), &state);
        assert!(url.starts_with("https://claude.ai/oauth/authorize?"));
        assert!(!url.contains("id_token_add_organizations"));
        assert!(!url.contains("prompt=login"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("scope=user%3Aprofile"));
        assert_eq!(claude().body_encoding, BodyEncoding::Json);
        assert_eq!(codex().body_encoding, BodyEncoding::Form);
    }

    #[test]
    fn expired_flows_are_pruned() {
        let (state, mut flow) = begin_flow(claude(), None);
        flow.created_at = super::now_secs() - FLOW_TTL_SECS - 1;
        super::flows().insert(state.clone(), flow);
        assert!(peek_flow(&state).is_none());
    }

    #[test]
    fn codex_claims_and_org_fallback_both_yield_account_id() {
        // {"chatgpt_account_id":"acct-direct"} as a JWT payload.
        let direct = format!(
            "eyJhbGciOiJub25lIn0.{}.sig",
            base64url_encode(br#"{"chatgpt_account_id":"acct-direct","email":"dev@example.com"}"#)
        );
        assert_eq!(
            extract_account_id(Some(&direct), "opaque").as_deref(),
            Some("acct-direct")
        );
        assert_eq!(
            extract_email(Some(&direct)).as_deref(),
            Some("dev@example.com")
        );

        let orgs = format!(
            "eyJhbGciOiJub25lIn0.{}.sig",
            base64url_encode(br#"{"email":"org@example.com","organizations":[{"id":"org-1"}]}"#)
        );
        assert_eq!(extract_account_id(None, &orgs).as_deref(), Some("org-1"));
        assert_eq!(
            extract_account_id(Some(&orgs), "opaque").as_deref(),
            Some("org-1")
        );
    }

    #[test]
    fn account_id_absent_from_every_token_yields_none() {
        assert!(extract_account_id(None, "not-a-jwt").is_none());
        assert!(extract_account_id(Some("nope"), "nope").is_none());
        let empty = format!("h.{}.s", base64url_encode(b"{}"));
        assert!(extract_account_id(Some(&empty), &empty).is_none());
    }

    #[test]
    fn device_flow_specs_expose_no_pkce_authorization_url() {
        let xai = spec("xai-oauth").unwrap();
        assert!(is_device_flow(xai));
        assert!(!is_device_flow(claude()));
        assert!(xai.device_code_url.is_some());
        assert!(xai.authorize_url.is_empty());
    }
}
