//! Provider credential shapes: how a route's resolved credential becomes upstream headers.
//!
//! The router already stores `auth_mode` per route and per Model Group endpoint. That axis is
//! the single place that decides which header a provider credential travels in, so OAuth does not
//! need a parallel mechanism: it is three more `auth_mode` values plus, optionally, one
//! per-credential header value (Codex account id).
//!
//! `resolve` is a pure function over already-loaded config. The proxy calls it per request to
//! pick a header mode and a constant header slice — no filesystem, no environment read, no
//! database. `hotpath_guard.py` stays green because nothing here does I/O.
//!
//! Wire dialects are unchanged: OAuth routes still speak OpenAI-compatible or Anthropic
//! Messages. Only the credential transport differs.
//!
//! `apply_headers` is the single place that turns an `AuthPlan` into header values. The proxy
//! and the admin "Test connection" / "Load models" probes all call it, so a probe that succeeds
//! proves the real upstream request carries the same credential and provider headers.

use axum::http::{HeaderMap, HeaderName, HeaderValue};

/// Header used to carry the provider credential on the upstream request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HeaderMode {
    /// `Authorization: Bearer <credential>`.
    #[default]
    Bearer,
    /// `x-api-key: <credential>`.
    XApiKey,
    /// No provider credential header at all (local llama.cpp / vLLM / Ollama).
    None,
}

/// `anthropic-version` sent when the client did not pin one.
///
/// The Anthropic Messages API rejects a request without it, so every route on that dialect needs
/// a default — including a `Bearer` OAuth route, which is exactly the case an
/// "x-api-key implies anthropic" shortcut gets wrong.
pub const DEFAULT_ANTHROPIC_VERSION: &str = "2023-06-01";

/// `anthropic-beta` values every Claude OAuth request must carry. Anthropic accepts a
/// comma-separated list, so one static header covers both betas.
///
/// Credential-scoped on purpose: these are added only for `anthropic_oauth` routes. An
/// `anthropic` (API-key) route keeps passing the client's own `anthropic-beta` through
/// untouched — re-injecting these would silently override a client's opt-out.
pub const CLAUDE_OAUTH_BETA: &str = "oauth-2025-04-20,extended-cache-ttl-2025-04-11";

/// Anthropic only treats OAuth traffic from the Claude Code surface as CLI traffic, and gates
/// quota reset grants on that User-Agent. Pinned rather than discovered: BrighTO-Router is not
/// the Claude Code client and must not track its release cadence. Documented in SECURITY.md.
pub const CLAUDE_OAUTH_USER_AGENT: &str = "claude-cli/2.0.0 (external, cli)";

/// Header carrying the ChatGPT account that owns a Codex OAuth credential. Required by
/// `chatgpt.com/backend-api/*`; the value is read from the `id_token` JWT claim
/// `chatgpt_account_id` (or `access_token.organizations[0].id`) at exchange time.
pub const CODEX_ACCOUNT_HEADER: &str = "chatgpt-account-id";

/// Header `cli-chat-proxy.grok.com` reads the client version from. The gate sits behind
/// authentication, so it cannot be probed unauthenticated, and it reads exactly this header:
/// `User-Agent`, `x-cli-version`, `x-client-version`, `x-grok-cli-version` and friends all parse
/// as version `(none)` and the request dies with HTTP 426.
pub const XAI_CLIENT_VERSION_HEADER: &str = "x-grok-client-version";

/// Version floor advertised on SuperGrok/X Premium+ OAuth (Grok CLI subscription) requests.
/// Verified against the live proxy: `1.0.13` returns 200 while omitting the header returns
/// `426 Your Grok CLI version (none) is outdated. Please update to version 1.0.13 or later`.
/// When xAI raises the floor, the 426 body names the new minimum — bump this constant.
pub const XAI_GROK_CLIENT_VERSION: &str = "1.0.13";

/// Static headers required by an OAuth credential type.
pub fn oauth_static_headers(auth_mode: &str) -> &'static [(&'static str, &'static str)] {
    if auth_mode.eq_ignore_ascii_case(OAUTH_AUTH_MODE_ANTHROPIC) {
        &[
            ("anthropic-beta", CLAUDE_OAUTH_BETA),
            ("user-agent", CLAUDE_OAUTH_USER_AGENT),
        ]
    } else if auth_mode.eq_ignore_ascii_case(OAUTH_AUTH_MODE_XAI) {
        &[(XAI_CLIENT_VERSION_HEADER, XAI_GROK_CLIENT_VERSION)]
    } else {
        &[]
    }
}

/// `auth_mode` for a Claude Pro/Max OAuth credential.
pub const OAUTH_AUTH_MODE_ANTHROPIC: &str = "anthropic_oauth";
/// `auth_mode` for a ChatGPT Plus/Pro (Codex) OAuth credential.
pub const OAUTH_AUTH_MODE_CHATGPT: &str = "chatgpt_oauth";
/// `auth_mode` for a SuperGrok / X Premium+ OAuth credential.
pub const OAUTH_AUTH_MODE_XAI: &str = "xai_oauth";

/// Every `auth_mode` the router accepts. Kept in one place so admin validation, the catalog
/// and the Portal cannot drift apart.
pub const AUTH_MODES: &[&str] = &[
    "bearer",
    "anthropic",
    "none",
    OAUTH_AUTH_MODE_ANTHROPIC,
    OAUTH_AUTH_MODE_CHATGPT,
    OAUTH_AUTH_MODE_XAI,
];

/// True when `auth_mode` selects an OAuth credential.
pub fn is_oauth_mode(auth_mode: &str) -> bool {
    let m = auth_mode.trim().to_ascii_lowercase();
    m == OAUTH_AUTH_MODE_ANTHROPIC || m == OAUTH_AUTH_MODE_CHATGPT || m == OAUTH_AUTH_MODE_XAI
}

/// Normalize a client-supplied `auth_mode`, or `None` when the value is not one BrighTO knows.
pub fn parse_auth_mode(raw: &str) -> Option<&'static str> {
    let m = raw.trim().to_ascii_lowercase();
    AUTH_MODES.iter().copied().find(|k| *k == m)
}

/// Resolved header recipe for one upstream request.
///
/// Two independent axes, deliberately not merged:
/// * `mode` — where the credential travels. Decided by `auth_mode`.
/// * `anthropic_dialect` — whether the route speaks Anthropic Messages and therefore needs an
///   `anthropic-version` default. Decided by the backend template, because Claude OAuth rides a
///   bearer token on an Anthropic-dialect route.
///
/// `extra_headers` is a constant slice chosen by credential type; `account_id` is the only
/// per-credential value and is already resolved at config-load time.
#[derive(Clone, Copy)]
pub struct AuthPlan<'a> {
    pub mode: HeaderMode,
    pub anthropic_dialect: bool,
    pub extra_headers: &'static [(&'static str, &'static str)],
    pub account_id: Option<&'a str>,
}

impl Default for AuthPlan<'_> {
    fn default() -> Self {
        Self {
            mode: HeaderMode::Bearer,
            anthropic_dialect: false,
            extra_headers: &[],
            account_id: None,
        }
    }
}

impl std::fmt::Debug for AuthPlan<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthPlan")
            .field("mode", &self.mode)
            .field("anthropic_dialect", &self.anthropic_dialect)
            .field("extra_headers", &self.extra_headers)
            .field("account_id", &self.account_id.map(|_| "***"))
            .finish()
    }
}

/// Decide how a route's credential reaches its provider.
///
/// `backend_anthropic` (the backend template's dialect) is only consulted for the pre-OAuth
/// `bearer` / `anthropic` / `none` modes, which historically took their header from the backend
/// rather than from the route. Keeping that fallback means existing deployments keep
/// byte-identical upstream requests; OAuth modes are decided by `auth_mode` alone.
///
/// It always sets `anthropic_dialect`, including for OAuth, because that axis is orthogonal to
/// the credential: a Claude OAuth route is a bearer request to an Anthropic-dialect endpoint and
/// still needs `anthropic-version`.
pub fn resolve<'a>(
    auth_mode: &str,
    backend_anthropic: bool,
    account_id: Option<&'a str>,
) -> AuthPlan<'a> {
    let mode = auth_mode.trim().to_ascii_lowercase();
    let dialect =
        |mode: HeaderMode, extra: &'static [(&'static str, &'static str)], account_id| AuthPlan {
            mode,
            anthropic_dialect: backend_anthropic,
            extra_headers: extra,
            account_id,
        };
    match mode.as_str() {
        "none" => dialect(HeaderMode::None, &[], None),
        "anthropic" => dialect(
            if backend_anthropic {
                HeaderMode::XApiKey
            } else {
                HeaderMode::Bearer
            },
            &[],
            None,
        ),
        // Every OAuth credential travels as a bearer token, including Claude OAuth: Anthropic
        // accepts the OAuth access token in `Authorization` and rejects it in `x-api-key`.
        m if is_oauth_mode(m) => dialect(
            HeaderMode::Bearer,
            oauth_static_headers(m),
            if m == OAUTH_AUTH_MODE_CHATGPT {
                account_id
            } else {
                None
            },
        ),
        // "bearer" and any legacy value: the backend template decides, as it always has.
        _ => dialect(
            if backend_anthropic {
                HeaderMode::XApiKey
            } else {
                HeaderMode::Bearer
            },
            &[],
            None,
        ),
    }
}

/// Write the credential and any credential-scoped provider headers into an outgoing header map.
///
/// The map is expected to already carry the client's headers filtered by the caller's
/// allow-list. This function replaces the credential header outright — never appends to it, so a
/// client's `Authorization` cannot survive alongside the provider's — and *appends* the
/// `anthropic-beta` values, so a client that explicitly opted out of a beta stays opted out.
///
/// An empty `credential` writes nothing at all: a route whose credential did not resolve is
/// better rejected by the provider with a clear 401 than sent as a half-formed request.
pub fn apply_headers(
    headers: &mut HeaderMap,
    plan: &AuthPlan<'_>,
    credential: &str,
) -> Result<(), String> {
    if credential.is_empty() {
        return Ok(());
    }
    match plan.mode {
        HeaderMode::None => return Ok(()),
        HeaderMode::Bearer => {
            headers.insert(
                HeaderName::from_static("authorization"),
                HeaderValue::from_str(&format!("Bearer {credential}"))
                    .map_err(|_| "invalid provider credential".to_string())?,
            );
        }
        HeaderMode::XApiKey => {
            headers.insert(
                HeaderName::from_static("x-api-key"),
                HeaderValue::from_str(credential)
                    .map_err(|_| "invalid provider credential".to_string())?,
            );
        }
    }
    // Only when the client did not pin its own version. Tied to the dialect, not to the
    // credential header: Anthropic rejects a Messages request without `anthropic-version`, and a
    // Claude OAuth route is a bearer request to an Anthropic-dialect endpoint.
    if plan.anthropic_dialect && !headers.contains_key("anthropic-version") {
        headers.insert(
            HeaderName::from_static("anthropic-version"),
            HeaderValue::from_static(DEFAULT_ANTHROPIC_VERSION),
        );
    }
    for (name, value) in plan.extra_headers {
        headers.append(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if let Some(account_id) = plan.account_id {
        headers.insert(
            HeaderName::from_static(CODEX_ACCOUNT_HEADER),
            HeaderValue::from_str(account_id)
                .map_err(|_| "invalid oauth account id".to_string())?,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_headers_puts_the_credential_in_the_planned_header() {
        let mut h = HeaderMap::new();
        apply_headers(&mut h, &resolve("bearer", false, None), "secret-token").unwrap();
        assert_eq!(h.get("authorization").unwrap(), "Bearer secret-token");
        assert!(h.get("x-api-key").is_none());

        let mut h = HeaderMap::new();
        apply_headers(&mut h, &resolve("anthropic", true, None), "secret-token").unwrap();
        assert_eq!(h.get("x-api-key").unwrap(), "secret-token");
        assert_eq!(h.get("anthropic-version").unwrap(), "2023-06-01");
        assert!(h.get("authorization").is_none());

        let mut h = HeaderMap::new();
        apply_headers(&mut h, &resolve("none", true, Some("acct")), "ignored").unwrap();
        assert!(h.is_empty());
    }

    #[test]
    fn apply_headers_skips_everything_for_an_empty_credential() {
        let mut h = HeaderMap::new();
        apply_headers(&mut h, &resolve("anthropic_oauth", true, None), "").unwrap();
        // No credential resolved means the route cannot serve traffic; fail loudly upstream
        // rather than sending a half-formed OAuth request.
        assert!(h.get("authorization").is_none());
        assert!(h.get("anthropic-beta").is_none());
    }

    #[test]
    fn apply_headers_adds_provider_headers_and_account_id() {
        let mut h = HeaderMap::new();
        apply_headers(
            &mut h,
            &resolve(OAUTH_AUTH_MODE_CHATGPT, false, Some("acct-9")),
            "codex-token",
        )
        .unwrap();
        assert_eq!(h.get(CODEX_ACCOUNT_HEADER).unwrap(), "acct-9");

        let mut h = HeaderMap::new();
        apply_headers(
            &mut h,
            &resolve(OAUTH_AUTH_MODE_ANTHROPIC, true, None),
            "claude-token",
        )
        .unwrap();
        assert_eq!(
            h.get("anthropic-beta").unwrap(),
            CLAUDE_OAUTH_BETA,
            "single comma-joined header, not two values"
        );
        assert!(h.get("user-agent").is_some());
    }

    #[test]
    fn apply_headers_rejects_a_credential_with_a_forbidden_byte() {
        let mut h = HeaderMap::new();
        let err =
            apply_headers(&mut h, &resolve("bearer", false, None), "tok\nX-Evil: 1").unwrap_err();
        // A newline in a credential would otherwise inject an extra header into the upstream
        // request, or a forged line into the plain-text request log.
        assert!(err.contains("invalid provider credential"), "got: {err}");
    }

    #[test]
    fn apply_headers_rejects_a_malformed_account_id() {
        let mut h = HeaderMap::new();
        let err = apply_headers(
            &mut h,
            &resolve(OAUTH_AUTH_MODE_CHATGPT, false, Some("acct bad\nvalue")),
            "codex-token",
        )
        .unwrap_err();
        assert!(err.contains("invalid oauth account id"), "got: {err}");
    }

    #[test]
    fn legacy_bearer_follows_backend_template() {
        assert_eq!(resolve("bearer", false, None).mode, HeaderMode::Bearer);
        assert_eq!(resolve("bearer", true, None).mode, HeaderMode::XApiKey);
        // Legacy route that says bearer but points at an Anthropic backend keeps x-api-key.
        assert_eq!(resolve("anthropic", true, None).mode, HeaderMode::XApiKey);
        assert_eq!(resolve("anthropic", false, None).mode, HeaderMode::Bearer);
    }

    #[test]
    fn none_auth_mode_sends_no_credential() {
        let p = resolve("none", true, Some("acct"));
        assert_eq!(p.mode, HeaderMode::None);
        assert!(p.extra_headers.is_empty());
        assert!(p.account_id.is_none());
    }

    #[test]
    fn claude_oauth_uses_bearer_plus_beta_and_never_x_api_key() {
        let p = resolve(OAUTH_AUTH_MODE_ANTHROPIC, true, None);
        assert_eq!(p.mode, HeaderMode::Bearer);
        assert!(
            p.extra_headers
                .contains(&("anthropic-beta", CLAUDE_OAUTH_BETA))
        );
        assert!(p.extra_headers.iter().any(|(k, _)| *k == "user-agent"));
        // A Claude OAuth route on an anthropic-format backend must not regress to x-api-key.
        assert_ne!(p.mode, HeaderMode::XApiKey);
    }

    #[test]
    fn codex_oauth_carries_account_id_only() {
        let p = resolve(OAUTH_AUTH_MODE_CHATGPT, false, Some("acct-123"));
        assert_eq!(p.mode, HeaderMode::Bearer);
        assert_eq!(p.account_id, Some("acct-123"));
        assert!(p.extra_headers.is_empty());
    }

    #[test]
    fn codex_oauth_without_account_id_is_still_bearer() {
        let p = resolve(OAUTH_AUTH_MODE_CHATGPT, false, None);
        assert_eq!(p.mode, HeaderMode::Bearer);
        assert!(p.account_id.is_none());
    }

    #[test]
    fn xai_oauth_ignores_backend_template_and_carries_client_version() {
        let p = resolve(OAUTH_AUTH_MODE_XAI, true, Some("acct"));
        assert_eq!(p.mode, HeaderMode::Bearer);
        assert!(p.account_id.is_none());
        assert_eq!(
            p.extra_headers,
            &[(XAI_CLIENT_VERSION_HEADER, XAI_GROK_CLIENT_VERSION)]
        );
        // Case-insensitive like every auth mode comparison, and no other OAuth mode leaks the
        // Grok header.
        assert_eq!(
            oauth_static_headers("XAI_OAUTH"),
            &[(XAI_CLIENT_VERSION_HEADER, XAI_GROK_CLIENT_VERSION)]
        );
        assert!(oauth_static_headers(OAUTH_AUTH_MODE_CHATGPT).is_empty());
    }

    #[test]
    fn auth_mode_parsing_is_case_insensitive_and_closed() {
        assert_eq!(parse_auth_mode("  Bearer "), Some("bearer"));
        assert_eq!(parse_auth_mode("ANTHROPIC_OAUTH"), Some("anthropic_oauth"));
        assert_eq!(parse_auth_mode("chatgpt_oauth"), Some("chatgpt_oauth"));
        assert_eq!(parse_auth_mode("xai_oauth"), Some("xai_oauth"));
        assert_eq!(parse_auth_mode("basic"), None);
        assert_eq!(parse_auth_mode(""), None);
    }

    #[test]
    fn oauth_mode_detection() {
        assert!(is_oauth_mode("anthropic_oauth"));
        assert!(is_oauth_mode("XAI_OAUTH"));
        assert!(!is_oauth_mode("anthropic"));
        assert!(!is_oauth_mode("bearer"));
    }

    #[test]
    fn account_id_is_redacted_in_debug() {
        let p = resolve(OAUTH_AUTH_MODE_CHATGPT, false, Some("secret-account"));
        let rendered = format!("{p:?}");
        assert!(!rendered.contains("secret-account"));
        assert!(rendered.contains("***"));
    }
}
