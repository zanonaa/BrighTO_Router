//! OAuth provider credentials — control plane only.
//!
//! Every provider difference lives in one declarative table (`PROVIDERS`). There is no
//! per-provider code path: authorize, token exchange, refresh, storage and the credential's
//! required headers are all data. Adding a fourth OAuth provider is one `OAuthProviderSpec`
//! entry, not a new module.
//!
//! `flow` holds the authorize / device-code / exchange / refresh machinery; `refresh` runs the
//! background renewal loop. The provider table below is pure data.
//!
//! This module is deliberately allowed to touch the filesystem and the network. The proxy
//! never calls into it — `DbConfigLoader` resolves tokens here at config-load time and hands
//! the proxy a plain `AuthPlan`. `scripts/hotpath_guard.py` enforces that separation.
//!
//! Secrets layout: `$DATA_DIR/oauth/<provider>_<label>.json`, directory 0700, file 0600 — the
//! same permissions `admin::write_provider_key_file` already applies to provider keys. The
//! database only ever holds an `oauth:<provider>:<label>` reference, never token material.

pub mod flow;
pub mod refresh;

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::provider_auth;

/// How a provider obtains a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthFlow {
    /// RFC 8252 authorization code with PKCE. The admin Portal shows the authorize URL and the
    /// operator pastes back the redirect URL or bare code.
    Pkce,
    /// RFC 8628 device code. No loopback port needed, so it works from a container or a VPS.
    DeviceCode,
}

/// Token endpoint body encoding. Not cosmetic: Codex accepts form encoding while Claude's
/// endpoint expects JSON, and sending the wrong one fails the exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyEncoding {
    Form,
    Json,
}

/// JSON shape a provider's quota endpoint returns.
///
/// This is the one place PR #2 admits a per-provider branch, and it is deliberate: the three
/// responses genuinely do not share a structure. Claude returns named windows keyed by window
/// name, Codex returns a rate-limit object with fixed primary/secondary slots, and xAI returns
/// protobuf-JSON with numbers wrapped in `{ val: n }`. A single generic parser over those would
/// be guesswork dressed as generality. Everything else about a probe — URL, headers, caching,
/// cooldown, staleness — is data or shared code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaShape {
    /// `utilization` windows keyed by name (`five_hour`, `seven_day`, `seven_day_<model>`, …).
    Claude,
    /// `rate_limits.primary_window` / `.secondary_window`.
    Codex,
    /// Protobuf-JSON: numbers arrive as `{ val: n }`.
    Xai,
}

/// How to ask one provider for its quota.
#[derive(Debug, Clone, Copy)]
pub struct QuotaProbeSpec {
    /// Appended to `quota_base_url`.
    pub path: &'static str,
    /// Query string, appended after `?`. Claude's `cedar_ember=1` adds the reset-grant block and
    /// is the flag Claude Code itself sends.
    pub query: &'static str,
    /// Headers required *beyond* the credential. The credential and every OAuth-standard header
    /// come from `provider_auth::apply_headers`, so a probe request is byte-equivalent to the real
    /// one; only genuinely extra markers belong here.
    pub extra_headers: &'static [(&'static str, &'static str)],
    pub shape: QuotaShape,
}

/// Everything BrighTO needs to drive one provider's OAuth flow.
#[derive(Debug, Clone, Copy)]
pub struct OAuthProviderSpec {
    /// Catalog key. Must match the `key` used in `PROVIDER_CATALOG` so the Portal can offer
    /// "Connect account" without a second lookup table.
    pub key: &'static str,
    pub label: &'static str,
    pub flow: OAuthFlow,
    pub authorize_url: &'static str,
    /// Device code endpoint, when `flow == DeviceCode`.
    pub device_code_url: Option<&'static str>,
    pub token_url: &'static str,
    pub client_id: &'static str,
    pub scope: &'static str,
    /// Loopback redirect for PKCE flows.
    pub redirect_uri: &'static str,
    pub body_encoding: BodyEncoding,
    /// Non-standard authorize parameters some providers require.
    pub extra_authorize_params: &'static [(&'static str, &'static str)],
    /// How early to refresh. Claude hands out long-lived tokens and tolerates a 4-hour lead;
    /// Codex rotates the refresh token on every use and wants a 10-minute lead.
    pub refresh_lead: Duration,
    /// `auth_mode` written on a route that uses this credential.
    pub auth_mode: &'static str,
    /// `ProviderProtocol::as_str()` written on such a route.
    pub protocol: &'static str,
    /// Base URL for inference requests. For xAI this is the CLI proxy, because
    /// `api.x.ai` rejects consumer OAuth accounts.
    pub api_base_url: &'static str,
    /// Base URL for quota probes, when it differs from the inference base URL.
    pub quota_base_url: &'static str,
    /// `None` when the provider exposes no quota endpoint. The account is then passive-only, which
    /// is a real limitation and is documented rather than papered over.
    pub quota_probe: Option<QuotaProbeSpec>,
    /// Third-party risk, surfaced verbatim in the Portal and documented in SECURITY.md.
    pub risk_note: &'static str,
}

/// Claude Pro / Max. Authorize runs on `claude.ai`, the token endpoint on
/// `platform.claude.com`, and inference on `api.anthropic.com` — three different hosts.
const CLAUDE: OAuthProviderSpec = OAuthProviderSpec {
    key: "claude-code",
    label: "Claude Code (OAuth)",
    flow: OAuthFlow::Pkce,
    authorize_url: "https://claude.ai/oauth/authorize",
    device_code_url: None,
    token_url: "https://platform.claude.com/v1/oauth/token",
    client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
    scope: "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload",
    redirect_uri: "http://localhost:54545/callback",
    body_encoding: BodyEncoding::Json,
    extra_authorize_params: &[],
    // Claude issues long-lived access tokens; a 4-hour lead is safe and avoids needless
    // refresh traffic against a provider that rate-limits its own token endpoint.
    refresh_lead: Duration::from_secs(4 * 60 * 60),
    auth_mode: provider_auth::OAUTH_AUTH_MODE_ANTHROPIC,
    protocol: "anthropic_messages",
    api_base_url: "https://api.anthropic.com",
    quota_base_url: "https://api.anthropic.com",
    quota_probe: Some(QuotaProbeSpec {
        path: "/api/oauth/usage",
        // The same flag Claude Code sends; it adds the limit-reset grant block.
        query: "cedar_ember=1",
        // Nothing extra: `anthropic-beta`, `user-agent` and `anthropic-version` all come from
        // `apply_headers`, so this request is shaped exactly like a real Claude OAuth request.
        extra_headers: &[],
        shape: QuotaShape::Claude,
    }),
    risk_note: "Anthropic treats third-party OAuth traffic differently from Claude Code itself and \
may require paid extra usage for this API path. Not covered by your Claude subscription quota \
unless Anthropic grants it. Use an Anthropic API key for billing-critical accounts.",
};

/// ChatGPT Plus / Pro (Codex). Inference runs on `chatgpt.com/backend-api/codex`, not
/// `api.openai.com`, and every request must name the owning account.
const CODEX: OAuthProviderSpec = OAuthProviderSpec {
    key: "codex",
    label: "OpenAI Codex (OAuth)",
    flow: OAuthFlow::Pkce,
    authorize_url: "https://auth.openai.com/oauth/authorize",
    device_code_url: None,
    token_url: "https://auth.openai.com/oauth/token",
    client_id: "app_EMoamEEZ73f0CkXaXp7hrann",
    scope: "openid email profile offline_access",
    redirect_uri: "http://localhost:1455/auth/callback",
    body_encoding: BodyEncoding::Form,
    extra_authorize_params: &[
        // Forces the account chooser, puts organizations in the id_token so we can read the
        // account id, and skips the consent screen.
        ("prompt", "login"),
        ("id_token_add_organizations", "true"),
        ("codex_cli_simplified_flow", "true"),
    ],
    // OpenAI rotates the refresh token on every use, so we refresh rarely but never late.
    refresh_lead: Duration::from_secs(10 * 60),
    auth_mode: provider_auth::OAUTH_AUTH_MODE_CHATGPT,
    protocol: "codex_responses",
    api_base_url: "https://chatgpt.com/backend-api/codex",
    quota_base_url: "https://chatgpt.com/backend-api",
    quota_probe: Some(QuotaProbeSpec {
        path: "/wham/usage",
        query: "",
        extra_headers: &[],
        shape: QuotaShape::Codex,
    }),
    risk_note: "Codex credentials draw on your ChatGPT Plus/Pro Codex allowance. OpenAI may \
change or withdraw this path. Shares one account allowance with Codex CLI usage.",
};

/// SuperGrok / X Premium+. Device code only, so the flow works headless. Inference runs on
/// `cli-chat-proxy.grok.com`; `api.x.ai` is the pay-as-you-go API and rejects consumer OAuth
/// accounts with a 403 spending-limit error.
const XAI: OAuthProviderSpec = OAuthProviderSpec {
    key: "xai-oauth",
    label: "xAI Grok (OAuth)",
    flow: OAuthFlow::DeviceCode,
    authorize_url: "",
    device_code_url: Some("https://auth.x.ai/oauth2/device/code"),
    token_url: "https://auth.x.ai/oauth2/token",
    client_id: "b1a00492-073a-47ea-816f-4c329264a828",
    scope: "openid profile email offline_access grok-cli:access api:access conversations:read \
conversations:write",
    redirect_uri: "",
    body_encoding: BodyEncoding::Form,
    extra_authorize_params: &[("referrer", "grok-build")],
    refresh_lead: Duration::from_secs(5 * 60),
    auth_mode: provider_auth::OAUTH_AUTH_MODE_XAI,
    protocol: "openai_responses",
    api_base_url: "https://cli-chat-proxy.grok.com/v1",
    quota_base_url: "https://cli-chat-proxy.grok.com/v1",
    quota_probe: Some(QuotaProbeSpec {
        path: "/billing",
        query: "format=credits",
        // The billing endpoint is gated on a client marker. Without it the CLI proxy answers 403.
        extra_headers: &[
            ("x-xai-token-auth", "xai-grok-cli"),
            ("x-grok-client-mode", "headless"),
        ],
        shape: QuotaShape::Xai,
    }),
    risk_note: "SuperGrok subscription access through a third-party client. xAI reserves the \
right to withdraw it, and Grok Code beta may be required for the full model set.",
};

/// The whole OAuth feature set: three rows, no branching code.
pub static PROVIDERS: &[OAuthProviderSpec] = &[CLAUDE, CODEX, XAI];

pub fn spec(key: &str) -> Option<&'static OAuthProviderSpec> {
    let k = key.trim().to_ascii_lowercase();
    PROVIDERS.iter().find(|s| s.key == k)
}

pub fn spec_for_auth_mode(auth_mode: &str) -> Option<&'static OAuthProviderSpec> {
    let m = auth_mode.trim().to_ascii_lowercase();
    PROVIDERS.iter().find(|s| s.auth_mode == m)
}

/// Reference stored in `model_routes.provider_key_ref` instead of token material.
pub fn credential_ref(provider: &str, label: &str) -> String {
    format!("oauth:{}:{}", provider.trim(), label.trim())
}

/// Parse `oauth:<provider>:<label>` back into its parts.
pub fn parse_credential_ref(reference: &str) -> Option<(&str, &str)> {
    let rest = reference.trim().strip_prefix("oauth:")?;
    let (provider, label) = rest.split_once(':')?;
    if provider.is_empty() || label.is_empty() {
        return None;
    }
    Some((provider, label))
}

// ===== Token record =====

/// A persisted OAuth credential. The refresh token is bearer-equivalent for the operator's
/// provider subscription, so this type never derives `Debug` and is never serialized to an
/// admin or portal response.
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    pub provider: String,
    /// Stable, filesystem- and UI-safe identifier derived from the account (email, or the
    /// organization short hash where the provider exposes no email).
    pub label: String,
    pub account_id: Option<String>,
    /// Display name shown in the Portal, e.g. an email address.
    pub account_name: Option<String>,
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Epoch seconds.
    pub expires_at: i64,
    pub scopes: Option<String>,
    /// Epoch seconds of the last successful refresh, for operator diagnostics.
    pub refreshed_at: i64,
}

impl std::fmt::Debug for OAuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthToken")
            .field("provider", &self.provider)
            .field("label", &self.label)
            .field("account_id", &self.account_id.as_ref().map(|_| "***"))
            .field("account_name", &self.account_name)
            .field("access_token", &"***")
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "***"))
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .field("refreshed_at", &self.refreshed_at)
            .finish()
    }
}

impl OAuthToken {
    pub fn needs_refresh(&self, spec: &OAuthProviderSpec, now: i64) -> bool {
        let lead = i64::try_from(spec.refresh_lead.as_secs()).unwrap_or(300);
        self.refresh_token.is_some() && self.expires_at - lead <= now
    }

    /// Reduce a token to what the Portal is allowed to see.
    pub fn public_summary(&self, now: i64) -> OAuthAccountSummary {
        OAuthAccountSummary {
            provider: self.provider.clone(),
            label: self.label.clone(),
            account_name: self.account_name.clone(),
            expires_at: self.expires_at,
            has_refresh_token: self.refresh_token.is_some(),
            last_refresh_state: self.refresh_state(now).to_string(),
        }
    }

    pub fn refresh_state(&self, now: i64) -> &'static str {
        if self.refresh_token.is_none() {
            "no_refresh_token"
        } else if self.expires_at <= now {
            "expired"
        } else if self.expires_at - now < 600 {
            "expiring"
        } else {
            "ok"
        }
    }
}

/// Admin-facing view of one connected account. Contains no token material by construction.
#[derive(Debug, Clone, Serialize)]
pub struct OAuthAccountSummary {
    pub provider: String,
    pub label: String,
    pub account_name: Option<String>,
    pub expires_at: i64,
    pub has_refresh_token: bool,
    pub last_refresh_state: String,
}

// ===== Filesystem store =====

/// One credential per file, so two accounts for the same provider never overwrite each other.
pub struct OAuthTokenStore {
    dir: PathBuf,
}

impl OAuthTokenStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// `$DATA_DIR/oauth`, matching where `admin` writes provider keys.
    pub fn from_env() -> Self {
        let data_dir =
            std::env::var("DATA_DIR").unwrap_or_else(|_| "/var/lib/brighto-router".into());
        Self::new(Path::new(&data_dir).join("oauth"))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path_for(&self, provider: &str, label: &str) -> PathBuf {
        self.dir
            .join(format!("{}_{}.json", sanitize(provider), sanitize(label)))
    }

    pub fn write(&self, token: &OAuthToken) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("create oauth dir: {e}"))?;
        restrict_dir(&self.dir);
        let json =
            serde_json::to_vec_pretty(token).map_err(|e| format!("encode oauth token: {e}"))?;
        write_private(&self.path_for(&token.provider, &token.label), &json)
    }

    pub fn read(&self, provider: &str, label: &str) -> Result<OAuthToken, String> {
        let path = self.path_for(provider, label);
        let raw = std::fs::read(&path).map_err(|e| format!("read oauth token: {e}"))?;
        serde_json::from_slice(&raw).map_err(|e| format!("parse oauth token: {e}"))
    }

    pub fn delete(&self, provider: &str, label: &str) -> Result<(), String> {
        let path = self.path_for(provider, label);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("delete oauth token: {e}")),
        }
    }

    /// Every credential on disk. A file that does not parse is skipped rather than failing the
    /// whole listing: one corrupt credential must not hide the healthy ones.
    pub fn list(&self) -> Vec<OAuthToken> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(raw) = std::fs::read(entry.path())
                && let Ok(token) = serde_json::from_slice::<OAuthToken>(&raw)
            {
                out.push(token);
            }
        }
        out.sort_by(|a, b| a.provider.cmp(&b.provider).then(a.label.cmp(&b.label)));
        out
    }
}

/// Resolve a route credential reference into the access token and, for Codex, the account id.
///
/// Prefers `oauth:` references; falls back to `resolve_backend_key` so `env:` and `file:`
/// routes keep working through the same call site.
pub fn resolve_route_credential(
    store: &OAuthTokenStore,
    reference: &str,
) -> (Option<String>, Option<String>) {
    if let Some((provider, label)) = parse_credential_ref(reference) {
        return match store.read(provider, label) {
            Ok(token) => (Some(token.access_token), token.account_id),
            Err(e) => {
                tracing::warn!(provider, label, error = %e, "oauth credential unreadable");
                (None, None)
            }
        };
    }
    (crate::config::resolve_backend_key(reference), None)
}

fn restrict_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

/// Reduce a free-form account identifier to something safe in a filename and in the Portal.
fn sanitize(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('_').to_ascii_lowercase();
    if trimmed.is_empty() {
        "account".to_string()
    } else {
        trimmed.chars().take(64).collect()
    }
}

/// Label for a newly connected account. Prefers the account's email, then a short hash of the
/// account id, so two accounts for one provider get distinct files.
pub fn account_label(email: Option<&str>, account_id: Option<&str>) -> String {
    if let Some(e) = email.map(str::trim).filter(|e| !e.is_empty()) {
        return sanitize(e);
    }
    if let Some(id) = account_id.map(str::trim).filter(|i| !i.is_empty()) {
        use sha2::{Digest, Sha256};
        let digest = hex_encode(&Sha256::digest(id.as_bytes()));
        return format!("acct-{}", &digest[..12]);
    }
    "account".to_string()
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ===== Refresh outcomes =====

/// Why a refresh attempt ended. Terminal states stop the retry loop; a token that is merely
/// stale must not be retried into a hammer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// Not due yet.
    NotDue,
    /// Token replaced on disk.
    Refreshed,
    /// Provider rejected the refresh token. Operator must reconnect; retrying cannot help.
    NeedsReconnect,
    /// Provider or network hiccup. Retry with backoff.
    Transient,
}

impl RefreshOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotDue => "not_due",
            Self::Refreshed => "refreshed",
            Self::NeedsReconnect => "needs_reconnect",
            Self::Transient => "transient",
        }
    }
}

/// Error strings that mean "this refresh token will never work again".
///
/// `refresh_token_reused` is the Codex case that matters: OpenAI rotates the refresh token on
/// every refresh, so replaying a spent one logs the credential out. Treating it as a retryable
/// error is how a single-token refresh turns into a reconnect storm.
pub fn is_terminal_refresh_error(raw: &str) -> bool {
    let r = raw.to_ascii_lowercase();
    [
        "refresh_token_reused",
        "unrecoverable_refresh_error",
        "invalid_grant",
        "invalid_request",
        "invalid_client",
        "invalid_token",
    ]
    .iter()
    .any(|m| r.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_store() -> (OAuthTokenStore, PathBuf) {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("brighto-oauth-test-{}-{n}", std::process::id()));
        (OAuthTokenStore::new(dir.clone()), dir)
    }

    fn token(provider: &str, label: &str) -> OAuthToken {
        OAuthToken {
            provider: provider.into(),
            label: label.into(),
            account_id: Some("acct-1".into()),
            account_name: Some("dev@example.com".into()),
            access_token: "at-secret".into(),
            refresh_token: Some("rt-secret".into()),
            expires_at: 2_000,
            scopes: Some("a b".into()),
            refreshed_at: 1_000,
        }
    }

    #[test]
    fn every_spec_has_a_distinct_key_and_matching_auth_mode() {
        let mut keys: Vec<&str> = PROVIDERS.iter().map(|s| s.key).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "duplicate provider key");
        for s in PROVIDERS {
            assert!(
                provider_auth::parse_auth_mode(s.auth_mode).is_some(),
                "{} has unknown auth_mode {}",
                s.key,
                s.auth_mode
            );
            assert!(
                provider_auth::is_oauth_mode(s.auth_mode),
                "{} auth_mode {} is not an oauth mode",
                s.key,
                s.auth_mode
            );
            assert!(spec(s.key).is_some());
            assert!(spec_for_auth_mode(s.auth_mode).is_some());
        }
    }

    #[test]
    fn pkce_specs_have_authorize_and_redirect() {
        for s in PROVIDERS.iter().filter(|s| s.flow == OAuthFlow::Pkce) {
            assert!(!s.authorize_url.is_empty(), "{} authorize", s.key);
            assert!(!s.redirect_uri.is_empty(), "{} redirect", s.key);
            assert!(s.device_code_url.is_none(), "{} has device url", s.key);
        }
    }

    #[test]
    fn device_code_specs_have_a_device_url_and_no_redirect() {
        for s in PROVIDERS.iter().filter(|s| s.flow == OAuthFlow::DeviceCode) {
            assert!(s.device_code_url.is_some(), "{} device url", s.key);
            assert!(s.redirect_uri.is_empty(), "{} redirect", s.key);
        }
    }

    #[test]
    fn spec_lookup_is_case_insensitive() {
        assert_eq!(spec("Claude-Code").map(|s| s.key), Some("claude-code"));
        assert_eq!(spec("CODEX").map(|s| s.key), Some("codex"));
        assert!(spec("nope").is_none());
    }

    #[test]
    fn credential_ref_round_trips() {
        let r = credential_ref("codex", "dev@example.com");
        assert_eq!(r, "oauth:codex:dev@example.com");
        assert_eq!(parse_credential_ref(&r), Some(("codex", "dev@example.com")));
        assert_eq!(parse_credential_ref("env:OPENAI_API_KEY"), None);
        assert_eq!(parse_credential_ref("oauth:codex"), None);
        assert_eq!(parse_credential_ref("oauth::label"), None);
    }

    #[test]
    fn store_round_trips_and_lists() {
        let (store, dir) = temp_store();
        store.write(&token("codex", "a@example.com")).unwrap();
        store.write(&token("claude-code", "b@example.com")).unwrap();
        let got = store.read("codex", "a@example.com").unwrap();
        assert_eq!(got.access_token, "at-secret");
        assert_eq!(got.account_id.as_deref(), Some("acct-1"));
        assert_eq!(store.list().len(), 2);
        store.delete("codex", "a@example.com").unwrap();
        assert!(store.read("codex", "a@example.com").is_err());
        // Deleting twice is not an error; disconnect is idempotent.
        store.delete("codex", "a@example.com").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_skips_corrupt_files_instead_of_failing_the_listing() {
        let (store, dir) = temp_store();
        store.write(&token("codex", "good@example.com")).unwrap();
        std::fs::write(store.path_for("codex", "broken"), b"{not json").unwrap();
        let all = store.list();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].label, "good@example.com");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn credentials_do_not_leak_through_debug() {
        let rendered = format!("{:?}", token("codex", "a@example.com"));
        assert!(!rendered.contains("at-secret"));
        assert!(!rendered.contains("rt-secret"));
        assert!(!rendered.contains("acct-1"));
    }

    #[test]
    fn summary_exposes_no_token_material() {
        let json =
            serde_json::to_string(&token("codex", "a@example.com").public_summary(1_500)).unwrap();
        assert!(!json.contains("at-secret"));
        assert!(!json.contains("rt-secret"));
        assert!(json.contains("has_refresh_token"));
    }

    #[test]
    fn refresh_is_due_only_inside_the_lead_window() {
        let claude = spec("claude-code").unwrap();
        let lead = i64::try_from(claude.refresh_lead.as_secs()).unwrap();
        let mut t = token("claude-code", "a@example.com");
        // 4h lead: due only once less than 4h of validity remains.
        t.expires_at = 1_000 + lead + 60;
        assert!(!t.needs_refresh(claude, 1_000));
        t.expires_at = 1_000 + lead - 60;
        assert!(t.needs_refresh(claude, 1_000));
        t.expires_at = 1_000;
        assert!(t.needs_refresh(claude, 1_000));
    }

    #[test]
    fn a_short_lived_token_is_due_immediately() {
        // The failure mode this guards: a token that expires before its provider's refresh lead
        // has elapsed. With Claude's 4h lead, a 1000s token is due on the very first tick, which
        // is correct — refreshing early beats forwarding an expired credential.
        let claude = spec("claude-code").unwrap();
        let t = token("claude-code", "a@example.com");
        assert!(t.needs_refresh(claude, 0));
    }

    #[test]
    fn token_without_refresh_token_is_never_due() {
        let claude = spec("claude-code").unwrap();
        let mut t = token("claude-code", "a@example.com");
        t.refresh_token = None;
        t.expires_at = 0;
        assert!(!t.needs_refresh(claude, 9_999));
        assert_eq!(t.refresh_state(9_999), "no_refresh_token");
    }

    #[test]
    fn refresh_state_tracks_expiry_buckets() {
        let t = token("codex", "a@example.com");
        assert_eq!(t.refresh_state(1_000), "ok");
        assert_eq!(t.refresh_state(1_500), "expiring");
        assert_eq!(t.refresh_state(2_500), "expired");
    }

    #[test]
    fn rotated_and_invalid_refresh_errors_are_terminal() {
        assert!(is_terminal_refresh_error(
            "{\"error\":\"refresh_token_reused\"}"
        ));
        assert!(is_terminal_refresh_error("invalid_grant"));
        assert!(is_terminal_refresh_error("unrecoverable_refresh_error"));
        assert!(is_terminal_refresh_error("invalid_client"));
        assert!(!is_terminal_refresh_error("temporarily unavailable"));
        assert!(!is_terminal_refresh_error("connection reset by peer"));
    }

    #[test]
    fn labels_are_filesystem_safe_and_bounded() {
        assert_eq!(sanitize("Dev@Example.com"), "dev_example.com");
        assert_eq!(
            account_label(Some("dev@example.com"), Some("abc")),
            "dev_example.com"
        );
        assert!(account_label(None, Some("acct-uuid")).starts_with("acct-"));
        assert_eq!(account_label(None, None), "account");
        let long = "a".repeat(200);
        assert!(sanitize(&long).len() <= 64);
    }

    #[test]
    fn oauth_reference_resolves_to_access_token_and_account_id() {
        let (store, dir) = temp_store();
        store.write(&token("codex", "a@example.com")).unwrap();
        let (access, account) =
            resolve_route_credential(&store, &credential_ref("codex", "a@example.com"));
        assert_eq!(access.as_deref(), Some("at-secret"));
        assert_eq!(account.as_deref(), Some("acct-1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_oauth_reference_yields_no_credential() {
        let (store, dir) = temp_store();
        let (access, account) = resolve_route_credential(&store, "oauth:codex:ghost");
        assert!(access.is_none());
        assert!(account.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
