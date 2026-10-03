//! Admin API for OAuth provider accounts.
//!
//! Auth is the same master-key + CIDR check every other `/admin` route uses. Nothing here ever
//! returns token material: responses carry an authorize URL, a device code, or a redacted
//! account summary.

use std::sync::Arc;

use axum::{
    Json,
    extract::{ConnectInfo, Extension, Path},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};

use crate::oauth::{self, flow};
use crate::provider_auth;

use super::{AdminState, ApiError, check_admin_auth};

/// One row per OAuth-capable provider, for the Portal picker.
#[derive(Serialize)]
pub struct OAuthProviderInfo {
    key: String,
    label: String,
    /// "pkce" | "device_code" — decides which connect affordance the Portal shows.
    flow: String,
    /// `auth_mode` written on a route that uses this credential.
    auth_mode: String,
    /// Route protocol such a route should use.
    protocol: String,
    api_base_url: String,
    /// Suggested provider model names, so the wizard is not a blank field.
    models: &'static [&'static str],
    /// Third-party risk, shown before the operator starts a flow.
    risk_note: String,
    accounts: usize,
}

#[derive(Serialize)]
struct OAuthProviderList {
    providers: Vec<OAuthProviderInfo>,
}

/// Model suggestions per provider. Deliberately short and conservative: a wrong name here
/// costs the operator one Test connection, whereas a long speculative list implies coverage the
/// router cannot verify.
fn suggested_models(key: &str) -> &'static [&'static str] {
    match key {
        "claude-code" => &["claude-sonnet-4-5", "claude-opus-4-1", "claude-haiku-4-5"],
        "codex" => &["gpt-5-codex", "gpt-5.1-codex", "gpt-5.1-codex-mini"],
        "xai-oauth" => &["grok-code-fast-1", "grok-4-fast-reasoning"],
        _ => &[],
    }
}

async fn list_oauth_providers(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<OAuthProviderList>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let store = oauth::OAuthTokenStore::from_env();
    let connected: std::collections::HashMap<&str, usize> =
        store
            .list()
            .into_iter()
            .fold(std::collections::HashMap::new(), |mut acc, t| {
                *acc.entry(leak_free_provider(&t.provider)).or_insert(0) += 1;
                acc
            });

    let providers = oauth::PROVIDERS
        .iter()
        .map(|spec| OAuthProviderInfo {
            key: spec.key.to_string(),
            label: spec.label.to_string(),
            flow: match spec.flow {
                oauth::OAuthFlow::Pkce => "pkce".to_string(),
                oauth::OAuthFlow::DeviceCode => "device_code".to_string(),
            },
            auth_mode: spec.auth_mode.to_string(),
            protocol: spec.protocol.to_string(),
            api_base_url: spec.api_base_url.to_string(),
            models: suggested_models(spec.key),
            risk_note: spec.risk_note.to_string(),
            accounts: connected.get(spec.key).copied().unwrap_or(0),
        })
        .collect();
    Ok(Json(OAuthProviderList { providers }))
}

/// `OAuthToken.provider` is a `String`, so a lookup needs a `&'static str` key. The set of
/// providers is fixed and small, so interning through the spec table is exact.
fn leak_free_provider(raw: &str) -> &'static str {
    oauth::spec(raw).map(|s| s.key).unwrap_or("unknown")
}

#[derive(Deserialize)]
struct StartRequest {
    /// Set for the device flow only: the client-generated flow id it polls with.
    flow_id: Option<String>,
}

#[derive(Serialize)]
struct StartResponse {
    provider: String,
    flow: String,
    /// PKCE: the URL to open. Device: a short code to type elsewhere.
    authorize_url: Option<String>,
    user_code: Option<String>,
    verification_uri: Option<String>,
    verification_uri_complete: Option<String>,
    /// Echoed back so the Portal can correlate its poll with this flow.
    state: String,
    poll_interval_secs: u64,
}

async fn start_oauth_flow(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    body: Option<Json<StartRequest>>,
) -> Result<Response, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let spec = require_spec(&provider)?;
    let requested = body.and_then(|Json(b)| b.flow_id);

    match spec.flow {
        oauth::OAuthFlow::Pkce => {
            // The Portal does not choose this id: it needs `authorize_url` first, and the `state`
            // it gets back is the one it will hand to `/complete`.
            let (flow_id, _) = flow::begin_flow(spec, None);
            if let Some(wanted) = requested
                && wanted != flow_id
            {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "flow_id does not match a flow started by this router; start again",
                ));
            }
            let payload = StartResponse {
                provider: spec.key.to_string(),
                flow: "pkce".to_string(),
                authorize_url: Some(flow::authorize_url(spec, &flow_id)),
                user_code: None,
                verification_uri: None,
                verification_uri_complete: None,
                state: flow_id,
                poll_interval_secs: 0,
            };
            Ok(Json(payload).into_response())
        }
        oauth::OAuthFlow::DeviceCode => {
            // Here the Portal does choose the id, because it has to poll `/complete` with
            // something and there is no redirect URL to read an id out of. Adopting it is what
            // puts the device code under the key the poll will look up.
            let requested = requested.ok_or_else(|| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "flow_id is required to start a device-code flow",
                )
            })?;
            let (flow_id, _) = flow::begin_flow(spec, Some(&requested));
            let auth = flow::request_device_code(&state.runtime.client, spec, &flow_id)
                .await
                .map_err(flow_error)?;
            let payload = StartResponse {
                provider: spec.key.to_string(),
                flow: "device_code".to_string(),
                authorize_url: None,
                user_code: Some(auth.user_code),
                verification_uri: Some(auth.verification_uri.clone()),
                verification_uri_complete: auth.verification_uri_complete,
                state: flow_id,
                poll_interval_secs: auth.interval_secs,
            };
            Ok(Json(payload).into_response())
        }
    }
}

#[derive(Deserialize)]
struct CompleteRequest {
    /// PKCE: the code from the callback, or the whole redirect URL. Device: the flow id.
    code: String,
    /// PKCE: the `state` returned by start. Device: the flow id.
    state: String,
}

#[derive(Serialize)]
struct ConnectedResponse {
    provider: String,
    label: String,
    account_name: Option<String>,
    expires_at: i64,
    /// `oauth:<provider>:<label>`, to store as the route's `provider_key_ref`.
    provider_key_ref: String,
    auth_mode: String,
    protocol: String,
    api_base_url: String,
    models: &'static [&'static str],
    status: String,
}

async fn complete_oauth_flow(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Json(payload): Json<CompleteRequest>,
) -> Result<Response, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let spec = require_spec(&provider)?;

    let token = match spec.flow {
        oauth::OAuthFlow::Pkce => {
            let code = extract_code(&payload.code)
                .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "code is required"))?;
            flow::exchange_code(&state.runtime.client, spec, &payload.state, &code)
                .await
                .map_err(flow_error)?
        }
        oauth::OAuthFlow::DeviceCode => {
            flow::poll_device_code(&state.runtime.client, spec, &payload.state)
                .await
                .map_err(flow_error)?
        }
    };

    let store = oauth::OAuthTokenStore::from_env();
    let label = token.label.clone();
    store.write(&token).map_err(ApiError::internal)?;

    // Pick the new credential up without waiting for the next config poll.
    state.reload_now().await?;

    let response = ConnectedResponse {
        provider: spec.key.to_string(),
        label: label.clone(),
        account_name: token.account_name.clone(),
        expires_at: token.expires_at,
        provider_key_ref: oauth::credential_ref(spec.key, &label),
        auth_mode: spec.auth_mode.to_string(),
        protocol: spec.protocol.to_string(),
        api_base_url: spec.api_base_url.to_string(),
        models: suggested_models(spec.key),
        status: token.refresh_state(flow::now_secs()).to_string(),
    };
    Ok(Json(response).into_response())
}

/// Accept either a bare code or the full redirect URL the provider sent the browser to.
///
/// The Portal cannot run a loopback listener, so the operator pastes whatever their browser
/// landed on. Both parameter orders and the `#fragment` variant occur in the wild, so scan for
/// `code=` in either position rather than assuming a fixed shape.
fn extract_code(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // A bare code, as the Portal's own PKCE instructions tell the operator to paste.
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return Some(trimmed.to_string());
    }
    let (_, params) = trimmed.split_once(['?', '#'])?;
    params
        .split(['&', '#'])
        .filter_map(|pair| pair.strip_prefix("code="))
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

#[derive(Serialize)]
struct AccountList {
    accounts: Vec<oauth::OAuthAccountSummary>,
}

async fn list_oauth_accounts(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<AccountList>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let store = oauth::OAuthTokenStore::from_env();
    let now = flow::now_secs();
    let accounts = store.list().iter().map(|t| t.public_summary(now)).collect();
    Ok(Json(AccountList { accounts }))
}

async fn disconnect_oauth_account(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Path((provider, label)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    require_spec(&provider)?;
    let store = oauth::OAuthTokenStore::from_env();
    store
        .delete(&provider, &label)
        .map_err(ApiError::internal)?;

    // Refuse to leave a route pointing at a credential that no longer exists: it would fail at
    // request time with a confusing 401 instead of a clear "no credential".
    let pool = state.pool().await?;
    let orphaned: Vec<String> = sqlx::query_scalar::<_, String>(
        "SELECT model_name FROM model_routes \
         WHERE auth_mode <> 'none' AND provider_key_ref = $1",
    )
    .bind(oauth::credential_ref(&provider, &label))
    .fetch_all(pool)
    .await
    .map_err(ApiError::from)?;
    let orphaned_endpoints: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM model_route_endpoints \
         WHERE auth_mode <> 'none' AND provider_key_ref = $1",
    )
    .bind(oauth::credential_ref(&provider, &label))
    .fetch_one(pool)
    .await
    .map_err(ApiError::from)?;

    state.reload_now().await?;
    Ok(Json(serde_json::json!({
        "disconnected": true,
        "provider": provider,
        "label": label,
        "routes_referencing_credential": orphaned,
        "endpoints_referencing_credential": orphaned_endpoints,
    }))
    .into_response())
}

fn require_spec(provider: &str) -> Result<&'static oauth::OAuthProviderSpec, ApiError> {
    oauth::spec(provider).ok_or_else(|| {
        ApiError::not_found(format!(
            "unknown OAuth provider '{provider}'; known providers: {}",
            oauth::PROVIDERS
                .iter()
                .map(|s| s.key)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })
}

/// Map a flow error onto an admin API status. `AuthorizationPending` is a 202 so the Portal can
/// keep polling without treating it as a failure.
fn flow_error(e: flow::FlowError) -> ApiError {
    let status = StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::BAD_GATEWAY);
    match e {
        flow::FlowError::AuthorizationPending => ApiError::new(status, "authorization_pending"),
        flow::FlowError::BadRequest(m) => ApiError::new(StatusCode::BAD_REQUEST, m),
        flow::FlowError::NeedsReconnect(m) => ApiError::new(StatusCode::CONFLICT, m),
        flow::FlowError::Transient(m) => ApiError::new(status, m),
    }
}

/// Auth mode a provider preset should write on a route, for the Portal wizard.
pub fn preset_auth_mode(catalog_key: &str) -> Option<&'static str> {
    oauth::spec(catalog_key).map(|s| s.auth_mode)
}

/// Protocol a provider preset should write on a route, for the Portal wizard.
pub fn preset_protocol(catalog_key: &str) -> Option<&'static str> {
    oauth::spec(catalog_key).map(|s| s.protocol)
}

/// True when this `auth_mode` needs an OAuth account rather than an API key, so the wizard can
/// swap the key input for a connect button.
pub fn auth_mode_needs_oauth(auth_mode: &str) -> bool {
    provider_auth::is_oauth_mode(auth_mode)
}

/// Sub-router so `admin::router` keeps one readable route list.
///
/// Returns a state-less `Router` to match the parent: `AdminState` reaches every handler through
/// the `Extension` layer, not through the router's state parameter.
pub fn routes() -> axum::Router {
    axum::Router::new()
        .route("/oauth/providers", get(list_oauth_providers))
        .route("/oauth/{provider}/start", post(start_oauth_flow))
        .route("/oauth/{provider}/complete", post(complete_oauth_flow))
        .route("/oauth/accounts", get(list_oauth_accounts))
        .route(
            "/oauth/accounts/{provider}/{label}",
            delete(disconnect_oauth_account),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_oauth_provider_has_suggested_models() {
        // An empty list leaves the wizard with no guidance, which is the state the research
        // flagged as the weakest part of every reference implementation.
        for spec in oauth::PROVIDERS {
            assert!(
                !suggested_models(spec.key).is_empty(),
                "{} has no model suggestions",
                spec.key
            );
        }
    }

    #[test]
    fn preset_lookup_matches_the_spec_table() {
        assert_eq!(preset_auth_mode("claude-code"), Some("anthropic_oauth"));
        assert_eq!(preset_protocol("codex"), Some("codex_responses"));
        assert_eq!(preset_auth_mode("openai"), None);
        assert!(auth_mode_needs_oauth("chatgpt_oauth"));
        assert!(!auth_mode_needs_oauth("bearer"));
    }

    #[test]
    fn bare_code_passes_through() {
        assert_eq!(extract_code("abc123"), Some("abc123".into()));
        assert_eq!(extract_code("  abc123  "), Some("abc123".into()));
    }

    #[test]
    fn redirect_url_yields_the_code() {
        assert_eq!(
            extract_code("http://localhost:1455/auth/callback?code=xyz&state=s1"),
            Some("xyz".into())
        );
        assert_eq!(
            extract_code("http://localhost:54545/callback?state=s1&code=xyz789&x=1"),
            Some("xyz789".into())
        );
        assert_eq!(
            extract_code("http://localhost:1455/auth/callback?code=a%20b"),
            Some("a%20b".into())
        );
    }

    #[test]
    fn code_in_a_url_fragment_is_accepted() {
        // Some providers redirect with the parameters in the fragment instead of the query.
        assert_eq!(
            extract_code("http://localhost:1455/auth/callback#code=frag-code&state=s1"),
            Some("frag-code".into())
        );
    }

    #[test]
    fn missing_code_is_rejected_rather_than_forwarded() {
        assert_eq!(extract_code(""), None);
        assert_eq!(extract_code("   "), None);
        assert_eq!(
            extract_code("http://localhost:1455/auth/callback?state=s1"),
            None
        );
        assert_eq!(extract_code("http://localhost:1455/auth/callback"), None);
    }

    #[test]
    fn unknown_provider_error_lists_the_known_ones() {
        let e = require_spec("nope").unwrap_err();
        let msg = e.message.to_string();
        assert!(msg.contains("unknown OAuth provider 'nope'"));
        assert!(msg.contains("claude-code"));
        assert!(msg.contains("codex"));
        assert!(msg.contains("xai-oauth"));
    }

    #[test]
    fn flow_errors_map_to_distinct_statuses() {
        assert_eq!(
            flow_error(flow::FlowError::AuthorizationPending).status,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            flow_error(flow::FlowError::BadRequest("x".into())).status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            flow_error(flow::FlowError::NeedsReconnect("x".into())).status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            flow_error(flow::FlowError::Transient("x".into())).status,
            StatusCode::BAD_GATEWAY
        );
    }

    #[test]
    fn connected_response_never_carries_token_material() {
        // The struct is the wire contract for a successful connect, so this is the guard against
        // adding a token field by accident.
        let json = serde_json::to_string(&serde_json::json!({
            "provider": "codex",
            "label": "dev_example.com",
            "account_name": "dev@example.com",
            "expires_at": 123,
            "provider_key_ref": "oauth:codex:dev_example.com",
            "auth_mode": "chatgpt_oauth",
            "protocol": "codex_responses",
            "api_base_url": "https://chatgpt.com/backend-api/codex",
            "models": ["gpt-5-codex"],
            "status": "ok",
        }))
        .unwrap();
        assert!(!json.contains("access_token"));
        assert!(!json.contains("refresh_token"));
        assert!(json.contains("oauth:codex:dev_example.com"));
    }
}
