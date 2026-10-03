//! End-to-end OAuth credential smoke: a mock provider that speaks the exact upstream contract
//! for each of the three OAuth providers, driven through the real proxy.
//!
//! What this proves, and why it needs mocks rather than live logins:
//!
//! * every upstream endpoint each provider really uses (`/v1/messages`, the Codex Responses
//!   path, the Grok CLI proxy) is reachable through a normal public route;
//! * the credential arrives in the right header, with the credential-scoped provider headers
//!   (`anthropic-beta`, `chatgpt-account-id`) that provider requires;
//! * a client's own `authorization` and `anthropic-beta` never leak through;
//! * the token file is the only thing that changes when the background loop refreshes — no
//!   restart, no admin write, no proxy change.
//!
//! Every one of those endpoints is reverse-engineered, not documented, so this is the only
//! place a change to the credential contract can be caught before it reaches a real account.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::body::{Body, Bytes, to_bytes};
use axum::http::{HeaderMap, Request};
use sqlx::postgres::PgPool;
use tower::ServiceExt;

use brighto_router::budget::RamBudgetStore;
use brighto_router::contract::AppState;
use brighto_router::ledger::LedgerSink;
use brighto_router::metrics::Metrics;
use brighto_router::oauth;
use brighto_router::route::RamBackendPool;

fn metrics() -> Metrics {
    static M: std::sync::OnceLock<Metrics> = std::sync::OnceLock::new();
    M.get_or_init(Metrics::install).clone()
}

/// Where a mock provider should record what it received.
#[derive(Clone, Default)]
struct Capture {
    inner: Arc<std::sync::Mutex<Vec<(String, HeaderMap)>>>,
}

impl Capture {
    fn push(&self, path: String, headers: HeaderMap) {
        self.inner.lock().unwrap().push((path, headers));
    }

    fn only(&self) -> (String, HeaderMap) {
        let all = self.inner.lock().unwrap();
        assert_eq!(all.len(), 1, "expected exactly one upstream request");
        all[0].clone()
    }
}

/// Mock upstream that answers each provider's real path with that provider's real response shape.
///
/// `protocol_hint` selects the response body shape so the proxy's usage parser is exercised on
/// the same bytes a real provider would send, not a generic fixture.
async fn spawn_provider(protocol_hint: &'static str, capture: Capture) -> String {
    let app = axum::Router::new().fallback(move |req: axum::http::Request<Body>| {
        let protocol_hint = protocol_hint.to_string();
        let capture = capture.clone();
        async move {
            capture.push(req.uri().path().to_string(), req.headers().clone());
            let body = match protocol_hint.as_str() {
                "anthropic_messages" => serde_json::json!({
                    "id": "msg_mock",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-mock",
                    "content": [{"type": "text", "text": "ok"}],
                    "usage": {"input_tokens": 2, "output_tokens": 3}
                }),
                "codex_responses" => serde_json::json!({
                    "id": "resp_mock",
                    "object": "response",
                    "model": "gpt-5-codex",
                    "output": [{"type": "message", "role": "assistant",
                                "content": [{"type": "output_text", "text": "ok"}]}],
                    "usage": {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5}
                }),
                _ => serde_json::json!({
                    "id": "resp_mock",
                    "object": "response",
                    "model": "grok-mock",
                    "output": [{"type": "message", "role": "assistant",
                                "content": [{"type": "output_text", "text": "ok"}]}],
                    "usage": {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5}
                }),
            };
            axum::response::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

/// Minimal router wired to a snapshot, mirroring `tests/model_group_smoke.rs`.
fn router_for(pool: PgPool, snap: brighto_router::contract::ConfigSnapshot) -> axum::Router {
    let cfg = Arc::new(ArcSwap::from_pointee(snap));
    let budget = Arc::new(RamBudgetStore::new());
    budget.load_teams(&cfg.load_full().teams);
    let backends = Arc::new(RamBackendPool::new_with_counter_pool(pool, 1));
    for b in cfg.load_full().backends.values() {
        backends.upsert_backend(b.clone());
    }
    let (ptx, mut prx) = tokio::sync::mpsc::channel(8192);
    let (otx, mut orx) = tokio::sync::mpsc::channel(8192);
    tokio::spawn(async move { while prx.recv().await.is_some() {} });
    tokio::spawn(async move { while orx.recv().await.is_some() {} });
    brighto_router::handlers::router(Arc::new(AppState {
        cfg,
        budget,
        backends,
        client: reqwest::Client::new(),
        ledger: LedgerSink::new(ptx, otx),
        metrics: metrics(),
        max_body_bytes: 10 * 1024 * 1024,
        quota: Arc::new(brighto_router::quota::QuotaStore::new()),
        reload_notify: Arc::new(tokio::sync::Notify::new()),
        config_ok_at: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        config_err_at: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        readiness_max_stale_ms: 5_000,
    }))
}

async fn seed_auth(pool: &PgPool) {
    sqlx::query("INSERT INTO teams (id, name, budget, enabled) VALUES (1, 'team-1', $1, TRUE)")
        .bind(r#"{"period":"day","max_tokens":1000000,"per_model":{}}"#)
        .execute(pool)
        .await
        .unwrap();
    let key_hash = hex::encode(brighto_router::auth::hash_key("test-key"));
    sqlx::query(
        "INSERT INTO api_keys (id, key_hash, key_prefix, team_id, owner, allowed_models, \
         budget, rpm_limit, concurrency_limit, expires_at, enabled) \
         VALUES (1, $1, 'sk-brigh', 1, 'tester', '[]', NULL, NULL, NULL, NULL, TRUE)",
    )
    .bind(&key_hash)
    .execute(pool)
    .await
    .unwrap();
}

/// One connected OAuth credential, written the way `admin::oauth_api` writes it.
fn write_credential(
    data_dir: &std::path::Path,
    provider: &str,
    label: &str,
    token: &str,
) -> String {
    let store = oauth::OAuthTokenStore::new(data_dir.join("oauth"));
    store
        .write(&oauth::OAuthToken {
            provider: provider.to_string(),
            label: label.to_string(),
            account_id: Some("acct-mock-1".to_string()),
            account_name: Some("dev@example.com".to_string()),
            access_token: token.to_string(),
            refresh_token: Some("rt-mock".to_string()),
            expires_at: 4_000_000_000,
            scopes: None,
            refreshed_at: 1_700_000_000,
        })
        .unwrap();
    oauth::credential_ref(provider, label)
}

/// `DATA_DIR` is process-global; the config loader and the admin API both read it. Set once per
/// test binary run and left alone, matching how the real container behaves.
///
/// Consequence: every test in this file shares one `oauth/` directory, and cargo runs them
/// concurrently. Tests that write a credential must therefore use a **distinct account label**, or
/// one test's `write` races another's `read` and an assertion about a token value ends up
/// depending on which thread ran last. A label that names the behaviour under test
/// (`header_contract_…`, `refresh_pickup_…`) makes such a collision obvious instead of leaving it
/// to be rediscovered.
fn data_dir() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("brighto_oauth_smoke_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: single-threaded setup before any test reads it; the value is constant for the
        // lifetime of the process.
        unsafe { std::env::set_var("DATA_DIR", &dir) };
        dir
    })
}

async fn load_router(pool: &PgPool) -> axum::Router {
    let loader = brighto_router::config::DbConfigLoader::new(pool.clone(), 5);
    let snap = loader.load_snapshot().await.unwrap();
    router_for(pool.clone(), snap)
}

/// Claude Pro/Max OAuth: a bearer token to an Anthropic-dialect route, carrying the OAuth betas.
///
/// Before this change the router could not express this at all: `anthropic` mode forced the
/// credential into `x-api-key`, which Anthropic rejects for an OAuth access token, and no mode
/// added the `anthropic-beta` values the OAuth path requires.
#[sqlx::test(migrations = "./migrations")]
async fn claude_oauth_route_uses_bearer_with_beta_not_x_api_key(pool: PgPool) {
    let capture = Capture::default();
    let base = spawn_provider("anthropic_messages", capture.clone()).await;

    sqlx::query(
        "INSERT INTO backends (id, name, base_url, api_key_ref, weight, max_inflight, format, enabled) \
         VALUES (1, 'claude-oauth', $1, 'env:UNSET_CLAUDE_KEY', 1, 100, 'anthropic', TRUE)",
    )
    .bind(&base)
    .execute(&pool)
    .await
    .unwrap();

    // A distinct account label per test: `DATA_DIR` is process-global, so sharing one credential
    // file across concurrently running tests would make one test's token assertion depend on which
    // thread wrote last. See `data_dir`.
    let key_ref = write_credential(
        data_dir(),
        "claude-code",
        "header_contract_example.com",
        "claude-access-1",
    );
    sqlx::query(
        "INSERT INTO model_routes (model_name, backend_ids, provider_model_name, enabled, \
         auth_mode, protocol, provider_key_ref) \
         VALUES ('claude-fast', '[1]', 'claude-sonnet-4-5', TRUE, 'anthropic_oauth', \
                 'anthropic_messages', $1)",
    )
    .bind(&key_ref)
    .execute(&pool)
    .await
    .unwrap();

    seed_auth(&pool).await;
    let app = load_router(&pool).await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("authorization", "Bearer test-key")
        // A client that pinned its own beta and its own version must keep both.
        .header("anthropic-beta", "disable-interleaved-thinking-2025-05-14")
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"model":"claude-fast","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["content"][0]["text"], "ok");

    let (path, headers) = capture.only();
    assert_eq!(path, "/v1/messages", "Anthropic Messages path unchanged");

    let auth = headers.get("authorization").unwrap().to_str().unwrap();
    assert_eq!(
        auth, "Bearer claude-access-1",
        "the OAuth access token must travel as a bearer token"
    );
    assert!(
        headers.get("x-api-key").is_none(),
        "Anthropic rejects an OAuth token in x-api-key"
    );

    let betas: Vec<String> = headers
        .get_all("anthropic-beta")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let joined = betas.join(",");
    assert!(
        joined.contains("oauth-2025-04-20"),
        "OAuth beta missing: {joined}"
    );
    assert!(
        joined.contains("disable-interleaved-thinking"),
        "client beta was dropped: {joined}"
    );
    assert!(
        headers.get("user-agent").is_some(),
        "CLI surface UA required"
    );
}

/// Codex: the account header is mandatory on `chatgpt.com/backend-api/*`; without it every
/// request fails regardless of how valid the token is.
#[sqlx::test(migrations = "./migrations")]
async fn codex_oauth_route_carries_account_id_and_responses_path(pool: PgPool) {
    let capture = Capture::default();
    let base = spawn_provider("codex_responses", capture.clone()).await;

    sqlx::query(
        "INSERT INTO backends (id, name, base_url, api_key_ref, weight, max_inflight, format, enabled) \
         VALUES (1, 'codex-oauth', $1, 'env:UNSET_CODEX_KEY', 1, 100, 'openai', TRUE)",
    )
    // Codex does not live on api.openai.com: the backend base URL carries the path prefix, and
    // `build_target_url` drops the client's `/v1` in front of it. So the real upstream is
    // `chatgpt.com/backend-api/codex/responses`.
    .bind(format!("{base}/backend-api/codex"))
    .execute(&pool)
    .await
    .unwrap();

    let key_ref = write_credential(
        data_dir(),
        "codex",
        "account_header_example.com",
        "codex-access-1",
    );
    sqlx::query(
        "INSERT INTO model_routes (model_name, backend_ids, provider_model_name, enabled, \
         auth_mode, protocol, provider_key_ref) \
         VALUES ('codex-fast', '[1]', 'gpt-5-codex', TRUE, 'chatgpt_oauth', 'codex_responses', $1)",
    )
    .bind(&key_ref)
    .execute(&pool)
    .await
    .unwrap();

    seed_auth(&pool).await;
    let app = load_router(&pool).await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header("authorization", "Bearer test-key")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"model":"codex-fast","input":"hi","max_output_tokens":8}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();

    let (path, headers) = capture.only();
    assert_eq!(path, "/backend-api/codex/responses");
    assert_eq!(
        headers
            .get("chatgpt-account-id")
            .expect("chatgpt-account-id is required by chatgpt.com/backend-api"),
        "acct-mock-1"
    );
    assert_eq!(
        headers.get("authorization").unwrap().to_str().unwrap(),
        "Bearer codex-access-1"
    );
    assert!(headers.get("anthropic-beta").is_none());
}

/// xAI: a plain bearer token, no account header. The subscription path is `cli-chat-proxy.grok.com`,
/// not `api.x.ai`, which rejects consumer OAuth accounts.
#[sqlx::test(migrations = "./migrations")]
async fn xai_oauth_route_is_bearer_only(pool: PgPool) {
    let capture = Capture::default();
    let base = spawn_provider("openai_responses", capture.clone()).await;

    sqlx::query(
        "INSERT INTO backends (id, name, base_url, api_key_ref, weight, max_inflight, format, enabled) \
         VALUES (1, 'grok-oauth', $1, 'env:UNSET_GROK_KEY', 1, 100, 'openai', TRUE)",
    )
    .bind(&base)
    .execute(&pool)
    .await
    .unwrap();

    let key_ref = write_credential(
        data_dir(),
        "xai-oauth",
        "bearer_only_example.com",
        "grok-access-1",
    );
    sqlx::query(
        "INSERT INTO model_routes (model_name, backend_ids, provider_model_name, enabled, \
         auth_mode, protocol, provider_key_ref) \
         VALUES ('grok-fast', '[1]', 'grok-code-fast-1', TRUE, 'xai_oauth', 'openai_responses', $1)",
    )
    .bind(&key_ref)
    .execute(&pool)
    .await
    .unwrap();

    seed_auth(&pool).await;
    let app = load_router(&pool).await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header("authorization", "Bearer test-key")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"model":"grok-fast","input":"hi","max_output_tokens":8}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();

    let (_, headers) = capture.only();
    assert_eq!(
        headers.get("authorization").unwrap().to_str().unwrap(),
        "Bearer grok-access-1"
    );
    assert!(headers.get("chatgpt-account-id").is_none());
    assert!(headers.get("anthropic-beta").is_none());
}

/// A refreshed access token must take effect on the next config reload — no restart, no admin
/// write. This is the whole reason `AppState::reload_notify` is wired into the refresh loop:
/// Codex rotates its refresh token on every use, so a token the router does not pick up is a
/// logged-out account.
#[sqlx::test(migrations = "./migrations")]
async fn refreshed_token_is_picked_up_by_the_next_snapshot(pool: PgPool) {
    let capture = Capture::default();
    let base = spawn_provider("anthropic_messages", capture.clone()).await;

    sqlx::query(
        "INSERT INTO backends (id, name, base_url, api_key_ref, weight, max_inflight, format, enabled) \
         VALUES (1, 'claude-oauth', $1, 'env:UNSET_CLAUDE_KEY', 1, 100, 'anthropic', TRUE)",
    )
    .bind(&base)
    .execute(&pool)
    .await
    .unwrap();

    let key_ref = write_credential(
        data_dir(),
        "claude-code",
        "refresh_pickup_example.com",
        "claude-access-1",
    );
    sqlx::query(
        "INSERT INTO model_routes (model_name, backend_ids, provider_model_name, enabled, \
         auth_mode, protocol, provider_key_ref) \
         VALUES ('claude-refresh', '[1]', 'claude-sonnet-4-5', TRUE, 'anthropic_oauth', \
                 'anthropic_messages', $1)",
    )
    .bind(&key_ref)
    .execute(&pool)
    .await
    .unwrap();

    seed_auth(&pool).await;

    let first = load_router(&pool).await;
    let before = capture.inner.lock().unwrap().len();
    send_claude_request(&first).await;
    assert_eq!(
        headers_of_last(&capture).get("authorization").unwrap(),
        "Bearer claude-access-1"
    );
    assert_eq!(capture.inner.lock().unwrap().len(), before + 1);

    // Simulate the background loop's write: same credential file, new access token.
    let store = oauth::OAuthTokenStore::new(data_dir().join("oauth"));
    let mut token = store
        .read("claude-code", "refresh_pickup_example.com")
        .unwrap();
    token.access_token = "claude-access-2".to_string();
    token.expires_at = 4_100_000_000;
    store.write(&token).unwrap();

    // No restart, no reload hook call: just the poll the router already runs every few seconds.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let second = load_router(&pool).await;
    send_claude_request(&second).await;
    assert_eq!(
        headers_of_last(&capture).get("authorization").unwrap(),
        "Bearer claude-access-2",
        "a refreshed token must reach the provider without an operator action"
    );
}

async fn send_claude_request(app: &axum::Router) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("authorization", "Bearer test-key")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"model":"claude-refresh","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let _ = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
}

fn headers_of_last(capture: &Capture) -> HeaderMap {
    capture.inner.lock().unwrap().last().unwrap().1.clone()
}

/// A revoked refresh token must stop the loop, not spin it. Codex returns `refresh_token_reused`
/// when a spent refresh token is replayed, which is how one bad token becomes a reconnect storm.
#[tokio::test]
async fn terminal_refresh_error_is_not_retried() {
    for body in [
        r#"{"error":"refresh_token_reused"}"#,
        r#"{"error":"invalid_grant"}"#,
        r#"{"error":{"code":"unrecoverable_refresh_error"}}"#,
    ] {
        assert!(
            oauth::is_terminal_refresh_error(body),
            "should be terminal: {body}"
        );
    }
    for body in [
        "temporarily unavailable",
        "HTTP 500",
        "connection reset by peer",
    ] {
        assert!(
            !oauth::is_terminal_refresh_error(body),
            "should be retryable: {body}"
        );
    }
}

/// A route pointing at a credential that does not exist must fail loudly at admin time, not
/// silently forward an empty credential on every request.
#[test]
fn an_unresolvable_oauth_reference_yields_no_credential() {
    let (key, account) = oauth::resolve_route_credential(
        &oauth::OAuthTokenStore::new(data_dir().join("does-not-exist")),
        "oauth:codex:nobody@example.com",
    );
    assert!(key.is_none());
    assert!(account.is_none());
}

/// `oauth:` references must never be confused with `env:` / `file:` ones: mixing them would send
/// a provider key where a renewable credential was expected.
#[test]
fn only_oauth_prefixed_references_are_routed_to_the_token_store() {
    assert_eq!(
        oauth::parse_credential_ref("oauth:codex:dev@example.com"),
        Some(("codex", "dev@example.com"))
    );
    for other in [
        "env:OPENAI_API_KEY",
        "file:/run/secrets/k",
        "",
        "oauth:codex",
        "oauth::x",
    ] {
        assert_eq!(
            oauth::parse_credential_ref(other),
            None,
            "must not be treated as an OAuth ref: {other}"
        );
    }
}

/// The caller's own API key must never reach a provider. The client authenticates to
/// BrighTO-Router with a BrighTO key; the provider must see only the OAuth credential.
#[sqlx::test(migrations = "./migrations")]
async fn client_authorization_never_reaches_a_provider(pool: PgPool) {
    let capture = Capture::default();
    let base = spawn_provider("anthropic_messages", capture.clone()).await;

    sqlx::query(
        "INSERT INTO backends (id, name, base_url, api_key_ref, weight, max_inflight, format, enabled) \
         VALUES (1, 'claude-oauth', $1, 'env:UNSET_CLAUDE_KEY', 1, 100, 'anthropic', TRUE)",
    )
    .bind(&base)
    .execute(&pool)
    .await
    .unwrap();

    let key_ref = write_credential(
        data_dir(),
        "claude-code",
        "leak_probe",
        "claude-access-only",
    );
    sqlx::query(
        "INSERT INTO model_routes (model_name, backend_ids, provider_model_name, enabled, \
         auth_mode, protocol, provider_key_ref) \
         VALUES ('claude-leak', '[1]', 'claude-sonnet-4-5', TRUE, 'anthropic_oauth', \
                 'anthropic_messages', $1)",
    )
    .bind(&key_ref)
    .execute(&pool)
    .await
    .unwrap();

    seed_auth(&pool).await;
    let app = load_router(&pool).await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        // The caller's own, valid BrighTO key.
        .header("authorization", "Bearer test-key")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"model":"claude-leak","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let _ = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();

    let (_, headers) = capture.only();
    let upstream = headers.get("authorization").unwrap().to_str().unwrap();
    assert_eq!(upstream, "Bearer claude-access-only");
    assert!(
        !upstream.contains("test-key"),
        "the caller's own key leaked to the provider: {upstream}"
    );
    assert!(headers.get("x-api-key").is_none());
}

/// An API-key route must not acquire OAuth betas, even on an Anthropic-format backend. Anthropic
/// rejects a plain API key that presents OAuth-only beta values.
#[sqlx::test(migrations = "./migrations")]
async fn api_key_route_never_gains_oauth_betas(pool: PgPool) {
    let capture = Capture::default();
    let base = spawn_provider("anthropic_messages", capture.clone()).await;

    let key_file =
        std::env::temp_dir().join(format!("brighto_oauth_smoke_key_{}", std::process::id()));
    std::fs::write(&key_file, "sk-ant-mock").unwrap();

    sqlx::query(
        "INSERT INTO backends (id, name, base_url, api_key_ref, weight, max_inflight, format, enabled) \
         VALUES (1, 'anthropic-key', $1, $2, 1, 100, 'anthropic', TRUE)",
    )
    .bind(&base)
    .bind(format!("file:{}", key_file.display()))
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO model_routes (model_name, backend_ids, provider_model_name, enabled, \
         auth_mode, protocol) \
         VALUES ('anthropic-key-route', '[1]', 'claude-sonnet-4-5', TRUE, 'anthropic', \
                 'anthropic_messages')",
    )
    .execute(&pool)
    .await
    .unwrap();

    seed_auth(&pool).await;
    let app = load_router(&pool).await;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("authorization", "Bearer test-key")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"model":"anthropic-key-route","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let _ = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();

    let (_, headers) = capture.only();
    assert_eq!(headers.get("x-api-key").unwrap(), "sk-ant-mock");
    assert!(
        headers.get("anthropic-beta").is_none(),
        "an API-key route must not present OAuth betas"
    );
    assert!(
        headers.get("user-agent").is_none(),
        "an API-key route must not spoof the Claude Code UA"
    );
    let _ = std::fs::remove_file(&key_file);
}

/// The credential file must be readable only by its owner. A token file that any local user can
/// read is equivalent to handing out the account.
#[test]
fn credential_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let store = oauth::OAuthTokenStore::new(data_dir().join("oauth"));
    store
        .write(&oauth::OAuthToken {
            provider: "claude-code".to_string(),
            label: "perm_probe".to_string(),
            account_id: None,
            account_name: None,
            access_token: "t".to_string(),
            refresh_token: Some("r".to_string()),
            expires_at: 1,
            scopes: None,
            refreshed_at: 0,
        })
        .unwrap();
    let mode = std::fs::metadata(store.path_for("claude-code", "perm_probe"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "credential file must be 0600, got {mode:o}");
    let dir_mode = std::fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        dir_mode, 0o700,
        "credential dir must be 0700, got {dir_mode:o}"
    );
}

/// Two accounts for one provider must not overwrite each other: an operator running a personal
/// and a work account is the normal case, not an edge case.
#[test]
fn two_accounts_for_one_provider_coexist() {
    let store = oauth::OAuthTokenStore::new(data_dir().join("oauth-multi"));
    for (label, token) in [("personal", "tok-personal"), ("work", "tok-work")] {
        store
            .write(&oauth::OAuthToken {
                provider: "codex".to_string(),
                label: label.to_string(),
                account_id: None,
                account_name: None,
                access_token: token.to_string(),
                refresh_token: None,
                expires_at: 1,
                scopes: None,
                refreshed_at: 0,
            })
            .unwrap();
    }
    assert_eq!(store.list().len(), 2);
    assert_eq!(
        store.read("codex", "personal").unwrap().access_token,
        "tok-personal"
    );
    assert_eq!(
        store.read("codex", "work").unwrap().access_token,
        "tok-work"
    );
    let _ = std::fs::remove_dir_all(data_dir().join("oauth-multi"));
}

/// `Bytes` is imported for the fallback handler's body type; keep the reference explicit so a
/// future edit does not silently drop it.
const _: Option<Bytes> = None;
