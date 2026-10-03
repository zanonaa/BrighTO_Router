//! End-to-end quota observation smoke: a mock provider that speaks each quota contract, plus a
//! proxy path that attaches real quota headers to real inference responses.
//!
//! What this proves, and why it needs mocks rather than live logins:
//!
//! * a response carrying quota headers actually populates the store through the normal proxy path,
//!   with no admin call and no restart;
//! * a response with no quota headers leaves the store untouched, which is the case that matters
//!   for hot-path cost — it must be silent, not an empty snapshot;
//! * the admin API renders `used`/`total` and never a precomputed percentage, so a provider
//!   cannot choose which field makes the UI look right;
//! * a credit balance is rendered as an amount, and an unreported window is rendered as unknown —
//!   neither becomes a percentage;
//! * active probes are rate-limited per credential, so a Portal refresh loop cannot become load on
//!   a provider.
//!
//! Every quota endpoint here is reverse-engineered, not documented. These tests are the only place a
//! change to the observation contract can be caught before it reaches a real account.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::postgres::PgPool;
use tower::ServiceExt;

use brighto_router::budget::RamBudgetStore;
use brighto_router::contract::AppState;
use brighto_router::ledger::LedgerSink;
use brighto_router::metrics::Metrics;
use brighto_router::oauth;
use brighto_router::quota::{
    self, QuotaKey, QuotaStore, QuotaWindow, QuotaWindowId, QuotaWindowKind,
};
use brighto_router::route::RamBackendPool;

fn metrics() -> Metrics {
    static M: std::sync::OnceLock<Metrics> = std::sync::OnceLock::new();
    M.get_or_init(Metrics::install).clone()
}

/// Every request the mock upstream saw, with the headers it received.
#[derive(Clone, Default)]
struct Capture {
    inner: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Capture {
    fn push(&self, path: String) {
        self.inner.lock().unwrap().push(path);
    }

    fn paths(&self) -> Vec<String> {
        self.inner.lock().unwrap().clone()
    }
}

/// Mock upstream that answers each provider's quota path with that provider's real response shape
/// and attaches that provider's real quota headers to every inference response.
async fn spawn_provider(
    protocol_hint: &'static str,
    quota_body: &'static str,
    headers: &'static [(&'static str, &'static str)],
    capture: Capture,
) -> String {
    let app = axum::Router::new().fallback(move |req: axum::http::Request<Body>| {
        let capture = capture.clone();
        async move {
            let path = req.uri().path().to_string();
            capture.push(path.clone());

            if path.contains("/usage") || path.contains("/billing") || path.contains("/wham") {
                return axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(quota_body.to_string()))
                    .unwrap();
            }

            let body = match protocol_hint {
                "anthropic_messages" => serde_json::json!({
                    "id": "msg_mock", "type": "message", "role": "assistant",
                    "model": "claude-mock",
                    "content": [{"type": "text", "text": "ok"}],
                    "usage": {"input_tokens": 2, "output_tokens": 3}
                }),
                "codex_responses" => serde_json::json!({
                    "id": "resp_mock", "object": "response", "model": "gpt-5-codex",
                    "output": [{"type": "message", "role": "assistant",
                                "content": [{"type": "output_text", "text": "ok"}]}],
                    "usage": {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5}
                }),
                _ => serde_json::json!({
                    "id": "resp_mock", "object": "response", "model": "grok-mock",
                    "output": [{"type": "message", "role": "assistant",
                                "content": [{"type": "output_text", "text": "ok"}]}],
                    "usage": {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5}
                }),
            };
            let mut builder = axum::response::Response::builder()
                .status(200)
                .header("content-type", "application/json");
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            builder.body(Body::from(body.to_string())).unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

struct Harness {
    app: axum::Router,
    quota: Arc<QuotaStore>,
}

fn router_for(pool: PgPool, snap: brighto_router::contract::ConfigSnapshot) -> Harness {
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
    let quota = Arc::new(QuotaStore::new());
    let app = brighto_router::handlers::router(Arc::new(AppState {
        cfg,
        budget,
        backends,
        client: reqwest::Client::new(),
        ledger: LedgerSink::new(ptx, otx),
        metrics: metrics(),
        max_body_bytes: 10 * 1024 * 1024,
        quota: quota.clone(),
        reload_notify: Arc::new(tokio::sync::Notify::new()),
        config_ok_at: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        config_err_at: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        readiness_max_stale_ms: 5_000,
    }));
    Harness { app, quota }
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

/// `DATA_DIR` is process-global, and these tests run concurrently. Every test that writes a
/// credential therefore uses a **distinct account label** — sharing one file makes one test's write
/// race another's read, and an assertion about a reading starts depending on thread order. The
/// labels below name the behaviour under test so a collision is obvious rather than mysterious.
fn data_dir() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("brighto_quota_smoke_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: single-threaded setup before any test reads it; constant for the process.
        unsafe { std::env::set_var("DATA_DIR", &dir) };
        dir
    })
}

async fn call(app: &axum::Router, protocol_path: &str, model: &str) -> axum::response::Response {
    let (path, body) = match protocol_path {
        "anthropic_messages" => (
            "/v1/messages",
            format!(
                r#"{{"model":"{model}","max_tokens":8,"messages":[{{"role":"user","content":"hi"}}]}}"#
            ),
        ),
        _ => (
            "/v1/responses",
            format!(r#"{{"model":"{model}","input":"hi"}}"#),
        ),
    };
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", "Bearer test-key")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Serve the full router on a real socket and return its base URL.
///
/// The admin routes take `ConnectInfo<SocketAddr>` — the router's only trusted source for a peer
/// address — so `oneshot` cannot exercise them: the extractor has nothing to read and the handler
/// fails before it reaches the auth check. Serving for real is also closer to production, where the
/// CIDR check is the thing standing between an operator and a quota readout.
async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    format!("http://{addr}")
}

fn admin_key() -> String {
    std::env::var("ADMIN_MASTER_KEY").unwrap_or_else(|_| "ci-admin-key".to_string())
}

async fn admin_get(base: &str, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .get(format!("{base}{uri}"))
        .header("x-admin-key", admin_key())
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let value = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, value)
}

/// Codex quota body in the shape OpenAI actually returns, including the `window_minutes` that
/// distinguishes the session window from the weekly one.
const CODEX_QUOTA: &str = r#"{
  "plan_type": "pro",
  "rate_limits": {
    "primary_window":   {"window_minutes": 300,  "used_percent": 42, "reset_at": 1800000000},
    "secondary_window": {"window_minutes": 10080, "used_percent": 20, "reset_at": 1800003600}
  }
}"#;

/// Anthropic passive headers on an inference response. `utilization` counts consumption.
const ANTHROPIC_HEADERS: &[(&str, &str)] = &[
    ("anthropic-ratelimit-unified-5h-utilization", "87"),
    ("anthropic-ratelimit-unified-5h-reset", "1800000000"),
    ("anthropic-ratelimit-unified-7d-utilization", "20"),
];

/// A Codex OAuth route. The proxy response carries quota headers, so the passive path fills the
/// store with no admin call at all.
#[sqlx::test(migrations = "./migrations")]
async fn response_headers_populate_the_store_through_the_proxy(pool: PgPool) {
    let capture = Capture::default();
    let base = spawn_provider("codex_responses", CODEX_QUOTA, &[], capture).await;

    sqlx::query(
        "INSERT INTO backends (id, name, base_url, api_key_ref, weight, max_inflight, format, enabled) \
         VALUES (1, 'codex-oauth', $1, 'env:UNSET_CODEX_KEY', 1, 100, 'openai', TRUE)",
    )
    .bind(&base)
    .execute(&pool)
    .await
    .unwrap();

    let key_ref = write_credential(data_dir(), "codex", "headers_from_proxy", "codex-at");
    sqlx::query(
        "INSERT INTO model_routes (model_name, backend_ids, provider_model_name, enabled, \
         auth_mode, protocol, provider_key_ref) \
         VALUES ('codex-fast', '[1]', 'gpt-5-codex', TRUE, 'chatgpt_oauth', \
                 'codex_responses', $1)",
    )
    .bind(&key_ref)
    .execute(&pool)
    .await
    .unwrap();

    seed_auth(&pool).await;
    let loader = brighto_router::config::DbConfigLoader::new(pool.clone(), 5);
    let Harness { app, quota } = router_for(pool.clone(), loader.load_snapshot().await.unwrap());

    let resp = call(&app, "codex_responses", "codex-fast").await;
    assert_eq!(resp.status().as_u16(), 200);

    // The mock sent no quota headers on the inference response, so nothing should be recorded.
    // This is the assertion that keeps the hot path honest: silence is not an empty snapshot.
    let key = QuotaKey::new("codex", "headers_from_proxy");
    assert!(
        quota.get(&key).is_none(),
        "a response with no quota headers must not create a snapshot"
    );

    // Now the same request through a provider that does send them.
    let capture2 = Capture::default();
    let base2 = spawn_provider("anthropic_messages", "{}", ANTHROPIC_HEADERS, capture2).await;
    sqlx::query("UPDATE backends SET base_url = $1 WHERE id = 1")
        .bind(&base2)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO model_routes (model_name, backend_ids, provider_model_name, enabled, \
         auth_mode, protocol, provider_key_ref) \
         VALUES ('claude-fast', '[1]', 'claude-sonnet-4-5', TRUE, 'anthropic_oauth', \
                 'anthropic_messages', $1)",
    )
    .bind(write_credential(
        data_dir(),
        "claude-code",
        "headers_from_proxy_claude",
        "claude-at",
    ))
    .execute(&pool)
    .await
    .unwrap();

    let loader = brighto_router::config::DbConfigLoader::new(pool.clone(), 5);
    let Harness { app, quota } = router_for(pool.clone(), loader.load_snapshot().await.unwrap());
    let resp = call(&app, "anthropic_messages", "claude-fast").await;
    assert_eq!(resp.status().as_u16(), 200);

    let key = QuotaKey::new("claude-code", "headers_from_proxy_claude");
    let snapshot = quota
        .get(&key)
        .expect("quota snapshot from response headers");
    let windows = snapshot.effective_windows();
    assert_eq!(windows.len(), 2, "5h and 7d, both from headers");

    let five = windows
        .iter()
        .find(|w| w.id == QuotaWindowId::FiveHour)
        .expect("5h window");
    // 87% used leaves 13%, and the fraction is derived rather than stored.
    assert!((five.remaining_fraction().unwrap() - 0.13).abs() < 1e-6);
    assert_eq!(five.reset_at, Some(1_800_000_000_000));
    assert_eq!(five.source, quota::QuotaSource::ResponseHeader);
    assert!(
        snapshot.probe.is_none(),
        "a passive read must not invent an active probe result"
    );
}

/// An API-key route sends no quota key, so nothing is observed and nothing is allocated. Without
/// this the router would need per-request bookkeeping to "know" a route is unobservable.
#[test]
fn an_api_key_route_observes_nothing() {
    let key = QuotaKey::from_credential_ref("env:OPENAI_API_KEY");
    assert!(
        key.is_none(),
        "only an oauth: reference identifies an account"
    );
    assert!(QuotaKey::from_credential_ref("file:/tmp/key").is_none());
}

/// The admin API reports `used`/`total` and a coarse level, never a percentage a provider could
/// poison. This is the payload-level version of the `used`/`total` rule.
#[sqlx::test(migrations = "./migrations")]
async fn the_admin_api_never_ships_a_precomputed_percentage(pool: PgPool) {
    let Harness { app, quota } = router_for(pool.clone(), empty_snapshot());
    let base = serve(app).await;
    let key = QuotaKey::new("codex", "admin_payload");
    quota.record_probe(
        &key,
        vec![QuotaWindow::percent_window(
            QuotaWindowId::FiveHour,
            42.0,
            None,
            quota::QuotaSource::Provider,
        )],
        Some("pro".into()),
        false,
        None,
    );

    let (status, body) = admin_get(&base, "/admin/quota").await;
    assert_eq!(status, StatusCode::OK);
    let accounts = body["accounts"].as_array().expect("accounts array");
    assert_eq!(accounts.len(), 1);

    let w = &accounts[0]["windows"][0];
    assert_eq!(w["id"], "five_hour");
    assert_eq!(w["used"], 42.0);
    assert_eq!(w["total"], 100.0);
    assert_eq!(w["level"], "low");
    assert_eq!(w["kind"], "window");
    assert_eq!(w["derived"], false);
    assert_eq!(w["exhausted"], false);
    assert_eq!(accounts[0]["plan"], "pro");
    assert_eq!(accounts[0]["stale"], false);

    let serialized = serde_json::to_string(&body).unwrap();
    assert!(
        !serialized.contains("remaining"),
        "the payload must not carry a provider-controlled field named `remaining`: {serialized}"
    );
}

/// A credit balance is an amount. Rendering it as a percentage is the reference implementation's
/// documented 100x bug, so the payload has to say what kind of number it is.
#[sqlx::test(migrations = "./migrations")]
async fn a_credit_balance_is_reported_as_a_balance(pool: PgPool) {
    let Harness { app, quota } = router_for(pool.clone(), empty_snapshot());
    let base = serve(app).await;
    let key = QuotaKey::new("xai-oauth", "balance_row");
    quota.record_probe(
        &key,
        vec![quota::observe::balance_window(
            QuotaWindowId::OnDemand,
            348.0,
            quota::QuotaSource::Provider,
        )],
        None,
        false,
        None,
    );

    let (_, body) = admin_get(&base, "/admin/quota").await;
    let w = &body["accounts"][0]["windows"][0];
    assert_eq!(w["kind"], "balance", "348 credits is not 348%");
    assert_eq!(w["used"], 348.0);
    assert_eq!(w["level"], "unknown", "a count has no percentage band");
    assert_eq!(w["exhausted"], false);
}

/// Unknown is not zero. A window the provider did not report must not read as empty, or an
/// operator concludes an account is spent when the truth is that nobody said.
#[sqlx::test(migrations = "./migrations")]
async fn an_unreported_window_is_not_an_empty_one(pool: PgPool) {
    let Harness { app, quota } = router_for(pool.clone(), empty_snapshot());
    let base = serve(app).await;
    let key = QuotaKey::new("codex", "unreported");
    quota.record_probe(
        &key,
        vec![QuotaWindow {
            id: QuotaWindowId::Month,
            kind: QuotaWindowKind::Window,
            used: 12.0,
            total: 0.0,
            unlimited: false,
            reset_at: None,
            source: quota::QuotaSource::Provider,
            variant: None,
        }],
        None,
        false,
        None,
    );

    let (_, body) = admin_get(&base, "/admin/quota").await;
    let account = &body["accounts"][0];
    let w = &account["windows"][0];
    assert_eq!(w["level"], "unknown");
    assert_eq!(w["exhausted"], false);
    assert_eq!(
        account["exhausted"], false,
        "an account with one unknown window is not an exhausted account"
    );
}

/// A failed probe must keep the last good reading. Blanking the panel on a provider's bad minute
/// makes "no data" and "no allowance" look identical.
#[sqlx::test(migrations = "./migrations")]
async fn a_failed_probe_keeps_the_last_good_reading(pool: PgPool) {
    let Harness { app, quota } = router_for(pool.clone(), empty_snapshot());
    let base = serve(app).await;
    let key = QuotaKey::new("claude-code", "stale_reading");
    quota.record_probe(
        &key,
        vec![QuotaWindow::percent_window(
            QuotaWindowId::FiveHour,
            10.0,
            None,
            quota::QuotaSource::Provider,
        )],
        None,
        false,
        None,
    );
    quota.record_probe(
        &key,
        vec![QuotaWindow::percent_window(
            QuotaWindowId::FiveHour,
            10.0,
            None,
            quota::QuotaSource::Provider,
        )],
        None,
        true,
        Some("quota probe returned HTTP 503".into()),
    );

    let (_, body) = admin_get(&base, "/admin/quota").await;
    let account = &body["accounts"][0];
    assert_eq!(
        account["windows"].as_array().unwrap().len(),
        1,
        "the previous reading survives"
    );
    assert_eq!(
        account["notes"][0]["message"],
        "quota probe returned HTTP 503"
    );
    assert_eq!(account["notes"][0]["stale"], true);
}

/// Active probes are gated per credential. Two probes a second apart make one HTTP request; the
/// second is refused locally. A Portal polling every few seconds must not become provider load.
#[sqlx::test(migrations = "./migrations")]
async fn repeated_probes_are_rate_limited_per_credential(_pool: PgPool) {
    let capture = Capture::default();
    let base = spawn_provider("codex_responses", CODEX_QUOTA, &[], capture.clone()).await;

    let label = "probe_gate";
    write_credential(data_dir(), "codex", label, "codex-at-probe");

    let store = Arc::new(oauth::OAuthTokenStore::from_env());
    let quota_store = Arc::new(QuotaStore::new());
    let prober = brighto_router::quota::probe::QuotaProbe::new(
        reqwest::Client::new(),
        store,
        quota_store.clone(),
    );
    // The probe URL comes from the provider spec, which is a real vendor host. Redirecting it at
    // the mock is the only way to test this contract without a live subscription account.
    prober.set_base_url("codex", &base);
    let key = QuotaKey::new("codex", label);

    let first = prober.refresh(&key, true).await;
    assert!(!first.windows.is_empty(), "mock returned the Codex shape");
    assert!(first.ok);

    // Second call inside the interval is refused without a request.
    let second = prober.refresh(&key, false).await;
    assert!(
        second.skipped,
        "the min-interval gate must refuse a second probe"
    );
    assert!(
        second.note.unwrap_or_default().contains("last probed"),
        "a skip must say why"
    );

    // Only one upstream request reached the mock.
    let paths = capture.paths();
    assert!(
        paths.iter().filter(|p| p.contains("/wham")).count() <= 1,
        "expected at most one quota request, got {paths:?}"
    );

    // The parsed windows land in the store with the right shape.
    let snapshot = quota_store.get(&key).expect("snapshot");
    let five = snapshot
        .effective_windows()
        .into_iter()
        .find(|w| w.id == QuotaWindowId::FiveHour)
        .expect("session window from window_minutes=300");
    assert_eq!(five.used, 42.0);
    let week = snapshot
        .effective_windows()
        .into_iter()
        .find(|w| w.id == QuotaWindowId::SevenDay)
        .expect("weekly window from window_minutes=10080");
    assert_eq!(week.used, 20.0);
    assert_eq!(snapshot.plan.as_deref(), Some("pro"));
}

/// The probe request is built by the same `apply_headers` the inference request uses, so a 403 on
/// the quota endpoint is a statement about the credential rather than about a different request.
#[test]
fn the_probe_request_carries_the_oauth_credential() {
    let spec = oauth::spec("claude-code").expect("claude spec");
    let probe = spec.quota_probe.expect("claude probe");
    assert_eq!(probe.shape, oauth::QuotaShape::Claude);
    assert_eq!(probe.query, "cedar_ember=1");
    assert_eq!(
        probe.extra_headers.len(),
        0,
        "credential headers come from apply_headers"
    );

    let mut headers = axum::http::HeaderMap::new();
    brighto_router::provider_auth::apply_headers(
        &mut headers,
        &brighto_router::provider_auth::resolve(spec.auth_mode, true, None),
        "secret",
    )
    .unwrap();
    assert_eq!(headers.get("authorization").unwrap(), "Bearer secret");
    assert!(headers.contains_key("anthropic-version"));
    assert!(headers.contains_key("anthropic-beta"));
    assert!(
        !headers.contains_key("x-api-key"),
        "an OAuth access token must never go in x-api-key"
    );
}

/// A route whose response carries no quota headers leaves the store empty even after many
/// requests. The bounded scan must not accumulate state.
#[sqlx::test(migrations = "./migrations")]
async fn repeated_headerless_responses_do_not_grow_the_store(pool: PgPool) {
    let capture = Capture::default();
    let base = spawn_provider("codex_responses", "{}", &[], capture).await;
    sqlx::query(
        "INSERT INTO backends (id, name, base_url, api_key_ref, weight, max_inflight, format, enabled) \
         VALUES (1, 'quiet', $1, 'env:UNSET_QUIET_KEY', 1, 100, 'openai', TRUE)",
    )
    .bind(&base)
    .execute(&pool)
    .await
    .unwrap();
    let key_ref = write_credential(data_dir(), "codex", "quiet_route", "codex-at");
    sqlx::query(
        "INSERT INTO model_routes (model_name, backend_ids, provider_model_name, enabled, \
         auth_mode, protocol, provider_key_ref) \
         VALUES ('quiet-model', '[1]', 'gpt-5-codex', TRUE, 'chatgpt_oauth', \
                 'codex_responses', $1)",
    )
    .bind(&key_ref)
    .execute(&pool)
    .await
    .unwrap();
    seed_auth(&pool).await;

    let loader = brighto_router::config::DbConfigLoader::new(pool.clone(), 5);
    let Harness { app, quota } = router_for(pool.clone(), loader.load_snapshot().await.unwrap());
    for _ in 0..5 {
        assert_eq!(
            call(&app, "codex_responses", "quiet-model")
                .await
                .status()
                .as_u16(),
            200
        );
    }
    assert!(
        quota.is_empty(),
        "five headerless responses produced {} snapshot(s)",
        quota.len()
    );
}

fn empty_snapshot() -> brighto_router::contract::ConfigSnapshot {
    brighto_router::contract::ConfigSnapshot::default()
}
