//! Combo admin API smoke: create/list/toggle/delete through the real admin HTTP surface.
//!
//! The admin handlers read `ConnectInfo<SocketAddr>` (the only trusted peer source), so the
//! router is served on a real socket like `quota_smoke` does. The admin pool is built from
//! `DATABASE_URL` at router-construction time, while `#[sqlx::test]` hands each test its own
//! database — the URL is therefore pointed at the test database only for the duration of the
//! router build, under a lock, and restored immediately after.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::Router;
use sqlx::Row;
use sqlx::postgres::PgPool;

use brighto_router::budget::RamBudgetStore;
use brighto_router::contract::AppState;
use brighto_router::ledger::LedgerSink;
use brighto_router::metrics::Metrics;
use brighto_router::route::RamBackendPool;

fn metrics() -> Metrics {
    static M: std::sync::OnceLock<Metrics> = std::sync::OnceLock::new();
    M.get_or_init(Metrics::install).clone()
}

fn admin_key() -> String {
    std::env::var("ADMIN_MASTER_KEY").unwrap_or_else(|_| "ci-admin-key".to_string())
}

/// Admin state captures `DATABASE_URL` synchronously while the router is built; this lock plus
/// the immediate restore keeps the process-global variable consistent for concurrent tests.
static ROUTER_BUILD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serve the full router (proxy + admin) with a DATABASE_URL pointing at THIS test's database.
async fn serve_admin_router(pool: &PgPool, state: Arc<AppState>) -> String {
    // Idempotent: loads .env values that are not already in the process environment, so this
    // also works under plain `cargo test` (sqlx::test does the same for its own setup).
    let _ = dotenvy::dotenv();
    let db: String = sqlx::query("SELECT current_database()")
        .fetch_one(pool)
        .await
        .unwrap()
        .try_get::<String, _>(0)
        .unwrap();
    let original = std::env::var("DATABASE_URL").expect("DATABASE_URL is set for tests");
    let (base, query) = match original.split_once('?') {
        Some((b, q)) => (b.to_string(), format!("?{q}")),
        None => (original.clone(), String::new()),
    };
    let idx = base
        .rfind('/')
        .expect("DATABASE_URL carries a database path");
    let test_url = format!("{}/{db}{query}", &base[..idx]);

    let _guard = ROUTER_BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: held under ROUTER_BUILD_LOCK for this binary's tests; restored immediately
    // after the admin state has captured the value.
    unsafe {
        std::env::set_var("DATABASE_URL", &test_url);
    }
    let app: Router = brighto_router::handlers::router(state);
    unsafe {
        std::env::set_var("DATABASE_URL", original);
    }
    drop(_guard);

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

async fn build_state(pool: PgPool) -> Arc<AppState> {
    let loader = brighto_router::config::DbConfigLoader::new(pool.clone(), 5);
    let snap = loader.load_snapshot().await.unwrap();
    let cfg = Arc::new(ArcSwap::from_pointee(snap));
    let budget = Arc::new(RamBudgetStore::new());
    budget.load_teams(&cfg.load_full().teams);
    let backends = Arc::new(RamBackendPool::new_with_counter_pool(pool.clone(), 1));
    for b in cfg.load_full().backends.values() {
        backends.upsert_backend(b.clone());
    }
    let (ptx, _prx) = tokio::sync::mpsc::channel(8192);
    let (otx, mut orx) = tokio::sync::mpsc::channel(8192);
    tokio::spawn(async move { while orx.recv().await.is_some() {} });
    Arc::new(AppState {
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
        dynamic_catalogs: Arc::new(brighto_router::catalog::DynamicCatalogStore::new_default()),
    })
}

async fn insert_backend(
    pool: &PgPool,
    id: i64,
    name: &str,
    api_key_ref: &str,
    provider_type: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO backends (id, name, base_url, api_key_ref, weight, max_inflight, format, enabled, provider_type) \
         VALUES ($1, $2, 'https://backend.example.com', $3, 1, 100, 'openai', TRUE, $4)",
    )
    .bind(id)
    .bind(name)
    .bind(api_key_ref)
    .bind(provider_type)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn combo_admin_endpoints_end_to_end(pool: PgPool) {
    insert_backend(
        &pool,
        7,
        "codex-pro",
        "oauth:codex:acct-a",
        Some("codex-oauth"),
    )
    .await;
    insert_backend(&pool, 2, "zai-main", "env:ZAI_API_KEY", Some("zai")).await;
    insert_backend(&pool, 9, "legacy-local", "file:/secrets/legacy.key", None).await;

    let state = build_state(pool.clone()).await;
    let base = serve_admin_router(&pool, state.clone()).await;
    let client = reqwest::Client::new();

    // --- POST create: 201, derived wiring, order preserved. ---
    let create = client
        .post(format!("{base}/admin/combos"))
        .header("x-admin-key", admin_key())
        .json(&serde_json::json!({
            "name": "zn-glm",
            "members": [
                {"backend_id": 7, "model": "gpt-6.1-sol"},
                {"backend_id": 2, "model": "glm-5.3"},
                {"backend_id": 9, "model": "qwen3.8-flash-next"}
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status().as_u16(), 201, "first POST creates");
    let body: serde_json::Value = create.json().await.unwrap();
    assert_eq!(body["name"], "zn-glm");
    assert_eq!(body["enabled"], true);
    let members = body["members"].as_array().unwrap();
    assert_eq!(
        members
            .iter()
            .map(|m| m["backend_id"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        vec![7, 2, 9]
    );
    assert_eq!(members[0]["protocol"], "codex_responses");
    assert_eq!(members[0]["auth_mode"], "chatgpt_oauth");
    assert_eq!(members[0]["backend_name"], "codex-pro");
    assert_eq!(members[0]["weight"], 8);
    assert_eq!(members[1]["protocol"], "openai_chat");
    assert_eq!(members[1]["weight"], 4);
    assert_eq!(members[2]["weight"], 2);

    // The admin mutation reloaded the live snapshot: the combo serves immediately.
    let snap = state.cfg.load_full();
    let route = snap.routes.get("zn-glm").expect("combo live after POST");
    assert_eq!(route.endpoints.len(), 3);
    assert_eq!(route.endpoint_weight(7), 8);

    // --- POST upsert: 200, members replaced, definition order wins. ---
    let update = client
        .post(format!("{base}/admin/combos"))
        .header("x-admin-key", admin_key())
        .json(&serde_json::json!({
            "name": "zn-glm",
            "members": [
                {"backend_id": 9, "model": "qwen3.8-flash-next"},
                {"backend_id": 2, "model": "glm-5.3"}
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status().as_u16(), 200, "second POST updates");
    let body: serde_json::Value = update.json().await.unwrap();
    assert_eq!(
        body["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["backend_id"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        vec![9, 2],
        "upsert replaces members in the new order"
    );

    // --- Validation reaches HTTP: duplicate backend 400 with the split-accounts hint. ---
    let dup = client
        .post(format!("{base}/admin/combos"))
        .header("x-admin-key", admin_key())
        .json(&serde_json::json!({
            "name": "bad-combo",
            "members": [
                {"backend_id": 2, "model": "a"},
                {"backend_id": 2, "model": "b"}
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status().as_u16(), 400);
    let text = dup.text().await.unwrap();
    assert!(text.contains("keyed by backend_id"), "got: {text}");

    // --- GET list: definition order roundtrip. ---
    let list = client
        .get(format!("{base}/admin/combos"))
        .header("x-admin-key", admin_key())
        .send()
        .await
        .unwrap();
    assert_eq!(list.status().as_u16(), 200);
    let list: serde_json::Value = list.json().await.unwrap();
    let combos = list.as_array().unwrap();
    assert_eq!(combos.len(), 1);
    let combo = &combos[0];
    assert_eq!(combo["name"], "zn-glm");
    assert_eq!(
        combo["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["backend_id"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        vec![9, 2],
        "GET replays the definition order from combo_members"
    );
    assert_eq!(combo["members"][0]["backend_name"], "legacy-local");
    assert_eq!(combo["members"][0]["weight"], 8);

    // --- DELETE blocked by usage history -> falls back to disable. ---
    sqlx::query(
        "INSERT INTO usage_ledger \
         (ts, request_id, key_id, team_id, model, backend_id, status, input_tokens, output_tokens, \
          estimated, ttfb_ms, total_ms, router_overhead_ms, stream, client_aborted) \
         VALUES (0, 'r1', 1, 1, 'zn-glm', 9, 200, 1, 1, FALSE, 0, 0, 0, FALSE, FALSE)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let blocked = client
        .delete(format!("{base}/admin/combos/zn-glm"))
        .header("x-admin-key", admin_key())
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status().as_u16(), 409);
    let text = blocked.text().await.unwrap();
    assert!(text.contains("disable"), "got: {text}");

    let toggle = client
        .patch(format!("{base}/admin/combos/zn-glm/enabled"))
        .header("x-admin-key", admin_key())
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(toggle.status().as_u16(), 200);
    let toggled: serde_json::Value = toggle.json().await.unwrap();
    assert_eq!(toggled["enabled"], false);

    let list = client
        .get(format!("{base}/admin/combos"))
        .header("x-admin-key", admin_key())
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = list.json().await.unwrap();
    assert_eq!(list[0]["enabled"], false, "combo survives, disabled");

    // --- Manual routes are never hijacked: 409, and 404 on the combo paths. ---
    sqlx::query(
        "INSERT INTO model_routes (model_name, backend_ids, chars_per_token, first_byte_timeout) \
         VALUES ('manual-model', '[2]', 4.0, 180)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let hijack = client
        .post(format!("{base}/admin/combos"))
        .header("x-admin-key", admin_key())
        .json(&serde_json::json!({
            "name": "manual-model",
            "members": [{"backend_id": 2, "model": "glm-5.3"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(hijack.status().as_u16(), 409);
    let manual_delete = client
        .delete(format!("{base}/admin/combos/manual-model"))
        .header("x-admin-key", admin_key())
        .send()
        .await
        .unwrap();
    assert_eq!(manual_delete.status().as_u16(), 404);

    // --- Fresh combo deletes cleanly (usage row names the other combo). ---
    client
        .post(format!("{base}/admin/combos"))
        .header("x-admin-key", admin_key())
        .json(&serde_json::json!({
            "name": "temp-combo",
            "members": [{"backend_id": 2, "model": "glm-5.3"}]
        }))
        .send()
        .await
        .unwrap();
    let deleted = client
        .delete(format!("{base}/admin/combos/temp-combo"))
        .header("x-admin-key", admin_key())
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    // --- Auth still applies: no key, no combos. ---
    let unauthorized = client
        .get(format!("{base}/admin/combos"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status().as_u16(), 401);
}

/// The proxy serves a combo like any Model Group: a chat-dialect client request reaches a
/// responses-family member translated (main's chat->responses path) — proving the derived
/// wiring is not just persisted but actually routable. Fully offline: the member backend is a
/// local mock with an explicit per-member override.
#[sqlx::test(migrations = "./migrations")]
async fn combo_serves_traffic_through_the_chat_dialect(pool: PgPool) {
    use axum::body::{Body, Bytes};

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let mock = axum::Router::new().route(
        "/v1/responses",
        axum::routing::post(move |body: Bytes| {
            let tx = tx.clone();
            async move {
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let model = body["model"].as_str().unwrap().to_string();
                let _ = tx.send(model).await;
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"id":"resp_abc","object":"response","created_at":1700000000,"model":"grok-code-fast-1",
                            "output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"OK from responses"}]}],
                            "output_text":"OK from responses",
                            "usage":{"input_tokens":12,"output_tokens":4,"total_tokens":16}}"#,
                    ))
                    .unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, mock).await;
    });

    let key_file = std::env::temp_dir().join(format!("brighto_combo_key_{}", std::process::id()));
    std::fs::write(&key_file, "mock-provider-key").unwrap();
    let key_ref = format!("file:{}", key_file.display());

    sqlx::query(
        "INSERT INTO backends (id, name, base_url, api_key_ref, weight, max_inflight, format, enabled) \
         VALUES (5, 'responses-mock', $1, $2, 1, 100, 'openai', TRUE)",
    )
    .bind(format!("http://{mock_addr}"))
    .bind(&key_ref)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO teams (id, name, budget, enabled) VALUES (1, 'team-1', $1, TRUE)")
        .bind(r#"{"period":"day","max_tokens":1000000,"per_model":{}}"#)
        .execute(&pool)
        .await
        .unwrap();
    let key_hash = hex::encode(brighto_router::auth::hash_key("test-key"));
    sqlx::query(
        "INSERT INTO api_keys (id, key_hash, key_prefix, team_id, owner, allowed_models, enabled) \
         VALUES (1, $1, 'sk-brigh', 1, 'tester', '[]', TRUE)",
    )
    .bind(&key_hash)
    .execute(&pool)
    .await
    .unwrap();

    let state = build_state(pool.clone()).await;
    let base = serve_admin_router(&pool, state.clone()).await;
    let client = reqwest::Client::new();

    // One admin call; the only hand-written wiring is the override for the no-registry mock.
    let create = client
        .post(format!("{base}/admin/combos"))
        .header("x-admin-key", admin_key())
        .json(&serde_json::json!({
            "name": "zn-glm",
            "members": [{
                "backend_id": 5,
                "model": "grok-code-fast-1",
                "protocol": "openai_responses",
                "auth_mode": "bearer"
            }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status().as_u16(), 201, "combo created over HTTP");
    let body: serde_json::Value = create.json().await.unwrap();
    assert_eq!(body["members"][0]["protocol"], "openai_responses");
    assert_eq!(body["members"][0]["weight"], 8);

    // Client speaks OpenAI Chat; the member speaks Responses. Translation is main's job —
    // here we assert the combo route makes the two meet.
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("authorization", "Bearer test-key")
        .json(&serde_json::json!({
            "model": "zn-glm",
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let chat: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        chat["choices"][0]["message"]["content"],
        "OK from responses"
    );

    let upstream_model = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("upstream saw the request")
        .expect("model captured");
    assert_eq!(
        upstream_model, "grok-code-fast-1",
        "the member's provider model name must reach the upstream, not the combo name"
    );
}
