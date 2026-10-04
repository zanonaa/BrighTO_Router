//! Chat -> Responses translation integration: a chat-family route (`/v1/chat/completions`) whose
//! Model Group holds a Responses-family endpoint. Mock upstreams serve the exact Responses wire
//! shape (JSON non-stream and SSE stream), proving:
//!
//! * the upstream request is translated (instructions + input items, flattened tools,
//!   `max_output_tokens`, `store:false`, no `messages`, no `stream_options`);
//! * a non-streaming client gets one `chat.completion` back (`responses_json_to_chat_completion`);
//! * a streaming client gets incremental `chat.completion.chunk` frames ending in `[DONE]`
//!   (`ResponsesSseToChat` in the proxy SSE pump), with usage tapped into the ledger;
//! * an SSE-only upstream (the pinned Codex behavior) answering a non-stream client is folded into
//!   one completion, tool calls included.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::body::{Body, Bytes, to_bytes};
use axum::http::Request;
use futures::StreamExt;
use sqlx::postgres::PgPool;
use tower::ServiceExt;

use brighto_router::budget::RamBudgetStore;
use brighto_router::contract::{AppState, UsageEvent};
use brighto_router::ledger::LedgerSink;
use brighto_router::metrics::Metrics;
use brighto_router::route::RamBackendPool;

fn metrics() -> Metrics {
    static M: std::sync::OnceLock<Metrics> = std::sync::OnceLock::new();
    M.get_or_init(Metrics::install).clone()
}

/// Mock Responses upstream: serves `/v1/responses` JSON or SSE depending on the request body, and
/// captures every translated request it receives.
async fn spawn_responses_backend() -> (String, tokio::sync::mpsc::Receiver<serde_json::Value>) {
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let app = axum::Router::new().route(
        "/v1/responses",
        axum::routing::post(move |body: Bytes| {
            let tx = tx.clone();
            async move {
                let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                tx.send(value.clone()).await.unwrap();
                let stream = value.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
                if stream {
                    let sse = concat!(
                        "event: response.created\n",
                        "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_abc\",\"created_at\":1700000000}}\n\n",
                        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hel\"}\n\n",
                        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"lo\"}\n\n",
                        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_abc\",\"created_at\":1700000000,\"usage\":{\"input_tokens\":21,\"output_tokens\":5,\"total_tokens\":26}}}\n\n",
                        "data: [DONE]\n\n"
                    );
                    axum::response::Response::builder()
                        .status(200)
                        .header("content-type", "text/event-stream")
                        .body(Body::from(sse))
                        .unwrap()
                } else {
                    axum::response::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            r#"{"id":"resp_abc","object":"response","created_at":1700000000,"model":"gpt-5.6-codex",
                                "output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"OK from responses"}]}],
                                "output_text":"OK from responses",
                                "usage":{"input_tokens":12,"output_tokens":4,"total_tokens":16}}"#,
                        ))
                        .unwrap()
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), rx)
}

/// SSE-only Responses upstream that ignores `stream` entirely — the pinned Codex behavior: even a
/// non-streaming translated request comes back as SSE, so the router must fold it.
async fn spawn_sse_only_responses_backend() -> String {
    let app = axum::Router::new().route(
        "/v1/responses",
        axum::routing::post(|| async {
            let sse = concat!(
                "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_pin\",\"created_at\":1700000000}}\n\n",
                "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call_1\",\"name\":\"get_weather\",\"arguments\":\"{\\\"city\\\":\\\"Hanoi\\\"}\"}}\n\n",
                "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_pin\",\"created_at\":1700000000,\"usage\":{\"input_tokens\":8,\"output_tokens\":3,\"total_tokens\":11}}}\n\n",
                "data: [DONE]\n\n"
            );
            axum::response::Response::builder()
                .status(200)
                .header("content-type", "text/event-stream")
                .body(Body::from(sse))
                .unwrap()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

/// One chat route (`openai_chat`) with one Responses-family endpoint: the mismatch is the trigger.
/// Returns the state wired to an observable ledger channel.
async fn build_translated_route_state(
    pool: PgPool,
    backend_base: String,
    endpoint_protocol: &str,
) -> (Arc<AppState>, tokio::sync::mpsc::Receiver<UsageEvent>) {
    let key_file = std::env::temp_dir().join(format!("brighto_tr_key_{}", std::process::id()));
    std::fs::write(&key_file, "mockkey").unwrap();
    let key_ref = format!("file:{}", key_file.display());

    sqlx::query(
        "INSERT INTO backends (id, name, base_url, api_key_ref, weight, max_inflight, format, enabled) \
         VALUES (1, 'responses-endpoint', $1, $2, 1, 100, 'openai', TRUE)",
    )
    .bind(&backend_base)
    .bind(&key_ref)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO model_routes \
         (model_name, backend_ids, fallback_backend_id, chars_per_token, first_byte_timeout, \
          provider_model_name, enabled, auth_mode, protocol, routing_policy) \
         VALUES ('combo-chat', '[1]', NULL, 4.0, 180, 'combo-chat', TRUE, 'bearer', 'openai_chat', 'least_loaded_weighted')",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO model_route_endpoints \
         (model_name, backend_id, provider_model_name, provider_key_ref, auth_mode, protocol, weight, max_inflight, enabled) \
         VALUES ('combo-chat', 1, 'gpt-5.6-codex', $1, 'bearer', $2, 1, 100, TRUE)",
    )
    .bind(&key_ref)
    .bind(endpoint_protocol)
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
        "INSERT INTO api_keys (id, key_hash, key_prefix, team_id, owner, allowed_models, budget, rpm_limit, concurrency_limit, expires_at, enabled) \
         VALUES (1, $1, 'sk-brigh', 1, 'tester', '[]', NULL, NULL, NULL, NULL, TRUE)",
    )
    .bind(&key_hash)
    .execute(&pool)
    .await
    .unwrap();

    let loader = brighto_router::config::DbConfigLoader::new(pool, 5);
    let snap = loader.load_snapshot().await.unwrap();
    let cfg = Arc::new(ArcSwap::from_pointee(snap));
    let budget = Arc::new(RamBudgetStore::new());
    budget.load_teams(&cfg.load_full().teams);
    let backends = Arc::new(RamBackendPool::new());
    for b in cfg.load_full().backends.values() {
        backends.upsert_backend(b.clone());
    }
    let (ptx, prx) = tokio::sync::mpsc::channel(8192);
    let (otx, mut orx) = tokio::sync::mpsc::channel(8192);
    tokio::spawn(async move { while orx.recv().await.is_some() {} });
    let state = Arc::new(AppState {
        cfg,
        budget,
        backends,
        client: reqwest::Client::new(),
        ledger: LedgerSink::new(ptx, otx),
        metrics: metrics(),
        max_body_bytes: 10 * 1024 * 1024,
        quota: Arc::new(brighto_router::quota::QuotaStore::new()),
        reload_notify: Arc::new(tokio::sync::Notify::new()),
        dynamic_catalogs: Arc::new(brighto_router::catalog::DynamicCatalogStore::new_default()),
        config_ok_at: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        config_err_at: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        readiness_max_stale_ms: 5_000,
    });
    (state, prx)
}

#[sqlx::test(migrations = "./migrations")]
async fn chat_client_nonstream_translates_request_and_response(pool: PgPool) {
    let (backend_base, mut upstream_rx) = spawn_responses_backend().await;
    let (state, mut ledger_rx) =
        build_translated_route_state(pool, backend_base, "openai_responses").await;
    let app = brighto_router::handlers::router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("authorization", "Bearer test-key")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"model":"combo-chat","stream":false,"messages":[
                {"role":"system","content":"be terse"},
                {"role":"user","content":"hello"}
            ],"max_tokens":64,"temperature":0.2,
            "tools":[{"type":"function","function":{"name":"get_weather","description":"d","parameters":{"type":"object"}}}]}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = to_bytes(resp.into_body(), 10 * 1024 * 1024).await.unwrap();
    let completion: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(completion["object"], "chat.completion");
    assert_eq!(completion["model"], "combo-chat", "client-facing name only");
    assert_eq!(completion["id"], "resp_abc");
    assert_eq!(completion["created"], 1_700_000_000u64);
    assert_eq!(
        completion["choices"][0]["message"]["content"],
        "OK from responses"
    );
    assert_eq!(completion["choices"][0]["finish_reason"], "stop");
    assert_eq!(completion["usage"]["prompt_tokens"], 12);
    assert_eq!(completion["usage"]["completion_tokens"], 4);
    assert_eq!(completion["usage"]["total_tokens"], 16);

    // The upstream saw a Responses request, not chat.
    let upstream = tokio::time::timeout(Duration::from_secs(2), upstream_rx.recv())
        .await
        .expect("upstream capture")
        .unwrap();
    assert_eq!(upstream["model"], "gpt-5.6-codex", "endpoint model applied");
    assert_eq!(upstream["instructions"], "be terse");
    assert_eq!(upstream["input"][0]["role"], "user");
    assert_eq!(upstream["input"][0]["content"][0]["type"], "input_text");
    assert_eq!(upstream["input"][0]["content"][0]["text"], "hello");
    assert_eq!(upstream["tools"][0]["type"], "function");
    assert_eq!(upstream["tools"][0]["name"], "get_weather");
    assert!(
        upstream["tools"][0].get("function").is_none(),
        "tools must be flattened"
    );
    assert_eq!(upstream["max_output_tokens"], 64);
    assert_eq!(upstream["temperature"], 0.2);
    assert_eq!(upstream["stream"], false);
    assert_eq!(upstream["store"], false);
    for dropped in ["messages", "stream_options", "max_tokens"] {
        assert!(upstream.get(dropped).is_none(), "{dropped} leaked upstream");
    }

    let ev = tokio::time::timeout(Duration::from_secs(2), ledger_rx.recv())
        .await
        .expect("ledger event")
        .unwrap();
    assert_eq!(ev.model, "combo-chat");
    assert_eq!(ev.input_tokens, 12);
    assert_eq!(ev.output_tokens, 4);
    assert!(!ev.estimated);
}

#[sqlx::test(migrations = "./migrations")]
async fn chat_client_stream_gets_incremental_chat_chunks(pool: PgPool) {
    let (backend_base, mut upstream_rx) = spawn_responses_backend().await;
    let (state, mut ledger_rx) =
        build_translated_route_state(pool, backend_base, "openai_responses").await;
    let app = brighto_router::handlers::router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("authorization", "Bearer test-key")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"model":"combo-chat","stream":true,"messages":[{"role":"user","content":"hello"}]}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "text/event-stream"
    );

    let mut body = Vec::new();
    let mut stream = resp.into_body().into_data_stream();
    while let Some(chunk) = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("next stream chunk")
    {
        body.extend_from_slice(&chunk.expect("chunk bytes"));
    }
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("\"object\":\"chat.completion.chunk\""),
        "{text}"
    );
    assert!(text.contains("\"content\":\"Hel\""), "{text}");
    assert!(text.contains("\"content\":\"lo\""), "{text}");
    assert!(text.contains("\"finish_reason\":\"stop\""), "{text}");
    assert!(text.contains("\"prompt_tokens\":21"), "{text}");
    assert!(text.contains("\"model\":\"combo-chat\""), "{text}");
    assert!(text.trim_end().ends_with("data: [DONE]"), "{text}");
    assert!(
        !text.contains("response.output_text"),
        "upstream events must not leak through: {text}"
    );

    // The streaming request still went upstream as Responses.
    let upstream = tokio::time::timeout(Duration::from_secs(2), upstream_rx.recv())
        .await
        .expect("upstream capture")
        .unwrap();
    assert_eq!(upstream["model"], "gpt-5.6-codex");
    assert_eq!(upstream["stream"], true);
    assert_eq!(upstream["store"], false);

    // Usage tapped from the translated final chunk.
    let ev = tokio::time::timeout(Duration::from_secs(2), ledger_rx.recv())
        .await
        .expect("ledger event")
        .unwrap();
    assert_eq!(ev.input_tokens, 21);
    assert_eq!(ev.output_tokens, 5);
    assert!(!ev.estimated);
    assert!(ev.stream);
}

#[sqlx::test(migrations = "./migrations")]
async fn sse_only_upstream_folds_tool_calls_into_one_completion(pool: PgPool) {
    let backend_base = spawn_sse_only_responses_backend().await;
    let (state, mut ledger_rx) =
        build_translated_route_state(pool, backend_base, "openai_responses").await;
    let app = brighto_router::handlers::router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("authorization", "Bearer test-key")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"model":"combo-chat","stream":false,"messages":[{"role":"user","content":"weather?"}]}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = to_bytes(resp.into_body(), 10 * 1024 * 1024).await.unwrap();
    let completion: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(completion["object"], "chat.completion");
    let message = &completion["choices"][0]["message"];
    assert_eq!(message["content"], serde_json::Value::Null);
    let call = &message["tool_calls"][0];
    assert_eq!(call["id"], "call_1");
    assert_eq!(call["type"], "function");
    assert_eq!(call["function"]["name"], "get_weather");
    assert_eq!(call["function"]["arguments"], "{\"city\":\"Hanoi\"}");
    assert_eq!(completion["choices"][0]["finish_reason"], "tool_calls");
    assert_eq!(completion["usage"]["prompt_tokens"], 8);
    assert_eq!(completion["usage"]["completion_tokens"], 3);

    let ev = tokio::time::timeout(Duration::from_secs(2), ledger_rx.recv())
        .await
        .expect("ledger event")
        .unwrap();
    assert_eq!(ev.input_tokens, 8);
    assert_eq!(ev.output_tokens, 3);
    assert!(!ev.estimated);
    assert!(!ev.stream);
}
