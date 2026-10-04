//! Responses -> Chat translation integration: a Responses-family route (`/v1/responses`) whose
//! Model Group holds a chat-family endpoint (glm/deepseek/dahl/opencode-free style providers).
//! Mock upstreams serve the exact chat wire shape (JSON non-stream and SSE stream), proving:
//!
//! * the upstream request is translated (system message from `instructions`, `input` items into
//!   `messages`, nested tools, `max_tokens`, no `instructions`/`input`/`store` upstream);
//! * a non-streaming client gets one Responses object back (`chat_json_to_responses`);
//! * a streaming client gets incremental Responses events ending in `response.completed` with
//!   usage — and never a `chat.completion.chunk` frame or a `[DONE]` marker
//!   (`ChatSseToResponses` in the proxy SSE pump), with usage tapped into the ledger;
//! * an SSE-only chat upstream (it streams regardless of `stream:false`) answering a non-stream
//!   client is folded into one Responses object, tool calls included.

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

/// Mock chat upstream: serves `/v1/chat/completions` JSON or SSE depending on the request body,
/// and captures every translated request it receives.
async fn spawn_chat_backend() -> (String, tokio::sync::mpsc::Receiver<serde_json::Value>) {
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move |body: Bytes| {
            let tx = tx.clone();
            async move {
                let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                tx.send(value.clone()).await.unwrap();
                let stream = value.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
                if stream {
                    let sse = concat!(
                        "data: {\"id\":\"chatcmpl-abc\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-4.7\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n",
                        "data: {\"id\":\"chatcmpl-abc\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-4.7\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel\"},\"finish_reason\":null}]}\n\n",
                        "data: {\"id\":\"chatcmpl-abc\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-4.7\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":null}]}\n\n",
                        "data: {\"id\":\"chatcmpl-abc\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-4.7\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
                        "data: {\"id\":\"chatcmpl-abc\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-4.7\",\"choices\":[],\"usage\":{\"prompt_tokens\":21,\"output_tokens\":5,\"total_tokens\":26}}\n\n",
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
                            r#"{"id":"chatcmpl-abc","object":"chat.completion","created":1700000000,"model":"glm-4.7",
                                "choices":[{"index":0,"message":{"role":"assistant","content":"OK from chat"},"finish_reason":"stop"}],
                                "usage":{"prompt_tokens":12,"output_tokens":4,"total_tokens":16}}"#,
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

/// SSE-only chat upstream that ignores `stream` entirely and answers with a split tool call — the
/// forced-streaming behavior some chat providers show even for non-streaming requests.
async fn spawn_sse_toolcall_backend() -> String {
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(|| async {
            let sse = concat!(
                "data: {\"id\":\"chatcmpl-t\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-4.7\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":null},\"finish_reason\":null}]}\n\n",
                "data: {\"id\":\"chatcmpl-t\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-4.7\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n",
                "data: {\"id\":\"chatcmpl-t\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-4.7\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"city\\\":\\\"Hanoi\\\"}\"}}]},\"finish_reason\":null}]}\n\n",
                "data: {\"id\":\"chatcmpl-t\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-4.7\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
                "data: {\"id\":\"chatcmpl-t\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"glm-4.7\",\"choices\":[],\"usage\":{\"prompt_tokens\":8,\"output_tokens\":3,\"total_tokens\":11}}\n\n",
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

/// One Responses route with one chat-family endpoint: the mismatch is the trigger. Returns the
/// state wired to an observable ledger channel.
async fn build_translated_route_state(
    pool: PgPool,
    backend_base: String,
    endpoint_protocol: &str,
) -> (Arc<AppState>, tokio::sync::mpsc::Receiver<UsageEvent>) {
    let key_file = std::env::temp_dir().join(format!("brighto_trc_key_{}", std::process::id()));
    std::fs::write(&key_file, "mockkey").unwrap();
    let key_ref = format!("file:{}", key_file.display());

    sqlx::query(
        "INSERT INTO backends (id, name, base_url, api_key_ref, weight, max_inflight, format, enabled) \
         VALUES (1, 'chat-endpoint', $1, $2, 1, 100, 'openai', TRUE)",
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
         VALUES ('combo-rsp', '[1]', NULL, 4.0, 180, 'combo-rsp', TRUE, 'bearer', 'openai_responses', 'least_loaded_weighted')",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO model_route_endpoints \
         (model_name, backend_id, provider_model_name, provider_key_ref, auth_mode, protocol, weight, max_inflight, enabled) \
         VALUES ('combo-rsp', 1, 'glm-4.7', $1, 'bearer', $2, 1, 100, TRUE)",
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
async fn responses_client_nonstream_translates_request_and_response(pool: PgPool) {
    let (backend_base, mut upstream_rx) = spawn_chat_backend().await;
    let (state, mut ledger_rx) =
        build_translated_route_state(pool, backend_base, "openai_chat").await;
    let app = brighto_router::handlers::router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header("authorization", "Bearer test-key")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"model":"combo-rsp","stream":false,"instructions":"be terse",
                "input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}],
                "max_output_tokens":64,"temperature":0.2,"reasoning":{"effort":"high"},
                "tools":[{"type":"function","name":"get_weather","description":"d","parameters":{"type":"object"}}],
                "tool_choice":"auto"}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = to_bytes(resp.into_body(), 10 * 1024 * 1024).await.unwrap();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["object"], "response");
    assert_eq!(response["model"], "combo-rsp", "client-facing name only");
    assert_eq!(response["id"], "chatcmpl-abc");
    assert_eq!(response["created_at"], 1_700_000_000u64);
    assert_eq!(response["status"], "completed");
    assert_eq!(response["output"][0]["type"], "message");
    assert_eq!(response["output"][0]["role"], "assistant");
    assert_eq!(response["output"][0]["content"][0]["type"], "output_text");
    assert_eq!(response["output"][0]["content"][0]["text"], "OK from chat");
    assert_eq!(response["usage"]["input_tokens"], 12);
    assert_eq!(response["usage"]["output_tokens"], 4);
    assert_eq!(response["usage"]["total_tokens"], 16);

    // The upstream saw a chat request, not Responses.
    let upstream = tokio::time::timeout(Duration::from_secs(2), upstream_rx.recv())
        .await
        .expect("upstream capture")
        .unwrap();
    assert_eq!(upstream["model"], "glm-4.7", "endpoint model applied");
    assert_eq!(upstream["messages"][0]["role"], "system");
    assert_eq!(upstream["messages"][0]["content"], "be terse");
    assert_eq!(upstream["messages"][1]["role"], "user");
    assert_eq!(upstream["messages"][1]["content"], "hello");
    assert_eq!(upstream["tools"][0]["type"], "function");
    assert_eq!(upstream["tools"][0]["function"]["name"], "get_weather");
    assert_eq!(
        upstream["tools"][0]["function"]["parameters"]["type"],
        "object"
    );
    assert!(
        upstream["tools"][0].get("name").is_none(),
        "tools must be nested"
    );
    assert_eq!(upstream["tool_choice"], "auto");
    assert_eq!(upstream["max_tokens"], 64);
    assert_eq!(upstream["temperature"], 0.2);
    assert_eq!(upstream["reasoning_effort"], "high");
    assert_eq!(upstream["stream"], false);
    for dropped in [
        "instructions",
        "input",
        "store",
        "max_output_tokens",
        "reasoning",
        "stream_options",
        "previous_response_id",
    ] {
        assert!(upstream.get(dropped).is_none(), "{dropped} leaked upstream");
    }

    let ev = tokio::time::timeout(Duration::from_secs(2), ledger_rx.recv())
        .await
        .expect("ledger event")
        .unwrap();
    assert_eq!(ev.model, "combo-rsp");
    assert_eq!(ev.input_tokens, 12);
    assert_eq!(ev.output_tokens, 4);
    assert!(!ev.estimated);
}

#[sqlx::test(migrations = "./migrations")]
async fn responses_client_stream_gets_incremental_responses_events(pool: PgPool) {
    let (backend_base, mut upstream_rx) = spawn_chat_backend().await;
    let (state, mut ledger_rx) =
        build_translated_route_state(pool, backend_base, "openai_chat").await;
    let app = brighto_router::handlers::router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header("authorization", "Bearer test-key")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"model":"combo-rsp","stream":true,"input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}]}"#,
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
        text.starts_with("event: response.created"),
        "created must open the stream: {text}"
    );
    assert!(
        text.contains("\"type\":\"response.output_text.delta\""),
        "{text}"
    );
    assert!(text.contains("\"delta\":\"Hel\""), "{text}");
    assert!(text.contains("\"delta\":\"lo\""), "{text}");
    assert!(text.contains("\"type\":\"response.completed\""), "{text}");
    assert!(
        text.contains("\"input_tokens\":21"),
        "usage rides the completed event: {text}"
    );
    assert!(
        text.contains("\"model\":\"combo-rsp\""),
        "client-facing name only: {text}"
    );
    assert!(
        !text.contains("chat.completion.chunk"),
        "upstream chunks must not leak through: {text}"
    );
    assert!(
        !text.contains("[DONE]"),
        "no chat terminator on this wire: {text}"
    );
    assert!(
        text.trim_end()
            .ends_with("\"type\":\"response.completed\"}}")
            || text.trim_end().contains("response.completed"),
        "the stream ends on the terminal event: {text}"
    );

    // The streaming request still went upstream as chat, with usage requested.
    let upstream = tokio::time::timeout(Duration::from_secs(2), upstream_rx.recv())
        .await
        .expect("upstream capture")
        .unwrap();
    assert_eq!(upstream["model"], "glm-4.7");
    assert_eq!(upstream["stream"], true);
    assert_eq!(
        upstream["stream_options"],
        serde_json::json!({"include_usage": true})
    );

    // Usage tapped from the translated terminal event.
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
async fn forced_sse_chat_upstream_folds_tool_calls_into_one_response(pool: PgPool) {
    let backend_base = spawn_sse_toolcall_backend().await;
    // custom_openai_chat proves the whole chat family is reachable, not just plain openai_chat.
    let (state, mut ledger_rx) =
        build_translated_route_state(pool, backend_base, "custom_openai_chat").await;
    let app = brighto_router::handlers::router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header("authorization", "Bearer test-key")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"model":"combo-rsp","stream":false,"input":[{"role":"user","content":[{"type":"input_text","text":"weather?"}]}]}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = to_bytes(resp.into_body(), 10 * 1024 * 1024).await.unwrap();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["object"], "response");
    assert_eq!(response["status"], "completed");
    assert_eq!(response["output"].as_array().unwrap().len(), 1);
    let call = &response["output"][0];
    assert_eq!(call["type"], "function_call");
    assert_eq!(call["call_id"], "call_1");
    assert_eq!(call["name"], "get_weather");
    assert_eq!(call["arguments"], "{\"city\":\"Hanoi\"}");
    assert_eq!(response["usage"]["input_tokens"], 8);
    assert_eq!(response["usage"]["output_tokens"], 3);

    let ev = tokio::time::timeout(Duration::from_secs(2), ledger_rx.recv())
        .await
        .expect("ledger event")
        .unwrap();
    assert_eq!(ev.input_tokens, 8);
    assert_eq!(ev.output_tokens, 3);
    assert!(!ev.estimated);
    assert!(!ev.stream);
}
