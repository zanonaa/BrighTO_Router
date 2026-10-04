//! Chat -> Responses protocol translation (client `POST /v1/chat/completions`, provider
//! `POST /v1/responses`).
//!
//! A chat-family route (`openai_chat` / `local_openai_chat` / `custom_openai_chat`) may hold a
//! Responses-family endpoint (`openai_responses`, `codex_responses`) inside the same Model Group.
//! That mismatch **is** the trigger: no config switch, no per-model override. When it holds,
//!
//! * the chat request is rewritten into a Responses request before it leaves the router
//!   (`chat_request_to_responses`),
//! * the upstream answer is rewritten back into OpenAI Chat shape — SSE
//!   (`responses_sse_to_chat_chunks`, incrementally through `ResponsesSseToChat`) or a single JSON
//!   body (`responses_json_to_chat_completion`).
//!
//! Deliberately out of scope: the reverse direction (Responses client -> chat provider), the
//! Anthropic dialect, and every chat field with no Responses equivalent (`n`, `logprobs`,
//! `frequency_penalty`, ... are dropped rather than approximated). See ADAPTERS.md.
//!
//! This module is pure like `opencode_free`: no I/O, no clock, no globals. It owns protocol shape
//! only — routing, retries, credentials, budget, and the ledger stay in the proxy.

use serde_json::{Map, Value, json};

use crate::contract::ProviderProtocol;

/// Upstream path every Responses-family endpoint receives, regardless of base URL: `build_target_url`
/// keeps it under an SDK-style base URL (`https://api.openai.com/v1`) and appends it to a Codex base
/// URL (`https://chatgpt.com/backend-api/codex`).
pub const RESPONSES_UPSTREAM_PATH: &str = "/v1/responses";

/// Route protocols whose client-facing endpoint is `POST /v1/chat/completions`.
fn is_chat_family(protocol: ProviderProtocol) -> bool {
    matches!(
        protocol,
        ProviderProtocol::OpenAiChat
            | ProviderProtocol::LocalOpenAiChat
            | ProviderProtocol::CustomOpenAiChat
    )
}

/// Endpoint protocols whose upstream speaks the Responses API.
fn is_responses_family(protocol: ProviderProtocol) -> bool {
    matches!(
        protocol,
        ProviderProtocol::OpenAiResponses | ProviderProtocol::CodexResponses
    )
}

/// True when this request must be translated chat -> responses on the wire.
///
/// Only one direction exists. Every other pair (responses route with a chat endpoint, a chat route
/// with a rerank endpoint, ...) must never reach the wire: the admin validation rejects it and the
/// proxy has no lane for it.
pub fn chat_to_responses_applies(
    route_protocol: ProviderProtocol,
    endpoint_protocol: ProviderProtocol,
) -> bool {
    is_chat_family(route_protocol) && is_responses_family(endpoint_protocol)
}

/// Request-side options. `provider_model` is the **endpoint** provider model name: the translated
/// body carries the upstream name, so the proxy must not rewrite `model` a second time.
pub struct ChatToResponsesOpts<'a> {
    pub provider_model: &'a str,
    /// Codex upstreams (`chatgpt.com/backend-api/codex/responses`) only serve the streaming
    /// Responses API, so the translated request pins `stream:true` and a non-streaming client call
    /// gets the forced SSE folded back into one `chat.completion`.
    pub pin_stream: bool,
}

/// Per-endpoint request options. Only Codex pins the stream.
pub fn request_opts<'a>(
    endpoint_protocol: ProviderProtocol,
    provider_model: &'a str,
) -> ChatToResponsesOpts<'a> {
    ChatToResponsesOpts {
        provider_model,
        pin_stream: endpoint_protocol == ProviderProtocol::CodexResponses,
    }
}

fn array_of(value: Option<&Value>) -> &[Value] {
    value
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

/// Chat message content -> plain text. Multimodal parts (`image_url`, `input_audio`, ...) carry no
/// Responses text equivalent in this adapter and are dropped; see the limits in ADAPTERS.md.
fn chat_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(parts)) => {
            let mut out = String::new();
            for part in parts {
                if part
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind != "text")
                {
                    continue;
                }
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    out.push_str(text);
                }
            }
            out
        }
        _ => String::new(),
    }
}

/// Translate one chat-completions request into a Responses request.
///
/// * `messages` -> `instructions` (system/developer texts joined by a blank line) + `input` items:
///   user -> `{role:"user",content:[{type:"input_text"}]}`, assistant -> `output_text`, assistant
///   `tool_calls` -> `function_call`, tool role -> `function_call_output`;
/// * chat tools (nested `function`) flatten into Responses tools (`{type, name, description,
///   parameters}`);
/// * `tool_choice` maps `auto`/`none`/`required` straight through and a pinned function onto
///   `{type:"function",name}`;
/// * `max_tokens`/`max_completion_tokens` -> `max_output_tokens`, `reasoning_effort` ->
///   `reasoning.effort`, `temperature`/`top_p`/`stop` pass through when present, `stream` passes
///   through unless the endpoint pins it;
/// * `store:false` always — the Responses API would otherwise persist the conversation server-side;
/// * chat-only fields with no Responses equivalent are dropped (`n`, `logprobs`, `frequency_penalty`,
///   `presence_penalty`, `logit_bias`, `user`, `stream_options`, ...).
///
/// Returns `None` when the body is not a JSON object, so the caller can answer 400 instead of
/// forwarding a half-translated request.
pub fn chat_request_to_responses(body: &[u8], opts: &ChatToResponsesOpts<'_>) -> Option<Vec<u8>> {
    let chat: Value = serde_json::from_slice(body).ok()?;
    let chat = chat.as_object()?;
    let mut out = Map::new();
    out.insert(
        "model".to_string(),
        Value::String(opts.provider_model.to_string()),
    );

    let mut instructions: Vec<String> = Vec::new();
    let mut input: Vec<Value> = Vec::new();
    for message in array_of(chat.get("messages")) {
        match message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "system" | "developer" => {
                let text = chat_text(message.get("content"));
                if !text.is_empty() {
                    instructions.push(text);
                }
            }
            "user" => input.push(json!({
                "role": "user",
                "content": [{"type": "input_text", "text": chat_text(message.get("content"))}],
            })),
            "assistant" => {
                let text = chat_text(message.get("content"));
                if !text.is_empty() {
                    input.push(json!({
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": text}],
                    }));
                }
                for call in array_of(message.get("tool_calls")) {
                    let Some(function) = call.get("function") else {
                        continue;
                    };
                    let Some(name) = function.get("name").and_then(Value::as_str) else {
                        continue;
                    };
                    input.push(json!({
                        "type": "function_call",
                        "call_id": call.get("id").and_then(Value::as_str).unwrap_or_default(),
                        "name": name,
                        "arguments": function
                            .get("arguments")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    }));
                }
            }
            // `function` is the legacy alias of the tool role.
            "tool" | "function" => {
                let call_id = message
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .or_else(|| message.get("name").and_then(Value::as_str))
                    .unwrap_or_default();
                input.push(json!({
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": chat_text(message.get("content")),
                }));
            }
            _ => {}
        }
    }
    if !instructions.is_empty() {
        out.insert(
            "instructions".to_string(),
            Value::String(instructions.join("\n\n")),
        );
    }
    out.insert("input".to_string(), Value::Array(input));

    let mut tools: Vec<Value> = Vec::with_capacity(
        chat.get("tools")
            .map_or(0, |t| t.as_array().map_or(0, Vec::len)),
    );
    for tool in array_of(chat.get("tools")) {
        if tool.get("type").and_then(Value::as_str) != Some("function") {
            continue;
        }
        let Some(function) = tool.get("function") else {
            continue;
        };
        let Some(name) = function.get("name").and_then(Value::as_str) else {
            continue;
        };
        let mut flat = Map::new();
        flat.insert("type".to_string(), Value::String("function".to_string()));
        flat.insert("name".to_string(), Value::String(name.to_string()));
        for key in ["description", "parameters"] {
            if let Some(value) = function.get(key) {
                flat.insert(key.to_string(), value.clone());
            }
        }
        tools.push(Value::Object(flat));
    }
    if !tools.is_empty() {
        out.insert("tools".to_string(), Value::Array(tools));
    }

    match chat.get("tool_choice") {
        Some(Value::String(choice)) if matches!(choice.as_str(), "auto" | "none" | "required") => {
            out.insert("tool_choice".to_string(), Value::String(choice.clone()));
        }
        Some(choice) => {
            if let Some(name) = choice
                .get("function")
                .and_then(|function| function.get("name"))
                .and_then(Value::as_str)
            {
                out.insert(
                    "tool_choice".to_string(),
                    json!({"type": "function", "name": name}),
                );
            }
        }
        None => {}
    }

    if let Some(value) = chat
        .get("max_completion_tokens")
        .or_else(|| chat.get("max_tokens"))
    {
        out.insert("max_output_tokens".to_string(), value.clone());
    }
    if let Some(effort) = chat.get("reasoning_effort").and_then(Value::as_str) {
        out.insert("reasoning".to_string(), json!({"effort": effort}));
    }
    for key in ["temperature", "top_p", "stop"] {
        if let Some(value) = chat.get(key) {
            out.insert(key.to_string(), value.clone());
        }
    }
    if opts.pin_stream {
        out.insert("stream".to_string(), Value::Bool(true));
    } else if let Some(value) = chat.get("stream") {
        out.insert("stream".to_string(), value.clone());
    }
    // Never persist the conversation upstream: the client asked for a chat completion, not a stored
    // response object.
    out.insert("store".to_string(), Value::Bool(false));

    serde_json::to_vec(&Value::Object(out)).ok()
}

/// Cross-protocol state carried while mapping one SSE stream, so the `id`/`created` envelope and the
/// tool-call counter survive across chunks of the same response.
#[derive(Debug, Default, Clone)]
pub struct ResponsesStreamState {
    id: Option<Value>,
    created: Option<Value>,
    role_sent: bool,
    tool_calls: usize,
    finished: bool,
}

fn role_chunk(state: &ResponsesStreamState, client_model: &str) -> Value {
    chat_chunk(
        state,
        client_model,
        json!([{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": null}]),
        None,
    )
}

fn chat_chunk(
    state: &ResponsesStreamState,
    client_model: &str,
    choices: Value,
    usage: Option<Value>,
) -> Value {
    let mut out = Map::new();
    if let Some(id) = &state.id {
        out.insert("id".to_string(), id.clone());
    }
    out.insert(
        "object".to_string(),
        Value::String("chat.completion.chunk".to_string()),
    );
    if let Some(created) = &state.created {
        out.insert("created".to_string(), created.clone());
    }
    // The client never sees the upstream model string: it called the public model name.
    out.insert("model".to_string(), Value::String(client_model.to_string()));
    out.insert("choices".to_string(), choices);
    if let Some(usage) = usage {
        out.insert("usage".to_string(), usage);
    }
    Value::Object(out)
}

fn error_event(message: &str) -> Value {
    json!({"error": {"message": message, "type": "server_error"}})
}

/// `created_at` is unix seconds on some providers and RFC 3339 on OpenAI itself; the chat envelope
/// wants unix seconds.
fn created_seconds(created_at: Option<&Value>) -> Option<Value> {
    match created_at {
        Some(Value::Number(seconds)) => Some(Value::Number(seconds.clone())),
        Some(Value::String(text)) => chrono::DateTime::parse_from_rfc3339(text)
            .ok()
            .map(|parsed| Value::from(parsed.timestamp())),
        _ => None,
    }
}

fn capture_response_meta(state: &mut ResponsesStreamState, response: &Value) {
    if let Some(id) = response.get("id").filter(|id| !id.is_null()) {
        state.id = Some(id.clone());
    }
    if state.created.is_none() {
        state.created = created_seconds(response.get("created_at"));
    }
}

/// Responses usage (`input_tokens`/`output_tokens`) -> chat usage (`prompt_tokens`/
/// `completion_tokens`/`total_tokens`). Returns `None` when the upstream reported nothing, so the
/// caller can fall back to the router estimate instead of reporting zero.
fn chat_usage(usage: &Value) -> Option<Value> {
    let input = usage
        .get("input_tokens")
        .or_else(|| usage.get("prompt_tokens"))
        .and_then(Value::as_u64);
    let output = usage
        .get("output_tokens")
        .or_else(|| usage.get("completion_tokens"))
        .and_then(Value::as_u64);
    if input.is_none() && output.is_none() {
        return None;
    }
    let prompt = input.unwrap_or(0);
    let completion = output.unwrap_or(0);
    let total = usage
        .get("total_tokens")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| prompt.saturating_add(completion));
    Some(json!({
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
    }))
}

/// Map one Responses SSE event onto the chat chunks it implies (0..n frames).
///
/// * `response.created` -> the opening `role` chunk (and it captures `id`/`created`);
/// * `response.output_text.delta` -> a `content` delta chunk;
/// * `response.output_item.done` with a `function_call` item -> a `tool_calls` delta chunk;
/// * `response.completed` / `response.incomplete` -> the `finish_reason` chunk
///   (`tool_calls` when the turn produced a call, `stop` otherwise, `length` when the upstream
///   stopped on `max_output_tokens`) plus the usage-only chunk OpenAI clients expect;
/// * `response.failed` / `error` -> an error frame that terminates the stream.
///
/// Unknown events (`response.output_item.added`, `response.in_progress`, annotation events, ...)
/// produce nothing: the translator is a filter, not an echo.
pub fn responses_event_to_chat_chunks(
    event: &Value,
    state: &mut ResponsesStreamState,
    client_model: &str,
) -> Vec<Value> {
    if state.finished {
        return Vec::new();
    }
    let Some(event_type) = event.get("type").and_then(Value::as_str) else {
        return Vec::new();
    };
    match event_type {
        "response.created" => {
            if let Some(response) = event.get("response") {
                capture_response_meta(state, response);
            }
            let mut chunks = Vec::new();
            if !state.role_sent {
                chunks.push(role_chunk(state, client_model));
                state.role_sent = true;
            }
            chunks
        }
        "response.output_text.delta" => {
            let mut chunks = Vec::new();
            if !state.role_sent {
                chunks.push(role_chunk(state, client_model));
                state.role_sent = true;
            }
            let delta = event
                .get("delta")
                .and_then(Value::as_str)
                .unwrap_or_default();
            chunks.push(chat_chunk(
                state,
                client_model,
                json!([{"index": 0, "delta": {"content": delta}, "finish_reason": null}]),
                None,
            ));
            chunks
        }
        "response.output_item.done" => {
            let Some(item) = event.get("item") else {
                return Vec::new();
            };
            if item.get("type").and_then(Value::as_str) != Some("function_call") {
                return Vec::new();
            }
            let Some(name) = item.get("name").and_then(Value::as_str) else {
                return Vec::new();
            };
            let index = state.tool_calls;
            state.tool_calls += 1;
            let mut chunks = Vec::new();
            if !state.role_sent {
                chunks.push(role_chunk(state, client_model));
                state.role_sent = true;
            }
            chunks.push(chat_chunk(
                state,
                client_model,
                json!([{"index": 0, "delta": {"tool_calls": [{
                    "index": index,
                    "id": item.get("call_id").and_then(Value::as_str).unwrap_or_default(),
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": item.get("arguments").and_then(Value::as_str).unwrap_or_default(),
                    },
                }]}, "finish_reason": null}]),
                None,
            ));
            chunks
        }
        "response.completed" | "response.incomplete" => {
            if let Some(response) = event.get("response") {
                capture_response_meta(state, response);
            }
            state.finished = true;
            let mut chunks = Vec::new();
            if !state.role_sent {
                chunks.push(role_chunk(state, client_model));
                state.role_sent = true;
            }
            let finish = if event_type == "response.incomplete" {
                match event
                    .pointer("/response/incomplete_details/reason")
                    .and_then(Value::as_str)
                {
                    Some("max_output_tokens") => "length",
                    _ => "stop",
                }
            } else if state.tool_calls > 0 {
                "tool_calls"
            } else {
                "stop"
            };
            chunks.push(chat_chunk(
                state,
                client_model,
                json!([{"index": 0, "delta": {}, "finish_reason": finish}]),
                None,
            ));
            let usage = event
                .pointer("/response/usage")
                .filter(|usage| !usage.is_null())
                .and_then(chat_usage);
            if let Some(usage) = usage {
                // OpenAI sends usage in its own chunk with an empty `choices` array.
                chunks.push(chat_chunk(
                    state,
                    client_model,
                    Value::Array(Vec::new()),
                    Some(usage),
                ));
            }
            chunks
        }
        "response.failed" | "error" => {
            state.finished = true;
            let message = event
                .pointer("/response/error/message")
                .and_then(Value::as_str)
                .or_else(|| event.pointer("/error/message").and_then(Value::as_str))
                .or_else(|| event.get("message").and_then(Value::as_str))
                .unwrap_or("upstream responses request failed");
            vec![error_event(message)]
        }
        _ => Vec::new(),
    }
}

/// Incremental byte-level translator for the proxy SSE pump: feed arbitrary upstream byte chunks,
/// get the chat chunk SSE bytes the client should receive. Line-boundary safe (a Responses event
/// split across two TCP chunks is buffered, never parsed twice), and it emits `data: [DONE]` exactly
/// once, right after the terminal event.
pub struct ResponsesSseToChat {
    client_model: String,
    state: ResponsesStreamState,
    partial: Vec<u8>,
    done_sent: bool,
}

impl ResponsesSseToChat {
    pub fn new(client_model: &str) -> Self {
        Self {
            client_model: client_model.to_string(),
            state: ResponsesStreamState::default(),
            partial: Vec::new(),
            done_sent: false,
        }
    }

    /// Translate one upstream byte chunk. Empty output means "nothing to say yet": the event was
    /// ignored or its line has not terminated.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.partial.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some(newline) = self.partial.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.partial.drain(..=newline).take(newline).collect();
            self.push_line(&line, &mut out);
        }
        out
    }

    /// Flush the trailing line (an upstream that ends without a final newline) and stop. Nothing is
    /// emitted when the stream never reached a terminal event: a truncated upstream must not look
    /// like a finished answer.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.partial.is_empty() {
            let line = std::mem::take(&mut self.partial);
            self.push_line(&line, &mut out);
        }
        out
    }

    fn push_line(&mut self, line: &[u8], out: &mut Vec<u8>) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(data) = line.strip_prefix(b"data:") else {
            // event:, id:, retry:, and comment lines carry no payload for a chat client.
            return;
        };
        let data = data.trim_ascii_start();
        // The upstream `[DONE]` marker is replaced by our own, emitted after the terminal event.
        if data.starts_with(b"[DONE]") || self.done_sent {
            return;
        }
        let Ok(event) = serde_json::from_slice::<Value>(data) else {
            return;
        };
        for chunk in responses_event_to_chat_chunks(&event, &mut self.state, &self.client_model) {
            out.extend_from_slice(b"data: ");
            match serde_json::to_vec(&chunk) {
                Ok(bytes) => out.extend_from_slice(&bytes),
                Err(_) => continue,
            }
            out.extend_from_slice(b"\n\n");
        }
        if self.state.finished {
            out.extend_from_slice(b"data: [DONE]\n\n");
            self.done_sent = true;
        }
    }
}

/// Translate a whole Responses SSE body into chat chunk SSE (used when a Responses upstream answers
/// a non-streaming client call, and by the unit tests). Returns `None` when no event mapped, so the
/// caller can answer 502 instead of returning an empty stream.
pub fn responses_sse_to_chat_chunks(sse: &[u8], client_model: &str) -> Option<String> {
    let mut translator = ResponsesSseToChat::new(client_model);
    let mut out = translator.feed(sse);
    out.extend_from_slice(&translator.finish());
    if out.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// Translate a non-streaming Responses body into one `chat.completion`: `output_text` becomes
/// `message.content`, `function_call` items become `message.tool_calls`, and the response `usage`
/// becomes chat usage. `model` is the client-facing public name.
///
/// Returns `None` when the body is not a JSON object.
pub fn responses_json_to_chat_completion(body: &[u8], client_model: &str) -> Option<Value> {
    let response = serde_json::from_slice::<Value>(body).ok()?;
    let response = response.as_object()?;

    let mut text = String::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    for item in array_of(response.get("output")) {
        match item
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("message")
        {
            "message" => {
                for part in array_of(item.get("content")) {
                    let Some(kind) = part.get("type").and_then(Value::as_str) else {
                        continue;
                    };
                    if kind != "output_text" && kind != "text" {
                        continue;
                    }
                    if let Some(value) = part.get("text").and_then(Value::as_str) {
                        text.push_str(value);
                    }
                }
            }
            "function_call" => {
                let name = item.get("name").and_then(Value::as_str).unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                let call_id = item
                    .get("call_id")
                    .or_else(|| item.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                tool_calls.push(json!({
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": item.get("arguments").and_then(Value::as_str).unwrap_or_default(),
                    },
                }));
            }
            _ => {}
        }
    }
    // Some providers only populate the convenience field.
    if text.is_empty()
        && let Some(flat) = response.get("output_text").and_then(Value::as_str)
    {
        text.push_str(flat);
    }

    let mut message = Map::new();
    message.insert("role".to_string(), Value::String("assistant".to_string()));
    message.insert(
        "content".to_string(),
        if text.is_empty() && !tool_calls.is_empty() {
            Value::Null
        } else {
            Value::String(text)
        },
    );
    let finish = if tool_calls.is_empty() {
        "stop"
    } else {
        "tool_calls"
    };
    if !tool_calls.is_empty() {
        message.insert("tool_calls".to_string(), Value::Array(tool_calls));
    }

    let mut choice = Map::new();
    choice.insert("index".to_string(), Value::from(0u64));
    choice.insert("message".to_string(), Value::Object(message));
    choice.insert(
        "finish_reason".to_string(),
        Value::String(finish.to_string()),
    );

    let mut out = Map::new();
    out.insert(
        "object".to_string(),
        Value::String("chat.completion".to_string()),
    );
    if let Some(id) = response.get("id").filter(|id| !id.is_null()) {
        out.insert("id".to_string(), id.clone());
    }
    if let Some(created) = created_seconds(response.get("created_at")) {
        out.insert("created".to_string(), created);
    }
    out.insert("model".to_string(), Value::String(client_model.to_string()));
    out.insert(
        "choices".to_string(),
        Value::Array(vec![Value::Object(choice)]),
    );
    if let Some(usage) = response
        .get("usage")
        .filter(|usage| !usage.is_null())
        .and_then(chat_usage)
    {
        out.insert("usage".to_string(), usage);
    }
    Some(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(model: &str) -> ChatToResponsesOpts<'_> {
        ChatToResponsesOpts {
            provider_model: model,
            pin_stream: false,
        }
    }

    fn translate(body: &str, model: &str) -> Value {
        serde_json::from_slice(&chat_request_to_responses(body.as_bytes(), &opts(model)).unwrap())
            .unwrap()
    }

    fn translate_codex(body: &str) -> Value {
        let out = chat_request_to_responses(
            body.as_bytes(),
            &ChatToResponsesOpts {
                provider_model: "gpt-5.6-codex",
                pin_stream: true,
            },
        )
        .unwrap();
        serde_json::from_slice(&out).unwrap()
    }

    fn types_of(value: &Value) -> Vec<&str> {
        value["input"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| match item.get("type").and_then(Value::as_str) {
                Some(explicit) => explicit,
                None => item["role"].as_str().unwrap(),
            })
            .collect()
    }

    #[test]
    fn translation_triggers_only_for_chat_route_onto_responses_endpoint() {
        for chat in [
            ProviderProtocol::OpenAiChat,
            ProviderProtocol::LocalOpenAiChat,
            ProviderProtocol::CustomOpenAiChat,
        ] {
            assert!(chat_to_responses_applies(
                chat,
                ProviderProtocol::OpenAiResponses
            ));
            assert!(chat_to_responses_applies(
                chat,
                ProviderProtocol::CodexResponses
            ));
            // No other endpoint family is reachable from the chat lane.
            for other in [
                ProviderProtocol::OpenAiCompletions,
                ProviderProtocol::OpenAiEmbeddings,
                ProviderProtocol::OpenAiRerank,
                ProviderProtocol::AnthropicMessages,
                ProviderProtocol::SystemOne,
                ProviderProtocol::OpenAiChat,
            ] {
                assert!(
                    !chat_to_responses_applies(chat, other),
                    "{chat:?} -> {other:?} must stay untranslated"
                );
            }
        }
        // The reverse direction does not exist yet.
        assert!(!chat_to_responses_applies(
            ProviderProtocol::OpenAiResponses,
            ProviderProtocol::OpenAiChat
        ));
        assert!(!chat_to_responses_applies(
            ProviderProtocol::CodexResponses,
            ProviderProtocol::OpenAiChat
        ));
    }

    #[test]
    fn only_codex_pins_the_translated_stream() {
        assert!(
            !request_opts(ProviderProtocol::OpenAiResponses, "m").pin_stream,
            "plain Responses endpoints must keep the caller's stream flag"
        );
        assert!(
            request_opts(ProviderProtocol::CodexResponses, "m").pin_stream,
            "the ChatGPT Codex backend only serves streaming Responses"
        );
    }

    #[test]
    fn plain_chat_request_becomes_instructions_and_input() {
        let out = translate(
            r#"{"model":"public-chat","messages":[
                {"role":"system","content":"be terse"},
                {"role":"user","content":"hello"}
            ],"stream":false}"#,
            "gpt-5.6-codex",
        );
        assert_eq!(out["model"], "gpt-5.6-codex");
        assert_eq!(out["instructions"], "be terse");
        assert_eq!(out["input"].as_array().unwrap().len(), 1);
        assert_eq!(out["input"][0]["role"], "user");
        assert_eq!(out["input"][0]["content"][0]["type"], "input_text");
        assert_eq!(out["input"][0]["content"][0]["text"], "hello");
        assert_eq!(out["stream"], false);
        assert_eq!(out["store"], false);
        // The chat-only envelope must not survive.
        assert!(out.get("messages").is_none());
        assert!(out.get("stream_options").is_none());
    }

    #[test]
    fn multi_turn_systems_are_concatenated_and_developer_joins_them() {
        let out = translate(
            r#"{"messages":[
                {"role":"system","content":[{"type":"text","text":"first"}]},
                {"role":"developer","content":"second"},
                {"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}
            ]}"#,
            "m",
        );
        assert_eq!(out["instructions"], "first\n\nsecond");
        assert_eq!(out["input"][0]["content"][0]["text"], "ab");
    }

    #[test]
    fn request_without_system_messages_has_no_instructions() {
        let out = translate(r#"{"messages":[{"role":"user","content":"hi"}]}"#, "m");
        assert!(out.get("instructions").is_none());
    }

    #[test]
    fn tool_round_maps_calls_and_outputs() {
        let out = translate(
            r#"{"messages":[
                {"role":"user","content":"weather?"},
                {"role":"assistant","content":null,"tool_calls":[
                    {"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Hanoi\"}"}},
                    {"id":"call_2","type":"function","function":{"name":"ping","arguments":"{}"}}
                ]},
                {"role":"tool","tool_call_id":"call_1","content":"31C"},
                {"role":"tool","tool_call_id":"call_2","content":"pong"}
            ]}"#,
            "m",
        );
        assert_eq!(
            types_of(&out),
            [
                "user",
                "function_call",
                "function_call",
                "function_call_output",
                "function_call_output"
            ]
        );
        assert_eq!(out["input"][1]["call_id"], "call_1");
        assert_eq!(out["input"][1]["name"], "get_weather");
        assert_eq!(out["input"][1]["arguments"], "{\"city\":\"Hanoi\"}");
        assert_eq!(out["input"][3]["call_id"], "call_1");
        assert_eq!(out["input"][3]["output"], "31C");
        // A null assistant content becomes no output_text item at all.
        assert_eq!(out["input"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn assistant_text_and_tool_calls_both_survive() {
        let out = translate(
            r#"{"messages":[{"role":"assistant","content":"checking","tool_calls":[
                {"id":"call_9","function":{"name":"f","arguments":"{}"}}
            ]}]}"#,
            "m",
        );
        assert_eq!(types_of(&out), ["assistant", "function_call"]);
        assert_eq!(out["input"][0]["content"][0]["type"], "output_text");
        assert_eq!(out["input"][0]["content"][0]["text"], "checking");
    }

    #[test]
    fn legacy_function_role_maps_to_function_call_output() {
        let out = translate(
            r#"{"messages":[{"role":"function","name":"legacy","content":"42"}]}"#,
            "m",
        );
        assert_eq!(out["input"][0]["type"], "function_call_output");
        assert_eq!(out["input"][0]["call_id"], "legacy");
    }

    #[test]
    fn tools_flatten_and_tool_choice_maps() {
        let out = translate(
            r#"{"messages":[],"tools":[
                {"type":"function","function":{"name":"get_weather","description":"d","parameters":{"type":"object"}}},
                {"type":"function","function":{"name":"bare"}}
            ],"tool_choice":{"type":"function","function":{"name":"get_weather"}}}"#,
            "m",
        );
        assert_eq!(out["tools"][0]["type"], "function");
        assert_eq!(out["tools"][0]["name"], "get_weather");
        assert_eq!(out["tools"][0]["description"], "d");
        assert_eq!(out["tools"][0]["parameters"]["type"], "object");
        assert!(
            out["tools"][0].get("function").is_none(),
            "chat tool nesting must be flattened away"
        );
        // A tool without a description/parameters keeps only name+type.
        assert_eq!(out["tools"][1].as_object().unwrap().len(), 2);
        assert_eq!(
            out["tool_choice"],
            serde_json::json!({"type": "function", "name": "get_weather"})
        );
    }

    #[test]
    fn tool_choice_strings_pass_through_and_unknown_shapes_drop() {
        for choice in ["auto", "none", "required"] {
            let out = translate(
                &format!(
                    r#"{{"messages":[],"tools":[{{"type":"function","function":{{"name":"f"}}}}],"tool_choice":"{choice}"}}"#
                ),
                "m",
            );
            assert_eq!(out["tool_choice"], choice);
        }
        // A shape with no Responses equivalent is dropped, not guessed.
        let out = translate(
            r#"{"messages":[],"tool_choice":{"type":"allowed_tools","allowed_tools":["a"]}}"#,
            "m",
        );
        assert!(out.get("tool_choice").is_none());
    }

    #[test]
    fn token_budget_reasoning_and_sampling_fields_map() {
        let out = translate(
            r#"{"messages":[],"max_tokens":128,"temperature":0.2,"top_p":0.9,"stop":["\n\n"]}"#,
            "m",
        );
        assert_eq!(out["max_output_tokens"], 128);
        assert_eq!(out["temperature"], 0.2);
        assert_eq!(out["top_p"], 0.9);
        assert_eq!(out["stop"][0], "\n\n");
        assert!(out.get("max_tokens").is_none());

        // The newer spelling wins when a client sends both.
        let out = translate(
            r#"{"messages":[],"max_tokens":1,"max_completion_tokens":2,"reasoning_effort":"high"}"#,
            "m",
        );
        assert_eq!(out["max_output_tokens"], 2);
        assert_eq!(out["reasoning"], serde_json::json!({"effort": "high"}));
    }

    #[test]
    fn chat_only_knobs_are_dropped() {
        let out = translate(
            r#"{"messages":[{"role":"user","content":"hi"}],"n":3,"logprobs":true,"top_logprobs":2,
                "frequency_penalty":0.5,"presence_penalty":-0.5,"logit_bias":{},"seed":7,"user":"u1",
                "parallel_tool_calls":false,"response_format":{"type":"json_object"},
                "stream_options":{"include_usage":true}}"#,
            "m",
        );
        for dropped in [
            "n",
            "logprobs",
            "top_logprobs",
            "frequency_penalty",
            "presence_penalty",
            "logit_bias",
            "seed",
            "user",
            "parallel_tool_calls",
            "response_format",
            "stream_options",
        ] {
            assert!(out.get(dropped).is_none(), "{dropped} must be dropped");
        }
        assert_eq!(out["store"], false);
    }

    #[test]
    fn codex_endpoint_pins_stream_true_for_a_non_stream_call() {
        let out = translate_codex(r#"{"model":"public","messages":[],"stream":false}"#);
        assert_eq!(out["stream"], true);
        assert_eq!(out["model"], "gpt-5.6-codex");
        assert_eq!(out["store"], false);
    }

    #[test]
    fn untranslatable_bodies_return_none() {
        assert!(chat_request_to_responses(b"not json", &opts("m")).is_none());
        assert!(chat_request_to_responses(b"[]", &opts("m")).is_none());
        assert!(chat_request_to_responses(b"\"x\"", &opts("m")).is_none());
    }

    // ===== response side =====

    fn created_event(id: &str) -> String {
        format!(
            "data: {{\"type\":\"response.created\",\"response\":{{\"id\":\"{id}\",\"created_at\":1700000000}}}}\n\n"
        )
    }

    fn text_delta(text: &str) -> String {
        format!("data: {{\"type\":\"response.output_text.delta\",\"delta\":\"{text}\"}}\n\n")
    }

    fn completed(usage: &str, extra: &str) -> String {
        format!(
            "data: {{\"type\":\"response.completed\",\"response\":{{\"id\":\"resp_1\",\"created_at\":1700000000{extra},\"usage\":{usage}}}}}\n\ndata: [DONE]\n\n"
        )
    }

    /// Collect the JSON payloads of an SSE body without translating it.
    fn parse_frames(sse: &str) -> Vec<Value> {
        sse.lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .filter(|data| *data != "[DONE]")
            .map(|data| serde_json::from_str(data).unwrap())
            .collect()
    }

    /// Translate a Responses SSE body and collect the resulting chat chunk frames.
    fn translate_frames(sse: &str) -> Vec<Value> {
        let out = responses_sse_to_chat_chunks(sse.as_bytes(), "public-model").unwrap();
        parse_frames(&out)
    }

    #[test]
    fn stream_happy_path_maps_created_deltas_and_completion() {
        let sse = format!(
            "{}{}{}{}",
            created_event("resp_1"),
            text_delta("Hel"),
            text_delta("lo"),
            completed(
                r#"{"input_tokens":11,"output_tokens":7,"total_tokens":18}"#,
                ""
            )
        );
        let out = responses_sse_to_chat_chunks(sse.as_bytes(), "public-model").unwrap();
        assert!(out.ends_with("data: [DONE]\n\n"), "{out}");
        let chunks = parse_frames(&out);
        assert_eq!(chunks.len(), 5);
        assert_eq!(chunks[0]["choices"][0]["delta"]["role"], "assistant");
        assert_eq!(chunks[1]["choices"][0]["delta"]["content"], "Hel");
        assert_eq!(chunks[2]["choices"][0]["delta"]["content"], "lo");
        assert_eq!(chunks[3]["choices"][0]["finish_reason"], "stop");
        assert_eq!(chunks[4]["usage"]["prompt_tokens"], 11);
        assert_eq!(chunks[4]["usage"]["completion_tokens"], 7);
        assert_eq!(chunks[4]["usage"]["total_tokens"], 18);
        assert_eq!(chunks[4]["choices"].as_array().unwrap().len(), 0);
        for chunk in &chunks {
            assert_eq!(chunk["object"], "chat.completion.chunk");
            assert_eq!(chunk["model"], "public-model", "client-facing name only");
            assert_eq!(
                chunk["id"], "resp_1",
                "id preserved from the response object"
            );
            assert_eq!(chunk["created"], 1_700_000_000u64);
        }
    }

    #[test]
    fn stream_usage_without_total_is_summed() {
        let sse = format!(
            "{}{}",
            created_event("resp_1"),
            completed(r#"{"input_tokens":3,"output_tokens":4}"#, "")
        );
        let chunks = translate_frames(&sse);
        let usage = &chunks.last().unwrap()["usage"];
        assert_eq!(usage["total_tokens"], 7);
    }

    #[test]
    fn stream_without_usage_emits_no_usage_chunk() {
        let sse = format!(
            "{}{}{}",
            created_event("resp_1"),
            text_delta("hi"),
            completed("null", "")
        );
        let chunks = translate_frames(&sse);
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|chunk| chunk.get("usage").is_none()));
    }

    #[test]
    fn stream_tool_call_item_becomes_a_tool_calls_delta() {
        let sse = format!(
            "{}{}{}{}",
            created_event("resp_1"),
            "data: {\"type\":\"response.output_item.added\",\"item\":{\"type\":\"function_call\"}}\n\n",
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call_7\",\"name\":\"get_weather\",\"arguments\":\"{\\\"city\\\":\\\"Hanoi\\\"}\"}}\n\n",
            completed(
                r#"{"input_tokens":4,"output_tokens":2,"total_tokens":6}"#,
                ""
            )
        );
        let chunks = translate_frames(&sse);
        // role chunk, the ignored `output_item.added`, the tool call, finish, usage.
        assert_eq!(chunks.len(), 4);
        let call = &chunks[1]["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(call["index"], 0);
        assert_eq!(call["id"], "call_7");
        assert_eq!(call["type"], "function");
        assert_eq!(call["function"]["name"], "get_weather");
        assert_eq!(call["function"]["arguments"], "{\"city\":\"Hanoi\"}");
        assert_eq!(chunks[2]["choices"][0]["finish_reason"], "tool_calls");
    }

    #[test]
    fn stream_indexes_multiple_tool_calls() {
        let mut sse = created_event("resp_1");
        for (index, call_id) in ["call_a", "call_b"].iter().enumerate() {
            sse.push_str(&format!(
                "data: {{\"type\":\"response.output_item.done\",\"item\":{{\"type\":\"function_call\",\"call_id\":\"{call_id}\",\"name\":\"f{index}\",\"arguments\":\"{{}}\"}}}}\n\n"
            ));
        }
        sse.push_str(&completed("null", ""));
        let chunks = translate_frames(&sse);
        let indexes: Vec<u64> = chunks
            .iter()
            .filter_map(|chunk| chunk.pointer("/choices/0/delta/tool_calls/0/index"))
            .filter_map(Value::as_u64)
            .collect();
        assert_eq!(indexes, [0, 1]);
        assert_eq!(
            chunks.last().unwrap()["choices"][0]["finish_reason"],
            "tool_calls"
        );
    }

    #[test]
    fn stream_incomplete_on_max_tokens_finishes_with_length() {
        let sse = concat!(
            "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"created_at\":1700000000}}\n\n",
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"part\"}\n\n",
            "data: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"resp_1\",\"incomplete_details\":{\"reason\":\"max_output_tokens\"},\"usage\":{\"input_tokens\":5,\"output_tokens\":5}}}\n\n"
        );
        let chunks = translate_frames(sse);
        assert_eq!(chunks[1]["choices"][0]["delta"]["content"], "part");
        assert_eq!(chunks[2]["choices"][0]["finish_reason"], "length");
        assert_eq!(chunks[3]["usage"]["total_tokens"], 10);
    }

    #[test]
    fn stream_failed_event_terminates_with_an_error_frame() {
        let sse = format!(
            "{}{}",
            created_event("resp_1"),
            "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"message\":\"model capacity\",\"code\":\"server_error\"}}}\n\n"
        );
        let out = responses_sse_to_chat_chunks(sse.as_bytes(), "public-model").unwrap();
        let chunks = parse_frames(&out);
        assert_eq!(chunks[1]["error"]["message"], "model capacity");
        assert_eq!(chunks[1]["error"]["type"], "server_error");
        assert!(out.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn stream_error_event_and_missing_message_fall_back() {
        let sse =
            "data: {\"type\":\"error\",\"code\":\"rate_limit\",\"message\":\"slow down\"}\n\n";
        let chunks = translate_frames(sse);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0]["error"]["message"], "slow down");

        let sse = "data: {\"type\":\"error\",\"code\":\"weird\"}\n\n";
        let chunks = translate_frames(sse);
        assert_eq!(
            chunks[0]["error"]["message"],
            "upstream responses request failed"
        );
    }

    #[test]
    fn stream_ignores_unknown_events_and_emits_done_once() {
        let sse = concat!(
            "event: ping\n\n",
            ": keep-alive comment\n\n",
            "data: {\"type\":\"response.in_progress\",\"response\":{\"id\":\"resp_1\"}}\n\n",
            "data: {\"type\":\"response.output_text.done\",\"text\":\"hi\"}\n\n",
        );
        let out = responses_sse_to_chat_chunks(sse.as_bytes(), "public-model");
        assert!(
            out.is_none(),
            "a stream with no mappable event has nothing to send"
        );

        // A duplicated terminal event must not produce a second [DONE].
        let sse = format!(
            "{}{}{}",
            created_event("resp_1"),
            completed(r#"{"input_tokens":1,"output_tokens":1}"#, ""),
            completed(r#"{"input_tokens":1,"output_tokens":1}"#, "")
        );
        let out = responses_sse_to_chat_chunks(sse.as_bytes(), "public-model").unwrap();
        assert_eq!(out.matches("data: [DONE]").count(), 1);
    }

    #[test]
    fn stream_survives_chunk_boundaries_splitting_an_event() {
        let sse = format!(
            "{}{}{}",
            created_event("resp_1"),
            text_delta("Hello"),
            completed(
                r#"{"input_tokens":11,"output_tokens":7,"total_tokens":18}"#,
                ""
            )
        );
        let mut translator = ResponsesSseToChat::new("public-model");
        let mut out = Vec::new();
        // Feed one byte at a time: no event may be lost, duplicated, or half-emitted.
        for byte in sse.as_bytes() {
            out.extend_from_slice(&translator.feed(&[*byte]));
        }
        out.extend_from_slice(&translator.finish());
        let whole = responses_sse_to_chat_chunks(sse.as_bytes(), "public-model").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), whole);
    }

    #[test]
    fn stream_final_line_without_newline_still_finishes() {
        let sse = format!(
            "{}{}",
            created_event("resp_1"),
            r#"data: {"type":"response.completed","response":{"id":"resp_1","created_at":1700000000,"usage":{"input_tokens":2,"output_tokens":3}}}"#
        );
        let chunks = translate_frames(&sse);
        assert_eq!(chunks[1]["choices"][0]["finish_reason"], "stop");
        assert_eq!(chunks[2]["usage"]["prompt_tokens"], 2);
    }

    #[test]
    fn stream_truncated_without_terminal_event_stops_silently() {
        let sse = format!("{}{}", created_event("resp_1"), text_delta("half"));
        let out = responses_sse_to_chat_chunks(sse.as_bytes(), "public-model").unwrap();
        assert!(
            !out.contains("[DONE]"),
            "no [DONE] without a terminal event"
        );
        assert!(out.contains("\"half\""));
    }

    #[test]
    fn stream_parses_rfc3339_created_at_into_unix_seconds() {
        let sse = concat!(
            "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_2\",\"created_at\":\"2023-11-14T22:13:20Z\"}}\n\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_2\"}}\n\n"
        );
        let chunks = translate_frames(sse);
        assert_eq!(chunks[0]["created"], 1_700_000_000u64);
    }

    #[test]
    fn nonstream_completion_maps_text_and_usage() {
        let body = br#"{"id":"resp_9","object":"response","created_at":1700000000,
            "output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hello there"}]}],
            "usage":{"input_tokens":9,"output_tokens":4,"total_tokens":13}}"#;
        let out = responses_json_to_chat_completion(body, "public-model").unwrap();
        assert_eq!(out["object"], "chat.completion");
        assert_eq!(out["id"], "resp_9");
        assert_eq!(out["created"], 1_700_000_000u64);
        assert_eq!(out["model"], "public-model");
        assert_eq!(out["choices"][0]["message"]["role"], "assistant");
        assert_eq!(out["choices"][0]["message"]["content"], "Hello there");
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        assert_eq!(out["usage"]["prompt_tokens"], 9);
        assert_eq!(out["usage"]["completion_tokens"], 4);
        assert_eq!(out["usage"]["total_tokens"], 13);
        assert!(out["choices"][0]["message"].get("tool_calls").is_none());
    }

    #[test]
    fn nonstream_completion_maps_tool_calls_with_null_content() {
        let body = br#"{"id":"resp_10","output":[
            {"type":"message","role":"assistant","content":[{"type":"output_text","text":""}]},
            {"type":"function_call","call_id":"call_1","name":"get_weather","arguments":"{\"city\":\"Hanoi\"}"},
            {"type":"reasoning","summary":[]}
        ]}"#;
        let out = responses_json_to_chat_completion(body, "public-model").unwrap();
        let message = &out["choices"][0]["message"];
        assert_eq!(message["content"], Value::Null);
        assert_eq!(message["tool_calls"][0]["id"], "call_1");
        assert_eq!(message["tool_calls"][0]["type"], "function");
        assert_eq!(message["tool_calls"][0]["function"]["name"], "get_weather");
        assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");
        assert!(out.get("usage").is_none());
        assert!(out.get("created").is_none());
    }

    #[test]
    fn nonstream_completion_uses_output_text_fallback_and_sums_usage() {
        let body =
            br#"{"id":"resp_11","output_text":"OK","usage":{"input_tokens":6,"output_tokens":2}}"#;
        let out = responses_json_to_chat_completion(body, "public-model").unwrap();
        assert_eq!(out["choices"][0]["message"]["content"], "OK");
        assert_eq!(out["usage"]["total_tokens"], 8);
    }

    #[test]
    fn nonstream_completion_concatenates_multiple_text_parts() {
        let body = br#"{"id":"resp_12","output":[{"type":"message","content":[
            {"type":"output_text","text":"a"},
            {"type":"refusal","refusal":"no"},
            {"type":"output_text","text":"b"}
        ]}]}"#;
        let out = responses_json_to_chat_completion(body, "public-model").unwrap();
        assert_eq!(out["choices"][0]["message"]["content"], "ab");
    }

    #[test]
    fn nonstream_completion_rejects_non_objects() {
        assert!(responses_json_to_chat_completion(b"[]", "m").is_none());
        assert!(
            responses_json_to_chat_completion(b"{\"error\":{\"message\":\"x\"}}", "m").is_some()
        );
        assert!(responses_json_to_chat_completion(b"not json", "m").is_none());
    }
}
