//! OpenCode Zen free tier (`https://opencode.ai/zen/v1`) wire adapter.
//!
//! The free lane is an OpenAI-compatible chat endpoint that needs **no credential** but gates
//! requests on client identity instead. The contract below was reverse-engineered from
//! VansRouter and validated with a live 200 probe; every rule is enforced exactly:
//!
//! * `Authorization: Bearer public` — literal shared credential.
//! * `User-Agent: opencode/<version>` — the upstream rejects a UA without an opencode version
//!   >= 1.17.0, so the version is pinned (see `OPENCODE_FREE_USER_AGENT`).
//! * `x-opencode-client: desktop`, `x-opencode-project: global`.
//! * `x-opencode-session` / `x-opencode-request` — canonical ids, fresh per request; a
//!   non-canonical or reused id is rejected with 403. Generated in `provider_auth` when the
//!   header set is applied.
//! * The upstream must receive `stream: true`; non-streaming bodies are 403'd. The router pins
//!   it and, when the client asked for a non-streaming completion, folds the SSE back into one
//!   `chat.completion` object (`aggregate_sse_to_completion`).
//! * The `tools` array must contain the fingerprint quartet `bash`, `glob`, `grep`, `read`
//!   exactly once each (case-insensitive caller spellings are canonicalized, duplicates are
//!   dropped, missing members are injected as decoys).
//!
//! This module is pure: no I/O, no clock reads — only the id generator touches the RNG, mirroring
//! `route` which already uses `rand` on the request path.

use serde_json::Value;

use crate::contract::ProviderProtocol;

/// `auth_mode` selecting the OpenCode Zen free tier. Needs no provider key.
pub const AUTH_MODE: &str = "opencode_free";

/// Tool names the upstream fingerprint-checks for. Order is the decoy injection order.
pub const FINGERPRINT_TOOLS: [&str; 4] = ["bash", "glob", "grep", "read"];

/// Description stamped on injected decoy tools so a model that tries to call one declines.
pub const DECOY_TOOL_DESCRIPTION: &str = "This tool is currently unavailable and must not be used.";

/// Number of lowercase-hex characters in the canonical id layout.
const ID_HEX_CHARS: usize = 12;
/// Six random bytes render as exactly 12 hex characters.
const ID_HEX_BYTES: usize = ID_HEX_CHARS / 2;
/// Number of base62 characters (`0-9A-Za-z`) in the canonical id layout.
const ID_BASE62_LEN: usize = 14;

const BASE62_ALPHABET: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

/// Generate a fresh canonical `ses_` id: `ses_` + 12 lowercase hex + 14 base62.
pub fn new_session_id() -> String {
    random_id("ses_")
}

/// Generate a fresh canonical `msg_` id: `msg_` + 12 lowercase hex + 14 base62.
pub fn new_request_id() -> String {
    random_id("msg_")
}

fn random_id(prefix: &str) -> String {
    use rand::RngExt as _;
    let mut bytes = [0u8; ID_HEX_BYTES + ID_BASE62_LEN];
    rand::rng().fill(&mut bytes);
    let mut out = String::with_capacity(prefix.len() + ID_HEX_CHARS + ID_BASE62_LEN);
    out.push_str(prefix);
    for b in &bytes[..ID_HEX_BYTES] {
        out.push(HEX_ALPHABET[(b >> 4) as usize] as char);
        out.push(HEX_ALPHABET[(b & 0x0f) as usize] as char);
    }
    for b in &bytes[ID_HEX_BYTES..] {
        out.push(BASE62_ALPHABET[(*b % BASE62_ALPHABET.len() as u8) as usize] as char);
    }
    out
}

/// True when `id` matches the canonical upstream layout for the given prefix
/// (`ses_`/`msg_` + 12 lowercase hex + 14 base62). Non-canonical ids are rejected with 403.
pub fn is_canonical_id(prefix: &str, id: &str) -> bool {
    let Some(rest) = id.strip_prefix(prefix) else {
        return false;
    };
    let bytes = rest.as_bytes();
    bytes.len() == ID_HEX_CHARS + ID_BASE62_LEN
        && bytes[..ID_HEX_CHARS]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        && bytes[ID_HEX_CHARS..]
            .iter()
            .all(|b| BASE62_ALPHABET.contains(b))
}

/// The chat-lane protocols the free-tier request adapter covers. Only `/v1/chat/completions`
/// is in scope: Responses and Claude lanes are not adapted.
fn is_chat_protocol(protocol: ProviderProtocol) -> bool {
    matches!(
        protocol,
        ProviderProtocol::OpenAiChat
            | ProviderProtocol::LocalOpenAiChat
            | ProviderProtocol::CustomOpenAiChat
    )
}

/// True when a route speaks the OpenCode free tier on the chat lane.
///
/// The adapter and the SSE aggregation only apply to a plain single-backend route
/// (`endpoints` empty, the natural config for this provider): a Model Group would need the
/// per-endpoint variant, which is out of scope here.
pub fn is_free_chat_route(
    auth_mode: &str,
    protocol: ProviderProtocol,
    has_endpoints: bool,
) -> bool {
    auth_mode.eq_ignore_ascii_case(AUTH_MODE) && is_chat_protocol(protocol) && !has_endpoints
}

/// Injected decoy tool: valid chat-shape function the model must never call.
pub fn decoy_tool(name: &str) -> Value {
    serde_json::json!({
        "type": "function",
        "function": {
            "name": name,
            "description": DECOY_TOOL_DESCRIPTION,
            "parameters": {"type": "object", "properties": {}}
        }
    })
}

/// Apply the free-tier body gates to a parsed chat-completions request object.
///
/// * pins top-level `stream` to `true` (the upstream 403s non-streaming bodies);
/// * makes `tools` contain the fingerprint quartet exactly once each: caller spellings are
///   canonicalized to lowercase (Claude Code sends `Bash`/`Glob`/`Grep`/`Read`), duplicate
///   spellings of the same member are dropped (the upstream rejects `Bash` + `bash`), missing
///   members are appended as decoy tools;
/// * when the caller supplied no tools, sets `tool_choice` to `"none"` so the decoys can never
///   be invoked; otherwise the caller's `tool_choice` (present or absent) is preserved.
///
/// Returns whether anything changed, so the caller can forward the original bytes untouched.
pub fn adapt_chat_request(obj: &mut serde_json::Map<String, Value>) -> bool {
    let mut changed = false;

    if obj.get("stream").and_then(Value::as_bool) != Some(true) {
        obj.insert("stream".to_string(), Value::Bool(true));
        changed = true;
    }

    let caller_tools = obj.get("tools").and_then(Value::as_array).cloned();
    let caller_had_tools = caller_tools.as_ref().is_some_and(|tools| !tools.is_empty());
    let mut adapted: Vec<Value> =
        Vec::with_capacity(caller_tools.as_ref().map_or(0, Vec::len) + FINGERPRINT_TOOLS.len());
    let mut seen = [false; FINGERPRINT_TOOLS.len()];
    for tool in caller_tools.unwrap_or_default() {
        let Some(name) = tool.pointer("/function/name").and_then(Value::as_str) else {
            adapted.push(tool);
            continue;
        };
        let Some(index) = FINGERPRINT_TOOLS
            .iter()
            .position(|member| name.eq_ignore_ascii_case(member))
        else {
            adapted.push(tool);
            continue;
        };
        // A duplicate spelling of the same member must not survive (upstream rejects it).
        if seen[index] {
            changed = true;
            continue;
        }
        seen[index] = true;
        if name == FINGERPRINT_TOOLS[index] {
            adapted.push(tool);
        } else {
            let mut canonical = tool;
            if let Some(serde_json::Value::String(slot)) = canonical.pointer_mut("/function/name") {
                *slot = FINGERPRINT_TOOLS[index].to_string();
            }
            adapted.push(canonical);
            changed = true;
        }
    }
    for (index, member) in FINGERPRINT_TOOLS.iter().enumerate() {
        if !seen[index] {
            adapted.push(decoy_tool(member));
            changed = true;
        }
    }
    if changed {
        obj.insert("tools".to_string(), Value::Array(adapted));
    }

    if !caller_had_tools && obj.get("tool_choice").and_then(Value::as_str) != Some("none") {
        obj.insert("tool_choice".to_string(), Value::String("none".to_string()));
        changed = true;
    }
    changed
}

/// Map an upstream free-tier error onto the status an OpenAI client can act on.
///
/// * 429/403 with a rate/quota-ish body -> 429 (the free tier throttles per IP);
/// * 401 with "Model ... is not supported" -> 404 model not found;
/// * 400 with "Model is unavailable" -> 503 model unavailable.
///
/// Returns `None` when the status/body pair is not one of the known gates; the raw upstream
/// response is then forwarded unchanged.
pub fn map_upstream_error(status: u16, body: &str) -> Option<(u16, &'static str)> {
    match status {
        429 | 403 if mentions_rate_limit(body) => Some((429, RATE_LIMIT_MESSAGE)),
        401 if model_not_supported(body) => Some((404, MODEL_NOT_FOUND_MESSAGE)),
        400 if contains_ci(body, "model is unavailable") => Some((503, MODEL_UNAVAILABLE_MESSAGE)),
        _ => None,
    }
}

pub const RATE_LIMIT_MESSAGE: &str = "OpenCode free tier per-IP limit reached: the shared \
     opencode.ai free upstream is throttling this router's IP address. Wait and retry, or point \
     this model at another backend.";
pub const MODEL_NOT_FOUND_MESSAGE: &str =
    "model not found: the OpenCode free tier does not support this model";
pub const MODEL_UNAVAILABLE_MESSAGE: &str =
    "model unavailable: the OpenCode free tier reports this model is temporarily unavailable";

/// /limit|rate|quota|exhausted|capacity|too many|retry/i, spelled without a regex engine.
fn mentions_rate_limit(body: &str) -> bool {
    const NEEDLES: [&str; 7] = [
        "limit",
        "rate",
        "quota",
        "exhausted",
        "capacity",
        "too many",
        "retry",
    ];
    NEEDLES.iter().any(|needle| contains_ci(body, needle))
}

/// /Model .* is not supported/i — "model" then anything then "is not supported".
fn model_not_supported(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower
        .find("model")
        .is_some_and(|start| lower[start..].contains("is not supported"))
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// OpenAI-style error body for a mapped upstream status.
pub fn error_body(status: u16, message: &str) -> Value {
    let error_type = match status {
        429 => "rate_limit_error",
        404 => "invalid_request_error",
        _ => "server_error",
    };
    serde_json::json!({
        "error": {"message": message, "type": error_type}
    })
}

/// One accumulating `delta.tool_calls` entry: `id`/`name` arrive on the first chunk for an index,
/// `arguments` arrives concatenated across chunks.
#[derive(Default)]
struct ToolCallFold {
    id: Option<Value>,
    name: Option<String>,
    arguments: String,
}

/// Fold a `chat.completion.chunk` SSE stream into one non-streaming `chat.completion`.
///
/// `id`/`created` come from the first chunk that carries them, `model` is the client-facing
/// model name (the client never sees the upstream model string), `choices[0].message.content`
/// is the concatenation of every `delta.content` (`delta.reasoning_content`, when present,
/// becomes a sibling `reasoning_content` field), `delta.tool_calls` entries fold by index into
/// `message.tool_calls`, `finish_reason` is taken from the last chunk that has one and `usage`
/// from the final chunk when the upstream sends one.
///
/// Returns `None` when no `data:` frame parsed — the caller turns that into a 502.
pub fn aggregate_sse_to_completion(sse: &[u8], client_model: &str) -> Option<Value> {
    let mut id: Option<Value> = None;
    let mut created: Option<Value> = None;
    let mut content = String::new();
    let mut reasoning = String::new();
    let mut saw_reasoning = false;
    let mut tool_calls: Vec<ToolCallFold> = Vec::new();
    let mut finish_reason: Option<Value> = None;
    let mut usage: Option<Value> = None;
    let mut saw_chunk = false;

    for line in sse.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(data) = line.strip_prefix(b"data:") else {
            continue;
        };
        let data = data.trim_ascii_start();
        if data.starts_with(b"[DONE]") {
            continue;
        }
        let Ok(chunk) = serde_json::from_slice::<Value>(data) else {
            continue;
        };
        saw_chunk = true;
        if id.is_none()
            && let Some(value) = chunk.get("id")
            && !value.is_null()
        {
            id = Some(value.clone());
        }
        if created.is_none()
            && let Some(value) = chunk.get("created")
            && !value.is_null()
        {
            created = Some(value.clone());
        }
        if let Some(choice) = chunk
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
        {
            if let Some(delta) = choice.get("delta") {
                if let Some(part) = delta.get("content").and_then(Value::as_str) {
                    content.push_str(part);
                }
                if let Some(part) = delta.get("reasoning_content").and_then(Value::as_str) {
                    reasoning.push_str(part);
                    saw_reasoning = true;
                }
                for call in delta
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .map_or(&[][..], Vec::as_slice)
                {
                    let index = call.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                    while tool_calls.len() <= index {
                        tool_calls.push(ToolCallFold::default());
                    }
                    let folded = &mut tool_calls[index];
                    if folded.id.is_none()
                        && let Some(call_id) = call.get("id").filter(|v| !v.is_null())
                    {
                        folded.id = Some(call_id.clone());
                    }
                    if folded.name.is_none()
                        && let Some(name) = call.pointer("/function/name").and_then(Value::as_str)
                    {
                        folded.name = Some(name.to_string());
                    }
                    if let Some(args) = call.pointer("/function/arguments").and_then(Value::as_str)
                    {
                        folded.arguments.push_str(args);
                    }
                }
            }
            if let Some(reason) = choice.get("finish_reason")
                && !reason.is_null()
            {
                finish_reason = Some(reason.clone());
            }
        }
        if let Some(chunk_usage) = chunk.get("usage")
            && !chunk_usage.is_null()
        {
            usage = Some(chunk_usage.clone());
        }
    }

    if !saw_chunk {
        return None;
    }

    let mut message = serde_json::Map::new();
    message.insert("role".to_string(), Value::String("assistant".to_string()));
    // Chat semantics: an assistant message that only calls tools carries null content.
    if content.is_empty() && !tool_calls.is_empty() {
        message.insert("content".to_string(), Value::Null);
    } else {
        message.insert("content".to_string(), Value::String(content));
    }
    if saw_reasoning {
        message.insert("reasoning_content".to_string(), Value::String(reasoning));
    }
    if !tool_calls.is_empty() {
        let calls: Vec<Value> = tool_calls
            .into_iter()
            .map(|folded| {
                let mut function = serde_json::Map::new();
                if let Some(name) = folded.name {
                    function.insert("name".to_string(), Value::String(name));
                }
                function.insert("arguments".to_string(), Value::String(folded.arguments));
                serde_json::json!({
                    "id": folded.id.unwrap_or(Value::Null),
                    "type": "function",
                    "function": Value::Object(function),
                })
            })
            .collect();
        message.insert("tool_calls".to_string(), Value::Array(calls));
    }
    let mut choice = serde_json::Map::new();
    choice.insert("index".to_string(), Value::from(0u64));
    choice.insert("message".to_string(), Value::Object(message));
    if let Some(reason) = finish_reason {
        choice.insert("finish_reason".to_string(), reason);
    }

    let mut out = serde_json::Map::new();
    out.insert(
        "object".to_string(),
        Value::String("chat.completion".to_string()),
    );
    if let Some(id) = id {
        out.insert("id".to_string(), id);
    }
    if let Some(created) = created {
        out.insert("created".to_string(), created);
    }
    out.insert("model".to_string(), Value::String(client_model.to_string()));
    out.insert(
        "choices".to_string(),
        Value::Array(vec![Value::Object(choice)]),
    );
    if let Some(usage) = usage {
        out.insert("usage".to_string(), usage);
    }
    Some(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_names(value: &Value) -> Vec<String> {
        value["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["function"]["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn generated_ids_match_the_canonical_layout() {
        for _ in 0..64 {
            let session = new_session_id();
            let request = new_request_id();
            assert!(
                is_canonical_id("ses_", &session),
                "non-canonical session id: {session}"
            );
            assert!(
                is_canonical_id("msg_", &request),
                "non-canonical request id: {request}"
            );
            assert!(session.starts_with("ses_") && request.starts_with("msg_"));
        }
    }

    #[test]
    fn generated_ids_are_fresh_per_call() {
        assert_ne!(new_session_id(), new_session_id());
        assert_ne!(new_request_id(), new_request_id());
    }

    #[test]
    fn canonical_id_check_rejects_non_canonical_shapes() {
        // Wrong length, uppercase hex, wrong prefix, illegal suffix characters.
        assert!(!is_canonical_id("ses_", "ses_0123456789ABcdefghijklmnop"));
        assert!(!is_canonical_id("ses_", "ses_0123456789ABCDEFghijklmn"));
        assert!(!is_canonical_id("ses_", "msg_0123456789abcdefghijkABC"));
        assert!(!is_canonical_id("ses_", "ses_0123456789abcdef-!@#$%^&*()"));
        assert!(!is_canonical_id("ses_", ""));
        assert!(is_canonical_id("ses_", "ses_0123456789abcdefghijABCDEF"));
    }

    #[test]
    fn adapt_pins_stream_and_injects_the_full_quartet() {
        let mut obj = serde_json::from_str::<serde_json::Map<String, Value>>(
            r#"{"model":"qwen3-coder","messages":[{"role":"user","content":"hi"}],"stream":false}"#,
        )
        .unwrap();
        assert!(adapt_chat_request(&mut obj));
        let value = Value::Object(obj);
        assert_eq!(value["stream"], true);
        assert_eq!(
            tool_names(&value),
            ["bash", "glob", "grep", "read"],
            "missing members must be injected as decoys in quartet order"
        );
        assert_eq!(value["tool_choice"], "none");
        // Decoy shape is the documented one.
        assert_eq!(
            value["tools"][0]["function"]["description"],
            DECOY_TOOL_DESCRIPTION
        );
        assert_eq!(
            value["tools"][0]["function"]["parameters"],
            serde_json::json!({"type":"object","properties":{}})
        );
    }

    #[test]
    fn adapt_canonicalizes_case_dedupes_and_keeps_caller_tools() {
        let mut obj = serde_json::from_str::<serde_json::Map<String, Value>>(
            r#"{"model":"m","messages":[],"stream":true,"tool_choice":"auto","tools":[
                {"type":"function","function":{"name":"Bash","description":"cli","parameters":{"type":"object"}}},
                {"type":"function","function":{"name":"BASH","description":"dup","parameters":{"type":"object"}}},
                {"type":"function","function":{"name":"Read","description":"files","parameters":{"type":"object"}}},
                {"type":"function","function":{"name":"WebSearch","description":"extra","parameters":{"type":"object"}}}
            ]}"#,
        )
        .unwrap();
        assert!(adapt_chat_request(&mut obj));
        let value = Value::Object(obj);
        let names = tool_names(&value);
        assert_eq!(
            names,
            ["bash", "read", "WebSearch", "glob", "grep"],
            "case canonicalized in place, duplicates dropped, extras kept, missing appended"
        );
        assert_eq!(
            value["tool_choice"], "auto",
            "caller tool_choice is preserved"
        );
        // The real tool definitions survive canonicalization; only the name changed.
        assert_eq!(value["tools"][0]["function"]["description"], "cli");
        assert_eq!(value["tools"][1]["function"]["description"], "files");
        assert_eq!(
            value["tools"][3]["function"]["description"],
            DECOY_TOOL_DESCRIPTION
        );
    }

    #[test]
    fn adapt_is_a_noop_for_an_already_conforming_request() {
        let raw = r#"{"model":"m","messages":[],"stream":true,"tool_choice":"auto","tools":[
            {"type":"function","function":{"name":"bash","parameters":{"type":"object"}}},
            {"type":"function","function":{"name":"glob","parameters":{"type":"object"}}},
            {"type":"function","function":{"name":"grep","parameters":{"type":"object"}}},
            {"type":"function","function":{"name":"read","parameters":{"type":"object"}}}
        ]}"#;
        let mut obj = serde_json::from_str::<serde_json::Map<String, Value>>(raw).unwrap();
        assert!(!adapt_chat_request(&mut obj));
    }

    #[test]
    fn adapt_treats_an_empty_tools_array_as_no_tools() {
        let mut obj = serde_json::from_str::<serde_json::Map<String, Value>>(
            r#"{"model":"m","messages":[],"tools":[]}"#,
        )
        .unwrap();
        assert!(adapt_chat_request(&mut obj));
        let value = Value::Object(obj);
        assert_eq!(tool_names(&value).len(), 4);
        assert_eq!(value["tool_choice"], "none");
    }

    #[test]
    fn error_mapping_statuses() {
        // Per-IP limit gates -> 429 with the free-tier message.
        assert_eq!(
            map_upstream_error(429, r#"{"error":{"message":"rate limit exceeded"}}"#)
                .unwrap()
                .0,
            429
        );
        assert_eq!(
            map_upstream_error(403, "You have exhausted your quota for today")
                .unwrap()
                .0,
            429
        );
        assert_eq!(
            map_upstream_error(429, "Too many requests, retry later")
                .unwrap()
                .0,
            429
        );
        // Model gates.
        assert_eq!(
            map_upstream_error(401, "Model qwen3-coder is not supported on the free plan")
                .unwrap()
                .0,
            404
        );
        assert_eq!(
            map_upstream_error(400, "Model is unavailable").unwrap().0,
            503
        );
        // Unknown shapes pass through unmapped.
        assert!(map_upstream_error(403, "forbidden signature").is_none());
        assert!(map_upstream_error(401, "invalid token").is_none());
        assert!(map_upstream_error(400, "bad json").is_none());
        assert!(map_upstream_error(500, "limit").is_none());
        assert!(map_upstream_error(200, "rate limit").is_none());
    }

    #[test]
    fn mapped_error_body_uses_openai_error_shape() {
        let body = error_body(429, RATE_LIMIT_MESSAGE);
        assert_eq!(body["error"]["type"], "rate_limit_error");
        assert_eq!(body["error"]["message"], RATE_LIMIT_MESSAGE);
        assert_eq!(
            error_body(404, "x")["error"]["type"],
            "invalid_request_error"
        );
        assert_eq!(error_body(503, "x")["error"]["type"], "server_error");
    }

    #[test]
    fn sse_aggregation_happy_path_with_usage_and_finish_reason() {
        let sse = concat!(
            "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"qwen3-coder\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"created\":1700000000,\"model\":\"qwen3-coder\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel\"},\"finish_reason\":null}]}\n",
            "data: {\"id\":\"chatcmpl-1\",\"created\":1700000000,\"model\":\"qwen3-coder\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"created\":1700000000,\"model\":\"qwen3-coder\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":2}}\n\n",
            "data: [DONE]\n\n"
        );
        let out = aggregate_sse_to_completion(sse.as_bytes(), "public-free-model").unwrap();
        assert_eq!(out["object"], "chat.completion");
        assert_eq!(out["id"], "chatcmpl-1");
        assert_eq!(out["created"], 1700000000);
        assert_eq!(
            out["model"], "public-free-model",
            "the client must see its own model name, not the upstream one"
        );
        assert_eq!(out["choices"][0]["index"], 0);
        assert_eq!(out["choices"][0]["message"]["role"], "assistant");
        assert_eq!(out["choices"][0]["message"]["content"], "Hello");
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        assert_eq!(out["usage"]["prompt_tokens"], 11);
        assert_eq!(out["usage"]["completion_tokens"], 2);
        assert!(out.get("reasoning_content").is_none());
    }

    #[test]
    fn sse_aggregation_handles_reasoning_content_and_missing_usage() {
        let sse = concat!(
            "data: {\"id\":\"c2\",\"created\":99,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"think \"},\"finish_reason\":null}]}\n",
            "data: {\"id\":\"c2\",\"created\":99,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"hard\",\"content\":\"answer\"},\"finish_reason\":null}]}\n",
            "data: {\"id\":\"c2\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"length\"}]}\n",
            "data: [DONE]\n"
        );
        let out = aggregate_sse_to_completion(sse.as_bytes(), "public").unwrap();
        assert_eq!(out["choices"][0]["message"]["content"], "answer");
        assert_eq!(
            out["choices"][0]["message"]["reasoning_content"],
            "think hard"
        );
        assert_eq!(out["choices"][0]["finish_reason"], "length");
        assert!(
            out.get("usage").is_none(),
            "no usage chunk -> no usage field"
        );
    }

    #[test]
    fn sse_aggregation_finish_reason_comes_from_the_last_chunk_that_has_one() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"},\"finish_reason\":\"stop\"}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"length\"}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":null}]}\n"
        );
        let out = aggregate_sse_to_completion(sse.as_bytes(), "m").unwrap();
        assert_eq!(out["choices"][0]["finish_reason"], "length");
    }

    #[test]
    fn sse_aggregation_folds_tool_call_deltas_into_message_tool_calls() {
        // Streaming tool-call rounds split one call across many delta chunks; the folded
        // completion must reconstruct id/name and concatenate the arguments string.
        let sse = concat!(
            "data: {\"id\":\"c3\",\"created\":99,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n",
            "data: {\"id\":\"c3\",\"created\":99,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"{\\\"ci\"}}]},\"finish_reason\":null}]}\n",
            "data: {\"id\":\"c3\",\"created\":99,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"ty\\\":\\\"Hanoi\\\"}\"}},{\"index\":1,\"id\":\"call_2\",\"type\":\"function\",\"function\":{\"name\":\"ping\",\"arguments\":\"{}\"}}]},\"finish_reason\":null}]}\n",
            "data: {\"id\":\"c3\",\"created\":99,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n",
            "data: [DONE]\n"
        );
        let out = aggregate_sse_to_completion(sse.as_bytes(), "public").unwrap();
        let message = &out["choices"][0]["message"];
        assert_eq!(message["content"], serde_json::Value::Null);
        let calls = message["tool_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["id"], "call_1");
        assert_eq!(calls[0]["function"]["name"], "get_weather");
        assert_eq!(
            calls[0]["function"]["arguments"], "{\"city\":\"Hanoi\"}",
            "arguments concatenate across chunks"
        );
        assert_eq!(calls[1]["id"], "call_2");
        assert_eq!(calls[1]["function"]["name"], "ping");
        assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");
    }

    #[test]
    fn sse_aggregation_rejects_garbage() {
        assert!(aggregate_sse_to_completion(b"", "m").is_none());
        assert!(aggregate_sse_to_completion(b"not sse at all", "m").is_none());
        assert!(
            aggregate_sse_to_completion(b"data: [DONE]\n\n", "m").is_none(),
            "[DONE] alone carries no chunk"
        );
    }

    #[test]
    fn free_route_detection_covers_only_the_chat_lane() {
        use crate::contract::ProviderProtocol as P;
        assert!(is_free_chat_route("opencode_free", P::OpenAiChat, false));
        assert!(is_free_chat_route(
            "OPENCODE_FREE",
            P::CustomOpenAiChat,
            false
        ));
        assert!(!is_free_chat_route("opencode_free", P::OpenAiChat, true));
        assert!(!is_free_chat_route(
            "opencode_free",
            P::OpenAiResponses,
            false
        ));
        assert!(!is_free_chat_route("bearer", P::OpenAiChat, false));
    }
}
