//! Admin API for "combos" — the one-call Model Group.
//!
//! A combo is a public model name plus an ORDERED list of members
//! (`[{backend_id, model, weight?}]`). One `POST /admin/combos` expands it into the existing
//! route + group-endpoints machinery with every wiring detail DERIVED:
//!
//! * client dialect is always OpenAI Chat (`openai_chat` route protocol) — the proxy already
//!   translates chat <-> responses in both directions, so cross-family members
//!   (codex_responses / openai_responses providers) just work;
//! * per-endpoint `protocol`/`auth_mode` come from the member backend's registry-derived
//!   values (`backends.provider_type`), defaulting to `openai_chat`/`bearer` for legacy
//!   backends, with an optional explicit per-member override;
//! * per-endpoint `provider_key_ref` is the backend's `api_key_ref` only when it is an
//!   `oauth:` reference (per-account OAuth); static keys keep resolving through the backend;
//! * `weight` is the explicit member weight, else derived from position: 8, 4, 2, 1, 1, ...
//!
//! The operator never picks protocols, auth modes, or routing policies. Member order is
//! persisted verbatim in `model_routes.combo_members` (JSONB array): endpoint rows are keyed
//! by `(model_name, backend_id)` and carry no position, so the JSONB order is the single
//! source of truth for listing order and the derived weight sequence.
//!
//! Upsert semantics: re-POSTing a combo name replaces its members (endpoints +
//! `combo_members` + `backend_ids`) but keeps the enabled flag — the dedicated
//! `PATCH /admin/combos/{name}/enabled` endpoint owns on/off state. A name that exists as a
//! NON-combo (manual) route is never hijacked: 409.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json,
    extract::{ConnectInfo, Extension, Path},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, patch},
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::postgres::PgPool;

use crate::contract::ProviderProtocol;
use crate::provider_auth;
use crate::provider_registry;

use super::{
    AdminState, ApiError, ToggleEnabled, ValidatedRouteEndpoint, check_admin_auth,
    enable_referenced_backends, endpoint_family_allowed, non_empty_trimmed, parse_backend_ids,
    replace_route_endpoints,
};

/// The protocol every combo route speaks on the client side. Cross-family members are
/// translated by the proxy; this is why combos can mix providers freely.
const COMBO_ROUTE_PROTOCOL: &str = "openai_chat";

/// Route-level auth mode for combos. Inert: every member endpoint carries its own derived
/// `auth_mode`, and a combo route never has a route-level credential.
const COMBO_ROUTE_AUTH_MODE: &str = "bearer";

/// Load-balancing policy a combo expands to. Member order + weights drive the sequence.
const COMBO_ROUTING_POLICY: &str = "weighted_round_robin";

/// Per-endpoint concurrency cap a combo expands to.
const COMBO_ENDPOINT_MAX_INFLIGHT: u32 = 4;

// ===== Payload + persisted shapes =====

/// One member exactly as the operator defined it. This struct is also what gets stored in
/// `model_routes.combo_members`, verbatim and in order — the lossless listing source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ComboMember {
    backend_id: i64,
    /// Provider model name to send to this member's backend.
    model: String,
    /// Explicit weight override. Omitted = weight derived from member position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    weight: Option<u32>,
    /// Optional endpoint overrides, mainly for legacy backends the registry cannot derive
    /// wiring for. Validated against the same taxonomies the routes endpoint uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_mode: Option<String>,
}

#[derive(Deserialize)]
struct CreateCombo {
    name: String,
    members: Vec<ComboMember>,
}

#[derive(Serialize, Debug)]
struct ComboResponse {
    name: String,
    enabled: bool,
    /// Members in DEFINITION order (from `combo_members`), not backend_id order.
    members: Vec<ComboMemberResponse>,
}

#[derive(Serialize, Debug)]
struct ComboMemberResponse {
    backend_id: i64,
    backend_name: String,
    model: String,
    protocol: String,
    auth_mode: String,
    weight: u32,
    enabled: bool,
}

// ===== Expansion (pure, unit-testable) =====

/// The backend columns the expansion needs.
#[derive(Debug, Clone)]
struct ComboBackend {
    id: i64,
    name: String,
    enabled: bool,
    api_key_ref: String,
    provider_type: Option<String>,
}

/// One fully derived group endpoint for a combo member.
#[derive(Debug, Clone, PartialEq)]
struct ExpandedComboEndpoint {
    backend_id: i64,
    backend_name: String,
    provider_model_name: String,
    provider_key_ref: Option<String>,
    protocol: String,
    auth_mode: String,
    weight: u32,
    max_inflight: u32,
    enabled: bool,
}

/// Weight by member position: 8, 4, 2, then floor 1. An explicit member weight wins.
fn combo_weight_at(index: usize, explicit: Option<u32>) -> u32 {
    let derived = match index {
        0 => 8,
        1 => 4,
        2 => 2,
        _ => 1,
    };
    explicit.unwrap_or(derived).max(1)
}

/// Expand an ordered member list into fully derived endpoints. Every 400 the combos endpoint
/// can return originates here, so the rules are testable without a database.
fn expand_combo_members(
    members: &[ComboMember],
    backends: &HashMap<i64, ComboBackend>,
) -> Result<Vec<ExpandedComboEndpoint>, ApiError> {
    if members.is_empty() {
        return Err(ApiError::bad_request("members must not be empty"));
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(members.len());
    for (index, member) in members.iter().enumerate() {
        let backend = backends.get(&member.backend_id).ok_or_else(|| {
            ApiError::bad_request(format!(
                "unknown backend_id {}; create it first via POST /admin/backends",
                member.backend_id
            ))
        })?;
        if !backend.enabled {
            return Err(ApiError::bad_request(format!(
                "backend {} ({}) is disabled; enable it before adding it to a combo",
                backend.id, backend.name
            )));
        }
        if !seen.insert(member.backend_id) {
            return Err(ApiError::bad_request(format!(
                "backend_id {} appears in two members: combo endpoints are keyed by \
                 backend_id — put each provider account on its own backend (this is how the \
                 Codex account pool works)",
                member.backend_id
            )));
        }
        let model = member.model.trim();
        if model.is_empty() {
            return Err(ApiError::bad_request(format!(
                "member model for backend {} must not be empty",
                member.backend_id
            )));
        }

        // Registry-derived wiring when the backend has a known provider_type; plain defaults
        // otherwise. An explicit member override always wins (escape hatch for endpoints the
        // registry cannot describe).
        let entry = backend
            .provider_type
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(provider_registry::lookup);
        let default_protocol = entry
            .map(|e| e.protocol.to_string())
            .unwrap_or_else(|| ProviderProtocol::OpenAiChat.as_str().to_string());
        let default_auth = entry
            .map(|e| e.auth_mode.to_string())
            .unwrap_or_else(|| "bearer".to_string());
        let protocol = match member
            .protocol
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(p) => ProviderProtocol::parse(p).as_str().to_string(),
            None => default_protocol,
        };
        let auth_mode = match member
            .auth_mode
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(a) => provider_auth::parse_auth_mode(a)
                .map(str::to_string)
                .ok_or_else(|| {
                    ApiError::bad_request(format!(
                        "member auth_mode must be one of {}, got: {a}",
                        provider_auth::AUTH_MODES.join(", ")
                    ))
                })?,
            None => default_auth,
        };
        if provider_auth::is_opencode_free_mode(&auth_mode) {
            return Err(ApiError::bad_request(
                "member auth_mode opencode_free is not supported in combos: the free tier is \
                 a backend format marker, not an endpoint auth mode — create an \
                 opencode-free backend instead",
            ));
        }
        // Same cross-family guard the routes endpoint applies: the combo's client dialect is
        // openai_chat, so only chat-family and responses-family members can ride it.
        if !endpoint_family_allowed(COMBO_ROUTE_PROTOCOL, &protocol) {
            return Err(ApiError::bad_request(format!(
                "member protocol {protocol} for backend {} is not compatible with the combo \
                 client dialect {COMBO_ROUTE_PROTOCOL}: only the chat <-> responses pair is \
                 translated today",
                member.backend_id
            )));
        }

        // OAuth references name one connected account per endpoint (the Codex account pool);
        // every other credential keeps resolving through the backend's own key.
        let provider_key_ref = backend
            .api_key_ref
            .trim()
            .starts_with("oauth:")
            .then(|| backend.api_key_ref.trim().to_string());

        out.push(ExpandedComboEndpoint {
            backend_id: backend.id,
            backend_name: backend.name.clone(),
            provider_model_name: model.to_string(),
            provider_key_ref,
            protocol,
            auth_mode,
            weight: combo_weight_at(index, member.weight),
            max_inflight: COMBO_ENDPOINT_MAX_INFLIGHT,
            enabled: true,
        });
    }
    Ok(out)
}

async fn fetch_combo_backends(
    pool: &PgPool,
    ids: &[i64],
) -> Result<HashMap<i64, ComboBackend>, ApiError> {
    let rows = sqlx::query::<sqlx::Postgres>(
        "SELECT id, name, enabled, api_key_ref, provider_type FROM backends WHERE id = ANY($1)",
    )
    .bind(ids.to_vec())
    .fetch_all(pool)
    .await?;
    let mut out = HashMap::with_capacity(rows.len());
    for row in rows {
        let id: i64 = row.try_get("id")?;
        out.insert(
            id,
            ComboBackend {
                id,
                name: row.try_get("name")?,
                enabled: row.try_get("enabled")?,
                api_key_ref: row.try_get("api_key_ref")?,
                provider_type: row
                    .try_get::<Option<String>, _>("provider_type")?
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
            },
        );
    }
    Ok(out)
}

// ===== POST /admin/combos — create or replace members =====

#[derive(Debug)]
struct PersistedCombo {
    response: ComboResponse,
    /// true = row inserted, false = existing combo updated.
    created: bool,
}

/// Validate, derive, and persist a combo. Pure validation + the same writer path the routes
/// endpoint uses (`replace_route_endpoints`), so a combo row and a manual Model Group row are
/// indistinguishable to the config loader and the proxy.
async fn persist_combo(pool: &PgPool, payload: CreateCombo) -> Result<PersistedCombo, ApiError> {
    let name = non_empty_trimmed(payload.name, "name")?;
    let ids: Vec<i64> = payload.members.iter().map(|m| m.backend_id).collect();
    let backends = fetch_combo_backends(pool, &ids).await?;
    let endpoints = expand_combo_members(&payload.members, &backends)?;

    let members_json = serde_json::to_string(&payload.members)?;
    let backend_ids: Vec<i64> = endpoints.iter().map(|e| e.backend_id).collect();
    let backend_ids_json = serde_json::to_string(&backend_ids)?;

    let existing = sqlx::query::<sqlx::Postgres>(
        "SELECT is_combo, enabled FROM model_routes WHERE model_name = $1",
    )
    .bind(&name)
    .fetch_optional(pool)
    .await?;
    let (created, enabled) = match existing {
        // Never hijack a manually configured route — the operator would lose its endpoints.
        Some(row) if !row.try_get::<bool, _>("is_combo")? => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                format!(
                    "model name '{name}' already exists as a manually configured route; \
                     combos never overwrite manual routes — delete the route first or pick \
                     another combo name"
                ),
            ));
        }
        Some(row) => (false, row.try_get::<bool, _>("enabled")?),
        None => (true, true),
    };

    if created {
        sqlx::query::<sqlx::Postgres>(
            "INSERT INTO model_routes \
             (model_name, backend_ids, fallback_backend_id, chars_per_token, first_byte_timeout, \
              provider_model_name, context_tokens, max_output_tokens, enabled, provider_key_ref, \
              auth_mode, protocol, routing_policy, passthrough, is_combo, combo_members) \
             VALUES ($1, $2, NULL, 4.0, 180, $1, NULL, NULL, TRUE, NULL, $3, $4, $5, FALSE, TRUE, $6::jsonb)",
        )
        .bind(&name)
        .bind(&backend_ids_json)
        .bind(COMBO_ROUTE_AUTH_MODE)
        .bind(COMBO_ROUTE_PROTOCOL)
        .bind(COMBO_ROUTING_POLICY)
        .bind(&members_json)
        .execute(pool)
        .await?;
    } else {
        // Upsert replaces the member list; `enabled` stays owned by the toggle endpoint —
        // re-posting a definition must not silently resurrect a disabled combo.
        sqlx::query::<sqlx::Postgres>(
            "UPDATE model_routes SET backend_ids = $2, fallback_backend_id = NULL, \
             chars_per_token = 4.0, first_byte_timeout = 180, provider_model_name = $3, \
             context_tokens = NULL, max_output_tokens = NULL, provider_key_ref = NULL, \
             auth_mode = $4, protocol = $5, routing_policy = $6, passthrough = FALSE, \
             is_combo = TRUE, combo_members = $7::jsonb WHERE model_name = $1",
        )
        .bind(&name)
        .bind(&backend_ids_json)
        .bind(&name)
        .bind(COMBO_ROUTE_AUTH_MODE)
        .bind(COMBO_ROUTE_PROTOCOL)
        .bind(COMBO_ROUTING_POLICY)
        .bind(&members_json)
        .execute(pool)
        .await?;
    }
    replace_route_endpoints(
        pool,
        &name,
        Some(
            &endpoints
                .iter()
                .map(|e| ValidatedRouteEndpoint {
                    backend_id: e.backend_id,
                    provider_model_name: e.provider_model_name.clone(),
                    provider_key_ref: e.provider_key_ref.clone(),
                    auth_mode: e.auth_mode.clone(),
                    protocol: e.protocol.clone(),
                    weight: e.weight,
                    max_inflight: e.max_inflight,
                    enabled: e.enabled,
                })
                .collect::<Vec<_>>(),
        ),
    )
    .await?;

    Ok(PersistedCombo {
        response: ComboResponse {
            name,
            enabled,
            members: endpoints
                .iter()
                .map(|e| ComboMemberResponse {
                    backend_id: e.backend_id,
                    backend_name: e.backend_name.clone(),
                    model: e.provider_model_name.clone(),
                    protocol: e.protocol.clone(),
                    auth_mode: e.auth_mode.clone(),
                    weight: e.weight,
                    enabled: e.enabled,
                })
                .collect(),
        },
        created,
    })
}

async fn create_combo(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CreateCombo>,
) -> Result<Response, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    let out = persist_combo(pool, payload).await?;
    state.reload_now().await?;
    let status = if out.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(out.response)).into_response())
}

// ===== GET /admin/combos =====

async fn list_combos(pool: &PgPool) -> Result<Vec<ComboResponse>, ApiError> {
    let rows = sqlx::query::<sqlx::Postgres>(
        "SELECT model_name, enabled, combo_members::text AS combo_members \
         FROM model_routes WHERE is_combo ORDER BY model_name",
    )
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let names: Vec<String> = rows
        .iter()
        .map(|r| r.try_get::<String, _>("model_name"))
        .collect::<Result<_, sqlx::Error>>()?;

    let backend_rows = sqlx::query::<sqlx::Postgres>("SELECT id, name FROM backends")
        .fetch_all(pool)
        .await?;
    let backend_names: HashMap<i64, String> = backend_rows
        .iter()
        .map(|r| Ok((r.try_get::<i64, _>("id")?, r.try_get::<String, _>("name")?)))
        .collect::<Result<_, sqlx::Error>>()?;

    // Effective wiring lives on the endpoint rows; the JSONB array only supplies the order.
    let endpoint_rows = sqlx::query::<sqlx::Postgres>(
        "SELECT model_name, backend_id, protocol, auth_mode, weight, enabled \
         FROM model_route_endpoints WHERE model_name = ANY($1)",
    )
    .bind(names)
    .fetch_all(pool)
    .await?;
    let mut endpoint_wiring: HashMap<(String, i64), (String, String, u32, bool)> =
        HashMap::with_capacity(endpoint_rows.len());
    for row in endpoint_rows {
        let weight: i64 = row.try_get("weight")?;
        endpoint_wiring.insert(
            (
                row.try_get::<String, _>("model_name")?,
                row.try_get::<i64, _>("backend_id")?,
            ),
            (
                row.try_get("protocol")?,
                row.try_get("auth_mode")?,
                u32::try_from(weight.max(1)).unwrap_or(1),
                row.try_get("enabled")?,
            ),
        );
    }

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let name: String = row.try_get("model_name")?;
        let enabled: bool = row.try_get("enabled")?;
        let members_json: Option<String> = row.try_get("combo_members")?;
        let members: Vec<ComboMember> = members_json
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let members = members
            .iter()
            .enumerate()
            .map(|(index, member)| {
                let (protocol, auth_mode, weight, endpoint_enabled) = endpoint_wiring
                    .get(&(name.clone(), member.backend_id))
                    .cloned()
                    // Endpoint row missing (hand-edited DB): fall back to the derived weight
                    // so the listing still shows the definition faithfully.
                    .unwrap_or_else(|| {
                        (
                            COMBO_ROUTE_PROTOCOL.to_string(),
                            COMBO_ROUTE_AUTH_MODE.to_string(),
                            combo_weight_at(index, member.weight),
                            true,
                        )
                    });
                ComboMemberResponse {
                    backend_id: member.backend_id,
                    backend_name: backend_names
                        .get(&member.backend_id)
                        .cloned()
                        .unwrap_or_default(),
                    model: member.model.trim().to_string(),
                    protocol,
                    auth_mode,
                    weight,
                    enabled: endpoint_enabled,
                }
            })
            .collect();
        out.push(ComboResponse {
            name,
            enabled,
            members,
        });
    }
    Ok(out)
}

async fn list_combos_handler(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Vec<ComboResponse>>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    Ok(Json(list_combos(pool).await?))
}

// ===== DELETE /admin/combos/{name} =====

/// Same semantics as the routes delete: usage history blocks deletion (the client-facing name
/// must keep answering with the same identity), so the operator disables instead. 404 for
/// anything that is not a combo — the combos endpoint must never remove a manual route.
async fn delete_combo_in_pool(pool: &PgPool, name: &str) -> Result<StatusCode, ApiError> {
    let row =
        sqlx::query::<sqlx::Postgres>("SELECT is_combo FROM model_routes WHERE model_name = $1")
            .bind(name)
            .fetch_optional(pool)
            .await?;
    match row {
        None => Err(ApiError::not_found("combo not found")),
        Some(row) if !row.try_get::<bool, _>("is_combo")? => Err(ApiError::not_found(format!(
            "route '{name}' is not a combo; use DELETE /admin/routes/{name}"
        ))),
        Some(_) => Ok(()),
    }?;
    let usage: i64 =
        sqlx::query::<sqlx::Postgres>("SELECT COUNT(*) AS c FROM usage_ledger WHERE model = $1")
            .bind(name)
            .fetch_one(pool)
            .await?
            .try_get("c")?;
    if usage > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!(
                "combo '{name}' has transaction history; disable it instead \
                 (PATCH /admin/combos/{name}/enabled)"
            ),
        ));
    }
    // ON DELETE CASCADE removes the endpoint rows.
    let result = sqlx::query::<sqlx::Postgres>(
        "DELETE FROM model_routes WHERE model_name = $1 AND is_combo",
    )
    .bind(name)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("combo not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_combo(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    let status = delete_combo_in_pool(pool, &name).await?;
    state.reload_now().await?;
    Ok(status)
}

// ===== PATCH /admin/combos/{name}/enabled =====

/// Toggle without re-sending the payload — the same update the routes toggle performs,
/// guarded by `is_combo` so a manual route can never be flipped through the combos path.
async fn toggle_combo_enabled(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(payload): Json<ToggleEnabled>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    let row =
        sqlx::query::<sqlx::Postgres>("SELECT is_combo FROM model_routes WHERE model_name = $1")
            .bind(&name)
            .fetch_optional(pool)
            .await?;
    match row {
        None => return Err(ApiError::not_found("combo not found")),
        Some(row) if !row.try_get::<bool, _>("is_combo")? => {
            return Err(ApiError::not_found(format!(
                "route '{name}' is not a combo; use PATCH /admin/routes/{name}/enabled"
            )));
        }
        Some(_) => {}
    }
    let result =
        sqlx::query::<sqlx::Postgres>("UPDATE model_routes SET enabled = $1 WHERE model_name = $2")
            .bind(payload.enabled)
            .bind(&name)
            .execute(pool)
            .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("combo not found"));
    }
    // Mirrors the routes toggle: turning a group on activates the provider endpoints it
    // references (seed templates ship disabled).
    if payload.enabled {
        let row = sqlx::query::<sqlx::Postgres>(
            "SELECT backend_ids, fallback_backend_id FROM model_routes WHERE model_name = $1",
        )
        .bind(&name)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ApiError::not_found("combo not found"))?;
        let backend_ids_json: String = row.try_get("backend_ids")?;
        let backend_ids = parse_backend_ids(&backend_ids_json)?;
        let fallback: Option<i64> = row.try_get("fallback_backend_id")?;
        enable_referenced_backends(pool, &backend_ids, fallback).await?;
    }
    state.reload_now().await?;
    Ok(Json(
        serde_json::json!({ "name": name, "enabled": payload.enabled }),
    ))
}

// ===== Sub-router =====

/// Sub-router so `admin::router` keeps one readable route list, matching `oauth_api`/`quota_api`.
pub fn routes() -> axum::Router {
    axum::Router::new()
        .route("/combos", get(list_combos_handler).post(create_combo))
        .route("/combos/{name}", delete(delete_combo))
        .route("/combos/{name}/enabled", patch(toggle_combo_enabled))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(
        id: i64,
        name: &str,
        enabled: bool,
        api_key_ref: &str,
        provider_type: Option<&str>,
    ) -> ComboBackend {
        ComboBackend {
            id,
            name: name.to_string(),
            enabled,
            api_key_ref: api_key_ref.to_string(),
            provider_type: provider_type.map(str::to_string),
        }
    }

    fn member(backend_id: i64, model: &str) -> ComboMember {
        ComboMember {
            backend_id,
            model: model.to_string(),
            weight: None,
            protocol: None,
            auth_mode: None,
        }
    }

    fn combo_backends() -> HashMap<i64, ComboBackend> {
        let all = [
            // OAuth account pool: registry-derived codex_responses + chatgpt_oauth, and the
            // per-account oauth: ref must ride the endpoint.
            backend(
                7,
                "codex-pro",
                true,
                "oauth:codex:acct-a",
                Some("codex-oauth"),
            ),
            // API-key provider: registry-derived openai_chat + bearer; the static key keeps
            // resolving through the backend, so the endpoint carries no ref.
            backend(2, "zai-main", true, "env:ZAI_API_KEY", Some("zai")),
            // Legacy backend (no registry row): defaults + explicit override.
            backend(9, "legacy-local", true, "file:/secrets/legacy.key", None),
            backend(
                11,
                "grok-oauth",
                true,
                "oauth:xai-oauth:default",
                Some("xai-grok-oauth"),
            ),
            backend(12, "disabled-one", false, "env:OFF", Some("deepseek")),
        ];
        all.into_iter().map(|b| (b.id, b)).collect()
    }

    #[test]
    fn weights_follow_member_order_with_explicit_override() {
        // First 8, then 4, 2, floor 1; an explicit weight always wins.
        assert_eq!(combo_weight_at(0, None), 8);
        assert_eq!(combo_weight_at(1, None), 4);
        assert_eq!(combo_weight_at(2, None), 2);
        assert_eq!(combo_weight_at(3, None), 1);
        assert_eq!(combo_weight_at(9, None), 1);
        assert_eq!(combo_weight_at(0, Some(3)), 3);
        assert_eq!(combo_weight_at(4, Some(5)), 5);
        // A zero weight cannot disable a member by accident.
        assert_eq!(combo_weight_at(0, Some(0)), 1);
    }

    #[test]
    fn expansion_derives_endpoint_wiring_per_member() {
        let mut members = vec![
            member(7, "gpt-6.1-sol"),
            member(2, "glm-5.3"),
            ComboMember {
                protocol: Some("custom_openai_chat".to_string()),
                auth_mode: Some("none".to_string()),
                ..member(9, "qwen3.8-flash-next")
            },
            member(11, "grok-code-fast-1"),
        ];
        members[1].weight = Some(5);

        let endpoints = expand_combo_members(&members, &combo_backends()).expect("expansion");

        assert_eq!(endpoints.len(), 4);
        // Member order is preserved end to end.
        let ids: Vec<i64> = endpoints.iter().map(|e| e.backend_id).collect();
        assert_eq!(ids, vec![7, 2, 9, 11]);

        // Registry-derived OAuth member: codex wiring + per-account ref.
        assert_eq!(endpoints[0].protocol, "codex_responses");
        assert_eq!(endpoints[0].auth_mode, "chatgpt_oauth");
        assert_eq!(
            endpoints[0].provider_key_ref.as_deref(),
            Some("oauth:codex:acct-a")
        );
        assert_eq!(endpoints[0].provider_model_name, "gpt-6.1-sol");
        assert_eq!(endpoints[0].weight, 8);
        assert_eq!(endpoints[0].max_inflight, 4);
        assert!(endpoints[0].enabled);

        // Registry-derived API-key member with an explicit weight.
        assert_eq!(endpoints[1].protocol, "openai_chat");
        assert_eq!(endpoints[1].auth_mode, "bearer");
        assert_eq!(endpoints[1].provider_key_ref, None);
        assert_eq!(endpoints[1].weight, 5);

        // Legacy member: defaults overridden explicitly, static key stays on the backend.
        assert_eq!(endpoints[2].protocol, "custom_openai_chat");
        assert_eq!(endpoints[2].auth_mode, "none");
        assert_eq!(endpoints[2].provider_key_ref, None);
        assert_eq!(endpoints[2].weight, 2);

        // Cross-family OAuth member rides the translated responses path.
        assert_eq!(endpoints[3].protocol, "openai_responses");
        assert_eq!(endpoints[3].auth_mode, "xai_oauth");
        assert_eq!(
            endpoints[3].provider_key_ref.as_deref(),
            Some("oauth:xai-oauth:default")
        );
        assert_eq!(endpoints[3].weight, 1);
    }

    #[test]
    fn expansion_rejects_empty_members_unknown_disabled_duplicate_and_blank_model() {
        let backends = combo_backends();

        let err = expand_combo_members(&[], &backends).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("members must not be empty"));

        let err = expand_combo_members(&[member(99, "nope")], &backends).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("unknown backend_id 99"));

        // Two accounts on one backend cannot be expressed: endpoints are keyed by backend_id.
        let err =
            expand_combo_members(&[member(2, "glm-5.3"), member(2, "glm-5.3-air")], &backends)
                .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("keyed by backend_id"));
        assert!(err.message.contains("own backend"));

        let err = expand_combo_members(&[member(12, "deepseek-chat")], &backends).unwrap_err();
        assert!(err.message.contains("disabled"));

        let err = expand_combo_members(&[member(2, "   ")], &backends).unwrap_err();
        assert!(err.message.contains("must not be empty"));

        // An override the combo dialect cannot translate is rejected with the same reason the
        // routes endpoint gives.
        let anthropic = ComboMember {
            protocol: Some("anthropic_messages".to_string()),
            ..member(9, "claude")
        };
        let err = expand_combo_members(&[anthropic], &backends).unwrap_err();
        assert!(err.message.contains("not compatible"));

        let bad_auth = ComboMember {
            auth_mode: Some("magic".to_string()),
            ..member(9, "local")
        };
        let err = expand_combo_members(&[bad_auth], &backends).unwrap_err();
        assert!(err.message.contains("auth_mode must be one of"));

        // The free tier is a backend format marker; persisting it as an endpoint auth mode
        // would trip the endpoints CHECK, so it must fail validation with a clear reason.
        let free = ComboMember {
            auth_mode: Some("opencode_free".to_string()),
            ..member(9, "local")
        };
        let err = expand_combo_members(&[free], &backends).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("opencode-free backend"));
    }

    async fn insert_combo_backend(
        pool: &PgPool,
        id: i64,
        name: &str,
        api_key_ref: &str,
        provider_type: Option<&str>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO backends (id, name, base_url, api_key_ref, weight, max_inflight, format, enabled, provider_type) \
             VALUES ($1, $2, 'https://backend.example.com', $3, 1, 100, 'openai', TRUE, $4)",
        )
        .bind(id)
        .bind(name)
        .bind(api_key_ref)
        .bind(provider_type)
        .execute(pool)
        .await?;
        Ok(())
    }

    fn combo_payload(name: &str, members: Vec<ComboMember>) -> CreateCombo {
        CreateCombo {
            name: name.to_string(),
            members,
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn create_combo_persists_route_endpoints_and_definition_order(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        insert_combo_backend(
            &pool,
            7,
            "codex-pro",
            "oauth:codex:acct-a",
            Some("codex-oauth"),
        )
        .await?;
        insert_combo_backend(&pool, 2, "zai-main", "env:ZAI_API_KEY", Some("zai")).await?;
        insert_combo_backend(&pool, 9, "legacy-local", "file:/secrets/legacy.key", None).await?;
        insert_combo_backend(
            &pool,
            11,
            "grok-oauth",
            "oauth:xai-oauth:default",
            Some("xai-grok-oauth"),
        )
        .await?;

        let out = persist_combo(
            &pool,
            combo_payload(
                "zn-glm",
                vec![
                    member(7, "gpt-6.1-sol"),
                    member(2, "glm-5.3"),
                    ComboMember {
                        weight: Some(2),
                        ..member(9, "qwen3.8-flash-next")
                    },
                    member(11, "grok-code-fast-1"),
                ],
            ),
        )
        .await
        .expect("combo created");
        assert!(out.created);
        assert_eq!(out.response.name, "zn-glm");
        assert!(out.response.enabled);
        let order: Vec<i64> = out.response.members.iter().map(|m| m.backend_id).collect();
        assert_eq!(order, vec![7, 2, 9, 11]);
        assert_eq!(
            out.response.members[0].protocol, "codex_responses",
            "registry wiring must reach the response"
        );

        // Route row: combo flags + fixed expansion constants.
        let row = sqlx::query::<sqlx::Postgres>(
            "SELECT backend_ids, chars_per_token, first_byte_timeout, enabled, provider_key_ref, \
             auth_mode, protocol, routing_policy, passthrough, is_combo, combo_members::text AS members \
             FROM model_routes WHERE model_name = 'zn-glm'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(
            row.try_get::<String, _>("backend_ids")?,
            "[7,2,9,11]",
            "backend_ids keeps definition order"
        );
        assert_eq!(row.try_get::<f64, _>("chars_per_token")?, 4.0);
        assert_eq!(row.try_get::<i64, _>("first_byte_timeout")?, 180);
        assert!(row.try_get::<bool, _>("enabled")?);
        assert_eq!(row.try_get::<Option<String>, _>("provider_key_ref")?, None);
        assert_eq!(row.try_get::<String, _>("auth_mode")?, "bearer");
        assert_eq!(row.try_get::<String, _>("protocol")?, "openai_chat");
        assert_eq!(
            row.try_get::<String, _>("routing_policy")?,
            "weighted_round_robin"
        );
        assert!(!row.try_get::<bool, _>("passthrough")?);
        assert!(row.try_get::<bool, _>("is_combo")?);
        let members: serde_json::Value =
            serde_json::from_str(&row.try_get::<String, _>("members")?).unwrap();
        assert_eq!(
            members
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["backend_id"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            vec![7, 2, 9, 11],
            "combo_members stores the definition verbatim and in order"
        );

        // Endpoint rows: one per member, wiring derived per backend, weights by order.
        let rows = sqlx::query::<sqlx::Postgres>(
            "SELECT backend_id, provider_model_name, provider_key_ref, auth_mode, protocol, weight, max_inflight, enabled \
             FROM model_route_endpoints WHERE model_name = 'zn-glm'",
        )
        .fetch_all(&pool)
        .await?;
        let by_backend: HashMap<i64, &sqlx::postgres::PgRow> = rows
            .iter()
            .map(|r| (r.try_get::<i64, _>("backend_id").unwrap(), r))
            .collect();
        let expect = |id: i64,
                      model: &str,
                      key_ref: Option<&str>,
                      auth: &str,
                      protocol: &str,
                      weight: i64| {
            let row = *by_backend.get(&id).unwrap();
            assert_eq!(
                row.try_get::<String, _>("provider_model_name").unwrap(),
                model
            );
            assert_eq!(
                row.try_get::<Option<String>, _>("provider_key_ref")
                    .unwrap(),
                key_ref.map(str::to_string)
            );
            assert_eq!(row.try_get::<String, _>("auth_mode").unwrap(), auth);
            assert_eq!(row.try_get::<String, _>("protocol").unwrap(), protocol);
            assert_eq!(row.try_get::<i64, _>("weight").unwrap(), weight);
            assert_eq!(row.try_get::<i64, _>("max_inflight").unwrap(), 4);
            assert!(row.try_get::<bool, _>("enabled").unwrap());
        };
        assert_eq!(by_backend.len(), 4);
        expect(
            7,
            "gpt-6.1-sol",
            Some("oauth:codex:acct-a"),
            "chatgpt_oauth",
            "codex_responses",
            8,
        );
        expect(2, "glm-5.3", None, "bearer", "openai_chat", 4);
        expect(9, "qwen3.8-flash-next", None, "bearer", "openai_chat", 2);
        expect(
            11,
            "grok-code-fast-1",
            Some("oauth:xai-oauth:default"),
            "xai_oauth",
            "openai_responses",
            1,
        );

        // The config loader serves the combo exactly like a manual Model Group.
        let loader = crate::config::DbConfigLoader::new(pool.clone(), 0);
        let snap = loader.load_snapshot().await.expect("snapshot");
        let route = snap.routes.get("zn-glm").expect("combo route loads");
        assert_eq!(route.protocol, "openai_chat");
        assert_eq!(route.routing_policy.as_str(), "weighted_round_robin");
        assert_eq!(route.endpoints.len(), 4);
        assert_eq!(route.endpoint_weight(7), 8);
        assert_eq!(route.endpoint_weight(2), 4);
        assert_eq!(route.endpoint_weight(9), 2);
        assert_eq!(route.endpoint_weight(11), 1);
        Ok(())
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn listing_roundtrips_definition_order_and_member_details(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        insert_combo_backend(
            &pool,
            7,
            "codex-pro",
            "oauth:codex:acct-a",
            Some("codex-oauth"),
        )
        .await?;
        insert_combo_backend(&pool, 2, "zai-main", "env:ZAI_API_KEY", Some("zai")).await?;
        // Backend ids intentionally not in the same order as the members: the JSONB order
        // must win, because endpoint rows carry no position.
        persist_combo(
            &pool,
            combo_payload(
                "combo-b",
                vec![member(7, "gpt-6.1-sol"), member(2, "glm-5.3")],
            ),
        )
        .await
        .expect("create b");
        persist_combo(
            &pool,
            combo_payload(
                "combo-a",
                vec![member(2, "glm-5.3"), member(7, "gpt-6.1-sol")],
            ),
        )
        .await
        .expect("create a");

        let combos = list_combos(&pool).await.expect("list");
        assert_eq!(combos.len(), 2);
        // Sorted by name, but members keep their own definition order.
        assert_eq!(combos[0].name, "combo-a");
        let ids: Vec<i64> = combos[0].members.iter().map(|m| m.backend_id).collect();
        assert_eq!(ids, vec![2, 7]);
        assert_eq!(combos[0].members[0].backend_name, "zai-main");
        assert_eq!(combos[0].members[0].model, "glm-5.3");
        assert_eq!(combos[0].members[0].protocol, "openai_chat");
        assert_eq!(combos[0].members[0].auth_mode, "bearer");
        assert_eq!(combos[0].members[0].weight, 8);
        assert!(combos[0].members[0].enabled);
        assert_eq!(combos[0].members[1].backend_name, "codex-pro");
        assert_eq!(combos[0].members[1].protocol, "codex_responses");
        assert_eq!(combos[0].members[1].auth_mode, "chatgpt_oauth");
        assert_eq!(combos[0].members[1].weight, 4);

        let ids: Vec<i64> = combos[1].members.iter().map(|m| m.backend_id).collect();
        assert_eq!(ids, vec![7, 2]);
        assert_eq!(combos[1].members[0].weight, 8);
        assert_eq!(combos[1].members[1].weight, 4);
        Ok(())
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn upsert_replaces_members_but_keeps_the_disabled_state(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        insert_combo_backend(
            &pool,
            7,
            "codex-pro",
            "oauth:codex:acct-a",
            Some("codex-oauth"),
        )
        .await?;
        insert_combo_backend(&pool, 2, "zai-main", "env:ZAI_API_KEY", Some("zai")).await?;
        insert_combo_backend(&pool, 9, "legacy-local", "file:/secrets/legacy.key", None).await?;

        persist_combo(
            &pool,
            combo_payload(
                "zn-glm",
                vec![member(7, "gpt-6.1-sol"), member(2, "glm-5.3")],
            ),
        )
        .await
        .expect("first create");

        // Disable (the toggle endpoint owns on/off), then re-post a new member list.
        sqlx::query("UPDATE model_routes SET enabled = FALSE WHERE model_name = 'zn-glm'")
            .execute(&pool)
            .await?;

        let updated = persist_combo(
            &pool,
            combo_payload("zn-glm", vec![member(9, "qwen3.8-flash-next")]),
        )
        .await
        .expect("upsert");
        assert!(!updated.created, "same name is an update, not a second row");
        assert!(
            !updated.response.enabled,
            "upsert must not resurrect a disabled combo"
        );
        assert_eq!(updated.response.members.len(), 1);
        assert_eq!(
            updated.response.members[0].weight, 8,
            "weights recompute from the new order"
        );

        let count: i64 =
            sqlx::query("SELECT COUNT(*) AS c FROM model_routes WHERE model_name = 'zn-glm'")
                .fetch_one(&pool)
                .await?
                .try_get("c")?;
        assert_eq!(count, 1);

        let endpoint_count: i64 = sqlx::query(
            "SELECT COUNT(*) AS c FROM model_route_endpoints WHERE model_name = 'zn-glm'",
        )
        .fetch_one(&pool)
        .await?
        .try_get("c")?;
        assert_eq!(
            endpoint_count, 1,
            "old member endpoints are replaced, not merged"
        );
        Ok(())
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn manual_route_name_is_never_hijacked(pool: PgPool) -> anyhow::Result<()> {
        insert_combo_backend(&pool, 2, "zai-main", "env:ZAI_API_KEY", Some("zai")).await?;
        sqlx::query(
            "INSERT INTO model_routes (model_name, backend_ids, chars_per_token, first_byte_timeout, provider_model_name) \
             VALUES ('manual-model', '[2]', 4.0, 180, 'glm-5.3')",
        )
        .execute(&pool)
        .await?;

        let err = persist_combo(
            &pool,
            combo_payload("manual-model", vec![member(2, "glm-5.3")]),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert!(err.message.contains("manually configured route"));

        // The manual route is untouched.
        let row = sqlx::query::<sqlx::Postgres>(
            "SELECT is_combo, provider_model_name FROM model_routes WHERE model_name = 'manual-model'",
        )
        .fetch_one(&pool)
        .await?;
        assert!(!row.try_get::<bool, _>("is_combo")?);
        assert_eq!(row.try_get::<String, _>("provider_model_name")?, "glm-5.3");
        Ok(())
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn validation_errors_reach_the_database_path_too(pool: PgPool) -> anyhow::Result<()> {
        insert_combo_backend(&pool, 2, "zai-main", "env:ZAI_API_KEY", Some("zai")).await?;

        let err = persist_combo(&pool, combo_payload("bad", vec![]))
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);

        let err = persist_combo(&pool, combo_payload("bad", vec![member(42, "x")]))
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("unknown backend_id 42"));

        let err = persist_combo(
            &pool,
            combo_payload("bad", vec![member(2, "a"), member(2, "b")]),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("keyed by backend_id"));

        // Nothing was written.
        let count: i64 =
            sqlx::query("SELECT COUNT(*) AS c FROM model_routes WHERE model_name = 'bad'")
                .fetch_one(&pool)
                .await?
                .try_get("c")?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn delete_and_disable_fallback(pool: PgPool) -> anyhow::Result<()> {
        insert_combo_backend(&pool, 2, "zai-main", "env:ZAI_API_KEY", Some("zai")).await?;
        insert_combo_backend(&pool, 9, "legacy-local", "file:/secrets/legacy.key", None).await?;
        persist_combo(
            &pool,
            combo_payload("used-combo", vec![member(2, "glm-5.3")]),
        )
        .await
        .expect("create used combo");
        persist_combo(
            &pool,
            combo_payload("fresh-combo", vec![member(9, "qwen3.8-flash-next")]),
        )
        .await
        .expect("create fresh combo");
        sqlx::query(
            "INSERT INTO model_routes (model_name, backend_ids, chars_per_token, first_byte_timeout) \
             VALUES ('manual-keep', '[2]', 4.0, 180)",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO usage_ledger \
             (ts, request_id, key_id, team_id, model, backend_id, status, input_tokens, output_tokens, \
              estimated, ttfb_ms, total_ms, router_overhead_ms, stream, client_aborted) \
             VALUES (0, 'r1', 1, 1, 'used-combo', 2, 200, 10, 10, FALSE, 0, 0, 0, FALSE, FALSE)",
        )
        .execute(&pool)
        .await?;

        // Usage history blocks delete; the message points at the disable escape hatch.
        let err = delete_combo_in_pool(&pool, "used-combo").await.unwrap_err();
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert!(err.message.contains("transaction history"));
        assert!(err.message.contains("disable"));

        // Manual routes are not visible through the combos path at all.
        let err = delete_combo_in_pool(&pool, "manual-keep")
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert!(err.message.contains("not a combo"));
        let err = delete_combo_in_pool(&pool, "no-such-combo")
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::NOT_FOUND);

        // A combo without history deletes cleanly, endpoints cascade.
        delete_combo_in_pool(&pool, "fresh-combo")
            .await
            .expect("delete");
        let routes: i64 =
            sqlx::query("SELECT COUNT(*) AS c FROM model_routes WHERE model_name = 'fresh-combo'")
                .fetch_one(&pool)
                .await?
                .try_get("c")?;
        assert_eq!(routes, 0);
        let endpoints: i64 = sqlx::query(
            "SELECT COUNT(*) AS c FROM model_route_endpoints WHERE model_name = 'fresh-combo'",
        )
        .fetch_one(&pool)
        .await?
        .try_get("c")?;
        assert_eq!(endpoints, 0);
        Ok(())
    }
}
