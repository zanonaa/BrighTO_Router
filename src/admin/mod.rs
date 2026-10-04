//! B3 — Admin API + portal 1 trang HTML tĩnh.
//! Auth: master key từ env + IP allowlist. Admin có thể xem lại client key qua /admin/keys/{id}/reveal.

use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
    io::Read,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension, Path, Query},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, patch, post, put},
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions};

pub mod oauth_api;
pub mod quota_api;

use crate::auth;
use crate::config::{DbConfigLoader, resolve_backend_key};
use crate::contract::{
    ApiKey, AppState, Budget, KeyHash, ModelRoute, ProviderProtocol, RoutingPolicy,
};
use crate::oauth;
use crate::provider_auth::{self, parse_auth_mode};
use crate::provider_registry::{self, ProviderType};

/// Phân biệt "field bị bỏ qua" (None) với "field = null" (Some(None)) cho Option<Option<T>>.
/// serde mặc định map null -> None (giống bỏ qua); helper này giữ null -> Some(None).
fn deserialize_opt_opt<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::deserialize(deserializer)?))
}

// ===== Admin state =====

#[derive(Clone)]
struct AdminState {
    db_url: String,
    master_key: String,
    allow_cidrs: Vec<String>,
    pool: Arc<tokio::sync::OnceCell<PgPool>>,
    runtime: Arc<AppState>,
    /// Built once and shared, because it owns the per-credential min-interval gate and 429
    /// cooldown. Rebuilding it per request would reset both and turn a Portal refresh into a
    /// provider hammer.
    quota_probe: Arc<tokio::sync::OnceCell<Arc<crate::quota::probe::QuotaProbe>>>,
}

impl AdminState {
    fn from_env(runtime: Arc<AppState>) -> Self {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required for admin API");
        // Fail-fast: thiếu/trống ADMIN_MASTER_KEY -> process không được boot với admin secret rỗng.
        let master_key = validate_master_key(
            std::env::var("ADMIN_MASTER_KEY").expect("ADMIN_MASTER_KEY is required for admin API"),
        );
        let allow_cidrs = std::env::var("ADMIN_ALLOW_CIDR")
            .unwrap_or_else(|_| "127.0.0.1/32".to_string())
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();

        Self {
            db_url,
            master_key,
            allow_cidrs,
            pool: Arc::new(Default::default()),
            quota_probe: Arc::new(Default::default()),
            runtime,
        }
    }

    /// The shared quota prober, created on first use.
    async fn quota_probe(&self) -> Arc<crate::quota::probe::QuotaProbe> {
        self.quota_probe
            .get_or_try_init(|| async {
                Ok::<_, std::convert::Infallible>(Arc::new(crate::quota::probe::QuotaProbe::new(
                    self.runtime.client.clone(),
                    Arc::new(crate::oauth::OAuthTokenStore::from_env()),
                    self.runtime.quota.clone(),
                )))
            })
            .await
            .expect("quota probe init is infallible")
            .clone()
    }

    async fn pool(&self) -> Result<&PgPool, ApiError> {
        self.pool
            .get_or_try_init(|| async {
                PgPoolOptions::new()
                    .max_connections(5)
                    .connect(&self.db_url)
                    .await
                    .map_err(|e| ApiError::internal(e.to_string()))
            })
            .await
    }

    /// Reload config snapshot vào runtime state (cfg/budget/backends) đồng bộ, trước khi trả
    /// 200/204 cho mutation. Chỉ chạy trên admin path — KHÔNG phải proxy hot path.
    async fn reload_now(&self) -> Result<(), ApiError> {
        let pool = self.pool().await?;
        let loader = DbConfigLoader::new(pool.clone(), 0);
        let snap = loader.load_snapshot().await.map_err(|e| {
            ApiError::internal(format!("reload config after admin mutation: {e:#}"))
        })?;

        self.runtime.backends.sync_backends(&snap.backends);
        self.runtime.budget.sync_teams(&snap.teams);
        self.runtime.cfg.store(Arc::new(snap));
        self.runtime.reload_notify.notify_one();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.runtime
            .config_ok_at
            .store(now, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

// ===== API error =====

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        ApiError::internal(e.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::internal(e.to_string())
    }
}

// ===== Auth helpers =====

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (addr, prefix) = s.split_once('/')?;
    let ip: IpAddr = addr.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;

    match ip {
        IpAddr::V4(v4) if prefix <= 32 => Some((IpAddr::V4(v4), prefix)),
        IpAddr::V6(v6) if prefix <= 128 => Some((IpAddr::V6(v6), prefix)),
        _ => None,
    }
}

fn ip_matches_cidr(ip: IpAddr, cidr: &str) -> bool {
    let (network, prefix) = match parse_cidr(cidr) {
        Some(x) => x,
        None => return false,
    };

    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from_be_bytes(ip.octets()) & mask) == (u32::from_be_bytes(net.octets()) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from_be_bytes(ip.octets()) & mask) == (u128::from_be_bytes(net.octets()) & mask)
        }
        _ => false,
    }
}

/// Chặn admin secret rỗng ngay lúc khởi tạo (footgun production). Thuần tuý để unit-test không cần env.
fn validate_master_key(value: String) -> String {
    assert!(
        !value.trim().is_empty(),
        "ADMIN_MASTER_KEY must not be empty"
    );
    value
}

fn check_admin_auth(
    master_key: &str,
    allow_cidrs: &[String],
    headers: &HeaderMap,
    peer_ip: IpAddr,
) -> Result<(), ApiError> {
    let provided = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer ").map(str::to_owned))
        });

    if provided.as_deref() != Some(master_key) {
        return Err(ApiError::unauthorized("invalid admin key"));
    }

    // Nguồn IP duy nhất đáng tin = socket peer addr (chống spoof X-Forwarded-For).
    if !allow_cidrs
        .iter()
        .any(|cidr| ip_matches_cidr(peer_ip, cidr))
    {
        return Err(ApiError::forbidden("ip not allowed"));
    }

    Ok(())
}

// ===== Key helpers =====

fn generate_key() -> Result<String, ApiError> {
    let mut bytes = [0u8; 16];
    let f = std::fs::File::open("/dev/urandom").map_err(|e| ApiError::internal(e.to_string()))?;
    f.take(16)
        .read_exact(&mut bytes)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(format!("sk-brighto-{}", hex_encode(&bytes)))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{:02x}", b).expect("write into String cannot fail");
    }
    s
}

// ===== Router =====

/// Router con cho /admin/* — được nest_service vào router chính.
pub fn router(runtime: Arc<AppState>) -> Router {
    let state: Arc<AdminState> = Arc::new(AdminState::from_env(runtime));

    Router::new()
        .route("/", get(portal))
        .route("/teams", get(list_teams).post(create_team))
        .route("/keys", get(list_keys).post(create_key))
        .route("/backends", get(list_backends).post(create_backend))
        .route(
            "/backends/{id}",
            patch(update_backend).delete(delete_backend),
        )
        .route("/backends/{id}/key", put(put_backend_key))
        .route("/backends/{id}/models", get(fetch_backend_models))
        .route("/backends/{id}/models-catalog", get(backend_models_catalog))
        .route("/routes", get(list_routes).post(upsert_route))
        .route("/routes/preview-models", post(preview_models))
        .route("/provider-catalog", get(list_provider_catalog))
        .route("/providers", get(list_providers))
        .route("/test-connection", post(test_connection))
        .merge(oauth_api::routes())
        .merge(quota_api::routes())
        .route(
            "/routes/{model_name}",
            patch(patch_route).delete(delete_route),
        )
        .route("/routes/{model_name}/enabled", patch(toggle_route_enabled))
        .route("/teams/{id}", patch(update_team))
        .route("/keys/{id}", patch(update_key).delete(disable_key))
        .route("/keys/{id}/reveal", get(reveal_key))
        .route("/stats", get(get_stats))
        .route("/summary", get(get_summary))
        .route("/usage", get(get_usage))
        .route("/settings", get(get_settings))
        .layer(Extension(state))
}

/// Router con cho /portal/* — user tự phục vụ (auth bằng API key, KHÔNG phải admin key).
/// User xem key/team của mình + usage/charts/logs. Không lộ plaintext key.
pub fn user_router(runtime: Arc<AppState>) -> Router {
    let state = Arc::new(AdminState::from_env(runtime));
    Router::new()
        .route("/me", get(me))
        .route("/me/usage", get(me_usage))
        .route("/me/stats", get(me_stats))
        .layer(Extension(state))
}

async fn portal() -> impl IntoResponse {
    let body = std::env::var("PORTAL_STATIC_FILE")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .and_then(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_else(|| include_str!("../../static/index.html").to_string());
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body)
}

// ===== Request/response types =====

#[derive(Deserialize)]
struct CreateTeam {
    name: String,
    budget: Option<Budget>,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Serialize)]
struct TeamResponse {
    id: i64,
    name: String,
    budget: Option<Budget>,
    enabled: bool,
}

#[derive(Deserialize)]
struct CreateKey {
    team_id: i64,
    owner: String,
    #[serde(default)]
    allowed_models: Vec<String>,
    budget: Option<Budget>,
    rpm_limit: Option<u32>,
    concurrency_limit: Option<u32>,
    expires_at: Option<i64>,
}

#[derive(Deserialize)]
struct PatchKey {
    team_id: Option<i64>,
    owner: Option<String>,
    allowed_models: Option<Vec<String>>,
    /// Some(Some(b)) = set budget; Some(None) = clear budget; None = leave unchanged.
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    budget: Option<Option<Budget>>,
    rpm_limit: Option<u32>,
    concurrency_limit: Option<u32>,
    expires_at: Option<i64>,
    enabled: Option<bool>,
}

#[derive(Serialize)]
struct KeyResponse {
    id: i64,
    key: String,
    prefix: String,
}

#[derive(Deserialize)]
struct PatchTeam {
    name: Option<String>,
    /// Some(Some(b)) = set; Some(None) = clear; None = leave unchanged.
    #[serde(default, deserialize_with = "deserialize_opt_opt")]
    budget: Option<Option<Budget>>,
    enabled: Option<bool>,
}

#[derive(Serialize)]
struct BackendResponse {
    id: i64,
    name: String,
    base_url: String,
    api_key_ref: String,
    key_resolved: bool,
    weight: i64,
    max_inflight: i64,
    format: String,
    /// Model list fetched live from GET {base_url}/models (dynamic catalog).
    dynamic_models: bool,
    enabled: bool,
    /// Registry slug khi backend được tạo từ provider registry (null = backend thường).
    provider_type: Option<String>,
    /// Số model route ĐANG enabled tham chiếu provider này.
    active_route_count: i64,
    /// Số dòng usage_ledger ghi cho provider này.
    usage_count: i64,
    /// true chỉ khi không có active route và không có usage (an toàn để xoá).
    can_delete: bool,
    /// Lý do chặn xoá (rỗng nếu can_delete).
    delete_blockers: Vec<String>,
}

#[derive(Deserialize)]
struct PatchBackend {
    name: Option<String>,
    base_url: Option<String>,
    api_key_ref: Option<String>,
    weight: Option<u32>,
    max_inflight: Option<u32>,
    format: Option<String>,
    /// Bật/tắt dynamic catalog: model list luôn lấy từ GET {base_url}/models.
    dynamic_models: Option<bool>,
    enabled: Option<bool>,
}

#[derive(Deserialize, Clone)]
struct CreateBackend {
    name: String,
    /// Legacy path (no provider_type): required, exactly as before.
    /// With provider_type: required only for entries without a fixed base URL (custom-openai).
    #[serde(default)]
    base_url: Option<String>,
    /// Credential reference (env:NAME | file:/path). Legacy path: required non-empty.
    #[serde(default)]
    api_key_ref: Option<String>,
    /// Legacy path (no provider_type): required ("openai" | "anthropic"). Derived from the
    /// registry when provider_type is set.
    #[serde(default)]
    format: Option<String>,
    /// Registry slug (see GET /admin/providers). When present, base_url/format and the
    /// route-facing protocol/auth_mode defaults are derived from the registry.
    #[serde(default)]
    provider_type: Option<String>,
    /// Plaintext provider API key (write-only). Stored as a secrets-dir file reference,
    /// never in the DB — same mechanism as PUT /admin/backends/{id}/key.
    #[serde(default)]
    key: Option<String>,
    weight: Option<u32>,
    max_inflight: Option<u32>,
    /// Bật dynamic catalog ngay khi tạo backend.
    #[serde(default)]
    dynamic_models: bool,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

/// `POST /admin/backends` payload sau khi resolve: đúng các giá trị sẽ ghi vào DB (hoặc vào
/// file secrets). Pure function để unit-test đường derivation mà không cần DB/pool.
#[derive(Debug)]
struct ResolvedBackendCreate {
    name: String,
    /// Entry registry khi payload có provider_type hợp lệ (None = legacy payload).
    provider_type: Option<&'static ProviderType>,
    base_url: String,
    format: &'static str,
    /// Reference lưu trong DB; rỗng = credential đến từ `key` (ghi file sau INSERT) hoặc
    /// backend không cần credential.
    api_key_ref: String,
    /// Plaintext key cần ghi ra file secrets sau khi INSERT (không bao giờ lưu DB).
    plaintext_key: Option<String>,
    weight: u32,
    max_inflight: u32,
    enabled: bool,
}

/// Resolve payload create-backend thành các cột sẽ lưu.
///
/// Hai đường:
/// * Không có `provider_type` (legacy): mọi giá trị caller cung cấp, validate y hệt cũ.
/// * Có `provider_type`: registry suy ra base_url/format; entry có base_url cố định thì
///   override caller (tránh URL sai trỏ provider quen đi nơi khác), entry custom thì bắt
///   buộc caller gửi base_url.
fn resolve_backend_create(payload: CreateBackend) -> Result<ResolvedBackendCreate, ApiError> {
    let name = non_empty_trimmed(payload.name, "name")?;
    let plaintext_key = payload
        .key
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty());
    let api_key_ref = payload
        .api_key_ref
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    let weight = payload.weight.unwrap_or(1).max(1);
    let max_inflight = payload.max_inflight.unwrap_or(0);

    let provider_slug = payload
        .provider_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let (provider_type, base_url, format) = match provider_slug {
        None => {
            // Legacy payload: hành vi giữ nguyên 100% — base_url/api_key_ref/format bắt buộc.
            let base_url = match payload.base_url {
                Some(v) => non_empty_trimmed(v, "base_url")?,
                None => {
                    return Err(ApiError::bad_request("base_url must not be empty"));
                }
            };
            let format = match payload.format {
                Some(v) => normalize_backend_format(&v)?,
                None => {
                    return Err(ApiError::bad_request("format must be openai or anthropic"));
                }
            };
            let api_key_ref = api_key_ref
                .ok_or_else(|| ApiError::bad_request("api_key_ref must not be empty"))?;
            return Ok(ResolvedBackendCreate {
                name,
                provider_type: None,
                base_url,
                format,
                api_key_ref,
                plaintext_key,
                weight,
                max_inflight,
                enabled: payload.enabled,
            });
        }
        Some(slug) => {
            let entry = provider_registry::lookup(slug).ok_or_else(|| {
                ApiError::bad_request(format!(
                    "unknown provider_type '{slug}'; see GET /admin/providers"
                ))
            })?;
            // Entries với base_url cố định: registry thắng caller base_url. Entry custom
            // (base_url None): caller phải gửi base_url.
            let base_url = match entry.base_url {
                Some(fixed) => fixed.to_string(),
                None => match payload.base_url {
                    Some(v) => non_empty_trimmed(v, "base_url")?,
                    None => {
                        return Err(ApiError::bad_request(format!(
                            "provider_type '{slug}' requires base_url"
                        )));
                    }
                },
            };
            if crate::provider_auth::is_oauth_mode(entry.auth_mode) {
                // OAuth credential là connected account (oauth:<provider>:<label>), không bao
                // giờ là key dán tay — chặn ngay thay vì lưu thứ không chạy được.
                if plaintext_key.is_some() {
                    return Err(ApiError::bad_request(format!(
                        "provider_type '{slug}' uses a connected OAuth account; pass \
                         api_key_ref oauth:<provider>:<label> instead of a pasted key"
                    )));
                }
            } else if entry.requires_credential && api_key_ref.is_none() && plaintext_key.is_none()
            {
                return Err(ApiError::bad_request(format!(
                    "provider_type '{slug}' requires an API key (key or api_key_ref)"
                )));
            }
            (Some(entry), base_url, entry.backend_format())
        }
    };

    // provider_type path: api_key_ref tùy chọn; key (plaintext) ưu tiên như route flow.
    let api_key_ref = match (&plaintext_key, &api_key_ref) {
        (Some(_), _) => String::new(), // ref sẽ là file:... sau khi ghi key
        (None, Some(r)) => r.clone(),
        (None, None) => String::new(),
    };

    Ok(ResolvedBackendCreate {
        name,
        provider_type,
        base_url,
        format,
        api_key_ref,
        plaintext_key,
        weight,
        max_inflight,
        enabled: payload.enabled,
    })
}

#[derive(Serialize)]
struct ModelListResponse {
    backend_id: i64,
    backend_name: String,
    models: Vec<String>,
}

#[derive(Deserialize)]
struct PreviewModelsRequest {
    base_url: String,
    protocol: String,
    auth_mode: Option<String>,
    provider_key: Option<String>,
    /// env:NAME | file:/path — key hard-coded trong .env, resolve server-side.
    provider_key_ref: Option<String>,
}

#[derive(Deserialize)]
struct UpsertRoute {
    model_name: String,
    backend_ids: Vec<i64>,
    fallback_backend_id: Option<i64>,
    chars_per_token: Option<f64>,
    first_byte_timeout: Option<u64>,
    #[serde(default)]
    provider_model_name: Option<String>,
    context_tokens: Option<i64>,
    max_output_tokens: Option<i64>,
    price_input_per_mtok_usd: Option<f64>,
    price_output_per_mtok_usd: Option<f64>,
    enabled: Option<bool>,
    /// Plaintext provider key (write-only). Ghi ra file secrets + lưu provider_key_ref.
    provider_key: Option<String>,
    /// env:NAME | file:/path — tham chiếu key hard-coded trong .env (không ghi plaintext).
    provider_key_ref: Option<String>,
    /// bearer | anthropic | none
    auth_mode: Option<String>,
    /// Route-level protocol, for example openai_chat, openai_embeddings, cohere_rerank, openai_audio_transcriptions.
    protocol: Option<String>,
    /// Model Group routing policy: least_loaded_weighted | round_robin | weighted_round_robin.
    routing_policy: Option<String>,
    /// Optional endpoint overrides for Model Group load balancing. Omitted = keep existing endpoint rows.
    endpoints: Option<Vec<UpsertRouteEndpoint>>,
    /// Passthrough: route mọi model có trong dynamic catalog của backend (đúng 1 backend),
    /// không chỉ model_name của row này. Protocol/auth/pricing lấy từ row.
    passthrough: Option<bool>,
}

#[derive(Deserialize)]
struct UpsertRouteEndpoint {
    backend_id: i64,
    provider_model_name: Option<String>,
    provider_key: Option<String>,
    provider_key_ref: Option<String>,
    auth_mode: Option<String>,
    protocol: Option<String>,
    weight: Option<u32>,
    max_inflight: Option<u32>,
    enabled: Option<bool>,
}

#[derive(Debug, Clone)]
struct ValidatedRouteEndpoint {
    backend_id: i64,
    provider_model_name: String,
    provider_key_ref: Option<String>,
    auth_mode: String,
    protocol: String,
    weight: u32,
    max_inflight: u32,
    enabled: bool,
}

#[derive(Serialize)]
struct RouteEndpointResponse {
    backend_id: i64,
    provider_model_name: String,
    provider_key_ref: Option<String>,
    auth_mode: String,
    protocol: String,
    weight: u32,
    max_inflight: u32,
    enabled: bool,
}

#[derive(Serialize)]
struct RouteResponse {
    model_name: String,
    backend_ids: Vec<i64>,
    fallback_backend_id: Option<i64>,
    chars_per_token: f64,
    first_byte_timeout: u64,
    provider_model_name: String,
    context_tokens: Option<i64>,
    max_output_tokens: Option<i64>,
    price_input_per_mtok_usd: Option<f64>,
    price_output_per_mtok_usd: Option<f64>,
    enabled: bool,
    provider_key_ref: Option<String>,
    auth_mode: String,
    protocol: String,
    routing_policy: String,
    /// Passthrough route (dynamic catalog matching); hiện trong listing như route thường.
    passthrough: bool,
    endpoints: Vec<RouteEndpointResponse>,
    /// route.enabled && có ít nhất 1 backend tham chiếu enabled.
    effective_enabled: bool,
    /// None nếu effective; 'disabled manually' / 'provider disabled'.
    disabled_reason: Option<String>,
    /// Số dòng usage_ledger cho public model này.
    usage_count: i64,
    /// true chỉ khi không có usage history (có thể xoá; có usage thì phải disable).
    can_delete: bool,
}

#[derive(Deserialize)]
struct UsageQuery {
    team: Option<i64>,
    key: Option<i64>,
    backend: Option<i64>,
    model: Option<String>,
    status: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
}

#[derive(Serialize)]
struct UsageRow {
    ts: i64,
    request_id: String,
    key_id: i64,
    team_id: i64,
    model: String,
    backend_id: i64,
    status: i64,
    input_tokens: i64,
    output_tokens: i64,
    estimated: bool,
    ttfb_ms: i64,
    total_ms: i64,
    router_overhead_ms: i64,
    stream: bool,
    client_aborted: bool,
    error_class: Option<String>,
    // Computed (CODEX call-log: token throughput + cost + friendly durations + prompt bucket).
    total_tokens: i64,
    total_tokens_per_second: Option<f64>,
    input_tokens_per_second_to_first_byte: Option<f64>,
    output_tokens_per_second: Option<f64>,
    prompt_size_bucket: String,
    estimated_cost_usd: Option<f64>,
    cost_known: bool,
    duration_display: String,
    router_overhead_display: String,
}

#[derive(Serialize)]
struct TeamListRow {
    id: i64,
    name: String,
    budget: Option<Budget>,
    enabled: bool,
}

#[derive(Serialize)]
struct KeyListRow {
    id: i64,
    prefix: String,
    team_id: i64,
    team_name: String,
    owner: String,
    allowed_models: Vec<String>,
    budget: Option<Budget>,
    rpm_limit: Option<i64>,
    concurrency_limit: Option<i64>,
    expires_at: Option<i64>,
    enabled: bool,
    /// true nếu key_secret còn lưu (có thể xem lại plaintext); false = legacy (recreate để xem).
    revealable: bool,
}

#[derive(Serialize)]
struct StatRow {
    /// epoch giây đầu ngày (bucket 1 ngày)
    day: i64,
    model: String,
    input_tokens: i64,
    output_tokens: i64,
    requests: i64,
}

#[derive(Deserialize)]
struct StatsQuery {
    team: Option<i64>,
    days: Option<u32>,
}

#[derive(Deserialize)]
struct MeStatsQuery {
    days: Option<u32>,
}

#[derive(Serialize)]
struct MeResponse {
    key: MeKey,
    team: MeTeam,
}

#[derive(Serialize)]
struct MeKey {
    id: i64,
    prefix: String,
    owner: String,
    allowed_models: Vec<String>,
    budget: Option<Budget>,
    rpm_limit: Option<u32>,
    concurrency_limit: Option<u32>,
    expires_at: Option<i64>,
    enabled: bool,
}

#[derive(Serialize)]
struct MeTeam {
    id: i64,
    name: String,
    budget: Option<Budget>,
    enabled: bool,
}

#[derive(Serialize)]
struct KeyRevealResponse {
    id: i64,
    prefix: String,
    owner: String,
    key: String,
}

#[derive(Serialize)]
struct SettingsResponse {
    listen_addr: String,
    database_ok: bool,
    config_reload_ok: bool,
    max_body_bytes: usize,
    version: String,
}

// ===== Handlers =====

fn normalize_backend_format(value: &str) -> Result<&'static str, ApiError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "openai" | "open_ai" => Ok("openai"),
        "anthropic" => Ok("anthropic"),
        // Marker for the OpenCode Zen free tier, not a third wire dialect: config load maps it
        // to the OpenAI dialect, and admin probes use it to send the free-tier client headers.
        "opencode_free" | "opencode-free" => Ok("opencode_free"),
        _ => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "format must be openai, anthropic or opencode_free",
        )),
    }
}

fn non_empty_trimmed(value: String, field: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("{field} must not be empty"),
        ));
    }
    Ok(trimmed.to_owned())
}

/// Join base_url + route path. Shared by admin probes and the dynamic-catalog fetcher:
/// một base_url đã có path prefix (vd .../v1) chỉ nhận /models, không lặp /v1.
pub(crate) fn join_provider_url(base_url: &str, route: &str) -> String {
    let trimmed = base_url.trim_end_matches('/');
    let has_path_prefix = trimmed
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('/'))
        .is_some();
    let path = if has_path_prefix {
        route.strip_prefix("/v1").unwrap_or(route)
    } else {
        route
    };
    if path.starts_with('/') {
        format!("{trimmed}{path}")
    } else {
        format!("{trimmed}/{path}")
    }
}

/// Ghi provider key plaintext với quyền hạn chế (dir 0700, file 0600) để không lộ secret cho
/// user khác trên host. Dùng `create_dir_all` rồi `set_permissions` để khoá thư mục.
fn write_provider_key_file(path: &std::path::Path, key: &str) -> Result<(), ApiError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| ApiError::internal(format!("create provider_keys dir: {e}")))?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| ApiError::internal(format!("write provider key: {e}")))?;
    f.write_all(key.as_bytes())
        .map_err(|e| ApiError::internal(format!("write provider key: {e}")))?;
    Ok(())
}

fn parse_backend_ids(value: &str) -> Result<Vec<i64>, ApiError> {
    serde_json::from_str::<Vec<i64>>(value).map_err(|_| {
        ApiError::internal(format!("invalid backend_ids JSON in model_routes: {value}"))
    })
}

/// Aux data cho lifecycle: enabled map + usage theo backend/model + active route theo backend.
struct LifecycleData {
    backends_enabled: HashMap<i64, bool>,
    usage_by_backend: HashMap<i64, i64>,
    usage_by_model: HashMap<String, i64>,
    active_by_backend: HashMap<i64, Vec<String>>,
}

async fn load_lifecycle_data(pool: &PgPool) -> Result<LifecycleData, ApiError> {
    let backends = sqlx::query::<sqlx::Postgres>("SELECT id, enabled FROM backends")
        .fetch_all(pool)
        .await?;
    let mut backends_enabled = HashMap::new();
    for b in &backends {
        backends_enabled.insert(b.try_get::<i64, _>("id")?, b.try_get::<bool, _>("enabled")?);
    }

    let usage = sqlx::query::<sqlx::Postgres>(
        "SELECT backend_id, model, COUNT(*) AS c FROM usage_ledger GROUP BY backend_id, model",
    )
    .fetch_all(pool)
    .await?;
    let mut usage_by_backend: HashMap<i64, i64> = HashMap::new();
    let mut usage_by_model: HashMap<String, i64> = HashMap::new();
    for u in &usage {
        let bid: i64 = u.try_get("backend_id")?;
        let model: String = u.try_get("model")?;
        let c: i64 = u.try_get("c")?;
        *usage_by_backend.entry(bid).or_insert(0) += c;
        *usage_by_model.entry(model).or_insert(0) += c;
    }

    let routes = sqlx::query::<sqlx::Postgres>(
        "SELECT model_name, backend_ids, fallback_backend_id, enabled FROM model_routes",
    )
    .fetch_all(pool)
    .await?;
    let mut active_by_backend: HashMap<i64, Vec<String>> = HashMap::new();
    for r in &routes {
        let enabled: bool = r.try_get("enabled")?;
        if !enabled {
            continue;
        }
        let name: String = r.try_get("model_name")?;
        let ids_json: String = r.try_get("backend_ids")?;
        let mut ids = parse_backend_ids(&ids_json).unwrap_or_default();
        if let Ok(Some(fb)) = r.try_get::<Option<i64>, _>("fallback_backend_id") {
            ids.push(fb);
        }
        for id in ids {
            active_by_backend.entry(id).or_default().push(name.clone());
        }
    }

    Ok(LifecycleData {
        backends_enabled,
        usage_by_backend,
        usage_by_model,
        active_by_backend,
    })
}

async fn load_route_endpoint_responses(
    pool: &PgPool,
) -> Result<HashMap<String, Vec<RouteEndpointResponse>>, ApiError> {
    let rows = sqlx::query::<sqlx::Postgres>(
        "SELECT model_name, backend_id, provider_model_name, provider_key_ref, auth_mode, \
         protocol, weight, max_inflight, enabled FROM model_route_endpoints \
         ORDER BY model_name, backend_id",
    )
    .fetch_all(pool)
    .await?;
    let mut out: HashMap<String, Vec<RouteEndpointResponse>> = HashMap::new();
    for row in rows {
        let model_name: String = row.try_get("model_name")?;
        let weight: i64 = row.try_get("weight")?;
        let max_inflight: i64 = row.try_get("max_inflight")?;
        out.entry(model_name)
            .or_default()
            .push(RouteEndpointResponse {
                backend_id: row.try_get("backend_id")?,
                provider_model_name: row.try_get("provider_model_name")?,
                provider_key_ref: row.try_get("provider_key_ref")?,
                auth_mode: row.try_get("auth_mode")?,
                protocol: row.try_get("protocol")?,
                weight: u32::try_from(weight.max(1)).unwrap_or(1),
                max_inflight: u32::try_from(max_inflight.max(0)).unwrap_or(0),
                enabled: row.try_get("enabled")?,
            });
    }
    Ok(out)
}

async fn list_routes_from_pool(pool: &PgPool) -> Result<Vec<RouteResponse>, ApiError> {
    let rows = sqlx::query::<sqlx::Postgres>(
        "SELECT model_name, backend_ids, fallback_backend_id, chars_per_token, first_byte_timeout, \
         provider_model_name, context_tokens, max_output_tokens, \
         price_input_per_mtok_usd, price_output_per_mtok_usd, enabled, provider_key_ref, auth_mode, protocol, routing_policy, passthrough \
         FROM model_routes ORDER BY model_name",
    )
    .fetch_all(pool)
    .await?;
    let lc = load_lifecycle_data(pool).await?;
    let mut endpoint_rows = load_route_endpoint_responses(pool).await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let backend_ids_json: String = row.try_get("backend_ids")?;
        let model_name: String = row.try_get("model_name")?;
        let enabled: bool = row.try_get("enabled")?;
        let backend_ids = parse_backend_ids(&backend_ids_json)?;
        let fallback: Option<i64> = row.try_get("fallback_backend_id")?;

        let mut referenced = backend_ids.clone();
        if let Some(fb) = fallback {
            referenced.push(fb);
        }
        let any_backend_enabled = referenced
            .iter()
            .any(|id| lc.backends_enabled.get(id).copied().unwrap_or(false));
        let effective_enabled = enabled && any_backend_enabled;
        let disabled_reason = if !enabled {
            Some("disabled manually".to_string())
        } else if !any_backend_enabled {
            Some("provider disabled".to_string())
        } else {
            None
        };
        let usage_count = lc.usage_by_model.get(&model_name).copied().unwrap_or(0);
        let endpoints = endpoint_rows.remove(&model_name).unwrap_or_default();

        out.push(RouteResponse {
            model_name,
            backend_ids,
            fallback_backend_id: fallback,
            chars_per_token: row.try_get("chars_per_token")?,
            first_byte_timeout: row.try_get::<i64, _>("first_byte_timeout")? as u64,
            provider_model_name: row.try_get("provider_model_name")?,
            context_tokens: row.try_get("context_tokens")?,
            max_output_tokens: row.try_get("max_output_tokens")?,
            price_input_per_mtok_usd: row.try_get("price_input_per_mtok_usd")?,
            price_output_per_mtok_usd: row.try_get("price_output_per_mtok_usd")?,
            enabled,
            provider_key_ref: row.try_get("provider_key_ref")?,
            auth_mode: row.try_get("auth_mode")?,
            protocol: row.try_get("protocol")?,
            routing_policy: row.try_get("routing_policy")?,
            passthrough: row.try_get("passthrough")?,
            endpoints,
            effective_enabled,
            disabled_reason,
            usage_count,
            can_delete: usage_count == 0,
        });
    }
    Ok(out)
}

async fn create_backend(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CreateBackend>,
) -> Result<Json<BackendResponse>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let dynamic_models = payload.dynamic_models;
    let resolved = resolve_backend_create(payload)?;
    let pool = state.pool().await?;
    let provider_slug: Option<&str> = resolved.provider_type.map(|p| p.slug);
    let row = sqlx::query::<sqlx::Postgres>(
        "INSERT INTO backends (name, base_url, api_key_ref, weight, max_inflight, format, dynamic_models, enabled, provider_type) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(&resolved.name)
    .bind(&resolved.base_url)
    .bind(&resolved.api_key_ref)
    .bind(resolved.weight as i64)
    .bind(resolved.max_inflight as i64)
    .bind(resolved.format)
    .bind(dynamic_models)
    .bind(resolved.enabled)
    .bind(provider_slug)
    .fetch_one(pool)
    .await?;
    let id: i64 = row.try_get("id")?;
    // Plaintext key: ghi file secrets (0600) rồi lưu ref — không bao giờ lưu plaintext vào DB,
    // cùng cơ chế với PUT /admin/backends/{id}/key.
    let mut api_key_ref = resolved.api_key_ref.clone();
    if let Some(key) = resolved.plaintext_key.as_deref() {
        let data_dir =
            std::env::var("DATA_DIR").unwrap_or_else(|_| "/var/lib/brighto-router".to_string());
        let path = std::path::Path::new(&data_dir)
            .join("provider_keys")
            .join(format!("{id}.key"));
        write_provider_key_file(&path, key)?;
        api_key_ref = format!("file:{}", path.display());
        sqlx::query::<sqlx::Postgres>("UPDATE backends SET api_key_ref = $1 WHERE id = $2")
            .bind(&api_key_ref)
            .bind(id)
            .execute(pool)
            .await?;
    }
    state.reload_now().await?;
    Ok(Json(BackendResponse {
        id,
        name: resolved.name,
        base_url: resolved.base_url,
        key_resolved: resolve_backend_key(&api_key_ref)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false),
        api_key_ref,
        weight: resolved.weight as i64,
        max_inflight: resolved.max_inflight as i64,
        format: resolved.format.to_string(),
        dynamic_models,
        enabled: resolved.enabled,
        provider_type: provider_slug.map(str::to_owned),
        active_route_count: 0,
        usage_count: 0,
        can_delete: true,
        delete_blockers: vec![],
    }))
}

async fn list_backends(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Vec<BackendResponse>>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    let rows = sqlx::query::<sqlx::Postgres>(
        "SELECT id, name, base_url, api_key_ref, weight, max_inflight, format, dynamic_models, enabled, provider_type FROM backends ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    let lc = load_lifecycle_data(pool).await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let id: i64 = row.try_get("id")?;
        let api_key_ref: String = row.try_get("api_key_ref")?;
        let provider_type: Option<String> = row
            .try_get::<Option<String>, _>("provider_type")?
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let active_names = lc.active_by_backend.get(&id).cloned().unwrap_or_default();
        let active_route_count = active_names.len() as i64;
        let usage_count = lc.usage_by_backend.get(&id).copied().unwrap_or(0);
        let mut delete_blockers = Vec::new();
        if !active_names.is_empty() {
            delete_blockers.push(format!(
                "used by {} active route(s): {}",
                active_names.len(),
                active_names.join(", ")
            ));
        }
        if usage_count > 0 {
            delete_blockers.push(format!("has {usage_count} logged request(s)"));
        }
        out.push(BackendResponse {
            id,
            name: row.try_get("name")?,
            base_url: row.try_get("base_url")?,
            key_resolved: resolve_backend_key(&api_key_ref)
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false),
            api_key_ref,
            weight: row.try_get("weight")?,
            max_inflight: row.try_get("max_inflight")?,
            format: row.try_get("format")?,
            dynamic_models: row.try_get("dynamic_models")?,
            enabled: row.try_get("enabled")?,
            provider_type,
            active_route_count,
            usage_count,
            can_delete: delete_blockers.is_empty(),
            delete_blockers,
        });
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct PutBackendKey {
    key: String,
}

/// Ghi provider key ra file secrets (write-only, KHÔNG trả plaintext). Cập nhật api_key_ref = file:...
async fn put_backend_key(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(payload): Json<PutBackendKey>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let key = payload.key.trim().to_string();
    if key.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "provider key must not be empty",
        ));
    }
    let pool = state.pool().await?;
    let exists = sqlx::query::<sqlx::Postgres>("SELECT 1 FROM backends WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .is_some();
    if !exists {
        return Err(ApiError::not_found("backend not found"));
    }
    let data_dir =
        std::env::var("DATA_DIR").unwrap_or_else(|_| "/var/lib/brighto-router".to_string());
    let dir = std::path::Path::new(&data_dir).join("provider_keys");
    let path = dir.join(format!("{id}.key"));
    write_provider_key_file(&path, &key)?;
    let file_ref = format!("file:{}", path.display());
    sqlx::query::<sqlx::Postgres>("UPDATE backends SET api_key_ref = $1 WHERE id = $2")
        .bind(&file_ref)
        .bind(id)
        .execute(pool)
        .await?;
    state.reload_now().await?;
    Ok(Json(json!({ "id": id, "key_resolved": true })))
}

async fn update_backend(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(payload): Json<PatchBackend>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;

    let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE backends SET ");
    let mut first = true;

    if let Some(name) = payload.name {
        if !first {
            builder.push(", ");
        }
        builder
            .push("name = ")
            .push_bind(non_empty_trimmed(name, "name")?);
        first = false;
    }
    if let Some(base_url) = payload.base_url {
        if !first {
            builder.push(", ");
        }
        builder
            .push("base_url = ")
            .push_bind(non_empty_trimmed(base_url, "base_url")?);
        first = false;
    }
    if let Some(api_key_ref) = payload.api_key_ref {
        if !first {
            builder.push(", ");
        }
        builder
            .push("api_key_ref = ")
            .push_bind(non_empty_trimmed(api_key_ref, "api_key_ref")?);
        first = false;
    }
    if let Some(weight) = payload.weight {
        if weight == 0 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "weight must be at least 1",
            ));
        }
        if !first {
            builder.push(", ");
        }
        builder.push("weight = ").push_bind(weight as i64);
        first = false;
    }
    if let Some(max_inflight) = payload.max_inflight {
        if !first {
            builder.push(", ");
        }
        builder
            .push("max_inflight = ")
            .push_bind(max_inflight as i64);
        first = false;
    }
    if let Some(format) = payload.format {
        if !first {
            builder.push(", ");
        }
        builder
            .push("format = ")
            .push_bind(normalize_backend_format(&format)?);
        first = false;
    }
    if let Some(dynamic_models) = payload.dynamic_models {
        if !first {
            builder.push(", ");
        }
        builder.push("dynamic_models = ").push_bind(dynamic_models);
        first = false;
    }
    if let Some(enabled) = payload.enabled {
        if !first {
            builder.push(", ");
        }
        builder.push("enabled = ").push_bind(enabled);
        first = false;
    }

    if first {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "no fields to update",
        ));
    }
    builder.push(" WHERE id = ").push_bind(id);
    let result = builder.build().execute(pool).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("backend not found"));
    }

    state.reload_now().await?;
    Ok(Json(json!({ "id": id })))
}

/// Xoá provider/backend. Chặn nếu còn route tham chiếu (tránh route trỏ backend chết).
async fn delete_backend(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;

    // 1. Block if provider has usage history (CODEX lifecycle).
    let usage: i64 = sqlx::query::<sqlx::Postgres>(
        "SELECT COUNT(*) AS c FROM usage_ledger WHERE backend_id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?
    .try_get("c")?;
    if usage > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("provider has {usage} logged request(s); disable it instead of deleting"),
        ));
    }

    // 2. Block if any ENABLED route references it.
    let refs = sqlx::query::<sqlx::Postgres>(
        "SELECT model_name, backend_ids, fallback_backend_id, enabled FROM model_routes",
    )
    .fetch_all(pool)
    .await?;
    let mut active_in_use = Vec::new();
    for row in &refs {
        let enabled: bool = row.try_get("enabled")?;
        if !enabled {
            continue;
        }
        let ids_json: String = row.try_get("backend_ids")?;
        let ids = parse_backend_ids(&ids_json).unwrap_or_default();
        let fallback: Option<i64> = row.try_get("fallback_backend_id")?;
        if ids.contains(&id) || fallback == Some(id) {
            active_in_use.push(row.try_get::<String, _>("model_name")?);
        }
    }
    if !active_in_use.is_empty() {
        active_in_use.sort();
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!(
                "provider used by active routes: {}",
                active_in_use.join(", ")
            ),
        ));
    }

    // 3. Cascade-clean disabled-only routes still referencing this provider.
    for row in &refs {
        let model: String = row.try_get("model_name")?;
        let ids_json: String = row.try_get("backend_ids")?;
        let ids = parse_backend_ids(&ids_json).unwrap_or_default();
        let fallback: Option<i64> = row.try_get("fallback_backend_id")?;
        if !ids.contains(&id) && fallback != Some(id) {
            continue;
        }
        let remaining: Vec<i64> = ids.iter().copied().filter(|x| *x != id).collect();
        let new_fallback = if fallback == Some(id) { None } else { fallback };
        if remaining.is_empty() && new_fallback.is_none() {
            let _ = sqlx::query::<sqlx::Postgres>("DELETE FROM model_routes WHERE model_name = $1")
                .bind(&model)
                .execute(pool)
                .await?;
        } else {
            let json = serde_json::to_string(&remaining)?;
            let _ = sqlx::query::<sqlx::Postgres>(
                "UPDATE model_routes SET backend_ids = $1, fallback_backend_id = $2, enabled = false WHERE model_name = $3",
            )
            .bind(&json)
            .bind(new_fallback)
            .bind(&model)
            .execute(pool)
            .await?;
        }
    }

    let result = sqlx::query::<sqlx::Postgres>("DELETE FROM backends WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("backend not found"));
    }
    state.reload_now().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn fetch_backend_models(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ModelListResponse>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    let row = sqlx::query::<sqlx::Postgres>(
        "SELECT name, base_url, api_key_ref, format FROM backends WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::not_found("backend not found"))?;

    let name: String = row.try_get("name")?;
    let base_url: String = row.try_get("base_url")?;
    let api_key_ref: String = row.try_get("api_key_ref")?;
    let format: String = row.try_get("format")?;
    // Cho phép key rỗng (local llama.cpp/vLLM không cần key). Chỉ gắn auth khi key có giá trị.
    let key = resolve_backend_key(&api_key_ref).unwrap_or_default();
    let url = join_provider_url(&base_url, "/v1/models");
    let mut req = state
        .runtime
        .client
        .get(url)
        .timeout(Duration::from_secs(15));
    match normalize_backend_format(&format)? {
        "openai" => {
            if !key.is_empty() {
                req = req.bearer_auth(key);
            }
        }
        "anthropic" => {
            if !key.is_empty() {
                req = req
                    .header("x-api-key", key)
                    .header("anthropic-version", "2023-06-01");
            }
        }
        // No credential exists; the catalog still answers only with the free-tier identity
        // headers (pinned opencode User-Agent included) applied by the same code the proxy uses.
        "opencode_free" => {
            let plan = provider_auth::resolve(provider_auth::OPENCODE_FREE_AUTH_MODE, false, None);
            let mut headers = reqwest::header::HeaderMap::new();
            provider_auth::apply_headers(&mut headers, &plan, "")
                .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
            req = req.headers(headers);
        }
        _ => unreachable!(),
    }
    let resp = req
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("fetch models: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("provider models endpoint returned {}", resp.status()),
        ));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ApiError::internal(format!("parse models response: {e}")))?;
    let models = parse_model_list(&body);
    Ok(Json(ModelListResponse {
        backend_id: id,
        backend_name: name,
        models,
    }))
}

/// Trạng thái catalog động của một backend (last-known, không gọi upstream): id model đang
/// biết, thời điểm fetch thành công gần nhất, kết quả lần fetch cuối. Cho Portal/debug.
#[derive(Serialize)]
struct BackendCatalogResponse {
    backend_id: i64,
    ids: Vec<String>,
    /// Epoch ms của lần fetch THÀNH CÔNG tạo ra `ids` (0 = chưa từng fetch thành công).
    fetched_at_ms: u64,
    /// Kết quả lần fetch cuối cùng (false giữ nguyên ids cũ).
    ok: bool,
    /// Backend có bật dynamic catalog không.
    dynamic_models: bool,
}

async fn backend_models_catalog(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<BackendCatalogResponse>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    let row = sqlx::query::<sqlx::Postgres>("SELECT dynamic_models FROM backends WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ApiError::not_found("backend not found"))?;
    let dynamic_models: bool = row.try_get("dynamic_models")?;
    let catalog = state.runtime.dynamic_catalogs.catalog(id);
    Ok(Json(BackendCatalogResponse {
        backend_id: id,
        ids: catalog
            .as_ref()
            .map(|c| c.model_ids.iter().cloned().collect())
            .unwrap_or_default(),
        fetched_at_ms: catalog.as_ref().map_or(0, |c| c.fetched_at_ms),
        ok: catalog.as_ref().is_some_and(|c| c.ok),
        dynamic_models,
    }))
}

/// Load models dùng credential từ body (KHÔNG persist). Cho route wizard "Load models" trước khi save.
async fn preview_models(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<PreviewModelsRequest>,
) -> Result<Json<ModelListResponse>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let base_url = non_empty_trimmed(payload.base_url, "base_url")?;
    let protocol = normalize_backend_format(&payload.protocol)?;
    let auth_mode = payload
        .auth_mode
        .as_deref()
        .unwrap_or("bearer")
        .trim()
        .to_string();
    let (key, oauth_account_id) = resolve_route_key(
        payload.provider_key.as_deref(),
        payload.provider_key_ref.as_deref(),
    )?;
    // Blank key cho auth bắt buộc -> chặn ngay (không gọi provider rồi dính 401/502).
    // `opencode_free` is credential-less like `none`: it carries its own identity headers.
    if !provider_auth::auth_mode_needs_no_key(&auth_mode) && key.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "provider key is required for this auth mode",
        ));
    }
    let url = join_provider_url(&base_url, "/v1/models");
    let mut req = state
        .runtime
        .client
        .get(url)
        .timeout(Duration::from_secs(15));
    let free_identity_headers = provider_auth::is_opencode_free_mode(&auth_mode);
    if !key.is_empty() || free_identity_headers {
        // Same plan the proxy will use, so a green preview means the real route works.
        let plan = provider_auth::resolve(
            &auth_mode,
            protocol == "anthropic",
            oauth_account_id.as_deref(),
        );
        let mut headers = reqwest::header::HeaderMap::new();
        provider_auth::apply_headers(&mut headers, &plan, &key)
            .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
        req = req.headers(headers);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("fetch models: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("provider models endpoint returned {}", resp.status()),
        ));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ApiError::internal(format!("parse models response: {e}")))?;
    let models = parse_model_list(&body);
    Ok(Json(ModelListResponse {
        backend_id: 0,
        backend_name: base_url,
        models,
    }))
}

// ===== Provider catalog (hard-coded trong .env) =====

fn parse_model_list(body: &serde_json::Value) -> Vec<String> {
    if let Some(items) = body.get("data").and_then(|v| v.as_array()) {
        return items
            .iter()
            .filter_map(|item| {
                item.get("id")
                    .or_else(|| item.get("name"))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
                    .or_else(|| item.as_str().map(str::to_owned))
            })
            .collect();
    }
    if let Some(items) = body.get("models").and_then(|v| v.as_array()) {
        return items
            .iter()
            .filter_map(|item| {
                item.get("id")
                    .or_else(|| item.get("name"))
                    .or_else(|| item.get("model"))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
                    .or_else(|| item.as_str().map(str::to_owned))
            })
            .collect();
    }
    Vec::new()
}

#[derive(Serialize)]
struct ProviderCatalogEntry {
    key: String,
    label: String,
    base_url: String,
    /// "openai" | "anthropic" — API dialect duy nhất mà router cần biết.
    dialect: String,
    /// Tên env var chứa key (vd OPENAI_API_KEY); rỗng = phải paste key thủ công.
    key_env: String,
    /// true nếu env var đã set giá trị (UI hiện "dùng key từ .env", không lộ plaintext).
    key_set: bool,
    /// false = "coming soon"/experimental (Gemini, Meta Muse) — hiển thị nhưng không chọn được.
    enabled: bool,
    /// true khi entry khớp một `OAuthProviderSpec` (key trùng `OAuthProviderSpec::key`).
    /// Portal thay ô nhập API key bằng nút "Connect account". Không thêm cột mới vào
    /// `PROVIDER_CATALOG`: suy ra từ key giữ format pipe cũ nguyên vẹn.
    oauth: bool,
    /// "pkce" | "device_code" — quyết định affordance nào Portal hiển thị.
    oauth_flow: Option<&'static str>,
    /// `auth_mode` mà route của credential này phải dùng.
    oauth_auth_mode: Option<&'static str>,
    /// Rủi ro bên thứ ba, hiển thị trước khi operator bắt đầu flow.
    oauth_risk_note: Option<&'static str>,
}

/// Danh sách provider cố định, hard-coded trong .env qua PROVIDER_CATALOG.
/// Định dạng mỗi entry: key|label|base_url|dialect|key_env|enabled(1/0), phân tách bằng ';'.
/// Chỉ 2 dialect (openai/anthropic); phần còn lại chỉ là base URL khác nhau của cùng 1 dialect.
/// OAuth metadata for a catalog key, or all-`None` for a plain API-key provider.
///
/// Derived from the key rather than stored in `PROVIDER_CATALOG`, so the existing pipe-delimited
/// format — and every deployment's `.env` — keep working unchanged.
struct OAuthCatalogHint {
    oauth: bool,
    flow: Option<&'static str>,
    auth_mode: Option<&'static str>,
    risk_note: Option<&'static str>,
}

fn oauth_hint(key: &str) -> OAuthCatalogHint {
    match oauth::spec(key) {
        Some(spec) => OAuthCatalogHint {
            oauth: true,
            flow: Some(match spec.flow {
                oauth::OAuthFlow::Pkce => "pkce",
                oauth::OAuthFlow::DeviceCode => "device_code",
            }),
            auth_mode: Some(spec.auth_mode),
            risk_note: Some(spec.risk_note),
        },
        None => OAuthCatalogHint {
            oauth: false,
            flow: None,
            auth_mode: None,
            risk_note: None,
        },
    }
}

fn provider_env_key_set(key_env: &str) -> bool {
    std::env::var(key_env)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
        || matches!(key_env, "QWEN_API_KEY")
            && std::env::var("DASHSCOPE_API_KEY")
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
        || matches!(key_env, "DASHSCOPE_API_KEY")
            && std::env::var("QWEN_API_KEY")
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
}

fn provider_catalog_from_env() -> Vec<ProviderCatalogEntry> {
    let raw = std::env::var("PROVIDER_CATALOG").unwrap_or_else(|_| {
        "openai|OpenAI|https://api.openai.com|openai|OPENAI_API_KEY|1;         anthropic|Anthropic|https://api.anthropic.com|anthropic|ANTHROPIC_API_KEY|1;         gemini|Gemini|https://generativelanguage.googleapis.com/v1beta/openai|openai|GEMINI_API_KEY|0;         deepseek|DeepSeek|https://api.deepseek.com|openai|DEEPSEEK_API_KEY|1;         kimi|Kimi|https://api.moonshot.ai/v1|openai|KIMI_API_KEY|1;         qwen|Qwen|https://dashscope-intl.aliyuncs.com/compatible-mode/v1|openai|QWEN_API_KEY|1;         zai|Z.AI|https://api.z.ai/api/paas/v4|openai|ZAI_API_KEY|1;         openrouter|OpenRouter|https://openrouter.ai/api/v1|openai|OPENROUTER_API_KEY|1;         jina|Jina AI|https://api.jina.ai|openai|JINA_API_KEY|1;         voyage|Voyage AI|https://api.voyageai.com|openai|VOYAGE_API_KEY|1;         cohere|Cohere|https://api.cohere.com/v2|openai|COHERE_API_KEY|1;         meta-muse|Meta Muse|https://api.meta.ai/v1|openai|META_MUSE_API_KEY|0;         custom-llm|Custom LLM|http://127.0.0.1:8088/v1|openai|CUSTOM_LLM_API_KEY|1;         ollaya|Ollaya System One|http://127.0.0.1:11435/v1|openai|OLLAYA_API_KEY|1"
            .to_string()
    });
    let mut entries: Vec<ProviderCatalogEntry> = raw
        .split(';')
        .filter_map(|part| {
            let mut it = part.split('|');
            let key = it.next()?.trim().to_string();
            let label = it.next()?.trim().to_string();
            let base_url = it.next()?.trim().to_string();
            let dialect = it.next()?.trim().to_string();
            let key_env = it.next().map(str::trim).unwrap_or("").to_string();
            let enabled = it.next().map(|v| v.trim() != "0").unwrap_or(true);
            if key.is_empty() || label.is_empty() {
                return None;
            }
            let key_set = if key_env.is_empty() {
                false
            } else {
                std::env::var(&key_env)
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false)
            };
            let hint = oauth_hint(&key);
            Some(ProviderCatalogEntry {
                dialect: if dialect == "anthropic" {
                    "anthropic".into()
                } else {
                    "openai".into()
                },
                key,
                label,
                base_url,
                key_env,
                key_set,
                enabled,
                oauth: hint.oauth,
                oauth_flow: hint.flow,
                oauth_auth_mode: hint.auth_mode,
                oauth_risk_note: hint.risk_note,
            })
        })
        .collect();
    let adapter_defaults = [
        ("jina", "Jina AI", "https://api.jina.ai", "JINA_API_KEY"),
        (
            "voyage",
            "Voyage AI",
            "https://api.voyageai.com",
            "VOYAGE_API_KEY",
        ),
        (
            "cohere",
            "Cohere",
            "https://api.cohere.com/v2",
            "COHERE_API_KEY",
        ),
    ];
    for (key, label, base_url, key_env) in adapter_defaults {
        if entries.iter().any(|e| e.key == key) {
            continue;
        }
        let key_set = provider_env_key_set(key_env);
        entries.push(ProviderCatalogEntry {
            key: key.to_string(),
            label: label.to_string(),
            base_url: base_url.to_string(),
            dialect: "openai".to_string(),
            key_env: key_env.to_string(),
            key_set,
            enabled: true,
            oauth: false,
            oauth_flow: None,
            oauth_auth_mode: None,
            oauth_risk_note: None,
        });
    }
    // OpenCode Zen free tier: credential-less chat provider. The `opencode_free` dialect marks
    // the backend so admin probes (Load models) send the free-tier identity headers; the route
    // wizard pairs it with auth_mode `opencode_free`.
    if !entries.iter().any(|e| e.key == "opencode-free") {
        entries.push(ProviderCatalogEntry {
            key: "opencode-free".to_string(),
            label: "OpenCode Free".to_string(),
            base_url: "https://opencode.ai/zen/v1".to_string(),
            dialect: "opencode_free".to_string(),
            key_env: String::new(),
            key_set: false,
            enabled: true,
            oauth: false,
            oauth_flow: None,
            oauth_auth_mode: None,
            oauth_risk_note: None,
        });
    }
    // OAuth providers are appended from the spec table rather than from PROVIDER_CATALOG, so
    // an operator upgrading the binary gets them without also editing their .env. The table is
    // the single source of truth; a catalog entry with the same key simply wins, so an operator
    // can still override the base URL (for example to point at a gateway).
    for spec in oauth::PROVIDERS {
        if entries.iter().any(|e| e.key == spec.key) {
            continue;
        }
        entries.push(ProviderCatalogEntry {
            key: spec.key.to_string(),
            label: spec.label.to_string(),
            base_url: spec.api_base_url.to_string(),
            // Claude speaks the Anthropic dialect; Codex and xAI speak OpenAI-compatible.
            dialect: if spec.auth_mode == provider_auth::OAUTH_AUTH_MODE_ANTHROPIC {
                "anthropic".to_string()
            } else {
                "openai".to_string()
            },
            // Empty: there is no env var holding a managed OAuth access token, so the Portal must
            // not claim a key is "already set in .env".
            key_env: String::new(),
            key_set: false,
            enabled: true,
            oauth: true,
            oauth_flow: Some(match spec.flow {
                oauth::OAuthFlow::Pkce => "pkce",
                oauth::OAuthFlow::DeviceCode => "device_code",
            }),
            oauth_auth_mode: Some(spec.auth_mode),
            oauth_risk_note: Some(spec.risk_note),
        });
    }
    entries
}

async fn list_provider_catalog(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProviderCatalogEntry>>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    Ok(Json(provider_catalog_from_env()))
}

// ===== Provider registry (compiled-in catalog of provider types) =====

/// Catalog các provider type đã biết (src/provider_registry.rs) cho UI dropdown: mỗi entry
/// nói backend của loại đó cần base_url/protocol/auth_mode gì, để caller chỉ gửi
/// `provider_type + credential`. Khác `/provider-catalog` (preset Portal từ .env): bảng này
/// là nguồn chân lý cho derivation lúc tạo backend + load config.
async fn list_providers(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<&'static [ProviderType]>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    Ok(Json(provider_registry::list()))
}

// ===== Test connection =====

/// Resolve key cho preview/test/route: plaintext ưu tiên; nếu không có thì resolve ref
/// (env:/file:/oauth:).
///
/// Returns the access token plus the OAuth account id, which Codex requires on every request.
fn resolve_route_key(
    plain: Option<&str>,
    r#ref: Option<&str>,
) -> Result<(String, Option<String>), ApiError> {
    if let Some(p) = plain.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok((p.to_string(), None));
    }
    if let Some(r) = r#ref.map(str::trim).filter(|s| !s.is_empty()) {
        if oauth::parse_credential_ref(r).is_some() {
            let (key, account) =
                oauth::resolve_route_credential(&oauth::OAuthTokenStore::from_env(), r);
            let key = key.ok_or_else(|| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    format!("cannot resolve OAuth credential reference: {r}"),
                )
            })?;
            return Ok((key, account));
        }
        return resolve_backend_key(r).map(|k| (k, None)).ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("cannot resolve provider key reference: {r}"),
            )
        });
    }
    Ok((String::new(), None))
}

#[derive(Deserialize)]
struct TestConnectionRequest {
    base_url: String,
    /// "openai" | "anthropic"
    dialect: String,
    /// "bearer" | "anthropic" | "none"
    auth_mode: String,
    provider_key: Option<String>,
    provider_key_ref: Option<String>,
    provider_model_name: Option<String>,
    /// Route protocol to test. Defaults to old chat behavior for backward compatibility.
    protocol: Option<String>,
}

#[derive(Serialize)]
struct TestConnectionResponse {
    ok: bool,
    latency_ms: u64,
    status: u16,
    model_ok: Option<bool>,
    error: Option<String>,
    detail: Option<String>,
}

/// Attach the route's credential to a probe request.
///
/// Goes through `provider_auth::apply_headers` — the same function the proxy uses — so a green
/// "Test connection" proves the real upstream request carries an identical credential and the
/// identical credential-scoped provider headers (`anthropic-beta`, `chatgpt-account-id`). The
/// OpenCode free mode has no credential: it skips the empty-key shortcut so its fixed identity
/// headers still reach the probe.
fn add_provider_auth(
    req: reqwest::RequestBuilder,
    plan: &provider_auth::AuthPlan<'_>,
    key: &str,
) -> Result<reqwest::RequestBuilder, String> {
    if key.is_empty() && plan.mode != provider_auth::HeaderMode::OpenCodeFree {
        return Ok(req);
    }
    let mut headers = reqwest::header::HeaderMap::new();
    provider_auth::apply_headers(&mut headers, plan, key)?;
    Ok(req.headers(headers))
}

async fn post_json_probe(
    state: &Arc<AdminState>,
    base_url: &str,
    route: &str,
    plan: &provider_auth::AuthPlan<'_>,
    key: &str,
    body: serde_json::Value,
    timeout_secs: u64,
) -> Result<(u16, Option<serde_json::Value>), String> {
    let url = join_provider_url(base_url, route);
    let req = state
        .runtime
        .client
        .post(url)
        .timeout(Duration::from_secs(timeout_secs))
        .json(&body);
    let resp = add_provider_auth(req, plan, key)?
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let json = resp.json::<serde_json::Value>().await.ok();
    Ok((status, json))
}

/// 1-token chat/messages probe to prove key + model really work.
async fn test_chat_completion(
    state: &Arc<AdminState>,
    base_url: &str,
    dialect: &str,
    plan: &provider_auth::AuthPlan<'_>,
    key: &str,
    model: &str,
) -> Result<(u16, Option<serde_json::Value>), String> {
    let anthropic = dialect == "anthropic";
    let route = if anthropic {
        "/v1/messages"
    } else {
        "/v1/chat/completions"
    };
    let body = if anthropic {
        serde_json::json!({"model": model, "max_tokens": 1, "messages": [{"role":"user","content":"ping"}]})
    } else if plan.mode == provider_auth::HeaderMode::OpenCodeFree {
        // The free tier 403s non-streaming bodies, so the probe must stream too. A 200 then
        // arrives as SSE; the JSON parse yields None and the probe still reports success.
        serde_json::json!({"model": model, "max_tokens": 1, "stream": true, "messages": [{"role":"user","content":"ping"}]})
    } else {
        serde_json::json!({"model": model, "max_tokens": 1, "stream": false, "messages": [{"role":"user","content":"ping"}]})
    };
    post_json_probe(state, base_url, route, plan, key, body, 20).await
}

async fn test_text_completion(
    state: &Arc<AdminState>,
    base_url: &str,
    plan: &provider_auth::AuthPlan<'_>,
    key: &str,
    model: &str,
) -> Result<(u16, Option<serde_json::Value>), String> {
    let body = serde_json::json!({
        "model": model,
        "prompt": "ping",
        "max_tokens": 1,
        "stream": false
    });
    post_json_probe(state, base_url, "/v1/completions", plan, key, body, 20).await
}

async fn test_responses(
    state: &Arc<AdminState>,
    base_url: &str,
    plan: &provider_auth::AuthPlan<'_>,
    key: &str,
    model: &str,
) -> Result<(u16, Option<serde_json::Value>), String> {
    let body = serde_json::json!({
        "model": model,
        "input": "ping",
        "max_output_tokens": 1,
        "stream": false
    });
    post_json_probe(state, base_url, "/v1/responses", plan, key, body, 20).await
}

async fn test_embedding(
    state: &Arc<AdminState>,
    base_url: &str,
    plan: &provider_auth::AuthPlan<'_>,
    key: &str,
    model: &str,
) -> Result<(u16, bool, String), String> {
    let mut body = serde_json::json!({
        "model": model,
        "input": "BrighTO-Router adapter smoke test"
    });
    let lower = base_url.to_ascii_lowercase();
    if lower.contains("voyageai") {
        body["input_type"] = serde_json::Value::String("document".to_string());
    }
    if lower.contains("jina.ai") {
        body["normalized"] = serde_json::Value::Bool(true);
        body["embedding_type"] = serde_json::Value::String("float".to_string());
    }
    let (status, data) =
        post_json_probe(state, base_url, "/v1/embeddings", plan, key, body, 30).await?;
    let dim = data
        .as_ref()
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_array())
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("embedding"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    Ok((
        status,
        status < 400 && dim > 0,
        format!("embedding dim {dim}"),
    ))
}

fn qwen_rerank_probe(model: &str) -> (&'static str, serde_json::Value) {
    if model.trim().eq_ignore_ascii_case("qwen3-rerank") {
        return (
            "/compatible-api/v1/reranks",
            serde_json::json!({
                "model": model,
                "query": "fast Rust AI router",
                "documents": [
                    "BrighTO-Router is an ultra-fast Rust gateway for model routing.",
                    "Bananas are yellow fruit and unrelated to API gateways.",
                    "Rerankers improve retrieval quality by scoring candidate documents."
                ],
                "top_n": 2
            }),
        );
    }
    (
        "/api/v1/services/rerank/text-rerank/text-rerank",
        serde_json::json!({
            "model": model,
            "input": {
                "query": "fast Rust AI router",
                "documents": [
                    "BrighTO-Router is an ultra-fast Rust gateway for model routing.",
                    "Bananas are yellow fruit and unrelated to API gateways.",
                    "Rerankers improve retrieval quality by scoring candidate documents."
                ]
            },
            "parameters": {"top_n": 2}
        }),
    )
}

async fn test_rerank(
    state: &Arc<AdminState>,
    base_url: &str,
    plan: &provider_auth::AuthPlan<'_>,
    key: &str,
    model: &str,
    protocol: ProviderProtocol,
) -> Result<(u16, bool, String), String> {
    let (route, body) = if protocol == ProviderProtocol::QwenRerank {
        qwen_rerank_probe(model)
    } else {
        let mut body = serde_json::json!({
            "model": model,
            "query": "fast Rust AI router",
            "documents": [
                "BrighTO-Router is an ultra-fast Rust gateway for model routing.",
                "Bananas are yellow fruit and unrelated to API gateways.",
                "Rerankers improve retrieval quality by scoring candidate documents."
            ]
        });
        if protocol == ProviderProtocol::VoyageRerank {
            body["top_k"] = serde_json::Value::Number(2.into());
        } else {
            body["top_n"] = serde_json::Value::Number(2.into());
        }
        ("/v1/rerank", body)
    };
    let (status, data) = post_json_probe(state, base_url, route, plan, key, body, 30).await?;
    let results = data
        .as_ref()
        .and_then(|v| {
            v.get("results")
                .or_else(|| v.get("data"))
                .or_else(|| v.get("output").and_then(|o| o.get("results")))
        })
        .and_then(|v| v.as_array());
    let count = results.map(|r| r.len()).unwrap_or(0);
    let first_ok = results
        .and_then(|r| r.first())
        .and_then(|v| v.as_object())
        .map(|o| {
            o.get("index").is_some()
                && (o.get("relevance_score").is_some() || o.get("score").is_some())
        })
        .unwrap_or(false);
    Ok((
        status,
        status < 400 && first_ok,
        format!("rerank results {count}"),
    ))
}

async fn test_systemone(
    state: &Arc<AdminState>,
    base_url: &str,
    plan: &provider_auth::AuthPlan<'_>,
    key: &str,
    model: &str,
) -> Result<(u16, bool, String), String> {
    let body = serde_json::json!({
        "model": model,
        "state": {"message": "I was charged twice for one order."},
        "questions": {
            "duplicate_charge": {
                "type": "noul",
                "instructions": "Does the message report a duplicate charge?"
            },
            "team": {
                "type": "choice",
                "instructions": "Which team should handle this?",
                "criteria": {"billing": "payments and refunds", "support": "technical help"}
            }
        }
    });
    let (status, data) =
        post_json_probe(state, base_url, "/v1/systemone", plan, key, body, 30).await?;
    let answers = data
        .as_ref()
        .and_then(|v| v.get("answers"))
        .and_then(|v| v.as_object());
    let count = answers.map(|a| a.len()).unwrap_or(0);
    Ok((
        status,
        status < 400 && count > 0,
        format!("systemone answers {count}"),
    ))
}

async fn test_asr(
    state: &Arc<AdminState>,
    base_url: &str,
    plan: &provider_auth::AuthPlan<'_>,
    key: &str,
    model: &str,
) -> Result<(u16, bool, String), String> {
    const ASR_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/asr_smoke.wav");
    let boundary = "----brighto-router-asr-test-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n{model}\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"asr_smoke.wav\"\r\nContent-Type: audio/wav\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(ASR_FIXTURE);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let url = join_provider_url(base_url, "/v1/audio/transcriptions");
    let req = state
        .runtime
        .client
        .post(url)
        .timeout(Duration::from_secs(45))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body);
    let resp = add_provider_auth(req, plan, key)?
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let data = resp.json::<serde_json::Value>().await.ok();
    let text_len = data
        .as_ref()
        .and_then(|v| v.get("text"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().chars().count())
        .unwrap_or(0);
    Ok((
        status,
        status < 400 && text_len > 0,
        format!("transcript chars {text_len}"),
    ))
}

/// Test connection with the exact endpoint shape used by the selected route protocol.
/// UI only enables "Save enabled" when this returns ok=true.
async fn test_connection(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<TestConnectionRequest>,
) -> Result<Json<TestConnectionResponse>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let base_url = non_empty_trimmed(payload.base_url, "base_url")?;
    let dialect = normalize_backend_format(&payload.dialect)?;
    let auth_mode = parse_auth_mode(payload.auth_mode.trim())
        .map(str::to_string)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                format!(
                    "auth_mode must be one of {}, got: {}",
                    provider_auth::AUTH_MODES.join(", "),
                    payload.auth_mode.trim()
                ),
            )
        })?;
    let (key, oauth_account_id) = resolve_route_key(
        payload.provider_key.as_deref(),
        payload.provider_key_ref.as_deref(),
    )?;
    // The OpenCode free tier needs no key (it carries its own identity headers), like `none`.
    if !provider_auth::auth_mode_needs_no_key(&auth_mode) && key.is_empty() {
        return Ok(Json(TestConnectionResponse {
            ok: false,
            latency_ms: 0,
            status: 0,
            model_ok: None,
            error: Some("provider key is required for this auth mode".to_string()),
            detail: None,
        }));
    }
    let model = payload
        .provider_model_name
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "provider_model_name is required"))?;
    let protocol = payload
        .protocol
        .as_deref()
        .map(ProviderProtocol::parse)
        .unwrap_or_else(|| {
            if dialect == "anthropic" {
                ProviderProtocol::AnthropicMessages
            } else {
                ProviderProtocol::OpenAiChat
            }
        });
    let started = std::time::Instant::now();
    // Same plan the proxy will build for this route, so a green probe is evidence the route will
    // serve traffic — not just that the base URL answers.
    let plan = provider_auth::resolve(
        &auth_mode,
        dialect == "anthropic",
        oauth_account_id.as_deref(),
    );
    let tested = match protocol {
        ProviderProtocol::OpenAiResponses | ProviderProtocol::CodexResponses => {
            test_responses(&state, &base_url, &plan, &key, model)
                .await
                .map(|(status, _)| (status, status < 400, "responses OK".to_string()))
        }
        ProviderProtocol::OpenAiCompletions => {
            test_text_completion(&state, &base_url, &plan, &key, model)
                .await
                .map(|(status, _)| (status, status < 400, "completions OK".to_string()))
        }
        ProviderProtocol::OpenAiEmbeddings => {
            test_embedding(&state, &base_url, &plan, &key, model).await
        }
        ProviderProtocol::OpenAiRerank
        | ProviderProtocol::QwenRerank
        | ProviderProtocol::CohereRerank
        | ProviderProtocol::VoyageRerank
        | ProviderProtocol::JinaRerank => {
            test_rerank(&state, &base_url, &plan, &key, model, protocol).await
        }
        ProviderProtocol::OpenAiAudioTranscriptions => {
            test_asr(&state, &base_url, &plan, &key, model).await
        }
        ProviderProtocol::SystemOne => test_systemone(&state, &base_url, &plan, &key, model).await,
        _ => test_chat_completion(&state, &base_url, dialect, &plan, &key, model)
            .await
            .map(|(status, _)| (status, status < 400, "chat/messages OK".to_string())),
    };
    let latency_ms = started.elapsed().as_millis() as u64;
    match tested {
        Ok((status, ok, detail)) => Ok(Json(TestConnectionResponse {
            ok,
            latency_ms,
            status,
            model_ok: Some(ok),
            error: if ok {
                None
            } else {
                Some(format!(
                    "endpoint returned HTTP {status}; check base URL, key, model, and task type"
                ))
            },
            detail: Some(detail),
        })),
        Err(e) => Ok(Json(TestConnectionResponse {
            ok: false,
            latency_ms,
            status: 0,
            model_ok: None,
            error: Some(e),
            detail: None,
        })),
    }
}

async fn list_routes(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Vec<RouteResponse>>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    Ok(Json(list_routes_from_pool(pool).await?))
}

struct ValidatedRoute {
    model_name: String,
    backend_ids: Vec<i64>,
    backend_ids_json: String,
    fallback_backend_id: Option<i64>,
    chars_per_token: f64,
    first_byte_timeout: u64,
    provider_model_name: String,
    context_tokens: Option<i64>,
    max_output_tokens: Option<i64>,
    price_input_per_mtok_usd: Option<f64>,
    price_output_per_mtok_usd: Option<f64>,
    enabled: bool,
    provider_key_ref: Option<String>,
    auth_mode: String,
    protocol: String,
    routing_policy: RoutingPolicy,
    passthrough: bool,
    endpoints: Option<Vec<ValidatedRouteEndpoint>>,
}

/// Passthrough routes define the wire for every model they match, so the protocol must be one
/// the router forwards generically: a chat-family or responses-family protocol. Rerank/ASR/
/// embeddings/systemone shapes need per-model knowledge and stay explicit-route-only.
fn is_passthrough_protocol(protocol: &str) -> bool {
    matches!(
        ProviderProtocol::parse(protocol),
        ProviderProtocol::OpenAiChat
            | ProviderProtocol::LocalOpenAiChat
            | ProviderProtocol::CustomOpenAiChat
            | ProviderProtocol::OpenAiResponses
            | ProviderProtocol::CodexResponses
    )
}

fn protocol_family(protocol: &str) -> &'static str {
    match ProviderProtocol::parse(protocol) {
        ProviderProtocol::OpenAiChat
        | ProviderProtocol::LocalOpenAiChat
        | ProviderProtocol::CustomOpenAiChat => "openai_chat",
        ProviderProtocol::OpenAiResponses => "openai_responses",
        ProviderProtocol::OpenAiCompletions => "openai_completions",
        ProviderProtocol::OpenAiEmbeddings => "openai_embeddings",
        ProviderProtocol::OpenAiRerank
        | ProviderProtocol::QwenRerank
        | ProviderProtocol::CohereRerank
        | ProviderProtocol::VoyageRerank
        | ProviderProtocol::JinaRerank => "rerank",
        ProviderProtocol::OpenAiAudioTranscriptions => "openai_audio_transcriptions",
        ProviderProtocol::SystemOne => "systemone",
        ProviderProtocol::AnthropicMessages => "anthropic_messages",
        // Same client-facing wire shape as OpenAI Responses, so a Model Group endpoint may sit on
        // either; the difference is the upstream path and the account header.
        ProviderProtocol::CodexResponses => "openai_responses",
    }
}

fn validate_key_ref(value: &str) -> Result<String, ApiError> {
    let r = value.trim();
    if r.starts_with("oauth:") {
        return validate_oauth_key_ref(r);
    }
    if !(r.starts_with("env:") || r.starts_with("file:")) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "provider_key_ref must be env:NAME, file:/path or oauth:<provider>:<account>",
        ));
    }
    Ok(r.to_string())
}

/// An `oauth:` reference must name a provider this build knows about, otherwise the route would
/// load with no credential and fail every request with an opaque 401.
fn validate_oauth_key_ref(reference: &str) -> Result<String, ApiError> {
    let Some((provider, label)) = oauth::parse_credential_ref(reference) else {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "oauth provider_key_ref must be oauth:<provider>:<account>",
        ));
    };
    if oauth::spec(provider).is_none() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!(
                "unknown OAuth provider '{provider}'; known providers: {}",
                oauth::PROVIDERS
                    .iter()
                    .map(|s| s.key)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    if oauth::OAuthTokenStore::from_env()
        .read(provider, label)
        .is_err()
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!(
                "no connected OAuth account '{label}' for provider '{provider}'; \
                 connect it first via POST /admin/oauth/{provider}/start"
            ),
        ));
    }
    Ok(reference.to_string())
}

fn write_route_endpoint_key_file(
    model_name: &str,
    backend_id: i64,
    key: &str,
) -> Result<String, ApiError> {
    let data_dir =
        std::env::var("DATA_DIR").unwrap_or_else(|_| "/var/lib/brighto-router".to_string());
    let dir = std::path::Path::new(&data_dir).join("provider_keys");
    let file = format!(
        "route_{}_backend_{}.key",
        hex_encode(&Sha256::digest(model_name.as_bytes())),
        backend_id
    );
    let path = dir.join(&file);
    write_provider_key_file(&path, key)?;
    Ok(format!("file:{}", path.display()))
}

fn validate_route(payload: UpsertRoute) -> Result<ValidatedRoute, ApiError> {
    let model_name = non_empty_trimmed(payload.model_name, "model_name")?;
    if payload.backend_ids.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "backend_ids must not be empty",
        ));
    }
    if payload.backend_ids.iter().any(|id| *id <= 0) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "backend_ids must be positive integers",
        ));
    }
    let chars_per_token = payload.chars_per_token.unwrap_or(4.0);
    if !chars_per_token.is_finite() || chars_per_token <= 0.0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "chars_per_token must be greater than zero",
        ));
    }
    let first_byte_timeout = payload.first_byte_timeout.unwrap_or(180);
    if first_byte_timeout == 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "first_byte_timeout must be greater than zero",
        ));
    }
    if let Some(p) = payload.price_input_per_mtok_usd
        && (p < 0.0 || !p.is_finite())
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "price_input_per_mtok_usd must be zero or positive",
        ));
    }
    if let Some(p) = payload.price_output_per_mtok_usd
        && (p < 0.0 || !p.is_finite())
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "price_output_per_mtok_usd must be zero or positive",
        ));
    }
    let provider_model_name = payload
        .provider_model_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| model_name.clone());
    let enabled = payload.enabled.unwrap_or(true);
    let auth_mode = match parse_auth_mode(payload.auth_mode.as_deref().unwrap_or("bearer")) {
        Some(m) => m.to_string(),
        None => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!(
                    "auth_mode must be one of {}, got: {}",
                    provider_auth::AUTH_MODES.join(", "),
                    payload.auth_mode.as_deref().unwrap_or("bearer").trim()
                ),
            ));
        }
    };
    // Route-level protocol (CODEX taxonomy). Default: anthropic auth -> anthropic_messages,
    // OAuth auth -> provider's own protocol, ngược lại openai_chat. Client có thể ghi đè
    // tường minh.
    let protocol = match payload
        .protocol
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(p) => ProviderProtocol::parse(p).as_str().to_string(),
        None => match oauth::spec_for_auth_mode(&auth_mode) {
            Some(spec) => spec.protocol.to_string(),
            None if auth_mode == "anthropic" => "anthropic_messages".to_string(),
            None => "openai_chat".to_string(),
        },
    };
    // Passthrough: đúng 1 backend, không fallback, không group endpoints, không cần
    // provider_model_name (model client gọi chính là provider model khi match), protocol
    // phải thuộc chat/responses family vì nó định nghĩa wire cho mọi model được match.
    let passthrough = payload.passthrough.unwrap_or(false);
    if passthrough {
        if payload.backend_ids.len() != 1 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "passthrough route must have exactly one backend_id",
            ));
        }
        if payload.fallback_backend_id.is_some() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "passthrough route must not set fallback_backend_id",
            ));
        }
        if payload
            .endpoints
            .as_ref()
            .is_some_and(|endpoints| !endpoints.is_empty())
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "passthrough route must not declare group endpoints",
            ));
        }
        if !is_passthrough_protocol(&protocol) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!(
                    "passthrough route protocol must be a chat-family or responses-family \
                     protocol (e.g. openai_chat, openai_responses), got: {protocol}"
                ),
            ));
        }
    }
    // Ghi provider key (plaintext) ra file secrets nếu được cung cấp; chỉ lưu ref.
    let provider_key_ref = match payload
        .provider_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(key) => {
            if provider_auth::is_opencode_free_mode(&auth_mode) {
                // The free tier has no credential slot: a pasted key would be silently ignored
                // by the header plan, so reject it instead of storing a secret that does nothing.
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "provider key must be empty when auth_mode is opencode_free",
                ));
            }
            if auth_mode == "none" {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "provider key must be empty when auth_mode is none",
                ));
            }
            if provider_auth::is_oauth_mode(&auth_mode) {
                // A pasted OAuth access token expires within the hour and the router has no
                // refresh token to renew it. Accepting one would produce a route that works
                // briefly and then fails every request.
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "auth_mode {auth_mode} needs a connected OAuth account, not a pasted key; \
                         use provider_key_ref oauth:<provider>:<account>"
                    ),
                ));
            }
            let data_dir =
                std::env::var("DATA_DIR").unwrap_or_else(|_| "/var/lib/brighto-router".to_string());
            let dir = std::path::Path::new(&data_dir).join("provider_keys");
            let file = format!(
                "route_{}.key",
                hex_encode(&Sha256::digest(model_name.as_bytes()))
            );
            let path = dir.join(&file);
            write_provider_key_file(&path, key)?;
            Some(format!("file:{}", path.display()))
        }
        None => match payload
            .provider_key_ref
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(r) => Some(validate_key_ref(r)?),
            None => None,
        },
    };
    let routing_policy = RoutingPolicy::parse(
        payload
            .routing_policy
            .as_deref()
            .unwrap_or("least_loaded_weighted"),
    );

    let endpoints = match payload.endpoints {
        Some(items) => {
            let mut seen = HashSet::new();
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                if item.backend_id <= 0 {
                    return Err(ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "endpoint backend_id must be positive",
                    ));
                }
                if !payload.backend_ids.contains(&item.backend_id) {
                    return Err(ApiError::new(
                        StatusCode::BAD_REQUEST,
                        format!(
                            "endpoint backend_id {} must be listed in backend_ids",
                            item.backend_id
                        ),
                    ));
                }
                if !seen.insert(item.backend_id) {
                    return Err(ApiError::new(
                        StatusCode::BAD_REQUEST,
                        format!("duplicate endpoint backend_id {}", item.backend_id),
                    ));
                }
                let endpoint_auth =
                    match parse_auth_mode(item.auth_mode.as_deref().unwrap_or(&auth_mode).trim()) {
                        Some(m) => m.to_string(),
                        None => {
                            return Err(ApiError::new(
                                StatusCode::BAD_REQUEST,
                                format!(
                                    "endpoint auth_mode must be one of {}, got: {}",
                                    provider_auth::AUTH_MODES.join(", "),
                                    item.auth_mode.as_deref().unwrap_or(&auth_mode).trim()
                                ),
                            ));
                        }
                    };
                let endpoint_protocol = item
                    .protocol
                    .as_deref()
                    .map(ProviderProtocol::parse)
                    .unwrap_or_else(|| ProviderProtocol::parse(&protocol))
                    .as_str()
                    .to_string();
                if protocol_family(&endpoint_protocol) != protocol_family(&protocol) {
                    return Err(ApiError::new(
                        StatusCode::BAD_REQUEST,
                        format!(
                            "endpoint protocol {} is not compatible with group protocol {}",
                            endpoint_protocol, protocol
                        ),
                    ));
                }
                let endpoint_key_ref = match item
                    .provider_key
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    Some(key) => {
                        if provider_auth::is_opencode_free_mode(&endpoint_auth) {
                            return Err(ApiError::new(
                                StatusCode::BAD_REQUEST,
                                "endpoint provider key must be empty when auth_mode is \
                                 opencode_free",
                            ));
                        }
                        if endpoint_auth == "none" {
                            return Err(ApiError::new(
                                StatusCode::BAD_REQUEST,
                                "endpoint provider key must be empty when auth_mode is none",
                            ));
                        }
                        if provider_auth::is_oauth_mode(&endpoint_auth) {
                            return Err(ApiError::new(
                                StatusCode::BAD_REQUEST,
                                format!(
                                    "auth_mode {endpoint_auth} needs a connected OAuth account, \
                                     not a pasted key; use provider_key_ref \
                                     oauth:<provider>:<account>"
                                ),
                            ));
                        }
                        Some(write_route_endpoint_key_file(
                            &model_name,
                            item.backend_id,
                            key,
                        )?)
                    }
                    None => match item
                        .provider_key_ref
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        Some(r) => Some(validate_key_ref(r)?),
                        None => None,
                    },
                };
                out.push(ValidatedRouteEndpoint {
                    backend_id: item.backend_id,
                    provider_model_name: item
                        .provider_model_name
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| provider_model_name.clone()),
                    provider_key_ref: endpoint_key_ref,
                    auth_mode: endpoint_auth,
                    protocol: endpoint_protocol,
                    weight: item.weight.unwrap_or(1).max(1),
                    max_inflight: item.max_inflight.unwrap_or(0),
                    enabled: item.enabled.unwrap_or(true),
                });
            }
            Some(out)
        }
        None => None,
    };

    let backend_ids_json = serde_json::to_string(&payload.backend_ids)?;
    Ok(ValidatedRoute {
        model_name,
        backend_ids: payload.backend_ids,
        backend_ids_json,
        fallback_backend_id: payload.fallback_backend_id,
        chars_per_token,
        first_byte_timeout,
        provider_model_name,
        context_tokens: payload.context_tokens,
        max_output_tokens: payload.max_output_tokens,
        price_input_per_mtok_usd: payload.price_input_per_mtok_usd,
        price_output_per_mtok_usd: payload.price_output_per_mtok_usd,
        enabled,
        provider_key_ref,
        auth_mode,
        protocol,
        routing_policy,
        passthrough,
        endpoints,
    })
}

fn route_response(v: ValidatedRoute) -> RouteResponse {
    RouteResponse {
        model_name: v.model_name,
        backend_ids: v.backend_ids,
        fallback_backend_id: v.fallback_backend_id,
        chars_per_token: v.chars_per_token,
        first_byte_timeout: v.first_byte_timeout,
        provider_model_name: v.provider_model_name,
        context_tokens: v.context_tokens,
        max_output_tokens: v.max_output_tokens,
        price_input_per_mtok_usd: v.price_input_per_mtok_usd,
        price_output_per_mtok_usd: v.price_output_per_mtok_usd,
        enabled: v.enabled,
        provider_key_ref: v.provider_key_ref,
        auth_mode: v.auth_mode,
        protocol: v.protocol,
        routing_policy: v.routing_policy.as_str().to_string(),
        passthrough: v.passthrough,
        endpoints: v
            .endpoints
            .unwrap_or_default()
            .into_iter()
            .map(|e| RouteEndpointResponse {
                backend_id: e.backend_id,
                provider_model_name: e.provider_model_name,
                provider_key_ref: e.provider_key_ref,
                auth_mode: e.auth_mode,
                protocol: e.protocol,
                weight: e.weight,
                max_inflight: e.max_inflight,
                enabled: e.enabled,
            })
            .collect(),
        effective_enabled: v.enabled,
        disabled_reason: None,
        usage_count: 0,
        can_delete: true,
    }
}

/// Kích hoạt provider endpoints được route tham chiếu khi route được lưu/toggle sang enabled.
/// Seed templates ship disabled; một model route đã test "sử dụng" chúng, nên lưu route enabled
/// phải bật provider endpoint tương ứng (đúng intent trong scripts/seed_defaults.sql).
async fn enable_referenced_backends(
    pool: &sqlx::PgPool,
    backend_ids: &[i64],
    fallback_backend_id: Option<i64>,
) -> Result<(), ApiError> {
    for id in backend_ids.iter().chain(fallback_backend_id.iter()) {
        sqlx::query::<sqlx::Postgres>("UPDATE backends SET enabled = true WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn replace_route_endpoints(
    pool: &sqlx::PgPool,
    model_name: &str,
    endpoints: Option<&[ValidatedRouteEndpoint]>,
) -> Result<(), ApiError> {
    let Some(endpoints) = endpoints else {
        return Ok(());
    };
    sqlx::query::<sqlx::Postgres>("DELETE FROM model_route_endpoints WHERE model_name = $1")
        .bind(model_name)
        .execute(pool)
        .await?;
    for endpoint in endpoints {
        sqlx::query::<sqlx::Postgres>(
            "INSERT INTO model_route_endpoints \
             (model_name, backend_id, provider_model_name, provider_key_ref, auth_mode, protocol, weight, max_inflight, enabled) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(model_name)
        .bind(endpoint.backend_id)
        .bind(&endpoint.provider_model_name)
        .bind(&endpoint.provider_key_ref)
        .bind(&endpoint.auth_mode)
        .bind(&endpoint.protocol)
        .bind(endpoint.weight as i64)
        .bind(endpoint.max_inflight as i64)
        .bind(endpoint.enabled)
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn upsert_route(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<UpsertRoute>,
) -> Result<Json<RouteResponse>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let requested_name = non_empty_trimmed(payload.model_name.clone(), "model_name")?;
    let pool = state.pool().await?;
    if sqlx::query::<sqlx::Postgres>("SELECT 1 FROM model_routes WHERE model_name = $1")
        .bind(&requested_name)
        .fetch_optional(pool)
        .await?
        .is_some()
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "API model name already exists; model routes and Model Groups share one client-facing namespace",
        ));
    }
    let v = validate_route(payload)?;
    sqlx::query::<sqlx::Postgres>(
        "INSERT INTO model_routes (model_name, backend_ids, fallback_backend_id, chars_per_token, first_byte_timeout, \
         provider_model_name, context_tokens, max_output_tokens, \
         price_input_per_mtok_usd, price_output_per_mtok_usd, enabled, provider_key_ref, auth_mode, protocol, routing_policy, passthrough) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
    )
    .bind(&v.model_name)
    .bind(&v.backend_ids_json)
    .bind(v.fallback_backend_id)
    .bind(v.chars_per_token)
    .bind(v.first_byte_timeout as i64)
    .bind(&v.provider_model_name)
    .bind(v.context_tokens)
    .bind(v.max_output_tokens)
    .bind(v.price_input_per_mtok_usd)
    .bind(v.price_output_per_mtok_usd)
    .bind(v.enabled)
    .bind(&v.provider_key_ref)
    .bind(&v.auth_mode)
    .bind(&v.protocol)
    .bind(v.routing_policy.as_str())
    .bind(v.passthrough)
    .execute(pool)
    .await?;
    replace_route_endpoints(pool, &v.model_name, v.endpoints.as_deref()).await?;
    // Provider templates ship disabled; a tested route saved as enabled must activate them.
    if v.enabled {
        enable_referenced_backends(pool, &v.backend_ids, v.fallback_backend_id).await?;
    }
    state.reload_now().await?;
    Ok(Json(route_response(v)))
}

/// Cập nhật route theo model_name CŨ (path param), cho phép đổi tên public model.
/// 404 nếu route cũ không tồn tại; 409 nếu tên mới đã thuộc route khác.
async fn patch_route(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(old_name): Path<String>,
    Json(payload): Json<UpsertRoute>,
) -> Result<Json<RouteResponse>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let v = validate_route(payload)?;
    let pool = state.pool().await?;
    if v.model_name != old_name {
        let exists =
            sqlx::query::<sqlx::Postgres>("SELECT 1 FROM model_routes WHERE model_name = $1")
                .bind(&v.model_name)
                .fetch_optional(pool)
                .await?
                .is_some();
        if exists {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "API model name already exists",
            ));
        }
        // Block rename if the public model has usage history (audit identity).
        let usage: i64 = sqlx::query::<sqlx::Postgres>(
            "SELECT COUNT(*) AS c FROM usage_ledger WHERE model = $1",
        )
        .bind(&old_name)
        .fetch_one(pool)
        .await?
        .try_get("c")?;
        if usage > 0 {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "model has transaction history; renaming is not allowed",
            ));
        }
    }
    let result = sqlx::query::<sqlx::Postgres>(
        "UPDATE model_routes SET model_name = $1, backend_ids = $2, fallback_backend_id = $3, \
         chars_per_token = $4, first_byte_timeout = $5, provider_model_name = $6, \
         context_tokens = $7, max_output_tokens = $8, price_input_per_mtok_usd = $9, \
         price_output_per_mtok_usd = $10, enabled = $11, \
         provider_key_ref = COALESCE($12, provider_key_ref), auth_mode = $13, \
         protocol = $14, routing_policy = $15, passthrough = $16 WHERE model_name = $17",
    )
    .bind(&v.model_name)
    .bind(&v.backend_ids_json)
    .bind(v.fallback_backend_id)
    .bind(v.chars_per_token)
    .bind(v.first_byte_timeout as i64)
    .bind(&v.provider_model_name)
    .bind(v.context_tokens)
    .bind(v.max_output_tokens)
    .bind(v.price_input_per_mtok_usd)
    .bind(v.price_output_per_mtok_usd)
    .bind(v.enabled)
    .bind(&v.provider_key_ref)
    .bind(&v.auth_mode)
    .bind(&v.protocol)
    .bind(v.routing_policy.as_str())
    .bind(v.passthrough)
    .bind(&old_name)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("route not found"));
    }
    replace_route_endpoints(pool, &v.model_name, v.endpoints.as_deref()).await?;
    // Kích hoạt provider endpoints khi lưu route enabled (giống upsert_route).
    if v.enabled {
        enable_referenced_backends(pool, &v.backend_ids, v.fallback_backend_id).await?;
    }
    state.reload_now().await?;
    Ok(Json(route_response(v)))
}

/// Xoá model route theo API model name, rồi reload ngay.
async fn delete_route(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(model_name): Path<String>,
) -> Result<StatusCode, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    // Block delete if model has transaction history (only disable is allowed).
    let usage: i64 =
        sqlx::query::<sqlx::Postgres>("SELECT COUNT(*) AS c FROM usage_ledger WHERE model = $1")
            .bind(&model_name)
            .fetch_one(pool)
            .await?
            .try_get("c")?;
    if usage > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "model has transaction history; disable it instead",
        ));
    }
    let result = sqlx::query::<sqlx::Postgres>("DELETE FROM model_routes WHERE model_name = $1")
        .bind(&model_name)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("route not found"));
    }
    // Xoá file provider key của route (tránh orphan plaintext secret).
    let data_dir =
        std::env::var("DATA_DIR").unwrap_or_else(|_| "/var/lib/brighto-router".to_string());
    let key_path = std::path::Path::new(&data_dir)
        .join("provider_keys")
        .join(format!(
            "route_{}.key",
            hex_encode(&Sha256::digest(model_name.as_bytes()))
        ));
    let _ = std::fs::remove_file(&key_path);
    state.reload_now().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ToggleEnabled {
    enabled: bool,
}

/// Bật/tắt model route mà không cần gửi lại toàn bộ payload (giữ nguyên credential/backend_ids).
async fn toggle_route_enabled(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(model_name): Path<String>,
    Json(payload): Json<ToggleEnabled>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    let result =
        sqlx::query::<sqlx::Postgres>("UPDATE model_routes SET enabled = $1 WHERE model_name = $2")
            .bind(payload.enabled)
            .bind(&model_name)
            .execute(pool)
            .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("route not found"));
    }
    // Kích hoạt provider endpoints khi route được bật (không cần gửi lại toàn bộ payload).
    if payload.enabled {
        let row = sqlx::query::<sqlx::Postgres>(
            "SELECT backend_ids, fallback_backend_id FROM model_routes WHERE model_name = $1",
        )
        .bind(&model_name)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ApiError::not_found("route not found"))?;
        let backend_ids_json: String = row.try_get("backend_ids")?;
        let backend_ids = parse_backend_ids(&backend_ids_json)?;
        let fallback: Option<i64> = row.try_get("fallback_backend_id")?;
        enable_referenced_backends(pool, &backend_ids, fallback).await?;
    }
    state.reload_now().await?;
    Ok(Json(
        json!({ "model_name": model_name, "enabled": payload.enabled }),
    ))
}

async fn create_team(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CreateTeam>,
) -> Result<Json<TeamResponse>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;

    let budget_json = payload
        .budget
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;

    let row = sqlx::query::<sqlx::Postgres>(
        "INSERT INTO teams (name, budget, enabled) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(&payload.name)
    .bind(budget_json)
    .bind(payload.enabled)
    .fetch_one(pool)
    .await?;

    let id: i64 = row.try_get("id")?;

    state.reload_now().await?;
    Ok(Json(TeamResponse {
        id,
        name: payload.name,
        budget: payload.budget,
        enabled: payload.enabled,
    }))
}

async fn create_key(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CreateKey>,
) -> Result<Json<KeyResponse>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;

    let key = generate_key()?;
    let hash_bytes = Sha256::digest(key.as_bytes());
    let mut hash: KeyHash = [0u8; 32];
    hash.copy_from_slice(&hash_bytes);

    let prefix: String = key.chars().take(8).collect();
    let allowed_json = serde_json::to_string(&payload.allowed_models)?;
    let budget_json = payload
        .budget
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;

    let row = sqlx::query::<sqlx::Postgres>(
        "INSERT INTO api_keys \
         (key_hash, key_prefix, team_id, owner, allowed_models, budget, rpm_limit, concurrency_limit, expires_at, enabled, key_secret) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id",
    )
    .bind(hex_encode(&hash))
    .bind(&prefix)
    .bind(payload.team_id)
    .bind(&payload.owner)
    .bind(allowed_json)
    .bind(budget_json)
    .bind(payload.rpm_limit.map(|v| v as i64))
    .bind(payload.concurrency_limit.map(|v| v as i64))
    .bind(payload.expires_at)
    .bind(true)
    .bind(Some(&key))
    .fetch_one(pool)
    .await?;

    let id: i64 = row.try_get("id")?;

    if let Err(e) = state.reload_now().await {
        // Tạo key đã sinh plaintext secret; reload fail -> disable key để không tạo key mồ côi.
        let _ = sqlx::query::<sqlx::Postgres>("UPDATE api_keys SET enabled = false WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await;
        return Err(e);
    }
    Ok(Json(KeyResponse { id, key, prefix }))
}

async fn update_team(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(payload): Json<PatchTeam>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;

    // Dựng SET clause thủ công (không dùng Separated — nó chèn ", " trước bind, tạo SQL sai).
    let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE teams SET ");
    let mut first = true;

    if let Some(name) = payload.name {
        if !first {
            builder.push(", ");
        }
        builder.push("name = ").push_bind(name);
        first = false;
    }

    if let Some(budget) = payload.budget {
        if !first {
            builder.push(", ");
        }
        match budget {
            Some(b) => {
                let json = serde_json::to_string(&b)?;
                builder.push("budget = ").push_bind(json);
            }
            None => {
                builder.push("budget = NULL");
            }
        }
        first = false;
    }

    if let Some(enabled) = payload.enabled {
        if !first {
            builder.push(", ");
        }
        builder.push("enabled = ").push_bind(enabled);
        first = false;
    }

    if first {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "no fields to update",
        ));
    }

    builder.push(" WHERE id = ").push_bind(id);
    let query = builder.build();
    let result = query.execute(pool).await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("team not found"));
    }

    state.reload_now().await?;
    Ok(Json(json!({ "id": id })))
}

async fn disable_key(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;

    let result = sqlx::query::<sqlx::Postgres>("UPDATE api_keys SET enabled = false WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("key not found"));
    }

    state.reload_now().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Edit API-key metadata (owner/team/allowed models/budget/rpm/concurrency/expiry/enabled).
/// Không regenerate secret.
async fn update_key(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(payload): Json<PatchKey>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;

    let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE api_keys SET ");
    let mut first = true;
    if let Some(v) = payload.team_id {
        if !first {
            builder.push(", ");
        }
        builder.push("team_id = ").push_bind(v);
        first = false;
    }
    if let Some(v) = payload.owner {
        if !first {
            builder.push(", ");
        }
        builder
            .push("owner = ")
            .push_bind(non_empty_trimmed(v, "owner")?);
        first = false;
    }
    if let Some(v) = payload.allowed_models {
        if !first {
            builder.push(", ");
        }
        let json = serde_json::to_string(&v)?;
        builder.push("allowed_models = ").push_bind(json);
        first = false;
    }
    if let Some(v) = payload.budget {
        if !first {
            builder.push(", ");
        }
        let json = v.map(|b| serde_json::to_string(&b)).transpose()?;
        builder.push("budget = ").push_bind(json);
        first = false;
    }
    if let Some(v) = payload.rpm_limit {
        if !first {
            builder.push(", ");
        }
        builder.push("rpm_limit = ").push_bind(v as i64);
        first = false;
    }
    if let Some(v) = payload.concurrency_limit {
        if !first {
            builder.push(", ");
        }
        builder.push("concurrency_limit = ").push_bind(v as i64);
        first = false;
    }
    if let Some(v) = payload.expires_at {
        if !first {
            builder.push(", ");
        }
        builder.push("expires_at = ").push_bind(v);
        first = false;
    }
    if let Some(v) = payload.enabled {
        if !first {
            builder.push(", ");
        }
        builder.push("enabled = ").push_bind(v);
        first = false;
    }
    if first {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "no fields to update",
        ));
    }
    builder.push(" WHERE id = ").push_bind(id);
    let result = builder.build().execute(pool).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("key not found"));
    }
    state.reload_now().await?;
    Ok(Json(json!({ "id": id })))
}

/// Prompt-size bucket theo input tokens (CODEX): tránh 200k prompt làm nhiễu latency thường.
fn prompt_size_bucket(input_tokens: i64) -> &'static str {
    if input_tokens < 2_000 {
        "<2k"
    } else if input_tokens < 32_000 {
        "2k-32k"
    } else if input_tokens < 128_000 {
        "32k-128k"
    } else {
        "128k+"
    }
}

/// Friendly duration: 123 ms / 1.8 s / 3m 48s (không in raw ms khổng lồ).
fn format_duration(ms: i64) -> String {
    if ms < 0 {
        return "—".to_string();
    }
    if ms < 1_000 {
        return format!("{ms} ms");
    }
    let s = ms / 1_000;
    if s < 60 {
        return format!("{s}.{} s", (ms % 1_000) / 100);
    }
    let m = s / 60;
    let rem = s % 60;
    format!("{m}m {rem}s")
}

/// tokens/giây quan sát được.
///
/// Millisecond timers can record ultra-fast mock/local calls as 0ms even when the
/// response contains tokens. Clamp those positive-token samples to 1ms so the
/// admin log still shows useful throughput instead of `—`.
fn tokens_per_second(tokens: i64, ms: i64) -> Option<f64> {
    if tokens <= 0 {
        return None;
    }
    let effective_ms = ms.max(1);
    Some(tokens as f64 / (effective_ms as f64 / 1_000.0))
}

/// Ước lượng cost từ route prices (per 1M tokens). None khi chưa cấu hình cả 2 giá.
fn estimated_cost_usd(
    input_tokens: i64,
    output_tokens: i64,
    route: Option<&ModelRoute>,
) -> Option<f64> {
    let r = route?;
    let pi = r.price_input_per_mtok_usd?;
    let po = r.price_output_per_mtok_usd?;
    Some((input_tokens as f64 * pi + output_tokens as f64 * po) / 1_000_000.0)
}

#[allow(clippy::too_many_arguments)]
async fn query_usage_rows(
    pool: &PgPool,
    routes: &HashMap<String, ModelRoute>,
    team: Option<i64>,
    key: Option<i64>,
    backend: Option<i64>,
    model: Option<&str>,
    status: Option<&str>,
    from: Option<i64>,
    to: Option<i64>,
) -> Result<Vec<UsageRow>, ApiError> {
    let status = normalize_status(status)?;
    let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT ts, request_id, key_id, team_id, model, backend_id, status, \
         input_tokens, output_tokens, estimated, ttfb_ms, total_ms, router_overhead_ms, \
         stream, client_aborted, error_class FROM usage_ledger",
    );
    push_usage_filters(
        &mut builder,
        "",
        team,
        key,
        backend,
        model,
        &status,
        from,
        to,
    );
    builder.push(" ORDER BY ts DESC LIMIT 1000");
    let query = builder.build();
    let rows = query.fetch_all(pool).await?;

    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let model: String = row.try_get("model")?;
        let input_tokens: i64 = row.try_get("input_tokens")?;
        let output_tokens: i64 = row.try_get("output_tokens")?;
        let ttfb_ms: i64 = row.try_get("ttfb_ms")?;
        let total_ms: i64 = row.try_get("total_ms")?;
        let router_overhead_ms: i64 = row.try_get("router_overhead_ms")?;
        let total_tokens = input_tokens + output_tokens;
        let cost = estimated_cost_usd(input_tokens, output_tokens, routes.get(&model));
        result.push(UsageRow {
            ts: row.try_get("ts")?,
            request_id: row.try_get("request_id")?,
            key_id: row.try_get("key_id")?,
            team_id: row.try_get("team_id")?,
            model,
            backend_id: row.try_get("backend_id")?,
            status: row.try_get("status")?,
            input_tokens,
            output_tokens,
            estimated: row.try_get("estimated")?,
            ttfb_ms,
            total_ms,
            router_overhead_ms,
            stream: row.try_get("stream")?,
            client_aborted: row.try_get("client_aborted")?,
            error_class: row.try_get("error_class")?,
            total_tokens,
            total_tokens_per_second: tokens_per_second(total_tokens, total_ms),
            input_tokens_per_second_to_first_byte: tokens_per_second(input_tokens, ttfb_ms),
            output_tokens_per_second: if total_ms > ttfb_ms {
                tokens_per_second(output_tokens, total_ms - ttfb_ms)
            } else {
                None
            },
            prompt_size_bucket: prompt_size_bucket(input_tokens).to_string(),
            estimated_cost_usd: cost,
            cost_known: cost.is_some(),
            duration_display: format_duration(total_ms),
            router_overhead_display: format_duration(router_overhead_ms),
        });
    }
    Ok(result)
}

async fn get_usage(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<UsageQuery>,
) -> Result<Json<Vec<UsageRow>>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    let snap = state.runtime.cfg.load_full();
    Ok(Json(
        query_usage_rows(
            pool,
            &snap.routes,
            params.team,
            params.key,
            params.backend,
            params.model.as_deref(),
            params.status.as_deref(),
            params.from,
            params.to,
        )
        .await?,
    ))
}

// ===== Portal: user tự phục vụ (auth bằng API key, không phải admin key) =====

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    if let Some(auth) = headers.get(header::AUTHORIZATION)
        && let Ok(auth_str) = auth.to_str()
        && let Some(stripped) = auth_str.strip_prefix("Bearer ")
    {
        return Some(stripped.trim().to_string());
    }
    if let Some(key) = headers.get("x-api-key")
        && let Ok(key_str) = key.to_str()
    {
        return Some(key_str.trim().to_string());
    }
    None
}

/// Xác thực user bằng client API key. Trả ApiKey nếu hợp lệ + team còn enabled.
fn authorize_user_key(state: &AdminState, headers: &HeaderMap) -> Result<ApiKey, ApiError> {
    let plaintext =
        extract_api_key(headers).ok_or_else(|| ApiError::unauthorized("missing API key"))?;
    let hash = auth::hash_key(&plaintext);
    let snap = state.runtime.cfg.load_full();
    auth::authorize_key(&snap, &hash)
        .map_err(|_| ApiError::unauthorized("invalid or disabled API key"))
}

async fn list_teams(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Vec<TeamListRow>>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    let rows =
        sqlx::query::<sqlx::Postgres>("SELECT id, name, budget, enabled FROM teams ORDER BY id")
            .fetch_all(pool)
            .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let budget_json: Option<String> = row.try_get("budget")?;
        out.push(TeamListRow {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            budget: budget_json.map(|s| serde_json::from_str(&s)).transpose()?,
            enabled: row.try_get("enabled")?,
        });
    }
    Ok(Json(out))
}

async fn list_keys(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Vec<KeyListRow>>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    let rows = sqlx::query::<sqlx::Postgres>(
        "SELECT k.id, k.key_prefix, k.team_id, COALESCE(t.name, '') AS team_name, k.owner, \
         k.allowed_models, k.budget, k.rpm_limit, k.concurrency_limit, k.expires_at, k.enabled, \
         (k.key_secret IS NOT NULL) AS revealable \
         FROM api_keys k LEFT JOIN teams t ON t.id = k.team_id ORDER BY k.id",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let allowed_json: String = row.try_get("allowed_models")?;
        let budget_json: Option<String> = row.try_get("budget")?;
        out.push(KeyListRow {
            id: row.try_get("id")?,
            prefix: row.try_get("key_prefix")?,
            team_id: row.try_get("team_id")?,
            team_name: row.try_get("team_name")?,
            owner: row.try_get("owner")?,
            allowed_models: serde_json::from_str(&allowed_json).unwrap_or_default(),
            budget: budget_json.map(|s| serde_json::from_str(&s)).transpose()?,
            rpm_limit: row.try_get("rpm_limit")?,
            concurrency_limit: row.try_get("concurrency_limit")?,
            expires_at: row.try_get("expires_at")?,
            enabled: row.try_get("enabled")?,
            revealable: row.try_get("revealable")?,
        });
    }
    Ok(Json(out))
}

async fn query_stats(
    pool: &PgPool,
    team: Option<i64>,
    key: Option<i64>,
    days: u32,
) -> Result<Vec<StatRow>, ApiError> {
    let days = days.clamp(1, 365);
    let since = now_secs() - i64::from(days) * 86_400;
    let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT (ts / 86400) * 86400 AS day, model, \
         CAST(COALESCE(SUM(input_tokens), 0) AS BIGINT) AS input_tokens, \
         CAST(COALESCE(SUM(output_tokens), 0) AS BIGINT) AS output_tokens, \
         COUNT(*) AS requests \
         FROM usage_ledger WHERE ts >= ",
    );
    builder.push_bind(since);
    if let Some(team) = team {
        builder.push(" AND team_id = ").push_bind(team);
    }
    if let Some(key) = key {
        builder.push(" AND key_id = ").push_bind(key);
    }
    builder.push(" GROUP BY 1, 2 ORDER BY 1, 2");
    let query = builder.build();
    let rows = query.fetch_all(pool).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(StatRow {
            day: row.try_get("day")?,
            model: row.try_get("model")?,
            input_tokens: row.try_get("input_tokens")?,
            output_tokens: row.try_get("output_tokens")?,
            requests: row.try_get("requests")?,
        });
    }
    Ok(out)
}

async fn get_stats(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<StatsQuery>,
) -> Result<Json<Vec<StatRow>>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    Ok(Json(
        query_stats(pool, params.team, None, params.days.unwrap_or(30)).await?,
    ))
}

async fn me(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
) -> Result<Json<MeResponse>, ApiError> {
    let key = authorize_user_key(&state, &headers)?;
    let snap = state.runtime.cfg.load_full();
    let team = snap
        .teams
        .get(&key.team_id)
        .cloned()
        .ok_or_else(|| ApiError::unauthorized("team not found or disabled"))?;
    Ok(Json(MeResponse {
        key: MeKey {
            id: key.id,
            prefix: key.key_prefix.clone(),
            owner: key.owner.clone(),
            allowed_models: key.allowed_models.clone(),
            budget: key.budget.clone(),
            rpm_limit: key.rpm_limit,
            concurrency_limit: key.concurrency_limit,
            expires_at: key.expires_at,
            enabled: key.enabled,
        },
        team: MeTeam {
            id: team.id,
            name: team.name,
            budget: team.budget,
            enabled: team.enabled,
        },
    }))
}

async fn me_usage(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Query(params): Query<UsageQuery>,
) -> Result<Json<Vec<UsageRow>>, ApiError> {
    let key = authorize_user_key(&state, &headers)?;
    let pool = state.pool().await?;
    let snap = state.runtime.cfg.load_full();
    Ok(Json(
        query_usage_rows(
            pool,
            &snap.routes,
            None,
            Some(key.id),
            None,
            params.model.as_deref(),
            params.status.as_deref(),
            params.from,
            params.to,
        )
        .await?,
    ))
}

async fn me_stats(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Query(params): Query<MeStatsQuery>,
) -> Result<Json<Vec<StatRow>>, ApiError> {
    let key = authorize_user_key(&state, &headers)?;
    let pool = state.pool().await?;
    Ok(Json(
        query_stats(pool, None, Some(key.id), params.days.unwrap_or(30)).await?,
    ))
}

/// Admin xem lại plaintext client key (yêu cầu user). Chỉ key tạo SAU migration 0003 có key_secret.
async fn reveal_key(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<KeyRevealResponse>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    let row = sqlx::query::<sqlx::Postgres>(
        "SELECT key_prefix, owner, key_secret FROM api_keys WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::not_found("key not found"))?;
    let secret: Option<String> = row.try_get("key_secret")?;
    let key = secret.ok_or_else(|| {
        ApiError::new(
            StatusCode::GONE,
            "plaintext not stored (key created before key-reveal); disable and recreate it",
        )
    })?;
    Ok(Json(KeyRevealResponse {
        id,
        prefix: row.try_get("key_prefix")?,
        owner: row.try_get("owner")?,
        key,
    }))
}

/// Read-only runtime settings cho màn Settings (admin path, không phải hot path).
async fn get_settings(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<SettingsResponse>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    let database_ok = sqlx::query::<sqlx::Postgres>("SELECT 1")
        .fetch_optional(pool)
        .await
        .is_ok();
    let ok = state
        .runtime
        .config_ok_at
        .load(std::sync::atomic::Ordering::Relaxed);
    let err = state
        .runtime
        .config_err_at
        .load(std::sync::atomic::Ordering::Relaxed);
    Ok(Json(SettingsResponse {
        listen_addr: std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:18080".to_string()),
        database_ok,
        config_reload_ok: ok > 0 && ok > err,
        max_body_bytes: state.runtime.max_body_bytes,
        version: env!("CARGO_PKG_VERSION").to_string(),
    }))
}

#[derive(Deserialize)]
struct SummaryQuery {
    team: Option<i64>,
    key: Option<i64>,
    backend: Option<i64>,
    model: Option<String>,
    status: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
    days: Option<u32>,
}

#[derive(Serialize)]
struct TotalsRow {
    requests: i64,
    input_tokens: i64,
    output_tokens: i64,
    errors: i64,
    error_rate_pct: f64,
    p95_ttfb_ms: f64,
    p95_total_ms: f64,
    /// Router overhead p95 (ms) — chỉ số quan trọng nhất của router, tách khỏi provider latency.
    p95_router_overhead_ms: f64,
    /// Ước lượng cost tổng (USD) chỉ từ những route có đủ cả 2 giá. None khi không có route giá.
    estimated_cost_usd: Option<f64>,
    /// Số request có cost tính được (route có đủ input+output price).
    cost_known_requests: i64,
}

#[derive(Serialize)]
struct GroupRow {
    model: String,
    requests: i64,
    input_tokens: i64,
    output_tokens: i64,
    errors: i64,
    estimated_cost_usd: Option<f64>,
}

#[derive(Serialize)]
struct TeamGroupRow {
    team_id: i64,
    team_name: String,
    requests: i64,
    input_tokens: i64,
    output_tokens: i64,
    errors: i64,
}

#[derive(Serialize)]
struct KeyGroupRow {
    key_id: i64,
    key_prefix: String,
    requests: i64,
    input_tokens: i64,
    output_tokens: i64,
    errors: i64,
}

#[derive(Serialize)]
struct BucketRow {
    bucket: String,
    requests: i64,
    p95_ttfb_ms: f64,
    p95_total_ms: f64,
    p95_router_overhead_ms: f64,
}

#[derive(Serialize)]
struct ProviderHealthRow {
    backend_id: i64,
    backend_name: String,
    requests: i64,
    errors: i64,
    rate_limited: i64,
    server_errors: i64,
    timeouts: i64,
}

#[derive(Serialize)]
struct SummaryResponse {
    totals: TotalsRow,
    by_model: Vec<GroupRow>,
    by_team: Vec<TeamGroupRow>,
    by_key: Vec<KeyGroupRow>,
    by_bucket: Vec<BucketRow>,
    by_backend: Vec<ProviderHealthRow>,
}

/// Gắn bộ filter usage chung vào WHERE. `alias` = "" cho query usage_ledger trực tiếp, "u." cho JOIN.
#[allow(clippy::too_many_arguments)]
enum StatusFilter {
    None,
    Success,
    Error,
    Exact(i64),
}

/// Chuẩn hoá status filter: all/empty -> None, success -> 2xx, error -> >=400, số -> exact, lỗi -> 400.
fn normalize_status(raw: Option<&str>) -> Result<StatusFilter, ApiError> {
    let raw = raw.map(str::trim).filter(|s| !s.is_empty());
    match raw.map(|s| s.to_ascii_lowercase()).as_deref() {
        None | Some("all") => Ok(StatusFilter::None),
        Some("success") | Some("ok") | Some("2xx") => Ok(StatusFilter::Success),
        Some("error") | Some("err") | Some("4xx") | Some("5xx") => Ok(StatusFilter::Error),
        Some(s) => s.parse::<i64>().map(StatusFilter::Exact).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("invalid status filter: {s}"),
            )
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn push_usage_filters(
    b: &mut sqlx::QueryBuilder<sqlx::Postgres>,
    alias: &str,
    team: Option<i64>,
    key: Option<i64>,
    backend: Option<i64>,
    model: Option<&str>,
    status: &StatusFilter,
    from: Option<i64>,
    to: Option<i64>,
) {
    b.push(" WHERE 1=1");
    if let Some(t) = team {
        b.push(" AND ").push(alias).push("team_id = ").push_bind(t);
    }
    if let Some(k) = key {
        b.push(" AND ").push(alias).push("key_id = ").push_bind(k);
    }
    if let Some(bid) = backend {
        b.push(" AND ")
            .push(alias)
            .push("backend_id = ")
            .push_bind(bid);
    }
    if let Some(m) = model.filter(|m| !m.trim().is_empty()) {
        b.push(" AND ").push(alias).push("model = ").push_bind(m);
    }
    match status {
        StatusFilter::None => {}
        StatusFilter::Success => {
            b.push(" AND ")
                .push(alias)
                .push("status >= 200")
                .push(" AND ")
                .push(alias)
                .push("status < 400");
        }
        StatusFilter::Error => {
            b.push(" AND ").push(alias).push("status >= 400");
        }
        StatusFilter::Exact(code) => {
            b.push(" AND ")
                .push(alias)
                .push("status = ")
                .push_bind(*code);
        }
    }
    if let Some(f) = from {
        b.push(" AND ").push(alias).push("ts >= ").push_bind(f);
    }
    if let Some(t) = to {
        b.push(" AND ").push(alias).push("ts <= ").push_bind(t);
    }
}

/// Dashboard summary: totals + error rate + p95 + nhóm theo model/team/key.
async fn get_summary(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<SummaryQuery>,
) -> Result<Json<SummaryResponse>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;
    let pool = state.pool().await?;
    let days = params.days.unwrap_or(30).clamp(1, 365);
    let from = params
        .from
        .unwrap_or_else(|| now_secs() - i64::from(days) * 86_400);
    let team = params.team;
    let key = params.key;
    let backend = params.backend;
    let model = params.model.as_deref();
    let status = normalize_status(params.status.as_deref())?;
    let to = params.to;

    // Giá route (cả input + output) cho phép tính cost ước lượng per model.
    let snap = state.runtime.cfg.load_full();
    let prices: HashMap<String, (f64, f64)> = snap
        .routes
        .iter()
        .filter_map(|(name, r)| {
            Some((
                name.clone(),
                (r.price_input_per_mtok_usd?, r.price_output_per_mtok_usd?),
            ))
        })
        .collect();

    let mut tb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT COUNT(*) AS requests, \
         CAST(COALESCE(SUM(input_tokens),0) AS BIGINT) AS input_tokens, \
         CAST(COALESCE(SUM(output_tokens),0) AS BIGINT) AS output_tokens, \
         COUNT(*) FILTER (WHERE status >= 400) AS errors FROM usage_ledger",
    );
    push_usage_filters(
        &mut tb,
        "",
        team,
        key,
        backend,
        model,
        &status,
        Some(from),
        to,
    );
    let trow = tb.build().fetch_one(pool).await?;
    let requests: i64 = trow.try_get("requests")?;
    let errors: i64 = trow.try_get("errors")?;
    let error_rate_pct = if requests > 0 {
        errors as f64 * 100.0 / requests as f64
    } else {
        0.0
    };

    let mut pb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY ttfb_ms) AS p95_ttfb, \
         percentile_cont(0.95) WITHIN GROUP (ORDER BY total_ms) AS p95_total, \
         percentile_cont(0.95) WITHIN GROUP (ORDER BY router_overhead_ms) AS p95_overhead \
         FROM usage_ledger",
    );
    push_usage_filters(
        &mut pb,
        "",
        team,
        key,
        backend,
        model,
        &status,
        Some(from),
        to,
    );
    let prow = pb.build().fetch_one(pool).await?;
    let p95_ttfb_ms: Option<f64> = prow.try_get("p95_ttfb")?;
    let p95_total_ms: Option<f64> = prow.try_get("p95_total")?;
    let p95_overhead_ms: Option<f64> = prow.try_get("p95_overhead")?;

    let mut mb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT model, COUNT(*) AS requests, \
         CAST(COALESCE(SUM(input_tokens),0) AS BIGINT) AS input_tokens, \
         CAST(COALESCE(SUM(output_tokens),0) AS BIGINT) AS output_tokens, \
         COUNT(*) FILTER (WHERE status >= 400) AS errors FROM usage_ledger",
    );
    push_usage_filters(
        &mut mb,
        "",
        team,
        key,
        backend,
        model,
        &status,
        Some(from),
        to,
    );
    mb.push(" GROUP BY model ORDER BY requests DESC LIMIT 20");
    let mrows = mb.build().fetch_all(pool).await?;
    let by_model: Vec<GroupRow> = mrows
        .iter()
        .map(|r| {
            let model: String = r.try_get("model").unwrap_or_default();
            let input_tokens: i64 = r.try_get("input_tokens").unwrap_or(0);
            let output_tokens: i64 = r.try_get("output_tokens").unwrap_or(0);
            let estimated_cost_usd = prices.get(&model).map(|(pi, po)| {
                (input_tokens as f64 * pi + output_tokens as f64 * po) / 1_000_000.0
            });
            GroupRow {
                model,
                requests: r.try_get("requests").unwrap_or(0),
                input_tokens,
                output_tokens,
                errors: r.try_get("errors").unwrap_or(0),
                estimated_cost_usd,
            }
        })
        .collect();

    let mut tmb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT u.team_id, COALESCE(t.name,'') AS team_name, COUNT(*) AS requests, \
         CAST(COALESCE(SUM(u.input_tokens),0) AS BIGINT) AS input_tokens, \
         CAST(COALESCE(SUM(u.output_tokens),0) AS BIGINT) AS output_tokens, \
         COUNT(*) FILTER (WHERE u.status >= 400) AS errors \
         FROM usage_ledger u LEFT JOIN teams t ON t.id = u.team_id",
    );
    push_usage_filters(
        &mut tmb,
        "u.",
        team,
        key,
        backend,
        model,
        &status,
        Some(from),
        to,
    );
    tmb.push(" GROUP BY u.team_id, t.name ORDER BY requests DESC LIMIT 20");
    let trows = tmb.build().fetch_all(pool).await?;
    let by_team: Vec<TeamGroupRow> = trows
        .iter()
        .map(|r| TeamGroupRow {
            team_id: r.try_get("team_id").unwrap_or(0),
            team_name: r.try_get("team_name").unwrap_or_default(),
            requests: r.try_get("requests").unwrap_or(0),
            input_tokens: r.try_get("input_tokens").unwrap_or(0),
            output_tokens: r.try_get("output_tokens").unwrap_or(0),
            errors: r.try_get("errors").unwrap_or(0),
        })
        .collect();

    let mut kb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT u.key_id, COALESCE(k.key_prefix,'') AS key_prefix, COUNT(*) AS requests, \
         CAST(COALESCE(SUM(u.input_tokens),0) AS BIGINT) AS input_tokens, \
         CAST(COALESCE(SUM(u.output_tokens),0) AS BIGINT) AS output_tokens, \
         COUNT(*) FILTER (WHERE u.status >= 400) AS errors \
         FROM usage_ledger u LEFT JOIN api_keys k ON k.id = u.key_id",
    );
    push_usage_filters(
        &mut kb,
        "u.",
        team,
        key,
        backend,
        model,
        &status,
        Some(from),
        to,
    );
    kb.push(" GROUP BY u.key_id, k.key_prefix ORDER BY requests DESC LIMIT 20");
    let krows = kb.build().fetch_all(pool).await?;
    let by_key: Vec<KeyGroupRow> = krows
        .iter()
        .map(|r| KeyGroupRow {
            key_id: r.try_get("key_id").unwrap_or(0),
            key_prefix: r.try_get("key_prefix").unwrap_or_default(),
            requests: r.try_get("requests").unwrap_or(0),
            input_tokens: r.try_get("input_tokens").unwrap_or(0),
            output_tokens: r.try_get("output_tokens").unwrap_or(0),
            errors: r.try_get("errors").unwrap_or(0),
        })
        .collect();

    // Performance diagnostics: latency theo prompt-size bucket (tránh 200k prompt nhiễu latency thường).
    let mut bkb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT CASE              WHEN input_tokens < 2000 THEN '<2k'              WHEN input_tokens < 32000 THEN '2k-32k'              WHEN input_tokens < 128000 THEN '32k-128k'              ELSE '128k+' END AS bucket,          COUNT(*) AS requests,          percentile_cont(0.95) WITHIN GROUP (ORDER BY ttfb_ms) AS p95_ttfb,          percentile_cont(0.95) WITHIN GROUP (ORDER BY total_ms) AS p95_total,          percentile_cont(0.95) WITHIN GROUP (ORDER BY router_overhead_ms) AS p95_overhead          FROM usage_ledger",
    );
    push_usage_filters(
        &mut bkb,
        "",
        team,
        key,
        backend,
        model,
        &status,
        Some(from),
        to,
    );
    bkb.push(" GROUP BY 1 ORDER BY MIN(input_tokens)");
    let bkrows = bkb.build().fetch_all(pool).await?;
    let by_bucket: Vec<BucketRow> = bkrows
        .iter()
        .map(|r| BucketRow {
            bucket: r.try_get("bucket").unwrap_or_default(),
            requests: r.try_get("requests").unwrap_or(0),
            p95_ttfb_ms: r.try_get("p95_ttfb").unwrap_or(0.0),
            p95_total_ms: r.try_get("p95_total").unwrap_or(0.0),
            p95_router_overhead_ms: r.try_get("p95_overhead").unwrap_or(0.0),
        })
        .collect();

    // Provider health: lỗi/429/5xx/timeout theo backend (CODEX "what is failing").
    let mut bhb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT u.backend_id, COALESCE(b.name,'') AS backend_name, COUNT(*) AS requests, \
         COUNT(*) FILTER (WHERE u.status >= 400) AS errors, \
         COUNT(*) FILTER (WHERE u.status = 429) AS rate_limited, \
         COUNT(*) FILTER (WHERE u.status >= 500) AS server_errors, \
         COUNT(*) FILTER (WHERE u.error_class ILIKE '%timeout%' OR u.error_class ILIKE '%timed out%') AS timeouts \
         FROM usage_ledger u LEFT JOIN backends b ON b.id = u.backend_id",
    );
    push_usage_filters(
        &mut bhb,
        "u.",
        team,
        key,
        backend,
        model,
        &status,
        Some(from),
        to,
    );
    bhb.push(" GROUP BY u.backend_id, b.name ORDER BY errors DESC, requests DESC LIMIT 20");
    let bhrows = bhb.build().fetch_all(pool).await?;
    let by_backend: Vec<ProviderHealthRow> = bhrows
        .iter()
        .map(|r| ProviderHealthRow {
            backend_id: r.try_get("backend_id").unwrap_or(0),
            backend_name: r.try_get("backend_name").unwrap_or_default(),
            requests: r.try_get("requests").unwrap_or(0),
            errors: r.try_get("errors").unwrap_or(0),
            rate_limited: r.try_get("rate_limited").unwrap_or(0),
            server_errors: r.try_get("server_errors").unwrap_or(0),
            timeouts: r.try_get("timeouts").unwrap_or(0),
        })
        .collect();

    let estimated_cost_usd: f64 = by_model.iter().filter_map(|g| g.estimated_cost_usd).sum();
    let cost_known_requests: i64 = by_model
        .iter()
        .filter(|g| g.estimated_cost_usd.is_some())
        .map(|g| g.requests)
        .sum();

    Ok(Json(SummaryResponse {
        totals: TotalsRow {
            requests,
            input_tokens: trow.try_get("input_tokens")?,
            output_tokens: trow.try_get("output_tokens")?,
            errors,
            error_rate_pct,
            p95_ttfb_ms: p95_ttfb_ms.unwrap_or(0.0),
            p95_total_ms: p95_total_ms.unwrap_or(0.0),
            p95_router_overhead_ms: p95_overhead_ms.unwrap_or(0.0),
            estimated_cost_usd: Some(estimated_cost_usd),
            cost_known_requests,
        },
        by_model,
        by_team,
        by_key,
        by_bucket,
        by_backend,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_cidr_checks() {
        assert!(ip_matches_cidr(
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1/32"
        ));
        assert!(!ip_matches_cidr(
            "127.0.0.2".parse().unwrap(),
            "127.0.0.1/32"
        ));
        assert!(ip_matches_cidr("10.0.0.5".parse().unwrap(), "10.0.0.0/8"));
        assert!(ip_matches_cidr("::1".parse().unwrap(), "::1/128"));
    }

    #[test]
    fn provider_url_join_handles_host_and_sdk_base_urls() {
        assert_eq!(
            join_provider_url("https://api.openai.com", "/v1/models"),
            "https://api.openai.com/v1/models"
        );
        assert_eq!(
            join_provider_url("https://api.moonshot.ai/v1", "/v1/models"),
            "https://api.moonshot.ai/v1/models"
        );
        assert_eq!(
            join_provider_url("https://api.openai.com/v1", "/v1/responses"),
            "https://api.openai.com/v1/responses"
        );
        assert_eq!(
            join_provider_url(
                "https://dashscope.example.com/compatible-mode/v1",
                "/v1/models"
            ),
            "https://dashscope.example.com/compatible-mode/v1/models"
        );
        assert_eq!(
            join_provider_url("https://api.cohere.com/v2", "/v1/rerank"),
            "https://api.cohere.com/v2/rerank"
        );
        assert_eq!(
            join_provider_url("http://127.0.0.1:11435/v1", "/v1/systemone"),
            "http://127.0.0.1:11435/v1/systemone"
        );
    }

    #[test]
    fn backend_ids_parser_accepts_json_integer_array() {
        assert_eq!(parse_backend_ids("[1,2,3]").unwrap(), vec![1, 2, 3]);
        assert!(parse_backend_ids("not-json").is_err());
        assert!(parse_backend_ids("[1,\"bad\"]").is_err());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn list_routes_from_pool_returns_sorted_routes(pool: PgPool) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO model_routes \
             (model_name, backend_ids, fallback_backend_id, chars_per_token, first_byte_timeout) \
             VALUES ($1, $2, $3, $4, $5), ($6, $7, $8, $9, $10)",
        )
        .bind("z-model")
        .bind("[2,3]")
        .bind(3_i64)
        .bind(4.0_f64)
        .bind(180_i64)
        .bind("a-model")
        .bind("[1]")
        .bind(None::<i64>)
        .bind(3.5_f64)
        .bind(90_i64)
        .execute(&pool)
        .await?;
        sqlx::query("UPDATE model_routes SET passthrough = TRUE WHERE model_name = $1")
            .bind("a-model")
            .execute(&pool)
            .await?;

        let routes = list_routes_from_pool(&pool).await.expect("list routes");
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].model_name, "a-model");
        assert_eq!(routes[0].backend_ids, vec![1]);
        assert_eq!(routes[0].fallback_backend_id, None);
        assert_eq!(routes[0].chars_per_token, 3.5);
        assert_eq!(routes[0].first_byte_timeout, 90);
        assert_eq!(routes[1].model_name, "z-model");
        assert_eq!(routes[1].backend_ids, vec![2, 3]);
        assert_eq!(routes[1].fallback_backend_id, Some(3));
        // Passthrough flag must survive the listing query: operators need to see which rows
        // widen the served model set.
        assert!(routes[0].passthrough);
        assert!(!routes[1].passthrough);
        Ok(())
    }

    fn route_payload_with(passthrough: bool) -> UpsertRoute {
        UpsertRoute {
            model_name: "opencode/free".to_string(),
            backend_ids: vec![7],
            fallback_backend_id: None,
            chars_per_token: None,
            first_byte_timeout: None,
            provider_model_name: None,
            context_tokens: None,
            max_output_tokens: None,
            price_input_per_mtok_usd: None,
            price_output_per_mtok_usd: None,
            enabled: None,
            provider_key: None,
            provider_key_ref: None,
            auth_mode: None,
            protocol: None,
            routing_policy: None,
            endpoints: None,
            passthrough: Some(passthrough),
        }
    }

    #[test]
    fn passthrough_route_needs_one_backend_and_a_generic_wire_protocol() {
        let validated =
            validate_route(route_payload_with(true)).expect("passthrough route is valid");
        assert!(validated.passthrough);
        assert_eq!(validated.backend_ids, vec![7]);
        // provider_model_name stays defaulted: the matching model id *is* the provider model.
        assert_eq!(validated.provider_model_name, "opencode/free");
        assert_eq!(validated.protocol, "openai_chat");

        let mut two_backends = route_payload_with(true);
        two_backends.backend_ids = vec![7, 8];
        let Err(e) = validate_route(two_backends) else {
            panic!("two backends must be rejected");
        };
        assert!(e.message.contains("exactly one backend_id"));

        let mut with_fallback = route_payload_with(true);
        with_fallback.fallback_backend_id = Some(9);
        let Err(e) = validate_route(with_fallback) else {
            panic!("fallback must be rejected");
        };
        assert!(e.message.contains("must not set fallback_backend_id"));

        let mut with_endpoints = route_payload_with(true);
        with_endpoints.endpoints = Some(vec![UpsertRouteEndpoint {
            backend_id: 7,
            provider_model_name: None,
            provider_key: None,
            provider_key_ref: None,
            auth_mode: None,
            protocol: None,
            weight: None,
            max_inflight: None,
            enabled: None,
        }]);
        let Err(e) = validate_route(with_endpoints) else {
            panic!("group endpoints must be rejected");
        };
        assert!(e.message.contains("must not declare group endpoints"));

        for protocol in ["anthropic_messages", "openai_embeddings", "cohere_rerank"] {
            let mut wrong_wire = route_payload_with(true);
            wrong_wire.protocol = Some(protocol.to_string());
            let Err(e) = validate_route(wrong_wire) else {
                panic!("protocol {protocol} must be rejected for passthrough");
            };
            assert!(e.message.contains("chat-family or responses-family"));
        }

        let mut responses = route_payload_with(true);
        responses.protocol = Some("openai_responses".to_string());
        assert_eq!(
            validate_route(responses)
                .expect("responses is allowed")
                .protocol,
            "openai_responses"
        );
    }

    #[test]
    fn plain_route_keeps_multi_backend_validation_and_passthrough_flag_off() {
        let mut plain = route_payload_with(false);
        plain.backend_ids = vec![7, 8];
        let validated = validate_route(plain).expect("plain multi-backend route");
        assert!(!validated.passthrough);
        assert_eq!(validated.backend_ids, vec![7, 8]);

        // Passthrough omitted entirely behaves like `false`.
        let mut omitted = route_payload_with(true);
        omitted.passthrough = None;
        assert!(!validate_route(omitted).expect("omitted flag").passthrough);
    }

    #[test]
    fn passthrough_protocol_gate_covers_only_generic_families() {
        assert!(is_passthrough_protocol("openai_chat"));
        assert!(is_passthrough_protocol("local_openai_chat"));
        assert!(is_passthrough_protocol("custom_openai_chat"));
        assert!(is_passthrough_protocol("openai_responses"));
        assert!(is_passthrough_protocol("codex_responses"));
        assert!(!is_passthrough_protocol("openai_completions"));
        assert!(!is_passthrough_protocol("anthropic_messages"));
        assert!(!is_passthrough_protocol("openai_embeddings"));
        assert!(!is_passthrough_protocol("qwen_rerank"));
        assert!(!is_passthrough_protocol("openai_audio_transcriptions"));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn model_route_api_names_are_unique(pool: PgPool) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO model_routes (model_name, backend_ids, chars_per_token, first_byte_timeout) VALUES ($1, $2, $3, $4)")
            .bind("same-api-model-name")
            .bind("[1]")
            .bind(4.0_f64)
            .bind(180_i64)
            .execute(&pool)
            .await?;

        let duplicate = sqlx::query("INSERT INTO model_routes (model_name, backend_ids, chars_per_token, first_byte_timeout) VALUES ($1, $2, $3, $4)")
            .bind("same-api-model-name")
            .bind("[2]")
            .bind(4.0_f64)
            .bind(180_i64)
            .execute(&pool)
            .await;

        assert!(
            duplicate.is_err(),
            "model route and Model Group names must share one unique client-facing API namespace"
        );
        Ok(())
    }

    #[test]
    fn model_group_protocol_families_keep_endpoint_shapes_separate() {
        assert_eq!(protocol_family("openai_chat"), "openai_chat");
        assert_eq!(protocol_family("local_openai_chat"), "openai_chat");
        assert_eq!(protocol_family("openai_completions"), "openai_completions");
        assert_eq!(protocol_family("openai_responses"), "openai_responses");
        assert_ne!(
            protocol_family("openai_chat"),
            protocol_family("openai_completions")
        );
        assert_ne!(
            protocol_family("openai_chat"),
            protocol_family("openai_responses")
        );
        assert_ne!(
            protocol_family("openai_completions"),
            protocol_family("openai_responses")
        );
    }

    #[test]
    fn backend_format_validation_is_strict() {
        assert_eq!(normalize_backend_format("openai").unwrap(), "openai");
        assert_eq!(normalize_backend_format("Open_AI").unwrap(), "openai");
        assert_eq!(normalize_backend_format("anthropic").unwrap(), "anthropic");
        assert_eq!(
            normalize_backend_format("opencode_free").unwrap(),
            "opencode_free"
        );
        assert_eq!(
            normalize_backend_format(" OpenCode-Free ").unwrap(),
            "opencode_free"
        );
        assert!(normalize_backend_format("gemini").is_err());
    }

    // ===== POST /admin/backends payload -> row resolution =====

    fn legacy_backend_payload() -> CreateBackend {
        CreateBackend {
            dynamic_models: false,
            name: "legacy".into(),
            base_url: Some("https://api.example.com".into()),
            api_key_ref: Some("env:EXAMPLE_API_KEY".into()),
            format: Some("openai".into()),
            provider_type: None,
            key: None,
            weight: None,
            max_inflight: None,
            enabled: true,
        }
    }

    #[test]
    fn legacy_create_payload_resolves_exactly_as_before() {
        let resolved = resolve_backend_create(legacy_backend_payload()).expect("legacy payload");
        assert_eq!(resolved.provider_type, None);
        assert_eq!(resolved.name, "legacy");
        assert_eq!(resolved.base_url, "https://api.example.com");
        assert_eq!(resolved.api_key_ref, "env:EXAMPLE_API_KEY");
        assert_eq!(resolved.format, "openai");
        assert_eq!(resolved.plaintext_key, None);
        assert_eq!(resolved.weight, 1);
        assert_eq!(resolved.max_inflight, 0);
        assert!(resolved.enabled);
    }

    #[test]
    fn legacy_create_payload_keeps_its_validation_errors() {
        // Missing values that used to be required fields still fail with 400, not silently
        // deriving anything.
        let mut p = legacy_backend_payload();
        p.base_url = None;
        let err = resolve_backend_create(p).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("base_url"));

        let mut p = legacy_backend_payload();
        p.format = None;
        assert_eq!(
            resolve_backend_create(p).unwrap_err().status,
            StatusCode::BAD_REQUEST
        );

        let mut p = legacy_backend_payload();
        p.api_key_ref = None;
        let err = resolve_backend_create(p).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("api_key_ref"));
    }

    #[test]
    fn provider_type_derives_base_url_format_and_defaults() {
        let payload = CreateBackend {
            name: "ds".into(),
            dynamic_models: false,
            provider_type: Some("deepseek".into()),
            key: Some("sk-deepseek".into()),
            ..legacy_backend_payload()
        };
        let resolved = resolve_backend_create(payload).expect("deepseek resolves");
        assert_eq!(resolved.provider_type.map(|p| p.slug), Some("deepseek"));
        assert_eq!(resolved.base_url, "https://api.deepseek.com");
        assert_eq!(resolved.format, "openai");
        // Plaintext key travels to the secrets file; the stored ref is filled after INSERT.
        assert_eq!(resolved.plaintext_key.as_deref(), Some("sk-deepseek"));
        assert_eq!(resolved.api_key_ref, "");
    }

    #[test]
    fn fixed_base_url_entries_override_a_conflicting_caller_base_url() {
        let mut payload = CreateBackend {
            name: "zai".into(),
            dynamic_models: false,
            provider_type: Some("ZAI".into()), // case-insensitive slug
            key: Some("sk-zai".into()),
            ..legacy_backend_payload()
        };
        payload.base_url = Some("https://attacker.example.com".into());
        payload.format = Some("anthropic".into()); // derived format wins too
        let resolved = resolve_backend_create(payload).expect("zai resolves");
        assert_eq!(resolved.base_url, "https://api.z.ai/api/paas/v4");
        assert_eq!(resolved.format, "openai");
    }

    #[test]
    fn unknown_provider_type_is_rejected_with_400() {
        let payload = CreateBackend {
            name: "x".into(),
            dynamic_models: false,
            provider_type: Some("definitely-not-a-provider".into()),
            key: Some("sk-x".into()),
            ..legacy_backend_payload()
        };
        let err = resolve_backend_create(payload).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(
            err.message.contains("unknown provider_type"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn custom_openai_requires_a_caller_base_url() {
        let mut payload = CreateBackend {
            name: "local".into(),
            dynamic_models: false,
            provider_type: Some("custom-openai".into()),
            base_url: None,
            api_key_ref: None,
            format: None,
            key: None,
            weight: None,
            max_inflight: None,
            enabled: true,
        };
        let err = resolve_backend_create(payload.clone()).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(
            err.message.contains("custom-openai") && err.message.contains("requires base_url"),
            "got: {}",
            err.message
        );

        payload.base_url = Some("http://127.0.0.1:8088/v1".into());
        // No credential is fine: local no-auth endpoints are a supported custom-openai case.
        let resolved = resolve_backend_create(payload).expect("custom resolves");
        assert_eq!(resolved.base_url, "http://127.0.0.1:8088/v1");
        assert_eq!(resolved.format, "openai");
        assert_eq!(resolved.api_key_ref, "");
        assert_eq!(resolved.plaintext_key, None);
    }

    #[test]
    fn api_key_providers_without_any_credential_are_rejected() {
        let payload = CreateBackend {
            name: "dahl".into(),
            provider_type: Some("dahl".into()),
            dynamic_models: false,
            key: None,
            api_key_ref: None,
            base_url: None,
            format: None,
            weight: None,
            max_inflight: None,
            enabled: true,
        };
        let err = resolve_backend_create(payload).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("dahl"));
        assert!(err.message.contains("API key"));
    }

    #[test]
    fn provider_type_accepts_an_api_key_ref_instead_of_a_pasted_key() {
        let payload = CreateBackend {
            name: "zai".into(),
            provider_type: Some("zai".into()),
            api_key_ref: Some("env:ZAI_API_KEY".into()),
            dynamic_models: false,
            key: None,
            base_url: None,
            format: None,
            weight: None,
            max_inflight: None,
            enabled: true,
        };
        let resolved = resolve_backend_create(payload).expect("zai with ref");
        assert_eq!(resolved.api_key_ref, "env:ZAI_API_KEY");
        assert_eq!(resolved.plaintext_key, None);
    }

    #[test]
    fn oauth_provider_type_rejects_a_pasted_key() {
        let payload = CreateBackend {
            name: "codex".into(),
            provider_type: Some("codex-oauth".into()),
            key: Some("sk-not-how-oauth-works".into()),
            base_url: None,
            dynamic_models: false,
            api_key_ref: None,
            format: None,
            weight: None,
            max_inflight: None,
            enabled: true,
        };
        let err = resolve_backend_create(payload).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("connected OAuth account"));
    }

    #[test]
    fn oauth_provider_type_without_credential_resolves() {
        // The connected account is attached later (oauth:<provider>:<label> ref), so creating
        // the backend row itself needs no credential.
        let payload = CreateBackend {
            dynamic_models: false,
            name: "grok".into(),
            provider_type: Some("xai-grok-oauth".into()),
            api_key_ref: Some("oauth:xai-oauth:default".into()),
            key: None,
            base_url: None,
            format: None,
            weight: None,
            max_inflight: None,
            enabled: true,
        };
        let resolved = resolve_backend_create(payload).expect("grok resolves");
        assert_eq!(
            resolved.provider_type.map(|p| p.protocol),
            Some("openai_responses")
        );
        assert_eq!(resolved.base_url, "https://cli-chat-proxy.grok.com/v1");
        assert_eq!(resolved.api_key_ref, "oauth:xai-oauth:default");
    }

    #[test]
    fn providers_endpoint_lists_the_registry_entries() {
        let entries = provider_registry::list();
        assert!(entries.iter().any(|p| p.slug == "deepseek"));
        assert!(entries.iter().any(|p| p.slug == "custom-openai"));
        // Every listed entry must be resolvable as a create payload provider_type.
        for entry in entries {
            assert_eq!(
                provider_registry::lookup(entry.slug).unwrap().slug,
                entry.slug
            );
        }
    }

    #[test]
    fn opencode_free_backend_probe_headers_carry_the_free_identity() {
        // The Load-models probe must send the exact header set the proxy sends, or the
        // OpenCode catalog rejects the request (it requires the pinned opencode User-Agent).
        let plan = provider_auth::resolve(provider_auth::OPENCODE_FREE_AUTH_MODE, false, None);
        assert_eq!(plan.mode, provider_auth::HeaderMode::OpenCodeFree);
        let mut headers = reqwest::header::HeaderMap::new();
        provider_auth::apply_headers(&mut headers, &plan, "").unwrap();
        assert_eq!(headers.get("authorization").unwrap(), "Bearer public");
        assert_eq!(
            headers.get("user-agent").unwrap(),
            provider_auth::OPENCODE_FREE_USER_AGENT
        );
        assert!(headers.get("x-opencode-session").is_some());
    }

    #[test]
    fn opencode_free_is_in_the_provider_catalog_for_the_portal() {
        let catalog = provider_catalog_from_env();
        let entry = catalog
            .iter()
            .find(|e| e.key == "opencode-free")
            .expect("opencode-free catalog entry");
        assert_eq!(entry.base_url, "https://opencode.ai/zen/v1");
        assert_eq!(entry.dialect, "opencode_free");
        assert!(!entry.oauth && entry.key_env.is_empty());
    }

    #[test]
    fn generated_key_format() {
        let key = generate_key().expect("generate key");
        assert!(key.starts_with("sk-brighto-"));
        assert_eq!(key.len(), "sk-brighto-".len() + 32);
        assert!(
            key["sk-brighto-".len()..]
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
    }

    #[test]
    fn hash_prefix_length() {
        let key = generate_key().expect("generate key");
        let hash_bytes = Sha256::digest(key.as_bytes());
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);
        assert_eq!(hash.len(), 32);

        let prefix: String = key.chars().take(8).collect();
        assert_eq!(prefix.len(), 8);
    }

    #[test]
    fn master_key_validation_rejects_empty() {
        assert_eq!(validate_master_key("secret".into()), "secret");
        // whitespace-only phải bị chặn (footgun: key trông có vẻ set nhưng thực ra rỗng).
        let r = std::panic::catch_unwind(|| validate_master_key("   ".into()));
        assert!(r.is_err(), "empty/whitespace master key must panic");
    }

    #[test]
    fn prompt_bucket_and_duration_formatting() {
        assert_eq!(prompt_size_bucket(0), "<2k");
        assert_eq!(prompt_size_bucket(1_999), "<2k");
        assert_eq!(prompt_size_bucket(2_000), "2k-32k");
        assert_eq!(prompt_size_bucket(127_999), "32k-128k");
        assert_eq!(prompt_size_bucket(128_000), "128k+");
        assert_eq!(prompt_size_bucket(200_058), "128k+");

        assert_eq!(format_duration(123), "123 ms");
        assert_eq!(format_duration(1_800), "1.8 s");
        assert_eq!(format_duration(228_453), "3m 48s");
        assert_eq!(format_duration(228_000), "3m 48s");
        assert_eq!(format_duration(-1), "—");
    }

    #[test]
    fn token_throughput_calculation() {
        // 200066 tokens in 228453ms ~ 875.8 tok/s (CODEX call-log ví dụ).
        let t = tokens_per_second(200_066, 228_453).unwrap();
        assert!((t - 875.8).abs() < 0.5, "got {t}");
        assert_eq!(tokens_per_second(100, 0), Some(100_000.0));
        assert_eq!(tokens_per_second(100, -5), Some(100_000.0));
        assert_eq!(tokens_per_second(0, 0), None);
    }

    #[test]
    fn admin_auth_rejects_bad_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-admin-key", "secret".parse().unwrap());

        let err = check_admin_auth(
            "secret",
            &["10.0.0.0/8".to_string()],
            &headers,
            "1.2.3.4".parse().unwrap(),
        )
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn extract_api_key_prefers_bearer_then_x_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer secret-key".parse().unwrap());
        assert_eq!(extract_api_key(&headers).as_deref(), Some("secret-key"));

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "xkey".parse().unwrap());
        assert_eq!(extract_api_key(&headers).as_deref(), Some("xkey"));

        assert!(extract_api_key(&HeaderMap::new()).is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn stats_aggregate_daily_by_model(pool: PgPool) -> anyhow::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let today = (now / 86_400) * 86_400;

        let insert = |rid: &str, model: &str, input: i64, output: i64| {
            sqlx::query(
                "INSERT INTO usage_ledger \
                 (ts, request_id, key_id, team_id, model, backend_id, status, \
                  input_tokens, output_tokens, estimated, ttfb_ms, total_ms, router_overhead_ms, stream, client_aborted) \
                 VALUES ($1, $2, 1, 1, $3, 1, 200, $4, $5, false, 0, 0, 0, false, false)",
            )
            .bind(today)
            .bind(rid)
            .bind(model)
            .bind(input)
            .bind(output)
            .execute(&pool)
        };
        insert("r1", "model-a", 100, 10).await?;
        insert("r2", "model-a", 50, 5).await?;
        insert("r3", "model-b", 30, 3).await?;

        let stats = query_stats(&pool, None, None, 30).await.expect("stats");
        let a = stats
            .iter()
            .find(|s| s.model == "model-a")
            .expect("model-a present");
        assert_eq!(a.input_tokens, 150);
        assert_eq!(a.output_tokens, 15);
        assert_eq!(a.requests, 2);
        let b = stats
            .iter()
            .find(|s| s.model == "model-b")
            .expect("model-b present");
        assert_eq!(b.input_tokens, 30);
        assert_eq!(b.requests, 1);
        Ok(())
    }
}
