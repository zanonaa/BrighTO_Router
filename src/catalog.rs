//! Dynamic model catalogs: a `dynamic_models` backend's model list ALWAYS comes from the
//! upstream `GET {base_url}/models`, never from a hardcoded route table.
//!
//! A background loop (same shape as the backend health loop in `route`) refreshes every enabled
//! dynamic backend every ~5 minutes. When a request misses both the route table and every
//! passthrough catalog, a single bounded synchronous refresh runs before the 404, so a model
//! that just appeared upstream routes without waiting for the next tick.
//!
//! The store is a DashMap of immutable catalogs: the request path only reads it (never holding
//! a guard across an `.await`), the refresher is the sole writer, and a failed fetch keeps the
//! last-good catalog so a flaky upstream never empties the route surface.
//!
//! `fetched_at` is a caller-supplied epoch-ms value (and the staleness/claim decisions take
//! `now_ms` parameters) so tests can inject the clock instead of sleeping.

use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashMap;

use crate::contract::{Backend, BackendFormat, ConfigSnapshot};
use crate::provider_auth;

/// Background refresh cadence for every enabled `dynamic_models` backend (~5 minutes).
pub const REFRESH_INTERVAL_SECS: u64 = 300;
/// A catalog older than this makes an on-miss request eligible for the bounded synchronous
/// refresh (~60s).
pub const ON_MISS_STALE_MS: u64 = 60_000;
/// Stampede guard: at most one on-miss refresh claim per window, however many requests miss.
pub const ON_MISS_BACKOFF_MS: u64 = 10_000;
/// Hard bound on how long the on-miss refresh may block a request before it gives up.
pub const ON_MISS_BUDGET: Duration = Duration::from_secs(3);
/// Per-backend fetch timeout, same order of magnitude as the admin Load-models probe.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// One catalog fetch, injectable so tests need no network.
pub type ModelsFetchFuture = Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send>>;
pub type ModelsFetch = Arc<dyn Fn(reqwest::Client, Backend) -> ModelsFetchFuture + Send + Sync>;

/// Live fetch of one backend's catalog through the shared `provider_auth::apply_headers` choke
/// point — the same plan the proxy and the admin probes use, so a green catalog fetch proves
/// the real upstream request carries the same credential and provider headers.
pub fn default_models_fetch() -> ModelsFetch {
    Arc::new(|client: reqwest::Client, backend: Backend| {
        Box::pin(async move { fetch_models_once(client, backend).await })
    })
}

async fn fetch_models_once(
    client: reqwest::Client,
    backend: Backend,
) -> Result<Vec<String>, String> {
    // Same URL join as the admin Load-models probe: a base_url that already carries a path
    // prefix (e.g. https://opencode.ai/zen/v1) gets /models appended, not /v1 twice.
    let url = crate::admin::join_provider_url(&backend.base_url, "/v1/models");
    let mut req = client.get(url).timeout(FETCH_TIMEOUT);
    // The free-tier marker selects the identity-header plan; every other backend sends its own
    // resolved key in the header its dialect expects (bearer / x-api-key + anthropic-version).
    let (auth_mode, anthropic_dialect) = if backend.opencode_free {
        (provider_auth::OPENCODE_FREE_AUTH_MODE, false)
    } else {
        (
            match backend.format {
                BackendFormat::Anthropic => "anthropic",
                BackendFormat::OpenAi => "bearer",
            },
            backend.format == BackendFormat::Anthropic,
        )
    };
    let plan = provider_auth::resolve(auth_mode, anthropic_dialect, None);
    let mut headers = reqwest::header::HeaderMap::new();
    provider_auth::apply_headers(
        &mut headers,
        &plan,
        backend.api_key.as_deref().unwrap_or(""),
    )
    .map_err(|e| format!("build catalog headers: {e}"))?;
    req = req.headers(headers);
    let resp = req
        .send()
        .await
        .map_err(|e| format!("catalog request failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("catalog endpoint returned {status}"));
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| format!("read catalog body: {e}"))?;
    Ok(parse_model_ids(&body)?.into_iter().collect())
}

/// Parse an OpenAI-shaped model list: `{"data": [{"id": "..."}, ...]}`. Ids are trimmed,
/// empties dropped, the result deduped and sorted. A body without a `data` array is an error
/// so the caller keeps its last-good catalog instead of adopting garbage.
pub fn parse_model_ids(body: &[u8]) -> Result<BTreeSet<String>, String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("catalog body is not JSON: {e}"))?;
    let Some(items) = value.get("data").and_then(|v| v.as_array()) else {
        return Err("catalog body has no 'data' array".to_string());
    };
    Ok(items
        .iter()
        .filter_map(|item| {
            item.get("id")
                .or_else(|| item.get("name"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .collect())
}

/// The last-known catalog of one backend. `fetched_at_ms` is when the CURRENT ids were
/// fetched (0 = never fetched successfully); `ok` is the outcome of the last ATTEMPT.
#[derive(Debug, Clone)]
pub struct BackendCatalog {
    pub backend_id: i64,
    pub model_ids: BTreeSet<String>,
    pub fetched_at_ms: u64,
    pub ok: bool,
}

impl BackendCatalog {
    pub fn contains(&self, model: &str) -> bool {
        self.model_ids.contains(model)
    }

    pub fn is_stale(&self, now_ms: u64, max_age_ms: u64) -> bool {
        now_ms.saturating_sub(self.fetched_at_ms) > max_age_ms
    }
}

pub struct DynamicCatalogStore {
    entries: DashMap<i64, BackendCatalog>,
    fetcher: ModelsFetch,
    /// Epoch ms of the last claimed on-miss refresh (0 = never).
    last_on_miss_refresh_ms: AtomicU64,
}

impl DynamicCatalogStore {
    pub fn new(fetcher: ModelsFetch) -> Self {
        Self {
            entries: DashMap::new(),
            fetcher,
            last_on_miss_refresh_ms: AtomicU64::new(0),
        }
    }

    pub fn new_default() -> Self {
        Self::new(default_models_fetch())
    }

    pub fn catalog(&self, backend_id: i64) -> Option<BackendCatalog> {
        self.entries.get(&backend_id).map(|e| e.value().clone())
    }

    /// Owned ids of one catalog (admin JSON + /v1/models union; not the request path).
    pub fn model_ids(&self, backend_id: i64) -> Option<Vec<String>> {
        self.entries
            .get(&backend_id)
            .map(|e| e.model_ids.iter().cloned().collect())
    }

    /// Allocation-free membership check used by the passthrough hot-path fallback.
    pub fn contains(&self, backend_id: i64, model: &str) -> bool {
        self.entries
            .get(&backend_id)
            .is_some_and(|e| e.value().contains(model))
    }

    /// A missing catalog counts as stale: it has never been fetched.
    pub fn is_stale(&self, backend_id: i64, now_ms: u64, max_age_ms: u64) -> bool {
        self.entries
            .get(&backend_id)
            .map(|e| e.value().is_stale(now_ms, max_age_ms))
            .unwrap_or(true)
    }

    pub fn last_on_miss_refresh_ms(&self) -> u64 {
        self.last_on_miss_refresh_ms.load(Ordering::Acquire)
    }

    /// Merge one fetch outcome. Success replaces the ids wholesale; failure keeps the
    /// last-good ids and only flips `ok` (an entry is created failed-but-empty when there was
    /// nothing to keep, so the admin catalog view can still surface the failure).
    pub fn apply_fetch(&self, backend_id: i64, result: Result<Vec<String>, String>, now_ms: u64) {
        match result {
            Ok(ids) => {
                self.entries.insert(
                    backend_id,
                    BackendCatalog {
                        backend_id,
                        model_ids: ids.into_iter().collect(),
                        fetched_at_ms: now_ms,
                        ok: true,
                    },
                );
            }
            Err(_) => match self.entries.get_mut(&backend_id) {
                Some(mut entry) => entry.ok = false,
                None => {
                    self.entries.insert(
                        backend_id,
                        BackendCatalog {
                            backend_id,
                            model_ids: BTreeSet::new(),
                            fetched_at_ms: 0,
                            ok: false,
                        },
                    );
                }
            },
        }
    }

    /// Drop catalogs of backends that no longer exist in the config snapshot.
    pub fn retain_live(&self, live: &HashSet<i64>) {
        self.entries.retain(|id, _| live.contains(id));
    }

    /// Claim the single on-miss refresh slot for this window (stampede guard). The claim is a
    /// compare-exchange loop, so exactly one of N concurrent misses refreshes.
    pub fn claim_on_miss_refresh(&self, now_ms: u64) -> bool {
        let mut current = self.last_on_miss_refresh_ms.load(Ordering::Acquire);
        loop {
            if current != 0 && now_ms.saturating_sub(current) < ON_MISS_BACKOFF_MS {
                return false;
            }
            match self.last_on_miss_refresh_ms.compare_exchange(
                current,
                now_ms,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Fetch every target sequentially and merge the outcomes. Shared by the background loop
    /// and by the bounded on-miss refresh (which wraps this in a timeout).
    pub async fn refresh_backends(&self, client: reqwest::Client, targets: &[Backend]) {
        for backend in targets {
            let fetched_at = epoch_ms();
            match (self.fetcher)(client.clone(), backend.clone()).await {
                Ok(ids) => self.apply_fetch(backend.id, Ok(ids), fetched_at),
                Err(e) => {
                    tracing::warn!(
                        backend_id = backend.id,
                        backend = %backend.name,
                        error = %e,
                        "dynamic model catalog fetch failed; keeping last-good catalog"
                    );
                    self.apply_fetch(backend.id, Err(e), fetched_at);
                }
            }
        }
    }

    /// On-miss path: refresh only when some target catalog is stale AND the refresh slot is
    /// free, hard-bounded so a request never blocks more than a few seconds. Partial results
    /// that landed before the deadline survive (each fetch merges on completion).
    pub async fn refresh_on_miss(
        &self,
        client: reqwest::Client,
        targets: &[Backend],
        now_ms: u64,
    ) -> bool {
        if targets.is_empty()
            || !targets
                .iter()
                .any(|b| self.is_stale(b.id, now_ms, ON_MISS_STALE_MS))
            || !self.claim_on_miss_refresh(now_ms)
        {
            return false;
        }
        let refresh = self.refresh_backends(client, targets);
        if tokio::time::timeout(ON_MISS_BUDGET, refresh).await.is_err() {
            tracing::warn!(
                budget_ms = ON_MISS_BUDGET.as_millis() as u64,
                "dynamic catalog on-miss refresh deadline reached; retrying with what landed"
            );
        }
        true
    }

    /// Enabled `dynamic_models` backends of a snapshot — the background refresh target set.
    pub fn dynamic_targets(snapshot: &ConfigSnapshot) -> Vec<Backend> {
        snapshot
            .backends
            .values()
            .filter(|b| b.enabled && b.dynamic_models)
            .cloned()
            .collect()
    }

    /// Background refresher, same pattern as `RamBackendPool::start_health_loop`: every
    /// `interval`, fetch every enabled dynamic backend, then prune catalogs of backends that
    /// disappeared from the config. The first tick fires immediately, which also seeds
    /// catalogs at boot.
    pub fn start_refresh_loop(
        self: Arc<Self>,
        cfg: Arc<ArcSwap<ConfigSnapshot>>,
        client: reqwest::Client,
        interval: Duration,
    ) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let snapshot = cfg.load_full();
                let targets = Self::dynamic_targets(&snapshot);
                let live: HashSet<i64> = snapshot.backends.keys().copied().collect();
                drop(snapshot);
                self.retain_live(&live);
                if targets.is_empty() {
                    continue;
                }
                tracing::debug!(
                    backends = targets.len(),
                    "refreshing dynamic model catalogs"
                );
                self.refresh_backends(client.clone(), &targets).await;
            }
        });
    }
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(id: i64, dynamic: bool) -> Backend {
        Backend {
            id,
            name: format!("backend-{id}"),
            base_url: format!("http://127.0.0.1:9{id}00"),
            api_key_ref: String::new(),
            api_key: None,
            weight: 1,
            max_inflight: 0,
            format: BackendFormat::OpenAi,
            opencode_free: false,
            dynamic_models: dynamic,
            enabled: true,
        }
    }

    /// Fetcher stub returning `ids` and counting calls; tests assert on the call count to
    /// prove the stampede guard and staleness gate actually fire.
    fn counting_fetcher(ids: Vec<&str>) -> (ModelsFetch, Arc<AtomicU64>) {
        let calls = Arc::new(AtomicU64::new(0));
        let out: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
        let counter = calls.clone();
        (
            Arc::new(move |_client: reqwest::Client, _backend: Backend| {
                counter.fetch_add(1, Ordering::SeqCst);
                let out = out.clone();
                Box::pin(async move { Ok(out) })
            }),
            calls,
        )
    }

    #[test]
    fn parse_reads_openai_shaped_catalogs() {
        let ids = parse_model_ids(br#"{"object":"list","data":[{"id":"qwen3-coder","object":"model"},{"id":"gpt-5.6-mini"},{"id":"qwen3-coder"}]}"#)
            .expect("parse");
        assert_eq!(
            ids,
            BTreeSet::from(["qwen3-coder".to_string(), "gpt-5.6-mini".to_string()]),
            "duplicate ids deduped, sorted order"
        );
    }

    #[test]
    fn parse_skips_items_without_a_usable_id() {
        let ids = parse_model_ids(
            br#"{"data":[{"id":"keep"},{"id":""},{"id":"  "},{"object":"model"},{"name":"named"}]}"#,
        )
        .expect("parse");
        assert_eq!(
            ids,
            BTreeSet::from(["keep".to_string(), "named".to_string()])
        );
    }

    #[test]
    fn parse_accepts_an_empty_catalog_but_rejects_other_shapes() {
        assert!(
            parse_model_ids(br#"{"data":[]}"#)
                .expect("empty catalog is valid")
                .is_empty()
        );
        assert!(parse_model_ids(br#"{"models":[{"id":"x"}]}"#).is_err());
        assert!(parse_model_ids(br#"{"data":{"id":"x"}}"#).is_err());
        assert!(parse_model_ids(b"not json").is_err());
    }

    #[test]
    fn apply_fetch_replaces_on_success_and_keeps_last_good_on_failure() {
        let store = DynamicCatalogStore::new_default();
        store.apply_fetch(7, Ok(vec!["a".into(), "b".into()]), 1_000);
        let catalog = store.catalog(7).expect("catalog");
        assert!(catalog.ok);
        assert_eq!(catalog.fetched_at_ms, 1_000);
        assert!(store.contains(7, "a"));

        // Failure: ids and fetched_at survive, only `ok` flips.
        store.apply_fetch(7, Err("boom".to_string()), 9_000);
        let catalog = store.catalog(7).expect("catalog");
        assert!(!catalog.ok);
        assert_eq!(catalog.fetched_at_ms, 1_000, "last-good timestamp kept");
        assert!(store.contains(7, "a") && store.contains(7, "b"));

        // Recovery replaces wholesale.
        store.apply_fetch(7, Ok(vec!["c".into()]), 20_000);
        let catalog = store.catalog(7).expect("catalog");
        assert!(catalog.ok);
        assert_eq!(catalog.fetched_at_ms, 20_000);
        assert!(!store.contains(7, "a"));
        assert!(store.contains(7, "c"));
    }

    #[test]
    fn apply_fetch_failure_without_history_records_an_empty_failed_catalog() {
        let store = DynamicCatalogStore::new_default();
        store.apply_fetch(9, Err("upstream down".to_string()), 5_000);
        let catalog = store
            .catalog(9)
            .expect("failed entry still visible to admin");
        assert!(!catalog.ok);
        assert!(catalog.model_ids.is_empty());
        assert_eq!(catalog.fetched_at_ms, 0);
        assert!(
            store.is_stale(9, 5_000, ON_MISS_STALE_MS),
            "never fetched = stale"
        );
    }

    #[test]
    fn staleness_uses_the_injected_clock() {
        let store = DynamicCatalogStore::new_default();
        assert!(
            store.is_stale(1, 60_000, ON_MISS_STALE_MS),
            "missing = stale"
        );
        store.apply_fetch(1, Ok(vec!["m".into()]), 10_000);
        assert!(!store.is_stale(1, 60_000, ON_MISS_STALE_MS));
        assert!(
            !store.is_stale(1, 70_000, ON_MISS_STALE_MS),
            "exactly max-age is fresh"
        );
        assert!(store.is_stale(1, 70_001, ON_MISS_STALE_MS));
    }

    #[test]
    fn on_miss_claim_is_single_shot_per_backoff_window() {
        let store = DynamicCatalogStore::new_default();
        assert!(store.claim_on_miss_refresh(100_000), "first claim wins");
        assert!(!store.claim_on_miss_refresh(100_050), "inside backoff");
        assert!(!store.claim_on_miss_refresh(100_000 + ON_MISS_BACKOFF_MS - 1));
        assert!(
            store.claim_on_miss_refresh(100_000 + ON_MISS_BACKOFF_MS),
            "window elapsed -> claim again"
        );
        assert_eq!(
            store.last_on_miss_refresh_ms(),
            100_000 + ON_MISS_BACKOFF_MS
        );
    }

    #[tokio::test]
    async fn on_miss_refresh_runs_the_shared_fetcher_and_updates_the_catalog() {
        let (fetch, calls) = counting_fetcher(vec!["brand-new-model"]);
        let store = DynamicCatalogStore::new(fetch);
        assert!(
            !store.contains(7, "brand-new-model"),
            "catalog starts empty"
        );

        let refreshed = store
            .refresh_on_miss(
                reqwest::Client::new(),
                &[backend(7, true)],
                60_000, // no entry -> stale
            )
            .await;
        assert!(refreshed, "stale catalog must trigger the refresh");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one fetch");
        assert!(store.contains(7, "brand-new-model"));
    }

    #[tokio::test]
    async fn on_miss_refresh_skips_fresh_catalogs_and_respects_the_backoff() {
        let (fetch, calls) = counting_fetcher(vec!["m"]);
        let store = DynamicCatalogStore::new(fetch);

        // Fresh catalog: no refresh even before any claim.
        store.apply_fetch(7, Ok(vec!["m".into()]), 60_000);
        assert!(
            !store
                .refresh_on_miss(reqwest::Client::new(), &[backend(7, true)], 60_500)
                .await
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // Stale but the slot was claimed moments ago: stampede guard wins.
        store.apply_fetch(8, Ok(vec!["m".into()]), 0);
        assert!(store.claim_on_miss_refresh(60_000));
        assert!(
            !store
                .refresh_on_miss(
                    reqwest::Client::new(),
                    &[backend(7, true), backend(8, true)],
                    60_050
                )
                .await
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no second refresh inside the backoff window"
        );

        // Empty target list is a no-op.
        assert!(
            !store
                .refresh_on_miss(reqwest::Client::new(), &[], 61_000)
                .await
        );
    }

    #[test]
    fn retain_live_drops_catalogs_of_removed_backends() {
        let store = DynamicCatalogStore::new_default();
        store.apply_fetch(1, Ok(vec!["m".into()]), 1);
        store.apply_fetch(2, Ok(vec!["m".into()]), 1);
        store.retain_live(&HashSet::from([2]));
        assert!(store.catalog(1).is_none());
        assert!(store.catalog(2).is_some());
    }

    #[test]
    fn dynamic_targets_filters_enabled_dynamic_backends() {
        let mut snapshot = ConfigSnapshot::default();
        let mut a = backend(1, true);
        a.enabled = false;
        let b = backend(2, true);
        let mut c = backend(3, false);
        c.enabled = true;
        snapshot.backends.insert(1, a);
        snapshot.backends.insert(2, b);
        snapshot.backends.insert(3, c);
        let targets = DynamicCatalogStore::dynamic_targets(&snapshot);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, 2);
    }
}
