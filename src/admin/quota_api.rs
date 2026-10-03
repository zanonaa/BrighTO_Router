//! Admin API for per-provider quota.
//!
//! Auth is the same master-key + CIDR check every other `/admin` route uses. Read-only by default:
//! `GET /admin/quota` never touches the network, so opening the Portal cannot become a source of
//! load on a provider. Probing is a separate, explicit `POST`.
//!
//! ## What the numbers mean
//!
//! `used` and `total` are what the provider reported; the percentage is **not** in the payload.
//! The Portal derives it. That is deliberate and it is the fix for a class of bug rather than a
//! style choice: a reference implementation stored a `remaining` field, a provider put a credit
//! count in it, and the UI rendered "348%" because it read the field as a percentage. Returning
//! the two raw numbers and deriving at the edge means no provider can make this UI lie by choosing
//! which field to populate.
//!
//! `kind` matters for the same reason. A `balance` window has no denominator, and the Portal
//! renders it as an amount — never as a bar.
//!
//! ## Nothing here changes routing
//!
//! These endpoints report. They do not disable a backend, reorder endpoints, or arm a cooldown.

use std::sync::Arc;

use axum::{
    Json,
    extract::{ConnectInfo, Extension, Path, Query},
    http::HeaderMap,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::oauth::{self, OAuthTokenStore};
use crate::quota::{self, QuotaKey, QuotaSnapshot, QuotaWindowKind};

use super::{AdminState, ApiError, check_admin_auth};

/// One account's allowance, shaped for the Portal.
#[derive(Serialize)]
pub struct QuotaAccountView {
    provider: String,
    label: String,
    /// Subscription tier, when the provider reports one.
    plan: Option<String>,
    /// No reading anywhere in this snapshot is recent.
    stale: bool,
    /// Every reported window is empty.
    exhausted: bool,
    /// False when the provider exposes no quota endpoint, so the account is passive-only.
    active_probe_supported: bool,
    /// Which mechanisms have contributed: `provider`, `response_header`.
    sources: Vec<&'static str>,
    /// Operator-facing explanation per source that could not report.
    notes: Vec<QuotaNote>,
    windows: Vec<QuotaWindowView>,
}

#[derive(Serialize)]
pub struct QuotaNote {
    source: &'static str,
    /// True when the reading shown is an older one kept across a failed probe.
    stale: bool,
    message: String,
}

#[derive(Serialize)]
struct QuotaWindowView {
    id: &'static str,
    label: String,
    kind: QuotaWindowKind,
    used: f64,
    total: f64,
    unlimited: bool,
    /// Epoch millis, when the provider said.
    reset_at_ms: Option<u64>,
    source: &'static str,
    /// True for a window the router computed rather than one the provider stated.
    derived: bool,
    /// Coarse band: `ok` | `low` | `critical` | `unknown`. Derived from used/total.
    level: &'static str,
    exhausted: bool,
}

#[derive(Serialize)]
struct QuotaListResponse {
    accounts: Vec<QuotaAccountView>,
    /// Connected OAuth accounts with no quota endpoint. Listed so the Portal can say *why* a panel
    /// is empty instead of showing a blank table.
    passive_only: Vec<PassiveOnlyAccount>,
    /// True when nothing has been observed yet — expected on a fresh install with no traffic.
    idle: bool,
}

#[derive(Serialize)]
struct PassiveOnlyAccount {
    provider: String,
    label: String,
    reason: &'static str,
}

#[derive(Deserialize, Default)]
struct ListQuery {
    /// Probe every connected account before answering. Still rate-limited per credential.
    #[serde(default)]
    probe: bool,
}

async fn list_quota(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<QuotaListResponse>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;

    if query.probe {
        // Errors per account are reported inside each account's note; one provider being down must
        // not blank the whole panel.
        state.quota_probe().await.refresh_all(true).await;
    }

    let known = state.runtime.quota.snapshot_all();
    let mut accounts: Vec<QuotaAccountView> = known.iter().map(|s| view_of(s)).collect();

    // Accounts that exist but have produced nothing yet.
    let store = OAuthTokenStore::from_env();
    let mut passive_only = Vec::new();
    for token in store.list() {
        let key = QuotaKey::new(&token.provider, &token.label);
        if state.runtime.quota.get(&key).is_some() {
            continue;
        }
        let (supported, reason) = match oauth::spec(&token.provider).and_then(|s| s.quota_probe) {
            Some(_) => (true, "not probed yet"),
            None => (
                false,
                "provider exposes no quota endpoint — observed from response headers only",
            ),
        };
        if supported {
            continue;
        }
        passive_only.push(PassiveOnlyAccount {
            provider: token.provider,
            label: token.label,
            reason,
        });
    }

    accounts.sort_by(|a, b| a.provider.cmp(&b.provider).then(a.label.cmp(&b.label)));
    Ok(Json(QuotaListResponse {
        idle: accounts.is_empty(),
        accounts,
        passive_only,
    }))
}

async fn probe_one_account(
    Extension(state): Extension<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Path((provider, label)): Path<(String, String)>,
) -> Result<Json<QuotaAccountView>, ApiError> {
    check_admin_auth(&state.master_key, &state.allow_cidrs, &headers, peer.ip())?;

    let key = QuotaKey::new(&provider, &label);
    if oauth::spec(&provider).is_none() {
        return Err(ApiError::bad_request(format!(
            "unknown OAuth provider {provider}"
        )));
    }
    // A probe of an account that does not exist is a client error, not an observation: returning
    // 200 with an empty view would make a typo look like "no data yet". Reading the store here
    // matches what the listing does, and costs one stat + read of a 0600 file.
    if OAuthTokenStore::from_env().read(&provider, &label).is_err() {
        return Err(ApiError::bad_request(format!(
            "no connected account {provider}/{label}"
        )));
    }

    let result = state.quota_probe().await.refresh(&key, true).await;
    let snapshot =
        state.runtime.quota.get(&key).ok_or_else(|| {
            ApiError::bad_request(format!("no quota reading for {provider}/{label}"))
        })?;

    let mut view = view_of(&snapshot);
    // Surface a refusal that the snapshot itself does not carry, e.g. the min-interval gate.
    if let Some(note) = result.note {
        view.notes.insert(
            0,
            QuotaNote {
                source: quota::QuotaSource::Provider.as_str(),
                stale: true,
                message: note,
            },
        );
    }
    Ok(Json(view))
}

fn view_of(snapshot: &QuotaSnapshot) -> QuotaAccountView {
    let now = quota::now_ms();
    let mut sources = Vec::new();
    let mut notes = Vec::new();

    for set in [snapshot.probe.as_ref(), snapshot.headers.as_ref()]
        .into_iter()
        .flatten()
    {
        if set.is_empty() {
            continue;
        }
        sources.push(set.source.as_str());
        if set.stale
            && let Some(note) = &set.note
        {
            notes.push(QuotaNote {
                source: set.source.as_str(),
                stale: true,
                message: note.clone(),
            });
        }
    }

    let windows = snapshot
        .effective_windows()
        .into_iter()
        .map(|w| QuotaWindowView {
            id: w.id.as_str(),
            label: w.id.label(w.variant.as_deref()),
            kind: w.kind,
            used: w.used,
            total: w.total,
            unlimited: w.unlimited,
            reset_at_ms: w.reset_at,
            source: w.source.as_str(),
            derived: w.source == quota::QuotaSource::RouterDerived,
            level: w.level(),
            exhausted: w.is_exhausted(),
        })
        .collect();

    QuotaAccountView {
        provider: snapshot.provider.to_string(),
        label: snapshot.label.to_string(),
        plan: snapshot.plan.as_deref().map(str::to_string),
        stale: snapshot.is_stale(now),
        exhausted: snapshot.is_exhausted(),
        active_probe_supported: oauth::spec(&snapshot.provider)
            .is_some_and(|s| s.quota_probe.is_some()),
        sources,
        notes,
        windows,
    }
}

pub fn routes() -> axum::Router {
    axum::Router::new()
        .route("/quota", get(list_quota))
        .route("/quota/{provider}/{label}/probe", post(probe_one_account))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quota::{QuotaSource, QuotaWindow, QuotaWindowId, now_ms, rank_truncate};

    fn window(id: QuotaWindowId, used: f64, total: f64, source: QuotaSource) -> QuotaWindow {
        QuotaWindow {
            id,
            kind: QuotaWindowKind::Window,
            used,
            total,
            unlimited: false,
            reset_at: Some(now_ms() + 3_600_000),
            source,
            variant: None,
        }
    }

    #[test]
    fn a_view_carries_raw_numbers_and_never_a_precomputed_percentage() {
        let key = QuotaKey::new("codex", "acct");
        let store = quota::QuotaStore::new();
        store.record_probe(
            &key,
            vec![window(
                QuotaWindowId::FiveHour,
                42.0,
                100.0,
                QuotaSource::Provider,
            )],
            Some("pro".into()),
            false,
            None,
        );

        let snapshot = store.get(&key).unwrap();
        let view = view_of(&snapshot);
        assert_eq!(view.plan.as_deref(), Some("pro"));
        assert!(!view.stale);
        assert_eq!(view.windows.len(), 1);
        let w = &view.windows[0];
        assert_eq!(w.id, "five_hour");
        assert_eq!(w.label, "Session (5h)");
        assert_eq!(w.used, 42.0);
        assert_eq!(w.total, 100.0);
        assert_eq!(
            w.level, "low",
            "42% used leaves 58%, which is the middle band — 58% is not 'plenty'"
        );
        assert!(!w.derived);
        assert!(!w.exhausted);
        assert!(
            !serde_json::to_string(w).unwrap().contains("remaining"),
            "the payload must not precompute a percentage a provider could poison"
        );
    }

    #[test]
    fn a_balance_window_is_marked_as_such_and_scored_unknown() {
        let key = QuotaKey::new("xai-oauth", "acct");
        let store = quota::QuotaStore::new();
        store.record_probe(
            &key,
            vec![quota::observe::balance_window(
                QuotaWindowId::OnDemand,
                348.0,
                QuotaSource::Provider,
            )],
            None,
            false,
            None,
        );
        let view = view_of(&store.get(&key).unwrap());
        let w = &view.windows[0];
        assert_eq!(w.kind, QuotaWindowKind::Balance);
        assert_eq!(w.level, "unknown", "a count has no percentage");
        assert!(!w.exhausted);
    }

    #[test]
    fn a_derived_window_is_flagged() {
        let key = QuotaKey::new("codex", "acct");
        let store = quota::QuotaStore::new();
        store.record_probe(
            &key,
            vec![
                window(QuotaWindowId::SevenDay, 20.0, 100.0, QuotaSource::Provider),
                window(
                    QuotaWindowId::DerivedMonth,
                    86.9,
                    100.0,
                    QuotaSource::RouterDerived,
                ),
            ],
            None,
            false,
            None,
        );
        let view = view_of(&store.get(&key).unwrap());
        let derived: Vec<&QuotaWindowView> = view.windows.iter().filter(|w| w.derived).collect();
        assert_eq!(derived.len(), 1);
        assert_eq!(derived[0].id, "derived_month");
        assert_eq!(derived[0].label, "Monthly (derived)");
    }

    #[test]
    fn a_failed_probe_keeps_the_previous_reading_and_says_why() {
        let key = QuotaKey::new("claude-code", "acct");
        let store = quota::QuotaStore::new();
        store.record_probe(
            &key,
            vec![window(
                QuotaWindowId::FiveHour,
                10.0,
                100.0,
                QuotaSource::Provider,
            )],
            None,
            false,
            None,
        );
        store.record_probe(
            &key,
            vec![window(
                QuotaWindowId::FiveHour,
                10.0,
                100.0,
                QuotaSource::Provider,
            )],
            None,
            true,
            Some("provider returned HTTP 503".into()),
        );

        let view = view_of(&store.get(&key).unwrap());
        assert_eq!(
            view.windows.len(),
            1,
            "the old reading survives the failure"
        );
        assert_eq!(view.notes.len(), 1);
        assert!(view.notes[0].stale);
        assert_eq!(view.notes[0].message, "provider returned HTTP 503");
    }

    #[test]
    fn probe_support_is_reported_per_provider() {
        for spec in oauth::PROVIDERS {
            let key = QuotaKey::new(spec.key, "acct");
            let store = quota::QuotaStore::new();
            store.record_probe(&key, vec![], None, false, None);
            let view = view_of(&store.get(&key).unwrap());
            assert_eq!(
                view.active_probe_supported,
                spec.quota_probe.is_some(),
                "{} probe support",
                spec.key
            );
        }
    }

    #[test]
    fn the_view_is_renderable_before_any_number_exists() {
        let key = QuotaKey::new("codex", "acct");
        let store = quota::QuotaStore::new();
        store.record_probe(&key, Vec::new(), None, false, None);
        let view = view_of(&store.get(&key).unwrap());
        assert!(view.windows.is_empty());
        assert!(!view.exhausted, "no windows is not the same as empty");
        assert!(view.sources.is_empty());
    }

    #[test]
    fn truncation_applies_before_the_payload_is_built() {
        // The view must not be able to exceed the cap even if a parser slips past it.
        let many: Vec<QuotaWindow> = QuotaWindowId::ALL
            .iter()
            .map(|id| window(*id, 1.0, 100.0, QuotaSource::Provider))
            .collect();
        assert!(many.len() > quota::MAX_WINDOWS);
        assert_eq!(rank_truncate(many).len(), quota::MAX_WINDOWS);
    }
}
