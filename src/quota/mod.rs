//! Per-provider quota observation.
//!
//! This module answers one question: *how much of this account's allowance is left?* It answers
//! it from two independent sources and keeps them apart on purpose.
//!
//! * **Active probe** ([`probe`]) — ask the provider directly. Only possible for OAuth-backed
//!   routes, because it needs the account's own credential. Authoritative, costs a request.
//! * **Passive observation** ([`observe`]) — read the quota headers the provider already attached
//!   to an inference response. Free, works for API-key routes too, but only appears once traffic
//!   has actually flowed and only covers the windows the provider chose to report.
//!
//! ## The data model is `used`/`total`, never `remaining`
//!
//! There is deliberately no `remaining` field on [`QuotaWindow`]. A reference implementation
//! (VansRouter) shipped a bug of exactly this shape: a provider returned `remaining: 348`, which
//! was a *count of credits*, and the UI — which read `remaining` as a 0-100 percentage — rendered
//! "348%". Storing the two numbers the provider actually reports and deriving the fraction at the
//! display edge means a provider cannot make the UI lie by choosing which field to populate.
//!
//! [`QuotaWindowKind`] exists for the same reason. A prepaid credit balance is not a fraction of
//! anything, so rendering one as a percentage is wrong even when the arithmetic is right.
//!
//! ## Unknown is not zero
//!
//! [`QuotaWindow::remaining_fraction`] returns `Option<f64>`: `None` means "this provider did not
//! report enough to say", which is a different statement from `Some(0.0)`. Collapsing the two is
//! how an operator ends up staring at "0% remaining" for a window that simply was not reported.
//!
//! ## Observations never merge
//!
//! Two snapshots of the same window from the same source replace each other wholesale; they are
//! never blended field-by-field. Merging makes the result depend on arrival order and lets a
//! partial read resurrect a stale number. The two *sources* are also kept in separate slots
//! rather than being unified into one list, so provenance survives all the way to the Portal.
//! [`QuotaSnapshot::effective_windows`] is where the preference order is applied — and it is one
//! function, so the rule is testable.
//!
//! ## This does not change routing
//!
//! Nothing here feeds the circuit breaker, the retry policy, or endpoint selection. Observation
//! and cooldown are separate mechanisms on purpose: an out-of-credit 402 becoming a five-minute
//! backoff is a real failure mode, but it is a *routing* change and needs its own evidence. The
//! strongest reference implementation makes the same cut — its quota subsystem is thirteen
//! handlers of pure observation, and its cooldown path is fed by 429 body text, never by a quota
//! reading.

pub mod observe;
pub mod probe;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::Serialize;

/// Upper bound on windows retained per observation set.
///
/// Claude exposes one weekly window *per model family* (`seven_day_sonnet`, `seven_day_opus`, …),
/// discovered generically, so a busy account can report far more than a handful. Six is the
/// number of named windows the model knows about; anything past that is a model-specific extra
/// and is dropped by [`QuotaWindowId::rank`] order. See [`observe::MAX_HEADERS`] for the other
/// bound.
pub const MAX_WINDOWS: usize = 6;

/// A snapshot older than this is rendered as stale. Deliberately generous: these are
/// five-hour-to-month windows, so a reading from an hour ago is still informative — the flag
/// exists to say "this is not current", not to hide the number.
pub const STALE_AFTER_MS: u64 = 60 * 60 * 1000;

/// Which mechanism produced a set of windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaSource {
    /// Asked the provider's quota endpoint.
    Provider,
    /// Read from headers on an inference response.
    ResponseHeader,
    /// Computed by the router from windows the provider did report.
    RouterDerived,
}

impl QuotaSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::ResponseHeader => "response_header",
            Self::RouterDerived => "router_derived",
        }
    }
}

/// One quota window. Every field is `Copy` except `variant`, which only exists for the
/// model-specific weekly windows a provider may enumerate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct QuotaWindow {
    pub id: QuotaWindowId,
    pub kind: QuotaWindowKind,
    /// What the provider reported as consumed. Never inferred from a `remaining`-shaped field.
    pub used: f64,
    /// The window's ceiling. `0` combined with `unlimited == false` means "not reported", which
    /// is why [`Self::remaining_fraction`] returns `Option`.
    pub total: f64,
    /// The provider explicitly stated there is no cap.
    pub unlimited: bool,
    /// Epoch millis. `None` when the provider did not say.
    pub reset_at: Option<u64>,
    pub source: QuotaSource,
    /// Model family for a model-specific window, e.g. `sonnet` for `seven_day_sonnet`.
    pub variant: Option<Box<str>>,
}

/// Whether a number is a share of a budget or an absolute balance.
///
/// This is not decoration. A balance of 348 credits rendered as "348%" is the reference
/// implementation's documented 100x bug, and it is trivially avoidable by refusing to compute a
/// fraction for a value that is not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaWindowKind {
    /// `used` out of `total`. Percentage-shaped.
    Window,
    /// An absolute balance such as a prepaid credit amount. Not percentage-shaped.
    Balance,
}

/// Named quota windows. One variant per *shape*, never per model — model-specific weekly windows
/// share [`Self::SevenDayModel`] and differ by [`QuotaWindow::variant`].
///
/// `Month` and `DerivedMonth` are deliberately distinct. Only xAI reports a monthly window
/// upstream; for Claude and Codex the router can *derive* one by interpolating the weekly
/// window, but a derived number must never be displayed as if the provider stated it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaWindowId {
    /// Rolling 5-hour session window.
    FiveHour,
    /// Rolling 7-day window.
    SevenDay,
    /// The paid overage allowance on top of a Claude weekly window.
    SevenDayOverage,
    /// xAI on-demand spend cap, or the credit balance covering it.
    OnDemand,
    /// A monthly window the provider reported.
    Month,
    /// A monthly window the router interpolated from the weekly one. Label as derived in the UI.
    DerivedMonth,
    /// A weekly window for one model family. Lowest rank: dropped first under [`MAX_WINDOWS`].
    SevenDayModel,
}

impl QuotaWindowId {
    /// Every named window, most important first.
    pub const ALL: [QuotaWindowId; 7] = [
        Self::FiveHour,
        Self::SevenDay,
        Self::SevenDayOverage,
        Self::OnDemand,
        Self::Month,
        Self::DerivedMonth,
        Self::SevenDayModel,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FiveHour => "five_hour",
            Self::SevenDay => "seven_day",
            Self::SevenDayOverage => "seven_day_overage",
            Self::OnDemand => "on_demand",
            Self::Month => "month",
            Self::DerivedMonth => "derived_month",
            Self::SevenDayModel => "seven_day_model",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|w| w.as_str() == raw)
    }

    /// Truncation order. The five-hour window is first because it is the one that trips in
    /// practice; a model-specific weekly window is last because losing one costs the operator
    /// the least.
    pub fn rank(self) -> u8 {
        match self {
            Self::FiveHour => 0,
            Self::SevenDay => 1,
            Self::SevenDayOverage => 2,
            Self::OnDemand => 3,
            Self::Month => 4,
            Self::DerivedMonth => 5,
            Self::SevenDayModel => 6,
        }
    }

    /// Short label for the Portal, e.g. `Session (5h)`.
    pub fn label(self, variant: Option<&str>) -> String {
        match self {
            Self::FiveHour => "Session (5h)".into(),
            Self::SevenDay => "Weekly (7d)".into(),
            Self::SevenDayOverage => "Weekly overage".into(),
            Self::OnDemand => "On-demand".into(),
            Self::Month => "Monthly".into(),
            // The word is load-bearing: a reader must be able to tell at a glance which numbers
            // came from the provider and which the router produced.
            Self::DerivedMonth => "Monthly (derived)".into(),
            Self::SevenDayModel => match variant {
                Some(v) => format!("Weekly (7d) — {v}"),
                None => "Weekly (7d)".into(),
            },
        }
    }
}

impl QuotaWindow {
    /// Fraction of the window still available, in `0.0..=1.0`.
    ///
    /// `None` means the provider did not report enough to say. It never means zero.
    pub fn remaining_fraction(&self) -> Option<f64> {
        if self.kind == QuotaWindowKind::Balance {
            // A balance is an amount, not a share. Returning a number here is what produced
            // "348%" in the reference implementation.
            return None;
        }
        if self.unlimited {
            return Some(1.0);
        }
        // `partial_cmp` rather than `total <= 0.0`: an explicit comparison of two floats says
        // what happens with NaN, which `!` on a partial comparison quietly leaves undefined.
        match self.total.partial_cmp(&0.0) {
            Some(std::cmp::Ordering::Greater) => {
                Some(((self.total - self.used) / self.total).clamp(0.0, 1.0))
            }
            _ => None,
        }
    }

    /// The window is known to have nothing left. Distinct from "not reported".
    pub fn is_exhausted(&self) -> bool {
        self.remaining_fraction() == Some(0.0)
    }

    /// True when the reading should be refreshed rather than trusted as current.
    pub fn is_stale(&self, now_ms: u64) -> bool {
        self.reset_at.is_some_and(|r| r <= now_ms)
    }

    /// Builder for the overwhelmingly common shape: a 0-100 percentage window.
    pub fn percent_window(
        id: QuotaWindowId,
        used_percent: f64,
        reset_at: Option<u64>,
        source: QuotaSource,
    ) -> Self {
        let used = used_percent.clamp(0.0, 100.0);
        Self {
            id,
            kind: QuotaWindowKind::Window,
            used,
            total: 100.0,
            unlimited: false,
            reset_at,
            source,
            variant: None,
        }
    }

    /// Coarse band for display. Thresholds match the reference implementation's, because
    /// "plenty / getting tight / out" is the distinction an operator acts on, not "62% vs 58%".
    pub fn level(&self) -> &'static str {
        match self.remaining_fraction() {
            None => "unknown",
            Some(f) if f > 0.70 => "ok",
            Some(f) if f >= 0.30 => "low",
            _ => "critical",
        }
    }
}

/// One source's contribution to an account's quota picture.
#[derive(Debug, Clone, Serialize)]
pub struct QuotaObservationSet {
    pub source: QuotaSource,
    /// Epoch millis.
    pub observed_at: u64,
    pub windows: Vec<QuotaWindow>,
    /// The provider was asked and did not answer with usable numbers; `windows` is the previous
    /// good reading, kept so a transient blip does not blank the Portal.
    pub stale: bool,
    /// Why the last probe failed, when it did. Operator-facing, never token material.
    pub note: Option<String>,
}

impl QuotaObservationSet {
    pub fn fresh(source: QuotaSource, windows: Vec<QuotaWindow>) -> Self {
        Self {
            source,
            observed_at: now_ms(),
            windows,
            stale: false,
            note: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }
}

/// Everything the router knows about one account's allowance.
///
/// Two source slots rather than one merged window list, so the Portal can say *where* a number
/// came from and so a narrow passive read cannot erase a wide active probe.
#[derive(Debug, Clone, Serialize)]
pub struct QuotaSnapshot {
    pub provider: Arc<str>,
    pub label: Arc<str>,
    /// Subscription tier, when the provider reports one.
    pub plan: Option<Arc<str>>,
    /// Active probe result.
    pub probe: Option<QuotaObservationSet>,
    /// Passive header observation.
    pub headers: Option<QuotaObservationSet>,
}

impl QuotaSnapshot {
    /// Windows to display, in precedence order, deduplicated by id+variant.
    ///
    /// A probe reading wins over a header reading for the same window; a window only seen in
    /// headers is still shown. This is the single place the preference is applied.
    pub fn effective_windows(&self) -> Vec<&QuotaWindow> {
        let mut out: Vec<&QuotaWindow> = Vec::new();
        for set in [self.probe.as_ref(), self.headers.as_ref()]
            .into_iter()
            .flatten()
        {
            for w in &set.windows {
                let dup = out
                    .iter()
                    .any(|kept| kept.id == w.id && kept.variant.as_deref() == w.variant.as_deref());
                if !dup {
                    out.push(w);
                }
            }
        }
        out.sort_by(|a, b| window_order(a).cmp(&window_order(b)));
        out
    }
    /// True when nothing in this snapshot is recent enough to trust as current.
    pub fn is_stale(&self, now_ms: u64) -> bool {
        let fresh = [self.probe.as_ref(), self.headers.as_ref()]
            .into_iter()
            .flatten()
            .any(|s| now_ms.saturating_sub(s.observed_at) < STALE_AFTER_MS);
        !fresh
    }

    /// True when every reported window is empty.
    pub fn is_exhausted(&self) -> bool {
        let windows = self.effective_windows();
        !windows.is_empty() && windows.iter().all(|w| w.is_exhausted())
    }
}

/// Keep at most [`MAX_WINDOWS`] windows, deterministically.
///
/// Order is [`QuotaWindowId::rank`] then the variant name, so a provider that reports seven
/// model-specific weekly windows always loses the same ones — the UI must not reshuffle between
/// polls, and an operator debugging a wrong number needs a stable answer to "which ones were
/// dropped".
pub fn rank_truncate(mut windows: Vec<QuotaWindow>) -> Vec<QuotaWindow> {
    // `sort_by` rather than `sort_by_key`: the key borrows from the element, and a borrowed key
    // would tie the comparator to the sort's internal lifetimes.
    windows.sort_by(|a, b| window_order(a).cmp(&window_order(b)));
    windows.truncate(MAX_WINDOWS);
    windows
}

/// The single definition of "which window sorts first".
fn window_order(w: &QuotaWindow) -> (u8, &str) {
    (w.id.rank(), w.variant.as_deref().unwrap_or(""))
}

/// Identifies one account. Fields are `Arc<str>` so the proxy can carry a resolved key without
/// allocating per request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QuotaKey {
    pub provider: Arc<str>,
    pub label: Arc<str>,
}

impl QuotaKey {
    pub fn new(provider: &str, label: &str) -> Self {
        Self {
            provider: Arc::from(provider),
            label: Arc::from(label),
        }
    }

    /// Parse the `oauth:<provider>:<label>` reference stored in `provider_key_ref`.
    pub fn from_credential_ref(reference: &str) -> Option<Self> {
        let (provider, label) = crate::oauth::parse_credential_ref(reference)?;
        Some(Self::new(provider, label))
    }
}

/// In-memory quota store. Lives on `AppState`; never persisted.
///
/// Snapshots are replaced, never mutated in place, so a reader always sees a coherent set of
/// windows from one instant rather than a half-updated mixture.
#[derive(Default)]
pub struct QuotaStore {
    map: DashMap<QuotaKey, Arc<QuotaSnapshot>>,
}

impl QuotaStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &QuotaKey) -> Option<Arc<QuotaSnapshot>> {
        self.map.get(key).map(|e| e.value().clone())
    }

    /// Record a passive header observation. Replaces any previous header slot wholesale.
    ///
    /// Returns false when nothing was observed, which is the common case: most responses carry no
    /// quota headers and the caller should do no further work.
    pub fn observe_headers(&self, key: &QuotaKey, windows: Vec<QuotaWindow>) -> bool {
        if windows.is_empty() {
            return false;
        }
        self.put(key, QuotaSource::ResponseHeader, windows, None, false, None);
        true
    }

    /// Record an active probe result.
    pub fn record_probe(
        &self,
        key: &QuotaKey,
        windows: Vec<QuotaWindow>,
        plan: Option<String>,
        stale: bool,
        note: Option<String>,
    ) {
        self.put(key, QuotaSource::Provider, windows, plan, stale, note);
    }

    /// The single write path, so "replace this source's slot, leave the other alone" cannot be
    /// forgotten at a call site.
    ///
    /// The read-modify-write runs under the map's own entry lock. A probe can finish while an
    /// inference response is being observed on another connection; without the lock, the later
    /// write would publish a snapshot built from the *pre*-probe state and silently drop the
    /// probe's slot — the exact loss this module exists to prevent. The lock is per shard and
    /// held only for the merge, and the no-header case never reaches this method at all.
    fn put(
        &self,
        key: &QuotaKey,
        source: QuotaSource,
        windows: Vec<QuotaWindow>,
        plan: Option<String>,
        stale: bool,
        note: Option<String>,
    ) {
        let set = QuotaObservationSet {
            source,
            observed_at: now_ms(),
            windows,
            stale,
            note,
        };
        match self.map.entry(key.clone()) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                let previous: QuotaSnapshot = occupied.get().as_ref().clone();
                occupied.insert(Arc::new(merge(previous, source, set, plan)));
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                let fresh = QuotaSnapshot {
                    provider: key.provider.clone(),
                    label: key.label.clone(),
                    plan: None,
                    probe: None,
                    headers: None,
                };
                vacant.insert(Arc::new(merge(fresh, source, set, plan)));
            }
        }
    }

    /// Every known snapshot, in a deterministic order (provider, then label) so the panel does not
    /// reshuffle between polls. Read-only: used by the admin API.
    pub fn snapshot_all(&self) -> Vec<Arc<QuotaSnapshot>> {
        let mut out: Vec<Arc<QuotaSnapshot>> = self.map.iter().map(|e| e.value().clone()).collect();
        out.sort_by(|a, b| {
            a.provider
                .cmp(&b.provider)
                .then_with(|| a.label.cmp(&b.label))
        });
        out
    }

    pub fn forget(&self, key: &QuotaKey) {
        self.map.remove(key);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Publish one observation set into the snapshot, replacing only the slot its source owns.
///
/// The other slot is carried over untouched — a narrow passive read must not erase what a wide
/// probe found, and vice versa. Kept as a named function so the merge rule is one statement of
/// intent rather than a struct-spread idiom a reviewer has to decode.
fn merge(
    mut previous: QuotaSnapshot,
    source: QuotaSource,
    set: QuotaObservationSet,
    plan: Option<String>,
) -> QuotaSnapshot {
    if source == QuotaSource::Provider {
        previous.probe = Some(set);
    } else {
        previous.headers = Some(set);
    }
    // A plan is only ever attached by a probe; keep the last one seen rather than clearing it on
    // every header observation, which sees no plan at all.
    if let Some(plan) = plan {
        previous.plan = Some(Arc::from(plan));
    }
    previous
}

/// Epoch millis, saturating at 0 if the clock is before the epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(id: QuotaWindowId, used: f64, total: f64) -> QuotaWindow {
        QuotaWindow {
            id,
            kind: QuotaWindowKind::Window,
            used,
            total,
            unlimited: false,
            reset_at: None,
            source: QuotaSource::Provider,
            variant: None,
        }
    }

    #[test]
    fn fraction_is_derived_not_stored() {
        let w = window(QuotaWindowId::FiveHour, 87.0, 100.0);
        assert!((w.remaining_fraction().unwrap() - 0.13).abs() < 1e-9);
        // Levels bucket the derived number, not a stored one.
        assert_eq!(w.level(), "critical");
    }

    #[test]
    fn unknown_total_is_none_not_zero() {
        let w = window(QuotaWindowId::Month, 12.0, 0.0);
        assert_eq!(w.remaining_fraction(), None);
        assert!(
            !w.is_exhausted(),
            "an unreported window must not read as empty"
        );
        assert_eq!(w.level(), "unknown");
    }

    #[test]
    fn a_credit_balance_is_not_a_percentage() {
        // The reference implementation's bug: 348 credits rendered as "348%".
        let balance = QuotaWindow {
            kind: QuotaWindowKind::Balance,
            ..window(QuotaWindowId::OnDemand, 348.0, 0.0)
        };
        assert_eq!(balance.remaining_fraction(), None);
        assert_eq!(balance.level(), "unknown");
    }

    #[test]
    fn unlimited_is_full_not_unknown() {
        let w = QuotaWindow {
            unlimited: true,
            ..window(QuotaWindowId::Month, 0.0, 0.0)
        };
        assert_eq!(w.remaining_fraction(), Some(1.0));
        assert_eq!(w.level(), "ok");
    }

    #[test]
    fn exhausted_cap_is_not_unlimited() {
        // xAI's trap: cap 0 with used 0 means the account is spent, but `total == 0` renders as
        // "unlimited" downstream. The synthetic 1/1 depleted row is what avoids that.
        let exhausted = window(QuotaWindowId::OnDemand, 1.0, 1.0);
        assert!(exhausted.is_exhausted());
        let unlimited = QuotaWindow {
            unlimited: true,
            ..window(QuotaWindowId::OnDemand, 0.0, 0.0)
        };
        assert!(!unlimited.is_exhausted());
    }

    #[test]
    fn probe_reading_beats_header_reading_for_the_same_window() {
        let key = QuotaKey::new("codex", "acct");
        let store = QuotaStore::new();
        store.observe_headers(&key, vec![window(QuotaWindowId::FiveHour, 90.0, 100.0)]);
        store.record_probe(
            &key,
            vec![window(QuotaWindowId::FiveHour, 10.0, 100.0)],
            None,
            false,
            None,
        );

        let snap = store.get(&key).expect("snapshot");
        let effective = snap.effective_windows();
        assert_eq!(
            effective.len(),
            1,
            "same window from two sources is one row"
        );
        assert_eq!(effective[0].source, QuotaSource::Provider);
        assert!((effective[0].remaining_fraction().unwrap() - 0.90).abs() < 1e-9);
    }

    #[test]
    fn a_narrow_header_read_does_not_erase_a_wide_probe() {
        let key = QuotaKey::new("claude-code", "acct");
        let store = QuotaStore::new();
        store.record_probe(
            &key,
            vec![
                window(QuotaWindowId::FiveHour, 10.0, 100.0),
                window(QuotaWindowId::SevenDay, 20.0, 100.0),
            ],
            None,
            false,
            None,
        );
        store.observe_headers(&key, vec![window(QuotaWindowId::FiveHour, 11.0, 100.0)]);

        let snap = store.get(&key).expect("snapshot");
        let ids: Vec<QuotaWindowId> = snap.effective_windows().iter().map(|w| w.id).collect();
        assert_eq!(
            ids,
            vec![QuotaWindowId::FiveHour, QuotaWindowId::SevenDay],
            "the weekly window only the probe knew about must survive"
        );
    }

    #[test]
    fn observations_replace_rather_than_accumulate() {
        let key = QuotaKey::new("xai-oauth", "acct");
        let store = QuotaStore::new();
        store.observe_headers(&key, vec![window(QuotaWindowId::Month, 40.0, 100.0)]);
        store.observe_headers(&key, vec![window(QuotaWindowId::Month, 55.0, 100.0)]);
        let snap = store.get(&key).expect("snapshot");
        let windows = snap.effective_windows();
        assert_eq!(windows.len(), 1, "a second read replaces the first");
        assert!(
            (windows[0].used - 55.0).abs() < 1e-9,
            "latest value wins outright"
        );
    }

    #[test]
    fn empty_observation_is_not_recorded() {
        let store = QuotaStore::new();
        let key = QuotaKey::new("codex", "acct");
        assert!(!store.observe_headers(&key, Vec::new()));
        assert!(store.is_empty(), "no windows means no entry to allocate");
    }

    #[test]
    fn effective_windows_are_ranked_and_deduplicated() {
        let key = QuotaKey::new("claude-code", "acct");
        let store = QuotaStore::new();
        store.record_probe(
            &key,
            vec![
                window(QuotaWindowId::SevenDayModel, 5.0, 100.0),
                window(QuotaWindowId::Month, 5.0, 100.0),
                window(QuotaWindowId::FiveHour, 5.0, 100.0),
                window(QuotaWindowId::SevenDay, 5.0, 100.0),
            ],
            None,
            false,
            None,
        );
        let ids: Vec<QuotaWindowId> = store
            .get(&key)
            .unwrap()
            .effective_windows()
            .iter()
            .map(|w| w.id)
            .collect();
        assert_eq!(
            ids,
            vec![
                QuotaWindowId::FiveHour,
                QuotaWindowId::SevenDay,
                QuotaWindowId::Month,
                QuotaWindowId::SevenDayModel,
            ]
        );
    }

    #[test]
    fn plan_is_attached_without_disturbing_windows() {
        let key = QuotaKey::new("xai-oauth", "acct");
        let store = QuotaStore::new();
        store.record_probe(
            &key,
            vec![window(QuotaWindowId::Month, 10.0, 100.0)],
            None,
            false,
            None,
        );
        store.record_probe(
            &key,
            vec![window(QuotaWindowId::Month, 20.0, 100.0)],
            Some("SuperGrok".into()),
            false,
            None,
        );
        let snap = store.get(&key).unwrap();
        assert_eq!(snap.plan.as_deref(), Some("SuperGrok"));
        assert_eq!(snap.effective_windows().len(), 1);
        assert!((snap.effective_windows()[0].used - 20.0).abs() < 1e-9);
    }

    #[test]
    fn staleness_is_derived_from_age() {
        let key = QuotaKey::new("codex", "acct");
        let store = QuotaStore::new();
        store.record_probe(
            &key,
            vec![window(QuotaWindowId::FiveHour, 1.0, 100.0)],
            None,
            false,
            None,
        );
        let snap = store.get(&key).unwrap();
        assert!(!snap.is_stale(now_ms()));
        assert!(snap.is_stale(now_ms() + STALE_AFTER_MS + 1));
    }

    #[test]
    fn exhausted_snapshot_requires_at_least_one_window() {
        let key = QuotaKey::new("codex", "acct");
        let store = QuotaStore::new();
        store.record_probe(&key, Vec::new(), None, false, None);
        // An account with nothing reported is not an exhausted account.
        assert!(!store.get(&key).unwrap().is_exhausted());
    }

    #[test]
    fn every_window_id_round_trips_and_has_a_distinct_rank() {
        let mut ranks: Vec<u8> = QuotaWindowId::ALL.iter().map(|w| w.rank()).collect();
        let before = ranks.len();
        ranks.sort_unstable();
        ranks.dedup();
        assert_eq!(before, ranks.len(), "two windows share a truncation rank");
        for w in QuotaWindowId::ALL {
            assert_eq!(QuotaWindowId::parse(w.as_str()), Some(w));
        }
    }

    #[test]
    fn derived_month_is_labelled_as_derived() {
        assert_eq!(
            QuotaWindowId::DerivedMonth.label(None),
            "Monthly (derived)",
            "a router-computed number must be visibly distinguishable from a provider one"
        );
        assert_ne!(
            QuotaWindowId::DerivedMonth.label(None),
            QuotaWindowId::Month.label(None)
        );
    }

    #[test]
    fn truncation_is_deterministic_and_keeps_the_named_windows() {
        let mut many: Vec<QuotaWindow> = QuotaWindowId::ALL
            .iter()
            .map(|id| window(*id, 1.0, 100.0))
            .collect();
        // Claude can report one weekly window per model family; those must never displace a named one.
        for name in ["opus", "sonnet", "haiku"] {
            let mut w = window(QuotaWindowId::SevenDayModel, 5.0, 100.0);
            w.variant = Some(name.into());
            many.push(w);
        }

        let kept = rank_truncate(many.clone());
        assert_eq!(kept.len(), MAX_WINDOWS);
        let ids: Vec<QuotaWindowId> = kept.iter().map(|w| w.id).collect();
        assert_eq!(
            ids,
            vec![
                QuotaWindowId::FiveHour,
                QuotaWindowId::SevenDay,
                QuotaWindowId::SevenDayOverage,
                QuotaWindowId::OnDemand,
                QuotaWindowId::Month,
                QuotaWindowId::DerivedMonth,
            ],
            "model-specific windows are dropped first"
        );
        // Same input, same output — twice.
        assert_eq!(rank_truncate(many).len(), kept.len());
    }

    #[test]
    fn truncation_sorts_even_when_nothing_is_dropped() {
        let windows = vec![
            window(QuotaWindowId::Month, 1.0, 100.0),
            window(QuotaWindowId::FiveHour, 1.0, 100.0),
        ];
        let ids: Vec<QuotaWindowId> = rank_truncate(windows).iter().map(|w| w.id).collect();
        assert_eq!(ids, vec![QuotaWindowId::FiveHour, QuotaWindowId::Month]);
    }

    #[test]
    fn credential_ref_round_trips_into_a_key() {
        let key = QuotaKey::from_credential_ref("oauth:codex:acct-1").expect("key");
        assert_eq!(key.provider.as_ref(), "codex");
        assert_eq!(key.label.as_ref(), "acct-1");
        assert!(QuotaKey::from_credential_ref("env:OPENAI_API_KEY").is_none());
        assert!(QuotaKey::from_credential_ref("file:/tmp/k").is_none());
    }

    #[test]
    fn reset_in_the_past_means_the_window_reading_is_stale() {
        let w = QuotaWindow {
            reset_at: Some(now_ms() - 1),
            ..window(QuotaWindowId::FiveHour, 50.0, 100.0)
        };
        assert!(w.is_stale(now_ms()));
        let future = QuotaWindow {
            reset_at: Some(now_ms() + 60_000),
            ..window(QuotaWindowId::FiveHour, 50.0, 100.0)
        };
        assert!(!future.is_stale(now_ms()));
    }
}
