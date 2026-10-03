//! Active quota probes: ask the provider directly.
//!
//! # What this buys, and what it costs
//!
//! An active probe is the only way to learn an account's allowance *before* it runs out, and the
//! only way to see a window the provider does not put in response headers (a monthly cap, a
//! credit balance). It needs the account's own OAuth credential, so **API-key routes are
//! passive-only** — there is no credential to ask with. That limitation is real and is surfaced
//! in the Portal rather than hidden behind an empty panel.
//!
//! # Request equivalence
//!
//! A probe request is built by `provider_auth::apply_headers`, the same function that builds the
//! real inference request. A probe that returns 403 is therefore telling the truth about the
//! credential, not about a subtly different request shape.
//!
//! # Discipline against the provider
//!
//! Three behaviours, all copied from providers' own CLIs because they are what those CLIs do:
//!
//! * **Min-interval gate.** One probe per credential per [`PROBE_MIN_INTERVAL_MS`], so a Portal
//!   that polls cannot become a load generator. Concurrent bursts collapse onto the same gate.
//! * **429 cooldown.** A rate-limited quota endpoint is paused for [`QUOTA_429_COOLDOWN_MS`], per
//!   credential. Scoped to *probing only*: chat traffic with the same token is untouched, because
//!   the quota endpoint being busy says nothing about the inference endpoint.
//! * **Stale-while-error.** A failed probe keeps the last good reading and marks it stale, rather
//!   than blanking the Portal every time a provider has a bad minute.
//!
//! # The three parsers
//!
//! Claude, Codex and xAI do not share a response shape, so [`parse_body`] dispatches on the
//! `QuotaShape` recorded in the provider table. Everything around the parsers is shared.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use serde_json::{Map, Value};

use crate::oauth::{OAuthProviderSpec, OAuthTokenStore, QuotaProbeSpec, QuotaShape};
use crate::provider_auth;

use super::observe::balance_window;
use super::{
    QuotaKey, QuotaSource, QuotaStore, QuotaWindow, QuotaWindowId, QuotaWindowKind, now_ms,
    rank_truncate,
};

/// Shortest gap between two probes of the same credential.
pub const PROBE_MIN_INTERVAL_MS: u64 = 60_000;

/// How long a credential's quota endpoint stays paused after answering 429. Three minutes, which
/// is what the Claude CLI itself uses.
pub const QUOTA_429_COOLDOWN_MS: u64 = 180_000;

/// Wall-clock budget for one probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest quota response body accepted. These payloads are a few hundred bytes; anything larger
/// is not a quota response and is not worth buffering.
const MAX_BODY_BYTES: usize = 128 * 1024;

/// Days in an average month. Used only by [`derive_month`].
const DAYS_PER_MONTH: f64 = 30.44;

/// What one probe attempt produced.
#[derive(Debug, Clone, Default)]
pub struct ProbeResult {
    pub windows: Vec<QuotaWindow>,
    pub plan: Option<String>,
    /// Operator-facing explanation of a failure or a skip. Never token material.
    pub note: Option<String>,
    /// False when the provider did not answer with usable numbers, including a deliberate skip.
    pub ok: bool,
    /// The probe was not attempted: min-interval gate or an active 429 cooldown.
    pub skipped: bool,
}

impl ProbeResult {
    fn skip(note: impl Into<String>) -> Self {
        Self {
            note: Some(note.into()),
            skipped: true,
            ..Default::default()
        }
    }

    fn fail(note: impl Into<String>) -> Self {
        Self {
            note: Some(note.into()),
            ..Default::default()
        }
    }
}

/// Probes provider quota endpoints on demand and caches the answers.
///
/// Holds no connection state of its own: it borrows the router's shared `reqwest::Client`, so the
/// probe path cannot introduce a second pool, a second TLS configuration, or a second proxy
/// decision.
pub struct QuotaProbe {
    client: reqwest::Client,
    store: Arc<OAuthTokenStore>,
    quota: Arc<QuotaStore>,
    /// Credential -> epoch millis until which probing is paused.
    cooldowns: DashMap<QuotaKey, u64>,
    /// Credential -> epoch millis of the last attempt.
    last_attempt: DashMap<QuotaKey, u64>,
    /// Provider key -> replacement for `spec.quota_base_url`. Empty in a stock deployment.
    base_overrides: DashMap<String, String>,
}

impl QuotaProbe {
    pub fn new(
        client: reqwest::Client,
        store: Arc<OAuthTokenStore>,
        quota: Arc<QuotaStore>,
    ) -> Self {
        Self {
            client,
            store,
            quota,
            cooldowns: DashMap::new(),
            last_attempt: DashMap::new(),
            base_overrides: DashMap::new(),
        }
    }

    pub fn quota_store(&self) -> &QuotaStore {
        &self.quota
    }

    /// Point one provider's probes at a base URL other than the one in its spec.
    ///
    /// The quota endpoints are reverse-engineered and unversioned, so a deployment that fronts one
    /// of these providers through a relay needs to redirect the probe — the inference route can be
    /// pointed at a gateway today, and the probe must follow. It is also the only way to exercise
    /// this code's HTTP contract (header construction, status handling, body cap, 429 cooldown)
    /// without a live subscription account, which is why the seam exists rather than the tests
    /// reaching into `spec.quota_base_url`.
    pub fn set_base_url(&self, provider: &str, base_url: &str) {
        self.base_overrides
            .insert(provider.trim().to_ascii_lowercase(), base_url.to_string());
    }

    /// Probe one account. `force` skips the min-interval gate but still honours a 429 cooldown:
    /// a cooldown exists because the provider asked us to stop, and an operator clicking "refresh"
    /// is not the provider un-asking.
    pub async fn refresh(&self, key: &QuotaKey, force: bool) -> ProbeResult {
        let now = now_ms();

        if let Some(until) = self.cooldowns.get(key).map(|v| *v)
            && until > now
        {
            let secs = (until - now).div_ceil(1000);
            return ProbeResult::skip(format!(
                "provider rate-limited this account's quota endpoint; paused {secs}s"
            ));
        }

        if !force
            && let Some(last) = self.last_attempt.get(key).map(|v| *v)
            && now.saturating_sub(last) < PROBE_MIN_INTERVAL_MS
        {
            let secs = (PROBE_MIN_INTERVAL_MS - now.saturating_sub(last)).div_ceil(1000);
            return ProbeResult::skip(format!("last probed {secs}s ago"));
        }

        let Some(spec) = self.spec_for(key) else {
            let note = "no quota endpoint is known for this provider".to_string();
            return ProbeResult::fail(note);
        };
        let Some(probe) = spec.quota_probe else {
            // Not a failure: the account is simply passive-only. Saying so beats a bare timeout.
            // Nothing is recorded — an entry with no windows would sit in the list forever as a
            // phantom account, and `passive_only` in the admin listing already explains this case
            // from the token store itself.
            return ProbeResult::fail(format!(
                "{} exposes no quota endpoint — this account is observed from response headers only",
                spec.label
            ));
        };

        let token = match self.store.read(&key.provider, &key.label) {
            Ok(t) => t,
            Err(e) => {
                // No credential means no account. Recording here would create a store entry for an
                // account that cannot exist, so this stays a plain refusal.
                return ProbeResult::fail(format!("no usable credential: {e}"));
            }
        };

        self.last_attempt.insert(key.clone(), now);

        match self.send(key, spec, probe, &token.access_token).await {
            Ok(result) => {
                self.quota.record_probe(
                    key,
                    result.windows.clone(),
                    result.plan.clone(),
                    false,
                    None,
                );
                result
            }
            Err(FetchError::RateLimited) => {
                self.cooldowns
                    .insert(key.clone(), now_ms() + QUOTA_429_COOLDOWN_MS);
                let note =
                    "provider rate-limited the quota endpoint; paused for 3 minutes".to_string();
                self.record_failure(key, note.clone());
                ProbeResult::fail(note)
            }
            Err(FetchError::Other(msg)) => {
                self.record_failure(key, msg.clone());
                ProbeResult::fail(msg)
            }
        }
    }

    /// Probe every connected account, one request each. Sequential on purpose: bursting a provider
    /// with parallel quota requests is exactly what the min-interval gate exists to avoid.
    pub async fn refresh_all(&self, force: bool) -> Vec<(QuotaKey, ProbeResult)> {
        let mut out = Vec::new();
        for token in self.store.list() {
            let key = QuotaKey::new(&token.provider, &token.label);
            let result = self.refresh(&key, force).await;
            out.push((key, result));
        }
        out
    }

    fn spec_for(&self, key: &QuotaKey) -> Option<&'static OAuthProviderSpec> {
        crate::oauth::spec(&key.provider)
    }

    async fn send(
        &self,
        key: &QuotaKey,
        spec: &'static OAuthProviderSpec,
        probe: QuotaProbeSpec,
        access_token: &str,
    ) -> Result<ProbeResult, FetchError> {
        let base = self
            .base_overrides
            .get(key.provider.as_ref())
            .map(|v| v.value().clone())
            .unwrap_or_else(|| spec.quota_base_url.to_string());
        let mut url = format!("{base}{}", probe.path);
        if !probe.query.is_empty() {
            url.push('?');
            url.push_str(probe.query);
        }

        // Re-read the credential for the account id: `refresh` already read it once, and the two
        // reads are cheap, but this keeps `send` correct if it is ever called on its own.
        let token = self
            .store
            .read(&key.provider, &key.label)
            .map_err(|e| FetchError::Other(e.to_string()))?;
        let plan = provider_auth::resolve(
            spec.auth_mode,
            spec.protocol == "anthropic_messages",
            token.account_id.as_deref(),
        );

        let mut headers = axum::http::HeaderMap::new();
        provider_auth::apply_headers(&mut headers, &plan, access_token)
            .map_err(FetchError::Other)?;
        for (name, value) in probe.extra_headers {
            let name = axum::http::HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| FetchError::Other(format!("probe header name {name}: {e}")))?;
            let value = axum::http::HeaderValue::from_static(value);
            headers.append(name, value);
        }

        let response = self
            .client
            .get(&url)
            .headers(headers)
            .timeout(PROBE_TIMEOUT)
            .send()
            .await
            .map_err(|e| FetchError::Other(format!("quota probe request failed: {e}")))?;

        let status = response.status();
        if status.as_u16() == 429 {
            return Err(FetchError::RateLimited);
        }
        if !status.is_success() {
            return Err(FetchError::Other(format!(
                "quota probe returned HTTP {}",
                status.as_u16()
            )));
        }
        if let Some(len) = response.content_length()
            && len as usize > MAX_BODY_BYTES
        {
            return Err(FetchError::Other(format!(
                "quota response too large ({len} bytes)"
            )));
        }

        let body = response
            .text()
            .await
            .map_err(|e| FetchError::Other(format!("quota probe body: {e}")))?;
        if body.len() > MAX_BODY_BYTES {
            return Err(FetchError::Other(format!(
                "quota response too large ({} bytes)",
                body.len()
            )));
        }
        let json: Value = serde_json::from_str(&body)
            .map_err(|e| FetchError::Other(format!("quota response is not JSON: {e}")))?;

        Ok(parse_body(probe.shape, &json))
    }

    /// Stale-while-error: keep the previous reading, mark it stale, explain why.
    ///
    /// The alternative — recording an empty set — makes a provider's bad minute indistinguishable
    /// from "this account has no quota information", which is how a display starts lying.
    fn record_failure(&self, key: &QuotaKey, note: String) {
        let previous = self
            .quota
            .get(key)
            .and_then(|s| s.probe.clone())
            .map(|set| set.windows)
            .unwrap_or_default();
        self.quota
            .record_probe(key, previous, None, true, Some(note));
    }
}

enum FetchError {
    RateLimited,
    Other(String),
}

/// Dispatch to the parser for this provider's documented shape.
fn parse_body(shape: QuotaShape, json: &Value) -> ProbeResult {
    let (mut windows, plan) = match shape {
        QuotaShape::Claude => parse_claude(json),
        QuotaShape::Codex => parse_codex(json),
        QuotaShape::Xai => parse_xai(json),
    };

    // A monthly window only exists upstream for xAI. For Claude and Codex the router can
    // interpolate one from the weekly window — labelled as derived, and only when the provider did
    // not state one itself.
    if !windows.iter().any(|w| w.id == QuotaWindowId::Month)
        && let Some(weekly) = windows
            .iter()
            .find(|w| w.id == QuotaWindowId::SevenDay)
            .and_then(|w| w.used_percent())
    {
        windows.push(QuotaWindow::percent_window(
            QuotaWindowId::DerivedMonth,
            derive_month(weekly),
            windows
                .iter()
                .find(|w| w.id == QuotaWindowId::SevenDay)
                .and_then(|w| w.reset_at),
            QuotaSource::RouterDerived,
        ));
    }

    windows = rank_truncate(windows);
    ProbeResult {
        ok: !windows.is_empty(),
        windows,
        plan,
        note: None,
        skipped: false,
    }
}

/// Extrapolate a weekly percentage to a month.
///
/// A month holds `30.44 / 7 = 4.349` weekly windows, so weekly consumption scales by that factor.
/// Saturates at 100: once a week alone exceeds a month of budget the derivation has already
/// bottomed out, and continuing the arithmetic past the cap would be inventing precision.
///
/// This is a rough number by construction — traffic is not uniform across a week. It is reported
/// because an operator deciding whether to wait out a weekly window benefits from "this will run
/// out today", and it is labelled `(derived)` everywhere it appears so it is never mistaken for a
/// figure the provider published.
fn derive_month(weekly_used_percent: f64) -> f64 {
    (weekly_used_percent * (DAYS_PER_MONTH / 7.0)).clamp(0.0, 100.0)
}

/// Claude: `GET /api/oauth/usage?cedar_ember=1`.
///
/// ```json
/// { "five_hour": { "utilization": 87, "resets_at": "…" },
///   "seven_day": { "utilization": 12, "resets_at": "…" },
///   "seven_day_sonnet": { "utilization": 5, "resets_at": "…" },
///   "seven_day_oi":    { "utilization": 0, "resets_at": "…" } }
/// ```
///
/// `utilization` is percent **used**. Model-specific weekly windows are discovered by prefix rather
/// than enumerated, because Anthropic adds model families without notice and an exhaustive list is
/// wrong the day they ship one.
fn parse_claude(json: &Value) -> (Vec<QuotaWindow>, Option<String>) {
    let Some(root) = json.as_object() else {
        return (Vec::new(), None);
    };
    let mut windows = Vec::new();

    for (key, value) in root {
        let (id, variant): (QuotaWindowId, Option<Box<str>>) = if key == "five_hour" {
            (QuotaWindowId::FiveHour, None)
        } else if key == "seven_day" {
            (QuotaWindowId::SevenDay, None)
        } else if key == "seven_day_oi" {
            (QuotaWindowId::SevenDayOverage, None)
        } else if let Some(model) = key.strip_prefix("seven_day_") {
            // `seven_day_oi` is matched above, so everything here is genuinely a model family.
            if model.is_empty() {
                continue;
            }
            (QuotaWindowId::SevenDayModel, Some(model.into()))
        } else {
            continue;
        };

        let Some(window) = value.as_object() else {
            continue;
        };
        let Some(used) = first_num(window, &["utilization"]) else {
            continue;
        };
        let mut w = QuotaWindow::percent_window(
            id,
            used,
            first_reset(window, &["resets_at", "reset_at"]),
            QuotaSource::Provider,
        );
        w.variant = variant;
        windows.push(w);
    }

    (windows, None)
}

/// Codex: `GET /wham/usage`.
///
/// ```json
/// { "plan_type": "pro",
///   "rate_limits": {
///     "primary_window":   { "window_minutes": 300,  "used_percent": 42, "reset_at": 1800000000 },
///     "secondary_window": { "window_minutes": 10080, "used_percent": 5,  "reset_at": 1800003600 } } }
/// ```
///
/// `window_minutes` decides which window a slot is when present, because the provider states the
/// length outright; the slot name is only the fallback. Aliases are accepted at each level because
/// the payload has appeared both nested and flat.
fn parse_codex(json: &Value) -> (Vec<QuotaWindow>, Option<String>) {
    let Some(root) = json.as_object() else {
        return (Vec::new(), None);
    };
    let plan = first_str(root, &["plan_type", "plan"]);

    let limits = ["rate_limits", "rate_limit"]
        .iter()
        .find_map(|k| root.get(*k).and_then(Value::as_object))
        .unwrap_or(root);

    let mut windows = Vec::new();
    for (names, fallback) in [
        (&["primary_window", "primary"][..], QuotaWindowId::FiveHour),
        (
            &["secondary_window", "secondary"][..],
            QuotaWindowId::SevenDay,
        ),
    ] {
        let Some(slot) = names.iter().find_map(|n| limits.get(*n)) else {
            continue;
        };
        let Some(slot) = slot.as_object() else {
            continue;
        };
        let Some(used) = first_num(slot, &["used_percent", "percent_used"]) else {
            continue;
        };
        let id = match first_num(slot, &["window_minutes"]) {
            Some(m) if m > 0.0 && m <= 360.0 => QuotaWindowId::FiveHour,
            Some(m) if m > 360.0 && m <= 11_000.0 => QuotaWindowId::SevenDay,
            _ => fallback,
        };
        windows.push(QuotaWindow::percent_window(
            id,
            used,
            first_reset(slot, &["reset_at", "resets_at"]),
            QuotaSource::Provider,
        ));
    }

    (windows, plan)
}

/// xAI: `GET /billing?format=credits`.
///
/// ```json
/// { "config": { "onDemandCap": { "val": 3 }, "onDemandUsed": { "val": 1 },
///               "prepaidBalance": { "val": 0 }, "creditUsagePercent": 12,
///               "billingPeriodEnd": "…" } }
/// ```
///
/// Two traps, both of which a straightforward parser gets wrong:
///
/// 1. **Numbers are wrapped.** `onDemandCap` is `{ val: 3 }`, not `3`. Reading it directly yields
///    zero for every capped field, and a zero cap means "exhausted" — so a parser without
///    [`unwrap_val`] reports every paid account as spent.
/// 2. **`cap == 0` is ambiguous.** It means "no on-demand cap configured" for an account with a
///    prepaid balance, and "out of credit" for an exhausted free account. `total == 0` renders as
///    *unlimited* downstream, so the exhausted case has to be an explicit depleted row.
fn parse_xai(json: &Value) -> (Vec<QuotaWindow>, Option<String>) {
    let Some(root) = json.as_object() else {
        return (Vec::new(), None);
    };
    let config = ["config", "billing"]
        .iter()
        .find_map(|k| root.get(*k).and_then(Value::as_object))
        .unwrap_or(root);

    let reset = first_reset(config, &["billingPeriodEnd", "billing_period_end"]).or_else(|| {
        config
            .get("currentPeriod")
            .or_else(|| config.get("current_period"))
            .and_then(Value::as_object)
            .and_then(|p| first_reset(p, &["end"]))
    });

    let mut windows = Vec::new();

    // Monthly: the explicit limit wins; `creditUsagePercent` is the fallback for accounts that
    // report a percentage without a cap.
    let monthly_limit = first_num(config, &["monthlyLimit", "monthly_limit"]);
    let monthly_used = first_num(config, &["includedUsed", "included_used"]);
    match monthly_limit {
        Some(limit) if limit > 0.0 => windows.push(QuotaWindow {
            id: QuotaWindowId::Month,
            kind: QuotaWindowKind::Window,
            used: monthly_used.unwrap_or(0.0).clamp(0.0, limit),
            total: limit,
            unlimited: false,
            reset_at: reset,
            source: QuotaSource::Provider,
            variant: None,
        }),
        _ => {
            if let Some(pct) = first_num(config, &["creditUsagePercent", "credit_usage_percent"]) {
                windows.push(QuotaWindow::percent_window(
                    QuotaWindowId::Month,
                    pct,
                    reset,
                    QuotaSource::Provider,
                ));
            }
        }
    }

    let cap = first_num(config, &["onDemandCap", "on_demand_cap"]);
    let used = first_num(config, &["onDemandUsed", "on_demand_used"]);
    let prepaid = first_num(config, &["prepaidBalance", "prepaid_balance"]);

    let on_demand = match cap {
        Some(c) if c > 0.0 => QuotaWindow {
            id: QuotaWindowId::OnDemand,
            kind: QuotaWindowKind::Window,
            used: used.unwrap_or(0.0).clamp(0.0, c),
            total: c,
            unlimited: false,
            reset_at: reset,
            source: QuotaSource::Provider,
            variant: None,
        },
        _ => {
            let balance = prepaid.unwrap_or(0.0);
            if balance > 0.0 {
                // No spend cap, but there is something spendable. One row, of kind Balance: a
                // balance has no denominator, so it must not be rendered as a percentage.
                balance_window(QuotaWindowId::OnDemand, balance, QuotaSource::Provider)
            } else if cap == Some(0.0) && used.unwrap_or(0.0) == 0.0 {
                // Exhausted. `total == 0` would read as "unlimited" everywhere downstream, so the
                // spent state is spelled as a fully consumed 1/1 window.
                QuotaWindow::percent_window(
                    QuotaWindowId::OnDemand,
                    100.0,
                    reset,
                    QuotaSource::Provider,
                )
            } else {
                // Nothing reported about on-demand spend. Leaving the window out keeps "unknown"
                // distinct from "exhausted" and from "unlimited".
                return (windows, None);
            }
        }
    };
    windows.push(on_demand);

    (windows, None)
}

// ===== value helpers =====

/// Read a number that may arrive bare, as a string, or wrapped in protobuf-JSON `{ val: n }`.
///
/// Recursive on purpose: the wrapper nests, and a parser that only unwraps one level silently
/// reads zero for everything — which, for xAI's cap fields, reads as "exhausted".
fn unwrap_val(value: &Value) -> Option<f64> {
    let n = match value {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        Value::Object(m) => {
            let inner = m.get("val").or_else(|| m.get("value"))?;
            return unwrap_val(inner);
        }
        _ => None,
    }?;
    n.is_finite().then_some(n)
}

/// First key that resolves to a finite number.
fn first_num(obj: &Map<String, Value>, keys: &[&str]) -> Option<f64> {
    keys.iter().filter_map(|k| obj.get(*k)).find_map(unwrap_val)
}

/// First key that resolves to a non-empty string.
fn first_str(obj: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| obj.get(*k)).and_then(|v| {
        v.as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    })
}

/// First key that resolves to an instant. Accepts epoch seconds, epoch millis and RFC 3339,
/// because providers are not consistent and a reset time in the wrong unit is worse than none.
fn first_reset(obj: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .filter_map(|k| obj.get(*k))
        .find_map(reset_value)
}

fn reset_value(value: &Value) -> Option<u64> {
    if let Some(n) = unwrap_val(value) {
        if n <= 0.0 {
            return None;
        }
        // 1e12 separates epoch millis (~1.7e12) from seconds (~1.7e9).
        let ms = if n < 1e12 { n * 1000.0 } else { n };
        return (ms.is_finite() && ms > 0.0).then_some(ms as u64);
    }
    let s = value.as_str()?.trim();
    if s.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        // Millis, matching the numeric path: `reset_at` is one unit throughout the store, or a
        // countdown computed from an RFC 3339 reset is off by three orders of magnitude.
        .and_then(|d| u64::try_from(d.timestamp_millis()).ok())
}

/// Convenience for the derivable-month path, where only a percentage-shaped window is eligible.
trait UsedPercent {
    fn used_percent(&self) -> Option<f64>;
}
impl UsedPercent for QuotaWindow {
    fn used_percent(&self) -> Option<f64> {
        (self.kind == QuotaWindowKind::Window && self.total > 0.0).then_some(self.used)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(raw: &str) -> Value {
        serde_json::from_str(raw).expect("test json")
    }

    fn window(windows: &[QuotaWindow], id: QuotaWindowId) -> Option<&QuotaWindow> {
        windows.iter().find(|w| w.id == id)
    }

    // ===== Claude =====

    #[test]
    fn claude_named_windows_and_utilization_is_percent_used() {
        let body = json(
            r#"{"five_hour":{"utilization":87,"resets_at":"2027-01-15T10:00:00Z"},
                "seven_day":{"utilization":12,"resets_at":"2027-01-20T10:00:00Z"},
                "seven_day_oi":{"utilization":100}}"#,
        );
        let (windows, _) = parse_claude(&body);
        let five = window(&windows, QuotaWindowId::FiveHour).expect("5h");
        assert_eq!(five.used, 87.0);
        assert!((five.remaining_fraction().unwrap() - 0.13).abs() < 1e-6);
        assert_eq!(
            five.reset_at,
            chrono::DateTime::parse_from_rfc3339("2027-01-15T10:00:00Z")
                .ok()
                .and_then(|d| u64::try_from(d.timestamp_millis()).ok())
        );
        // 100% used, not 0% — `utilization` counts consumption.
        assert!(
            window(&windows, QuotaWindowId::SevenDayOverage)
                .unwrap()
                .is_exhausted()
        );
    }

    #[test]
    fn claude_zero_utilization_is_a_full_window() {
        let body = json(r#"{"five_hour":{"utilization":0}}"#);
        let (windows, _) = parse_claude(&body);
        let five = window(&windows, QuotaWindowId::FiveHour).unwrap();
        assert_eq!(
            five.remaining_fraction(),
            Some(1.0),
            "0% used means nothing consumed"
        );
        assert!(!five.is_exhausted());
    }

    #[test]
    fn claude_discovers_model_specific_weekly_windows_generically() {
        let body = json(
            r#"{"five_hour":{"utilization":1},
                "seven_day":{"utilization":2},
                "seven_day_sonnet":{"utilization":3},
                "seven_day_opus":{"utilization":4},
                "seven_day_oi":{"utilization":5}}"#,
        );
        let (windows, _) = parse_claude(&body);
        let models: Vec<&str> = windows
            .iter()
            .filter(|w| w.id == QuotaWindowId::SevenDayModel)
            .filter_map(|w| w.variant.as_deref())
            .collect();
        // Alphabetical, because a serde_json object iterates in key order.
        assert_eq!(models, vec!["opus", "sonnet"], "oi is overage, not a model");
        assert!(window(&windows, QuotaWindowId::SevenDayOverage).is_some());
    }

    #[test]
    fn claude_ignores_unrelated_keys() {
        let body = json(r#"{"limits":[],"extra_usage":{"x":1},"five_hour":{"utilization":9}}"#);
        let (windows, _) = parse_claude(&body);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].id, QuotaWindowId::FiveHour);
    }

    #[test]
    fn claude_window_without_utilization_is_skipped() {
        let body = json(r#"{"five_hour":{"resets_at":"2027-01-15T10:00:00Z"}}"#);
        let (windows, _) = parse_claude(&body);
        assert!(windows.is_empty(), "no percentage means no window");
    }

    // ===== Codex =====

    #[test]
    fn codex_windows_are_classified_by_window_minutes() {
        let body = json(
            r#"{"plan_type":"pro",
                "rate_limits":{"primary_window":{"window_minutes":300,"used_percent":42,"reset_at":1800000000},
                               "secondary_window":{"window_minutes":10080,"used_percent":5}}}"#,
        );
        let (windows, plan) = parse_codex(&body);
        assert_eq!(plan.as_deref(), Some("pro"));
        let primary = window(&windows, QuotaWindowId::FiveHour).expect("session");
        assert_eq!(primary.used, 42.0);
        assert_eq!(primary.reset_at, Some(1_800_000_000_000));
        let secondary = window(&windows, QuotaWindowId::SevenDay).expect("weekly");
        assert_eq!(secondary.used, 5.0);
    }

    #[test]
    fn codex_falls_back_to_slot_position_when_minutes_are_absent() {
        let body = json(
            r#"{"primary_window":{"used_percent":10},"secondary_window":{"used_percent":20}}"#,
        );
        let (windows, _) = parse_codex(&body);
        assert_eq!(
            window(&windows, QuotaWindowId::FiveHour).unwrap().used,
            10.0
        );
        assert_eq!(
            window(&windows, QuotaWindowId::SevenDay).unwrap().used,
            20.0
        );
    }

    #[test]
    fn codex_accepts_a_flat_payload_and_alias_names() {
        let flat = json(r#"{"primary":{"percent_used":11},"secondary":{"percent_used":22}}"#);
        let (windows, _) = parse_codex(&flat);
        assert_eq!(
            window(&windows, QuotaWindowId::FiveHour).unwrap().used,
            11.0
        );
        assert_eq!(
            window(&windows, QuotaWindowId::SevenDay).unwrap().used,
            22.0
        );

        let renamed = json(r#"{"rate_limit":{"primary_window":{"used_percent":7}}}"#);
        let (windows, _) = parse_codex(&renamed);
        assert_eq!(windows.len(), 1);
    }

    #[test]
    fn codex_unknown_window_length_keeps_the_slot_meaning() {
        let body = json(r#"{"primary_window":{"window_minutes":30,"used_percent":3}}"#);
        let (windows, _) = parse_codex(&body);
        // 30 minutes is not a five-hour window, but it is still the primary slot.
        assert_eq!(windows[0].id, QuotaWindowId::FiveHour);
    }

    // ===== xAI =====

    #[test]
    fn xai_unwraps_protobuf_json_numbers() {
        // Without unwrap_val every capped field reads 0, which means "exhausted" downstream.
        let body = json(
            r#"{"config":{"onDemandCap":{"val":10},"onDemandUsed":{"val":4},
                          "monthlyLimit":{"val":50},"includedUsed":{"val":5},
                          "billingPeriodEnd":"2027-02-01T00:00:00Z"}}"#,
        );
        let (windows, _) = parse_xai(&body);
        let on_demand = window(&windows, QuotaWindowId::OnDemand).expect("on-demand");
        assert_eq!(on_demand.total, 10.0);
        assert_eq!(on_demand.used, 4.0);
        assert!(!on_demand.is_exhausted());
        let month = window(&windows, QuotaWindowId::Month).expect("monthly");
        assert_eq!(month.total, 50.0);
        assert_eq!(month.used, 5.0);
    }

    #[test]
    fn xai_cap_zero_with_a_prepaid_balance_is_a_balance_not_a_percentage() {
        let body = json(r#"{"config":{"onDemandCap":{"val":0},"prepaidBalance":{"val":348}}}"#);
        let (windows, _) = parse_xai(&body);
        let on_demand = window(&windows, QuotaWindowId::OnDemand).expect("on-demand");
        assert_eq!(on_demand.kind, QuotaWindowKind::Balance);
        assert_eq!(on_demand.used, 348.0);
        assert_eq!(
            on_demand.remaining_fraction(),
            None,
            "the reference implementation rendered 348 credits as 348%"
        );
        assert!(!on_demand.is_exhausted());
    }

    #[test]
    fn xai_cap_zero_without_a_balance_is_exhausted_not_unlimited() {
        // Exhausted free/promo accounts report cap 0, used 0, balance 0 — and chat 402s.
        let body = json(
            r#"{"config":{"onDemandCap":{"val":0},"onDemandUsed":{"val":0},"prepaidBalance":{"val":0}}}"#,
        );
        let (windows, _) = parse_xai(&body);
        let on_demand = window(&windows, QuotaWindowId::OnDemand).expect("on-demand row");
        assert!(on_demand.is_exhausted());
        assert!(
            on_demand.total > 0.0,
            "total must be non-zero or the row renders as unlimited"
        );
        assert_eq!(on_demand.remaining_fraction(), Some(0.0));
    }

    #[test]
    fn xai_credit_usage_percent_is_the_monthly_fallback() {
        let body = json(r#"{"config":{"creditUsagePercent":62,"billing_period_end":1800000000}}"#);
        let (windows, _) = parse_xai(&body);
        let month = window(&windows, QuotaWindowId::Month).expect("monthly");
        assert_eq!(month.used, 62.0);
        assert_eq!(month.total, 100.0);
        assert_eq!(month.reset_at, Some(1_800_000_000_000));
    }

    #[test]
    fn xai_explicit_monthly_limit_wins_over_the_percentage() {
        let body = json(
            r#"{"config":{"monthlyLimit":{"val":200},"includedUsed":{"val":50},"creditUsagePercent":99}}"#,
        );
        let (windows, _) = parse_xai(&body);
        let month = window(&windows, QuotaWindowId::Month).expect("monthly");
        assert_eq!(month.total, 200.0);
        assert_eq!(month.used, 50.0);
    }

    #[test]
    fn xai_clamps_used_to_the_cap() {
        let body = json(r#"{"config":{"onDemandCap":{"val":10},"onDemandUsed":{"val":25}}}"#);
        let (windows, _) = parse_xai(&body);
        let on_demand = window(&windows, QuotaWindowId::OnDemand).unwrap();
        assert_eq!(on_demand.used, 10.0);
        assert!(on_demand.is_exhausted());
    }

    #[test]
    fn xai_reports_nothing_when_on_demand_is_silent() {
        let body = json(r#"{"config":{"monthlyLimit":{"val":10}}}"#);
        let (windows, _) = parse_xai(&body);
        assert!(
            window(&windows, QuotaWindowId::OnDemand).is_none(),
            "an unreported window must not appear as unlimited or exhausted"
        );
    }

    // ===== shared =====

    #[test]
    fn unwrap_val_handles_every_level() {
        assert_eq!(unwrap_val(&json("3")), Some(3.0));
        assert_eq!(unwrap_val(&json("\"3\"")), Some(3.0));
        assert_eq!(unwrap_val(&json(r#"{"val":3}"#)), Some(3.0));
        assert_eq!(unwrap_val(&json(r#"{"val":{"val":3}}"#)), Some(3.0));
        assert_eq!(unwrap_val(&json("null")), None);
        assert_eq!(unwrap_val(&json("[]")), None);
    }

    #[test]
    fn reset_values_accept_seconds_millis_and_rfc3339() {
        assert_eq!(reset_value(&json("1800000000")), Some(1_800_000_000_000));
        assert_eq!(reset_value(&json("1800000000000")), Some(1_800_000_000_000));
        assert_eq!(
            reset_value(&json("\"2027-01-15T10:00:00Z\"")),
            chrono::DateTime::parse_from_rfc3339("2027-01-15T10:00:00Z")
                .ok()
                .and_then(|d| u64::try_from(d.timestamp_millis()).ok())
        );
        assert_eq!(reset_value(&json("\"\"")), None);
        assert_eq!(reset_value(&json("0")), None);
        assert_eq!(reset_value(&json("-5")), None);
    }

    #[test]
    fn derived_month_is_added_and_labelled_as_derived() {
        let body = json(
            r#"{"primary_window":{"window_minutes":300,"used_percent":10},
                "secondary_window":{"window_minutes":10080,"used_percent":20}}"#,
        );
        let result = parse_body(QuotaShape::Codex, &body);
        let derived = window(&result.windows, QuotaWindowId::DerivedMonth).expect("derived");
        assert_eq!(derived.source, QuotaSource::RouterDerived);
        // 20% of a week scales by 30.44/7 to roughly 87% of a month.
        assert!(
            (derived.used - derive_month(20.0)).abs() < 1e-9,
            "got {}",
            derived.used
        );
        assert!(derived.used > 80.0 && derived.used < 95.0);
        assert_eq!(QuotaWindowId::DerivedMonth.label(None), "Monthly (derived)");
    }

    #[test]
    fn derived_month_is_not_added_when_the_provider_states_one() {
        let body = json(r#"{"config":{"monthlyLimit":{"val":100},"includedUsed":{"val":1}}}"#);
        let result = parse_body(QuotaShape::Xai, &body);
        assert!(
            window(&result.windows, QuotaWindowId::DerivedMonth).is_none(),
            "a router guess must never sit next to a published figure"
        );
    }

    #[test]
    fn derived_month_absent_without_a_weekly_window() {
        let body = json(r#"{"primary_window":{"used_percent":10}}"#);
        let result = parse_body(QuotaShape::Codex, &body);
        assert!(window(&result.windows, QuotaWindowId::DerivedMonth).is_none());
    }

    #[test]
    fn monthly_derivation_saturates() {
        assert_eq!(derive_month(100.0), 100.0);
        assert_eq!(derive_month(0.0), 0.0);
        // 30% of a week already extrapolates past a whole month, so it pins at the cap rather than
        // reporting 130%.
        assert_eq!(derive_month(30.0), 100.0);
        assert_eq!(derive_month(20.0), 20.0 * (DAYS_PER_MONTH / 7.0));
    }

    #[test]
    fn derived_month_is_truncated_before_model_specific_windows() {
        // Claude with four model families: 5 named windows plus 4 extras exceeds the cap.
        let body = json(
            r#"{"five_hour":{"utilization":1},"seven_day":{"utilization":2},
                "seven_day_haiku":{"utilization":3},"seven_day_opus":{"utilization":4},
                "seven_day_sonnet":{"utilization":5},"seven_day_unknown":{"utilization":6}}"#,
        );
        let result = parse_body(QuotaShape::Claude, &body);
        assert!(result.windows.len() <= super::super::MAX_WINDOWS);
        let ids: Vec<QuotaWindowId> = result.windows.iter().map(|w| w.id).collect();
        assert!(
            ids.contains(&QuotaWindowId::FiveHour)
                && ids.contains(&QuotaWindowId::SevenDay)
                && ids.contains(&QuotaWindowId::DerivedMonth),
            "named windows survive truncation: {ids:?}"
        );
        assert_eq!(
            ids.iter()
                .filter(|id| **id == QuotaWindowId::SevenDayModel)
                .count(),
            3,
            "exactly one model window is dropped"
        );
    }

    #[test]
    fn malformed_json_yields_an_empty_result_not_a_panic() {
        assert!(
            parse_body(QuotaShape::Claude, &json("[]"))
                .windows
                .is_empty()
        );
        assert!(
            parse_body(QuotaShape::Codex, &json("null"))
                .windows
                .is_empty()
        );
        assert!(
            parse_body(QuotaShape::Xai, &json("\"nope\""))
                .windows
                .is_empty()
        );
        assert!(
            parse_body(QuotaShape::Claude, &json("{}"))
                .windows
                .is_empty()
        );
    }

    #[test]
    fn an_empty_provider_response_is_reported_as_not_ok() {
        let result = parse_body(QuotaShape::Codex, &json("{}"));
        assert!(!result.ok, "an empty read must not look like a success");
        assert!(result.windows.is_empty());
    }

    #[test]
    fn every_spec_with_a_probe_declares_a_shape_and_base_url() {
        for spec in crate::oauth::PROVIDERS {
            let Some(probe) = spec.quota_probe else {
                continue;
            };
            assert!(
                spec.quota_base_url.starts_with("https://"),
                "{} has an insecure quota base URL",
                spec.key
            );
            assert!(
                probe.path.starts_with('/'),
                "{} probe path must be absolute",
                spec.key
            );
        }
    }

    #[test]
    fn every_shape_has_a_parser() {
        // Guards against adding a variant without a parser arm.
        for shape in [QuotaShape::Claude, QuotaShape::Codex, QuotaShape::Xai] {
            let result = parse_body(shape, &json("{}"));
            assert!(result.windows.is_empty());
        }
    }
}
