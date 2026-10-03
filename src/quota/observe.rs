//! Passive quota observation: read quota headers off an inference response.
//!
//! This is the only part of the quota module that touches the request path, and it is called
//! from `forward_backend_response` where the upstream `HeaderMap` is already cloned. Everything
//! about it is shaped by that constraint.
//!
//! ## Cost
//!
//! The common case is a response with no quota headers at all — most providers send none, and a
//! request to a plain API-key backend never will. For that case this function must do almost
//! nothing, so it dispatches on the **first byte** of the header name before any substring
//! comparison. Every marker in this module begins with `a` or `x`; every other header costs
//! one array index and a `match`. No allocation happens until a marker actually matches, and the
//! `Option` return makes "nothing seen" the cheap, silent path.
//!
//! ## Bounds
//!
//! Upstream response headers are attacker-influenced in the general case, so the scan is capped
//! at [`MAX_HEADERS`] headers and [`MAX_VALUE_CHARS`] bytes per value. Values containing a byte
//! below `0x20` or `0x7f` are rejected outright: a header value carrying CR/LF could forge a line
//! in whatever plain-text log later records it, and no legitimate quota number contains one.
//!
//! ## Marker allow-list
//!
//! Substring markers, not an exhaustive header list, and deliberately narrow. Only three windows
//! are readable from headers (5-hour, weekly, weekly overage), because only three providers emit
//! the headers this recognises.
//!
//! Generic `x-ratelimit-*` and IETF `ratelimit-*` counters are **not** folded into quota. Those
//! are per-minute request counters — a rate limit, not an allowance — and `src/budget/` already
//! owns that axis. Reporting a request rate as "quota remaining" would be wrong even when the
//! arithmetic is right. `Retry-After` is ignored for the same reason: this module has no timers,
//! and a retry hint that never reaches a retry timer is just a misleading number on a chart.
//!
//! ## Assumed header semantics
//!
//! [`ANTHROPIC_UTILIZATION_IS_USED_PERCENT`] records the one polarity assumption in this file. If
//! a live account shows 5-hour windows reading as exhausted while the provider dashboard says the
//! opposite, flipping that one constant is the entire fix — which is why it is a constant and not
//! an expression buried in a parse.

use axum::http::HeaderMap;

use super::{QuotaSource, QuotaWindow, QuotaWindowId, QuotaWindowKind};

/// Header count scanned before giving up. A response that carries quota headers has a couple of
/// dozen at most; anything past this is not a quota response.
pub const MAX_HEADERS: usize = 64;

/// Longest header value considered. Real quota numbers are short; a long value is not one.
pub const MAX_VALUE_CHARS: usize = 512;

/// Whether Anthropic's `*-utilization` headers report percent **used**.
///
/// The OAuth usage endpoint's `utilization` field is documented by the reference implementation as
/// percent used (87 means 13% left), and these headers carry the same word for the same number, so
/// the reading is percent used. It has not been confirmed against a live account — see PROVIDERS.md
/// — which is why it is isolated here.
pub const ANTHROPIC_UTILIZATION_IS_USED_PERCENT: bool = true;

const ANTHROPIC_PREFIX: &[u8] = b"anthropic-ratelimit-unified-";
const CODEX_PREFIX: &[u8] = b"x-codex-";

/// Which named field a header is. The value's meaning depends on this, so it travels with the
/// bucket rather than being re-derived from the value's shape. That distinction is the whole job:
/// `reset` and `utilization` are both frequently plain integers, and guessing from the value is
/// how a reset timestamp becomes "100% used".
#[derive(Clone, Copy, PartialEq)]
enum Field {
    Utilization,
    Status,
    Reset,
}

impl Field {
    /// Exact suffix match, not a contains: `five_hour_last_utilization` from a provider we do not
    /// know must not be read.
    fn parse(tail: &[u8]) -> Option<Self> {
        match tail {
            b"utilization" | b"used-percent" => Some(Self::Utilization),
            b"status" => Some(Self::Status),
            b"reset" | b"reset-at" => Some(Self::Reset),
            _ => None,
        }
    }
}

/// Windows a single response can fill. Three is not an arbitrary cap: it is the number of window
/// ids the recognised header families expose, so the header path cannot overflow the store.
#[derive(Clone, Copy)]
struct Bucket {
    id: QuotaWindowId,
    /// Whether this family's utilization reads as percent **used**. Starts at the Anthropic
    /// assumption (the one constant in this file) and is pinned per-family when the header name
    /// itself states the polarity, so that flipping the constant to debug one provider cannot
    /// silently invert another provider's readings.
    utilization_is_used: bool,
    /// Percent consumed, as the provider states it.
    used_percent: Option<f64>,
    reset_at: Option<u64>,
    /// From a `*-status` header. `Some(false)` means "not rejected", which is **not** the same as
    /// "nothing left" and must not be rendered as 100%.
    exhausted: Option<bool>,
}

impl Bucket {
    const fn new(id: QuotaWindowId) -> Self {
        Self {
            id,
            utilization_is_used: ANTHROPIC_UTILIZATION_IS_USED_PERCENT,
            used_percent: None,
            reset_at: None,
            exhausted: None,
        }
    }

    /// A bucket becomes a window only if the provider actually said something quantitative.
    /// `allowed` alone stays unreported rather than becoming a full window.
    fn finish(&self) -> Option<QuotaWindow> {
        if let Some(used) = self.used_percent {
            return Some(QuotaWindow::percent_window(
                self.id,
                used,
                self.reset_at,
                QuotaSource::ResponseHeader,
            ));
        }
        if self.exhausted == Some(true) {
            // Rejected with no percentage: the window is empty, and saying so beats showing
            // nothing at all while requests are failing.
            return Some(QuotaWindow::percent_window(
                self.id,
                100.0,
                self.reset_at,
                QuotaSource::ResponseHeader,
            ));
        }
        None
    }
}

/// Read whatever quota windows this response advertises.
///
/// Returns `None` — without allocating — when no recognised marker matched. A non-empty result is
/// always deduplicated and rank-ordered, and never contains more than [`super::MAX_WINDOWS`]
/// entries.
pub fn observe_headers(headers: &HeaderMap) -> Option<Vec<QuotaWindow>> {
    let mut five_hour = Bucket::new(QuotaWindowId::FiveHour);
    let mut seven_day = Bucket::new(QuotaWindowId::SevenDay);
    let mut overage = Bucket::new(QuotaWindowId::SevenDayOverage);
    let mut seen = false;

    let mut scanned = 0usize;
    for (name, value) in headers.iter() {
        scanned += 1;
        if scanned > MAX_HEADERS {
            tracing::debug!("quota observation stopped at {MAX_HEADERS} headers");
            break;
        }
        let raw_name = name.as_str().as_bytes();

        // One-byte dispatch. Every marker in this module starts with 'a' or 'x', so all other
        // headers — content-type, request-id, traceparent, the long lot — cost one match arm.
        let slot = match raw_name.first().copied() {
            Some(b'a') => anthropic_slot(raw_name, &mut five_hour, &mut seven_day, &mut overage),
            Some(b'x') => codex_slot(raw_name, &mut five_hour, &mut seven_day),
            _ => None,
        };
        if slot.is_some() {
            seen = true;
        }
        let Some((bucket, field)) = slot else {
            continue;
        };
        let Some(text) = safe_value(value.as_bytes()) else {
            continue;
        };
        apply_value(bucket, field, text);
    }

    if !seen {
        return None;
    }

    let mut out = Vec::with_capacity(3);
    // Partial validity is the point: one malformed bucket must not void the other two.
    for bucket in [five_hour, seven_day, overage] {
        if let Some(w) = bucket.finish() {
            out.push(w);
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(super::rank_truncate(out))
}

/// Route an Anthropic header to its bucket, or `None` if the name is not one of ours.
fn anthropic_slot<'a>(
    name: &'a [u8],
    five_hour: &'a mut Bucket,
    seven_day: &'a mut Bucket,
    overage: &'a mut Bucket,
) -> Option<(&'a mut Bucket, Field)> {
    let rest = strip(name, ANTHROPIC_PREFIX)?;
    // `7d_oi-` cannot be confused with `7d-`: the byte after `7d` differs, so ordering here is
    // free of ambiguity rather than merely conventional.
    let (bucket, tail) = match strip(rest, b"5h-") {
        Some(tail) => (five_hour, tail),
        None => match strip(rest, b"7d_oi-") {
            Some(tail) => (overage, tail),
            None => (seven_day, strip(rest, b"7d-")?),
        },
    };
    Some((bucket, Field::parse(tail)?))
}

/// Route a Codex header to its bucket.
fn codex_slot<'a>(
    name: &'a [u8],
    five_hour: &'a mut Bucket,
    seven_day: &'a mut Bucket,
) -> Option<(&'a mut Bucket, Field)> {
    let rest = strip(name, CODEX_PREFIX)?;
    let (bucket, tail) = match strip(rest, b"primary-") {
        Some(tail) => (five_hour, tail),
        None => (seven_day, strip(rest, b"secondary-")?),
    };
    // `window-minutes` is deliberately ignored: the header name already says which window this is,
    // and letting a provider rename its windows silently reclassify the row.
    let field = Field::parse(tail)?;
    // The Codex header is literally named `used-percent`, so its polarity is a stated fact about
    // the format, not an assumption. Pinning it per-bucket keeps a polarity debug flip for
    // Anthropic (the one constant below) from silently inverting Codex readings too.
    bucket.utilization_is_used = true;
    Some((bucket, field))
}

/// Apply one header value to its bucket, by what the header name said the value is.
///
/// The field kind is taken from the name, never guessed from the value's shape: `reset` and
/// `utilization` are both frequently plain integers, and treating a number as a percentage
/// because it parses as one is how a reset timestamp becomes "100% used".
fn apply_value(bucket: &mut Bucket, field: Field, text: &str) {
    match field {
        Field::Utilization => {
            if let Some(v) = percent(text) {
                bucket.used_percent = Some(if bucket.utilization_is_used {
                    v
                } else {
                    100.0 - v
                });
            }
        }
        Field::Status => {
            // `rejected_warning` means the window is closed with a warning attached, which for
            // quota purposes is the same fact as `rejected`: nothing left. `allowed` records the
            // absence of rejection, which is **not** the same as "nothing left" and so is stored
            // as a fact without ever becoming a rendered number. Anything else is a vocabulary
            // word this build does not know, and is ignored rather than guessed at.
            if text.eq_ignore_ascii_case("rejected")
                || text.eq_ignore_ascii_case("rejected_warning")
            {
                bucket.exhausted = Some(true);
            } else if text.eq_ignore_ascii_case("allowed") {
                bucket.exhausted = Some(false);
            }
        }
        Field::Reset => {
            if let Some(reset) = parse_reset_at(text) {
                bucket.reset_at = Some(reset);
            }
        }
    }
}

/// Parse a percentage, rejecting anything that is not a finite number in `0..=100`.
fn percent(text: &str) -> Option<f64> {
    let v: f64 = text.trim().parse().ok()?;
    if v.is_finite() && (0.0..=100.0).contains(&v) {
        Some(v)
    } else {
        None
    }
}

/// Parse a reset instant as epoch **milliseconds**, from epoch seconds, epoch millis, or RFC 3339.
fn parse_reset_at(text: &str) -> Option<u64> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(n) = t.parse::<f64>() {
        if !n.is_finite() || n <= 0.0 {
            return None;
        }
        // Providers are inconsistent about the unit; the 1e12 boundary separates them reliably
        // because epoch millis are ~1.7e12 and seconds ~1.7e9.
        let ms = if n < 1e12 { n * 1000.0 } else { n };
        return if ms.is_finite() && ms > 0.0 {
            Some(ms as u64)
        } else {
            None
        };
    }
    chrono::DateTime::parse_from_rfc3339(t)
        .ok()
        // Millis, like the numeric path above: `reset_at` is one unit throughout the store, or
        // every countdown built from it is silently off by three orders of magnitude.
        .and_then(|d| u64::try_from(d.timestamp_millis()).ok())
}

/// Validate a raw header value and view it as text.
///
/// Rejects oversized values and any control byte. CR and LF matter specifically: header values get
/// recorded in request logs, and a newline in a value forges a log line.
fn safe_value(bytes: &[u8]) -> Option<&str> {
    if bytes.is_empty() || bytes.len() > MAX_VALUE_CHARS {
        return None;
    }
    if bytes.iter().any(|b| *b < 0x20 || *b == 0x7f) {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

fn strip<'a>(name: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if name.len() > prefix.len() && name.starts_with(prefix) {
        Some(&name[prefix.len()..])
    } else {
        None
    }
}

/// Build a balance window. Kept here so the "never compute a fraction for a count" rule has one
/// constructor rather than three literals.
pub fn balance_window(id: QuotaWindowId, amount: f64, source: QuotaSource) -> QuotaWindow {
    QuotaWindow {
        id,
        kind: QuotaWindowKind::Balance,
        used: amount,
        total: 0.0,
        unlimited: false,
        reset_at: None,
        source,
        variant: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderName;

    fn map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                HeaderName::from_bytes(k.as_bytes()).expect("header name"),
                v.parse().expect("header value"),
            );
        }
        m
    }

    fn fraction(w: &QuotaWindow) -> f64 {
        w.remaining_fraction().expect("fraction")
    }

    #[test]
    fn anthropic_three_windows_from_one_response() {
        let headers = map(&[
            ("anthropic-ratelimit-unified-5h-utilization", "87.5"),
            ("anthropic-ratelimit-unified-5h-reset", "1800000000"),
            ("anthropic-ratelimit-unified-7d-utilization", "12"),
            ("anthropic-ratelimit-unified-7d_oi-utilization", "100"),
        ]);
        let windows = observe_headers(&headers).expect("windows");
        assert_eq!(windows.len(), 3);

        // Utilization is percent USED, so 87.5 leaves 12.5%.
        let five = windows
            .iter()
            .find(|w| w.id == QuotaWindowId::FiveHour)
            .unwrap();
        assert!((fraction(five) - 0.125).abs() < 1e-6);
        assert_eq!(five.reset_at, Some(1_800_000_000_000));
        assert_eq!(five.source, QuotaSource::ResponseHeader);

        let week = windows
            .iter()
            .find(|w| w.id == QuotaWindowId::SevenDay)
            .unwrap();
        assert!((fraction(week) - 0.88).abs() < 1e-6);

        let oi = windows
            .iter()
            .find(|w| w.id == QuotaWindowId::SevenDayOverage)
            .unwrap();
        assert!(
            oi.is_exhausted(),
            "100% used means the overage window is gone"
        );
    }

    #[test]
    fn zero_utilization_is_a_full_window() {
        let headers = map(&[("anthropic-ratelimit-unified-5h-utilization", "0")]);
        let windows = observe_headers(&headers).expect("windows");
        assert_eq!(fraction(&windows[0]), 1.0);
        assert!(!windows[0].is_exhausted());
    }

    #[test]
    fn utilization_polarity_is_one_constant() {
        let headers = map(&[("anthropic-ratelimit-unified-5h-utilization", "87")]);
        let windows = observe_headers(&headers).unwrap();
        let w = windows
            .iter()
            .find(|w| w.id == QuotaWindowId::FiveHour)
            .unwrap();
        if ANTHROPIC_UTILIZATION_IS_USED_PERCENT {
            assert!((fraction(w) - 0.13).abs() < 1e-6, "87 used leaves 13");
        } else {
            assert!((fraction(w) - 0.87).abs() < 1e-6, "87 remaining leaves 87");
        }
    }

    #[test]
    fn codex_primary_and_secondary_windows() {
        let headers = map(&[
            ("x-codex-primary-used-percent", "42"),
            ("x-codex-primary-reset-at", "1800000000"),
            ("x-codex-secondary-used-percent", "5"),
            ("x-codex-secondary-window-minutes", "10080"),
        ]);
        let windows = observe_headers(&headers).expect("windows");
        assert_eq!(windows.len(), 2);
        let primary = windows
            .iter()
            .find(|w| w.id == QuotaWindowId::FiveHour)
            .expect("primary maps to the session window");
        assert!((fraction(primary) - 0.58).abs() < 1e-6);
        let secondary = windows
            .iter()
            .find(|w| w.id == QuotaWindowId::SevenDay)
            .expect("secondary maps to the weekly window");
        assert!((fraction(secondary) - 0.95).abs() < 1e-6);
    }

    #[test]
    fn a_reset_value_is_never_read_as_a_percentage() {
        // The field's meaning comes from the header name, not the value's shape. `87` below is a
        // reset instant; taking it as "87% used" because it parses as a percentage is precisely
        // the guess this parser must not make. With no quantitative field reported, the response
        // reads as nothing rather than as a number built from the wrong field.
        let headers = map(&[
            ("anthropic-ratelimit-unified-5h-reset", "87"),
            ("anthropic-ratelimit-unified-5h-status", "allowed"),
            ("x-codex-primary-reset-at", "2027-01-15T10:00:00Z"),
        ]);
        assert!(
            observe_headers(&headers).is_none(),
            "reset values must not become utilization readings"
        );
        // A status word this build does not know is not a quantity either.
        let unknown = map(&[("anthropic-ratelimit-unified-5h-status", "throttled")]);
        assert!(observe_headers(&unknown).is_none());
    }

    #[test]
    fn codex_reset_accepts_rfc3339_in_millis() {
        let headers = map(&[
            ("x-codex-primary-used-percent", "10"),
            ("x-codex-primary-reset-at", "2027-01-15T10:00:00Z"),
        ]);
        let windows = observe_headers(&headers).expect("windows");
        let dt = chrono::DateTime::parse_from_rfc3339("2027-01-15T10:00:00Z").unwrap();
        assert_eq!(
            windows[0].reset_at,
            u64::try_from(dt.timestamp_millis()).ok(),
            "RFC 3339 resets share the store's millisecond unit"
        );
    }

    #[test]
    fn a_response_with_no_quota_headers_returns_none() {
        assert!(observe_headers(&map(&[("content-type", "application/json")])).is_none());
        assert!(observe_headers(&map(&[("x-request-id", "abc")])).is_none());
        assert!(observe_headers(&map(&[("retry-after", "30")])).is_none());
        assert!(observe_headers(&HeaderMap::new()).is_none());
    }

    #[test]
    fn generic_rate_limit_counters_are_not_quota() {
        // A request rate is not an allowance. Reporting it here would be a rate limit wearing a
        // quota label.
        let headers = map(&[
            ("x-ratelimit-limit-requests", "1000"),
            ("x-ratelimit-remaining-requests", "998"),
            ("ratelimit-remaining", "50"),
            ("ratelimit-limit", "100"),
        ]);
        assert!(
            observe_headers(&headers).is_none(),
            "per-minute request counters must not become quota windows"
        );
    }

    #[test]
    fn rejected_status_without_a_percentage_reports_exhausted() {
        let headers = map(&[
            ("anthropic-ratelimit-unified-5h-status", "rejected"),
            ("anthropic-ratelimit-unified-5h-reset", "1800000000"),
        ]);
        let windows = observe_headers(&headers).expect("windows");
        assert_eq!(windows.len(), 1);
        assert!(windows[0].is_exhausted());
        assert_eq!(windows[0].reset_at, Some(1_800_000_000_000));
    }

    #[test]
    fn allowed_status_does_not_become_a_full_window() {
        // "Not rejected" is not "nothing left". Turning it into 100% would be the unknown-vs-zero
        // mistake wearing a different hat.
        let headers = map(&[("anthropic-ratelimit-unified-5h-status", "allowed")]);
        assert!(
            observe_headers(&headers).is_none(),
            "an `allowed` status carries no quantity to report"
        );
    }

    #[test]
    fn rejected_warning_counts_as_exhausted() {
        let headers = map(&[("anthropic-ratelimit-unified-7d-status", "rejected_warning")]);
        let windows = observe_headers(&headers).expect("windows");
        assert!(windows[0].is_exhausted());
    }

    #[test]
    fn one_malformed_bucket_does_not_void_the_others() {
        let headers = map(&[
            ("anthropic-ratelimit-unified-5h-utilization", "not-a-number"),
            ("anthropic-ratelimit-unified-5h-status", "rejected"),
            ("anthropic-ratelimit-unified-7d-utilization", "30"),
        ]);
        let windows = observe_headers(&headers).expect("windows");
        assert_eq!(windows.len(), 2, "the 7d window survives the bad 5h value");
        let week = windows
            .iter()
            .find(|w| w.id == QuotaWindowId::SevenDay)
            .unwrap();
        assert!((fraction(week) - 0.70).abs() < 1e-6);
        let five = windows
            .iter()
            .find(|w| w.id == QuotaWindowId::FiveHour)
            .unwrap();
        assert!(five.is_exhausted(), "the status header still lands");
    }

    #[test]
    fn out_of_range_percentages_are_rejected() {
        for bad in ["-5", "101", "1e9", "NaN", "inf"] {
            let headers = map(&[("anthropic-ratelimit-unified-5h-utilization", bad)]);
            assert!(
                observe_headers(&headers).is_none(),
                "{bad} must not become a quota reading"
            );
        }
    }

    #[test]
    fn control_bytes_in_a_value_are_refused() {
        // A newline in a header value forges a line in whatever log records it next.
        //
        // Note that `HeaderValue::from_bytes` rejects this too, so a value like it cannot reach
        // `observe_headers` through a real response. The guard is the second line, and it is
        // tested at the boundary it defends rather than pretended to be reachable from the wire.
        assert!(
            axum::http::HeaderValue::from_bytes(b"50\nGET /admin HTTP/1.1").is_err(),
            "premise: the http crate refuses control bytes at construction"
        );
        for bad in [
            &b"50\nGET /admin HTTP/1.1"[..],
            &b"50\r"[..],
            &b"50\x00"[..],
            &b"50\x7f"[..],
            &b"50\x1b[31m"[..],
        ] {
            assert_eq!(safe_value(bad), None, "{bad:?} must be refused");
        }
        assert_eq!(safe_value(b"50"), Some("50"));
    }

    #[test]
    fn oversized_values_are_refused() {
        let huge = "9".repeat(MAX_VALUE_CHARS + 10);
        let headers = map(&[("anthropic-ratelimit-unified-5h-utilization", huge.as_str())]);
        assert!(observe_headers(&headers).is_none());
    }

    #[test]
    fn the_header_scan_is_bounded() {
        let mut m = HeaderMap::new();
        // Push the real marker past the scan cap; it must not be picked up.
        for i in 0..(MAX_HEADERS + 10) {
            m.insert(
                HeaderName::from_bytes(format!("x-filler-{i}").as_bytes()).unwrap(),
                "1".parse().unwrap(),
            );
        }
        m.insert(
            HeaderName::from_static("anthropic-ratelimit-unified-5h-utilization"),
            "10".parse().unwrap(),
        );
        assert!(
            observe_headers(&m).is_none(),
            "the cap must bound the scan, not be advisory"
        );
    }

    #[test]
    fn unknown_codex_subfamilies_are_ignored() {
        let headers = map(&[
            ("x-codex-primary-limit-reached", "true"),
            ("x-codex-credits-remaining", "3"),
            ("x-codex-plan-type", "pro"),
            ("x-request-id", "r-1"),
        ]);
        assert!(observe_headers(&headers).is_none());
    }

    #[test]
    fn similar_prefixes_do_not_match() {
        // The prefix must be a real prefix, not a substring test.
        let headers = map(&[("x-anthropic-ratelimit-unified-5h-utilization", "90")]);
        assert!(observe_headers(&headers).is_none());
    }

    #[test]
    fn reset_accepts_seconds_millis_and_rfc3339() {
        assert_eq!(parse_reset_at("1800000000"), Some(1_800_000_000_000));
        assert_eq!(parse_reset_at("1800000000000"), Some(1_800_000_000_000));
        // RFC 3339 must land in the same unit as the numeric paths. The reference this parser
        // follows returned raw seconds here, which made every RFC 3339 reset read as already
        // passed — three orders of magnitude is not a rounding error.
        let dt = chrono::DateTime::parse_from_rfc3339("2027-01-15T10:00:00Z").unwrap();
        assert_eq!(
            parse_reset_at("2027-01-15T10:00:00Z"),
            u64::try_from(dt.timestamp_millis()).ok()
        );
        assert_eq!(parse_reset_at(""), None);
        assert_eq!(parse_reset_at("   "), None);
        assert_eq!(parse_reset_at("-5"), None);
        assert_eq!(parse_reset_at("tomorrow"), None);
    }

    #[test]
    fn a_balance_window_never_reports_a_fraction() {
        let w = balance_window(QuotaWindowId::OnDemand, 348.0, QuotaSource::Provider);
        assert_eq!(w.remaining_fraction(), None);
        assert_eq!(w.level(), "unknown");
        assert_eq!(w.kind, QuotaWindowKind::Balance);
    }

    #[test]
    fn results_are_ranked_deterministically() {
        let headers = map(&[
            ("anthropic-ratelimit-unified-7d-utilization", "10"),
            ("anthropic-ratelimit-unified-5h-utilization", "20"),
            ("anthropic-ratelimit-unified-7d_oi-utilization", "30"),
        ]);
        let ids: Vec<QuotaWindowId> = observe_headers(&headers)
            .unwrap()
            .iter()
            .map(|w| w.id)
            .collect();
        assert_eq!(
            ids,
            vec![
                QuotaWindowId::FiveHour,
                QuotaWindowId::SevenDay,
                QuotaWindowId::SevenDayOverage
            ]
        );
    }
}
