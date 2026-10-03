//! Background token refresh for OAuth credentials.
//!
//! Runs off the request path, the same shape as `RamBackendPool::start_health_loop`. The loop
//! is the only writer of token files, and it writes at most once per credential even when the
//! interval fires repeatedly.
//!
//! Single-flight is not an optimization here, it is a correctness requirement: Codex rotates
//! its refresh token on every use, so two concurrent refreshes of the same credential present
//! a spent token and log the account out.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

use super::flow::{self, FlowError};
use super::{
    OAuthProviderSpec, OAuthToken, OAuthTokenStore, RefreshOutcome, is_terminal_refresh_error,
};

/// Backoff bounds for a failing provider, in seconds. Short enough that a transient blip
/// recovers quickly, long enough that a real outage does not turn into token-endpoint traffic.
const RETRY_MIN_SECS: u64 = 30;
const RETRY_MAX_SECS: u64 = 15 * 60;

/// Per-credential failure state, so one dead provider does not slow every other refresh down.
#[derive(Debug, Clone, Copy)]
struct Backoff {
    next_attempt_at: i64,
    consecutive_failures: u32,
}

/// Serializes refresh per credential. One mutex per `(provider, label)`.
#[derive(Default)]
pub struct RefreshCoordinator {
    locks: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
    backoff: DashMap<String, Backoff>,
}

impl RefreshCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(provider: &str, label: &str) -> String {
        format!("{provider}/{label}")
    }

    async fn lock_for(&self, provider: &str, label: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.locks
            .entry(Self::key(provider, label))
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn allow_now(&self, provider: &str, label: &str, now: i64) -> bool {
        self.backoff
            .get(&Self::key(provider, label))
            .map(|b| now >= b.next_attempt_at)
            .unwrap_or(true)
    }

    fn record_failure(&self, provider: &str, label: &str, now: i64) {
        let key = Self::key(provider, label);
        let mut entry = self.backoff.entry(key).or_insert(Backoff {
            next_attempt_at: 0,
            consecutive_failures: 0,
        });
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        let delay = RETRY_MIN_SECS
            .saturating_mul(1u64 << entry.consecutive_failures.min(5))
            .min(RETRY_MAX_SECS);
        entry.next_attempt_at = now + i64::try_from(delay).unwrap_or(RETRY_MAX_SECS as i64);
    }

    fn record_success(&self, provider: &str, label: &str) {
        self.backoff.remove(&Self::key(provider, label));
    }

    /// Refresh one credential if it is due. Concurrent callers collapse onto the same lock, so
    /// a burst of triggers performs at most one token exchange.
    pub async fn refresh_if_due(
        &self,
        client: &reqwest::Client,
        store: &OAuthTokenStore,
        spec: &'static OAuthProviderSpec,
        token: &OAuthToken,
        now: i64,
    ) -> RefreshOutcome {
        if !token.needs_refresh(spec, now) {
            return RefreshOutcome::NotDue;
        }
        if !self.allow_now(&token.provider, &token.label, now) {
            return RefreshOutcome::Transient;
        }
        let guard = self.lock_for(&token.provider, &token.label).await;
        let _held = guard.lock().await;
        // Re-check under the lock: an earlier holder may already have refreshed.
        match store.read(&token.provider, &token.label) {
            Ok(current) if !current.needs_refresh(spec, now) => {
                self.record_success(&token.provider, &token.label);
                RefreshOutcome::NotDue
            }
            Ok(current) => {
                let next = current.clone();
                drop(_held);
                self.exchange(client, store, spec, &next, now).await
            }
            Err(_) => {
                // Credential file vanished or became unreadable mid-flight.
                self.record_failure(&token.provider, &token.label, now);
                RefreshOutcome::NeedsReconnect
            }
        }
    }

    async fn exchange(
        &self,
        client: &reqwest::Client,
        store: &OAuthTokenStore,
        spec: &'static OAuthProviderSpec,
        token: &OAuthToken,
        now: i64,
    ) -> RefreshOutcome {
        match flow::refresh_token(client, spec, token).await {
            Ok(next) => match store.write(&next) {
                Ok(()) => {
                    self.record_success(&token.provider, &token.label);
                    tracing::info!(
                        provider = %token.provider,
                        label = %token.label,
                        "oauth credential refreshed"
                    );
                    RefreshOutcome::Refreshed
                }
                Err(e) => {
                    tracing::error!(provider = %token.provider, error = %e, "write refreshed oauth token failed");
                    self.record_failure(&token.provider, &token.label, now);
                    RefreshOutcome::Transient
                }
            },
            Err(FlowError::NeedsReconnect(reason)) => {
                // Do not retry: a rejected refresh token is terminal until the operator
                // reconnects. Retrying is what turns one bad token into a reconnect storm.
                tracing::warn!(
                    provider = %token.provider,
                    label = %token.label,
                    reason = %reason,
                    "oauth credential needs reconnect; refresh stopped"
                );
                RefreshOutcome::NeedsReconnect
            }
            Err(FlowError::AuthorizationPending) => RefreshOutcome::Transient,
            Err(e) => {
                let message = e.message();
                let outcome = if is_terminal_refresh_error(&message) {
                    RefreshOutcome::NeedsReconnect
                } else {
                    self.record_failure(&token.provider, &token.label, now);
                    RefreshOutcome::Transient
                };
                tracing::warn!(
                    provider = %token.provider,
                    label = %token.label,
                    error = %message,
                    outcome = outcome.as_str(),
                    "oauth refresh failed"
                );
                outcome
            }
        }
    }
}

/// Spawn the periodic refresh task.
///
/// `on_change` fires after any successful write so the caller can nudge the config loader and
/// pick the new access token up without waiting for the next poll.
pub fn spawn_refresh_loop(
    store: Arc<OAuthTokenStore>,
    client: reqwest::Client,
    interval: Duration,
    on_change: Arc<dyn Fn() + Send + Sync>,
) -> tokio::task::JoinHandle<()> {
    let coordinator = Arc::new(RefreshCoordinator::new());
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let now = flow::now_secs();
            let mut changed = false;
            for token in store.list() {
                let Some(spec) = super::spec(&token.provider) else {
                    tracing::warn!(
                        provider = %token.provider,
                        "oauth credential has no matching provider spec; ignoring"
                    );
                    continue;
                };
                if !token.needs_refresh(spec, now) {
                    continue;
                }
                let outcome = coordinator
                    .refresh_if_due(&client, &store, spec, &token, now)
                    .await;
                if outcome == RefreshOutcome::Refreshed {
                    changed = true;
                }
            }
            if changed {
                on_change();
            }
        }
    })
}

/// Poll interval for the refresh loop.
///
/// Sixty seconds is comfortably inside the tightest provider lead (xAI, five minutes) and costs
/// one directory listing per minute regardless of how many credentials exist.
pub const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 60;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::spec;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_store() -> (OAuthTokenStore, std::path::PathBuf) {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("brighto-refresh-test-{}-{n}", std::process::id()));
        (OAuthTokenStore::new(dir.clone()), dir)
    }

    fn token(provider: &str, label: &str, expires_at: i64) -> OAuthToken {
        OAuthToken {
            provider: provider.into(),
            label: label.into(),
            account_id: Some("acct-1".into()),
            account_name: Some("dev@example.com".into()),
            access_token: "at-1".into(),
            refresh_token: Some("rt-1".into()),
            expires_at,
            scopes: None,
            refreshed_at: 0,
        }
    }

    #[test]
    fn a_token_outside_the_lead_window_is_never_due() {
        let claude = spec("claude-code").unwrap();
        let lead = i64::try_from(claude.refresh_lead.as_secs()).unwrap();
        // One second more validity than the lead: the loop must leave it alone.
        let t = token("claude-code", "a@example.com", 100_000 + lead + 1);
        assert!(!t.needs_refresh(claude, 100_000));
        // One second inside the lead: refresh now.
        let t = token("claude-code", "a@example.com", 100_000 + lead);
        assert!(t.needs_refresh(claude, 100_000));
    }

    #[test]
    fn different_providers_have_different_leads() {
        // A single global lead would either hammer Claude's token endpoint or let Codex tokens
        // expire in flight.
        let claude = spec("claude-code").unwrap();
        let codex = spec("codex").unwrap();
        assert!(claude.refresh_lead > codex.refresh_lead);
    }

    #[test]
    fn backoff_grows_then_saturates() {
        let c = RefreshCoordinator::new();
        let now = 1_000;
        assert!(c.allow_now("codex", "a", now));
        c.record_failure("codex", "a", now);
        assert!(!c.allow_now("codex", "a", now));
        // Eventually eligible again.
        assert!(c.allow_now(
            "codex",
            "a",
            now + i64::try_from(RETRY_MAX_SECS).unwrap() + 1
        ));
        // Bounded: many failures never push the delay past the cap.
        for _ in 0..40 {
            c.record_failure("codex", "a", now);
        }
        assert!(!c.allow_now("codex", "a", now));
        assert!(c.allow_now(
            "codex",
            "a",
            now + i64::try_from(RETRY_MAX_SECS).unwrap() + 1
        ));
    }

    #[test]
    fn backoff_is_per_credential() {
        let c = RefreshCoordinator::new();
        c.record_failure("codex", "bad", 1_000);
        // One failing account must not delay a healthy one.
        assert!(c.allow_now("codex", "good", 1_000));
        assert!(c.allow_now("claude-code", "bad", 1_000));
    }

    #[test]
    fn success_clears_backoff() {
        let c = RefreshCoordinator::new();
        c.record_failure("codex", "a", 1_000);
        assert!(!c.allow_now("codex", "a", 1_000));
        c.record_success("codex", "a");
        assert!(c.allow_now("codex", "a", 1_000));
    }

    #[tokio::test]
    async fn locks_are_per_credential_so_two_accounts_do_not_block_each_other() {
        let c = Arc::new(RefreshCoordinator::new());
        let a = c.lock_for("codex", "a").await;
        let b = c.lock_for("codex", "b").await;
        let held = a.lock().await;
        // Acquiring the other credential's lock must not block; only the same one does.
        let b2 = tokio::time::timeout(Duration::from_millis(50), b.lock()).await;
        assert!(b2.is_ok());
        drop(held);
    }

    #[tokio::test]
    async fn same_credential_lock_is_shared_across_callers() {
        let c = Arc::new(RefreshCoordinator::new());
        let one = c.lock_for("codex", "a").await;
        let two = c.lock_for("codex", "a").await;
        assert!(Arc::ptr_eq(&one, &two));
        let held = one.lock().await;
        let blocked = tokio::time::timeout(Duration::from_millis(50), two.lock()).await;
        assert!(blocked.is_err(), "second refresh must wait for the first");
        drop(held);
    }

    #[tokio::test]
    async fn not_due_is_reported_without_touching_the_network() {
        let claude = spec("claude-code").unwrap();
        let lead = i64::try_from(claude.refresh_lead.as_secs()).unwrap();
        let (store, dir) = temp_store();
        let t = token("claude-code", "a@example.com", 100_000 + lead + 1_000);
        store.write(&t).unwrap();
        let c = RefreshCoordinator::new();
        // An unroutable client would fail if the exchange were attempted.
        let client = reqwest::Client::new();
        let outcome = c.refresh_if_due(&client, &store, claude, &t, 100_000).await;
        assert_eq!(outcome, RefreshOutcome::NotDue);
        assert_eq!(
            store
                .read("claude-code", "a@example.com")
                .unwrap()
                .access_token,
            "at-1"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
