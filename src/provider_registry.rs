//! Internal provider registry — a compiled-in catalog of known upstream provider types.
//!
//! Each entry is pure data (`ProviderType`): one row says what `base_url`, route `protocol`
//! and `auth_mode` a backend of that type uses, so creating a backend needs only
//! `provider_type + credential` instead of base_url/format/auth switches. The table is
//! deliberately a flat static slice: adding a provider is one self-contained row, no new
//! code paths, no migrations, and no `PROVIDER_CATALOG` edit.
//!
//! This catalog is separate from the two tables that already exist:
//! * `PROVIDER_CATALOG` (env) — Portal *presets* for the manual add-route wizard; optional,
//!   operator-editable, and it may never list a provider the registry knows.
//! * `oauth::PROVIDERS` — OAuth *flow* machinery (endpoints, client ids, refresh).
//!   Registry entries for OAuth providers reference the same `auth_mode` values and must stay
//!   in sync with those specs (a unit test pins the base URLs and protocols together).
//!
//! `backends.provider_type` stores a slug from this table. When it is set, config load
//! derives `base_url` + backend `format` (and the route-facing `protocol`/`auth_mode`
//! defaults) from the row here; a NULL column keeps the pre-registry behavior where every
//! value is caller-supplied. Backward compatibility is total: payloads and rows that never
//! mention `provider_type` are handled exactly as before.

use serde::Serialize;

/// One known upstream provider type. Self-contained: every field needed to derive a backend
/// row (and the route defaults that ride on it) lives on the row itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProviderType {
    /// Value stored in `backends.provider_type` and sent by callers of `POST /admin/backends`.
    pub slug: &'static str,
    /// Human-readable name for admin UI dropdowns.
    pub display_name: &'static str,
    /// Default upstream base URL. `None` means the caller must supply one (escape hatch).
    pub base_url: Option<&'static str>,
    /// Route protocol (`ProviderProtocol::as_str()` taxonomy), e.g. `openai_chat`.
    pub protocol: &'static str,
    /// Credential transport (`provider_auth::AUTH_MODES` taxonomy), e.g. `bearer`.
    pub auth_mode: &'static str,
    /// True when a backend of this type must be created with an API-key credential
    /// (`key` or `api_key_ref`). False for OAuth providers (the credential is a connected
    /// account attached later, never a pasted key) and for keyless entries such as local
    /// custom endpoints. `auth_mode` tells callers *which* kind of credential applies.
    pub requires_credential: bool,
    /// Operator-facing notes surfaced by `GET /admin/providers`.
    pub notes: &'static str,
}

/// The catalog. Ordered as the admin API should list it (API-key providers first, then
/// OAuth, then the escape hatch).
pub static PROVIDER_TYPES: &[ProviderType] = &[
    ProviderType {
        slug: "zai",
        display_name: "Z.AI",
        base_url: Some("https://api.z.ai/api/paas/v4"),
        protocol: "openai_chat",
        auth_mode: "bearer",
        requires_credential: true,
        notes: "OpenAI-compatible chat endpoint. Same defaults as the seeded `zai` backend \
                template (env:ZAI_API_KEY).",
    },
    ProviderType {
        slug: "deepseek",
        display_name: "DeepSeek",
        base_url: Some("https://api.deepseek.com"),
        protocol: "openai_chat",
        auth_mode: "bearer",
        requires_credential: true,
        notes: "OpenAI-compatible. Matches the seeded `deepseek` backend template \
                (env:DEEPSEEK_API_KEY).",
    },
    ProviderType {
        slug: "dahl",
        display_name: "Dahl",
        base_url: Some("https://inference.dahl.global/v1"),
        protocol: "openai_chat",
        auth_mode: "bearer",
        requires_credential: true,
        notes: "OpenAI-compatible endpoint on inference.dahl.global.",
    },
    ProviderType {
        slug: "codex-oauth",
        display_name: "Codex (ChatGPT OAuth)",
        base_url: Some("https://chatgpt.com/backend-api/codex"),
        protocol: "codex_responses",
        auth_mode: "chatgpt_oauth",
        requires_credential: false,
        notes: "ChatGPT Plus/Pro Codex allowance. Connect an account first and reference it as \
                oauth:codex:<label>; a pasted API key is rejected. Third-party OAuth path — see \
                SECURITY.md for risks.",
    },
    ProviderType {
        slug: "xai-grok-oauth",
        display_name: "xAI Grok (OAuth)",
        base_url: Some("https://cli-chat-proxy.grok.com/v1"),
        protocol: "openai_responses",
        auth_mode: "xai_oauth",
        requires_credential: false,
        notes: "SuperGrok subscription via the CLI proxy host (api.x.ai rejects consumer OAuth). \
                Connect an account first and reference it as oauth:xai-oauth:<label>.",
    },
    ProviderType {
        slug: "custom-openai",
        display_name: "Custom OpenAI-compatible",
        base_url: None,
        protocol: "openai_chat",
        auth_mode: "bearer",
        requires_credential: false,
        notes: "Escape hatch for any OpenAI-compatible endpoint, local or hosted. Caller must \
                supply base_url; the key is optional (leave empty for no-auth local servers).",
    },
];

/// Look up a registry entry by slug (case-insensitive, surrounding whitespace ignored).
pub fn lookup(slug: &str) -> Option<&'static ProviderType> {
    let s = slug.trim().to_ascii_lowercase();
    PROVIDER_TYPES.iter().find(|p| p.slug == s)
}

/// Every registry entry, in catalog order, for `GET /admin/providers`.
pub fn list() -> &'static [ProviderType] {
    PROVIDER_TYPES
}

impl ProviderType {
    /// Backend `format` column value this entry's protocol implies: only the Anthropic
    /// Messages protocol rides an `anthropic`-format backend; everything else is `openai`.
    pub fn backend_format(&self) -> &'static str {
        backend_format_for(self.protocol)
    }

    /// Resolve the runtime base URL for a backend of this type given the value stored in the
    /// row. Entries with a fixed base URL always win over the stored value (including an
    /// empty one), so a registry fix propagates on the next poll; entries without one
    /// (`custom-openai`) keep whatever the caller stored.
    pub fn resolve_base_url(&self, stored: &str) -> String {
        match self.base_url {
            Some(fixed) => fixed.to_string(),
            None => stored.to_string(),
        }
    }
}

/// Backend `format` implied by a route protocol name ("anthropic" | "openai").
pub fn backend_format_for(protocol: &str) -> &'static str {
    if protocol == "anthropic_messages" {
        "anthropic"
    } else {
        "openai"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth;
    use crate::provider_auth::is_oauth_mode;

    #[test]
    fn lookup_finds_every_shipped_slug() {
        for entry in PROVIDER_TYPES {
            let found = lookup(entry.slug).expect("every slug must resolve to itself");
            assert_eq!(found.slug, entry.slug);
            assert_eq!(found.base_url, entry.base_url);
            assert_eq!(found.protocol, entry.protocol);
            assert_eq!(found.auth_mode, entry.auth_mode);
        }
    }

    #[test]
    fn lookup_is_case_insensitive_and_trims() {
        assert_eq!(lookup("DeepSeek").unwrap().slug, "deepseek");
        assert_eq!(lookup("  CODEX-OAUTH ").unwrap().slug, "codex-oauth");
        assert!(lookup("not-a-provider").is_none());
        assert!(lookup("").is_none());
    }

    #[test]
    fn catalog_has_no_duplicate_slugs() {
        let mut slugs: Vec<&str> = PROVIDER_TYPES.iter().map(|p| p.slug).collect();
        slugs.sort_unstable();
        let count = slugs.len();
        slugs.dedup();
        assert_eq!(slugs.len(), count, "duplicate slug in PROVIDER_TYPES");
    }

    #[test]
    fn api_key_providers_carry_bearer_auth_and_a_fixed_base_url() {
        for slug in ["zai", "deepseek", "dahl"] {
            let entry = lookup(slug).unwrap();
            assert_eq!(entry.auth_mode, "bearer", "{slug}");
            assert_eq!(entry.protocol, "openai_chat", "{slug}");
            assert!(
                entry.requires_credential,
                "{slug} needs a key at create time"
            );
            assert!(entry.base_url.is_some(), "{slug} pins a base URL");
        }
        // Grounded in the live deployment this registry describes.
        assert_eq!(
            lookup("zai").unwrap().base_url,
            Some("https://api.z.ai/api/paas/v4")
        );
        assert_eq!(
            lookup("deepseek").unwrap().base_url,
            Some("https://api.deepseek.com")
        );
        assert_eq!(
            lookup("dahl").unwrap().base_url,
            Some("https://inference.dahl.global/v1")
        );
    }

    #[test]
    fn oauth_entries_stay_in_sync_with_the_oauth_spec_table() {
        // The registry must not drift from oauth::PROVIDERS: same auth_mode must mean the
        // same inference base URL and route protocol, or backend derivation and route
        // creation would disagree about where traffic goes.
        for entry in PROVIDER_TYPES.iter().filter(|p| is_oauth_mode(p.auth_mode)) {
            let spec = oauth::spec_for_auth_mode(entry.auth_mode)
                .unwrap_or_else(|| panic!("no OAuth spec for {}", entry.auth_mode));
            assert_eq!(
                entry.base_url,
                Some(spec.api_base_url),
                "{}: base_url must match the OAuth spec",
                entry.slug
            );
            assert_eq!(
                entry.protocol, spec.protocol,
                "{}: protocol must match the OAuth spec",
                entry.slug
            );
            assert!(
                !entry.requires_credential,
                "{}: OAuth providers are created without a pasted key",
                entry.slug
            );
        }
    }

    #[test]
    fn custom_openai_requires_a_caller_base_url() {
        let entry = lookup("custom-openai").unwrap();
        assert_eq!(entry.base_url, None);
        assert_eq!(entry.protocol, "openai_chat");
        assert_eq!(entry.auth_mode, "bearer");
        // Key optional: local llama.cpp/vLLM endpoints run without auth.
        assert!(!entry.requires_credential);
    }

    #[test]
    fn backend_format_follows_the_protocol_family() {
        assert_eq!(backend_format_for("anthropic_messages"), "anthropic");
        assert_eq!(backend_format_for("openai_chat"), "openai");
        assert_eq!(backend_format_for("codex_responses"), "openai");
        assert_eq!(backend_format_for("openai_responses"), "openai");
    }

    #[test]
    fn fixed_base_url_entries_override_the_stored_value() {
        let deepseek = lookup("deepseek").unwrap();
        assert_eq!(
            deepseek.resolve_base_url("https://stale.example.com"),
            "https://api.deepseek.com"
        );
        assert_eq!(deepseek.resolve_base_url(""), "https://api.deepseek.com");

        let custom = lookup("custom-openai").unwrap();
        assert_eq!(
            custom.resolve_base_url("http://127.0.0.1:8088/v1"),
            "http://127.0.0.1:8088/v1"
        );
    }

    #[test]
    fn list_returns_the_catalog_for_the_admin_endpoint() {
        let entries = list();
        assert!(entries.len() >= 6);
        assert!(entries.iter().any(|p| p.slug == "custom-openai"));
    }
}
