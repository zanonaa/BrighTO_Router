-- OAuth provider credentials.
--
-- Adds three `auth_mode` values that carry a short-lived OAuth access token instead of a
-- long-lived API key. `auth_mode` is the axis that already exists on both the route and the
-- Model Group endpoint table, so no new column is needed for the credential itself.
--
-- Existing deployments are untouched: the CHECK is widened, never narrowed, and every route
-- keeps the value it already had.
ALTER TABLE model_routes
    DROP CONSTRAINT IF EXISTS model_routes_auth_mode_check;

ALTER TABLE model_routes
    ADD CONSTRAINT model_routes_auth_mode_check
    CHECK (auth_mode IN ('bearer','anthropic','none','anthropic_oauth','chatgpt_oauth','xai_oauth'));

-- 0007 created this CHECK inline, so PostgreSQL named it after the column.
ALTER TABLE model_route_endpoints
    DROP CONSTRAINT IF EXISTS model_route_endpoints_auth_mode_check;

ALTER TABLE model_route_endpoints
    ADD CONSTRAINT model_route_endpoints_auth_mode_check
    CHECK (auth_mode IN ('bearer','anthropic','none','anthropic_oauth','chatgpt_oauth','xai_oauth'));

-- A credential reference for an OAuth route must be an `oauth:<provider>:<label>` reference, or
-- the router has no refresh token to renew and the route breaks the moment the token expires.
--
-- No protocol backfill: no row could carry `chatgpt_oauth` before this migration widened the
-- CHECK above, so there is nothing to rewrite. `admin::validate_route` derives the protocol from
-- the credential's `OAuthProviderSpec` (`codex_responses` for Codex) when the caller omits one.
ALTER TABLE model_routes
    ADD CONSTRAINT model_routes_oauth_ref_check
    CHECK (
        auth_mode NOT IN ('anthropic_oauth','chatgpt_oauth','xai_oauth')
        OR (provider_key_ref IS NOT NULL AND provider_key_ref LIKE 'oauth:%')
    );

ALTER TABLE model_route_endpoints
    ADD CONSTRAINT model_route_endpoints_oauth_ref_check
    CHECK (
        auth_mode NOT IN ('anthropic_oauth','chatgpt_oauth','xai_oauth')
        OR (provider_key_ref IS NOT NULL AND provider_key_ref LIKE 'oauth:%')
    );