-- Provider registry (code-level catalog of known upstream provider types).
--
-- `backends.provider_type` stores a slug from the compiled-in registry
-- (src/provider_registry.rs). When it is set, config load derives base_url + backend format
-- (and the route-facing protocol/auth_mode defaults) from the registry row, so a backend can
-- be created with just provider_type + credential and the stored columns may be empty.
--
-- The column stays free-form TEXT on purpose: the registry lives in code and other entries
-- ship in later releases, so a database CHECK would reject rows written by a newer binary.
-- NULL (or empty) keeps the legacy behavior where every value is caller-supplied.
ALTER TABLE backends
    ADD COLUMN IF NOT EXISTS provider_type TEXT NULL;
