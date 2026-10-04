-- Dynamic model catalog + passthrough routing.
--
-- backends.dynamic_models: the backend's model list is fetched live from
-- GET {base_url}/models (OpenAI-shaped {data:[{id}]}) by a background refresher, instead of
-- being hardcoded as one model_routes row per model. Motivating case: OpenCode Free
-- (https://opencode.ai/zen/v1), whose free model list rotates frequently.
--
-- model_routes.passthrough: the route row no longer names one client-facing model; it supplies
-- protocol/auth/pricing for EVERY model present in its single backend's dynamic catalog.
-- Models unknown to the route table still route when the catalog contains them.

ALTER TABLE backends
    ADD COLUMN IF NOT EXISTS dynamic_models BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE model_routes
    ADD COLUMN IF NOT EXISTS passthrough BOOLEAN NOT NULL DEFAULT FALSE;
