-- Combos: one admin call that expands an ordered member list into a Model Group route.
--
-- model_routes.is_combo marks rows owned by POST /admin/combos. The flag is what makes the
-- upsert safe: a combo may replace its own members, but never a manually configured route
-- (those keep the plain 409 the routes endpoint already returns).
--
-- model_routes.combo_members stores the ordered member list verbatim (JSONB array:
-- [{"backend_id":7,"model":"glm-5.3"}, ...]) so GET /admin/combos can replay the definition
-- order. Endpoint rows are keyed by (model_name, backend_id) and carry no position; the JSONB
-- array order is the single source of truth for member order (and therefore for the derived
-- weight sequence 8, 4, 2, 1, 1, ...).
--
-- Nothing else changes: a combo route is a normal model_routes row plus
-- model_route_endpoints rows, so the config loader, proxy, /v1/models and the routes admin
-- API all serve it without knowing the flag exists. Existing rows keep is_combo = FALSE.
ALTER TABLE model_routes
    ADD COLUMN IF NOT EXISTS is_combo BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE model_routes
    ADD COLUMN IF NOT EXISTS combo_members JSONB;
