-- PR #9 (opencode-free) recreated `backends_format_check` to accept the free-tier
-- marker dialect but missed `model_routes_auth_mode_check`: routes could not persist
-- auth_mode = 'opencode_free', so the free-tier lane (identity headers + body
-- adaptation) never engaged and upstream answered 403 "free tier can only be used
-- from within OpenCode". Recreate the check with the value added.
ALTER TABLE model_routes DROP CONSTRAINT IF EXISTS model_routes_auth_mode_check;
ALTER TABLE model_routes ADD CONSTRAINT model_routes_auth_mode_check
    CHECK (auth_mode = ANY (ARRAY[
        'bearer', 'anthropic', 'none',
        'anthropic_oauth', 'chatgpt_oauth', 'xai_oauth', 'opencode_free'
    ]));
