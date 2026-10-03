-- OpenCode Zen free tier (https://opencode.ai/zen/v1): backends can carry the marker format
-- 'opencode_free'. It is not a third wire dialect (config load maps it to the OpenAI dialect);
-- it tells admin probes such as GET /admin/backends/{id}/models to send the free-tier identity
-- headers (pinned opencode User-Agent, client/project headers, canonical session ids) that the
-- upstream catalog endpoint requires.
ALTER TABLE backends DROP CONSTRAINT IF EXISTS backends_format_check;
ALTER TABLE backends ADD CONSTRAINT backends_format_check
    CHECK (format IN ('openai', 'anthropic', 'opencode_free'));
