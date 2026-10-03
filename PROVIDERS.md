# Provider setup

BrighTO-Router 1.1.0 keeps provider setup simple: use **Add model route** for one tested endpoint, or **Create model group** to load-balance one API model name across two or more existing tested routes of the same type. The single-route flow covers chat, embeddings, rerank, System One/Decision, and ASR/transcription.

A **provider catalog entry** is only a preset: display name, default Base URL, protocol family, and optional `.env` key name. It is not an active route.

A **model route** is what clients use for one endpoint. It maps one API model name to one upstream provider model, with its task type, provider API key/reference, price, limits, and enabled/disabled state.

The API model name must be unique across all model routes and Model Groups. It is not a decorative display label; it is the exact `model` string clients send.

A **Model Group** is also what clients use, but it points one API model name at several existing tested routes of the same type. Clients still send one `model` value. The router chooses the source route by round robin or weighted round robin and skips unhealthy endpoints.

## Provider catalog

The catalog is configured by `PROVIDER_CATALOG` in `.env`. The default catalog includes:

| Provider | Default Base URL | Protocol family | Env key |
|---|---|---|---|
| OpenAI | `https://api.openai.com` | OpenAI-compatible | `OPENAI_API_KEY` |
| Anthropic | `https://api.anthropic.com` | Anthropic Messages | `ANTHROPIC_API_KEY` |
| Gemini | `https://generativelanguage.googleapis.com/v1beta/openai` | OpenAI-compatible | `GEMINI_API_KEY` |
| DeepSeek | `https://api.deepseek.com` | OpenAI-compatible | `DEEPSEEK_API_KEY` |
| Kimi | `https://api.moonshot.ai/v1` | OpenAI-compatible | `KIMI_API_KEY` |
| Qwen | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` | OpenAI-compatible chat/embedding; DashScope rerank adapter uses workspace root URL | `QWEN_API_KEY` or `DASHSCOPE_API_KEY` |
| Z.AI | `https://api.z.ai/api/paas/v4` | OpenAI-compatible | `ZAI_API_KEY` |
| OpenRouter | `https://openrouter.ai/api/v1` | OpenAI-compatible | `OPENROUTER_API_KEY` |
| Jina AI | `https://api.jina.ai` | Embedding/rerank adapter | `JINA_API_KEY` |
| Voyage AI | `https://api.voyageai.com` | Embedding/rerank adapter | `VOYAGE_API_KEY` |
| Cohere | `https://api.cohere.com/v2` | Rerank adapter | `COHERE_API_KEY` |
| Meta Muse | `https://api.meta.ai/v1` | OpenAI-compatible | `META_MUSE_API_KEY` |
| Custom LLM | `http://127.0.0.1:8088/v1` | OpenAI-compatible or System One when selected by task | `CUSTOM_LLM_API_KEY` |
| Ollaya System One | `http://127.0.0.1:11435/v1` | System One decisions | `OLLAYA_API_KEY` |

**OpenAI-compatible** means the backend accepts OpenAI-style routes such as `/v1/chat/completions`, `/v1/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/audio/transcriptions`, or `/v1/models` depending on the selected task. Rerank providers are selected by task type because several providers use different request shapes.

## OAuth providers (subscription accounts)

Some subscriptions are usable through the router without a paid API key, by signing in with the
account the same way the vendor's own CLI does. Three such providers ship with the router:

| Catalog key | Account | `auth_mode` | Route protocol | Flow | Inference base URL |
|---|---|---|---|---|---|
| `claude-code` | Claude Pro / Max (Anthropic subscription) | `anthropic_oauth` | `anthropic_messages` | browser + PKCE | `https://api.anthropic.com` |
| `codex` | ChatGPT Plus / Pro (Codex allowance) | `chatgpt_oauth` | `codex_responses` | browser + PKCE | `https://chatgpt.com/backend-api/codex` |
| `xai-oauth` | SuperGrok / X Premium+ | `xai_oauth` | `openai_responses` | device code | `https://cli-chat-proxy.grok.com/v1` |

These three are appended to the catalog from a table compiled into the binary, so **you do not have
to edit `PROVIDER_CATALOG`** to see them. Listing one in `PROVIDER_CATALOG` yourself also works and
takes precedence, which is the supported way to point a provider at a gateway that forwards to the
real upstream path. Do not do that casually: Codex needs the `/backend-api/codex` path prefix, and a
bare host makes every request fail with a 404.

### Connecting an account

In the Portal, open **Providers → Connected accounts → Connect account**.

- **Browser + PKCE** (Claude, Codex): click *Get sign-in link*, sign in on the provider's own site,
  then paste the URL your browser was redirected to. The browser shows a connection error because
  nothing is listening on the loopback address — that is expected, and the URL in the address bar is
  what you need.
- **Device code** (xAI): click *Get sign-in code*, type the short code on the provider's page, then
  press *Check approval*. The Portal keeps checking on the interval the provider asked for.

You never see or paste a password: the login happens on the provider's site. What the router stores
is the resulting credential, on disk, owner-readable only.

### Using the account on a route

Add the account in **Models & Routes → Add model route**. Choosing an OAuth provider replaces the
API-key field with a **Connected account** picker; the route stores a *reference*
(`oauth:<provider>:<account>`), never a token. The wizard fills in `auth_mode`, the route protocol,
and the base URL for you, and **Test connection** runs the real request.

Only the tasks each subscription actually serves are offered: `claude-code` is Chat only, `codex` is
Responses only, and `xai-oauth` is either. Saving a route outside that set would create a route that
can only ever fail.

### Renewal

The router refreshes each credential ahead of its expiry, in a background loop, one refresh at a time
per account. Codex rotates its refresh token on every use, so concurrent refreshes would spend it —
this is why refresh is single-flight rather than "usually fine". Accounts appear in
**Connected accounts** with a status: `Connected`, `Expiring soon`, `Expired — reconnect`, or
`Connected (no auto-renewal)`. A `409` from the admin API means the credential is unrecoverable and
needs a fresh sign-in.

### What this costs you, and what can break

These paths are **not** the vendors' supported API integrations. They exist because a subscription
your account already pays for can be used from a router, and they can stop working without notice.

- Anthropic may require or bill **extra paid usage** for traffic that does not come from the Claude
  CLI. Check your plan before sending real workloads; use an API key for anything billing-critical.
- OpenAI, Anthropic, and xAI may change or withdraw the endpoint, the client identifier, or the scope
  set. A rotation like that invalidates every stored credential at once.
- xAI's `api.x.ai` rejects consumer OAuth accounts with a `403` spending-limit error even when the
  subscription quota is available. The router uses the subscription host
  (`cli-chat-proxy.grok.com`) for this reason.
- A credential shares its allowance with the vendor's own CLI. Using the router and Codex CLI at the
  same time means the quota is shared, not doubled.

The Portal shows each provider's risk note before you start a flow, and the same notes are in
[SECURITY.md](SECURITY.md).


## Default seeded provider endpoints

`./start.sh seed` inserts missing provider endpoint templates into the database so the Portal **Providers** screen is useful on first run. These endpoints are templates and are inserted disabled; creating an enabled model route still happens in **Models & Routes → Add model route** after **Test connection** passes.

Seeded adapter endpoint templates include:

| Endpoint template | Base URL | Typical task type in Add model route | Notes |
|---|---|---|---|
| `qwen` | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` | Embedding | Use `qwen3.7-text-embedding` for the current text embedding smoke. |
| `qwen-rerank` | `https://dashscope-intl.aliyuncs.com` | Rerank | Use `qwen3-rerank`; do not use `/compatible-mode/v1` for rerank. |
| `jina` | `https://api.jina.ai` | Embedding or Rerank | Use Jina embedding/rerank model names from the wizard suggestions. |
| `voyage` | `https://api.voyageai.com` | Embedding or Rerank | Free trial accounts may need slower testing because of rate limits. |
| `cohere` | `https://api.cohere.com/v2` | Rerank | Cohere rerank maps BrighTO `/v1/rerank` to provider `/v2/rerank`. |

## Add a model route

In the Portal:

1. Open **Models & Routes**.
2. Click **Add model route**.
3. Choose **Task type**: Chat / LLM, Embedding, Rerank, System One / Decision, or ASR / transcription.
4. Pick a provider preset or **Custom LLM**.
5. Enter the Base URL.
6. Paste the provider API key when required, leave it blank to use the provider `.env` key when configured, or leave it blank for local/no-auth **Custom LLM** endpoints.
7. Click **Load models** when available, or use the task-specific suggestion/manual model name.
8. Click **Test connection**.
9. Save enabled only after the test passes.

The Portal automatically creates or reuses the provider endpoint for the Base URL. You do not need to create a provider first.

## Create a Model Group

Use **Models & Routes → Create Model Group** when several existing tested routes should serve the same API model name. Good examples are:

- two local OpenAI-compatible chat routes running the same or compatible model;
- one local chat route plus one cloud fallback route;
- several embedding or rerank routes of the same type where one has more capacity than the others.

Rules in 1.1.0:

- Group members must be existing tested routes.
- All selected routes must match the selected model type: chat, embedding, rerank, System One, or ASR.
- Provider Base URL, provider model name, auth mode, and provider key/reference stay on the source route. The group wizard does not ask for provider keys.
- Round robin rotates evenly and does not use weights. Weighted round robin shows per-route weights.
- Route counters are stored through PostgreSQL so multiple router pods keep consistent rotation.
- Repeated endpoint failure opens a circuit temporarily; later traffic can probe recovery and bring the endpoint back into service.

The client request does not change:

```json
{
  "model": "coding-fast",
  "messages": [{"role": "user", "content": "Reply OK"}],
  "stream": true
}
```

`coding-fast` can be a single model route today and a Model Group tomorrow without client code changes.

## Local OpenAI-compatible endpoint

For llama.cpp, vLLM, LiteLLM, or another local OpenAI-compatible server, choose **Custom LLM** and use a Base URL such as:

```text
http://127.0.0.1:8088/v1
```

If the local endpoint does not require auth, leave API key blank. BrighTO saves that route as no-auth routing. This also works for LAN hostnames such as `http://llm-host.local:8088/v1` when you choose **Custom LLM**.

## URL handling

Both host-only and SDK-style Base URLs work:

| Base URL | Incoming route | Forwarded URL |
|---|---|---|
| `https://api.openai.com` | `/v1/chat/completions` | `https://api.openai.com/v1/chat/completions` |
| `https://api.openai.com/v1` | `/v1/completions` | `https://api.openai.com/v1/completions` |
| `https://api.openai.com/v1` | `/v1/responses` | `https://api.openai.com/v1/responses` |
| `https://api.moonshot.ai/v1` | `/v1/chat/completions` | `https://api.moonshot.ai/v1/chat/completions` |
| `https://example.com/compatible-mode/v1` | `/v1/models` | `https://example.com/compatible-mode/v1/models` |

## Client API keys

Provider API keys are different from client API keys.

- Provider API key: used by BrighTO to call OpenAI, Anthropic, DeepSeek, or another upstream.
- Client API key: used by your app/team to call BrighTO.

Create client keys in **API Keys**. Admin can view and copy them again later.

## Credential storage

| Credential kind | Reference | Where the secret lives | Who can read it |
|---|---|---|---|
| `.env` variable | `env:OPENAI_API_KEY` | the process environment | the router process only |
| Pasted provider key | `file:/var/lib/brighto-router/provider_keys/<hash>.key` | one file per route, mode `0600` | the router process, and root |
| OAuth account | `oauth:codex:default` | `$DATA_DIR/oauth/<provider>_<label>.json`, mode `0600` in a `0700` directory | the router process, and root |

The database only ever stores the reference. OAuth access tokens are **never** written to the
database, never returned by an admin endpoint, and never included in a request log line. Disconnecting
an account deletes the file; routes that still reference it are reported rather than silently broken.

## Adapter providers

Embeddings, rerank, System One/Decision, and ASR/transcription are first-class 1.1.0 setup flows. The Portal task-type wizard uses task-specific model suggestions and Test Connection probes instead of assuming every provider supports `/v1/models` or the same request shape. Provider catalog entries are templates only; provider keys are supplied per route from `.env` or pasted in the Add model route wizard. Model Groups reuse those tested routes and do not ask for provider keys.

System One routes use `/v1/systemone` and `/v1/decisions` for Ollaya/Laya, Jev/DJev-style, or TypeSafe System One-compatible endpoints. Local Ollaya/Laya can run with no API key; hosted endpoints normally use Bearer auth.

Qwen rerank needs special handling: embeddings can use the OpenAI-compatible `/compatible-mode/v1` Base URL, while rerank uses DashScope workspace endpoints. In the Portal, choose **Qwen + Rerank**, then enter `https://dashscope-intl.aliyuncs.com` or your workspace root Base URL such as `https://<workspace>.<region>.maas.aliyuncs.com`. For live smoke tests, set `QWEN_RERANK_BASE_URL` to that same root URL.

Useful provider key placeholders are present in `.env.example`:

- `JINA_API_KEY`
- `VOYAGE_API_KEY`
- `COHERE_API_KEY`
- `DASHSCOPE_API_KEY`
- `OLLAYA_API_KEY`

See [ADAPTERS.md](ADAPTERS.md) for current adapter endpoints and smoke commands.
