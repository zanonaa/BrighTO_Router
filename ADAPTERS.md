# BrighTO-Router 1.1.0 adapters: embeddings, rerank, System One, ASR, and Model Groups

This is the BrighTO-Router 1.1.0 adapter and routing scope: embeddings stay on the OpenAI-compatible route, rerank, System One, and ASR/transcription are task-specific adapters, and Model Groups add same-type route load balancing without changing the client API call.

Implemented and tested in 1.1.0:

| Task | Public BrighTO endpoint | Route protocol | Request shape | Status |
|---|---|---|---|---|
| Embeddings | `/v1/embeddings` | `openai_embeddings` | OpenAI-compatible JSON | Mock/integration tested; live OpenAI, Qwen, Jina, and Voyage smoke passed |
| Rerank | `/v1/rerank` | `openai_rerank`, `qwen_rerank`, `cohere_rerank`, `voyage_rerank`, `jina_rerank` | JSON with `model`, `query`, `documents`, optional `top_n` | Mock/integration tested; live Qwen, Jina, Voyage, and Cohere smoke passed |
| ASR / speech-to-text | `/v1/audio/transcriptions` | `openai_audio_transcriptions` | OpenAI-compatible multipart form upload | Mock/integration tested; live OpenAI smoke passed with repo WAV fixtures |
| System One / decisions | `/v1/systemone`, `/v1/decisions` | `systemone` | TypeSafe/Jev-compatible JSON with `model`, `state`, and typed `questions` | Mock/integration tested; live Ollaya/Laya smoke passed with no-auth and Bearer-key mode |
| Model Groups | Same endpoint as selected route type | `model_group_<type>` | Normal request shape for chat, embeddings, rerank, System One, or ASR using the public group model name | Mock/integration tested; Portal browser smoke creates source routes, saves a group from existing routes, and lists it |

The router still does not run models. It forwards to a configured provider or local service, applies client-key auth, route policy, budget/concurrency limits, and usage logging. It does not store vectors, rerank documents, audio files, transcripts, prompts, or provider response bodies.

## Live provider smoke tests

Use `scripts/adapter_smoke.py` to prove a provider API key, endpoint, and model with tiny direct requests. It reads keys from environment or `.env`, never prints provider keys, and skips missing providers.

```bash
python3 scripts/adapter_smoke.py --provider qwen --task embedding
python3 scripts/adapter_smoke.py --provider qwen --task rerank
python3 scripts/adapter_smoke.py --provider jina --task embedding
python3 scripts/adapter_smoke.py --provider jina --task rerank
python3 scripts/adapter_smoke.py --provider all --task all
python3 scripts/adapter_smoke.py --provider openai --task asr --file tests/fixtures/asr_smoke.wav
```

Provider key env vars:

| Provider | Env key | Tasks |
|---|---|---|
| OpenAI | `OPENAI_API_KEY` | embedding, ASR |
| Qwen/DashScope | `QWEN_API_KEY` or `DASHSCOPE_API_KEY` | embedding, rerank |
| Jina AI | `JINA_API_KEY` | embedding, rerank |
| Voyage AI | `VOYAGE_API_KEY` | embedding, rerank |
| Cohere | `COHERE_API_KEY` | rerank |

Keep stress tests on mock providers. Live provider smoke should stay small and cheap.

## OAuth provider adapters

The three OAuth providers are adapters in the same sense: each maps one client request shape onto a
vendor path the router reaches with a renewable subscription credential. They are described here
because, unlike the adapters above, they are not selected by task alone — the `auth_mode` decides
how the credential travels, and the protocol decides the body shape.

| Provider | `auth_mode` | Route protocol | Credential transport | Extra upstream headers |
|---|---|---|---|---|
| Claude Code | `anthropic_oauth` | `anthropic_messages` | `Authorization: Bearer <access_token>` | `anthropic-version`, merged `anthropic-beta` set, Claude CLI `User-Agent` |
| Codex | `chatgpt_oauth` | `codex_responses` | `Authorization: Bearer <access_token>` | `chatgpt-account-id` |
| xAI Grok | `xai_oauth` | `openai_responses` | `Authorization: Bearer <access_token>` | none |

`codex_responses` exists to *mark* the route, not to change the path. `build_target_url` strips the
incoming `/v1` when the base URL carries a path prefix, so base
`https://chatgpt.com/backend-api/codex` plus incoming `/v1/responses` becomes
`https://chatgpt.com/backend-api/codex/responses`, which is the real Codex endpoint. A bare
`https://chatgpt.com` therefore 404s; the Portal warns when the base URL is edited away from the
default.

The `auth_mode` axis and the protocol axis are independent, and deliberately so:

- `auth_mode` decides how the credential is transported and what else the request must carry. The
  three OAuth modes are the only ones that consult the OAuth provider table for static headers.
- The route protocol (equivalently, the backend template's dialect) decides the request body. Claude
  OAuth is a **bearer** request to an Anthropic-dialect endpoint, which is why `anthropic-version` is
  still required on it.

Legacy `bearer` / `anthropic` / `none` modes take their header shape from the backend template
exactly as before, so upgrading does not change a single byte of an existing upstream request.

Beta headers are **merged** into whatever the caller sent, never substituted, and only on OAuth
routes: a client that opts into a preview beta must keep working against a provider that later
removes it from the CLI's default set.

### Smoke testing an OAuth adapter

There is no script for this, and that is deliberate. A live smoke would need a real subscription
account and would spend real quota. `tests/oauth_smoke.rs` covers what can be covered without one:
the reference grammar, the header contract, protocol defaults, route validation, and the refusals
for a pasted key or a missing account. Verify a new provider by running **Test connection** in the
Portal against a model you have already used successfully in that vendor's CLI, and treat the result
as provider-specific rather than as a regression suite.

### Adding a fourth OAuth provider

Add one row to `oauth::PROVIDERS` in `src/oauth/mod.rs`. The flows, the token store, the refresh
loop, the admin endpoints, the Portal UI, and the credential-reference grammar all read that table.
The only things a new row must supply are its own facts: authorize/device/token URLs, client id,
scopes, body encoding, refresh lead, `auth_mode`, protocol, base URLs, model suggestions, and a risk
note. If a change requires a new `if provider ==` branch anywhere, it belongs in the row instead.

A quota probe is part of the same row (`quota_probe`): path, query, any extra headers, and which
response shape comes back. Leave it `None` and the account is passive-only — the Portal says so
instead of showing a spinner.

## Chat client -> Responses provider translation

The one supported cross-family pair: a **chat-family route** (`/v1/chat/completions`, route protocol
`openai_chat`) whose Model Group holds a **Responses-family endpoint** (endpoint protocol
`openai_responses` or `codex_responses`, including xAI Grok and Codex OAuth). The mismatch itself is
the trigger — there is no config switch and no per-model override. When it holds, the router rewrites
the request into a Responses request before it leaves and rewrites the answer back into OpenAI Chat
shape, so an OpenAI Chat client keeps working unchanged.

How each side is mapped:

- **Request** (`chat_request_to_responses`): the first system message becomes top-level
  `instructions`; every other message becomes an `input` item with `input_text`/`output_text` parts;
  chat tools flatten from the nested `function` form to Responses `{type, name, description,
  parameters}`; `max_tokens` becomes `max_output_tokens`; the endpoint's provider model replaces the
  public model name; `store:false` is always sent; `temperature`, `top_p`, and `stop` pass through.
- **Response**: a JSON Responses answer becomes one `chat.completion` (`id`, `created`, client-facing
  model name, choices, usage). A streamed answer becomes incremental `chat.completion.chunk` frames
  ending in `[DONE]`, with usage carried on the final chunk.
- **Codex endpoints** (`codex_responses`) always send `stream:true` upstream — the ChatGPT backend
  only speaks SSE — so a non-streaming client call has the forced SSE folded back into one completion
  before it is returned. Tool calls are folded too.
- The upstream URL is always built on `/v1/responses`, so both SDK-style base URLs and Codex base
  URLs (`.../backend-api/codex`) work unchanged.

Limits, deliberate and validated:

- **One direction only.** A Responses-family route with a chat endpoint, and every other cross, is
  rejected by admin validation with a "not supported yet" message — the Portal route/group editor is
  the same validation.
- Chat fields with no Responses equivalent are **dropped, not approximated**: `n`, `logprobs`,
  `frequency_penalty`, `presence_penalty`, `logit_bias`, `user`, `seed`, `parallel_tool_calls`,
  `response_format`, and `stream_options`.
- Multimodal chat parts (`image_url`, `input_audio`, ...) are dropped from text extraction; this
  adapter is text-only.
- Translated requests take the buffered path (never a streaming upload), and the fold-back lane caps
  upstream bodies at 1 MiB.
- Upstream error bodies pass through untranslated — an error is already provider-shaped diagnostics,
  not a completion.

The pure mapping lives in `src/translate_chat_responses.rs` (unit-tested in place); routing, retries,
credentials, budget, and the ledger are untouched proxy concerns. `tests/translator_chat_responses.rs`
drives the full path against in-test mock Responses upstreams.

## Quota smoke

`tests/quota_smoke.rs` drives the real proxy against mock upstreams that reproduce each provider's
documented quota contract, exactly as `tests/oauth_smoke.rs` does for credentials.

What it pins down, and why each one is worth a test rather than a code review:

- A response carrying quota headers populates the store through the normal proxy path — no admin
  call, no restart. A response without them leaves the store empty, which is the case that keeps the
  observation cheap: silence must not cost a snapshot.
- The admin payload carries `used`/`total` and never a percentage. A reference implementation stored
  a `remaining` field, a provider put a credit count in it, and the UI rendered "348%". The same
  class of bug is prevented here at the payload boundary, with an explicit `kind` separating a
  window from a balance.
- A credit balance renders as an amount with no percentage band; an unreported limit reads as
  `unknown` and not as empty. Unknown and exhausted are different statements.
- A failed probe keeps the previous reading and explains itself, so a provider's bad minute is not
  indistinguishable from "no allowance".
- Repeated probes are refused by the per-credential gate without a second upstream request, so a
  Portal polling loop cannot become provider load.

The probe URL comes from the provider table (a real vendor host), so the prober accepts a per-provider
base-URL override. That is the seam that makes the HTTP contract testable without a live
subscription, and it is also what a deployment fronting a provider through a relay needs to point
the probe at its gateway.

## System One Ollaya/Laya smoke

To prove System One locally without a paid provider, run:

```bash
./smoke/systemone/run_ollaya_laya.sh
```

The script starts `ghcr.io/ollaya-dev/ollaya:latest`, pulls `laya`, creates two BrighTO routes and one Model Group, calls `/v1/systemone`, calls `/v1/decisions`, waits past the health interval, and calls again.

No-auth local mode is the default. Auth-required mode is one environment variable:

```bash
OLLAYA_API_KEY="test-systemone-key" ./smoke/systemone/run_ollaya_laya.sh
```

## Client smoke tests through BrighTO-Router

These commands call BrighTO-Router as a client app. They require a BrighTO client API key and a public model route that already exists.

Embeddings:

```bash
python3 test_router.py \
  --mode embeddings \
  --router http://127.0.0.1:18080 \
  --api-key sk-brighto-... \
  --model <public-embedding-route> \
  --text "BrighTO embedding smoke test"
```

Provider shortcuts when you use the documented public route names:

```bash
python3 test_router.py --list-presets
python3 test_router.py --provider qwen --mode embeddings --text "hello"
python3 test_router.py --provider qwen --mode rerank --query "router speed"
python3 test_router.py --provider jina --mode embeddings --text "hello"
python3 test_router.py --provider jina --mode rerank --query "router speed"
python3 test_router.py --provider voyage --mode embeddings --text "hello"
python3 test_router.py --provider voyage --mode rerank --query "router speed"
python3 test_router.py --provider cohere --mode rerank --query "router speed"
```

Rerank:

```bash
python3 test_router.py \
  --mode rerank \
  --router http://127.0.0.1:18080 \
  --api-key sk-brighto-... \
  --model <public-rerank-route> \
  --query "router speed" \
  --document "BrighTO-Router is a fast Rust gateway" \
  --document "Bananas are yellow fruit" \
  --top-n 1
```

ASR / transcription:

```bash
python3 test_router.py \
  --mode asr \
  --router http://127.0.0.1:18080 \
  --api-key sk-brighto-... \
  --model <public-asr-route> \
  --file tests/fixtures/asr_smoke.wav
```

Raw curl equivalents:

```bash
curl -sS http://127.0.0.1:18080/v1/embeddings \
  -H "Authorization: Bearer sk-brighto-..." \
  -H "Content-Type: application/json" \
  -d '{"model":"<public-embedding-route>","input":"hello"}'
```

```bash
curl -sS http://127.0.0.1:18080/v1/rerank \
  -H "Authorization: Bearer sk-brighto-..." \
  -H "Content-Type: application/json" \
  -d '{"model":"<public-rerank-route>","query":"router speed","documents":["fast rust router","slow proxy"],"top_n":1}'
```

```bash
curl -sS http://127.0.0.1:18080/v1/audio/transcriptions \
  -H "Authorization: Bearer sk-brighto-..." \
  -F "model=<public-asr-route>" \
  -F "file=@tests/fixtures/asr_smoke.wav"
```

## Portal setup: how adapter routes differ from chat

Embedding and rerank routes are not selected by changing only the provider. In **Models & Routes → Add model route**, choose the **Task type** first:

1. **Embedding** creates a route for `/v1/embeddings`. The provider model must be an embedding model such as Qwen `qwen3.7-text-embedding`, Jina embedding models, Voyage embedding models, or OpenAI embedding models.
2. **Rerank** creates a route for `/v1/rerank`. The provider model must be a reranker such as Qwen `qwen3-rerank`, Jina reranker, Voyage reranker, or Cohere reranker.
3. **ASR / transcription** creates a route for `/v1/audio/transcriptions` and tests with the small bundled WAV fixture.
4. **System One / Decision** creates a route for `/v1/systemone` and `/v1/decisions`. It works with Ollaya/Laya, hosted Jev/System One, and compatible local services.
5. **Chat Completions** creates a route for `/v1/chat/completions`.
6. **Completions** creates a route for `/v1/completions` for legacy text-completion providers.
7. **Responses API** creates a route for `/v1/responses`. Use it when the upstream backend exposes OpenAI Responses semantics.

Provider endpoint templates in **Providers** are only Base URLs. A route becomes usable only after the task-specific **Test connection** passes and the route is saved enabled.

## Portal setup: Model Groups

A Model Group is not a new provider type. It is one unique API model name backed by multiple existing tested routes of the same type. Use it for backend load balancing and failover while keeping client code stable.

In **Models & Routes → Create Model Group**:

1. Choose the model type.
2. Set the public group model name.
3. Choose round robin or weighted round robin.
4. Add existing tested routes from the compatible-route dropdown.
5. Save enabled after at least two compatible routes are selected.

Provider URL, provider model, auth mode, and provider key/reference stay on the source routes. The group wizard does not ask for provider keys. 1.1.0 Model Groups do not mix protocol shapes: Chat Completions group with Chat Completions, Completions with Completions, Responses with Responses, embeddings with embeddings, rerank with rerank, System One with System One, and ASR with ASR.

## Route creation status

The Portal model wizard supports task-specific route creation for Chat, Embedding, Rerank, and ASR. Test Connection uses the selected task's exact endpoint shape before enabling the route:

- Chat: one tiny chat/messages request.
- Embedding: one short `/v1/embeddings` request and vector-dimension validation.
- Rerank: one `/v1/rerank` request with three tiny documents and score validation.
- ASR: one `/v1/audio/transcriptions` multipart request using `tests/fixtures/asr_smoke.wav`.
- System One: one `/v1/systemone` request with a tiny `state` and two typed questions.

Save enabled only after Test Connection passes. Save draft remains available for disabled routes.

## Provider notes

- OpenAI-compatible embeddings use `/v1/embeddings`.
- Cohere rerank uses provider path `/v2/rerank`; the default Cohere Base URL includes `/v2`, so BrighTO's incoming `/v1/rerank` maps to `/v2/rerank`.
- Voyage and Jina rerank use `/v1/rerank`. BrighTO maps public `top_n` to Voyage `top_k` when needed.
- Qwen/DashScope rerank is not OpenAI-compatible. BrighTO accepts public `/v1/rerank`, then maps `qwen3-rerank` to `/compatible-api/v1/reranks`; `qwen3.7-text-rerank`, `qwen3-vl-rerank`, and `gte-rerank-v2` map to `/api/v1/services/rerank/text-rerank/text-rerank`. Configure the Base URL as `https://dashscope-intl.aliyuncs.com` for the international shared endpoint, or as your workspace root such as `https://<workspace>.<region>.maas.aliyuncs.com`.
- Qwen `tongyi-embedding-vision-flash` is a real multimodal embedding model, but it uses DashScope multimodal embedding APIs, not the OpenAI-compatible `/v1/embeddings` text route. It should be a dedicated future adapter rather than a misleading model suggestion in the current text embedding flow.
- System One currently expects the TypeSafe/Jev-compatible `/v1/systemone` JSON contract. `/v1/decisions` is accepted as an alias. Provider keys may be blank for local/no-auth Ollaya/Laya or set per route for auth-required Jev/Ollaya endpoints.
- ASR currently expects OpenAI-compatible `/v1/audio/transcriptions` multipart behavior.
- Additional Qwen/Alibaba ASR or media adapters should wait for exact provider API proof before coding.

## Validation in 1.1.0

- `cargo fmt --check`
- `cargo check --locked`
- `cargo clippy --locked --all-targets -- -D warnings`
- `python3 -m py_compile test_router.py scripts/adapter_smoke.py scripts/api_matrix_smoke.py scripts/adapter_router_smoke.py scripts/anthropic_smoke.py`
- `python3 scripts/api_matrix_smoke.py` for deterministic mock coverage of OpenAI-compatible chat, Anthropic Messages, embeddings, rerank, ASR multipart, and protocol guard behavior.
- `python3 scripts/adapter_router_smoke.py` for live OpenAI chat/embeddings/ASR plus Qwen, Jina, Voyage, and Cohere adapter coverage when keys are present.
- `python3 scripts/anthropic_smoke.py` for live Anthropic Messages coverage when `ANTHROPIC_API_KEY` is present.
- `./scripts/test_postgres.sh`

`./scripts/test_postgres.sh` includes integration tests for embeddings, rerank, ASR multipart, streaming chat, large non-stream uploads, PostgreSQL ledger writing, and fallback behavior.
