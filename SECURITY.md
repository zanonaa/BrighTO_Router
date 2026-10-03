# Security Policy

BrighTO-Router handles API keys, backend provider credentials, usage metadata, and administrative operations. Please do not disclose security issues publicly before maintainers have had a chance to assess them.

## Reporting a vulnerability

Open a private security advisory on GitHub if available. If private advisories are not enabled for the repository yet, contact the maintainers through the project owner channel and include:

- Affected commit or release.
- Clear reproduction steps.
- Expected and observed behavior.
- Impact assessment.
- Any suggested fix.

Do not include real provider keys, customer prompts, production logs, or private traffic captures in the report.

## Security expectations

- Admin API access requires `x-admin-key` and source IP/CIDR allowlisting.
- Client API keys are hashed for fast auth lookup.
- Backend provider keys are resolved from environment variables or files, not stored as plaintext in route config.
- Usage ledger and logs must not store prompt or message payloads.
- Production deployments should terminate TLS at a hardened edge proxy or load balancer unless binary-level TLS is explicitly configured and tested.

## OAuth provider credentials

BrighTO-Router can sign in to third-party provider accounts (Claude Code, ChatGPT Codex, xAI Grok) on
your behalf and forward requests with the resulting credential. That is a materially different trust
position from holding an API key you were issued, and it is opt-in per account.

### What the router does and does not do with them

- The sign-in happens on the provider's own site. The router never sees, receives, or logs a
  password, and it has no UI for entering one.
- Credentials are written to `$DATA_DIR/oauth/<provider>_<label>.json` with mode `0600` inside a
  `0700` directory. They are **never** stored in PostgreSQL. The database holds only a reference of
  the form `oauth:<provider>:<account>`.
- No admin endpoint returns token material. Listings expose provider, account name, expiry, and a
  renewal state. `Debug` formatting of a credential is redacted so it cannot leak through a log line
  or a panic message.
- The client API key supplied by the caller is never forwarded upstream in place of the provider
  credential, and the provider credential is never returned in a response body.
- Renewal runs in a background loop, single-flight per account. A credential whose refresh token was
  rotated away, revoked, or reused is reported as needing reconnection rather than retried forever.
- Disconnecting an account removes the file and reports every route that still references it, so a
  forgotten dependency is visible instead of becoming a stream of unexplained `401`s.

### Risks the operator is accepting

- **These are unofficial client integrations.** The endpoints, client identifiers, and scope sets
  are reverse-engineered from the vendors' own CLIs and can change or be withdrawn without notice. A
  vendor-side rotation invalidates every stored credential at once.
- **Billing may differ from what you expect.** Anthropic may require or bill extra paid usage for
  traffic that does not originate from the Claude CLI. A subscription allowance is also shared with
  the vendor's CLI, so router traffic and CLI traffic draw on one budget.
- **The router identifies itself with the vendor's CLI User-Agent** on Claude routes, because the
  endpoint rejects requests that do not. This is an intentional compatibility choice, and it means an
  upstream operator cannot distinguish router traffic from Claude CLI traffic by User-Agent alone.
- **A connected account grants the router the ability to spend your money** for as long as the
  credential lives. Treat connecting an account as granting standing spend authority, and prefer a
  dedicated account with spend limits.
- **Credential storage is filesystem security, not encryption at rest.** Back up `DATA_DIR` as you
  would back up an SSH key directory, and do not put it on a shared or unencrypted volume.

### Operator guidance

- Prefer a paid API key for anything billing-critical or availability-sensitive. Use OAuth accounts
  where the failure mode of a sudden `403` is acceptable.
- Connect only from a trusted admin session, and keep the admin CIDR allowlist narrow.
- Watch the renewal status in **Providers → Connected accounts**. `Expired — reconnect` or
  `Connected (no auto-renewal)` means the router cannot renew that credential and will start failing
  requests at expiry.
- If a provider revokes the integration, delete the credential files rather than waiting for the
  refresh loop to notice.

## Content logging policy

BrighTO-Router stores request metadata for analytics and operations, not conversation content. The PostgreSQL `usage_ledger` records request id, key/team/model/backend identifiers, status, token counts, timing, streaming/client-abort flags, and a short error class. If PostgreSQL is temporarily unavailable, the same event shape is buffered in the local JSONL file configured by `LEDGER_FALLBACK_FILE` and replayed later. It does not store prompts, message arrays, uploaded media, tool payloads, provider response bodies, or model answers.

Provider error bodies are forwarded to the caller but are not persisted. If a deployment needs transcript retention, implement it as an explicit opt-in enterprise feature with encryption, redaction, retention limits, and audited access.

## Admin key re-view

To let administrators view client API keys again after creation, the plaintext is stored in
`api_keys.key_secret` (migration 0003). Only the admin `GET /admin/keys/{id}/reveal` endpoint returns
it; list endpoints and user endpoints never expose it.

This is a deliberate open-source/simple-mode tradeoff chosen by the operator. Protect PostgreSQL
and `ADMIN_MASTER_KEY`. For production/enterprise, prefer encrypting `key_secret` at rest
(`key_ciphertext` + `API_KEY_ENCRYPTION_SECRET`) or a managed secret store.

Provider LLM API keys remain environment/file references and are never returned as plaintext.
