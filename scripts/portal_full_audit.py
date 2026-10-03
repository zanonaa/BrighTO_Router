#!/usr/bin/env python3
"""Full Playwright audit for the BrighTO Admin Portal.

Runs an isolated local stack: temporary PostgreSQL, local brighto-router binary,
Rust mock upstream, and headless Chromium. The audit clicks through every main
Portal section and exercises create/edit/delete flows that have broken before.
"""
from __future__ import annotations

import os
import sys
import textwrap

import portal_browser_smoke as smoke


def full_playwright_spec(base_url: str, admin_key: str, mock_url: str) -> str:
    return textwrap.dedent(
        f"""
        const {{ chromium, expect }} = require('@playwright/test');

        const baseURL = {base_url!r};
        const adminKey = {admin_key!r};
        const mockURL = {mock_url!r};

        function attachPageDiagnostics(page) {{
          page.on('pageerror', err => console.error('PAGEERROR ' + (err.stack || err.message)));
          page.on('console', msg => {{
            if (['error', 'warning'].includes(msg.type())) console.error('BROWSER ' + msg.type() + ' ' + msg.text());
          }});
          page.on('response', resp => {{
            const url = resp.url();
            if (url.includes('/admin/') && resp.status() >= 500) console.error('ADMIN_5XX ' + resp.status() + ' ' + url);
          }});
        }}

        async function adminFetch(path, method = 'GET', body = undefined) {{
          const resp = await fetch(baseURL + path, {{
            method,
            headers: {{ 'content-type': 'application/json', 'x-admin-key': adminKey }},
            body: body === undefined ? undefined : JSON.stringify(body),
          }});
          const text = await resp.text();
          let data = null;
          try {{ data = text ? JSON.parse(text) : null; }} catch {{ data = text; }}
          if (!resp.ok) throw new Error(method + ' ' + path + ' -> ' + resp.status + ' ' + text);
          return data;
        }}

        async function login(page) {{
          await page.goto(baseURL + '/', {{ waitUntil: 'domcontentloaded' }});
          await expect(page.locator('#login-view')).toBeVisible();
          await expect(page.locator('#login-user')).toBeVisible();
          await page.fill('#login-user', 'admin');
          let blockedOnce = false;
          await page.route('**/admin/backends', async route => {{
            if (!blockedOnce && route.request().method() === 'GET') {{
              blockedOnce = true;
              await route.fulfill({{ status: 403, body: 'ip not allowed' }});
            }} else {{
              await route.continue();
            }}
          }});
          await page.fill('#login-pass', adminKey);
          await page.click('#login-submit');
          await expect(page.locator('#login-error')).toContainText('Admin access blocked: ip not allowed');
          await page.unroute('**/admin/backends');
          const pastedAdminKey = ' ' + String.fromCharCode(0x200b) + adminKey.replace('-', String.fromCharCode(0x2011)) + ' ';
          await page.fill('#login-pass', pastedAdminKey);
          await page.click('#login-submit');
          await expect(page.locator('#app-view')).toBeVisible();
          await expect(page.locator('#page-title')).toContainText('Dashboard');
        }}

        async function nav(page, view, title) {{
          await page.locator('.nav[data-view="' + view + '"]').click();
          await expect(page.locator('#page-title')).toContainText(title, {{ timeout: 15000 }});
          await expect(page.locator('#content')).toBeVisible();
          await expect(page.locator('#toast.show')).toHaveCount(0);
        }}

        async function auditNavigation(page) {{
          await nav(page, 'dashboard', 'Dashboard');
          await nav(page, 'providers', 'Providers');
          await nav(page, 'models', 'Models');
          await nav(page, 'teams', 'Teams');
          await nav(page, 'keys', 'API Keys');
          await nav(page, 'usage', 'Usage');
          await nav(page, 'settings', 'Settings');
        }}

        async function openAddModel(page) {{
          await nav(page, 'models', 'Models');
          const addButton = page.getByRole('button', {{ name: /^Add model route$/ }}).last();
          await expect(addButton).toBeVisible({{ timeout: 15000 }});
          await addButton.click();
          const modal = page.locator('#modal-overlay .modal').last();
          await expect(modal).toBeVisible();
          await expect(modal).toContainText('Task type');
          return modal;
        }}

        async function openCreateModelGroup(page) {{
          await nav(page, 'models', 'Models');
          const groupButton = page.getByRole('button', {{ name: /^Create model group$/ }}).last();
          await expect(groupButton).toBeVisible({{ timeout: 15000 }});
          await groupButton.click();
          const modal = page.locator('#modal-overlay .modal').last();
          await expect(modal).toBeVisible();
          await expect(modal).toContainText('Create model group');
          await expect(modal).toContainText('Model Group');
          return modal;
        }}

        async function choosePickerModel(page, modelName) {{
          const picker = page.locator('.picker-overlay .modal').last();
          await expect(picker).toBeVisible();
          await picker.locator('.picker-search input').fill(modelName);
          await picker.getByRole('option').filter({{ hasText: modelName }}).first().click();
          await picker.getByRole('button', {{ name: 'Use this model' }}).click();
          await expect(picker).toHaveCount(0);
        }}

        function expectedProtocolForTask(task) {{
          return {{ chat: 'local_openai_chat', completion: 'openai_completions', responses: 'openai_responses', embedding: 'openai_embeddings', rerank: 'openai_rerank', asr: 'openai_audio_transcriptions', systemone: 'systemone' }}[task] || 'openai_chat';
        }}

        async function createCustomRoute(page, task, providerModel, publicName, baseUrl = mockURL) {{
          const expectedProtocol = expectedProtocolForTask(task);
          let testPayload = null;
          let savePayload = null;
          await page.route('**/admin/test-connection', async route => {{
            if (route.request().method() === 'POST') {{
              const body = route.request().postDataJSON();
              if (body.provider_model_name === providerModel && body.base_url === baseUrl) {{
                testPayload = body;
                expect(body.protocol).toBe(expectedProtocol);
                expect(body.auth_mode).toBe('none');
                expect(body.provider_key).toBeUndefined();
                expect(body.provider_key_ref).toBeUndefined();
              }}
            }}
            await route.continue();
          }});
          await page.route('**/admin/routes', async route => {{
            if (route.request().method() === 'POST') {{
              const body = route.request().postDataJSON();
              if (body.model_name === publicName) {{
                savePayload = body;
                expect(body.protocol).toBe(expectedProtocol);
                expect(body.provider_model_name).toBe(providerModel);
                expect(body.auth_mode).toBe('none');
                expect(body.provider_key).toBeUndefined();
                expect(body.provider_key_ref).toBeUndefined();
              }}
            }}
            await route.continue();
          }});
          const modal = await openAddModel(page);
          const selects = modal.locator('select');
          await selects.nth(0).selectOption(task);
          await selects.nth(1).selectOption('custom-llm');
          const inputs = modal.locator('input');
          await inputs.nth(0).fill(baseUrl);
          await modal.getByRole('button', {{ name: /Load models/i }}).click();
          await choosePickerModel(page, providerModel);
          await inputs.nth(3).fill(publicName);
          await modal.getByRole('button', {{ name: /^Test connection$/ }}).click();
          await expect(modal.locator('.connection-status')).toContainText('Connected', {{ timeout: 15000 }});
          expect(testPayload).toBeTruthy();
          await modal.getByRole('button', {{ name: /^Save enabled$/ }}).click();
          await expect(page.locator('#modal-overlay')).toHaveClass(/hidden/, {{ timeout: 15000 }});
          expect(savePayload).toBeTruthy();
          await page.unroute('**/admin/test-connection');
          await page.unroute('**/admin/routes');
          await expect(page.locator('#content')).toContainText(publicName, {{ timeout: 15000 }});
        }}

        async function createModelGroupRoute(page) {{
          let payload = null;
          await page.route('**/admin/routes', async route => {{
            if (route.request().method() === 'POST') {{
              const body = route.request().postDataJSON();
              if (body.model_name === 'audit-model-group') {{
                payload = body;
                expect(body.protocol).toBe('openai_chat');
                expect(body.routing_policy).toBe('weighted_round_robin');
                expect(body.endpoints).toHaveLength(2);
                expect(body.endpoints[0].weight).toBe(2);
                expect(body.endpoints[1].weight).toBe(1);
                for (const ep of body.endpoints) expect(ep.provider_key).toBeUndefined();
              }}
            }}
            await route.continue();
          }});
          const modal = await openCreateModelGroup(page);
          await expect(modal).toContainText('Add existing tested route');
          await expect(modal).toContainText('No provider key is entered here');
          await expect(modal).not.toContainText('Provider API key');
          const selects = modal.locator('select');
          await selects.nth(0).selectOption('chat');
          await selects.nth(1).selectOption('weighted_round_robin');
          const inputs = modal.locator('input');
          await inputs.nth(0).fill('audit-model-group');
          await selects.nth(2).selectOption('audit-chat');
          await modal.getByRole('button', {{ name: /^Add route to group$/ }}).click();
          await expect(modal.locator('.route-picker-row')).toHaveCount(1);
          await expect(modal.getByRole('button', {{ name: /^Save enabled$/ }})).toBeDisabled();
          await selects.nth(2).selectOption('audit-chat-b');
          await modal.getByRole('button', {{ name: /^Add route to group$/ }}).click();
          await expect(modal.locator('.route-picker-row')).toHaveCount(2);
          await expect(modal.locator('.group-weight-input')).toHaveCount(2);
          await modal.locator('.group-weight-input').nth(0).fill('2');
          await modal.locator('.group-weight-input').nth(1).fill('1');
          await expect(modal.getByRole('button', {{ name: /^Save enabled$/ }})).toBeEnabled();
          await modal.getByRole('button', {{ name: /^Save enabled$/ }}).click();
          await expect(page.locator('#modal-overlay')).toHaveClass(/hidden/, {{ timeout: 15000 }});
          expect(payload).toBeTruthy();
          await page.unroute('**/admin/routes');

          const row = page.locator('.route-list-table tbody tr').filter({{ hasText: 'audit-model-group' }}).first();
          await expect(page.locator('#content')).toContainText('Model Groups');
          await expect(page.locator('#content')).toContainText('Single model routes');
          await expect(row).toContainText('Model Group');
          await expect(row).toContainText('weighted round robin');
          await expect(row).toContainText('weighted RR');
          await expect(row).toContainText('2 endpoints');
          await row.getByRole('button', {{ name: /^Edit$/ }}).click();
          const editModal = page.locator('#modal-overlay .modal').last();
          await expect(editModal).toContainText('Edit model group');
          await expect(editModal.locator('.route-picker-row')).toHaveCount(2);
          await expect(editModal.locator('.group-weight-input')).toHaveCount(2);
          await editModal.getByRole('button', {{ name: /^Cancel$/ }}).click();
          await expect(page.locator('#modal-overlay')).toHaveClass(/hidden/);
        }}

        async function createSystemOneModelGroupRoute(page) {{
          let payload = null;
          await page.route('**/admin/routes', async route => {{
            if (route.request().method() === 'POST') {{
              const body = route.request().postDataJSON();
              if (body.model_name === 'audit-systemone-group') {{
                payload = body;
                expect(body.protocol).toBe('systemone');
                expect(body.routing_policy).toBe('round_robin');
                expect(body.endpoints).toHaveLength(2);
                for (const ep of body.endpoints) {{
                  expect(ep.protocol).toBe('systemone');
                  expect(ep.auth_mode).toBe('none');
                  expect(ep.provider_key).toBeUndefined();
                  expect(ep.provider_key_ref).toBeUndefined();
                  expect(ep.weight).toBe(1);
                }}
              }}
            }}
            await route.continue();
          }});
          const modal = await openCreateModelGroup(page);
          await expect(modal).toContainText('No provider key is entered here');
          await expect(modal).not.toContainText('Provider API key');
          const selects = modal.locator('select');
          await selects.nth(0).selectOption('systemone');
          await selects.nth(1).selectOption('round_robin');
          const inputs = modal.locator('input');
          await inputs.nth(0).fill('audit-systemone-group');
          await selects.nth(2).selectOption('audit-systemone');
          await modal.getByRole('button', {{ name: /^Add route to group$/ }}).click();
          await selects.nth(2).selectOption('audit-systemone-b');
          await modal.getByRole('button', {{ name: /^Add route to group$/ }}).click();
          await expect(modal.locator('.route-picker-row')).toHaveCount(2);
          await expect(modal.locator('.group-weight-input')).toHaveCount(0);
          await modal.getByRole('button', {{ name: /^Save enabled$/ }}).click();
          await expect(page.locator('#modal-overlay')).toHaveClass(/hidden/, {{ timeout: 15000 }});
          expect(payload).toBeTruthy();
          await page.unroute('**/admin/routes');
          const row = page.locator('.route-list-table tbody tr').filter({{ hasText: 'audit-systemone-group' }}).first();
          await expect(row).toContainText('System One / Decision (/v1/systemone) Model Group');
          await expect(row).toContainText('2 endpoints');
        }}


        async function auditProviderTaskChoices(page) {{
          const modal = await openAddModel(page);
          const selects = modal.locator('select');
          await expect(selects.nth(0).locator('option[value="chat"]')).toContainText('/v1/chat/completions');
          await expect(selects.nth(0).locator('option[value="completion"]')).toContainText('/v1/completions');
          await expect(selects.nth(0).locator('option[value="responses"]')).toContainText('/v1/responses');
          await selects.nth(0).selectOption('completion');
          await expect(modal).toContainText('Completions calls /v1/completions');
          await selects.nth(0).selectOption('responses');
          await expect(modal).toContainText('Responses API calls /v1/responses');
          await selects.nth(0).selectOption('rerank');
          const providerSelect = selects.nth(1);
          for (const key of ['jina', 'voyage', 'cohere', 'qwen']) {{
            await expect(providerSelect.locator('option[value="' + key + '"]')).toHaveCount(1);
          }}
          await providerSelect.selectOption('qwen');
          await expect(modal.locator('input').nth(0)).toHaveAttribute('placeholder', /workspace/);
          await expect(modal.locator('input').nth(2)).toHaveValue('qwen3-rerank');
          await providerSelect.selectOption('cohere');
          await expect(modal.locator('input').nth(2)).toHaveValue('rerank-v3.5');
          await expect(modal.locator('input').nth(3)).toHaveValue('rerank-v3.5');
          await modal.getByRole('button', {{ name: /Load models/i }}).click();
          const picker = page.locator('.picker-overlay .modal').last();
          await expect(picker).toContainText('rerank-v3.5');
          await expect(picker).not.toContainText('qwen3-rerank');
          await picker.getByRole('button', {{ name: 'Cancel' }}).click();
          await selects.nth(0).selectOption('systemone');
          await expect(providerSelect.locator('option[value="ollaya"]')).toHaveCount(1);
          await providerSelect.selectOption('ollaya');
          await expect(modal.locator('input').nth(0)).toHaveValue(/11435\/v1/);
          await expect(modal.locator('input').nth(2)).toHaveValue('laya');
          await expect(modal).toContainText('System One calls /v1/systemone');
          await modal.getByRole('button', {{ name: 'Cancel' }}).click();
          await expect(page.locator('#modal-overlay')).toHaveClass(/hidden/);
        }}

        async function auditTeamAndKeyUi(page) {{
          await nav(page, 'teams', 'Teams');
          await page.getByRole('button', {{ name: /^New team$/ }}).click();
          let modal = page.locator('#modal-overlay .modal').last();
          await expect(modal).toContainText('Create team');
          await modal.locator('input').first().fill('Audit Team');
          await modal.getByRole('button', {{ name: /^Create$/ }}).click();
          await expect(page.locator('#modal-overlay')).toHaveClass(/hidden/, {{ timeout: 15000 }});
          await expect(page.locator('#content')).toContainText('Audit Team');
          const teamRows = await page.locator('.team-list-table tbody tr').count();
          if (teamRows !== 2) throw new Error('expected seeded team + Audit Team, got team rows=' + teamRows);

          const row = page.locator('.team-list-table tbody tr').filter({{ hasText: 'Audit Team' }}).first();
          await row.getByRole('button', {{ name: /^Edit$/ }}).click();
          modal = page.locator('#modal-overlay .modal').last();
          await modal.locator('input').first().fill('Audit Team Renamed');
          await modal.getByRole('button', {{ name: /^Save$/ }}).click();
          await expect(page.locator('#modal-overlay')).toHaveClass(/hidden/, {{ timeout: 15000 }});
          await expect(page.locator('#content')).toContainText('Audit Team Renamed');

          await nav(page, 'keys', 'API Keys');
          await page.getByRole('button', {{ name: /^New key$/ }}).click();
          modal = page.locator('#modal-overlay .modal').last();
          await expect(modal).toContainText('Create API key');
          const teamSelect = modal.locator('select').first();
          const auditTeamValue = await teamSelect.locator('option').filter({{ hasText: 'Audit Team Renamed' }}).first().getAttribute('value');
          if (!auditTeamValue) throw new Error('Audit Team Renamed option not found');
          await teamSelect.selectOption(auditTeamValue);
          await modal.locator('input').first().fill('audit@example.com');
          await modal.getByRole('button', {{ name: /^Create$/ }}).click();
          modal = page.locator('#modal-overlay .modal').last();
          await expect(modal).toContainText('Key created', {{ timeout: 15000 }});
          await expect(modal.locator('.key-reveal')).toContainText(/sk-/);
          await modal.getByRole('button', {{ name: /^Done$/ }}).click();
          await expect(page.locator('#modal-overlay')).toHaveClass(/hidden/);
          await expect(page.locator('#content')).toContainText('audit@example.com');
        }}

        async function auditProviderEndpointUi(page) {{
          await nav(page, 'providers', 'Providers');
          await page.getByRole('button', {{ name: /Advanced endpoint/i }}).click();
          const modal = page.locator('#modal-overlay .modal').last();
          await expect(modal).toBeVisible();
          await expect(modal).toContainText(/endpoint|Provider/i);
          await modal.getByRole('button', {{ name: /^Cancel$/ }}).click();
          await expect(page.locator('#modal-overlay')).toHaveClass(/hidden/);
        }}

        async function auditRoutes(page) {{
          await createCustomRoute(page, 'chat', 'mock-model', 'audit-chat');
          await createCustomRoute(page, 'chat', 'mock-model', 'audit-chat-b', mockURL + '/');
          await createCustomRoute(page, 'completion', 'mock-completion', 'audit-completions', mockURL + '/v1');
          await createCustomRoute(page, 'responses', 'mock-responses', 'audit-responses', mockURL + '/v1');
          await createCustomRoute(page, 'embedding', 'mock-embedding', 'audit-embedding');
          await createCustomRoute(page, 'rerank', 'mock-rerank', 'audit-rerank');
          await createCustomRoute(page, 'asr', 'mock-asr', 'audit-asr');
          await createCustomRoute(page, 'systemone', 'mock-systemone', 'audit-systemone');
          await createCustomRoute(page, 'systemone', 'mock-systemone', 'audit-systemone-b', mockURL + '/');
          await createModelGroupRoute(page);
          await createSystemOneModelGroupRoute(page);

          await page.reload({{ waitUntil: 'domcontentloaded' }});
          await expect(page.locator('#app-view')).toBeVisible();
          await nav(page, 'models', 'Models');
          for (const name of ['audit-chat', 'audit-chat-b', 'audit-completions', 'audit-responses', 'audit-embedding', 'audit-rerank', 'audit-asr', 'audit-systemone', 'audit-systemone-b', 'audit-model-group', 'audit-systemone-group']) {{
            await expect(page.locator('#content')).toContainText(name);
          }}

          const routeRow = page.locator('.route-list-table tbody tr').filter({{ hasText: 'audit-chat' }}).first();
          await routeRow.getByRole('button', {{ name: /^Edit$/ }}).click();
          let modal = page.locator('#modal-overlay .modal').last();
          await expect(modal).toContainText('Edit model');
          await modal.locator('input').nth(3).fill('audit-chat-renamed');
          await modal.getByRole('button', {{ name: /^Test connection$/ }}).click();
          await expect(modal.locator('.connection-status')).toContainText('Connected', {{ timeout: 15000 }});
          await modal.getByRole('button', {{ name: /^Save enabled$/ }}).click();
          await expect(page.locator('#modal-overlay')).toHaveClass(/hidden/, {{ timeout: 15000 }});
          await expect(page.locator('#content')).toContainText('audit-chat-renamed');
        }}

        async function auditOAuthUi(page) {{
          /* The OAuth connect flow reaches Anthropic/OpenAI/xAI's own login pages, which this
             audit must not touch. Everything below is checkable without a login: the provider
             table, the risk disclosure, and the fact that an account-less OAuth preset swaps the
             API-key field for a connect affordance instead of silently saving a broken route. */
          const providers = await adminFetch('/admin/oauth/providers');
          const keys = providers.providers.map(p => p.key).sort();
          const expected = ['claude-code', 'codex', 'xai-oauth'];
          if (JSON.stringify(keys) !== JSON.stringify(expected)) {{
            throw new Error('unexpected OAuth provider set: ' + JSON.stringify(keys));
          }}
          for (const p of providers.providers) {{
            if (!p.risk_note) throw new Error(p.key + ' exposes no risk note; third-party OAuth must disclose it');
            if (['pkce', 'device_code'].indexOf(p.flow) < 0) throw new Error(p.key + ' has unknown flow ' + p.flow);
            if (!p.api_base_url) throw new Error(p.key + ' has no api_base_url');
            if (!p.models || !p.models.length) throw new Error(p.key + ' has no model suggestions');
          }}
          const byKey = Object.fromEntries(providers.providers.map(p => [p.key, p]));
          if (byKey['codex'].api_base_url !== 'https://chatgpt.com/backend-api/codex') {{
            throw new Error('codex api_base_url changed: ' + byKey['codex'].api_base_url);
          }}

          /* No account is connected, so the accounts panel must say so and offer Connect. */
          await nav(page, 'providers', 'Providers');
          const panel = page.locator('.oauth-account-table');
          await expect(page.locator('#content')).toContainText('Connected accounts');
          await expect(page.locator('#content')).toContainText('No account connected yet');
          if (await panel.count()) throw new Error('account table rendered with zero connected accounts');

          await page.getByRole('button', {{ name: /^Connect account$/ }}).click();
          let modal = page.locator('#modal-overlay .modal').last();
          await expect(modal).toContainText('Connect an account');
          await expect(modal.locator('.oauth-risk')).toBeVisible();
          /* The device-code provider must not show a PKCE paste box, and vice versa. */
          await modal.locator('select').first().selectOption('xai-oauth');
          await expect(modal.getByRole('button', {{ name: /^Get sign-in code$/ }})).toBeVisible();
          await expect(modal).not.toContainText('Paste the URL your browser was redirected to');
          await modal.locator('select').first().selectOption('claude-code');
          await expect(modal.getByRole('button', {{ name: /^Get sign-in link$/ }})).toBeVisible();
          await modal.getByRole('button', {{ name: /^Cancel$/ }}).click();
          await expect(page.locator('#modal-overlay')).toHaveClass(/hidden/);

          /* Selecting an OAuth preset must replace the API-key field with the account picker. */
          const addModel = await openAddModel(page);
          const taskSelect = addModel.locator('select').nth(0);
          const providerSelect = addModel.locator('select').nth(1);
          /* The provider list is filtered by task, and Codex only serves Responses — so with the
             default task it must be absent, and present once the task is one it supports. */
          await expect(providerSelect.locator('option[value="codex"]')).toHaveCount(0);
          await expect(providerSelect.locator('option[value="claude-code"]')).toHaveCount(1);
          await taskSelect.selectOption('responses');
          await expect(providerSelect.locator('option[value="codex"]')).toHaveCount(1);
          await expect(providerSelect.locator('option[value="claude-code"]')).toHaveCount(0);
          await taskSelect.selectOption('chat');
          await providerSelect.selectOption('claude-code');
          await expect(addModel.locator('.oauth-account-field')).toBeVisible();
          await expect(addModel.locator('.provider-key-field').first()).toBeHidden();
          await expect(addModel).toContainText('No account connected');
          /* With no account there is no credential to test against: refuse rather than send one. */
          await addModel.locator('input').nth(2).fill('claude-sonnet-4-5');
          await addModel.getByRole('button', {{ name: /^Test connection$/ }}).click();
          await expect(page.locator('#toast')).toContainText('Connect an account');
          /* Without a connection the wizard must still offer the way to get one. */
          await expect(addModel.getByRole('button', {{ name: /^Connect account$/ }})).toBeVisible();
          await addModel.getByRole('button', {{ name: /^Cancel$/ }}).click();
          await expect(page.locator('#modal-overlay')).toHaveClass(/hidden/);

          /* The wizard cannot save an account-less OAuth route, so these three refusals are checked
             straight through the API: a browser guard that the Portal could regress away is not a
             guarantee, and the check has to be about the credential, not about the form. */
          const backend = await adminFetch('/admin/backends', 'POST', {{
            name: 'audit-oauth-endpoint',
            base_url: byKey['codex'].api_base_url,
            api_key_ref: 'env:NONE',
            weight: 1,
            max_inflight: 0,
            format: 'openai',
            enabled: true,
          }});
          const baseRoute = {{
            backend_ids: [backend.id],
            provider_model_name: 'gpt-5-codex',
            enabled: false,
            auth_mode: 'chatgpt_oauth',
            protocol: 'codex_responses',
            first_byte_timeout: 180,
          }};
          async function expectRouteRejected(name, body, mustMention) {{
            let rejected = null;
            try {{ await adminFetch('/admin/routes', 'POST', Object.assign({{ model_name: name }}, baseRoute, body)); }}
            catch (e) {{ rejected = String(e.message); }}
            if (rejected === null) throw new Error('accepted a route that cannot work: ' + name);
            if (!mustMention.test(rejected)) {{
              throw new Error(name + ' was refused, but not for the reason under test: ' + rejected);
            }}
          }}
          try {{
            await expectRouteRejected(
              'audit-oauth-non-oauth-ref',
              {{ provider_key_ref: 'env:NOT_A_CREDENTIAL' }},
              /oauth/i);
            await expectRouteRejected(
              'audit-oauth-unconnected-account',
              {{ provider_key_ref: 'oauth:codex:audit-never-connected' }},
              /connect|no connected/i);
            await expectRouteRejected(
              'audit-oauth-missing-ref',
              {{}},
              /oauth|credential/i);
            /* The reference is the only thing an OAuth route may carry: a pasted key would work for
               an hour and then fail every request with no way to tell why. */
            await expectRouteRejected(
              'audit-oauth-pasted-key',
              {{ provider_key: 'sk-should-be-refused' }},
              /connect|account|oauth/i);
          }} finally {{
            await adminFetch('/admin/backends/' + backend.id, 'DELETE');
          }}

          /* The admin responses must never carry token material. */
          const accounts = await adminFetch('/admin/oauth/accounts');
          const raw = JSON.stringify(accounts);
          if (/access_token|refresh_token|code_verifier/.test(raw)) {{
            throw new Error('account listing leaked token material');
          }}
        }}

        async function auditQuotaUi(page) {{
          /* The passive-observation path (response headers -> store -> payload) is proven by
             tests/quota_smoke.rs against a real mock upstream, so this audit covers what only the
             Portal can regress: the payload contract and the rendering rules that stop a credit
             count from being displayed as a percentage. */
          const quota = await adminFetch('/admin/quota');
          for (const field of ['accounts', 'passive_only', 'idle']) {{
            if (!(field in quota)) throw new Error('/admin/quota is missing ' + field);
          }}

          const raw = JSON.stringify(quota);
          /* No precomputed percentage may ever ship. A provider that reports a credit count in a
             "remaining"-shaped field would render as "348%" — this is the payload-level guard.
             A plain substring check is stricter than a field-name regex and adds no escapes. */
          if (raw.indexOf('"remaining') >= 0) {{
            throw new Error('quota payload carries a provider-controlled remaining field');
          }}
          if (raw.indexOf('%') >= 0) throw new Error('quota payload carries a percentage');

          const levels = ['ok', 'low', 'critical', 'unknown'];
          const ids = ['five_hour', 'seven_day', 'seven_day_overage', 'on_demand', 'month',
                       'derived_month', 'seven_day_model'];
          for (const a of quota.accounts) {{
            if (typeof a.stale !== 'boolean') throw new Error(a.label + ': stale is not a boolean');
            if (typeof a.exhausted !== 'boolean') throw new Error(a.label + ': exhausted is not a boolean');
            if (typeof a.active_probe_supported !== 'boolean') {{
              throw new Error(a.label + ': active_probe_supported is not a boolean');
            }}
            for (const w of a.windows || []) {{
              if (ids.indexOf(w.id) < 0) throw new Error('unknown window id ' + w.id);
              if (levels.indexOf(w.level) < 0) throw new Error('unknown level ' + w.level);
              if (typeof w.used !== 'number' || typeof w.total !== 'number') {{
                throw new Error(w.id + ': used/total must be numbers');
              }}
              /* A count has no denominator, so it can never sit in a percentage band. */
              if (w.kind === 'balance' && w.level !== 'unknown') {{
                throw new Error(w.id + ': a balance window must read as unknown, got ' + w.level);
              }}
              if (w.kind === 'window' && w.total === 0 && w.level !== 'unknown') {{
                throw new Error(w.id + ': no reported limit must read as unknown, got ' + w.level);
              }}
              if (w.id === 'derived_month' && !w.derived) {{
                throw new Error('derived_month must be labelled derived');
              }}
              if (w.id !== 'derived_month' && w.derived) {{
                throw new Error(w.id + ': only the router-computed window may be labelled derived');
              }}
              if (w.id === 'derived_month' && w.source !== 'router_derived') {{
                throw new Error('derived_month has source ' + w.source);
              }}
            }}
            /* An account with no windows at all is not an exhausted account. */
            if (!(a.windows || []).length && a.exhausted) {{
              throw new Error(a.label + ': nothing reported, yet flagged exhausted');
            }}
          }}

          /* Probing an account that does not exist must be refused with a reason, not a 500. */
          let refused = null;
          try {{ await adminFetch('/admin/quota/codex/audit-never-connected/probe', 'POST'); }}
          catch (e) {{ refused = String(e.message); }}
          if (refused === null) throw new Error('probed an account that does not exist');
          if (!/connected|credential|no such/i.test(refused)) {{
            throw new Error('probe refusal did not explain itself: ' + refused);
          }}

          /* The panel must say why it is empty rather than render a blank card. */
          await nav(page, 'providers', 'Providers');
          await expect(page.locator('#content')).toContainText('Allowance');
          await expect(page.locator('#content')).toContainText('Display only');
          await expect(page.locator('#content')).toContainText('No quota yet');
          /* Nothing has been observed, so no card may exist. */
          if (await page.locator('.quota-card').count()) {{
            throw new Error('quota card rendered with no observation at all');
          }}
        }}

        async function auditProviderKeyFilePath() {{
          const backends = await adminFetch('/admin/backends');
          const backend = backends.find(b => b.name === 'custom-llm') || backends[0];
          const routeName = 'audit-provider-key-file';
          await adminFetch('/admin/routes', 'POST', {{
            model_name: routeName,
            backend_ids: [backend.id],
            provider_model_name: 'mock-model',
            enabled: false,
            auth_mode: 'bearer',
            protocol: 'openai_chat',
            provider_key: 'sk-playwright-provider-key-file-test',
            first_byte_timeout: 180,
          }});
          const routes = await adminFetch('/admin/routes');
          const route = routes.find(r => r.model_name === routeName);
          if (!route) throw new Error('provider-key file route not saved');
          await adminFetch('/admin/routes/' + encodeURIComponent(routeName), 'DELETE');
        }}


        async function assertResponsiveLayout(page, label) {{
          const metrics = await page.evaluate(() => {{
            const modal = document.querySelector('#modal-overlay .modal');
            const sidebar = document.querySelector('#sidebar');
            const hamburger = document.querySelector('.hamburger');
            return {{
              width: window.innerWidth,
              bodyScrollWidth: document.body.scrollWidth,
              docScrollWidth: document.documentElement.scrollWidth,
              modalWidth: modal ? modal.getBoundingClientRect().width : 0,
              sidebarOpen: sidebar ? sidebar.classList.contains('open') : false,
              sidebarPointerEvents: sidebar ? getComputedStyle(sidebar).pointerEvents : '',
              hamburgerVisible: hamburger ? (getComputedStyle(hamburger).display !== 'none' && hamburger.getBoundingClientRect().width > 0) : false,
            }};
          }});
          const maxScroll = Math.max(metrics.bodyScrollWidth, metrics.docScrollWidth);
          if (maxScroll > metrics.width + 2) throw new Error(label + ' horizontal overflow: ' + maxScroll + ' > ' + metrics.width);
          if (metrics.modalWidth && metrics.modalWidth > metrics.width + 2) throw new Error(label + ' modal overflow: ' + metrics.modalWidth + ' > ' + metrics.width);
          return metrics;
        }}

        async function auditResponsivePortal(browser) {{
          const outDir = '/tmp/brighto-portal-responsive-audit';
          require('fs').mkdirSync(outDir, {{ recursive: true }});
          for (const cfg of [
            {{ name: 'mobile', width: 390, height: 844 }},
            {{ name: 'tablet', width: 768, height: 1024 }},
          ]) {{
            const page = await browser.newPage({{ viewport: {{ width: cfg.width, height: cfg.height }} }});
            attachPageDiagnostics(page);
            await login(page);
            let m = await assertResponsiveLayout(page, cfg.name + '-dashboard');
            if (!m.hamburgerVisible) throw new Error(cfg.name + ' hamburger is not visible');
            await page.screenshot({{ path: outDir + '/' + cfg.name + '-dashboard.png', fullPage: true }});
            await page.locator('.hamburger').click();
            await expect(page.locator('#sidebar')).toHaveClass(/open/);
            await page.locator('.nav[data-view="models"]').click();
            await expect(page.locator('#page-title')).toContainText('Models', {{ timeout: 15000 }});
            await expect(page.locator('#sidebar')).not.toHaveClass(/open/);
            await page.waitForTimeout(250);
            m = await assertResponsiveLayout(page, cfg.name + '-models');
            if (m.sidebarPointerEvents !== 'none') throw new Error(cfg.name + ' closed sidebar can still intercept clicks');
            await page.screenshot({{ path: outDir + '/' + cfg.name + '-models.png', fullPage: true }});
            await expect(page.locator('#content')).toContainText('Model Groups');
            await expect(page.locator('#content')).toContainText('Single model routes');
            await page.getByRole('button', {{ name: /^Create model group$/ }}).last().click();
            const modal = page.locator('#modal-overlay .modal').last();
            await expect(modal).toBeVisible();
            await expect(modal).toContainText('API model group name');
            await assertResponsiveLayout(page, cfg.name + '-model-group-modal');
            await page.screenshot({{ path: outDir + '/' + cfg.name + '-model-group-modal.png', fullPage: true }});
            await modal.getByRole('button', {{ name: /^Cancel$/ }}).click();
            await page.close();
          }}
        }}

        async function run() {{
          const browser = await chromium.launch({{ executablePath: process.env.PLAYWRIGHT_CHROME_EXECUTABLE, headless: true, args: ['--no-sandbox'] }});
          const page = await browser.newPage({{ viewport: {{ width: 1440, height: 1000 }} }});
          attachPageDiagnostics(page);
          page.on('dialog', dialog => dialog.accept());
          try {{
            await login(page);
            await auditNavigation(page);
            await auditProviderEndpointUi(page);
            await auditProviderTaskChoices(page);
            await auditOAuthUi(page);
            await auditQuotaUi(page);
            await auditRoutes(page);
            await auditTeamAndKeyUi(page);
            await auditProviderKeyFilePath();
            await nav(page, 'usage', 'Usage');
            await nav(page, 'settings', 'Settings');
            await auditResponsivePortal(browser);
          }} finally {{
            await browser.close();
          }}
        }}

        run().then(() => {{
          console.log('RESULT PASS full portal audit');
        }}).catch((err) => {{
          console.error(err && err.stack ? err.stack : err);
          process.exit(1);
        }});
        """
    )


def main() -> int:
    if os.environ.get("BRIGHTO_SKIP_RELEASE_BUILD") != "1":
        print("Building release binaries for full portal audit")
        smoke.sh("cargo", "build", "--release", "--locked", env=dict(os.environ))
    smoke.playwright_spec = full_playwright_spec
    return smoke.main()


if __name__ == "__main__":
    raise SystemExit(main())
