# Select models once; check access before use

The shared skill contains procedures and code. Your model choices belong in `~/.config/organized-chaos/inventory.json`; your coordinator routing preferences belong in `~/.config/organized-chaos/routing.md`. Credentials stay in provider stores or the protected gateway file. Updating this package must preserve those files.

## 1. Select a model and execution method

Use the user's stated model preferences; ask only for missing choices that block staffing. Record the actual model ID, provider, shared pool alias, execution method, billing policy, enabled state, and roles. Each preference list selects models for that role and supplies a tie-break order for usage balancing. Offer implementation, review, and coordination roles for every model; keep the saved roles user-selected. Roles express user permission, not a demonstrated capability ranking. An empty reviewer list means review is not configured.

This example selects one native Codex model. Select an ID supported by the actual execution method. For Jev usage routing, also check the usage adapter in `scripts/jev_route.py`. Declaring an ID does not add adapter support or establish access.

```json
{
  "schema_version": 1,
  "models": [{
    "id": "gpt-6-luna",
    "provider": "openai",
    "pool_alias": "codex-default",
    "execution": {"kind": "codex_native"},
    "billing_policy": "subscription_only",
    "enabled": true,
    "roles": ["implementation"]
  }],
  "preferences": {"implementation": ["gpt-6-luna"], "review": []}
}
```

Before saving the inventory, create or repair its private directory:

```sh
umask 077
mkdir -p "$HOME/.config/organized-chaos"
chmod 700 "$HOME/.config/organized-chaos"
```

Save the inventory with owner-only file permissions (`chmod 600 "$HOME/.config/organized-chaos/inventory.json"`). Select a new filename rather than overwriting an existing inventory. The reader accepts bounded JSON with exact schema keys; credentials and extra fields are rejected.

| Execution kind | Configuration | Check and limit |
| --- | --- | --- |
| `codex_native` | `{"kind":"codex_native"}` | Requires fresh host evidence; CLI login is insufficient |
| `codex_cli` | Kind plus absolute `executable` path | Official login status; model capability remains separately unproven |
| `claude_cli` | Kind plus absolute `executable` path | Official auth status only; model capability, subscription coverage, and environment overrides remain unproven |
| `local_http` | Kind plus loopback `url` | Loaded model observation; quota/context/slot custody checked separately |
| `grok_cli` | Kind plus absolute `executable` path; `xai` provider | CLI sign-in, exact model discovery, read-only billing, and an explicit bounded response test |
| `api` | `enabled:false`, `unsupported_pending` billing | Explicit pending declarations only in this version |

Provider IDs are `openai`, `anthropic`, `xai`, or `local`. Billing policies are `subscription_only`, `local_only`, or `unsupported_pending`. An unsupported provider lane cannot be enabled by adding credentials. The command-line access check does not purchase access, log in, install a runtime, load a model, or run inference. The browser response test below is a separate explicit action.

## 2. Run a bounded access check

Run from the package directory. Keep observations and task evidence in the private configuration directory, outside the package and public asset trees:

```sh
umask 077
python3 scripts/onboarding.py check --config "$HOME/.config/organized-chaos/inventory.json" > "$HOME/.config/organized-chaos/observation.json"
```

A successful command means the configuration and observation are structurally valid. It does not mean every model is ready. Inspect `auth_observed`, `runtime_capability`, and the reason for each entry. CLI login does not verify subscription billing or environment overrides; CLI lanes remain pending until supported evidence can resolve those facts. Missing access remains `unknown`. The check emits sanitized fields instead of raw CLI output or credentials.

For native Codex, the coordinator may supply a private `host.json` created from current app observations:

```json
{
  "schema_version": 1,
  "source": "codex_app",
  "observed_at": "<current UTC timestamp>",
  "models": {
    "<selected native model ID>": {
      "provider": "openai",
      "pool_alias": "codex-default",
      "execution_kind": "codex_native",
      "auth_observed": "ready",
      "runtime_capability": "ready"
    }
  }
}
```

This is a schema example, not evidence. Populate only facts observed through the current authenticated host and its exposed model capabilities. Use `unknown` when unproven. Runtime metadata proves an exposed capability, not task suitability or successful inference. Keep the host observation owner-only and run:

```sh
python3 scripts/onboarding.py check --config "$HOME/.config/organized-chaos/inventory.json" --host-observation "$HOME/.config/organized-chaos/host.json" > "$HOME/.config/organized-chaos/observation.json"
```

The receipt is bound to the exact inventory hash and time. Refresh it after configuration changes or expiration. Host JSON is coordinator-owned evidence, not cryptographic attestation. Fresh provider usage remains a separate input to routing; onboarding creates no quota.

### Read the result before staffing

Interpreting system outputs correctly prevents premature assumptions about model availability or capacity. Each observation carries specific implications for routing decisions and requires distinct follow-up actions to ensure safe dispatch. The following table summarizes common scenarios, clarifying what each signal proves and what steps must follow before assigning work.

| Observation | Meaning | Next action |
| :--- | :--- | :--- |
| Inventory selection saved | Records user choice only; does not confirm availability or capacity. | Verify current access and free slots before dispatching any tasks. |
| Bounded response test passed | Proves bounded response access at that specific time, not quota or quality. | Treat as historical evidence; do not infer ongoing quota status from this alone. |
| Quota unknown | Status is indeterminate; never assume zero or unlimited capacity. | Keep model pending for usage-based routing until fresh quota evidence arrives. |
| Observation expired/changed | Previous state is stale due to expiry or configuration updates. | Refresh affected observations immediately before making new staffing decisions. |
| Local model unloaded | Selection retained, but no work assigned without fresh availability checks. | Perform context and free-slot checks; do not load silently or dispatch automatically. |

Jev chooses among admitted plans; the coordinator validates current access and capacity and authorizes dispatch.

## Reuse fresh response checks from the CLI

Use the supported command instead of a one-off preparation script:

```sh
umask 077
python3 scripts/onboarding.py check \
  --config "$HOME/.config/organized-chaos/inventory.json" \
  --host-observation "$HOME/.config/organized-chaos/host.json" \
  --response-observation "$HOME/.config/organized-chaos/luna-smoke.json" > "$HOME/.config/organized-chaos/observation.json"
```

Omit `--host-observation` when no native host evidence is available. Repeat `--response-observation` for each fresh response test. Each file must be private and contain the raw observation or a connection receipt with `state: ready` and its observation. This command runs access checks but no new inference. It verifies the inventory hash and expiry, adopts only ready response rows, preserves other models, rejects conflicting negative access/quota evidence, and retains the oldest contributing timestamp. Current authentication must still be confirmed; local and native runtimes must still be available. Fresh Grok billing and quota stay attached to their original check time in `grok_billing_observed_at`, even when an older response is reused for another model. The whole observation still expires from its oldest contributing timestamp, and quota expires when its billing period ends. Expired evidence requires a new check, not a new timestamp. Python callers must name `now=` and `host_observation=` explicitly.

## Open the local selection editor

To edit selections in an existing private inventory, run:

```sh
python3 scripts/onboarding_http.py --config /absolute/path/to/inventory.json
```

The command checks that the file is an owner-only, valid inventory before it opens a browser or listens for requests. Keep the terminal open while editing. The page can change which existing models are enabled and save those changes. For an enabled, role-selected OpenAI model, **Use Codex CLI** explicitly changes that inventory entry from native Codex to the discovered local Codex CLI executable. This does not prove the executable's publisher or change credentials.

**For Grok CLI, Connect and test** checks `grok -m <selected-model> models` in an empty temporary directory. If signed out, it runs official `grok login --oauth`. It then requests one fixed response with tools denied, web search disabled, no subagents, a one-turn limit, a 45-second deadline, and capped output. The page discloses the response request before the click. Page load and ordinary `onboarding.py check` never run inference.

A passing test requires the exact response and normal completion, selected-model session authentication before and after, and unchanged inventory bytes. Key-based or unknown access blocks the test. Per-model authentication is checked explicitly because it can override the session. See the [official authentication guide](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-pager/docs/user-guide/02-authentication.md).

The resulting `bounded_grok_cli_smoke` observation confirms response access and the observed session billing path. It expires after five minutes or any inventory change. It does not prove task suitability, future access, charge amounts, or remaining quota. Quota stays `unknown`; user-reported usage and Auto Top Up settings remain separate manual evidence. Jev still requires its own fresh usage evidence. Cancellation and shutdown stop the owned process group. Legacy disabled Grok declarations without an executable still load.

The account billing check starts an isolated Grok ACP process and sends only `initialize` and `_x.ai/billing`. It creates no model session or prompt. The `grok_billing` observation preserves recognized subscription tiers, typed usage percentages, current periods, and paid-credit fields returned by the [official billing extension](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-shell/src/extensions/billing.rs). Missing or invalid fields stay absent. Quota is `ready` only when an explicit percentage below 100 belongs to the current period; 100 is `exhausted`. A missing percentage, missing period, or passed reset leaves quota `unknown`. The validator rejects quota evidence that expires between observation and use. Account billing does not establish which credentials a future model request will use, and it does not feed or bypass Jev’s separate usage adapter.

The billing process has a 35-second deadline and a 128 KiB combined-output limit. It uses the existing sanitized environment, rejects client action requests, redacts errors, and stops its owned process group on every exit. Failure preserves the selected model and authentication observation while leaving billing and quota unconfirmed.

**Known limitation, documented 2026-09-28:** The checked Grok CLI billing response did not establish remaining quota. A successful response test does not fill that gap. If the allowance runs out during an otherwise authorized task, the task may stop or fail; report that outcome without treating it as completion. Routing behavior is unchanged: unknown quota remains pending for usage-based routing. For an authorized task interrupted by exhausted allowance, follow [provider quota exhaustion recovery](delivery.md#provider-quota-exhaustion).

**For Codex CLI, Connect and test** reuses the Codex CLI's existing ChatGPT login. If the CLI reports signed out, it runs the official browser login. API-key login is blocked with guidance; this flow does not log out or replace credentials. Before starting, the page states that the test makes one model response using the subscription and may count toward plan usage. The test uses the selected model, a fixed prompt, an empty temporary working directory, ephemeral read-only execution, and disabled shell and unified-exec tools. It does not run inference on page load or reload. Cancellation and server shutdown terminate the owned process group.

**For Codex CLI, Test passed** means the selected enabled model passed that bounded response test with ChatGPT login confirmed both before and after, the subscription-only policy configured, and the exact inventory bytes unchanged. Its observation is session-local and expires after five minutes; any inventory change invalidates it. This does not establish quota availability, task suitability, native Codex availability, or future access. The ordinary `onboarding.py check` remains an auth-only CLI check and keeps CLI runtime pending until a fresh smoke observation is supplied by the loopback editor.

**For local LM Studio models (including Qwen),** select the enabled model already assigned to a role, load exactly one instance of it in LM Studio, and start the configured loopback server. **Connect and test** checks the loaded instance, sends one short response request, verifies the response and instance identity, and checks that the same instance remains loaded. It never explicitly installs, downloads, or loads a model. Models must support `reasoning: off`; authentication-required local servers remain pending in this version.

The local test uses the [native chat API](https://lmstudio.ai/docs/developer/rest/chat), a 64-token output cap, no integrations, no stored conversation, and a 45-second client deadline. Discovery uses the [models API](https://lmstudio.ai/docs/developer/rest/list). Opening the page sends no inference. Cancel and shutdown terminate the owned client process; this does not prove the runtime stopped generating its bounded response.

For local models, **Test passed** records when the bounded response test succeeded for that model. Its routing observation expires after five minutes and is bound to the inventory hash; the timestamp remains historical after expiry. **Available now** is a separate, short-lived metadata-only check of `GET /api/v1/models`. Its API reports the loaded instance and context length, sends no inference request, grants no routing authority, and reserves no runtime capacity. A changed inventory does not carry either result forward as proof for the new configuration. Selections and billing policy are unchanged by either check. Availability refreshes on page load, selection change, save, and successful test; the refresh button requests another check. The displayed snapshot expires after 30 seconds. Live Jev CLI routing independently checks local availability before reading gateway credentials and after receiving advice, and withholds its plan if the inventory, loaded instance, or context no longer matches the capacity snapshot. Neither UI nor CLI check grants dispatch authority or reserves the runtime slot. A model can unload after any check.

Press Ctrl+C to stop. SIGTERM also requests a graceful stop. If a save is still writing, the command stays open and reports that shutdown is waiting until the save has finished. It does not cancel filesystem writes.

## 3. Configure Jev for usage-based routing

Use an existing gateway account and protected gateway configuration. The default file is `~/.config/organized-chaos/jev-gateway.curl`; `--gateway-config` selects another existing file. It must be a regular file owned by the current user with mode `0600`.

The file contains one literal quoted `url` and one `header` with `Authorization: Bearer` followed by the issued gateway token. Enter the token privately; never include it in a task packet, example, public archive, or shell argument. The URL must use the exact `/v1/systemone` path. Prefer HTTPS. The parser permits HTTP only for loopback or the `100.64.0.0/10` address range. That range is an address check, not proof of Tailscale identity. Before saving a bearer token for a non-loopback HTTP endpoint, the operator must verify the exact intended peer in their authenticated Tailscale network and the operating-system route to that peer. Use this only for a personally trusted gateway; recheck after network changes. The adapter does not verify peer identity at runtime, and the route can change after inspection. Redirects and ambient proxy settings are not used. The parser reads data and never executes curl options.

This package does not provide gateway hosting, a gateway account, or provider credentials. Jev chooses among admitted plans using availability and usage. If its access is missing, retain the configuration and follow the pending/fallback procedure in [routing](routing.md). Model-quality qualification is not required for this default mode.

## Runnable offline example

From the package directory, run the behavioral suite:

```sh
(cd scripts && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover)
```

The suite uses synthetic provider and host observations. It checks unavailable authentication, stale/config-mismatched evidence, billing constraints, and routing admission without live inference. Passing it proves the tested local decisions; it does not establish your provider access.

## Updating one package

Use one maintained package source for installation and download. Package only its allowlisted instructions, references, scripts, and tests. Keep personal inventories, host observations, gateway credentials, usage receipts, and backups outside it. Verify package hashes before installation and preserve the previous installed version for recovery. Publish only within the repository's release authority.
