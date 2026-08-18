# Shannon AI Pentest — GitHub Action

**AI penetration testing in your CI pipeline.** Point Shannon at a running deployment; it maps the attack surface, analyzes your source, attempts real exploits, and returns findings as SARIF (GitHub code scanning), a PR comment, a job summary, and a full report artifact — and can fail the build on severity.

Powered by [Shannon](https://github.com/KeygraphHQ/shannon) by [Keygraph](https://keygraph.io).

> ⚠️ Authorized testing only. Run this against applications you own or have explicit permission to test.

---

## What it does

On each run the action:

1. **Launches Shannon** (`npx @keygraph/shannon`) against your `target-url`, using your checked‑out source for whitebox analysis and a committed config to scope the scan.
2. **Waits for the scan to finish** and streams progress.
3. **Publishes results** — uploads SARIF to the **Security** tab, writes a **job summary**, optionally posts a **PR comment**, and always uploads the full report as a **build artifact**.
4. **Gates the build** — optionally fails the job when findings meet or exceed a severity you choose.

## Prerequisites

- **A GitHub‑hosted runner** (`ubuntu-latest`) or a self‑hosted runner **with Docker available** — Shannon runs its engine in containers.
- **An AI provider API key** — Anthropic by default; OpenAI, xAI, Bedrock, or a custom OpenAI‑compatible endpoint via the `model` input — stored as an encrypted repository/organization **secret**.
- **A running target URL** to scan (e.g. a staging or per‑commit preview deployment).
- **A committed Shannon config** at `.shannon/ci.yml` (recommended — without it, every run is a full max‑scope scan).

## Quick start

```yaml
name: Shannon Pentest
on:
  workflow_dispatch:
    inputs:
      target_url: { description: URL to scan, required: true }

permissions:
  contents: read
  security-events: write        # required to upload SARIF to the Security tab

jobs:
  pentest:
    runs-on: ubuntu-latest
    timeout-minutes: 120
    steps:
      - uses: actions/checkout@v4
      - uses: KeygraphHQ/shannon-action@v1
        with:
          api-key: ${{ secrets.SHANNON_AI_API_KEY }}
          target-url: ${{ inputs.target_url }}
          fail-on: critical      # fail the build only on Critical findings
          # model: anthropic:claude-sonnet-4-6   # optional — <provider>:<model-id>
```

## Where the findings show up

| Surface | How |
|---|---|
| **Security tab** (code scanning) | SARIF upload — needs `permissions: security-events: write`. Each finding links to the exact `file:line`. |
| **Pull‑request comment** | Set `comment-pr: true` and `permissions: pull-requests: write`. The comment is upserted (updated in place) each run. |
| **Job summary** | Always written — a severity table + top findings on the run page. |
| **Report artifact** | Always uploaded — the full Markdown report, `report.json`, per‑agent logs, and evidence. |
| **Build status** | Set `fail-on` to fail the job on findings at/above a severity. |

## The config file (`.shannon/ci.yml`)

Commit a Shannon config to your repo and the action passes it with `-c`. This scopes the scan so PR runs are fast and cheap — **without it, every run scans all vulnerability classes with exploitation enabled.** Put only non‑secret scoping here (the config does not interpolate environment variables; inject auth secrets at runtime):

```yaml
# .shannon/ci.yml
vuln_classes: [injection, xss, authz]   # subset keeps PR runs fast; widen for nightly
exploit: "false"                        # string, not boolean; "false" = analysis only

rules_of_engagement: |
  Read-only probing. Do not exercise payment, delete, or email-send endpoints.

# Each rule is { type, value, description? }.
# type ∈ url_path | subdomain | domain | method | header | parameter | code_path
rules:
  focus:
    - { type: code_path, value: "src/api/**", description: "The API surface" }
  avoid:
    - { type: code_path, value: "**/vendor/**", description: "Third-party code" }

report:
  min_severity: high                    # low | medium | high | critical
  min_confidence: medium
```

See [`examples/shannon-config.yml`](examples/shannon-config.yml) for a complete, annotated config (authentication, `code_path` globs, report filters).

See the [Shannon configuration reference](https://github.com/KeygraphHQ/shannon) for the full schema (authentication, MFA/TOTP, focus/avoid paths, report filters).

## Inputs

| Input | Required | Default | Description |
|---|:--:|---|---|
| `api-key` | ✅ | — | AI provider API key. Pass from a secret; exported internally as `SHANNON_AI_API_KEY` (provider‑neutral). |
| `model` |  | Shannon default | Model as `<provider>:<model-id>` (e.g. `anthropic:claude-sonnet-4-6`, `openai:gpt-…`, `xai:…`). Exported as `SHANNON_AI_MODEL`. |
| `target-url` | ✅ | — | URL of the running target to scan. |
| `repo-path` |  | `.` | Checked‑out source for whitebox analysis. Run `actions/checkout` first. |
| `config-path` |  | `.shannon/ci.yml` | Path to the committed Shannon config. Missing file → max‑scope scan (with a warning). |
| `fail-on` |  | `none` | Fail the job if any finding is ≥ this severity: `none`, `info`, `low`, `medium`, `high`, `critical`. |
| `pipeline-testing` |  | `false` | Fast smoke test with minimal prompts (no real analysis) — for validating wiring. |
| `upload-sarif` |  | `true` | Upload SARIF to code scanning. Needs `security-events: write`; degrades gracefully if absent. |
| `comment-pr` |  | `false` | Upsert a findings comment on the PR. Needs `pull-requests: write` and a `pull_request` event. |
| `workspace` |  | `ci-<run_id>` | Scan workspace name. |
| `artifact-name` |  | `shannon-report` | Name of the uploaded report artifact. |
| `shannon-version` |  | `latest` | Version / dist‑tag of `@keygraph/shannon` to run. |

## Outputs

| Output | Description |
|---|---|
| `result` | `completed` or `failed`. |
| `findings-count` | Total findings. |
| `blocking-count` | Findings at/above `fail-on`. |
| `highest-severity` | Highest severity found (`none` if clean). |
| `report-path` | Path to the Markdown report. |
| `report-json` | Path to `report.json`. |
| `sarif-path` | Path to the generated SARIF file. |

## Permissions

```yaml
permissions:
  contents: read
  security-events: write   # upload-sarif (Security tab)
  pull-requests: write     # comment-pr
```

> **Fork PRs:** GitHub does not expose secrets to workflows triggered by pull requests from forks, so the scan can't authenticate there. Gate the action on non‑fork events, or run it on `push`/`workflow_dispatch`/a trusted `pull_request_target` flow.

## Examples

**Scan a PR preview and block on Critical, comment inline:** [`examples/pr.yml`](examples/pr.yml)

**Nightly full scan with exploitation:** [`examples/nightly.yml`](examples/nightly.yml)

```yaml
# nightly, broader scope
- uses: KeygraphHQ/shannon-action@v1
  with:
    api-key: ${{ secrets.SHANNON_AI_API_KEY }}
    target-url: https://staging.example.com
    config-path: .shannon/nightly.yml   # all classes, exploit: true
    fail-on: high
    comment-pr: false
```

## Cost & scope

A full scan takes **tens of minutes** and consumes real LLM credits (you bring your own Anthropic key). Recommendations:

- Prefer **scheduled/nightly** or **manual** runs, or scope PR runs tightly via `.shannon/ci.yml` (`vuln_classes` subset, `exploit: false`).
- Keep a generous `timeout-minutes` (the CLI has no built‑in cost cap).
- Use `pipeline-testing: true` to validate wiring cheaply before your first real scan.

## Security & data handling

Shannon sends application source and observed traffic context to an LLM (Anthropic, or your configured provider) to perform analysis. Only run it against systems you are authorized to test, and review your provider's data‑handling terms. Authentication credentials placed in the Shannon config are written to the runner's disk for the duration of the job; use ephemeral runners and rotate as appropriate.

## How it works (under the hood)

The action wraps the `@keygraph/shannon` CLI and handles the CI‑specific details for you: it exports your key as `SHANNON_AI_API_KEY` (the CLI's provider‑neutral credential) plus optional `SHANNON_AI_MODEL`, waits for completion by polling the run log directly (robust in ephemeral CI environments, where `shannon logs -f` can hang), converts `report.json` into SARIF, and separates "scan failed" from "findings found" so gating is accurate.

## License

[Apache‑2.0](LICENSE). This license covers **this wrapper action only**. Use of the Shannon CLI and the Keygraph service is governed by Keygraph's own terms; "Shannon" and "Keygraph" are trademarks of Keygraph and are not licensed here.
