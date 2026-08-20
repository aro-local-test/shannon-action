# Shannon AI Pentest - GitHub Action

Run [Shannon](https://github.com/KeygraphHQ/shannon), Keygraph's autonomous AI pentester, as a CI gate: it maps the attack surface, analyzes your source, attempts real exploits against a running deployment, and fails the build on severity. Results land as native SARIF (GitHub code scanning), a job summary, and a full report artifact (PDF, Markdown, and a full-run zip).

Powered by [Shannon](https://github.com/KeygraphHQ/shannon) by [Keygraph](https://keygraph.io).

> Authorized testing only. Run this against applications you own or have explicit permission to test.

---

## Recommended: gate each release

A full Shannon pentest performs real reconnaissance, analysis, and exploitation. It takes tens of minutes and consumes real LLM credits (you bring your own key). So the sweet spot is **one scan per release** - a version tag or a published release, a small number of high-value events - rather than on every pull request. Wire it to your release event, fail the build on High/Critical, and make it a required check so a release with an exploitable vulnerability cannot ship.

## Quick start (release gate)

```yaml
name: Shannon release pentest
on:
  push:
    tags:
      - 'v*'                 # scan on each release tag
permissions:
  contents: read
  security-events: write     # upload SARIF to the Security tab
jobs:
  pentest:
    runs-on: ubuntu-latest
    timeout-minutes: 180
    steps:
      - uses: actions/checkout@v4
      # Deploy this release to a reachable target here, or point target-url at staging.
      - uses: KeygraphHQ/shannon-action@v1
        with:
          api-key: ${{ secrets.SHANNON_AI_API_KEY }}
          target-url: https://staging.example.com
          config-path: .shannon/ci.yml
          fail-on: high              # fail the release on High or Critical
          scan-timeout-minutes: 150  # a too-long scan fails cleanly, not as a cancellation
```

To block a release, make this a required check: Settings > Branches (or Rulesets) > Require status checks to pass.

## What it does

Each run launches Shannon (`npx @keygraph/shannon`) against your `target-url` using your checked-out source for whitebox analysis, waits for the scan to finish, publishes the results (SARIF to code scanning, a job summary, and the report artifacts), and gates the build on severity.

## Prerequisites

- A GitHub-hosted runner (`ubuntu-latest`) or a self-hosted runner with Docker - Shannon runs its engine in containers.
- An AI provider API key (Anthropic by default; OpenAI, xAI, or Bedrock via `model`) stored as an encrypted secret.
- A running target URL (a staging or release deployment).
- A committed Shannon config at `.shannon/ci.yml` (recommended - without it, every run is a full max-scope scan).

## Gating

The job fails on two independent conditions, so a release with an exploitable vuln - or a scan that could not finish - never passes silently:

1. **The scan did not complete cleanly.** The scan runs with `--follow`; the action fails the job if the scan errored, timed out, or produced only a partial report (never a false pass). `scan-timeout-minutes` caps a runaway scan as a clean failure.
2. **Findings meet your threshold.** Set `fail-on` to `low` / `medium` / `high` / `critical`; the action counts findings at or above it (the `blocking-count` output) and fails if any exist. Default `none` is report-only.

## The config file (`.shannon/ci.yml`)

Commit a config to scope and steer the scan (and to control cost). Without it, every run tests all vulnerability classes with exploitation enabled.

```yaml
# .shannon/ci.yml
exploit: "true"        # string, not boolean; a real pentest for a release gate
report:
  sarif: "true"        # emit report.sarif for code scanning
# Optional: narrow scope to control cost
# vuln_classes: [injection, xss, authz]
# rules_of_engagement: |
#   Read-only probing. Do not exercise payment, delete, or email-send endpoints.
```

See [`examples/shannon-config.yml`](examples/shannon-config.yml) and the [Shannon configuration reference](https://github.com/KeygraphHQ/shannon) for the full schema (authentication, focus/avoid paths, report filters).

## Inputs

| Input | Default | Description |
|---|---|---|
| `api-key` (required) | - | AI provider API key; exported internally as `SHANNON_AI_API_KEY` (provider-neutral). |
| `target-url` (required) | - | URL of the running target to scan. |
| `model` | Shannon default | Model as `<provider>:<model-id>` (e.g. `anthropic:claude-sonnet-4-6`). |
| `config-path` | `.shannon/ci.yml` | Path to the committed Shannon config. Missing file means a max-scope scan. |
| `fail-on` | `none` | Fail if any finding is at or above: `none`, `info`, `low`, `medium`, `high`, `critical`. |
| `scan-timeout-minutes` | (unset) | Fail the job if the scan runs longer than this, so a too-long scan is a clean failure. Keep the job's `timeout-minutes` a little higher. |
| `upload-sarif` | `true` | Upload `report.sarif` to code scanning (needs `security-events: write` and `report.sarif: "true"` in config). |
| `pipeline-testing` | `false` | Fast smoke test with minimal prompts (no real analysis) - for validating wiring cheaply. |
| `shannon-version` | `latest` | Version / dist-tag of `@keygraph/shannon`. |
| `comment-pr` | `false` | Pull-request only. Post an AI-written review comment (see below). |
| `app-id`, `app-private-key` | (unset) | Pull-request only. GitHub App for the review-comment identity. |

The action uses the workflow run id as its workspace. Report artifacts: `shannon-report-pdf`, `shannon-report-md`, `shannon-report-zip`.

## Outputs

| Output | Description |
|---|---|
| `result` | `completed` or `failed`. |
| `findings-count` | Total findings. |
| `blocking-count` | Findings at or above `fail-on`. |
| `highest-severity` | Highest severity found (`none` if clean). |

## Permissions

```yaml
permissions:
  contents: read
  security-events: write   # upload-sarif (Security tab)
  # pull-requests: write   # only if you enable the PR comment (see below)
```

## Cost and scope

A full scan takes tens of minutes and uses real LLM credits. To manage it: run per release (recommended), scope tightly via `.shannon/ci.yml`, keep a generous `timeout-minutes`, and use `pipeline-testing: true` to validate wiring before the first real scan.

## Security and data handling

Shannon sends application source and observed traffic context to an LLM to perform analysis. Only run it against systems you are authorized to test, and review your provider's data-handling terms. Authentication credentials placed in the config are written to the runner's disk for the duration of the job; use ephemeral runners and rotate as appropriate.

## How it works

The action wraps the `@keygraph/shannon` CLI: it exports your key as `SHANNON_AI_API_KEY` (plus optional `SHANNON_AI_MODEL`), runs the scan with `--follow`, fails the job on an incomplete or timed-out scan or a severity breach, uploads Shannon's native `report.sarif` to code scanning, and publishes the report artifacts.

---

## Pull-request scanning (optional, least recommended)

You can run Shannon on pull requests, but a full pentest burns real tokens on every push and most teams do not need it per-PR - prefer the release gate above. If you do want PR feedback, keep the scan tightly scoped and enable the comment:

```yaml
on: pull_request
permissions:
  contents: read
  security-events: write
  pull-requests: write
# ... deploy a PR preview, then:
- uses: KeygraphHQ/shannon-action@v1
  with:
    api-key: ${{ secrets.SHANNON_AI_API_KEY }}
    target-url: ${{ steps.preview.outputs.url }}
    config-path: .shannon/ci.yml   # scope tightly (vuln_classes subset, exploit: false) to limit cost
    fail-on: none
    comment-pr: true               # short AI-written verdict, upserted on the PR
```

- `comment-pr: true` posts a short AI-written review (needs `pull-requests: write`). Set `app-id` + `app-private-key` to post it as your own GitHub App instead of `github-actions[bot]`.
- Fork PRs: GitHub does not expose secrets to fork-triggered PRs, so the scan cannot authenticate there; gate on non-fork events.
- Full PR example: [`examples/pr.yml`](examples/pr.yml).

## License

[Apache-2.0](LICENSE). This license covers this wrapper action only. Use of the Shannon CLI and the Keygraph service is governed by Keygraph's own terms; "Shannon" and "Keygraph" are trademarks of Keygraph and are not licensed here.
