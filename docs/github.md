# GitHub Actions Setup

## Quick Start

1. Copy three files into your repository:

```
templates/github/pr-cicd-abuse-detector.yml → .github/workflows/pr-cicd-abuse-detector.yml
prompts/analyze-cicd-change.md              → prompts/analyze-cicd-change.md
schemas/verdict.schema.json                 → schemas/verdict.schema.json
```

2. Add repository secrets (Settings → Secrets and variables → Actions):

**LLM authentication (pick one):**

| Secret | Notes |
|--------|-------|
| `ANTHROPIC_API_KEY` | Standard Anthropic API key |

Or, for Foundry (enterprise):

| Secret | Notes |
|--------|-------|
| `ANTHROPIC_FOUNDRY_BASE_URL` | Foundry endpoint URL |
| `ANTHROPIC_FOUNDRY_API_KEY` | Foundry API key |

**Optional integrations:**

| Secret | Notes |
|--------|-------|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook for alert notifications |
| `ES_URL` | Elasticsearch endpoint for verdict shipping (e.g. `https://<deployment>.elastic.cloud`) |
| `ES_API_KEY` | Elasticsearch API key (base64-encoded) |

3. Optionally add repository variables (Settings → Secrets and variables → Actions → Variables):

| Variable | Default | Description |
|----------|---------|-------------|
| `CI_CD_ABUSE_ALERT_THRESHOLD` | `high` | Minimum severity to trigger alerts (low/medium/high/critical) |
| `CI_CD_ABUSE_FAIL_ON_SEVERITY` | _(empty — disabled)_ | Fail the PR check at this severity or above |
| `CI_CD_ABUSE_INCLUDE_PUSHES` | `true` | Analyze direct pushes to main/master |
| `CI_CD_ABUSE_EXTRA_PATHS` | _(empty)_ | Comma-separated additional path patterns to monitor |

4. Done. Open a PR that touches a workflow file and watch it run.

## How It Works

The workflow triggers on pull requests and pushes to `main`/`master`. It:

1. **Filters** changed files across three tiers: workflow/pipeline files, build/release/packaging files (`setup.py`, `package.json`, lockfiles, Dockerfiles), and user-configured extra paths
2. **Generates per-file diffs** (each capped at 10k chars to prevent bypass via padding)
3. **Adds prescreen labels** — regex-derived hints plus metadata (secrets-shaped lines, privileged triggers, permission changes, exfiltration-shaped patterns, author trust, commit date anomalies). These enrich the LLM bundle; they are not a gate.
4. **Calls Claude** via Claude Code CLI to analyze the bundle against the threat model
5. **Renders results** to the GitHub Step Summary
6. **Alerts** via GitHub Issue and/or Slack when severity meets the threshold
7. **Optionally fails** the check when severity meets the fail gate

## Workflow Permissions

The workflow requests minimal permissions:

```yaml
permissions:
  contents: read        # Read repository contents and diffs
  pull-requests: read   # Read PR metadata
  issues: write         # Create alert issues
```

## Security Model

### Why `pull_request` and Not `pull_request_target`

The workflow uses `pull_request` trigger, which means:
- **Fork PRs do NOT have access to repository secrets** — the attacker can't steal the Anthropic API key
- The attacker's modifications to CI/CD files are the **diff being analyzed**, not the analyzer

### Secret Scoping

Secrets are scoped to minimize exposure:
- `ANTHROPIC_*` only on the "Analyze with Claude" step `env:` (step-scoped, not exposed to other steps)
- `SLACK_WEBHOOK_URL` only on the Slack notification step
- `GH_TOKEN` only on the author enrichment and issue creation steps

### LLM Sandboxing

Claude Code runs with `--allowedTools "Read,Write"` — no Bash tool, no network tool. It can only read the analysis bundle and write the verdict JSON.

### Output Safety

All LLM-derived outputs (severity, verdict, summary) are passed through `env:` mappings in downstream steps, never interpolated via `${{ }}` in `run:` blocks. This prevents shell injection even if Claude produces adversarial output.

## Customization

### Extra Path Patterns

The workflow only analyzes changes that match its **built-in path tiers** (workflows, pipelines, common build/packaging files) **or** patterns you add here. If an important automation file lives in an unusual directory, **this job will skip** unless you extend the list—set the repository variable `CI_CD_ABUSE_EXTRA_PATHS` accordingly.

**How to use it**

1. **Inventory** paths that affect CI/CD or release behavior: extra workflow directories, `Makefile` / `Taskfile`, `Justfile`, `Jenkinsfile`, `.circleci/`, `.buildkite/`, `azure-pipelines*.yml` in non-default locations, scripts invoked only from YAML, IaC under `tools/` or `infra/`, etc.
2. **Add comma-separated substrings** (no spaces, or they are stripped). Each entry is OR-matched against changed file paths—include enough of the path to be unique, e.g. `my-org/ci-templates/,deploy/`.
3. **Verify** by opening a PR that only touches one of those paths; you should see this workflow run and produce an analysis bundle (not “No CI/CD-relevant files changed”).

Example:

```
.circleci/,.buildkite/,Jenkinsfile,Makefile,my-org/workflows/
```

### Alert Threshold

`CI_CD_ABUSE_ALERT_THRESHOLD` controls when GitHub Issues and Slack alerts fire:
- `low` — alert on everything
- `medium` — alert on medium, high, critical
- `high` (default) — alert on high and critical only
- `critical` — alert on critical only

### Fail Gate

Set `CI_CD_ABUSE_FAIL_ON_SEVERITY` to block PRs:
- Empty (default) — never block, alerts only
- `critical` — block critical findings
- `high` — block high and critical
- `medium` — block medium and above
- `low` — block everything (not recommended)

## Example Alert

When the detector flags a malicious change, a GitHub Issue is created automatically with severity, verdict, actor, and structured evidence.

## Troubleshooting

### "No CI/CD-relevant files changed"
The PR didn't modify any files matching the CI/CD path patterns. If you're monitoring custom paths, add them to `CI_CD_ABUSE_EXTRA_PATHS`.

### "No pre-screen signals detected"
The diffs didn't match any prescreen regex patterns. Claude still analyzes the full diff — labels are advisory enrichment, not a gate. This message is informational only.

### "Verdict JSON is missing or malformed"
Claude didn't produce valid JSON. This can happen due to API errors, rate limits, or prompt injection in the diff content. The workflow gracefully degrades — the Step Summary will note manual review is required.

### Slack notifications not sending
Verify the `SLACK_WEBHOOK_URL` secret is set and the webhook is active. The Slack step only runs when severity meets the alert threshold AND the secret is non-empty.
