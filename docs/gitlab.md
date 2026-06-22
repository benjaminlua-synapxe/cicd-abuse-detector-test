# GitLab CI/CD Setup

## Quick Start

1. Copy the template and supporting files into your repository:

```
templates/gitlab/pr-cicd-abuse-detector.yml → (merge into your .gitlab-ci.yml)
prompts/analyze-cicd-change.md              → prompts/analyze-cicd-change.md
schemas/verdict.schema.json                 → schemas/verdict.schema.json
```

2. Add CI/CD variables (Settings → CI/CD → Variables):

**LLM authentication:**

| Variable | Masked | Notes |
|----------|--------|-------|
| `COPILOT_GITHUB_TOKEN` | Yes | Copilot CLI auth token used by Copilot analysis |

**Optional integrations:**

| Variable | Masked | Notes |
|----------|--------|-------|
| `SLACK_WEBHOOK_URL` | Yes | Slack incoming webhook for alert notifications |
| `GITLAB_ISSUE_TOKEN` | Yes | Token with `api` scope for issue creation (falls back to `CI_JOB_TOKEN` which may lack permissions) |
| `ES_URL` | Yes | Elasticsearch endpoint for verdict shipping |
| `ES_API_KEY` | Yes | Elasticsearch API key (base64-encoded) |

3. Optionally configure variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CI_CD_ABUSE_EXTRA_PATHS` | _(empty)_ | Comma-separated path fragments so non-default layouts still match ([semantics](github.md#extra-path-patterns), [operator guide](threat-model.md#operator-guide-diff-only-and-external-limits)) |
| `CI_CD_ABUSE_ALERT_THRESHOLD` | `high` | Minimum severity to trigger Slack/issue alerts (`low`, `medium`, `high`, `critical`) |
| `CI_CD_ABUSE_FAIL_ON_SEVERITY` | _(empty — disabled)_ | Fail the pipeline if severity meets or exceeds this level (`low`/`medium`/`high`/`critical`). When empty (default), the detector alerts only and never blocks merges. |
| `CI_CD_ABUSE_INCLUDE_PUSHES` | `true` | Set to `false` to skip push event analysis |
| `COPILOT_MODEL` | `auto` | Copilot CLI model ID used for analysis |
| `COPILOT_PROVIDER_BASE_URL` | _(empty)_ | Optional BYOK provider endpoint for Copilot CLI advanced setups |

4. The job runs on merge requests and pushes that modify CI/CD-relevant files.

## What's Included

- Merge request and push event triggering with path-based `rules:` + `changes:`
- Full Tier 1 + Tier 2 + Tier 3 path filtering (workflow, build, packaging, dependency, and IDE/tooling files)
- Per-file diff generation (10k char cap per file)
- Full prescreen label extraction (shared regex set plus GitLab-specific labels)
- Copilot analysis via Copilot CLI
- Verdict JSON artifact output (retained 30 days)
- Configurable model and optional BYOK provider variables for Copilot CLI
- Extra paths support via `CI_CD_ABUSE_EXTRA_PATHS`
- Alert threshold checking (`CI_CD_ABUSE_ALERT_THRESHOLD`)
- Slack notifications via incoming webhook (block kit payload with severity, verdict, summary, and pipeline/MR links)
- GitLab issue creation via API (uses `GITLAB_ISSUE_TOKEN` if set, falls back to `CI_JOB_TOKEN`; severity/verdict labels)
- Fail gate logic (`CI_CD_ABUSE_FAIL_ON_SEVERITY`)

## Feature Parity

The GitLab template is at full feature parity with the GitHub template. See [docs/parity.md](parity.md) for the cross-platform comparison matrix.

## GitLab-specific prescreen labels

The template includes three GitLab CI–specific regex labels:

| Label | Pattern | Detects |
|--------|---------|---------|
| `ci_job_token` | `CI_JOB_TOKEN` | Access to the per-job authentication token |
| `ci_registry_password` | `CI_REGISTRY_PASSWORD`, `CI_DEPLOY_PASSWORD`, `CI_DEPLOY_USER` | Container registry / deploy credential access |
| `gitlab_remote_include` | `include:.*remote:`, `include:.*https?://` | Remote CI config includes (supply chain via external YAML) |

## Example Alert

When the detector flags a malicious change, a GitLab Issue is created automatically with severity, verdict, and structured evidence:

<!-- Screenshot: GitLab issue alert (add gitlab-issue-alert.png to this directory to display) -->

## Platform-Specific Caveats

### `CI_JOB_TOKEN` scope and issue creation

`CI_JOB_TOKEN` may lack the `api` scope needed for issue creation. If alert issues are not being created, set a `GITLAB_ISSUE_TOKEN` CI/CD variable (masked) with a project or personal access token that has `api` scope. The template automatically prefers `GITLAB_ISSUE_TOKEN` over `CI_JOB_TOKEN` when available.

### `rules: changes:` behavior on pushes

GitLab's `changes:` filter within `rules:` evaluates against the changed files in a merge request. For **non-MR push pipelines**, `changes:` always evaluates to **true** — GitLab cannot determine which files changed in a push without MR context.

This means push events will always enter the job, but the **in-script grep** against `CI_PATTERNS` (a regex defined inside the template's `script:` block listing all monitored file path patterns) provides the actual file filtering. This is by design — the `rules: changes:` block is a fast-path optimization for MR events, not the sole filter.

### Artifact retention

The template sets `expire_in: 30 days` on the verdict artifact. Adjust this to match your organization's retention policy. GitLab defaults to 30 days if unset, but explicit is better.

### `allow_failure` consideration

The template includes a built-in fail gate controlled by `CI_CD_ABUSE_FAIL_ON_SEVERITY`. When unset (default), the pipeline always passes — advisory only. Set it to `high` or `critical` to block merges on high-severity detections.

If you want the detector to never block the pipeline regardless of configuration, add `allow_failure: true` to the job definition.

### Image and tool availability

The template uses `node:22-slim` and installs `jq`, `git`, and `curl` via `apt-get` in `before_script`. If your runners already have Node.js, jq, and git, you can use a lighter image or remove the `before_script` block.

## Adapting the Template

The `rules:` block filters to common CI/CD paths across Tier 1 (workflow/pipeline files), Tier 2 (build, packaging, and dependency files), and Tier 3 (IDE/developer tooling configs). Add your custom paths to both:

1. The `rules: changes:` list (for MR-event fast-path filtering)
2. The `CI_PATTERNS` variable in the script (for actual file filtering)

Keep both lists in sync to ensure consistent behavior.

## Validating the Template

### VS Code GitLab Extension

The recommended way to validate this template locally:

1. Install the [GitLab Workflow extension](https://marketplace.visualstudio.com/items?itemName=GitLab.gitlab-workflow) for VS Code
2. Open the template file and make sure its tab is active
3. Open the Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`)
4. Run `GitLab: Validate GitLab CI Config`

The extension will alert you to any syntax or structural issues. You can also select **Show Merged GitLab CI/CD Configuration** to preview how all includes and references resolve.

See [GitLab docs on testing CI/CD configuration](https://docs.gitlab.com/editor_extensions/visual_studio_code/cicd/#test-gitlab-cicd-configuration).

### GitLab CI Lint API

The project-scoped lint endpoint requires a GitLab access token:

```bash
# Replace :id with your GitLab project ID and TOKEN with a personal access token
cat templates/gitlab/pr-cicd-abuse-detector.yml | \
  python3 -c "import sys,json; print(json.dumps({'content': sys.stdin.read()}))" | \
  curl -s --header "Content-Type: application/json" \
    --header "PRIVATE-TOKEN: $TOKEN" \
    --url "https://gitlab.com/api/v4/projects/:id/ci/lint" \
    --data @-
```

### Local Validation

For offline validation without a GitLab instance:

```bash
# Using gitlab-ci-local (npm package)
npx gitlab-ci-local --validate

# Basic YAML parsing (included in make validate)
python3 -c "import yaml; yaml.safe_load(open('templates/gitlab/pr-cicd-abuse-detector.yml'))"
```
