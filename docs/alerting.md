# Alerting

The CI/CD Abuse Detector supports multiple alerting channels: **issue/work item creation**, **Slack notifications**, and optional **Elastic verdict shipping**. All fire when the verdict severity meets or exceeds the configured `CI_CD_ABUSE_ALERT_THRESHOLD` (default: `high`).

## Slack Notifications

When a suspicious or malicious change is detected, the template sends a Slack notification via incoming webhook. Each alert includes the repository, severity, verdict, actor, and a summary from Copilot analysis. Buttons link directly to the CI run and the corresponding PR/MR.

| Platform | Method |
|----------|--------|
| GitHub Actions | `slackapi/slack-github-action` with `incoming-webhook` type |
| GitLab CI | `curl` to webhook with jq-built Block Kit payload |
| Azure DevOps | `curl` to webhook with jq-built Block Kit payload |

All three use the same Block Kit structure: header, section with severity/verdict/actor fields, summary section, and action buttons linking to the build and PR.

## Issue / Work Item Creation

Alert issues or work items are created automatically with structured metadata, severity labels, and the full verdict from Copilot analysis.

| Platform | Method | Labels/Tags |
|----------|--------|-------------|
| GitHub | `gh issue create` | `cicd-abuse-alert`, severity level |
| GitLab | GitLab REST API (`/api/v4/projects/:id/issues`) | `cicd-abuse-alert`, severity level |
| Azure DevOps | ADO Work Items API (auto-detects `Bug` or `Issue`) | `cicd-abuse-alert;severity` tag, VSTS severity field (Bug only) |

Each issue/work item contains a structured breakdown: severity, verdict, actor, event type, PR/MR reference, summary, reasons, suspicious files, evidence, and recommended actions.

### GitLab issue creation note

`CI_JOB_TOKEN` may lack the `api` scope needed for issue creation. Set a `GITLAB_ISSUE_TOKEN` CI/CD variable with a personal access token that has `api` scope as a workaround.

## Configuration

**Behavior:**

| Variable | Default | Description |
|----------|---------|-------------|
| `CI_CD_ABUSE_ALERT_THRESHOLD` | `high` | Minimum severity to trigger alerts (`low`/`medium`/`high`/`critical`) |
| `CI_CD_ABUSE_FAIL_ON_SEVERITY` | _(empty — disabled)_ | Fail the PR/pipeline at this severity or above |
| `CI_CD_ABUSE_WORK_ITEM_TYPE` | _(auto-detected)_ | ADO only: work item type (`Bug`, `Issue`, etc.). Auto-detects from project process template |

**Secrets:**

| Secret | Description |
|--------|-------------|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |
| `GITLAB_ISSUE_TOKEN` | GitLab only: token with `api` scope for issue creation (falls back to `CI_JOB_TOKEN`) |
| `ES_URL` | Elasticsearch endpoint for verdict shipping (e.g. `https://<deployment>.elastic.cloud`) |
| `ES_API_KEY` | Elasticsearch API key (base64-encoded) for verdict shipping |

## How It Works

1. **Verdict rendered** — Copilot analysis produces a JSON verdict with severity, reasons, and evidence
2. **Threshold checked** — Severity compared against `CI_CD_ABUSE_ALERT_THRESHOLD`
3. **Issue/work item created** — GitHub Issue, GitLab Issue, or ADO work item (auto-detects Bug or Issue based on process template) with structured body and severity labels
4. **Slack sent** — Block Kit payload with metadata fields and buttons linking to the run and PR
5. **Elastic shipped** — Structured verdict document sent to `logs-cicd.abuse-default` data stream (optional, requires `ES_URL` and `ES_API_KEY`). See [Elastic Shipping](elastic-queries.md) for ES|QL queries.
6. **Fail gate** — If `CI_CD_ABUSE_FAIL_ON_SEVERITY` is set and severity meets it, the pipeline fails
