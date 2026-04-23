# Cross-Platform Parity

All CI platform templates aim for identical detection capabilities. This document tracks feature parity across supported platforms.

## Feature Matrix

| Feature | GitHub Actions | GitLab CI | Azure DevOps |
|---------|---------------|-----------|--------------|
| Prescreen labels (shared regex + metadata) | Yes | Yes | Yes |
| Cross-platform prescreen parity | Same `check_signal()` patterns in every template — includes GitHub, GitLab, and Azure DevOps shapes | Yes | Yes |
| Author trust metadata (3 labels) | Yes | Yes | Yes |
| Author enrichment (account age, membership, prior commits) | GitHub Users/Members API | GitLab Users/Members API | Git log; ADO Graph/membership **hint** uses the **pipeline** `System.AccessToken` (weak signal — not a direct “PR author is a project member” check) |
| Backdated commit detection | Yes | Yes | Yes |
| Per-file diff processing (10k cap) | Yes | Yes | Yes |
| Claude Code CLI analysis | Yes | Yes | Yes |
| Alert threshold | `CI_CD_ABUSE_ALERT_THRESHOLD` | `CI_CD_ABUSE_ALERT_THRESHOLD` | `CI_CD_ABUSE_ALERT_THRESHOLD` |
| Slack notifications (Block Kit) | `slackapi/slack-github-action` | `curl` to webhook | `curl` to webhook |
| Issue/work item creation | `gh issue create` | GitLab REST API | ADO Work Items API (auto-detects Bug or Issue) |
| Elastic verdict shipping | `curl` to `ES_URL` | `curl` to `ES_URL` | `curl` to `ES_URL` |
| Fail gate | `CI_CD_ABUSE_FAIL_ON_SEVERITY` | `CI_CD_ABUSE_FAIL_ON_SEVERITY` | `CI_CD_ABUSE_FAIL_ON_SEVERITY` |
| Verdict display | GitHub Step Summary | Job log + JSON artifact | Build log + JSON artifact |
| Artifact storage | Step Summary only (no persistent artifact) | `verdict.json` + `author_profile.json` (30 days) | `verdict.json` + `author_profile.json` (pipeline artifact) |
| Push event gating | `CI_CD_ABUSE_INCLUDE_PUSHES` | `CI_CD_ABUSE_INCLUDE_PUSHES` | N/A (uses YAML triggers) |
| Extra path filtering | `CI_CD_ABUSE_EXTRA_PATHS` | `CI_CD_ABUSE_EXTRA_PATHS` | `CI_CD_ABUSE_EXTRA_PATHS` |

## Platform-Specific Adaptations

Each platform has minor implementation differences dictated by the CI system:

- **GitHub**: Multi-step workflow with `env:` mappings for shell injection safety. Uses `actions/checkout` for repo access. Step Summary for rich markdown rendering.
- **GitLab**: Single `script:` block with declarative `rules: changes:` for path filtering. Uses `node:22-slim` image with `apt-get` for dependencies. Verdict stored as a pipeline artifact. Issue creation uses `GITLAB_ISSUE_TOKEN` (falls back to `CI_JOB_TOKEN`).
- **Azure DevOps**: Single `script:` block with `env:` mappings for variable injection. Uses `checkout: self` with `fetchDepth: 0`. Verdict published as pipeline artifact. Uses ADO REST API for work item creation (auto-detects `Bug` for Agile/Scrum/CMMI or `Issue` for Basic process, configurable via `CI_CD_ABUSE_WORK_ITEM_TYPE`) and `##vso` logging commands for build system integration.

## Shared Core

The following are identical across all platforms:

1. **Prescreen labels** — Same `check_signal()` regex set (plus tail checks where applicable) across all platforms; labels are enrichment for the LLM, not standalone detection
2. **Analysis bundle schema** — Same JSON structure passed to Claude
3. **LLM prompt** — Same `prompts/analyze-cicd-change.md` and `schemas/verdict.schema.json`
4. **Verdict schema** — Same JSON output format
5. **Severity ranking** — Same `severity_rank()` function (critical=4, high=3, medium=2, low=1)
6. **Slack payload** — Same Block Kit structure with platform-appropriate links
