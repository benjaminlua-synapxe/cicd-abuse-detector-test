# Azure DevOps Pipelines Setup

## Quick Start

1. Copy the template and supporting files into your repository:

```
templates/azure-devops/pr-cicd-abuse-detector.yml → .azure-pipelines/pr-cicd-abuse-detector.yml
prompts/analyze-cicd-change.md                    → prompts/analyze-cicd-change.md
schemas/verdict.schema.json                        → schemas/verdict.schema.json
```

2. Add pipeline variables (Pipelines → Edit → Variables, or use a variable group):

**LLM authentication (pick one):**

| Variable | Secret | Notes |
|----------|--------|-------|
| `ANTHROPIC_API_KEY` | Yes | Standard Anthropic API key |

Or, for Foundry (enterprise):

| Variable | Secret | Notes |
|----------|--------|-------|
| `ANTHROPIC_FOUNDRY_BASE_URL` | No | Foundry endpoint URL |
| `ANTHROPIC_FOUNDRY_API_KEY` | Yes | Foundry API key |
| `CLAUDE_CODE_USE_FOUNDRY` | No | Set to `1` |

**Optional integrations:**

| Variable | Secret | Notes |
|----------|--------|-------|
| `SLACK_WEBHOOK_URL` | Yes | Slack incoming webhook for alert notifications |
| `ES_URL` | Yes | Elasticsearch endpoint for verdict shipping |
| `ES_API_KEY` | Yes | Elasticsearch API key (base64-encoded) |

3. Optionally configure variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CI_CD_ABUSE_EXTRA_PATHS` | _(empty)_ | Comma-separated path fragments so non-default layouts still match ([semantics](github.md#extra-path-patterns), [operator guide](threat-model.md#operator-guide-diff-only-and-external-limits)) |
| `CI_CD_ABUSE_ALERT_THRESHOLD` | `high` | Minimum severity to trigger Slack/work item alerts (`low`, `medium`, `high`, `critical`) |
| `CI_CD_ABUSE_FAIL_ON_SEVERITY` | _(empty — disabled)_ | Fail the pipeline if severity meets or exceeds this level (`low`/`medium`/`high`/`critical`). When empty (default), the detector alerts only and never blocks merges. Set to `high` to block high and critical findings. |
| `CI_CD_ABUSE_WORK_ITEM_TYPE` | _(auto-detected)_ | Work item type for alerts. Auto-detects `Bug` (Agile/Scrum/CMMI) or `Issue` (Basic) |

4. The pipeline runs on pull requests and pushes that modify CI/CD-relevant files.

## What's Included

- PR and push triggering with path-based filters (Tier 1 + Tier 2 + Tier 3)
- Per-file diff generation (10k char cap per file)
- Full prescreen label extraction (shared regex set plus Azure DevOps–specific labels)
- Author enrichment (prior commits, backdated commit detection; optional Graph/membership **hint** — the membership call uses the **pipeline** `System.AccessToken`, not the PR author, so it is a weak trust signal, not a direct “is this user a project member” check)
- Claude Code CLI analysis with Read/Write tools only
- Verdict JSON published as pipeline artifact
- Model routing env vars for Foundry
- Extra paths support via `CI_CD_ABUSE_EXTRA_PATHS`
- Alert threshold checking (`CI_CD_ABUSE_ALERT_THRESHOLD`)
- Slack notifications via incoming webhook (Block Kit payload with severity, verdict, summary, and build/PR links)
- Azure DevOps work item creation (Bug type with severity mapping)
- Fail gate logic (`CI_CD_ABUSE_FAIL_ON_SEVERITY`)

## Feature Parity

The Azure DevOps template is at full feature parity with the GitHub and GitLab templates. See [docs/parity.md](parity.md) for the cross-platform comparison matrix.

## Azure DevOps–specific prescreen labels

The template includes Azure DevOps–specific regex labels:

| Label | Pattern | Detects |
|--------|---------|---------|
| `system_access_token` | `System.AccessToken`, `SYSTEM_ACCESSTOKEN` | Access to the build service OAuth token |
| `ado_service_connection` | `serviceConnection`, `azureSubscription` | References to Azure service connections (cloud credential access) |
| `ado_spn_exposure` | `addSpnToEnvironment` | Service principal credential exposure in environment |
| `ado_secure_file` | `DownloadSecureFile` | Download of secure files (certificates, keys) |
| `persist_credentials` | `persistCredentials` | Git credential persistence (token exposure risk) |
| `task_source_patch` | `_tasks/.*\.js`, `.js.bak` | Task source file tampering |
| `ado_aws_task` | `AWSShellScript@` | AWS credential injection via ADO task |
| `ado_sonar_task` | `SonarQubePrepare@` | SonarQube token injection |

## Example Alert

When the detector flags a malicious change, an Azure DevOps work item is created automatically with severity, verdict, and structured evidence:

<!-- Screenshot: Azure DevOps work item (add azure-devops-workitem.png to this directory to display) -->

## Platform-Specific Caveats

### PR trigger and Azure Repos vs. GitHub

The `pr:` trigger in the template only works with **Azure Repos Git**. If your Azure DevOps project connects to a GitHub repository, PR builds are triggered via:
- **Branch policies** (Azure Repos → Settings → Branch policies → Build validation)
- **GitHub service connections** with webhook-based triggers

For GitHub-hosted repos, configure a build validation policy instead of the `pr:` YAML trigger.

### Diff range computation

**PR builds**: Azure DevOps checks out a merge commit (the merge of the source branch into the target). The template computes the real diff base using `git merge-base` against the target branch (`System.PullRequest.TargetBranch`).

**Push builds**: There is no built-in "before SHA" equivalent to GitHub's `github.event.before`. The template diffs against `HEAD~1` (the parent commit). This means:
- Single-commit pushes are fully analyzed
- Multi-commit pushes only analyze the last commit's changes
- For comprehensive push analysis, consider storing the last successful build SHA and diffing against it

### Secret variables must be explicitly mapped

Azure DevOps does **not** automatically expose secret variables as environment variables. All secrets must be explicitly mapped in the step's `env:` block:

```yaml
env:
  ANTHROPIC_API_KEY: $(ANTHROPIC_API_KEY)
```

Non-secret pipeline variables are automatically available as environment variables (with dots replaced by underscores and uppercased).

### Predefined variable mapping

Azure DevOps predefined variables are available in bash scripts with transformed names:

| Azure DevOps Variable | Env Var in Script | Used For |
|-----------------------|-------------------|----------|
| `Build.Reason` | `BUILD_REASON` | Detecting PR vs push (`PullRequest` / `IndividualCI`) |
| `Build.SourceVersion` | `BUILD_SOURCEVERSION` | Current commit SHA |
| `Build.SourceBranchName` | `BUILD_SOURCEBRANCHNAME` | Branch name (without `refs/heads/`) |
| `Build.Repository.Name` | `BUILD_REPOSITORY_NAME` | Repository name |
| `Build.RequestedFor` | `BUILD_REQUESTEDFOR` | User who triggered the build |
| `Build.RequestedForEmail` | `BUILD_REQUESTEDFOREMAIL` | Email of trigger actor |
| `System.PullRequest.TargetBranch` | `SYSTEM_PULLREQUEST_TARGETBRANCH` | PR target branch (`refs/heads/main`) |
| `System.PullRequest.PullRequestId` | `SYSTEM_PULLREQUEST_PULLREQUESTID` | PR ID |
| `System.CollectionUri` | `SYSTEM_COLLECTIONURI` | Organization URL |
| `System.TeamProject` | `SYSTEM_TEAMPROJECT` | Project name |
| `Build.BuildId` | `BUILD_BUILDID` | Build ID for links |

### Artifact publishing

The template uses the `publish` shortcut to publish the `.cicd-abuse-detector/` directory as a pipeline artifact named `cicd-abuse-detector`. This is equivalent to the `PublishPipelineArtifact@1` task. The artifact is published with `condition: always()` so it's available even if the analysis step fails.

### Agent pool

The template uses `vmImage: 'ubuntu-latest'` (Microsoft-hosted agents). Microsoft-hosted Ubuntu agents include Node.js, jq, and git pre-installed. If using self-hosted agents, ensure these tools are available.

### Hosted parallelism

New Azure DevOps organizations may need to request a free parallelism grant at https://aka.ms/azpipelines-parallelism-request before Microsoft-hosted agents can run. Approval typically takes 2-3 business days. Alternatively, use a self-hosted agent.

### Variable groups and Key Vault

For enterprise deployments, consider storing API keys in an **Azure Key Vault** linked via a variable group:

```yaml
variables:
  - group: cicd-abuse-detector-secrets

# In the variable group, link to Key Vault secrets:
# ANTHROPIC-FOUNDRY-API-KEY → mapped as ANTHROPIC_FOUNDRY_API_KEY
# ANTHROPIC-API-KEY → mapped as ANTHROPIC_API_KEY
```

Note: Key Vault secret names use hyphens; map them to underscore-based pipeline variable names in the variable group configuration.

## Adapting the Template

The path filters in `trigger:` and `pr:` cover Tier 1 (workflow/pipeline files), Tier 2 (build, packaging, and dependency files), and Tier 3 (IDE/developer tooling). Add custom paths to the `trigger:` paths, the `pr:` paths, and the `CI_PATTERNS` variable in the script. Keep all three in sync.
