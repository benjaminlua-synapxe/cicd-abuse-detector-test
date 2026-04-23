# AI-Assisted Setup & Testing

This guide explains how to use AI coding assistants (Claude Code, Cursor, etc.) with platform CLIs to set up and test the CI/CD Abuse Detector on each supported platform.

The idea is simple: authenticate the CLI tools, give your AI assistant access, and let it handle the copy, configure, push, test, and debug cycle.

## Prerequisites

### 1. Platform CLI Tools

Install the CLI for each platform you want to test:

```bash
# GitHub
brew install gh
gh auth login

# GitLab
brew install glab
glab auth login

# Azure DevOps
brew install azure-cli
az extension add --name azure-devops
az devops login  # paste a Personal Access Token (PAT) with Full access
az devops configure --defaults organization=https://dev.azure.com/YOUR_ORG project=YOUR_PROJECT
```

### 2. SSH Keys

Add your SSH key to each platform so `git push` works:

| Platform | Where to add |
|----------|-------------|
| GitHub | Settings → SSH and GPG keys |
| GitLab | Preferences → SSH Keys |
| Azure DevOps | User Settings → SSH Public Keys |

### 3. Test Repositories

Create a test repository on each platform. These are disposable repos for validating the detector:

```bash
# GitHub
gh repo create YOUR_ORG/cicd-abuse-detector-testing --private --clone

# GitLab
glab repo create cicd-abuse-detector-testing --private
git clone git@gitlab.com:YOUR_USER/cicd-abuse-detector-testing.git

# Azure DevOps (create project + repo via portal, then clone)
git clone git@ssh.dev.azure.com:v3/YOUR_ORG/YOUR_PROJECT/cicd-abuse-detector-testing-azure
```

### 4. API Credentials

You'll need an Anthropic API key (or Foundry credentials) and optionally a Slack webhook URL. Have these ready — your AI assistant will set them as secrets/variables.

## Verify CLI Access

Before handing off to your AI assistant, verify each CLI has access:

```bash
# GitHub — should show your repos
gh repo list YOUR_ORG --limit 5

# GitLab — should show your projects
glab repo list

# Azure DevOps — should show your project
az devops project list -o table
```

If any of these fail, fix authentication first. The AI assistant can't proceed without CLI access.

## What the AI Assistant Does

Once CLI access is verified, tell your AI assistant to set up and test the detector. Here's what it will do for each platform:

### GitHub (`gh`)

1. **Copy files** — Copies `templates/github/pr-cicd-abuse-detector.yml`, `prompts/analyze-cicd-change.md`, and `schemas/verdict.schema.json` into the test repo
2. **Set secrets** — Uses `gh secret set` for `ANTHROPIC_FOUNDRY_BASE_URL`, `ANTHROPIC_FOUNDRY_API_KEY`, `SLACK_WEBHOOK_URL`
3. **Set variables** — Uses `gh variable set` for `CI_CD_ABUSE_ALERT_THRESHOLD`, `CLAUDE_CODE_USE_FOUNDRY`
4. **Push to main** — Initial commit with all files
5. **Create test branch** — Adds a malicious workflow fixture (e.g., secret exfil via curl)
6. **Open PR** — Uses `gh pr create` to trigger the detector
7. **Monitor** — Uses `gh run watch` to track the workflow execution
8. **Validate** — Checks Step Summary, GitHub Issue creation, Slack notification

### GitLab (`glab`)

1. **Copy files** — Copies `templates/gitlab/pr-cicd-abuse-detector.yml` (as `.gitlab-ci.yml`), `prompts/`, and `schemas/` into the test repo
2. **Set CI/CD variables** — Uses `glab variable set` for API keys and webhook
3. **Push to main** — Initial commit
4. **Create test branch + MR** — Uses `glab mr create` to trigger the detector
5. **Monitor** — Uses `glab ci view` to track the pipeline
6. **Validate** — Checks job log, verdict artifact, GitLab Issue creation, Slack notification

### Azure DevOps (`az devops`)

1. **Copy files** — Copies `templates/azure-devops/pr-cicd-abuse-detector.yml` (as `.azure-pipelines/pr-cicd-abuse-detector.yml`), `prompts/`, and `schemas/`
2. **Create pipeline** — Uses `az pipelines create` pointing to the YAML file
3. **Set variables** — Uses `az pipelines variable create` (with `--secret true` for sensitive values)
4. **Add build policy** — Creates a build validation branch policy so PRs trigger the pipeline
5. **Push to main** — Initial commit
6. **Create test branch + PR** — Uses `az repos pr create` to trigger the detector
7. **Monitor** — Uses `az pipelines runs show` to track build status
8. **Validate** — Checks build log, published artifacts, work item creation, Slack notification

> **Note:** New Azure DevOps organizations may need to request a free hosted parallelism grant at https://aka.ms/azpipelines-parallelism-request before pipelines can run on Microsoft-hosted agents.

## Example Prompts for Your AI Assistant

### Full setup from scratch

> Set up the CI/CD Abuse Detector in my test repo at [REPO_PATH]. The Anthropic Foundry base URL is [URL] and the API key is [KEY]. My Slack webhook is [WEBHOOK]. Copy the template files, set all secrets and variables, push to main, then create a test PR with a malicious workflow change and verify the detector runs successfully.

### Test a specific platform

> I've already set up the GitHub version. Now set up GitLab CI in my repo at [PATH]. Use `glab` CLI to set CI/CD variables and create a test MR. The Foundry credentials are the same as GitHub.

### Debug a failing pipeline

> The CI/CD Abuse Detector pipeline failed on [PLATFORM]. Check the logs, identify the issue, fix it, and re-run.

### Validate cross-platform parity

> Run a test with the same malicious diff on all three platforms (GitHub, GitLab, Azure DevOps). Compare prescreen labels, verdict, and alerting to verify equivalent behavior.

## Platform CLI Reference

### GitHub (`gh`)

```bash
# Secrets & variables
gh secret set SECRET_NAME --body "value" --repo OWNER/REPO
gh variable set VAR_NAME --body "value" --repo OWNER/REPO

# PRs & workflow runs
gh pr create --title "..." --body "..."
gh run list --workflow pr-cicd-abuse-detector.yml
gh run watch RUN_ID
gh run view RUN_ID --log

# Issues
gh issue list --label cicd-abuse-alert
```

### GitLab (`glab`)

```bash
# CI/CD variables
glab variable set VAR_NAME "value"
glab variable set VAR_NAME "value" --masked  # for secrets

# MRs & pipelines
glab mr create --title "..." --description "..."
glab ci list
glab ci view PIPELINE_ID

# Issues
glab issue list --label cicd-abuse-alert
```

### Azure DevOps (`az devops`)

```bash
# Pipeline variables
az pipelines variable create --pipeline-id ID --name NAME --value "value"
az pipelines variable create --pipeline-id ID --name NAME --value "value" --secret true

# PRs & builds
az repos pr create --repository REPO --source-branch BRANCH --target-branch main --title "..."
az pipelines runs list --pipeline-ids ID
az pipelines runs show --id RUN_ID

# Build policies (required for PR triggers with Azure Repos)
# Use REST API to create build validation policy (see docs/azure-devops.md)
```

## Troubleshooting

### `gh auth` fails
Run `gh auth login` and follow the prompts. Select HTTPS or SSH based on your setup.

### `glab` can't find the project
Run `glab repo view` from inside the repo directory, or set the remote with `glab config set -g host gitlab.com`.

### `az devops` commands fail with 401
Your PAT may have expired or lack the required scopes. Create a new PAT with **Full access** at `https://dev.azure.com/YOUR_ORG/_usersSettings/tokens`.

### Azure DevOps pipeline fails with "No hosted parallelism"
Request a free grant at https://aka.ms/azpipelines-parallelism-request (approval takes 2-3 business days). Alternatively, set up a self-hosted agent.

### GitLab issue creation returns null
`CI_JOB_TOKEN` may lack `api` scope. Set a `GITLAB_ISSUE_TOKEN` CI/CD variable with a personal access token that has `api` scope.
