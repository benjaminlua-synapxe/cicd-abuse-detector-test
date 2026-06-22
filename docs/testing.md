# Testing

This document covers how to test the CI/CD Abuse Detector locally before deploying it.

## Quick Validation

```bash
make validate   # YAML lint, JSON Schema check, no-Python-in-templates check
make build      # Validates, then produces dist/pr-cicd-abuse-detector.yml
```

## Prescreen label tests (regex)

`make test` runs the same `check_signal` regex set as the templates against every example diff in `examples/` (41 fixtures). Patterns cover **all three platforms** (GitHub, GitLab, Azure DevOps), including platform-specific labels like `ci_job_token`, `system_access_token`, and `ado_service_connection`. (Metadata labels — `first_time_contributor`, `non_org_member`, `backdated_commits` — come from APIs/git and are not exercised here.) It verifies that:

- Each **malicious** example triggers the **expected prescreen labels** listed in `tests/expected-signals.txt`
- Each **benign** example triggers **zero** matching labels (or only expected benign ones)

```bash
make test
```

Example output:
```
=== Prescreen label tests ===
  malicious/secret-exfil-curl.diff:                secrets_context, cloud_auth_action, id_token_write, curl_wget ✅
  malicious/runner-memory-exfil.diff:              pull_request_target, curl_wget, base64, checkout_ref, proc_mem_read, context_injection ✅
  ...
  benign/lint-workflow.diff:                       (none) ✅

Results: 41 passed, 0 failed, 41 total
```

If a label is missing or unexpected, the test prints the diff between expected and actual.

### Adding a new fixture

1. Add the `.diff` file to `examples/benign/` or `examples/malicious/`
2. Add an entry to `tests/expected-signals.txt` (expected prescreen labels per file):
   ```
   malicious/my-new-attack.diff: label_a, label_b
   ```
3. Run `make test` to verify

## LLM Analysis Tests (manual)

These test the full pipeline end-to-end: prescreen regex labels + Copilot analysis + verdict JSON.

### Prerequisites

```bash
# Copilot CLI auth token
export COPILOT_GITHUB_TOKEN="ghp_..."
# Optional BYOK provider endpoint (advanced)
# export COPILOT_PROVIDER_BASE_URL="https://provider.example.com/v1/responses"
export COPILOT_MODEL="auto"
```

### Run against an example diff

```bash
# Pick a diff to test
DIFF_FILE="examples/malicious/secret-exfil-curl.diff"

# Create working directory
mkdir -p .cicd-abuse-detector

# Copy diff as the "relevant diff"
cp "$DIFF_FILE" .cicd-abuse-detector/relevant.diff

# Extract signals (copy the check_signal function from the template)
SIGNALS=""
check_signal() {
  local name="$1" pattern="$2"
  if grep -qE "$pattern" .cicd-abuse-detector/relevant.diff 2>/dev/null; then
    SIGNALS="${SIGNALS:+$SIGNALS, }$name"
  fi
}

# Paste all check_signal lines from templates/github/pr-cicd-abuse-detector.yml here
# (or source them from a helper script — see tests/extract-signals.sh)
source tests/extract-signals.sh

echo "Signals: $SIGNALS"

# Build a minimal analysis bundle
jq -n \
  --arg signals "${SIGNALS:-none}" \
  --arg diff "$(cat .cicd-abuse-detector/relevant.diff)" \
  --arg change_path "pull_request" \
  --arg target_branch "main" \
  '{repo:"test/repo", actor:"test-user", event_name:"pull_request",
    ref_name:"feature-branch", target_branch:$target_branch,
    change_path:$change_path, interesting_files:["test.yml"],
    signals:$signals, author_profile:{
      login:"test-user", type:"User", created_at:"2024-01-01T00:00:00Z",
      public_repos:2, followers:0, company:null,
      prior_commits_to_repo:0, is_org_member:false
    }, diff_excerpt:$diff}' > .cicd-abuse-detector/analysis_bundle.json

# Run Copilot analysis via Copilot CLI
PROMPT_TEXT="$(cat prompts/analyze-cicd-change.md)

Read the analysis bundle below:
$(cat .cicd-abuse-detector/analysis_bundle.json)

Read the verdict schema below:
$(cat schemas/verdict.schema.json)

Return only the verdict JSON object that matches the schema.
Do not include markdown, code fences, or extra text."

COPILOT_GITHUB_TOKEN="$COPILOT_GITHUB_TOKEN" \
  copilot -p "$PROMPT_TEXT" \
    --model "${COPILOT_MODEL:-auto}" \
    --silent \
    --output-format text \
    --no-color \
    --no-custom-instructions \
    > .cicd-abuse-detector/verdict_raw.txt

cat .cicd-abuse-detector/verdict_raw.txt \
  | sed -e '1s/^```json[[:space:]]*//' -e '1s/^```[[:space:]]*//' -e '$s/[[:space:]]*```$//' \
  > .cicd-abuse-detector/verdict.json

# Check the verdict
jq '.' .cicd-abuse-detector/verdict.json
```

### What to verify

| Example | Expected verdict | Expected severity | Key signals |
|---------|-----------------|-------------------|-------------|
| `malicious/secret-exfil-curl.diff` | `malicious` | `critical` | `secrets_context`, `curl_wget`, `cloud_auth_action` |
| `malicious/runner-memory-exfil.diff` | `malicious` | `critical` | `proc_mem_read`, `curl_wget`, `base64`, `pull_request_target` |
| `malicious/pull-request-target-checkout.diff` | `suspicious` or `malicious` | `high` | `pull_request_target`, `secrets_context` |
| `malicious/write-all-permissions.diff` | `suspicious` or `malicious` | `high` | `write_all`, `secrets_context`, `printenv` |
| `malicious/artifact-token-leak.diff` | `suspicious` | `medium` to `high` | `upload_artifact` |
| `malicious/codecov-curl-pipe-bash.diff` | `malicious` | `critical` | `curl_pipe_bash`, `setup_py_command`, `secrets_context` |
| `malicious/oidc-token-minting.diff` | `malicious` | `critical` | `workflow_run`, `actions_id_token_url`, `id_token_write` |
| `malicious/npm-worm-supply-chain.diff` | `malicious` | `critical` | `gh_auth_token`, `secret_scanning_tool`, `secrets_to_output` |
| `malicious/self-hosted-runner-escape.diff` | `malicious` | `critical` | `self_hosted`, `container_escape`, `k8s_secret_access` |
| `malicious/exfil-channels-variety.diff` | `malicious` | `critical` | `nc_ncat`, `dns_exfil`, `cloud_cred_file_access` |
| `malicious/supply-chain-lockfile.diff` | `malicious` | `high` to `critical` | `lockfile_registry_swap`, `mcp_config_write`, `github_app_token` |
| `malicious/gitlab-ci-secrets.diff` | `malicious` | `critical` | `double_base64`, `env_null_dump`, `env_secret_grep` |
| `benign/lint-workflow.diff` | `benign` | `low` | (none) |
| `benign/action-pin-upgrade.diff` | `benign` | `low` | (none) |
| `benign/cache-optimization.diff` | `benign` | `low` | (none) |
| `benign/curl-download-tools.diff` | `benign` | `low` | `curl_wget`, `curl_pipe_bash` (false positives) |

### Trust context variations

Test the same diff with different `author_profile` values to verify trust modifiers work:

```bash
# Trusted maintainer — should lower severity
"author_profile": {
  "login": "senior-dev", "type": "User",
  "created_at": "2019-01-01T00:00:00Z",
  "public_repos": 45, "followers": 120, "company": "@elastic",
  "prior_commits_to_repo": 200, "is_org_member": true
}

# Suspicious newcomer — should raise severity
"author_profile": {
  "login": "new-acct-42x", "type": "User",
  "created_at": "2026-04-01T00:00:00Z",
  "public_repos": 1, "followers": 0, "company": null,
  "prior_commits_to_repo": 0, "is_org_member": false
}

# Bot making expected changes — should lower severity
"author_profile": {
  "login": "dependabot[bot]", "type": "Bot",
  "created_at": "2019-01-01T00:00:00Z",
  "public_repos": 0, "followers": 0, "company": null,
  "prior_commits_to_repo": 50, "is_org_member": false
}
```

## Integration Testing

Use a dedicated testing repository for integration tests. Create a separate repo (or fork) where you can safely open test PRs without affecting production.

### Setup

1. Create or clone a testing repository
2. Copy the three files into the repo (see [Quick Start](../README.md#quick-start))
3. Add the `COPILOT_GITHUB_TOKEN` secret to the repo settings

### Verify outputs

After opening a test PR, check:

1. **GitHub Step Summary** on the workflow run — should contain verdict, severity, reasons
2. If severity >= threshold: a **GitHub Issue** labeled `cicd-abuse-alert`
3. If Slack configured: a **Slack notification**
4. If `CI_CD_ABUSE_FAIL_ON_SEVERITY` set: the check **fails** on high-severity PRs

---


## End-to-end validation in your environment

For a full run through your platform (prescreen, Copilot, verdict JSON, optional alerts), use a **fork** or other non-production repository, configure LLM and optional alert secrets, open pull requests that modify CI or config files, and review the **workflow run** (Step Summary, logs) for prescreen labels and verdict JSON.

Use `make test` and `make validate` in this repository to catch regressions in **prescreen regex** behavior. They do not exercise the full LLM—run a test PR in CI when you change prompts or heuristics meaningfully.
