# Scoring Notes

Guidelines for severity calibration used by the LLM analysis prompt.

## Prescreen labels vs IOCs

Named patterns in the workflow (e.g. `curl_wget`, `go_run_remote`, `bun_remote_https`) are **enrichment metadata** passed to the model: cheap heuristics that often correlate with risky edits. They are **not** claims that a string is malicious, and they are **not** exhaustive. **Primary classification always comes from the LLM analyzing the diff.** Use combinations in the tables below for severity hints, not as automatic verdicts.

## Severity Levels

### Critical

Active credential harvesting or exfiltration with clear attacker intent.

**Indicators:**
- Secrets sent to external endpoints (curl/wget/nc POST with `secrets.*`)
- Runner memory scraping (`/proc/<pid>/mem` with credential patterns)
- Process environment scraping (`/proc/self/environ`)
- Multiple secrets referenced with network exfiltration in same workflow
- New workflow file combining: secret access + external network call + encoding
- `gh auth token` extraction (harvesting GitHub CLI PAT)
- Archiving credential directories (`.ssh/`, `.aws/`, `.gnupg/`) combined with upload or network call
- Kubernetes secret enumeration (`kubectl get secrets`) or direct service account token reads

**Expected verdict:** `malicious`
**Expected confidence:** `high`

### High

Permission escalation combined with new secret access, or privileged trigger abuse.

**Indicators:**
- `pull_request_target` + checkout of untrusted PR head SHA
- `permissions: write-all` replacing restrictive permissions
- `id-token: write` added without clear OIDC use case
- `workflow_run` trigger added with secret access
- Self-hosted runner targeting combined with secret references
- `RUNNER_TRACKING_ID` tampering (disabling runner telemetry/cleanup)
- Privileged container with host filesystem mount (container escape)
- Cloud credential file access (`.aws/credentials`, `.config/gcloud/`, `.azure/`) combined with network calls

**Expected verdict:** `suspicious` or `malicious`
**Expected confidence:** `medium` to `high`

### Medium

Potentially risky patterns that require context to evaluate.

**Indicators:**
- Mutable action references (`@main`, `@master`, `@latest`)
- New third-party actions with secrets passed as inputs
- `curl | bash` or `wget | sh` patterns
- Alternate download CLIs (`aria2c`, `axel`, `httpie`, `wget2`) used to fetch remote scripts when `curl`/`wget` are avoided for grep or log evasion
- Node `globalThis.fetch` / undecorated `fetch` with `new Function` or other dynamic execution of remote response (evades `require('https')`-style greps)
- Perl `HTTP::Tiny`, `LWP::*`, or `WWW::Mechanize` in CI to download and run follow-on payloads
- PHP `file_get_contents` / `readfile` against `https://` URLs or `php -r` one-liners pulling remote code
- `go run https://...` executing remote modules from the workflow
- `deno run|compile|install` with a remote `https://` URL (possibly with CLI flags before the URL)
- `bun` / `uv` / `cargo install --git` / `pnpm dlx` / `yarn dlx` with remote URLs — prescreen may flag `bun_remote_https`, `uv_remote_https`, `cargo_install_git`, `node_dlx_remote_https`; LLM confirms intent
- `issue_comment` trigger with elevated permissions
- Dependency installation changes in CI/build/signing pipelines
- Silent npm installs (`--loglevel silent`, `--no-save`)
- Artifact upload of broad directory paths
- Credential scanning tools (`trufflehog`, `gitleaks`) without clear security scanning context
- MCP config file writes from CI (`claude_desktop_config`, `mcp.json`)
- Build scripts (Gradle, Rake/Gemfile) using `java.net.URL` / `HttpURLConnection`, or Ruby `Net::HTTP` / `open-uri`, to POST tokens or env data to non-package-registry hosts
- CMake `file(DOWNLOAD ...)`, `ExternalProject_Add`, or `FetchContent` pulling from attacker-controlled URLs or embedding `GITHUB_TOKEN` in download URLs
- MSBuild `Directory.Build.props` / project files running `pwsh`, `Invoke-WebRequest`, or `Invoke-RestMethod` with secrets or environment exfil
- `actions/github-script` (or inline Node) using `require('child_process')` / `execSync` to run shell downloaders (SmokedMeat-style stagers)
- Bash `${IFS}` instead of spaces in `curl`/`base64` pipelines (SmokedMeat branch/title constraints); Node `process.mainModule.require('child_process')` to bypass restricted `require` shims
- Nix `flake.nix` / `shell.nix` with `shellHook` or `builtins.fetchurl` pulling from untrusted hosts, or shell hooks that exfil environment data

**Expected verdict:** `suspicious`
**Expected confidence:** `low` to `medium`

### Low

Minor changes that slightly affect the security posture.

**Indicators:**
- New environment variables (non-secret)
- Minor permission additions with clear justification
- Workflow restructuring with no new capabilities
- Cache configuration changes
- Job renaming or reordering

**Expected verdict:** `benign`
**Expected confidence:** `high`

## Trust Context Modifiers

The analysis bundle includes `author_profile` with enriched metadata. These factors should adjust severity up or down:

| Factor | Source | Effect |
|--------|--------|--------|
| Author is a bot (dependabot, renovate) making expected changes | `author_profile.type == "Bot"` | Lower severity by one level |
| First-time contributor to this repo | `author_profile.prior_commits_to_repo == 0` | Raise severity by one level |
| Author is not an org member | `author_profile.is_org_member == false` | Raise severity by one level |
| Account created recently (< 30 days) | `author_profile.created_at` | Raise severity by one level |
| Low-activity account (< 5 repos, 0 followers) | `author_profile.public_repos`, `followers` | Raise severity by one level |
| Change is via direct push to main (no PR review) | `change_path == "direct_push"` | Raise severity by one level |
| Change is in a well-established workflow (existing file) | Diff shows `---` (modification, not new file) | Neutral — but removal of security controls is high severity |
| Change is a brand-new workflow file with secret access | Diff shows `new file mode` | Raise severity by one level |

### Compounding trust signals

Multiple trust signals compound. A change that hits 3+ trust risk factors simultaneously should be treated with extreme scrutiny:

- `first_time_contributor` + `non_org_member` + `secrets_context` → near-certain malicious
- `first_time_contributor` + `non_org_member` + new workflow file → high suspicion even without other signals
- New account (< 7 days) + any credential harvesting signal → critical

## Prescreen label combinations

Some label combinations are more dangerous than others:

| Combination | Severity |
|-------------|----------|
| `secrets_context` + `curl_wget` | Critical — canonical exfil pattern |
| `secrets_context` + `nc_ncat` | Critical — exfil via raw socket |
| `pull_request_target` + `checkout_ref` | **Critical** — untrusted code runs with base-branch secrets (Orca/Grafana/Synacktiv/Trivy attack chain) |
| `pull_request_target` + `id_token_write` | **Critical** — OIDC token minting from untrusted PRs enables cloud account takeover |
| `pull_request_target` alone | High — dangerous trigger, script injection via PR metadata can exfil secrets |
| `write_all` + `secrets_context` | **Critical** — maximum permissions with credential access |
| `write_all` + `printenv` | **Critical** — permission broadening + environment dump = credential harvesting staging |
| `id_token_write` + `cloud_auth_action` | High — cloud credential escalation |
| `proc_mem_read` + `curl_wget` | Critical — memory scraping with exfil |
| `proc_self_environ` + `curl_wget` | Critical — env scraping with exfil |
| `gh_auth_token` + `curl_wget` | Critical — PAT harvesting with exfil |
| `ssh_key_access` + `sensitive_file_archive` | Critical — SSH key archival for bulk exfil |
| `cloud_cred_file_access` + `curl_wget` | Critical — cloud credential theft with exfil |
| `k8s_secret_access` + `curl_wget` | Critical — K8s secret harvesting with exfil |
| `secret_scanning_tool` + `curl_wget` | High — credential scanning with exfil channel |
| `runner_tracking_tamper` + any credential signal | High — evasion combined with harvesting |
| `container_escape` + any credential signal | High — breakout combined with harvesting |
| `silent_npm_install` + `secrets_context` | High — hidden dependency with secret access |
| `mutable_action_ref` alone | Medium — risky but may be benign |
| `dependency_install_change` alone | Medium — context needed |
| `upload_artifact` with workspace/root path upload | **High** — ArtiPACKED pattern, `.git/config` contains GITHUB_TOKEN |
| `upload_artifact` + `checkout_ref` | High — potential token leak via artifact |
| `base64` + `curl_wget` | High — encoded exfiltration |
| `dns_exfil` + `secrets_context` | High — DNS exfiltration of secrets |
| `postinstall_script` + `secrets_context` | High — packaging hook with secret access |
| `setup_py_command` + `curl_wget` | High — Python install hook with exfil |
| `backdated_commits` + `secrets_context` | Critical — evasion combined with credential harvesting (XCTDH/DEV#POPPER TTP) |
| `backdated_commits` + `first_time_contributor` | High — unknown actor hiding activity timeline |
| `backdated_commits` + `pull_request_target` | High — timing manipulation with privileged trigger |
| `backdated_commits` + obfuscated code | Critical — matches DPRK XCTDH pattern (eval, hex strings, single-letter vars in config files) |
| `backdated_commits` alone | High — active evasion technique (MITRE T1070.006), never dismiss without content analysis |
| `double_base64` + `secrets_context` | **Critical** — nord-stream log-based exfiltration pattern (double-encode secrets, read from CI logs) |
| `double_base64` + `env_null_dump` | **Critical** — exact nord-stream tool signature |
| `env_null_dump` + `base64` | Critical — environment dump with encoding for exfil |
| `vscode_auto_task` + `curl_pipe_node` | **Critical** — Contagious Interview / Lazarus IDE poisoning (zero-click code exec on folder open) |
| `vscode_auto_task` + `hidden_ide_config` | **Critical** — auto-execute with hidden config = deliberate evasion |
| `vscode_auto_task` alone | High — auto-execution on folder open is almost never benign in PRs |
| `eval_remote_code` + `curl_wget` | High — dynamic remote code evaluation with network fetch |
| `node_global_fetch` + `js_function_ctor_unsafe` | **Critical** — remote response executed via `new Function` (SmokedMeat-style; no `curl` / `require('https')` substring) |
| `perl_http_lite` + `env_secret_grep` | **Critical** — Perl HTTP client in pipeline with secret filtering (Nord Stream–style multi-runtime) |
| `github_env_write` + `ld_preload` | **Critical** — arbitrary shared library injection in subsequent steps (Synacktiv/Legit Security) |
| `github_env_write` + `github_path_write` | High — environment and PATH manipulation combined |
| `context_injection` + `pull_request_target` | **Critical** — HackerBot-Claw exact pattern: script injection via PR metadata in privileged trigger |
| `context_injection` + `secrets_context` | Critical — shell injection with secret access |
| `dispatch_input_injection` + `secrets_context` | Critical — controllable input with secret access (CVE-2026-35580 / NSA Emissary) |
| `schedule_trigger` + `secrets_context` | High — persistent scheduled secret harvesting |
| `schedule_trigger` + `curl_wget` | High — persistent scheduled exfiltration |
| `contents_write` + `secrets_context` | High — self-modifying workflow with secret access |
| `secrets_inherit` + `mutable_action_ref` | **Critical** — all repo secrets passed to mutable external workflow |
| `secrets_inherit` alone | High — blanket secret passing, should be explicit |
| `devcontainer_lifecycle` + `curl_wget` | High — devcontainer lifecycle command with exfil |
| `devcontainer_lifecycle` + `docker_socket_mount` | **Critical** — container escape combined with code execution on attach |
| `docker_socket_mount` + any credential signal | Critical — Docker socket access enables host compromise |
| `github_app_token` + `curl_wget` | Critical — GitHub App token theft with exfil |
| `ado_spn_exposure` + `double_base64` | **Critical** — Azure service principal extraction via nord-stream pattern |
| `ado_secure_file` + `base64` | Critical — Azure DevOps secure file exfiltration |
| `persist_credentials` + `base64` | Critical — credential persistence + exfiltration (GitHub PAT in .git/config) |
| `task_source_patch` + any credential signal | **Critical** — runtime task code patching = active evasion + credential theft (nord-stream SSH technique) |
| `ado_aws_task` + `double_base64` | **Critical** — AWS credential extraction via AWSShellScript task (nord-stream pattern) |
| `ado_aws_task` + `env_secret_grep` | **Critical** — AWS credential filtering + exfil |
| `ado_sonar_task` + `base64` | **High** — SonarQube credential extraction via SONARQUBE_SCANNER_PARAMS (nord-stream pattern) |
| `ado_sonar_task` + `env_secret_grep` | **Critical** — SonarQube token exfiltration |
| `python_urllib` + `python_env_capture` | **Critical** — Python stdlib credential exfiltration (bypasses curl_wget and printenv signals) |
| `python_urllib` + `secrets_context` | **Critical** — Python HTTP with secret access |
| `python_env_capture` + `python_base64` | **High** — Python environment capture with encoding |
| `bash_tcp_redirect` + `secrets_context` | **Critical** — Bash `/dev/tcp/` or `/dev/udp/` redirect exfil (bypasses classic `nc`/`socat` substring unless those also appear) |
| `http_cli_download_alt` + `secrets_context` | **Critical** — alternate HTTP CLI (`aria2c`, `wget2`, `httpie`, `xh`, …) with secret in request body |
| `openssl_encoding` + `curl_wget` | **High** — alternative encoding with exfil channel |
| `cross_repo_dispatch` + `secrets_context` | **High** — secrets forwarded to another repo via repository-dispatch (destination may be attacker-controlled) |
| `action_secret_input` + `mutable_action_ref` | **High** — secrets passed to unpinned action (tag can be repointed to malicious code) |
| `action_secret_input` + `cross_repo_dispatch` | **High** — action input laundering combined with cross-repo forwarding |
| `hex_decode` + `secrets_context` | **Critical** — command obfuscation (hex-encoded tool names) with secret access — active evasion |
| `printf_decode` + `secrets_context` | **Critical** — printf-based command reconstruction with secret access — active evasion |
| `variable_cmd_exec` + `secrets_context` | **Critical** — variable-constructed commands with secret access — likely automated evasion |
| `rev_obfuscation` + any exfil signal | **High** — string reversal obfuscation combined with exfil channel |
| `prompt_file_modified` + any signal | **Critical** — attacker attempting to neuter the analysis itself (defense evasion) |
| `prompt_file_modified` alone | **High** — analysis prompt or schema modified in PR/MR, even without other signals |
| `openssl_s_client` + any credential signal | **Critical** — openssl s_client used as TLS exfil channel to bypass curl_wget detection |
| `openssl_s_client` alone | **High** — TLS connection as data channel (legitimate mTLS possible but rare in CI) |
| `node_https_request` + any credential signal | **Critical** — Node.js native HTTP used to bypass curl_wget detection |
| `node_https_request` + `cloud_auth_action` | **Critical** — cloud credential theft via Node.js HTTPS (deploy-staging attack pattern) |
| `github_script_token` + any exfil signal | **Critical** — GITHUB_TOKEN accessed via actions/github-script and exfiltrated |
| `github_script_token` alone | **High** — actions/github-script reading the token directly is suspicious |
| `gh_api_exfil` + `github_token` | **High** — gh CLI API calls with token access (API-based exfil to repo vars/comments) |
| `toJSON_secrets` + any exfil signal | **Critical** — bulk secret dump via toJSON(secrets) with exfil channel |
| `toJSON_secrets` alone | **High** — toJSON(secrets) dumps all repo secrets at once |

## False Positive Guidance

These patterns commonly trigger signals but are usually benign:

- `curl` for downloading known tools or health checks (no secrets in payload)
- `base64` for encoding non-secret data (build metadata, test fixtures)
- `upload-artifact` for known build outputs with specific paths (e.g., `dist/`, `build/`). If `path` is `.` or repo root, this is NOT a false positive — it uploads `.git/config` containing GITHUB_TOKEN (ArtiPACKED)
- `dependency_install_change` in routine dependency update PRs (Dependabot/Renovate)
- `secrets_context` for well-known patterns (`secrets.GITHUB_TOKEN` in standard actions)
- `ssh_key_access` in SSH deployment steps that legitimately use deploy keys
- `cloud_cred_file_access` in workflows that intentionally configure cloud CLI tools
- `secret_scanning_tool` when `trufflehog` or `gitleaks` is run as a legitimate security scan step (check for `--no-verification` flag and whether results are uploaded to a security dashboard vs. exfiltrated)
- `k8s_secret_access` in Kubernetes deployment workflows that need to read config
- `nc_ncat` for health checks or connectivity tests (no data payload)

- `backdated_commits` when merging a long-lived feature branch or cherry-picking old commits with a small temporal gap (weeks, not years). A multi-year gap between author date and analysis date is never benign — treat as active evasion. Use `analysis_date` in the bundle to compute the gap.

The LLM should use the full diff context to distinguish these from actual threats.
