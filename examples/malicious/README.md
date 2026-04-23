# Malicious Examples

These diff fixtures represent CI/CD and developer environment changes that the detector should classify as **suspicious** or **malicious**. Each is modeled after a real-world attack.

## Class B — CI/CD Pipeline Attacks

| File | Mirrors Incident | Attack Technique |
|------|-----------------|------------------|
| `secret-exfil-curl.diff` | GhostAction (2025) | Secrets POSTed to external endpoint via curl |
| `pull-request-target-checkout.diff` | Orca/Grafana/Synacktiv (2024-2025) | `pull_request_target` + untrusted PR checkout |
| `write-all-permissions.diff` | Common escalation pattern | Permissions broadened to `write-all` |
| `artifact-token-leak.diff` | ArtiPACKED (2024) | Artifact upload of checkout dir leaking GITHUB_TOKEN |
| `runner-memory-exfil.diff` | Trivy/Aqua TeamPCP (2026) | `/proc/<pid>/mem` scraping for runner credentials |
| `nord-stream-pipeline-exfil.diff` | Nord Stream / Synacktiv (2023-2026) | GitHub: double-base64 secret dump + OIDC token theft via log exfil |
| `nord-stream-azure-devops.diff` | Nord Stream / Synacktiv (2023-2026) | Azure DevOps: variable group extraction, AzureRM SPN exposure, secure file theft, GitHub PAT via .git/config, SSH task patching |
| `github-env-injection.diff` | Legit Security / Synacktiv (2023-2025) | GITHUB_ENV/GITHUB_PATH injection + LD_PRELOAD + cron persistence |
| `context-injection-reusable.diff` | HackerBot-Claw / NSA Emissary CVE-2026-35580 | Script injection via untrusted context + secrets:inherit + mutable reusable workflow |

## Class A — Developer Workstation / IDE Attacks

| File | Mirrors Incident | Attack Technique |
|------|-----------------|------------------|
| `ide-config-poisoning.diff` | Contagious Interview / Lazarus (2025-2026) | `.vscode/tasks.json` auto-execute on folder open + hidden config + trojanized postinstall |
| `devcontainer-lifecycle-attack.diff` | Codespaces abuse / Dev Container exploitation | `postCreateCommand` + `postAttachCommand` credential theft + Docker socket mount |

## Class C — Supply Chain / Exfiltration Channels

| File | Mirrors Incident | Attack Technique |
|------|-----------------|------------------|
| `codecov-curl-pipe-bash.diff` | Codecov (2021) | `curl ... \| bash` remote script execution + trojanized `setup.py` with `cmdclass` |
| `oidc-token-minting.diff` | OIDC abuse research (2024-2026) | `workflow_run` privilege escalation + OIDC token minting via `ACTIONS_ID_TOKEN_REQUEST_URL` |
| `npm-worm-supply-chain.diff` | Shai-Hulud (2025) | npm worm: `gh auth token` PAT harvest + trufflehog/gitleaks + secrets piped to output/env |
| `self-hosted-runner-escape.diff` | Runner escape research (2024-2026) | Self-hosted runner + privileged container escape + K8s secret access + `/proc/mem` scraping |
| `exfil-channels-variety.diff` | Multi-channel exfiltration patterns | DNS exfil + `nc`/`ncat` + bash `/dev/tcp` + `tar` credential archive + `openssl`/`xxd` encoding |
| `python-stdlib-exfil.diff` | Signal evasion via Python stdlib | `urllib.request` + `os.environ` + `base64` + `socket` — bypasses shell-based signal detection |
| `gradle-jvm-ruby-runtime-exfil.diff` | Build-script exfil (JVM / Ruby) | Gradle Kotlin DSL using `java.net.URL`/`HttpURLConnection`; Rakefile using `Net::HTTP` — evades curl/node-only greps |
| `cmake-file-download-exfil.diff` | CMake supply-chain abuse | `file(DOWNLOAD ...)` with token in URL — evades shell/Node/Python greps if CMake was off-path |
| `msbuild-directory-build-exfil.diff` | MSBuild pivot | Root `Directory.Build.props` with `pwsh` + `Invoke-RestMethod` posting `GITHUB_TOKEN` — evades bash-centric greps when .NET files were off-path |
| `smokedmeat-github-script-stager.diff` | SmokedMeat-style stager | `actions/github-script` + `require('child_process').execSync('curl … \| bash')` |
| `smokedmeat-ifs-mainmodule.diff` | SmokedMeat rye stagers | `${IFS}` + base64 URL decode + `curl \| bash`; `process.mainModule.require('child_process')` sandbox bypass |
| `alternate-http-cli-aria2c-stager.diff` | Alternate CLI (aria2c) | `aria2c` + `bash` on fetched script — no `curl`/`wget` substring; closes gap vs `curl_wget` |
| `smokedmeat-node-fetch-function.diff` | SmokedMeat-style JS (fetch) | `globalThis.fetch` + `new Function` remote execution — evades `require('https')` / `node_https_request` greps |
| `nord-stream-perl-http-tiny-stager.diff` | Nord Stream multi-runtime (Perl) | `HTTP::Tiny` + `exec` — Perl HTTP client coverage |
| `php-stream-remote-stager.diff` | PHP in CI | `file_get_contents("https://...")` + `include` — `php_stream_remote` |
| `smokedmeat-node-fetch-bare-url.diff` | Bare `fetch` URL | Same as global fetch stager without `globalThis` prefix |
| `go-run-remote-module.diff` | Go supply chain (remote module) | `go run https://...` remote module — `go_run_remote` |
| `pkg-runner-remote-enrichment.diff` | Remote package runners | Combined fixture for `bun_remote_https`, `uv_remote_https`, `cargo_install_git`, `node_dlx_remote_https` (prescreen enrichment, not IOCs) |
| `deno-run-remote-module.diff` | Deno remote module | `deno run https://...` — `deno_run_remote` (avoid spelling classic shell downloaders in YAML comments; grep sees comments) |
| `wget2-pipe-bash-stager.diff` | wget2 pipe stager | `wget2` evades `\b(curl|wget)\b`; pipe-to-shell uses word-boundary-safe `curl_pipe_bash` + `http_cli_download_alt` |
| `bash-udp-socat-exfil.diff` | Bash UDP + socat | `printf … > /dev/udp/…` + `socat` TCP relay — no `curl`/`wget`; `bash_tcp_redirect`, `nc_ncat` |
| `xh-http-cli-exfil.diff` | xh HTTP CLI | `pip install xh` + `xh post … --body` with secret — `http_cli_download_alt` (`\bxh\b`) |
| `nix-flake-shellhook-exfil.diff` | Nix dev shell abuse | `flake.nix` + `mkShell` / `shellHook` posting environment via `curl` + `printenv`/`base64` |
| `supply-chain-lockfile.diff` | Dependency confusion (2021-2026) | Lockfile registry swap + MCP config write + GitHub App token theft |
| `gitlab-ci-secrets.diff` | Nord Stream GitLab (2023-2026) | GitLab CI: double-base64 variable dump + Vault integration abuse + CI_JOB_TOKEN API access |

## Defense Evasion

| File | Mirrors Incident | Attack Technique |
|------|-----------------|------------------|
| `backdated-config-trojan.diff` | XCTDH/DEV#POPPER (2026) | Backdated commit with trojanized config file (obfuscated JS loader) |

## Usage

These fixtures can be used to test the detector for true positives. Each should trigger the expected pre-screen signals (see `tests/expected-signals.txt`) and receive an appropriate severity verdict from the LLM.

Run `make test` to verify prescreen regex labels against all examples.

## Incident References

### Class B — CI/CD Pipeline
- **GhostAction**: GitGuardian, 2025 — Compromised maintainer accounts inject exfil workflows
- **Orca "Pull Request Nightmare"**: Orca Security, 2024 — `pull_request_target` exploitation in major repos
- **Grafana**: Grafana security blog, 2025 — Script injection via crafted branch names
- **Synacktiv**: Synacktiv blog, 2024 — Dependabot app abuse for `pull_request_target` exploitation
- **ArtiPACKED**: Palo Alto Unit 42, 2024 — Artifact upload leaks `.git` with GITHUB_TOKEN
- **Trivy/Aqua TeamPCP**: Aqua Security / Wiz / Palo Alto, 2026 — Runner memory scraping for credential theft
- **Nord Stream**: Synacktiv, 2023-2026 — CI/CD secret extraction tool for GitHub, GitLab, Azure DevOps
- **Legit Security**: Google & Apache GITHUB_ENV injection, 2023
- **HackerBot-Claw**: StepSecurity, 2026 — Automated AI bot exploiting GitHub Actions script injection across Microsoft, DataDog, CNCF
- **NSA Emissary CVE-2026-35580**: 10 shell injection points via workflow_dispatch inputs

### Class A — Developer Workstation
- **Contagious Interview / Lazarus**: Microsoft/JAMF/ThreatLocker, 2025-2026 — DPRK-linked VS Code tasks.json auto-execute targeting developers via fake job interviews
- **Codespaces abuse**: Various, 2024-2025 — Dev container lifecycle commands for credential theft

### Class C — Supply Chain / Exfiltration Channels
- **Codecov**: Codecov post-mortem, 2021 — Modified hosted bash script exfils env vars via curl
- **Shai-Hulud**: Socket.dev, 2025 — npm supply chain worm harvesting GitHub PATs via `gh auth token`, running trufflehog for secret reconnaissance
- **Dependency confusion**: Alex Birsan, 2021 — Registry swap in lockfiles, extended to MCP config injection
- **Nord Stream GitLab**: Synacktiv, 2023-2026 — GitLab CI variable extraction, Vault integration abuse, CI_JOB_TOKEN API enumeration

### Defense Evasion
- **XCTDH/DEV#POPPER**: KL4R10N / Ransom-ISAC / eSentire, 2026 — DPRK-linked commit-date spoofing to hide trojanized config files
