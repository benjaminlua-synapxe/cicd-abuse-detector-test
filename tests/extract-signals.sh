#!/usr/bin/env bash
# Extract signals from a diff file using the same regex patterns as the CI templates.
# Usage: source tests/extract-signals.sh  (reads .cicd-abuse-detector/relevant.diff)
#    or: DIFF_FILE=path/to/file.diff source tests/extract-signals.sh

DIFF_TARGET="${DIFF_FILE:-.cicd-abuse-detector/relevant.diff}"

# Prescreen labels: enrichment metadata for the LLM bundle (not an IOC list; incomplete by design).
SIGNALS=""
check_signal() {
  local name="$1" pattern="$2"
  if grep -qE -- "$pattern" "$DIFF_TARGET" 2>/dev/null; then
    SIGNALS="${SIGNALS:+$SIGNALS, }$name"
  fi
}

# ── Credential harvesting ──
check_signal "secrets_context"        '\$\{\{.*secrets\.'
check_signal "github_token"           '\$\{\{.*github\.token'
check_signal "actions_runtime_token"  'ACTIONS_RUNTIME_TOKEN'
check_signal "actions_id_token_url"   'ACTIONS_ID_TOKEN_REQUEST_URL'
check_signal "secrets_to_output"      'secrets\..*>>.*GITHUB_OUTPUT'
check_signal "secrets_to_env"         'secrets\..*>>.*GITHUB_ENV'
check_signal "cloud_auth_action"      'aws-actions/configure-aws-credentials|google-github-actions/auth|azure/login'
check_signal "gh_auth_token"          'gh auth token'
check_signal "cloud_cred_file_access" '\.aws/credentials|\.config/gcloud|\.azure/'
check_signal "ssh_key_access"         '\.ssh/id_|id_rsa|id_ed25519|id_ecdsa'
check_signal "env_secret_grep"        '(env|printenv).*grep'
check_signal "proc_self_environ"      '/proc/self/environ'
check_signal "k8s_secret_access"      'kubectl.*get.*secrets|/var/run/secrets/kubernetes\.io'

# ── Privileged triggers ──
check_signal "pull_request_target"    'pull_request_target'
check_signal "workflow_run"           'workflow_run'

# ── Permission broadening ──
check_signal "write_all"              'write-all'
check_signal "id_token_write"         'id-token.*write'

# ── Runner targeting ──
check_signal "self_hosted"            'self-hosted'
check_signal "runner_tracking_tamper"  'RUNNER_TRACKING_ID'
check_signal "container_escape"       '--privileged.*-v.*/:/|--privileged.*--pid.*host'

# ── Exfiltration ──
check_signal "curl_wget"              '\b(curl|wget)\b'
# Alternate CLI downloaders (evade curl|wget grep; SmokedMeat-style variants)
check_signal "http_cli_download_alt"  '\baria2c\b|\baxel\b|\bhttpie\b|\bwget2\b|\bxh\b'
# Node 18+ fetch (globalThis or bare fetch(...https://...); evades require('https') greps)
check_signal "node_global_fetch"     'globalThis\.fetch\s*\(|\bfetch\s*\([^)\n]*https?://'
check_signal "js_function_ctor_unsafe" '\bnew Function\s*\('
# Perl HTTP clients (Nord Stream / polyglot pipelines)
check_signal "perl_http_lite"         'HTTP::Tiny|LWP::|WWW::Mechanize'
# PHP stream wrappers / remote includes
check_signal "php_stream_remote"     'file_get_contents\s*\([^)\n]*https?://|readfile\s*\([^)\n]*https?://|\bphp\s+-r'
# Go remote module execution
check_signal "go_run_remote"         '\bgo\s+run\s+https?://'
check_signal "deno_run_remote"       '\bdeno\s+(run|compile|install)\b.*https?://'
check_signal "bun_remote_https"      '\bbun\s+(x|run|install)\b.*https?://'
check_signal "uv_remote_https"       '\buv\s+(run|tool\s+run|pip(\s+install)?|add)\b.*https?://'
check_signal "cargo_install_git"     '\bcargo\s+(install|add)\b[^\n]*--git'
check_signal "node_dlx_remote_https" '\b(pnpm\s+dlx|yarn\s+dlx|yarn\s+npm\s+exec)\b.*https?://'
check_signal "nc_ncat"                '\b(nc|ncat|netcat|socat)\b'
check_signal "base64"                 '\bbase64\b'
check_signal "printenv"               '\bprintenv\b'
check_signal "sensitive_file_archive" '\b(tar|zip|gzip)\b.*(\.ssh|\.aws|\.gnupg|\.config/gcloud)'
check_signal "dns_exfil"              '\b(dig|nslookup)\b.*\$'

# ── Supply chain ──
check_signal "upload_artifact"        'upload-artifact'
check_signal "download_artifact"      'download-artifact'
check_signal "mutable_action_ref"     'uses:.*@(main|master|latest|dev)\b'
check_signal "checkout_ref"           'ref:.*github\.event\.pull_request\.head\.(sha|ref)'
check_signal "secret_scanning_tool"   '\b(trufflehog|gitleaks)\b'
check_signal "silent_npm_install"     'npm.*--loglevel.*(silent|error)|npm.*--no-save'
check_signal "mcp_config_write"       'claude_desktop_config|mcp\.json|\.continue/config'

# ── Python/alternative exfiltration (signal evasion countermeasures) ──
check_signal "python_urllib"           'urllib\.request|urllib\.urlopen|requests\.(get|post|put)'
check_signal "python_env_capture"     'os\.environ|dict\(os\.environ\)'
check_signal "python_base64"          'import base64|from base64'
check_signal "python_socket"          'socket\.(connect|getaddrinfo|create_connection)'
check_signal "bash_tcp_redirect"      '/dev/tcp/|/dev/udp/'
check_signal "openssl_encoding"       'openssl.*(enc|base64)'
check_signal "openssl_s_client"      'openssl s_client'
check_signal "xxd_encoding"           '\bxxd\b'

# ── Memory/process scanning ──
check_signal "proc_mem_read"          '/proc/.*mem\b'

# ── Dangerous triggers ──
check_signal "issue_comment_trigger"  'issue_comment'

# ── External script execution ──
check_signal "curl_pipe_bash"         '(\bcurl\b|\bwget2?\b).*\|.*(ba)?sh'

# ── Dependency installation changes ──
check_signal "dependency_install_change" 'npm install|yarn add|pip install|poetry add|gem install|cargo install|go install'

# ── Packaging manipulation ──
check_signal "postinstall_script"    '"(pre|post)install"'
check_signal "setup_py_command"       'cmdclass|install_requires|setup\(|subprocess'
check_signal "lockfile_registry_swap" 'resolved.*https?://[^r]|registry.*https?://[^r]|registry\.npmjs\.org.*replaced'

# ── Nord-stream / log-based exfiltration ──
check_signal "double_base64"         'base64.*\|.*base64'
check_signal "env_null_dump"         'env -0'

# ── IDE config poisoning (Contagious Interview / Lazarus) ──
check_signal "curl_pipe_node"        '(\bcurl\b|\bwget2?\b).*\|.*node'
check_signal "vscode_auto_task"      'runOn.*folderOpen'
check_signal "hidden_ide_config"     '\*\*/\.vscode.*true'
check_signal "eval_remote_code"      '\beval\('

# ── GITHUB_ENV / GITHUB_PATH injection ──
check_signal "github_env_write"     '>>\s*\$?\{?GITHUB_ENV\}?'
check_signal "github_path_write"    '>>\s*\$?\{?GITHUB_PATH\}?'
check_signal "ld_preload"           'LD_PRELOAD'

# ── Devcontainer lifecycle attacks ──
check_signal "devcontainer_lifecycle" 'postCreateCommand|postStartCommand|postAttachCommand|onCreateCommand|initializeCommand'
check_signal "docker_socket_mount"  'docker\.sock|/var/run/docker'

# ── Script injection via untrusted context ──
check_signal "context_injection"    '\$\{\{.*github\.event\.(pull_request\.(title|body|head\.(ref|sha))|issue\.(title|body)|comment\.body|head_commit\.message)'
check_signal "dispatch_input_injection" 'github\.event\.inputs\.'

# ── Persistence and privilege ──
check_signal "schedule_trigger"     '\bschedule:'
check_signal "contents_write"       'contents:\s*write'
check_signal "secrets_inherit"      'secrets:\s*inherit'

# ── GitHub App token theft ──
check_signal "github_app_token"    'create-github-app-token|APP_PRIVATE_KEY'

# ── Cross-repo secret sharing ──
check_signal "cross_repo_dispatch"  'repository-dispatch|repository:.*\w+/\w+'
check_signal "action_secret_input"  'with:[\s\S]{0,200}secrets\.'

# ── Command obfuscation / evasion ──
check_signal "hex_decode"           'xxd -r|\\x[0-9a-f]{2}'
check_signal "printf_decode"        "printf.*\\\\x|printf.*\$'\\\\x"
check_signal "rev_obfuscation"      '\brev\b.*\||\|.*\brev\b'
check_signal "variable_cmd_exec"    '\$\w+\s+-[sS].*POST|\$\w+.*-d.*\$|\$\(\w+\)'
check_signal "bash_ifs_whitespace"  '\$\{IFS\}'
check_signal "node_main_module_bypass" 'process\.mainModule\.require'

# ── Node.js / runtime exfiltration (signal evasion countermeasures) ──
check_signal "node_https_request"   'https\.request\(|http\.request\(|require\(.https.\)'
check_signal "node_child_process_exec" 'child_process|execSync\s*\('
check_signal "ruby_http_client"     'Net::HTTP|open-uri|Faraday|Typhoeus|Excon\.|RestClient|OpenURI'
check_signal "jvm_http_client"       'HttpURLConnection|java\.net\.URL|OkHttpClient|okhttp3'
check_signal "cmake_remote_fetch"  'file\s*\(\s*DOWNLOAD|ExternalProject_Add|FetchContent'
check_signal "powershell_invoke_web" 'Invoke-WebRequest|Invoke-RestMethod|\bpwsh\b.*-Command|powershell\.exe'
check_signal "nix_shell_hook"      'mkShell|shellHook|builtins\.fetchurl'
check_signal "github_script_token"  'core\.getInput.*github-token|core\.getInput.*token'
check_signal "gh_api_exfil"         '\bgh api\b'
check_signal "toJSON_secrets"       'toJSON\(secrets\)'

# ── GitLab-specific (cross-platform) ──
check_signal "ci_job_token"          'CI_JOB_TOKEN'
check_signal "ci_registry_password"  'CI_REGISTRY_PASSWORD|CI_DEPLOY_PASSWORD|CI_DEPLOY_USER'
check_signal "gitlab_remote_include" 'include:.*remote:|remote:.*https?://|include:.*https?://'

# ── Azure DevOps-specific (cross-platform) ──
check_signal "system_access_token"   'System\.AccessToken|SYSTEM_ACCESSTOKEN'
check_signal "ado_spn_exposure"     'addSpnToEnvironment'
check_signal "ado_secure_file"     'DownloadSecureFile'
check_signal "persist_credentials" 'persistCredentials'
check_signal "ado_service_connection" 'serviceConnection|azureSubscription'
check_signal "task_source_patch"   '_tasks/.*\.js|\.js\.bak'
check_signal "ado_aws_task"        'AWSShellScript@'
check_signal "ado_sonar_task"      'SonarQubePrepare@'
