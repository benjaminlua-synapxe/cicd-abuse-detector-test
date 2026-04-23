# Benign Examples

These diff fixtures represent legitimate CI/CD changes that the detector should classify as **benign**.

| File | Description | Expected Signals |
|------|-------------|-----------------|
| `lint-workflow.diff` | New lint workflow with read-only permissions | none |
| `action-pin-upgrade.diff` | Upgrading an action from mutable tag to pinned SHA | none |
| `cache-optimization.diff` | Adding caching to speed up CI | none |
| `curl-download-tools.diff` | Installing system tools via curl/wget + pip + upload-artifact for build output | `curl_wget`, `upload_artifact`, `curl_pipe_bash`, `dependency_install_change` |

## Usage

These fixtures can be used to test the detector for false positives. Each represents a common, safe CI/CD maintenance pattern.

### False-Positive Calibration

`curl-download-tools.diff` is designed to test the LLM's false-positive handling. It triggers four prescreen labels (`curl_wget`, `upload_artifact`, `curl_pipe_bash`, `dependency_install_change`) that would indicate malicious activity in other contexts, but the actual content is benign: downloading well-known tools from official sources, installing standard dev dependencies, and uploading build artifacts from a specific path. The LLM should classify this as **benign** despite the label count.
