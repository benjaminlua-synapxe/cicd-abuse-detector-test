# Contributing to CI/CD Abuse Detector

This repository is published as **drop-in CI templates** (workflows, prompt, and verdict schema) under the [Apache License 2.0](LICENSE). It is a **prototype** (see the [Security Labs post](https://www.elastic.co/security-labs/detecting-cicd-pipeline-abuse-with-llm-augmented-analysis)) and is **not** an officially supported Elastic product; contributions help the reference implementation, not a product release train.

**Customizing for your org:** The straightforward path is to **fork** (or copy) this repository and edit `templates/`, `prompts/`, and `schemas/` where you control CI. That is the right place for environment-specific tuning, most prescreen or prompt experiments, and iteration speed.

**Security:** Report vulnerabilities in this project’s code or docs through [SECURITY.md](SECURITY.md) and [Elastic’s disclosure process](https://www.elastic.co/community/security); avoid public issues until a fix is available.

**Changes to this upstream repo:** Pull requests that fix bugs, improve docs, or improve the shared templates in line with the project’s goals are welcome. Reviewers are listed in [CODEOWNERS](CODEOWNERS). Large or highly specific features may be better maintained in a fork; we may not be able to take on every idea.

## Development setup (validation only)

The **shipped** templates do not require Python in consumer CI. This repo uses **Python 3** only for **local checks** and embed tooling:

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
make validate
make test
```

- `make validate` — Parse all template YAML, validate the JSON schema, and check prescreen-signal invariants.
- `make test` — Run prescreen label tests against `examples/*.diff`.
- `make build` — Optional: produce `dist/pr-cicd-abuse-detector.yml` (single-file GitHub workflow with embedded prompt and schema).

## License

By contributing, you agree your contributions are licensed under the [Apache License 2.0](LICENSE).
