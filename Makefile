.PHONY: build validate test clean

DIST_DIR := dist
TEMPLATE := templates/github/pr-cicd-abuse-detector.yml
PROMPT := prompts/analyze-cicd-change.md
SCHEMA := schemas/verdict.schema.json
OUTPUT := $(DIST_DIR)/pr-cicd-abuse-detector.yml

# Build a single-file workflow with prompt and schema embedded inline.
# The run: | block requires all content indented to the same level (10 spaces).
# The prompt replaces $(cat ...) inside a shell double-quoted string in the run block.
# The schema replaces the file-read instruction with inline content.
build: validate
	@mkdir -p $(DIST_DIR)
	@echo "Embedding prompt and schema into workflow..."
	@python3 scripts/build-embed.py $(TEMPLATE) $(PROMPT) $(SCHEMA) $(OUTPUT)

# Validate YAML, JSON, and shell scripts.
validate:
	@echo "=== Validating YAML ==="
	@for f in templates/github/*.yml templates/gitlab/*.yml templates/azure-devops/*.yml; do \
		python3 -c "import yaml; yaml.safe_load(open('$$f'))" && echo "  OK: $$f" || exit 1; \
	done
	@echo "=== Validating JSON Schema ==="
	@python3 -c "import json; json.load(open('$(SCHEMA)'))" && echo "  OK: $(SCHEMA)"
	@echo "=== Checking for Python in templates ==="
	@if grep -rn 'python' templates/ | grep -v '#' | grep -v 'python3 -c' | grep -v '.gitignore' | grep -v 'check_signal\|check_tail_signal'; then \
		echo "WARNING: Found 'python' references in templates (expected zero Python dependency)"; \
	else \
		echo "  OK: No Python dependency in templates"; \
	fi
	@echo "=== Validation complete ==="

# Run prescreen label (regex) tests against example diffs.
test: validate
	@echo "=== Prescreen label tests ==="
	@bash tests/run-signal-tests.sh

clean:
	rm -rf $(DIST_DIR)
