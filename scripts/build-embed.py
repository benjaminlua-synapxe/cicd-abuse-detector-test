#!/usr/bin/env python3
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright ownership. The ASF
# licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.

"""Embed prompt and schema into the GitHub Actions workflow template.

Part of the CI/CD Abuse Detector prototype; see:
https://www.elastic.co/security-labs/detecting-cicd-pipeline-abuse-with-llm-augmented-analysis

Produces a single-file dist/*.yml where the prompt and schema are inline
instead of read from separate files at runtime.

The key challenge: the content is inside a YAML block scalar (run: |),
so every embedded line must maintain the indentation level of the
surrounding shell code (10 spaces for the GitHub template).
"""
import sys


def indent_block(text: str, spaces: int) -> str:
    """Indent every non-empty line of text by the given number of spaces."""
    pad = " " * spaces
    lines = text.split("\n")
    return "\n".join(pad + line if line.strip() else "" for line in lines)


def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} TEMPLATE PROMPT SCHEMA OUTPUT")
        sys.exit(1)

    template_path, prompt_path, schema_path, output_path = sys.argv[1:5]

    with open(template_path) as f:
        wf = f.read()
    with open(prompt_path) as f:
        prompt = f.read().rstrip()
    with open(schema_path) as f:
        schema = f.read().rstrip()

    # The content lives inside a YAML block scalar (run: |) indented at 10 spaces.
    # Every non-empty embedded line must have at least 10 spaces of indentation,
    # otherwise the YAML parser treats it as the end of the block scalar.
    YAML_INDENT = 10

    # 1. Remove the trusted prompt/schema loading block (git show lines).
    #    In the single-file build, the prompt is embedded directly, so base-branch
    #    protection is inherent — the workflow YAML itself comes from the base branch
    #    on pull_request events.
    import re

    # Remove the comment block + git show lines for trusted prompt/schema
    trusted_block_pattern = re.compile(
        r"^[ ]*# Read prompt and schema from base branch.*?\n"
        r"(?:[ ]*#.*?\n)*"  # continuation comments
        r"[ ]*DIFF_BASE=\$\(cat \.cicd-abuse-detector/diff_base\.txt\)\n"
        r"[ ]*TRUSTED_PROMPT=\$\(git show.*?\n"
        r"[ ]*git show.*?trusted_schema\.json.*?\n"
        r"[ ]*\|\| cp.*?trusted_schema\.json\n",
        re.MULTILINE,
    )
    wf = trusted_block_pattern.sub("", wf)

    # 2. Replace ${TRUSTED_PROMPT} with the actual prompt content.
    trusted_prompt_token = "${TRUSTED_PROMPT}"
    if trusted_prompt_token in wf:
        indented_prompt = indent_block(prompt, YAML_INDENT)
        wf = wf.replace(trusted_prompt_token, indented_prompt.lstrip())
    else:
        # Fallback: try the old $(cat ...) pattern
        cat_token = "$(cat prompts/analyze-cicd-change.md)"
        if cat_token in wf:
            indented_prompt = indent_block(prompt, YAML_INDENT)
            wf = wf.replace(cat_token, indented_prompt.lstrip())
        else:
            print(f"WARNING: Neither '{trusted_prompt_token}' nor '{cat_token}' found in template", file=sys.stderr)

    # 3. Replace the schema file-read instruction with inline schema.
    #    Try the trusted schema path first, then fall back to the original.
    schema_instruction_trusted = "Read the verdict schema at .cicd-abuse-detector/trusted_schema.json."
    schema_instruction_orig = "Read the verdict schema at schemas/verdict.schema.json."
    indented_schema = indent_block(schema, YAML_INDENT)
    schema_replacement = (
        "The verdict schema is:\n"
        + indented_schema
        + "\n"
        + " " * YAML_INDENT
        + "Use this schema for your output."
    )
    if schema_instruction_trusted in wf:
        wf = wf.replace(schema_instruction_trusted, schema_replacement)
    elif schema_instruction_orig in wf:
        wf = wf.replace(schema_instruction_orig, schema_replacement)
    else:
        print(f"WARNING: Schema instruction not found in template", file=sys.stderr)

    # 4. Write the output.
    #    The embedded content is inside a run: | block scalar, so we need
    #    to ensure all lines have proper indentation. Since the content is
    #    inside a shell double-quoted string, the YAML parser sees it as
    #    part of the scalar block — which is fine as long as indentation
    #    is maintained.
    #
    #    NOTE: PyYAML may reject ${{ }} GitHub expressions as invalid YAML.
    #    We skip strict validation here and rely on `make validate` for the
    #    source template. The dist output is structurally identical.

    with open(output_path, "w") as f:
        f.write(wf)

    print(f"Built: {output_path}")


if __name__ == "__main__":
    main()
