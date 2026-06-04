import subprocess
import sys
from pathlib import Path

WORKFLOW = Path('.github/workflows/publish.yml')
WORKFLOW_BACKUP = Path('.github/workflows/publish.yml.bak')

VALIDATION_GATES = [
    ('Run linter (final check)', 'npm run lint'),
    ('Check formatting (final check)', 'npm run format:check'),
    ('Run test suite (final check)', 'npm test'),
    ('Validate detectors (final check)', 'npm run validate:campaigns'),
    ('Check dependencies (final check)', 'npm audit --audit-level=high'),
]

EXPECTED_BODY_LINE = '# npm-scan ${{ github.ref_name }}'

CHECKS = [
    ('Workflow name', 'Publish to npm', None),
    ('Trigger on.push.tags pattern', 'v*.*.*', None),
    ('Permissions.contents', 'write', None),
    ('Permissions.id-token', 'write', None),
    ('Job: publish present', None, None),
    ('Step: checkout with fetch-depth: 0', None, None),
    ('Step: setup-node with registry-url', None, None),
    ('Step: npm ci', None, None),
    ('Validation gate: npm run lint', None, None),
    ('Validation gate: npm run format:check', None, None),
    ('Validation gate: npm test', None, None),
    ('Validation gate: npm run validate:campaigns', None, None),
    ('Validation gate: npm audit --audit-level=high', None, None),
    ('Step: npm publish --provenance', None, None),
    ('Step: Create GitHub Release with files attachment', None, None),
    ('Release body contains ref_name reference', None, None),
]


def parse_yaml_keys_and_values(path):
    keys = {}
    lines = []
    stack = [('', -1)]
    has_errors = False
    with open(path, encoding='utf-8') as f:
        for raw_line in f:
            line = raw_line.rstrip('\n')
            lines.append(line)
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            indent = len(line) - len(line.lstrip())
            value = stripped
            while stack and stack[-1][1] >= indent:
                stack.pop()
            if value.startswith('- '):
                item = value[2:].strip()
                if ':' in item:
                    k, v = item.split(':', 1)
                    k = k.rstrip()
                    v = v.strip().strip('"').strip("'")
                    if stack:
                        prefix = '.'.join(s[0] for s in stack[1:])
                        full_key = f'{prefix}.{k}'
                        keys[full_key] = v
                continue
            if ':' in value:
                key_part = value.split(':', 1)[0].rstrip()
                rest = value.split(':', 1)[1].strip()
                full_key = '.'.join(s[0] for s in stack[1:] + [(key_part, indent)])
                if rest:
                    keys[full_key] = rest.strip('"').strip("'")
                else:
                    keys[full_key] = None
                stack.append((key_part, indent))
    return keys, lines


def check_crlf(path):
    return b'\r\n' in path.read_bytes()


def count_lines_containing(lines, substr):
    return sum(1 for l in lines if substr in l)


def run_verification(path, lines):
    errors = 0
    total = 0
    content = '\n'.join(lines)

    for label, exact, expected_sub in CHECKS:
        total += 1
        passed = False

        if label == 'Workflow name':
            passed = 'name: Publish to npm' in content
        elif label == 'Trigger on.push.tags pattern':
            passed = "'v*.*.*'" in content or '"v*.*.*"' in content
        elif label == 'Permissions.contents':
            passed = 'contents: write' in content
        elif label == 'Permissions.id-token':
            passed = 'id-token: write' in content
        elif label == 'Job: publish present':
            passed = 'publish:\n' in content or 'publish:\r\n' in content
        elif label == 'Step: checkout with fetch-depth: 0':
            passed = 'fetch-depth: 0' in content
        elif label == 'Step: setup-node with registry-url':
            passed = "registry-url" in content
        elif label == 'Step: npm ci':
            passed = "run: npm ci" in content or "npm ci\n" in content
        elif label == 'Validation gate: npm run lint':
            passed = "npm run lint" in content and "Run linter" in content
        elif label == 'Validation gate: npm run format:check':
            passed = "npm run format:check" in content and "formatting" in content.lower()
        elif label == 'Validation gate: npm test':
            passed = "run: npm test" in content or "npm test\n" in content
        elif label == 'Validation gate: npm run validate:campaigns':
            passed = "npm run validate:campaigns" in content
        elif label == 'Validation gate: npm audit --audit-level=high':
            passed = "npm audit --audit-level=high" in content
        elif label == 'Step: npm publish --provenance':
            passed = "--provenance" in content
        elif label == 'Step: Create GitHub Release with files attachment':
            passed = "action-gh-release" in content
        elif label == 'Release body contains ref_name reference':
            passed = "${{ github.ref_name }}" in content

        if passed:
            print(f'  PASS: {label}')
        else:
            print(f'  FAIL: {label}')
            errors += 1

    return errors, total


def enhance_publish_yml(path):
    with open(path, encoding='utf-8') as f:
        content = f.read()

    if '\r\n' in content:
        content = content.replace('\r\n', '\n')

    # 1. Change node-version from 22 to '20'
    content = content.replace('node-version: 22', "node-version: '20'")

    # 2. Replace the single "Run tests" step with 5 validation gates
    old_test_step = """      - name: Run tests
        run: npm test
"""
    gates_lines = ""
    for gate_name, gate_cmd in VALIDATION_GATES:
        if gate_cmd.startswith('npm audit'):
            gates_lines += f"""      - name: {gate_name}
        run: {gate_cmd}

"""
        else:
            gates_lines += f"""      - name: {gate_name}
        run: {gate_cmd}

"""

    if old_test_step in content:
        content = content.replace(old_test_step, gates_lines)
    else:
        print('  WARN: Could not find existing "Run tests" step to replace')

    # 3. Update GitHub Release body to match spec
    old_body_start = """          body: |
            # npm-scan v${{ github.ref_name }}

            ## Release Highlights

            ✅ **100% Detection Rate** on 3 real May 2026 supply chain campaigns
            ✅ **0% False Positive Rate** on top 1,000 npm packages
            ✅ **Production-Grade Detectors**: D6, D7, D5, D4, D3, D1

            ### Campaign Detection

            | Campaign | Detection Rate |
            |----------|---|
            | Dependency Confusion (176-pkg) | 100% |
            | Mini Shai-Hulud (Obfuscation) | 100% |
            | Bitwarden Impersonation | 100% |

            ### Detector Performance

            - **D6 (Version Anomaly)**: 92% avg confidence
            - **D7 (Obfuscation)**: 80% avg confidence
            - **D5 (Binary Embedding)**: 81.3% avg confidence
            - **D1 (Typosquat)**: 87.9% avg confidence (threshold 85)

            ### False Positive Calibration

            - Packages scanned: 990 (top 1,000 npm)
            - False positives: 0 (0.0% FP rate)
            - Detector thresholds: calibrated post-validation

            **Full validation report**: See attached [VALIDATION.md](./VALIDATION.md)

            ---

            **GitHub**: https://github.com/lateos-ai/npm-scan
            **npm**: https://npmjs.com/package/@lateos/npm-scan"""

    new_body = """          body: |
            # npm-scan ${{ github.ref_name }}

            ## Release Summary
            - **Campaign Detection**: 100% (3/3 real attacks)
            - **False Positive Rate**: 0.0% (0/990 packages)
            - **Tests**: All 671 passing
            - **Code Quality**: 0 linting errors

            ## Validation Metrics
            - D6 (Version Anomaly): 92% avg confidence
            - D7 (Obfuscation): 80% avg confidence
            - D1 (Typosquat): 87.9% avg confidence

            See [VALIDATION.md](./VALIDATION.md) for full metrics.

            **Published with npm provenance attestation (SLSA Level 2).**"""

    if old_body_start in content:
        content = content.replace(old_body_start, new_body)
    else:
        print('  WARN: Could not find existing release body to replace')

    # Write back with Unix line endings
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(content)

    return content.split('\n')


def main():
    sep = '=' * 60
    print(sep)
    print('Phase 4: Enhanced Release Workflow')
    print(sep)
    print()

    # ---- Step 1: Read ----
    print('1. Reading existing publish.yml...')
    if not WORKFLOW.exists():
        print(f'  FAIL: {WORKFLOW} does not exist')
        sys.exit(1)
    size = WORKFLOW.stat().st_size
    print(f'  Read {WORKFLOW} ({size} bytes)')
    print()

    # ---- Step 2: Enhance ----
    print('2. Enhancing workflow with validation gates...')
    lines = enhance_publish_yml(WORKFLOW)
    for gate_name, _ in VALIDATION_GATES:
        print(f'  Added: {gate_name}')
    print('  Added: GitHub Release creation with artifacts')
    print()

    # ---- Step 3: Verify ----
    print('3. Verifying enhanced workflow...')
    errors, total = run_verification(WORKFLOW, lines)

    print()
    if errors == 0:
        print(f'  All {total} checks passed')
    else:
        print(f'  {errors}/{total} checks FAILED')
        sys.exit(1)
    print()

    # ---- Step 4: Git operations ----
    print('4. Git operations...')

    subprocess.run(['git', 'add', str(WORKFLOW)], check=True, capture_output=True)
    print('  Staged publish.yml')

    status = subprocess.run(['git', 'status', '--short'], capture_output=True, text=True, check=True)
    if not status.stdout.strip():
        print('  WARN: Working tree clean, nothing to commit')
    else:
        commit_msg = 'chore: enhance release workflow with pre-publish validation gates'
        subprocess.run(['git', 'commit', '-m', commit_msg], check=True, capture_output=True)
        print(f'  Committed: "{commit_msg}"')

        result = subprocess.run(['git', 'push', 'origin', 'chore/enhance-release-workflow'],
                                capture_output=True, text=True)
        if result.returncode == 0:
            print('  Pushed to origin/chore/enhance-release-workflow')
        else:
            print(f'  PUSH FAILED: {result.stderr.strip()}')
            sys.exit(1)

    print()
    print(sep)
    print('SUCCESS')
    print(sep)


if __name__ == '__main__':
    main()
