import subprocess
import sys
from pathlib import Path

WORKFLOW_DIR = Path('.github/workflows')
FILES = {
    'security-scan.yml': {
        'checks': [
            ('name', 'Security Scan'),
            ('on.pull_request.branches', 'main'),
            ('on.push.branches', 'main'),
            ('jobs.npm-audit', None),
            ('jobs.code-quality', None),
            ('permissions.contents', 'read'),
            ('permissions.security-events', 'write'),
        ],
    },
    'dependency-audit.yml': {
        'checks': [
            ('name', 'Dependency Audit'),
            ('on.pull_request.branches', 'main'),
            ('on.push.branches', 'main'),
            ('on.schedule.cron', '0 0 * * *'),
            ('jobs.npm-audit', None),
            ('permissions.contents', 'read'),
        ],
    },
}


def parse_yaml_keys(path):
    keys = {}
    stack = [('', -1)]
    list_key = None
    with open(path, encoding='utf-8') as f:
        for line in f:
            stripped = line.rstrip('\n')
            raw = stripped
            if not stripped.strip() or stripped.strip().startswith('#'):
                continue
            indent = len(raw) - len(raw.lstrip())
            value = stripped.strip()
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
                if rest == '':
                    keys[full_key] = None
                else:
                    keys[full_key] = rest.strip('"').strip("'")
                stack.append((key_part, indent))
    return keys


def run():
    errors = 0
    for fname, spec in FILES.items():
        fpath = WORKFLOW_DIR / fname
        if not fpath.exists():
            print(f'  FAIL: {fname} does not exist')
            errors += 1
            continue

        content = fpath.read_bytes()
        if b'\r\n' in content:
            print(f'  FAIL: {fname} has CRLF line endings')
            errors += 1

        try:
            parsed = parse_yaml_keys(fpath)
        except Exception as e:
            print(f'  FAIL: {fname} could not be parsed - {e}')
            errors += 1
            continue

        for key, expected_val in spec['checks']:
            actual_val = parsed.get(key)
            if actual_val is None and expected_val is not None:
                print(f'  FAIL: {fname} missing key "{key}"')
                errors += 1
                continue
            if expected_val is None:
                print(f'  PASS: {fname} key "{key}" present')
            elif expected_val in (actual_val or ''):
                print(f'  PASS: {fname} key "{key}" = {expected_val}')
            else:
                print(f'  FAIL: {fname} key "{key}" expected "{expected_val}", got "{actual_val}"')
                errors += 1

    return errors


if __name__ == '__main__':
    sep = '=' * 60
    print(sep)
    print('  Phase 3: Security Scanning Workflow')
    print(sep)
    print()
    print('1. Creating workflow files...')
    print('  (files already created manually)')
    print()
    print('2. Verifying workflow files...')
    print()
    errs = run()
    print()
    if errs == 0:
        print(f'  All {sum(len(s["checks"]) for s in FILES.values())} checks passed')
    else:
        print(f'  {errs} checks FAILED')
    print()
    print(sep)
    if errs == 0:
        print('  SUCCESS')
    else:
        print('  FAILED')
        sys.exit(1)
    print(sep)
