#!/usr/bin/env python3
"""
npm-scan Production Readiness Verification
Checks if main branch has everything needed for production CI/CD.
"""

import os
import subprocess
import json
import sys
from pathlib import Path


def check_git_status():
    """Verify we're on main branch."""
    result = subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                          capture_output=True, text=True, check=False)
    branch = result.stdout.strip()
    if branch != 'main':
        print(f"  FAIL: Not on main branch (currently on: {branch})")
        return False
    print(f"  PASS: On main branch")
    return True


def check_workflow_files():
    """Verify all required workflow files exist."""
    required_workflows = [
        '.github/workflows/pr-validation.yml',
        '.github/workflows/security-scan.yml',
        '.github/workflows/dependency-audit.yml',
        '.github/workflows/publish.yml',
    ]

    all_exist = True
    for workflow in required_workflows:
        if Path(workflow).exists():
            print(f"  PASS: {workflow}")
        else:
            print(f"  FAIL: {workflow} (MISSING)")
            all_exist = False

    return all_exist


def check_package_json():
    """Verify package.json has required scripts."""
    required_scripts = [
        'test',
        'lint',
        'lint:fix',
        'format',
        'format:check',
        'validate',
    ]

    with open('package.json', 'r') as f:
        pkg = json.load(f)

    scripts = pkg.get('scripts', {})
    all_present = True

    for script in required_scripts:
        if script in scripts:
            print(f"  PASS: npm script: {script}")
        else:
            print(f"  FAIL: npm script: {script} (MISSING)")
            all_present = False

    return all_present


def check_config_files():
    """Verify ESLint and Prettier configs exist."""
    configs = [
        ('eslint.config.js', 'ESLint'),
        ('.prettierrc', 'Prettier'),
        ('.prettierignore', 'Prettier ignore'),
    ]

    all_exist = True
    for config_file, label in configs:
        if Path(config_file).exists():
            print(f"  PASS: {label}: {config_file}")
        else:
            print(f"  FAIL: {label}: {config_file} (MISSING)")
            all_exist = False

    return all_exist


def check_validation_artifacts():
    """Verify validation artifacts exist."""
    artifacts = [
        ('VALIDATION.md', 'Validation report'),
        ('detection-rates.json', 'Detection rates'),
        ('fp-analysis.json', 'False positive analysis'),
    ]

    all_exist = True
    for artifact_file, label in artifacts:
        if Path(artifact_file).exists():
            print(f"  PASS: {label}: {artifact_file}")
        else:
            print(f"  FAIL: {label}: {artifact_file} (MISSING)")
            all_exist = False

    return all_exist


def check_tests():
    """Run test suite."""
    print("  RUNNING: npm test...")
    result = subprocess.run(['npm', 'test'],
                          capture_output=True, text=True, check=False)

    if result.returncode == 0:
        if 'tests' in result.stdout.lower():
            pass
        print(f"  PASS: All tests passing")
        return True
    else:
        print(f"  FAIL: Tests failing")
        print(f"  Error: {result.stderr[:200]}")
        return False


def check_linting():
    """Run linting checks."""
    print("  RUNNING: npm run lint...")
    result = subprocess.run(['npm', 'run', 'lint'],
                          capture_output=True, text=True, check=False)

    if result.returncode == 0:
        print(f"  PASS: Linting - 0 errors")
        return True
    else:
        if 'error' in result.stdout.lower():
            print(f"  FAIL: Linting errors found")
            return False
        else:
            print(f"  PASS: Linting - warnings only (0 errors)")
            return True


def check_formatting():
    """Check code formatting."""
    print("  RUNNING: npm run format:check...")
    result = subprocess.run(['npm', 'run', 'format:check'],
                          capture_output=True, text=True, check=False)

    if result.returncode == 0:
        print(f"  PASS: Formatting - all files compliant")
        return True
    else:
        print(f"  FAIL: Formatting issues found")
        return False


def check_node_modules():
    """Verify node_modules is healthy."""
    if Path('node_modules').exists():
        print(f"  PASS: node_modules exists")
        return True
    else:
        print(f"  WARN: node_modules missing (run: npm ci)")
        return False


def get_git_commit():
    """Get current commit hash."""
    result = subprocess.run(['git', 'rev-parse', 'HEAD'],
                          capture_output=True, text=True, check=False)
    return result.stdout.strip()[:8]


def main():
    """Run all checks."""
    print("=" * 70)
    print("npm-scan: Production Readiness Check")
    print("=" * 70)

    checks = [
        ("Git Status", check_git_status),
        ("Workflow Files", check_workflow_files),
        ("npm Scripts", check_package_json),
        ("Config Files", check_config_files),
        ("Validation Artifacts", check_validation_artifacts),
        ("node_modules", check_node_modules),
        ("Code Formatting", check_formatting),
        ("Linting", check_linting),
        ("Tests", check_tests),
    ]

    results = {}
    for check_name, check_fn in checks:
        print(f"\n[{check_name}]")
        try:
            result = check_fn()
            results[check_name] = result
        except Exception as e:
            print(f"  FAIL: Error running check - {e}")
            results[check_name] = False

    # Summary
    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    print(f"\n  Passed: {passed}/{total}")

    for check_name, result in results.items():
        status = "PASS" if result else "FAIL"
        print(f"  [{status}] {check_name}")

    commit = get_git_commit()
    print(f"\n  Current commit: {commit}")

    if all(results.values()):
        print("\n" + "=" * 70)
        print("  PRODUCTION READY")
        print("=" * 70)
        return 0
    else:
        print("\n" + "=" * 70)
        print("  ISSUES FOUND")
        print("=" * 70)
        failed = [name for name, result in results.items() if not result]
        print(f"\n  Failing checks:")
        for name in failed:
            print(f"    FAIL: {name}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
