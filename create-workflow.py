#!/usr/bin/env python3
"""
Create clean GitHub Actions workflow files for npm-scan CI/CD.
Handles file creation, encoding, and git operations.
"""

import os
import subprocess
import sys
from pathlib import Path

def create_pr_validation_workflow():
    """Create the PR validation workflow file."""
    
    workflow_dir = Path('.github/workflows')
    workflow_file = workflow_dir / 'pr-validation.yml'
    
    # Ensure directory exists
    workflow_dir.mkdir(parents=True, exist_ok=True)
    
    workflow_content = """name: PR Validation

on:
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
          cache: "npm"
      - run: npm ci
      - run: npm run lint

  format:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
          cache: "npm"
      - run: npm ci
      - run: npm run format:check

  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: ["20", "22"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: "npm"
      - run: npm ci
      - run: npm test

  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
          cache: "npm"
      - run: npm ci
      - run: npm run validate:campaigns

  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
          cache: "npm"
      - run: npm ci
      - run: npm pack --dry-run
"""
    
    try:
        # Write file with UTF-8 encoding, Unix line endings
        with open(workflow_file, 'w', encoding='utf-8', newline='\n') as f:
            f.write(workflow_content)
        
        print(f"✅ Created: {workflow_file}")
        return True
    except Exception as e:
        print(f"❌ Error creating workflow file: {e}")
        return False


def verify_workflow_file():
    """Verify the workflow file was created correctly."""
    
    workflow_file = Path('.github/workflows/pr-validation.yml')
    
    if not workflow_file.exists():
        print(f"❌ File does not exist: {workflow_file}")
        return False
    
    # Check file size (should be ~1500+ bytes)
    file_size = workflow_file.stat().st_size
    if file_size < 1000:
        print(f"⚠️  Warning: File size is {file_size} bytes (expected >1000)")
        return False
    
    # Read and verify content
    with open(workflow_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for key workflow elements
    checks = [
        ('name: PR Validation', 'Workflow name'),
        ('pull_request:', 'Pull request trigger'),
        ('jobs:', 'Jobs section'),
        ('lint:', 'Lint job'),
        ('test:', 'Test job'),
        ('validate:', 'Validate job'),
        ('actions/checkout@v4', 'Checkout action'),
        ('actions/setup-node@v4', 'Setup Node action'),
    ]
    
    all_passed = True
    for check_str, check_name in checks:
        if check_str in content:
            print(f"  ✅ {check_name}")
        else:
            print(f"  ❌ {check_name} (MISSING)")
            all_passed = False
    
    if all_passed:
        print(f"\n✅ Workflow file verified ({file_size} bytes)")
    else:
        print(f"\n⚠️  Workflow file has issues")
    
    return all_passed


def run_git_commands():
    """Stage, commit, and push the workflow file."""
    
    try:
        print("\n📝 Git operations:")
        
        # Add file
        print("  Running: git add .github/workflows/pr-validation.yml")
        subprocess.run(['git', 'add', '.github/workflows/pr-validation.yml'], 
                      check=True, capture_output=True)
        print("  ✅ Added to staging")
        
        # Commit
        commit_msg = "chore: create PR validation workflow (lint, format, test, validate, build)"
        print(f"  Running: git commit -m '{commit_msg}'")
        result = subprocess.run(['git', 'commit', '-m', commit_msg],
                               check=True, capture_output=True, text=True)
        print(f"  ✅ Committed")
        print(f"     {result.stdout.strip().split(chr(10))[0]}")  # First line of commit output
        
        # Get current branch
        current_branch = subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                                       check=True, capture_output=True, text=True).stdout.strip()
        print(f"  Current branch: {current_branch}")
        
        # Push
        print(f"  Running: git push origin {current_branch}")
        result = subprocess.run(['git', 'push', 'origin', current_branch],
                               check=True, capture_output=True, text=True)
        print(f"  ✅ Pushed to remote")
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"  ❌ Git error: {e.stderr or e.stdout}")
        return False
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False


def main():
    """Main execution."""
    
    print("=" * 60)
    print("npm-scan CI/CD Workflow Creator")
    print("=" * 60)
    
    # Step 1: Create workflow file
    print("\n1️⃣  Creating workflow file...")
    if not create_pr_validation_workflow():
        sys.exit(1)
    
    # Step 2: Verify workflow file
    print("\n2️⃣  Verifying workflow file...")
    if not verify_workflow_file():
        print("⚠️  Continuing anyway...")
    
    # Step 3: Git operations
    print("\n3️⃣  Staging, committing, and pushing...")
    if not run_git_commands():
        print("⚠️  Git operations failed. You may need to manually commit and push.")
        sys.exit(1)
    
    # Summary
    print("\n" + "=" * 60)
    print("✅ SUCCESS")
    print("=" * 60)
    print("""
Workflow file created and pushed to GitHub.

Next steps:
1. Go to: https://github.com/lateos-ai/npm-scan/pulls
2. Create a new PR from chore/add-cicd to main
3. Wait for workflows to run (3-5 minutes)
4. Verify all checks pass
5. Merge the PR

GitHub will automatically run the workflows when you create the PR.
Watch the "Checks" section to see job status.
""")


if __name__ == '__main__':
    main()