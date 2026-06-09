import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-bun-runtime-swap.js';

test('D24: bun binary execution via spawn detected', async () => {
  const files = [
    {
      path: 'install.js',
      content: `const { spawn } = require('child_process'); spawn('bun', ['run', 'payload.js']);`,
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'bun_binary_execution'));
});

test('D24: Bun.serve API usage detected', async () => {
  const files = [{ path: 'server.js', content: `Bun.serve({ port: 3000, fetch() {} });` }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'bun_api_usage'));
});

test('D24: process.argv swap detected', async () => {
  const files = [{ path: 'install.js', content: `process.argv[0] = '/usr/local/bin/bun';` }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'process_argv_swap'));
});

test('D24: bun downloader detected', async () => {
  const files = [{ path: 'install.js', content: `curl -fsSL https://bun.sh/install | bash` }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'bun_downloader'));
});

test('D24: bun credential combo returns BLOCK', async () => {
  const files = [
    { path: 'install.js', content: `Bun.spawn(['echo', process.env.AWS_SECRET_ACCESS_KEY]);` },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].recommendation?.startsWith('BLOCK'));
  assert.ok(findings[0].detail?.some((d) => d.type === 'bun_credential_combo'));
});

test('D24: node-to-bun swap detected', async () => {
  const files = [
    {
      path: 'install.js',
      content: `spawn('node', ['-e', 'require("child_process").spawn("bun", ...)']);`,
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'node_to_bun_swap'));
});

test('D24: bun in scripts detected', async () => {
  const pkgJson = { name: 'test-pkg', scripts: { install: 'bun run setup.js' } };
  const files = [{ path: 'setup.js', content: 'console.log("ok");' }];
  const findings = await scan(pkgJson, [], null, files);
  assert(findings.length > 0);
});

test('D24: legitimate package producing no findings', async () => {
  const files = [{ path: 'app.js', content: `console.log('hello world');` }];
  const findings = await scan({}, [], null, files);
  assert.equal(findings.length, 0);
});

test('D24: empty package returns no findings', async () => {
  const findings = await scan({}, [], null, []);
  assert.equal(findings.length, 0);
});

test('D24: no files returns no findings', async () => {
  const findings = await scan({}, [], null, null);
  assert.equal(findings.length, 0);
});
