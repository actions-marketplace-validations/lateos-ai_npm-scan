import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-profiling-recon.js';

test('D20: platform enumeration (os.platform) detected', async () => {
  const files = [{ path: 'install.js', content: 'if (os.platform() === "win32") {' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'platform_enumeration'));
});

test('D20: user enumeration (os.homedir) detected', async () => {
  const files = [{ path: 'install.js', content: 'const home = os.homedir()' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'user_enumeration'));
});

test('D20: network check (dns.lookup) detected', async () => {
  const files = [{ path: 'install.js', content: 'dns.lookup("google.com", cb)' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'network_check'));
});

test('D20: cloud detection (metadata.google.internal) detected', async () => {
  const files = [{ path: 'install.js', content: 'fetch("http://metadata.google.internal")' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'cloud_detection'));
});

test('D20: directory scanning (readdirSync) detected', async () => {
  const files = [{ path: 'install.js', content: 'const files = fs.readdirSync("/home")' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'directory_scan'));
});

test('D20: tools detection (require.resolve) detected', async () => {
  const files = [{ path: 'install.js', content: 'const fp = require.resolve("typescript")' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'tools_detection'));
});

test('D20: cloud + directory scan returns BLOCK recommendation', async () => {
  const files = [
    {
      path: 'install.js',
      content: `
      const os = require("os");
      const fs = require("fs");
      if (os.platform() === "linux") {
        const dirs = fs.readdirSync("/home");
        fetch("http://metadata.google.internal");
      }
    `,
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].recommendation?.startsWith('BLOCK'));
});

test('D20: legitimate code produces no findings', async () => {
  const files = [{ path: 'index.js', content: 'module.exports = { name: "test" };' }];
  const findings = await scan({}, [], null, files);
  assert.equal(findings.length, 0);
});

test('D20: empty package returns no findings', async () => {
  const findings = await scan({}, [], null, []);
  assert.equal(findings.length, 0);
});
