import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-self-defending.js';

test('D18: debugger detection (process.env.NODE_DEBUG) detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: 'process.env.NODE_DEBUG' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'debugger_detection'));
});

test('D18: execution guard (SANDBOX env) detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: 'if (process.env.SANDBOX !== "1") {' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'execution_guard'));
});

test('D18: package validation (require package.json) detected', async () => {
  const files = [{ path: 'install.js', content: 'const pkg = require("./package.json")' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'package_validation'));
});

test('D18: environment detection (GITHUB_ACTIONS) detected', async () => {
  const files = [{ path: 'install.js', content: 'process.env.GITHUB_ACTIONS' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'environment_detection'));
});

test('D18: anti-tamper (integrity check) returns BLOCK', async () => {
  const files = [{ path: 'install.js', content: 'throw new Error("integrity check failed")' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'anti_tamper'));
});

test('D18: file modification detection (mtime) detected', async () => {
  const files = [{ path: 'install.js', content: 'const mtime = fs.statSync(__filename).mtime' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'file_modification_detection'));
});

test('D18: legitimate code produces no findings', async () => {
  const files = [
    { path: 'index.js', content: 'module.exports = function add(a, b) { return a + b; }' },
  ];
  const findings = await scan({}, [], null, files);
  assert.equal(findings.length, 0);
});

test('D18: empty package returns no findings', async () => {
  const findings = await scan({}, [], null, []);
  assert.equal(findings.length, 0);
});

test('D18: no files returns no findings', async () => {
  const findings = await scan({}, [], null, null);
  assert.equal(findings.length, 0);
});
