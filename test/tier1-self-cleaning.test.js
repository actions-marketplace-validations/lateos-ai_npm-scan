import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-self-cleaning.js';

test('D21: self-deletion (fs.unlink __filename) detected as HIGH', async () => {
  const files = [{ path: 'install.js', content: 'fs.unlinkSync(__filename);' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'self_deletion'));
});

test('D21: package.json manipulation detected as HIGH', async () => {
  const files = [
    { path: 'install.js', content: 'fs.writeFileSync("package.json", JSON.stringify(pkg))' },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'package_json_manipulation'));
});

test('D21: file replacement (rename) detected', async () => {
  const files = [{ path: 'install.js', content: 'fs.renameSync("install.js", "install.bak")' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'file_swap'));
});

test('D21: log clearing (fs.unlink *.log) detected', async () => {
  const files = [{ path: 'install.js', content: 'fs.unlinkSync("/tmp/debug.log")' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'log_cache_clear'));
});

test('D21: git history removal detected as HIGH', async () => {
  const files = [
    { path: 'install.js', content: 'child_process.exec("git clean -fdx && rm -rf .git")' },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'git_history_removal'));
});

test('D21: timestamp manipulation (utimes) detected', async () => {
  const files = [{ path: 'install.js', content: 'fs.utimesSync(__filename, atime, mtime)' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'timestamp_manipulation'));
});

test('D21: self-deletion + package.json manipulation returns BLOCK recommendation', async () => {
  const files = [
    {
      path: 'install.js',
      content: `
      // Remove traces
      fs.unlinkSync(__filename);
      fs.writeFileSync("package.json", JSON.stringify({ name: "clean-pkg" }));
      exec("git clean -fdx");
    `,
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].recommendation?.startsWith('BLOCK'));
});

test('D21: legitimate code produces no findings', async () => {
  const files = [
    { path: 'index.js', content: 'module.exports = function sum(a, b) { return a + b; };' },
  ];
  const findings = await scan({}, [], null, files);
  assert.equal(findings.length, 0);
});

test('D21: empty package returns no findings', async () => {
  const findings = await scan({}, [], null, []);
  assert.equal(findings.length, 0);
});
