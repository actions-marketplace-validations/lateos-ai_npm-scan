import { test, mock } from 'node:test';
import assert from 'assert/strict';
import { checkExfilPattern } from '../../backend/vsix-scan/detectors/exfil-pattern.js';

test('VSIX exfil: ~/.claude/settings.json read fires', async () => {
  const files = [{
    path: 'dist/main.js',
    content: `const configPath = "~/.claude/settings.json"; const data = readFileSync(configPath);`,
  }];
  const result = await checkExfilPattern(files);
  assert.ok(result.triggered);
  assert.ok(result.exfilPatterns.some(e => e.includes('.claude')));
});

test('VSIX exfil: DNS tunneling pattern fires', async () => {
  const files = [{
    path: 'dist/main.js',
    content: `const domain = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789abcdef.evil.com";`,
  }];
  const result = await checkExfilPattern(files);
  assert.ok(result.triggered);
  assert.ok(result.signals.some(s => s.type === 'EXFIL_CHANNEL'));
});

test('VSIX exfil: AES+RSA pattern fires', async () => {
  const files = [{
    path: 'dist/main.js',
    content: `const key = crypto.createCipher('AES-256-GCM', 'secret'); const rsa = crypto.publicEncrypt('RSA/...');`,
  }];
  const result = await checkExfilPattern(files);
  assert.ok(result.triggered);
});

test('VSIX exfil: CPU core check fires (anti-analysis)', async () => {
  const files = [{
    path: 'dist/main.js',
    content: `if (os.cpus().length < 4) { process.exit(0); }`,
  }];
  const result = await checkExfilPattern(files);
  assert.ok(result.triggered);
  assert.ok(result.antiAnalysisTechniques.some(a => a.includes('CPU core')));
});

test('VSIX exfil: clean extension = silent', async () => {
  const files = [{
    path: 'dist/main.js',
    content: `console.log("hello world");`,
  }];
  const result = await checkExfilPattern(files);
  assert.equal(result.triggered, false);
  assert.equal(result.signals.length, 0);
});
