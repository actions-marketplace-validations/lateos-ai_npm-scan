import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-transitive-deps.js';

test('D12: suspicious transitive dep detected (plain-crypto-js pattern)', async () => {
  const pkgJson = {
    name: 'test-app',
    dependencies: {
      plain: '1.0.0',
      'plain-crypto-js': '1.0.0',
      lodash: '4.17.21',
    },
  };
  const findings = await scan(pkgJson, [], null, null);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].detector, 'tier1-transitive-deps');
  assert.ok(
    findings[0].confidenceScore >= 50,
    `expected >= 50, got ${findings[0].confidenceScore}`
  );
});

test('D12: typosquat dependency detected', async () => {
  const pkgJson = {
    name: 'test-pkg',
    dependencies: {
      'crypto-js-fake': '1.0.0',
      typescrip: '1.0.0',
    },
  };
  const findings = await scan(pkgJson, [], null, null);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].evidence.some((e) => e.includes('typosquat')));
});

test('D12: clean dependencies produce no findings', async () => {
  const pkgJson = {
    name: 'test-app',
    dependencies: {
      express: '4.18.2',
      lodash: '4.17.21',
      moment: '2.29.4',
    },
  };
  const findings = await scan(pkgJson, [], null, null);
  assert.equal(findings.length, 0);
});

test('D12: no dependencies returns no findings', async () => {
  const pkgJson = { name: 'test-pkg' };
  const findings = await scan(pkgJson, [], null, null);
  assert.equal(findings.length, 0);
});

test('D12: known reputable package returns no findings', async () => {
  const pkgJson = {
    name: 'express',
    dependencies: { 'plain-crypto-js': '1.0.0' },
  };
  const findings = await scan(pkgJson, [], null, null);
  assert.equal(findings.length, 0);
});

test('D12: version anomaly with high major version detected', async () => {
  const pkgJson = {
    name: 'test-pkg',
    dependencies: {
      'weird-lib': '99.99.99',
    },
  };
  const findings = await scan(pkgJson, [], null, null);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].evidence.some((e) => e.includes('version_anomaly')));
});
