import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-maintainer-compromise.js';

test('D13: burst of 12 versions in 2 hours triggers critical detection', async () => {
  const now = new Date('2026-06-01T03:00:00Z');
  const times = { '1.0.0': '2024-01-01T00:00:00.000Z' };
  for (let i = 0; i < 12; i++) {
    const t = new Date(now.getTime() - (12 - i) * 10 * 60 * 1000);
    times[`2.${i}.0`] = t.toISOString();
  }
  const registryMeta = { time: times };
  const pkgJson = { name: '@redhat-cloud-services/foo', version: '2.11.0' };
  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].detector, 'tier1-maintainer-compromise');
  assert.ok(
    findings[0].confidenceScore >= 75,
    `expected >= 75, got ${findings[0].confidenceScore}`
  );
});

test('D13: 3 versions in burst detected', async () => {
  const registryMeta = {
    time: {
      '1.0.0': '2024-01-01T00:00:00.000Z',
      '2.0.0': '2026-06-01T00:00:00.000Z',
      '2.0.1': '2026-06-01T00:15:00.000Z',
      '2.0.2': '2026-06-01T00:30:00.000Z',
    },
  };
  const pkgJson = { name: 'test-pkg', version: '2.0.2' };
  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
});

test('D13: fewer than 3 versions produces no finding', async () => {
  const registryMeta = {
    time: {
      '1.0.0': '2024-01-01T00:00:00.000Z',
      '1.0.1': '2026-06-01T00:00:00.000Z',
    },
  };
  const pkgJson = { name: 'test-pkg', version: '1.0.1' };
  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 0);
});

test('D13: known reputable package returns no findings', async () => {
  const registryMeta = {
    time: {
      '1.0.0': '2024-01-01T00:00:00.000Z',
      '2.0.0': '2026-06-01T00:00:00.000Z',
      '2.0.1': '2026-06-01T00:15:00.000Z',
      '2.0.2': '2026-06-01T00:30:00.000Z',
    },
  };
  const pkgJson = { name: 'webpack', version: '2.0.2' };
  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 0);
});

test('D13: slow steady releases produce no finding', async () => {
  const registryMeta = {
    time: {
      '1.0.0': '2024-06-01T00:00:00.000Z',
      '1.1.0': '2024-07-01T00:00:00.000Z',
      '1.2.0': '2024-08-01T00:00:00.000Z',
      '1.3.0': '2024-09-01T00:00:00.000Z',
    },
  };
  const pkgJson = { name: 'steady-pkg', version: '1.3.0' };
  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 0);
});

test('D13: cross-package burst flag boosts confidence', async () => {
  const now = new Date('2026-06-01T03:00:00Z');
  const times = { '1.0.0': '2024-01-01T00:00:00.000Z' };
  for (let i = 0; i < 8; i++) {
    const t = new Date(now.getTime() - (8 - i) * 10 * 60 * 1000);
    times[`2.${i}.0`] = t.toISOString();
  }
  const registryMeta = {
    time: times,
    crossPackageBurst: true,
  };
  const pkgJson = { name: 'test-pkg', version: '2.7.0' };
  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const hasCrossPkg = findings[0].evidence.some((e) => e.includes('cross_package'));
  assert.ok(hasCrossPkg);
});
