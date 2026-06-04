import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-self-propagation.js';

test('D10: burst of 4 versions in 1 hour triggers detection', async () => {
  const registryMeta = {
    time: {
      '1.0.0': '2024-01-01T00:00:00.000Z',
      '2.0.0': '2026-06-01T00:00:00.000Z',
      '2.0.1': '2026-06-01T00:15:00.000Z',
      '2.0.2': '2026-06-01T00:30:00.000Z',
      '2.0.3': '2026-06-01T00:45:00.000Z',
    },
    namespacePackages: ['@redhat-cloud-services/bar', '@redhat-cloud-services/baz'],
  };
  const pkgJson = { name: '@redhat-cloud-services/foo', version: '2.0.3' };
  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].detector, 'tier1-self-propagation');
  assert.ok(
    findings[0].confidenceScore >= 75,
    `expected >= 75, got ${findings[0].confidenceScore}`
  );
});

test('D10: fewer than 3 versions produces no finding', async () => {
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

test('D10: known reputable package returns no findings', async () => {
  const registryMeta = {
    time: {
      '1.0.0': '2024-01-01T00:00:00.000Z',
      '2.0.0': '2026-06-01T00:00:00.000Z',
      '2.0.1': '2026-06-01T00:15:00.000Z',
      '2.0.2': '2026-06-01T00:30:00.000Z',
    },
  };
  const pkgJson = { name: 'electron', version: '2.0.2' };
  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 0);
});

test('D10: no registry meta returns empty findings', async () => {
  const pkgJson = { name: 'test-pkg', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, null);
  assert.equal(findings.length, 0);
});

test('D10: clean package steady releases returns no finding', async () => {
  const registryMeta = {
    time: {
      '1.0.0': '2024-01-01T00:00:00.000Z',
      '1.1.0': '2024-02-01T00:00:00.000Z',
      '1.2.0': '2024-03-01T00:00:00.000Z',
      '1.3.0': '2024-04-01T00:00:00.000Z',
    },
  };
  const pkgJson = { name: 'steady-pkg', version: '1.3.0' };
  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 0);
});
