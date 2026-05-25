import { test, mock } from 'node:test';
import assert from 'assert/strict';
import { checkBurstPublish } from '../../backend/vsix-scan/detectors/burst-publish.js';

function makeVersionHistory(versions) {
  return versions.map(([v, t]) => ({ version: v, publishedAt: t, publishedBy: 'nrwl', flags: [] }));
}

test('VSIX burst: ≥2 versions in 30 min fires', async () => {
  const versions = makeVersionHistory([
    ['18.90.0', '2026-05-01T00:00:00Z'],
    ['18.94.0', '2026-05-18T12:00:00Z'],
    ['18.95.0', '2026-05-18T12:15:00Z'],
  ]);
  const result = await checkBurstPublish(versions);
  assert.ok(result.triggered);
  assert.ok(result.burstWindow);
  assert.equal(result.burstWindow.versionCount, 2);
});

test('VSIX burst: 1 version in 30 min = silent', async () => {
  const versions = makeVersionHistory([
    ['18.90.0', '2026-05-01T00:00:00Z'],
    ['18.95.0', '2026-05-18T12:00:00Z'],
  ]);
  const result = await checkBurstPublish(versions);
  assert.equal(result.triggered, false);
});

test('VSIX burst: hot pull (version live < 20 min) fires', async () => {
  const versions = makeVersionHistory([
    ['18.90.0', '2026-05-01T00:00:00Z'],
    ['18.94.0', '2026-05-18T12:00:00Z'],
    ['18.95.0', '2026-05-18T12:11:00Z'],
  ]);
  const result = await checkBurstPublish(versions);
  assert.ok(result.triggered);
  assert.ok(result.hotPullDetected);
});

test('VSIX burst: Open VSX longer window (36 min) fires separately', async () => {
  const versions = makeVersionHistory([
    ['18.90.0', '2026-05-01T00:00:00Z'],
    ['18.94.0', '2026-05-18T12:00:00Z'],
    ['18.95.0', '2026-05-18T12:35:00Z'],
  ]);
  const result = await checkBurstPublish(versions, { burstWindowMinutes: 36 });
  assert.ok(result.triggered);
  assert.equal(result.burstWindow.versionCount, 2);
});
