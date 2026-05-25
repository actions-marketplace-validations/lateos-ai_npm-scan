import { test, mock } from 'node:test';
import assert from 'assert/strict';
import { checkPublisherAnomaly } from '../../backend/vsix-scan/detectors/publisher-anomaly.js';

function makeExtMeta(installCount = 0) {
  return {
    statistics: installCount ? [{ statisticName: 'install', value: installCount }] : [],
  };
}

function makeProfile(ageDays) {
  if (ageDays === null) return {};
  const created = new Date(Date.now() - ageDays * 24 * 60 * 60 * 1000).toISOString();
  return { dateCreated: created };
}

function makeVersions(entries) {
  return entries.map(([v, t, pub]) => ({ version: v, publishedAt: t, publishedBy: pub, flags: [] }));
}

test('VSIX publisher: cross-namespace burst fires', async () => {
  const extMeta = makeExtMeta();
  const profile = makeProfile(200);
  const versions = makeVersions([
    ['1.0.0', '2026-05-01T00:00:00Z', 'nrwl'],
    ['2.0.0', '2026-05-15T00:00:00Z', 'nrwl'],
  ]);
  const result = await checkPublisherAnomaly(extMeta, profile, versions);
  assert.equal(result.triggered, false);
});

test('VSIX publisher: new account on high-install ext fires', async () => {
  const extMeta = makeExtMeta(150000);
  const profile = makeProfile(15);
  const versions = makeVersions([
    ['1.0.0', '2026-05-01T00:00:00Z', 'nrwl'],
  ]);
  const result = await checkPublisherAnomaly(extMeta, profile, versions);
  assert.ok(result.triggered);
  assert.ok(result.signals.some(s => s.type === 'NEW_ACCOUNT_HIGH_INSTALL'));
});

test('VSIX publisher: 15-min add+publish window fires', async () => {
  const extMeta = makeExtMeta();
  const profile = makeProfile(200);
  const versions = makeVersions([
    ['1.0.0', '2026-05-01T00:00:00Z', 'nrwl'],
    ['18.95.0', '2026-05-18T12:10:00Z', 'nrwl'],
    ['18.95.1', '2026-05-18T12:15:00Z', 'attacker'],
  ]);
  const result = await checkPublisherAnomaly(extMeta, profile, versions);
  assert.ok(result.triggered);
  assert.ok(result.signals.some(s => s.type === 'ADD_PUBLISH_RAPID'));
});

test('VSIX publisher: different publisher account fires', async () => {
  const extMeta = makeExtMeta();
  const profile = makeProfile(200);
  const versions = makeVersions([
    ['1.0.0', '2026-04-01T00:00:00Z', 'nrwl'],
    ['18.95.0', '2026-05-18T12:00:00Z', 'attacker'],
  ]);
  const result = await checkPublisherAnomaly(extMeta, profile, versions);
  assert.ok(result.triggered);
  assert.ok(result.signals.some(s => s.type === 'PUBLISHER_ACCOUNT_SUBSTITUTION'));
});

test('VSIX publisher: same publisher history = silent', async () => {
  const extMeta = makeExtMeta();
  const profile = makeProfile(200);
  const versions = makeVersions([
    ['1.0.0', '2026-01-01T00:00:00Z', 'nrwl'],
    ['18.90.0', '2026-05-01T00:00:00Z', 'nrwl'],
    ['18.95.0', '2026-05-18T12:00:00Z', 'nrwl'],
  ]);
  const result = await checkPublisherAnomaly(extMeta, profile, versions);
  assert.equal(result.triggered, false);
});
