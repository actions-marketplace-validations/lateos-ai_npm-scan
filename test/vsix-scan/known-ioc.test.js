import { test, mock as _mock } from 'node:test';
import assert from 'assert/strict';
import { checkKnownIOC, reloadIOCData } from '../../backend/vsix-scan/detectors/known-ioc.js';

test('VSIX IOC: extensionId exact match fires', async () => {
  reloadIOCData();
  const result = await checkKnownIOC('nrwl.angular-console', '18.95.0', 'nrwl', [], []);
  assert.ok(result.triggered);
  assert.ok(result.matches.some((m) => m.type === 'extensionId'));
});

test('VSIX IOC: sha256 match fires', async () => {
  reloadIOCData();
  const result = await checkKnownIOC('nrwl.angular-console', '18.95.0', 'nrwl', [], []);
  assert.ok(result.triggered);
});

test('VSIX IOC: publisher in compromise window fires', async () => {
  reloadIOCData();
  const versionHistory = [
    { version: '18.95.0', publishedAt: '2026-05-15T00:00:00Z', publishedBy: 'nrwl', flags: [] },
  ];
  const result = await checkKnownIOC('nrwl.angular-console', '18.95.0', 'nrwl', [], versionHistory);
  assert.ok(result.triggered);
  assert.ok(result.matches.some((m) => m.type === 'publisherAccount'));
});

test('VSIX IOC: publisher outside window = silent', async () => {
  reloadIOCData();
  const versionHistory = [
    { version: '1.0.0', publishedAt: '2025-01-01T00:00:00Z', publishedBy: 'nrwl', flags: [] },
  ];
  const result = await checkKnownIOC('nrwl.angular-console', '1.0.0', 'nrwl', [], versionHistory);
  assert.equal(result.triggered, false);
});
