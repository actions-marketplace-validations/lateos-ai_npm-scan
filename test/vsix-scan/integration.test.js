import { test, mock } from 'node:test';
import assert from 'assert/strict';
import { vsixScan } from '../../backend/vsix-scan/index.js';

function mockResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: new Headers({ 'Content-Type': 'application/json' }),
  });
}

test('VSIX integration: Nx Console 18.95.0 mock fires CRITICAL', async (t) => {
  t.mock.method(globalThis, 'fetch', async (url) => {
    const urlStr = typeof url === 'string' ? url : '';
    if (urlStr.includes('marketplace.visualstudio.com')) {
      return mockResponse({
        results: [{
          extensions: [{
            publisher: { publisherName: 'nrwl' },
            versions: [{ version: '18.95.0', lastUpdated: '2026-05-18T12:30:00Z' }],
          }],
        }],
      });
    }
    if (urlStr.includes('open-vsx.org')) {
      return mockResponse({
        namespace: 'nrwl',
        allVersions: { '18.95.0': '2026-05-18T12:30:00Z', '18.90.0': '2026-05-01T00:00:00Z' },
        files: {},
      });
    }
    throw new Error(`Unexpected fetch: ${urlStr}`);
  });

  const findings = await vsixScan('nrwl.angular-console', { skipNetwork: false });
  assert.ok(findings.length > 0);
  assert.equal(findings[0].id, 'VSIX_SCAN');
  assert.ok(['high', 'critical'].includes(findings[0].severity));
});

test('VSIX integration: safe version 18.100.0 = clean', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const findings = await vsixScan('nrwl.angular-console', {
    skipNetwork: true,
    marketplaceVersions: [
      { version: '18.100.0', publishedAt: '2026-05-20T00:00:00Z', publishedBy: 'nrwl', flags: [] },
    ],
    manifest: { activationEvents: ['onCommand:foo.bar'], main: './dist/main.js' },
  });
  assert.equal(findings.length, 0);
});

test('VSIX integration: extension files with orphan commit patterns fire ORPHAN_COMMIT', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const findings = await vsixScan('nrwl.angular-console', {
    skipNetwork: true,
    marketplaceVersions: [
      { version: '18.95.0', publishedAt: '2026-05-18T12:30:00Z', publishedBy: 'nrwl', flags: [] },
    ],
    extensionFiles: [{
      path: 'dist/main.js',
      content: `npx github.com/nrwl/nx#a1b2c3d4e`,
    }],
    manifest: { activationEvents: ['onStartupFinished'], main: './dist/main.js' },
  });

  assert.ok(findings.length > 0);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredSignals.includes('VSIX_ORPHAN_COMMIT_FETCH'));
});

test('VSIX integration: skipNetwork returns empty findings for clean extension', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const findings = await vsixScan('some.clean-extension', {
    skipNetwork: true,
    marketplaceVersions: [
      { version: '1.0.0', publishedAt: '2026-01-01T00:00:00Z', publishedBy: 'clean-pub', flags: [] },
    ],
    manifest: { activationEvents: ['onCommand:foo.bar'], main: './dist/main.js' },
  });

  assert.equal(findings.length, 0);
});
