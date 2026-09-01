import { describe, it } from 'node:test';
import assert from 'node:assert';
import { scan } from '../backend/detectors/tier1-maintainer-compromise.js';

describe('tier1-maintainer-compromise: single_version_compromise', () => {
  it('detects single version published after 30+ day gap, deprecated within 24h', async () => {
    const pkgJson = { name: 'test-package' };
    const registryMeta = {
      time: {
        created: '2024-01-01T00:00:00.000Z',
        modified: '2026-07-11T18:00:00.000Z',
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '1.1.0': '2024-06-01T00:00:00.000Z',
        '1.2.0': '2026-06-10T10:00:00.000Z',
        '8.14.0': '2026-07-11T14:30:00.000Z',
        '8.15.0': '2026-07-11T18:00:00.000Z',
      },
      versions: {
        '1.0.0': { dist: { shasum: 'abc123' } },
        '1.1.0': { dist: { shasum: 'def456' } },
        '1.2.0': { dist: { shasum: 'ghi789' } },
        '8.14.0': {
          dist: { shasum: 'malicious' },
          deprecated: 'SECURITY: version 8.14.0 is compromised. Do not install.',
        },
        '8.15.0': { dist: { shasum: 'clean' } },
      },
    };

    const findings = await scan(pkgJson, [], registryMeta, []);
    const singleFindings = findings.filter((f) => f.subtype === 'single_version_compromise');

    assert.strictEqual(singleFindings.length, 1);
    assert.strictEqual(singleFindings[0].confidenceScore, 70);
    assert.ok(singleFindings[0].message.includes('8.14.0'));
    assert.ok(singleFindings[0].evidence.some((e) => e.includes('gap_days: 31.2')));
    assert.ok(singleFindings[0].evidence.some((e) => e.includes('hours_to_remediation: 3.5')));
  });

  it('does not flag version published within 30 days of previous', async () => {
    const pkgJson = { name: 'test-package' };
    const registryMeta = {
      time: {
        created: '2024-01-01T00:00:00.000Z',
        modified: '2026-07-11T14:30:00.000Z',
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '1.1.0': '2026-06-20T00:00:00.000Z',
        '1.2.0': '2026-07-11T14:30:00.000Z',
      },
      versions: {
        '1.0.0': { dist: { shasum: 'abc123' } },
        '1.1.0': { dist: { shasum: 'def456' } },
        '1.2.0': {
          dist: { shasum: 'ghi789' },
          deprecated: '2026-07-11T18:00:00.000Z',
        },
      },
    };

    const findings = await scan(pkgJson, [], registryMeta, []);
    const singleFindings = findings.filter((f) => f.subtype === 'single_version_compromise');

    assert.strictEqual(singleFindings.length, 0);
  });

  it('does not flag version deprecated after 24+ hours', async () => {
    const pkgJson = { name: 'test-package' };
    const registryMeta = {
      time: {
        created: '2024-01-01T00:00:00.000Z',
        modified: '2026-07-13T14:30:00.000Z',
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '1.1.0': '2024-06-01T00:00:00.000Z',
        '8.14.0': '2026-07-11T14:30:00.000Z',
        '8.15.0': '2026-07-13T14:30:00.000Z',
      },
      versions: {
        '1.0.0': { dist: { shasum: 'abc123' } },
        '1.1.0': { dist: { shasum: 'def456' } },
        '8.14.0': {
          dist: { shasum: 'malicious' },
          deprecated: 'SECURITY: version 8.14.0 is compromised. Do not install.',
        },
        '8.15.0': { dist: { shasum: 'clean' } },
      },
    };

    const findings = await scan(pkgJson, [], registryMeta, []);
    const singleFindings = findings.filter((f) => f.subtype === 'single_version_compromise');

    assert.strictEqual(singleFindings.length, 0);
  });

  it('does not flag version without deprecation', async () => {
    const pkgJson = { name: 'test-package' };
    const registryMeta = {
      time: {
        created: '2024-01-01T00:00:00.000Z',
        modified: '2026-07-11T14:30:00.000Z',
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '1.1.0': '2024-06-01T00:00:00.000Z',
        '8.14.0': '2026-07-11T14:30:00.000Z',
      },
      versions: {
        '1.0.0': { dist: { shasum: 'abc123' } },
        '1.1.0': { dist: { shasum: 'def456' } },
        '8.14.0': { dist: { shasum: 'malicious' } },
      },
    };

    const findings = await scan(pkgJson, [], registryMeta, []);
    const singleFindings = findings.filter((f) => f.subtype === 'single_version_compromise');

    assert.strictEqual(singleFindings.length, 0);
  });
});

describe('tier1-maintainer-compromise: dist_tag_manipulation', () => {
  it('detects dist-tag pointing to version with next version within 1 hour', async () => {
    const pkgJson = { name: 'test-package' };
    const registryMeta = {
      'dist-tags': {
        latest: '8.14.0',
      },
      time: {
        created: '2024-01-01T00:00:00.000Z',
        modified: '2026-07-11T15:00:00.000Z',
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '1.1.0': '2024-06-01T00:00:00.000Z',
        '8.13.0': '2026-06-15T10:00:00.000Z',
        '8.14.0': '2026-07-11T14:30:00.000Z',
        '8.15.0': '2026-07-11T15:00:00.000Z',
      },
      versions: {
        '1.0.0': { dist: { shasum: 'abc123' } },
        '1.1.0': { dist: { shasum: 'def456' } },
        '8.13.0': { dist: { shasum: 'ghi789' } },
        '8.14.0': { dist: { shasum: 'malicious' } },
        '8.15.0': { dist: { shasum: 'clean' } },
      },
    };

    const findings = await scan(pkgJson, [], registryMeta, []);
    const distTagFindings = findings.filter((f) => f.subtype === 'dist_tag_manipulation');

    assert.strictEqual(distTagFindings.length, 1);
    assert.strictEqual(distTagFindings[0].confidenceScore, 85);
    assert.ok(distTagFindings[0].message.includes('Dist-tag manipulation'));
    assert.ok(distTagFindings[0].evidence.some((e) => e.includes('tag: latest → 8.14.0')));
    assert.ok(distTagFindings[0].evidence.some((e) => e.includes('next version in 0.50h')));
  });

  it('does not flag dist-tag when next version is more than 1 hour away', async () => {
    const pkgJson = { name: 'test-package' };
    const registryMeta = {
      'dist-tags': {
        latest: '8.14.0',
      },
      time: {
        created: '2024-01-01T00:00:00.000Z',
        modified: '2026-07-11T18:00:00.000Z',
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '1.1.0': '2024-06-01T00:00:00.000Z',
        '8.13.0': '2026-06-15T10:00:00.000Z',
        '8.14.0': '2026-07-11T14:30:00.000Z',
        '8.15.0': '2026-07-11T18:00:00.000Z',
      },
      versions: {
        '1.0.0': { dist: { shasum: 'abc123' } },
        '1.1.0': { dist: { shasum: 'def456' } },
        '8.13.0': { dist: { shasum: 'ghi789' } },
        '8.14.0': { dist: { shasum: 'malicious' } },
        '8.15.0': { dist: { shasum: 'clean' } },
      },
    };

    const findings = await scan(pkgJson, [], registryMeta, []);
    const distTagFindings = findings.filter((f) => f.subtype === 'dist_tag_manipulation');

    assert.strictEqual(distTagFindings.length, 0);
  });

  it('does not flag dist-tag pointing to latest version', async () => {
    const pkgJson = { name: 'test-package' };
    const registryMeta = {
      'dist-tags': {
        latest: '8.15.0',
      },
      time: {
        created: '2024-01-01T00:00:00.000Z',
        modified: '2026-07-11T18:00:00.000Z',
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '1.1.0': '2024-06-01T00:00:00.000Z',
        '8.13.0': '2026-06-15T10:00:00.000Z',
        '8.14.0': '2026-07-11T14:30:00.000Z',
        '8.15.0': '2026-07-11T18:00:00.000Z',
      },
      versions: {
        '1.0.0': { dist: { shasum: 'abc123' } },
        '1.1.0': { dist: { shasum: 'def456' } },
        '8.13.0': { dist: { shasum: 'ghi789' } },
        '8.14.0': { dist: { shasum: 'malicious' } },
        '8.15.0': { dist: { shasum: 'clean' } },
      },
    };

    const findings = await scan(pkgJson, [], registryMeta, []);
    const distTagFindings = findings.filter((f) => f.subtype === 'dist_tag_manipulation');

    assert.strictEqual(distTagFindings.length, 0);
  });

  it('detects multiple dist-tags with rapid succession', async () => {
    const pkgJson = { name: 'test-package' };
    const registryMeta = {
      'dist-tags': {
        latest: '8.14.0',
        next: '8.16.0',
      },
      time: {
        created: '2024-01-01T00:00:00.000Z',
        modified: '2026-07-11T16:00:00.000Z',
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '1.1.0': '2024-06-01T00:00:00.000Z',
        '8.13.0': '2026-06-15T10:00:00.000Z',
        '8.14.0': '2026-07-11T14:30:00.000Z',
        '8.15.0': '2026-07-11T15:00:00.000Z',
        '8.16.0': '2026-07-11T15:30:00.000Z',
        '8.17.0': '2026-07-11T16:00:00.000Z',
      },
      versions: {
        '1.0.0': { dist: { shasum: 'abc123' } },
        '1.1.0': { dist: { shasum: 'def456' } },
        '8.13.0': { dist: { shasum: 'ghi789' } },
        '8.14.0': { dist: { shasum: 'malicious1' } },
        '8.15.0': { dist: { shasum: 'clean' } },
        '8.16.0': { dist: { shasum: 'malicious2' } },
        '8.17.0': { dist: { shasum: 'malicious3' } },
      },
    };

    const findings = await scan(pkgJson, [], registryMeta, []);
    const distTagFindings = findings.filter((f) => f.subtype === 'dist_tag_manipulation');

    assert.strictEqual(distTagFindings.length, 1);
    assert.ok(distTagFindings[0].evidence.length >= 2);
  });
});

describe('tier1-maintainer-compromise: combined detection', () => {
  it('detects both burst and single version compromise in same package', async () => {
    const pkgJson = { name: 'test-package' };
    const registryMeta = {
      time: {
        created: '2024-01-01T00:00:00.000Z',
        modified: '2026-07-11T18:00:00.000Z',
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '1.1.0': '2024-06-01T00:00:00.000Z',
        '1.2.0': '2026-06-10T10:00:00.000Z',
        '8.14.0': '2026-07-11T14:30:00.000Z',
        '8.15.0': '2026-07-11T15:00:00.000Z',
        '8.16.0': '2026-07-11T15:30:00.000Z',
        '8.17.0': '2026-07-11T16:00:00.000Z',
      },
      versions: {
        '1.0.0': { dist: { shasum: 'abc123' } },
        '1.1.0': { dist: { shasum: 'def456' } },
        '1.2.0': { dist: { shasum: 'ghi789' } },
        '8.14.0': {
          dist: { shasum: 'malicious1' },
          deprecated: '2026-07-11T18:00:00.000Z',
        },
        '8.15.0': { dist: { shasum: 'clean' } },
        '8.16.0': { dist: { shasum: 'malicious2' } },
        '8.17.0': { dist: { shasum: 'malicious3' } },
      },
    };

    const findings = await scan(pkgJson, [], registryMeta, []);

    const burstFindings = findings.filter((f) => f.subtype === 'maintainer_compromise_burst');
    const singleFindings = findings.filter((f) => f.subtype === 'single_version_compromise');

    assert.strictEqual(burstFindings.length, 1);
    assert.strictEqual(singleFindings.length, 1);
  });
});
